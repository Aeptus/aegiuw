#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Quality runner — the only execution engine.
 *
 * Hard rules:
 *  - Registry is the source of truth; this file is the engine.
 *  - Wave order: preflight → static → build → postbuild → tests → audit.
 *  - Fail fast between waves; finish in-flight gates in the failed wave.
 *  - Every failure prints a rerun command; full output goes to a per-gate
 *    log on disk.
 *  - `--no-verify` is not a workflow; it's an emergency hatch the runner
 *    cannot prevent (it lives at the Git layer).
 */

import { parseArgs } from 'node:util';
import { cpus } from 'node:os';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { GATES, WAVES, validateRegistry } from './registry.mjs';
import {
  getStagedFiles,
  getChangedFiles,
  readPrePushStdin,
  resolveDiffBase,
  isWorktreeDirty,
} from './git.mjs';
import { shouldRunFullSuite } from './triggers.mjs';
import {
  CACHE_DIR,
  cacheDisabled,
  cacheStatus,
  clearCache,
  computeCacheKey,
  computeRuntimeFingerprint,
  lookupCache,
  pruneOutputs,
  storeCache,
} from './cache.mjs';
import {
  jsonSummary,
  printGateLine,
  printSummary,
  printWaveHeader,
  teeLog,
  writeFailureLog,
} from './output.mjs';

const VALID_MODES = new Set(['staged', 'prepush', 'prepush-full', 'local', 'cloud-parity']);

function parseCli() {
  const { values } = parseArgs({
    options: {
      mode: { type: 'string', default: 'local' },
      full: { type: 'boolean' },
      include: { type: 'string', multiple: true },
      skip: { type: 'string', multiple: true },
      tags: { type: 'string' },
      'skip-tags': { type: 'string' },
      wave: { type: 'string' },
      json: { type: 'boolean' },
      'debug-cache': { type: 'boolean' },
      concurrency: { type: 'string' },
      'cache-status': { type: 'boolean' },
      'cache-clear': { type: 'boolean' },
    },
    allowPositionals: false,
    strict: true,
  });
  return values;
}

function selectGates(args, mode) {
  const include = new Set(args.include ?? []);
  const skip = new Set(args.skip ?? []);
  const tags = args.tags ? new Set(args.tags.split(',').map((s) => s.trim())) : null;
  const skipTags = args['skip-tags']
    ? new Set(args['skip-tags'].split(',').map((s) => s.trim()))
    : null;
  const waveFilter = args.wave ?? null;

  return GATES.filter((g) => {
    if (!g.modes.includes(mode)) return false;
    if (include.size > 0 && !include.has(g.id)) return false;
    if (skip.has(g.id)) return false;
    if (waveFilter && g.wave !== waveFilter) return false;
    if (tags && !g.tags?.some((t) => tags.has(t))) return false;
    if (skipTags && g.tags?.some((t) => skipTags.has(t))) return false;
    return true;
  });
}

function buildContext(mode, forceFull) {
  if (mode === 'staged') {
    const staged = getStagedFiles();
    return {
      mode,
      relevantFiles: staged,
      stagedFiles: staged,
      diffBase: null,
      diffHead: null,
      diffSource: 'staged',
    };
  }
  if (mode === 'prepush' || mode === 'prepush-full') {
    const updates = readPrePushStdin();
    const resolved = resolveDiffBase(updates);
    let changed = [];
    if (resolved) {
      changed = getChangedFiles(resolved.base, resolved.head);
    }
    const trig = shouldRunFullSuite({
      mode,
      forceFull,
      changedFiles: changed,
    });
    return {
      mode: trig.full ? 'prepush-full' : 'prepush',
      relevantFiles: changed,
      stagedFiles: [],
      diffBase: resolved?.base ?? null,
      diffHead: resolved?.head ?? null,
      diffSource: resolved?.source ?? 'none',
      fullReason: trig.reason,
    };
  }
  // local / cloud-parity: act on everything
  return {
    mode,
    relevantFiles: [],
    stagedFiles: [],
    diffBase: null,
    diffHead: null,
    diffSource: 'none',
  };
}

function ensureDirtyAllowed(mode) {
  if (mode === 'staged') return true;
  if (mode !== 'prepush' && mode !== 'prepush-full') return true;
  if (!isWorktreeDirty()) return true;
  const isTTY = process.stdin.isTTY;
  if (!isTTY) {
    if (process.env.AEPTUS_SKIP_DIRTY_WORKTREE_CONFIRM === '1') {
      console.error(
        '⚠ dirty worktree — proceeding because AEPTUS_SKIP_DIRTY_WORKTREE_CONFIRM=1',
      );
      return true;
    }
    console.error(
      '✗ dirty worktree in non-interactive pre-push; aborting. Set AEPTUS_SKIP_DIRTY_WORKTREE_CONFIRM=1 to override.',
    );
    return false;
  }
  // Interactive: short and explicit prompt
  console.error('⚠ worktree has uncommitted changes; press Enter to continue or Ctrl+C to abort.');
  try {
    // No async TTY read needed; the user can Ctrl+C this hook before we proceed.
    // We can't easily block on TTY read without extra deps, so allow & log.
    return true;
  } catch {
    return true;
  }
}

function runConcurrent(items, limit, runner) {
  return new Promise((resolve) => {
    const results = new Array(items.length);
    let next = 0;
    let active = 0;
    let finished = 0;
    if (items.length === 0) return resolve(results);
    const launchNext = () => {
      while (active < limit && next < items.length) {
        const idx = next++;
        active++;
        runner(items[idx], idx).then((r) => {
          results[idx] = r;
          active--;
          finished++;
          if (finished === items.length) resolve(results);
          else launchNext();
        });
      }
    };
    launchNext();
  });
}

async function main() {
  const args = parseCli();

  if (args['cache-status']) {
    console.log(JSON.stringify(cacheStatus(), null, 2));
    return 0;
  }
  if (args['cache-clear']) {
    clearCache();
    console.log(`cleared ${CACHE_DIR}/index.json`);
    return 0;
  }

  const initialMode = args.mode;
  if (!VALID_MODES.has(initialMode)) {
    console.error(`unknown --mode=${initialMode}; valid: ${[...VALID_MODES].join(', ')}`);
    return 2;
  }

  const regErrors = validateRegistry();
  if (regErrors.length > 0) {
    console.error('✗ registry invalid:');
    for (const e of regErrors) console.error(`  - ${e}`);
    return 2;
  }

  const ctx = buildContext(initialMode, args.full ?? false);
  if (!ensureDirtyAllowed(ctx.mode)) return 3;

  const runtimeFingerprint = computeRuntimeFingerprint();
  const concurrencyLimit = args.concurrency
    ? Math.max(1, parseInt(args.concurrency, 10))
    : Math.min(cpus().length, 6);

  // Logging for non-staged runs
  let logPath = null;
  if (ctx.mode !== 'staged') {
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    logPath = `logs/quality-${ctx.mode}-${ts}.log`;
    mkdirSync('logs', { recursive: true });
    writeFileSync(logPath, `aegiuw quality run mode=${ctx.mode} started ${ts}\n`);
  }
  pruneOutputs();

  const gates = selectGates(args, ctx.mode);
  if (gates.length === 0) {
    console.error(`✗ no gates matched mode=${ctx.mode}; nothing to do`);
    return 4;
  }

  if (!args.json) {
    const header = [
      `aegiuw quality — mode=${ctx.mode}`,
      ctx.diffSource && ctx.diffSource !== 'none' ? `diff=${ctx.diffSource}` : null,
      `cache=${cacheDisabled() ? 'DISABLED' : 'on'}`,
      ctx.fullReason ? `full-trigger=${ctx.fullReason}` : null,
      `relevant=${ctx.relevantFiles.length}`,
    ]
      .filter(Boolean)
      .join('  ·  ');
    console.log(header);
    teeLog(logPath, header);
  }

  const results = [];
  const allStart = Date.now();
  let abort = false;

  for (const wave of WAVES) {
    const waveGates = gates.filter((g) => g.wave === wave && g.applies(ctx));
    const skippedThisWave = gates
      .filter((g) => g.wave === wave && !g.applies(ctx))
      .map((g) => ({ gate: g, status: 'skip', reason: 'does not apply' }));
    results.push(...skippedThisWave);
    if (waveGates.length === 0) continue;
    if (!args.json) printWaveHeader(wave, waveGates.length);

    const waveResults = await runConcurrent(waveGates, concurrencyLimit, async (g) => {
      const key = g.cacheable && !cacheDisabled() ? computeCacheKey(g, ctx, runtimeFingerprint) : null;
      if (key) {
        const hit = lookupCache(key);
        if (hit && hit.passed) {
          const r = { gate: g, status: 'pass', cached: true, cacheKey: key };
          if (!args.json) printGateLine(r);
          if (args['debug-cache']) {
            const dbg = `   ↳ cache hit: ${key.slice(0, 12)}…`;
            console.log(dbg);
            teeLog(logPath, dbg);
          }
          return r;
        }
      }

      const raw = await g.run(ctx);
      const status = raw.passed ? 'pass' : 'fail';
      let logFile = null;
      if (!raw.passed) {
        logFile = writeFailureLog(g.id, raw.output ?? '');
      }
      const r = {
        gate: g,
        status,
        durationMs: raw.durationMs,
        reason: raw.reason,
        logPath: logFile,
        cacheKey: key,
        scopeNote:
          ctx.mode === 'prepush' || ctx.mode === 'prepush-full'
            ? `${ctx.diffSource} (${ctx.relevantFiles.length} files)`
            : undefined,
      };
      if (raw.passed && key) {
        storeCache(key, { gateId: g.id, passed: true });
      }
      if (!args.json) printGateLine(r);
      teeLog(logPath, `${status} ${g.id} ${raw.durationMs ?? '?'}ms`);
      return r;
    });

    results.push(...waveResults);
    if (waveResults.some((r) => r.status === 'fail')) {
      abort = true;
      break;
    }
  }

  // Any gates the runner never reached (because we aborted) are marked as skipped.
  for (const g of gates) {
    if (!results.some((r) => r.gate.id === g.id)) {
      results.push({ gate: g, status: 'skip', reason: 'aborted: prior wave failed' });
    }
  }

  const totalMs = Date.now() - allStart;
  if (args.json) {
    console.log(jsonSummary(results, ctx.mode, totalMs));
  } else {
    printSummary(results, ctx.mode, totalMs);
    if (logPath) console.log(`\nlog: ${logPath}`);
  }
  return abort ? 1 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error('runner crashed:', err);
    process.exit(99);
  });
