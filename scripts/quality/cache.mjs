// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Content-hash cache for successful gates.
 *
 * Hard rules from the spec:
 *  - cache successful gates ONLY;
 *  - cache keys must include schema version, gate id, runtime fingerprint,
 *    declared input contents, runner code hash, registry code hash, and
 *    relevant env vars;
 *  - never trust timestamps for validity;
 *  - never use a cache entry unless every meaningful input is in the key.
 */

import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

export const CACHE_DIR = '.aeptus-cache/quality';
export const CACHE_INDEX = `${CACHE_DIR}/index.json`;
export const OUTPUTS_DIR = `${CACHE_DIR}/outputs`;
export const SCHEMA_VERSION = 1;

const CACHE_INFLUENCING_ENVS = ['CARGO_TARGET_DIR', 'RUSTFLAGS', 'NODE_OPTIONS'];

function safeRead(path) {
  try {
    return readFileSync(path);
  } catch {
    return null;
  }
}

function safeExec(cmd, args) {
  try {
    return execFileSync(cmd, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return 'unknown';
  }
}

/**
 * Stable fingerprint of the runtime environment.
 * Recomputed once per invocation — cheap to do.
 */
export function computeRuntimeFingerprint() {
  const h = createHash('sha256');
  h.update(`schema:${SCHEMA_VERSION}\n`);
  h.update(`node:${process.version}\n`);
  h.update(`cargo:${safeExec('cargo', ['--version'])}\n`);
  h.update(`rustc:${safeExec('rustc', ['--version'])}\n`);
  h.update(`npm:${safeExec('npm', ['--version'])}\n`);
  for (const k of CACHE_INFLUENCING_ENVS) {
    h.update(`env:${k}=${process.env[k] ?? ''}\n`);
  }
  // Self-hash: any change to the quality system invalidates every cache entry.
  for (const f of [
    'scripts/quality/runner.mjs',
    'scripts/quality/registry.mjs',
    'scripts/quality/cache.mjs',
    'scripts/quality/triggers.mjs',
    'scripts/quality/exec.mjs',
    'scripts/quality/git.mjs',
    'scripts/quality/output.mjs',
    'scripts/quality/filter.mjs',
    'scripts/quality/gates/secrets.mjs',
    'scripts/quality/gates/spdx.mjs',
  ]) {
    const c = safeRead(f);
    if (c) {
      h.update(`self:${f}:`);
      h.update(c);
      h.update('\n');
    }
  }
  return h.digest('hex');
}

/**
 * Expand declared input paths into a concrete file list.
 *
 * Supports:
 *  - exact file paths (committed or untracked);
 *  - directory paths (recursed via `git ls-files` for tracked, then manual
 *    walk for untracked — so untracked files inside declared input dirs
 *    DO invalidate the cache, per the spec).
 */
function expandInputs(patterns) {
  const out = new Set();
  for (const p of patterns ?? []) {
    if (!existsSync(p)) {
      out.add(`__missing__:${p}`);
      continue;
    }
    const st = statSync(p);
    if (st.isFile()) {
      out.add(p);
      continue;
    }
    if (st.isDirectory()) {
      const tracked = safeExec('git', ['ls-files', '-z', '--', p]).split('\0').filter(Boolean);
      for (const f of tracked) out.add(f);
      // Untracked files in the same directory must also count.
      const untracked = safeExec('git', [
        'ls-files',
        '--others',
        '--exclude-standard',
        '-z',
        '--',
        p,
      ])
        .split('\0')
        .filter(Boolean);
      for (const f of untracked) out.add(f);
    }
  }
  return [...out].sort();
}

export function computeCacheKey(gate, ctx, runtimeFingerprint) {
  const h = createHash('sha256');
  h.update(`schema:${SCHEMA_VERSION}\n`);
  h.update(`gate:${gate.id}\n`);
  h.update(`runtime:${runtimeFingerprint}\n`);
  h.update(`mode:${ctx.mode}\n`);

  const inputs = expandInputs(gate.inputs ?? []);
  for (const f of inputs) {
    if (f.startsWith('__missing__:')) {
      h.update(`${f}\n`);
      continue;
    }
    const buf = safeRead(f);
    if (buf == null) {
      h.update(`file:${f}:UNREADABLE\n`);
    } else {
      h.update(`file:${f}:`);
      h.update(buf);
      h.update('\n');
    }
  }
  // For scope='changed' gates outside full mode, the set of relevant files
  // matters because the gate decides what to act on from that set.
  if (gate.scope === 'changed' && ctx.mode !== 'prepush-full' && ctx.mode !== 'local') {
    for (const f of [...ctx.relevantFiles].sort()) {
      h.update(`relevant:${f}\n`);
    }
  }
  return h.digest('hex');
}

function loadIndex() {
  if (!existsSync(CACHE_INDEX)) return {};
  try {
    return JSON.parse(readFileSync(CACHE_INDEX, 'utf8'));
  } catch {
    return {};
  }
}

function saveIndex(idx) {
  mkdirSync(CACHE_DIR, { recursive: true });
  writeFileSync(CACHE_INDEX, JSON.stringify(idx, null, 2));
}

export function lookupCache(key) {
  const idx = loadIndex();
  return idx[key] ?? null;
}

export function storeCache(key, entry) {
  const idx = loadIndex();
  idx[key] = { ...entry, storedAt: new Date().toISOString() };
  saveIndex(idx);
}

export function clearCache() {
  if (existsSync(CACHE_INDEX)) writeFileSync(CACHE_INDEX, '{}');
}

export function cacheDisabled() {
  return (
    process.env.AEPTUS_QUALITY_DISABLE_CACHE === '1' ||
    // Backwards-compat per spec
    process.env.AEPTUS_PREPUSH_DISABLE_CACHE === '1'
  );
}

export function cacheStatus() {
  const idx = loadIndex();
  const entries = Object.entries(idx);
  return {
    dir: CACHE_DIR,
    schemaVersion: SCHEMA_VERSION,
    disabled: cacheDisabled(),
    entryCount: entries.length,
    perGate: Object.fromEntries(
      Object.entries(
        entries.reduce((acc, [, v]) => {
          const g = v.gateId ?? 'unknown';
          acc[g] = (acc[g] ?? 0) + 1;
          return acc;
        }, {}),
      ),
    ),
  };
}

/** Remove per-gate failure logs older than `maxAgeMs`. */
export function pruneOutputs(maxAgeMs = 7 * 24 * 60 * 60 * 1000) {
  if (!existsSync(OUTPUTS_DIR)) return 0;
  const now = Date.now();
  let removed = 0;
  for (const name of readdirSync(OUTPUTS_DIR)) {
    const p = join(OUTPUTS_DIR, name);
    try {
      const st = statSync(p);
      if (now - st.mtimeMs > maxAgeMs) {
        rmSync(p);
        removed++;
      }
    } catch {
      // ignore
    }
  }
  return removed;
}
