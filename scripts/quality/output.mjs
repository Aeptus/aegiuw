// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Output formatting + per-gate failure logs.
 *
 * Spec rules:
 *  - every failed gate prints id, short reason, rerun, log path, cache state;
 *  - no buried failures, no swallowed stderr;
 *  - terminal stays readable: detailed log goes to disk, summary to stdout.
 */

import { mkdirSync, writeFileSync, appendFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { OUTPUTS_DIR } from './cache.mjs';

const C = {
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
};

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
function c(code, s) {
  return useColor ? `${code}${s}${C.reset}` : s;
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

/** Write per-gate failure detail to disk, return the file path. */
export function writeFailureLog(gateId, body) {
  mkdirSync(OUTPUTS_DIR, { recursive: true });
  const path = join(OUTPUTS_DIR, `${gateId}-${timestamp()}.log`);
  writeFileSync(path, body ?? '');
  return path;
}

export function printGateLine(result) {
  const { gate, status, durationMs, cached, attested } = result;
  const mark =
    status === 'pass'
      ? c(C.green, '✓')
      : status === 'skip'
        ? c(C.dim, '·')
        : c(C.red, '✗');
  const tag = cached
    ? c(C.dim, ' (cached)')
    : attested
      ? c(C.dim, ' (attested)')
      : durationMs != null
        ? c(C.dim, ` ${(durationMs / 1000).toFixed(2)}s`)
        : '';
  console.log(`  ${mark} ${gate.id}${tag}`);
}

export function printWaveHeader(wave, gateCount) {
  if (gateCount === 0) return;
  console.log(c(C.bold, `\n[${wave}]`));
}

export function printSummary(results, mode, totalMs) {
  const passed = results.filter((r) => r.status === 'pass').length;
  const skipped = results.filter((r) => r.status === 'skip').length;
  const failed = results.filter((r) => r.status === 'fail').length;
  const cached = results.filter((r) => r.cached).length;
  const attested = results.filter((r) => r.attested).length;

  console.log('');
  if (failed === 0) {
    console.log(
      c(
        C.green,
        `✓ ${passed} passed (${cached} cached, ${attested} attested, ${skipped} skipped) in ${(totalMs / 1000).toFixed(2)}s [mode=${mode}]`,
      ),
    );
  } else {
    console.log(
      c(C.red, `✗ ${failed} failed, ${passed} passed, ${skipped} skipped [mode=${mode}]`),
    );
    for (const r of results.filter((r) => r.status === 'fail')) {
      console.log('');
      console.log(c(C.red + C.bold, `  ✗ ${r.gate.id} failed`));
      console.log(c(C.dim, `      Scope:`) + ` ${describeScope(r.gate, r.scopeNote)}`);
      console.log(c(C.dim, `      Rerun:`) + ` ${r.gate.rerun}`);
      if (r.logPath) console.log(c(C.dim, `      Log:`) + `   ${r.logPath}`);
      if (r.reason) console.log(c(C.dim, `      Reason:`) + ` ${r.reason}`);
    }
  }
}

function describeScope(gate, note) {
  if (gate.scope === 'staged') return note || 'staged files';
  if (gate.scope === 'changed') return note || 'changed surface';
  return note || 'repo-wide';
}

export function jsonSummary(results, mode, totalMs) {
  return JSON.stringify(
    {
      mode,
      totalMs,
      results: results.map((r) => ({
        id: r.gate.id,
        status: r.status,
        cached: r.cached ?? false,
        attested: r.attested ?? false,
        durationMs: r.durationMs ?? null,
        reason: r.reason ?? null,
        logPath: r.logPath ?? null,
        rerun: r.gate.rerun,
      })),
    },
    null,
    2,
  );
}

/** Append a line to a run log if logging is enabled. */
export function teeLog(logPath, line) {
  if (!logPath) return;
  try {
    if (!existsSync(logPath)) {
      mkdirSync(join(logPath, '..'), { recursive: true });
    }
  } catch {
    // ignore
  }
  try {
    appendFileSync(logPath, line + '\n');
  } catch {
    // ignore
  }
}
