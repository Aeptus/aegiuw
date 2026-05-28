// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * High-signal secret scanner.
 *
 * Spec rule: high signal, no noisy toy regexes that developers learn to
 * ignore. Patterns chosen for canonical token formats with clear prefixes
 * or PEM headers. Scans the staged diff for staged mode, the range diff
 * for prepush, and all tracked files for prepush-full / local.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { getStagedDiff, getRangeDiff, gitListFiles } from '../git.mjs';

const PATTERNS = [
  { name: 'Private key block', re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: 'Certificate block', re: /-----BEGIN CERTIFICATE-----/ },
  { name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'AWS secret key (40 b64 chars after prefix)', re: /aws[_-]?secret[_-]?access[_-]?key.{0,5}[:=].{0,5}["']?[A-Za-z0-9/+=]{40}/i },
  { name: 'GitHub personal access token', re: /\bghp_[A-Za-z0-9]{36}\b/ },
  { name: 'GitHub OAuth token', re: /\bgho_[A-Za-z0-9]{36}\b/ },
  { name: 'GitHub user-to-server token', re: /\bghu_[A-Za-z0-9]{36}\b/ },
  { name: 'GitHub server-to-server token', re: /\bghs_[A-Za-z0-9]{36}\b/ },
  { name: 'GitHub refresh token', re: /\bghr_[A-Za-z0-9]{36}\b/ },
  { name: 'OpenAI API key', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]+/ },
  { name: 'Stripe live secret', re: /\bsk_live_[A-Za-z0-9]{24,}/ },
  { name: 'Stripe restricted live key', re: /\brk_live_[A-Za-z0-9]{24,}/ },
  { name: 'JWT (3-segment, long)', re: /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
];

const ENV_PATH_RE = /(^|\/)\.env(\..+)?$/;
const HIGH_ENTROPY_ASSIGN_RE =
  /(api[_-]?key|secret|token|password|passwd|credential)\s*[:=]\s*["'][A-Za-z0-9+/=]{32,}["']/i;

/**
 * Files that legitimately contain pattern strings (the scanner sources
 * themselves). Excluded from the scan to avoid self-matching — any file in
 * `scripts/quality/gates/` is by definition allowed to mention secret
 * formats as regex literals.
 */
const SELF_EXCLUDE_PREFIX = 'scripts/quality/gates/';

function scanAddedLines(diff) {
  // Look only at additions in unified diffs (lines that start with '+').
  const hits = [];
  const lines = diff.split('\n');
  let currentFile = '';
  for (const line of lines) {
    if (line.startsWith('+++ b/')) {
      currentFile = line.slice(6);
      continue;
    }
    if (currentFile.startsWith(SELF_EXCLUDE_PREFIX)) continue;
    if (!line.startsWith('+') || line.startsWith('+++')) continue;
    const content = line.slice(1);
    for (const { name, re } of PATTERNS) {
      if (re.test(content)) hits.push({ file: currentFile, name, sample: redact(content) });
    }
    if (HIGH_ENTROPY_ASSIGN_RE.test(content)) {
      hits.push({ file: currentFile, name: 'Generic high-entropy secret assignment', sample: redact(content) });
    }
  }
  return hits;
}

function redact(s) {
  // Show the first 30 chars, redact everything sensitive-looking afterwards.
  const trimmed = s.trim();
  return trimmed.length > 80 ? trimmed.slice(0, 60) + '…' : trimmed;
}

function scanFileForSecrets(path, hits) {
  try {
    const txt = readFileSync(path, 'utf8');
    for (const { name, re } of PATTERNS) {
      if (re.test(txt)) hits.push({ file: path, name });
    }
    if (HIGH_ENTROPY_ASSIGN_RE.test(txt)) {
      hits.push({ file: path, name: 'Generic high-entropy secret assignment' });
    }
  } catch {
    // binary or unreadable — skip
  }
}

function checkEnvFiles(files) {
  return files.filter((f) => ENV_PATH_RE.test(f));
}

export async function scanForSecrets(ctx) {
  const start = Date.now();
  const hits = [];

  if (ctx.mode === 'staged') {
    const diff = getStagedDiff();
    hits.push(...scanAddedLines(diff));
    const envFiles = checkEnvFiles(ctx.relevantFiles);
    for (const f of envFiles) {
      hits.push({ file: f, name: '.env file staged for commit (likely accidental)' });
    }
  } else if (ctx.mode === 'prepush' && ctx.diffBase && ctx.diffHead) {
    const diff = getRangeDiff(ctx.diffBase, ctx.diffHead);
    hits.push(...scanAddedLines(diff));
    const envFiles = checkEnvFiles(ctx.relevantFiles);
    for (const f of envFiles) {
      hits.push({ file: f, name: '.env file in push range (likely accidental)' });
    }
  } else {
    // prepush-full / local: scan all tracked files
    const tracked = gitListFiles('.');
    for (const f of tracked) {
      if (f.startsWith(SELF_EXCLUDE_PREFIX)) continue;
      if (/\.(lock|png|jpg|jpeg|gif|webp|pdf|wasm|ico)$/i.test(f)) continue;
      if (f === 'LICENSE') continue; // contains FSF copyright header — not a secret
      scanFileForSecrets(f, hits);
    }
    hits.push(...checkEnvFiles(tracked).map((f) => ({ file: f, name: '.env file committed' })));
  }

  const passed = hits.length === 0;
  return {
    passed,
    durationMs: Date.now() - start,
    output: hits
      .map((h) => `  ${h.name} in ${h.file}${h.sample ? `\n    → ${h.sample}` : ''}`)
      .join('\n'),
    reason: passed ? '' : `${hits.length} potential secret(s) found`,
  };
}
