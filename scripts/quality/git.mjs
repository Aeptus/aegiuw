// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Git surface used by the runner: staged files, changed files, diff-base
 * resolution from pre-push stdin or fallbacks, and worktree dirtiness.
 */

import { execSync, execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { filterRelevant } from './filter.mjs';

const ZERO_SHA = '0000000000000000000000000000000000000000';

function gitSync(args, opts = {}) {
  try {
    return execFileSync('git', args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      ...opts,
    }).trim();
  } catch {
    return '';
  }
}

/** ACMR = Added, Copied, Modified, Renamed; excludes deletions. */
export function getStagedFiles() {
  const out = gitSync(['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z']);
  return filterRelevant(out.split('\0').filter(Boolean));
}

export function getChangedFiles(base, head) {
  const out = gitSync(['diff', '--name-only', '--diff-filter=ACMR', '-z', `${base}...${head}`]);
  return filterRelevant(out.split('\0').filter(Boolean));
}

export function getStagedDiff() {
  // Patch of staged changes (used by secrets-scan to look at added lines only)
  return gitSync(['diff', '--cached', '--unified=0', '--no-color']);
}

export function getRangeDiff(base, head) {
  return gitSync(['diff', '--unified=0', '--no-color', `${base}...${head}`]);
}

/**
 * Parse pre-push stdin. Git pipes "local_ref local_sha remote_ref remote_sha"
 * per ref being pushed. Empty array if no stdin is available.
 */
export function readPrePushStdin() {
  try {
    const data = readFileSync(0, 'utf8');
    return data
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        const [localRef, localSha, remoteRef, remoteSha] = line.split(' ');
        return { localRef, localSha, remoteRef, remoteSha };
      });
  } catch {
    return [];
  }
}

/**
 * Resolve a `{ base, head }` pair for the diff. Tries stdin-supplied refs
 * first, then upstream, then origin/main, origin/production, main, production,
 * HEAD^. Returns null if nothing resolves.
 */
export function resolveDiffBase(updates) {
  // Prefer explicit updates from stdin
  for (const upd of updates ?? []) {
    if (!upd?.localSha) continue;
    if (upd.localSha === ZERO_SHA) continue; // branch deletion
    if (upd.remoteSha && upd.remoteSha !== ZERO_SHA) {
      // Updating an existing branch
      return { base: upd.remoteSha, head: upd.localSha, source: 'stdin' };
    }
    // New branch on remote — find merge base with default branches
    for (const def of ['origin/main', 'main', 'origin/production', 'production']) {
      const base = gitSync(['merge-base', upd.localSha, def]);
      if (base) return { base, head: upd.localSha, source: `new-branch-vs-${def}` };
    }
    return { base: 'HEAD^', head: upd.localSha, source: 'new-branch-no-default' };
  }

  // Fallback chain when no stdin available
  const candidates = [
    { ref: gitSync(['rev-parse', '--abbrev-ref', '@{u}']), label: 'upstream' },
    { ref: 'origin/main', label: 'origin/main' },
    { ref: 'origin/production', label: 'origin/production' },
    { ref: 'main', label: 'main' },
    { ref: 'production', label: 'production' },
    { ref: 'HEAD^', label: 'HEAD^' },
  ];
  for (const { ref, label } of candidates) {
    if (!ref) continue;
    const base = gitSync(['rev-parse', ref]);
    if (base) {
      const head = gitSync(['rev-parse', 'HEAD']);
      return { base, head, source: label };
    }
  }
  return null;
}

export function isWorktreeDirty() {
  return gitSync(['status', '--porcelain']).length > 0;
}

/** SHA-tracked content of a file at HEAD; useful for fingerprints. */
export function gitHashObject(path) {
  return gitSync(['hash-object', path]);
}

export function gitListFiles(pathspec) {
  const out = gitSync(['ls-files', '-z', '--', pathspec]);
  return out.split('\0').filter(Boolean);
}
