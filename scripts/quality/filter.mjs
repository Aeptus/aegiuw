// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Single helper for excluding generated/local artifacts from gate scopes.
 *
 * The spec's hard rule: ignore generated output, caches, virtualenvs, dist,
 * coverage, target, node_modules through a single helper — never repeat
 * inline filters in gates.
 */

const EXCLUDE_PREFIXES = [
  'target/',
  'node_modules/',
  '.aeptus-cache/',
  '.chau7/',
  '.claude/',
  '.git/',
  'logs/',
  'dist/',
  'coverage/',
  '.venv/',
  'venv/',
  '__pycache__/',
];

const EXCLUDE_FILES = new Set(['.DS_Store']);

export function isExcluded(path) {
  if (!path) return true;
  if (EXCLUDE_FILES.has(path) || path.endsWith('/.DS_Store')) return true;
  for (const p of EXCLUDE_PREFIXES) {
    if (path.startsWith(p) || path.includes(`/${p}`)) return true;
  }
  return false;
}

export function filterRelevant(files) {
  return (files ?? []).filter((f) => !isExcluded(f));
}
