#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Install our git hooks by pointing `core.hooksPath` at the versioned
 * `hooks/` directory. No Husky needed — modern git supports this natively.
 */

import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync } from 'node:fs';

const HOOKS_DIR = 'hooks';
const HOOKS = ['pre-commit', 'pre-push'];

function gitConfig(args) {
  return execFileSync('git', ['config', ...args], { encoding: 'utf8' }).trim();
}

function ensureExecutable(path) {
  try {
    chmodSync(path, 0o755);
  } catch (err) {
    console.warn(`could not chmod ${path}: ${err.message}`);
  }
}

const current = (() => {
  try {
    return gitConfig(['core.hooksPath']);
  } catch {
    return '';
  }
})();

if (current === HOOKS_DIR) {
  console.log(`core.hooksPath already = ${HOOKS_DIR}`);
} else {
  execFileSync('git', ['config', 'core.hooksPath', HOOKS_DIR], { stdio: 'inherit' });
  console.log(`core.hooksPath set to ${HOOKS_DIR}`);
}

for (const h of HOOKS) {
  const p = `${HOOKS_DIR}/${h}`;
  if (!existsSync(p)) {
    console.warn(`missing hook file: ${p}`);
    continue;
  }
  ensureExecutable(p);
  console.log(`  ✓ ${p} executable`);
}
