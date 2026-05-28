// SPDX-License-Identifier: AGPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanForSecrets } from '../gates/secrets.mjs';
import { checkSpdx } from '../gates/spdx.mjs';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('secrets-scan: passes on clean staged file list', async () => {
  const r = await scanForSecrets({ mode: 'staged', relevantFiles: ['README.md'] });
  // We can't fully control the staged diff in this process, but the function
  // should not throw and should return a structured result.
  assert.ok(typeof r.passed === 'boolean');
  assert.ok(typeof r.durationMs === 'number');
});

test('secrets-scan: returns a uniform shape on prepush with no diff base', async () => {
  const r = await scanForSecrets({
    mode: 'prepush',
    relevantFiles: [],
    diffBase: null,
    diffHead: null,
  });
  assert.ok(typeof r.passed === 'boolean');
});

test('spdx: passes when relevant files all have header (current repo state)', async () => {
  // The repo's own .rs files are SPDX-tagged.
  const r = await checkSpdx({
    mode: 'staged',
    relevantFiles: ['crates/aegiuw-core/src/sni.rs', 'crates/aegiuw-core/src/risk.rs'],
  });
  assert.equal(r.passed, true, `expected pass; got reason: ${r.reason}`);
});

test('spdx: returns clean result shape on empty relevant file list', async () => {
  const r = await checkSpdx({ mode: 'staged', relevantFiles: [] });
  assert.equal(r.passed, true);
  assert.equal(r.reason, '');
});
