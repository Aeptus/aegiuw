// SPDX-License-Identifier: AGPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isExcluded, filterRelevant } from '../filter.mjs';

test('filter: excludes target/', () => {
  assert.equal(isExcluded('target/debug/foo'), true);
});

test('filter: excludes node_modules/', () => {
  assert.equal(isExcluded('workers/aegiuw-router/node_modules/x.js'), true);
});

test('filter: excludes .aeptus-cache/', () => {
  assert.equal(isExcluded('.aeptus-cache/quality/index.json'), true);
});

test('filter: excludes .DS_Store anywhere', () => {
  assert.equal(isExcluded('.DS_Store'), true);
  assert.equal(isExcluded('workers/.DS_Store'), true);
});

test('filter: includes legitimate source files', () => {
  assert.equal(isExcluded('crates/aegiuw-core/src/sni.rs'), false);
  assert.equal(isExcluded('workers/aegiuw-router/src/index.ts'), false);
  assert.equal(isExcluded('README.md'), false);
});

test('filter: filterRelevant strips excluded entries', () => {
  const out = filterRelevant([
    'crates/aegiuw-core/src/sni.rs',
    'target/debug/foo',
    'node_modules/x',
    'README.md',
    '.DS_Store',
  ]);
  assert.deepEqual(out, ['crates/aegiuw-core/src/sni.rs', 'README.md']);
});
