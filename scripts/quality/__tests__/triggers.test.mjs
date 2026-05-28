// SPDX-License-Identifier: AGPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shouldRunFullSuite } from '../triggers.mjs';

test('triggers: --full flag forces full', () => {
  const r = shouldRunFullSuite({ mode: 'prepush', forceFull: true, changedFiles: ['README.md'] });
  assert.equal(r.full, true);
  assert.match(r.reason, /--full/);
});

test('triggers: empty changed-file list forces full (cannot scope safely)', () => {
  const r = shouldRunFullSuite({ mode: 'prepush', forceFull: false, changedFiles: [] });
  assert.equal(r.full, true);
  assert.match(r.reason, /no changed files/);
});

test('triggers: docs-only change does NOT force full', () => {
  const r = shouldRunFullSuite({
    mode: 'prepush',
    forceFull: false,
    changedFiles: ['README.md', 'docs/PRD.md'],
  });
  assert.equal(r.full, false);
});

test('triggers: hook changes force full', () => {
  const r = shouldRunFullSuite({
    mode: 'prepush',
    forceFull: false,
    changedFiles: ['hooks/pre-push'],
  });
  assert.equal(r.full, true);
  assert.match(r.reason, /hooks\/pre-push/);
});

test('triggers: runner changes force full', () => {
  const r = shouldRunFullSuite({
    mode: 'prepush',
    forceFull: false,
    changedFiles: ['scripts/quality/runner.mjs'],
  });
  assert.equal(r.full, true);
});

test('triggers: Cargo.lock changes force full', () => {
  const r = shouldRunFullSuite({
    mode: 'prepush',
    forceFull: false,
    changedFiles: ['Cargo.lock'],
  });
  assert.equal(r.full, true);
});

test('triggers: worker tsconfig changes force full', () => {
  const r = shouldRunFullSuite({
    mode: 'prepush',
    forceFull: false,
    changedFiles: ['workers/aegiuw-router/tsconfig.json'],
  });
  assert.equal(r.full, true);
});

test('triggers: per-crate Cargo.toml changes force full', () => {
  const r = shouldRunFullSuite({
    mode: 'prepush',
    forceFull: false,
    changedFiles: ['crates/aegiuw-core/Cargo.toml'],
  });
  assert.equal(r.full, true);
});

test('triggers: explicit prepush-full mode forces full', () => {
  const r = shouldRunFullSuite({
    mode: 'prepush-full',
    forceFull: false,
    changedFiles: ['README.md'],
  });
  assert.equal(r.full, true);
});
