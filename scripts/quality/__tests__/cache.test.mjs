// SPDX-License-Identifier: AGPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { computeCacheKey, cacheDisabled } from '../cache.mjs';

function makeGate(overrides = {}) {
  return {
    id: 'test-gate',
    cacheable: true,
    scope: 'repo',
    inputs: [],
    ...overrides,
  };
}

test('cache: different gate ids produce different keys', () => {
  const ctx = { mode: 'local', relevantFiles: [] };
  const a = computeCacheKey(makeGate({ id: 'a' }), ctx, 'fp');
  const b = computeCacheKey(makeGate({ id: 'b' }), ctx, 'fp');
  assert.notEqual(a, b);
});

test('cache: runtime fingerprint changes invalidate the key', () => {
  const ctx = { mode: 'local', relevantFiles: [] };
  const a = computeCacheKey(makeGate(), ctx, 'fp1');
  const b = computeCacheKey(makeGate(), ctx, 'fp2');
  assert.notEqual(a, b);
});

test('cache: input file content change invalidates the key', () => {
  const dir = mkdtempSync(join(tmpdir(), 'aegiuw-cache-'));
  try {
    const f = join(dir, 'input.txt');
    writeFileSync(f, 'hello');
    const ctx = { mode: 'local', relevantFiles: [] };
    const k1 = computeCacheKey(makeGate({ inputs: [f] }), ctx, 'fp');
    writeFileSync(f, 'world');
    const k2 = computeCacheKey(makeGate({ inputs: [f] }), ctx, 'fp');
    assert.notEqual(k1, k2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('cache: missing input file is encoded distinctly in the key', () => {
  const ctx = { mode: 'local', relevantFiles: [] };
  const present = computeCacheKey(makeGate({ inputs: ['scripts/quality/runner.mjs'] }), ctx, 'fp');
  const absent = computeCacheKey(makeGate({ inputs: ['scripts/quality/does-not-exist.mjs'] }), ctx, 'fp');
  assert.notEqual(present, absent);
});

test('cache: relevantFiles change invalidates scope=changed keys', () => {
  const gate = makeGate({ scope: 'changed' });
  const k1 = computeCacheKey(gate, { mode: 'prepush', relevantFiles: ['a.rs'] }, 'fp');
  const k2 = computeCacheKey(gate, { mode: 'prepush', relevantFiles: ['b.rs'] }, 'fp');
  assert.notEqual(k1, k2);
});

test('cache: AEPTUS_QUALITY_DISABLE_CACHE=1 disables the cache', () => {
  const before = process.env.AEPTUS_QUALITY_DISABLE_CACHE;
  try {
    process.env.AEPTUS_QUALITY_DISABLE_CACHE = '1';
    assert.equal(cacheDisabled(), true);
    delete process.env.AEPTUS_QUALITY_DISABLE_CACHE;
    assert.equal(cacheDisabled(), false);
  } finally {
    if (before !== undefined) process.env.AEPTUS_QUALITY_DISABLE_CACHE = before;
    else delete process.env.AEPTUS_QUALITY_DISABLE_CACHE;
  }
});

test('cache: backwards-compat AEPTUS_PREPUSH_DISABLE_CACHE=1 also disables', () => {
  const before = process.env.AEPTUS_PREPUSH_DISABLE_CACHE;
  try {
    process.env.AEPTUS_PREPUSH_DISABLE_CACHE = '1';
    assert.equal(cacheDisabled(), true);
  } finally {
    if (before !== undefined) process.env.AEPTUS_PREPUSH_DISABLE_CACHE = before;
    else delete process.env.AEPTUS_PREPUSH_DISABLE_CACHE;
  }
});
