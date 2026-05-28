// SPDX-License-Identifier: AGPL-3.0-or-later

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GATES, WAVES, validateRegistry } from '../registry.mjs';

test('registry: schema validates clean', () => {
  const errors = validateRegistry();
  assert.deepEqual(errors, [], `registry errors: ${errors.join('; ')}`);
});

test('registry: every gate has a stable id, modes, scope, wave, rerun', () => {
  for (const g of GATES) {
    assert.ok(g.id, 'id required');
    assert.ok(Array.isArray(g.modes) && g.modes.length > 0, `${g.id}: modes`);
    assert.ok(['staged', 'changed', 'repo'].includes(g.scope), `${g.id}: scope`);
    assert.ok(WAVES.includes(g.wave), `${g.id}: wave`);
    assert.ok(g.rerun, `${g.id}: rerun`);
    assert.equal(typeof g.applies, 'function', `${g.id}: applies()`);
    assert.equal(typeof g.run, 'function', `${g.id}: run()`);
  }
});

test('registry: cacheable gates declare inputs', () => {
  for (const g of GATES) {
    if (g.cacheable) {
      assert.ok(
        Array.isArray(g.inputs),
        `${g.id} is cacheable but has no inputs array — it would be cached against nothing`,
      );
    }
  }
});

test('registry: every gate id is unique', () => {
  const ids = GATES.map((g) => g.id);
  assert.equal(new Set(ids).size, ids.length, `duplicate ids in: ${ids.join(', ')}`);
});

test('registry: rust-test does not run in staged mode (too slow)', () => {
  const g = GATES.find((g) => g.id === 'rust-test');
  assert.ok(g);
  assert.equal(g.modes.includes('staged'), false, 'rust-test must not be in staged mode');
});

test('registry: secrets-scan is never cacheable (security-sensitive)', () => {
  const g = GATES.find((g) => g.id === 'secrets-scan');
  assert.ok(g);
  assert.equal(g.cacheable, false);
});
