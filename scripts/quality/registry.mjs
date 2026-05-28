// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Central source of truth for quality gates.
 *
 * Every gate declares: id, modes, scope, wave, tags, cacheable, inputs,
 * applies(ctx), run(ctx), rerun.
 *
 * The runner executes gates in wave order. The cache module hashes the
 * gate's declared `inputs` (plus a runtime fingerprint) to decide cache hits.
 *
 * Hard rule: scattered checks belong here, not in shell scripts or
 * package.json one-liners.
 */

import { runCmd } from './exec.mjs';
import { scanForSecrets } from './gates/secrets.mjs';
import { checkSpdx } from './gates/spdx.mjs';

const RUST_FILE_RE = /\.rs$/;
const TS_WORKER_RE = /^workers\/aegiuw-router\/src\/.*\.ts$/;

function anyRustChanged(ctx) {
  return ctx.relevantFiles.some((f) => RUST_FILE_RE.test(f));
}
function anyWorkerTsChanged(ctx) {
  return ctx.relevantFiles.some((f) => TS_WORKER_RE.test(f));
}
function workspaceConfigChanged(ctx) {
  return ctx.relevantFiles.some(
    (f) =>
      f === 'Cargo.toml' ||
      f === 'Cargo.lock' ||
      f === 'rust-toolchain.toml' ||
      f.endsWith('/Cargo.toml'),
  );
}
function workerConfigChanged(ctx) {
  return ctx.relevantFiles.some(
    (f) =>
      f === 'workers/aegiuw-router/package.json' ||
      f === 'workers/aegiuw-router/package-lock.json' ||
      f === 'workers/aegiuw-router/tsconfig.json' ||
      f === 'workers/aegiuw-router/wrangler.jsonc',
  );
}

export const GATES = [
  // ── Preflight ─────────────────────────────────────────────────────────────
  {
    id: 'secrets-scan',
    modes: ['staged', 'prepush', 'prepush-full', 'local'],
    scope: 'changed',
    wave: 'preflight',
    tags: ['security'],
    cacheable: false, // security-sensitive: always live
    inputs: [],
    applies: (ctx) => ctx.relevantFiles.length > 0 || ctx.mode === 'prepush-full' || ctx.mode === 'local',
    rerun: 'npm run quality:local -- --include=secrets-scan',
    run: async (ctx) => scanForSecrets(ctx),
  },
  {
    id: 'cargo-lock-consistency',
    modes: ['staged', 'prepush', 'prepush-full', 'local'],
    scope: 'repo',
    wave: 'preflight',
    tags: ['rust', 'deps'],
    cacheable: true,
    inputs: ['Cargo.toml', 'Cargo.lock', 'crates/aegiuw-core/Cargo.toml', 'crates/aegiuw-daemon/Cargo.toml'],
    applies: (ctx) =>
      workspaceConfigChanged(ctx) ||
      ctx.mode === 'prepush' ||
      ctx.mode === 'prepush-full' ||
      ctx.mode === 'local',
    rerun: 'cargo metadata --locked --format-version 1 > /dev/null',
    run: async () =>
      runCmd('cargo', ['metadata', '--locked', '--format-version', '1'], { timeoutMs: 30_000 }),
  },

  // ── Static ────────────────────────────────────────────────────────────────
  {
    id: 'spdx-headers',
    modes: ['staged', 'prepush', 'prepush-full', 'local'],
    scope: 'changed',
    wave: 'static',
    tags: ['license'],
    cacheable: true,
    inputs: [], // computed from relevant files at run time
    applies: (ctx) =>
      ctx.relevantFiles.some((f) => RUST_FILE_RE.test(f) || TS_WORKER_RE.test(f)) ||
      ctx.mode === 'prepush-full' ||
      ctx.mode === 'local',
    rerun: 'npm run quality:local -- --include=spdx-headers',
    run: async (ctx) => checkSpdx(ctx),
  },
  {
    id: 'rust-fmt',
    modes: ['staged', 'prepush', 'prepush-full', 'local'],
    scope: 'repo',
    wave: 'static',
    tags: ['rust', 'format'],
    cacheable: true,
    inputs: ['crates/aegiuw-core/src', 'crates/aegiuw-daemon/src'],
    applies: (ctx) =>
      anyRustChanged(ctx) ||
      workspaceConfigChanged(ctx) ||
      ctx.mode === 'prepush-full' ||
      ctx.mode === 'local',
    rerun: 'cargo fmt --all',
    run: async () => runCmd('cargo', ['fmt', '--all', '--check'], { timeoutMs: 60_000 }),
  },
  {
    id: 'rust-clippy',
    modes: ['staged', 'prepush', 'prepush-full', 'local'],
    scope: 'repo',
    wave: 'static',
    tags: ['rust', 'lint'],
    cacheable: true,
    inputs: [
      'crates/aegiuw-core/src',
      'crates/aegiuw-daemon/src',
      'crates/aegiuw-core/Cargo.toml',
      'crates/aegiuw-daemon/Cargo.toml',
      'Cargo.toml',
      'Cargo.lock',
      'rust-toolchain.toml',
    ],
    applies: (ctx) =>
      anyRustChanged(ctx) ||
      workspaceConfigChanged(ctx) ||
      ctx.mode === 'prepush-full' ||
      ctx.mode === 'local',
    rerun: 'cargo clippy --workspace --all-targets -- -D warnings',
    run: async () =>
      runCmd('cargo', ['clippy', '--workspace', '--all-targets', '--', '-D', 'warnings'], {
        timeoutMs: 300_000,
      }),
  },
  {
    id: 'worker-typecheck',
    modes: ['staged', 'prepush', 'prepush-full', 'local'],
    scope: 'repo',
    wave: 'static',
    tags: ['typescript'],
    cacheable: true,
    inputs: [
      'workers/aegiuw-router/src',
      'workers/aegiuw-router/tsconfig.json',
      'workers/aegiuw-router/package.json',
      'workers/aegiuw-router/package-lock.json',
    ],
    applies: (ctx) =>
      anyWorkerTsChanged(ctx) ||
      workerConfigChanged(ctx) ||
      ctx.mode === 'prepush-full' ||
      ctx.mode === 'local',
    rerun: 'cd workers/aegiuw-router && npm run typecheck',
    run: async () =>
      runCmd('npm', ['run', 'typecheck', '--prefix', 'workers/aegiuw-router'], {
        timeoutMs: 120_000,
      }),
  },

  // ── Tests ─────────────────────────────────────────────────────────────────
  {
    id: 'rust-test',
    modes: ['prepush', 'prepush-full', 'local'], // intentionally NOT staged: too slow for pre-commit
    scope: 'repo',
    wave: 'tests',
    tags: ['rust', 'test'],
    cacheable: true,
    inputs: [
      'crates/aegiuw-core/src',
      'crates/aegiuw-daemon/src',
      'crates/aegiuw-core/Cargo.toml',
      'crates/aegiuw-daemon/Cargo.toml',
      'Cargo.toml',
      'Cargo.lock',
    ],
    applies: (ctx) =>
      anyRustChanged(ctx) ||
      workspaceConfigChanged(ctx) ||
      ctx.mode === 'prepush-full' ||
      ctx.mode === 'local',
    rerun: 'cargo test --workspace',
    run: async () => runCmd('cargo', ['test', '--workspace', '--quiet'], { timeoutMs: 600_000 }),
  },
];

export const WAVES = ['preflight', 'static', 'build', 'postbuild', 'tests', 'audit'];

const VALID_SCOPES = new Set(['staged', 'changed', 'repo']);
const VALID_MODES = new Set(['staged', 'prepush', 'prepush-full', 'local', 'cloud-parity']);

/**
 * Validate the registry shape — must run at startup so we catch typos in
 * gate declarations rather than at the moment one fails to fire.
 */
export function validateRegistry() {
  const ids = new Set();
  const errors = [];
  for (const g of GATES) {
    if (!g.id) errors.push('gate missing id');
    if (ids.has(g.id)) errors.push(`duplicate gate id: ${g.id}`);
    ids.add(g.id);
    if (!Array.isArray(g.modes) || g.modes.length === 0) errors.push(`${g.id}: missing modes`);
    for (const m of g.modes ?? []) {
      if (!VALID_MODES.has(m)) errors.push(`${g.id}: invalid mode ${m}`);
    }
    if (!WAVES.includes(g.wave)) errors.push(`${g.id}: invalid wave ${g.wave}`);
    if (!VALID_SCOPES.has(g.scope)) errors.push(`${g.id}: invalid scope ${g.scope}`);
    if (typeof g.applies !== 'function') errors.push(`${g.id}: missing applies()`);
    if (typeof g.run !== 'function') errors.push(`${g.id}: missing run()`);
    if (!g.rerun) errors.push(`${g.id}: missing rerun command`);
    if (g.cacheable && !Array.isArray(g.inputs))
      errors.push(`${g.id}: cacheable but no inputs array`);
  }
  return errors;
}
