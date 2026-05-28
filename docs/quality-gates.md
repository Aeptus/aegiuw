# Quality gates

aegiuw's quality firewall lives entirely in `scripts/quality/`. The same registry
is used by git hooks and direct local invocation; there is no separate CI
pipeline by deliberate choice (DECISIONS.N81 — Aeptus org policy disables GitHub
Actions, and our scale doesn't justify a parallel automation surface).

## Architecture

```
hooks/pre-commit  →  node scripts/quality/runner.mjs --mode=staged
hooks/pre-push    →  node scripts/quality/runner.mjs --mode=prepush
                              │
                              ├── git.mjs       (staged/changed file detection,
                              │                  pre-push stdin parsing, dirty
                              │                  worktree, diff-base fallback)
                              ├── triggers.mjs  (rules that escalate prepush →
                              │                  prepush-full)
                              ├── registry.mjs  (the gates — source of truth)
                              ├── cache.mjs     (content-hash cache)
                              ├── exec.mjs      (subprocess runner)
                              ├── filter.mjs    (single exclusion helper)
                              ├── output.mjs    (formatted summary + per-gate
                              │                  failure logs)
                              └── gates/
                                  ├── secrets.mjs
                                  └── spdx.mjs
```

Hooks are thin shell shims (~5 lines each). Policy and impl live in JS.

## Installing

After cloning the repo:

```bash
npm run hooks:install
```

This sets `git config core.hooksPath hooks` so hooks are versioned with the
codebase. No Husky, no extra dependencies.

## Commands

| Command | Purpose |
|---|---|
| `npm run quality:staged` | Run staged-mode gates (mirrors pre-commit). |
| `npm run quality:prepush` | Run prepush gates against `origin/main…HEAD`. |
| `npm run quality:prepush:full` | Force the full repo-wide suite. |
| `npm run quality:local` | Run every gate that supports local mode. |
| `npm run quality:cache:status` | Print cache index summary. |
| `npm run quality:cache:clear` | Empty the cache index (keeps logs). |
| `npm run test:quality` | Run the runner/registry unit tests. |

Runtime filters (debugging only — they do not weaken the default workflow):

```bash
node scripts/quality/runner.mjs --mode=prepush --include=rust-clippy
node scripts/quality/runner.mjs --mode=local --skip=rust-test
node scripts/quality/runner.mjs --mode=local --tags=rust
node scripts/quality/runner.mjs --mode=local --skip-tags=test
node scripts/quality/runner.mjs --mode=local --wave=static
node scripts/quality/runner.mjs --mode=prepush --json
node scripts/quality/runner.mjs --mode=prepush --debug-cache
node scripts/quality/runner.mjs --mode=prepush --concurrency=2
```

## Gates

Each gate is declared in `scripts/quality/registry.mjs`. The contract:

```js
{
  id: string,
  modes: Array<'staged' | 'prepush' | 'prepush-full' | 'local' | 'cloud-parity'>,
  scope: 'staged' | 'changed' | 'repo',
  wave: 'preflight' | 'static' | 'build' | 'postbuild' | 'tests' | 'audit',
  tags: string[],
  cacheable: boolean,
  inputs: string[],          // required when cacheable
  applies: (ctx) => boolean,
  run: (ctx) => Promise<{ passed, durationMs, output, reason }>,
  rerun: string,             // shown verbatim on failure
}
```

Current gates:

| id | modes | scope | wave | cacheable | rerun |
|---|---|---|---|---|---|
| `secrets-scan` | staged, prepush, prepush-full, local | changed | preflight | **no** (security-sensitive) | `npm run quality:local -- --include=secrets-scan` |
| `cargo-lock-consistency` | staged, prepush, prepush-full, local | repo | preflight | yes | `cargo metadata --locked --format-version 1 > /dev/null` |
| `spdx-headers` | staged, prepush, prepush-full, local | changed | static | yes | `npm run quality:local -- --include=spdx-headers` |
| `rust-fmt` | staged, prepush, prepush-full, local | repo | static | yes | `cargo fmt --all` |
| `rust-clippy` | staged, prepush, prepush-full, local | repo | static | yes | `cargo clippy --workspace --all-targets -- -D warnings` |
| `worker-typecheck` | staged, prepush, prepush-full, local | repo | static | yes | `cd workers/aegiuw-router && npm run typecheck` |
| `rust-test` | prepush, prepush-full, local *(not staged — too slow)* | repo | tests | yes | `cargo test --workspace` |

## Full-suite triggers

`prepush` automatically escalates to `prepush-full` when any of these are true:

- `--full` is passed.
- No changed files can be resolved from the push range.
- The change touches `hooks/`, `scripts/quality/`, `Cargo.toml`, `Cargo.lock`,
  `rust-toolchain.toml`, any per-crate `Cargo.toml`, the worker's `package.json`
  / `package-lock.json` / `tsconfig.json` / `wrangler.jsonc`, the root
  `package.json` / `package-lock.json`, or `.gitignore`.

The philosophy: if the change alters the graph, the validator, or shared
contracts, a scoped run cannot be trusted.

## Caching

Content-hash cache under `.aeptus-cache/quality/`. Cache keys include:

1. Schema version
2. Gate id
3. Runtime fingerprint (node/cargo/rustc/npm versions + relevant env vars +
   self-hash of every quality-system source file — any change to the runner
   invalidates every entry)
4. Declared input file contents (recursed via `git ls-files` and a manual walk
   for untracked files inside declared input dirs)
5. For `scope=changed` gates, the sorted list of relevant files

Hard rules:

- **Only successful gates are cached.**
- **`secrets-scan` is never cached** (security-sensitive — always live).
- **Cache invalidates the moment any input content, runner code, registry
  code, or runtime version changes.**

Disabling the cache:

```bash
AEPTUS_QUALITY_DISABLE_CACHE=1 npm run quality:prepush
# backwards-compat alias also accepted:
AEPTUS_PREPUSH_DISABLE_CACHE=1 npm run quality:prepush
```

Inspect: `npm run quality:cache:status` — clear: `npm run quality:cache:clear`.

## Output format

Success (concise):

```
aegiuw quality — mode=prepush  ·  diff=upstream  ·  cache=on  ·  relevant=3

[preflight]
  ✓ secrets-scan 0.04s
  ✓ cargo-lock-consistency (cached)

[static]
  ✓ spdx-headers 0.03s
  ✓ rust-fmt (cached)
  ✓ rust-clippy (cached)
  ✓ worker-typecheck (cached)

[tests]
  ✓ rust-test 1.83s

✓ 7 passed (4 cached, 0 attested, 0 skipped) in 2.40s [mode=prepush]
```

Failure (always actionable):

```
[static]
  ✓ spdx-headers 0.03s
  ✗ rust-clippy 1.21s

✗ 1 failed, 1 passed, 5 skipped [mode=prepush]

  ✗ rust-clippy failed
      Scope: upstream (3 files)
      Rerun: cargo clippy --workspace --all-targets -- -D warnings
      Log:   .aeptus-cache/quality/outputs/rust-clippy-2026-05-28T….log
      Reason: cargo clippy --workspace --all-targets -- -D warnings exited 101
```

The full clippy stderr is in the log file; the terminal stays readable.

## Adding a new gate

1. If the gate is more than ~30 lines, drop a `gates/<name>.mjs` exporting an
   `async (ctx) => { passed, durationMs, output, reason }` function.
2. Add a new entry to the `GATES` array in `registry.mjs`. Fill in every field
   in the contract (the schema validator runs at startup and refuses missing
   keys).
3. If the gate is `cacheable`, declare the `inputs` array — every meaningful
   input must be listed, including config files.
4. If the gate is `scope: 'changed'`, write its `applies()` to short-circuit
   when no relevant files changed.
5. Add a test under `__tests__/`. Run `npm run test:quality`.
6. Run `npm run quality:local` to verify it integrates cleanly.

## Reproducing a failure

Every failed gate prints a one-line `Rerun:` command. Copy and paste it. The
runner deliberately keeps gate commands as-is so the rerun matches what CI
*would* run (if we had CI).

If the failure depends on staged or pushed state, you can also re-run the
exact gate inside the runner:

```bash
node scripts/quality/runner.mjs --mode=prepush --include=<gate-id>
```

## Dirty worktree behaviour

On `pre-push`, if the worktree has uncommitted changes:

- **Interactive (TTY)**: warning printed, runner proceeds (you can Ctrl+C).
- **Non-interactive** (e.g. CI hook, scripted push): runner aborts unless
  `AEPTUS_SKIP_DIRTY_WORKTREE_CONFIRM=1` is set.

## When `--no-verify` is acceptable

The escape hatch is `git commit --no-verify` / `git push --no-verify`. The
hooks cannot prevent it (Git's choice). The acceptable uses are:

- Emergency hotfix with explicit Slack/PR-comment justification.
- The hook itself is broken and you're fixing it.

Anything else is a smell. If you reach for `--no-verify` regularly, fix the
underlying gate — file an issue against the registry first.

## Anti-goals

The system intentionally does not:

- Use Husky / lint-staged / pre-commit (the Python tool). Native git hooks
  cover this perfectly.
- Add a polyglot registry for Python / Pages / OpenAPI / design-system
  contracts. None of those exist in this repo today; we'll add gates if the
  repo grows.
- Mirror its definitions into a CI workflow. There is no CI by org policy.
- Cache `secrets-scan` or any audit-style live-state check.

If any of those constraints change, the registry is the place to express it —
not a shell script.
