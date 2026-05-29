# Fuzzing `aegiuw-core`

[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) harnesses for the SNI
parser's three public entry points. The harnesses exist to prove the contract
documented in [`crates/aegiuw-core/src/sni.rs`](../src/sni.rs):

- **Panic-free** on every input.
- **No OOB reads** (AddressSanitizer, on by default in cargo-fuzz builds).
- **Bounded time** (per-run timeout flag).
- **Bounded allocation** (`MAX_HANDSHAKE_BYTES = 64 KiB` cap inside
  `reassemble_handshake`).

This is **SNI backlog S1**.

## Prerequisites

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

Both are one-time. The main workspace builds on stable; only this crate
needs nightly, and it's `[workspace] exclude`-d from the top-level
`Cargo.toml` so `cargo build`/`cargo test` at the root don't touch it.

## Targets

| Target | What it fuzzes | Why a dedicated target |
|---|---|---|
| `extract_sni` | the whole pipeline (record → handshake → SNI) | transitive coverage; matches the public API entry |
| `reassemble_handshake` | the allocation hot-path | best signal on the `MAX_HANDSHAKE_BYTES` cap |
| `parse_handshake_message` | the post-reassembly walker | QUIC parser will reuse this entry directly |
| `differential_rustls` | host extraction vs. rustls's `Acceptor::accept` | finds cases where two independent parsers disagree on the SNI host (SNI backlog S8) |

The differential target tolerates *policy* differences (rustls rejects many
ClientHellos for non-SNI reasons — cipher list, supported_versions, TLS-1.3
specifics) and only panics when **both** parsers extract a host string **and
they disagree** on its value. That's the high-signal class. Run it with:

```bash
cargo +nightly fuzz run differential_rustls -- -timeout=1 -max_total_time=600
```

## Quick run

From the repo root:

```bash
cd crates/aegiuw-core/fuzz

# Smoke run (10 seconds, useful as a sanity check)
cargo +nightly fuzz run extract_sni -- -max_total_time=10 -timeout=1

# Sustained run (until you Ctrl+C; artifacts written on crash)
cargo +nightly fuzz run extract_sni -- -timeout=1
```

A crash produces a reproducer at `artifacts/extract_sni/crash-<hex>` and
prints the failing input. Re-run a single artifact:

```bash
cargo +nightly fuzz run extract_sni artifacts/extract_sni/crash-<hex>
```

## What to do on a crash

1. **Don't `--no-verify` past it.** A crash here means the parser broke its
   contract — that's exactly what this harness is for.
2. Minimize the input:
   ```bash
   cargo +nightly fuzz tmin extract_sni artifacts/extract_sni/crash-<hex>
   ```
3. Open the minimized blob as a regression test under
   `crates/aegiuw-core/src/sni.rs` (the test module's `#[test]` block).
4. Fix the parser so the test passes, re-run the fuzzer to confirm no new
   crashes follow from the same fix shape.

## Seed corpus (optional, recommended for serious runs)

cargo-fuzz works much faster when given a corpus of known-valid inputs to
mutate. Place ClientHello blobs (one per file) at:

```text
corpus/extract_sni/
corpus/reassemble_handshake/
corpus/parse_handshake_message/
```

A future improvement (not yet implemented) is a small `cargo run`-driven
generator that emits the runtime-built fixtures from the unit test suite
into these directories. For now the fuzzer starts from `/dev/urandom`-like
seeds and discovers structure through coverage feedback.

## Not in the default quality gates

The `cargo fuzz run …` invocations are intentionally *not* registered in
`scripts/quality/registry.mjs` because:

1. They require nightly Rust and `cargo-fuzz` — soft dependencies that
   contributors shouldn't be forced to install for `quality:staged` /
   `quality:prepush` to pass.
2. Fuzzing is open-ended: there's no natural "done" signal that fits a
   wave-ordered runner.

The right rhythm is **periodic manual runs** (e.g. before a release, or
when refactoring the SNI parser) rather than a hot-loop CI gate.
