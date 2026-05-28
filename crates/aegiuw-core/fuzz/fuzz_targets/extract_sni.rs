// SPDX-License-Identifier: AGPL-3.0-or-later

//! Primary fuzz target: `aegiuw_core::extract_sni`.
//!
//! Feed arbitrary bytes and assert the parser:
//!
//! - **never panics** — libFuzzer aborts and writes the reproducer to
//!   `artifacts/extract_sni/` on any panic;
//! - **never reads out of bounds** — AddressSanitizer (default for
//!   `cargo fuzz`-built binaries) catches OOB reads/writes;
//! - **completes in bounded time** — invoke with `-timeout=1` to kill any
//!   run > 1 s, which catches infinite loops and quadratic blowups;
//! - **never allocates more than `aegiuw_core::MAX_HANDSHAKE_BYTES`** —
//!   the reassembly cap guarantees this; an allocator-instrumented build
//!   would surface OOM attempts as crashes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aegiuw_core::extract_sni(data);
});
