// SPDX-License-Identifier: AGPL-3.0-or-later

//! S8: Differential fuzz target — `aegiuw_core::extract_sni` vs. rustls.
//!
//! We treat rustls as an independent reference parser and look for
//! *host-extraction* disagreements. We deliberately tolerate *policy*
//! disagreements: rustls rejects many ClientHellos for reasons unrelated
//! to SNI extraction (cipher suite list, supported_versions extension,
//! TLS-1.3 specific fields…), so "rustls rejects, we accept" or vice
//! versa is normal and not a bug.
//!
//! Failure conditions (we panic, libFuzzer captures the reproducer):
//!
//! - **Both parsers extract a host AND the host strings differ.**
//!   Case-insensitive compare per RFC 4343 — we return wire-case, rustls
//!   may normalize. This is the high-signal class.
//!
//! Tolerated discrepancies (no panic):
//!
//! - We return `Cleartext { host: X }`, rustls rejects entire CH. Policy
//!   difference (rustls is stricter on ciphers/versions than our SNI-only
//!   parser).
//! - We return `Malformed`, rustls extracts `host = Y`. Possible bug in
//!   ours, but high false-positive rate from inputs where the SNI bytes
//!   are valid but the surrounding ClientHello is malformed in ways rustls
//!   happens to tolerate. Logged as a curiosity, not asserted.
//! - We return `Encrypted` (ECH detected), rustls extracts an outer host.
//!   By design — ECH outer SNI is a decoy per DECISIONS.C14.
//! - Either side returns `NotFound`. Agreement.
//!
//! Running:
//!
//! ```sh
//! cargo +nightly fuzz run differential_rustls -- -timeout=1 -max_total_time=600
//! ```
//!
//! Any panic writes a reproducer to `artifacts/differential_rustls/`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustls::server::Acceptor;

fn rustls_host(data: &[u8]) -> Option<String> {
    let mut acceptor = Acceptor::default();
    // Acceptor::read_tls consumes from a `Read` impl. `&[u8]` is `Read`,
    // so a small inner `&mut` gives us the right shape. Bounded reads —
    // rustls itself caps how much it'll buffer.
    let mut cursor = data;
    // Drive read_tls until accept() yields a decision or we run dry.
    while acceptor.read_tls(&mut cursor).ok()? > 0 {
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                // accepted.client_hello() returns a ClientHello<'_> with a
                // server_name() accessor — exactly what we want for the
                // differential.
                return accepted
                    .client_hello()
                    .server_name()
                    .map(|s| s.to_ascii_lowercase());
            }
            Ok(None) => continue, // need more bytes
            Err(_) => return None,
        }
    }
    None
}

fuzz_target!(|data: &[u8]| {
    use aegiuw_core::SniOutcome;

    let ours = aegiuw_core::extract_sni(data);
    let our_host = match &ours {
        SniOutcome::Cleartext { host } => Some(host.to_ascii_lowercase()),
        // ECH: outer SNI is by-design a decoy; don't compare to rustls.
        SniOutcome::Encrypted => return,
        _ => None,
    };
    let their_host = rustls_host(data);

    match (our_host, their_host) {
        (Some(ours), Some(theirs)) => {
            // The high-signal case: both extracted a host. Disagreement is
            // a bug in one of the two parsers.
            assert_eq!(
                ours, theirs,
                "SNI host disagreement: aegiuw={ours:?} rustls={theirs:?}",
            );
        }
        _ => {
            // Tolerate policy mismatches. See module docs for the matrix.
        }
    }
});
