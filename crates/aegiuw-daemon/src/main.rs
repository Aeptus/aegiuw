// SPDX-License-Identifier: AGPL-3.0-or-later

//! `aegiuw-daemon` — the privileged local agent.
//!
//! Scaffold status: the privileged networking layer (TUN interface, routing-table
//! configuration, SNI peeking, and the actual fork to NIC-vs-edge) is **not yet
//! implemented** — see the `TODO(FR-1)` markers below. What *is* wired up is the
//! pure decision pipeline from [`aegiuw_core`], so running this binary shows how a
//! domain flows from heuristics to a fork decision.

use aegiuw_core::heuristics::{context, levenshtein};
use aegiuw_core::risk::{RiskSignal, Verdict};

/// Inputs the daemon will eventually gather from the live connection.
struct Connection<'a> {
    /// SNI host extracted from the TLS ClientHello (FR-1).
    domain: &'a str,
    /// Name of the parent process that launched the call (FR-2.3).
    parent_process: &'a str,
    /// Whether the domain is in the signed local allow-cache (PRD §1.1, Condition A).
    in_safe_cache: bool,
}

/// Run the local, no-API heuristics for one connection and fold them into a verdict.
///
/// This is the daemon-side composition of the [`aegiuw_core`] heuristics: an
/// allow-cache hit short-circuits to [`Verdict::safe`]; otherwise we collect every
/// signal and let [`Verdict::evaluate`] decide.
fn assess(conn: &Connection<'_>) -> Verdict {
    if conn.in_safe_cache {
        return Verdict::safe();
    }

    let mut signals = vec![RiskSignal::NotInSafeCache];

    if let Some(sig) = levenshtein::check_typosquat(
        conn.domain,
        levenshtein::SAMPLE_BRANDS,
        levenshtein::DEFAULT_MAX_DISTANCE,
    ) {
        signals.push(sig);
    }
    if let Some(sig) = context::assess_context(conn.parent_process, conn.in_safe_cache) {
        signals.push(sig);
    }

    Verdict::evaluate(signals)
}

fn main() -> anyhow::Result<()> {
    println!(
        "aegiuw-daemon v{} — Aegiuw local agent",
        env!("CARGO_PKG_VERSION")
    );
    println!("status: scaffold — TUN interface + SNI fork not yet implemented (FR-1.x)\n");

    // Demo the decision pipeline against a few representative connections so the
    // wiring between the daemon and aegiuw-core is observable. The real daemon
    // replaces these literals with data peeked off the wire.
    let samples = [
        Connection {
            domain: "github.com",
            parent_process: "Google Chrome",
            in_safe_cache: true,
        },
        Connection {
            domain: "micr0soft.com",
            parent_process: "Google Chrome",
            in_safe_cache: false,
        },
        Connection {
            domain: "totally-new-vendor.io",
            parent_process: "Outlook",
            in_safe_cache: false,
        },
    ];

    for conn in &samples {
        let verdict = assess(conn);
        let path = if verdict.allows_native_path() {
            "NATIVE → NIC"
        } else {
            "ISOLATE → edge"
        };
        println!(
            "  {:<24} via {:<14} → {:<11?} [{}]",
            conn.domain, conn.parent_process, verdict.level, path
        );
    }

    // TODO(FR-1): bring up the TUN interface, program the OS routing tables to
    // capture outbound :443, peek the ClientHello via aegiuw_core::sni::extract_sni,
    // and for ISOLATE verdicts marshal the URL to the edge router over HTTPS.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegiuw_core::risk::RiskLevel;

    #[test]
    fn cached_domain_takes_native_path() {
        let conn = Connection {
            domain: "github.com",
            parent_process: "Chrome",
            in_safe_cache: true,
        };
        assert!(assess(&conn).allows_native_path());
    }

    #[test]
    fn email_launched_unknown_domain_is_high_risk() {
        let conn = Connection {
            domain: "new-vendor.io",
            parent_process: "Outlook",
            in_safe_cache: false,
        };
        assert_eq!(assess(&conn).level, RiskLevel::HighRisk);
    }

    #[test]
    fn typosquat_from_browser_is_suspicious() {
        let conn = Connection {
            domain: "micr0soft.com",
            parent_process: "Chrome",
            in_safe_cache: false,
        };
        assert_eq!(assess(&conn).level, RiskLevel::Suspicious);
    }
}
