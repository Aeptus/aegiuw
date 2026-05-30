// SPDX-License-Identifier: AGPL-3.0-or-later

//! `aegiuw-daemon` — the privileged local agent.
//!
//! Scaffold status: the privileged networking layer (TUN interface, routing-table
//! configuration, the actual fork to NIC-vs-edge) is **not yet implemented** — see
//! the `TODO(FR-1)` markers below. What *is* wired up is the full decision pipeline
//! from [`aegiuw_core`]: this binary peeks a fixture TLS ClientHello, extracts the
//! SNI via [`aegiuw_core::extract_sni`] (SNI backlog I1), folds the outcome into
//! Layer-2 risk signals, and produces a fork verdict — the same flow the live
//! daemon will run against bytes peeked off the wire.

use aegiuw_core::heuristics::{context, levenshtein};
use aegiuw_core::risk::{into_signals, RiskSignal, Verdict};
use aegiuw_core::{extract_sni, SniOutcome};

/// One demo connection: fixture ClientHello bytes the daemon would peek off
/// the wire, plus the launch context it would gather from the OS.
struct Sample {
    /// Human description for the demo output.
    label: &'static str,
    /// Record-framed TLS ClientHello bytes — what the daemon peeks at the
    /// start of an outbound `:443` connection (FR-1).
    client_hello: Vec<u8>,
    /// Name of the parent process that launched the call (FR-2.3).
    parent_process: &'static str,
}

/// The signed local allow-cache (PRD §1.1, Condition A). The real daemon
/// loads an ed25519-signed JSON cache (DECISIONS.D20); here it's a static
/// slice the extracted host is checked against.
const ALLOW_CACHE: &[&str] = &["github.com", "www.example.com"];

fn host_in_cache(host: &str) -> bool {
    ALLOW_CACHE.iter().any(|&c| c.eq_ignore_ascii_case(host))
}

/// Run the full Layer-1 + Layer-2 pipeline for one connection: peek the SNI,
/// then fold the outcome into a fork verdict.
///
/// - **Cleartext** host: an allow-cache hit short-circuits to [`Verdict::safe`]
///   (the only short-circuit); otherwise the host runs through the typosquat
///   and launch-context heuristics.
/// - **Encrypted / NotFound / Malformed**: there's no host to score, so the
///   SNI-outcome signal from [`into_signals`] stands in for the
///   couldn't-score evidence; launch context (host-independent) still applies.
fn assess<'ch>(client_hello: &'ch [u8], parent_process: &str) -> (SniOutcome<'ch>, Verdict) {
    let outcome = extract_sni(client_hello);

    let verdict = match &outcome {
        SniOutcome::Cleartext { host } => {
            if host_in_cache(host) {
                Verdict::safe()
            } else {
                let mut signals = vec![RiskSignal::NotInSafeCache];
                if let Some(sig) = levenshtein::check_typosquat(
                    host,
                    levenshtein::SAMPLE_BRANDS,
                    levenshtein::DEFAULT_MAX_DISTANCE,
                ) {
                    signals.push(sig);
                }
                if let Some(sig) = context::assess_context(parent_process, false) {
                    signals.push(sig);
                }
                Verdict::evaluate(signals)
            }
        }
        // No observable host: the SNI-outcome signal (EncryptedClientHello /
        // NoServerName / MalformedClientHello) carries the evidence. Launch
        // context is host-independent, so still factor it in.
        _ => {
            let mut signals = into_signals(&outcome);
            if let Some(sig) = context::assess_context(parent_process, false) {
                signals.push(sig);
            }
            Verdict::evaluate(signals)
        }
    };

    (outcome, verdict)
}

fn main() -> anyhow::Result<()> {
    println!(
        "aegiuw-daemon v{} — Aegiuw local agent",
        env!("CARGO_PKG_VERSION")
    );
    println!("status: scaffold — TUN interface + SNI fork not yet implemented (FR-1.x)");
    println!("demo: peeking fixture ClientHellos through aegiuw_core::extract_sni (I1)\n");

    // Fixture ClientHellos covering each SNI outcome the daemon must handle.
    // The live daemon replaces these with bytes peeked off the wire.
    let samples = [
        Sample {
            label: "cached host, from browser",
            client_hello: client_hello(&sni_extension("github.com")),
            parent_process: "Google Chrome",
        },
        Sample {
            label: "typosquat, from browser",
            client_hello: client_hello(&sni_extension("micr0soft.com")),
            parent_process: "Google Chrome",
        },
        Sample {
            label: "unknown host, from email",
            client_hello: client_hello(&sni_extension("totally-new-vendor.io")),
            parent_process: "Outlook",
        },
        Sample {
            label: "ECH (encrypted SNI)",
            client_hello: client_hello(&ech_then_decoy_sni("cloudflare-ech.com")),
            parent_process: "Google Chrome",
        },
        Sample {
            label: "non-TLS / malformed bytes",
            client_hello: vec![0xff, 0xff, 0xff, 0xff],
            parent_process: "unknown",
        },
    ];

    for sample in &samples {
        let (outcome, verdict) = assess(&sample.client_hello, sample.parent_process);
        let observed = describe_outcome(&outcome);
        let path = if verdict.allows_native_path() {
            "NATIVE → NIC"
        } else {
            "ISOLATE → edge"
        };
        println!(
            "  {:<26} {:<22} via {:<14} → {:<11?} [{}]",
            sample.label, observed, sample.parent_process, verdict.level, path
        );
    }

    // TODO(FR-1): bring up the TUN interface, program the OS routing tables to
    // capture outbound :443, peek the ClientHello via aegiuw_core::extract_sni
    // (now wired above), and for ISOLATE verdicts marshal the URL to the edge
    // router over HTTPS.
    Ok(())
}

/// Short human description of what the parser observed.
fn describe_outcome(outcome: &SniOutcome<'_>) -> String {
    match outcome {
        SniOutcome::Cleartext { host } => format!("host={host}"),
        SniOutcome::Encrypted => "host=<encrypted>".to_string(),
        SniOutcome::NotFound => "host=<absent>".to_string(),
        SniOutcome::Malformed => "host=<malformed>".to_string(),
    }
}

// ── Fixture ClientHello builders ─────────────────────────────────────────────
//
// Minimal but spec-valid wire bytes so the demo exercises the real parser.
// (aegiuw-core's own test fixtures are `#[cfg(test)]` and not importable; these
// mirror the same wire layout — see the worked example in sni.rs module docs.)

/// Wrap an `extensions` block into a complete single-record ClientHello.
fn client_hello(extensions: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&[0xAA; 32]); // random
    body.push(0); // legacy_session_id (empty)
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: [TLS_AES_128_GCM_SHA256]
    body.extend_from_slice(&[0x01, 0x00]); // compression_methods: [null]
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);

    let mut handshake = vec![0x01]; // HandshakeType::client_hello
    let body_len = body.len() as u32;
    handshake.push(((body_len >> 16) & 0xff) as u8);
    handshake.push(((body_len >> 8) & 0xff) as u8);
    handshake.push((body_len & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01]; // content_type=handshake, legacy_record_version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// A `server_name` extension carrying one `host_name` entry.
fn sni_extension(host: &str) -> Vec<u8> {
    let host_bytes = host.as_bytes();
    let mut entry = vec![0x00]; // NameType::host_name
    entry.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    entry.extend_from_slice(host_bytes);

    let mut list = (entry.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&entry);

    let mut ext = 0x0000u16.to_be_bytes().to_vec(); // extension_type = server_name
    ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
    ext.extend_from_slice(&list);
    ext
}

/// An `encrypted_client_hello` (0xfe0d) extension followed by a decoy
/// `server_name` — the real ECH wire shape: ECH must win and mask the
/// visible host (DECISIONS.C14).
fn ech_then_decoy_sni(decoy_host: &str) -> Vec<u8> {
    let mut exts = 0xfe0du16.to_be_bytes().to_vec(); // extension_type = ECH
    exts.extend_from_slice(&[0x00, 0x00]); // empty extension_data
    exts.extend_from_slice(&sni_extension(decoy_host));
    exts
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegiuw_core::risk::RiskLevel;

    #[test]
    fn cached_host_takes_native_path() {
        let ch = client_hello(&sni_extension("github.com"));
        let (_, verdict) = assess(&ch, "Chrome");
        assert!(verdict.allows_native_path());
    }

    #[test]
    fn email_launched_unknown_host_is_high_risk() {
        let ch = client_hello(&sni_extension("new-vendor.io"));
        let (_, verdict) = assess(&ch, "Outlook");
        assert_eq!(verdict.level, RiskLevel::HighRisk);
    }

    #[test]
    fn typosquat_from_browser_is_suspicious() {
        let ch = client_hello(&sni_extension("micr0soft.com"));
        let (outcome, verdict) = assess(&ch, "Chrome");
        assert!(matches!(outcome, SniOutcome::Cleartext { .. }));
        assert_eq!(verdict.level, RiskLevel::Suspicious);
    }

    #[test]
    fn ech_connection_isolates_via_encrypted_signal() {
        let ch = client_hello(&ech_then_decoy_sni("cloudflare-ech.com"));
        let (outcome, verdict) = assess(&ch, "Chrome");
        // ECH wins: the decoy host is masked (DECISIONS.C14).
        assert_eq!(outcome, SniOutcome::Encrypted);
        assert!(!verdict.allows_native_path());
        assert!(verdict.signals.contains(&RiskSignal::EncryptedClientHello));
    }

    #[test]
    fn malformed_bytes_isolate_via_malformed_signal() {
        let (outcome, verdict) = assess(&[0xff, 0xff, 0xff, 0xff], "unknown");
        assert_eq!(outcome, SniOutcome::Malformed);
        assert!(!verdict.allows_native_path());
        assert!(verdict.signals.contains(&RiskSignal::MalformedClientHello));
    }

    #[test]
    fn fixture_client_hello_round_trips_through_extract_sni() {
        // The demo builders must produce bytes the real parser accepts —
        // otherwise the end-to-end demonstration is hollow.
        let ch = client_hello(&sni_extension("example.com"));
        assert_eq!(
            extract_sni(&ch),
            SniOutcome::Cleartext {
                host: "example.com".into()
            },
        );
    }
}
