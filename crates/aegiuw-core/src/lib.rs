// SPDX-License-Identifier: AGPL-3.0-or-later

#![cfg_attr(not(feature = "std"), no_std)]
//! # aegiuw-core
//!
//! The pure decision logic of the Aegiuw local agent. Everything here is free of
//! I/O, OS calls, and `unsafe` (see the `forbid(unsafe_code)` lint in Cargo.toml),
//! which keeps it:
//!
//! - **unit-testable** in isolation (no network, no TUN, no process tree), and
//! - **WASM-friendly**, so the identical risk logic can later be compiled and run
//!   inside the Cloudflare Worker rather than reimplemented in TypeScript.
//!
//! The agent flow is: parse the SNI host from a TLS ClientHello ([`sni`]), gather
//! [`heuristics`] signals about it, and fold those signals into a single
//! [`risk::Verdict`] that decides Native Path vs. Isolate Path (PRD §1.1).
//!
//! ## no_std support (SNI backlog P6)
//!
//! Default features include `std`. Pass `--no-default-features` to compile
//! against `core + alloc` only — the parser keeps full functionality; only the
//! `duration_us` field on the `extract_sni` trace event is dropped because
//! `std::time::Instant` is std-only.

extern crate alloc;

pub mod fingerprint;
pub mod heuristics;
pub mod risk;
pub mod sni;

pub use fingerprint::{
    ja3, ja4, ja4_h, known_client_from_ja3, known_client_from_ja4, likely_launch_source, Ja3, Ja4,
    Ja4H, Ja4HInput, KnownClient, LaunchSource, KNOWN_JA3_FINGERPRINTS, KNOWN_JA4_FINGERPRINTS,
};
pub use risk::{RiskLevel, RiskSignal, Verdict};
pub use sni::{
    extract_sni, hrr_sni_consistent, is_cloudflare_ech_outer, is_idn_host, parse_client_hello_full,
    parse_handshake_message, parse_handshake_message_full, parse_handshake_only, parse_record,
    reassemble_handshake, verify_handshake_type, AlpnProtocol, ClientHelloMetadata, KeyShareGroup,
    SniOutcome, TlsVersion, CLOUDFLARE_ECH_OUTER_SNI,
};
