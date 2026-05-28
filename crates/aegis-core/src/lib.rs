// SPDX-License-Identifier: AGPL-3.0-or-later

//! # aegis-core
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

pub mod heuristics;
pub mod risk;
pub mod sni;

pub use risk::{RiskLevel, RiskSignal, Verdict};
