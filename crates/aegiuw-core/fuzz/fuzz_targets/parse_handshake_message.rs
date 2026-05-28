// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dedicated fuzz target for `aegiuw_core::parse_handshake_message`.
//!
//! This is the pure handshake-body walker that the upcoming QUIC parser
//! will reuse (it expects already-stripped CRYPTO-frame bytes). Fuzz it
//! directly so the contract holds independently of record framing.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aegiuw_core::parse_handshake_message(data);
});
