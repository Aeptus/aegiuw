// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dedicated fuzz target for `aegiuw_core::reassemble_handshake`.
//!
//! `extract_sni` transitively exercises this path, but a focused harness
//! gives libFuzzer better mutation signal on the reassembly state machine
//! — record-content-type checking, fragment concatenation, and the
//! `MAX_HANDSHAKE_BYTES` allocation cap.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aegiuw_core::reassemble_handshake(data);
});
