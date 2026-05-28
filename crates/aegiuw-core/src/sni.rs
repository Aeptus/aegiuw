// SPDX-License-Identifier: AGPL-3.0-or-later

//! SNI extraction from a raw TLS ClientHello (PRD §1.1, FR-1).
//!
//! The daemon peeks at the first outbound TCP bytes *before* relaying them,
//! pulls the Server Name Indication out of the (normally cleartext)
//! ClientHello, and uses that host for the fork decision. The parse must
//! complete in ≤ 1.5 ms (PRD §1.1 sub-millisecond budget).
//!
//! # Wire layout we walk
//!
//! ```text
//! TLSPlaintext record    u8  ContentType            (handshake = 22)
//!                        u16 LegacyRecordVersion
//!                        u16 Length
//!   Handshake            u8  HandshakeType          (client_hello = 1)
//!                        u24 Length
//!     ClientHello        u16 LegacyVersion
//!                        u8[32] Random
//!                        u8  + bytes                LegacySessionId
//!                        u16 + bytes                CipherSuites
//!                        u8  + bytes                CompressionMethods
//!                        u16 + bytes                Extensions
//!       Extension        u16 ExtensionType
//!                        u16 ExtensionDataLength
//!                        u8[Length] ExtensionData
//!
//! Extensions we care about:
//!   server_name             type 0x0000  → ServerNameList → HostName (NameType 0)
//!   encrypted_client_hello  type 0xfe0d  → real SNI is hidden inside an outer
//!                                          handshake; the visible SNI is a decoy
//! ```
//!
//! # Safety discipline
//!
//! This function parses adversary-controlled bytes. Every length prefix MUST be
//! checked against the remaining buffer before use. The local [`Cursor`] type
//! makes that discipline structural: each read returns `Option`, so the parser
//! cannot accidentally walk past the buffer end without a `?` short-circuit.

/// Extension type for `server_name` (RFC 6066 §3).
pub const EXT_SERVER_NAME: u16 = 0x0000;

/// Extension type for `encrypted_client_hello` (draft-ietf-tls-esni, IANA).
pub const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// TLS record content type for handshake messages.
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// Handshake type for ClientHello.
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// Bounds-checked cursor over an adversary-controlled byte slice.
///
/// Every read advances the position only on success and returns `None` if the
/// requested span doesn't fit — so the parser body can use `?` and never has to
/// write a manual `if idx + N > bytes.len()` check.
pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

// Cursor is scaffolded for the upcoming `extract_sni` walk — it's exercised by
// tests today but only becomes hot once the outcome type lands and the parser
// body is wired. Suppress dead-code lints in the meantime.
#[allow(dead_code)]
impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    pub(crate) fn read_u8(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    pub(crate) fn read_u16(&mut self) -> Option<u16> {
        let s = self.read_slice(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }

    /// 24-bit big-endian length, used by the TLS Handshake header.
    pub(crate) fn read_u24(&mut self) -> Option<u32> {
        let s = self.read_slice(3)?;
        Some(((s[0] as u32) << 16) | ((s[1] as u32) << 8) | (s[2] as u32))
    }

    pub(crate) fn read_slice(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.bytes.len() {
            return None;
        }
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Some(s)
    }

    /// Read a `u8`-prefixed length, then that many bytes (e.g. session_id,
    /// compression_methods).
    pub(crate) fn read_u8_prefixed(&mut self) -> Option<&'a [u8]> {
        let n = self.read_u8()? as usize;
        self.read_slice(n)
    }

    /// Read a `u16`-prefixed length, then that many bytes (e.g. cipher_suites,
    /// extensions, individual extension data).
    pub(crate) fn read_u16_prefixed(&mut self) -> Option<&'a [u8]> {
        let n = self.read_u16()? as usize;
        self.read_slice(n)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 🔧 DESIGN POINT — define the outcome type for `extract_sni`
// ─────────────────────────────────────────────────────────────────────────────
//
// The daemon needs to distinguish at least three observable outcomes, because
// each routes to a *different* policy upstream:
//
//   1. SNI host extracted cleanly             → Layer 2 scores it normally.
//   2. ECH extension (type 0xfe0d) present    → real SNI is hidden; per
//                                                DECISIONS.C14 we treat the
//                                                connection as Unknown and
//                                                isolate by default.
//   3. Not a ClientHello / no SNI / malformed → per DECISIONS.D25, fall through
//                                                to the "couldn't deliver
//                                                isolation" warning UX.
//
// Three reasonable shapes for the return type:
//
//   (a) Result<String, SniError>
//         enum SniError { NotClientHello, NoSniExtension, Encrypted, Malformed }
//       Conventional Rust. Downstream uses `?` and matches on the error.
//
//   (b) Single sum type capturing every outcome as a variant:
//         enum SniOutcome { Cleartext(String), Encrypted, NotFound, Malformed }
//       The parse has no "errors" in the I/O sense — all outcomes are observable
//       facts the daemon must handle. Every state is one match arm.
//
//   (c) Option<String> + a separate is_ech_present(&[u8]) -> bool
//       Simple, but forces callers to remember two parse passes.
//
// My lean: (b). The parse is total — every byte slice maps to exactly one of
// the four states; none are "errors" the caller might want to bubble up
// unchanged. But it's your call, and it shapes how Layer 2 consumes the result.
//
// TODO(christophe): define the outcome type below (≈ 5 lines), then I'll wire
// the parser body. The walk will use `Cursor` (above) plus the extension
// constants `EXT_SERVER_NAME` and `EXT_ENCRYPTED_CLIENT_HELLO`.

// ─────────────────────────────────────────────────────────────────────────────

/// **Temporary signature** until the outcome type lands above. Returns `None`
/// for every input. Will be replaced once the design point is resolved.
pub fn extract_sni(_client_hello: &[u8]) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_no_sni() {
        assert_eq!(extract_sni(&[]), None);
    }

    // ── Cursor: structural safety tests ──────────────────────────────────

    #[test]
    fn cursor_reads_multi_byte_ints_big_endian() {
        let mut c = Cursor::new(&[0x01, 0xab, 0xcd, 0x12, 0x34, 0x56]);
        assert_eq!(c.read_u8(), Some(0x01));
        assert_eq!(c.read_u16(), Some(0xabcd));
        assert_eq!(c.read_u24(), Some(0x123456));
        assert_eq!(c.remaining(), 0);
    }

    #[test]
    fn cursor_refuses_overrun() {
        let mut c = Cursor::new(&[0x01, 0x02]);
        assert_eq!(c.read_slice(5), None);
        assert_eq!(c.read_u24(), None);
        // Position is unchanged after a failed read — verified by being able
        // to still read the bytes that *are* present.
        assert_eq!(c.read_u16(), Some(0x0102));
    }

    #[test]
    fn cursor_length_prefixed_reads() {
        // u8 length=3, then "abc". Then u16 length=2, then "xy".
        let buf = [0x03, b'a', b'b', b'c', 0x00, 0x02, b'x', b'y'];
        let mut c = Cursor::new(&buf);
        assert_eq!(c.read_u8_prefixed(), Some(&b"abc"[..]));
        assert_eq!(c.read_u16_prefixed(), Some(&b"xy"[..]));
    }

    #[test]
    fn cursor_length_prefix_rejects_truncated_payload() {
        // Claims 10 bytes follow; only 3 do.
        let buf = [0x0a, b'a', b'b', b'c'];
        let mut c = Cursor::new(&buf);
        assert_eq!(c.read_u8_prefixed(), None);
    }

    // TODO(FR-1): once the outcome type is defined, add fixtures here:
    //   • real ClientHello with SNI present
    //   • ClientHello with no server_name extension
    //   • ClientHello with ECH (extension type 0xfe0d)
    //   • truncated / malformed records (must not panic, must not read OOB)
}
