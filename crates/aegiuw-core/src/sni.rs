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
//!                                          handshake; the visible SNI is decoy
//! ```
//!
//! # Safety discipline
//!
//! This function parses adversary-controlled bytes. Every length prefix MUST be
//! checked against the remaining buffer before use. The local [`Cursor`] type
//! makes that discipline structural: each read returns `Option`, so the parser
//! cannot accidentally walk past the buffer end without a `?` short-circuit.

use serde::{Deserialize, Serialize};

/// Extension type for `server_name` (RFC 6066 §3).
pub const EXT_SERVER_NAME: u16 = 0x0000;

/// Extension type for `encrypted_client_hello` (draft-ietf-tls-esni, IANA).
pub const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// TLS record content type for handshake messages.
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// Handshake type for ClientHello.
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// NameType value for `host_name` inside a ServerName (RFC 6066 §3).
const NAME_TYPE_HOST_NAME: u8 = 0;

/// What [`extract_sni`] observed about a candidate ClientHello.
///
/// The parse is *total* — every input byte slice maps to exactly one variant.
/// None of these are "errors" the caller might pass through; each routes to a
/// distinct upstream policy:
///
/// | Variant         | Routed to                                                  |
/// |-----------------|------------------------------------------------------------|
/// | `Cleartext`     | Layer 2 scores the host normally.                          |
/// | `Encrypted`     | `DECISIONS.C14` — treat as Unknown, isolate.               |
/// | `NotFound`      | `DECISIONS.D25` — fall through to the "couldn't deliver    |
/// |                 |    isolation" warning UX.                                  |
/// | `Malformed`     | Same as `NotFound` operationally, distinguished for        |
/// |                 |    telemetry — a malformed ClientHello suggests either an  |
/// |                 |    attacker or a non-TLS protocol on :443.                 |
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SniOutcome {
    /// A visible (unencrypted) `server_name` extension was found and its host
    /// extracted. The bytes are reported verbatim, exactly as on the wire —
    /// case normalization, punycode decode, and confusables folding are the
    /// "normalize + enrich" step's job, not this parser's.
    Cleartext { host: String },
    /// An `encrypted_client_hello` extension (type `0xfe0d`) was present. The
    /// visible SNI, if any, is a decoy and must be ignored.
    Encrypted,
    /// The bytes parsed as a valid ClientHello but no `server_name` extension
    /// was present.
    NotFound,
    /// The bytes do not parse as a ClientHello (wrong content type, truncated
    /// record, bad length prefix, non-UTF-8 host, etc.).
    Malformed,
}

/// Parse the supplied bytes as a TLS ClientHello and report what was observed
/// about the Server Name Indication.
///
/// Returns one of the four [`SniOutcome`] variants — see that type's docs for
/// how each routes upstream. ECH presence always wins over a visible SNI per
/// `DECISIONS.C14`.
pub fn extract_sni(bytes: &[u8]) -> SniOutcome {
    parse_client_hello(bytes).unwrap_or(SniOutcome::Malformed)
}

/// Walk a candidate ClientHello. Returns `None` to mean "the bytes don't parse"
/// (which [`extract_sni`] surfaces as [`SniOutcome::Malformed`]); returns
/// `Some(outcome)` for any other observable result.
///
/// Using `?` inside this function is deliberate: any failed cursor read here
/// represents a truncated record / bad length prefix, which is malformation.
fn parse_client_hello(bytes: &[u8]) -> Option<SniOutcome> {
    let mut c = Cursor::new(bytes);

    // ── TLSPlaintext record header ─────────────────────────────────────────
    if c.read_u8()? != CONTENT_TYPE_HANDSHAKE {
        return Some(SniOutcome::Malformed);
    }
    c.read_u16()?; // legacy_record_version (ignored)
    c.read_u16()?; // record fragment length (ignored — we use the handshake's own length)

    // ── Handshake header ───────────────────────────────────────────────────
    if c.read_u8()? != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Some(SniOutcome::Malformed);
    }
    c.read_u24()?; // handshake length

    // ── ClientHello body ───────────────────────────────────────────────────
    c.read_u16()?; // legacy_version
    c.read_slice(32)?; // random
    c.read_u8_prefixed()?; // legacy_session_id
    c.read_u16_prefixed()?; // cipher_suites
    c.read_u8_prefixed()?; // compression_methods

    // ── Extensions ─────────────────────────────────────────────────────────
    let extensions = c.read_u16_prefixed()?;

    // Scan ALL extensions before deciding: ECH wins over any visible SNI, so we
    // must look at every extension even after spotting a server_name entry.
    let mut ech_present = false;
    let mut sni_host: Option<String> = None;
    let mut ext = Cursor::new(extensions);

    while ext.remaining() >= 4 {
        let ext_type = ext.read_u16()?;
        let ext_data = ext.read_u16_prefixed()?;

        match ext_type {
            EXT_ENCRYPTED_CLIENT_HELLO => {
                ech_present = true;
            }
            EXT_SERVER_NAME if sni_host.is_none() => {
                // Failures inside a single extension don't fail the whole
                // parse — they just mean we didn't get a usable host from
                // this one. Other extensions (e.g. ECH) are still scanned.
                if let Some(host) = parse_server_name_extension(ext_data) {
                    sni_host = Some(host);
                }
            }
            _ => {}
        }
    }

    Some(if ech_present {
        SniOutcome::Encrypted
    } else if let Some(host) = sni_host {
        SniOutcome::Cleartext { host }
    } else {
        SniOutcome::NotFound
    })
}

/// Parse the body of a `server_name` extension (RFC 6066 §3) and return the
/// first `host_name` entry as a String. Returns `None` if the extension is
/// malformed, empty, or only contains non-`host_name` entries — the caller
/// treats `None` as "no SNI in this extension" and keeps scanning.
fn parse_server_name_extension(data: &[u8]) -> Option<String> {
    let mut c = Cursor::new(data);
    let list = c.read_u16_prefixed()?;
    let mut entries = Cursor::new(list);

    // We only consume the *first* ServerName. RFC 6066 §3 leaves room for a
    // list but in practice clients send exactly one host_name entry, and the
    // structure of any non-host_name entry is undefined — so we can't safely
    // skip past one to look for a later host_name.
    if entries.remaining() < 3 {
        return None;
    }
    let name_type = entries.read_u8()?;
    if name_type != NAME_TYPE_HOST_NAME {
        return None;
    }
    let host = entries.read_u16_prefixed()?;
    // RFC 6066: HostName is ASCII (IDNs are ACE/punycode-encoded). ASCII is
    // valid UTF-8, so anything that fails this is malformed in practice.
    core::str::from_utf8(host).ok().map(str::to_string)
}

/// Bounds-checked cursor over an adversary-controlled byte slice.
///
/// Every read advances the position only on success and returns `None` if the
/// requested span doesn't fit — so the parser body can use `?` and never has to
/// write a manual `if idx + N > bytes.len()` check.
pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    // ── Cursor: structural safety tests ──────────────────────────────────────

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
        let buf = [0x03, b'a', b'b', b'c', 0x00, 0x02, b'x', b'y'];
        let mut c = Cursor::new(&buf);
        assert_eq!(c.read_u8_prefixed(), Some(&b"abc"[..]));
        assert_eq!(c.read_u16_prefixed(), Some(&b"xy"[..]));
    }

    #[test]
    fn cursor_length_prefix_rejects_truncated_payload() {
        let buf = [0x0a, b'a', b'b', b'c'];
        let mut c = Cursor::new(&buf);
        assert_eq!(c.read_u8_prefixed(), None);
    }

    // ── ClientHello fixture builders ─────────────────────────────────────────
    //
    // Constructed at runtime so length prefixes stay correct as we tweak
    // payloads. A hand-typed hex blob would drift the first time anyone added
    // a field.

    /// Wrap a ClientHello body in a Handshake message and a TLSPlaintext record.
    fn build_client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
        body.extend_from_slice(&[0xAA; 32]); // random
        body.push(0); // legacy_session_id length = 0
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        body.extend_from_slice(&[0x01, 0x00]); // compression_methods: null
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let body_len = body.len() as u32;
        handshake.push(((body_len >> 16) & 0xff) as u8);
        handshake.push(((body_len >> 8) & 0xff) as u8);
        handshake.push((body_len & 0xff) as u8);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // legacy_record_version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// Build a `server_name` extension carrying a single host_name entry.
    fn build_sni_extension(host: &str) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let mut entry = Vec::new();
        entry.push(NAME_TYPE_HOST_NAME);
        entry.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        entry.extend_from_slice(host_bytes);

        let mut list = Vec::new();
        list.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        list.extend_from_slice(&entry);

        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
        ext
    }

    /// Build a minimal `encrypted_client_hello` extension. The contents are
    /// opaque to this parser; only the type matters.
    fn build_ech_extension() -> Vec<u8> {
        let payload = [0x00, 0x01, 0x02, 0x03]; // arbitrary
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
        ext.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        ext.extend_from_slice(&payload);
        ext
    }

    // ── extract_sni: outcome tests ───────────────────────────────────────────

    #[test]
    fn extracts_visible_sni() {
        let bytes = build_client_hello(&build_sni_extension("example.com"));
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext {
                host: "example.com".into()
            }
        );
    }

    #[test]
    fn ech_wins_over_visible_sni() {
        // Some ECH-using clients send a decoy server_name in the OUTER
        // ClientHello. Reporting Cleartext here would defeat C14 — ensure ECH
        // dominates regardless of extension order.
        let mut extensions = build_sni_extension("decoy.example.com");
        extensions.extend_from_slice(&build_ech_extension());
        let bytes = build_client_hello(&extensions);
        assert_eq!(extract_sni(&bytes), SniOutcome::Encrypted);

        // And in the reverse order.
        let mut extensions = build_ech_extension();
        extensions.extend_from_slice(&build_sni_extension("decoy.example.com"));
        let bytes = build_client_hello(&extensions);
        assert_eq!(extract_sni(&bytes), SniOutcome::Encrypted);
    }

    #[test]
    fn no_sni_extension_is_not_found() {
        let bytes = build_client_hello(&[]);
        assert_eq!(extract_sni(&bytes), SniOutcome::NotFound);
    }

    #[test]
    fn empty_input_is_malformed() {
        assert_eq!(extract_sni(&[]), SniOutcome::Malformed);
    }

    #[test]
    fn wrong_content_type_is_malformed() {
        // 0x17 = application_data, not handshake.
        assert_eq!(
            extract_sni(&[0x17, 0x03, 0x01, 0x00, 0x00]),
            SniOutcome::Malformed
        );
    }

    #[test]
    fn truncated_record_is_malformed() {
        // Just the content type, no length yet.
        assert_eq!(extract_sni(&[0x16, 0x03, 0x01]), SniOutcome::Malformed);
    }

    #[test]
    fn non_client_hello_handshake_is_malformed() {
        // Valid record header, but handshake type is ServerHello (2), not ClientHello (1).
        let bytes = [0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn non_utf8_host_is_malformed() {
        // RFC 6066: HostName is ASCII. A non-UTF-8 byte sequence cannot be a
        // legitimate host_name, so the parse-pass on the SNI extension fails
        // and (with no ECH present) we report NotFound, not Cleartext.
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        // list_len=6, entry: name_type=0, host_len=3, three non-UTF-8 bytes
        ext.extend_from_slice(&[0x00, 0x06, 0x00, 0x06, 0x00, 0x03, 0xff, 0xfe, 0xfd]);
        let bytes = build_client_hello(&ext);
        assert_eq!(extract_sni(&bytes), SniOutcome::NotFound);
    }

    #[test]
    fn extension_with_over_claimed_data_length_is_malformed() {
        // Place one extension inside the extensions block: type=0x0064, claims
        // 100 bytes of data, only has 0. The u16-prefixed read of the
        // extension data will fail inside the scan loop and propagate via `?`
        // through parse_client_hello → Malformed.
        let bad_extensions = vec![
            0x00, 0x64, // ext_type
            0x00, 0x64, // ext_data_length = 100 (lie)
                       // …no payload follows…
        ];
        let bytes = build_client_hello(&bad_extensions);
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }
}
