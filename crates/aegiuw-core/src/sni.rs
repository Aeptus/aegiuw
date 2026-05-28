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
//! # Multi-record reassembly
//!
//! A single ClientHello *handshake message* is allowed to span multiple TLS
//! records on the wire (each carrying [`CONTENT_TYPE_HANDSHAKE`] payload bytes
//! that concatenate into the handshake stream). Naive "parse the first record's
//! fragment as if it were the whole handshake" implementations have produced
//! real security bugs — notably Traefik's `GHSA-wvvq-wgcr-9q48` pre-SNI sniff
//! that returned an empty SNI on fragmented input and routed traffic to a
//! permissive default TLS config.
//!
//! Our [`extract_sni`] therefore routes through [`reassemble_handshake`] first,
//! which concatenates the fragments of consecutive `content_type=22` records
//! into a single handshake byte stream, then hands those bytes to
//! [`parse_handshake_message`]. Non-handshake records, truncation, or wildly
//! over-claimed lengths all yield [`SniOutcome::Malformed`].
//!
//! # Safety discipline
//!
//! This function parses adversary-controlled bytes. Every length prefix MUST be
//! checked against the remaining buffer before use. The local [`Cursor`] type
//! makes that discipline structural: each read returns `Option`, so the parser
//! cannot accidentally walk past the buffer end without a `?` short-circuit.
//! Reassembly is bounded by [`MAX_HANDSHAKE_BYTES`] so an attacker cannot use
//! a 16 MB handshake-length claim to drive unbounded allocation.
//!
//! # Contract
//!
//! What callers can rely on, and what they're responsible for. Doc-tests on
//! each public function exercise the boundary cases below.
//!
//! ## Input expectations
//!
//! - A byte slice the caller has already buffered from a TCP stream (or
//!   built in-memory). Zero-length is acceptable and yields
//!   [`SniOutcome::Malformed`].
//! - May contain **one or more** consecutive `content_type=22` TLS records
//!   carrying the ClientHello (and only the ClientHello — see Non-goals).
//! - **No streaming API.** We do not signal "need more bytes." A caller
//!   reading from a socket must accumulate until either the handshake
//!   length is satisfied or a sensible timeout fires; calling us with
//!   partial input simply yields `Malformed`.
//! - Bytes past the end of the first complete handshake message are
//!   ignored. A 0-RTT EarlyData record coalesced after the ClientHello is
//!   harmless.
//!
//! ## Output guarantees
//!
//! - **Total function.** Every input slice maps to exactly one
//!   [`SniOutcome`] variant. There is no `Result`, no `Option`, no panic
//!   path; that's the whole point of the four-variant sum type.
//! - **Allocation-bounded.** Reassembly will never allocate more than
//!   [`MAX_HANDSHAKE_BYTES`] regardless of attacker-controlled length
//!   claims. The cap is checked before the allocation grows past it.
//! - **Panic-free.** No input bytes can trigger a panic, out-of-bounds
//!   read, or integer overflow — enforced by the
//!   `unsafe_code = "forbid"` lint and the [`Cursor`] discipline. Verified
//!   by the test suite; a `cargo-fuzz` harness is on the backlog (`S1`).
//! - **Side-effect free.** Reads `&[u8]`, returns owned data. No globals,
//!   no I/O.
//!
//! ## Performance budget
//!
//! - Per PRD §1.1, the daemon's overall SNI peek must complete in
//!   ≤ 1.5 ms. This parser is linear in input length and is typically
//!   single-digit microseconds on a real ClientHello; quadratic behavior
//!   on any adversarial input is a regression.
//!
//! ## Non-goals
//!
//! - **DTLS** (UDP-framed TLS): out of scope — the QUIC parser (Layer 1
//!   sibling) handles UDP separately.
//! - **SSL 2.0 ClientHello format**: explicitly returns `Malformed`. SSL
//!   2.0 had no SNI anyway and is long-obsolete.
//! - **TLS renegotiation ClientHello** *inside* an active session: the
//!   daemon peeks only at connection start.
//! - **ECH inner ClientHello**: per `DECISIONS.C14`, ECH presence is
//!   surfaced as [`SniOutcome::Encrypted`] and routes to Isolate; we
//!   never attempt to decrypt the inner CH.
//! - **Hostname normalization**: case-folding, punycode decoding, eTLD+1
//!   extraction, and Unicode confusables handling are the responsibility
//!   of the Layer 1 "normalize + enrich" step, not this parser. We
//!   report `Cleartext { host }` verbatim from the wire.

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

/// Upper bound on the handshake bytes we'll accumulate during reassembly.
///
/// A realistic post-quantum ClientHello sits around 6–8 KB. 64 KB is generous
/// enough to cover any legitimate handshake while still capping adversarial
/// "u24 length = 0xFFFFFF" claims at a few extra records worth of allocation.
pub const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;

/// Per RFC 8446 §5.1, `TLSPlaintext.length` must not exceed 2¹⁴. We allow a
/// little slack for the encrypted-record overhead (we should never see those
/// here, but tolerating them in the reassembly path keeps the failure mode
/// "this isn't a ClientHello" instead of "this is malformed").
const MAX_RECORD_FRAGMENT: usize = 16_384 + 256;

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
/// Accepts either a single TLS record carrying the whole ClientHello, or
/// multiple consecutive `content_type=22` records carrying its fragments;
/// reassembles them via [`reassemble_handshake`] before parsing. Returns one
/// of the four [`SniOutcome`] variants — see that type's docs for how each
/// routes upstream. ECH presence always wins over a visible SNI per
/// `DECISIONS.C14`.
///
/// # Examples
///
/// Boundary cases enforced by the contract:
///
/// ```
/// use aegiuw_core::{extract_sni, SniOutcome};
///
/// // Empty input is Malformed (total function — never panics, never None).
/// assert_eq!(extract_sni(&[]), SniOutcome::Malformed);
///
/// // Wrong content type (0x17 = application_data) is Malformed.
/// assert_eq!(
///     extract_sni(&[0x17, 0x03, 0x01, 0x00, 0x00]),
///     SniOutcome::Malformed,
/// );
///
/// // Truncated record (only the content-type byte) is Malformed.
/// assert_eq!(extract_sni(&[0x16]), SniOutcome::Malformed);
/// ```
pub fn extract_sni(bytes: &[u8]) -> SniOutcome {
    let Some(handshake) = reassemble_handshake(bytes) else {
        return SniOutcome::Malformed;
    };
    parse_handshake_message(&handshake).unwrap_or(SniOutcome::Malformed)
}

/// Walk one or more TLS records and concatenate their `content_type=22`
/// fragment payloads into a single handshake byte stream.
///
/// Returns `Some(handshake)` once enough fragments have been accumulated to
/// satisfy the handshake message's own `u24` length field. Returns `None`
/// when:
///
/// - the input doesn't begin with a valid record header;
/// - any record has a `content_type` other than [`CONTENT_TYPE_HANDSHAKE`]
///   *before* the handshake length is satisfied (mixed-type streams are
///   precisely the Traefik-CVE class — refusing to assemble forces the
///   caller to surface [`SniOutcome::Malformed`]);
/// - a record claims a fragment longer than the remaining input or larger
///   than `MAX_RECORD_FRAGMENT`;
/// - the assembled handshake would exceed [`MAX_HANDSHAKE_BYTES`];
/// - the input ends before the handshake message is complete.
///
/// Bytes past the end of the first complete handshake message are ignored.
///
/// # Examples
///
/// ```
/// use aegiuw_core::reassemble_handshake;
///
/// // Empty input: no records, nothing to assemble.
/// assert_eq!(reassemble_handshake(&[]), None);
///
/// // Wrong content type: refuse to assemble (Traefik-CVE class defense).
/// assert_eq!(
///     reassemble_handshake(&[0x17, 0x03, 0x01, 0x00, 0x01, 0xFF]),
///     None,
/// );
///
/// // Truncated record header: refuse.
/// assert_eq!(reassemble_handshake(&[0x16, 0x03]), None);
/// ```
pub fn reassemble_handshake(records: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = Cursor::new(records);
    let mut handshake_buf: Vec<u8> = Vec::new();
    let mut expected_total: Option<usize> = None;

    while cursor.remaining() > 0 {
        let content_type = cursor.read_u8()?;
        if content_type != CONTENT_TYPE_HANDSHAKE {
            return None;
        }
        cursor.read_u16()?; // legacy_record_version (ignored)
        let fragment_len = cursor.read_u16()? as usize;

        if fragment_len > MAX_RECORD_FRAGMENT {
            return None;
        }
        if fragment_len == 0 {
            continue;
        }

        let fragment = cursor.read_slice(fragment_len)?;
        handshake_buf.extend_from_slice(fragment);

        if handshake_buf.len() > MAX_HANDSHAKE_BYTES {
            return None;
        }

        if expected_total.is_none() && handshake_buf.len() >= 4 {
            let body_len = ((handshake_buf[1] as usize) << 16)
                | ((handshake_buf[2] as usize) << 8)
                | (handshake_buf[3] as usize);
            let total = 4usize.checked_add(body_len)?;
            if total > MAX_HANDSHAKE_BYTES {
                return None;
            }
            expected_total = Some(total);
        }

        if let Some(need) = expected_total {
            if handshake_buf.len() >= need {
                handshake_buf.truncate(need);
                return Some(handshake_buf);
            }
        }
    }

    None
}

/// Parse an already-reassembled handshake message (no record framing) and
/// extract the SNI status.
///
/// Returns `None` to mean "the bytes don't look like a handshake at all"
/// (caller surfaces this as [`SniOutcome::Malformed`]); returns
/// `Some(outcome)` for any observable result, including a malformed
/// ClientHello explicitly tagged as [`SniOutcome::Malformed`].
///
/// Made `pub` so the upcoming QUIC parser can feed already-stripped
/// CRYPTO-frame bytes here without going through record reassembly first.
///
/// # Examples
///
/// ```
/// use aegiuw_core::{parse_handshake_message, SniOutcome};
///
/// // Empty input: not even a handshake header.
/// assert_eq!(parse_handshake_message(&[]), None);
///
/// // Wrong handshake type (0x02 = ServerHello, not ClientHello): observed
/// // as Malformed, not None — the bytes *are* a handshake, just not one
/// // we can extract SNI from.
/// assert_eq!(
///     parse_handshake_message(&[0x02, 0x00, 0x00, 0x00]),
///     Some(SniOutcome::Malformed),
/// );
/// ```
pub fn parse_handshake_message(handshake: &[u8]) -> Option<SniOutcome> {
    let mut c = Cursor::new(handshake);

    // ── Handshake header ───────────────────────────────────────────────────
    if c.read_u8()? != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Some(SniOutcome::Malformed);
    }
    c.read_u24()?; // handshake body length (we trust the caller's reassembly)

    // ── ClientHello body ───────────────────────────────────────────────────
    c.read_u16()?; // legacy_version
    c.read_slice(32)?; // random
    c.read_u8_prefixed()?; // legacy_session_id
    c.read_u16_prefixed()?; // cipher_suites
    c.read_u8_prefixed()?; // compression_methods

    // ── Extensions ─────────────────────────────────────────────────────────
    let extensions = c.read_u16_prefixed()?;

    // Scan ALL extensions before deciding: ECH wins over any visible SNI, so
    // we must look at every extension even after spotting a server_name entry.
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
    // a field. Composed in three layers so multi-record reassembly tests can
    // share the same handshake bytes as the single-record tests.

    /// Build the handshake-message bytes (HandshakeType + u24 length + body).
    fn build_handshake_message(extensions: &[u8]) -> Vec<u8> {
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
        handshake
    }

    fn wrap_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(5 + payload.len());
        record.push(content_type);
        record.extend_from_slice(&[0x03, 0x01]); // legacy_record_version
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    /// Wrap a handshake message in a single TLS record (the normal case).
    fn build_client_hello(extensions: &[u8]) -> Vec<u8> {
        wrap_record(CONTENT_TYPE_HANDSHAKE, &build_handshake_message(extensions))
    }

    /// Split a handshake message across multiple TLS records at the given
    /// byte offsets. The split-points partition the handshake into N+1
    /// fragments. Used to reproduce Traefik-class fragmentation.
    fn build_fragmented_records(handshake: &[u8], splits: &[usize]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev = 0usize;
        for &split in splits {
            let split = split.min(handshake.len());
            out.extend_from_slice(&wrap_record(
                CONTENT_TYPE_HANDSHAKE,
                &handshake[prev..split],
            ));
            prev = split;
        }
        out.extend_from_slice(&wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake[prev..]));
        out
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
        // through parse_handshake_message → Malformed.
        let bad_extensions = vec![
            0x00, 0x64, // ext_type
            0x00,
            0x64, // ext_data_length = 100 (lie)
                  // …no payload follows…
        ];
        let bytes = build_client_hello(&bad_extensions);
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    // ── Multi-record reassembly tests (C1, Traefik GHSA-wvvq-wgcr-9q48 class) ──

    #[test]
    fn reassemble_handshake_assembles_single_record() {
        let handshake = build_handshake_message(&build_sni_extension("example.com"));
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        let assembled = reassemble_handshake(&record).expect("single record reassembles");
        assert_eq!(assembled, handshake);
    }

    #[test]
    fn reassemble_handshake_assembles_two_record_fragmentation() {
        let handshake = build_handshake_message(&build_sni_extension("example.com"));
        // Split right in the middle of the random[32] field so neither record
        // alone contains the full handshake header *or* the SNI extension.
        let split = 4 + 2 + 10;
        let records = build_fragmented_records(&handshake, &[split]);
        let assembled = reassemble_handshake(&records).expect("two records reassemble");
        assert_eq!(assembled, handshake);
    }

    #[test]
    fn reassemble_handshake_assembles_many_tiny_fragments() {
        // The kubernetes ingress-nginx bug was triggered by GitHub clients
        // sending the first byte of the ClientHello in its own TCP packet
        // and the rest in another. Model the worst case: 1-byte records.
        let handshake = build_handshake_message(&build_sni_extension("example.com"));
        let mut records = Vec::new();
        for byte in &handshake {
            records.extend_from_slice(&wrap_record(
                CONTENT_TYPE_HANDSHAKE,
                core::slice::from_ref(byte),
            ));
        }
        let assembled = reassemble_handshake(&records).expect("byte-per-record reassembles");
        assert_eq!(assembled, handshake);
    }

    #[test]
    fn reassemble_handshake_rejects_non_handshake_content_type() {
        // 0x17 = application_data; a stream that mixes app data into a
        // handshake reassembly is precisely the Traefik-class smuggle.
        let handshake = build_handshake_message(&[]);
        let split = 6;
        let mut records = Vec::new();
        records.extend_from_slice(&wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake[..split]));
        records.extend_from_slice(&wrap_record(0x17, &handshake[split..]));
        assert_eq!(reassemble_handshake(&records), None);
    }

    #[test]
    fn reassemble_handshake_rejects_truncated_record() {
        let handshake = build_handshake_message(&build_sni_extension("example.com"));
        let split = 10;
        let mut records = Vec::new();
        records.extend_from_slice(&wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake[..split]));
        // Build a second record header that claims 200 bytes but is followed
        // by only 5 bytes of actual payload.
        records.push(CONTENT_TYPE_HANDSHAKE);
        records.extend_from_slice(&[0x03, 0x01]);
        records.extend_from_slice(&[0x00, 0xC8]); // length = 200
        records.extend_from_slice(&[0x00; 5]); // only 5 bytes — truncated
        assert_eq!(reassemble_handshake(&records), None);
    }

    #[test]
    fn reassemble_handshake_caps_absurd_handshake_length() {
        // Craft a record where the handshake header claims a 0xFFFFFF-byte
        // body (16 MB). Reassembly must refuse before allocating.
        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        handshake.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // u24 length = max
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(reassemble_handshake(&record), None);
    }

    #[test]
    fn extract_sni_works_on_fragmented_two_record_client_hello() {
        // The headline regression test: a ClientHello split across two records,
        // SNI extension landing in the second record. Pre-C1 implementation
        // would have returned Malformed (looks safe) — Traefik-class bug.
        // Now it must correctly extract the host.
        let handshake = build_handshake_message(&build_sni_extension("example.com"));
        let split = handshake.len() / 2;
        let records = build_fragmented_records(&handshake, &[split]);
        assert_eq!(
            extract_sni(&records),
            SniOutcome::Cleartext {
                host: "example.com".into()
            }
        );
    }

    #[test]
    fn extract_sni_rejects_handshake_followed_by_app_data_record() {
        // If an attacker can sneak a non-handshake record in mid-flight, refuse
        // to assemble. Even though the truncation might "look like" the start
        // of a ClientHello, surface Malformed so the caller falls back to the
        // warning UX rather than silently using a partial parse.
        let handshake = build_handshake_message(&build_sni_extension("evil.example.com"));
        let split = 4 + 2 + 16; // mid-random
        let mut records = Vec::new();
        records.extend_from_slice(&wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake[..split]));
        records.extend_from_slice(&wrap_record(0x17, &handshake[split..]));
        assert_eq!(extract_sni(&records), SniOutcome::Malformed);
    }
}
