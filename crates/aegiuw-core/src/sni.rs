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
//! ## SSL 2.0 ClientHello (legacy, never accepted)
//!
//! SSL 2.0 had a fundamentally different ClientHello layout — a record header
//! whose first byte has the high bit set (`0x80`/`0x82`) and a `msg_type=0x01`
//! at byte `[2]`. The first byte therefore doesn't match
//! [`CONTENT_TYPE_HANDSHAKE`] (`22 = 0x16`), so the parser immediately rejects
//! these as [`SniOutcome::Malformed`]. SSL 2.0 had no SNI extension anyway
//! and is forbidden by RFC 6176; we keep no special variant for it. Vintage
//! probing tools still send this shape — the test suite pins the rejection.
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
//! - **DTLS** (UDP-framed TLS, RFC 9147): out of scope — the QUIC parser
//!   (Layer 1 sibling) handles UDP-based encrypted transports separately.
//!   DTLS records share the leading `content_type=22` byte with TLS but have
//!   a different 13-byte header (version + epoch + sequence + length) and
//!   a 12-byte handshake-fragment header — so DTLS bytes happen to fail one
//!   of our subsequent checks (record-length-mismatch, wrong handshake type,
//!   or wrong `legacy_version`) and surface as [`SniOutcome::Malformed`].
//!   This is *incidental* rejection rather than explicit DTLS detection;
//!   the test suite pins it so the failure mode can't drift. (SNI backlog C14.)
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

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Extension type for `server_name` (RFC 6066 §3).
pub const EXT_SERVER_NAME: u16 = 0x0000;

/// Extension type for `encrypted_client_hello` (draft-ietf-tls-esni, IANA).
pub const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// Extension type for `pre_shared_key` (RFC 8446 §4.2.11). The spec requires
/// this to be the **last** extension in any ClientHello that uses it; a CH
/// where another extension follows `pre_shared_key` is malformed.
pub const EXT_PRE_SHARED_KEY: u16 = 0x0029;

/// TLS record content type for handshake messages.
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// Handshake type for ClientHello.
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// NameType value for `host_name` inside a ServerName (RFC 6066 §3).
const NAME_TYPE_HOST_NAME: u8 = 0;

/// The wire value a TLS 1.2 *or* 1.3 ClientHello MUST carry in its
/// `legacy_version` field (RFC 8446 §4.1.2). TLS 1.3 uses the
/// `supported_versions` extension for actual negotiation; the legacy field is
/// pinned to 0x0303 to dodge "version intolerance" middleboxes.
///
/// SSL 3.0 (`0x0300`), TLS 1.0 (`0x0301`), and TLS 1.1 (`0x0302`) are
/// deprecated by RFC 8996. A `legacy_version > 0x0303` (e.g. the literal
/// `0x0304`) is an implementation bug per RFC 8446 §4.1.2.
pub const TLS_LEGACY_VERSION: u16 = 0x0303;

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

/// Verify that the SNI in a ClientHello sent *after* a HelloRetryRequest
/// matches the SNI in the first ClientHello, as required by RFC 8446 §4.1.4.
///
/// Returns `Some(true)` if both inputs extract to the same `Cleartext { host }`,
/// `Some(false)` if they extract *different* hosts, and `None` when either
/// side wasn't a clean `Cleartext` outcome — `ECH`, `NotFound`, or `Malformed`
/// either side makes the comparison meaningless and the caller should fall
/// back to whatever the original isolate-vs-native decision was.
///
/// This is a stateless helper; the daemon is responsible for *identifying*
/// the second ClientHello in a given connection (a HelloRetryRequest came
/// between them) and passing both blobs here.
///
/// # Examples
///
/// ```
/// use aegiuw_core::{hrr_sni_consistent, SniOutcome, extract_sni};
///
/// // Two empty inputs are both Malformed, so the comparison is meaningless.
/// assert_eq!(hrr_sni_consistent(&[], &[]), None);
///
/// // Identical inputs that both parse cleanly return Some(true)/(false) only
/// // when both extract to Cleartext.
/// assert_eq!(extract_sni(&[]), SniOutcome::Malformed);
/// ```
pub fn hrr_sni_consistent(first: &[u8], second: &[u8]) -> Option<bool> {
    match (extract_sni(first), extract_sni(second)) {
        (SniOutcome::Cleartext { host: a }, SniOutcome::Cleartext { host: b }) => Some(a == b),
        _ => None,
    }
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
    //
    // RFC 8446 §4.1.2: a TLS 1.2 or 1.3 ClientHello MUST set legacy_version =
    // 0x0303. SSL 3.0, TLS 1.0, and TLS 1.1 are deprecated by RFC 8996 — any
    // such wire value means we're looking at obsolete or hostile traffic and
    // should refuse to extract a fork decision from it. SNI backlog C5.
    if c.read_u16()? != TLS_LEGACY_VERSION {
        return Some(SniOutcome::Malformed);
    }
    c.read_slice(32)?; // random

    // RFC 8446 §4.1.2: `legacy_session_id<0..32>` — at most 32 bytes. A
    // longer session_id is either a malformed sender or an attacker abusing
    // the u8 length prefix's 0–255 range. SNI backlog C8.
    let session_id = c.read_u8_prefixed()?;
    if session_id.len() > 32 {
        return Some(SniOutcome::Malformed);
    }

    // RFC 8446 §4.1.2: `cipher_suites<2..2^16-2>` — at least one suite, and
    // each suite is exactly 2 bytes. An empty list or an odd byte count is a
    // spec violation (and a strong signal of a malformed/probe handshake).
    // SNI backlog C7.
    let cipher_suites = c.read_u16_prefixed()?;
    if cipher_suites.is_empty() || cipher_suites.len() % 2 != 0 {
        return Some(SniOutcome::Malformed);
    }

    // RFC 8446 §4.1.2: a TLS 1.3 ClientHello MUST list a single null
    // compression method. Older TLS allowed deflate too, but the CRIME
    // attack (CVE-2012-4929) means a sender claiming non-null compression
    // alongside null is either obsolete or hostile. The lenient bar from
    // the backlog (C6) is "MUST contain null(0)"; an empty list or a list
    // of only non-null methods is rejected.
    let compression = c.read_u8_prefixed()?;
    if !compression.contains(&0) {
        return Some(SniOutcome::Malformed);
    }

    // ── Extensions ─────────────────────────────────────────────────────────
    //
    // We read exactly `extensions_len` bytes and never look at the cursor
    // again. Any bytes after the extensions block (still inside the handshake
    // body) are ignored — RFC 8446 §4 leaves room for additional fields
    // ("clients MUST send anything not understood as unknown extensions"),
    // and conventional TLS servers MUST ignore trailing bytes rather than
    // reject. SNI backlog C9.
    let extensions = c.read_u16_prefixed()?;

    // Scan ALL extensions before deciding: ECH wins over any visible SNI, so
    // we must look at every extension even after spotting a server_name entry.
    let mut ech_present = false;
    let mut sni_host: Option<String> = None;
    let mut ext = Cursor::new(extensions);

    // RFC 8446 §4.2: "There MUST NOT be more than one extension of the same
    // type in a given extension block." Track every type we've already seen so
    // we can refuse repeats — this single check addresses both the duplicate
    // `server_name` case (SNI backlog C3, RFC 6066) and the duplicate
    // `encrypted_client_hello` case (C4) in one place. A small `Vec` is faster
    // than a `HashSet` for the realistic ~15–20 extension count per CH.
    let mut seen_ext_types: Vec<u16> = Vec::new();
    // RFC 8446 §4.2.11: pre_shared_key MUST be the last extension. If we've
    // already seen one and we're about to read another, that's a violation.
    // SNI backlog C11.
    let mut psk_seen = false;

    while ext.remaining() >= 4 {
        if psk_seen {
            // Any extension after pre_shared_key violates the "MUST be last"
            // rule. Refuse the whole ClientHello.
            return Some(SniOutcome::Malformed);
        }
        let ext_type = ext.read_u16()?;
        let ext_data = ext.read_u16_prefixed()?;

        if seen_ext_types.contains(&ext_type) {
            return Some(SniOutcome::Malformed);
        }
        seen_ext_types.push(ext_type);
        if ext_type == EXT_PRE_SHARED_KEY {
            psk_seen = true;
        }

        match ext_type {
            EXT_ENCRYPTED_CLIENT_HELLO => {
                ech_present = true;
            }
            EXT_SERVER_NAME => {
                match parse_server_name_extension(ext_data) {
                    ServerNameOutcome::Host(host) => {
                        sni_host = Some(host);
                    }
                    ServerNameOutcome::Skip => {
                        // Well-formed extension but no usable host_name (e.g.
                        // first entry was a non-host_name name_type, or its
                        // payload wasn't valid UTF-8 ASCII). Other extensions
                        // (e.g. ECH) may still apply.
                    }
                    ServerNameOutcome::Malformed => {
                        // RFC violation inside the extension itself (e.g. two
                        // `host_name` entries in the same ServerNameList,
                        // truncated length prefix). Reject the whole CH.
                        return Some(SniOutcome::Malformed);
                    }
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

/// Result of parsing one `server_name` extension's body.
///
/// Distinguishing the three states matters: `Skip` lets the caller keep
/// scanning other extensions (so a non-`host_name` entry doesn't break ECH
/// detection), while `Malformed` propagates as `SniOutcome::Malformed` — the
/// failure-closed signal for clear RFC violations.
enum ServerNameOutcome {
    /// Successfully extracted a `host_name` entry.
    Host(String),
    /// Well-formed extension but no usable host: empty list, first entry was
    /// a non-`host_name` name_type, or the host bytes weren't valid UTF-8
    /// ASCII (RFC 6066 forbids non-ASCII anyway).
    Skip,
    /// Spec violation that should reject the whole ClientHello — e.g. two
    /// `host_name` entries in the same ServerNameList (RFC 6066 §3
    /// "MUST NOT contain more than one name of the same name_type") or a
    /// length prefix that overruns its payload.
    Malformed,
}

/// Parse the body of a `server_name` extension (RFC 6066 §3) into a
/// [`ServerNameOutcome`].
///
/// We consume the *first* ServerName entry. Then, before returning, we peek
/// at the next byte to detect a duplicate `host_name(0)` entry — the
/// RFC 6066 §3 "MUST NOT contain more than one name of the same name_type"
/// violation. Subsequent entries with non-host_name types are ignored
/// (their structure is undefined — we can't safely walk past them but we
/// don't reject either).
fn parse_server_name_extension(data: &[u8]) -> ServerNameOutcome {
    let mut c = Cursor::new(data);
    let Some(list) = c.read_u16_prefixed() else {
        return ServerNameOutcome::Malformed;
    };
    let mut entries = Cursor::new(list);

    if entries.remaining() < 3 {
        // RFC 6066 §3 defines `ServerNameList<1..2^16-1>` — non-empty by type
        // construction. An empty list, or a list too short to contain even one
        // ServerName entry (name_type + u16 host_len + 0 bytes = 3), is a
        // clear spec violation; refuse the whole ClientHello. SNI backlog C10.
        return ServerNameOutcome::Malformed;
    }

    let Some(name_type) = entries.read_u8() else {
        return ServerNameOutcome::Malformed;
    };
    if name_type != NAME_TYPE_HOST_NAME {
        return ServerNameOutcome::Skip;
    }
    let Some(host) = entries.read_u16_prefixed() else {
        return ServerNameOutcome::Malformed;
    };
    let Ok(host_str) = core::str::from_utf8(host) else {
        // RFC 6066: HostName is ASCII. Non-UTF-8 is illegal but we treat it
        // as "no usable host" rather than reject, to match existing behavior
        // and avoid being more strict than necessary on garbage payloads.
        return ServerNameOutcome::Skip;
    };

    // RFC 6066 §3: HostName is defined as `opaque HostName<1..2^16-1>` —
    // the type itself requires a non-empty byte string. An empty host_name
    // is a clear spec violation; refuse the whole ClientHello so callers
    // route to the warning UX rather than try to match "" against the
    // allow-cache. SNI backlog H2.
    if host_str.is_empty() {
        return ServerNameOutcome::Malformed;
    }

    // RFC 1035 §2.3.4 / §3.1: DNS hostnames have a 253-octet presentation-form
    // ceiling (255 octets on the wire minus the leading length byte and the
    // final terminator), and each label is bounded to 63 octets. Anything
    // larger is either a typo, a misconfigured client, or an attacker
    // probing for length-handling bugs. SNI backlog H3.
    const MAX_HOSTNAME_LEN: usize = 253;
    const MAX_LABEL_LEN: usize = 63;
    if host_str.len() > MAX_HOSTNAME_LEN {
        return ServerNameOutcome::Malformed;
    }
    if host_str.split('.').any(|label| label.len() > MAX_LABEL_LEN) {
        return ServerNameOutcome::Malformed;
    }

    // RFC 6066 §3: "Literal IPv4 and IPv6 addresses are not permitted in
    // HostName." SNI backlog H1. We use Rust's `IpAddr::from_str` because
    // it handles every legal IPv4/IPv6 textual form (dotted quad, full and
    // compressed IPv6, IPv4-mapped IPv6, etc.) — far more accurate than a
    // regex would be. Bracket-wrapped forms (`[::1]`) fail to parse and
    // fall through; they're degenerate non-hostnames the upstream allowlist
    // will reject anyway.
    if host_str.parse::<IpAddr>().is_ok() {
        return ServerNameOutcome::Malformed;
    }

    // Peek for a duplicate host_name(0) after the one we just extracted.
    if let Some(next_type) = entries.read_u8() {
        if next_type == NAME_TYPE_HOST_NAME {
            return ServerNameOutcome::Malformed;
        }
        // Any other subsequent entry has undefined structure; we accept the
        // host we already extracted and stop scanning the list.
    }

    ServerNameOutcome::Host(host_str.to_string())
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

    /// Default cipher_suites used by every wrapper that doesn't override it.
    const DEFAULT_CIPHER_SUITES: &[u8] = &[0x13, 0x01]; // TLS_AES_128_GCM_SHA256

    /// Build the handshake-message bytes (HandshakeType + u24 length + body).
    /// Uses spec-compliant defaults across every knob.
    fn build_handshake_message(extensions: &[u8]) -> Vec<u8> {
        build_handshake_message_custom(
            extensions,
            TLS_LEGACY_VERSION,
            &[],
            DEFAULT_CIPHER_SUITES,
            &[0x00],
        )
    }

    /// Build with a custom `legacy_version` (C5 tests).
    fn build_handshake_message_with_version(extensions: &[u8], legacy_version: u16) -> Vec<u8> {
        build_handshake_message_custom(
            extensions,
            legacy_version,
            &[],
            DEFAULT_CIPHER_SUITES,
            &[0x00],
        )
    }

    /// Build with custom `compression_methods` (C6 tests).
    fn build_handshake_message_with_compression(
        extensions: &[u8],
        compression_methods: &[u8],
    ) -> Vec<u8> {
        build_handshake_message_custom(
            extensions,
            TLS_LEGACY_VERSION,
            &[],
            DEFAULT_CIPHER_SUITES,
            compression_methods,
        )
    }

    /// Build with custom `cipher_suites` (C7 tests).
    fn build_handshake_message_with_cipher_suites(
        extensions: &[u8],
        cipher_suites: &[u8],
    ) -> Vec<u8> {
        build_handshake_message_custom(extensions, TLS_LEGACY_VERSION, &[], cipher_suites, &[0x00])
    }

    /// Build with custom `legacy_session_id` (C8 tests). The u8 length prefix
    /// is computed from the slice — pass 33 bytes to exercise the >32 boundary.
    fn build_handshake_message_with_session_id(extensions: &[u8], session_id: &[u8]) -> Vec<u8> {
        build_handshake_message_custom(
            extensions,
            TLS_LEGACY_VERSION,
            session_id,
            DEFAULT_CIPHER_SUITES,
            &[0x00],
        )
    }

    /// Parameter order tracks the wire layout (version → session_id →
    /// cipher_suites → compression → extensions) so the function reads in
    /// the same order as the bytes it produces.
    fn build_handshake_message_custom(
        extensions: &[u8],
        legacy_version: u16,
        session_id: &[u8],
        cipher_suites: &[u8],
        compression_methods: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&legacy_version.to_be_bytes());
        body.extend_from_slice(&[0xAA; 32]); // random
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
        body.extend_from_slice(cipher_suites);
        body.push(compression_methods.len() as u8);
        body.extend_from_slice(compression_methods);
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

    /// Build a `server_name` extension whose ServerNameList contains every
    /// host_name in `hosts`. Used to construct the
    /// "two-host_names-in-one-list" RFC 6066 §3 violation fixture.
    fn build_sni_extension_with_hosts(hosts: &[&str]) -> Vec<u8> {
        let mut entries = Vec::new();
        for h in hosts {
            let b = h.as_bytes();
            entries.push(NAME_TYPE_HOST_NAME);
            entries.extend_from_slice(&(b.len() as u16).to_be_bytes());
            entries.extend_from_slice(b);
        }
        let mut list = Vec::new();
        list.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        list.extend_from_slice(&entries);
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
        ext
    }

    /// Build an arbitrary extension by type and payload.
    fn build_extension(ext_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&ext_type.to_be_bytes());
        ext.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        ext.extend_from_slice(payload);
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
    fn non_utf8_host_yields_not_found_not_malformed() {
        // RFC 6066: HostName is ASCII. A non-UTF-8 byte sequence is technically
        // a spec violation, but we *don't* upgrade it to Malformed — pragmatic
        // leniency: garbage payload is treated as "no usable host" so other
        // extensions (e.g. ECH) can still be observed.
        //
        // Fixture geometry — be precise so the length prefixes don't have a
        // hidden second malformation:
        //   ext_data_length = 8 (list_len_prefix=2 + list=6)
        //   list_len = 6 (entry = name_type=1 + host_len_prefix=2 + host=3)
        //   entry: name_type=0, host_len=3, host bytes = 0xff 0xfe 0xfd
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        ext.extend_from_slice(&[
            0x00, 0x08, // ext_data_length = 8
            0x00, 0x06, // list_len = 6
            0x00, // name_type = host_name(0)
            0x00, 0x03, // host_len = 3
            0xff, 0xfe, 0xfd, // non-UTF-8 host bytes
        ]);
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

    // ── DNS length bounds (H3, RFC 1035 §2.3.4 / §3.1) ───────────────────────

    #[test]
    fn rejects_hostname_longer_than_253_bytes() {
        // Construct a 254-byte hostname out of single-char labels so the
        // total-length rule fires rather than the label-length rule:
        //   "a." repeated 126 times = 252 chars, plus "aa" = 254 chars total.
        // Each label is ≤ 2 chars (well under the 63-byte label cap).
        let mut host = "a.".repeat(126);
        host.push_str("aa");
        assert_eq!(host.len(), 254);
        let bytes = build_client_hello(&build_sni_extension(&host));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn accepts_hostname_at_253_byte_boundary() {
        // 253 bytes is the spec maximum and a common ceiling in real DNS.
        let mut host = "a.".repeat(126);
        host.push('a');
        assert_eq!(host.len(), 253);
        let bytes = build_client_hello(&build_sni_extension(&host));
        assert_eq!(extract_sni(&bytes), SniOutcome::Cleartext { host });
    }

    #[test]
    fn rejects_label_longer_than_63_bytes() {
        // 64-char label embedded in an otherwise tiny hostname — label rule
        // must fire even when the total stays well under 253.
        let label = "a".repeat(64);
        let host = format!("{label}.example.com");
        let bytes = build_client_hello(&build_sni_extension(&host));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn accepts_label_at_63_byte_boundary() {
        // 63 bytes is the spec maximum for a single label (RFC 1035 §2.3.4).
        let label = "a".repeat(63);
        let host = format!("{label}.example.com");
        let bytes = build_client_hello(&build_sni_extension(&host));
        assert_eq!(extract_sni(&bytes), SniOutcome::Cleartext { host });
    }

    // ── Empty-hostname rejection (H2, RFC 6066 §3) ───────────────────────────

    #[test]
    fn rejects_empty_host_name() {
        // RFC 6066 §3 defines `HostName<1..2^16-1>` — at least one byte. A
        // host_name with length-prefix=0 is malformed by the type itself.
        let bytes = build_client_hello(&build_sni_extension(""));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn accepts_single_character_hostname() {
        // Positive control: a 1-byte host is the spec minimum and must not
        // be confused with the empty case. Future H3 (length bounds) won't
        // change this — labels up to 63 bytes are legal.
        let bytes = build_client_hello(&build_sni_extension("a"));
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext { host: "a".into() }
        );
    }

    // ── Numeric-IP SNI rejection (H1, RFC 6066 §3) ───────────────────────────

    #[test]
    fn rejects_ipv4_literal_as_sni() {
        // RFC 6066 §3: "Literal IPv4 and IPv6 addresses are not permitted in
        // HostName." A bare dotted quad is the most common violation we'd
        // expect from non-browser clients.
        let bytes = build_client_hello(&build_sni_extension("192.168.1.1"));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_ipv4_public_literal_as_sni() {
        // Same rule for public IPs — the protocol doesn't care which range.
        let bytes = build_client_hello(&build_sni_extension("8.8.8.8"));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_ipv6_loopback_as_sni() {
        // Compressed IPv6 form "::1" — loopback.
        let bytes = build_client_hello(&build_sni_extension("::1"));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_ipv6_documentation_range_as_sni() {
        // The RFC 3849 documentation range, conventional in tests.
        let bytes = build_client_hello(&build_sni_extension("2001:db8::1"));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6_as_sni() {
        // IPv4-mapped IPv6 (::ffff:a.b.c.d) is still an IP literal.
        let bytes = build_client_hello(&build_sni_extension("::ffff:192.168.1.1"));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn accepts_hostname_that_starts_with_digits() {
        // Sanity: "1.example.com" looks vaguely numeric but is a perfectly
        // legal DNS hostname — must not be rejected by the IP check.
        let bytes = build_client_hello(&build_sni_extension("1.example.com"));
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext {
                host: "1.example.com".into()
            }
        );
    }

    #[test]
    fn accepts_hostname_with_three_dots_but_not_four_octets() {
        // "1.2.3" (three dots, three components) parses as neither a valid
        // IPv4 nor a typical DNS name — it's a fragment. `IpAddr::from_str`
        // rejects it, so we fall through to the hostname path and accept it
        // as-is (the upstream allowlist will be the gate on whether it's
        // actually a recognized domain).
        let bytes = build_client_hello(&build_sni_extension("1.2.3.4.example.com"));
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext {
                host: "1.2.3.4.example.com".into()
            }
        );
    }

    // ── DTLS bytes rejection (C14, RFC 9147, out-of-scope by design) ─────────

    #[test]
    fn dtls_1_2_record_is_rejected_as_malformed() {
        // DTLS 1.2 record layout: content_type | version(2) | epoch(2) |
        // sequence(6) | length(2). Shares the leading 0x16 byte with TLS but
        // the bytes that follow don't match our subsequent expectations
        // (legacy_version != 0x0303, or the handshake-type byte falls into
        // the middle of the epoch/sequence field). Either way → Malformed.
        let dtls = [
            0x16, // content_type = handshake
            0xfe, 0xfd, // version = DTLS 1.2
            0x00, 0x01, // epoch = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence
            0x00, 0x10, // length = 16
            0x01, // looks like client_hello type byte…
            0x00, 0x00, 0x0C, // u24 length (12)
            // body that won't pass our legacy_version == 0x0303 check:
            0xfe, 0xfd, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        ];
        assert_eq!(extract_sni(&dtls), SniOutcome::Malformed);
    }

    #[test]
    fn dtls_1_3_unified_header_is_rejected_as_malformed() {
        // DTLS 1.3 introduces a "unified" record header whose first byte has
        // distinctive top bits (0b001_xxxxx) — for the purpose of this
        // rejection test, anything that doesn't equal CONTENT_TYPE_HANDSHAKE
        // is enough. We use the canonical short-header pattern 0x2F.
        let dtls13 = [0x2F, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(extract_sni(&dtls13), SniOutcome::Malformed);
    }

    // ── SSL 2.0 ClientHello rejection (C13, RFC 6176) ────────────────────────

    #[test]
    fn rejects_ssl_2_0_short_format_client_hello() {
        // Classic SSL 2.0 short-form ClientHello header:
        //   byte[0]: 0x80 + msg_length_hi (high bit set indicates 2-byte length, no padding)
        //   byte[1]: msg_length_lo
        //   byte[2]: msg_type = 0x01 (CLIENT-HELLO)
        //   byte[3..5]: version = 0x0002 (SSL 2.0)
        // Our content-type check at byte[0] != 0x16 immediately rejects.
        // RFC 6176 prohibits SSL 2.0 anyway.
        let ssl2 = [
            0x80, 0x2E, // 2-byte length, high bit set
            0x01, // CLIENT-HELLO
            0x00, 0x02, // version = SSL 2.0
            0x00, 0x18, // cipher-spec-length
            0x00, 0x00, // session-id-length
            0x00, 0x10, // challenge-length
        ];
        assert_eq!(extract_sni(&ssl2), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_ssl_2_0_long_format_client_hello() {
        // SSL 2.0 long-form (3-byte length) variant: byte[0] high bit clear,
        // but the first byte is still 0x00..=0x3F (record-length high), not 0x16.
        let ssl2 = [
            0x00, 0x00, 0x2E, // 3-byte length
            0x01, // CLIENT-HELLO
            0x00, 0x02, // version = SSL 2.0
        ];
        assert_eq!(extract_sni(&ssl2), SniOutcome::Malformed);
    }

    // ── HRR SNI consistency (C12, RFC 8446 §4.1.4) ───────────────────────────

    #[test]
    fn hrr_sni_consistent_matches_identical_hosts() {
        let a = build_client_hello(&build_sni_extension("example.com"));
        let b = build_client_hello(&build_sni_extension("example.com"));
        assert_eq!(hrr_sni_consistent(&a, &b), Some(true));
    }

    #[test]
    fn hrr_sni_consistent_flags_changed_host() {
        // RFC 8446 §4.1.4: the second ClientHello MUST carry the same SNI.
        // A changed host means either a buggy client or a stitched-together
        // attack.
        let a = build_client_hello(&build_sni_extension("first.example.com"));
        let b = build_client_hello(&build_sni_extension("second.example.com"));
        assert_eq!(hrr_sni_consistent(&a, &b), Some(false));
    }

    #[test]
    fn hrr_sni_consistent_returns_none_when_either_side_is_not_cleartext() {
        // ECH on one side: we can't tell what the real SNI was, so the
        // comparison is meaningless (None) — caller falls back to the
        // standalone outcome of each parse.
        let mut a_exts = build_sni_extension("example.com");
        a_exts.extend_from_slice(&build_ech_extension());
        let a = build_client_hello(&a_exts);
        let b = build_client_hello(&build_sni_extension("example.com"));
        assert_eq!(hrr_sni_consistent(&a, &b), None);

        // Malformed on either side: also None.
        assert_eq!(hrr_sni_consistent(&[], &b), None);
        assert_eq!(hrr_sni_consistent(&b, &[]), None);
    }

    // ── pre_shared_key position rule (C11, RFC 8446 §4.2.11) ─────────────────

    /// Build a minimal `pre_shared_key` extension. The payload is opaque to
    /// our parser; only the type and ordering matter.
    fn build_psk_extension() -> Vec<u8> {
        let payload = [0x00, 0x04, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x21, 0xBB]; // arbitrary
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_PRE_SHARED_KEY.to_be_bytes());
        ext.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        ext.extend_from_slice(&payload);
        ext
    }

    #[test]
    fn rejects_pre_shared_key_followed_by_another_extension() {
        // PSK before SNI: violates "MUST be last." Other extensions appearing
        // after PSK must reject the whole ClientHello.
        let mut extensions = build_psk_extension();
        extensions.extend_from_slice(&build_sni_extension("example.com"));
        let bytes = build_client_hello(&extensions);
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn accepts_pre_shared_key_as_last_extension() {
        // SNI first, PSK last — the legal ordering. Parser must accept and
        // continue to extract the SNI correctly.
        let mut extensions = build_sni_extension("example.com");
        extensions.extend_from_slice(&build_psk_extension());
        let bytes = build_client_hello(&extensions);
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext {
                host: "example.com".into()
            }
        );
    }

    #[test]
    fn accepts_pre_shared_key_as_only_extension() {
        // PSK with nothing else: parses successfully, no SNI → NotFound.
        let extensions = build_psk_extension();
        let bytes = build_client_hello(&extensions);
        assert_eq!(extract_sni(&bytes), SniOutcome::NotFound);
    }

    // ── Empty ServerNameList rejection (C10, RFC 6066 §3) ────────────────────

    #[test]
    fn rejects_server_name_extension_with_empty_list() {
        // ServerNameList<1..2^16-1> requires at least one entry; an explicit
        // empty list (list_length = 0) is malformed.
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        ext.extend_from_slice(&[0x00, 0x02]); // ext_data_length = 2 (just the list-length prefix)
        ext.extend_from_slice(&[0x00, 0x00]); // ServerNameList length = 0 (empty)
        let bytes = build_client_hello(&ext);
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_server_name_extension_with_one_byte_list() {
        // Too short to contain even one entry header (1 byte instead of >= 3).
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        ext.extend_from_slice(&[0x00, 0x03]); // ext_data_length = 3
        ext.extend_from_slice(&[0x00, 0x01]); // list_length = 1
        ext.extend_from_slice(&[0x00]); // garbage 1-byte entry
        let bytes = build_client_hello(&ext);
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

    // ── Trailing-bytes tolerance (C9, RFC 8446 §4) ───────────────────────────

    /// Local fixture: build a ClientHello whose handshake body has extra bytes
    /// after the extensions block. body_len includes those bytes; the parser
    /// must ignore them rather than reject.
    fn build_handshake_with_trailing_body_bytes(extensions: &[u8], trailing: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&TLS_LEGACY_VERSION.to_be_bytes());
        body.extend_from_slice(&[0xAA; 32]);
        body.push(0); // session_id len = 0
        body.extend_from_slice(&(DEFAULT_CIPHER_SUITES.len() as u16).to_be_bytes());
        body.extend_from_slice(DEFAULT_CIPHER_SUITES);
        body.push(1);
        body.push(0); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        body.extend_from_slice(trailing); // ← the point of this fixture

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let body_len = body.len() as u32;
        handshake.push(((body_len >> 16) & 0xff) as u8);
        handshake.push(((body_len >> 8) & 0xff) as u8);
        handshake.push((body_len & 0xff) as u8);
        handshake.extend_from_slice(&body);
        handshake
    }

    #[test]
    fn tolerates_trailing_bytes_after_extensions_block() {
        // 4 bytes of garbage tacked onto the body after the extensions block.
        // Servers MUST ignore these; we must too — refusing would be over-
        // strict against legitimate-but-padded ClientHellos.
        let handshake = build_handshake_with_trailing_body_bytes(
            &build_sni_extension("example.com"),
            &[0xDE, 0xAD, 0xBE, 0xEF],
        );
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(
            extract_sni(&record),
            SniOutcome::Cleartext {
                host: "example.com".into()
            }
        );
    }

    #[test]
    fn tolerates_zero_padding_after_extensions_block() {
        // Some implementations pad with zero bytes; pin that this still parses.
        let handshake = build_handshake_with_trailing_body_bytes(
            &build_sni_extension("padded.example.com"),
            &[0x00; 16],
        );
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(
            extract_sni(&record),
            SniOutcome::Cleartext {
                host: "padded.example.com".into()
            }
        );
    }

    // ── session_id validation (C8, RFC 8446 §4.1.2) ──────────────────────────

    #[test]
    fn rejects_session_id_longer_than_32_bytes() {
        // `legacy_session_id<0..32>` — 33 bytes is outside the spec range. The
        // u8 length prefix happily encodes anything up to 255, so this only
        // gets caught by an explicit length check.
        let handshake = build_handshake_message_with_session_id(&[], &[0xBB; 33]);
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(extract_sni(&record), SniOutcome::Malformed);
    }

    #[test]
    fn accepts_session_id_at_32_byte_boundary() {
        // 32 bytes is the spec maximum and a common length for legitimate
        // session resumption — positive control on the inclusive upper bound.
        let handshake = build_handshake_message_with_session_id(
            &build_sni_extension("example.com"),
            &[0xCC; 32],
        );
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(
            extract_sni(&record),
            SniOutcome::Cleartext {
                host: "example.com".into()
            }
        );
    }

    // ── cipher_suites validation (C7, RFC 8446 §4.1.2) ───────────────────────

    #[test]
    fn rejects_empty_cipher_suites_list() {
        // `cipher_suites<2..2^16-2>` — at least one 2-byte suite is required.
        let handshake = build_handshake_message_with_cipher_suites(&[], &[]);
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(extract_sni(&record), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_odd_length_cipher_suites_list() {
        // Each cipher suite is exactly 2 bytes; an odd-byte list means the
        // sender's length prefix or contents are corrupt.
        let handshake = build_handshake_message_with_cipher_suites(&[], &[0x13, 0x01, 0x13]);
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(extract_sni(&record), SniOutcome::Malformed);
    }

    #[test]
    fn accepts_multiple_cipher_suites() {
        // Positive control: three suites (6 bytes) — TLS_AES_128_GCM_SHA256,
        // TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.
        let handshake = build_handshake_message_with_cipher_suites(
            &build_sni_extension("example.com"),
            &[0x13, 0x01, 0x13, 0x02, 0x13, 0x03],
        );
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(
            extract_sni(&record),
            SniOutcome::Cleartext {
                host: "example.com".into()
            }
        );
    }

    // ── legacy_version validation (C5, RFC 8446 §4.1.2, RFC 8996) ────────────

    #[test]
    fn rejects_legacy_version_tls_1_0() {
        // TLS 1.0 (0x0301) is deprecated by RFC 8996 and not a valid
        // legacy_version per RFC 8446 §4.1.2.
        let handshake = build_handshake_message_with_version(&[], 0x0301);
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(extract_sni(&record), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_legacy_version_tls_1_1() {
        // TLS 1.1 (0x0302) is also deprecated by RFC 8996.
        let handshake = build_handshake_message_with_version(&[], 0x0302);
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(extract_sni(&record), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_legacy_version_ssl_3_0() {
        // SSL 3.0 (0x0300) was already deprecated by RFC 7568 (2015).
        let handshake = build_handshake_message_with_version(&[], 0x0300);
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(extract_sni(&record), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_legacy_version_above_tls_1_2() {
        // RFC 8446 §4.1.2 explicitly forbids `legacy_version > 0x0303`. A
        // ClientHello with 0x0304 in the legacy field is a buggy or hostile
        // sender; the real version negotiation lives in `supported_versions`.
        let handshake = build_handshake_message_with_version(&[], 0x0304);
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(extract_sni(&record), SniOutcome::Malformed);
    }

    #[test]
    fn accepts_legacy_version_0x0303() {
        // Positive control: the one legal value still parses successfully.
        let handshake = build_handshake_message_with_version(
            &build_sni_extension("example.com"),
            TLS_LEGACY_VERSION,
        );
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(
            extract_sni(&record),
            SniOutcome::Cleartext {
                host: "example.com".into()
            }
        );
    }

    // ── compression_methods validation (C6, RFC 8446 §4.1.2) ─────────────────

    #[test]
    fn rejects_compression_methods_without_null() {
        // Only deflate (0x01), no null — TLS 1.3 says MUST be exactly [0x00],
        // and even legacy senders include null. A list without null is
        // either CRIME-attack-vintage or hostile.
        let handshake = build_handshake_message_with_compression(&[], &[0x01]);
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(extract_sni(&record), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_empty_compression_methods() {
        // RFC 8446 §4.1.2 requires exactly one byte (null). Empty list is
        // both spec-violating and a degenerate sentinel — refuse.
        let handshake = build_handshake_message_with_compression(&[], &[]);
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(extract_sni(&record), SniOutcome::Malformed);
    }

    #[test]
    fn accepts_legacy_compression_with_null_present() {
        // A legacy TLS 1.2 client offering [deflate, null] meets the "MUST
        // contain null" bar. TLS 1.3 senders never send this, but accepting
        // it keeps the parser tolerant of older traffic that still includes
        // a fallback path to the (mandatory) null method.
        let handshake = build_handshake_message_with_compression(
            &build_sni_extension("example.com"),
            &[0x01, 0x00],
        );
        let record = wrap_record(CONTENT_TYPE_HANDSHAKE, &handshake);
        assert_eq!(
            extract_sni(&record),
            SniOutcome::Cleartext {
                host: "example.com".into()
            }
        );
    }

    // ── Duplicate-extension rejection (C3 + C4, RFC 8446 §4.2, RFC 6066 §3) ──

    #[test]
    fn rejects_two_server_name_extensions_in_one_client_hello() {
        // RFC 8446 §4.2: no duplicate extension types. Pre-C3 this silently
        // ignored the second.
        let mut extensions = build_sni_extension("first.example.com");
        extensions.extend_from_slice(&build_sni_extension("second.example.com"));
        let bytes = build_client_hello(&extensions);
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_two_host_name_entries_inside_one_server_name() {
        // RFC 6066 §3: ServerNameList MUST NOT contain more than one name of
        // the same name_type. Pre-C3 we kept only the first host_name and
        // silently dropped the second.
        let extensions =
            build_sni_extension_with_hosts(&["first.example.com", "second.example.com"]);
        let bytes = build_client_hello(&extensions);
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_two_encrypted_client_hello_extensions() {
        // Same RFC 8446 §4.2 rule, applied to ECH. Closes C4 alongside C3
        // via the shared "no duplicate ext types" check.
        let mut extensions = build_ech_extension();
        extensions.extend_from_slice(&build_ech_extension());
        let bytes = build_client_hello(&extensions);
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_two_duplicate_unknown_extensions() {
        // RFC 8446 §4.2 applies to every extension type, not just the ones we
        // care about. A duplicate of an unknown type is still a malformed
        // ClientHello.
        let mut extensions = build_extension(0x0050, &[0xAA, 0xBB]);
        extensions.extend_from_slice(&build_extension(0x0050, &[0xCC, 0xDD]));
        // Add a real SNI extension too so the test is unambiguous: if dup
        // detection weren't firing, we'd see Cleartext instead of Malformed.
        extensions.extend_from_slice(&build_sni_extension("legit.example.com"));
        let bytes = build_client_hello(&extensions);
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn accepts_two_distinct_unknown_extensions() {
        // Sanity check: GREASE-style noise (two *different* unknown types)
        // must still parse cleanly to ensure C3 didn't over-correct into
        // rejecting legitimate variety.
        let mut extensions = build_extension(0x0A0A, &[]); // GREASE pattern
        extensions.extend_from_slice(&build_extension(0x1A1A, &[]));
        extensions.extend_from_slice(&build_sni_extension("example.com"));
        extensions.extend_from_slice(&build_extension(0x2A2A, &[]));
        let bytes = build_client_hello(&extensions);
        assert_eq!(
            extract_sni(&bytes),
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
