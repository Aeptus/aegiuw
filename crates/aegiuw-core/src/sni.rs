// SPDX-License-Identifier: AGPL-3.0-or-later

#![deny(clippy::indexing_slicing)]

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

// P6: `core::net::IpAddr` is stable since Rust 1.77; we are on 1.82 so the
// no_std swap is free. `alloc` brings `String`/`Vec` for the few places we
// allocate (multi-record reassembly buffer, host string, hex preview).
// P1: `Cow<'a, str>` is the host return type — borrowed from input on the
// single-record happy path, owned on the multi-record path.
use alloc::borrow::Cow;
#[cfg(feature = "debug-malformed")]
use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Extension type for `server_name` (RFC 6066 §3).
pub const EXT_SERVER_NAME: u16 = 0x0000;

/// Extension type for `encrypted_client_hello` (draft-ietf-tls-esni, IANA).
pub const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// Extension type for `pre_shared_key` (RFC 8446 §4.2.11). The spec requires
/// this to be the **last** extension in any ClientHello that uses it; a CH
/// where another extension follows `pre_shared_key` is malformed.
pub const EXT_PRE_SHARED_KEY: u16 = 0x0029;

/// Extension type for `application_layer_protocol_negotiation` (RFC 7301).
/// Surfaces in [`ClientHelloMetadata::alpn_protocols`] (SNI backlog A1).
pub const EXT_ALPN: u16 = 0x0010;

/// Extension type for `supported_versions` (RFC 8446 §4.2.1). In a
/// ClientHello its body is a `u8`-prefixed list of `u16` versions.
/// Surfaces in [`ClientHelloMetadata::supported_versions`] (SNI backlog A1).
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// Extension type for `key_share` (RFC 8446 §4.2.8). We only check presence;
/// the body's group/key bytes aren't required for our routing decisions.
/// Surfaces in [`ClientHelloMetadata::key_share_present`] (SNI backlog A1).
pub const EXT_KEY_SHARE: u16 = 0x0033;

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
pub enum SniOutcome<'a> {
    /// A visible (unencrypted) `server_name` extension was found and its host
    /// extracted. The bytes are reported verbatim, exactly as on the wire —
    /// case normalization, punycode decode, and confusables folding are the
    /// "normalize + enrich" step's job, not this parser's.
    ///
    /// SNI backlog P1: the host is a [`Cow<'a, str>`] — borrowed from the
    /// caller's input slice on the single-record happy path (zero
    /// allocation), owned on the multi-record path (the reassembly buffer
    /// drops at the end of `extract_sni`, so the host must be promoted to
    /// owned to outlive the call). Callers who need a long-lived `String`
    /// can do `.into_owned()` cheaply on either variant.
    Cleartext { host: Cow<'a, str> },
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

impl SniOutcome<'_> {
    /// Stable lowercase string for telemetry dimensions (SNI backlog O2).
    /// Matches the `serde(rename_all = "snake_case")` shape so JSON-emitted
    /// outcomes use the same label set.
    pub fn kind(&self) -> &'static str {
        match self {
            SniOutcome::Cleartext { .. } => "cleartext",
            SniOutcome::Encrypted => "encrypted",
            SniOutcome::NotFound => "not_found",
            SniOutcome::Malformed => "malformed",
        }
    }
}

/// Full set of observable fields extracted from a TLS ClientHello.
///
/// Returned by [`parse_client_hello_full`] (records → metadata) and by
/// [`parse_handshake_message_full`] (already-reassembled handshake →
/// metadata). [`SniOutcome`] is a strict projection of this type — the
/// existing `extract_sni` / `parse_handshake_message` entry points are thin
/// wrappers that call the full parser and drop everything except the host
/// and ECH-presence signal.
///
/// SNI backlog A1.
///
/// **Strictness:** identical to `extract_sni`. A ClientHello that fails any
/// structural check (bad cipher list, oversized session_id, duplicated
/// extension, RFC-violating ServerName entry, etc.) returns `None`. There is
/// no lenient mode — see DECISIONS for the rationale.
///
/// **Lifetimes:** every borrowed field is tied to the input slice via `'a`.
/// On the single-record happy path, all fields borrow directly from the
/// caller's bytes (zero allocation for the slice contents — the only
/// allocations are the `Vec` containers themselves, which are typically tiny:
/// 0–2 ALPN entries, 0–4 supported_versions entries). On the multi-record
/// path the reassembly buffer is owned and dropped at end of arm, so every
/// borrowed field is promoted to owned by [`parse_client_hello_full`] before
/// returning.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientHelloMetadata<'a> {
    /// Visible SNI host, if a `server_name` extension carried one and it
    /// passed the H1–H5 hostname checks. Mirrors `SniOutcome::Cleartext.host`.
    /// `None` when SNI was absent, when ECH was present (outer SNI is a
    /// decoy per DECISIONS.C14 — we deliberately null it here), or when the
    /// SNI extension was well-formed but carried a non-`host_name`
    /// `name_type`.
    pub host: Option<Cow<'a, str>>,
    /// `true` if an `encrypted_client_hello` (0xfe0d) extension was seen.
    /// When set, [`host`] is `None` regardless of any visible SNI on the
    /// wire — the visible SNI is a decoy.
    ///
    /// [`host`]: ClientHelloMetadata::host
    pub ech_present: bool,
    /// ALPN extension contents in wire order. `None` if the extension was
    /// absent (client offered no preference); `Some(vec)` if present, with
    /// each entry a single protocol identifier (e.g. `b"h2"`, `b"http/1.1"`).
    /// The container is `Cow<'a, [u8]>` per-entry so each protocol can be
    /// borrowed on the single-record path and owned on the multi-record path.
    pub alpn_protocols: Option<Vec<Cow<'a, [u8]>>>,
    /// `supported_versions` extension contents (each entry a wire TLS version,
    /// e.g. `0x0304` = TLS 1.3, `0x0303` = TLS 1.2). `None` if the extension
    /// was absent (then the legacy `0x0303` in the ClientHello header is the
    /// negotiated version).
    pub supported_versions: Option<Vec<u16>>,
    /// `true` if a `key_share` extension was present, regardless of its
    /// contents. Useful to detect "TLS 1.3-style" handshakes even when the
    /// `supported_versions` extension is absent.
    pub key_share_present: bool,
}

/// Classified ALPN protocol identifier (SNI backlog A2).
///
/// Layer 2 (the local risk engine) needs to ask "is this an HTTP/3 client?",
/// "is this HTTP/2?" etc. without comparing byte strings everywhere. This
/// enum collapses the IANA ALPN registry to the five buckets that drive our
/// routing decisions; everything else lands in [`AlpnProtocol::Other`].
///
/// Variants are intentionally narrow — adding a bucket here is a
/// public-API change and downstream telemetry dimensions
/// ([`AlpnProtocol::kind`]) would change with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlpnProtocol {
    /// `http/1.0` — RFC 1945. Vanishingly rare in 2026 but in the registry.
    Http10,
    /// `http/1.1` — RFC 9112.
    Http11,
    /// `h2` — HTTP/2 over TLS, RFC 7540 (now RFC 9113).
    Http2,
    /// `h3` or any draft variant (`h3-29`, `h3-32`, …) — HTTP/3 over QUIC,
    /// RFC 9114. The `h3-NN` prefix is matched because draft codepoints
    /// remained in real-world ClientHellos for years after RFC 9114.
    Http3,
    /// Anything not in the HTTP family — DNS-over-TLS (`dot`), DNS-over-QUIC
    /// (`doq`), `acme-tls/1`, `mqtt`, `webrtc`, GREASE-pad strings, unknown.
    Other,
}

impl AlpnProtocol {
    /// Classify a single ALPN protocol identifier from its wire bytes
    /// (e.g. `b"h2"`, `b"http/1.1"`, `b"h3-29"`).
    ///
    /// # Examples
    ///
    /// ```
    /// use aegiuw_core::AlpnProtocol;
    ///
    /// assert_eq!(AlpnProtocol::from_wire(b"h2"), AlpnProtocol::Http2);
    /// assert_eq!(AlpnProtocol::from_wire(b"h3"), AlpnProtocol::Http3);
    /// assert_eq!(AlpnProtocol::from_wire(b"h3-29"), AlpnProtocol::Http3);
    /// assert_eq!(AlpnProtocol::from_wire(b"http/1.1"), AlpnProtocol::Http11);
    /// assert_eq!(AlpnProtocol::from_wire(b"acme-tls/1"), AlpnProtocol::Other);
    /// ```
    pub fn from_wire(value: &[u8]) -> Self {
        match value {
            b"http/1.0" => Self::Http10,
            b"http/1.1" => Self::Http11,
            b"h2" => Self::Http2,
            b"h3" => Self::Http3,
            // h3-NN draft codepoints (e.g. h3-29 through h3-34 saw real deployment).
            // `h3-` is the prefix we look for; anything past it is treated as a draft.
            v if v.starts_with(b"h3-") => Self::Http3,
            _ => Self::Other,
        }
    }

    /// Stable lowercase string for telemetry dimensions (mirrors the
    /// `serde(rename_all = "snake_case")` shape). Matches the
    /// [`SniOutcome::kind`] / O2 pattern so dashboards across the codebase
    /// share a label convention.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Http10 => "http_1_0",
            Self::Http11 => "http_1_1",
            Self::Http2 => "http_2",
            Self::Http3 => "http_3",
            Self::Other => "other",
        }
    }

    /// `true` for any classified HTTP variant. Useful when Layer 2 only
    /// cares whether the connection is HTTP at all (vs. a non-HTTP protocol
    /// like DNS-over-TLS).
    pub fn is_http(&self) -> bool {
        !matches!(self, Self::Other)
    }
}

impl ClientHelloMetadata<'_> {
    /// Classify every offered ALPN protocol in wire order (the client's
    /// preference order). Returns `None` if the ALPN extension was absent
    /// (caller can interpret as "client expressed no preference"). Returns
    /// `Some(empty)` only if the extension was present with an empty list —
    /// the strictness layer would have rejected that already (RFC 7301
    /// §3.1 forbids empty `ProtocolName`), so callers won't see it.
    ///
    /// SNI backlog A2.
    pub fn alpn_classified(&self) -> Option<Vec<AlpnProtocol>> {
        self.alpn_protocols
            .as_ref()
            .map(|protos| protos.iter().map(|p| AlpnProtocol::from_wire(p)).collect())
    }

    /// `true` if the client offered the given ALPN protocol class. Common
    /// queries: `meta.offers(AlpnProtocol::Http3)` for "did they ask for
    /// QUIC?", `meta.offers(AlpnProtocol::Http2)` for "is this an h2
    /// client?".
    ///
    /// Returns `false` when the ALPN extension was absent.
    ///
    /// SNI backlog A2.
    pub fn offers(&self, proto: AlpnProtocol) -> bool {
        match &self.alpn_protocols {
            None => false,
            Some(protos) => protos.iter().any(|p| AlpnProtocol::from_wire(p) == proto),
        }
    }

    /// Classify every offered TLS version in wire order. Returns `None` if
    /// the `supported_versions` extension was absent — in which case the
    /// client offers up to TLS 1.2 (our strictness layer enforces
    /// `legacy_version == 0x0303`, so a `None` here strictly means "TLS 1.2
    /// or older, no extension-based negotiation").
    ///
    /// SNI backlog A3.
    pub fn supported_versions_classified(&self) -> Option<Vec<TlsVersion>> {
        self.supported_versions
            .as_ref()
            .map(|versions| versions.iter().map(|&v| TlsVersion::from_wire(v)).collect())
    }

    /// `true` if the client advertised the given TLS version. For TLS 1.3,
    /// this looks at the `supported_versions` extension (the only place
    /// 1.3 is signalled). For older versions, the extension may be absent
    /// and the legacy `0x0303` in the ClientHello header carries the
    /// version — in which case only `TlsVersion::Tls12` returns `true`.
    ///
    /// SNI backlog A3.
    pub fn offers_tls_version(&self, version: TlsVersion) -> bool {
        match &self.supported_versions {
            Some(versions) => versions
                .iter()
                .any(|&v| TlsVersion::from_wire(v) == version),
            // Extension absent: only TLS 1.2 is implicitly offered (our
            // parser enforces legacy_version == 0x0303 = TLS 1.2 wire).
            None => matches!(version, TlsVersion::Tls12),
        }
    }

    /// Highest TLS version the client advertised. Filters out GREASE and
    /// unknown codepoints ([`TlsVersion::Other`]) before computing the max,
    /// so a fuzzing client can't fool a "modern enough?" check by listing
    /// a phantom version.
    ///
    /// Falls back to [`TlsVersion::Tls12`] when the `supported_versions`
    /// extension is absent — our strictness layer enforces the
    /// `legacy_version == 0x0303` wire value, so TLS 1.2 is the implicit
    /// ceiling for any CH that lacks the extension.
    ///
    /// SNI backlog A3.
    pub fn highest_supported_tls_version(&self) -> TlsVersion {
        match &self.supported_versions {
            None => TlsVersion::Tls12,
            Some(versions) => versions
                .iter()
                .map(|&v| TlsVersion::from_wire(v))
                .filter(|v| !matches!(v, TlsVersion::Other))
                .max()
                .unwrap_or(TlsVersion::Tls12),
        }
    }
}

/// Classified TLS protocol version (SNI backlog A3).
///
/// Layer 2 (the local risk engine) needs to ask "is this a TLS 1.3 client?"
/// or "is this dangerously old?" without juggling wire codepoints. This enum
/// collapses the wire `u16` values to the five protocol versions plus
/// [`TlsVersion::Other`] for GREASE / unknown.
///
/// **Ordering:** `Other` sorts *lowest* (variant declaration order) so
/// `version >= TlsVersion::Tls13` correctly excludes GREASE — the
/// alternative would let a fuzzing client fool the check by listing a
/// codepoint we don't recognise.
///
/// **Versus the `legacy_version` field:** every TLS 1.2/1.3 ClientHello
/// carries `legacy_version = 0x0303` for middlebox compatibility (RFC 8446
/// §4.1.2), so the legacy field is *not* a version signal. The
/// `supported_versions` extension is the only place TLS 1.3 is advertised;
/// see [`ClientHelloMetadata::supported_versions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    /// GREASE codepoint, future TLS version, or any other value we don't
    /// recognise. Sorts *lowest* so `>= Tls13` and similar checks exclude it.
    Other,
    /// SSL 3.0 — wire value `0x0300`. Deprecated by RFC 7568.
    Ssl30,
    /// TLS 1.0 — wire value `0x0301`. Deprecated by RFC 8996.
    Tls10,
    /// TLS 1.1 — wire value `0x0302`. Deprecated by RFC 8996.
    Tls11,
    /// TLS 1.2 — wire value `0x0303`.
    Tls12,
    /// TLS 1.3 — wire value `0x0304`. RFC 8446.
    Tls13,
}

impl TlsVersion {
    /// Classify a single TLS version from its `u16` wire value.
    ///
    /// # Examples
    ///
    /// ```
    /// use aegiuw_core::TlsVersion;
    ///
    /// assert_eq!(TlsVersion::from_wire(0x0304), TlsVersion::Tls13);
    /// assert_eq!(TlsVersion::from_wire(0x0303), TlsVersion::Tls12);
    /// // GREASE codepoints (RFC 8701) collapse to Other.
    /// assert_eq!(TlsVersion::from_wire(0x0A0A), TlsVersion::Other);
    /// ```
    pub fn from_wire(value: u16) -> Self {
        match value {
            0x0300 => Self::Ssl30,
            0x0301 => Self::Tls10,
            0x0302 => Self::Tls11,
            0x0303 => Self::Tls12,
            0x0304 => Self::Tls13,
            _ => Self::Other,
        }
    }

    /// Stable lowercase string for telemetry dimensions (mirrors the
    /// [`SniOutcome::kind`] / [`AlpnProtocol::kind`] O2 convention).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ssl30 => "ssl_3_0",
            Self::Tls10 => "tls_1_0",
            Self::Tls11 => "tls_1_1",
            Self::Tls12 => "tls_1_2",
            Self::Tls13 => "tls_1_3",
            Self::Other => "other",
        }
    }
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
pub fn extract_sni(bytes: &[u8]) -> SniOutcome<'_> {
    // O1: emit one structured trace event per parse with the outcome kind,
    // input size, and wall-clock duration. Downstream telemetry can group
    // by `outcome` for per-variant counters (O2) and bucket `duration_us`
    // for the parse-time histogram (O3).
    //
    // Field contract:
    //   outcome:     stable lowercase string (see `SniOutcome::kind()`)
    //   byte_count:  usize, input slice length
    //   duration_us: u64, wall-clock microseconds (matches PRD §1.1's
    //                ≤ 1.5 ms = ≤ 1500 µs budget — downstream histograms
    //                should bucket near {50, 100, 250, 500, 1000, 1500, 2500}).
    // P6: Instant is std-only; under `--no-default-features` we drop the
    // duration_us field but keep the rest of the trace event so downstream
    // counts and outcome dimensions still work.
    #[cfg(feature = "std")]
    let start = std::time::Instant::now();
    // A1: extract_sni is now a thin projection over parse_client_hello_full,
    // which handles reassembly + multi-record Cow promotion in one place.
    let outcome = match parse_client_hello_full(bytes) {
        None => SniOutcome::Malformed,
        Some(meta) if meta.ech_present => SniOutcome::Encrypted,
        Some(meta) => match meta.host {
            Some(host) => SniOutcome::Cleartext { host },
            None => SniOutcome::NotFound,
        },
    };
    #[cfg(feature = "std")]
    tracing::trace!(
        target: "aegiuw_core::sni",
        outcome = outcome.kind(),
        byte_count = bytes.len(),
        duration_us = start.elapsed().as_micros() as u64,
        "extract_sni"
    );
    #[cfg(not(feature = "std"))]
    tracing::trace!(
        target: "aegiuw_core::sni",
        outcome = outcome.kind(),
        byte_count = bytes.len(),
        "extract_sni"
    );
    // O4: under the `debug-malformed` feature flag, emit a hex dump of the
    // first 64 bytes on Malformed for forensic analysis. Off by default —
    // Malformed input is attacker-controlled and may contain unwanted
    // strings if logs are later scraped.
    #[cfg(feature = "debug-malformed")]
    if matches!(outcome, SniOutcome::Malformed) {
        tracing::debug!(
            target: "aegiuw_core::sni",
            hex = %malformed_hex_preview(bytes),
            "malformed input"
        );
    }
    outcome
}

#[cfg(feature = "debug-malformed")]
fn malformed_hex_preview(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(64 * 3);
    for &b in bytes.iter().take(64) {
        // Single-pass `write!` into a String can't fail.
        let _ = write!(out, "{b:02x} ");
    }
    out.pop(); // trailing space
    out
}

/// Returns `true` if any label in `host` is a punycode A-label (a
/// case-insensitive `xn--` prefix, per RFC 5890 §2.3.2.1).
///
/// IDN-encoded hostnames are pure ASCII LDH on the wire (so they pass the
/// H5 character check inside [`extract_sni`]) but originate from a
/// non-ASCII Unicode name. Surfacing this distinction is useful for
/// observability: IDN traffic disproportionately includes homograph and
/// typosquat attempts, so a "host is IDN" flag is a useful telemetry
/// input — even though it isn't a block signal on its own.
///
/// # Examples
///
/// ```
/// use aegiuw_core::is_idn_host;
///
/// assert!(is_idn_host("xn--caf-dma.com"));            // primary label
/// assert!(is_idn_host("foo.xn--zb9c.example.com"));   // any label triggers
/// assert!(is_idn_host("XN--CAF-DMA.com"));             // case-insensitive
/// assert!(!is_idn_host("example.com"));
/// assert!(!is_idn_host("xn-test.com"));                // needs *two* hyphens
/// assert!(!is_idn_host(""));
/// ```
/// The outer SNI Cloudflare uses for all ECH-enabled zones (per the
/// Cloudflare blog post *"Encrypted Client Hello — the last puzzle piece
/// to privacy"*). Every Cloudflare-hosted ECH connection presents this
/// host name in the *visible* ClientHello; the real destination is inside
/// the encrypted inner ClientHello and never observable to us. SNI
/// backlog O5.
pub const CLOUDFLARE_ECH_OUTER_SNI: &str = "cloudflare-ech.com";

/// Whether `host` is the exact Cloudflare ECH outer-SNI sentinel (case-
/// insensitive). When this returns `true` while ECH is *not* present in
/// the same ClientHello, the bytes are almost certainly a misconfigured
/// or probing client — Cloudflare itself only emits this name as the
/// outer SNI in actual ECH handshakes.
///
/// Today's `SniOutcome::Encrypted` doesn't carry the outer SNI (we
/// prioritise ECH detection over the visible host bytes), so this helper
/// is most useful when the daemon has a separate path that observes the
/// raw SNI bytes from the TUN layer before they're parsed. The constant
/// and predicate live here so the value lives in one place.
///
/// # Examples
///
/// ```
/// use aegiuw_core::{is_cloudflare_ech_outer, CLOUDFLARE_ECH_OUTER_SNI};
///
/// assert!(is_cloudflare_ech_outer(CLOUDFLARE_ECH_OUTER_SNI));
/// assert!(is_cloudflare_ech_outer("Cloudflare-ECH.com"));        // case-insensitive
/// assert!(!is_cloudflare_ech_outer("example.com"));
/// assert!(!is_cloudflare_ech_outer("cloudflare-ech.example.com")); // suffix, not the name
/// ```
pub fn is_cloudflare_ech_outer(host: &str) -> bool {
    host.eq_ignore_ascii_case(CLOUDFLARE_ECH_OUTER_SNI)
}

pub fn is_idn_host(host: &str) -> bool {
    host.split('.').any(|label| {
        label
            .as_bytes()
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"xn--"))
    })
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
        // Cow<'_, str>'s PartialEq compares via Deref<Target = str> regardless
        // of which variant each side is, so borrowed-vs-owned doesn't matter.
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
pub fn reassemble_handshake(records: &[u8]) -> Option<Cow<'_, [u8]>> {
    // P1 fast path: a complete handshake in one record means we can hand the
    // caller a `Cow::Borrowed` slice of `records` and skip the allocation
    // entirely. This is the overwhelmingly common shape for ClientHellos on
    // modern web traffic (typical CH ≈ 200–600 bytes; MAX_RECORD_FRAGMENT
    // = 16 640).
    if let Some(handshake) = try_reassemble_single_record(records) {
        return Some(Cow::Borrowed(handshake));
    }
    // Slow path: fragmented or partial first record. Walk the stream and
    // accumulate into a Vec, then return Cow::Owned.
    reassemble_handshake_owned(records).map(Cow::Owned)
}

/// Best-effort single-record short-circuit for [`reassemble_handshake`].
///
/// Returns `Some(handshake)` when:
/// - the first record is a well-formed `content_type = 22` record,
/// - its fragment is ≥ 4 bytes (enough for the handshake header), and
/// - the fragment payload contains a complete handshake message
///   (`4 + body_len <= fragment_len`).
///
/// Returns `None` otherwise — the caller falls back to the owned slow path,
/// which is the authoritative validator (the fast path only needs to be
/// *safe* and *correct when it succeeds*; it does not need to detect every
/// invalid case).
fn try_reassemble_single_record(records: &[u8]) -> Option<&[u8]> {
    let mut cursor = Cursor::new(records);
    if cursor.read_u8()? != CONTENT_TYPE_HANDSHAKE {
        return None;
    }
    cursor.read_u16()?; // legacy_record_version
    let fragment_len = cursor.read_u16()? as usize;
    if !(4..=MAX_RECORD_FRAGMENT).contains(&fragment_len) {
        return None;
    }
    let fragment = cursor.read_slice(fragment_len)?;
    let header = fragment.get(..4)?;
    let &[_, hi, mi, lo] = header else {
        return None;
    };
    let body_len = ((hi as usize) << 16) | ((mi as usize) << 8) | (lo as usize);
    let total = 4usize.checked_add(body_len)?;
    if total > MAX_HANDSHAKE_BYTES {
        return None;
    }
    if total <= fragment_len {
        // Trailing bytes inside the fragment are tolerated — truncate.
        fragment.get(..total)
    } else {
        None
    }
}

/// Multi-record slow path for [`reassemble_handshake`]. Always allocates a
/// `Vec<u8>` for the assembled handshake. Kept as the authoritative
/// implementation: the fast path defers to this on any non-trivial case.
fn reassemble_handshake_owned(records: &[u8]) -> Option<Vec<u8>> {
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
            let header = handshake_buf.get(..4)?;
            let &[_, hi, mi, lo] = header else {
                return None;
            };
            let body_len = ((hi as usize) << 16) | ((mi as usize) << 8) | (lo as usize);
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

/// Parse an already-reassembled handshake message into the full set of
/// observable fields (SNI backlog A1).
///
/// This is the canonical parser; [`parse_handshake_message`] is a thin
/// projection over its result. Returns `None` to mean "the bytes don't look
/// like a handshake at all" (caller surfaces this as
/// [`SniOutcome::Malformed`]) or "the ClientHello is malformed and we want
/// failure-closed semantics" (any internal RFC violation). Strictness is
/// identical to [`extract_sni`].
///
/// # Examples
///
/// ```
/// use aegiuw_core::parse_handshake_message_full;
///
/// // Empty input: not even a handshake header.
/// assert_eq!(parse_handshake_message_full(&[]), None);
/// ```
pub fn parse_handshake_message_full(handshake: &[u8]) -> Option<ClientHelloMetadata<'_>> {
    let mut c = Cursor::new(handshake);

    // ── Handshake header ───────────────────────────────────────────────────
    if c.read_u8()? != HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }
    c.read_u24()?; // handshake body length (we trust the caller's reassembly)

    // ── ClientHello body ───────────────────────────────────────────────────
    //
    // RFC 8446 §4.1.2: a TLS 1.2 or 1.3 ClientHello MUST set legacy_version =
    // 0x0303. SSL 3.0, TLS 1.0, and TLS 1.1 are deprecated by RFC 8996 — any
    // such wire value means we're looking at obsolete or hostile traffic and
    // should refuse to extract a fork decision from it. SNI backlog C5.
    if c.read_u16()? != TLS_LEGACY_VERSION {
        return None;
    }
    c.read_slice(32)?; // random

    // RFC 8446 §4.1.2: `legacy_session_id<0..32>` — at most 32 bytes. A
    // longer session_id is either a malformed sender or an attacker abusing
    // the u8 length prefix's 0–255 range. SNI backlog C8.
    let session_id = c.read_u8_prefixed()?;
    if session_id.len() > 32 {
        return None;
    }

    // RFC 8446 §4.1.2: `cipher_suites<2..2^16-2>` — at least one suite, and
    // each suite is exactly 2 bytes. An empty list or an odd byte count is a
    // spec violation (and a strong signal of a malformed/probe handshake).
    // SNI backlog C7.
    let cipher_suites = c.read_u16_prefixed()?;
    if cipher_suites.is_empty() || cipher_suites.len() % 2 != 0 {
        return None;
    }

    // RFC 8446 §4.1.2: a TLS 1.3 ClientHello MUST list a single null
    // compression method. Older TLS allowed deflate too, but the CRIME
    // attack (CVE-2012-4929) means a sender claiming non-null compression
    // alongside null is either obsolete or hostile. The lenient bar from
    // the backlog (C6) is "MUST contain null(0)"; an empty list or a list
    // of only non-null methods is rejected.
    let compression = c.read_u8_prefixed()?;
    if !compression.contains(&0) {
        return None;
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

    // A1: collect every field the metadata struct exposes. Scan ALL extensions
    // before deciding so ECH always wins over any visible SNI (DECISIONS.C14).
    let mut meta = ClientHelloMetadata {
        host: None,
        ech_present: false,
        alpn_protocols: None,
        supported_versions: None,
        key_share_present: false,
    };
    // P1: host borrows from the input `handshake` slice; no allocation.
    let mut sni_host: Option<&str> = None;
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
            return None;
        }
        let ext_type = ext.read_u16()?;
        let ext_data = ext.read_u16_prefixed()?;

        if seen_ext_types.contains(&ext_type) {
            return None;
        }
        seen_ext_types.push(ext_type);
        if ext_type == EXT_PRE_SHARED_KEY {
            psk_seen = true;
        }

        match ext_type {
            EXT_ENCRYPTED_CLIENT_HELLO => {
                meta.ech_present = true;
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
                        return None;
                    }
                }
            }
            EXT_ALPN => {
                meta.alpn_protocols = Some(parse_alpn_extension(ext_data)?);
            }
            EXT_SUPPORTED_VERSIONS => {
                meta.supported_versions = Some(parse_supported_versions_extension(ext_data)?);
            }
            EXT_KEY_SHARE => {
                meta.key_share_present = true;
            }
            _ => {}
        }
    }

    // DECISIONS.C14: ECH masks the outer SNI as a decoy. Only publish the
    // host when ECH is absent.
    if !meta.ech_present {
        meta.host = sni_host.map(Cow::Borrowed);
    }
    Some(meta)
}

/// Parse an already-reassembled handshake message and project to a
/// [`SniOutcome`].
///
/// Thin wrapper over [`parse_handshake_message_full`] that drops every field
/// except `host` / `ech_present` (SNI backlog A1).
///
/// Returns `None` only when the bytes don't look like a handshake at all
/// (caller surfaces as `Malformed`); a structurally-parseable but
/// spec-violating CH returns `Some(SniOutcome::Malformed)` so the difference
/// between "not a handshake" and "a bad handshake" is preserved.
///
/// Kept `pub` so the upcoming QUIC parser can feed already-stripped
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
pub fn parse_handshake_message(handshake: &[u8]) -> Option<SniOutcome<'_>> {
    // The difference between None ("not a handshake") and
    // Some(SniOutcome::Malformed) ("a handshake we refuse") matters to
    // extract_sni's contract. We preserve it by inspecting the first byte
    // here: if it isn't HANDSHAKE_TYPE_CLIENT_HELLO we mirror today's
    // None-vs-Some(Malformed) behaviour exactly. The full parser internally
    // returns None for both "wrong type" and "malformed body" — we widen
    // that to Some(Malformed) for the malformed-body case so contract
    // semantics survive the refactor.
    match handshake.first() {
        None => return None,
        Some(&b) if b != HANDSHAKE_TYPE_CLIENT_HELLO => return Some(SniOutcome::Malformed),
        Some(_) => {}
    }
    Some(match parse_handshake_message_full(handshake) {
        None => SniOutcome::Malformed,
        Some(meta) if meta.ech_present => SniOutcome::Encrypted,
        Some(meta) => match meta.host {
            Some(host) => SniOutcome::Cleartext { host },
            None => SniOutcome::NotFound,
        },
    })
}

/// Parse a TLS ClientHello (records-level entry) into the full set of
/// observable fields (SNI backlog A1).
///
/// Reassembles records via [`reassemble_handshake`] then walks the
/// ClientHello via [`parse_handshake_message_full`]. On the multi-record
/// path the reassembly buffer is dropped at end of arm, so every borrowed
/// field is promoted to owned before returning — the API stays uniform
/// regardless of input shape.
///
/// Returns `None` on any structural failure (not a handshake, malformed
/// body, fragmented past `MAX_HANDSHAKE_BYTES`, etc.) — same strictness as
/// [`extract_sni`].
pub fn parse_client_hello_full(bytes: &[u8]) -> Option<ClientHelloMetadata<'_>> {
    match reassemble_handshake(bytes)? {
        Cow::Borrowed(handshake) => parse_handshake_message_full(handshake),
        Cow::Owned(handshake) => {
            let borrowed = parse_handshake_message_full(&handshake)?;
            // Promote every borrowed field to owned. Container Vecs survive
            // verbatim; the per-entry borrows are upgraded to Cow::Owned.
            Some(ClientHelloMetadata {
                host: borrowed.host.map(|h| Cow::Owned(h.into_owned())),
                ech_present: borrowed.ech_present,
                alpn_protocols: borrowed
                    .alpn_protocols
                    .map(|v| v.into_iter().map(|c| Cow::Owned(c.into_owned())).collect()),
                supported_versions: borrowed.supported_versions,
                key_share_present: borrowed.key_share_present,
            })
        }
    }
}

/// Parse the body of an ALPN extension (RFC 7301): a `u16`-prefixed list of
/// `u8`-prefixed protocol identifiers. Returns `None` if any length prefix
/// overruns; returns `Some(empty)` if the list is empty (RFC 7301 §3.1
/// allows zero entries — we tolerate, even though it's a degenerate case
/// servers usually reject).
fn parse_alpn_extension(data: &[u8]) -> Option<Vec<Cow<'_, [u8]>>> {
    let mut c = Cursor::new(data);
    let list = c.read_u16_prefixed()?;
    let mut entries = Cursor::new(list);
    let mut out: Vec<Cow<'_, [u8]>> = Vec::new();
    while entries.remaining() > 0 {
        let proto = entries.read_u8_prefixed()?;
        if proto.is_empty() {
            // RFC 7301 §3.1: each ProtocolName MUST be non-empty.
            return None;
        }
        out.push(Cow::Borrowed(proto));
    }
    Some(out)
}

/// Parse the body of a `supported_versions` extension as it appears in a
/// ClientHello (RFC 8446 §4.2.1): a `u8`-prefixed list of `u16` versions.
/// Returns `None` if the byte length is odd or the prefix overruns.
fn parse_supported_versions_extension(data: &[u8]) -> Option<Vec<u16>> {
    let mut c = Cursor::new(data);
    let list = c.read_u8_prefixed()?;
    if list.is_empty() || list.len() % 2 != 0 {
        return None;
    }
    let mut versions = Cursor::new(list);
    let mut out: Vec<u16> = Vec::with_capacity(list.len() / 2);
    while versions.remaining() > 0 {
        out.push(versions.read_u16()?);
    }
    Some(out)
}

/// Result of parsing one `server_name` extension's body.
///
/// Distinguishing the three states matters: `Skip` lets the caller keep
/// scanning other extensions (so a non-`host_name` entry doesn't break ECH
/// detection), while `Malformed` propagates as `SniOutcome::Malformed` — the
/// failure-closed signal for clear RFC violations.
enum ServerNameOutcome<'a> {
    /// Successfully extracted a `host_name` entry (borrowed from the input
    /// handshake bytes — see SNI backlog P1).
    Host(&'a str),
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
fn parse_server_name_extension(data: &[u8]) -> ServerNameOutcome<'_> {
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

    // RFC 1034 §3.1 / DNS convention: a single trailing dot is the FQDN
    // marker indicating "absolute name from root." `example.com.` and
    // `example.com` resolve to the same name — strip the dot so the
    // upstream allow-cache and telemetry see one canonical shape.
    // Normalizing *before* H1–H3 means a trailing-dot IP literal
    // (`192.168.1.1.`) is still caught by H1, and the 253-byte limit
    // applies to the non-dot form (the spec's intended bound).
    // SNI backlog H4.
    let host_str = host_str.strip_suffix('.').unwrap_or(host_str);

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
    // P5: walk the dot positions with `memchr::memchr_iter` (SIMD-accelerated
    // inside the crate, no `unsafe` for us) instead of `split('.').any(...)`.
    // The previous form built an iterator chain that the optimiser had to
    // unwrap; this form drops straight into a byte-search primitive and is
    // measurably faster on hostnames that have many short labels (the
    // 10 000-extension fuzz test and any FQDN with a deep subdomain).
    {
        let bytes = host_str.as_bytes();
        let mut prev: usize = 0;
        for dot in memchr::memchr_iter(b'.', bytes) {
            if dot - prev > MAX_LABEL_LEN {
                return ServerNameOutcome::Malformed;
            }
            prev = dot + 1;
        }
        if bytes.len() - prev > MAX_LABEL_LEN {
            return ServerNameOutcome::Malformed;
        }
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

    // RFC 6066 §3 + RFC 5890 §2.3.2.4: SNI hostnames are ASCII-only LDH
    // (letter, digit, hyphen) plus dots separating labels. A-labels (IDN
    // encoding, e.g. `xn--caf-dma`) match the same LDH shape because the
    // `xn--` prefix and the punycode payload are pure ASCII. Anything else
    // — raw Unicode, emoji, underscore, control bytes — is illegal here.
    // The earlier `from_utf8` only confirms valid UTF-8; this is the actual
    // character-set check. SNI backlog H5.
    if !host_str
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return ServerNameOutcome::Malformed;
    }

    // DNS hostname comparisons are case-insensitive (RFC 4343), but case
    // normalization is *not* the parser's job — we return the host verbatim
    // from the wire and let the upstream "normalize + enrich" Layer-1 step
    // own the canonical form. This keeps `aegiuw-core` a pure observer:
    // telemetry sees what the sender actually sent, and allow-list lookups
    // happen one layer up where case-folding and IDN unification belong.
    // SNI backlog H6 — confirmed *not* normalizing here; tests pin the
    // case-preservation contract.

    // Peek for a duplicate host_name(0) after the one we just extracted.
    if let Some(next_type) = entries.read_u8() {
        if next_type == NAME_TYPE_HOST_NAME {
            return ServerNameOutcome::Malformed;
        }
        // Any other subsequent entry has undefined structure; we accept the
        // host we already extracted and stop scanning the list.
    }

    // P1: borrow directly from the input — no allocation.
    ServerNameOutcome::Host(host_str)
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

// P2: `#[inline]` on every Cursor accessor — they're all single-expression
// readers and the parse loop calls them tens of times per ClientHello. Letting
// the compiler inline across crate boundaries removes the call overhead and
// lets the bounds checks fuse with adjacent ones.
impl<'a> Cursor<'a> {
    #[inline]
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[inline]
    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    #[inline]
    pub(crate) fn read_u8(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    #[inline]
    pub(crate) fn read_u16(&mut self) -> Option<u16> {
        let s = self.read_slice(2)?;
        let bytes: [u8; 2] = s.try_into().ok()?;
        Some(u16::from_be_bytes(bytes))
    }

    /// 24-bit big-endian length, used by the TLS Handshake header.
    #[inline]
    pub(crate) fn read_u24(&mut self) -> Option<u32> {
        let s = self.read_slice(3)?;
        let &[a, b, c] = s else { return None };
        Some(((a as u32) << 16) | ((b as u32) << 8) | (c as u32))
    }

    #[inline]
    pub(crate) fn read_slice(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    /// Read a `u8`-prefixed length, then that many bytes (e.g. session_id,
    /// compression_methods).
    #[inline]
    pub(crate) fn read_u8_prefixed(&mut self) -> Option<&'a [u8]> {
        let n = self.read_u8()? as usize;
        self.read_slice(n)
    }

    /// Read a `u16`-prefixed length, then that many bytes (e.g. cipher_suites,
    /// extensions, individual extension data).
    #[inline]
    pub(crate) fn read_u16_prefixed(&mut self) -> Option<&'a [u8]> {
        let n = self.read_u16()? as usize;
        self.read_slice(n)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)] // test fixtures hand-craft byte arrays; deliberate
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

    // ── Stable counter-dimension strings (O2) ────────────────────────────────

    #[test]
    fn sni_outcome_kind_strings_are_stable() {
        // These string values are part of the public API surface (used as
        // counter dimensions, log fields, dashboard labels). Renaming them
        // is a breaking change for downstream telemetry — pin them here.
        assert_eq!(
            SniOutcome::Cleartext { host: "x".into() }.kind(),
            "cleartext"
        );
        assert_eq!(SniOutcome::Encrypted.kind(), "encrypted");
        assert_eq!(SniOutcome::NotFound.kind(), "not_found");
        assert_eq!(SniOutcome::Malformed.kind(), "malformed");
    }

    // ── Allocation cap holds under drip-feed (S7) ────────────────────────────

    #[test]
    fn allocation_cap_holds_against_drip_feed_of_small_records() {
        // Strongest version of the cap test: the first record's handshake
        // header claims a u24 body length of 0xFFFFFF (≈ 16 MB), then we
        // send a stream of small records the attacker would *like* us to
        // keep buffering. The cap in `reassemble_handshake` must fire after
        // MAX_HANDSHAKE_BYTES (64 KiB), never approaching the 16 MB claim.
        let mut bytes = Vec::new();

        let mut first = Vec::new();
        first.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        first.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // claim 16 MiB body
        first.extend_from_slice(&[0xAA; 4_000]); // start the drip
        bytes.extend_from_slice(&wrap_record(CONTENT_TYPE_HANDSHAKE, &first));

        // 16 more records of 4 KB each → 64 KB additional → trips the cap.
        // Sender hopes we'll keep buffering all the way to 16 MB; we don't.
        for _ in 0..16 {
            bytes.extend_from_slice(&wrap_record(CONTENT_TYPE_HANDSHAKE, &[0xBB; 4_000]));
        }

        assert_eq!(reassemble_handshake(&bytes), None);
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    // ── Maximum-size single record within budget (S4) ────────────────────────

    #[test]
    fn parses_maximum_single_record_within_debug_budget() {
        // A single TLS record near the RFC 8446 §5.1 16 KiB ceiling, packed
        // with extensions. Asserts the parse completes within a generous
        // debug-mode budget — PRD §1.1 calls for ≤ 1.5 ms in release; 50 ms
        // here covers debug + sanitizers + slow CI hardware while still
        // catching any catastrophic regression.
        use std::time::Instant;

        const N: usize = 4_000; // 4000 × 4 bytes ≈ 16 KiB of extensions
        let mut extensions = Vec::with_capacity(N * 4);
        for i in 0..N {
            let ext_type = (0x0100u16).wrapping_add(i as u16);
            extensions.extend_from_slice(&build_extension(ext_type, &[]));
        }
        let bytes = build_client_hello(&extensions);

        // Sanity: confirm this still fits in a *single* record.
        assert!(
            bytes.len() <= 5 + 16_640,
            "fixture grew past one record (len={})",
            bytes.len(),
        );

        let start = Instant::now();
        let outcome = extract_sni(&bytes);
        let elapsed = start.elapsed();

        assert_eq!(outcome, SniOutcome::NotFound);
        // Budget 200 ms: a true quadratic blowup on N=4000 takes ~seconds even
        // on fast hardware; the loose budget tolerates debug-build noise on
        // a loaded machine without losing the linear-vs-quadratic signal.
        assert!(
            elapsed.as_millis() < 200,
            "parser took {elapsed:?} for {N}-extension max-size record",
        );
    }

    // ── Linear scaling under extension explosion (S3) ────────────────────────

    #[test]
    fn parses_client_hello_with_many_small_extensions_in_linear_time() {
        // Build a ClientHello with N small extensions (each a unique type
        // outside the well-known range, empty payload). The handshake bytes
        // exceed a single 16 KiB TLS record (RFC 8446 §5.1 MAX_RECORD_FRAGMENT)
        // so this also exercises the C1 multi-record reassembly path.
        // Assert the parser stays linear — quadratic blowup in the
        // duplicate-tracking set would take seconds, while linear behavior
        // takes milliseconds.
        use std::time::Instant;

        const N: usize = 10_000;
        let mut extensions = Vec::with_capacity(N * 4);
        for i in 0..N {
            // 0x0100..0x2810 — no overlap with any well-known extension type
            // (server_name=0x0000, ECH=0xfe0d, pre_shared_key=0x0029, …).
            let ext_type = (0x0100u16).wrapping_add(i as u16);
            extensions.extend_from_slice(&build_extension(ext_type, &[]));
        }

        // Fragment across ~12 KB records (well under MAX_RECORD_FRAGMENT)
        // so reassembly walks several records.
        let handshake = build_handshake_message(&extensions);
        let chunk = 12_000usize;
        let mut splits = Vec::new();
        let mut at = chunk;
        while at < handshake.len() {
            splits.push(at);
            at += chunk;
        }
        let bytes = build_fragmented_records(&handshake, &splits);

        let start = Instant::now();
        let outcome = extract_sni(&bytes);
        let elapsed = start.elapsed();

        assert_eq!(outcome, SniOutcome::NotFound, "got {outcome:?} for N={N}");

        // 2000 ms is generous — covers debug builds with sanitizers, a slow
        // CI machine, and momentary load on a developer laptop. A quadratic
        // loop on N=10_000 would take ~tens of seconds on the same hardware,
        // so this budget retains all the linear-vs-quadratic detection power
        // while not flaking on wall-clock jitter.
        assert!(
            elapsed.as_millis() < 2_000,
            "parser took {elapsed:?} for {N} extensions — quadratic blowup?",
        );
    }

    // ── Property tests: panic-free for arbitrary bytes (S2) ──────────────────
    //
    // Complements the cargo-fuzz harnesses under `crates/aegiuw-core/fuzz/`.
    // Fuzzing runs externally on nightly and finds new edge cases over
    // hours; proptest runs in every `cargo test` and pins the panic-free
    // contract per commit. Default 256 cases per property × 3 properties
    // ≈ 768 calls per test run; parser is linear in input length so this
    // costs sub-second on a typical machine.

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn extract_sni_never_panics_on_arbitrary_bytes(
            bytes in prop::collection::vec(any::<u8>(), 0..2048)
        ) {
            // Any return value is acceptable — the property is "doesn't panic."
            let _ = extract_sni(&bytes);
        }

        #[test]
        fn reassemble_handshake_never_panics_on_arbitrary_bytes(
            // Larger range here so proptest can probe the MAX_HANDSHAKE_BYTES
            // (= 64 KiB) cap with inputs that claim large handshake bodies.
            bytes in prop::collection::vec(any::<u8>(), 0..70_000)
        ) {
            let _ = reassemble_handshake(&bytes);
        }

        #[test]
        fn parse_handshake_message_never_panics_on_arbitrary_bytes(
            bytes in prop::collection::vec(any::<u8>(), 0..2048)
        ) {
            let _ = parse_handshake_message(&bytes);
        }
    }

    // ── Cloudflare ECH outer-SNI sentinel (O5) ───────────────────────────────

    #[test]
    fn cloudflare_ech_outer_detector_matches_exact_string() {
        assert!(is_cloudflare_ech_outer(CLOUDFLARE_ECH_OUTER_SNI));
    }

    #[test]
    fn cloudflare_ech_outer_detector_is_case_insensitive() {
        assert!(is_cloudflare_ech_outer("CLOUDFLARE-ECH.COM"));
        assert!(is_cloudflare_ech_outer("Cloudflare-Ech.Com"));
    }

    #[test]
    fn cloudflare_ech_outer_detector_rejects_non_matches() {
        assert!(!is_cloudflare_ech_outer("example.com"));
        assert!(!is_cloudflare_ech_outer("cloudflare-ech.example.com"));
        assert!(!is_cloudflare_ech_outer("notcloudflare-ech.com"));
        assert!(!is_cloudflare_ech_outer(""));
    }

    // ── IDN / punycode detection (H7, RFC 5890 §2.3.2.1) ─────────────────────

    #[test]
    fn is_idn_host_detects_lowercase_xn_prefix() {
        assert!(is_idn_host("xn--caf-dma.com"));
    }

    #[test]
    fn is_idn_host_detects_uppercase_xn_prefix() {
        // RFC 5890 §5: A-label matching is case-insensitive. Our H6 contract
        // preserves wire case, so the *detector* must lowercase-compare.
        assert!(is_idn_host("XN--CAF-DMA.com"));
        assert!(is_idn_host("Xn--Caf-Dma.com"));
    }

    #[test]
    fn is_idn_host_detects_xn_in_subdomain() {
        // Any label can be an A-label; not just the leftmost.
        assert!(is_idn_host("foo.xn--zb9c.example.com"));
    }

    #[test]
    fn is_idn_host_returns_false_for_plain_hostname() {
        assert!(!is_idn_host("example.com"));
    }

    #[test]
    fn is_idn_host_requires_double_hyphen() {
        // `xn-` (single hyphen) is just a normal label that happens to
        // start with "xn-". RFC 5890 requires *two* hyphens after the prefix.
        assert!(!is_idn_host("xn-test.com"));
        assert!(!is_idn_host("xn.com"));
    }

    #[test]
    fn is_idn_host_handles_empty_and_short_inputs() {
        assert!(!is_idn_host(""));
        assert!(!is_idn_host("xn-")); // 3 chars, not enough for the prefix
    }

    // ── Case preservation (H6, RFC 4343 — but normalized upstream) ───────────

    #[test]
    fn preserves_mixed_case_hostname() {
        // DNS comparisons are case-insensitive (RFC 4343), but the SNI parser
        // deliberately returns the host verbatim — case normalization is the
        // upstream "normalize + enrich" step's responsibility. If a future
        // refactor accidentally lowercases here, this test fails immediately.
        let bytes = build_client_hello(&build_sni_extension("Example.COM"));
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext {
                host: "Example.COM".into()
            }
        );
    }

    #[test]
    fn preserves_uppercase_punycode_prefix() {
        // RFC 5890 §5: A-labels are case-insensitive *for matching*, but
        // their canonical form is lowercase `xn--`. We still return the
        // bytes as observed on the wire — `XN--CAF-DMA` and `xn--caf-dma`
        // are both spec-legal LDH and the upstream step canonicalizes.
        let bytes = build_client_hello(&build_sni_extension("XN--CAF-DMA.com"));
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext {
                host: "XN--CAF-DMA.com".into()
            }
        );
    }

    // ── LDH/ASCII-only character validation (H5, RFC 5890 §2.3.2.4) ──────────

    #[test]
    fn rejects_non_ascii_unicode_in_hostname() {
        // `café.com` is valid UTF-8 but contains a non-ASCII codepoint.
        // RFC 6066 SNI requires ASCII; IDN names use punycode A-labels
        // (`xn--caf-dma`), not raw Unicode.
        let bytes = build_client_hello(&build_sni_extension("café.com"));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_emoji_in_hostname() {
        // Emoji are valid UTF-8 (4-byte sequences with high-bit-set bytes)
        // but obviously not LDH.
        let bytes = build_client_hello(&build_sni_extension("hello💩.com"));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn rejects_underscore_in_hostname() {
        // `_` is permitted in some DNS contexts (SRV labels, DKIM selectors)
        // but not in *host* names per RFC 952/1123. SNI is host-only.
        let bytes = build_client_hello(&build_sni_extension("foo_bar.example.com"));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn accepts_punycode_a_label() {
        // The A-label form of `café.com` — `xn--caf-dma.com`. Pure LDH,
        // must parse cleanly: IDNs land in SNI in this encoded form.
        let bytes = build_client_hello(&build_sni_extension("xn--caf-dma.com"));
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext {
                host: "xn--caf-dma.com".into()
            }
        );
    }

    #[test]
    fn accepts_hostname_with_hyphens_in_label() {
        // Hyphens within labels are legal LDH; positive control to pin that
        // the byte-set check doesn't accidentally reject hyphens.
        let bytes = build_client_hello(&build_sni_extension("foo-bar.example.com"));
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext {
                host: "foo-bar.example.com".into()
            }
        );
    }

    // ── Trailing-dot normalization (H4, RFC 1034 §3.1) ───────────────────────

    #[test]
    fn strips_single_trailing_dot_from_fqdn() {
        // `example.com.` and `example.com` are the same DNS name; the
        // trailing dot is the FQDN marker. Returned host MUST be the
        // canonical (no-dot) form so the allow-cache only needs one shape.
        let bytes = build_client_hello(&build_sni_extension("example.com."));
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext {
                host: "example.com".into()
            }
        );
    }

    #[test]
    fn lone_trailing_dot_is_malformed_via_empty_check() {
        // After stripping the single dot, the host is empty — H2's empty
        // check fires. This is the right cascade: H4 normalizes, H2 enforces.
        let bytes = build_client_hello(&build_sni_extension("."));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn ipv4_with_trailing_dot_is_malformed_via_ip_check() {
        // Normalize first, then validate — strips the dot, then H1 catches
        // the bare IPv4 literal. Without H4 (i.e. with a naive parser that
        // didn't normalize), `192.168.1.1.` would have slipped past H1.
        let bytes = build_client_hello(&build_sni_extension("192.168.1.1."));
        assert_eq!(extract_sni(&bytes), SniOutcome::Malformed);
    }

    #[test]
    fn hostname_without_trailing_dot_is_unchanged() {
        // Positive control: H4 must not touch hostnames that don't end in
        // a dot. `strip_suffix('.')` returns `None`, the `.unwrap_or` keeps
        // the original `&str`.
        let bytes = build_client_hello(&build_sni_extension("example.com"));
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext {
                host: "example.com".into()
            }
        );
    }

    #[test]
    fn hostname_at_253_chars_with_trailing_dot_passes_after_strip() {
        // 253 chars + 1 trailing dot = 254 bytes on the wire, but the
        // *name* is 253 chars after normalization — exactly the RFC 1035
        // presentation-form ceiling. Must parse cleanly; the H3 check
        // applies to the stripped form, not the raw bytes.
        let mut host = "a.".repeat(126);
        host.push('a');
        assert_eq!(host.len(), 253);
        let with_dot = format!("{host}.");
        let bytes = build_client_hello(&build_sni_extension(&with_dot));
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext { host: host.into() },
        );
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
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext { host: host.into() },
        );
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
        assert_eq!(
            extract_sni(&bytes),
            SniOutcome::Cleartext { host: host.into() },
        );
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

    // ── A1: parse_client_hello_full + ClientHelloMetadata ────────────────────

    /// Build an ALPN extension body from a list of protocol identifiers.
    /// Layout (RFC 7301): `u16` total list length + repeated `u8`-prefixed
    /// protocol_name entries.
    fn build_alpn_extension(protos: &[&[u8]]) -> Vec<u8> {
        let mut list: Vec<u8> = Vec::new();
        for p in protos {
            list.push(p.len() as u8);
            list.extend_from_slice(p);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&(list.len() as u16).to_be_bytes());
        body.extend_from_slice(&list);
        build_extension(EXT_ALPN, &body)
    }

    /// Build a supported_versions extension body for a ClientHello (RFC 8446
    /// §4.2.1): `u8`-prefixed list of `u16` versions.
    fn build_supported_versions_extension(versions: &[u16]) -> Vec<u8> {
        let mut list: Vec<u8> = Vec::new();
        for v in versions {
            list.extend_from_slice(&v.to_be_bytes());
        }
        let mut body = Vec::new();
        body.push(list.len() as u8);
        body.extend_from_slice(&list);
        build_extension(EXT_SUPPORTED_VERSIONS, &body)
    }

    #[test]
    fn parse_client_hello_full_extracts_host_alpn_versions_and_key_share() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&build_sni_extension("example.com"));
        exts.extend_from_slice(&build_alpn_extension(&[b"h2", b"http/1.1"]));
        exts.extend_from_slice(&build_supported_versions_extension(&[0x0304, 0x0303]));
        exts.extend_from_slice(&build_extension(EXT_KEY_SHARE, &[0x00, 0x00])); // empty client_shares
        let bytes = build_client_hello(&exts);

        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert_eq!(meta.host.as_deref(), Some("example.com"));
        assert!(!meta.ech_present);
        let alpn = meta.alpn_protocols.as_ref().expect("ALPN parsed");
        assert_eq!(alpn.len(), 2);
        assert_eq!(&*alpn[0], b"h2");
        assert_eq!(&*alpn[1], b"http/1.1");
        assert_eq!(
            meta.supported_versions.as_deref(),
            Some(&[0x0304, 0x0303][..])
        );
        assert!(meta.key_share_present);
    }

    #[test]
    fn parse_client_hello_full_returns_none_alpn_when_absent() {
        let bytes = build_client_hello(&build_sni_extension("example.com"));
        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert!(meta.alpn_protocols.is_none(), "extension absent -> None");
        assert!(meta.supported_versions.is_none());
        assert!(!meta.key_share_present);
    }

    #[test]
    fn parse_client_hello_full_masks_host_when_ech_present() {
        // DECISIONS.C14: ECH outer SNI is a decoy. Metadata must null the host.
        let mut exts = Vec::new();
        exts.extend_from_slice(&build_sni_extension("decoy.example.com"));
        exts.extend_from_slice(&build_extension(EXT_ENCRYPTED_CLIENT_HELLO, &[]));
        let bytes = build_client_hello(&exts);

        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert!(meta.ech_present);
        assert!(meta.host.is_none(), "ECH must mask the outer SNI");
    }

    #[test]
    fn parse_client_hello_full_rejects_empty_alpn_protocol_name() {
        // RFC 7301 §3.1: each ProtocolName MUST be non-empty. A zero-length
        // entry inside an otherwise well-formed list is a spec violation.
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_be_bytes()); // list length 1
        body.push(0); // zero-length proto
        let mut exts = Vec::new();
        exts.extend_from_slice(&build_sni_extension("example.com"));
        exts.extend_from_slice(&build_extension(EXT_ALPN, &body));
        let bytes = build_client_hello(&exts);
        assert_eq!(parse_client_hello_full(&bytes), None);
    }

    #[test]
    fn parse_client_hello_full_rejects_odd_length_supported_versions() {
        // Each version is u16 — odd list length is a spec violation.
        let mut body = Vec::new();
        body.push(3); // u8 list length = 3 (odd)
        body.extend_from_slice(&[0x03, 0x04, 0x03]); // truncated
        let mut exts = Vec::new();
        exts.extend_from_slice(&build_sni_extension("example.com"));
        exts.extend_from_slice(&build_extension(EXT_SUPPORTED_VERSIONS, &body));
        let bytes = build_client_hello(&exts);
        assert_eq!(parse_client_hello_full(&bytes), None);
    }

    #[test]
    fn extract_sni_is_thin_projection_of_parse_client_hello_full() {
        // Pin the contract that extract_sni is just a projection — for every
        // input the two functions agree on the host/ECH signal.
        let inputs: &[Vec<u8>] = &[
            // Cleartext SNI
            build_client_hello(&build_sni_extension("example.com")),
            // ECH masking SNI
            {
                let mut exts = Vec::new();
                exts.extend_from_slice(&build_sni_extension("decoy.example.com"));
                exts.extend_from_slice(&build_extension(EXT_ENCRYPTED_CLIENT_HELLO, &[]));
                build_client_hello(&exts)
            },
            // No SNI extension at all
            build_client_hello(&[]),
            // Garbage — not even a record
            vec![0xff, 0xff, 0xff],
        ];
        for bytes in inputs {
            let projected = match parse_client_hello_full(bytes) {
                None => SniOutcome::Malformed,
                Some(m) if m.ech_present => SniOutcome::Encrypted,
                Some(m) => match m.host {
                    Some(host) => SniOutcome::Cleartext { host },
                    None => SniOutcome::NotFound,
                },
            };
            assert_eq!(extract_sni(bytes), projected, "input len={}", bytes.len());
        }
    }

    // ── A2: AlpnProtocol classification ──────────────────────────────────────

    #[test]
    fn alpn_protocol_classifies_the_well_known_wire_values() {
        assert_eq!(AlpnProtocol::from_wire(b"http/1.0"), AlpnProtocol::Http10);
        assert_eq!(AlpnProtocol::from_wire(b"http/1.1"), AlpnProtocol::Http11);
        assert_eq!(AlpnProtocol::from_wire(b"h2"), AlpnProtocol::Http2);
        assert_eq!(AlpnProtocol::from_wire(b"h3"), AlpnProtocol::Http3);
        // RFC 9114 was preceded by a long line of draft codepoints. We saw
        // h3-23, h3-25, h3-27, h3-29, h3-32 deployed in real-world clients
        // for years — the prefix match must classify them as Http3.
        assert_eq!(AlpnProtocol::from_wire(b"h3-29"), AlpnProtocol::Http3);
        assert_eq!(AlpnProtocol::from_wire(b"h3-32"), AlpnProtocol::Http3);
        // Non-HTTP and unknown values land in Other.
        assert_eq!(AlpnProtocol::from_wire(b"acme-tls/1"), AlpnProtocol::Other);
        assert_eq!(AlpnProtocol::from_wire(b"dot"), AlpnProtocol::Other);
        assert_eq!(AlpnProtocol::from_wire(b"doq"), AlpnProtocol::Other);
        assert_eq!(AlpnProtocol::from_wire(b""), AlpnProtocol::Other);
        // h3 prefix without the trailing draft suffix isn't `h3-` — must not
        // false-positive on something like `h3foo`.
        assert_eq!(AlpnProtocol::from_wire(b"h3foo"), AlpnProtocol::Other);
        assert_eq!(AlpnProtocol::from_wire(b"h2c"), AlpnProtocol::Other);
    }

    #[test]
    fn alpn_protocol_kind_strings_are_stable_snake_case() {
        // O2-style stable telemetry labels: any change here breaks
        // dashboards / aggregation pipelines downstream, so pin every one.
        assert_eq!(AlpnProtocol::Http10.kind(), "http_1_0");
        assert_eq!(AlpnProtocol::Http11.kind(), "http_1_1");
        assert_eq!(AlpnProtocol::Http2.kind(), "http_2");
        assert_eq!(AlpnProtocol::Http3.kind(), "http_3");
        assert_eq!(AlpnProtocol::Other.kind(), "other");
    }

    #[test]
    fn alpn_protocol_is_http_excludes_other_only() {
        assert!(AlpnProtocol::Http10.is_http());
        assert!(AlpnProtocol::Http11.is_http());
        assert!(AlpnProtocol::Http2.is_http());
        assert!(AlpnProtocol::Http3.is_http());
        assert!(!AlpnProtocol::Other.is_http());
    }

    #[test]
    fn alpn_classified_preserves_wire_order() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&build_sni_extension("example.com"));
        // Client preference order: h3 > h2 > http/1.1. Pin that classified
        // output is in the same order so a "first acceptable" downstream
        // selector still picks correctly.
        exts.extend_from_slice(&build_alpn_extension(&[b"h3", b"h2", b"http/1.1"]));
        let bytes = build_client_hello(&exts);
        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert_eq!(
            meta.alpn_classified().as_deref(),
            Some(
                &[
                    AlpnProtocol::Http3,
                    AlpnProtocol::Http2,
                    AlpnProtocol::Http11
                ][..]
            ),
        );
    }

    #[test]
    fn alpn_classified_is_none_when_extension_absent() {
        let bytes = build_client_hello(&build_sni_extension("example.com"));
        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert!(meta.alpn_classified().is_none());
        // And offers() returns false in that case — no preference expressed.
        assert!(!meta.offers(AlpnProtocol::Http2));
        assert!(!meta.offers(AlpnProtocol::Http3));
    }

    #[test]
    fn offers_returns_true_for_each_advertised_protocol() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&build_sni_extension("example.com"));
        exts.extend_from_slice(&build_alpn_extension(&[b"h2", b"http/1.1"]));
        let bytes = build_client_hello(&exts);
        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert!(meta.offers(AlpnProtocol::Http2));
        assert!(meta.offers(AlpnProtocol::Http11));
        assert!(!meta.offers(AlpnProtocol::Http3));
        assert!(!meta.offers(AlpnProtocol::Http10));
        assert!(!meta.offers(AlpnProtocol::Other));
    }

    #[test]
    fn offers_recognises_h3_draft_codepoints_as_http3() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&build_sni_extension("example.com"));
        // Real-world client that offers only a draft h3 codepoint.
        exts.extend_from_slice(&build_alpn_extension(&[b"h3-29"]));
        let bytes = build_client_hello(&exts);
        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert!(
            meta.offers(AlpnProtocol::Http3),
            "draft h3-29 must classify as Http3",
        );
    }

    // ── A3: TlsVersion classification ────────────────────────────────────────

    #[test]
    fn tls_version_classifies_the_known_wire_codepoints() {
        assert_eq!(TlsVersion::from_wire(0x0300), TlsVersion::Ssl30);
        assert_eq!(TlsVersion::from_wire(0x0301), TlsVersion::Tls10);
        assert_eq!(TlsVersion::from_wire(0x0302), TlsVersion::Tls11);
        assert_eq!(TlsVersion::from_wire(0x0303), TlsVersion::Tls12);
        assert_eq!(TlsVersion::from_wire(0x0304), TlsVersion::Tls13);
        // GREASE codepoints (RFC 8701): the high and low bytes are equal,
        // bits 0..4 are 0xA. We see them in real ClientHellos as filler.
        assert_eq!(TlsVersion::from_wire(0x0A0A), TlsVersion::Other);
        assert_eq!(TlsVersion::from_wire(0x1A1A), TlsVersion::Other);
        // Future TLS 1.4 codepoint → Other (must not be silently treated
        // as Tls13 or anything else known).
        assert_eq!(TlsVersion::from_wire(0x0305), TlsVersion::Other);
        // Zero and max also Other.
        assert_eq!(TlsVersion::from_wire(0x0000), TlsVersion::Other);
        assert_eq!(TlsVersion::from_wire(0xFFFF), TlsVersion::Other);
    }

    #[test]
    fn tls_version_kind_strings_are_stable_snake_case() {
        // O2 dashboard contract — any change here breaks downstream.
        assert_eq!(TlsVersion::Ssl30.kind(), "ssl_3_0");
        assert_eq!(TlsVersion::Tls10.kind(), "tls_1_0");
        assert_eq!(TlsVersion::Tls11.kind(), "tls_1_1");
        assert_eq!(TlsVersion::Tls12.kind(), "tls_1_2");
        assert_eq!(TlsVersion::Tls13.kind(), "tls_1_3");
        assert_eq!(TlsVersion::Other.kind(), "other");
    }

    #[test]
    fn tls_version_ord_puts_other_below_every_known_version() {
        // The whole point of putting Other first in declaration order: a
        // "modern enough?" check like `>= Tls13` must reject GREASE.
        assert!(TlsVersion::Other < TlsVersion::Ssl30);
        assert!(TlsVersion::Other < TlsVersion::Tls13);
        // Known versions sort in ascending TLS protocol order.
        assert!(TlsVersion::Ssl30 < TlsVersion::Tls10);
        assert!(TlsVersion::Tls10 < TlsVersion::Tls11);
        assert!(TlsVersion::Tls11 < TlsVersion::Tls12);
        assert!(TlsVersion::Tls12 < TlsVersion::Tls13);
        // The two common Layer-2 queries.
        assert!(TlsVersion::Tls13 >= TlsVersion::Tls13);
        assert!(TlsVersion::Other < TlsVersion::Tls13);
    }

    #[test]
    fn supported_versions_classified_preserves_wire_order() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&build_sni_extension("example.com"));
        // Client preference order: 1.3 first, 1.2 fallback. Pin that
        // classified output preserves it (downstream "first acceptable"
        // selectors rely on this).
        exts.extend_from_slice(&build_supported_versions_extension(&[0x0304, 0x0303]));
        let bytes = build_client_hello(&exts);
        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert_eq!(
            meta.supported_versions_classified().as_deref(),
            Some(&[TlsVersion::Tls13, TlsVersion::Tls12][..]),
        );
    }

    #[test]
    fn supported_versions_classified_is_none_when_extension_absent() {
        let bytes = build_client_hello(&build_sni_extension("example.com"));
        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert!(meta.supported_versions_classified().is_none());
    }

    #[test]
    fn highest_supported_tls_version_picks_max_excluding_grease() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&build_sni_extension("example.com"));
        // 1.2 + 1.3 + GREASE: highest must be 1.3, GREASE must not contribute.
        exts.extend_from_slice(&build_supported_versions_extension(&[
            0x0A0A, 0x0303, 0x0304,
        ]));
        let bytes = build_client_hello(&exts);
        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert_eq!(meta.highest_supported_tls_version(), TlsVersion::Tls13);
    }

    #[test]
    fn highest_supported_tls_version_falls_back_to_tls12_without_extension() {
        // Parser enforces legacy_version == 0x0303, so absent extension
        // means TLS 1.2 is the implicit ceiling.
        let bytes = build_client_hello(&build_sni_extension("example.com"));
        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert_eq!(meta.highest_supported_tls_version(), TlsVersion::Tls12);
    }

    #[test]
    fn highest_supported_tls_version_falls_back_to_tls12_when_only_grease() {
        // Pathological CH: supported_versions present but every entry is
        // GREASE. Filter empties; fall back to Tls12 rather than panic on
        // .max().unwrap().
        let mut exts = Vec::new();
        exts.extend_from_slice(&build_sni_extension("example.com"));
        exts.extend_from_slice(&build_supported_versions_extension(&[0x0A0A, 0x1A1A]));
        let bytes = build_client_hello(&exts);
        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert_eq!(meta.highest_supported_tls_version(), TlsVersion::Tls12);
    }

    #[test]
    fn offers_tls_version_when_extension_present() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&build_sni_extension("example.com"));
        exts.extend_from_slice(&build_supported_versions_extension(&[0x0304, 0x0303]));
        let bytes = build_client_hello(&exts);
        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert!(meta.offers_tls_version(TlsVersion::Tls13));
        assert!(meta.offers_tls_version(TlsVersion::Tls12));
        assert!(!meta.offers_tls_version(TlsVersion::Tls11));
        assert!(!meta.offers_tls_version(TlsVersion::Ssl30));
    }

    #[test]
    fn offers_tls_version_implicit_tls12_without_extension() {
        // Without the extension we implicitly know only TLS 1.2 (legacy_version
        // is enforced to 0x0303); offers_tls_version mirrors this.
        let bytes = build_client_hello(&build_sni_extension("example.com"));
        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        assert!(meta.offers_tls_version(TlsVersion::Tls12));
        assert!(!meta.offers_tls_version(TlsVersion::Tls13));
        assert!(!meta.offers_tls_version(TlsVersion::Tls11));
    }

    #[test]
    fn parse_handshake_message_full_borrows_alpn_entries_from_input() {
        // P1/A1 zero-alloc contract: on the borrowed path, every ALPN entry
        // must be Cow::Borrowed (a pointer into the input slice). This test
        // would silently still pass on Cow::Owned — pinning the Borrowed
        // variant explicitly catches accidental allocations in the parser.
        let mut exts = Vec::new();
        exts.extend_from_slice(&build_sni_extension("example.com"));
        exts.extend_from_slice(&build_alpn_extension(&[b"h2"]));
        let bytes = build_client_hello(&exts);

        let meta = parse_client_hello_full(&bytes).expect("well-formed CH");
        let alpn = meta.alpn_protocols.expect("ALPN parsed");
        assert!(
            matches!(alpn[0], Cow::Borrowed(_)),
            "expected borrowed ALPN"
        );
        assert!(
            matches!(meta.host, Some(Cow::Borrowed(_))),
            "expected borrowed host"
        );
    }
}
