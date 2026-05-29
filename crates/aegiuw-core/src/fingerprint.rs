// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS ClientHello fingerprinting — JA3 (and later JA4) over our parsed
//! [`ClientHelloMetadata`].
//!
//! This module is the F-cluster home for the SNI backlog:
//!
//! - **F1** ([`ja3`]): JA3 fingerprint (Althouse/Atkinson/Atkins, 2017).
//!   MD5 of a comma-separated string of TLS version + cipher suites +
//!   extension types + supported_groups + ec_point_formats. GREASE
//!   codepoints excluded per RFC 8701 §3.
//!
//! GREASE filtering is centralised in [`is_grease_codepoint`] so JA3 / JA4 /
//! KnownClient lookup all share the same definition.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::sni::ClientHelloMetadata;

/// `true` if `value` is a GREASE codepoint per RFC 8701 §3.
///
/// GREASE values are intentionally invalid codepoints clients sprinkle into
/// cipher / extension / group lists to stress server implementations into
/// ignoring unknown values. Every TLS fingerprint algorithm must filter
/// them out — otherwise the fingerprint flips on every browser release that
/// re-randomises its GREASE picks.
///
/// The pattern from RFC 8701 §3: the high byte equals the low byte, and the
/// low nibble is `0xA`. That gives `0x0A0A, 0x1A1A, 0x2A2A, …, 0xFAFA`.
///
/// # Examples
///
/// ```
/// use aegiuw_core::fingerprint::is_grease_codepoint;
///
/// assert!(is_grease_codepoint(0x0A0A));
/// assert!(is_grease_codepoint(0xFAFA));
/// assert!(!is_grease_codepoint(0x1301)); // TLS_AES_128_GCM_SHA256
/// assert!(!is_grease_codepoint(0x0000)); // server_name
/// ```
pub const fn is_grease_codepoint(value: u16) -> bool {
    let hi = (value >> 8) as u8;
    let lo = value as u8;
    hi == lo && (lo & 0x0F) == 0x0A
}

/// JA3 fingerprint (SNI backlog F1).
///
/// Two surfaces:
///
/// - [`Ja3::raw`] is the comma-separated input string used by the algorithm.
///   Stable across runs for the same ClientHello. Useful for debugging
///   and for indexing into a JA3 → "likely client" mapping table (F4).
/// - [`Ja3::md5`] is the lowercase hex MD5 digest of `raw`. The classic
///   JA3 hash string seen in threat-intel feeds.
///
/// Why MD5: not for cryptographic strength — the JA3 paper picked it for
/// length (32 hex chars) and ubiquity. Don't read JA3 as "secure"; treat it
/// as a fast fingerprint identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ja3 {
    /// `SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat`
    /// — five comma-separated fields, each a `-`-joined list of decimal
    /// codepoints with GREASE filtered out.
    pub raw: String,
    /// Lowercase hex MD5 of `raw` (32 hex chars).
    pub md5: String,
}

/// Compute the JA3 fingerprint of a parsed ClientHello.
///
/// The algorithm (Althouse/Atkinson/Atkins, 2017):
///
/// 1. Build the comma-separated string
///    `Version,Ciphers,Extensions,SupportedGroups,ECPointFormats`.
///    - `Version`: ClientHello `legacy_version` (we enforce `0x0303` = `771`).
///    - `Ciphers`, `Extensions`, `SupportedGroups`: lists of decimal codepoints
///      joined by `-`, with GREASE codepoints filtered out.
///    - `ECPointFormats`: list of decimal codepoints joined by `-` (no GREASE
///      filter — these are `u8` values).
/// 2. MD5 the resulting string → hex-encode lowercase.
///
/// Returns `Some(_)` for every well-formed CH; the only way to fail is a CH
/// that didn't parse in the first place, which already short-circuits at
/// `parse_client_hello_full`.
///
/// # Examples
///
/// JA3 strings for absent extensions show as empty fields:
///
/// ```text
/// 771,4865,,,
/// 771,4865-4866-4867,0-43-51,29-23-24,0
/// ```
pub fn ja3(meta: &ClientHelloMetadata<'_>) -> Ja3 {
    let mut raw = String::with_capacity(128);

    // 1. legacy_version. We enforce 0x0303 (771) upstream, so this is
    //    always "771" — but write it dynamically so a future relaxation
    //    doesn't silently bake the constant in.
    let _ = write!(raw, "{}", crate::sni::TLS_LEGACY_VERSION);
    raw.push(',');

    // 2. Cipher suites (GREASE filtered).
    write_u16_list(&mut raw, &meta.cipher_suites, true);
    raw.push(',');

    // 3. Extension types in wire order (GREASE filtered).
    write_u16_list(&mut raw, &meta.extension_order, true);
    raw.push(',');

    // 4. supported_groups (GREASE filtered). Empty if extension absent.
    if let Some(groups) = meta.supported_groups.as_deref() {
        write_u16_list(&mut raw, groups, true);
    }
    raw.push(',');

    // 5. ec_point_formats. u8 — no GREASE convention applies.
    if let Some(formats) = meta.ec_point_formats.as_deref() {
        write_u8_list(&mut raw, formats);
    }

    let md5 = md5_hex_lower(raw.as_bytes());
    Ja3 { raw, md5 }
}

/// Push a `-`-joined decimal list of `u16` values into `out`, optionally
/// filtering GREASE.
fn write_u16_list(out: &mut String, values: &[u16], filter_grease: bool) {
    let mut first = true;
    for &v in values {
        if filter_grease && is_grease_codepoint(v) {
            continue;
        }
        if !first {
            out.push('-');
        }
        let _ = write!(out, "{v}");
        first = false;
    }
}

/// Push a `-`-joined decimal list of `u8` values into `out`.
fn write_u8_list(out: &mut String, values: &[u8]) {
    let mut first = true;
    for &v in values {
        if !first {
            out.push('-');
        }
        let _ = write!(out, "{v}");
        first = false;
    }
}

/// Lowercase hex MD5 digest. The classic JA3 representation.
fn md5_hex_lower(input: &[u8]) -> String {
    let digest = Md5::digest(input);
    let mut out = String::with_capacity(32);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ── F2: JA4 fingerprint (FoxIO 2023) ─────────────────────────────────────────

/// JA4 fingerprint (SNI backlog F2).
///
/// Three underscore-separated parts: `a_b_c`. Format from the FoxIO 2023
/// specification:
///
/// | Part | Width | Contents |
/// |---|---|---|
/// | `a` | 10 chars | `{q\|t}{12\|13}{d\|n}{cc}{ee}{aa}` — protocol, TLS version, SNI presence, cipher count, extension count, first ALPN's first+last alphanumeric chars |
/// | `b` | 12 hex chars | SHA-256 of sorted ciphers (sans GREASE) joined by comma; first 12 hex chars |
/// | `c` | 12 hex chars | SHA-256 of sorted extensions (sans GREASE, sans SNI, sans ALPN) + optional `_` + sigalgs in wire order; first 12 hex chars |
///
/// Why JA4 supersedes JA3 for new work: JA3's first field is always `771`
/// (`legacy_version` = `0x0303`) for every TLS 1.3 connection, so it lost
/// version discrimination. JA4 reads `supported_versions` and reports the
/// actual offered version. JA4 also sorts cipher/extension lists so a
/// browser that re-randomises extension order between releases keeps the
/// same fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ja4 {
    /// The `a` segment — protocol + TLS version + SNI + counts + ALPN.
    pub a: String,
    /// The `b` segment — 12 hex chars of the sorted cipher hash.
    pub b: String,
    /// The `c` segment — 12 hex chars of the sorted-extension + sigalg hash.
    pub c: String,
    /// `{a}_{b}_{c}` joined with underscores. The form seen in JA4
    /// threat-intel feeds and dashboards.
    pub raw: String,
}

/// Compute the JA4 fingerprint of a parsed ClientHello.
///
/// Always succeeds for a successfully-parsed `ClientHelloMetadata`. Empty
/// cipher or extension lists hash to the sentinel `"000000000000"` per the
/// FoxIO spec.
///
/// Protocol prefix is always `t` (TCP) — `aegiuw-core` doesn't see QUIC
/// CRYPTO frames directly today; a future QUIC integration that calls
/// [`parse_handshake_message_full`](crate::sni::parse_handshake_message_full)
/// directly would need a separate entry point with `q`.
pub fn ja4(meta: &ClientHelloMetadata<'_>) -> Ja4 {
    let a = ja4_a(meta);
    let b = ja4_b(meta);
    let c = ja4_c(meta);
    let raw = format!("{a}_{b}_{c}");
    Ja4 { a, b, c, raw }
}

/// `a` segment: protocol + TLS version + SNI presence + cipher count +
/// extension count + first-ALPN chars. Fixed 10-char width.
fn ja4_a(meta: &ClientHelloMetadata<'_>) -> String {
    let mut out = String::with_capacity(10);
    // Protocol: we only see TCP at this layer.
    out.push('t');
    // TLS version: highest non-GREASE from supported_versions, falling back
    // to the legacy 0x0303 (TLS 1.2) when the extension is absent.
    out.push_str(ja4_tls_version_str(meta));
    // SNI indicator: 'd' if a host parsed (IPs are rejected upstream as
    // Malformed so 'i' is unreachable here), 'n' if absent.
    out.push(if meta.host.is_some() { 'd' } else { 'n' });
    // Cipher count sans GREASE, 2 digits, clamped to 99.
    let cc = meta
        .cipher_suites
        .iter()
        .filter(|&&v| !is_grease_codepoint(v))
        .count()
        .min(99);
    let _ = write!(out, "{cc:02}");
    // Extension count sans GREASE, 2 digits, clamped to 99.
    let ee = meta
        .extension_order
        .iter()
        .filter(|&&v| !is_grease_codepoint(v))
        .count()
        .min(99);
    let _ = write!(out, "{ee:02}");
    // First ALPN's first + last alphanumeric chars, "00" if absent / empty.
    out.push_str(&ja4_alpn_chars(meta));
    out
}

/// Map the highest non-GREASE offered TLS version to its JA4 2-char code.
fn ja4_tls_version_str(meta: &ClientHelloMetadata<'_>) -> &'static str {
    let highest = meta
        .supported_versions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .copied()
        .filter(|&v| !is_grease_codepoint(v))
        .max()
        // No extension (or all GREASE) → fall back to legacy_version, which
        // our parser enforces to 0x0303 = TLS 1.2.
        .unwrap_or(crate::sni::TLS_LEGACY_VERSION);
    match highest {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

/// First + last alphanumeric byte of the first ALPN value, ASCII. `"00"` if
/// the ALPN extension is absent, the first value is empty, or has no
/// alphanumeric characters.
fn ja4_alpn_chars(meta: &ClientHelloMetadata<'_>) -> String {
    let Some(protos) = meta.alpn_protocols.as_deref() else {
        return "00".to_string();
    };
    let Some(first) = protos.first() else {
        return "00".to_string();
    };
    let bytes: &[u8] = first.as_ref();
    let first_char = bytes
        .iter()
        .copied()
        .find(u8::is_ascii_alphanumeric)
        .map(char::from);
    let last_char = bytes
        .iter()
        .copied()
        .rfind(u8::is_ascii_alphanumeric)
        .map(char::from);
    match (first_char, last_char) {
        (Some(f), Some(l)) => {
            let mut s = String::with_capacity(2);
            s.push(f);
            s.push(l);
            s
        }
        _ => "00".to_string(),
    }
}

/// `b` segment: SHA-256 of the sorted cipher list (sans GREASE) joined by
/// comma in decimal. Returns the first 12 hex chars, or the sentinel
/// `"000000000000"` if no ciphers survive the filter.
fn ja4_b(meta: &ClientHelloMetadata<'_>) -> String {
    let mut ciphers: Vec<u16> = meta
        .cipher_suites
        .iter()
        .copied()
        .filter(|&v| !is_grease_codepoint(v))
        .collect();
    ciphers.sort_unstable();
    let input = join_u16_decimal(&ciphers, ',');
    sha256_first_12_hex(input.as_bytes())
}

/// `c` segment: SHA-256 of the sorted extension list (sans GREASE, sans
/// SNI `0x0000`, sans ALPN `0x0010`) joined by comma; if
/// `signature_algorithms` is present, append `_` then the sigalg list
/// (sans GREASE) in **wire order**. SNI and ALPN are dropped from the
/// extension input because they're already represented in the `a` segment.
fn ja4_c(meta: &ClientHelloMetadata<'_>) -> String {
    let mut exts: Vec<u16> = meta
        .extension_order
        .iter()
        .copied()
        .filter(|&v| !is_grease_codepoint(v))
        .filter(|&v| v != crate::sni::EXT_SERVER_NAME && v != crate::sni::EXT_ALPN)
        .collect();
    exts.sort_unstable();
    let mut input = join_u16_decimal(&exts, ',');
    if let Some(sigs) = meta.signature_algorithms.as_deref() {
        let filtered: Vec<u16> = sigs
            .iter()
            .copied()
            .filter(|&v| !is_grease_codepoint(v))
            .collect();
        if !filtered.is_empty() {
            input.push('_');
            input.push_str(&join_u16_decimal(&filtered, ','));
        }
    }
    sha256_first_12_hex(input.as_bytes())
}

fn join_u16_decimal(values: &[u16], sep: char) -> String {
    let mut out = String::with_capacity(values.len() * 4);
    let mut first = true;
    for &v in values {
        if !first {
            out.push(sep);
        }
        let _ = write!(out, "{v}");
        first = false;
    }
    out
}

/// First 12 hex chars of SHA-256(input), lowercase. Returns the FoxIO
/// sentinel `"000000000000"` for empty input (an empty cipher / extension
/// list with no sigalgs).
fn sha256_first_12_hex(input: &[u8]) -> String {
    if input.is_empty() {
        return "000000000000".to_string();
    }
    let digest = Sha256::digest(input);
    let mut out = String::with_capacity(12);
    for byte in digest.iter().take(6) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ── F3: JA4_H stub (HTTP-layer fingerprint) ──────────────────────────────────

/// Input the daemon's HTTP layer collects from each HTTP request and
/// forwards into [`ja4_h`].
///
/// JA4_H is the HTTP-layer fingerprint half of the JA4 suite (FoxIO 2023):
/// it characterises a client by HTTP method, version, header order, cookie
/// presence, and Accept-Language. None of those signals are visible to
/// `aegiuw-core` itself — we only see the TLS handshake. So we ship the
/// type and the entry point in the core (for shared serde shape and a
/// stable public API) and stub the implementation until the daemon's
/// HTTP layer is wired up.
///
/// **Stub scope:** the daemon collects these fields and passes them in;
/// [`ja4_h`] then assembles them into the JA4_H string. The current
/// implementation returns a sentinel — see [`ja4_h`] for the contract.
///
/// SNI backlog F3.
///
/// Not `Serialize`/`Deserialize` — this is a borrowed view over caller-held
/// header data, constructed at the call site and consumed immediately. If
/// you need to persist the input, build a separate owned type and convert
/// at the boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ja4HInput<'a> {
    /// HTTP method as ASCII uppercase (`"GET"`, `"POST"`, …). The JA4_H
    /// `a` segment uses the first two characters.
    pub method: &'a str,
    /// HTTP major version: `"11"` for HTTP/1.1, `"20"` for HTTP/2,
    /// `"30"` for HTTP/3. JA4_H pads to 2 chars.
    pub version: &'a str,
    /// Whether a `Cookie` header was sent (`c` if yes, `n` if no).
    pub has_cookie: bool,
    /// Whether a `Referer` header was sent (`r` if yes, `n` if no).
    pub has_referer: bool,
    /// Header names as the client sent them, in wire order. JA4_H hashes
    /// a filtered, lowercased version for its `b` segment.
    pub header_names: &'a [&'a str],
    /// Value of the `Accept-Language` header if present, else `""`.
    /// JA4_H takes the first 4 alphabetic chars (e.g. `"en-U"` from
    /// `"en-US,en;q=0.9"`).
    pub accept_language: &'a str,
}

/// Compute the JA4_H HTTP-layer fingerprint (SNI backlog F3).
///
/// **Stub:** returns a placeholder string that includes the input shape
/// so the call site is wired up but downstream code can detect "not yet
/// implemented" without crashing. The shape matches the JA4_H format
/// (`{a}_{b}_{c}_{d}`) but each segment is a sentinel.
///
/// The real implementation lands once the daemon's HTTP layer collects
/// the [`Ja4HInput`] fields per request. Until then, this entry point
/// keeps the public API stable: downstream consumers can call `ja4_h`
/// today and only need to recompile (not refactor) when the
/// implementation arrives.
///
/// # Why a stub in core
///
/// The JA4 suite (`ja4`, `ja4_h`, `ja4_s`, `ja4_x`, `ja4_t`) shares a
/// hash-and-format convention. Centralising the entry points in
/// `aegiuw_core::fingerprint` keeps the serde shapes and label
/// conventions consistent across the suite.
pub fn ja4_h(_input: &Ja4HInput<'_>) -> Ja4H {
    Ja4H {
        a: "00000000".to_string(),
        b: "000000000000".to_string(),
        c: "000000000000".to_string(),
        d: "000000000000".to_string(),
        raw: "00000000_000000000000_000000000000_000000000000".to_string(),
        implemented: false,
    }
}

/// JA4_H HTTP-layer fingerprint (SNI backlog F3 — stub today).
///
/// Format: `{a}_{b}_{c}_{d}`.
///
/// - `a` (8 chars): method (2) + version (2) + cookie/referer flags (2)
///   + Accept-Language first 4 alphanumeric (padded with `0`).
/// - `b` (12 hex): SHA-256 of filtered, lowercased, comma-joined header
///   list; first 12 hex chars.
/// - `c` (12 hex): SHA-256 of cookie field name list, first 12 hex chars.
///   `"000000000000"` if no cookies.
/// - `d` (12 hex): SHA-256 of cookie field-value pair list, first 12 hex
///   chars. `"000000000000"` if no cookies.
///
/// [`implemented`](Ja4H::implemented) is `false` while the stub is in
/// place; callers should treat the segment strings as opaque sentinels.
///
/// [`implemented`]: Ja4H::implemented
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ja4H {
    pub a: String,
    pub b: String,
    pub c: String,
    pub d: String,
    pub raw: String,
    /// `false` while [`ja4_h`] is a stub; `true` once the real algorithm
    /// lands. Downstream filters / dashboards can gate JA4_H-based
    /// decisions on this flag.
    pub implemented: bool,
}

// ── F4: JA3 / JA4 → KnownClient mapping ──────────────────────────────────────

/// Bucketed identification of the TLS client that produced a fingerprint
/// (SNI backlog F4). Intentionally coarse — we want to ask "is this a
/// real browser?" not "which patch version of Chrome?".
///
/// `Other` covers anything not in our [built-in starter
/// table](KNOWN_JA4_FINGERPRINTS) — including most CLI tools, embedded TLS
/// stacks, and *any* version of Chrome / Firefox / Safari that doesn't
/// match a specific fingerprint we shipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnownClient {
    Chrome,
    Firefox,
    Safari,
    /// `curl` (and tools that link the same TLS stack, e.g. older `wget`).
    Curl,
    /// Go's `crypto/tls` (default `net/http` client).
    Go,
    /// Anything not matched by the built-in starter table.
    Other,
}

impl KnownClient {
    /// Stable lowercase string for telemetry dimensions, mirroring the
    /// O2 / A2 / A3 convention.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Curl => "curl",
            Self::Go => "go",
            Self::Other => "other",
        }
    }
}

/// Look up a JA3 MD5 hash in the built-in starter table. Returns
/// `Some(KnownClient)` only for exact matches.
///
/// **Scope:** the table is a small set of well-documented public
/// fingerprints, intended as a starting point. Real deployments should
/// layer a production fingerprint database on top (the JA4 ecosystem
/// is rapidly evolving — pinning specific hashes in source ages quickly).
///
/// See [`KNOWN_JA3_FINGERPRINTS`] for the table contents.
pub fn known_client_from_ja3(ja3_md5: &str) -> Option<KnownClient> {
    KNOWN_JA3_FINGERPRINTS
        .iter()
        .find(|(fp, _)| *fp == ja3_md5)
        .map(|(_, c)| *c)
}

/// Look up a JA4 raw fingerprint (the underscore-joined `a_b_c` form) in
/// the built-in starter table.
///
/// See [`KNOWN_JA4_FINGERPRINTS`] for the table contents.
pub fn known_client_from_ja4(ja4_raw: &str) -> Option<KnownClient> {
    KNOWN_JA4_FINGERPRINTS
        .iter()
        .find(|(fp, _)| *fp == ja4_raw)
        .map(|(_, c)| *c)
}

/// Built-in JA3 → [`KnownClient`] starter table.
///
/// **Curation policy:** entries here must come from publicly-documented
/// sources (research papers, FoxIO blog posts, ja3er.com archives). JA3
/// hashes are particularly fragile — a single browser-version update can
/// reshuffle extension order and flip the hash. Treat this as a tiny
/// reference set, not a production directory.
pub const KNOWN_JA3_FINGERPRINTS: &[(&str, KnownClient)] = &[
    // No JA3 entries shipped: the JA3 ecosystem has effectively been
    // superseded by JA4 (which is sort-invariant and survives browser
    // extension-order randomisation). Callers can extend at the call site
    // by checking their own table before falling back to ours.
];

/// Built-in JA4 → [`KnownClient`] starter table.
///
/// JA4 is sort-stable so its hashes age much better than JA3. The
/// fingerprints below are seeded from FoxIO's public reference material
/// (the "Introducing JA4+" blog and the open-sourced `ja4` repository).
/// Production deployments should still layer their own data on top — the
/// table is a starting point, not an exhaustive directory.
pub const KNOWN_JA4_FINGERPRINTS: &[(&str, KnownClient)] = &[
    // FoxIO 2023 reference: a representative Chrome JA4 from a TLS 1.3 +
    // X25519 + h2-ALPN handshake. Documented in the "Introducing JA4+"
    // launch post (foxio.io/blog/ja4-network-fingerprinting).
    ("t13d1516h2_8daaf6152771_b186095e22b6", KnownClient::Chrome),
];

#[cfg(test)]
mod tests {
    use alloc::borrow::Cow;
    use alloc::string::ToString;
    use alloc::vec;

    use crate::sni::ClientHelloMetadata;

    use super::*;

    /// Minimal `ClientHelloMetadata` skeleton for fingerprint tests —
    /// every field at its absent / empty default so individual tests can
    /// fill in just what they exercise.
    fn empty_meta<'a>() -> ClientHelloMetadata<'a> {
        ClientHelloMetadata {
            host: None,
            ech_present: false,
            alpn_protocols: None,
            supported_versions: None,
            key_share_groups: None,
            psk_present: false,
            early_data_present: false,
            compress_certificate_present: false,
            record_size_limit: None,
            signature_algorithms: None,
            supported_groups: None,
            ec_point_formats: None,
            extension_order: Vec::new(),
            cipher_suites: Vec::new(),
        }
    }

    #[test]
    fn grease_pattern_matches_rfc_8701_codepoints() {
        // RFC 8701 §3.1 lists the 16 GREASE values:
        //   0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        //   0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA.
        for nibble in 0..=15u8 {
            let value = (u16::from(nibble) << 12) | (u16::from(nibble) << 4) | 0x0A0A;
            assert!(
                is_grease_codepoint(value),
                "expected GREASE for {value:#06x}"
            );
        }
        // And a handful of obviously-not-GREASE codepoints:
        for not_grease in [
            0x0000u16, // server_name
            0x0010,    // ALPN
            0x0017,    // secp256r1
            0x001d,    // x25519
            0x1301,    // TLS_AES_128_GCM_SHA256
            0xc02b,    // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0x0303,    // TLS_LEGACY_VERSION
            0x0A0B,    // off-by-one from GREASE: 0x0A0A
        ] {
            assert!(!is_grease_codepoint(not_grease));
        }
    }

    #[test]
    fn ja3_minimal_clienthello_renders_771_with_empty_lists() {
        let mut meta = empty_meta();
        meta.cipher_suites = vec![0x1301]; // single TLS_AES_128_GCM_SHA256
        let ja3 = ja3(&meta);
        // "771" + cipher + nothing else.
        assert_eq!(ja3.raw, "771,4865,,,");
        // MD5("771,4865,,,") — independent verification:
        //   printf '%s' '771,4865,,,' | md5sum
        //   ea1e247991e541e39bf918cb7cfa5139
        assert_eq!(ja3.md5, "ea1e247991e541e39bf918cb7cfa5139");
    }

    #[test]
    fn ja3_filters_grease_from_cipher_extension_and_group_lists() {
        let mut meta = empty_meta();
        // GREASE-padded cipher list: real ciphers + interleaved GREASE.
        meta.cipher_suites = vec![0x0A0A, 0x1301, 0x1302, 0x1A1A];
        meta.extension_order = vec![0xCACA, 0x0000, 0x0010, 0xFAFA];
        meta.supported_groups = Some(vec![0x6A6A, 0x001d, 0x0017]);
        // ec_point_formats has no GREASE convention; all values pass through.
        meta.ec_point_formats = Some(vec![0]);

        let ja3 = ja3(&meta);
        assert_eq!(ja3.raw, "771,4865-4866,0-16,29-23,0");
    }

    #[test]
    fn ja3_empty_optional_fields_render_as_empty_strings() {
        let mut meta = empty_meta();
        meta.cipher_suites = vec![0x1301];
        // supported_groups: Some(empty) shouldn't happen (parser rejects
        // empty list as Malformed) but pin the renderer's behaviour anyway.
        meta.supported_groups = Some(vec![]);
        meta.ec_point_formats = Some(vec![]);
        let ja3 = ja3(&meta);
        assert_eq!(ja3.raw, "771,4865,,,");
    }

    #[test]
    fn ja3_md5_is_32_lowercase_hex_chars() {
        let mut meta = empty_meta();
        meta.cipher_suites = vec![0x1301];
        let ja3 = ja3(&meta);
        assert_eq!(ja3.md5.len(), 32);
        assert!(
            ja3.md5
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "expected lowercase hex, got {}",
            ja3.md5,
        );
    }

    #[test]
    fn ja3_preserves_wire_order_within_each_field() {
        // The original JA3 paper: lists are joined in *wire* order, NOT sorted.
        // (JA4 sorts cipher/extension lists — JA3 deliberately does not.)
        let mut meta = empty_meta();
        meta.cipher_suites = vec![0x1303, 0x1301, 0x1302]; // reverse-ish
        meta.extension_order = vec![0x0010, 0x0000, 0x002b]; // ALPN before SNI
        let ja3 = ja3(&meta);
        assert!(
            ja3.raw.starts_with("771,4867-4865-4866,16-0-43,"),
            "wire order should survive: {}",
            ja3.raw,
        );
    }

    #[test]
    fn ja3_reference_fingerprint_for_chrome_like_clienthello() {
        // Realistic mini-Chrome shape: TLS 1.3 cipher set + the typical
        // extension order + x25519 + secp256r1 + uncompressed point format.
        // The MD5 below is computed against the rendered raw string,
        // independent of this code path — change with care.
        let mut meta = empty_meta();
        meta.cipher_suites = vec![0x1301, 0x1302, 0x1303];
        meta.extension_order = vec![
            0x0000, // server_name
            0x000a, // supported_groups
            0x000b, // ec_point_formats
            0x000d, // signature_algorithms
            0x0010, // ALPN
            0x002b, // supported_versions
            0x0033, // key_share
        ];
        meta.supported_groups = Some(vec![0x001d, 0x0017, 0x0018]);
        meta.ec_point_formats = Some(vec![0]);
        let ja3 = ja3(&meta);
        assert_eq!(ja3.raw, "771,4865-4866-4867,0-10-11-13-16-43-51,29-23-24,0",);
        // Independent verification (any external MD5):
        //   printf '%s' '771,4865-4866-4867,0-10-11-13-16-43-51,29-23-24,0' | md5sum
        //   18b09f675f7eb9f71106f787ac17abaa
        assert_eq!(ja3.md5, "18b09f675f7eb9f71106f787ac17abaa");
    }

    // ── Sanity: a real-traffic-shaped struct path through parse_client_hello_full
    // is exercised in sni.rs's test suite; here we focus on the algorithm itself
    // so failures localise to the renderer / hasher.

    #[test]
    fn ja3_with_host_and_alpn_doesnt_affect_string() {
        // JA3 deliberately doesn't include the SNI host or ALPN values — only
        // the *extension type code* shows up in the third field. Adding a host
        // or ALPN entries to the metadata must not change the JA3 raw string.
        let mut meta = empty_meta();
        meta.cipher_suites = vec![0x1301];
        meta.extension_order = vec![0x0000, 0x0010];
        let baseline = ja3(&meta);

        meta.host = Some(Cow::Owned("example.com".to_string()));
        meta.alpn_protocols = Some(vec![Cow::Borrowed(b"h2".as_slice())]);
        let with_host = ja3(&meta);

        assert_eq!(baseline, with_host);
    }

    // ── F2: JA4 ──────────────────────────────────────────────────────────────

    /// Build a Chrome-like ClientHelloMetadata used by several JA4 tests.
    fn chrome_like_meta<'a>() -> ClientHelloMetadata<'a> {
        let mut meta = empty_meta();
        meta.host = Some(Cow::Borrowed("example.com"));
        meta.cipher_suites = vec![0x1301, 0x1302, 0x1303];
        meta.extension_order = vec![
            0x0000, // server_name (excluded from JA4_c)
            0x000a, // supported_groups
            0x000b, // ec_point_formats
            0x000d, // signature_algorithms
            0x0010, // ALPN (excluded from JA4_c)
            0x002b, // supported_versions
            0x0033, // key_share
        ];
        meta.alpn_protocols = Some(vec![Cow::Borrowed(b"h2".as_slice())]);
        meta.supported_versions = Some(vec![0x0304, 0x0303]);
        meta.supported_groups = Some(vec![0x001d, 0x0017, 0x0018]);
        meta.ec_point_formats = Some(vec![0]);
        meta.signature_algorithms = Some(vec![0x0403, 0x0804, 0x0401]);
        meta
    }

    #[test]
    fn ja4_a_segment_for_chrome_like_clienthello() {
        let meta = chrome_like_meta();
        let ja4 = ja4(&meta);
        // t (TCP) + 13 (TLS 1.3) + d (SNI domain) + 03 (3 ciphers, sans GREASE)
        // + 07 (7 extensions, sans GREASE) + h2 (first ALPN's first+last alnum).
        assert_eq!(ja4.a, "t13d0307h2");
    }

    #[test]
    fn ja4_b_hashes_sorted_cipher_list() {
        let meta = chrome_like_meta();
        let ja4 = ja4(&meta);
        // SHA-256('4865,4866,4867') first 12 hex:
        //   printf '%s' '4865,4866,4867' | sha256sum | head -c 12
        //   12e7d38c872c
        assert_eq!(ja4.b, "12e7d38c872c");
    }

    #[test]
    fn ja4_c_includes_sigalgs_when_present() {
        let meta = chrome_like_meta();
        let ja4 = ja4(&meta);
        // Sorted exts sans SNI(0) and ALPN(16): 10,11,13,43,51
        // Then "_" + sigalgs in WIRE order (NOT sorted): 1027,2052,1025
        //   printf '%s' '10,11,13,43,51_1027,2052,1025' | sha256sum | head -c 12
        //   bc990851d7f5
        assert_eq!(ja4.c, "bc990851d7f5");
    }

    #[test]
    fn ja4_raw_is_underscore_joined_three_parts() {
        let meta = chrome_like_meta();
        let ja4 = ja4(&meta);
        assert_eq!(ja4.raw, format!("{}_{}_{}", ja4.a, ja4.b, ja4.c));
    }

    #[test]
    fn ja4_c_drops_sigalgs_section_when_absent() {
        let mut meta = chrome_like_meta();
        meta.signature_algorithms = None;
        let ja4 = ja4(&meta);
        // Same exts but no "_sigs" trailer:
        //   printf '%s' '10,11,13,43,51' | sha256sum | head -c 12
        //   b87188ea39eb
        assert_eq!(ja4.c, "b87188ea39eb");
    }

    #[test]
    fn ja4_a_uses_n_when_sni_absent() {
        let mut meta = chrome_like_meta();
        meta.host = None;
        let ja4 = ja4(&meta);
        // Third char is 'n' instead of 'd'.
        assert_eq!(&ja4.a[..3], "t13");
        assert_eq!(&ja4.a[3..4], "n");
    }

    #[test]
    fn ja4_a_uses_00_when_alpn_absent() {
        let mut meta = chrome_like_meta();
        meta.alpn_protocols = None;
        let ja4 = ja4(&meta);
        // Last two chars of `a` are 00 when no ALPN.
        assert_eq!(&ja4.a[8..10], "00");
    }

    #[test]
    fn ja4_alpn_chars_picks_first_and_last_alphanumeric() {
        // http/1.1 → first alphanumeric 'h', last alphanumeric '1'.
        let mut meta = empty_meta();
        meta.cipher_suites = vec![0x1301];
        meta.alpn_protocols = Some(vec![Cow::Borrowed(b"http/1.1".as_slice())]);
        meta.supported_versions = Some(vec![0x0304]);
        let ja4 = ja4(&meta);
        assert_eq!(&ja4.a[8..10], "h1");
    }

    #[test]
    fn ja4_alpn_chars_h3_draft_codepoint_collapses_to_h9() {
        // h3-29 → first 'h', last '9'.
        let mut meta = empty_meta();
        meta.cipher_suites = vec![0x1301];
        meta.alpn_protocols = Some(vec![Cow::Borrowed(b"h3-29".as_slice())]);
        meta.supported_versions = Some(vec![0x0304]);
        let ja4 = ja4(&meta);
        assert_eq!(&ja4.a[8..10], "h9");
    }

    #[test]
    fn ja4_filters_grease_from_cipher_and_ext_counts() {
        let mut meta = empty_meta();
        // Three real ciphers + two GREASE — count must be 03.
        meta.cipher_suites = vec![0x0A0A, 0x1301, 0x1302, 0x1303, 0x1A1A];
        // Three real extensions + one GREASE — count must be 03.
        meta.extension_order = vec![0xCACA, 0x0000, 0x002b, 0x0033];
        meta.supported_versions = Some(vec![0x0304]);
        meta.host = Some(Cow::Borrowed("example.com"));
        let ja4 = ja4(&meta);
        // a = t + 13 + d + 03 + 03 + 00
        assert_eq!(ja4.a, "t13d030300");
    }

    #[test]
    fn ja4_tls_version_falls_back_to_legacy_when_no_supported_versions() {
        let mut meta = empty_meta();
        meta.cipher_suites = vec![0x1301];
        meta.host = Some(Cow::Borrowed("example.com"));
        // Without supported_versions, we report TLS 1.2 (legacy_version
        // enforced to 0x0303 by our parser).
        let ja4 = ja4(&meta);
        assert_eq!(&ja4.a[..3], "t12");
    }

    #[test]
    fn ja4_b_empty_cipher_list_returns_sentinel() {
        let mut meta = empty_meta();
        meta.cipher_suites = vec![]; // pathological — parser rejects but the helper must not panic
        meta.host = Some(Cow::Borrowed("example.com"));
        let ja4 = ja4(&meta);
        assert_eq!(ja4.b, "000000000000");
    }

    #[test]
    fn ja4_c_empty_returns_sentinel_when_no_exts_no_sigs() {
        let mut meta = empty_meta();
        meta.cipher_suites = vec![0x1301];
        meta.host = Some(Cow::Borrowed("example.com"));
        // No extensions at all → c is the sentinel.
        let ja4 = ja4(&meta);
        assert_eq!(ja4.c, "000000000000");
    }

    #[test]
    fn ja4_b_sorts_ciphers_independent_of_wire_order() {
        // JA4 sorts cipher list (JA3 doesn't — pinned by ja3_preserves_wire_order_within_each_field).
        let mut meta_a = empty_meta();
        meta_a.cipher_suites = vec![0x1301, 0x1302, 0x1303];
        meta_a.host = Some(Cow::Borrowed("example.com"));

        let mut meta_b = empty_meta();
        meta_b.cipher_suites = vec![0x1303, 0x1301, 0x1302]; // permuted
        meta_b.host = Some(Cow::Borrowed("example.com"));

        // Equal JA4_b means the sort happened.
        assert_eq!(ja4(&meta_a).b, ja4(&meta_b).b);
    }

    // ── F3: JA4_H stub ───────────────────────────────────────────────────────

    #[test]
    fn ja4_h_stub_returns_implemented_false() {
        let input = Ja4HInput {
            method: "GET",
            version: "20",
            has_cookie: true,
            has_referer: false,
            header_names: &["host", "user-agent", "accept"],
            accept_language: "en-US,en;q=0.9",
        };
        let result = ja4_h(&input);
        assert!(
            !result.implemented,
            "stub must signal not-yet-implemented so callers can gate decisions",
        );
    }

    #[test]
    fn ja4_h_stub_segments_have_correct_widths() {
        // Even as a stub, the shape of each segment must match the spec —
        // downstream parsers shouldn't have to special-case the stub form.
        let input = Ja4HInput {
            method: "POST",
            version: "11",
            has_cookie: false,
            has_referer: false,
            header_names: &[],
            accept_language: "",
        };
        let result = ja4_h(&input);
        assert_eq!(result.a.len(), 8, "a segment must be 8 chars wide");
        assert_eq!(result.b.len(), 12, "b segment must be 12 hex chars");
        assert_eq!(result.c.len(), 12, "c segment must be 12 hex chars");
        assert_eq!(result.d.len(), 12, "d segment must be 12 hex chars");
    }

    #[test]
    fn ja4_h_stub_raw_is_underscore_joined_four_parts() {
        let input = Ja4HInput {
            method: "GET",
            version: "20",
            has_cookie: false,
            has_referer: false,
            header_names: &[],
            accept_language: "",
        };
        let result = ja4_h(&input);
        assert_eq!(
            result.raw,
            format!("{}_{}_{}_{}", result.a, result.b, result.c, result.d)
        );
    }

    // ── F4: KnownClient lookup ───────────────────────────────────────────────

    #[test]
    fn known_client_kind_strings_are_stable_snake_case() {
        // O2 / A2 / A3 dashboard convention. Any rename here breaks
        // downstream telemetry — pin every variant.
        assert_eq!(KnownClient::Chrome.kind(), "chrome");
        assert_eq!(KnownClient::Firefox.kind(), "firefox");
        assert_eq!(KnownClient::Safari.kind(), "safari");
        assert_eq!(KnownClient::Curl.kind(), "curl");
        assert_eq!(KnownClient::Go.kind(), "go");
        assert_eq!(KnownClient::Other.kind(), "other");
    }

    #[test]
    fn known_client_from_ja4_matches_seeded_chrome_entry() {
        // The FoxIO 2023 reference fingerprint shipped in the starter table.
        // Documented in foxio.io/blog/ja4-network-fingerprinting.
        assert_eq!(
            known_client_from_ja4("t13d1516h2_8daaf6152771_b186095e22b6"),
            Some(KnownClient::Chrome),
        );
    }

    #[test]
    fn known_client_from_ja4_returns_none_for_unknown_fingerprints() {
        assert_eq!(
            known_client_from_ja4("t13d0000h2_aaaaaaaaaaaa_bbbbbbbbbbbb"),
            None
        );
        assert_eq!(known_client_from_ja4(""), None);
    }

    #[test]
    fn known_client_from_ja3_returns_none_for_anything() {
        // The starter table ships with no JA3 entries (JA3 hashes are
        // fragile across browser releases; JA4 is the canonical surface).
        // Pin the empty-table contract so a future PR can't quietly slip
        // in unverified entries.
        assert!(KNOWN_JA3_FINGERPRINTS.is_empty());
        assert_eq!(
            known_client_from_ja3("d41d8cd98f00b204e9800998ecf8427e"),
            None
        );
    }

    #[test]
    fn known_client_lookup_round_trips_via_ja4_pipeline() {
        // End-to-end smoke: build a meta that produces the seeded JA4,
        // then look up the result. This is the "would real code work"
        // path that wires F2 → F4.
        let mut meta = empty_meta();
        // We can't recover the exact JA4 from synthetic metadata easily —
        // instead, smoke-test the *interface* by feeding the raw form of
        // any computed JA4 through the lookup and checking the type.
        meta.cipher_suites = vec![0x1301];
        meta.host = Some(Cow::Borrowed("example.com"));
        let computed_ja4 = ja4(&meta);
        // This synthetic JA4 won't be in the table, but the lookup must
        // accept a real Ja4::raw string without panic.
        let _ = known_client_from_ja4(&computed_ja4.raw);
    }

    #[test]
    fn known_client_table_entries_are_well_formed() {
        // Pin shape: every entry's JA4 string has the t/q prefix + version
        // + valid alphanumeric chars + underscores. Catches typos in the
        // table at compile-affecting test time rather than at production.
        for (fp, _client) in KNOWN_JA4_FINGERPRINTS {
            let parts: Vec<&str> = fp.split('_').collect();
            assert_eq!(
                parts.len(),
                3,
                "JA4 must have 3 underscore-joined segments: {fp}"
            );
            assert!(
                matches!(parts[0].chars().next(), Some('t' | 'q')),
                "JA4_a must start t or q: {fp}"
            );
            assert_eq!(parts[1].len(), 12, "JA4_b must be 12 hex chars: {fp}");
            assert_eq!(parts[2].len(), 12, "JA4_c must be 12 hex chars: {fp}");
        }
    }
}
