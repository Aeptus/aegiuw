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

use alloc::string::String;
use core::fmt::Write as _;

use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};

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
}
