// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared logic for the aegiuw SNI debug tools.
//!
//! Two binaries live in this crate:
//! - `aegiuw-sni-inspect` (SNI backlog U1) — deep dump of a single ClientHello.
//! - `aegiuw-sni-replay`  (SNI backlog U3) — batch-replay many ClientHellos
//!   through [`aegiuw_core::extract_sni`] and report an outcome histogram.
//!
//! The shared pieces are the [`decode_hex`] helper and the pure, testable
//! [`OutcomeHistogram`] aggregation type.

use std::cmp::Reverse;
use std::collections::BTreeMap;

/// Decode a string of hex characters into bytes. Any character not in
/// `[0-9A-Fa-f]` is stripped before pairing nibbles, so whitespace,
/// commas, and colons (e.g. tshark's `16:03:01:…` field output) are all
/// tolerated. Returns `Err` on an odd nibble count after stripping.
///
/// **Not** prefix-aware: a `0x`-prefixed blob like `0x16` keeps the leading
/// `0` and drops only the `x`, yielding `[0x01, 0x6…]` — strip `0x`
/// yourself if your input uses it. Real capture exports (tshark, tcpdump)
/// emit bare or `:`-separated hex, so this hasn't been needed.
pub fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() % 2 != 0 {
        return Err(format!(
            "odd number of hex digits ({}); pairs required",
            cleaned.len(),
        ));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // `cleaned` contains only ASCII hex digits, so both nibble lookups
        // succeed; the `?` is defence-in-depth, never taken in practice.
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(format!("invalid hex byte: {other:#04x}")),
    }
}

/// Running tally of `extract_sni` outcomes across a replay run (SNI backlog U3).
///
/// The four outcome buckets key off the stable [`aegiuw_core::SniOutcome::kind`]
/// strings (the O2 telemetry labels), so this histogram buckets traffic
/// identically to any downstream Prometheus dashboard. `decode_errors`
/// counts input lines that weren't valid hex (kept separate from the parse
/// outcomes — a decode error means we never got bytes to parse).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OutcomeHistogram {
    pub cleartext: u64,
    pub encrypted: u64,
    pub not_found: u64,
    pub malformed: u64,
    pub decode_errors: u64,
    /// Per-host counts for `Cleartext` outcomes — `BTreeMap` for
    /// deterministic iteration order (tests and reproducible reports).
    host_counts: BTreeMap<String, u64>,
}

impl OutcomeHistogram {
    /// Record one parse outcome by its [`aegiuw_core::SniOutcome::kind`]
    /// string. Unknown kinds are ignored (the four labels are stable, but
    /// staying total avoids a panic if O2 ever grows a variant).
    pub fn record_kind(&mut self, kind: &str) {
        match kind {
            "cleartext" => self.cleartext += 1,
            "encrypted" => self.encrypted += 1,
            "not_found" => self.not_found += 1,
            "malformed" => self.malformed += 1,
            _ => {}
        }
    }

    /// Record a `Cleartext` host. Call alongside `record_kind("cleartext")`.
    pub fn record_host(&mut self, host: &str) {
        *self.host_counts.entry(host.to_string()).or_insert(0) += 1;
    }

    /// Record an input line that failed hex decoding (never reached the parser).
    pub fn record_decode_error(&mut self) {
        self.decode_errors += 1;
    }

    /// Count of lines that reached the parser (all four outcome buckets).
    /// Excludes `decode_errors`.
    pub fn total_parsed(&self) -> u64 {
        self.cleartext + self.encrypted + self.not_found + self.malformed
    }

    /// Total input lines processed, including those that failed hex decoding.
    pub fn total_lines(&self) -> u64 {
        self.total_parsed() + self.decode_errors
    }

    /// ECH adoption: the fraction of *successfully parsed* ClientHellos
    /// that carried ECH (`encrypted` / `total_parsed`). Returns `0.0` when
    /// nothing parsed, so the caller never divides by zero. This is the
    /// headline metric a replay over real traffic produces — see the D2
    /// "ECH adoption" module docs for context.
    pub fn ech_adoption_fraction(&self) -> f64 {
        let parsed = self.total_parsed();
        if parsed == 0 {
            0.0
        } else {
            self.encrypted as f64 / parsed as f64
        }
    }

    /// Top `n` cleartext hosts by count, descending. Ties broken by host
    /// name ascending so the output is deterministic.
    pub fn top_hosts(&self, n: usize) -> Vec<(String, u64)> {
        let mut pairs: Vec<(String, u64)> = self
            .host_counts
            .iter()
            .map(|(h, &c)| (h.clone(), c))
            .collect();
        // (count desc, host asc). `BTreeMap` already yields host-asc, so a
        // stable sort by count-desc preserves name order within a tie.
        pairs.sort_by_key(|p| Reverse(p.1));
        pairs.truncate(n);
        pairs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_tolerates_whitespace_commas_and_colons() {
        assert_eq!(decode_hex("16 03 01").unwrap(), vec![0x16, 0x03, 0x01]);
        assert_eq!(decode_hex("16,03,01").unwrap(), vec![0x16, 0x03, 0x01]);
        // tshark's `tls.record` field output uses colon separators.
        assert_eq!(
            decode_hex("DE:AD:BE:EF").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_hex_is_not_0x_prefix_aware() {
        // Documents the sharp edge: per-token `0x` prefixes keep the leading
        // `0` and drop only `x`, mangling the bytes. `0x16,0x03` → digits
        // "016003" → [0x01, 0x60, 0x03], not [0x16, 0x03]. Callers must
        // strip `0x` themselves. (Real capture exports never use it.)
        assert_eq!(decode_hex("0x16,0x03").unwrap(), vec![0x01, 0x60, 0x03]);
    }

    #[test]
    fn decode_hex_rejects_odd_nibble_count() {
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn histogram_buckets_by_kind_string() {
        let mut h = OutcomeHistogram::default();
        h.record_kind("cleartext");
        h.record_kind("cleartext");
        h.record_kind("encrypted");
        h.record_kind("not_found");
        h.record_kind("malformed");
        h.record_kind("bogus_future_kind"); // ignored, stays total
        assert_eq!(h.cleartext, 2);
        assert_eq!(h.encrypted, 1);
        assert_eq!(h.not_found, 1);
        assert_eq!(h.malformed, 1);
        assert_eq!(h.total_parsed(), 5);
    }

    #[test]
    fn histogram_separates_decode_errors_from_parsed() {
        let mut h = OutcomeHistogram::default();
        h.record_kind("cleartext");
        h.record_decode_error();
        h.record_decode_error();
        assert_eq!(h.total_parsed(), 1);
        assert_eq!(h.total_lines(), 3);
        assert_eq!(h.decode_errors, 2);
    }

    #[test]
    fn ech_adoption_is_zero_on_empty_and_excludes_decode_errors() {
        let mut h = OutcomeHistogram::default();
        assert_eq!(h.ech_adoption_fraction(), 0.0);
        // 1 encrypted of 4 parsed = 25%. A decode error must NOT change it.
        h.record_kind("cleartext");
        h.record_kind("cleartext");
        h.record_kind("cleartext");
        h.record_kind("encrypted");
        h.record_decode_error();
        assert!((h.ech_adoption_fraction() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn top_hosts_sorts_by_count_then_name() {
        let mut h = OutcomeHistogram::default();
        for _ in 0..3 {
            h.record_host("b.example");
        }
        for _ in 0..3 {
            h.record_host("a.example"); // tie with b.example on count
        }
        h.record_host("c.example");
        let top = h.top_hosts(2);
        // Both have count 3; name-asc tiebreak puts a.example first.
        assert_eq!(
            top,
            vec![("a.example".to_string(), 3), ("b.example".to_string(), 3)]
        );
    }
}
