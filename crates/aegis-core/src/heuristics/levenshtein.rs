//! FR-2.1 — Levenshtein typo-squat detection.
//!
//! Compares an SNI domain against a dictionary of known brands. A small edit
//! distance to a brand the user did *not* actually intend to visit
//! (`micr0soft.com` vs `microsoft.com`) is a classic phishing tell.

use crate::risk::RiskSignal;

/// Compute the Levenshtein edit distance between two strings, measured in Unicode
/// scalar values (`char`s), not bytes — so multi-byte characters count as one edit.
///
/// Uses the standard two-row dynamic-programming formulation: O(n·m) time but only
/// O(min(n, m)) space, which matters because this runs on the hot path inside the
/// agent's ≤1.5ms parsing budget.
pub fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();

    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }

    // `prev[j]` = distance between a[..i] and b[..j]; we roll two rows.
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];

    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1) // deletion
                .min(curr[j] + 1) // insertion
                .min(prev[j] + cost); // substitution
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b.len()]
}

/// A minimal stand-in for the "top 10,000 corporate domains" the PRD calls for.
/// In production this is loaded from a bundled dataset plus the organization's own
/// internal domains; this short list keeps tests and the scaffold self-contained.
pub const SAMPLE_BRANDS: &[&str] = &[
    "microsoft.com",
    "paypal.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "github.com",
];

/// Default edit-distance threshold (FR-2.1 specifies ≤ 2).
pub const DEFAULT_MAX_DISTANCE: usize = 2;

/// Check `domain` against `brands`. Returns a [`RiskSignal::Typosquat`] for the
/// closest brand within `max_distance`, or `None` if the domain is an exact brand
/// match or far from every brand.
///
/// TODO(policy): several refinements are deliberately left open here —
///   1. Compare the registrable domain (eTLD+1), not the full host, so
///      `login.microsoft.com` is not flagged against `microsoft.com`.
///   2. Treat known homoglyph/leet substitutions (`0→o`, `1→l`, `rn→m`) as
///      near-zero-cost edits so `paypa1.com` scores even closer.
///   3. Skip comparisons where `domain` is itself in the allow-cache.
pub fn check_typosquat(domain: &str, brands: &[&str], max_distance: usize) -> Option<RiskSignal> {
    let mut best: Option<(usize, &str)> = None;

    for &brand in brands {
        if domain.eq_ignore_ascii_case(brand) {
            return None; // exact, legitimate match — not a squat
        }
        let d = distance(domain, brand);
        if d > 0 && d <= max_distance {
            match best {
                Some((bd, _)) if bd <= d => {}
                _ => best = Some((d, brand)),
            }
        }
    }

    best.map(|(distance, brand)| RiskSignal::Typosquat {
        domain: domain.to_string(),
        looks_like: brand.to_string(),
        distance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_basics() {
        assert_eq!(distance("", ""), 0);
        assert_eq!(distance("abc", "abc"), 0);
        assert_eq!(distance("kitten", "sitting"), 3);
        assert_eq!(distance("microsoft.com", "micr0soft.com"), 1);
    }

    #[test]
    fn flags_a_close_typosquat() {
        let signal = check_typosquat("micr0soft.com", SAMPLE_BRANDS, DEFAULT_MAX_DISTANCE);
        assert!(matches!(
            signal,
            Some(RiskSignal::Typosquat { distance: 1, .. })
        ));
    }

    #[test]
    fn ignores_exact_brand() {
        assert_eq!(
            check_typosquat("microsoft.com", SAMPLE_BRANDS, DEFAULT_MAX_DISTANCE),
            None
        );
    }

    #[test]
    fn ignores_clearly_different_domain() {
        assert_eq!(
            check_typosquat(
                "totally-unrelated-site.dev",
                SAMPLE_BRANDS,
                DEFAULT_MAX_DISTANCE
            ),
            None
        );
    }
}
