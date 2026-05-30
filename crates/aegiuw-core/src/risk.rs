// SPDX-License-Identifier: AGPL-3.0-or-later

//! Risk verdicts: the data model that every heuristic feeds into, and the policy
//! that folds a set of signals into one decision.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::sni::SniOutcome;

/// How dangerous a domain looks, from least to most severe.
///
/// Variant **declaration order is significant**: it is the severity order used by
/// the derived [`Ord`] impl, so `RiskLevel::HighRisk > RiskLevel::Safe`. Keep them
/// sorted ascending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Present in the signed local allow-cache — eligible for the Native Path.
    Safe,
    /// No information either way. Fail-safe: unknown domains take the Isolate Path.
    Unknown,
    /// One or more heuristics flagged a concern (e.g. close typo of a known brand).
    Suspicious,
    /// Strong indicator of an attack (e.g. risky launch context on an unknown link).
    HighRisk,
}

/// A single piece of evidence produced by a heuristic. Tagged for clean JSON when
/// streamed as telemetry to the edge router (PRD §1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RiskSignal {
    /// The domain is within the configured edit distance of a known brand (FR-2.1).
    Typosquat {
        domain: String,
        looks_like: String,
        distance: usize,
    },
    /// The outbound call was launched from a higher-risk parent process — e.g. an
    /// email client or document reader — and the domain is not cached (FR-2.3).
    RiskyLaunchContext { parent_process: String },
    /// The domain was not found in the signed local allow-cache.
    NotInSafeCache,
    /// The ClientHello carried an `encrypted_client_hello` extension (ECH) — the
    /// real SNI is unobservable. Per `DECISIONS.C14` we treat the connection as
    /// `Unknown` and route to Isolate. **Not** inherently malicious (ECH is normal
    /// modern-browser behaviour), but the host can't be scored locally. SNI
    /// backlog I2.
    EncryptedClientHello,
    /// The ClientHello parsed but carried no `server_name` extension. No host to
    /// score; fail-safe to Isolate. Distinguished from [`MalformedClientHello`]
    /// and from ECH for telemetry. SNI backlog I2.
    NoServerName,
    /// The peeked bytes did not parse as a TLS ClientHello — truncated input, a
    /// non-TLS protocol on `:443`, or hostile probing. No host to score; fail-safe
    /// to Isolate. Kept distinct for telemetry (PRD §1.1: a malformed CH suggests
    /// either an attacker or a non-TLS protocol). SNI backlog I2.
    MalformedClientHello,
}

impl RiskSignal {
    /// The severity this individual signal implies on its own.
    pub fn severity(&self) -> RiskLevel {
        match self {
            RiskSignal::Typosquat { .. } => RiskLevel::Suspicious,
            RiskSignal::RiskyLaunchContext { .. } => RiskLevel::HighRisk,
            RiskSignal::NotInSafeCache => RiskLevel::Unknown,
            // The three SNI-outcome signals all fail-safe to Isolate without
            // crying wolf: unreadable/absent/malformed host → `Unknown`. They
            // exist as distinct variants for telemetry, not to escalate the
            // verdict beyond what an allow-cache miss already implies. SNI
            // backlog I2.
            RiskSignal::EncryptedClientHello => RiskLevel::Unknown,
            RiskSignal::NoServerName => RiskLevel::Unknown,
            RiskSignal::MalformedClientHello => RiskLevel::Unknown,
        }
    }
}

/// Adapt a parsed [`SniOutcome`] into the Layer-2 risk signals it implies
/// (SNI backlog I2).
///
/// This is the bridge between Layer 1 (the SNI parser) and Layer 2 (the risk
/// engine): the daemon peeks the ClientHello, calls
/// [`extract_sni`](crate::extract_sni), then folds the outcome into the
/// signal stream alongside its allow-cache / typosquat / context signals.
///
/// | Outcome | Signals |
/// |---|---|
/// | [`SniOutcome::Cleartext`] | **none** — the host is the *input* to the typosquat / cache heuristics, not a signal itself |
/// | [`SniOutcome::Encrypted`] | `[EncryptedClientHello]` |
/// | [`SniOutcome::NotFound`] | `[NoServerName]` |
/// | [`SniOutcome::Malformed`] | `[MalformedClientHello]` |
///
/// Takes `&SniOutcome` (not by value) so a caller that matched on
/// `Cleartext { host }` to run the host heuristics can still pass the same
/// outcome here for the non-Cleartext cases.
pub fn into_signals(outcome: &SniOutcome<'_>) -> Vec<RiskSignal> {
    match outcome {
        SniOutcome::Cleartext { .. } => Vec::new(),
        SniOutcome::Encrypted => vec![RiskSignal::EncryptedClientHello],
        SniOutcome::NotFound => vec![RiskSignal::NoServerName],
        SniOutcome::Malformed => vec![RiskSignal::MalformedClientHello],
    }
}

/// The final assessment for one domain: a level plus the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub level: RiskLevel,
    pub signals: Vec<RiskSignal>,
}

impl Verdict {
    /// Fold a set of signals into a single verdict.
    ///
    /// Baseline policy: the verdict is the **worst** signal observed; with no
    /// signals at all we return [`RiskLevel::Unknown`] (deny-by-default), never
    /// `Safe`. `Safe` is only ever asserted by an explicit allow-cache hit via
    /// [`Verdict::safe`], not inferred from absence of evidence.
    ///
    /// TODO(policy): richer weighting may be wanted later — e.g. a typosquat AND a
    /// risky launch context together should arguably escalate above either alone.
    pub fn evaluate(signals: Vec<RiskSignal>) -> Self {
        let level = signals
            .iter()
            .map(RiskSignal::severity)
            .max()
            .unwrap_or(RiskLevel::Unknown);
        Verdict { level, signals }
    }

    /// Construct the verdict for a confirmed allow-cache hit.
    pub fn safe() -> Self {
        Verdict {
            level: RiskLevel::Safe,
            signals: Vec::new(),
        }
    }

    /// Whether this domain may use the Native Path (direct to NIC). Only an
    /// explicit `Safe` qualifies; everything else is isolated.
    pub fn allows_native_path(&self) -> bool {
        self.level == RiskLevel::Safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_signals_is_unknown_not_safe() {
        let v = Verdict::evaluate(vec![]);
        assert_eq!(v.level, RiskLevel::Unknown);
        assert!(!v.allows_native_path());
    }

    #[test]
    fn verdict_takes_the_worst_signal() {
        let v = Verdict::evaluate(vec![
            RiskSignal::NotInSafeCache,
            RiskSignal::Typosquat {
                domain: "paypa1.com".into(),
                looks_like: "paypal.com".into(),
                distance: 1,
            },
            RiskSignal::RiskyLaunchContext {
                parent_process: "outlook".into(),
            },
        ]);
        assert_eq!(v.level, RiskLevel::HighRisk);
    }

    #[test]
    fn severity_ordering_holds() {
        assert!(RiskLevel::HighRisk > RiskLevel::Suspicious);
        assert!(RiskLevel::Suspicious > RiskLevel::Unknown);
        assert!(RiskLevel::Unknown > RiskLevel::Safe);
    }

    #[test]
    fn only_safe_allows_native_path() {
        assert!(Verdict::safe().allows_native_path());
    }

    // ── I2: into_signals adapter ─────────────────────────────────────────────

    use alloc::borrow::Cow;

    #[test]
    fn into_signals_cleartext_emits_nothing() {
        // The host flows into the typosquat / cache heuristics one layer up —
        // it is not itself a risk signal.
        let outcome = SniOutcome::Cleartext {
            host: Cow::Borrowed("example.com"),
        };
        assert!(into_signals(&outcome).is_empty());
    }

    #[test]
    fn into_signals_encrypted_emits_ech_signal() {
        assert_eq!(
            into_signals(&SniOutcome::Encrypted),
            vec![RiskSignal::EncryptedClientHello],
        );
    }

    #[test]
    fn into_signals_not_found_emits_no_server_name() {
        assert_eq!(
            into_signals(&SniOutcome::NotFound),
            vec![RiskSignal::NoServerName],
        );
    }

    #[test]
    fn into_signals_malformed_emits_malformed_signal() {
        assert_eq!(
            into_signals(&SniOutcome::Malformed),
            vec![RiskSignal::MalformedClientHello],
        );
    }

    #[test]
    fn sni_outcome_signals_all_fail_safe_to_isolate() {
        // None of the SNI-outcome signals assert `Safe` — every one routes to
        // Isolate when folded into a verdict (the host couldn't be scored).
        for outcome in [
            SniOutcome::Encrypted,
            SniOutcome::NotFound,
            SniOutcome::Malformed,
        ] {
            let verdict = Verdict::evaluate(into_signals(&outcome));
            assert!(
                !verdict.allows_native_path(),
                "{outcome:?} must not take the Native Path",
            );
            assert_eq!(verdict.level, RiskLevel::Unknown);
        }
    }
}
