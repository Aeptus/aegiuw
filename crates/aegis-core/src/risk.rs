//! Risk verdicts: the data model that every heuristic feeds into, and the policy
//! that folds a set of signals into one decision.

use serde::{Deserialize, Serialize};

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
}

impl RiskSignal {
    /// The severity this individual signal implies on its own.
    pub fn severity(&self) -> RiskLevel {
        match self {
            RiskSignal::Typosquat { .. } => RiskLevel::Suspicious,
            RiskSignal::RiskyLaunchContext { .. } => RiskLevel::HighRisk,
            RiskSignal::NotInSafeCache => RiskLevel::Unknown,
        }
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
}
