//! FR-2.3 — Launch-context tracking.
//!
//! The same URL is far more dangerous when it arrives via an email client or PDF
//! reader than when typed into a browser. This module classifies the *parent
//! process* that triggered an outbound call. Walking the OS process tree to find
//! the PPID is the daemon's job (it's platform-specific I/O); this module only
//! makes the pure classification decision from a process name.

use crate::risk::RiskSignal;

/// The category of application that originated a web request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentCategory {
    /// Email clients — a top phishing delivery vector.
    EmailClient,
    /// Document readers (PDF, Office) that can embed malicious links.
    DocumentReader,
    /// A normal web browser, or anything we don't consider elevated-risk.
    Browser,
    /// Unrecognized parent.
    Other,
}

impl ParentCategory {
    /// Whether a link from this category, when the domain is *not* in the safe
    /// cache, should be treated as high-risk per FR-2.3.
    pub fn is_elevated_risk(self) -> bool {
        matches!(
            self,
            ParentCategory::EmailClient | ParentCategory::DocumentReader
        )
    }
}

/// Map a raw process name (as reported by the OS) to a [`ParentCategory`].
///
/// Matching is case-insensitive and substring-based to tolerate platform variance
/// (`Outlook.exe`, `Microsoft Outlook`, `outlook`). The match tables below are a
/// starting set.
///
/// TODO(data): expand these tables and consider matching on the executable's code
/// signature / bundle identifier rather than a display name, which is spoofable.
pub fn classify_parent(process_name: &str) -> ParentCategory {
    const EMAIL: &[&str] = &["outlook", "thunderbird", "apple mail", "mailmate", "spark"];
    const DOCS: &[&str] = &["acrobat", "acrord32", "preview", "winword", "powerpnt"];
    const BROWSERS: &[&str] = &["chrome", "firefox", "safari", "msedge", "brave", "arc"];

    let name = process_name.to_ascii_lowercase();
    let hit = |table: &[&str]| table.iter().any(|p| name.contains(p));

    if hit(EMAIL) {
        ParentCategory::EmailClient
    } else if hit(DOCS) {
        ParentCategory::DocumentReader
    } else if hit(BROWSERS) {
        ParentCategory::Browser
    } else {
        ParentCategory::Other
    }
}

/// Produce a [`RiskSignal::RiskyLaunchContext`] when an elevated-risk parent
/// launched a call to a domain that is not already trusted (`in_safe_cache`).
pub fn assess_context(parent_process: &str, in_safe_cache: bool) -> Option<RiskSignal> {
    if in_safe_cache {
        return None;
    }
    if classify_parent(parent_process).is_elevated_risk() {
        Some(RiskSignal::RiskyLaunchContext {
            parent_process: parent_process.to_string(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_parents() {
        assert_eq!(classify_parent("OUTLOOK.EXE"), ParentCategory::EmailClient);
        assert_eq!(
            classify_parent("Adobe Acrobat"),
            ParentCategory::DocumentReader
        );
        assert_eq!(classify_parent("Google Chrome"), ParentCategory::Browser);
        assert_eq!(classify_parent("some-random-tool"), ParentCategory::Other);
    }

    #[test]
    fn email_launch_to_uncached_domain_is_flagged() {
        assert!(assess_context("Outlook", false).is_some());
    }

    #[test]
    fn cached_domain_is_never_flagged_on_context() {
        assert!(assess_context("Outlook", true).is_none());
    }

    #[test]
    fn browser_launch_is_not_flagged() {
        assert!(assess_context("Safari", false).is_none());
    }
}
