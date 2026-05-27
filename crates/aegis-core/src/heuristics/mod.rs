//! Local, no-API risk heuristics (PRD §2.2). Each submodule produces
//! [`crate::risk::RiskSignal`]s from cheap, local computation so the agent never
//! has to phone home just to classify a domain.

pub mod context;
pub mod levenshtein;
