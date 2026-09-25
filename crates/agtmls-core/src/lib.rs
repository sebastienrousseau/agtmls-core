// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Engine for the `AgtMLS` agent skills registry.
//!
//! Two capabilities, both defined normatively by
//! [`agtmls-spec`](https://github.com/sebastienrousseau/agtmls-spec):
//!
//! * [`digest`] — the content address of a skill, stable across every
//!   transport, which is what makes install verification possible.
//! * [`analyzer`] — static analysis of skill content against a rule set
//!   loaded from data, shared byte-for-byte with the Python implementation.
//!
//! This crate is deliberately I/O-light and allocation-conscious so the same
//! code can serve a CLI, a language server, an MCP server and a WASM module
//! without four rule sets drifting apart.

#![forbid(unsafe_code)]
#![doc(html_root_url = "https://docs.rs/agtmls-core")]
// The README is the crate documentation, so its examples are compiled by
// `cargo test`. A README example that has never been compiled is a guess.
#![doc = include_str!("../../../README.md")]

pub mod advisories;
pub mod analyzer;
pub mod digest;
pub mod lockfile;
pub mod rules;
pub mod signatures;
pub mod skill;

pub use analyzer::{Analyzer, Finding};
pub use digest::{Manifest, ManifestEntry, skill_digest};
pub use lockfile::{Lockfile, Problem};
pub use rules::{RuleSet, Severity};
pub use skill::{SkillFiles, audit_skill};

/// The `agtmls-spec` version this crate implements.
pub const SPEC_VERSION: &str = "0.1.0";

/// Conformance level claimed by this crate. Recomputed by the conformance
/// runner; a claim that differs from the computed level is a build failure.
///
/// L4: everything in L3, plus lockfile verification semantics. Verified by
/// comparing this crate's output with the Python implementation's, case by
/// case — not only against expected values, since two implementations can each
/// match the expectations and still disagree with each other.
pub const CONFORMANCE_LEVEL: &str = "L4";
