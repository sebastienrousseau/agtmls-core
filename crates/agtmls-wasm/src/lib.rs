// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! WebAssembly bindings for the `AgtMLS` engine.
//!
//! The point of this crate is not portability for its own sake. A skill is
//! often the most sensitive thing a team has written down — internal process,
//! architecture, the shape of their systems — and asking someone to upload one
//! to a scanning service to find out whether it is safe is a poor trade.
//!
//! Compiled to WASM, the analyzer runs in the page. "We cannot see your skill
//! because it never reaches us" is a stronger claim than any privacy policy,
//! and it is the one this crate exists to make true.
//!
//! The rule set is embedded at compile time from `agtmls-spec`, so a browser
//! build enforces exactly the rules the specification defines.

#![forbid(unsafe_code)]

use agtmls_core::{Analyzer, RuleSet, digest, rules, skill};
use wasm_bindgen::prelude::*;

include!(concat!(env!("OUT_DIR"), "/embedded_rules.rs"));

fn ruleset() -> Result<RuleSet, JsError> {
    RuleSet::from_sources(EMBEDDED_RULES.iter().copied())
        .map_err(|error| JsError::new(&format!("embedded rule set failed to load: {error}")))
}

/// Number of rules compiled into this module.
///
/// Exposed so a caller can assert the module is armed. Zero findings from a
/// module with zero rules is not the same answer as zero findings from a
/// module with nineteen, and only the caller can tell the difference.
#[wasm_bindgen]
#[must_use]
pub fn rule_count() -> usize {
    EMBEDDED_RULES.len()
}

/// Identifiers of every embedded rule, sorted.
#[wasm_bindgen]
#[must_use]
pub fn rule_ids() -> Vec<String> {
    ruleset().map_or_else(|_| Vec::new(), |set| set.rules.keys().cloned().collect())
}

/// The `agtmls-spec` version this module implements.
#[wasm_bindgen]
#[must_use]
pub fn spec_version() -> String {
    agtmls_core::SPEC_VERSION.to_owned()
}

/// Analyse one document.
///
/// `name` is used only to report the finding's location and to decide which
/// rules apply; nothing is read from disk.
///
/// # Errors
/// Returns a `JsError` if the embedded rule set cannot be loaded, which would
/// mean the module was built wrong rather than that the input was bad.
#[wasm_bindgen]
pub fn audit(name: &str, content: &str) -> Result<JsValue, JsError> {
    let findings = Analyzer::new(ruleset()?).audit_str(name, content);
    serde_wasm_bindgen::to_value(&findings).map_err(|error| JsError::new(&error.to_string()))
}

/// Analyse a whole skill: pattern rules over each file, plus the structural
/// rules that reason about the skill rather than any one document.
///
/// `files` is a JS object mapping a relative path to its text content.
///
/// # Errors
/// Returns a `JsError` if `files` is not an object of strings, or if the
/// embedded rule set cannot be loaded.
#[wasm_bindgen]
pub fn audit_skill(files: JsValue) -> Result<JsValue, JsError> {
    let map: skill::SkillFiles = serde_wasm_bindgen::from_value(files)
        .map_err(|error| JsError::new(&format!("expected an object of path -> text: {error}")))?;
    let set = ruleset()?;
    let analyzer = Analyzer::new(set.clone());

    let mut findings = Vec::new();
    for (path, content) in &map {
        findings.extend(analyzer.audit_str(path, content));
    }
    findings.extend(skill::audit_skill(&map));
    serde_wasm_bindgen::to_value(&findings).map_err(|error| JsError::new(&error.to_string()))
}

/// Content address for a set of skill files, per `agtmls-spec` 3.1.
///
/// Computed from the supplied files rather than from a directory, so a browser
/// can verify a skill it was handed without a filesystem. The result matches
/// what the CLI computes for the same file set.
///
/// # Errors
/// Returns a `JsError` if `files` is not an object of strings.
#[wasm_bindgen]
pub fn skill_digest(files: JsValue) -> Result<String, JsError> {
    let map: skill::SkillFiles = serde_wasm_bindgen::from_value(files)
        .map_err(|error| JsError::new(&format!("expected an object of path -> text: {error}")))?;
    let entries: Vec<digest::ManifestEntry> = map
        .iter()
        .map(|(path, content)| digest::ManifestEntry {
            path: path.clone(),
            sha256: digest::sha256_hex(content.as_bytes()),
        })
        .collect();
    // spec 3.7: sort on the raw UTF-8 bytes of the path, never a collation.
    let mut entries = entries;
    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    Ok(digest::digest_from_manifest(&entries))
}

/// Collapse whitespace the way the analyzer does, for callers that want to
/// show why a split payload still matched.
#[wasm_bindgen]
#[must_use]
pub fn normalise(content: &str) -> String {
    rules::normalise(content)
}
