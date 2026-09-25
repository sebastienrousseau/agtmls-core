// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-skill in-toto attestations (agtmls-spec chapter 10).
//!
//! An attestation is a pure function of the skill and the rule data,
//! rendered canonically, so two runs, or two implementations, produce the
//! same bytes and the spec's vectors can be reproduced exactly.

use std::io;
use std::path::Path;

use serde_json::{Value, json};

use crate::digest::{digest_from_manifest, manifest};
use crate::rules::RuleSet;
use crate::skill::{escalations, frontmatter_tools};

/// The in-toto Statement type.
pub const STATEMENT: &str = "https://in-toto.io/Statement/v1";
/// The manifest predicate (spec 10.4).
pub const MANIFEST: &str = "https://agtmls.dev/manifest/v1";
/// The capabilities predicate (spec 10.5).
pub const CAPABILITIES: &str = "https://agtmls.dev/capabilities/v1";

/// Spec 10.2: keys sorted, two-space indentation, UTF-8 unescaped, one
/// trailing newline. `serde_json` keeps object keys in a sorted map and
/// writes non-ASCII as is, which is exactly that rendering.
#[must_use]
pub fn render(statement: &Value) -> String {
    let mut text = serde_json::to_string_pretty(statement).unwrap_or_default();
    text.push('\n');
    text
}

fn subject(name: &str, digest: &str) -> Value {
    json!([{"name": name, "digest": {"sha256": digest.trim_start_matches("sha256:")}}])
}

/// The manifest statement for the skill at `dir` (spec 10.4): the digest's
/// own file list, so a verifier can recompute it and name the file that
/// differs.
///
/// # Errors
/// Returns the I/O error if the skill cannot be read.
pub fn manifest_statement(name: &str, dir: &Path) -> io::Result<Value> {
    let entries = manifest(dir)?.entries;
    let files: Vec<Value> = entries
        .iter()
        .map(|e| json!({"path": e.path, "digest": {"sha256": e.sha256}}))
        .collect();
    Ok(json!({
        "_type": STATEMENT,
        "subject": subject(name, &digest_from_manifest(&entries)),
        "predicateType": MANIFEST,
        "predicate": {"digest_algorithm": "agtmls-skill-digest-v1", "files": files},
    }))
}

/// The capabilities statement for the skill at `dir` (spec 10.5): the
/// declared policy, the granted tools and the `AGT-CAP-001` escalations.
/// `digest` replaces the computed subject digest, as the spec's vectors do.
///
/// # Errors
/// Returns an I/O error if the skill cannot be read or `metadata.json` is
/// not JSON.
pub fn capabilities_statement(
    rules: &RuleSet,
    name: &str,
    dir: &Path,
    digest: Option<&str>,
) -> io::Result<Value> {
    let metadata = dir.join("metadata.json");
    let policy = if metadata.is_file() {
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&metadata)?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        value
            .get("safety_policy")
            .cloned()
            .unwrap_or_else(|| json!({}))
    } else {
        json!({})
    };
    let skill_md = std::fs::read_to_string(dir.join("SKILL.md")).unwrap_or_default();
    let found: Vec<Value> = escalations(rules, &skill_md, &policy)
        .into_iter()
        .map(|(tool, capability)| json!({"tool": tool, "capability": capability}))
        .collect();
    let digest = match digest {
        Some(digest) => digest.to_owned(),
        None => digest_from_manifest(&manifest(dir)?.entries),
    };
    Ok(json!({
        "_type": STATEMENT,
        "subject": subject(name, &digest),
        "predicateType": CAPABILITIES,
        "predicate": {
            "declared_policy": policy,
            "allowed_tools": frontmatter_tools(&skill_md),
            "escalations": found,
        },
    }))
}
