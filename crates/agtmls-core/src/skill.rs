// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structural rules: the ones that are not patterns.
//!
//! `AGT-STEG-001`, `AGT-CAP-001` and `AGT-POLICY-*` reason about a skill's
//! *shape* — which code points it contains, which tools its frontmatter
//! grants versus which its policy admits to, whether it declares a policy at
//! all. None of those is expressible as a regex over a document.
//!
//! They are still declared in `rules/` with `kind = "structural"`, so the rule
//! set can be enumerated from data alone, and `AGT-STEG-001` carries its code
//! point set there rather than here — neither implementation owns the list.

use std::collections::BTreeMap;

use crate::analyzer::Finding;
use crate::rules::{RuleSet, Severity};

/// Tools that grant a capability a `safety_policy` may be denying.
///
/// The runtime honours the frontmatter, so frontmatter granting what the
/// policy denies is an escalation, not a documentation error.
const TOOL_CAPABILITIES: &[(&str, &str)] = &[
    ("Bash", "executes_commands"),
    ("BashOutput", "executes_commands"),
    ("KillShell", "executes_commands"),
    ("Write", "writes_files"),
    ("Edit", "writes_files"),
    ("NotebookEdit", "writes_files"),
    ("WebFetch", "network_access"),
    ("WebSearch", "network_access"),
];

fn finding(
    file: &str,
    line: usize,
    severity: Severity,
    category: &str,
    rule: &str,
    message: String,
) -> Finding {
    Finding {
        file: file.into(),
        line,
        severity: severity.as_str().to_owned(),
        category: category.to_owned(),
        rule: rule.to_owned(),
        message,
    }
}

/// `AGT-STEG-001`: code points that render as nothing.
///
/// The set comes from the rule declaration, so it cannot drift from the other
/// implementation's without the rule file changing.
#[must_use]
pub fn check_invisible(rules: &RuleSet, file: &str, content: &str) -> Vec<Finding> {
    let Some(rule) = rules.rules.get("AGT-STEG-001") else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for (line_index, line) in content.lines().enumerate() {
        for (column, ch) in line.chars().enumerate() {
            if let Some(name) = rule.invisible_name(ch) {
                findings.push(finding(
                    file,
                    line_index + 1,
                    rule.spec.severity,
                    &rule.spec.category,
                    &rule.spec.id,
                    format!(
                        "Invisible unicode character detected: {name} (U+{:04X}) at column {}",
                        ch as u32,
                        column + 1
                    ),
                ));
            }
        }
    }
    findings
}

/// Tools granted by `SKILL.md` frontmatter, if any.
#[must_use]
pub fn frontmatter_tools(skill_md: &str) -> Vec<String> {
    let Some(block) = frontmatter(skill_md) else {
        return Vec::new();
    };
    block
        .lines()
        .find_map(|line| line.strip_prefix("allowed-tools:"))
        .map(|value| {
            value
                .trim()
                .trim_matches(['[', ']'])
                .split(',')
                .map(|tool| tool.trim().trim_matches(['\'', '"']).to_owned())
                .filter(|tool| !tool.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn frontmatter(text: &str) -> Option<&str> {
    let rest = text
        .strip_prefix("---")?
        .trim_start_matches([' ', '\t'])
        .strip_prefix('\n')?;
    let end = rest.find("\n---")?;
    Some(&rest[..end])
}

/// A skill as a set of files, so the same code serves a directory, an archive
/// and a corpus case without any of them needing a filesystem.
pub type SkillFiles = BTreeMap<String, String>;

/// Read the declared safety policy, or report why it cannot be read.
///
/// Fails closed. Returning no findings when `metadata.json` is missing or
/// unparseable made deleting the file that declares the policy the cheapest
/// way to pass every policy check.
fn load_policy(files: &SkillFiles) -> (serde_json::Value, Vec<Finding>) {
    let empty = serde_json::json!({});
    let Some(raw) = files.get("metadata.json") else {
        return (
            empty,
            vec![finding(
                "SKILL.md",
                1,
                Severity::High,
                "policy_honesty",
                "AGT-POLICY-001",
                "Skill declares no metadata.json, so its safety policy cannot be verified; \
                 an unattested skill is not a safe skill"
                    .to_owned(),
            )],
        );
    };
    match serde_json::from_str::<serde_json::Value>(raw) {
        Err(error) => (
            empty,
            vec![finding(
                "metadata.json",
                1,
                Severity::High,
                "policy_honesty",
                "AGT-POLICY-002",
                format!(
                    "metadata.json is unparseable, so its safety policy cannot be verified: {error}"
                ),
            )],
        ),
        Ok(value) => match value.get("safety_policy") {
            Some(policy) if policy.is_object() => (policy.clone(), Vec::new()),
            Some(_) => (
                empty,
                vec![finding(
                    "metadata.json",
                    1,
                    Severity::High,
                    "policy_honesty",
                    "AGT-POLICY-003",
                    "metadata.json safety_policy is not an object".to_owned(),
                )],
            ),
            None => (empty, Vec::new()),
        },
    }
}

/// `AGT-CAP-001`: frontmatter must not grant what the policy denies.
fn check_capability_escalation(skill_md: &str, policy: &serde_json::Value) -> Vec<Finding> {
    frontmatter_tools(skill_md)
        .into_iter()
        .filter_map(|tool| {
            let (_, capability) = TOOL_CAPABILITIES.iter().find(|(name, _)| *name == tool)?;
            let granted = if *capability == "network_access" {
                matches!(
                    policy
                        .get("network_access")
                        .and_then(serde_json::Value::as_str),
                    Some("optional" | "required")
                )
            } else {
                policy
                    .get(*capability)
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
            };
            (!granted).then(|| {
                finding(
                    "SKILL.md",
                    1,
                    Severity::High,
                    "capability_escalation",
                    "AGT-CAP-001",
                    format!(
                        "Frontmatter grants '{tool}' but safety_policy denies {capability}; \
                         the runtime honours the frontmatter"
                    ),
                )
            })
        })
        .collect()
}

/// `AGT-POLICY-004` / `AGT-POLICY-005`: prose contradicting the declaration.
fn check_policy_prose(skill_md: &str, policy: &serde_json::Value) -> Vec<Finding> {
    let body = skill_md.to_lowercase();
    let mut findings = Vec::new();

    if policy
        .get("executes_commands")
        .and_then(serde_json::Value::as_bool)
        == Some(false)
        && [
            "run the following",
            "run this script",
            "run this command",
            "run this bash",
        ]
        .iter()
        .any(|phrase| body.contains(phrase))
    {
        findings.push(finding(
            "SKILL.md",
            1,
            Severity::Medium,
            "policy_honesty",
            "AGT-POLICY-004",
            "Skill claims executes_commands=false but text instructs agent to run commands"
                .to_owned(),
        ));
    }

    if policy
        .get("network_access")
        .and_then(serde_json::Value::as_str)
        == Some("none")
        && ["fetch http", "download http", "curl http", "wget http"]
            .iter()
            .any(|phrase| body.contains(phrase))
    {
        findings.push(finding(
            "SKILL.md",
            1,
            Severity::Medium,
            "policy_honesty",
            "AGT-POLICY-005",
            "Skill claims network_access=none but text contains instructions to fetch URLs"
                .to_owned(),
        ));
    }
    findings
}

/// Structural analysis of a whole skill.
///
/// Pattern rules see one file at a time; these see the skill. Whether a policy
/// is declared at all, and whether the frontmatter grants more than the policy
/// admits, are not properties of any single document.
#[must_use]
pub fn audit_skill(rules: &RuleSet, files: &SkillFiles) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (name, content) in files {
        findings.extend(check_invisible(rules, name, content));
    }

    let Some(skill_md) = files.get("SKILL.md") else {
        return findings;
    };

    let (policy, policy_findings) = load_policy(files);
    findings.extend(policy_findings);
    findings.extend(check_capability_escalation(skill_md, &policy));
    findings.extend(check_policy_prose(skill_md, &policy));
    findings
}
