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
use crate::rules::{EmojiContext, RuleSet, Severity};

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
    check_invisible_with(rules, file, content, false)
}

/// Column of each well-formed subdivision flag's first tag, with the number
/// of code points it covers up to and including the terminator.
fn subdivision_flags(chars: &[char], context: &EmojiContext) -> BTreeMap<usize, usize> {
    let mut flags = BTreeMap::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == context.flag_base() {
            let mut j = i + 1;
            while j < chars.len() && context.is_tag(chars[j]) {
                j += 1;
            }
            if j > i + 1 && j < chars.len() && chars[j] == context.terminator() {
                flags.insert(i + 1, j - i);
                i = j;
            }
        }
        i += 1;
    }
    flags
}

/// `AGT-STEG-001` with the emoji context applied (spec 4.10).
///
/// A selector directly after an emoji base is an emoji as written: it is
/// `AGT-STEG-002` at LOW and reported only when `pedantic`. A well-formed
/// subdivision flag is `AGT-STEG-002` at LOW, always, once per flag. Without
/// a declared context every selector and tag character is a channel.
#[must_use]
pub fn check_invisible_with(
    rules: &RuleSet,
    file: &str,
    content: &str,
    pedantic: bool,
) -> Vec<Finding> {
    let Some(rule) = rules.rules.get("AGT-STEG-001") else {
        return Vec::new();
    };
    let ctx = rule.emoji_context();
    let mut findings = Vec::new();
    for (line_index, line) in content.lines().enumerate() {
        let chars: Vec<char> = line.chars().collect();
        let flags = ctx.map_or_else(BTreeMap::new, |c| subdivision_flags(&chars, c));
        let covered = |column: usize| {
            flags
                .iter()
                .any(|(start, count)| column >= *start && column < start + count)
        };
        for (column, &ch) in chars.iter().enumerate() {
            let Some(name) = rule.invisible_name(ch) else {
                continue;
            };
            if let Some(context) = ctx {
                if context.is_selector(ch) {
                    let after_base = column > 0 && context.is_base(chars[column - 1]);
                    let in_run = chars
                        .get(column + 1)
                        .is_some_and(|&n| context.is_selector(n));
                    if after_base && !in_run {
                        if pedantic {
                            findings.push(finding(
                                file,
                                line_index + 1,
                                Severity::Low,
                                &rule.spec.category,
                                "AGT-STEG-002",
                                format!(
                                    "{name} (U+{:04X}) after an emoji base at column {}: emoji presentation, not a channel",
                                    ch as u32,
                                    column + 1
                                ),
                            ));
                        }
                        continue;
                    }
                }
                if covered(column) {
                    if let Some(count) = flags.get(&column) {
                        findings.push(finding(
                            file,
                            line_index + 1,
                            Severity::Low,
                            &rule.spec.category,
                            "AGT-STEG-002",
                            format!(
                                "Tag sequence forming a subdivision flag at column {} ({} tag character(s), terminated)",
                                column + 1,
                                count - 1
                            ),
                        ));
                    }
                    continue;
                }
            }
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
    findings
}

/// Tools granted by `SKILL.md` frontmatter, if any (spec 10.5).
///
/// The Agent Skills spec writes the field space-separated
/// (`allowed-tools: "Read Grep Bash"`), so it is split on whitespace and
/// commas, YAML list brackets and quotes dropped, and a parenthesised
/// specifier such as `Bash(git log:*)` kept with its tool. Splitting on commas
/// alone read that example as one tool named `Read Grep Bash`, which granted
/// nothing.
#[must_use]
pub fn frontmatter_tools(skill_md: &str) -> Vec<String> {
    let Some(block) = frontmatter(skill_md) else {
        return Vec::new();
    };
    block
        .lines()
        .find_map(|line| line.strip_prefix("allowed-tools:"))
        .map(tool_tokens)
        .unwrap_or_default()
}

/// A run of characters that are not whitespace, a comma, a bracket, a quote
/// or a parenthesis, optionally followed by one parenthesised specifier.
fn tool_tokens(value: &str) -> Vec<String> {
    let separator =
        |c: char| c.is_whitespace() || matches!(c, ',' | '(' | ')' | '\'' | '"' | '[' | ']');
    let mut tools = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find(|c: char| !separator(c)) {
        rest = &rest[start..];
        let end = rest.find(separator).unwrap_or(rest.len());
        let mut token_end = end;
        if rest[end..].starts_with('(') {
            if let Some(close) = rest[end..].find(')') {
                token_end = end + close + 1;
            }
        }
        tools.push(rest[..token_end].to_owned());
        rest = &rest[token_end..];
    }
    tools
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

/// Whether `policy` grants `capability`: `network_access` by `optional` or
/// `required`, the others by `true` (spec 10.5).
#[must_use]
pub fn policy_grants(policy: &serde_json::Value, capability: &str) -> bool {
    if capability == "network_access" {
        matches!(
            policy
                .get("network_access")
                .and_then(serde_json::Value::as_str),
            Some("optional" | "required")
        )
    } else {
        policy
            .get(capability)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }
}

/// Each granted tool whose capability the policy denies, in frontmatter
/// order: the `AGT-CAP-001` judgement, shared with the capabilities
/// attestation (spec 10.5).
#[must_use]
pub fn escalations(
    rules: &RuleSet,
    skill_md: &str,
    policy: &serde_json::Value,
) -> Vec<(String, String)> {
    frontmatter_tools(skill_md)
        .into_iter()
        .filter_map(|tool| {
            let capability = rules.tool_capability(&tool)?.to_owned();
            (!policy_grants(policy, &capability)).then_some((tool, capability))
        })
        .collect()
}

/// `AGT-CAP-001`: frontmatter must not grant what the policy denies.
fn check_capability_escalation(
    rules: &RuleSet,
    skill_md: &str,
    policy: &serde_json::Value,
) -> Vec<Finding> {
    escalations(rules, skill_md, policy)
        .into_iter()
        .map(|(tool, capability)| {
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
    // check_invisible is per-document and now lives in Analyzer::audit_str, so
    // every caller gets it whether or not it is auditing a whole skill.
    let mut findings = Vec::new();
    let Some(skill_md) = files.get("SKILL.md") else {
        return findings;
    };

    let (policy, policy_findings) = load_policy(files);
    findings.extend(policy_findings);
    findings.extend(check_capability_escalation(rules, skill_md, &policy));
    findings.extend(check_policy_prose(skill_md, &policy));
    findings
}

#[cfg(test)]
mod emoji_context_tests {
    use super::*;

    const STEG: &str = r#"
id = "AGT-STEG-001"
category = "steganography"
severity = "critical"
title = "Invisible code point"
kind = "structural"
scope = "raw"
applies_to = ["*"]
code_points = [ { cp = "U+200B", name = "Zero-width space" } ]
code_point_ranges = [
  { from = "U+FE00",  to = "U+FE0F",  name = "Variation selectors" },
  { from = "U+E0000", to = "U+E007F", name = "Unicode tag block" },
  { from = "U+E0100", to = "U+E01EF", name = "Variation selectors supplement" },
]
[emoji_context]
selectors = { from = "U+FE0E", to = "U+FE0F" }
keycap = "U+20E3"
base_points = ["U+0023", "U+0031"]
base_ranges = [ { from = "U+2600", to = "U+27BF", name = "Symbols" }, { from = "U+1F000", to = "U+1FAFF", name = "Emoji" } ]
[emoji_context.subdivision_flag]
base = "U+1F3F4"
tags_from = "U+E0061"
tags_to = "U+E007A"
terminator = "U+E007F"
"#;

    const PLAIN: &str = r#"
id = "AGT-STEG-001"
category = "steganography"
severity = "critical"
title = "Invisible code point"
kind = "structural"
scope = "raw"
applies_to = ["*"]
code_points = [ { cp = "U+200B", name = "Zero-width space" } ]
code_point_ranges = [ { from = "U+FE00", to = "U+FE0F", name = "Variation selectors" }, { from = "U+E0000", to = "U+E007F", name = "Unicode tag block" } ]
"#;

    const FLAG: &str = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}";

    fn rules(text: &str) -> RuleSet {
        RuleSet::from_sources([("AGT-STEG-001", text)]).expect("rule loads")
    }

    fn ids(rules: &RuleSet, text: &str, pedantic: bool) -> Vec<(String, String)> {
        check_invisible_with(rules, "SKILL.md", text, pedantic)
            .into_iter()
            .map(|f| (f.rule, f.severity))
            .collect()
    }

    #[test]
    fn a_selector_after_an_emoji_base_is_silent_unless_pedantic() {
        let rules = rules(STEG);
        assert!(
            ids(
                &rules,
                "Done \u{2705}\u{FE0F} and \u{1F680}\u{FE0F}.",
                false
            )
            .is_empty()
        );
        assert_eq!(
            ids(&rules, "Done \u{2705}\u{FE0F}.", true),
            vec![("AGT-STEG-002".to_owned(), "LOW".to_owned())]
        );
    }

    #[test]
    fn a_keycap_is_an_emoji_base() {
        assert!(
            ids(
                &rules(STEG),
                "Press 1\u{FE0F}\u{20E3} and #\u{FE0F}\u{20E3}.",
                false
            )
            .is_empty()
        );
    }

    #[test]
    fn a_run_a_letter_base_and_the_supplement_stay_critical() {
        let rules = rules(STEG);
        let critical = ("AGT-STEG-001".to_owned(), "CRITICAL".to_owned());
        assert_eq!(
            ids(&rules, "Done \u{2705}\u{FE0F}\u{FE0F}.", false),
            vec![critical.clone(), critical.clone()]
        );
        assert_eq!(
            ids(&rules, "Plain a\u{FE0F} text.", false),
            vec![critical.clone()]
        );
        assert_eq!(ids(&rules, "\u{FE0F} text.", false), vec![critical.clone()]);
        assert_eq!(
            ids(&rules, "Done \u{2705}\u{E0100}.", false),
            vec![critical]
        );
    }

    #[test]
    fn a_well_formed_subdivision_flag_is_low_once_and_always() {
        let findings =
            check_invisible_with(&rules(STEG), "SKILL.md", &format!("England: {FLAG}"), false);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "AGT-STEG-002");
        assert_eq!(findings[0].severity, "LOW");
        assert!(
            findings[0].message.contains("5 tag character(s)"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn tags_outside_a_flag_stay_critical() {
        let rules = rules(STEG);
        assert_eq!(
            ids(&rules, "Notes\u{E0067}\u{E0062}\u{E007F} here.", false).len(),
            3
        );
        assert_eq!(
            ids(&rules, "\u{1F3F4}\u{E0067}\u{E0062} here.", false).len(),
            2
        );
        assert_eq!(
            ids(&rules, "\u{1F3F4}\u{E0067}\u{E0041}\u{E007F}.", false).len(),
            3
        );
        assert!(
            ids(&rules, "\u{1F3F4}\u{E0067}\u{E0062} here.", false)
                .iter()
                .all(|(r, _)| r == "AGT-STEG-001")
        );
    }

    #[test]
    fn without_a_context_every_selector_and_tag_is_critical() {
        let rules = rules(PLAIN);
        assert_eq!(ids(&rules, "Done \u{2705}\u{FE0F}.", false).len(), 1);
        assert_eq!(ids(&rules, FLAG, true).len(), 6);
        assert!(
            ids(&rules, "Done \u{2705}\u{FE0F}.", true)
                .iter()
                .all(|(r, s)| r == "AGT-STEG-001" && s == "CRITICAL")
        );
    }
}

#[cfg(test)]
mod capability_tests {
    use super::{SkillFiles, audit_skill, frontmatter_tools};
    use crate::rules::RuleSet;

    const CAP: &str = r#"
id = "AGT-CAP-001"
category = "capability_escalation"
severity = "high"
title = "Frontmatter grants a denied capability"
kind = "structural"
scope = "raw"
[tool_capabilities]
Bash = "executes_commands"
WebFetch = "network_access"
"#;

    fn skill(tools: &str, policy: &str) -> SkillFiles {
        let mut files = SkillFiles::new();
        files.insert(
            "SKILL.md".to_owned(),
            format!(
                "---\nname: s\ndescription: Use when testing.\nallowed-tools: {tools}\n---\n\n# S\n"
            ),
        );
        files.insert(
            "metadata.json".to_owned(),
            format!("{{\"safety_policy\": {policy}}}"),
        );
        files
    }

    fn escalated(tools: &str, policy: &str) -> Vec<String> {
        let rules = RuleSet::from_sources([("AGT-CAP-001", CAP)]).expect("rule loads");
        audit_skill(&rules, &skill(tools, policy))
            .into_iter()
            .filter(|f| f.rule == "AGT-CAP-001")
            .map(|f| f.message)
            .collect()
    }

    #[test]
    fn tools_split_on_whitespace_and_commas_keeping_specifiers() {
        let md = |v: &str| format!("---\nname: s\nallowed-tools: {v}\n---\n");
        assert_eq!(
            frontmatter_tools(&md("\"Read Grep Bash\"")),
            ["Read", "Grep", "Bash"]
        );
        assert_eq!(frontmatter_tools(&md("[Read, 'Write']")), ["Read", "Write"]);
        assert_eq!(
            frontmatter_tools(&md("\"Read Bash(git log:*) WebFetch\"")),
            ["Read", "Bash(git log:*)", "WebFetch"]
        );
        assert!(frontmatter_tools("no frontmatter").is_empty());
    }

    #[test]
    fn a_space_separated_grant_escalates() {
        let found = escalated("\"Read Grep Bash\"", r#"{"executes_commands": false}"#);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("'Bash'"));
    }

    #[test]
    fn a_specifier_narrows_a_tool_and_still_grants_it() {
        assert_eq!(
            escalated("\"Bash(git log:*)\"", r#"{"executes_commands": false}"#).len(),
            1
        );
        assert!(escalated("\"Bash(git log:*)\"", r#"{"executes_commands": true}"#).is_empty());
        assert!(escalated("WebFetch", r#"{"network_access": "optional"}"#).is_empty());
        assert_eq!(
            escalated("WebFetch", r#"{"network_access": "none"}"#).len(),
            1
        );
    }

    #[test]
    fn a_capability_rule_without_its_table_does_not_load() {
        let bare = CAP.split("[tool_capabilities]").next().expect("head");
        assert!(RuleSet::from_sources([("AGT-CAP-001", bare)]).is_err());
    }
}
