// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rule definitions, loaded from `agtmls-spec/rules/*.toml`.
//!
//! Rules are data, not code. Both implementations load the same TOML files, so
//! adding a rule means adding a file and a corpus case — never writing the
//! same regex twice in two languages and hoping they stay equivalent.

use std::collections::BTreeMap;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;

/// Severity, ordered so comparisons mean what they read like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational.
    Low,
    /// Worth review before publication.
    Medium,
    /// Blocks an import or a release.
    High,
    /// Hidden content: never benign in a skill.
    Critical,
}

impl Severity {
    /// The uppercase spelling used in reports and JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// Where a pattern is matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Against the whitespace-normalised document, so a payload split across a
    /// newline cannot evade the rule. The default, and almost always correct.
    #[default]
    Normalised,
    /// Against each line independently.
    Line,
    /// Against the raw bytes as decoded, with no normalisation.
    Raw,
}

/// One rule, as declared in TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleSpec {
    /// Stable identifier, e.g. `AGT-EXEC-001`. Permanent; never reused.
    pub id: String,
    /// Finding category, e.g. `unsafe_execution`.
    pub category: String,
    /// Default severity.
    pub severity: Severity,
    /// Short human title.
    pub title: String,
    /// Regex source. Absent for structural rules implemented in code.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Matching scope.
    #[serde(default)]
    pub scope: Scope,
    /// Glob-ish file selectors, plus the literal `executable`.
    #[serde(default)]
    pub applies_to: Vec<String>,
    /// Prose description.
    #[serde(default)]
    pub description: String,
    /// Inputs the rule must flag.
    #[serde(default)]
    pub true_positive: Vec<Example>,
    /// Inputs the rule must not flag.
    #[serde(default)]
    pub false_positive: Vec<Example>,
    /// Individual code points, for `AGT-STEG-001`.
    #[serde(default)]
    pub code_points: Vec<CodePoint>,
    /// Code point ranges the enumeration cannot practically cover.
    #[serde(default)]
    pub code_point_ranges: Vec<CodePointRange>,
}

/// One named code point declared by a structural rule.
#[derive(Debug, Clone, Deserialize)]
pub struct CodePoint {
    /// `U+XXXX` spelling.
    pub cp: String,
    /// Human-readable name, used in the finding message.
    pub name: String,
}

/// An inclusive range of code points.
#[derive(Debug, Clone, Deserialize)]
pub struct CodePointRange {
    /// Inclusive lower bound, `U+XXXX`.
    pub from: String,
    /// Inclusive upper bound, `U+XXXX`.
    pub to: String,
    /// Human-readable name for the class.
    pub name: String,
}

fn parse_code_point(value: &str) -> Option<char> {
    let hex = value
        .strip_prefix("U+")
        .or_else(|| value.strip_prefix("u+"))?;
    char::from_u32(u32::from_str_radix(hex, 16).ok()?)
}

/// A worked example attached to a rule.
#[derive(Debug, Clone, Deserialize)]
pub struct Example {
    /// The example text.
    pub text: String,
    /// Why it is listed.
    #[serde(default)]
    pub note: String,
}

/// A rule with its pattern compiled.
#[derive(Debug, Clone)]
pub struct Rule {
    /// The declaration this was built from.
    pub spec: RuleSpec,
    /// Compiled pattern, `None` for structural rules.
    pub regex: Option<Regex>,
    /// Resolved code points, by character, for structural rules that declare
    /// them. Built from the rule data so neither implementation owns the set.
    invisible: BTreeMap<char, String>,
}

impl Rule {
    /// The declared name of `ch`, if this rule treats it as invisible.
    #[must_use]
    pub fn invisible_name(&self, ch: char) -> Option<&str> {
        if let Some(name) = self.invisible.get(&ch) {
            return Some(name.as_str());
        }
        self.spec.code_point_ranges.iter().find_map(|range| {
            let low = parse_code_point(&range.from)?;
            let high = parse_code_point(&range.to)?;
            (ch >= low && ch <= high).then_some(range.name.as_str())
        })
    }
}

/// Every rule, keyed by identifier so lookup and reporting are stable.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    /// Rules by identifier, in sorted order.
    pub rules: BTreeMap<String, Rule>,
}

/// Why a rule set could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The rules directory could not be read.
    Io(std::io::Error),
    /// A rule file was not valid TOML, or did not match the schema.
    Toml(String, toml::de::Error),
    /// A rule declared a pattern that is not a valid regex.
    Regex(String, Box<regex::Error>),
    /// A rule's own declared example contradicts its pattern.
    SelfTest(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "reading rules: {e}"),
            Self::Toml(id, e) => write!(f, "{id}: invalid rule TOML: {e}"),
            Self::Regex(id, e) => write!(f, "{id}: invalid pattern: {e}"),
            Self::SelfTest(m) => write!(f, "rule self-test failed: {m}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl RuleSet {
    /// Load and compile every `*.toml` in `dir`.
    ///
    /// # Errors
    /// Returns [`LoadError`] if the directory cannot be read, a file is not
    /// valid TOML, a pattern does not compile, or a self-test fails.
    pub fn load(dir: &Path) -> Result<Self, LoadError> {
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .map_err(LoadError::Io)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "toml"))
            .collect();
        paths.sort();

        let mut sources = Vec::with_capacity(paths.len());
        for path in paths {
            let text = std::fs::read_to_string(&path).map_err(LoadError::Io)?;
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            sources.push((name, text));
        }
        Self::from_sources(sources.iter().map(|(n, t)| (n.as_str(), t.as_str())))
    }

    /// Load and compile rules from in-memory TOML sources.
    ///
    /// The filesystem-free path: a WASM build embeds the rule data at compile
    /// time and has nowhere to read it from at runtime. Both entry points run
    /// the same self-tests, so an embedded rule set is no less checked than a
    /// loaded one.
    ///
    /// # Errors
    /// Returns [`LoadError`] if a source is not valid TOML, a pattern does not
    /// compile, or a rule fails its own declared examples.
    pub fn from_sources<'a>(
        sources: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, LoadError> {
        let mut rules = BTreeMap::new();
        for (name, text) in sources {
            let spec: RuleSpec =
                toml::from_str(text).map_err(|e| LoadError::Toml(name.to_owned(), e))?;
            let regex = match &spec.pattern {
                Some(source) => Some(
                    Regex::new(source)
                        .map_err(|e| LoadError::Regex(spec.id.clone(), Box::new(e)))?,
                ),
                None => None,
            };
            let invisible = spec
                .code_points
                .iter()
                .filter_map(|point| Some((parse_code_point(&point.cp)?, point.name.clone())))
                .collect();
            let rule = Rule {
                spec,
                regex,
                invisible,
            };
            rule.self_test()?;
            rules.insert(rule.spec.id.clone(), rule);
        }
        Ok(Self { rules })
    }

    /// Number of loaded rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Rule {
    fn self_test(&self) -> Result<(), LoadError> {
        let Some(regex) = &self.regex else {
            return Ok(());
        };
        for example in &self.spec.true_positive {
            if !regex.is_match(&normalise(&example.text)) {
                return Err(LoadError::SelfTest(format!(
                    "{}: declared true_positive is not matched: {:?}",
                    self.spec.id, example.text
                )));
            }
        }
        for example in &self.spec.false_positive {
            if regex.is_match(&normalise(&example.text)) {
                return Err(LoadError::SelfTest(format!(
                    "{}: declared false_positive IS matched: {:?}",
                    self.spec.id, example.text
                )));
            }
        }
        Ok(())
    }
}

/// Collapse every whitespace run to a single space.
///
/// Matching the normalised document is what stops a payload split across a
/// newline from walking past a line-scoped rule.
#[must_use]
pub fn normalise(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut previous_was_space = false;
    for ch in content.chars() {
        if ch.is_whitespace() {
            if !previous_was_space {
                out.push(' ');
                previous_was_space = true;
            }
        } else {
            out.push(ch);
            previous_was_space = false;
        }
    }
    out
}
