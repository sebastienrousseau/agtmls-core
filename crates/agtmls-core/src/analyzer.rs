// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Static analysis of skill content.
//!
//! Every finding carries a stable rule identifier, because suppressions, SARIF
//! export and cross-implementation comparison all need to key on something
//! other than a prose message.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::rules::{RuleSet, Scope, Severity, normalise};
use crate::skill::check_invisible;

/// Files an agent could read or a user could execute.
///
/// Restricting analysis to Markdown was the gap that mattered in the Python
/// implementation: skills ship harness scripts and examples beside `SKILL.md`,
/// and a malicious `verify.sh` passed a strict audit cleanly.
const AUDITABLE_SUFFIXES: &[&str] = &[
    "md", "markdown", "txt", "rst", "sh", "bash", "zsh", "fish", "ps1", "py", "js", "mjs", "cjs",
    "ts", "rb", "pl", "lua", "json", "yaml", "yml", "toml", "ini", "cfg",
];

/// A hostile skill must not be able to exhaust memory during its own audit.
const MAX_AUDIT_BYTES: u64 = 5 * 1024 * 1024;

/// One finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// File the finding is in.
    pub file: PathBuf,
    /// 1-indexed source line.
    pub line: usize,
    /// Severity as an uppercase string.
    pub severity: String,
    /// Finding category, e.g. `unsafe_execution`.
    pub category: String,
    /// Stable rule identifier.
    pub rule: String,
    /// Human-readable description.
    pub message: String,
}

/// Runs a [`RuleSet`] over content.
#[derive(Debug, Clone)]
pub struct Analyzer {
    rules: RuleSet,
}

impl Analyzer {
    /// Build an analyzer over `rules`.
    #[must_use]
    pub const fn new(rules: RuleSet) -> Self {
        Self { rules }
    }

    /// The rule set in use.
    #[must_use]
    pub const fn rules(&self) -> &RuleSet {
        &self.rules
    }

    /// Analyse in-memory content. The entry point a WASM build uses, since it
    /// never needs a filesystem.
    ///
    /// Runs the pattern rules *and* the per-document structural ones. Invisible
    /// code points are a property of a document, so putting that check only in
    /// [`crate::skill::audit_skill`] left every single-file caller reporting
    /// clean on a file full of smuggled instructions.
    #[must_use]
    pub fn audit_str(&self, name: &str, content: &str) -> Vec<Finding> {
        let mut findings = check_invisible(&self.rules, name, content);
        findings.extend(self.audit_patterns(name, content));
        findings.sort_by(|a, b| (a.line, &a.rule).cmp(&(b.line, &b.rule)));
        findings.dedup_by(|a, b| a.line == b.line && a.rule == b.rule && a.message == b.message);
        findings
    }

    fn audit_patterns(&self, name: &str, content: &str) -> Vec<Finding> {
        let flat = normalise(content);
        // The line map costs a pass over every character, so it is built only
        // once something has actually matched. Almost every file is clean.
        let mut line_of: Option<Vec<usize>> = None;
        let mut findings = Vec::new();

        for rule in self.rules.rules.values() {
            let Some(regex) = &rule.regex else { continue };
            let haystack = match rule.spec.scope {
                Scope::Normalised => flat.as_str(),
                Scope::Line | Scope::Raw => content,
            };
            for m in regex.find_iter(haystack) {
                let line = if matches!(rule.spec.scope, Scope::Normalised) {
                    let map = line_of.get_or_insert_with(|| line_map(content));
                    map.get(m.start()).copied().unwrap_or(1)
                } else {
                    content[..m.start()].matches('\n').count() + 1
                };
                findings.push(Finding {
                    file: PathBuf::from(name),
                    line,
                    severity: rule.spec.severity.as_str().to_owned(),
                    category: rule.spec.category.clone(),
                    rule: rule.spec.id.clone(),
                    message: rule.spec.title.clone(),
                });
            }
        }
        findings
    }

    /// Analyse one file on disk.
    ///
    /// A file too large to analyse yields an `AGT-SCAN-001` finding rather
    /// than being skipped: an unscanned file is not a clean file.
    #[must_use]
    pub fn audit_file(&self, path: &Path) -> Vec<Finding> {
        let too_big = std::fs::metadata(path).is_ok_and(|m| m.len() > MAX_AUDIT_BYTES);
        if too_big {
            return vec![Finding {
                file: path.to_path_buf(),
                line: 1,
                severity: Severity::Medium.as_str().to_owned(),
                category: "scan_limit".to_owned(),
                rule: "AGT-SCAN-001".to_owned(),
                message: format!(
                    "File skipped: larger than the {MAX_AUDIT_BYTES} byte audit limit"
                ),
            }];
        }
        match std::fs::read(path) {
            Ok(bytes) => {
                let content = String::from_utf8_lossy(&bytes);
                self.audit_str(&path.to_string_lossy(), &content)
            }
            Err(_) => vec![Finding {
                file: path.to_path_buf(),
                line: 1,
                severity: Severity::Medium.as_str().to_owned(),
                category: "scan_limit".to_owned(),
                rule: "AGT-SCAN-001".to_owned(),
                message: "File could not be read".to_owned(),
            }],
        }
    }

    /// Whether a path is analysed: a known text suffix, or executable.
    #[must_use]
    pub fn is_auditable(path: &Path) -> bool {
        if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| AUDITABLE_SUFFIXES.contains(&e.to_lowercase().as_str()))
        {
            return true;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

/// Source line number for every character of `normalise(content)`.
fn line_map(content: &str) -> Vec<usize> {
    let mut map = Vec::with_capacity(content.len());
    let mut line = 1usize;
    let mut previous_was_space = false;
    for ch in content.chars() {
        if ch.is_whitespace() {
            if !previous_was_space {
                map.extend(std::iter::repeat_n(line, ' '.len_utf8()));
                previous_was_space = true;
            }
        } else {
            map.extend(std::iter::repeat_n(line, ch.len_utf8()));
            previous_was_space = false;
        }
        if ch == '\n' {
            line += 1;
        }
    }
    map
}
