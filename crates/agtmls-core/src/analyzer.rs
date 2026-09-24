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
use crate::skill::check_invisible_with;

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
    pedantic: bool,
}

impl Analyzer {
    /// Build an analyzer over `rules`.
    #[must_use]
    pub const fn new(rules: RuleSet) -> Self {
        Self {
            rules,
            pedantic: false,
        }
    }

    /// Also report emoji-presentation selectors (`AGT-STEG-002`, LOW).
    #[must_use]
    pub const fn pedantic(mut self, pedantic: bool) -> Self {
        self.pedantic = pedantic;
        self
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
        let mut findings = check_invisible_with(&self.rules, name, content, self.pedantic);
        findings.extend(self.audit_patterns(name, content));
        findings.sort_by(|a, b| (a.line, &a.rule).cmp(&(b.line, &b.rule)));
        findings.dedup_by(|a, b| a.line == b.line && a.rule == b.rule && a.message == b.message);
        findings
    }

    fn audit_patterns(&self, name: &str, content: &str) -> Vec<Finding> {
        // spec 4.3: a model reads a JSON tool description decoded.
        let decoded;
        let source = if name.to_lowercase().ends_with(".json") {
            decoded = decode_json_escapes(content);
            decoded.as_str()
        } else {
            content
        };
        let flat = normalise(source);
        // The line map costs a pass over every character, so it is built only
        // once something has actually matched. Almost every file is clean.
        let mut line_of: Option<Vec<usize>> = None;
        let mut findings = Vec::new();

        for rule in self.rules.rules.values() {
            let Some(regex) = &rule.regex else { continue };
            if !applies(&rule.spec.applies_to, name, content) {
                continue;
            }
            let haystack = match rule.spec.scope {
                Scope::Normalised => flat.as_str(),
                Scope::Line | Scope::Raw => content,
            };
            for m in regex.find_iter(haystack) {
                let line = if matches!(rule.spec.scope, Scope::Normalised) {
                    let map = line_of.get_or_insert_with(|| line_map(source));
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
        // A script with no extension and no execute bit is still a script
        // (spec 4.11): `executable` selects by `#!`, so it must be walked.
        if has_shebang(path) {
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

fn has_shebang(path: &Path) -> bool {
    use std::io::Read as _;
    let mut head = [0_u8; 2];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && &head == b"#!"
}

/// One `applies_to` selector against one file (spec 4.11): `*`, `*.<ext>`
/// compared case-insensitively, or `executable` for content beginning `#!`.
/// Any other form matches nothing.
#[must_use]
pub fn selector_matches(selector: &str, name: &str, content: &str) -> bool {
    match selector {
        "*" => true,
        "executable" => content.starts_with("#!"),
        _ => selector
            .strip_prefix('*')
            .filter(|ext| ext.starts_with('.') && !ext.contains('*'))
            .is_some_and(|ext| {
                let file = name.rsplit(['/', '\\']).next().unwrap_or(name);
                file.to_lowercase().ends_with(&ext.to_lowercase())
            }),
    }
}

/// Whether a pattern rule runs on this file. No selectors means everywhere.
#[must_use]
pub fn applies(selectors: &[String], name: &str, content: &str) -> bool {
    selectors.is_empty() || selectors.iter().any(|s| selector_matches(s, name, content))
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

/// JSON string escapes decoded, never creating a line (spec 4.3).
///
/// Escaped whitespace and any decoded line terminator become a space, so line
/// numbers still point into the source; a surrogate pair is one code point,
/// a lone surrogate U+FFFD.
#[must_use]
pub fn decode_json_escapes(content: &str) -> String {
    const REPLACEMENT: char = '\u{FFFD}';
    let mut out = String::with_capacity(content.len());
    let mut pending_high: Option<u32> = None;
    let mut chars = content.char_indices().peekable();
    while let Some((i, ch)) = chars.next() {
        let escape = if ch == '\\' {
            match content[i + 1..].chars().next() {
                Some(c @ ('"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't')) => Some((c, None)),
                Some('u') => content
                    .get(i + 2..i + 6)
                    .filter(|h| h.chars().all(|c| c.is_ascii_hexdigit()))
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .map(|code| ('u', Some(code))),
                _ => None,
            }
        } else {
            None
        };
        let Some((kind, code)) = escape else {
            if pending_high.take().is_some() {
                out.push(REPLACEMENT);
            }
            out.push(ch);
            continue;
        };
        let skip = if kind == 'u' { 5 } else { 1 };
        for _ in 0..skip {
            chars.next();
        }
        match code {
            None => {
                if pending_high.take().is_some() {
                    out.push(REPLACEMENT);
                }
                out.push(match kind {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    _ => ' ',
                });
            }
            Some(high @ 0xD800..=0xDBFF) => {
                if pending_high.replace(high).is_some() {
                    out.push(REPLACEMENT);
                }
            }
            Some(low @ 0xDC00..=0xDFFF) => match pending_high.take() {
                Some(high) => out.push(
                    char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))
                        .unwrap_or(REPLACEMENT),
                ),
                None => out.push(REPLACEMENT),
            },
            Some(other) => {
                if pending_high.take().is_some() {
                    out.push(REPLACEMENT);
                }
                let decoded = char::from_u32(other).unwrap_or(REPLACEMENT);
                out.push(
                    if matches!(
                        decoded,
                        '\n' | '\r' | '\u{2028}' | '\u{2029}' | '\u{85}' | '\u{0b}' | '\u{0c}'
                    ) {
                        ' '
                    } else {
                        decoded
                    },
                );
            }
        }
    }
    if pending_high.is_some() {
        out.push(REPLACEMENT);
    }
    out
}

#[cfg(test)]
mod json_escape_tests {
    use super::decode_json_escapes as d;

    #[test]
    fn escapes_decode_and_whitespace_becomes_a_space() {
        assert_eq!(d(r#"a\nb\tc\"d\\e\/f"#), "a b c\"d\\e/f");
        assert_eq!(d(r"A😀"), "A\u{1F600}");
        assert_eq!(d(r"\u000a"), " ");
        assert_eq!(d(r"\\n"), "\\n");
    }

    #[test]
    fn every_malformed_surrogate_becomes_one_replacement() {
        assert_eq!(d(r"\ud83dx\ude00"), "\u{FFFD}x\u{FFFD}");
        assert_eq!(d(r"\ud83d\n"), "\u{FFFD} ");
        assert_eq!(d(r"\ud83d😀"), "\u{FFFD}\u{1F600}");
        assert_eq!(d(r"\ud83dA"), "\u{FFFD}A");
        assert_eq!(d(r"\ude00"), "\u{FFFD}");
        assert_eq!(d(r"\ud83d"), "\u{FFFD}");
    }
}

#[cfg(test)]
mod applies_to_tests {
    use super::{applies, selector_matches};

    #[test]
    fn selectors_follow_the_grammar() {
        assert!(selector_matches("*", "anything.xyz", ""));
        assert!(selector_matches("*.md", "a/B.MD", ""));
        assert!(!selector_matches("*.md", "a.mdx", ""));
        assert!(selector_matches("executable", "run", "#!/bin/sh\n"));
        assert!(!selector_matches("executable", "run.sh", "echo\n"));
        assert!(!selector_matches("README.md", "README.md", ""));
    }

    #[test]
    fn no_selectors_means_everywhere() {
        assert!(applies(&[], "x.lua", ""));
        assert!(!applies(&["*.json".to_owned()], "notes.md", ""));
        assert!(applies(
            &["*.json".to_owned(), "executable".to_owned()],
            "bin/run",
            "#!/bin/sh\n"
        ));
    }
}
