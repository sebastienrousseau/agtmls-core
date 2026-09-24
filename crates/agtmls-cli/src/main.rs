// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Command-line interface to the `AgtMLS` engine.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agtmls_core::{Analyzer, Problem, RuleSet, digest, lockfile, skill};

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  \
         agtmls-rs digest <skill-dir>\n  \
         agtmls-rs audit  <path> --rules <dir> [--json] [--pedantic]\n  \
         agtmls-rs manifest <skill-dir> [--json]\n  \
         agtmls-rs verify <target> --agent <claude|codex|aider> [--json]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        return usage();
    };
    let json = args.iter().any(|a| a == "--json");
    let pedantic = args.iter().any(|a| a == "--pedantic");
    let rules_dir = args
        .iter()
        .position(|a| a == "--rules")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);
    let target = args.get(1).map(PathBuf::from);

    match (command.as_str(), target) {
        ("digest", Some(path)) => match digest::skill_digest(&path) {
            Ok(value) => {
                println!("{value}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        },
        ("manifest", Some(path)) => match digest::manifest(&path) {
            Ok(manifest) => {
                if json {
                    let entries: Vec<_> = manifest
                        .entries
                        .iter()
                        .map(|e| serde_json::json!({"path": e.path, "sha256": e.sha256}))
                        .collect();
                    println!(
                        "{}",
                        serde_json::json!({"entries": entries, "symlinks": manifest.symlinks})
                    );
                } else {
                    for entry in &manifest.entries {
                        println!("{}  {}", entry.sha256, entry.path);
                    }
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        },
        ("audit", Some(path)) => audit(&path, rules_dir.as_deref(), json, pedantic),
        ("verify", Some(path)) => {
            let agent = args
                .iter()
                .position(|a| a == "--agent")
                .and_then(|i| args.get(i + 1))
                .map_or("claude", String::as_str);
            verify(&path, agent, json)
        }
        _ => usage(),
    }
}

/// Exit code 3: the install cannot be trusted. Distinct from 1 (error) and
/// 2 (usage) so a calling script can branch on it.
const EXIT_INTEGRITY_FAILURE: u8 = 3;

fn verify(target: &Path, agent: &str, json: bool) -> ExitCode {
    let dot = match agent {
        "claude" => ".claude",
        "codex" => ".codex",
        "aider" => ".aider",
        other => {
            eprintln!("error: unknown agent {other:?}; expected claude, codex or aider");
            return ExitCode::from(2);
        }
    };
    let problems = match lockfile::verify(target, &target.join(dot).join("skills")) {
        Ok(problems) => problems,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(EXIT_INTEGRITY_FAILURE);
        }
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "target": target.display().to_string(),
                "ok": problems.is_empty(),
                "problems": problems,
            }))
            .unwrap_or_default()
        );
    } else if problems.is_empty() {
        println!("OK: installed tree matches the lockfile");
    } else {
        for problem in &problems {
            match problem {
                Problem::Modified {
                    name,
                    expected,
                    actual,
                } => {
                    eprintln!("MODIFIED     {name}  expected {expected}, found {actual}");
                }
                Problem::Missing { name } => {
                    eprintln!("MISSING      {name}  recorded in the lockfile but not installed");
                }
                Problem::Unmanaged { name } => {
                    eprintln!("UNMANAGED    {name}  installed but not in the lockfile");
                }
            }
        }
    }

    if problems.iter().any(Problem::is_integrity_failure) {
        ExitCode::from(EXIT_INTEGRITY_FAILURE)
    } else {
        ExitCode::SUCCESS
    }
}

/// Load a skill directory's files into memory for structural analysis.
fn read_skill(dir: &Path) -> Option<skill::SkillFiles> {
    if !dir.join("SKILL.md").is_file() {
        return None;
    }
    let mut files = skill::SkillFiles::new();
    for name in ["SKILL.md", "metadata.json"] {
        if let Ok(text) = std::fs::read_to_string(dir.join(name)) {
            files.insert(name.to_owned(), text);
        }
    }
    // metadata.json may exist but be unreadable as UTF-8; record its presence
    // so AGT-POLICY-002 fires rather than AGT-POLICY-001.
    if !files.contains_key("metadata.json") && dir.join("metadata.json").exists() {
        files.insert("metadata.json".to_owned(), String::from("\u{fffd}"));
    }
    Some(files)
}

/// Every skill directory at or below `root`, structurally analysed.
fn audit_skill_dirs(root: &Path) -> Vec<agtmls_core::Finding> {
    let mut findings = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Some(files) = read_skill(&dir) {
            findings.extend(skill::audit_skill(&files));
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let child = entry.path();
            if std::fs::symlink_metadata(&child)
                .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
            {
                stack.push(child);
            }
        }
    }
    findings
}

fn audit(path: &Path, rules_dir: Option<&Path>, json: bool, pedantic: bool) -> ExitCode {
    let Some(rules_dir) = rules_dir else {
        eprintln!("error: --rules <dir> is required (agtmls-spec/rules)");
        return ExitCode::from(2);
    };
    let rules = match RuleSet::load(rules_dir) {
        Ok(rules) => rules,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let analyzer = Analyzer::new(rules).pedantic(pedantic);

    let mut findings = Vec::new();
    if path.is_dir() {
        // Structural rules reason about the skill, not about any one file:
        // whether a policy is declared at all, and whether the frontmatter
        // grants more than the policy admits. Running only the per-file
        // pattern rules here left the binary silently weaker than the library
        // it is built on -- caught by the cross-implementation differential,
        // not by this crate's own tests.
        findings.extend(audit_skill_dirs(path));
        let mut stack = vec![path.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let child = entry.path();
                let Ok(meta) = std::fs::symlink_metadata(&child) else {
                    continue;
                };
                if meta.file_type().is_symlink() {
                    continue;
                }
                if meta.is_dir() {
                    stack.push(child);
                } else if Analyzer::is_auditable(&child) {
                    findings.extend(analyzer.audit_file(&child));
                }
            }
        }
    } else {
        findings.extend(analyzer.audit_file(path));
    }
    findings.sort_by(|a, b| (&a.file, a.line, &a.rule).cmp(&(&b.file, b.line, &b.rule)));

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "findings_count": findings.len(),
                "findings": findings,
            }))
            .unwrap_or_default()
        );
    } else if findings.is_empty() {
        println!("OK: zero findings");
    } else {
        for f in &findings {
            println!(
                "[{}] {}:{} ({} {}): {}",
                f.severity,
                f.file.display(),
                f.line,
                f.rule,
                f.category,
                f.message
            );
        }
    }
    if findings
        .iter()
        .any(|f| f.severity == "HIGH" || f.severity == "CRITICAL")
    {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
