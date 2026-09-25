// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Command-line interface to the `AgtMLS` engine.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agtmls_core::advisories::{self, Revocation};
use agtmls_core::signatures::{self, Status};
use agtmls_core::{Analyzer, Problem, RuleSet, digest, lockfile, skill};

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  \
         agtmls-rs digest <skill-dir>\n  \
         agtmls-rs audit  <path> --rules <dir> [--json] [--pedantic]\n  \
         agtmls-rs manifest <skill-dir> [--json]\n  \
         agtmls-rs verify <target> --agent <claude|codex|aider> [--json]\n    \
                          [--registry <dir> [--signatures] [--allowed-signers <file>]]\n  \
         agtmls-rs signature <file> --sig <file> --allowed-signers <file> --namespace <ns>\n    \
                          [--verify-time YYYYMMDD] [--json]\n  \
         agtmls-rs advisories <feed> --allowed-signers <file> --lockfile <file>\n    \
                          [--sig <file>] [--verify-time YYYYMMDD] [--json]"
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
            let require_signed = args.iter().any(|a| a == "--signatures");
            let registry = option(&args, "--registry")
                .map(|dir| Registry::new(Path::new(dir), option(&args, "--allowed-signers")));
            if require_signed && registry.is_none() {
                eprintln!("error: --signatures needs --registry <dir>");
                return ExitCode::from(2);
            }
            let options = VerifyOptions {
                agent: option(&args, "--agent").unwrap_or("claude"),
                json,
                require_signed,
                registry,
                verify_time: option(&args, "--verify-time"),
            };
            verify(&path, &options)
        }
        ("signature", Some(path)) => signature_command(&path, &args, json),
        ("advisories", Some(path)) => advisories_command(&path, &args, json),
        _ => usage(),
    }
}

/// Exit code 3: the install cannot be trusted. Distinct from 1 (error) and
/// 2 (usage) so a calling script can branch on it.
const EXIT_INTEGRITY_FAILURE: u8 = 3;
/// Exit codes of agtmls-spec 9.5: nobody signed this, someone signed
/// something else, and a verified source names a revoked digest.
const EXIT_UNSIGNED: u8 = 4;
const EXIT_BAD_SIGNATURE: u8 = 5;
const EXIT_REVOKED: u8 = 6;

/// The value after `flag`, if present.
fn option<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Where a registry keeps what `verify` judges an install by.
struct Registry {
    index: PathBuf,
    feed: PathBuf,
    allowed_signers: PathBuf,
}

impl Registry {
    fn new(dir: &Path, allowed_signers: Option<&str>) -> Self {
        Self {
            index: dir.join("index.json"),
            feed: dir.join("advisories.json"),
            allowed_signers: allowed_signers
                .map_or_else(|| dir.join("ALLOWED_SIGNERS"), PathBuf::from),
        }
    }
}

fn sig_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

/// agtmls-spec 11.4: when several failures apply, the exit code is the
/// first of these. A source that does not verify supports no conclusion,
/// then what is installed is not what was published, then it is revoked,
/// then a required signature is absent.
const PRECEDENCE: [u8; 4] = [
    EXIT_BAD_SIGNATURE,
    EXIT_INTEGRITY_FAILURE,
    EXIT_REVOKED,
    EXIT_UNSIGNED,
];

/// The exit code for the failures that apply, `0` for none.
fn exit_code(failures: &[(u8, bool)]) -> u8 {
    PRECEDENCE
        .into_iter()
        .find(|code| failures.iter().any(|&(c, applies)| c == *code && applies))
        .unwrap_or(0)
}

/// A verified feed's revocations, or none: an unverified feed is never
/// consulted (spec 11.3).
fn feed_revocations<'a>(
    feed: &Path,
    status: Status,
    installed: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Vec<Revocation>, String> {
    if status != Status::Verified {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(feed)
        .map_err(|e| format!("{} could not be read: {e}", feed.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not valid JSON: {e}", feed.display()))?;
    Ok(advisories::revoked(&value, installed))
}

struct VerifyOptions<'a> {
    agent: &'a str,
    json: bool,
    require_signed: bool,
    registry: Option<Registry>,
    verify_time: Option<&'a str>,
}

/// The index signature, the feed signature and a verified feed's revocations.
type Judged = (Option<Status>, Option<Status>, Vec<Revocation>);

/// The index signature (when required), the feed's signature (when a feed
/// ships) and the revocations a verified feed names.
fn judge_registry(
    target: &Path,
    registry: &Registry,
    options: &VerifyOptions<'_>,
) -> Result<Judged, String> {
    let check = |data: &Path, namespace: &str| {
        signatures::verify(
            data,
            &sig_path(data),
            &registry.allowed_signers,
            namespace,
            signatures::PRINCIPAL,
            options.verify_time,
        )
        .map_err(|e| e.to_string())
    };
    let index = if options.require_signed {
        Some(check(&registry.index, signatures::INDEX_NAMESPACE)?)
    } else {
        None
    };
    if !registry.feed.is_file() {
        return Ok((index, None, Vec::new()));
    }
    let feed = check(&registry.feed, signatures::ADVISORY_NAMESPACE)?;
    let hits = match lockfile::read(target) {
        Ok(lock) => feed_revocations(
            &registry.feed,
            feed,
            lock.skills
                .iter()
                .map(|s| (s.name.as_str(), s.integrity.as_str())),
        )?,
        Err(_) => Vec::new(),
    };
    Ok((index, Some(feed), hits))
}

fn verify(target: &Path, options: &VerifyOptions<'_>) -> ExitCode {
    let dot = match options.agent {
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
    let judged = match &options.registry {
        None => Ok((None, None, Vec::new())),
        Some(registry) => judge_registry(target, registry, options),
    };
    let (index_status, feed_status, hits) = match judged {
        Ok(judged) => judged,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut notes = Vec::new();
    if feed_status == Some(Status::Unsigned) {
        notes.push("advisories.json is not signed; not consulted".to_owned());
    }
    let statuses = [index_status, feed_status];
    let integrity = problems.iter().any(Problem::is_integrity_failure);
    let code = exit_code(&[
        (
            EXIT_BAD_SIGNATURE,
            statuses.contains(&Some(Status::BadSignature)),
        ),
        (EXIT_INTEGRITY_FAILURE, integrity),
        (EXIT_REVOKED, !hits.is_empty()),
        (
            EXIT_UNSIGNED,
            options.require_signed && statuses.contains(&Some(Status::Unsigned)),
        ),
    ]);
    let label =
        |status: Option<Status>, absent: &'static str| status.map_or(absent, Status::as_str);

    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "target": target.display().to_string(),
                "ok": code == 0,
                "problems": problems,
                "index_signature": label(index_status, "not checked"),
                "advisory_feed": label(feed_status, "absent"),
                "revoked": hits,
                "notes": notes,
            }))
            .unwrap_or_default()
        );
        return ExitCode::from(code);
    }
    print_report(
        &problems,
        &hits,
        &notes,
        [index_status, feed_status],
        !integrity && code == 0,
    );
    ExitCode::from(code)
}

/// The human-readable form of a verification.
fn print_report(
    problems: &[Problem],
    hits: &[Revocation],
    notes: &[String],
    [index_status, feed_status]: [Option<Status>; 2],
    clean: bool,
) {
    for problem in problems {
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
    for hit in hits {
        eprintln!(
            "REVOKED      {}  {} by {}",
            hit.skill,
            hit.digest,
            hit.advisories.join(", ")
        );
    }
    for note in notes {
        eprintln!("note: {note}");
    }
    match index_status {
        Some(Status::Verified) => println!("OK: index.json signature verified"),
        Some(Status::BadSignature) => {
            eprintln!("BAD_SIGNATURE index.json.sig does not verify against ALLOWED_SIGNERS");
        }
        Some(Status::Unsigned) => {
            eprintln!("UNSIGNED     index.json has no signature, or there is no ALLOWED_SIGNERS");
        }
        None => {}
    }
    if feed_status == Some(Status::BadSignature) {
        eprintln!("BAD_SIGNATURE advisories.json.sig does not verify; the feed is not consulted");
    }
    if clean {
        println!("OK: installed tree matches the lockfile");
    }
}

/// `signature <data>`: one verification, for the conformance runner.
fn signature_command(data: &Path, args: &[String], json: bool) -> ExitCode {
    let (Some(sig), Some(allowed), Some(namespace)) = (
        option(args, "--sig"),
        option(args, "--allowed-signers"),
        option(args, "--namespace"),
    ) else {
        eprintln!("error: signature needs --sig, --allowed-signers and --namespace");
        return ExitCode::from(2);
    };
    match signatures::verify(
        data,
        Path::new(sig),
        Path::new(allowed),
        namespace,
        signatures::PRINCIPAL,
        option(args, "--verify-time"),
    ) {
        Ok(status) => {
            if json {
                println!("{}", serde_json::json!({"status": status.as_str()}));
            } else {
                println!("{}", status.as_str());
            }
            ExitCode::from(match status {
                Status::Verified => 0,
                Status::BadSignature => EXIT_BAD_SIGNATURE,
                Status::Unsigned => EXIT_UNSIGNED,
            })
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `advisories <feed>`: a feed judged against a lockfile, for the
/// conformance runner. Exit `5`, `6` or `4` as spec 11.4 orders them.
fn advisories_command(feed: &Path, args: &[String], json: bool) -> ExitCode {
    let (Some(allowed), Some(lock_path)) = (
        option(args, "--allowed-signers"),
        option(args, "--lockfile"),
    ) else {
        eprintln!("error: advisories needs --allowed-signers and --lockfile");
        return ExitCode::from(2);
    };
    let sig = option(args, "--sig").map_or_else(|| sig_path(feed), PathBuf::from);
    let status = match signatures::verify(
        feed,
        &sig,
        Path::new(allowed),
        signatures::ADVISORY_NAMESPACE,
        signatures::PRINCIPAL,
        option(args, "--verify-time"),
    ) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let lock: serde_json::Value = match std::fs::read_to_string(lock_path)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
    {
        Ok(value) => value,
        Err(error) => {
            eprintln!("error: {lock_path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let installed = lock
        .get("skills")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|s| Some((s.get("name")?.as_str()?, s.get("integrity")?.as_str()?)));
    let hits = match feed_revocations(feed, status, installed) {
        Ok(hits) => hits,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let code = exit_code(&[
        (EXIT_BAD_SIGNATURE, status == Status::BadSignature),
        (EXIT_REVOKED, !hits.is_empty()),
        (EXIT_UNSIGNED, status == Status::Unsigned),
    ]);
    if json {
        println!(
            "{}",
            serde_json::json!({"advisory_feed": status.as_str(), "revoked": hits})
        );
    } else {
        println!("{}", status.as_str());
        for hit in &hits {
            println!(
                "REVOKED {}  {} by {}",
                hit.skill,
                hit.digest,
                hit.advisories.join(", ")
            );
        }
    }
    ExitCode::from(code)
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
