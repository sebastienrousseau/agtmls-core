// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conformance against `agtmls-spec`.
//!
//! These tests replay the shared corpus. They FAIL rather than skip when the
//! spec cannot be found: a conformance suite that quietly skips is worse than
//! none, because it reports green while proving nothing.
//!
//! Point `AGTMLS_SPEC` at a checkout of
//! <https://github.com/sebastienrousseau/agtmls-spec>.

use std::path::{Path, PathBuf};

use std::collections::BTreeMap;

use agtmls_core::{Analyzer, RuleSet, digest, skill};
use serde_json::Value;

fn spec_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AGTMLS_SPEC") {
        return PathBuf::from(dir);
    }
    // Sibling checkout, the usual local layout.
    // CARGO_MANIFEST_DIR is crates/agtmls-core, so a sibling checkout of the
    // spec is four levels up and across.
    for candidate in ["../../../agtmls-spec", "../../../../Other/agtmls-spec"] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(candidate);
        if path.join("corpus").is_dir() {
            return path;
        }
    }
    panic!(
        "agtmls-spec not found. Set AGTMLS_SPEC to a checkout of \
         https://github.com/sebastienrousseau/agtmls-spec. Refusing to skip: a \
         conformance suite that skips reports green while proving nothing."
    );
}

fn materialise(case: &Value, root: &Path) {
    std::fs::create_dir_all(root).expect("create case root");
    if let Some(files) = case["files"].as_object() {
        for (relative, content) in files {
            let path = root.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("create parent");
            }
            std::fs::write(&path, content.as_str().unwrap_or_default()).expect("write file");
        }
    }
    for dir in case["directories"].as_array().into_iter().flatten() {
        std::fs::create_dir_all(root.join(dir.as_str().unwrap_or_default())).expect("create dir");
    }
    #[cfg(unix)]
    if let Some(links) = case["symlinks"].as_object() {
        for (link, target) in links {
            let _ =
                std::os::unix::fs::symlink(target.as_str().unwrap_or_default(), root.join(link));
        }
    }
}

/// L2: the digest must match the Python reference byte for byte.
#[test]
fn digest_vectors_match_the_specification() {
    let spec = spec_dir();
    let corpus: Value = serde_json::from_str(
        &std::fs::read_to_string(spec.join("corpus/digest/cases.json"))
            .expect("read digest corpus"),
    )
    .expect("parse digest corpus");

    let tmp = std::env::temp_dir().join(format!("agtmls-conformance-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);

    let cases = corpus["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty(), "corpus is empty");

    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap_or("?");
        let root = tmp.join(name);
        materialise(case, &root);

        let expected = case["expected_digest"].as_str().unwrap_or_default();
        let actual = digest::skill_digest(&root).expect("compute digest");
        if actual != expected {
            let manifest = digest::manifest(&root).expect("manifest");
            failures.push(format!(
                "{name}: {}\n    expected {expected}\n    actual   {actual}\n    manifest {:?}",
                case["why"].as_str().unwrap_or(""),
                manifest.entries.iter().map(|e| &e.path).collect::<Vec<_>>()
            ));
            continue;
        }

        // The manifest itself must agree, not only the folded digest: two
        // different manifests colliding on a digest would otherwise pass.
        let expected_manifest: Vec<(String, String)> = case["expected_manifest"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|e| {
                        (
                            e["path"].as_str().unwrap_or_default().to_owned(),
                            e["sha256"].as_str().unwrap_or_default().to_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let actual_manifest: Vec<(String, String)> = digest::manifest(&root)
            .expect("manifest")
            .entries
            .into_iter()
            .map(|e| (e.path, e.sha256))
            .collect();
        if actual_manifest != expected_manifest {
            failures.push(format!(
                "{name}: manifest mismatch\n    expected {expected_manifest:?}\n    actual   {actual_manifest:?}"
            ));
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);
    assert!(
        failures.is_empty(),
        "{} of {} digest vectors failed:\n  {}",
        failures.len(),
        cases.len(),
        failures.join("\n  ")
    );
}

/// Every rule must load, compile, and satisfy its own declared examples.
#[test]
fn rules_load_and_self_test() {
    let rules = RuleSet::load(&spec_dir().join("rules")).expect("load rules");
    assert!(
        rules.len() >= 15,
        "expected the full rule set, got {}",
        rules.len()
    );
    for (id, rule) in &rules.rules {
        assert_eq!(id, &rule.spec.id, "rule filename and id disagree");
        assert!(!rule.spec.title.is_empty(), "{id} has no title");
        assert!(!rule.spec.category.is_empty(), "{id} has no category");
    }
}

/// L3: the entire security corpus, including its evasion variants.
///
/// No category is excluded. The suite previously skipped the structural
/// categories while the analyzer implemented only pattern rules, which meant
/// it passed by not testing the thing that was missing.
#[test]
fn security_corpus_detections_match() {
    let spec = spec_dir();
    let rules = RuleSet::load(&spec.join("rules")).expect("load rules");
    let analyzer = Analyzer::new(rules.clone());
    let corpus: Value = serde_json::from_str(
        &std::fs::read_to_string(spec.join("corpus/security/corpus.json"))
            .expect("read security corpus"),
    )
    .expect("parse security corpus");

    let mut failures = Vec::new();
    let mut detections = 0usize;

    for case in corpus["cases"].as_array().expect("cases") {
        let name = case["name"].as_str().unwrap_or("?");
        let files: BTreeMap<String, String> = case["files"]
            .as_object()
            .expect("files")
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned()))
            .collect();

        // Pattern rules over each file, plus structural rules over the skill.
        let mut findings = Vec::new();
        for (relative, content) in &files {
            findings.extend(analyzer.audit_str(relative, content));
        }
        findings.extend(skill::audit_skill(&rules, &files));

        for want in case["must_detect"].as_array().into_iter().flatten() {
            detections += 1;
            let category = want["category"].as_str().unwrap_or_default();
            let floor = severity_rank(want["min_severity"].as_str().unwrap_or("LOW"));
            let hit = findings.iter().any(|f| {
                f.category == category
                    && severity_rank(&f.severity) >= floor
                    && want["in_file"]
                        .as_str()
                        .is_none_or(|wanted| f.file.to_string_lossy().ends_with(wanted))
            });
            if !hit {
                failures.push(format!(
                    "{name}: missed {category} >= {} -- {}",
                    want["min_severity"].as_str().unwrap_or("LOW"),
                    case["description"].as_str().unwrap_or("")
                ));
            }
        }
        for category in case["must_not_detect"].as_array().into_iter().flatten() {
            let category = category.as_str().unwrap_or_default();
            if let Some(noise) = findings.iter().find(|f| f.category == category) {
                failures.push(format!(
                    "{name}: FALSE POSITIVE {category}: {} -- {}",
                    noise.rule, noise.message
                ));
            }
        }
    }

    assert!(detections > 0, "no detections were exercised");
    assert!(
        failures.is_empty(),
        "{} failure(s) across {} detection(s):\n  {}",
        failures.len(),
        detections,
        failures.join("\n  ")
    );
}

fn severity_rank(value: &str) -> u8 {
    match value {
        "CRITICAL" => 3,
        "HIGH" => 2,
        "MEDIUM" => 1,
        _ => 0,
    }
}
