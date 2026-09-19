// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Install lockfile: what was installed, and what it hashed to.
//!
//! Normative definition: `agtmls-spec/spec/06-lockfile.md`.
//!
//! Without this there is no answer to "is what I have what you published?",
//! and a skills registry is a decorated `ln -s`. The lockfile is what turns a
//! digest from a number in a JSON file into a control.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::digest::skill_digest;

/// Where the lockfile lives inside an install target.
pub const LOCKFILE_RELATIVE: &str = ".agtmls/manifest.json";

/// One installed skill, as recorded at install time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Skill name.
    pub name: String,
    /// Content address at install time.
    pub integrity: String,
    /// Path relative to the runtime's skills directory.
    pub path: String,
    /// Files whose executable bit matters.
    ///
    /// Mode bits are excluded from the digest by design (spec 3.4) because the
    /// executable bit does not survive every transport. Recorded separately so
    /// a lost bit can be repaired without looking like tampering.
    #[serde(default)]
    pub executable_files: Vec<String>,
}

/// Where the install came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    /// Registry URL.
    pub registry: String,
    /// Registry version at install time.
    pub registry_version: String,
}

/// The lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lockfile {
    /// Format version.
    pub schema_version: u32,
    /// `agtmls-spec` version the install targeted.
    pub spec_version: String,
    /// When the install happened.
    pub installed_at: String,
    /// Where it came from.
    pub source: Source,
    /// `symlink` or `copy`.
    pub mode: String,
    /// What was installed.
    pub skills: Vec<Entry>,
}

/// What a verification found wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum Problem {
    /// Content no longer matches what was installed.
    Modified {
        /// Skill name.
        name: String,
        /// Digest recorded at install time.
        expected: String,
        /// Digest computed now.
        actual: String,
    },
    /// Recorded in the lockfile but no longer on disk.
    Missing {
        /// Skill name.
        name: String,
    },
    /// Present but not installed by `AgtMLS`.
    ///
    /// Reported, never removed. Deleting something there is no record of
    /// installing is not the tool's to do.
    Unmanaged {
        /// Directory name.
        name: String,
    },
}

impl Problem {
    /// Whether this problem means the install cannot be trusted.
    ///
    /// `Unmanaged` is informational: a skill the tool did not install is not
    /// evidence that what it did install was altered.
    #[must_use]
    pub const fn is_integrity_failure(&self) -> bool {
        matches!(self, Self::Modified { .. } | Self::Missing { .. })
    }
}

/// Read the lockfile from an install target.
///
/// # Errors
/// Returns an error string if the file is absent or not valid JSON.
pub fn read(target: &Path) -> Result<Lockfile, String> {
    let path = target.join(LOCKFILE_RELATIVE);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("no lockfile at {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("lockfile is not valid JSON: {e}"))
}

/// Compare an installed tree against its lockfile.
///
/// Reports rather than repairs. Silently rewriting a skill whose digest moved
/// would destroy a local edit and would hide tampering behind the same
/// behaviour.
///
/// # Errors
/// Returns an error string if the lockfile cannot be read.
pub fn verify(target: &Path, skills_dir: &Path) -> Result<Vec<Problem>, String> {
    let lock = read(target)?;
    let mut problems = Vec::new();
    let mut recorded: Vec<&str> = Vec::new();

    for entry in &lock.skills {
        recorded.push(entry.name.as_str());
        let installed: PathBuf = skills_dir.join(&entry.path);
        if !installed.exists() {
            problems.push(Problem::Missing {
                name: entry.name.clone(),
            });
            continue;
        }
        match skill_digest(&installed) {
            Ok(actual) if actual == entry.integrity => {}
            Ok(actual) => problems.push(Problem::Modified {
                name: entry.name.clone(),
                expected: entry.integrity.clone(),
                actual,
            }),
            Err(error) => problems.push(Problem::Modified {
                name: entry.name.clone(),
                expected: entry.integrity.clone(),
                actual: format!("<unreadable: {error}>"),
            }),
        }
    }

    if let Ok(entries) = std::fs::read_dir(skills_dir) {
        let mut strangers: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| !recorded.contains(&name.as_str()))
            .collect();
        strangers.sort();
        problems.extend(
            strangers
                .into_iter()
                .map(|name| Problem::Unmanaged { name }),
        );
    }

    Ok(problems)
}
