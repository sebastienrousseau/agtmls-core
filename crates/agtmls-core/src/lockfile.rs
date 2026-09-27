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

/// Each native agent and the directory its skills live under, relative to
/// the target. Mirrors `native_agents.*.skills_dir` in the reference
/// implementation's `providers.json`; Antigravity reads the shared
/// `.agents/` directory rather than one of its own.
pub const NATIVE_AGENTS: &[(&str, &str)] = &[
    ("aider", ".aider/skills"),
    ("antigravity", ".agents/skills"),
    ("claude", ".claude/skills"),
    ("codex", ".codex/skills"),
];

/// The skills directory `agent` reads, relative to the target, or `None`
/// for an agent this implementation does not know.
#[must_use]
pub fn skills_dir(agent: &str) -> Option<&'static str> {
    NATIVE_AGENTS
        .iter()
        .find(|(name, _)| *name == agent)
        .map(|(_, dir)| *dir)
}

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
    /// The native agents this entry was installed for (spec 6.2).
    ///
    /// One lockfile serves every agent installed in a target. `None` is an
    /// entry written before the field existed, and counts for every agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<String>>,
}

impl Entry {
    /// Whether this entry describes `agent`'s skills directory. `None` asks
    /// about every agent.
    #[must_use]
    pub fn serves(&self, agent: Option<&str>) -> bool {
        match (agent, &self.agents) {
            (None, _) | (_, None) => true,
            (Some(agent), Some(agents)) => agents.iter().any(|a| a == agent),
        }
    }
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
/// Only the entries that serve `agent` are compared (spec 6.3): another
/// agent's record is not this directory's to answer for. `None` compares
/// every entry.
///
/// # Errors
/// Returns an error string if the lockfile cannot be read.
pub fn verify(
    target: &Path,
    skills_dir: &Path,
    agent: Option<&str>,
) -> Result<Vec<Problem>, String> {
    let lock = read(target)?;
    let mut problems = Vec::new();
    let mut recorded: Vec<&str> = Vec::new();

    for entry in lock.skills.iter().filter(|entry| entry.serves(agent)) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A target with one skill per agent directory and a lockfile describing
    /// both, in a directory removed when the guard drops.
    struct Target(PathBuf);

    impl Drop for Target {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// (agent directories holding it, skill name, recorded `agents`).
    type Placed<'a> = (&'a [&'a str], &'a str, Option<&'a [&'a str]>);

    /// Each skill is written into every listed agent directory and recorded
    /// once, with `agents` when given.
    fn target(name: &str, skills: &[Placed<'_>]) -> Target {
        let root = std::env::temp_dir().join(format!("agtmls-lock-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut entries = Vec::new();
        for (agent_dirs, skill, agents) in skills {
            let mut integrity = String::new();
            for agent_dir in *agent_dirs {
                let dir = root.join(agent_dir).join("skills").join(skill);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("SKILL.md"), format!("# {skill}\n")).unwrap();
                integrity = skill_digest(&dir).unwrap();
            }
            let mut entry = json!({"name": skill, "integrity": integrity, "path": skill});
            if let Some(agents) = agents {
                entry["agents"] = json!(agents);
            }
            entries.push(entry);
        }
        std::fs::create_dir_all(root.join(".agtmls")).unwrap();
        let lock = json!({
            "schema_version": 1, "spec_version": "0.1.0", "installed_at": "2026-09-27T00:00:00Z",
            "source": {"registry": "https://example.com", "registry_version": "0.0.0"},
            "mode": "copy", "skills": entries,
        });
        std::fs::write(root.join(LOCKFILE_RELATIVE), lock.to_string()).unwrap();
        Target(root)
    }

    #[test]
    fn each_agent_is_verified_against_its_own_entries() {
        let t = target(
            "agents",
            &[
                (
                    &[".claude", ".codex"],
                    "general",
                    Some(&["claude", "codex"]),
                ),
                (&[".codex"], "bundled", Some(&["codex"])),
            ],
        );
        let claude = verify(&t.0, &t.0.join(".claude/skills"), Some("claude")).unwrap();
        assert_eq!(
            claude,
            Vec::new(),
            "codex's bundled skill was reported missing for claude"
        );
        let codex = verify(&t.0, &t.0.join(".codex/skills"), Some("codex")).unwrap();
        assert_eq!(codex, Vec::new());
    }

    #[test]
    fn an_entry_without_agents_counts_for_every_agent() {
        let t = target("legacy", &[(&[".claude"], "general", None)]);
        let codex = verify(&t.0, &t.0.join(".codex/skills"), Some("codex")).unwrap();
        assert_eq!(
            codex,
            vec![Problem::Missing {
                name: "general".into()
            }]
        );
        let everyone = verify(&t.0, &t.0.join(".claude/skills"), None).unwrap();
        assert_eq!(everyone, Vec::new());
    }

    #[test]
    fn every_native_agent_has_a_skills_directory() {
        assert_eq!(skills_dir("antigravity"), Some(".agents/skills"));
        assert_eq!(skills_dir("claude"), Some(".claude/skills"));
        assert_eq!(skills_dir("codex"), Some(".codex/skills"));
        assert_eq!(skills_dir("aider"), Some(".aider/skills"));
        assert_eq!(skills_dir("cursor"), None);
    }

    #[test]
    fn agents_are_written_back_only_when_recorded() {
        let entry: Entry =
            serde_json::from_value(json!({"name": "a", "integrity": "sha256:0", "path": "a"}))
                .unwrap();
        assert!(entry.serves(Some("claude")) && entry.serves(None));
        assert!(!serde_json::to_string(&entry).unwrap().contains("agents"));
        let entry: Entry = serde_json::from_value(
            json!({"name": "a", "integrity": "sha256:0", "path": "a", "agents": ["codex"]}),
        )
        .unwrap();
        assert!(!entry.serves(Some("claude")) && entry.serves(Some("codex")) && entry.serves(None));
    }
}
