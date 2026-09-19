// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Content-addressed identity for a skill.
//!
//! Normative definition: `agtmls-spec/spec/03-integrity.md`. The Python
//! reference implementation lives in `agtmls/scripts/_lib/digest.py`, and the
//! shared vectors in `agtmls-spec/corpus/digest/cases.json` are what keep the
//! two honest — if they disagree, both builds fail.
//!
//! The digest is taken over a manifest of `(relative path, content hash)`
//! pairs rather than over an archive, so it is identical across a git clone,
//! a copied install, an extracted wheel and a release tarball. Without that
//! property a digest cannot verify an install, which is the only thing it is
//! for.

use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Never part of a skill's identity: OS debris.
const EXCLUDED_NAMES: &[&str] = &[".DS_Store", "Thumbs.db"];
/// Build, VCS and install caches. Excluded at any path depth, not just the root.
const EXCLUDED_DIRS: &[&str] = &["__pycache__", ".git", ".agtmls", "node_modules", ".venv"];
/// Derived or editor artefacts.
const EXCLUDED_SUFFIXES: &[&str] = &["pyc", "pyo", "swp"];

/// One entry of the manifest the digest is computed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Path relative to the skill root, always `/`-separated.
    pub path: String,
    /// Lowercase hex SHA-256 of the file's bytes.
    pub sha256: String,
}

/// What a scan of a skill directory found.
#[derive(Debug, Clone, Default)]
pub struct Manifest {
    /// Included files, sorted by the UTF-8 bytes of `path` (spec 3.7).
    pub entries: Vec<ManifestEntry>,
    /// Symlinks encountered. Excluded from the digest, reported to the caller
    /// (spec 3.5) so a non-portable skill is visible rather than silent.
    pub symlinks: Vec<String>,
}

fn is_excluded(relative: &Path, name: &str) -> bool {
    if EXCLUDED_NAMES.contains(&name) {
        return true;
    }
    if relative
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| EXCLUDED_SUFFIXES.contains(&e))
    {
        return true;
    }
    // Any *parent* component may be an excluded directory.
    relative
        .parent()
        .into_iter()
        .flat_map(Path::components)
        .filter_map(|c| c.as_os_str().to_str())
        .any(|c| EXCLUDED_DIRS.contains(&c))
}

fn walk(root: &Path, dir: &Path, out: &mut Manifest) -> io::Result<()> {
    let mut children: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    children.sort();

    for path in children {
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let relative_str = relative.to_string_lossy().replace('\\', "/");

        // symlink_metadata does not traverse: a symlinked directory must not
        // be descended into, or the digest would depend on files outside the
        // skill (spec 3.5).
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            out.symlinks.push(relative_str);
            continue;
        }

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if meta.is_dir() {
            if EXCLUDED_DIRS.contains(&name) {
                continue;
            }
            walk(root, &path, out)?;
        } else if meta.is_file() && !is_excluded(relative, name) {
            let bytes = std::fs::read(&path)?;
            out.entries.push(ManifestEntry {
                path: relative_str,
                sha256: hex(&Sha256::digest(&bytes)),
            });
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            // Writing to a String cannot fail.
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// Scan `root`, returning the manifest and any symlinks found.
///
/// # Errors
/// Returns the underlying [`io::Error`] if the tree cannot be read.
pub fn manifest(root: &Path) -> io::Result<Manifest> {
    let mut out = Manifest::default();
    walk(root, root, &mut out)?;
    // Sort on raw UTF-8 bytes, never a locale collation: otherwise the same
    // tree digests differently under different LANG settings, and only for
    // skills with non-ASCII filenames (spec 3.7).
    out.entries
        .sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    out.symlinks.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Ok(out)
}

/// Fold a manifest into its digest, `sha256:` followed by 64 lowercase hex.
#[must_use]
pub fn digest_from_manifest(entries: &[ManifestEntry]) -> String {
    let mut accumulator = Sha256::new();
    for entry in entries {
        accumulator.update(entry.path.as_bytes());
        accumulator.update([0x00]);
        // The 32 RAW bytes, not the hex text (spec 3.8).
        let raw: Vec<u8> = (0..entry.sha256.len() / 2)
            .filter_map(|i| u8::from_str_radix(&entry.sha256[i * 2..i * 2 + 2], 16).ok())
            .collect();
        accumulator.update(&raw);
        accumulator.update([0x00]);
    }
    format!("sha256:{}", hex(&accumulator.finalize()))
}

/// Content address of the skill directory at `root`.
///
/// # Errors
/// Returns the underlying [`io::Error`] if the tree cannot be read.
pub fn skill_digest(root: &Path) -> io::Result<String> {
    Ok(digest_from_manifest(&manifest(root)?.entries))
}
