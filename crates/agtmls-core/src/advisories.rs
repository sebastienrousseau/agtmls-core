// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The advisory feed (agtmls-spec chapter 11).
//!
//! OSV records whose revoked skill digests sit under
//! `affected[].ecosystem_specific.digests`. A skill is revoked by digest,
//! never by name or version, and a withdrawn advisory revokes nothing. The
//! caller verifies the feed's signature first: an unverified feed is never
//! consulted (spec 11.3).

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

/// One installed skill a live advisory lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Revocation {
    /// The installed skill's name.
    pub skill: String,
    /// Its recorded digest.
    pub digest: String,
    /// Every live advisory listing that digest, sorted.
    pub advisories: Vec<String>,
}

/// Every installed `(name, digest)` a live advisory in `feed` lists, in
/// installed order (spec 11.4).
#[must_use]
pub fn revoked<'a>(
    feed: &Value,
    installed: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Vec<Revocation> {
    let mut by_digest: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let advisories = feed.get("advisories").and_then(Value::as_array);
    for advisory in advisories.into_iter().flatten() {
        if advisory.get("withdrawn").is_some() {
            continue;
        }
        let Some(id) = advisory.get("id").and_then(Value::as_str) else {
            continue;
        };
        let affected = advisory.get("affected").and_then(Value::as_array);
        for entry in affected.into_iter().flatten() {
            let digests = entry
                .pointer("/ecosystem_specific/digests")
                .and_then(Value::as_array);
            for digest in digests.into_iter().flatten().filter_map(Value::as_str) {
                by_digest.entry(digest).or_default().push(id.to_owned());
            }
        }
    }
    installed
        .into_iter()
        .filter_map(|(skill, digest)| {
            let mut ids = by_digest.get(digest)?.clone();
            ids.sort();
            Some(Revocation {
                skill: skill.to_owned(),
                digest: digest.to_owned(),
                advisories: ids,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::revoked;
    use serde_json::json;

    fn feed() -> serde_json::Value {
        json!({"schema_version": 1, "advisories": [
            {"id": "AGT-ADV-2026-002", "modified": "2026-09-01T00:00:00Z",
             "affected": [{"package": {"ecosystem": "AgtMLS", "name": "a"},
                           "ecosystem_specific": {"digests": ["sha256:22"]}}]},
            {"id": "AGT-ADV-2026-001", "modified": "2026-09-01T00:00:00Z",
             "affected": [{"package": {"ecosystem": "AgtMLS", "name": "a"},
                           "ecosystem_specific": {"digests": ["sha256:22"]}}]},
            {"id": "AGT-ADV-2026-003", "modified": "2026-09-01T00:00:00Z",
             "withdrawn": "2026-09-02T00:00:00Z",
             "affected": [{"package": {"ecosystem": "AgtMLS", "name": "b"},
                           "ecosystem_specific": {"digests": ["sha256:33"]}}]}
        ]})
    }

    #[test]
    fn a_listed_digest_names_every_live_advisory_sorted() {
        let hits = revoked(&feed(), [("a", "sha256:22"), ("c", "sha256:99")]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].skill, "a");
        assert_eq!(hits[0].advisories, ["AGT-ADV-2026-001", "AGT-ADV-2026-002"]);
    }

    #[test]
    fn withdrawn_and_same_name_other_digest_revoke_nothing() {
        assert!(revoked(&feed(), [("b", "sha256:33"), ("a", "sha256:44")]).is_empty());
    }

    #[test]
    fn a_malformed_feed_revokes_nothing() {
        assert!(revoked(&json!({"advisories": "no"}), [("a", "sha256:22")]).is_empty());
    }
}
