<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
the AgtMLS pre-1.0 policy: increments of exactly `0.0.1` on the `0.0.x` line.

## Unreleased

### Added

- `digest`: the content-addressed skill identity defined by
  `agtmls-spec/spec/03-integrity.md`. Verified against all 14 shared vectors
  and against all 31 skills in the `agtmls` registry, which digest identically
  under both implementations.
- `rules`: a data-driven rule set loaded from `agtmls-spec/rules/*.toml`, with
  every declared example executed at load time.
- `analyzer`: static analysis over normalised content, so a payload split
  across a newline cannot evade a rule. Findings carry stable rule IDs.
- `agtmls-cli`: the `agtmls-rs` binary — `digest`, `manifest`, `audit`.
- `skill`: the structural rules — `AGT-STEG-001` (invisible code points),
  `AGT-CAP-001` (capability escalation) and `AGT-POLICY-001..005` (policy
  honesty). These reason about the skill rather than about any one document,
  so they cannot be expressed as patterns.
- `lockfile`: reads and verifies `.agtmls/manifest.json`, so an install
  created by the Python implementation can be verified by this one. Reports
  rather than repairs, and never deletes a skill it has no record of
  installing.
- `agtmls-rs verify <target> --agent <agent>`, with exit `3` reserved for
  `INTEGRITY_FAILURE` so a calling script can distinguish "the tool broke"
  from "your install has been altered".
- Conformance tests that fail, rather than skip, when the spec is absent, and
  that exercise **every** corpus category with no exclusions.

### Conformance

Claims **L4 (Registry)**, verified rather than asserted:

- all 14 digest vectors, and all 31 skills in the `agtmls` registry, digesting
  identically under both implementations;
- all 16 security corpus cases producing an identical rule set in both;
- all 31 registry skills producing an identical rule set in both;
- lockfile verification agreeing on a deliberately tampered install — the same
  skills flagged, the same statuses, the same exit codes.

The claim was deliberately held at L2 until the structural rules landed, and
at L3 until the lockfile did. A conformance claim nobody checked is the defect
the specification exists to prevent.



### Fixed

Four defects found by building the second implementation and diffing it
against the first. Three also affected the Python implementation, and none was
visible from inside either one:

- `AGT-EXEC-001` matched prose warning against `curl | bash`. The pattern now
  requires an actual fetch target.
- Pattern case-insensitivity was a host-language compile flag and did not
  survive export to the shared rule data. It is now an inline `(?i)`.
- Rule patterns were escaped as TOML *basic* strings, so every backslash was
  doubled and no pattern matched anything.
- The `agtmls-rs` binary ran only the per-file pattern rules, never the
  structural ones, so it was silently weaker than the library it is built on.
  The library's own tests passed throughout; only the cross-implementation
  differential caught it.

`AGT-CAP-001` could not fire on a real skill. The Agent Skills spec writes
`allowed-tools` space-separated (`allowed-tools: "Read Glob Bash"`), and
`frontmatter_tools` split on commas only, so that value came back as one
tool named `Read Glob Bash` that granted nothing. It now tokenises exactly
as the Python reference does: whitespace and commas separate tools, quotes
and `[...]` flow-list brackets are ignored, and a parenthesised specifier
such as `Bash(git log:*)` stays part of its token and still counts as the
tool before the `(`.
