<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
the AgtMLS pre-1.0 policy: increments of exactly `0.0.1` on the `0.0.x` line.

## Unreleased

### Changed

- Claims conformance level L5 (Trust) in `conformance.json` and
  `CONFORMANCE_LEVEL`. The release gate now computes the level from the
  runner's report instead of comparing against a literal `L4`, which
  would have refused a correct higher claim and accepted a stale one.

### Fixed

- `AGT-CAP-001` read `allowed-tools` split on commas only, so the Agent
  Skills spelling `allowed-tools: "Read Grep Bash"` was one tool that
  granted nothing, and `Bash(git log:*)` matched no tool. Tools now split
  on whitespace and commas with a specifier kept with its tool, and a
  specifier still grants its tool's capability (agtmls-spec 10.5), as in
  agtmls.

### Changed

- The tool-to-capability table is read from `AGT-CAP-001`'s
  `[tool_capabilities]` in the rule data instead of a copy kept here; a
  rule set whose `AGT-CAP-001` lacks it does not load. `audit_skill` now
  takes the `RuleSet`.

### Added

- Normalised matching strips every code point `AGT-STEG-001` declares
  and applies NFKC before collapsing whitespace (agtmls-spec 4.3), as
  agtmls already does: a keyword split by a zero-width space or a tag
  character, or spelt in fullwidth letters, is matched, on its source
  line. `RuleSet::fold` does both and borrows ASCII unchanged. New
  dependency: `unicode-normalization` (MIT OR Apache-2.0).
- Per-skill attestations (agtmls-spec chapter 10): `attestations` renders
  the manifest and capabilities in-toto statements canonically, and
  `agtmls-rs attest <manifest|capabilities> <dir> --name --rules
  [--digest]` prints one. `cargo test` rebuilds every attestation vector
  from its inputs and compares it byte for byte.
- Index signatures and the advisory feed (agtmls-spec chapters 9 and 11).
  `verify --registry <dir> --signatures` requires `index.json` to carry an
  `SSHSIG` under `agtmls-index@v1` that verifies against the registry's
  `ALLOWED_SIGNERS` (or `--allowed-signers`); a signed `advisories.json`
  in the registry is consulted on every verify, and an installed digest a
  live advisory lists exits `6` naming it. An unverified feed is never
  read. Exit codes `4` unsigned, `5` bad signature, `6` revoked, in the
  spec's precedence `5`, `3`, `6`, `4`. `signatures` and `advisories`
  modules; `signature` and `advisories` subcommands for the conformance
  runner. Every signature and advisory vector is replayed by `cargo test`.
- `*.json` files are escape-decoded before normalised matching (agtmls-spec
  4.3): `decode_json_escapes`, with escaped whitespace as a space so line
  numbers survive and surrogates combined or replaced with U+FFFD.
- Pattern rules run only on files their `applies_to` selectors match
  (agtmls-spec 4.11: `*`, `*.<ext>`, `executable` for `#!`), and any file
  beginning with `#!` is audited whatever its name or mode.
- Emoji context for `AGT-STEG-001` (agtmls-spec 4.10): a variation selector
  directly after an emoji base, and a well-formed subdivision flag, are
  `AGT-STEG-002` at LOW rather than CRITICAL. The selector is reported only
  with `audit --pedantic` (`Analyzer::pedantic`); the flag always. The line
  is the rule's `emoji_context` data; without it the behaviour is unchanged.
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
