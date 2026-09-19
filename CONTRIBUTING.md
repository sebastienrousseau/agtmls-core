<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Contributing to agtmls-core

## The rule that matters

**A change to analysis behaviour lands with a corpus case that fails without
it.** Same pull request, not a follow-up. The corpus is how two
implementations in two languages stay equivalent; a change that is not in the
corpus is a change the other implementation does not know about.

## Adding an analysis rule

1. Add `rules/AGT-<CLASS>-<NNN>.toml` in `agtmls-spec`. Never hard-code a
   pattern in an implementation.
2. Declare at least one `[[true_positive]]`, and either a
   `[[false_positive]]` or an explicit `false_positive_policy` with a
   comment saying why none is acceptable. Both are executed at load time.
3. Express case-insensitivity inline as `(?i)`. A host-language compile flag
   does not survive export and the implementations will silently disagree.
4. Store the pattern in a TOML **literal** string (`'''…'''`). Escaping it as
   a basic string doubles every backslash and the pattern matches nothing.
5. Add a case to `corpus/security/corpus.json`, including an **evasion
   variant**. One canonical string proves the regex compiles and nothing else.
6. Run `conformance/run.py --python … --rust …`. Both must pass and agree.

## Before opening a pull request

```bash
conformance/validate-corpus.py                      # corpus is well-formed
conformance/run.py --python … --rust …              # implementations agree
```

Rust repositories additionally:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Commits

Conventional commits. Commits and tags must be signed; CI verifies this
against `KEYS.asc`.

## What gets rejected

- A rule with no corpus case.
- A corpus case weakened to make a failing implementation pass. Rules are data
  precisely so that "make the test pass" and "fix the rule" are the same
  action.
- A conformance suite that skips when its inputs are missing. It must fail:
  skipping reports green while proving nothing.
