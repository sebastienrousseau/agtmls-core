<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# ADR 0001 — Rules are data, not code

**Status:** accepted
**Date:** 2026-09-19

## Context

The AgtMLS analyzer will run behind four surfaces — a CLI, a language server,
an MCP server and a WASM module — across at least two implementation
languages. The obvious approach is for each implementation to carry its own
compiled pattern table.

That approach has a specific, predictable failure: the tables drift. Not
visibly, and not all at once. One implementation gains a rule, or tightens a
pattern, or compiles with a flag the other does not, and from then on a
payload that one blocks is one the other calls clean. Because both still pass
their own test suites, nothing reports a problem.

For a security tool this is worse than having one implementation, because the
divergence is invisible precisely where the guarantee is claimed.

## Decision

Rules live as TOML files in `agtmls-spec/rules/`. Every implementation loads
that same directory. No implementation hard-codes a pattern that exists there.

Each rule carries its own executable evidence — `[[true_positive]]` and
`[[false_positive]]` entries — which are run when the rule set loads. A rule
that does not match its own true positive, or that matches its own false
positive, causes the load to fail.

Portability constraints are part of the rule format, not convention:

- case-insensitivity is inline `(?i)`, never a host compile flag;
- patterns live in TOML *literal* strings so backslashes stay literal;
- no backreferences or lookaround, since Rust's `regex` has no backtracking.

## Consequences

**Good.** Adding a rule is adding a file and a corpus case. The two
implementations cannot disagree about a pattern, because there is only one.
The rule set can be enumerated from data without reading anyone's source,
which is what makes SARIF export and a documentation site derivable rather
than hand-maintained.

**Costly.** Rule loading is now fallible at runtime, so every entry point must
handle a `LoadError`. The implementations depend on a third repository being
present, which is why the conformance suite fails rather than skips when it is
absent. Structural rules — invisible code points, capability escalation,
policy honesty — cannot be expressed as patterns and are still implemented
twice; they are declared in `rules/` with `kind = "structural"` so the rule
set stays enumerable, but their *behaviour* is kept honest only by the corpus.

**Validated immediately.** Within the first load of the rule set, the
self-tests caught two defects that had shipped in the Python implementation:
a pattern that matched prose warning against `curl | bash`, and an entire rule
table exported with doubled backslashes so that nothing matched. The
differential run caught a third, where case-insensitivity was a compile flag
and silently did not cross the language boundary.

## Alternatives rejected

**Generate code from the rule data at build time.** Faster, and keeps the
patterns compiled in. Rejected because the generated artefact is what runs,
so a stale generation step reintroduces exactly the drift this decision
exists to prevent — and a stale artefact is harder to notice than a missing
file.

**Keep one implementation.** Simplest, and genuinely tempting. Rejected
because WASM and a responsive language server both need a compiled engine,
and because the Python implementation's stdlib-only dependency profile is a
real security property worth keeping for the CLI.
