<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# ADR 0002 — The WebAssembly bindings live in their own repository

**Status:** accepted (supersedes the arrangement introduced in `feat/v0.0.2`)
**Date:** 2026-09-19

## Context

The WASM bindings were first added as `crates/agtmls-wasm` in this workspace.
The reasoning was that a wasm-bindgen wrapper is a *build target* rather than
a product: splitting it forces a coordinated two-repo release for every core
change, and the differential conformance CI already lives here.

That reasoning is correct about the binding and wrong about everything
attached to it.

## Decision

`agtmls-wasm` is its own repository:
<https://github.com/sebastienrousseau/agtmls-wasm>.

It depends on this crate by **pinned revision** until this crate is published
to crates.io, at which point it pins a version. A branch dependency would not
be reproducible, and reproducibility is the claim the whole ecosystem makes.

## Consequences

**Why the split is right.** The npm package, its TypeScript surface, the
500 KB size budget, the browser playground and the publishing identity all
have an audience and a cadence that have nothing to do with this crate.
Carrying them here means every core patch release drags an npm publish behind
it, and the size budget — which is a real constraint that will shape the
binding's API — becomes a gate on unrelated work.

The release surfaces differ too: this workspace publishes to crates.io via a
crates.io trusted publisher; `agtmls-wasm` publishes to npmjs via an npm
trusted publisher. One repository would need both identities and an
environment for each, and a tag would mean two different things.

**What it costs.** A core change that alters the analyzer's behaviour now
needs a second commit in `agtmls-wasm` to re-pin. That is real friction, and
it is the friction that makes the pinned revision visible in a diff rather
than implied by a branch name.

**What keeps them honest.** Both replay the `agtmls-spec` corpus. The
`agtmls-wasm` smoke script asserts digest parity against the same vector this
crate's conformance suite uses, so a divergence fails a build rather than
shipping.

## Alternatives rejected

**Keep it here and publish to npm from this workspace.** Simplest, and what
was originally done. Rejected because a tag would trigger both a crates.io and
an npm release, so a patch to the CLI would republish the browser package for
no reason, and the two would share a version number that means different
things to their users.

**A monorepo for the whole ecosystem.** Consistent, and would make the
differential conformance trivial. Rejected for the reason the ecosystem is
split at all: the registry's *content* changes weekly while the *spec* should
change quarterly and loudly, and one repository couples those cadences.
