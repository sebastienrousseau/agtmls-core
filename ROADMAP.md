<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Roadmap

## Now

L5 (Trust), verified by the conformance runner rather than claimed:
digest vectors, the full security corpus including evasions, lockfile
verification agreeing with the Python implementation on a tampered install,
and index signatures, advisories and attestations (agtmls-spec chapters 9
to 11).

## Next

- **Publish to crates.io.** The workflow exists and uses Trusted Publishing;
  it needs a one-time registration. Until then `agtmls-wasm`, `agtmls-mcp`
  and `agtmls-lsp` pin this crate by git revision.
- **Fuzz every parser.** `cargo-fuzz` targets for frontmatter, metadata,
  index and rule TOML, seeded from the corpus. This crate's entire job is
  parsing hostile input and it has no fuzzing.
- **A structural rule for base64 and entropy.** The analyzer catches what it
  can read; encoded payloads it cannot.

## Not planned

- **Installing skills.** That stays with the Python implementation. This
  crate verifies an install; the lockfile is the boundary between them.
