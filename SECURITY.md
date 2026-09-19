<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Security Policy

## Reporting

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/sebastienrousseau/agtmls-core/security/advisories/new).
Do not open a public issue.

**Acknowledgement within 48 hours. Initial assessment within 7 days.** If you
do not hear back in that window, escalate to
<sebastian.rousseau@gmail.com>.

## Scope

This project analyses untrusted input — skill content authored by third
parties — so the following are in scope and treated as vulnerabilities, not
feature requests:

- **An evasion of any `AGT-*` rule.** A payload that a rule should catch and
  does not is a security bug. Include the payload; it becomes a corpus case.
- **A parser crash, hang or unbounded allocation** on hostile input.
- **Path traversal** during install, import or analysis, including via
  symlinks or archive entries.
- **A false attestation**: any path by which unverified content acquires
  metadata claiming it was checked.

Out of scope: false positives (open a normal issue), and findings that require
an attacker to already control the machine running the tool.

## Disclosure

Coordinated. A fix ships with a corpus case that fails without it, so the same
evasion cannot return unnoticed.

## Verifying releases

Commits and tags are signed. Keys are in [`KEYS.asc`](KEYS.asc).

```bash
git config gpg.ssh.allowedSignersFile KEYS.asc
git verify-commit HEAD
```
