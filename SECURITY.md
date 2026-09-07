# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately via GitHub's built-in vulnerability reporting: **[Report a vulnerability](https://github.com/radar-hooves/signet/security/advisories/new)**

Include in your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- The signet version(s) affected
- Any suggested mitigations you have identified

You will receive an acknowledgement within 5 business days. Fixes are coordinated privately and a public advisory is published alongside the patched release.

## Supported versions

| Version        | Supported                          |
| -------------- | ---------------------------------- |
| Latest release | Yes                                |
| Older releases | No — upgrade to the latest release |

signet uses calendar versioning (`YYYY.M.x`). Only the most recent release receives security fixes; the recommendation is always to upgrade.

## Scope

signet's security model rests on one guarantee: the P-256 signing key is generated in, and never leaves, the secure hardware (Apple Secure Enclave, TPM 2.0, or a YubiKey/PIV token). Vulnerabilities in scope include anything that weakens this guarantee — key exfiltration, bearer-cache exposure, replay attacks, or bypass of the hardware attestation contract. Supply-chain issues (dependency tampering, release artifact integrity) are also in scope.

Out of scope: the broker that verifies signatures and mints bearers (signet carries no broker code). Broker-side issues should be reported to the broker's maintainers.
