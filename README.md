# AMNOS Browser — signed ruleset distribution

Public static distribution of digitally signed AMNOS Browser protection rulesets. **No signing keys, credentials, user data or browser history are stored here.**

## Release state: QA only

This repository currently contains **only a synthetic `.invalid` QA fixture** signed by the owner-controlled, non-exportable Google Cloud HSM P-256 key. The QA material lives under `qa/20261121-hsm-synthetic-v1/` and **must not be advertised or activated as real content protection**.

The production URL `/browser-rulesets/latest.manifest.json` is deliberately **absent** pending dataset licensing, public HTTPS transport verification, independent key-trust approval, and native device QA.

Expected static host prefix: `https://media.amnos.se/browser-rulesets/` (existing AMNOS-controlled Hostinger static subdomain). The marketing website `amnos.se` and its separate deployment remain unchanged.

## Immutable publishing contract

1. Sign the exact canonical manifest signing message using the authorized HSM signer account. Store no private keys or long-lived service-account credentials in Git.
2. Independently review provenance, licenses, attribution, false positives, bounded payload SHA-256 and approved public-key fingerprint.
3. Publish each new `releases/<positive-integer>/ruleset.json` **before** replacing `latest.manifest.json`; do not overwrite numbered releases. The append-only release history is enforced operationally and by source review.
4. The client must reject redirects, TLS failures, compressed or altered payloads, invalid signatures, stale versions and rollback attempts.
5. An uncached current manifest and identity-encoded immutable payloads must be verified by real anonymous HTTPS probes. Never assume server settings alone enforce this.
6. Keep `latest.manifest.json` absent until the first production candidate is signed, legally reviewed, and passes all release checks.

Public HSM SPKI SHA-256 candidate (owner verification required before client trust): `06cdbb0744db68bb9b9763739a8db9b8c7ed086d9f61aa2653b2395a7e29c95a`.

For source and release engineering, see [AMNOS Browser Issue #58](https://github.com/AMNOS-Industries/Amnos-Browser/issues/58).

ΛMNOS
Made with purpose.
