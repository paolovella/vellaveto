# vellaveto-canary

Warrant canary creation and cryptographic verification.

## Overview

Ed25519-signed warrant canaries:

- `create_canary()` — generate a signed canary with expiration
- `verify_canary()` — check signature consistency, expiration, and tampering

`vellaveto-shield` calls `verify_canary()` when a canary is supplied.

## What a canary does and does not establish

A warrant canary is a signed statement asserting that no covert access or data
request has been received. Its signal is the **absence** of a renewal, not the
presence of a signature. Three limits apply to this implementation:

- **`verify_canary()` does not authenticate the signer.** The signature is
  verified against the verifying key carried *inside the canary*, so
  `signature_valid: true` means the canary is internally consistent — nothing
  more. Anyone can generate a keypair and sign an arbitrary statement and get a
  valid result. Callers must compare `canary.verifying_key` against a publisher
  key obtained out of band; this crate does not do it for you.
- **The dates are self-asserted.** `signed_date` comes from the signer's own
  clock at day granularity. There is no RFC 3161 timestamp authority and no
  external anchor, so a canary can be back- or forward-dated. To bound the
  signing time, the statement itself should quote a recent public unpredictable
  value — a news headline or a recent Bitcoin block hash — which proves the
  canary was signed no earlier than that value existed.
- **A cadence must be published** alongside the canary, or a reader cannot tell
  a missed renewal from a slow one.

`create_canary()` currently has no caller in this repository: there is no CLI,
route, or publication workflow. See DOC-CRED-4 in
[docs/AUDIT_LOG.md](../docs/AUDIT_LOG.md).

## Usage

```toml
[dependencies]
vellaveto-canary = "6"
```

```rust
use vellaveto_canary::{create_canary, verify_canary};
```

## License

Apache-2.0 — see [LICENSE-APACHE-2.0](../LICENSE-APACHE-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
