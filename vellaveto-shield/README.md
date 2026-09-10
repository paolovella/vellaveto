# vellaveto-shield

Consumer AI shield — privacy-preserving protection for end-user MCP interactions.

## Overview

Protects individual users when interacting with AI agents and MCP tools:

- **Bidirectional PII sanitization** — strips detected personal data before it reaches tools, restores on return
- **Encrypted local audit** — every intercepted request and response written to
  an XChaCha20-Poly1305 store (Argon2id-derived key), with optional Merkle
  chaining. Enabled by `shield.audit_mode = "local"` plus a passphrase; set
  `audit.strict_mode` to refuse traffic that cannot be recorded. Separate from
  the plaintext decision log, which records policy verdicts rather than content
- **Session isolation** — per-session PII and context isolation
- **Credential vault** — encrypted credential storage with epoch-based rotation
- **Warrant canary** — verification of Ed25519-signed canaries (issuance not yet shipped)

## Scope and limits

- **PII patterns are US-centric and do not cover file paths or personal names.**
  The built-in set is email, US SSN, US phone, credit card (Luhn-checked), IPv4,
  JWT, and AWS key ID. Anything else — IBAN, NHS number, EU national IDs, non-US
  phone formats, filesystem paths — must be added as a `CustomPiiPattern`.
- **Warrant canary verification does not authenticate the signer.** The
  signature is checked against the key carried inside the canary, so a valid
  result means the canary is internally consistent, not that it came from a
  particular publisher. Pin the publisher key out of band. See
  [Security Model](../docs/SECURITY_MODEL.md#warrant-canary).
- **Traffic padding does not apply to this stdio proxy.**
  `shield.traffic_padding` offers padding to opted-in clients on the *HTTP*
  proxy; a stdio proxy has no network transport of its own, so the setting does
  nothing here. Even on HTTP it pads only clients that send
  `X-Vellaveto-Padding: v1`, and no shipped client does yet. Privacy header
  stripping (`shield.strip_privacy_headers`) is real and applies to the HTTP
  proxy.
- **Platform support:** Linux and macOS are built and shipped; CI tests on
  Linux. Windows is neither built nor tested — the child-process environment
  allowlist passes POSIX variable names only, and `0o600` permission hardening
  on the audit log is a no-op outside Unix.

## Quick start

```bash
# Pre-built binary, SHA-256 verified (no Rust toolchain needed):
curl -fsSL https://raw.githubusercontent.com/paolovella/vellaveto/main/scripts/install.sh \
  | VELLAVETO_BINARY=vellaveto-shield sh

# From source:
cargo install vellaveto-shield

vellaveto-shield --passphrase-env SHIELD_KEY -- ./your-mcp-server
```

## License

MPL-2.0 (crate source). The compiled binary links `vellaveto-mcp` (BUSL-1.1), but the BSL Additional Use Grant permits Consumer Shield deployments on end-user devices without a commercial license.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
