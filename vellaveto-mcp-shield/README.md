# vellaveto-mcp-shield

Consumer shield logic for the [Vellaveto](https://vellaveto.online) MCP security gateway.

## Overview

Privacy-preserving protection for end-user AI interactions:

- **QuerySanitizer** — bidirectional PII sanitization with reversible placeholders.
  Wraps `vellaveto_audit::PiiScanner`, so coverage is that scanner's seven
  built-in patterns (email, US SSN, US phone, credit card, IPv4, JWT, AWS key
  ID) plus any `CustomPiiPattern` supplied — **file paths and personal names are
  not detected**. Placeholders are `[PII_{CAT}_{TOKEN}]` with a random 16-hex
  token, not a sequence, so they cannot be guessed and probed as a
  desanitization oracle.
- **SessionIsolator** — per-session PII isolation with bounded history
- **EncryptedAuditStore** — XChaCha20-Poly1305 encrypted local audit with Argon2id KDF
- **LocalAuditManager** — encrypted audit entries with Merkle proof generation
- **CredentialVault** — encrypted credential storage with epoch expiration
- **SessionUnlinker** — credential rotation for session unlinkability
- **StylometricNormalizer** — fingerprint resistance (whitespace, punctuation, emoji normalization)

## Usage

```toml
[dependencies]
vellaveto-mcp-shield = "6"
```

## License

MPL-2.0 — see [LICENSE-MPL-2.0](../LICENSE-MPL-2.0) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
