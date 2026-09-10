# vellaveto-mcp

MCP protocol security layer for the [Vellaveto](https://vellaveto.online) gateway.

## Overview

Handles MCP-specific security concerns between agents and their tools:

- **DLP inspection** - 5-layer decode pipeline with Aho-Corasick pattern matching
- **Injection detection** - NFKC normalization, ROT13/base64/leetspeak decode, Policy Puppetry defense
- **Tool registry** - topology-aware tool verification with Levenshtein suggestions
- **Semantic guardrails** - output schema validation and behavioral constraints
- **Multimodal inspection** - image and document content scanning
- **A2A hardening** - Agent Card signature verification and ingestion (`a2a` feature; enforced by the
  A2A listener in `vellaveto-http-proxy`, not by the stdio relay), DPoP token binding
- **MCP 2025-11-25 / 2026-07-28 adapters** - version-gated wire
  normalization into canonical policy and audit requests
- **Typed `_meta` ingestion** - bounded trace context parsing, protocol-version
  agreement checks, and quarantine for unknown metadata keys

## Usage

```toml
[dependencies]
vellaveto-mcp = "6"
```

## Wire Normalization

`vellaveto-mcp::wire` is the adapter boundary between MCP JSON-RPC wire
messages and Vellaveto's transport-independent policy model. Supported
versions are parsed as ordered `McpProtocolVersion` values, with `2026-07-28`
preferred and `2025-11-25` retained for the migration window.

The adapter normalizes inbound messages into `CanonicalRequest` values with:

- method and optional name
- message kind: request, notification, or response
- validated protocol version
- bounded typed `_meta`
- sanitized trace correlation
- normalized JSON arguments

Malformed `_meta`, conflicting top-level and `params._meta`, protocol-version
mismatch, malformed `traceparent`, oversized metadata, and JSON-RPC batch
messages return an adapter denial instead of passing through silently.

## License

BUSL-1.1 - see [LICENSE-BSL-1.1](../LICENSE-BSL-1.1) and [LICENSING.md](../LICENSING.md) in the repository root.

Part of the [Vellaveto](https://github.com/paolovella/vellaveto) project.
