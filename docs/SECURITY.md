# Vellaveto Security Hardening Guide

This guide covers security best practices and hardening configurations for production Vellaveto deployments.

## Table of Contents

- [Security Principles](#security-principles)
- [Authentication & Authorization](#authentication--authorization)
  - [API Key Authentication](#api-key-authentication)
  - [OAuth 2.1 / JWT](#oauth-21--jwt)
  - [RBAC Configuration](#rbac-configuration)
- [Network Security](#network-security)
  - [TLS Configuration](#tls-configuration)
  - [Firewall Rules](#firewall-rules)
  - [DNS Rebinding Protection](#dns-rebinding-protection)
- [Policy Hardening](#policy-hardening)
  - [Strict Mode](#strict-mode)
  - [Credential Protection](#credential-protection)
  - [Network Allowlisting](#network-allowlisting)
  - [Command Restrictions](#command-restrictions)
- [Detection & Prevention](#detection--prevention)
  - [Injection Scanning](#injection-scanning)
  - [DLP Configuration](#dlp-configuration)
  - [Rug-Pull Detection](#rug-pull-detection)
  - [MCP Protocol Guardrails](#mcp-protocol-guardrails)
  - [Behavioral Anomaly Detection](#behavioral-anomaly-detection)
- [Audit & Compliance](#audit--compliance)
  - [Audit Log Configuration](#audit-log-configuration)
  - [PII Redaction](#pii-redaction)
  - [Log Integrity](#log-integrity)
- [Runtime Security](#runtime-security)
  - [Container Hardening](#container-hardening)
  - [Systemd Hardening](#systemd-hardening)
  - [Resource Limits](#resource-limits)
- [Supply Chain Security](#supply-chain-security)
  - [Binary Verification](#binary-verification)
  - [MCP Server Pinning](#mcp-server-pinning)
- [Security Checklist](#security-checklist)

---

## Committer Requirements

All individuals with commit access to the Vellaveto repository must:

1. **Enable two-factor authentication (2FA)** on their GitHub account using
   FIDO2/WebAuthn security keys or TOTP authenticator apps.
2. **Sign commits** with GPG or SSH keys when possible.
3. **Never share credentials** or access tokens.

GitHub's organization settings enforce 2FA for all members.

---

## Security Principles

Vellaveto follows these security principles:

1. **Fail-Closed**: Errors, missing policies, and unresolved context produce `Deny`, never `Allow`.
2. **Defense in Depth**: Multiple layers of security controls.
3. **Least Privilege**: Minimal permissions for the Vellaveto process.
4. **Observability**: All decisions logged, all failures diagnosed.
5. **Zero Trust**: Validate every request, authenticate every caller.
6. **Semantic Containment**: Untrusted semantic content carries trust tier, taint, lineage, and risk metadata; privileged flows require containment, approval, or quarantine when that metadata crosses trust or meaning boundaries.

---

## Authentication & Authorization

### API Key Authentication

For simple deployments, use API key authentication for admin endpoints.

```bash
# Generate a secure API key
export VELLAVETO_API_KEY=$(openssl rand -hex 32)

# Store securely
echo "VELLAVETO_API_KEY=$VELLAVETO_API_KEY" >> /etc/vellaveto/env
chmod 600 /etc/vellaveto/env
```

Configure in systemd:

```ini
[Service]
EnvironmentFile=/etc/vellaveto/env
```

Test authentication:

```bash
# Without key - should fail
curl localhost:3000/api/policies
# Response: 401 Unauthorized

# With key - should succeed
curl -H "Authorization: Bearer $VELLAVETO_API_KEY" localhost:3000/api/policies
```

### OAuth 2.1 / JWT

For enterprise deployments, use OAuth 2.1 with JWT tokens.

```toml
# config.toml

[auth]
enabled = true
provider = "oauth2"

[auth.oauth2]
issuer = "https://auth.example.com"
audience = "vellaveto-api"
jwks_url = "https://auth.example.com/.well-known/jwks.json"

# Required scopes for different operations
[auth.oauth2.scopes]
evaluate = ["vellaveto:evaluate"]
admin = ["vellaveto:admin"]
read = ["vellaveto:read"]
```

JWT token requirements:
- **Algorithm**: RS256 or ES256 (never HS256 in production)
- **Expiry**: Short-lived tokens (< 1 hour)
- **Audience**: Must match configured audience
- **Issuer**: Must match configured issuer

### RBAC Configuration

Define roles for fine-grained access control:

```toml
# config.toml

[rbac]
enabled = true

[[rbac.roles]]
name = "evaluator"
permissions = ["evaluate"]

[[rbac.roles]]
name = "operator"
permissions = ["evaluate", "read_audit", "manage_approvals"]

[[rbac.roles]]
name = "admin"
permissions = ["evaluate", "read_audit", "manage_approvals", "manage_policies", "manage_config"]

# Map JWT claims to roles
[rbac.claim_mapping]
claim = "roles"  # JWT claim containing roles
mapping = { "vellaveto-evaluator" = "evaluator", "vellaveto-operator" = "operator", "vellaveto-admin" = "admin" }
```

---

## Network Security

### TLS Configuration

Always terminate TLS in front of Vellaveto. Use a reverse proxy with strong TLS settings.

#### Vellaveto TLS policy controls

When Vellaveto terminates TLS directly, configure TLS 1.3 and an explicit key exchange policy:

```toml
[tls]
mode = "tls"
min_version = "1.3"
kex_policy = "hybrid_preferred"
```

`kex_policy` values:
- `classical_only`
- `hybrid_preferred`
- `hybrid_required_when_supported`

For staged rollout and rollback guidance, see `./quantum-migration.md`.

#### Nginx Configuration

```nginx
# /etc/nginx/conf.d/vellaveto.conf

server {
    listen 443 ssl http2;
    server_name vellaveto.example.com;

    # TLS 1.2 and 1.3 only
    ssl_protocols TLSv1.2 TLSv1.3;

    # Strong cipher suites
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Rate limiting
        limit_req zone=vellaveto burst=50 nodelay;
    }
}

# Rate limit zone
limit_req_zone $binary_remote_addr zone=vellaveto:10m rate=100r/s;
```

### Firewall Rules

Restrict network access to Vellaveto:

```bash
# Allow only internal network to access Vellaveto
sudo ufw allow from 10.0.0.0/8 to any port 3000

# Allow only specific IPs for admin endpoints
sudo iptables -A INPUT -p tcp --dport 3000 -s 10.0.0.10 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 3000 -s 10.0.0.11 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 3000 -j DROP
```

For Kubernetes:

```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vellaveto-network-policy
spec:
  podSelector:
    matchLabels:
      app: vellaveto
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ai-agents
        - podSelector:
            matchLabels:
              role: ai-agent
      ports:
        - protocol: TCP
          port: 3000
```

### DNS Rebinding Protection

Prevent DNS rebinding attacks where a public domain resolves to private IPs:

```toml
# config.toml

[[policies]]
name = "DNS rebinding protection"
tool_pattern = "http_request"
function_pattern = "*"
policy_type = "Allow"
priority = 240

[policies.network_rules.ip_rules]
# Block all private IP ranges
block_private = true

# Also block carrier-grade NAT
blocked_cidrs = [
  "100.64.0.0/10",   # CGN
  "169.254.0.0/16",  # Link-local
  "192.0.0.0/24",    # IETF protocol assignments
]

# Allow specific internal services if needed
allowed_cidrs = [
  "10.0.1.100/32",   # Internal API gateway
]
```

---

## Policy Hardening

### Strict Mode

Enable strict mode to deny unknown tools by default:

```bash
# Environment variable
export VELLAVETO_STRICT_MODE=true

# Or in config.toml
[vellaveto]
strict_mode = true
```

In strict mode:
- Tools not matched by any policy are denied
- New tools require explicit policy before use
- Provides defense against tool injection

### Credential Protection

Block access to credential files and secrets:

```toml
# config.toml

[[policies]]
name = "Block credential file access"
tool_pattern = "*"
function_pattern = "*"
priority = 300
id = "*:*:credential-block"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  # SSH keys
  { param = "*", op = "glob", pattern = "/home/*/.ssh/**", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/root/.ssh/**", on_match = "deny", on_missing = "skip" },

  # Cloud credentials
  { param = "*", op = "glob", pattern = "/home/*/.aws/**", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.gcp/**", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.azure/**", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.kube/config", on_match = "deny", on_missing = "skip" },

  # Environment files
  { param = "*", op = "glob", pattern = "**/.env*", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/credentials*", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/secrets*", on_match = "deny", on_missing = "skip" },

  # System files
  { param = "*", op = "glob", pattern = "/etc/shadow", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/etc/passwd", on_match = "deny", on_missing = "skip" },
]
```

### Network Allowlisting

Restrict outbound network access to approved domains:

```toml
# config.toml

[[policies]]
name = "Block known exfiltration domains"
tool_pattern = "*"
function_pattern = "*"
priority = 280

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  # Tunneling services
  { param = "*", op = "domain_match", pattern = "*.ngrok.io", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.ngrok-free.app", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.serveo.net", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.localtunnel.me", on_match = "deny", on_missing = "skip" },

  # Pastebins
  { param = "*", op = "domain_match", pattern = "*.pastebin.com", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.hastebin.com", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.ghostbin.com", on_match = "deny", on_missing = "skip" },

  # File sharing
  { param = "*", op = "domain_match", pattern = "*.transfer.sh", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.file.io", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.wetransfer.com", on_match = "deny", on_missing = "skip" },

  # Request catchers
  { param = "*", op = "domain_match", pattern = "*.requestbin.com", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.pipedream.net", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.webhook.site", on_match = "deny", on_missing = "skip" },
  { param = "*", op = "domain_match", pattern = "*.burpcollaborator.net", on_match = "deny", on_missing = "skip" },
]

[[policies]]
name = "HTTP domain allowlist"
tool_pattern = "http_request"
function_pattern = "*"
priority = 250

[policies.policy_type.Conditional.conditions]
on_no_match = "deny"  # Deny if not in allowlist
parameter_constraints = [
  { param = "url", op = "domain_in", patterns = [
    "api.github.com",
    "*.googleapis.com",
    "api.openai.com",
    "api.anthropic.com",
    "registry.npmjs.org",
    "pypi.org",
    "*.internal.example.com",
  ], on_match = "allow" },
]
```

### Command Restrictions

Require approval for dangerous commands:

```toml
# config.toml

[[policies]]
name = "Dangerous commands require approval"
tool_pattern = "bash"
function_pattern = "execute"
priority = 200

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  # Destructive file operations
  { param = "command", op = "regex", pattern = "(?i)(rm\\s+-rf|rm\\s+-r\\s+/|shred|wipe)", on_match = "require_approval" },

  # Disk operations
  { param = "command", op = "regex", pattern = "(?i)(dd\\s+if=|mkfs|fdisk|wipefs)", on_match = "require_approval" },

  # Network exfiltration
  { param = "command", op = "regex", pattern = "(?i)(curl.*\\|.*sh|wget.*\\|.*bash|nc\\s+-e)", on_match = "deny" },
]

[[policies]]
name = "Block privilege escalation"
tool_pattern = "bash"
function_pattern = "execute"
priority = 190

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "command", op = "regex", pattern = "(?i)(^sudo\\s|\\bsu\\s+-|\\bchmod\\s+[0-7]*s|\\bchown\\s+root)", on_match = "deny" },
  { param = "command", op = "regex", pattern = "(?i)(\\busermod\\s|\\bpasswd\\s|\\bvisudo)", on_match = "deny" },
]
```

---

## Detection & Prevention

### Injection Scanning

Enable and configure injection detection:

```toml
# config.toml

[injection]
enabled = true
block_on_injection = true  # Block detected injections

# Additional patterns to detect
extra_patterns = [
  "ignore previous instructions",
  "you are now",
  "new system prompt",
  "forget everything",
  "disregard all",
  "transfer funds",
  "send cryptocurrency",
  "execute malicious",
]

# Patterns to exclude (false positives)
disabled_patterns = []

# Unicode normalization (prevents homoglyph attacks)
normalize_unicode = true
```

### DLP Configuration

Enable Data Loss Prevention scanning:

```toml
# config.toml

[dlp]
enabled = true
block_on_finding = true  # Block requests/responses with sensitive data
scan_requests = true     # Scan outgoing data
scan_responses = true    # Scan incoming data

# Default patterns: credit cards, SSNs, API keys, etc.
# Add custom patterns:
[[dlp.custom_patterns]]
name = "employee_id"
pattern = "EMP-\\d{6}"
severity = "medium"

[[dlp.custom_patterns]]
name = "internal_api_key"
pattern = "sk-internal-[a-zA-Z0-9]{32}"
severity = "high"

# Decode layers (catches encoded secrets)
[dlp.decoding]
enabled = true
layers = ["base64", "url", "unicode"]
max_decode_depth = 5
```

### Rug-Pull Detection

Pin tool schemas to detect unauthorized changes:

```toml
# config.toml

[manifest]
enabled = true
enforcement = "Block"  # "Warn" or "Block"
require_signature = false

# Path to store manifest
manifest_path = "/etc/vellaveto/manifest.json"

# For signed manifests (optional)
# trusted_keys = ["hex-encoded-ed25519-public-key"]
```

On first run, Vellaveto captures tool schemas. On subsequent runs, any schema changes trigger alerts or blocks.

### MCP Protocol Guardrails

For HTTP and WebSocket MCP traffic, Vellaveto enforces protocol checks before
forwarding to the upstream server:

- Unknown MCP protocol versions are denied. HTTP requests must include
  `MCP-Protocol-Version` unless `require_protocol_version_header` is explicitly
  disabled.
- `streamable_http.protocol_version_floor` defaults to `2025-11-25`. Lower
  versions are not advertised or accepted at the default floor.
- `Mcp-Method` and `Mcp-Name` routing headers must agree with the JSON-RPC
  body on `2026-07-28` traffic.
- `Mcp-Param-*` headers are denied unless the suffix is operator-allowlisted
  and the current tool definition declared the same `x-mcp-header` binding.
- Upstream `requestState` values are sealed before the client sees them.
  Continuations are accepted once, in the same session, before expiry.
- Detached server-initiated requests on GET SSE are denied. WebSocket
  server-initiated requests are only forwarded while a client request is live
  on that connection.

Recommended baseline:

```toml
[streamable_http]
protocol_version_floor = "2025-11-25"
require_protocol_version_header = true
allowed_mcp_param_headers = []
```

### Behavioral Anomaly Detection

Detect unusual agent behavior:

```toml
# config.toml

[behavioral]
enabled = true

# EMA smoothing factor (0.0, 1.0] - lower = slower adaptation
alpha = 0.2

# Flag when current count >= threshold * baseline
threshold = 10.0

# Minimum sessions before alerting (cold start protection)
min_sessions = 5

# Memory limits
max_tools_per_agent = 500
max_agents = 10000
```

This detects anomalies like:
- Agent suddenly making 100x more file reads than normal
- Tool usage patterns changing dramatically
- Unusual tool combinations

---

## Audit & Compliance

### Audit Log Configuration

Configure comprehensive audit logging:

```toml
# config.toml

[audit]
enabled = true
path = "/var/lib/vellaveto/audit.log"

# Log every decision, not just denials
log_allows = true

# Include request/response bodies (with redaction)
log_bodies = true

# Hash chain for tamper detection
hash_chain = true

# Ed25519 checkpoints
checkpoint_interval = 1000  # entries
checkpoint_signature = true
```

### PII Redaction

Configure automatic PII redaction:

```toml
# config.toml

[audit]
# Redaction levels:
# - "Off": No redaction
# - "KeysOnly": Redact values for keys like "password", "token", "secret"
# - "KeysAndPatterns": Above + pattern matching (emails, SSNs, cards)
# - "High": Aggressive redaction including partial data masking
redaction_level = "KeysAndPatterns"

# Custom PII patterns
[[audit.custom_pii_patterns]]
name = "employee_id"
pattern = "EMP-\\d{6}"

[[audit.custom_pii_patterns]]
name = "customer_id"
pattern = "CUST-[A-Z]{2}\\d{8}"

# Keys to always redact (in addition to defaults)
sensitive_keys = [
  "api_key",
  "access_token",
  "refresh_token",
  "session_id",
  "credit_card",
  "ssn",
  "password",
  "secret",
]
```

### Log Integrity

Verify audit log integrity:

```bash
# Verify hash chain
vellaveto audit verify --path /var/lib/vellaveto/audit.log

# Verify with checkpoint signatures
vellaveto audit verify --path /var/lib/vellaveto/audit.log --verify-signatures

# Output:
# Verified 15,234 entries
# Hash chain: valid
# Checkpoints: 15 (all valid)
# Last verified entry: 2026-02-08T10:30:00Z
```

For compliance, export logs to SIEM:

```toml
# config.toml

[audit.export]
enabled = true

# Splunk
[audit.export.splunk]
enabled = true
hec_url = "https://splunk.example.com:8088/services/collector"
hec_token_env = "SPLUNK_HEC_TOKEN"  # Read from environment
source = "vellaveto"
sourcetype = "vellaveto:audit"

# Elasticsearch
[audit.export.elasticsearch]
enabled = true
url = "https://elastic.example.com:9200"
index = "vellaveto-audit"
api_key_env = "ELASTIC_API_KEY"

# Webhook (generic)
[audit.export.webhook]
enabled = true
url = "https://siem.example.com/ingest"
batch_size = 100
batch_interval_secs = 30
```

---

## Runtime Security

### Container Hardening

Use the included Dockerfile which follows security best practices:

```dockerfile
# Key security features in the Dockerfile:

# 1. Multi-stage build (minimal attack surface)
FROM rust:1.82-alpine AS builder
FROM alpine:3.21

# 2. Non-root user
RUN addgroup -S vellaveto && adduser -S vellaveto -G vellaveto
USER vellaveto

# 3. Read-only filesystem (where possible)
# 4. No shell in final image (use alpine for debugging only)
```

Runtime security options:

```bash
docker run -d \
  --name vellaveto \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,nodev \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=./seccomp.json \
  -p 3000:3000 \
  vellaveto:latest
```

For Kubernetes:

```yaml
# values.yaml

securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault

podSecurityContext:
  fsGroup: 1000
```

### Systemd Hardening

The provided systemd service includes comprehensive hardening:

```ini
# /etc/systemd/system/vellaveto.service

[Service]
# Run as dedicated user
User=vellaveto
Group=vellaveto

# Filesystem isolation
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/vellaveto /var/log/vellaveto

# Kernel protection
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true

# Capability restrictions
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=

# Namespace isolation
PrivateUsers=true
RestrictNamespaces=true

# System call filtering
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

# Network restrictions (if only localhost needed)
# IPAddressDeny=any
# IPAddressAllow=localhost

# Resource limits
MemoryMax=256M
CPUQuota=200%
TasksMax=100
```

### Resource Limits

Configure resource limits to prevent DoS:

```toml
# config.toml

[limits]
# Maximum request body size
max_body_size = "1MB"

# Maximum policy count
max_policies = 10000

# Maximum concurrent evaluations
max_concurrent_evaluations = 1000

# Request timeout
request_timeout_secs = 30
```

Rate limiting:

```toml
[rate_limit]
# Per-endpoint limits
evaluate_rps = 1000
evaluate_burst = 50

admin_rps = 20
admin_burst = 5

readonly_rps = 200
readonly_burst = 20

# Per-IP limits
per_ip_rps = 100
per_ip_burst = 20

# Per-principal limits (authenticated users)
per_principal_rps = 50
per_principal_burst = 10
```

---

## Supply Chain Security

### Binary Verification

Each release publishes one `tar.gz` per supported target plus a single
`checksums-sha256.txt` file. Verify before deployment:

```bash
# Pick the right target for your platform:
#   x86_64-unknown-linux-musl, aarch64-unknown-linux-musl,
#   x86_64-apple-darwin, aarch64-apple-darwin
TARGET=x86_64-unknown-linux-musl
VERSION=6.1.1
BASE=https://github.com/paolovella/vellaveto/releases/download/v${VERSION}

# Download the archive and the checksums file
curl -fsSLO "${BASE}/vellaveto-${VERSION}-${TARGET}.tar.gz"
curl -fsSLO "${BASE}/checksums-sha256.txt"

# Verify (passes only if the archive matches its line in checksums-sha256.txt)
sha256sum --ignore-missing -c checksums-sha256.txt
```

For the standard install path, `scripts/install.sh` performs this same
checksum verification automatically (see [`scripts/install.sh`](../scripts/install.sh)).

Binary GPG/sigstore signing is not yet implemented — track [#TBD](https://github.com/paolovella/vellaveto/issues)
for status. Maven Central artifacts (Java SDK) are GPG signed today.

For container images:

```bash
# Use image digest, not tag
docker pull ghcr.io/paolovella/vellaveto@sha256:abc123...

# Verify with cosign (if signed)
cosign verify ghcr.io/paolovella/vellaveto:latest
```

### MCP Server Pinning

Pin allowed MCP server binaries by SHA-256 hash:

```toml
# config.toml

[supply_chain]
enabled = true
validate_paths_on_load = true

# Allowed server binaries (path -> expected SHA-256)
[supply_chain.allowed_servers]
"/usr/local/bin/mcp-filesystem" = "a1b2c3d4e5f6..."
"/usr/local/bin/mcp-github" = "f6e5d4c3b2a1..."
"/opt/mcp/custom-server" = "1234567890ab..."
```

Generate hashes:

```bash
sha256sum /usr/local/bin/mcp-*
```

---

## Verified Hardening Backlog (2026-02-13)

This section captures externally researched controls and current implementation status.

### P0
- CI supply-chain hardening pack:
  dependency review on PRs, Dependabot for Cargo/Actions, action SHA pinning,
  build provenance attestations, and SBOM publishing are implemented.
- OAuth sender-constrained token enforcement in HTTP proxy:
  DPoP proof validation is integrated into request authorization path (not only NHI subsystem),
  with explicit failure/replay audit events and dedicated proxy counters.
- **RwLock poisoning fail-closed hardening:**
  All `unwrap_or_else(|e| e.into_inner())` patterns on RwLock operations across 12 `vellaveto-mcp` modules
  and `vellaveto-server/src/opa.rs` replaced with explicit `match` blocks. Each logs `tracing::error!`
  with the exact method name and returns a fail-closed default (Deny, empty set, None, or error).
  Zero silent lock recovery — all poisoned lock states are now observable and fail-closed.
- **Constant-time key comparison:**
  Public key matching in `accountability.rs` now uses `subtle::ConstantTimeEq`
  to prevent timing side-channel attacks on attestation verification.

### P1
- `cargo-deny` dependency policy checks (advisories/bans/sources/licenses) are now wired in CI with a baseline `deny.toml`.
- OPA runtime decision enforcement wiring is active with fail-open/fail-closed controls and runtime metrics.
  Remaining: expand complex-policy integration matrix coverage as architecture split stabilizes.
- **Identity verification tiers:**
  Ordered enum (Unverified → FullyVerified) with fail-closed policy enforcement via `min_verification_tier`
  condition. Missing verification tier in evaluation context produces Deny.
- **DID:PLC generation:**
  Deterministic decentralized identifiers from SHA-256 + Base32 encoding of canonicalized genesis operations.
  Integrated into NHI lifecycle for agent identity binding.
- **Agent card SSRF prevention (FIND-055):**
  `validate_agent_card_base_url()` rejects non-HTTPS schemes, localhost, private IPs,
  IPv6 private ranges, path traversal, and userinfo-based host spoofing.
- **Control character rejection (FIND-074):**
  Audit logger now rejects ALL control characters (U+0000–U+009F) in tool/function names,
  not just \n, \r, and \0. Prevents log injection via tabs, backspaces, and escape sequences.

### P2
- **Bounded JSON traversal (FIND-057):**
  `collect_string_leaves()` now enforces MAX_STACK_SIZE (10,000) to prevent memory exhaustion
  from extremely wide fan-out JSON structures in A2A messages.
- **Regex pattern length limits (FIND-063):**
  DLP and PII pattern strings bounded to MAX_PATTERN_LEN (2,048 chars) before regex compilation.
  Prevents ReDoS and excessive compile-time memory usage from malicious config patterns.

### P3
- **Audit log permission warnings (FIND-065):**
  `set_permissions(0o600)` failures on Unix are now logged as `tracing::warn!` instead of silently
  ignored with `let _ =`. Operators can now detect permission issues in their logs.
- **Attestation empty field validation (FIND-068):**
  `sign_attestation()` rejects empty agent_id, statement, and policy_hash to prevent
  valid but meaningless attestations.
- **Observability batch size bounds (FIND-071):**
  `ObservabilityExporterConfig` validates batch_size (1..=10,000) and timeout_secs (>0)
  to prevent OOM from misconfigured exporter buffers.

Status details and rollout progress are tracked in:
- `ROADMAP.md` (active/planned tracks)
- `CHANGELOG.md` (shipped controls)

---

## Identity Verification & A2A Security

### Verification Tiers

Vellaveto supports ordered identity verification tiers for policy enforcement:

| Tier | Description |
|------|-------------|
| `Unverified` | No verification performed |
| `SelfAsserted` | Agent self-reported identity |
| `ThirdPartyAttested` | Identity attested by a trusted third party |
| `CryptographicallyVerified` | Identity verified via cryptographic proof (e.g., Ed25519 signature) |
| `FullyVerified` | All verification layers passed |

Configure minimum verification tier requirements in policies:

```toml
[[policies]]
name = "Require cryptographic verification for sensitive tools"
tool_pattern = "database"
function_pattern = "write"
priority = 300

[policies.policy_type.Conditional.conditions]
min_verification_tier = "CryptographicallyVerified"
```

When `min_verification_tier` is set, actions without a verification tier in the evaluation context are **denied** (fail-closed).

### DID:PLC Identifiers

Vellaveto generates deterministic decentralized identifiers (DID:PLC) for agent identity binding:

- SHA-256 hash of canonicalized genesis operations
- Base32 encoding for URL-safe identifier representation
- Integrated into NHI lifecycle for identity-to-key binding

### Accountability Attestations

Ed25519-signed accountability attestations provide tamper detection and
authorship attribution under a pinned verifying key. They do not establish
*when* an attestation was made: `created_at` and `expires_at` are read from the
signing host's clock with no external anchor
(see [Signing and timestamps](SECURITY_MODEL.md#where-signing-time-comes-from)).

- Length-prefixed content prevents boundary collision attacks
- Constant-time public key comparison (`subtle::ConstantTimeEq`) prevents timing side-channels
- Expiry checking with fail-closed default (unparseable expiry = expired)

### A2A Protocol Security

When using the A2A (Agent-to-Agent) protocol, Vellaveto provides:

- **Message classification** — Parses and classifies A2A JSON-RPC messages by method type
- **Batch rejection** — JSON-RPC batch requests rejected to prevent TOCTOU attacks
- **Agent Card validation** — Fetches and validates `/.well-known/agent.json` with TTL-based cache expiration and SSRF-safe URL validation (FIND-055)
- **Authentication validation** — Validates request authentication against agent card supported schemes
- **DLP and injection scanning** — Full security pipeline applied to A2A message content

```toml
[a2a]
enabled = true
allowed_operations = ["tasks/get", "message/send"]
agent_card_cache_ttl_secs = 300
```

---

## Security Checklist

Use this checklist before production deployment:

### Authentication & Authorization
- [ ] API key configured for admin endpoints
- [ ] OAuth 2.1 configured (if enterprise)
- [ ] RBAC roles defined
- [ ] Service accounts use minimal permissions

### Network Security
- [ ] TLS termination configured
- [ ] TLS 1.2+ only, strong ciphers
- [ ] Security headers configured
- [ ] Firewall rules restrict access
- [ ] DNS rebinding protection enabled

### Policy Configuration
- [ ] Strict mode enabled
- [ ] Credential file access blocked
- [ ] Exfiltration domains blocked
- [ ] Dangerous commands require approval
- [ ] Default-deny for network access

### Detection & Prevention
- [ ] Injection scanning enabled and blocking
- [ ] DLP scanning enabled
- [ ] Rug-pull detection enabled
- [ ] Behavioral anomaly detection enabled

### Audit & Compliance
- [ ] Audit logging enabled
- [ ] PII redaction configured
- [ ] Hash chain integrity enabled
- [ ] SIEM export configured
- [ ] Log retention policy defined

### Runtime Security
- [ ] Running as non-root user
- [ ] Read-only filesystem where possible
- [ ] Capabilities dropped
- [ ] Resource limits configured
- [ ] Rate limiting enabled

### Supply Chain
- [ ] Binary checksums verified
- [ ] Container images signed/verified
- [ ] MCP server binaries pinned

### Operations
- [ ] Monitoring alerts configured
- [ ] Runbook documented
- [ ] Incident response plan defined
- [ ] Backup procedures tested

---

## Related Documentation

- [Deployment Guide](./DEPLOYMENT.md) - Installation and configuration
- [Operations Runbook](./OPERATIONS.md) - Monitoring and troubleshooting
- [API Reference](./API.md) - Complete API documentation
