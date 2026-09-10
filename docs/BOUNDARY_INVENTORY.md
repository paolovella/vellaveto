# E1-3: Transport Interception Boundary Inventory

> **Version:** 1.0 — 2026-03-09
> **Epic:** E1 (ACIS Contract and Boundary Inventory)
> **Status:** Closed

Every side-effecting decision in Vellaveto crosses one of the interception
points listed below. This inventory maps each point to its fingerprint source,
approval gate, and audit hook.

---

## 1. stdio Relay (`vellaveto-mcp/src/proxy/bridge/relay.rs`)

| Handler | MCP Method | Fingerprint | Approval | DLP | Injection | ABAC | Audit |
|---------|-----------|-------------|----------|-----|-----------|------|-------|
| `handle_tool_call()` | `tools/call` | `fingerprint_action` | RequireApproval gate | Y | Y | Y | `log_entry_with_acis` |
| `handle_resource_read()` | `resources/read` | `fingerprint_action` | RequireApproval gate | Y | Y | Y | `log_entry_with_acis` |
| `handle_task_request()` | `tasks/*` | `fingerprint_action` | RequireApproval gate | Y | Y | Y | `log_entry_with_acis` |
| `handle_extension_method()` | Extension methods | `fingerprint_action` | RequireApproval gate | Y | Y | Y | `log_entry_with_acis` |
| `handle_sampling_request()` | `sampling/create` | — | Circuit breaker | N | Y | Y | `log_entry_with_acis` |
| `handle_elicitation_request()` | `sampling/elicit` | — | Circuit breaker | N | Y | Y | `log_entry_with_acis` |
| `handle_passthrough()` | Unknown methods | Memory poisoning | — | N | N | N | `log_entry_with_acis` |
| `handle_child_response()` | Server responses | — | — | Y | Y | N | `log_entry_with_acis` |
| `handle_tools_list_response()` | `tools/list` response | — | — | N | Y (schema) | N | `log_entry_with_acis` |
| `handle_agent_message()` | JSON-RPC routing | Shadow agent FP | — | N | Y | Y | `log_entry_with_acis` |
| Batch rejection | JSON-RPC batch | — | — | N | N | N | `log_entry_with_acis` |

**Session identity:** Per-relay UUID (`RelayState.session_id`), agent identity
via `RelayState.agent_id`.

---

## 2. HTTP Proxy (`vellaveto-http-proxy/src/proxy/`)

| Handler | Route | Fingerprint | Approval | DLP | Injection | ABAC | Audit |
|---------|-------|-------------|----------|-----|-----------|------|-------|
| `handle_mcp_post()` | `POST /mcp` | `fingerprint_action` | RequireApproval gate | Y | Y | Y | `log_entry_with_acis` |
| `handle_mcp_delete()` | `DELETE /mcp/*` | `fingerprint_action` | RequireApproval gate | Y | Y | Y | `log_entry_with_acis` |
| `handle_mcp_get()` | `GET /mcp/*` | `fingerprint_action` | RequireApproval gate | Y | Y | Y | `log_entry_with_acis` |
| `handle_protected_resource_metadata()` | `GET /api/resource-metadata` | — | — | N | N | N | Y |

**Session identity:** HTTP proxy session state, OAuth/API-key principal, and
legacy `Mcp-Session-Id` when present. MCP `2026-07-28` peers are treated as
stateless per request; protocol session headers are not assumed.

### HTTP Sub-interceptors

| Module | Function | Purpose | Audit |
|--------|----------|---------|-------|
| `inspection.rs` | DLP + injection scanning | Parameter/response scanning | `log_entry_with_acis` |
| `auth.rs` | Auth validation | OAuth/API-key enforcement | `log_entry_with_acis` |
| `upstream.rs` | Upstream forwarding | Response DLP + injection | `log_entry_with_acis` |
| `helpers.rs` | Approval gate | Approval creation/consumption | `log_entry_with_acis` |
| `request_state.rs` | Continuation sealing | HMAC-sealed `requestState`, replay/expiry denial | `log_entry_with_acis` |
| `server_request.rs` | Server-request control | Deny detached server-initiated JSON-RPC requests | `log_entry_with_acis` |

---

## 3. WebSocket Proxy (`vellaveto-http-proxy/src/proxy/websocket/mod.rs`)

| Handler | Message Type | Fingerprint | Approval | DLP | Injection | Audit |
|---------|-------------|-------------|----------|-----|-----------|-------|
| `handle_ws_upgrade()` | Connection upgrade | — | — | N | N | Metrics |
| `handle_ws_connection()` | Frame processing | `fingerprint_action` | RequireApproval gate | Y | Y | `log_entry_with_acis` |

**Session identity:** Per-connection UUID, bound on upgrade.

**Parity notes:**
- Binary frames rejected (code 1003)
- Bidirectional rate limiting (client→upstream 100/s, upstream→client 500/s)
- Re-serialized JSON forwarded (TOCTOU defense)

---

## 4. gRPC Proxy (`vellaveto-http-proxy/src/proxy/grpc/service.rs`)

| Handler | RPC Method | Fingerprint | Approval | DLP | Injection | ABAC | Audit |
|---------|-----------|-------------|----------|-----|-----------|------|-------|
| `handle_tool_call()` | `CallTool` | `fingerprint_action` | RequireApproval gate | Y | Y | Y | `log_entry_with_acis` |
| `handle_resource_read()` | `ReadResource` | `fingerprint_action` | RequireApproval gate | Y | Y | Y | `log_entry_with_acis` |
| `handle_task_request()` | `RequestTask` | `fingerprint_action` | RequireApproval gate | Y | Y | Y | `log_entry_with_acis` |
| `handle_extension_method()` | `CallExtension` | `fingerprint_action` | RequireApproval gate | Y | Y | Y | `log_entry_with_acis` |

**Session identity:** gRPC metadata, call chain via `CallChainManager`.

---

## 5. Server API Routes (`vellaveto-server/src/routes/`)

### State-Mutating Routes (audit-logged)

| Module | Route | Method | Purpose | Audit |
|--------|-------|--------|---------|-------|
| `approval.rs` | `/api/approvals/{id}/approve` | POST | Approve pending approval | `log_entry_with_acis` |
| `approval.rs` | `/api/approvals/{id}/deny` | POST | Deny pending approval | `log_entry_with_acis` |
| `policy.rs` | `/api/policies` | POST | Create policy | `log_entry_with_acis` |
| `policy.rs` | `/api/policies/{id}` | PUT | Update policy | `log_entry_with_acis` |
| `policy_lifecycle.rs` | `/api/policies/versions` | POST | Create policy version | `log_entry_with_acis` |
| `policy_lifecycle.rs` | `/api/policies/versions/{id}/approve` | POST | Approve version | `log_entry_with_acis` |
| `policy_lifecycle.rs` | `/api/policies/versions/{id}/promote` | POST | Promote to active | `log_entry_with_acis` |
| `policy_lifecycle.rs` | `/api/policies/versions/{id}/archive` | POST | Archive version | `log_entry_with_acis` |
| `policy_lifecycle.rs` | `/api/policies/rollback` | POST | Rollback policy | `log_entry_with_acis` |
| `deputy.rs` | `/api/deputies` | POST | Create deputy chain | `log_entry_with_acis` |
| `deputy.rs` | `/api/deputies/{id}/revoke` | POST | Revoke deputy | `log_entry_with_acis` |
| `auth_level.rs` | `/api/auth-level/step-up` | POST | Step-up auth | `log_entry_with_acis` |
| `auth_level.rs` | `/api/auth-level/step-down` | POST | Step-down auth | `log_entry_with_acis` |
| `registry.rs` | `/api/registry` | POST | Register tool | `log_entry_with_acis` |
| `registry.rs` | `/api/registry/{id}` | DELETE | Unregister tool | `log_entry_with_acis` |
| `circuit_breaker.rs` | `/api/circuit-breaker/reset` | POST | Reset circuit breaker | `log_entry_with_acis` |
| `schema_lineage.rs` | `/api/schemas` | POST | Register schema | `log_entry_with_acis` |
| `schema_lineage.rs` | `/api/schemas/{id}/lineage` | POST | Add lineage | `log_entry_with_acis` |
| `billing.rs` | `/api/webhooks/stripe` | POST | Stripe webhook | `log_entry_with_acis` |
| `shadow_agent.rs` | `/api/shadow-agents` | POST | Register agent FP | `log_entry_with_acis` |
| `shadow_agent.rs` | `/api/shadow-agents/verify` | POST | Verify agent FP | `log_entry_with_acis` |
| `main.rs` | `/api/evaluate` | POST | Policy evaluation | `log_entry_with_acis` |

### Read-Only Routes (no state mutation)

Read-only routes (`GET /api/health`, `GET /api/policies`, `GET /api/audit/*`,
`GET /api/topology/*`, etc.) are not listed — they do not produce verdicts or
mutate state. Auth validation still applies via middleware.

---

## 6. Consumer Shield (`vellaveto-mcp-shield/src/`, `vellaveto-shield/src/main.rs`)

| Module | Interception | Purpose | Audit |
|--------|-------------|---------|-------|
| `sanitizer.rs` | `sanitize_query()` / `desanitize_response()` | Bidirectional PII redaction | Via relay |
| `session_isolator.rs` | `isolate()` | Per-session context isolation | Via relay |
| `context_isolation.rs` | `ContextIsolator` | Bounded context window | Via relay |
| `credential_vault.rs` | `consume_credential()` | Per-session credential binding | Via relay |
| `session_unlinker.rs` | `end_session()` | Credential rotation | Via relay |
| `stylometric.rs` | `normalize()` | Fingerprint resistance | Via relay |

Shield components intercept within the relay pipeline (outbound:
sanitize→stylometric→context, inbound: desanitize→context). They produce
Deny verdicts on failure (PII block, credential exhaustion) which are logged
via `log_entry_with_acis` in the relay.

---

## 7. Transport Parity Matrix

| Feature | stdio | HTTP | WS | gRPC | SSE |
|---------|-------|------|----|------|-----|
| DLP parameter scanning | Y | Y | Y | Y | Y |
| Injection detection | Y | Y | Y | Y | Y |
| Memory poisoning detection | Y | Y | Y | Y | — |
| Approval gate | Y | Y | Y | Y | Y |
| ABAC evaluation | Y | Y | Y | Y | Y |
| Session binding | Y | Y | Y | Y | Y |
| Agent identity validation | Y | Y | Y | Y | Y |
| Call chain tracking | Y | Y | Y | Y | Y |
| Audit logging (ACIS) | Y | Y | Y | Y | Y |
| Rate limiting | — | Y | Y | Y | Y |
| Output schema validation | Y | Y | Y | Y | Y |
| Control char validation | Y | Y | Y | Y | Y |

---

## 8. Fingerprint Sources

All runtime surfaces use the shared `fingerprint_action()` /
`compute_action_fingerprint()` from `vellaveto-engine/src/acis.rs` (SHA-256).
No transport-local fingerprint generation exists.

---

## Non-Goals

- **Progress notifications:** Forwarded without policy evaluation (no
  side effect). Injection scanning applied for defense-in-depth.
- **Ping/pong:** Protocol-level keepalive, no policy gate.
- **tools/list requests (outbound):** Discovery metadata, not side-effecting.
  Responses are scanned for schema injection.

---

## References

- [ACIS types](../vellaveto-types/src/acis.rs)
- [Mediation helpers](../vellaveto-mcp/src/mediation.rs)
- [Transport coverage](../README.md) — verified parity across HTTP, WebSocket, gRPC, stdio, and SSE
- [Roadmap](../ROADMAP.md) — E1-3 acceptance criteria
