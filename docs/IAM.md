---
title: Enterprise IAM & SAML
---

# Enterprise IAM Overview

Vellaveto’s Phase‑46 IAM integration centralizes: OpenID Connect logins, session management, SAML SSO for legacy IdPs, and optional SCIM provisioning. This document highlights the SAML surface area that was recently implemented.

## SAML Service Provider metadata

- **Endpoint:** `GET /iam/saml/metadata`  
- **Content type:** `application/samlmetadata+xml`  
- **Purpose:** Export an SP descriptor that IdP administrators can import to configure SAML trust (entity ID + ACS URL + assertion consumer binding).
- **Requirements:** IAM must be enabled and `iam.saml.enabled = true` in the TOML config. The endpoint fails fast if SAML is disabled to avoid leaking configuration in shared deployments.

Example curl:

```bash
curl -H "Authorization: Bearer $VELLAVETO_API_KEY" \
     https://<host>/iam/saml/metadata
```

Use the returned XML as the IdP’s SP metadata when configuring your IdP (Okta, Azure AD, Keycloak, etc.). The metadata contains:
1. `entityID` set to `iam.saml.entity_id`.
1. `AssertionConsumerService` pointing to `iam.saml.acs_url`.
1. A short SPSSODescriptor with `NameIDFormat` and POST binding so the IdP knows how to deliver assertions.

## ACS callback

- **Endpoint:** `POST /iam/saml/acs`  
- **Payload:** standard HTTP-POST `SAMLResponse` (base64-encoded, optionally compressed) and optional `RelayState`.  
- **Behavior:**  
  - Decodes + (de)compresses the response, canonicalizes assertions, validates status/signer/digest, and enforces `Destination == iam.saml.acs_url`.  
  - Extracts the `NameID` and configured role attribute to build `RoleClaims`.  
  - Creates a server session with the role, issues the configured session cookie, and redirects to `RelayState` or `/`.

> **Tip:** Always include the RelayState that your login flow supplied when posting assertions. Vellaveto redirects back to it after the session is created.

### SAML flow support and replay defence

**Only IdP-initiated SSO is supported.** There is no SP-initiated AuthnRequest
handler, so no request ID is ever stored — a `SAMLResponse` carrying
`InResponseTo` cannot be matched against a pending request and is rejected.
Configure your IdP for IdP-initiated SSO to this ACS endpoint.

Assertion replay is defended by an **assertion-ID deduplication cache** (1-hour
TTL, 100,000-entry capacity): an assertion ID seen before is rejected. This is
per-process, so it does not survive a restart and is not shared across replicas
— behind a load balancer, terminate SAML at a single instance or accept that
replay protection is per-instance. `<Conditions>` `NotBefore` / `NotOnOrAfter`
are enforced, and an assertion with no `<Conditions>` element is rejected rather
than accepted.

### DPoP scope

DPoP (RFC 9449) is enforced on the **HTTP proxy's OAuth path**, which implements
the full check: `jti` replay cache keyed with `ath` when token binding is
present, `iat` skew bounds, and `exp`/`nbf` validation. It is not a
server-wide control — do not assume a request to another surface carries DPoP
proof-of-possession.

## Session / RBAC insights

- After successful login (OIDC/SAML), the `iam` service emits a session cookie named `iam.session.cookie_name` with `HttpOnly`, `Secure`, and `SameSite=Strict`.  
- Sessions are scoped per subject and expire after `iam.session.max_age_secs`; you can revoke them via `/iam/logout`.  
- The `/iam/session` endpoint returns the current session role + expiry so RBAC middleware can make permission decisions and dashboards can reflect the logged-in identity. Combine it with `/iam/scim/status` when drilling into provisioning state and user sync cadence.

RBAC enforcement prioritizes:
1. `X-Vellaveto-Role` (if `rbac.allow_header_role` is enabled).  
2. Valid JWT tokens signed by the configured JWKS.  
3. Session cookies created by IAM (`iam_state.sessions`).  
4. Default role (Viewer) only when IAM and RBAC are both disabled.

## SCIM provisioning observability

- **Endpoint:** `GET /iam/scim/status`  
- **Use case:** Monitoring dashboards should poll this when `iam.scim.enabled = true` to show sync health for enterprise user directories.
- **Payload includes:**
  * whether SCIM is enabled / sync interval (`iam.scim.sync_interval_secs`)
  * `last_sync` timestamp, `last_user_count`, and `last_sync_duration_ms` from the running sync task.
  * `last_error` (useful for alerts when provisioning endpoint becomes unavailable).  
- **Background sync:** The server spawns a tokio task that queries `iam.scim.endpoint` every `sync_interval_secs` with `iam.scim.bearer_token`. The task updates the status object and logs warnings for any failures; a healthy deployment should show a recent `last_sync` and `last_user_count`.

When onboarding, configure the SCIM endpoint and token, then verify the status endpoint shows your user count and no errors before relying on automated provisioning.

## OIDC & SCIM context

- OIDC login flows (`/iam/login` + `/iam/callback`) remain the primary path; SAML is intended for IdPs without modern OIDC support.  
- SCIM sync state (status + last user count) is exposed at `/iam/scim/status` for monitoring.

## Config pointers

Relevant TOML entries:

```toml
[iam]
enabled = true

[iam.saml]
enabled = true
entity_id = "https://your-enterprise/vellaveto"
acs_url = "https://your-enterprise/iam/saml/acs"
idp_metadata_url = "https://idp.example.com/metadata"
role_attribute = "Role" # optional attribute containing RBAC role/tenant info
```

When rotating IdP certificates, the SAML state fetches metadata on startup. After downloading, Vellaveto rejects assertions signed by unknown certificate fingerprint(s).
