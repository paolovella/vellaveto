// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

use axum::{
    extract::{DefaultBodyLimit, Extension, Query, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::Ordering;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use vellaveto_approval::{
    review_safe_provenance_summary, ApprovalContainmentContext, ApprovalStatus,
};
use vellaveto_engine::acis::fingerprint_action;
use vellaveto_mcp::mediation::{build_acis_envelope, build_acis_envelope_with_security_context};
use vellaveto_mcp::tool_registry::TrustLevel;
use vellaveto_types::acis::{AcisDecisionEnvelope, DecisionOrigin};
use vellaveto_types::{
    project_agent_identity_from_transport, project_capability_token_from_transport, Action,
    ContainmentMode, EvaluationContext, RuntimeSecurityContext, SemanticTaint, SinkClass,
    TrustTier, Verdict,
};

use governor::clock::Clock;

use subtle::ConstantTimeEq;

use crate::iam;
use crate::rbac::{rbac_middleware, RbacState};
use crate::tenant::{tenant_middleware, TenantContext, TenantState};
use crate::AppState;

/// Maximum allowed request body size in bytes (1 MB).
/// FIND-R56-SRV-005: Extracted from inline magic number for clarity.
const MAX_REQUEST_BODY_SIZE: usize = 1_048_576;
const APPROVAL_ID_HEADER: &str = "x-vellaveto-approval-id";
const INVALID_PRESENTED_APPROVAL_REASON: &str = "Supplied approval is not valid for this action";

// Phase 15: Observability integration
#[cfg(feature = "observability-exporters")]
use vellaveto_audit::observability::{SecuritySpan, SpanKind, TraceContext};

pub fn build_router(state: AppState) -> Router {
    // Build CORS layer from configured origins.
    // Default (empty vec) = localhost only. "*" = any origin.
    let cors = build_cors_layer(&state.cors_origins);

    // Authenticated routes (behind API key + rate limit middleware)
    let authenticated = Router::new()
        .route("/health", get(health))
        .route("/api/evaluate", post(evaluate))
        .route("/api/policies", get(super::policy::list_policies))
        .route("/api/policies", post(super::policy::add_policy))
        .route("/api/policies/reload", post(super::policy::reload_policies))
        .route("/api/policies/{id}", delete(super::policy::remove_policy))
        .route("/api/audit/entries", get(super::audit::audit_entries))
        .route("/api/audit/export", get(super::audit::audit_export))
        .route("/api/audit/report", get(super::audit::audit_report))
        .route("/api/audit/verify", get(super::audit::audit_verify))
        .route("/api/audit/otel-spans", get(super::audit::otel_spans))
        // Compliance evidence endpoints (Phase 19/21)
        .route(
            "/api/compliance/status",
            get(super::compliance::compliance_status),
        )
        .route(
            "/api/compliance/iso42001/report",
            get(super::compliance::iso42001_report),
        )
        .route(
            "/api/compliance/eu-ai-act/report",
            get(super::compliance::eu_ai_act_report),
        )
        .route(
            "/api/compliance/soc2/evidence",
            get(super::compliance::soc2_evidence),
        )
        .route(
            "/api/compliance/soc2/access-review",
            get(super::compliance::soc2_access_review),
        )
        // Threat coverage and gap analysis endpoints (Phase 19.3)
        .route(
            "/api/compliance/threat-coverage",
            get(super::compliance::threat_coverage),
        )
        .route(
            "/api/compliance/gap-analysis",
            get(super::compliance::gap_analysis),
        )
        .route(
            "/api/compliance/data-governance",
            get(super::compliance::data_governance_summary),
        )
        // OWASP ASI coverage (Phase 41)
        .route(
            "/api/compliance/owasp-agentic",
            get(super::compliance::owasp_asi_coverage),
        )
        // Evidence pack endpoints (Phase 48)
        .route(
            "/api/compliance/evidence-pack/status",
            get(super::compliance::evidence_pack_status),
        )
        .route(
            "/api/compliance/evidence-pack/{framework}",
            get(super::compliance::evidence_pack),
        )
        // Phase 4: Compliance evidence factory endpoints
        .route(
            "/api/compliance/annex-iv",
            get(super::compliance::annex_iv_package),
        )
        .route(
            "/api/compliance/incident-report",
            post(super::compliance::create_incident_report),
        )
        .route("/api/compliance/fria", get(super::compliance::fria_export))
        .route(
            "/api/audit/checkpoints",
            get(super::audit::list_checkpoints),
        )
        .route(
            "/api/audit/checkpoints/verify",
            get(super::audit::verify_checkpoints),
        )
        .route(
            "/api/audit/checkpoint",
            post(super::audit::create_checkpoint),
        )
        .route(
            "/api/approvals/pending",
            get(super::approval::list_pending_approvals),
        )
        .route("/api/approvals/{id}", get(super::approval::get_approval))
        .route(
            "/api/approvals/{id}/approve",
            post(super::approval::approve_approval),
        )
        .route(
            "/api/approvals/{id}/deny",
            post(super::approval::deny_approval),
        )
        .route("/api/metrics", get(metrics_json))
        // IAM operational routes that expose deployment/auth metadata.
        .route("/iam/scim/status", get(iam::scim_status))
        // CIMD fetch endpoint performs outbound requests and must stay behind auth.
        .route("/api/auth/client-metadata", post(iam::client_metadata))
        // Tool registry endpoints (P2.1)
        .route(
            "/api/registry/tools",
            get(super::registry::list_registry_tools),
        )
        .route(
            "/api/registry/tools/{name}/approve",
            post(super::registry::approve_registry_tool),
        )
        .route(
            "/api/registry/tools/{name}/revoke",
            post(super::registry::revoke_registry_tool),
        )
        // Tenant management endpoints (Phase 3)
        .route("/api/tenants", get(super::tenant::list_tenants))
        .route("/api/tenants", post(super::tenant::create_tenant))
        .route("/api/tenants/{id}", get(super::tenant::get_tenant))
        .route(
            "/api/tenants/{id}",
            axum::routing::put(super::tenant::update_tenant),
        )
        .route("/api/tenants/{id}", delete(super::tenant::delete_tenant))
        // Phase 15: AI Observability Platform Integration
        .route(
            "/api/observability/exporters",
            get(super::observability::list_observability_exporters),
        )
        .route(
            "/api/observability/stats",
            get(super::observability::observability_stats),
        )
        .route(
            "/api/observability/test",
            post(super::observability::test_observability),
        )
        // Root redirect → dashboard
        .route("/", get(|| async { Redirect::permanent("/dashboard") }))
        // Admin dashboard (P3.2)
        .route("/dashboard", get(crate::dashboard::dashboard_page))
        .route(
            "/dashboard/approvals/{id}/approve",
            post(crate::dashboard::dashboard_approve),
        )
        .route(
            "/dashboard/approvals/{id}/deny",
            post(crate::dashboard::dashboard_deny),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 3.1: Security Manager Admin APIs
        // ═══════════════════════════════════════════════════════════════════
        // Circuit Breaker (OWASP ASI08)
        .route(
            "/api/circuit-breaker",
            get(super::circuit_breaker::list_circuit_breakers),
        )
        .route(
            "/api/circuit-breaker/stats",
            get(super::circuit_breaker::circuit_breaker_stats),
        )
        .route(
            "/api/circuit-breaker/{tool}",
            get(super::circuit_breaker::get_circuit_state),
        )
        .route(
            "/api/circuit-breaker/{tool}/reset",
            post(super::circuit_breaker::reset_circuit),
        )
        // Shadow Agent Detection
        .route(
            "/api/shadow-agents",
            get(super::shadow_agent::list_shadow_agents),
        )
        .route(
            "/api/shadow-agents",
            post(super::shadow_agent::register_shadow_agent),
        )
        .route(
            "/api/shadow-agents/{id}",
            delete(super::shadow_agent::remove_shadow_agent),
        )
        .route(
            "/api/shadow-agents/{id}/trust",
            axum::routing::put(super::shadow_agent::update_agent_trust),
        )
        // Schema Lineage (OWASP ASI05)
        .route(
            "/api/schema-lineage",
            get(super::schema_lineage::list_schema_lineage),
        )
        .route(
            "/api/schema-lineage/{tool}",
            get(super::schema_lineage::get_schema_lineage),
        )
        .route(
            "/api/schema-lineage/{tool}/trust",
            axum::routing::put(super::schema_lineage::reset_schema_trust),
        )
        .route(
            "/api/schema-lineage/{tool}",
            delete(super::schema_lineage::remove_schema_lineage),
        )
        // Task State (MCP 2025-11-25 Async Tasks)
        .route("/api/tasks", get(super::task_state::list_tasks))
        .route("/api/tasks/stats", get(super::task_state::task_stats))
        .route("/api/tasks/{id}", get(super::task_state::get_task))
        .route(
            "/api/tasks/{id}/cancel",
            post(super::task_state::cancel_task),
        )
        // Auth Level (Step-Up Authentication)
        .route(
            "/api/auth-levels/{session}",
            get(super::auth_level::get_auth_level),
        )
        .route(
            "/api/auth-levels/{session}/upgrade",
            post(super::auth_level::upgrade_auth_level),
        )
        .route(
            "/api/auth-levels/{session}",
            delete(super::auth_level::clear_auth_level),
        )
        // Sampling Detection
        .route("/api/sampling/stats", get(super::sampling::sampling_stats))
        .route(
            "/api/sampling/{session}/reset",
            post(super::sampling::reset_sampling_stats),
        )
        // Deputy Validation (OWASP ASI02)
        .route(
            "/api/deputy/delegations",
            get(super::deputy::list_delegations),
        )
        .route(
            "/api/deputy/delegations",
            post(super::deputy::register_delegation),
        )
        .route(
            "/api/deputy/delegations/{session}",
            delete(super::deputy::remove_delegation),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 6: Execution Graph Export
        // ═══════════════════════════════════════════════════════════════════
        .route("/api/graphs", get(super::exec_graph::list_graphs))
        .route("/api/graphs/{session}", get(super::exec_graph::get_graph))
        .route(
            "/api/graphs/{session}/dot",
            get(super::exec_graph::get_graph_dot),
        )
        .route(
            "/api/graphs/{session}/stats",
            get(super::exec_graph::get_graph_stats),
        )
        .route(
            "/api/graphs/{session}/svg",
            get(super::exec_graph::get_graph_svg),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 8: ETDI Cryptographic Tool Security
        // ═══════════════════════════════════════════════════════════════════
        // Tool Signatures
        .route(
            "/api/etdi/signatures",
            get(super::etdi::list_tool_signatures),
        )
        .route(
            "/api/etdi/signatures/{tool}",
            get(super::etdi::get_tool_signature),
        )
        .route(
            "/api/etdi/signatures/{tool}/verify",
            post(super::etdi::verify_tool_signature),
        )
        // Attestation Chain
        .route(
            "/api/etdi/attestations",
            get(super::etdi::list_attestations),
        )
        .route(
            "/api/etdi/attestations/{tool}",
            get(super::etdi::get_tool_attestations),
        )
        .route(
            "/api/etdi/attestations/{tool}/verify",
            get(super::etdi::verify_attestation_chain),
        )
        // Version Pins
        .route("/api/etdi/pins", get(super::etdi::list_version_pins))
        .route("/api/etdi/pins/{tool}", get(super::etdi::get_version_pin))
        .route(
            "/api/etdi/pins/{tool}",
            post(super::etdi::create_version_pin),
        )
        .route(
            "/api/etdi/pins/{tool}",
            delete(super::etdi::remove_version_pin),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 9: Memory Injection Defense (MINJA)
        // ═══════════════════════════════════════════════════════════════════
        .route(
            "/api/memory/entries",
            get(super::memory::list_memory_entries),
        )
        .route(
            "/api/memory/entries/{id}",
            get(super::memory::get_memory_entry),
        )
        .route(
            "/api/memory/entries/{id}/quarantine",
            post(super::memory::quarantine_memory_entry),
        )
        .route(
            "/api/memory/entries/{id}/release",
            post(super::memory::release_memory_entry),
        )
        .route(
            "/api/memory/integrity/{session}",
            get(super::memory::verify_memory_integrity),
        )
        .route(
            "/api/memory/provenance/{id}",
            get(super::memory::get_memory_provenance),
        )
        .route(
            "/api/memory/namespaces",
            get(super::memory::list_memory_namespaces),
        )
        .route(
            "/api/memory/namespaces",
            post(super::memory::create_memory_namespace),
        )
        .route(
            "/api/memory/namespaces/{id}/share",
            post(super::memory::share_memory_namespace),
        )
        .route(
            "/api/memory/stats",
            get(super::memory::memory_security_stats),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 10: Non-Human Identity (NHI) Lifecycle
        // ═══════════════════════════════════════════════════════════════════
        // Agent Identities
        .route("/api/nhi/agents", get(super::nhi::list_nhi_agents))
        .route("/api/nhi/agents", post(super::nhi::register_nhi_agent))
        .route("/api/nhi/agents/{id}", get(super::nhi::get_nhi_agent))
        .route("/api/nhi/agents/{id}", delete(super::nhi::revoke_nhi_agent))
        .route(
            "/api/nhi/agents/{id}/activate",
            post(super::nhi::activate_nhi_agent),
        )
        .route(
            "/api/nhi/agents/{id}/suspend",
            post(super::nhi::suspend_nhi_agent),
        )
        // Behavioral Baselines
        .route(
            "/api/nhi/agents/{id}/baseline",
            get(super::nhi::get_nhi_baseline),
        )
        .route(
            "/api/nhi/agents/{id}/check",
            post(super::nhi::check_nhi_behavior),
        )
        // Delegations
        .route(
            "/api/nhi/delegations",
            get(super::nhi::list_nhi_delegations),
        )
        .route(
            "/api/nhi/delegations",
            post(super::nhi::create_nhi_delegation),
        )
        .route(
            "/api/nhi/delegations/{from}/{to}",
            get(super::nhi::get_nhi_delegation),
        )
        .route(
            "/api/nhi/delegations/{from}/{to}",
            delete(super::nhi::revoke_nhi_delegation),
        )
        .route(
            "/api/nhi/delegations/{id}/chain",
            get(super::nhi::get_nhi_delegation_chain),
        )
        // Credentials
        .route(
            "/api/nhi/agents/{id}/rotate",
            post(super::nhi::rotate_nhi_credentials),
        )
        .route(
            "/api/nhi/expiring",
            get(super::nhi::get_expiring_nhi_identities),
        )
        // DPoP
        .route("/api/nhi/dpop/nonce", post(super::nhi::generate_dpop_nonce))
        // Stats
        .route("/api/nhi/stats", get(super::nhi::nhi_stats))
        // ═══════════════════════════════════════════════════════════════════
        // Phase 22: Policy Simulator
        // ═══════════════════════════════════════════════════════════════════
        .route(
            "/api/simulator/evaluate",
            post(super::simulator::simulate_evaluate),
        )
        .route(
            "/api/simulator/batch",
            post(super::simulator::simulate_batch),
        )
        .route(
            "/api/simulator/validate",
            post(super::simulator::simulate_validate),
        )
        .route("/api/simulator/diff", post(super::simulator::simulate_diff))
        .route(
            "/api/simulator/red-team",
            post(super::simulator::simulate_red_team),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 27: Kubernetes-Native Deployment
        // ═══════════════════════════════════════════════════════════════════
        .route(
            "/api/deployment/info",
            get(super::deployment::deployment_info),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 26: Shadow AI Detection & Governance Visibility
        // ═══════════════════════════════════════════════════════════════════
        .route(
            "/api/governance/shadow-report",
            get(super::governance::shadow_report),
        )
        .route(
            "/api/governance/unregistered-agents",
            get(super::governance::unregistered_agents),
        )
        .route(
            "/api/governance/unapproved-tools",
            get(super::governance::unapproved_tools),
        )
        .route(
            "/api/governance/least-agency/{agent_id}/{session_id}",
            get(super::governance::least_agency_report),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 34: Tool Discovery Service
        // ═══════════════════════════════════════════════════════════════════
        .route(
            "/api/discovery/search",
            post(super::discovery::discovery_search),
        )
        .route(
            "/api/discovery/index/stats",
            get(super::discovery::discovery_stats),
        )
        .route(
            "/api/discovery/reindex",
            post(super::discovery::discovery_reindex),
        )
        .route(
            "/api/discovery/tools",
            get(super::discovery::discovery_tools),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Topology Management (live topology graph inspection + control)
        // ═══════════════════════════════════════════════════════════════════
        .route("/api/topology", get(super::topology::topology_snapshot))
        .route(
            "/api/topology/status",
            get(super::topology::topology_status),
        )
        .route(
            "/api/topology/recrawl",
            post(super::topology::topology_recrawl),
        )
        .route(
            "/api/topology/servers/{name}",
            delete(super::topology::topology_remove_server),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 73: Inventory and Posture Views
        // ═══════════════════════════════════════════════════════════════════
        .route(
            "/api/inventory/agents",
            get(super::inventory::inventory_agents),
        )
        .route(
            "/api/inventory/mcp-servers",
            get(super::inventory::inventory_mcp_servers),
        )
        .route(
            "/api/inventory/tools",
            get(super::inventory::inventory_tools),
        )
        .route(
            "/api/inventory/graph",
            get(super::inventory::inventory_graph),
        )
        .route(
            "/api/inventory/assets",
            get(super::inventory::inventory_assets),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 35.3: Model Projector
        // ═══════════════════════════════════════════════════════════════════
        .route(
            "/api/projector/models",
            get(super::projector::projector_models),
        )
        .route(
            "/api/projector/transform",
            post(super::projector::projector_transform),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 37: Zero-Knowledge Audit Trails
        // ═══════════════════════════════════════════════════════════════════
        .route(
            "/api/zk-audit/status",
            get(super::zk_audit::zk_audit_status),
        )
        .route(
            "/api/zk-audit/proofs",
            get(super::zk_audit::zk_audit_proofs),
        )
        .route(
            "/api/zk-audit/verify",
            post(super::zk_audit::zk_audit_verify),
        )
        .route(
            "/api/zk-audit/commitments",
            get(super::zk_audit::zk_audit_commitments),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 43: Centralized Audit Store
        // ═══════════════════════════════════════════════════════════════════
        .route("/api/audit/search", get(super::audit_store::audit_search))
        .route(
            "/api/audit/store/status",
            get(super::audit_store::audit_store_status),
        )
        .route(
            "/api/audit/entry/{id}",
            get(super::audit_store::audit_entry_by_id),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 39: Agent Identity Federation
        // ═══════════════════════════════════════════════════════════════════
        .route(
            "/api/federation/status",
            get(super::federation::federation_status),
        )
        .route(
            "/api/federation/trust-anchors",
            get(super::federation::federation_trust_anchors),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Phase 47: Policy Lifecycle Management
        // ═══════════════════════════════════════════════════════════════════
        .route(
            "/api/policies/{id}/versions",
            get(super::policy_lifecycle::list_versions)
                .post(super::policy_lifecycle::create_version),
        )
        .route(
            "/api/policies/{id}/versions/{version}",
            get(super::policy_lifecycle::get_version),
        )
        .route(
            "/api/policies/{id}/versions/{version}/approve",
            post(super::policy_lifecycle::approve_version),
        )
        .route(
            "/api/policies/{id}/versions/{version}/promote",
            post(super::policy_lifecycle::promote_version),
        )
        .route(
            "/api/policies/{id}/versions/{version}/archive",
            post(super::policy_lifecycle::archive_version),
        )
        .route(
            "/api/policies/{id}/rollback",
            post(super::policy_lifecycle::rollback_policy),
        )
        .route(
            "/api/policies/{id}/versions/{v1}/diff/{v2}",
            get(super::policy_lifecycle::diff_versions),
        )
        .route(
            "/api/policy-lifecycle/status",
            get(super::policy_lifecycle::lifecycle_status),
        )
        // ═══════════════════════════════════════════════════════════════════
        // Billing & Licensing
        // ═══════════════════════════════════════════════════════════════════
        .route("/api/billing/license", get(super::billing::license_info))
        // Phase 50: Usage metering API endpoints
        .route(
            "/api/billing/usage/{tenant_id}",
            get(super::billing::get_usage),
        )
        .route(
            "/api/billing/quotas/{tenant_id}",
            get(super::billing::get_quota_status),
        )
        .route(
            "/api/billing/usage/{tenant_id}/history",
            get(super::billing::get_usage_history),
        )
        .route(
            "/api/billing/usage/{tenant_id}/reset",
            post(super::billing::reset_usage),
        )
        // SECURITY (R38-SRV-1): /metrics inside auth — exposes policy count
        // and pending approval count, which are security-sensitive (see R26-SRV-6).
        // SECURITY (R38-SRV-2): /metrics inside rate_limit — prevents scraper DoS.
        .route("/metrics", get(prometheus_metrics))
        // Tenant middleware (innermost - runs after auth, extracts tenant context)
        // When multi-tenancy is disabled, all requests get the default tenant.
        .route_layer(middleware::from_fn_with_state(
            TenantState {
                config: state.tenant_config.clone(),
                store: state.tenant_store.clone(),
            },
            tenant_middleware,
        ))
        // RBAC middleware (after tenant - runs after auth, checks permissions)
        // When RBAC is disabled, all requests get Admin role and pass through.
        .route_layer(middleware::from_fn_with_state(
            RbacState {
                config: state.rbac_config.clone(),
                iam_state: state.iam_state.clone(),
            },
            rbac_middleware,
        ))
        // SECURITY (R27-SRV-8): rate_limit MUST be outermost (applied last)
        // so it runs BEFORE auth. Previously auth was outermost, meaning
        // unauthenticated flood requests bypassed rate limiting entirely.
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit));

    // Billing webhook routes — bypass API key auth (use provider-specific signatures).
    // SECURITY (P1-5): Rate limiting applied to prevent webhook flood attacks.
    let billing = if state.billing_config.enabled {
        Router::new()
            .route(
                "/api/billing/paddle/webhook",
                post(super::billing::paddle_webhook),
            )
            .route(
                "/api/billing/stripe/webhook",
                post(super::billing::stripe_webhook),
            )
            .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit))
    } else {
        Router::new()
    };

    // Self-service signup route — unauthenticated (creates credentials).
    // SECURITY (Phase 53): Rate-limited to prevent abuse.
    let signup_routes = Router::new()
        .route("/api/signup", post(super::signup::signup))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit));

    let iam_routes = Router::new()
        .route("/iam/login", get(iam::login))
        .route("/iam/callback", get(iam::callback))
        .route("/iam/session", get(iam::session_info))
        .route("/iam/logout", post(iam::logout))
        .route("/iam/saml/metadata", get(iam::saml_metadata))
        .route("/iam/saml/acs", post(iam::saml_acs))
        // M2M client credentials token endpoint
        .route("/api/auth/token", post(iam::m2m_token))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit));

    // Setup wizard routes — unauthenticated (before API key middleware).
    // Protected by the setup_guard middleware which returns 403 after setup is completed.
    let wizard = Router::new()
        .route("/setup", get(crate::setup_wizard::step_welcome))
        .route(
            "/setup/security",
            get(crate::setup_wizard::step_security).post(crate::setup_wizard::step_security_post),
        )
        .route(
            "/setup/policies",
            get(crate::setup_wizard::step_policies).post(crate::setup_wizard::step_policies_post),
        )
        .route(
            "/setup/detection",
            get(crate::setup_wizard::step_detection).post(crate::setup_wizard::step_detection_post),
        )
        .route(
            "/setup/audit",
            get(crate::setup_wizard::step_audit).post(crate::setup_wizard::step_audit_post),
        )
        .route(
            "/setup/compliance",
            get(crate::setup_wizard::step_compliance)
                .post(crate::setup_wizard::step_compliance_post),
        )
        .route("/setup/review", get(crate::setup_wizard::step_review))
        .route("/setup/apply", post(crate::setup_wizard::step_apply))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::setup_wizard::setup_guard,
        ))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit));

    Router::new()
        .merge(authenticated)
        .merge(billing)
        .merge(signup_routes)
        .merge(iam_routes)
        .merge(wizard)
        .layer(middleware::from_fn(request_id))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        // SECURITY: CSRF defense-in-depth via Origin/Referer validation
        .layer(middleware::from_fn_with_state(
            state.clone(),
            csrf_referer_check,
        ))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_SIZE))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

fn build_cors_layer(origins: &[String]) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .max_age(std::time::Duration::from_secs(3600)); // Cache preflight for 1 hour

    if origins.iter().any(|o| o == "*") {
        // SECURITY (R256-SRV-3): Warn when wildcard CORS is configured so operators
        // notice the open policy in logs rather than accepting it silently.
        tracing::warn!(
            "CORS wildcard origin configured — all cross-origin requests will be accepted"
        );
        base.allow_origin(Any)
    } else if origins.is_empty() {
        // Strict default: localhost only
        base.allow_origin([
            HeaderValue::from_static("http://localhost"),
            HeaderValue::from_static("http://127.0.0.1"),
            HeaderValue::from_static("http://[::1]"),
        ])
    } else {
        let allowed: Vec<HeaderValue> = origins
            .iter()
            .filter_map(|o| o.parse::<HeaderValue>().ok())
            .collect();
        base.allow_origin(allowed)
    }
}

/// Middleware that adds standard security headers to all responses.
///
/// Headers added:
/// - `X-Content-Type-Options: nosniff` — prevents MIME-type sniffing
/// - `X-Frame-Options: DENY` — prevents clickjacking via iframes
/// - `Content-Security-Policy: default-src 'none'` — blocks all content loading (API-only server)
/// - `Cache-Control: no-store` — prevents caching of sensitive API responses
/// - `X-Permitted-Cross-Domain-Policies: none` — blocks cross-domain policy files
/// - `Strict-Transport-Security` — HSTS header, only for HTTPS requests or
///   trusted-proxy `X-Forwarded-Proto: https`
async fn security_headers(State(state): State<AppState>, request: Request, next: Next) -> Response {
    // Detect HTTPS before consuming the request:
    // Check the URI scheme or trusted-proxy X-Forwarded-Proto header.
    // Untrusted clients must not be able to force HTTPS semantics via headers.
    let from_trusted_proxy = is_connection_from_trusted_proxy(&request, &state.trusted_proxies);
    let has_forwarded_proto = request.headers().contains_key("x-forwarded-proto");
    let forwarded_proto_https = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("https"))
        .unwrap_or(false);
    let is_https = request.uri().scheme_str() == Some("https")
        || (from_trusted_proxy && forwarded_proto_https);

    if has_forwarded_proto && !from_trusted_proxy {
        tracing::warn!("Ignoring X-Forwarded-Proto from non-trusted connection");
        crate::metrics::increment_forwarded_header_rejections("x_forwarded_proto");
    }
    let path = request.uri().path();
    // SECURITY (FIND-R73-SRV-015): Both /dashboard and /setup serve inline <style>
    // CSS, so they need style-src 'unsafe-inline'. All other routes use strict CSP.
    let needs_inline_style = path.starts_with("/dashboard") || path.starts_with("/setup");

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    // Dashboard and setup wizard serve inline <style> CSS, so they need style-src 'unsafe-inline'.
    // All other routes use the strictest CSP: default-src 'none'.
    if needs_inline_style {
        headers.insert(
            header::HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"),
        );
    } else {
        headers.insert(
            header::HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'"),
        );
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
    if is_https {
        headers.insert(
            header::HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    response
}

/// Middleware that adds a unique request ID to every response.
///
/// Generates a UUID v4 and sets it as the `X-Request-Id` response header.
/// If the client sends an `X-Request-Id` header, that value is preserved.
async fn request_id(request: Request, next: Next) -> Response {
    let incoming_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        // SECURITY (R31-SRV-6): Reject control characters (including TAB) in
        // client-supplied request IDs to prevent log injection attacks.
        .filter(|s| s.len() <= 128 && !s.chars().any(crate::routes::is_unsafe_char))
        .map(|s| s.to_string());

    let mut response = next.run(request).await;
    let id = incoming_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if let Ok(val) = HeaderValue::from_str(&id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), val);
    }
    response
}

/// Middleware that validates Origin/Referer headers on mutating requests.
///
/// This is a defense-in-depth CSRF protection layer. For state-changing requests
/// (POST, PUT, DELETE), we validate that the Origin or Referer header is present
/// and matches one of the allowed origins.
///
/// Validation rules:
/// - OPTIONS requests: skip (CORS preflight)
/// - GET/HEAD requests: skip (safe methods)
/// - POST/PUT/DELETE: require valid Origin or Referer
///
/// Origin matching:
/// - If `cors_origins` is empty: only localhost (127.0.0.1, ::1, localhost) allowed
/// - If `cors_origins` contains "*": any origin allowed (not recommended)
/// - Otherwise: origin must match one of the configured origins
async fn csrf_referer_check(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Skip validation for safe methods and CORS preflight
    let method = request.method().clone();
    if method == Method::OPTIONS || method == Method::GET || method == Method::HEAD {
        return next.run(request).await;
    }

    // For mutating methods, validate Origin or Referer
    let headers = request.headers();
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract origin from either header (prefer Origin, fall back to Referer)
    let request_origin = origin.or_else(|| {
        referer.and_then(|r| {
            // Extract origin from Referer URL (scheme + host + port)
            url::Url::parse(&r).ok().map(|u| {
                let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
                format!("{}://{}{}", u.scheme(), u.host_str().unwrap_or(""), port)
            })
        })
    });

    // Validate the origin
    let is_valid = match &request_origin {
        None => {
            // No origin header - this could be a same-origin request from the browser
            // or a direct API call. For defense-in-depth, we allow it but log.
            // The main CSRF protection is the API key requirement.
            tracing::debug!("CSRF check: no Origin/Referer header, allowing (API key required)");
            true
        }
        Some(origin) => validate_origin(origin, &state.cors_origins),
    };

    if !is_valid {
        tracing::warn!(
            origin = ?request_origin,
            method = %method,
            path = %request.uri().path(),
            "CSRF check failed: origin not allowed"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Origin not allowed",
                "code": "CSRF_ORIGIN_MISMATCH"
            })),
        )
            .into_response();
    }

    next.run(request).await
}

/// Validate that an origin is in the allowed list.
///
/// SECURITY (R33-001): This function avoids timing side-channels by always
/// checking all configured origins rather than returning early on match.
/// This prevents attackers from enumerating allowed origins via timing analysis.
fn validate_origin(origin: &str, allowed_origins: &[String]) -> bool {
    // SECURITY (R227-SRV-2): Explicitly reject the literal "null" origin.
    // Browsers send "Origin: null" from sandboxed iframes, data: URIs, and
    // cross-origin redirects. Previously rejected implicitly by URL parse
    // failure, but explicit rejection is more robust and testable.
    if origin == "null" {
        return false;
    }

    // Wildcard allows everything (not secret, can return early)
    if allowed_origins.iter().any(|o| o == "*") {
        return true;
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ParsedOrigin {
        scheme: String,
        host: String,
        port: u16,
    }

    fn parse_origin(input: &str) -> Option<ParsedOrigin> {
        // `Origin` header values are typically scheme://host[:port] with no trailing slash.
        // Accept both forms by retrying with a synthetic trailing slash when needed.
        let url = url::Url::parse(input).ok().or_else(|| {
            if input.ends_with('/') {
                None
            } else {
                let with_slash = format!("{input}/");
                url::Url::parse(&with_slash).ok()
            }
        })?;
        // SECURITY: Origin validation is only meaningful for HTTP(S).
        let scheme = url.scheme().to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return None;
        }
        // SECURITY: Reject userinfo-bearing origins explicitly.
        if !url.username().is_empty() || url.password().is_some() {
            return None;
        }
        let host = url.host_str()?.to_ascii_lowercase();
        let port = url.port_or_known_default()?;
        Some(ParsedOrigin { scheme, host, port })
    }

    fn is_localhost(origin: &ParsedOrigin) -> bool {
        matches!(
            origin.host.as_str(),
            "localhost" | "127.0.0.1" | "::1" | "[::1]" | "0:0:0:0:0:0:0:1"
        )
    }

    let parsed_origin = match parse_origin(origin) {
        Some(o) => o,
        None => return false,
    };

    // If no origins configured, only allow localhost (strict default)
    if allowed_origins.is_empty() {
        return is_localhost(&parsed_origin);
    }

    // SECURITY (R33-001): Iterate all origins without early return to prevent
    // a timing side-channel that could reveal the number of configured origins.
    // This is NOT constant-time comparison (origins are not secrets), but avoids
    // leaking the position of a matching origin in the list.
    let mut matched = false;
    for allowed in allowed_origins {
        if let Some(parsed_allowed) = parse_origin(allowed) {
            if parsed_origin == parsed_allowed {
                matched = true;
            }
        }
    }

    // SECURITY (FIND-R110-SRV-001): When allowed_origins is non-empty, only origins in the
    // explicit allowlist are permitted. The localhost fallback is intentionally NOT applied here:
    // if an operator has configured allowed_origins, localhost requests from unauthorized agents
    // must be blocked. Localhost-as-fallback only applies when no origins are configured (above).
    // Previously `matched || is_localhost(&parsed_origin)` allowed any localhost request to bypass
    // a non-empty allowlist — a CSRF bypass when deployed with an explicit origin allowlist.
    matched
}

/// Middleware that requires API key authentication.
///
/// **Public endpoints** (no auth required): `/health`, and all `OPTIONS` requests.
/// When `metrics_require_auth` is false, `/metrics` and `/api/metrics` are also public.
///
/// **All other endpoints** (including GET on `/api/policies`, `/api/audit/*`,
/// `/api/approvals/*`) require a valid `Bearer` token when `VELLAVETO_API_KEY`
/// is configured. This prevents unauthenticated access to sensitive policy
/// configurations, audit logs, and pending approvals (Finding #25).
///
/// If no API key is configured, all requests are allowed (development mode).
async fn require_api_key(State(state): State<AppState>, request: Request, next: Next) -> Response {
    // R230-SRV-4: Reject TRACE/CONNECT methods explicitly (defense in depth).
    // TRACE can reflect headers (XST attack, CVE-2004-2320); CONNECT is a
    // tunneling method that has no legitimate use in an API server.
    // Axum returns 405 for unrouted methods, but this catch is earlier
    // (before auth, rate limiting, or logging), reducing attack surface.
    let method = request.method().clone();
    if method == Method::TRACE || method == Method::CONNECT {
        return (StatusCode::METHOD_NOT_ALLOWED, "Method not allowed").into_response();
    }

    // SECURITY: Only skip auth for CORS preflight (OPTIONS).
    // HEAD requests MUST go through auth — they can reveal endpoint existence,
    // response sizes, and header values (R30-SRV-1).
    if method == Method::OPTIONS {
        return next.run(request).await;
    }

    // Public endpoints: always accessible without auth.
    let path = request.uri().path();
    if path == "/health" {
        return next.run(request).await;
    }

    // SECURITY (FIND-004): Metrics endpoint authentication is configurable.
    // When metrics_require_auth is false, /metrics and /api/metrics are public.
    // Default is true (auth required) for security — metrics expose policy counts
    // and pending approval counts (sensitive, per R26-SRV-6 and R38-SRV-1).
    if !state.metrics_require_auth && (path == "/metrics" || path == "/api/metrics") {
        return next.run(request).await;
    }

    // When RBAC JWT validation is enabled, authentication is enforced by the
    // RBAC middleware using Authorization: Bearer <jwt>. In that mode, API key
    // auth must not preempt JWT handling.
    // SECURITY (R228-SRV-1): Only pass through when the header actually contains
    // a Bearer token. Previously, ANY Authorization header value (even garbage)
    // would bypass API key auth, allowing unauthenticated access when RBAC JWT
    // validation had configuration gaps.
    if state.rbac_config.enabled && state.rbac_config.jwt_config.is_some() {
        if let Some(auth_val) = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            if auth_val.len() > 7 && auth_val[..7].eq_ignore_ascii_case("bearer ") {
                return next.run(request).await;
            }
        }
    }

    // Skip auth if no API key configured (development mode)
    let api_key = match &state.api_key {
        Some(key) => key.clone(),
        None => return next.run(request).await,
    };

    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match auth_header {
        // RFC 7235: Authorization scheme comparison is case-insensitive.
        Some(ref h) if h.len() > 7 && h[..7].eq_ignore_ascii_case("bearer ") => {
            // SECURITY (R259-SRV-1): Trim whitespace from token to prevent
            // hash mismatch when "Bearer  token" has extra spaces.
            let token = h[7..].trim();
            // SECURITY (R34-SRV-8): Hash before comparing to prevent length oracle.
            // ct_eq short-circuits on length mismatch; hashing normalizes to 32 bytes.
            use sha2::{Digest, Sha256};
            let token_hash = Sha256::digest(token.as_bytes());
            let key_hash = Sha256::digest(api_key.as_bytes());
            if token_hash.ct_eq(&key_hash).into() {
                next.run(request).await
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid API key"})),
                )
                    .into_response()
            }
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Authentication required"})),
        )
            .into_response(),
    }
}

// SECURITY (R26-SRV-6): Health response no longer leaks policy count.
// Policy count is operational metrics, not health status. Moved to
// the authenticated /api/metrics endpoint.
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<String>,
    /// Security scanning subsystem status (SEC-006).
    scanning: ScanningStatus,
    /// Leader election status (Phase 27). Omitted in standalone mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    leader_status: Option<vellaveto_types::LeaderStatus>,
    /// Instance identifier (Phase 27). Omitted in standalone mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,
    /// Number of discovered service endpoints (Phase 27). Omitted in standalone mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    discovered_endpoints: Option<usize>,
}

/// Status of security scanning subsystems.
#[derive(Serialize)]
struct ScanningStatus {
    /// Whether DLP (Data Loss Prevention) scanning is available.
    dlp_available: bool,
    /// Whether injection detection is available.
    injection_available: bool,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    // Check cluster backend health if configured
    let cluster_status = match state.cluster_health().await {
        Ok(()) => None,
        Err(msg) => {
            tracing::warn!("Cluster health check failed: {}", msg);
            Some(msg)
        }
    };

    // Check security scanning subsystem availability (SEC-006).
    let dlp_available = vellaveto_mcp::inspection::is_dlp_available();
    let injection_available = vellaveto_mcp::inspection::is_injection_available();
    let scanning = ScanningStatus {
        dlp_available,
        injection_available,
    };

    // Degraded if cluster is unhealthy or any security scanning is unavailable
    let status = if cluster_status.is_some() || !dlp_available || !injection_available {
        "degraded".to_string()
    } else {
        "ok".to_string()
    };

    // Phase 27: Deployment status (only populated when leader election / discovery is configured)
    // SECURITY (FIND-P27-001): Use cached values — never call discover() from /health.
    let leader_status = state.leader_election.as_ref().map(|le| le.current_status());
    let instance_id = if state.leader_election.is_some() || state.service_discovery.is_some() {
        Some(state.cached_instance_id.as_ref().clone())
    } else {
        None
    };
    let discovered_endpoints = if state.service_discovery.is_some() {
        Some(
            state
                .cached_discovered_endpoints
                .load(std::sync::atomic::Ordering::Relaxed) as usize,
        )
    } else {
        None
    };

    Json(HealthResponse {
        status,
        cluster: cluster_status,
        scanning,
        leader_status,
        instance_id,
        discovered_endpoints,
    })
}

/// Request body for the evaluate endpoint.
///
/// Accepts an action plus an optional evaluation context for context-aware
/// policy evaluation (time windows, call limits, agent identity, etc.).
///
/// # Security note (FIND-R110-SRV-003)
///
/// `#[serde(deny_unknown_fields)]` is intentionally omitted here.
/// `serde_json` does not support combining `deny_unknown_fields` with
/// `#[serde(flatten)]` — when both are present, the flattened fields from
/// `Action` are treated as unknown and the entire deserialization fails.
/// This is a known serde limitation tracked at <https://github.com/serde-rs/serde/issues/1358>.
///
/// Mitigation: `Action::validate()` is called on every request (see evaluate handler
/// below), which enforces structural invariants on the deserialized action. Unknown
/// top-level fields beyond `action` and `context` are silently ignored but cannot
/// influence policy evaluation.
#[derive(Deserialize)]
struct EvaluateRequest {
    #[serde(flatten)]
    action: Action,
    #[serde(default)]
    context: Option<EvaluationContext>,
    /// Optional simulated tool response for content inspection benchmarking.
    /// When present, the server runs injection and DLP scanners on this
    /// content and includes results in the response's `inspection` field.
    /// Used by MCPSEC benchmark to test the gateway's detection capabilities
    /// without requiring a live proxy connection.
    #[serde(default, rename = "_test_response")]
    test_response: Option<serde_json::Value>,
}

/// Query parameters for the evaluate endpoint.
/// IMPROVEMENT_PLAN 10.4: Add ?trace=true for OPA-style decision logging.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct EvaluateQuery {
    /// When true, return detailed evaluation trace with per-policy match info.
    #[serde(default)]
    trace: bool,
}

/// Content inspection results from injection and DLP scanning.
/// Only present when `_test_response` is provided in the request.
#[derive(Serialize)]
struct InspectionResults {
    injection_detected: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    injection_patterns: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dlp_findings: Vec<DlpFindingSummary>,
}

/// Summary of a DLP finding for the API response.
#[derive(Serialize)]
struct DlpFindingSummary {
    pattern_name: String,
    location: String,
}

#[derive(Serialize)]
struct EvaluateResponse {
    verdict: Verdict,
    action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_id: Option<String>,
    /// Detailed evaluation trace (only present when ?trace=true).
    #[serde(skip_serializing_if = "Option::is_none")]
    trace: Option<vellaveto_types::EvaluationTrace>,
    /// Content inspection results (only present when `_test_response` is provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    inspection: Option<InspectionResults>,
}

/// SECURITY (R31-SRV-1): Redact action parameters before returning in the evaluate
/// response. Parameters may contain secrets (API keys, credentials) that should not
/// be echoed back over the wire where intermediary proxies/logs could capture them.
/// The caller already knows the parameters they submitted.
fn redact_response_action(mut action: Action) -> Action {
    action.parameters = serde_json::Value::Object(Default::default());
    // SECURITY (R32-SRV-2): Also clear extracted targets — they contain
    // file paths and domains derived from parameters, leaking the same info.
    action.target_paths.clear();
    action.target_domains.clear();
    action.resolved_ips.clear();
    action
}

fn extract_presented_approval_id(
    headers: &HeaderMap,
) -> Result<Option<String>, (StatusCode, Json<ErrorResponse>)> {
    let Some(value) = headers.get(APPROVAL_ID_HEADER) else {
        return Ok(None);
    };

    let approval_id = value.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Approval ID header must be valid UTF-8".to_string(),
            }),
        )
    })?;

    super::approval::validate_approval_id(approval_id)?;
    Ok(Some(approval_id.to_string()))
}

async fn presented_approval_matches_action(
    state: &AppState,
    presented_approval_id: Option<&str>,
    action: &Action,
) -> Result<Option<String>, ()> {
    let Some(approval_id) = presented_approval_id else {
        return Ok(None);
    };

    let approval = match state.get_approval(approval_id).await {
        Ok(approval) => approval,
        Err(e) => {
            tracing::warn!(
                approval_id = %approval_id,
                error = ?e,
                "Presented approval lookup failed"
            );
            return Err(());
        }
    };

    if approval.status != ApprovalStatus::Approved {
        tracing::warn!(
            approval_id = %approval_id,
            status = ?approval.status,
            "Presented approval is not approved"
        );
        return Err(());
    }

    // Fail closed on approvals that predate action-fingerprint binding.
    if approval.action_fingerprint.is_none() {
        tracing::warn!(
            approval_id = %approval_id,
            "Presented approval missing action fingerprint binding"
        );
        return Err(());
    }

    let action_fingerprint = fingerprint_action(action);
    if !approval.scope_matches(None, Some(action_fingerprint.as_str())) {
        tracing::warn!(
            approval_id = %approval_id,
            "Presented approval scope does not match the current action"
        );
        return Err(());
    }

    Ok(Some(approval_id.to_string()))
}

/// QUALITY (FIND-GAP-010): Standard error response format.
///
/// All API endpoints in the Vellaveto server return errors as JSON objects
/// with an `error` field containing a human-readable message:
///
/// ```json
/// { "error": "description of what went wrong" }
/// ```
///
/// This convention is used consistently across all route modules (compliance,
/// governance, discovery, zk_audit, exec_graph, simulator, etc.). The HTTP
/// status code carries the machine-readable error category (400, 404, 500, etc.).
///
/// Standard error response body for Vellaveto REST API endpoints.
///
/// Returned as `Json<ErrorResponse>` alongside an HTTP status code (e.g., 400, 404, 500).
/// The `error` field carries a human-readable description of what went wrong. The HTTP
/// status code carries the machine-readable error category.
///
/// **Note:** The MCP JSON-RPC proxy layer (`vellaveto-http-proxy`) uses
/// JSON-RPC error format (`{ "jsonrpc": "2.0", "error": { "code": ..., "message": ... } }`)
/// for MCP protocol responses, which is a different convention dictated by the
/// MCP specification. The `ErrorResponse` struct is only for REST API endpoints.
#[derive(Serialize)]
pub struct ErrorResponse {
    /// Human-readable error description.
    pub error: String,
}

/// Auto-extract target_paths and target_domains from action parameters.
///
/// Scans string values in parameters for file paths (starting with `/`)
/// and URLs (starting with `http://` or `https://`), populating the
/// corresponding Action fields for path/domain policy enforcement.
fn auto_extract_targets(action: &mut Action) {
    scan_params_for_targets(
        &action.parameters,
        &mut action.target_paths,
        &mut action.target_domains,
    );
}

/// Maximum recursion depth for parameter scanning (defense-in-depth against stack overflow).
const MAX_PARAM_SCAN_DEPTH: usize = 32;

/// Maximum number of extracted paths + domains to prevent OOM from large parameter arrays.
const MAX_EXTRACTED_TARGETS: usize = 256;

pub fn scan_params_for_targets(
    value: &serde_json::Value,
    paths: &mut Vec<String>,
    domains: &mut Vec<String>,
) {
    scan_params_for_targets_inner(value, paths, domains, 0);
}

fn scan_params_for_targets_inner(
    value: &serde_json::Value,
    paths: &mut Vec<String>,
    domains: &mut Vec<String>,
    depth: usize,
) {
    if depth >= MAX_PARAM_SCAN_DEPTH {
        return;
    }
    if paths.len() + domains.len() >= MAX_EXTRACTED_TARGETS {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            let lower = s.to_lowercase();
            if let Some(lower_after_scheme) = lower.strip_prefix("file://") {
                // Preserve original path case for case-sensitive filesystems
                let after_scheme = &s[7..]; // skip "file://"
                                            // SECURITY (R32-SRV-3): Boundary check after "localhost" — must be
                                            // followed by '/' or end-of-string. Without this, file://localhost.evil.com
                                            // incorrectly strips "localhost" and extracts ".evil.com/path".
                                            // SECURITY (R33-SRV-2): Only extract paths from file://localhost/...
                                            // or file:///... (empty host). A file://remote-host/path reference
                                            // would silently discard the remote hostname and extract the path,
                                            // allowing policy bypass if the path matches an allowed pattern.
                let path_original = if lower_after_scheme == "localhost"
                    || lower_after_scheme.starts_with("localhost/")
                {
                    &after_scheme["localhost".len()..]
                } else if after_scheme.starts_with('/') {
                    after_scheme
                } else {
                    // Non-localhost, non-empty host — this is a remote file reference.
                    // Extract the hostname as a domain target instead of a path.
                    if let Some(slash_idx) = after_scheme.find('/') {
                        let host_part = &after_scheme[..slash_idx];
                        if !host_part.is_empty() {
                            domains.push(host_part.to_lowercase());
                        }
                    }
                    ""
                };
                // Strip query strings and fragments
                let file_path = strip_query_and_fragment(path_original);
                if !file_path.is_empty() {
                    // SECURITY (R29-SRV-2): Percent-decode file:// paths to prevent
                    // bypass via encoding (e.g., file:///etc/%70asswd → /etc/passwd).
                    // SECURITY (R245-SRV-4): Strict UTF-8 — skip malformed sequences.
                    if let Ok(decoded) =
                        percent_encoding::percent_decode_str(file_path).decode_utf8()
                    {
                        paths.push(decoded.into_owned());
                    }
                }
            } else if let Some(lower_scheme_end) = lower.find("://") {
                // SECURITY (R15-EVAL-15): Extract domains from all schemes
                // with authority (http, https, ftp, ssh, wss, ldap, etc.),
                // not just http/https. Otherwise ftp://evil.com/file bypasses
                // network rules that block evil.com.
                // SECURITY (R32-SRV-1): Use lower.find("://") instead of s.find("://")
                // for indexing into `lower`. Unicode case-folding can change byte length
                // (e.g., Turkish İ U+0130 → "i\u{0307}" changes from 2 to 3 bytes),
                // so byte offsets from `s` are invalid for `lower`.
                let scheme = &lower[..lower_scheme_end];
                // Only process if scheme looks valid (alphabetic, 1-10 chars)
                // SECURITY (R31-SRV-3): Skip data: URIs — they are inline content,
                // not network addresses. Extracting a "domain" from data: URIs
                // produces bogus entries (e.g., "text" from "data:text/plain,...").
                if !scheme.is_empty()
                    && scheme.len() <= 10
                    && scheme.chars().all(|c| c.is_ascii_alphabetic())
                    && scheme != "data"
                {
                    // SECURITY (R32-SRV-1): Use lower_scheme_end consistently.
                    // Since scheme is validated as all-ASCII, the byte offset is
                    // identical in both `s` and `lower`. Use `get()` for safety.
                    if let Some(authority) = s.get(lower_scheme_end + 3..) {
                        // SECURITY (R37-SRV-1): Normalize backslashes to forward slashes
                        // before splitting authority. Per the WHATWG URL Standard, `\` is
                        // treated as a path separator in special schemes (http, https, etc.).
                        // Without this, `http://evil.com\@allowed.com/path` would yield
                        // "evil.com\@allowed.com" as authority, and rfind('@') would then
                        // extract "allowed.com" — but the actual HTTP connection goes to
                        // evil.com.
                        let authority_normalized = authority.replace('\\', "/");
                        let host_raw = authority_normalized
                            .split('/')
                            .next()
                            .unwrap_or(&authority_normalized);
                        // SECURITY (R12-EXT-2): Percent-decode authority before splitting on '@'.
                        // Without this, http://evil.com%40blocked.com bypasses domain matching.
                        // SECURITY (R245-SRV-4): Strict UTF-8 — skip malformed authority.
                        if let Ok(decoded) =
                            percent_encoding::percent_decode_str(host_raw).decode_utf8()
                        {
                            let host = decoded.as_ref();
                            let host = host.split(':').next().unwrap_or(host);
                            let host = host.split('?').next().unwrap_or(host);
                            let host = host.split('#').next().unwrap_or(host);
                            let host = if let Some(pos) = host.rfind('@') {
                                &host[pos + 1..]
                            } else {
                                host
                            };
                            if !host.is_empty() {
                                domains.push(host.to_lowercase());
                            }
                        }
                    }
                }
            } else if s.starts_with('/') && !s.contains(' ') {
                // Strip query/fragments from raw paths
                let clean = strip_query_and_fragment(s);
                if !clean.is_empty() {
                    // SECURITY (R30-SRV-6): Percent-decode absolute paths for
                    // consistency with file:// URL handling (R29-SRV-2). Without
                    // this, /etc/%70asswd bypasses path policy checks.
                    // SECURITY (R245-SRV-4): Strict UTF-8 — skip malformed sequences.
                    if let Ok(decoded) = percent_encoding::percent_decode_str(clean).decode_utf8() {
                        paths.push(decoded.into_owned());
                    }
                }
            } else if looks_like_relative_path(s) {
                // SECURITY (R11-PATH-3): Catch relative paths containing ..
                // or starting with ~/ that would bypass extraction. Prepend /
                // so they are visible to path policy checks.
                let clean = strip_query_and_fragment(s);
                if !clean.is_empty() {
                    // SECURITY (R30-SRV-6): Percent-decode relative paths too.
                    // SECURITY (R245-SRV-4): Strict UTF-8 — skip malformed sequences.
                    if let Ok(decoded) = percent_encoding::percent_decode_str(clean).decode_utf8() {
                        paths.push(format!("/{decoded}"));
                    }
                }
            }
        }
        serde_json::Value::Object(map) => {
            for val in map.values() {
                scan_params_for_targets_inner(val, paths, domains, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for val in arr {
                scan_params_for_targets_inner(val, paths, domains, depth + 1);
            }
        }
        _ => {}
    }
}

/// Strip query string (`?...`) and fragment (`#...`) from a path.
fn strip_query_and_fragment(path: &str) -> &str {
    let path = path.split('?').next().unwrap_or(path);
    path.split('#').next().unwrap_or(path)
}

/// Detect relative paths that could bypass extraction.
///
/// Catches `../` traversal, `~/` home directory expansion, and `./` current
/// directory relative paths. These are not caught by the `starts_with('/')`
/// check for absolute paths but could be resolved by downstream tools.
fn looks_like_relative_path(s: &str) -> bool {
    if s.contains(' ') {
        return false; // Likely not a path
    }
    // SECURITY (R34-SRV-6): Percent-decode before checking to catch ..%2F evasion.
    // SECURITY (R245-SRV-4): Strict UTF-8 — treat malformed as non-path (return false).
    let decoded = match percent_encoding::percent_decode_str(s).decode_utf8() {
        Ok(d) => d,
        Err(_) => return false,
    };
    let d = decoded.as_ref();
    // Also normalize backslashes for Windows-style traversals.
    let d_normalized = d.replace('\\', "/");
    let d = &d_normalized;
    d.starts_with("../")
        || d.starts_with("./")
        || d.starts_with("~/")
        || d.contains("/../")
        || d == ".."
        || d == "~"
}

// FIND-R56-SRV-001: Removed private derive_resolver_identity duplicate.
// Use crate::routes::approval::derive_resolver_identity instead.

/// Negotiated TLS metadata carried from an upstream TLS terminator/reverse proxy.
///
/// Vellaveto currently receives plain HTTP at this hop in many deployments.
/// When a trusted edge proxy injects TLS details, we preserve them in audit and
/// observability metadata for forensic visibility.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NegotiatedTlsMetadata {
    protocol: Option<String>,
    cipher: Option<String>,
    kex_group: Option<String>,
}

impl NegotiatedTlsMetadata {
    fn is_empty(&self) -> bool {
        self.protocol.is_none() && self.cipher.is_none() && self.kex_group.is_none()
    }

    fn as_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        if let Some(ref protocol) = self.protocol {
            obj.insert("protocol".to_string(), json!(protocol));
        }
        if let Some(ref cipher) = self.cipher {
            obj.insert("cipher".to_string(), json!(cipher));
        }
        if let Some(ref kex_group) = self.kex_group {
            obj.insert("kex_group".to_string(), json!(kex_group));
        }
        serde_json::Value::Object(obj)
    }
}

/// Handle a failed audit write on a security-decision path.
///
/// SECURITY (FIND-005, parity restored by R269-SRV-1): `audit.strict_mode` is
/// documented as "audit logging failures cause requests to be denied instead of
/// proceeding without an audit trail … every decision must be recorded". The
/// evaluate handler honoured that on its final audit write but not on the six
/// registry and trust-level branches that return a verdict earlier, so a
/// deployment with strict mode on still served decisions it had failed to
/// record.
///
/// Scope, stated precisely: four of those branches return a `Deny` and two a
/// `RequireApproval`. None of the six can serve an `Allow` — the allow path
/// runs through the final audit write, which was already guarded. So this is
/// not an authorization bypass. What it breaks is the recording guarantee the
/// setting sells: denials that no auditor can see, and pending approvals
/// created with no record of why.
///
/// Routing every audit failure on the decision path through this one function
/// is what keeps the branches in step — parity by construction rather than by
/// six copies that have to be kept in sync.
///
/// Returns `Err` in strict mode so callers propagate a 503 with `?`; in
/// non-strict mode the failure is recorded and evaluation continues, which
/// preserves the documented default (fail-open for availability).
fn handle_decision_audit_failure(
    state: &AppState,
    error: &dyn std::fmt::Display,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    tracing::error!("AUDIT FAILURE: security decision not recorded: {}", error);
    state.metrics.record_error();

    if state.audit_strict_mode {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Audit logging failed — request denied (strict audit mode)".to_string(),
            }),
        ));
    }
    Ok(())
}

/// Build evaluate-route audit metadata, including optional TLS handshake details.
fn build_evaluate_audit_metadata(
    tenant_id: &str,
    tls_metadata: Option<&NegotiatedTlsMetadata>,
    extra: serde_json::Value,
) -> serde_json::Value {
    let mut metadata = json!({
        "source": "http",
        "tenant_id": tenant_id
    });

    if let Some(meta_obj) = metadata.as_object_mut() {
        if let Some(tls) = tls_metadata {
            meta_obj.insert("tls".to_string(), tls.as_json());
        }
        if let Some(extra_obj) = extra.as_object() {
            for (k, v) in extra_obj {
                meta_obj.insert(k.clone(), v.clone());
            }
        }
    }

    metadata
}

fn build_evaluate_acis_envelope(
    action: &Action,
    verdict: &Verdict,
    context: Option<&EvaluationContext>,
    tenant_id: &str,
    origin: DecisionOrigin,
    evaluation_us: u64,
) -> AcisDecisionEnvelope {
    build_acis_envelope(
        &uuid::Uuid::new_v4().to_string().replace('-', ""),
        action,
        verdict,
        origin,
        "http",
        &[],
        Some(evaluation_us),
        None,
        Some(tenant_id),
        context,
    )
}

fn build_evaluate_acis_envelope_with_security_context(
    action: &Action,
    verdict: &Verdict,
    context: Option<&EvaluationContext>,
    tenant_id: &str,
    origin: DecisionOrigin,
    evaluation_us: u64,
    security_context: Option<&RuntimeSecurityContext>,
) -> AcisDecisionEnvelope {
    build_acis_envelope_with_security_context(
        &uuid::Uuid::new_v4().to_string().replace('-', ""),
        action,
        verdict,
        origin,
        "http",
        &[],
        Some(evaluation_us),
        None,
        Some(tenant_id),
        context,
        security_context,
    )
}

fn approval_containment_context_from_envelope(
    envelope: &AcisDecisionEnvelope,
    reason: &str,
) -> Option<ApprovalContainmentContext> {
    let provenance_summary = review_safe_provenance_summary(envelope.client_provenance.as_ref());
    let context = ApprovalContainmentContext {
        semantic_taint: envelope.semantic_taint.clone(),
        lineage_channels: envelope
            .lineage_refs
            .iter()
            .map(|lineage| lineage.channel)
            .collect(),
        effective_trust_tier: envelope.effective_trust_tier,
        sink_class: envelope.sink_class,
        containment_mode: envelope.containment_mode,
        semantic_risk_score: envelope.semantic_risk_score,
        signature_status: provenance_summary.signature_status,
        client_key_id: provenance_summary.client_key_id,
        workload_binding_status: provenance_summary.workload_binding_status,
        replay_status: provenance_summary.replay_status,
        session_key_scope: provenance_summary.session_key_scope,
        session_scope_binding: provenance_summary.session_scope_binding,
        canonical_request_hash: provenance_summary.canonical_request_hash,
        execution_is_ephemeral: provenance_summary.execution_is_ephemeral,
        counterfactual_review_required: reason.contains("counterfactual review required"),
    }
    .normalized();

    context.is_meaningful().then_some(context)
}

fn contains_security_keyword(tool: &str, function: &str, keywords: &[&str]) -> bool {
    keywords
        .iter()
        .any(|keyword| tool.contains(keyword) || function.contains(keyword))
}

fn looks_like_mutating_action(tool: &str, function: &str) -> bool {
    contains_security_keyword(
        tool,
        function,
        &[
            "write", "edit", "update", "delete", "remove", "create", "append", "save", "set",
        ],
    )
}

fn looks_like_read_only_action(tool: &str, function: &str) -> bool {
    contains_security_keyword(
        tool,
        function,
        &["read", "list", "get", "fetch", "show", "view", "describe"],
    )
}

fn infer_action_sink_class(action: &Action) -> Option<SinkClass> {
    let tool = action.tool.to_ascii_lowercase();
    let function = action.function.to_ascii_lowercase();

    if action.tool == "resources" && action.function == "read" {
        return Some(SinkClass::ReadOnly);
    }
    if contains_security_keyword(&tool, &function, &["approval", "consent", "prompt"]) {
        return Some(SinkClass::ApprovalUi);
    }
    if contains_security_keyword(
        &tool,
        &function,
        &[
            "secret",
            "credential",
            "token",
            "password",
            "apikey",
            "api_key",
            "auth",
        ],
    ) {
        return Some(SinkClass::CredentialAccess);
    }
    if contains_security_keyword(
        &tool,
        &function,
        &["policy", "config", "rule", "governance"],
    ) {
        return Some(SinkClass::PolicyMutation);
    }
    if contains_security_keyword(&tool, &function, &["memory", "memo", "cache", "store"]) {
        return Some(SinkClass::MemoryWrite);
    }
    if contains_security_keyword(
        &tool,
        &function,
        &[
            "exec", "execute", "run", "shell", "bash", "python", "node", "script", "command",
            "spawn", "terminal",
        ],
    ) {
        return Some(SinkClass::CodeExecution);
    }
    if !action.target_domains.is_empty() {
        return Some(SinkClass::NetworkEgress);
    }
    if !action.target_paths.is_empty() {
        if looks_like_mutating_action(&tool, &function) {
            return Some(SinkClass::FilesystemWrite);
        }
        return Some(SinkClass::ReadOnly);
    }
    if looks_like_mutating_action(&tool, &function) {
        return Some(SinkClass::LowRiskWrite);
    }
    if looks_like_read_only_action(&tool, &function) {
        return Some(SinkClass::ReadOnly);
    }
    Some(SinkClass::LowRiskWrite)
}

fn build_server_approval_security_context(
    action: &Action,
    effective_trust_tier: Option<TrustTier>,
    semantic_taint: Vec<SemanticTaint>,
) -> Option<RuntimeSecurityContext> {
    let mut security_context = RuntimeSecurityContext {
        semantic_taint,
        effective_trust_tier,
        sink_class: infer_action_sink_class(action),
        containment_mode: Some(ContainmentMode::RequireApproval),
        ..RuntimeSecurityContext::default()
    };

    if let Some(sink_class) = security_context.sink_class {
        let semantic_risk = security_context.recommended_semantic_risk_score_for_sink(sink_class);
        security_context.merge_semantic_risk_score(semantic_risk);
        let counterfactual =
            security_context.recommended_counterfactual_attribution_score_for_sink(sink_class);
        security_context.merge_semantic_risk_score(counterfactual);
    }

    if security_context == RuntimeSecurityContext::default() {
        None
    } else {
        Some(security_context)
    }
}

fn is_valid_tls_metadata_token(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/'))
}

fn sanitize_tls_metadata_token(value: &str, max_len: usize) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > max_len
        || trimmed.chars().any(crate::routes::is_unsafe_char)
        || !is_valid_tls_metadata_token(trimmed)
    {
        return None;
    }
    Some(trimmed.to_string())
}

/// Extract a single header token and require consistency across duplicate header entries.
///
/// Returns:
/// - `Ok(None)`: header absent
/// - `Ok(Some(token))`: header present with one consistent, valid token value
/// - `Err(())`: header present but invalid or conflicting values were supplied
fn extract_consistent_header_token(
    headers: &HeaderMap,
    name: &str,
    max_len: usize,
) -> Result<Option<String>, ()> {
    let mut saw_any = false;
    let mut selected: Option<String> = None;
    for raw in headers.get_all(name) {
        saw_any = true;
        let raw = raw.to_str().map_err(|_| ())?;
        let token = sanitize_tls_metadata_token(raw, max_len).ok_or(())?;
        if let Some(ref existing) = selected {
            if existing != &token {
                return Err(());
            }
        } else {
            selected = Some(token);
        }
    }

    if !saw_any {
        Ok(None)
    } else {
        Ok(selected)
    }
}

fn extract_sanitized_header_token(
    headers: &HeaderMap,
    names: &[&str],
    max_len: usize,
) -> Option<String> {
    let mut selected: Option<String> = None;

    for name in names {
        match extract_consistent_header_token(headers, name, max_len) {
            Ok(None) => continue,
            // Invalid/ambiguous values for a lower-priority alias should not
            // clobber a valid higher-priority alias.
            Err(()) => continue,
            Ok(Some(token)) => {
                if let Some(ref existing) = selected {
                    // Conflicting aliases are ambiguous; drop the field.
                    if existing != &token {
                        return None;
                    }
                } else {
                    selected = Some(token);
                }
            }
        }
    }

    selected
}

/// Extract negotiated TLS metadata forwarded by reverse proxies.
///
/// Accepted header aliases (higher-priority names are preferred):
/// - protocol: `x-forwarded-tls-protocol`, `x-forwarded-tls-version`, `x-tls-protocol`, `x-tls-version`
/// - cipher: `x-forwarded-tls-cipher`, `x-tls-cipher`
/// - kex group: `x-forwarded-tls-kex-group`, `x-tls-kex-group`
///
/// For each field, duplicate header entries must agree. Conflicting duplicate
/// values or conflicting alias values are treated as ambiguous and the field is
/// dropped. Invalid higher-priority aliases do not block fallback to valid
/// lower-priority aliases.
fn extract_negotiated_tls_metadata(headers: &HeaderMap) -> Option<NegotiatedTlsMetadata> {
    let metadata = NegotiatedTlsMetadata {
        protocol: extract_sanitized_header_token(
            headers,
            &[
                "x-forwarded-tls-protocol",
                "x-forwarded-tls-version",
                "x-tls-protocol",
                "x-tls-version",
            ],
            32,
        ),
        cipher: extract_sanitized_header_token(
            headers,
            &["x-forwarded-tls-cipher", "x-tls-cipher"],
            96,
        ),
        kex_group: extract_sanitized_header_token(
            headers,
            &["x-forwarded-tls-kex-group", "x-tls-kex-group"],
            64,
        ),
    };
    if metadata.is_empty() {
        None
    } else {
        Some(metadata)
    }
}

/// Sanitize client-supplied evaluation context.
///
/// The server evaluate endpoint is a stateless API — it has no session tracking.
/// Clients cannot be trusted to provide their own `call_counts` or
/// `previous_actions` because they could lie to bypass MaxCalls or
/// RequirePreviousAction policies. These fields are stripped.
///
/// SECURITY (R20-AGENT-ID): When the request is authenticated with a Bearer
/// token, `agent_id` is derived from the token hash (matching the approval
/// endpoint's `derive_resolver_identity` pattern). This prevents a client
/// from spoofing another agent's identity to bypass agent_id-based policies.
/// Client-supplied agent_id is only preserved as a note appended to the
/// derived principal, or used as-is when no auth is configured.
fn sanitize_context(
    context: Option<EvaluationContext>,
    headers: &HeaderMap,
    tenant_id: Option<String>,
) -> Option<EvaluationContext> {
    /// Maximum agent_id length to prevent memory abuse via oversized identifiers.
    const MAX_AGENT_ID_LEN: usize = 256;
    context.map(|ctx| {
        // Derive agent_id from authenticated principal when available.
        let client_agent_id = ctx
            .agent_id
            .filter(|id| !id.is_empty() && id.len() <= MAX_AGENT_ID_LEN);

        let agent_id = if let Some(auth) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            if auth.len() > 7 && auth[..7].eq_ignore_ascii_case("bearer ") {
                let token = &auth[7..];
                if !token.is_empty() {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(token.as_bytes());
                    let principal = format!("bearer:{}", hex::encode(&hash[..16]));
                    // Append client-supplied agent_id as a note (not authoritative)
                    // SECURITY (R33-SRV-3): Strip control characters from client_id
                    // before embedding in agent_id string. Control chars could break
                    // log parsing or inject ANSI escape sequences.
                    Some(match client_agent_id {
                        Some(ref client_id) => {
                            let sanitized: String = client_id
                                .chars()
                                .filter(|c| !crate::routes::is_unsafe_char(*c))
                                .take(256)
                                .collect();
                            format!("{principal} (note: {sanitized})")
                        }
                        None => principal,
                    })
                } else {
                    client_agent_id
                }
            } else {
                client_agent_id
            }
        } else {
            // No auth header — accept client-supplied agent_id as-is
            client_agent_id
        };

        // SECURITY (R21-SRV-3): The stateless server does not trust transport-
        // supplied agent identity or capability tokens. Route both sensitive
        // fields through the shared fail-closed transport boundary.
        let agent_identity = project_agent_identity_from_transport(false, ctx.agent_identity);
        let capability_token = project_capability_token_from_transport(false, ctx.capability_token);

        EvaluationContext {
            // Override timestamp with server time — never trust client clocks
            timestamp: None,
            agent_id,
            agent_identity,
            // Strip session-state fields: the stateless server API has no session
            // tracking, so these must not be client-controlled
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            // Tenant ID is set by the tenant middleware, not client-controlled
            tenant_id,
            verification_tier: None,
            capability_token,
            session_state: None,
        }
    })
}

async fn apply_opa_runtime_verdict(
    action: &Action,
    context: Option<&EvaluationContext>,
    vellaveto_verdict: Verdict,
) -> (Verdict, Option<serde_json::Value>) {
    if !matches!(vellaveto_verdict, Verdict::Allow) {
        return (vellaveto_verdict, None);
    }

    let Some(opa_client) = crate::opa::runtime_client() else {
        return (vellaveto_verdict, None);
    };

    let opa_input = crate::opa::OpaInput {
        tool: action.tool.clone(),
        function: action.function.clone(),
        parameters: action.parameters.clone(),
        principal: context.and_then(|ctx| ctx.agent_id.clone()),
        session_id: None,
        context: json!({
            "tenant_id": context.and_then(|ctx| ctx.tenant_id.clone()),
            "target_paths": action.target_paths.clone(),
            "target_domains": action.target_domains.clone(),
            "resolved_ips": action.resolved_ips.clone(),
            "vellaveto_verdict": vellaveto_verdict.clone(),
        }),
    };

    let start = std::time::Instant::now();
    match opa_client.evaluate(&opa_input).await {
        Ok(decision) => {
            crate::metrics::record_opa_query(
                if decision.allow { "allow" } else { "deny" },
                start.elapsed().as_secs_f64(),
            );
            let metadata = json!({
                "result": if decision.allow { "allow" } else { "deny" },
                "reason": decision.reason,
                "metadata": decision.metadata,
            });

            if decision.allow {
                (vellaveto_verdict, Some(metadata))
            } else {
                (
                    Verdict::Deny {
                        reason: "Denied by OPA policy".to_string(),
                    },
                    Some(metadata),
                )
            }
        }
        Err(e) => {
            let err_msg = e.to_string();
            let result_label = if err_msg.contains("timed out") {
                "timeout"
            } else {
                "error"
            };
            crate::metrics::record_opa_query(result_label, start.elapsed().as_secs_f64());

            if opa_client.fail_open() {
                tracing::warn!("OPA evaluation failed in fail-open mode: {}", err_msg);
                (
                    vellaveto_verdict,
                    Some(json!({
                        "result": "error",
                        "fail_open": true,
                        "error": "OPA evaluation failed",
                    })),
                )
            } else {
                crate::metrics::increment_opa_fail_closed_denial();
                (
                    Verdict::Deny {
                        reason: "OPA evaluation failed (fail-closed)".to_string(),
                    },
                    Some(json!({
                        "result": "error",
                        "fail_open": false,
                        "error": "OPA evaluation failed",
                    })),
                )
            }
        }
    }
}

#[tracing::instrument(
    name = "vellaveto.policy_evaluation",
    skip(state, headers, req, proxy_ctx),
    fields(
        tool = %req.action.tool,
        function = %req.action.function,
        tenant_id = %tenant_ctx.tenant_id,
    )
)]
#[allow(deprecated)] // evaluate_action_with_context: migration tracked in FIND-CREATIVE-005
async fn evaluate(
    State(state): State<AppState>,
    Extension(tenant_ctx): Extension<TenantContext>,
    proxy_ctx: Option<Extension<TrustedProxyContext>>,
    Query(query): Query<EvaluateQuery>,
    headers: HeaderMap,
    Json(req): Json<EvaluateRequest>,
) -> Result<Json<EvaluateResponse>, (StatusCode, Json<ErrorResponse>)> {
    let eval_start = std::time::Instant::now();
    let mut action = req.action;
    let from_trusted_proxy = proxy_ctx
        .as_ref()
        .map(|Extension(ctx)| ctx.from_trusted_proxy)
        .unwrap_or(false);
    // SECURITY: Forwarded TLS metadata headers are only trusted when the direct
    // connection comes from a configured trusted proxy. Otherwise clients could
    // spoof handshake details (protocol/cipher/KEX) via plain headers.
    // Fail-safe behavior: missing proxy context is treated as untrusted.
    let tls_metadata = if from_trusted_proxy {
        extract_negotiated_tls_metadata(&headers)
    } else {
        if has_forwarded_tls_metadata_headers(&headers) {
            tracing::warn!("Ignoring forwarded TLS metadata headers from non-trusted connection");
            crate::metrics::increment_forwarded_header_rejections("tls_metadata");
        }
        None
    };

    // SECURITY (R10-1): Validate the deserialized action to catch null bytes,
    // oversized fields, and other malformed input before processing.
    if let Err(e) = action.validate() {
        // SECURITY (FIND-051): Don't leak internal state, but DO tell users
        // which field failed so they can fix their request. The ValidationError
        // variants only reference user-supplied field names (tool, function,
        // target_paths, parameters), not internal server details.
        // UX (UX-R110-001): "Invalid action" alone gave users no guidance.
        tracing::warn!("Action validation failed: {}", e);
        let hint = match &e {
            vellaveto_types::ValidationError::EmptyField { field } => {
                format!("The '{field}' field must not be empty")
            }
            vellaveto_types::ValidationError::TooLong { field, max, .. } => {
                format!("The '{field}' field exceeds the maximum length of {max} bytes")
            }
            vellaveto_types::ValidationError::NullByte { field }
            | vellaveto_types::ValidationError::ControlCharacter { field } => {
                format!("The '{field}' field contains invalid characters")
            }
            vellaveto_types::ValidationError::ParametersTooLarge { max, .. } => {
                format!("The 'parameters' payload is too large (max {max} bytes)")
            }
            vellaveto_types::ValidationError::TooManyTargets { max, .. } => {
                format!("Too many target_paths + target_domains entries (max {max})")
            }
            _ => "Check that tool, function, and parameters are well-formed".to_string(),
        };
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid action: {hint}"),
            }),
        ));
    }

    // SECURITY: Sanitize client-supplied context to prevent spoofing of
    // session-state fields (call_counts, previous_actions, timestamp).
    // R20-AGENT-ID: Derive agent_id from auth header when present.
    // SECURITY: Tenant ID is extracted by middleware, never client-supplied.
    let context = sanitize_context(req.context, &headers, Some(tenant_ctx.tenant_id.clone()));

    // SECURITY (R10-2): Always run auto-extraction from parameters,
    // ignoring client-supplied target_paths/target_domains. A malicious
    // client could supply crafted paths that bypass path policy checks,
    // so we clear them and re-extract from the actual parameters.
    // SECURITY (R22-SRV-1): Also clear resolved_ips — a client could supply
    // crafted IPs to bypass DNS rebinding / private-IP checks entirely.
    action.target_paths.clear();
    action.target_domains.clear();
    action.resolved_ips.clear();
    auto_extract_targets(&mut action);
    let presented_approval_id = extract_presented_approval_id(&headers)?;
    let mut gate_audit_metadata = serde_json::Map::new();
    let mut gate_approval_id: Option<String> = None;

    // SECURITY (R15-CFG-2): Single atomic load of engine + policies.
    // Previously two separate loads had a microsecond-wide race.
    let snap = state.policy_state.load();

    // Phase 44: Per-tenant evaluation rate limiting.
    // Enforces TenantQuotas.max_evaluations_per_minute. Default tenant (unlimited)
    // is skipped. Checked before engine evaluation to reject early.
    if let Some(ref quotas) = tenant_ctx.quotas {
        if let Some(_retry_after) = state
            .tenant_rate_limiter
            .check(&tenant_ctx.tenant_id, quotas.max_evaluations_per_minute)
        {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: "Tenant evaluation rate limit exceeded".to_string(),
                }),
            ));
        }
    }

    // Phase 50: Per-tenant evaluation quota reservation (metering).
    // Reserves one evaluation slot atomically before evaluation to prevent
    // race conditions under concurrent requests.
    if let Some(ref tracker) = state.usage_tracker {
        let tier = &state.billing_config.licensing_validation.tier;
        let tier_limit = tracker.limit_for_tier(tier);
        if let Err(reason) = tracker.check_evaluation_quota(&tenant_ctx.tenant_id, tier_limit) {
            // SECURITY (R239-SRV-13): Genericize — do not expose capacity details.
            tracing::warn!(tenant = %tenant_ctx.tenant_id, "Evaluation quota exceeded: {reason}");
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: "Evaluation quota exceeded".to_string(),
                }),
            ));
        }
    }

    let record_usage_outcome = |allowed: bool| {
        if let Some(ref tracker) = state.usage_tracker {
            tracker.record_evaluation_outcome(&tenant_ctx.tenant_id, allowed);
        }
    };
    let record_usage_deny = || record_usage_outcome(false);

    // Tool registry check: if enabled, unknown or untrusted tools require approval.
    // This runs BEFORE engine evaluation so that completely unknown tools are caught
    // even if no policy explicitly covers them (fail-closed).
    if let Some(ref registry) = state.tool_registry {
        let tool_name = &action.tool;
        let trust = registry.check_trust_level(tool_name).await;
        match trust {
            TrustLevel::Unknown => {
                // Unknown tool: register it and require approval
                registry.register_unknown(tool_name).await;
                match presented_approval_matches_action(
                    &state,
                    presented_approval_id.as_deref(),
                    &action,
                )
                .await
                {
                    Ok(Some(id)) => {
                        gate_audit_metadata.insert("registry".to_string(), json!("unknown_tool"));
                        gate_approval_id = Some(id);
                    }
                    Err(()) => {
                        let deny = Verdict::Deny {
                            reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                        };
                        record_usage_deny();
                        state.metrics.record_evaluation(&deny);
                        crate::metrics::record_evaluation_verdict("deny");
                        crate::metrics::record_evaluation_duration(
                            eval_start.elapsed().as_secs_f64(),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &deny,
                                build_evaluate_audit_metadata(
                                    &tenant_ctx.tenant_id,
                                    tls_metadata.as_ref(),
                                    json!({
                                        "registry": "unknown_tool",
                                        "approval_id": presented_approval_id,
                                    }),
                                ),
                                build_evaluate_acis_envelope(
                                    &action,
                                    &deny,
                                    context.as_ref(),
                                    &tenant_ctx.tenant_id,
                                    DecisionOrigin::TopologyGuard,
                                    eval_start.elapsed().as_micros() as u64,
                                ),
                            )
                            .await
                        {
                            handle_decision_audit_failure(&state, &e)?;
                        } else {
                            crate::metrics::increment_audit_entries();
                        }
                        return Ok(Json(EvaluateResponse {
                            verdict: deny,
                            action: redact_response_action(action),
                            approval_id: None,
                            trace: None,
                            inspection: None,
                        }));
                    }
                    Ok(None) => {
                        // SECURITY (R253-SRV-1): Genericize reason to prevent
                        // registry membership enumeration via API responses.
                        let reason = "Approval required".to_string();
                        let verdict = Verdict::RequireApproval {
                            reason: reason.clone(),
                        };
                        let approval_security_context = build_server_approval_security_context(
                            &action,
                            Some(TrustTier::Unknown),
                            vec![SemanticTaint::Untrusted],
                        );
                        let approval_envelope = build_evaluate_acis_envelope_with_security_context(
                            &action,
                            &verdict,
                            context.as_ref(),
                            &tenant_ctx.tenant_id,
                            DecisionOrigin::TopologyGuard,
                            eval_start.elapsed().as_micros() as u64,
                            approval_security_context.as_ref(),
                        );
                        let approval_context =
                            approval_containment_context_from_envelope(&approval_envelope, &reason);
                        // SECURITY (R30-SRV-3): Defer metrics recording until after
                        // approval creation — if creation fails, the final verdict is
                        // Deny, not RequireApproval. Recording both double-counts.

                        // Create pending approval if store available
                        let requester = crate::routes::approval::derive_resolver_identity(
                            &headers,
                            "anonymous",
                        );
                        let requested_by = if requester != "anonymous" {
                            Some(requester)
                        } else {
                            None
                        };
                        let approval_id = match state
                            .create_approval_with_context(
                                action.clone(),
                                reason,
                                requested_by,
                                None,
                                Some(fingerprint_action(&action)),
                                approval_context,
                            )
                            .await
                        {
                            Ok(id) => Some(id),
                            Err(e) => {
                                tracing::error!(
                                    "Failed to create approval for unknown tool (fail-closed → Deny): {:?}",
                                    e
                                );
                                let deny = Verdict::Deny {
                                    reason:
                                        "Unknown tool requires approval but could not be created"
                                            .to_string(),
                                };
                                record_usage_deny();
                                state.metrics.record_evaluation(&deny);
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &deny,
                                        build_evaluate_audit_metadata(
                                            &tenant_ctx.tenant_id,
                                            tls_metadata.as_ref(),
                                            json!({"registry": "unknown_tool"}),
                                        ),
                                        build_evaluate_acis_envelope(
                                            &action,
                                            &deny,
                                            context.as_ref(),
                                            &tenant_ctx.tenant_id,
                                            DecisionOrigin::TopologyGuard,
                                            eval_start.elapsed().as_micros() as u64,
                                        ),
                                    )
                                    .await
                                {
                                    handle_decision_audit_failure(&state, &e)?;
                                } else {
                                    crate::metrics::increment_audit_entries();
                                }
                                return Ok(Json(EvaluateResponse {
                                    verdict: deny,
                                    action: redact_response_action(action),
                                    approval_id: None,
                                    trace: None,
                                    inspection: None,
                                }));
                            }
                        };

                        // Record RequireApproval metrics only on success path
                        record_usage_deny();
                        state.metrics.record_evaluation(&verdict);
                        crate::metrics::record_evaluation_verdict("require_approval");
                        crate::metrics::record_evaluation_duration(
                            eval_start.elapsed().as_secs_f64(),
                        );

                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &verdict,
                                build_evaluate_audit_metadata(
                                    &tenant_ctx.tenant_id,
                                    tls_metadata.as_ref(),
                                    json!({"registry": "unknown_tool", "approval_id": approval_id}),
                                ),
                                approval_envelope,
                            )
                            .await
                        {
                            handle_decision_audit_failure(&state, &e)?;
                        } else {
                            crate::metrics::increment_audit_entries();
                        }
                        return Ok(Json(EvaluateResponse {
                            verdict,
                            action: redact_response_action(action),
                            approval_id,
                            trace: None,
                            inspection: None,
                        }));
                    }
                }
            }
            TrustLevel::Untrusted { score } => {
                match presented_approval_matches_action(
                    &state,
                    presented_approval_id.as_deref(),
                    &action,
                )
                .await
                {
                    Ok(Some(id)) => {
                        gate_audit_metadata.insert("registry".to_string(), json!("untrusted_tool"));
                        gate_approval_id = Some(id);
                    }
                    Err(()) => {
                        let deny = Verdict::Deny {
                            reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                        };
                        record_usage_deny();
                        state.metrics.record_evaluation(&deny);
                        crate::metrics::record_evaluation_verdict("deny");
                        crate::metrics::record_evaluation_duration(
                            eval_start.elapsed().as_secs_f64(),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &deny,
                                build_evaluate_audit_metadata(
                                    &tenant_ctx.tenant_id,
                                    tls_metadata.as_ref(),
                                    json!({
                                        "registry": "untrusted_tool",
                                        "approval_id": presented_approval_id,
                                    }),
                                ),
                                build_evaluate_acis_envelope(
                                    &action,
                                    &deny,
                                    context.as_ref(),
                                    &tenant_ctx.tenant_id,
                                    DecisionOrigin::TopologyGuard,
                                    eval_start.elapsed().as_micros() as u64,
                                ),
                            )
                            .await
                        {
                            handle_decision_audit_failure(&state, &e)?;
                        } else {
                            crate::metrics::increment_audit_entries();
                        }
                        return Ok(Json(EvaluateResponse {
                            verdict: deny,
                            action: redact_response_action(action),
                            approval_id: None,
                            trace: None,
                            inspection: None,
                        }));
                    }
                    Ok(None) => {
                        // SECURITY (R253-SRV-1): Genericize reason to prevent
                        // trust score enumeration via API responses. The numeric
                        // score is logged server-side only.
                        tracing::info!(
                            tool = %tool_name,
                            score = score,
                            "Tool trust score below threshold — requires approval"
                        );
                        let reason = "Approval required".to_string();
                        let verdict = Verdict::RequireApproval {
                            reason: reason.clone(),
                        };
                        let approval_security_context = build_server_approval_security_context(
                            &action,
                            Some(TrustTier::Untrusted),
                            vec![SemanticTaint::Untrusted],
                        );
                        let approval_envelope = build_evaluate_acis_envelope_with_security_context(
                            &action,
                            &verdict,
                            context.as_ref(),
                            &tenant_ctx.tenant_id,
                            DecisionOrigin::TopologyGuard,
                            eval_start.elapsed().as_micros() as u64,
                            approval_security_context.as_ref(),
                        );
                        let approval_context =
                            approval_containment_context_from_envelope(&approval_envelope, &reason);
                        // SECURITY (R30-SRV-3): Defer metrics until after approval creation

                        let requester = crate::routes::approval::derive_resolver_identity(
                            &headers,
                            "anonymous",
                        );
                        let requested_by = if requester != "anonymous" {
                            Some(requester)
                        } else {
                            None
                        };
                        let approval_id = match state
                            .create_approval_with_context(
                                action.clone(),
                                reason,
                                requested_by,
                                None,
                                Some(fingerprint_action(&action)),
                                approval_context,
                            )
                            .await
                        {
                            Ok(id) => Some(id),
                            Err(e) => {
                                tracing::error!(
                                    "Failed to create approval for untrusted tool (fail-closed → Deny): {:?}",
                                    e
                                );
                                let deny = Verdict::Deny {
                                    reason:
                                        "Untrusted tool requires approval but could not be created"
                                            .to_string(),
                                };
                                record_usage_deny();
                                state.metrics.record_evaluation(&deny);
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &deny,
                                        build_evaluate_audit_metadata(
                                            &tenant_ctx.tenant_id,
                                            tls_metadata.as_ref(),
                                            json!({"registry": "untrusted_tool"}),
                                        ),
                                        build_evaluate_acis_envelope(
                                            &action,
                                            &deny,
                                            context.as_ref(),
                                            &tenant_ctx.tenant_id,
                                            DecisionOrigin::TopologyGuard,
                                            eval_start.elapsed().as_micros() as u64,
                                        ),
                                    )
                                    .await
                                {
                                    handle_decision_audit_failure(&state, &e)?;
                                } else {
                                    crate::metrics::increment_audit_entries();
                                }
                                return Ok(Json(EvaluateResponse {
                                    verdict: deny,
                                    action: redact_response_action(action),
                                    approval_id: None,
                                    trace: None,
                                    inspection: None,
                                }));
                            }
                        };

                        // Record RequireApproval metrics only on success path
                        record_usage_deny();
                        state.metrics.record_evaluation(&verdict);
                        crate::metrics::record_evaluation_verdict("require_approval");
                        crate::metrics::record_evaluation_duration(
                            eval_start.elapsed().as_secs_f64(),
                        );

                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &verdict,
                                build_evaluate_audit_metadata(
                                    &tenant_ctx.tenant_id,
                                    tls_metadata.as_ref(),
                                    json!({"registry": "untrusted_tool", "approval_id": approval_id}),
                                ),
                                approval_envelope,
                            )
                            .await
                        {
                            handle_decision_audit_failure(&state, &e)?;
                        } else {
                            crate::metrics::increment_audit_entries();
                        }
                        return Ok(Json(EvaluateResponse {
                            verdict,
                            action: redact_response_action(action),
                            approval_id,
                            trace: None,
                            inspection: None,
                        }));
                    }
                }
            }
            TrustLevel::Trusted => {
                // Trusted — proceed to engine evaluation
            }
        }
    }

    // Phase 44: Filter policies to only those visible to this tenant.
    // Default tenant sees all policies (unlimited access for backwards compatibility).
    // Named tenants only see their own namespaced + global + legacy policies.
    let tenant_policies: Vec<vellaveto_types::Policy> = if tenant_ctx.is_default() {
        snap.policies.clone()
    } else {
        snap.policies
            .iter()
            .filter(|p| tenant_ctx.policy_matches(&p.id))
            .cloned()
            .collect()
    };

    // IMPROVEMENT_PLAN 10.4: Support ?trace=true for OPA-style decision logging.
    // When trace is requested, we use the traced evaluation path which returns
    // per-policy match details along with the verdict.
    let (verdict, eval_trace) = if query.trace {
        // Phase 44: Build a temporary engine with tenant-filtered policies for tracing.
        // Trace is diagnostic-only (not hot path), so compilation cost is acceptable.
        let trace_engine = vellaveto_engine::PolicyEngine::with_policies(
            snap.engine.strict_mode(),
            &tenant_policies,
        )
        .map_err(|e| {
            tracing::error!(
                "Failed to compile tenant-filtered policies for trace: {:?}",
                e
            );
            record_usage_deny();
            state.metrics.record_error();
            crate::metrics::record_evaluation_verdict("error");
            crate::metrics::record_evaluation_duration(eval_start.elapsed().as_secs_f64());
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Policy evaluation failed".to_string(),
                }),
            )
        })?;
        trace_engine
            .evaluate_action_traced_with_context(&action, context.as_ref())
            .map(|(v, t)| (v, Some(t)))
            .map_err(|e| {
                tracing::error!("Engine evaluation error: {}", e);
                record_usage_deny();
                state.metrics.record_error();
                crate::metrics::record_evaluation_verdict("error");
                crate::metrics::record_evaluation_duration(eval_start.elapsed().as_secs_f64());
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Policy evaluation failed".to_string(),
                    }),
                )
            })?
    } else {
        // SECURITY (FIND-CREATIVE-001): For non-default tenants, build a tenant-scoped
        // engine rather than using snap.engine (which was compiled with ALL tenants'
        // policies). The compiled engine's evaluate_action_with_context() ignores
        // the `policies` parameter on the compiled path, so passing tenant_policies
        // is insufficient — a scoped engine is required for correct tenant isolation.
        // Default tenant uses the pre-compiled engine for maximum performance.
        let v = if !tenant_ctx.is_default() {
            let scoped_engine = vellaveto_engine::PolicyEngine::with_policies(
                snap.engine.strict_mode(),
                &tenant_policies,
            )
            .map_err(|e| {
                tracing::error!("Failed to compile tenant-scoped policies: {:?}", e);
                record_usage_deny();
                state.metrics.record_error();
                crate::metrics::record_evaluation_verdict("error");
                crate::metrics::record_evaluation_duration(eval_start.elapsed().as_secs_f64());
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Policy evaluation failed".to_string(),
                    }),
                )
            })?;
            scoped_engine
                .evaluate_action_with_context(&action, &tenant_policies, context.as_ref())
                .map_err(|e| {
                    tracing::error!("Engine evaluation error: {}", e);
                    record_usage_deny();
                    state.metrics.record_error();
                    crate::metrics::record_evaluation_verdict("error");
                    crate::metrics::record_evaluation_duration(eval_start.elapsed().as_secs_f64());
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Policy evaluation failed".to_string(),
                        }),
                    )
                })?
        } else {
            snap.engine
                .evaluate_action_with_context(&action, &tenant_policies, context.as_ref())
                .map_err(|e| {
                    tracing::error!("Engine evaluation error: {}", e);
                    record_usage_deny();
                    state.metrics.record_error();
                    crate::metrics::record_evaluation_verdict("error");
                    crate::metrics::record_evaluation_duration(eval_start.elapsed().as_secs_f64());
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "Policy evaluation failed".to_string(),
                        }),
                    )
                })?
        };
        (v, None)
    };

    let (verdict, opa_metadata) =
        apply_opa_runtime_verdict(&action, context.as_ref(), verdict).await;
    let mut acis_origin = match &verdict {
        Verdict::Allow | Verdict::Deny { .. } => DecisionOrigin::PolicyEngine,
        Verdict::RequireApproval { .. } => DecisionOrigin::ApprovalGate,
        _ => DecisionOrigin::PolicyEngine,
    };
    let mut approval_security_context: Option<RuntimeSecurityContext> = None;

    // If RequireApproval, create a pending approval.
    // Fail-closed: if approval creation fails, convert to Deny so the caller
    // can't proceed without a resolvable approval_id.
    let (mut verdict, mut approval_id) = if let Verdict::RequireApproval { ref reason } = verdict {
        if let Some(id) = gate_approval_id.clone() {
            (Verdict::Allow, Some(id))
        } else {
            match presented_approval_matches_action(
                &state,
                presented_approval_id.as_deref(),
                &action,
            )
            .await
            {
                Ok(Some(id)) => {
                    acis_origin = DecisionOrigin::ApprovalGate;
                    (Verdict::Allow, Some(id))
                }
                Err(()) => {
                    acis_origin = DecisionOrigin::ApprovalGate;
                    (
                        Verdict::Deny {
                            reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                        },
                        None,
                    )
                }
                Ok(None) => {
                    let derived_security_context =
                        build_server_approval_security_context(&action, None, Vec::new());
                    let approval_envelope = build_evaluate_acis_envelope_with_security_context(
                        &action,
                        &verdict,
                        context.as_ref(),
                        &tenant_ctx.tenant_id,
                        DecisionOrigin::ApprovalGate,
                        eval_start.elapsed().as_micros() as u64,
                        derived_security_context.as_ref(),
                    );
                    let approval_context =
                        approval_containment_context_from_envelope(&approval_envelope, reason);
                    // SECURITY (R9-2): Record the requester identity so the approval endpoint
                    // can enforce separation of privilege (different principal must approve).
                    let requester =
                        crate::routes::approval::derive_resolver_identity(&headers, "anonymous");
                    let requested_by = if requester != "anonymous" {
                        Some(requester)
                    } else {
                        None
                    };
                    match state
                        .create_approval_with_context(
                            action.clone(),
                            reason.clone(),
                            requested_by,
                            None,
                            Some(fingerprint_action(&action)),
                            approval_context,
                        )
                        .await
                    {
                        Ok(id) => {
                            acis_origin = DecisionOrigin::ApprovalGate;
                            approval_security_context = derived_security_context;
                            (verdict, Some(id))
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to create approval (fail-closed → Deny): {:?}",
                                e
                            );
                            let deny_reason =
                                "Approval required but could not be created".to_string();
                            acis_origin = DecisionOrigin::ApprovalGate;
                            (
                                Verdict::Deny {
                                    reason: deny_reason,
                                },
                                None,
                            )
                        }
                    }
                }
            }
        }
    } else if matches!(verdict, Verdict::Allow) {
        if gate_approval_id.is_some() {
            acis_origin = DecisionOrigin::ApprovalGate;
        }
        (verdict, gate_approval_id.clone())
    } else {
        (verdict, None)
    };

    if matches!(verdict, Verdict::Allow) {
        if let Some(ref approval_id_to_consume) = approval_id {
            let action_fingerprint = fingerprint_action(&action);
            match state
                .consume_approved_approval(
                    approval_id_to_consume,
                    None,
                    Some(action_fingerprint.as_str()),
                )
                .await
            {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    tracing::warn!(
                        approval_id = %approval_id_to_consume,
                        "Presented approval could not be consumed for this action"
                    );
                    acis_origin = DecisionOrigin::ApprovalGate;
                    verdict = Verdict::Deny {
                        reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                    };
                    approval_id = None;
                }
            }
        }
    }
    let audit_approval_id = if matches!(verdict, Verdict::Allow) {
        approval_id.clone()
    } else {
        approval_id
            .clone()
            .or(gate_approval_id.clone())
            .or(presented_approval_id.clone())
    };

    // Record metrics (both internal AtomicU64 and Prometheus)
    state.metrics.record_evaluation(&verdict);

    // Phase 50: Record evaluation in usage tracker for metering.
    record_usage_outcome(matches!(verdict, Verdict::Allow));

    let verdict_label = match &verdict {
        Verdict::Allow => "allow",
        Verdict::Deny { .. } => "deny",
        Verdict::RequireApproval { .. } => "require_approval",
        // Handle future variants — Verdict is #[non_exhaustive]
        _ => "unknown",
    };
    crate::metrics::record_evaluation_verdict(verdict_label);
    crate::metrics::record_evaluation_duration(eval_start.elapsed().as_secs_f64());

    // Record tool call in registry on Allow (for trust score tracking)
    if matches!(verdict, Verdict::Allow) {
        if let Some(ref registry) = state.tool_registry {
            registry.record_call(&action.tool).await;
        }
    }

    // Log to audit.
    // SECURITY (R16-AUDIT-3): Log at error level (not warn) because a silent
    // audit failure means security decisions proceed without an audit trail.
    // SECURITY (FIND-005): In strict audit mode, audit failures block the request.
    let mut audit_metadata = build_evaluate_audit_metadata(
        &tenant_ctx.tenant_id,
        tls_metadata.as_ref(),
        json!({ "approval_id": audit_approval_id }),
    );
    if let Some(obj) = audit_metadata.as_object_mut() {
        obj.extend(gate_audit_metadata);
    }
    if let Some(opa) = opa_metadata {
        if let Some(obj) = audit_metadata.as_object_mut() {
            obj.insert("opa".to_string(), opa);
        }
    }
    let acis_envelope = build_evaluate_acis_envelope_with_security_context(
        &action,
        &verdict,
        context.as_ref(),
        &tenant_ctx.tenant_id,
        acis_origin,
        eval_start.elapsed().as_micros() as u64,
        approval_security_context.as_ref(),
    );

    if let Err(e) = state
        .audit
        .log_entry_with_acis(&action, &verdict, audit_metadata, acis_envelope)
        .await
    {
        // SECURITY (FIND-005): Strict audit mode — fail-closed if audit fails,
        // so no unaudited security decision can be served. Shared with the six
        // earlier-returning branches; see handle_decision_audit_failure.
        handle_decision_audit_failure(&state, &e)?;
    } else {
        crate::metrics::increment_audit_entries();
    }

    // Phase 47: Staging shadow evaluation (non-blocking, non-verdict-affecting).
    // When a policy version is in Staging state, the staging engine evaluates
    // the same action and logs divergences for comparison. This runs AFTER the
    // active verdict is finalized and audit-logged, so it never affects latency
    // or correctness of the active evaluation path.
    if let Some(ref staging) = **state.staging_snapshot.load() {
        let staging_verdict = staging
            .engine
            .evaluate_action_with_context(&action, &staging.policies, context.as_ref())
            .unwrap_or(Verdict::Deny {
                reason: "staging evaluation error".to_string(),
            });
        let active_label = match &verdict {
            Verdict::Allow => "allow",
            Verdict::Deny { .. } => "deny",
            Verdict::RequireApproval { .. } => "require_approval",
            // Verdict is #[non_exhaustive] — fail-closed for unknown variants
            _ => "unknown",
        };
        let staging_label = match &staging_verdict {
            Verdict::Allow => "allow",
            Verdict::Deny { .. } => "deny",
            Verdict::RequireApproval { .. } => "require_approval",
            // Verdict is #[non_exhaustive] — fail-closed for unknown variants
            _ => "unknown",
        };
        if active_label != staging_label {
            tracing::info!(
                "Policy lifecycle staging divergence: tool={} function={} active={} staging={}",
                action.tool,
                action.function,
                active_label,
                staging_label
            );
        }
    }
    // Phase 15: Submit observability span if enabled
    #[cfg(feature = "observability-exporters")]
    if let Some(ref obs) = state.observability {
        // Extract trace context from incoming request
        let trace_ctx = headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .and_then(TraceContext::parse_traceparent);

        // Generate trace ID (use incoming or create new)
        let trace_id = trace_ctx
            .as_ref()
            .and_then(|ctx| ctx.trace_id.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string().replace("-", ""));

        let duration_ms = eval_start.elapsed().as_millis() as u64;
        let now = chrono::Utc::now();
        let start_time = (now - chrono::Duration::milliseconds(duration_ms as i64)).to_rfc3339();
        let end_time = now.to_rfc3339();

        let mut builder = SecuritySpan::builder(trace_id, SpanKind::Policy)
            .name(format!("policy.evaluate/{}", action.tool))
            .start_time(start_time)
            .end_time(end_time)
            .duration_ms(duration_ms)
            .action_from(&action)
            .verdict_from(&verdict)
            .attribute("tenant_id", json!(tenant_ctx.tenant_id));

        // Phase 28: Add agent identity attributes for GenAI semantic conventions
        if let Some(ref eval_context) = context {
            if let Some(ref agent_id) = eval_context.agent_id {
                builder = builder.attribute("gen_ai.agent.id", json!(agent_id));
            }
        }

        // Set parent span if provided
        if let Some(ref ctx) = trace_ctx {
            if let Some(ref parent) = ctx.parent_span_id {
                builder = builder.parent_span_id(parent.clone());
            }
        }

        // Add approval info if present
        if let Some(ref id) = audit_approval_id {
            builder = builder.attribute("approval_id", json!(id));
        }
        if let Some(ref tls) = tls_metadata {
            if let Some(ref protocol) = tls.protocol {
                builder = builder.attribute("tls.protocol", json!(protocol));
            }
            if let Some(ref cipher) = tls.cipher {
                builder = builder.attribute("tls.cipher", json!(cipher));
            }
            if let Some(ref kex_group) = tls.kex_group {
                builder = builder.attribute("tls.kex_group", json!(kex_group));
            }
        }

        if let Some(span) = builder.build() {
            obs.submit(span);
        }
    }

    // MCPSEC benchmark support: when `_test_response` is provided, run injection
    // and DLP scanners on the simulated tool response content. This lets external
    // benchmarks test the gateway's detection capabilities through the evaluate API.
    let inspection = if let Some(ref test_response) = req.test_response {
        // Wrap as MCP result structure for scanner compatibility.
        // The scanners expect {"result": {"content": [...]}} format.
        let as_result = json!({"result": test_response});

        // Injection scanning
        let mut injection_patterns: Vec<String> =
            vellaveto_mcp::inspection::scan_response_for_injection(&as_result)
                .into_iter()
                .map(String::from)
                .collect();

        // Also scan error field at top level if present (MCP error responses)
        if let Some(error) = test_response.get("error") {
            let as_error = json!({"error": error});
            injection_patterns.extend(
                vellaveto_mcp::inspection::scan_response_for_injection(&as_error)
                    .into_iter()
                    .map(String::from),
            );
        }

        let injection_detected = !injection_patterns.is_empty();

        // DLP scanning — structured response scanner for raw secrets
        let mut dlp_findings: Vec<DlpFindingSummary> =
            vellaveto_mcp::inspection::scan_response_for_secrets(&as_result)
                .into_iter()
                .map(|f| DlpFindingSummary {
                    pattern_name: f.pattern_name,
                    location: f.location,
                })
                .collect();

        // Multi-layer decode DLP: scan_parameters_for_secrets recursively decodes
        // base64, percent-encoding, etc. before matching. This catches encoded secrets
        // that scan_response_for_secrets misses (e.g., base64-wrapped tokens).
        dlp_findings.extend(
            vellaveto_mcp::inspection::scan_parameters_for_secrets(test_response)
                .into_iter()
                .map(|f| DlpFindingSummary {
                    pattern_name: f.pattern_name,
                    location: f.location,
                }),
        );

        // Also scan error field for DLP
        if let Some(error) = test_response.get("error") {
            let as_error = json!({"error": error});
            dlp_findings.extend(
                vellaveto_mcp::inspection::scan_response_for_secrets(&as_error)
                    .into_iter()
                    .map(|f| DlpFindingSummary {
                        pattern_name: f.pattern_name,
                        location: f.location,
                    }),
            );
        }

        // Deduplicate DLP findings (same pattern found by both scanners)
        dlp_findings.sort_by(|a, b| a.pattern_name.cmp(&b.pattern_name));
        dlp_findings.dedup_by(|a, b| a.pattern_name == b.pattern_name && a.location == b.location);

        Some(InspectionResults {
            injection_detected,
            injection_patterns,
            dlp_findings,
        })
    } else {
        None
    };

    Ok(Json(EvaluateResponse {
        verdict,
        action: redact_response_action(action),
        approval_id,
        trace: eval_trace,
        inspection,
    }))
}

// === Prometheus Metrics Endpoint ===

/// Serve Prometheus text exposition format metrics.
///
/// SECURITY (R38-SRV-1/R38-SRV-2): This endpoint is behind auth and rate
/// limiting because it exposes `vellaveto_policies_loaded` and pending approval
/// counts, which are security-sensitive (see R26-SRV-6). Prometheus scrapers
/// must provide a valid API key via Bearer token.
async fn prometheus_metrics(State(state): State<AppState>) -> Response {
    match &state.prometheus_handle {
        Some(handle) => {
            // Update dynamic gauges before rendering
            let policy_count = state.policy_state.load().policies.len();
            crate::metrics::set_policies_loaded(policy_count as f64);
            crate::metrics::set_uptime_seconds(state.metrics.start_time.elapsed().as_secs_f64());
            let pending_count = state.pending_approval_count().await.unwrap_or(0);
            crate::metrics::set_active_sessions(pending_count as f64);

            let body = handle.render();
            ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// === JSON Metrics Endpoint ===

async fn metrics_json(State(state): State<AppState>) -> Json<serde_json::Value> {
    let m = &state.metrics;
    let uptime = m.start_time.elapsed();
    Json(json!({
        "uptime_seconds": uptime.as_secs(),
        "policies_loaded": state.policy_state.load().policies.len(),
        "evaluations": {
            "total": m.evaluations_total.load(Ordering::SeqCst),
            "allow": m.evaluations_allow.load(Ordering::SeqCst),
            "deny": m.evaluations_deny.load(Ordering::SeqCst),
            "require_approval": m.evaluations_require_approval.load(Ordering::SeqCst),
            "error": m.evaluations_error.load(Ordering::SeqCst),
        },
        "scanning": {
            "dlp": {
                "available": vellaveto_mcp::inspection::is_dlp_available(),
                "pattern_count": vellaveto_mcp::inspection::active_pattern_count(),
            },
            "injection": {
                "available": vellaveto_mcp::inspection::is_injection_available(),
                "pattern_count": vellaveto_mcp::inspection::injection_pattern_count(),
            },
        }
    }))
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 3.1: Security Manager Admin API Handlers
// ═══════════════════════════════════════════════════════════════════════════

/// Middleware that enforces per-category rate limits.
///
/// Categories:
/// - **evaluate**: POST /api/evaluate
/// - **admin**: All other non-GET/OPTIONS requests (policy changes, approvals)
/// - **readonly**: GET requests (health, audit, policy listing)
///
/// The `/health` endpoint is always exempt from rate limiting so that
/// load balancer probes are never throttled.
///
/// Returns 429 Too Many Requests with a `Retry-After` header when exceeded.
async fn rate_limit(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let mut request = request;

    // Health endpoint is exempt — load balancer probes must never be throttled
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }

    // SECURITY: Mark whether this request came from a trusted proxy before any
    // handlers inspect forwarded headers.
    let from_trusted_proxy = is_connection_from_trusted_proxy(&request, &state.trusted_proxies);
    request
        .extensions_mut()
        .insert(TrustedProxyContext { from_trusted_proxy });

    // Per-IP rate limiting (checked before global to catch single-IP floods)
    if let Some(ref per_ip) = state.rate_limits.per_ip {
        let client_ip = extract_client_ip(&request, &state.trusted_proxies);
        if let Some(retry_after) = per_ip.check(client_ip) {
            crate::metrics::increment_rate_limit_rejections();
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after.to_string())],
                Json(json!({"error": "Rate limit exceeded. Try again later."})),
            )
                .into_response();
        }
    }

    // Per-principal rate limiting (keyed by X-Principal header, Bearer token, or client IP)
    if let Some(ref per_principal) = state.rate_limits.per_principal {
        let principal_key = extract_principal_key(&request, &state.trusted_proxies);
        if let Some(retry_after) = per_principal.check(principal_key) {
            crate::metrics::increment_rate_limit_rejections();
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after.to_string())],
                Json(json!({"error": "Rate limit exceeded. Try again later."})),
            )
                .into_response();
        }
    }

    // Global per-category rate limiting
    let limiter = categorize_rate_limit(&state.rate_limits, request.method(), request.uri().path());

    if let Some(limiter) = limiter {
        if let Err(not_until) = limiter.check() {
            let wait = not_until.wait_time_from(governor::clock::DefaultClock::default().now());
            let retry_after = wait.as_secs().max(1);
            crate::metrics::increment_rate_limit_rejections();
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after.to_string())],
                Json(json!({"error": "Rate limit exceeded. Try again later."})),
            )
                .into_response();
        }
    }

    next.run(request).await
}

#[derive(Debug, Clone, Copy)]
struct TrustedProxyContext {
    from_trusted_proxy: bool,
}

fn has_forwarded_tls_metadata_headers(headers: &HeaderMap) -> bool {
    [
        "x-forwarded-tls-protocol",
        "x-forwarded-tls-version",
        "x-tls-protocol",
        "x-tls-version",
        "x-forwarded-tls-cipher",
        "x-tls-cipher",
        "x-forwarded-tls-kex-group",
        "x-tls-kex-group",
    ]
    .iter()
    .any(|name| headers.contains_key(*name))
}

fn connection_ip_from_request(request: &Request) -> std::net::IpAddr {
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

fn is_connection_from_trusted_proxy(
    request: &Request,
    trusted_proxies: &[std::net::IpAddr],
) -> bool {
    if trusted_proxies.is_empty() {
        return false;
    }
    trusted_proxies.contains(&connection_ip_from_request(request))
}

/// Extract the client IP from the request using a secure trust model.
///
/// **When `trusted_proxies` is empty (default):** Proxy headers (`X-Forwarded-For`,
/// `X-Real-IP`) are ignored entirely. The connection IP from `ConnectInfo` is used,
/// falling back to 127.0.0.1 in test environments without real connections.
/// This prevents spoofing attacks where clients set arbitrary proxy headers.
///
/// **When `trusted_proxies` is configured:** The **rightmost untrusted** IP from the
/// `X-Forwarded-For` chain is used (RFC 7239). This is the last entry NOT in the
/// trusted proxy list. The leftmost entry is always attacker-controlled and must
/// never be used directly.
fn extract_client_ip(request: &Request, trusted_proxies: &[std::net::IpAddr]) -> std::net::IpAddr {
    // Get the real TCP connection IP from ConnectInfo (set by axum when using
    // into_make_service_with_connect_info). Falls back to localhost in tests.
    let connection_ip = connection_ip_from_request(request);

    // If no trusted proxies configured, never trust proxy headers.
    // This is the safe default that prevents XFF spoofing.
    if trusted_proxies.is_empty() {
        return connection_ip;
    }

    // Only trust proxy headers if the direct connection comes from a trusted proxy.
    if !trusted_proxies.contains(&connection_ip) {
        return connection_ip;
    }

    // SECURITY (R33-SRV-1): Use get_all() to collect ALL X-Forwarded-For headers,
    // not just the first. An attacker behind a trusted proxy can send multiple XFF
    // headers; .get() only reads the first, allowing the attacker to inject a spoofed
    // IP in a second header that the proxy appended to the first.
    // Combine all headers into a single comma-separated string before parsing.
    let xff_values: Vec<&str> = request
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if !xff_values.is_empty() {
        let combined = xff_values.join(",");
        // Walk from right to left, skipping trusted proxy IPs.
        for entry in combined.rsplit(',') {
            if let Ok(ip) = entry.trim().parse::<std::net::IpAddr>() {
                if !trusted_proxies.contains(&ip) {
                    return ip;
                }
            }
        }
    }

    // Fall back to X-Real-IP if set by a trusted proxy
    if let Some(xri) = request.headers().get("x-real-ip") {
        if let Ok(val) = xri.to_str() {
            if let Ok(ip) = val.trim().parse::<std::net::IpAddr>() {
                return ip;
            }
        }
    }

    // All XFF entries were trusted proxies — use connection IP
    connection_ip
}

/// Extract the principal key from the request for per-principal rate limiting.
///
/// Resolution order:
/// 1. `X-Principal` header — only trusted from connections originating from a
///    configured trusted proxy IP. When `trusted_proxies` is empty, X-Principal
///    is ignored entirely to prevent spoofing (KL1 hardening).
/// 2. Bearer token from the `Authorization` header — hashed with SHA-256 to
///    prevent raw token leakage in rate limit logs/maps (KL1 hardening).
/// 3. Client IP address as a string — fallback for unauthenticated requests.
///
/// Rate limiting runs BEFORE `require_api_key` (outermost middleware),
/// so the Bearer token may not yet be validated when this is called.
fn extract_principal_key(request: &Request, trusted_proxies: &[std::net::IpAddr]) -> String {
    /// Maximum X-Principal header length to prevent memory abuse in rate-limit maps.
    const MAX_PRINCIPAL_LEN: usize = 256;

    // SECURITY (R226-SRV-2, R228-SRV-5): Include tenant_id in rate limit key to
    // prevent cross-tenant collision, but ONLY from trusted proxies. An unauthenticated
    // client could forge X-Tenant-ID to create arbitrary rate-limit buckets, escaping
    // per-IP rate limits or DoS-ing other tenants' buckets.
    let tenant_prefix = if is_connection_from_trusted_proxy(request, trusted_proxies) {
        request
            .headers()
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .filter(|t| {
                !t.is_empty()
                    && t.len() <= MAX_PRINCIPAL_LEN
                    && !t.chars().any(crate::routes::is_unsafe_char)
            })
            .map(|t| format!("t:{t}|"))
            .unwrap_or_default()
    } else {
        String::new()
    };

    // 1. X-Principal header — only trust from known proxies (KL1)
    if is_connection_from_trusted_proxy(request, trusted_proxies) {
        if let Some(principal) = request
            .headers()
            .get("x-principal")
            .and_then(|v| v.to_str().ok())
        {
            if !principal.is_empty()
                && principal.len() <= MAX_PRINCIPAL_LEN
                && !principal.chars().any(crate::routes::is_unsafe_char)
            {
                return format!("{tenant_prefix}principal:{principal}");
            }
        }
    }

    // 2. Bearer token from Authorization header — hashed for privacy (KL1)
    if let Some(auth) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = auth
            .get(7..)
            .map(|t| t.trim())
            .filter(|_| auth.len() > 7 && auth[..7].eq_ignore_ascii_case("bearer "))
        {
            if !token.is_empty() {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(token.as_bytes());
                // 128-bit truncation is sufficient for rate limit bucketing
                return format!("{}bearer:{}", tenant_prefix, hex::encode(&hash[..16]));
            }
        }
    }

    // 3. Fallback to client IP
    let client_ip = extract_client_ip(request, trusted_proxies);
    format!("{tenant_prefix}ip:{client_ip}")
}

fn categorize_rate_limit<'a>(
    limits: &'a crate::RateLimits,
    method: &Method,
    path: &str,
) -> Option<&'a governor::DefaultDirectRateLimiter> {
    // Check for endpoint-specific limits first (takes priority)
    if let Some(limiter) = limits.get_endpoint_limiter(path) {
        return Some(limiter);
    }

    // SECURITY (R41-SRV-4): Match any method for /api/evaluate, not just POST.
    // The rate limit middleware runs before routing, so a PUT /api/evaluate
    // would be categorized as "admin" instead of "evaluate", bypassing
    // tighter evaluate limits when admin_rps > evaluate_rps.
    if path == "/api/evaluate" {
        limits.evaluate.as_ref()
    } else if method != Method::GET && method != Method::OPTIONS && method != Method::HEAD {
        limits.admin.as_ref()
    } else {
        limits.readonly.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    use std::collections::HashMap;
    use vellaveto_types::{AgentIdentity, CapabilityGrant, CapabilityToken};

    /// Helper to build a request with specific headers for testing extract_principal_key.
    fn build_request(headers: &[(&str, &str)]) -> Request {
        let mut builder = HttpRequest::builder().uri("/api/evaluate").method("POST");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn test_extract_negotiated_tls_metadata_from_forwarded_headers() {
        let request = build_request(&[
            ("x-forwarded-tls-version", "TLSv1.3"),
            ("x-forwarded-tls-cipher", "TLS_AES_256_GCM_SHA384"),
            ("x-forwarded-tls-kex-group", "X25519MLKEM768"),
        ]);
        let metadata = extract_negotiated_tls_metadata(request.headers())
            .expect("expected tls metadata from forwarded headers");
        assert_eq!(metadata.protocol.as_deref(), Some("TLSv1.3"));
        assert_eq!(metadata.cipher.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
        assert_eq!(metadata.kex_group.as_deref(), Some("X25519MLKEM768"));
    }

    #[test]
    fn test_extract_negotiated_tls_metadata_accepts_alias_headers() {
        let request = build_request(&[
            ("x-tls-protocol", "TLSv1.2"),
            ("x-tls-cipher", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
            ("x-tls-kex-group", "secp256r1"),
        ]);
        let metadata = extract_negotiated_tls_metadata(request.headers())
            .expect("expected tls metadata from alias headers");
        assert_eq!(metadata.protocol.as_deref(), Some("TLSv1.2"));
        assert_eq!(
            metadata.cipher.as_deref(),
            Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        );
        assert_eq!(metadata.kex_group.as_deref(), Some("secp256r1"));
    }

    #[test]
    fn test_extract_negotiated_tls_metadata_rejects_invalid_tokens() {
        let request = build_request(&[
            ("x-forwarded-tls-version", "TLSv1.3"),
            ("x-forwarded-tls-cipher", "TLS_AES_256_GCM_SHA384;DROP"),
        ]);
        let metadata = extract_negotiated_tls_metadata(request.headers())
            .expect("valid protocol should still produce metadata");
        assert_eq!(metadata.protocol.as_deref(), Some("TLSv1.3"));
        assert!(
            metadata.cipher.is_none(),
            "cipher with invalid token characters must be ignored"
        );
        assert!(metadata.kex_group.is_none());
    }

    #[test]
    fn test_extract_negotiated_tls_metadata_accepts_identical_duplicate_values() {
        let request = build_request(&[
            ("x-forwarded-tls-version", "TLSv1.3"),
            ("x-forwarded-tls-version", "TLSv1.3"),
            ("x-forwarded-tls-cipher", "TLS_AES_256_GCM_SHA384"),
            ("x-forwarded-tls-cipher", "TLS_AES_256_GCM_SHA384"),
        ]);
        let metadata = extract_negotiated_tls_metadata(request.headers())
            .expect("expected tls metadata from identical duplicate headers");
        assert_eq!(metadata.protocol.as_deref(), Some("TLSv1.3"));
        assert_eq!(metadata.cipher.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
    }

    #[test]
    fn test_extract_negotiated_tls_metadata_rejects_conflicting_duplicate_values() {
        let request = build_request(&[
            ("x-forwarded-tls-version", "TLSv1.3"),
            ("x-forwarded-tls-version", "TLSv1.2"),
        ]);
        assert!(
            extract_negotiated_tls_metadata(request.headers()).is_none(),
            "conflicting duplicate protocol headers must be rejected"
        );
    }

    #[test]
    fn test_extract_negotiated_tls_metadata_rejects_conflicting_alias_values() {
        let request = build_request(&[
            ("x-forwarded-tls-version", "TLSv1.3"),
            ("x-tls-protocol", "TLSv1.2"),
            ("x-forwarded-tls-cipher", "TLS_AES_256_GCM_SHA384"),
        ]);
        let metadata = extract_negotiated_tls_metadata(request.headers())
            .expect("cipher should preserve non-empty metadata object");
        assert!(
            metadata.protocol.is_none(),
            "conflicting protocol aliases must clear protocol field"
        );
        assert_eq!(metadata.cipher.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
    }

    #[test]
    fn test_extract_negotiated_tls_metadata_invalid_primary_alias_falls_back() {
        let request = build_request(&[
            ("x-forwarded-tls-version", "TLSv1.3;BAD"),
            ("x-tls-protocol", "TLSv1.2"),
        ]);
        let metadata = extract_negotiated_tls_metadata(request.headers())
            .expect("valid fallback alias should provide protocol metadata");
        assert_eq!(metadata.protocol.as_deref(), Some("TLSv1.2"));
    }

    #[test]
    fn test_extract_presented_approval_id_accepts_valid_header() {
        let request = build_request(&[(APPROVAL_ID_HEADER, "apr-123")]);
        let approval_id = extract_presented_approval_id(request.headers());
        assert!(approval_id.is_ok());
        assert_eq!(
            approval_id.ok().and_then(|value| value),
            Some("apr-123".to_string())
        );
    }

    #[test]
    fn test_extract_presented_approval_id_rejects_invalid_utf8_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            APPROVAL_ID_HEADER,
            axum::http::HeaderValue::from_bytes(b"\xFF").expect("opaque header value"),
        );

        let err = extract_presented_approval_id(&headers).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("valid UTF-8"));
    }

    #[test]
    fn test_extract_presented_approval_id_rejects_invalid_characters() {
        let request = build_request(&[(APPROVAL_ID_HEADER, "apr\tbad")]);
        let err = extract_presented_approval_id(request.headers()).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("invalid characters"));
    }

    #[test]
    fn test_is_connection_from_trusted_proxy_requires_config() {
        let request = build_request(&[]);
        assert!(
            !is_connection_from_trusted_proxy(&request, &[]),
            "empty trusted_proxies must not trust forwarded headers"
        );
    }

    #[test]
    fn test_is_connection_from_trusted_proxy_matches_direct_peer() {
        let request = build_request(&[]);
        let trusted = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        assert!(is_connection_from_trusted_proxy(&request, &trusted));
    }

    #[test]
    fn test_is_connection_from_trusted_proxy_rejects_untrusted_peer() {
        let request = build_request(&[]);
        let trusted = vec!["10.0.0.1".parse().unwrap()];
        assert!(!is_connection_from_trusted_proxy(&request, &trusted));
    }

    // --- KL1: X-Principal only trusted from trusted proxies ---

    #[test]
    fn test_principal_key_x_principal_ignored_without_trusted_proxies() {
        // With empty trusted_proxies, X-Principal header should be ignored
        let request = build_request(&[("x-principal", "alice")]);
        let key = extract_principal_key(&request, &[]);
        // Should fall through to IP fallback, not use X-Principal
        assert!(key.starts_with("ip:"), "Expected ip: prefix, got: {key}");
    }

    #[test]
    fn test_principal_key_x_principal_trusted_from_known_proxy() {
        // With trusted_proxies and connection from a trusted IP, X-Principal is accepted
        let trusted = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        let request = build_request(&[("x-principal", "alice")]);
        // In test environment, connection IP defaults to 127.0.0.1 (LOCALHOST)
        let key = extract_principal_key(&request, &trusted);
        assert_eq!(key, "principal:alice");
    }

    #[test]
    fn test_principal_key_x_principal_trusted_with_xff_chain() {
        // Even when XFF resolves to a non-proxy client IP, trust decision for
        // X-Principal must be based on direct peer proxy trust.
        let trusted = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        let request = build_request(&[
            ("x-principal", "alice"),
            ("x-forwarded-for", "203.0.113.10, 127.0.0.1"),
        ]);
        let key = extract_principal_key(&request, &trusted);
        assert_eq!(key, "principal:alice");
    }

    #[test]
    fn test_principal_key_x_principal_ignored_from_untrusted_ip() {
        // Trusted proxies configured but connection IP is not in the list
        let trusted = vec!["10.0.0.1".parse().unwrap()];
        let request = build_request(&[("x-principal", "alice")]);
        // Connection IP is 127.0.0.1 (test default), not in trusted list
        let key = extract_principal_key(&request, &trusted);
        assert!(
            !key.starts_with("principal:"),
            "X-Principal should be ignored from untrusted IP, got: {key}"
        );
    }

    // --- KL1: Bearer token hashed ---

    #[test]
    fn test_principal_key_bearer_token_hashed() {
        let request = build_request(&[("authorization", "Bearer my-secret-token")]);
        let key = extract_principal_key(&request, &[]);
        assert!(
            key.starts_with("bearer:"),
            "Expected bearer: prefix, got: {key}"
        );
        // Must NOT contain the raw token
        assert!(
            !key.contains("my-secret-token"),
            "Raw token should not appear in key: {key}"
        );
        // Hash should be 32 hex chars (128 bits = 16 bytes)
        let hash_part = key.strip_prefix("bearer:").unwrap();
        assert_eq!(hash_part.len(), 32, "Hash should be 32 hex chars");
    }

    #[test]
    fn test_principal_key_bearer_hash_deterministic() {
        let r1 = build_request(&[("authorization", "Bearer token-abc")]);
        let r2 = build_request(&[("authorization", "Bearer token-abc")]);
        let k1 = extract_principal_key(&r1, &[]);
        let k2 = extract_principal_key(&r2, &[]);
        assert_eq!(k1, k2, "Same token should produce same key");
    }

    #[test]
    fn test_principal_key_different_tokens_different_hashes() {
        let r1 = build_request(&[("authorization", "Bearer token-a")]);
        let r2 = build_request(&[("authorization", "Bearer token-b")]);
        let k1 = extract_principal_key(&r1, &[]);
        let k2 = extract_principal_key(&r2, &[]);
        assert_ne!(k1, k2, "Different tokens should produce different keys");
    }

    // R259-SRV-1: Bearer token with extra whitespace should produce same hash
    #[test]
    fn test_principal_key_bearer_whitespace_trimmed() {
        let r1 = build_request(&[("authorization", "Bearer token-abc")]);
        let r2 = build_request(&[("authorization", "Bearer  token-abc")]);
        let r3 = build_request(&[("authorization", "Bearer token-abc ")]);
        let k1 = extract_principal_key(&r1, &[]);
        let k2 = extract_principal_key(&r2, &[]);
        let k3 = extract_principal_key(&r3, &[]);
        assert_eq!(k1, k2, "Leading whitespace after Bearer should be trimmed");
        assert_eq!(k1, k3, "Trailing whitespace should be trimmed");
    }

    // --- KL1: IP fallback ---

    #[test]
    fn test_principal_key_fallback_to_ip() {
        let request = build_request(&[]);
        let key = extract_principal_key(&request, &[]);
        assert!(key.starts_with("ip:"), "Should fall back to IP, got: {key}");
    }

    // --- Context sanitization tests ---

    #[test]
    fn test_sanitize_context_none_stays_none() {
        let headers = HeaderMap::new();
        assert!(sanitize_context(None, &headers, None).is_none());
    }

    #[test]
    fn test_sanitize_context_strips_call_counts_and_history() {
        let headers = HeaderMap::new();
        let mut call_counts = std::collections::HashMap::new();
        call_counts.insert("read_file".to_string(), 99);
        let spoofed = EvaluationContext {
            timestamp: Some("2026-01-01T00:00:00Z".to_string()),
            agent_id: Some("agent-a".to_string()),
            agent_identity: None,
            call_counts,
            previous_actions: vec!["login".to_string(), "auth".to_string()],
            call_chain: Vec::new(),
            tenant_id: None,
            verification_tier: None,
            capability_token: None,
            session_state: None,
        };
        let sanitized = sanitize_context(Some(spoofed), &headers, None).unwrap();
        // agent_id preserved (no auth header)
        assert_eq!(sanitized.agent_id, Some("agent-a".to_string()));
        // Session-state fields stripped
        assert!(sanitized.call_counts.is_empty());
        assert!(sanitized.previous_actions.is_empty());
        // Timestamp overridden (set to None = server will use wall clock)
        assert!(sanitized.timestamp.is_none());
    }

    #[test]
    fn test_sanitize_context_preserves_agent_id_without_auth() {
        let headers = HeaderMap::new();
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some("my-agent".to_string()),
            agent_identity: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
            verification_tier: None,
            capability_token: None,
            session_state: None,
        };
        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();
        assert_eq!(sanitized.agent_id, Some("my-agent".to_string()));
    }

    /// SECURITY (R20-AGENT-ID): When a Bearer token is present, agent_id
    /// must be derived from the token hash, not accepted from the client.
    #[test]
    fn test_sanitize_context_derives_agent_id_from_auth() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer my-secret-key".parse().unwrap(),
        );
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some("spoofed-agent".to_string()),
            agent_identity: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
            verification_tier: None,
            capability_token: None,
            session_state: None,
        };
        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();
        let agent_id = sanitized.agent_id.unwrap();
        assert!(
            agent_id.starts_with("bearer:"),
            "agent_id should be derived from token hash, got: {agent_id}"
        );
        assert!(
            agent_id.contains("(note: spoofed-agent)"),
            "Client agent_id should appear as note, got: {agent_id}"
        );
    }

    /// SECURITY (R20-AGENT-ID): Without client agent_id, auth-derived only.
    #[test]
    fn test_sanitize_context_derives_agent_id_from_auth_no_client() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer my-secret-key".parse().unwrap(),
        );
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: None,
            agent_identity: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
            verification_tier: None,
            capability_token: None,
            session_state: None,
        };
        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();
        let agent_id = sanitized.agent_id.unwrap();
        assert!(
            agent_id.starts_with("bearer:"),
            "agent_id should be derived from token hash, got: {agent_id}"
        );
        assert!(
            !agent_id.contains("note:"),
            "No note when no client agent_id"
        );
    }

    #[test]
    fn test_sanitize_context_rejects_oversized_agent_id() {
        let headers = HeaderMap::new();
        let oversized_id = "a".repeat(257);
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some(oversized_id),
            agent_identity: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
            verification_tier: None,
            capability_token: None,
            session_state: None,
        };
        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();
        assert!(
            sanitized.agent_id.is_none(),
            "Agent ID > 256 bytes should be rejected"
        );
    }

    #[test]
    fn test_sanitize_context_allows_max_length_agent_id() {
        let headers = HeaderMap::new();
        let max_id = "b".repeat(256);
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some(max_id.clone()),
            agent_identity: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
            verification_tier: None,
            capability_token: None,
            session_state: None,
        };
        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();
        assert_eq!(sanitized.agent_id, Some(max_id));
    }

    #[test]
    fn test_sanitize_context_rejects_empty_agent_id() {
        let headers = HeaderMap::new();
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some("".to_string()),
            agent_identity: None,
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
            verification_tier: None,
            capability_token: None,
            session_state: None,
        };
        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();
        assert!(
            sanitized.agent_id.is_none(),
            "Empty agent_id should be rejected"
        );
    }

    fn sample_agent_identity() -> AgentIdentity {
        AgentIdentity {
            claims: HashMap::new(),
            issuer: Some("issuer.example".to_string()),
            subject: Some("agent-http".to_string()),
            audience: vec!["vellaveto".to_string()],
        }
    }

    fn sample_capability_token() -> CapabilityToken {
        CapabilityToken {
            token_id: "token-http".to_string(),
            parent_token_id: None,
            issuer: "issuer-1".to_string(),
            holder: "holder-1".to_string(),
            grants: vec![CapabilityGrant {
                tool_pattern: "file_system".to_string(),
                function_pattern: "read_file".to_string(),
                allowed_paths: vec!["/tmp/*".to_string()],
                allowed_domains: Vec::new(),
                max_invocations: 1,
            }],
            remaining_depth: 1,
            issued_at: "2026-03-08T00:00:00Z".to_string(),
            expires_at: "2026-03-09T00:00:00Z".to_string(),
            signature: "deadbeef".to_string(),
            issuer_public_key: "feedface".to_string(),
        }
    }

    #[test]
    fn test_sanitize_context_strips_untrusted_identity_and_capability_token() {
        let headers = HeaderMap::new();
        let ctx = EvaluationContext {
            timestamp: None,
            agent_id: Some("agent-a".to_string()),
            agent_identity: Some(sample_agent_identity()),
            call_counts: std::collections::HashMap::new(),
            previous_actions: Vec::new(),
            call_chain: Vec::new(),
            tenant_id: None,
            verification_tier: None,
            capability_token: Some(sample_capability_token()),
            session_state: None,
        };

        let sanitized = sanitize_context(Some(ctx), &headers, None).unwrap();

        assert!(sanitized.agent_identity.is_none());
        assert!(sanitized.capability_token.is_none());
    }

    #[test]
    fn test_principal_key_rejects_oversized_x_principal() {
        let oversized = "x".repeat(257);
        let trusted = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        let request = build_request(&[("x-principal", &oversized)]);
        let key = extract_principal_key(&request, &trusted);
        assert!(
            !key.starts_with("principal:"),
            "Oversized X-Principal should be ignored"
        );
    }

    #[test]
    fn test_principal_key_allows_max_length_x_principal() {
        let max_principal = "y".repeat(256);
        let trusted = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        let request = build_request(&[("x-principal", &max_principal)]);
        let key = extract_principal_key(&request, &trusted);
        assert_eq!(key, format!("principal:{max_principal}"));
    }

    #[test]
    fn test_principal_key_rejects_control_chars_in_x_principal() {
        let trusted = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        let request = build_request(&[("x-principal", "alice\tadmin")]);
        let key = extract_principal_key(&request, &trusted);
        assert!(
            !key.starts_with("principal:"),
            "X-Principal containing control characters should be ignored"
        );
    }

    // --- R11-PATH-3: Relative path detection ---

    #[test]
    fn test_looks_like_relative_path_traversal() {
        assert!(looks_like_relative_path("../etc/passwd"));
        assert!(looks_like_relative_path("./config.json"));
        assert!(looks_like_relative_path("~/secret.txt"));
        assert!(looks_like_relative_path("foo/../bar"));
        assert!(looks_like_relative_path(".."));
        assert!(looks_like_relative_path("~"));
    }

    #[test]
    fn test_looks_like_relative_path_rejects_non_paths() {
        assert!(!looks_like_relative_path("some normal text"));
        assert!(!looks_like_relative_path("/absolute/path"));
        assert!(!looks_like_relative_path("filename.txt"));
        assert!(!looks_like_relative_path(""));
        assert!(!looks_like_relative_path("hello world ../foo"));
    }

    // --- R11-APPR-4: Resolver identity from auth headers ---

    #[test]
    fn test_derive_resolver_identity_with_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer my-secret-token".parse().unwrap(),
        );
        let result = crate::routes::approval::derive_resolver_identity(&headers, "anonymous");
        assert!(
            result.starts_with("bearer:"),
            "Expected bearer: prefix, got: {result}"
        );
        // Should be deterministic
        let result2 = crate::routes::approval::derive_resolver_identity(&headers, "anonymous");
        assert_eq!(result, result2);
    }

    #[test]
    fn test_derive_resolver_identity_with_bearer_and_client_note() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer my-secret-token".parse().unwrap(),
        );
        let result = crate::routes::approval::derive_resolver_identity(&headers, "admin-alice");
        assert!(result.contains("bearer:"), "Should contain bearer hash");
        assert!(
            result.contains("(note: admin-alice)"),
            "Should include client note: {result}"
        );
    }

    #[test]
    fn test_derive_resolver_identity_case_insensitive_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "BEARER my-secret-token".parse().unwrap(),
        );
        let result = crate::routes::approval::derive_resolver_identity(&headers, "anonymous");
        assert!(
            result.starts_with("bearer:"),
            "Should handle uppercase BEARER: {result}"
        );
    }

    #[test]
    fn test_derive_resolver_identity_no_auth_falls_back() {
        let headers = HeaderMap::new();
        let result = crate::routes::approval::derive_resolver_identity(&headers, "some-user");
        assert_eq!(result, "some-user");
    }

    #[test]
    fn test_derive_resolver_identity_non_bearer_auth_falls_back() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());
        let result = crate::routes::approval::derive_resolver_identity(&headers, "some-user");
        assert_eq!(result, "some-user");
    }

    // --- R34-SRV-4: Token hash uses 16 bytes (128-bit) ---

    #[test]
    fn test_derive_resolver_identity_uses_128bit_hash() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer test-token-123".parse().unwrap(),
        );
        let identity = crate::routes::approval::derive_resolver_identity(&headers, "anonymous");
        // Should be "bearer:" + 32 hex chars (16 bytes = 128 bits)
        assert!(identity.starts_with("bearer:"));
        let hex_part = &identity[7..];
        assert_eq!(
            hex_part.len(),
            32,
            "hash truncation should be 16 bytes (32 hex chars)"
        );
    }

    // --- R34-SRV-6: Percent-encoded relative path detection ---

    #[test]
    fn test_looks_like_relative_path_percent_encoded() {
        // Percent-encoded ../ should be detected
        assert!(looks_like_relative_path("..%2F..%2Fetc%2Fpasswd"));
        assert!(looks_like_relative_path("..%2fetc%2fpasswd"));
        assert!(looks_like_relative_path(".%2Fconfig.json"));
        assert!(looks_like_relative_path("~%2Fsecret.txt"));
        assert!(looks_like_relative_path("foo%2F..%2Fbar"));
    }

    #[test]
    fn test_looks_like_relative_path_backslash() {
        assert!(looks_like_relative_path("..\\etc\\passwd"));
        assert!(looks_like_relative_path(".\\config.json"));
        assert!(looks_like_relative_path("foo\\..\\bar"));
    }

    // --- R34-SRV-7: Control char sanitization in derive_resolver_identity ---

    #[test]
    fn test_derive_resolver_identity_strips_control_chars() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer mytoken".parse().unwrap());
        let identity =
            crate::routes::approval::derive_resolver_identity(&headers, "user\x00\x0a\x0dname");
        assert!(!identity.contains('\x00'));
        assert!(!identity.contains('\x0a'));
        assert!(!identity.contains('\x0d'));
        assert!(identity.contains("(note: username)"));
    }

    // --- R34-SRV-8: Hash-based auth comparison ---

    #[test]
    fn test_auth_comparison_constant_time_hash() {
        // This is a unit test verifying the hash-comparison approach works.
        // We can't easily test timing, but verify correct accept/reject.
        use sha2::{Digest, Sha256};
        let key = "correct-api-key";
        let good_token = "correct-api-key";
        let bad_token = "wrong-api-key";

        let key_hash = Sha256::digest(key.as_bytes());
        let good_hash = Sha256::digest(good_token.as_bytes());
        let bad_hash = Sha256::digest(bad_token.as_bytes());

        use subtle::ConstantTimeEq;
        assert!(bool::from(key_hash.ct_eq(&good_hash)));
        assert!(!bool::from(key_hash.ct_eq(&bad_hash)));
    }

    // --- R37-SRV-1: Backslash as path separator in domain extraction ---

    #[test]
    fn test_scan_params_backslash_authority_bypass() {
        // SECURITY (R37-SRV-1): Backslash in URL authority must be treated as
        // path separator per WHATWG URL Standard. Without normalization,
        // http://evil.com\@allowed.com/path would extract "allowed.com"
        // instead of "evil.com".
        let mut paths = Vec::new();
        let mut domains = Vec::new();
        let value = serde_json::json!("http://evil.com\\@allowed.com/path");
        scan_params_for_targets_inner(&value, &mut paths, &mut domains, 0);
        assert!(
            domains.contains(&"evil.com".to_string()),
            "Should extract evil.com as the domain, got: {domains:?}"
        );
        assert!(
            !domains.contains(&"allowed.com".to_string()),
            "Should NOT extract allowed.com (it is after the backslash-path), got: {domains:?}"
        );
    }

    #[test]
    fn test_scan_params_backslash_no_at_sign() {
        // Backslash without @ — the backslash is a path separator, so only
        // the part before it is the authority host.
        let mut paths = Vec::new();
        let mut domains = Vec::new();
        let value = serde_json::json!("https://example.com\\malicious-path");
        scan_params_for_targets_inner(&value, &mut paths, &mut domains, 0);
        assert!(
            domains.contains(&"example.com".to_string()),
            "Should extract example.com, got: {domains:?}"
        );
    }

    // --- R41-SRV-4: Rate limit category bypass via method override ---

    #[test]
    fn test_categorize_rate_limit_put_evaluate_uses_evaluate_bucket() {
        // SECURITY (R41-SRV-4): A PUT /api/evaluate must use the evaluate
        // rate limit bucket, not fall through to admin. The rate limit
        // middleware runs before routing, so non-POST methods to /api/evaluate
        // would consume the wrong bucket if we only match POST.
        use governor::{Quota, RateLimiter};
        use std::num::NonZeroU32;

        let limits = crate::RateLimits {
            evaluate: Some(RateLimiter::direct(Quota::per_second(
                NonZeroU32::new(10).unwrap(),
            ))),
            admin: Some(RateLimiter::direct(Quota::per_second(
                NonZeroU32::new(100).unwrap(),
            ))),
            readonly: None,
            per_ip: None,
            per_principal: None,
            endpoint_limits: std::collections::HashMap::new(),
        };

        // POST should use evaluate bucket
        let limiter_post = categorize_rate_limit(&limits, &Method::POST, "/api/evaluate");
        assert!(
            limiter_post.is_some(),
            "POST /api/evaluate must match evaluate bucket"
        );

        // PUT should also use evaluate bucket, not admin
        let limiter_put = categorize_rate_limit(&limits, &Method::PUT, "/api/evaluate");
        assert!(
            limiter_put.is_some(),
            "PUT /api/evaluate must match evaluate bucket"
        );

        // Verify both return the same limiter (evaluate, not admin)
        // by checking they are the same pointer
        let ptr_post = limiter_post.unwrap() as *const _;
        let ptr_put = limiter_put.unwrap() as *const _;
        assert_eq!(
            ptr_post, ptr_put,
            "PUT /api/evaluate must use the same (evaluate) rate limiter as POST"
        );

        // Also verify DELETE, PATCH, GET all use evaluate bucket for this path
        for method in &[Method::DELETE, Method::PATCH, Method::GET, Method::HEAD] {
            let limiter = categorize_rate_limit(&limits, method, "/api/evaluate");
            let ptr = limiter.unwrap() as *const _;
            assert_eq!(
                ptr, ptr_post,
                "{method:?} /api/evaluate must use evaluate bucket, not admin or readonly"
            );
        }
    }

    // --- CSRF Referer/Origin Validation Tests (Phase 5) ---

    #[test]
    fn test_validate_origin_localhost_allowed_by_default() {
        let origins: Vec<String> = vec![];

        assert!(validate_origin("http://localhost", &origins));
        assert!(validate_origin("http://localhost:3000", &origins));
        assert!(validate_origin("https://localhost", &origins));
        assert!(validate_origin("http://127.0.0.1", &origins));
        assert!(validate_origin("http://127.0.0.1:8080", &origins));
        assert!(validate_origin("http://[::1]", &origins));
        assert!(validate_origin("https://[::1]:443", &origins));
    }

    #[test]
    fn test_validate_origin_external_blocked_by_default() {
        let origins: Vec<String> = vec![];

        assert!(!validate_origin("http://example.com", &origins));
        assert!(!validate_origin("https://attacker.com", &origins));
        assert!(!validate_origin("http://192.168.1.1", &origins));
    }

    #[test]
    fn test_validate_origin_wildcard_allows_all() {
        let origins = vec!["*".to_string()];

        assert!(validate_origin("http://example.com", &origins));
        assert!(validate_origin("https://attacker.com", &origins));
        assert!(validate_origin("http://localhost", &origins));
    }

    #[test]
    fn test_validate_origin_configured_origins() {
        let origins = vec![
            "https://app.example.com".to_string(),
            "https://admin.example.com".to_string(),
        ];

        assert!(validate_origin("https://app.example.com", &origins));
        assert!(validate_origin("https://admin.example.com", &origins));
        // SECURITY (FIND-R110-SRV-001): localhost is NOT a fallback when origins are configured.
        // An explicit allowlist means only listed origins are permitted — localhost must be
        // explicitly added to the allowlist if desired.
        assert!(!validate_origin("http://localhost", &origins));
        // Other origins blocked
        assert!(!validate_origin("https://attacker.com", &origins));
        assert!(!validate_origin("https://example.com", &origins));
    }

    #[test]
    fn test_validate_origin_localhost_blocked_when_origins_configured() {
        // SECURITY (FIND-R110-SRV-001): When allowed_origins is non-empty, localhost must
        // NOT bypass the configured allowlist. This prevents CSRF attacks from localhost
        // agents against servers with an explicit origin policy.
        let origins = vec!["https://app.example.com".to_string()];
        assert!(!validate_origin("http://localhost", &origins));
        assert!(!validate_origin("http://localhost:8080", &origins));
        assert!(!validate_origin("http://127.0.0.1", &origins));
        assert!(!validate_origin("http://[::1]", &origins));
        // But if localhost IS in the allowlist, it should be permitted
        let origins_with_localhost = vec![
            "https://app.example.com".to_string(),
            "http://localhost:3000".to_string(),
        ];
        assert!(validate_origin(
            "http://localhost:3000",
            &origins_with_localhost
        ));
        assert!(!validate_origin(
            "http://localhost:8080",
            &origins_with_localhost
        ));
    }

    #[test]
    fn test_validate_origin_case_insensitive() {
        let origins = vec!["https://APP.Example.COM".to_string()];

        assert!(validate_origin("https://app.example.com", &origins));
        assert!(validate_origin("https://APP.EXAMPLE.COM", &origins));
        assert!(validate_origin("https://App.Example.Com", &origins));
    }

    #[test]
    fn test_validate_origin_with_port() {
        let origins = vec!["https://app.example.com:8443".to_string()];

        assert!(validate_origin("https://app.example.com:8443", &origins));
        // Different port should not match exact origin
        assert!(!validate_origin("https://app.example.com:9000", &origins));
        // No port should not match origin with port
        assert!(!validate_origin("https://app.example.com", &origins));
    }

    #[test]
    fn test_validate_origin_blocks_localhost_prefix_spoof() {
        let origins: Vec<String> = vec![];
        assert!(!validate_origin("https://localhost.evil.com", &origins));
        assert!(!validate_origin("https://127.0.0.1.evil.com", &origins));
        assert!(!validate_origin("https://[::1].evil.com", &origins));
    }

    #[test]
    fn test_validate_origin_blocks_configured_prefix_spoof() {
        let origins = vec!["https://app.example.com".to_string()];
        assert!(!validate_origin(
            "https://app.example.com.evil.com",
            &origins
        ));
        assert!(!validate_origin("https://app.example.com:8443", &origins));
        assert!(validate_origin("https://app.example.com", &origins));
    }

    // --- Per-Endpoint Rate Limiting Tests (Phase 5) ---

    #[test]
    fn test_endpoint_limit_takes_priority() {
        use std::num::NonZeroU32;

        let limits =
            crate::RateLimits::new_with_burst(Some(100), None, Some(50), None, Some(25), None)
                .with_endpoint_limit("/api/special", NonZeroU32::new(10).unwrap(), None);

        // Endpoint-specific limit should be returned
        let limiter = categorize_rate_limit(&limits, &Method::POST, "/api/special");
        assert!(limiter.is_some());

        // Different endpoint falls back to category limits
        let limiter = categorize_rate_limit(&limits, &Method::POST, "/api/evaluate");
        assert!(limiter.is_some());
    }

    #[test]
    fn test_endpoint_limit_prefix_matching() {
        use std::num::NonZeroU32;

        let limits =
            crate::RateLimits::new_with_burst(Some(100), None, Some(50), None, Some(25), None)
                .with_endpoint_limit("/api/audit", NonZeroU32::new(10).unwrap(), None);

        // Exact match
        assert!(limits.get_endpoint_limiter("/api/audit").is_some());
        // Prefix match
        assert!(limits.get_endpoint_limiter("/api/audit/entries").is_some());
        assert!(limits.get_endpoint_limiter("/api/audit/report").is_some());
        // Non-match
        assert!(limits.get_endpoint_limiter("/api/policies").is_none());
    }

    #[test]
    fn test_endpoint_limit_longest_match_wins() {
        use std::num::NonZeroU32;

        let limits = crate::RateLimits::new_with_burst(None, None, None, None, None, None)
            .with_endpoint_limit("/api", NonZeroU32::new(100).unwrap(), None)
            .with_endpoint_limit("/api/audit", NonZeroU32::new(50).unwrap(), None)
            .with_endpoint_limit("/api/audit/checkpoint", NonZeroU32::new(10).unwrap(), None);

        // Most specific match should win
        let l1 = limits.get_endpoint_limiter("/api/audit/checkpoint");
        let l2 = limits.get_endpoint_limiter("/api/audit/entries");
        let l3 = limits.get_endpoint_limiter("/api/policies");

        // All should have limiters (from different prefix matches)
        assert!(l1.is_some());
        assert!(l2.is_some());
        assert!(l3.is_some());

        // Pointers should be different (different limiters)
        assert!(!std::ptr::eq(
            l1.unwrap() as *const _,
            l2.unwrap() as *const _
        ));
    }

    // --- SEC-006: Health endpoint reports scanning subsystem status ---

    #[test]
    fn test_scanning_status_serializes_correctly() {
        let status = ScanningStatus {
            dlp_available: true,
            injection_available: true,
        };
        let json = serde_json::to_value(&status).expect("serialize");
        assert_eq!(json["dlp_available"], true);
        assert_eq!(json["injection_available"], true);
    }

    #[test]
    fn test_health_response_includes_scanning() {
        let response = HealthResponse {
            status: "ok".to_string(),
            cluster: None,
            scanning: ScanningStatus {
                dlp_available: true,
                injection_available: true,
            },
            leader_status: None,
            instance_id: None,
            discovered_endpoints: None,
        };
        let json = serde_json::to_value(&response).expect("serialize");
        assert_eq!(json["status"], "ok");
        assert!(json["scanning"].is_object());
        assert_eq!(json["scanning"]["dlp_available"], true);
        assert_eq!(json["scanning"]["injection_available"], true);
        // cluster should be omitted when None
        assert!(json.get("cluster").is_none());
    }

    #[test]
    fn test_health_response_degraded_when_scanning_unavailable() {
        // This tests the response structure, not the actual subsystem state
        let response = HealthResponse {
            status: "degraded".to_string(),
            cluster: None,
            scanning: ScanningStatus {
                dlp_available: false,
                injection_available: true,
            },
            leader_status: None,
            instance_id: None,
            discovered_endpoints: None,
        };
        let json = serde_json::to_value(&response).expect("serialize");
        assert_eq!(json["status"], "degraded");
        assert_eq!(json["scanning"]["dlp_available"], false);
    }
}
