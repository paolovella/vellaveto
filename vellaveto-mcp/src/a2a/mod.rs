// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! A2A (Agent-to-Agent) Protocol Security — Phase 14.
//!
//! This module provides security controls for A2A protocol traffic, following
//! the same patterns established for MCP:
//!
//! - **Message Classification**: Parse and classify A2A JSON-RPC messages
//! - **Policy Evaluation**: Reuse existing PolicyEngine for access control
//! - **Audit Logging**: Track all A2A requests/responses with tamper-evident logging
//! - **Security Integration**: Apply existing protections (circuit breaker, DLP, etc.)
//!
//! # A2A Protocol Summary
//!
//! The A2A (Agent-to-Agent) protocol is a standard for agent interoperability.
//! It uses JSON-RPC 2.0 over HTTP(S) with these key methods:
//!
//! | Method            | Description                              |
//! |-------------------|------------------------------------------|
//! | `message/send`    | Send message to agent (primary)          |
//! | `message/stream`  | Send message with streaming response     |
//! | `tasks/get`       | Get task status                          |
//! | `tasks/cancel`    | Cancel a running task                    |
//! | `tasks/resubscribe` | Resubscribe to task events             |
//!
//! Discovery: Agent Cards at `/.well-known/agent.json`
//!
//! Authentication: APIKey, HTTP Bearer, OAuth 2.0, OpenID Connect, mTLS
//!
//! # Architecture
//!
//! ```text
//! vellaveto-mcp/src/a2a/
//! ├── mod.rs              # This facade + re-exports
//! ├── error.rs            # A2aError types (thiserror)
//! ├── message.rs          # A2A message types and classification
//! ├── extractor.rs        # Action extraction from A2A messages
//! ├── agent_card.rs       # Agent Card fetching and validation
//! └── proxy.rs            # Proxy service logic
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use vellaveto_mcp::a2a::{
//!     classify_a2a_message, extract_a2a_action,
//!     A2aProxyService, A2aProxyConfig,
//! };
//! use serde_json::json;
//!
//! // Parse and classify an A2A message
//! let msg = json!({
//!     "jsonrpc": "2.0",
//!     "id": 1,
//!     "method": "message/send",
//!     "params": {
//!         "message": {
//!             "role": "user",
//!             "parts": [{"type": "text", "text": "Hello"}]
//!         }
//!     }
//! });
//!
//! let msg_type = classify_a2a_message(&msg);
//! if let Some(action) = extract_a2a_action(&msg_type) {
//!     // Evaluate policy, log audit, etc.
//! }
//! ```
//!
//! # Security Features
//!
//! 1. **Batch Rejection**: JSON-RPC batch requests are rejected to prevent TOCTOU attacks
//! 2. **Method Normalization**: Unicode stripping prevents bypass via invisible characters
//! 3. **Agent Card Validation**: Optional verification that requests match card capabilities
//! 4. **DLP Scanning**: Reuse existing DLP on message content
//! 5. **Injection Detection**: Reuse existing injection scanner on text parts
//! 6. **Circuit Breaker**: Apply to upstream A2A servers
//! 7. **Authentication**: Validate auth header matches allowed schemes
//! 8. **Size Limits**: Prevent DoS via large messages
//!
//! # Feature Flag
//!
//! This module is gated behind the `a2a` feature flag:
//!
//! ```toml
//! [dependencies]
//! vellaveto-mcp = { version = "2.0", features = ["a2a"] }
//! ```

pub mod agent_card;
pub mod error;
pub mod extractor;
pub mod fetch;
pub mod message;
pub mod proxy;
pub mod signature;

// Re-export commonly used types at the module level
pub use agent_card::{
    build_agent_card_url, parse_agent_card, scan_agent_card_for_injection, supports_auth_scheme,
    supports_streaming, validate_agent_card, validate_request_method, AgentCapabilities, AgentCard,
    AgentCardCache, AgentSkill, AuthScheme, AuthenticationInfo, ProviderInfo,
};
pub use error::A2aError;
pub use extractor::{
    extract_a2a_action, get_method_name, get_request_id, make_a2a_denial_response,
    make_a2a_error_response, make_a2a_success_response, requires_policy_check, A2A_TOOL,
};
pub use fetch::{AgentCardFetcher, AGENT_CARD_CLAIMS_HEADER, AGENT_CARD_SIGNATURE_HEADER};
pub use message::{
    classify_a2a_message, extract_text_content, normalize_a2a_method, A2aMessage, A2aMessageType,
    FileContent, MessagePart, PartContent, TaskState,
};
pub use proxy::{process_response, A2aProxyConfig, A2aProxyDecision, A2aProxyService};
pub use signature::{
    compute_card_hash, AgentCardClaims, AgentCardSignatureVerifier, AgentSigningKey,
    SignatureEnforcementConfig,
};
