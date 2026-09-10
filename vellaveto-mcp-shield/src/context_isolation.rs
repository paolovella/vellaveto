// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Context window isolation — prevents cross-session context leakage.
//!
//! Each session's recorded context is kept separate: entries recorded under one
//! session id are never returned for another, and [`end_session`] wipes a
//! session's entries entirely. That isolation is what this module provides, and
//! it is enforced by the proxy bridge, which records every intercepted request
//! and response against the current session.
//!
//! # No prompt injection — deliberately
//!
//! An earlier version of this documentation said local context was "injected
//! into the new session's prompt" to give the user continuity. It never was,
//! and it should not be. A stdio MCP proxy does not sit on the path between the
//! agent and the model, so the only message crossing it that carries a prompt
//! is a server-initiated `sampling/createMessage`. Injecting local history
//! there would hand it to whichever MCP server asked: the agent runs the
//! sampling request against the model and returns the completion **to that
//! server**, so a malicious server could harvest the user's history by
//! requesting sampling and reading what came back. DLP scanning on the return
//! path catches patterned secrets, not general private content.
//!
//! [`get_recent_context`] therefore exists as a **local read API**: a host
//! application that wants to offer continuity can read a session's own history
//! and decide what to do with it, under the user's control. This module will
//! not put that history on the wire.
//!
//! [`end_session`]: ContextIsolator::end_session
//! [`get_recent_context`]: ContextIsolator::get_recent_context

use crate::error::ShieldError;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Maximum number of context entries per session.
const MAX_CONTEXT_ENTRIES: usize = 1_000;

/// Maximum total sessions tracked for context isolation.
const MAX_CONTEXT_SESSIONS: usize = 10_000;

/// Maximum length of a single context entry text (64 KB).
const MAX_CONTEXT_ENTRY_LEN: usize = 65_536;

/// Maximum total context bytes across all entries in a session (1 MB).
const MAX_CONTEXT_TOTAL_BYTES: usize = 1_048_576;

/// Maximum length of a session ID in bytes.
/// SECURITY (R238-SHLD-4): Prevents unbounded session ID strings from
/// consuming excessive memory in HashMap keys.
const MAX_SESSION_ID_LEN: usize = 256;

/// A single piece of conversation context.
struct ContextEntry {
    /// The role: "user" or "assistant".
    role: String,
    /// The text content (sanitized — no PII).
    text: String,
    /// Monotonic sequence number within the session.
    #[allow(dead_code)]
    sequence: u64,
}

/// Per-session context state.
struct SessionContext {
    entries: VecDeque<ContextEntry>,
    total_bytes: usize,
    next_sequence: u64,
}

impl SessionContext {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            total_bytes: 0,
            next_sequence: 0,
        }
    }
}

/// Manages per-session context isolation.
///
/// Ensures that:
/// 1. Each session has an independent context window
/// 2. Context is never shared between sessions at the provider level
/// 3. Local context history is maintained for user convenience
/// 4. All stored context is PII-sanitized (should be run AFTER QuerySanitizer)
pub struct ContextIsolator {
    sessions: Mutex<HashMap<String, SessionContext>>,
    max_entries: usize,
    max_sessions: usize,
}

impl ContextIsolator {
    /// Validate session_id for dangerous characters and length.
    fn validate_session_id(session_id: &str) -> Result<(), ShieldError> {
        // SECURITY (R234-SHIELD-4): Reject session IDs with control chars, bidi
        // overrides, zero-width chars, etc.
        if session_id.is_empty() {
            return Err(ShieldError::SessionIsolation(
                "session_id must not be empty".to_string(),
            ));
        }
        // SECURITY (R238-SHLD-4): Reject session IDs exceeding MAX_SESSION_ID_LEN
        // to prevent excessive memory consumption in HashMap keys.
        if session_id.len() > MAX_SESSION_ID_LEN {
            return Err(ShieldError::SessionIsolation(format!(
                "session_id too long ({} bytes, max {MAX_SESSION_ID_LEN})",
                session_id.len()
            )));
        }
        if vellaveto_types::has_dangerous_chars(session_id) {
            return Err(ShieldError::SessionIsolation(
                "session_id contains control or format characters (rejected)".to_string(),
            ));
        }
        Ok(())
    }

    /// Create a new context isolator with default bounds.
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_entries: MAX_CONTEXT_ENTRIES,
            max_sessions: MAX_CONTEXT_SESSIONS,
        }
    }

    /// Create with custom limits.
    pub fn with_limits(max_entries: usize, max_sessions: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_entries: max_entries.min(MAX_CONTEXT_ENTRIES),
            max_sessions: max_sessions.min(MAX_CONTEXT_SESSIONS),
        }
    }

    /// Record a context entry for a session (e.g., a user message or assistant response).
    ///
    /// Text should already be PII-sanitized before calling this.
    pub fn record(&self, session_id: &str, role: &str, text: &str) -> Result<(), ShieldError> {
        Self::validate_session_id(session_id)?;
        // SECURITY (R234-SHIELD-9): Validate role parameter for dangerous chars.
        // Only "user" and "assistant" are valid roles.
        if role != "user" && role != "assistant" {
            return Err(ShieldError::Config(
                "context role must be 'user' or 'assistant'".to_string(),
            ));
        }
        if text.len() > MAX_CONTEXT_ENTRY_LEN {
            return Err(ShieldError::Config(format!(
                "context entry too large ({} bytes, max {})",
                text.len(),
                MAX_CONTEXT_ENTRY_LEN
            )));
        }
        // SECURITY (R241-SHLD-1): Filter null bytes from context text.
        // Null bytes can truncate strings in downstream consumers (C FFI,
        // some databases, log parsers) causing context corruption.
        if text.contains('\0') {
            return Err(ShieldError::Config(
                "context entry text contains null bytes".to_string(),
            ));
        }

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("context lock poisoned: {e}")))?;

        // Create session if needed
        if !sessions.contains_key(session_id) {
            if sessions.len() >= self.max_sessions {
                return Err(ShieldError::SessionIsolation(
                    "context session capacity exhausted (fail-closed)".to_string(),
                ));
            }
            sessions.insert(session_id.to_string(), SessionContext::new());
        }

        let ctx = sessions.get_mut(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation("session not found after insert".to_string())
        })?;

        // Check total bytes limit
        if ctx.total_bytes.saturating_add(text.len()) > MAX_CONTEXT_TOTAL_BYTES {
            // Evict oldest entries to make room
            while ctx.total_bytes.saturating_add(text.len()) > MAX_CONTEXT_TOTAL_BYTES {
                if let Some(old) = ctx.entries.pop_front() {
                    ctx.total_bytes = ctx.total_bytes.saturating_sub(old.text.len());
                } else {
                    break;
                }
            }
        }

        // Enforce entry count limit
        while ctx.entries.len() >= self.max_entries {
            if let Some(old) = ctx.entries.pop_front() {
                ctx.total_bytes = ctx.total_bytes.saturating_sub(old.text.len());
            }
        }

        let seq = ctx.next_sequence;
        ctx.next_sequence = ctx.next_sequence.saturating_add(1);
        ctx.total_bytes = ctx.total_bytes.saturating_add(text.len());

        ctx.entries.push_back(ContextEntry {
            role: role.to_string(),
            text: text.to_string(),
            sequence: seq,
        });

        Ok(())
    }

    /// Get the last N context entries for a session (for local context injection).
    ///
    /// Returns entries in chronological order. These can be injected into
    /// a new session's system prompt so the user gets continuity without
    /// the provider linking sessions.
    pub fn get_recent_context(
        &self,
        session_id: &str,
        max_entries: usize,
    ) -> Result<Vec<(String, String)>, ShieldError> {
        Self::validate_session_id(session_id)?;
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("context lock poisoned: {e}")))?;

        let ctx = sessions.get(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation(format!("unknown context session: {session_id}"))
        })?;

        let entries: Vec<(String, String)> = ctx
            .entries
            .iter()
            .rev()
            .take(max_entries)
            .map(|e| (e.role.clone(), e.text.clone()))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        Ok(entries)
    }

    /// Get the total number of context entries in a session.
    pub fn entry_count(&self, session_id: &str) -> usize {
        match self.sessions.lock() {
            Ok(s) => s.get(session_id).map(|ctx| ctx.entries.len()).unwrap_or(0),
            Err(_) => {
                // SECURITY (R240-P3-SHLD-1): Log poisoning instead of silent 0.
                tracing::error!("context sessions lock poisoned in entry_count");
                0
            }
        }
    }

    /// End a session's context, clearing all stored entries.
    ///
    /// SECURITY (R238-SHLD-1): Recovers from lock poisoning via `into_inner()`
    /// to ensure context entries are always cleared. Silently skipping cleanup
    /// on poisoning would leave conversation context in memory.
    pub fn end_session(&self, session_id: &str) {
        match self.sessions.lock() {
            Ok(mut sessions) => {
                sessions.remove(session_id);
            }
            Err(poisoned) => {
                tracing::error!(
                    "SECURITY (R238-SHLD-1): context sessions lock poisoned during end_session — recovering"
                );
                poisoned.into_inner().remove(session_id);
            }
        }
    }

    /// Get the number of active context sessions.
    pub fn session_count(&self) -> usize {
        match self.sessions.lock() {
            Ok(s) => s.len(),
            Err(_) => {
                // SECURITY (R240-P3-SHLD-2): Log poisoning instead of silent 0.
                tracing::error!("context sessions lock poisoned in session_count");
                0
            }
        }
    }

    /// Record context from a JSON-RPC response message.
    ///
    /// Extracts text content from the response result/error and records it.
    /// Only processes responses with `result` or `error` fields.
    pub fn record_json_response(
        &self,
        session_id: &str,
        msg: &serde_json::Value,
    ) -> Result<(), ShieldError> {
        // Extract text from result.content[].text or error.message
        let text = if let Some(result) = msg.get("result") {
            extract_text_from_result(result)
        } else if let Some(error) = msg.get("error") {
            error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string()
        } else {
            return Ok(());
        };

        if text.is_empty() {
            return Ok(());
        }

        // SECURITY (R240-SHLD-1): Sanitize response text for control characters and
        // Unicode format characters before storing in context. Without this, a malicious
        // MCP server can embed bidi overrides, zero-width joiners, or ANSI escapes in
        // tool call results, creating a stored cross-session injection vector.
        // Parity with record_json_request() which sanitizes params at line 321-323.
        let safe_text: String = text
            .chars()
            .filter(|c| !c.is_control() && !vellaveto_types::core::is_unicode_format_char(*c))
            .collect();

        if safe_text.is_empty() {
            return Ok(());
        }

        self.record(session_id, "assistant", &safe_text)
    }

    /// Record context from a JSON-RPC request message (user side).
    ///
    /// Extracts the tool name and arguments as context.
    pub fn record_json_request(
        &self,
        session_id: &str,
        msg: &serde_json::Value,
    ) -> Result<(), ShieldError> {
        let method = msg
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        // SECURITY (R237-SHLD-3): Sanitize method name from MCP server to prevent
        // control characters, ANSI escapes, or Unicode format chars from being
        // injected into context entries that may influence future sessions.
        let safe_method: String = method
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '/' | '_' | '-' | '.'))
            .take(128)
            .collect();
        let params = msg
            .get("params")
            .and_then(|p| serde_json::to_string(p).ok())
            .unwrap_or_default();

        // Truncate params to avoid huge context entries
        let truncated: String = params.chars().take(4096).collect();
        // SECURITY (R239-SHLD-4): Filter out control chars and Unicode format chars
        // from params to prevent injection into context entries that may influence
        // future sessions.
        let safe_truncated: String = truncated
            .chars()
            .filter(|c| !c.is_control() && !vellaveto_types::core::is_unicode_format_char(*c))
            .collect();
        let text = format!("[{safe_method}] {safe_truncated}");

        self.record(session_id, "user", &text)
    }
}

/// Extract text content from a JSON-RPC result value.
///
/// Handles common MCP response formats:
/// - `result.content[].text` (tool call results)
/// - `result.text` (simple text responses)
/// - `result` as string directly
///
/// SECURITY (R238-SHLD-2): Output is bounded to `MAX_CONTEXT_ENTRY_LEN` to
/// prevent unbounded string allocation from responses with thousands of
/// content items. The `record()` method also checks length, but capping here
/// prevents the allocation itself.
fn extract_text_from_result(result: &serde_json::Value) -> String {
    // Try result.content[].text (MCP tool result format)
    if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
        let mut combined = String::new();
        for item in content {
            if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                // R238-SHLD-2: Cap at MAX_CONTEXT_ENTRY_LEN to prevent unbounded allocation
                if combined.len().saturating_add(text.len()).saturating_add(1)
                    > MAX_CONTEXT_ENTRY_LEN
                {
                    break;
                }
                if !combined.is_empty() {
                    combined.push('\n');
                }
                combined.push_str(text);
            }
        }
        if !combined.is_empty() {
            return combined;
        }
    }

    // Try result.text
    if let Some(text) = result.get("text").and_then(|t| t.as_str()) {
        // R238-SHLD-2: Bound single text field
        // R239-SHLD-1: Use char-boundary-aware truncation to avoid UTF-8 panic
        if text.len() > MAX_CONTEXT_ENTRY_LEN {
            let mut end = MAX_CONTEXT_ENTRY_LEN;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            return text[..end].to_string();
        }
        return text.to_string();
    }

    // Try result as string directly
    if let Some(s) = result.as_str() {
        // R238-SHLD-2: Bound string result
        // R239-SHLD-1: Use char-boundary-aware truncation to avoid UTF-8 panic
        if s.len() > MAX_CONTEXT_ENTRY_LEN {
            let mut end = MAX_CONTEXT_ENTRY_LEN;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            return s[..end].to_string();
        }
        return s.to_string();
    }

    String::new()
}

impl Default for ContextIsolator {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ContextIsolator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextIsolator")
            .field("session_count", &self.session_count())
            .field("max_entries", &self.max_entries)
            .finish()
    }
}
