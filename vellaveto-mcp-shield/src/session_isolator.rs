// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Per-session PII sanitization and history tracking.

use crate::error::ShieldError;
use crate::sanitizer::QuerySanitizer;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use vellaveto_audit::{CustomPiiPattern, PiiScanner};

/// Maximum number of concurrent sessions.
const MAX_SESSIONS: usize = 1_000;

/// Maximum length of a session ID in bytes.
/// SECURITY (R238-SHLD-4): Prevents unbounded session ID strings from
/// consuming excessive memory in HashMap keys.
const MAX_SESSION_ID_LEN: usize = 256;

/// Maximum history entries per session.
const MAX_HISTORY_PER_SESSION: usize = 10_000;

/// A single session's state.
struct SessionState {
    sanitizer: QuerySanitizer,
    history: VecDeque<String>,
}

/// Manages per-session PII sanitization with independent mapping tables.
pub struct SessionIsolator {
    sessions: Mutex<HashMap<String, SessionState>>,
    max_sessions: usize,
    max_history: usize,
    /// Operator-supplied PII patterns, used to build each session's scanner.
    ///
    /// Stored as patterns rather than a shared `PiiScanner` because every
    /// session needs its own scanner instance, and the compiled scanner is not
    /// cloneable. Without this, per-session isolation would silently drop the
    /// custom patterns the global sanitizer honours.
    custom_patterns: Vec<CustomPiiPattern>,
}

impl SessionIsolator {
    /// Extract placeholder tokens from a desanitization candidate.
    ///
    /// Supports both legacy decimal placeholders and the current 16-hex token
    /// format so session binding keeps working across format migrations.
    fn extract_placeholders(input: &str) -> Result<Vec<String>, ShieldError> {
        let re = regex::Regex::new(r"\[PII_[A-Z0-9_]+_(?:\d{6}|[0-9A-F]{16})\]")
            .map_err(|e| ShieldError::Config(format!("invalid placeholder regex: {e}")))?;
        Ok(re
            .find_iter(input)
            .map(|m| m.as_str().to_string())
            .collect())
    }

    /// Create a new session isolator with default bounds and the built-in
    /// PII patterns only.
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_sessions: MAX_SESSIONS,
            max_history: MAX_HISTORY_PER_SESSION,
            custom_patterns: Vec::new(),
        }
    }

    /// Create a session isolator that also applies operator-supplied PII
    /// patterns, matching what a globally-configured [`QuerySanitizer`] scans
    /// for. Each session gets its own scanner built from these patterns.
    pub fn with_custom_patterns(patterns: Vec<CustomPiiPattern>) -> Self {
        Self {
            custom_patterns: patterns,
            ..Self::new()
        }
    }

    /// Create a new session isolator with custom bounds.
    ///
    /// Values are clamped to safety constants to prevent unbounded memory growth.
    pub fn with_limits(max_sessions: usize, max_history: usize) -> Self {
        // SECURITY (R240-SHLD-4): Clamp to MAX constants — parity with
        // ContextIsolator::with_limits() which clamps to MAX_CONTEXT_ENTRIES.
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_sessions: max_sessions.min(MAX_SESSIONS),
            max_history: max_history.min(MAX_HISTORY_PER_SESSION),
            custom_patterns: Vec::new(),
        }
    }

    /// Validate session_id for dangerous characters and length.
    fn validate_session_id(session_id: &str) -> Result<(), ShieldError> {
        // SECURITY (R234-SHIELD-4): Reject session IDs with control chars, bidi
        // overrides, zero-width chars, etc. These can cause log injection, HashMap
        // key confusion, or display-layer attacks.
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

    /// Get or create a session, returning Ok if the session exists or was created.
    fn ensure_session(&self, session_id: &str) -> Result<(), ShieldError> {
        Self::validate_session_id(session_id)?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("lock poisoned: {e}")))?;

        if sessions.contains_key(session_id) {
            return Ok(());
        }

        if sessions.len() >= self.max_sessions {
            return Err(ShieldError::SessionIsolation(
                "session capacity exhausted (fail-closed)".to_string(),
            ));
        }

        sessions.insert(
            session_id.to_string(),
            SessionState {
                sanitizer: QuerySanitizer::new(PiiScanner::new_for_sanitizer(
                    &self.custom_patterns,
                )),
                history: VecDeque::new(),
            },
        );
        Ok(())
    }

    /// Sanitize input within a specific session's context.
    pub fn sanitize_in_session(
        &self,
        session_id: &str,
        input: &str,
    ) -> Result<String, ShieldError> {
        self.ensure_session(session_id)?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("lock poisoned: {e}")))?;

        let state = sessions.get_mut(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation("session not found after ensure".to_string())
        })?;

        let result = state.sanitizer.sanitize(input)?;

        // Record in history (bounded)
        if state.history.len() >= self.max_history {
            state.history.pop_front();
        }
        state.history.push_back(result.clone());

        Ok(result)
    }

    /// Desanitize input within a specific session's context.
    pub fn desanitize_in_session(
        &self,
        session_id: &str,
        input: &str,
    ) -> Result<String, ShieldError> {
        Self::validate_session_id(session_id)?;
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("lock poisoned: {e}")))?;

        let state = sessions.get(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation(format!("unknown session: {session_id}"))
        })?;

        // SECURITY (R238-SHLD-2): Bind restoration to the most recent outbound
        // sanitized request in this session. Without explicit request IDs, the
        // latest request is the safest fail-closed approximation; restoring
        // placeholders from older turns lets a server probe the session's
        // mapping table by replaying guessed placeholder IDs.
        //
        // Only check placeholders that this session's sanitizer OWNS. Placeholders
        // from other sessions are unknown to this sanitizer and will pass through
        // unchanged during desanitization — no PII leak risk.
        let placeholders = Self::extract_placeholders(input)?;
        let owned_placeholders: Vec<&String> = placeholders
            .iter()
            .filter(|p| state.sanitizer.has_placeholder(p))
            .collect();
        if !owned_placeholders.is_empty() {
            let latest_outbound = state.history.back().ok_or_else(|| {
                ShieldError::Desanitization(
                    "no outbound sanitized request available for placeholder restoration"
                        .to_string(),
                )
            })?;
            if owned_placeholders
                .iter()
                .any(|placeholder| !latest_outbound.contains(placeholder.as_str()))
            {
                return Err(ShieldError::Desanitization(
                    "response placeholders do not match the most recent outbound sanitized request (fail-closed)"
                        .to_string(),
                ));
            }
        }

        state.sanitizer.desanitize(input)
    }

    /// Sanitize every string in a JSON message within a session's own mapping
    /// table.
    ///
    /// The JSON equivalent of [`sanitize_in_session`], for the proxy bridge,
    /// which works in whole JSON-RPC messages rather than bare strings. Reuses
    /// [`QuerySanitizer::sanitize_json`] for the traversal and records the
    /// serialized result in session history, so the binding check in
    /// [`desanitize_json_in_session`] has something to bind against.
    ///
    /// [`sanitize_in_session`]: Self::sanitize_in_session
    /// [`desanitize_json_in_session`]: Self::desanitize_json_in_session
    pub fn sanitize_json_in_session(
        &self,
        session_id: &str,
        value: &serde_json::Value,
    ) -> Result<serde_json::Value, ShieldError> {
        self.ensure_session(session_id)?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("lock poisoned: {e}")))?;

        let state = sessions.get_mut(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation("session not found after ensure".to_string())
        })?;

        let sanitized = state.sanitizer.sanitize_json(value)?;

        // Record the serialized form so placeholder binding can check that a
        // response only restores placeholders this session actually emitted.
        let record = serde_json::to_string(&sanitized)
            .map_err(|e| ShieldError::Sanitization(format!("serialize sanitized json: {e}")))?;
        if state.history.len() >= self.max_history {
            state.history.pop_front();
        }
        state.history.push_back(record);

        Ok(sanitized)
    }

    /// Restore PII in a JSON message from a session's own mapping table.
    ///
    /// The JSON equivalent of [`desanitize_in_session`], and it keeps that
    /// method's fail-closed property: placeholders this session owns must
    /// appear in its most recent outbound message, so a server cannot probe the
    /// mapping table by replaying guessed placeholder IDs. Placeholders
    /// belonging to other sessions are unknown to this sanitizer and pass
    /// through unchanged — which is the isolation guarantee.
    ///
    /// [`desanitize_in_session`]: Self::desanitize_in_session
    pub fn desanitize_json_in_session(
        &self,
        session_id: &str,
        value: &serde_json::Value,
    ) -> Result<serde_json::Value, ShieldError> {
        Self::validate_session_id(session_id)?;
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("lock poisoned: {e}")))?;

        let state = sessions.get(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation(format!("unknown session: {session_id}"))
        })?;

        let serialized = serde_json::to_string(value)
            .map_err(|e| ShieldError::Desanitization(format!("serialize json: {e}")))?;
        let placeholders = Self::extract_placeholders(&serialized)?;
        let owned: Vec<&String> = placeholders
            .iter()
            .filter(|p| state.sanitizer.has_placeholder(p))
            .collect();
        if !owned.is_empty() {
            if state.history.is_empty() {
                return Err(ShieldError::Desanitization(
                    "no outbound sanitized request available for placeholder restoration"
                        .to_string(),
                ));
            }
            // Every owned placeholder must have been emitted by *some* outbound
            // message in this session's bounded history.
            //
            // Deliberately not "the most recent message only", which is what the
            // string-based `desanitize_in_session` checks. JSON-RPC allows
            // several requests in flight at once, so a response to request A can
            // legitimately arrive after request B has gone out; binding to the
            // latest message alone would fail those responses closed and break
            // pipelining. Searching the whole history still blocks the attack
            // that check exists for — a server echoing a guessed placeholder ID
            // to probe the mapping table — because a placeholder this session
            // never emitted appears nowhere in it.
            if owned.iter().any(|placeholder| {
                !state
                    .history
                    .iter()
                    .any(|outbound| outbound.contains(placeholder.as_str()))
            }) {
                return Err(ShieldError::Desanitization(
                    "response contains placeholders this session never emitted (fail-closed)"
                        .to_string(),
                ));
            }
        }

        state.sanitizer.desanitize_json(value)
    }

    /// End a session, wiping all state.
    ///
    /// SECURITY (R238-SHLD-1): Recovers from lock poisoning via `into_inner()`
    /// to ensure PII mappings are always cleared. Silently skipping cleanup
    /// on poisoning would leave sensitive data in memory.
    pub fn end_session(&self, session_id: &str) {
        match self.sessions.lock() {
            Ok(mut sessions) => {
                sessions.remove(session_id);
            }
            Err(poisoned) => {
                tracing::error!(
                    "SECURITY (R238-SHLD-1): sessions lock poisoned during end_session — recovering"
                );
                poisoned.into_inner().remove(session_id);
            }
        }
    }

    /// Get the number of active sessions.
    pub fn session_count(&self) -> usize {
        match self.sessions.lock() {
            Ok(s) => s.len(),
            Err(_) => {
                // SECURITY (R240-P3-SHLD-3): Log poisoning instead of silent 0.
                tracing::error!("SessionIsolator lock poisoned in session_count");
                0
            }
        }
    }
}

impl Default for SessionIsolator {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SessionIsolator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionIsolator")
            .field("session_count", &self.session_count())
            .finish()
    }
}
