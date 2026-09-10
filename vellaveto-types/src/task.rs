// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! MCP 2025-11-25 compliance types and Phase 11 secure task primitives.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum number of metadata entries in `TaskCreateParams`.
const MAX_TASK_METADATA_ENTRIES: usize = 64;

/// Parameters for the MCP 2025-11-25 `tasks/create` method.
///
/// The `tasks/create` method allows clients to explicitly create a new async task
/// for a specified tool invocation. The server assigns a task ID and begins
/// executing the tool in the background.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TaskCreateParams {
    /// The tool to invoke for this task.
    pub tool: String,
    /// Arguments to pass to the tool.
    #[serde(default)]
    pub arguments: serde_json::Value,
    /// Optional client-supplied task ID. If omitted, the server generates one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Optional metadata for the task (e.g., labels, priority hints).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

impl TaskCreateParams {
    /// Maximum length for `tool` field (bytes).
    const MAX_TOOL_LEN: usize = 256;
    /// Maximum length for `task_id` field (bytes).
    const MAX_TASK_ID_LEN: usize = 256;
    /// Maximum serialized size for `arguments` (bytes).
    const MAX_ARGUMENTS_SIZE: usize = 1_048_576; // 1 MiB
    /// Maximum length for individual metadata keys (bytes).
    const MAX_METADATA_KEY_LEN: usize = 256;
    /// Maximum serialized size for individual metadata values (bytes).
    const MAX_METADATA_VALUE_SIZE: usize = 8192;

    /// Validate structural bounds on all fields.
    ///
    /// SECURITY: Prevents memory exhaustion and control character injection
    /// from untrusted `tasks/create` payloads.
    pub fn validate(&self) -> Result<(), String> {
        // Validate tool
        if self.tool.is_empty() {
            return Err("TaskCreateParams tool must not be empty".to_string());
        }
        if self.tool.len() > Self::MAX_TOOL_LEN {
            return Err(format!(
                "TaskCreateParams tool length {} exceeds max {}",
                self.tool.len(),
                Self::MAX_TOOL_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.tool) {
            return Err("TaskCreateParams tool contains control or format characters".to_string());
        }

        // Validate arguments size
        let args_size = serde_json::to_string(&self.arguments)
            .map(|s| s.len())
            .unwrap_or(0);
        if args_size > Self::MAX_ARGUMENTS_SIZE {
            return Err(format!(
                "TaskCreateParams arguments serialized size {} exceeds max {}",
                args_size,
                Self::MAX_ARGUMENTS_SIZE,
            ));
        }

        // Validate optional task_id
        if let Some(ref tid) = self.task_id {
            if tid.is_empty() {
                return Err("TaskCreateParams task_id must not be empty when provided".to_string());
            }
            if tid.len() > Self::MAX_TASK_ID_LEN {
                return Err(format!(
                    "TaskCreateParams task_id length {} exceeds max {}",
                    tid.len(),
                    Self::MAX_TASK_ID_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(tid) {
                return Err(
                    "TaskCreateParams task_id contains control or format characters".to_string(),
                );
            }
        }

        // Validate metadata
        if let Some(ref meta) = self.metadata {
            if meta.len() > MAX_TASK_METADATA_ENTRIES {
                return Err(format!(
                    "TaskCreateParams metadata entry count {} exceeds max {}",
                    meta.len(),
                    MAX_TASK_METADATA_ENTRIES,
                ));
            }
            for (key, value) in meta {
                if key.len() > Self::MAX_METADATA_KEY_LEN {
                    return Err(format!(
                        "TaskCreateParams metadata key length {} exceeds max {}",
                        key.len(),
                        Self::MAX_METADATA_KEY_LEN,
                    ));
                }
                if crate::core::has_dangerous_chars(key) {
                    return Err(
                        "TaskCreateParams metadata key contains control or format characters"
                            .to_string(),
                    );
                }
                let val_size = serde_json::to_string(value).map(|s| s.len()).unwrap_or(0);
                if val_size > Self::MAX_METADATA_VALUE_SIZE {
                    return Err(format!(
                        "TaskCreateParams metadata value size {} exceeds max {}",
                        val_size,
                        Self::MAX_METADATA_VALUE_SIZE,
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Status of an async MCP task for lifecycle tracking.
///
/// MCP 2025-11-25 introduces async tasks that run in the background.
/// This enum tracks the current state for policy enforcement and audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum TaskStatus {
    /// Task has been accepted but not yet started.
    #[default]
    Pending,
    /// Task is currently executing.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task failed with an error.
    Failed { reason: String },
    /// Task was cancelled by request.
    Cancelled,
    /// Task expired due to timeout.
    Expired,
}

impl TaskStatus {
    /// Maximum length for the `reason` field in `Failed` variant.
    const MAX_REASON_LEN: usize = 4096;

    /// Validate structural bounds on variant fields.
    ///
    /// SECURITY (R243-TYP-2): The `Failed { reason }` string flows through
    /// `Display` into audit logs and API responses. Without validation,
    /// control characters or oversized strings can corrupt log output.
    pub fn validate(&self) -> Result<(), String> {
        if let TaskStatus::Failed { reason } = self {
            if reason.len() > Self::MAX_REASON_LEN {
                return Err(format!(
                    "TaskStatus::Failed reason length {} exceeds max {}",
                    reason.len(),
                    Self::MAX_REASON_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(reason) {
                return Err(
                    "TaskStatus::Failed reason contains control or format characters".to_string(),
                );
            }
        }
        Ok(())
    }
}

impl fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaskStatus::Pending => write!(f, "pending"),
            TaskStatus::Running => write!(f, "running"),
            TaskStatus::Completed => write!(f, "completed"),
            TaskStatus::Failed { reason } => write!(f, "failed: {reason}"),
            TaskStatus::Cancelled => write!(f, "cancelled"),
            TaskStatus::Expired => write!(f, "expired"),
        }
    }
}

/// A tracked async MCP task for lifecycle management.
///
/// Vellaveto tracks task state to enforce policies on:
/// - Maximum concurrent tasks per session/agent
/// - Task duration limits
/// - Cancellation authorization (self-cancel only vs. any agent)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrackedTask {
    /// Unique task identifier from the MCP server.
    pub task_id: String,
    /// Tool that created this task.
    pub tool: String,
    /// Function that created this task.
    pub function: String,
    /// Current task status.
    pub status: TaskStatus,
    /// ISO 8601 timestamp when the task was created.
    pub created_at: String,
    /// ISO 8601 timestamp when the task expires (if set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Agent ID that created this task (for cancellation authorization).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Session ID this task belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl TrackedTask {
    /// Maximum length for `task_id` (bytes).
    const MAX_TASK_ID_LEN: usize = 256;
    /// Maximum length for `tool` (bytes).
    const MAX_TOOL_LEN: usize = 256;
    /// Maximum length for `function` (bytes).
    const MAX_FUNCTION_LEN: usize = 256;
    /// Maximum length for ISO 8601 timestamp fields (bytes).
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for `created_by` and `session_id` (bytes).
    const MAX_ID_FIELD_LEN: usize = 256;

    /// Returns true if the task is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            TaskStatus::Completed
                | TaskStatus::Failed { .. }
                | TaskStatus::Cancelled
                | TaskStatus::Expired
        )
    }

    /// Returns true if the task is active (pending or running).
    pub fn is_active(&self) -> bool {
        matches!(self.status, TaskStatus::Pending | TaskStatus::Running)
    }

    /// Validate structural bounds on fields.
    ///
    /// SECURITY (FIND-R53-P3-002): Prevents memory exhaustion and control character
    /// injection from untrusted `TrackedTask` payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.task_id.is_empty() {
            return Err("TrackedTask task_id must not be empty".to_string());
        }
        if self.task_id.len() > Self::MAX_TASK_ID_LEN {
            return Err(format!(
                "TrackedTask task_id length {} exceeds max {}",
                self.task_id.len(),
                Self::MAX_TASK_ID_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.task_id) {
            return Err("TrackedTask task_id contains control or format characters".to_string());
        }
        // SECURITY (R243-TYP-2): Validate nested TaskStatus (Failed reason).
        self.status
            .validate()
            .map_err(|e| format!("TrackedTask status: {e}"))?;
        if self.tool.is_empty() {
            return Err("TrackedTask tool must not be empty".to_string());
        }
        if self.tool.len() > Self::MAX_TOOL_LEN {
            return Err(format!(
                "TrackedTask tool length {} exceeds max {}",
                self.tool.len(),
                Self::MAX_TOOL_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.tool) {
            return Err("TrackedTask tool contains control or format characters".to_string());
        }
        if self.function.is_empty() {
            return Err("TrackedTask function must not be empty".to_string());
        }
        if self.function.len() > Self::MAX_FUNCTION_LEN {
            return Err(format!(
                "TrackedTask function length {} exceeds max {}",
                self.function.len(),
                Self::MAX_FUNCTION_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.function) {
            return Err("TrackedTask function contains control or format characters".to_string());
        }
        if self.created_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "TrackedTask created_at length {} exceeds max {}",
                self.created_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        // SECURITY (FIND-R203-002): Reject control/format chars and validate ISO 8601 format.
        if crate::core::has_dangerous_chars(&self.created_at) {
            return Err("TrackedTask created_at contains control or format characters".to_string());
        }
        if !self.created_at.is_empty() {
            crate::time_util::parse_iso8601_secs(&self.created_at)
                .map_err(|e| format!("TrackedTask created_at is not valid ISO 8601: {e}"))?;
        }
        if let Some(ref ea) = self.expires_at {
            if ea.len() > Self::MAX_TIMESTAMP_LEN {
                return Err(format!(
                    "TrackedTask expires_at length {} exceeds max {}",
                    ea.len(),
                    Self::MAX_TIMESTAMP_LEN,
                ));
            }
            // SECURITY (FIND-R203-002): Reject control/format chars and validate ISO 8601 format.
            if crate::core::has_dangerous_chars(ea) {
                return Err(
                    "TrackedTask expires_at contains control or format characters".to_string(),
                );
            }
            if !ea.is_empty() {
                crate::time_util::parse_iso8601_secs(ea)
                    .map_err(|e| format!("TrackedTask expires_at is not valid ISO 8601: {e}"))?;
            }
        }
        if let Some(ref cb) = self.created_by {
            if cb.len() > Self::MAX_ID_FIELD_LEN {
                return Err(format!(
                    "TrackedTask created_by length {} exceeds max {}",
                    cb.len(),
                    Self::MAX_ID_FIELD_LEN,
                ));
            }
            if cb
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(
                    "TrackedTask created_by contains control or format characters".to_string(),
                );
            }
        }
        if let Some(ref sid) = self.session_id {
            if sid.len() > Self::MAX_ID_FIELD_LEN {
                return Err(format!(
                    "TrackedTask session_id length {} exceeds max {}",
                    sid.len(),
                    Self::MAX_ID_FIELD_LEN,
                ));
            }
            if sid
                .chars()
                .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
            {
                return Err(
                    "TrackedTask session_id contains control or format characters".to_string(),
                );
            }
        }
        Ok(())
    }
}

/// A state transition in a task's hash chain for tamper detection.
///
/// Each transition records the previous hash, new state, and produces
/// a new hash, forming an append-only chain that detects tampering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TaskStateTransition {
    /// Sequence number in the hash chain (0-indexed).
    pub sequence: u64,
    /// SHA-256 hash of the previous transition (empty string for first).
    pub prev_hash: String,
    /// The new task status after this transition.
    pub new_status: TaskStatus,
    /// ISO 8601 timestamp of this transition.
    pub timestamp: String,
    /// Agent ID that triggered this transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<String>,
    /// `SHA-256` hash of this transition (computed from `prev_hash` + `new_status` + timestamp).
    pub hash: String,
}

impl TaskStateTransition {
    /// Maximum hash field length (SHA-256 hex = 64 chars, with margin).
    const MAX_HASH_LEN: usize = 256;
    /// Maximum timestamp field length.
    const MAX_TIMESTAMP_LEN: usize = 64;

    /// Validate bounds on deserialized data.
    ///
    /// Checks all string fields for length bounds and control characters.
    pub fn validate(&self) -> Result<(), String> {
        if self.hash.len() > Self::MAX_HASH_LEN {
            return Err(format!(
                "TaskStateTransition hash length {} exceeds max {}",
                self.hash.len(),
                Self::MAX_HASH_LEN,
            ));
        }
        if self.prev_hash.len() > Self::MAX_HASH_LEN {
            return Err(format!(
                "TaskStateTransition prev_hash length {} exceeds max {}",
                self.prev_hash.len(),
                Self::MAX_HASH_LEN,
            ));
        }
        if self.timestamp.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "TaskStateTransition timestamp length {} exceeds max {}",
                self.timestamp.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        // SECURITY (FIND-R203-002): Reject control/format chars in timestamp.
        if crate::core::has_dangerous_chars(&self.timestamp) {
            return Err(
                "TaskStateTransition timestamp contains control or format characters".to_string(),
            );
        }
        if let Some(ref tb) = self.triggered_by {
            if tb.len() > MAX_ENTRY_LEN {
                return Err(format!(
                    "TaskStateTransition triggered_by length {} exceeds max {}",
                    tb.len(),
                    MAX_ENTRY_LEN,
                ));
            }
            // SECURITY (FIND-R112-005): Reject Unicode format characters in addition to control chars.
            if crate::core::has_dangerous_chars(tb) {
                return Err(
                    "TaskStateTransition triggered_by contains control or format characters"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

/// Maximum byte length for individual entries in `state_chain` hashes and `seen_nonces`.
pub const MAX_ENTRY_LEN: usize = 256;

/// A secure task with encryption and integrity protection.
///
/// Extends `TrackedTask` with:
/// - Encrypted state data (`ChaCha20-Poly1305`)
/// - Hash chain for tamper detection
/// - Resume token for authenticated task resumption
/// - Replay protection via nonces
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecureTask {
    /// The underlying tracked task.
    pub task: TrackedTask,
    /// Encrypted task state/result data (base64-encoded ciphertext).
    /// Only present when task has state to protect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_state: Option<String>,
    /// Nonce used for encryption (base64-encoded, 12 bytes for ChaCha20-Poly1305).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_nonce: Option<String>,
    /// Hash chain of state transitions for tamper detection.
    #[serde(default)]
    pub state_chain: Vec<TaskStateTransition>,
    /// HMAC-SHA256 resume token (hex-encoded) for authenticated resumption.
    /// Generated on task creation, verified on resume requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_token: Option<String>,
    /// Nonces seen for replay protection (hex-encoded).
    /// Prevents replaying old task resume/cancel requests.
    #[serde(default)]
    pub seen_nonces: Vec<String>,
    /// Maximum number of nonces to track (FIFO eviction).
    /// Capped at `MAX_NONCES_CAP` (10,000) to prevent memory exhaustion.
    #[serde(
        default = "default_max_nonces",
        deserialize_with = "deserialize_capped_max_nonces"
    )]
    pub max_nonces: usize,
}

/// Absolute upper bound for `max_nonces` to prevent memory exhaustion.
pub const MAX_NONCES_CAP: usize = 10_000;

/// SECURITY (FIND-R49-001): Maximum number of state chain entries to prevent
/// unbounded growth from repeated status transitions.
pub const MAX_STATE_CHAIN: usize = 1_000;

fn default_max_nonces() -> usize {
    1000
}

fn deserialize_capped_max_nonces<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = usize::deserialize(deserializer)?;
    Ok(value.min(MAX_NONCES_CAP))
}

impl SecureTask {
    /// Create a new secure task from a tracked task.
    pub fn new(task: TrackedTask) -> Self {
        Self {
            task,
            encrypted_state: None,
            encryption_nonce: None,
            state_chain: Vec::new(),
            resume_token: None,
            seen_nonces: Vec::new(),
            max_nonces: default_max_nonces(),
        }
    }

    /// Check if a nonce has been seen (replay detection).
    pub fn is_nonce_seen(&self, nonce: &str) -> bool {
        self.seen_nonces.iter().any(|n| n == nonce)
    }

    /// Record a nonce as seen, evicting the oldest when full.
    ///
    /// # Prefer [`try_record_nonce`]
    ///
    /// SECURITY (DOC-CRED-6): Evicting a nonce un-does the replay protection
    /// it was recording. Once evicted, a captured request carrying that nonce
    /// verifies as fresh again, because [`is_nonce_seen`] has no memory of it.
    /// [`try_record_nonce`] refuses instead of evicting, which is the
    /// fail-closed behaviour every caller in this workspace wants.
    ///
    /// Kept for backward compatibility only.
    ///
    /// [`try_record_nonce`]: Self::try_record_nonce
    /// [`is_nonce_seen`]: Self::is_nonce_seen
    #[deprecated(
        since = "7.0.1",
        note = "evicting a nonce reopens the replay window it was protecting against; \
                use try_record_nonce, which fails closed when the cache is full"
    )]
    pub fn record_nonce(&mut self, nonce: String) {
        let effective_max = self.max_nonces.min(MAX_NONCES_CAP);
        if self.seen_nonces.len() >= effective_max {
            self.seen_nonces.remove(0); // FIFO eviction
        }
        self.seen_nonces.push(Self::truncate_nonce(nonce));
    }

    /// Record a nonce as seen, refusing rather than evicting when full.
    ///
    /// Returns `false` when the cache is at capacity, leaving it unchanged. The
    /// caller must then deny the request: recording is what makes a later replay
    /// detectable, so a request whose nonce could not be recorded has no replay
    /// protection and must not be honoured.
    ///
    /// SECURITY (DOC-CRED-6): This replaces FIFO eviction, under which an
    /// evicted nonce became replayable — [`is_nonce_seen`] would report a
    /// captured request as fresh once its nonce aged out of the cache.
    ///
    /// # Why not evict by time instead
    ///
    /// Time-window eviction is the usual answer, and is wrong here.
    /// [`TaskResumeRequest`] carries no timestamp, so nothing bounds a
    /// request's own freshness; the nonce cache is the only thing standing
    /// between a captured request and a successful replay. Dropping nonces
    /// after a TTL would make every captured request replayable by simply
    /// waiting out the window — trading a replay that is hard to trigger for
    /// one that opens on a timer. A time window only becomes correct once the
    /// request itself carries a signed timestamp checked against that same
    /// window, as [`crate::task::TaskResumeRequest`] does not.
    ///
    /// Refusing is safe in practice because `seen_nonces` is per task: one task
    /// legitimately resumes a handful of times, not `max_nonces` times, and
    /// only a caller holding a valid resume token ever reaches this method.
    ///
    /// [`is_nonce_seen`]: Self::is_nonce_seen
    #[must_use = "a false return means the nonce was NOT recorded and the request must be denied"]
    pub fn try_record_nonce(&mut self, nonce: String) -> bool {
        let effective_max = self.max_nonces.min(MAX_NONCES_CAP);
        if self.seen_nonces.len() >= effective_max {
            return false;
        }
        self.seen_nonces.push(Self::truncate_nonce(nonce));
        true
    }

    /// Enforce `MAX_ENTRY_LEN` at runtime, not just in `validate()`.
    ///
    /// SECURITY (FIND-R60-007): Bounds attacker-controlled nonce values.
    /// SECURITY (FIND-R104-001): Walks back to a char boundary to avoid a
    /// panic on multi-byte UTF-8 sequences straddling the limit.
    fn truncate_nonce(nonce: String) -> String {
        if nonce.len() > MAX_ENTRY_LEN {
            let mut end = MAX_ENTRY_LEN;
            while end > 0 && !nonce.is_char_boundary(end) {
                end -= 1;
            }
            nonce[..end].to_string()
        } else {
            nonce
        }
    }

    /// Get the latest hash in the state chain.
    pub fn latest_hash(&self) -> Option<&str> {
        self.state_chain.last().map(|t| t.hash.as_str())
    }

    /// Get the current sequence number.
    pub fn current_sequence(&self) -> u64 {
        self.state_chain.last().map_or(0, |t| t.sequence)
    }

    /// Validate bounds on deserialized data.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (FIND-R67-FC-002): Validate the inner TrackedTask first.
        self.task
            .validate()
            .map_err(|e| format!("SecureTask inner task: {e}"))?;

        if self.state_chain.len() > MAX_STATE_CHAIN {
            return Err(format!(
                "SecureTask state_chain length {} exceeds max {}",
                self.state_chain.len(),
                MAX_STATE_CHAIN
            ));
        }
        if self.seen_nonces.len() > MAX_NONCES_CAP {
            return Err(format!(
                "SecureTask seen_nonces length {} exceeds max {}",
                self.seen_nonces.len(),
                MAX_NONCES_CAP
            ));
        }
        for (i, nonce) in self.seen_nonces.iter().enumerate() {
            if nonce.len() > MAX_ENTRY_LEN {
                return Err(format!(
                    "SecureTask seen_nonces[{}] length {} exceeds max {}",
                    i,
                    nonce.len(),
                    MAX_ENTRY_LEN
                ));
            }
        }
        for (i, transition) in self.state_chain.iter().enumerate() {
            // SECURITY (FIND-R67-MV-001): Delegate to TaskStateTransition::validate()
            // which checks all fields including hash, prev_hash, timestamp, triggered_by.
            transition
                .validate()
                .map_err(|e| format!("SecureTask state_chain[{i}]: {e}"))?;
        }
        Ok(())
    }
}

impl fmt::Debug for SecureTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureTask")
            .field("task", &self.task)
            .field("encrypted_state", &self.encrypted_state)
            .field("encryption_nonce", &self.encryption_nonce)
            .field("state_chain", &self.state_chain)
            .field(
                "resume_token",
                &self.resume_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("seen_nonces", &self.seen_nonces)
            .field("max_nonces", &self.max_nonces)
            .finish()
    }
}

/// A checkpoint of task state for verification.
///
/// Checkpoints are signed snapshots that can be used to verify
/// task state integrity at a specific point in time.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TaskCheckpoint {
    /// Unique checkpoint identifier.
    pub checkpoint_id: String,
    /// Task ID this checkpoint belongs to.
    pub task_id: String,
    /// Sequence number in the state chain at checkpoint time.
    pub sequence: u64,
    /// Hash of the state chain at checkpoint time.
    pub state_hash: String,
    /// ISO 8601 timestamp of checkpoint creation.
    pub created_at: String,
    /// Ed25519 signature of the checkpoint (hex-encoded).
    pub signature: String,
    /// Public key used to sign (hex-encoded).
    pub public_key: String,
}

/// SECURITY (FIND-R53-001): Custom Debug redacts `signature` and `public_key`
/// to prevent secret leakage in logs/debug output.
impl fmt::Debug for TaskCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskCheckpoint")
            .field("checkpoint_id", &self.checkpoint_id)
            .field("task_id", &self.task_id)
            .field("sequence", &self.sequence)
            .field("state_hash", &self.state_hash)
            .field("created_at", &self.created_at)
            .field("signature", &"[REDACTED]")
            .field("public_key", &"[REDACTED]")
            .finish()
    }
}

impl TaskCheckpoint {
    /// Maximum length for `checkpoint_id` (bytes).
    const MAX_CHECKPOINT_ID_LEN: usize = 256;
    /// Maximum length for `task_id` (bytes).
    const MAX_TASK_ID_LEN: usize = 256;
    /// Maximum length for `state_hash` (bytes).
    const MAX_HASH_LEN: usize = 256;
    /// Maximum length for ISO 8601 timestamp fields (bytes).
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for hex-encoded signature (bytes).
    const MAX_SIGNATURE_LEN: usize = 512;
    /// Maximum length for hex-encoded public key (bytes).
    const MAX_PUBLIC_KEY_LEN: usize = 512;

    /// Validate structural bounds on fields.
    ///
    /// SECURITY (FIND-R53-P3-003): Prevents memory exhaustion and control character
    /// injection from untrusted `TaskCheckpoint` payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.checkpoint_id.is_empty() {
            return Err("TaskCheckpoint checkpoint_id must not be empty".to_string());
        }
        if self.checkpoint_id.len() > Self::MAX_CHECKPOINT_ID_LEN {
            return Err(format!(
                "TaskCheckpoint checkpoint_id length {} exceeds max {}",
                self.checkpoint_id.len(),
                Self::MAX_CHECKPOINT_ID_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.checkpoint_id) {
            return Err(
                "TaskCheckpoint checkpoint_id contains control or format characters".to_string(),
            );
        }
        if self.task_id.is_empty() {
            return Err("TaskCheckpoint task_id must not be empty".to_string());
        }
        if self.task_id.len() > Self::MAX_TASK_ID_LEN {
            return Err(format!(
                "TaskCheckpoint task_id length {} exceeds max {}",
                self.task_id.len(),
                Self::MAX_TASK_ID_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.task_id) {
            return Err("TaskCheckpoint task_id contains control or format characters".to_string());
        }
        if self.state_hash.len() > Self::MAX_HASH_LEN {
            return Err(format!(
                "TaskCheckpoint state_hash length {} exceeds max {}",
                self.state_hash.len(),
                Self::MAX_HASH_LEN,
            ));
        }
        if self.created_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "TaskCheckpoint created_at length {} exceeds max {}",
                self.created_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        // SECURITY (FIND-R224-003): Validate state_hash, created_at, signature, and
        // public_key for dangerous characters. These fields could be used for log
        // injection or identity confusion if control/format characters are present.
        if crate::core::has_dangerous_chars(&self.state_hash) {
            return Err(
                "TaskCheckpoint state_hash contains control or format characters".to_string(),
            );
        }
        if crate::core::has_dangerous_chars(&self.created_at) {
            return Err(
                "TaskCheckpoint created_at contains control or format characters".to_string(),
            );
        }
        if self.signature.len() > Self::MAX_SIGNATURE_LEN {
            return Err(format!(
                "TaskCheckpoint signature length {} exceeds max {}",
                self.signature.len(),
                Self::MAX_SIGNATURE_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.signature) {
            return Err(
                "TaskCheckpoint signature contains control or format characters".to_string(),
            );
        }
        if self.public_key.len() > Self::MAX_PUBLIC_KEY_LEN {
            return Err(format!(
                "TaskCheckpoint public_key length {} exceeds max {}",
                self.public_key.len(),
                Self::MAX_PUBLIC_KEY_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.public_key) {
            return Err(
                "TaskCheckpoint public_key contains control or format characters".to_string(),
            );
        }
        Ok(())
    }
}

/// Request to resume a task with authentication.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskResumeRequest {
    /// Task ID to resume.
    pub task_id: String,
    /// Resume token for authentication.
    pub resume_token: String,
    /// Unique nonce for replay protection (hex-encoded).
    pub nonce: String,
    /// Agent ID requesting the resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

impl TaskResumeRequest {
    /// Maximum length for `task_id` (bytes).
    const MAX_TASK_ID_LEN: usize = 256;
    /// Maximum length for `resume_token` (bytes).
    const MAX_RESUME_TOKEN_LEN: usize = 512;
    /// Maximum length for `nonce` (bytes).
    const MAX_NONCE_LEN: usize = 256;
    /// Maximum length for `agent_id` (bytes).
    const MAX_AGENT_ID_LEN: usize = 256;

    /// Validate structural bounds on all fields.
    ///
    /// SECURITY (R243-TYP-1): `task_id` is used as a HashMap key in
    /// `SecureTaskManager`, `nonce` is stored in `seen_nonces`, and
    /// `resume_token` is compared in constant-time. Without validation,
    /// oversized or control-character-laden strings cause memory exhaustion
    /// and log injection.
    pub fn validate(&self) -> Result<(), String> {
        if self.task_id.is_empty() {
            return Err("TaskResumeRequest task_id must not be empty".to_string());
        }
        if self.task_id.len() > Self::MAX_TASK_ID_LEN {
            return Err(format!(
                "TaskResumeRequest task_id length {} exceeds max {}",
                self.task_id.len(),
                Self::MAX_TASK_ID_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.task_id) {
            return Err(
                "TaskResumeRequest task_id contains control or format characters".to_string(),
            );
        }
        if self.resume_token.is_empty() {
            return Err("TaskResumeRequest resume_token must not be empty".to_string());
        }
        if self.resume_token.len() > Self::MAX_RESUME_TOKEN_LEN {
            return Err(format!(
                "TaskResumeRequest resume_token length {} exceeds max {}",
                self.resume_token.len(),
                Self::MAX_RESUME_TOKEN_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.resume_token) {
            return Err(
                "TaskResumeRequest resume_token contains control or format characters".to_string(),
            );
        }
        if self.nonce.is_empty() {
            return Err("TaskResumeRequest nonce must not be empty".to_string());
        }
        if self.nonce.len() > Self::MAX_NONCE_LEN {
            return Err(format!(
                "TaskResumeRequest nonce length {} exceeds max {}",
                self.nonce.len(),
                Self::MAX_NONCE_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.nonce) {
            return Err(
                "TaskResumeRequest nonce contains control or format characters".to_string(),
            );
        }
        if let Some(ref aid) = self.agent_id {
            if aid.len() > Self::MAX_AGENT_ID_LEN {
                return Err(format!(
                    "TaskResumeRequest agent_id length {} exceeds max {}",
                    aid.len(),
                    Self::MAX_AGENT_ID_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(aid) {
                return Err(
                    "TaskResumeRequest agent_id contains control or format characters".to_string(),
                );
            }
        }
        Ok(())
    }
}

impl fmt::Debug for TaskResumeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskResumeRequest")
            .field("task_id", &self.task_id)
            .field("resume_token", &"[REDACTED]")
            .field("nonce", &self.nonce)
            .field("agent_id", &self.agent_id)
            .finish()
    }
}

/// Result of a task resume attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskResumeResult {
    /// Whether the resume was authorized.
    pub authorized: bool,
    /// The task if authorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<SecureTask>,
    /// Decrypted state data if authorized and available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decrypted_state: Option<serde_json::Value>,
    /// Reason for denial if not authorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
}

impl TaskResumeResult {
    /// Maximum length for `denial_reason` field.
    const MAX_DENIAL_REASON_LEN: usize = 4096;

    /// Validate structural bounds on deserialized data.
    ///
    /// SECURITY (FIND-R216-012): Validates nested SecureTask and denial_reason
    /// to prevent oversized or injection-prone strings.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref task) = self.task {
            task.validate()
                .map_err(|e| format!("TaskResumeResult task: {e}"))?;
        }
        if let Some(ref reason) = self.denial_reason {
            if reason.len() > Self::MAX_DENIAL_REASON_LEN {
                return Err(format!(
                    "TaskResumeResult denial_reason length {} exceeds max {}",
                    reason.len(),
                    Self::MAX_DENIAL_REASON_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(reason) {
                return Err(
                    "TaskResumeResult denial_reason contains control or format characters"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

/// Result of validating a task's state chain integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskIntegrityResult {
    /// Whether the state chain is valid.
    pub valid: bool,
    /// Number of transitions verified.
    pub transitions_verified: u64,
    /// First broken transition index if invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_broken_at: Option<u64>,
    /// Reason for failure if invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

impl TaskIntegrityResult {
    /// Maximum length for `failure_reason` field.
    const MAX_FAILURE_REASON_LEN: usize = 4096;

    /// Validate structural bounds on deserialized data.
    ///
    /// SECURITY (FIND-R216-012): Validates failure_reason to prevent oversized
    /// or injection-prone strings.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref reason) = self.failure_reason {
            if reason.len() > Self::MAX_FAILURE_REASON_LEN {
                return Err(format!(
                    "TaskIntegrityResult failure_reason length {} exceeds max {}",
                    reason.len(),
                    Self::MAX_FAILURE_REASON_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(reason) {
                return Err(
                    "TaskIntegrityResult failure_reason contains control or format characters"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

/// Statistics about secure task management.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureTaskStats {
    /// Total secure tasks tracked.
    pub total_tasks: usize,
    /// Tasks with encrypted state.
    pub encrypted_tasks: usize,
    /// Total state transitions recorded.
    pub total_transitions: u64,
    /// Checkpoints created.
    pub checkpoints_created: u64,
    /// Resume attempts.
    pub resume_attempts: u64,
    /// Successful resumes.
    pub resume_successes: u64,
    /// Replay attacks blocked.
    pub replay_attacks_blocked: u64,
    /// Integrity violations detected.
    pub integrity_violations: u64,
}

impl SecureTaskStats {
    /// Validate structural invariants.
    ///
    /// SECURITY (FIND-R216-012): Currently all fields are bounded integer types,
    /// but provided for forward-compatibility and API consistency.
    pub fn validate(&self) -> Result<(), String> {
        // All fields are u64/usize — no string bounds to check.
        Ok(())
    }
}
