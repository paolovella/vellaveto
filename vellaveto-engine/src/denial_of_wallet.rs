// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Denial of Wallet (DoW) / unbounded consumption detection (OWASP LLM10).
//!
//! Detects patterns that cause excessive resource consumption:
//! - Agentic loop amplification (tool calls that trigger more tool calls)
//! - High-cost inference patterns (very long outputs, many completions)
//! - Token exhaustion via repeated sampling
//! - Recursive tool invocation patterns

/// Maximum number of in-window call timestamps retained.
///
/// This bounds memory, not correctness. `record_call` evicts timestamps that
/// have aged out of the rate window before recording a new one, so a session's
/// live window stays far below this in normal operation; reaching it means this
/// many calls landed inside a single window, which is itself a spike.
const MAX_WINDOW_ENTRIES: usize = 1000;

/// Width of the sliding window used for rate-spike detection (ms).
const RATE_WINDOW_MS: u64 = 60_000;

/// Maximum recent tool names retained for recursive-loop detection.
const MAX_RECENT_TOOLS: usize = 20;

/// Maximum bytes of a tool name retained for recursive-loop detection.
const MAX_TOOL_NAME_BYTES: usize = 256;

/// A denial of wallet finding.
#[derive(Debug, Clone)]
pub struct DoWFinding {
    pub finding_type: DoWType,
    pub severity: u32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoWType {
    /// Tool call rate exceeds normal bounds.
    RateSpike,
    /// Recursive tool pattern detected (A calls B calls A).
    RecursiveLoop,
    /// Sampling requests consuming excessive tokens.
    TokenExhaustion,
    /// Session duration exceeds bounds.
    SessionExhaustion,
}

/// Tracks resource consumption patterns per session.
pub struct DoWTracker {
    /// Tool call timestamps (ms).
    call_timestamps: Vec<u64>,
    /// Recent tool names for loop detection.
    recent_tools: Vec<String>,
    /// Total estimated tokens consumed.
    total_tokens: u64,
    /// Session start time (ms).
    session_start_ms: u64,
    /// Config thresholds.
    max_calls_per_minute: u32,
    max_tokens_per_session: u64,
    max_session_duration_ms: u64,
}

impl DoWTracker {
    pub fn new(
        max_calls_per_minute: u32,
        max_tokens_per_session: u64,
        max_session_duration_ms: u64,
    ) -> Self {
        // The window holds at most MAX_WINDOW_ENTRIES timestamps, so a
        // threshold at or above that could never be exceeded and the check
        // would silently never fire. Clamp it below the cap -- downwards, so
        // the effect is to detect sooner rather than never.
        let max_calls_per_minute = max_calls_per_minute.min(MAX_WINDOW_ENTRIES as u32 - 1);
        Self {
            call_timestamps: Vec::new(),
            recent_tools: Vec::new(),
            total_tokens: 0,
            session_start_ms: now_ms(),
            max_calls_per_minute,
            max_tokens_per_session,
            max_session_duration_ms,
        }
    }

    /// Record a tool call and check for DoW patterns.
    pub fn record_call(&mut self, tool_name: &str, estimated_tokens: u64) -> Vec<DoWFinding> {
        self.record_call_at(tool_name, estimated_tokens, now_ms())
    }

    /// [`record_call`](Self::record_call) with the current time supplied by the
    /// caller.
    ///
    /// Split out so the sliding-window and session-duration logic can be tested
    /// deterministically. The freeze defect below was invisible to a fast test
    /// precisely because every call landed in the same window; proving it needs
    /// a clock that can move.
    fn record_call_at(
        &mut self,
        tool_name: &str,
        estimated_tokens: u64,
        now: u64,
    ) -> Vec<DoWFinding> {
        let mut findings = Vec::new();

        // Record timestamp.
        //
        // SECURITY: evict timestamps that have aged out of the window before
        // recording this call. Previously this only pushed while
        // `len() < MAX_WINDOW_ENTRIES` and never removed anything, so once that
        // many calls had been recorded the vector froze. The retained
        // timestamps then aged past the window and `calls_last_minute` settled
        // permanently at zero -- RateSpike could never fire again for the life
        // of the tracker, so an attacker only had to make enough cheap calls
        // first and then wait out one window. The window now slides, which
        // makes the cap a memory bound instead of an off switch.
        let window_start = now.saturating_sub(RATE_WINDOW_MS);
        self.call_timestamps.retain(|&t| t >= window_start);
        if self.call_timestamps.len() < MAX_WINDOW_ENTRIES {
            self.call_timestamps.push(now);
        }

        // Record tool name for loop detection
        if self.recent_tools.len() >= MAX_RECENT_TOOLS {
            self.recent_tools.remove(0);
        }
        // SECURITY: truncate on a char boundary. Slicing a `&str` by byte index
        // panics when that index splits a codepoint, and on the HTTP, WebSocket
        // and gRPC paths the tool name is attacker-controlled request data --
        // which made this a reachable denial of service rather than a latent
        // bug. `floor_char_boundary` is still unstable, hence the walk back.
        let truncated = if tool_name.len() <= MAX_TOOL_NAME_BYTES {
            tool_name
        } else {
            let mut end = MAX_TOOL_NAME_BYTES;
            while end > 0 && !tool_name.is_char_boundary(end) {
                end -= 1;
            }
            &tool_name[..end]
        };
        self.recent_tools.push(truncated.to_string());

        // Track tokens
        self.total_tokens = self.total_tokens.saturating_add(estimated_tokens);

        // Check rate spike.
        //
        // `call_timestamps` was pruned to the window above, so its length IS
        // the in-window count; the filter is kept as a belt-and-braces guard
        // against a caller passing a `now` that moves backwards.
        let calls_last_minute = self
            .call_timestamps
            .iter()
            .filter(|&&t| t >= window_start)
            .count() as u32;
        if calls_last_minute > self.max_calls_per_minute {
            findings.push(DoWFinding {
                finding_type: DoWType::RateSpike,
                severity: 70,
                description: format!(
                    "{calls_last_minute} calls in last minute (max {0})",
                    self.max_calls_per_minute
                ),
            });
        }

        // Check recursive loop (A→B→A pattern)
        if self.recent_tools.len() >= 4 {
            let len = self.recent_tools.len();
            // Check for A-B-A-B pattern
            if self.recent_tools[len - 1] == self.recent_tools[len - 3]
                && self.recent_tools[len - 2] == self.recent_tools[len - 4]
                && self.recent_tools[len - 1] != self.recent_tools[len - 2]
            {
                findings.push(DoWFinding {
                    finding_type: DoWType::RecursiveLoop,
                    severity: 85,
                    description: format!(
                        "Recursive loop: {} ↔ {}",
                        &self.recent_tools[len - 1],
                        &self.recent_tools[len - 2]
                    ),
                });
            }
        }

        // Check token exhaustion
        if self.total_tokens > self.max_tokens_per_session {
            findings.push(DoWFinding {
                finding_type: DoWType::TokenExhaustion,
                severity: 75,
                description: format!(
                    "{} tokens consumed (max {})",
                    self.total_tokens, self.max_tokens_per_session
                ),
            });
        }

        // Check session exhaustion
        let duration = now.saturating_sub(self.session_start_ms);
        if duration > self.max_session_duration_ms {
            findings.push(DoWFinding {
                finding_type: DoWType::SessionExhaustion,
                severity: 60,
                description: format!(
                    "Session running {}ms (max {}ms)",
                    duration, self.max_session_duration_ms
                ),
            });
        }

        findings
    }

    /// Get total tokens consumed.
    pub fn total_tokens(&self) -> u64 {
        self.total_tokens
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_spike_detected() {
        let mut tracker = DoWTracker::new(5, 1_000_000, 3_600_000);
        for _ in 0..6 {
            tracker.record_call("tool", 10);
        }
        let findings = tracker.record_call("tool", 10);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == DoWType::RateSpike));
    }

    #[test]
    fn test_recursive_loop_detected() {
        let mut tracker = DoWTracker::new(100, 1_000_000, 3_600_000);
        tracker.record_call("tool_a", 10);
        tracker.record_call("tool_b", 10);
        tracker.record_call("tool_a", 10);
        let findings = tracker.record_call("tool_b", 10);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == DoWType::RecursiveLoop));
    }

    #[test]
    fn test_token_exhaustion() {
        let mut tracker = DoWTracker::new(100, 100, 3_600_000);
        tracker.record_call("tool", 60);
        let findings = tracker.record_call("tool", 60);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == DoWType::TokenExhaustion));
    }

    // ── Regression tests for the two defects found while planning transport
    // ── parity. Both are written to FAIL against the original implementation.

    #[test]
    fn rate_spike_still_detected_after_window_cap_is_reached() {
        // DEFECT: `call_timestamps` was capped at MAX_WINDOW_ENTRIES and never
        // pruned. After that many calls the vector froze; the retained
        // timestamps then aged out of the window and `calls_last_minute`
        // settled permanently at zero, so RateSpike could never fire again for
        // the life of the tracker. An attacker made enough cheap calls to fill
        // the window, waited one window out, and the rate check was gone.
        //
        // This needs a clock that moves: with every call in the same window the
        // frozen timestamps still counted, which is why a fast test passed
        // against the broken code.
        let mut tracker = DoWTracker::new(5, u64::MAX, u64::MAX);
        let t0 = now_ms();

        // Fill the window past its cap.
        for _ in 0..(MAX_WINDOW_ENTRIES + 50) {
            tracker.record_call_at("tool", 0, t0);
        }

        // One window later, a fresh burst must still be caught.
        let t1 = t0 + RATE_WINDOW_MS + 1_000;
        for _ in 0..10 {
            tracker.record_call_at("tool", 0, t1);
        }
        let findings = tracker.record_call_at("tool", 0, t1);
        assert!(
            findings
                .iter()
                .any(|f| f.finding_type == DoWType::RateSpike),
            "the rate check must survive the window cap; it is a memory bound, \
             not an off switch"
        );
    }

    #[test]
    fn stale_timestamps_are_evicted_not_retained() {
        // The other half of the same fix: a burst that has aged out must stop
        // counting, so the window genuinely slides in both directions.
        let mut tracker = DoWTracker::new(50, u64::MAX, u64::MAX);
        let t0 = now_ms();
        for _ in 0..40 {
            tracker.record_call_at("tool", 0, t0);
        }
        assert_eq!(tracker.call_timestamps.len(), 40);

        let t1 = t0 + RATE_WINDOW_MS + 1;
        let findings = tracker.record_call_at("tool", 0, t1);
        assert_eq!(
            tracker.call_timestamps.len(),
            1,
            "timestamps older than the window must be evicted"
        );
        assert!(
            findings.is_empty(),
            "a single call after the window moved on is not a spike: {findings:?}"
        );
    }

    #[test]
    fn threshold_at_or_above_the_window_cap_is_clamped() {
        // A threshold the window can never reach would mean the check never
        // fires. It is clamped downwards, so it still fires.
        let mut tracker = DoWTracker::new(u32::MAX, u64::MAX, u64::MAX);
        assert!(tracker.max_calls_per_minute < MAX_WINDOW_ENTRIES as u32);
        let t0 = now_ms();
        let mut saw_spike = false;
        for _ in 0..MAX_WINDOW_ENTRIES {
            if tracker
                .record_call_at("tool", 0, t0)
                .iter()
                .any(|f| f.finding_type == DoWType::RateSpike)
            {
                saw_spike = true;
                break;
            }
        }
        assert!(
            saw_spike,
            "an unreachable threshold must be clamped, not left undetectable"
        );
    }

    #[test]
    fn oversized_multibyte_tool_name_does_not_panic() {
        // DEFECT: `tool_name[..tool_name.len().min(256)]` sliced by BYTE index.
        // Slicing a `&str` at an index that splits a codepoint panics. On stdio
        // the tool name comes from a local child process; on HTTP, WebSocket and
        // gRPC it is attacker-controlled request data, which makes this a
        // reachable denial of service.
        //
        // Reachability depends on the codepoint width: 256 is divisible by 2 and
        // 4, so names built from 2-byte or 4-byte characters land exactly on the
        // boundary and never panicked. 256 % 3 == 1, so a 3-byte character such
        // as U+20AC straddles it -- that is the case that crashed.
        let mut tracker = DoWTracker::new(100, u64::MAX, u64::MAX);

        let three_byte = "\u{20AC}".repeat(150);
        assert!(three_byte.len() > MAX_TOOL_NAME_BYTES);
        assert!(
            !three_byte.is_char_boundary(MAX_TOOL_NAME_BYTES),
            "this input must straddle the truncation bound or it proves nothing"
        );
        let _ = tracker.record_call(&three_byte, 0);

        // The widths that happen to align, for completeness.
        let _ = tracker.record_call(&"\u{E9}".repeat(200), 0);
        let _ = tracker.record_call(&"\u{1F600}".repeat(100), 0);

        // A mixed string, where the straddling character is not the first.
        let mixed = format!("{}{}", "a".repeat(254), "\u{20AC}".repeat(10));
        assert!(!mixed.is_char_boundary(MAX_TOOL_NAME_BYTES));
        let _ = tracker.record_call(&mixed, 0);

        // Truncation must still bound what is stored.
        assert!(
            tracker
                .recent_tools
                .iter()
                .all(|t| t.len() <= MAX_TOOL_NAME_BYTES),
            "a truncated name must not exceed the byte bound"
        );
    }

    #[test]
    fn recent_tools_stays_bounded() {
        let mut tracker = DoWTracker::new(u32::MAX, u64::MAX, u64::MAX);
        for i in 0..(MAX_RECENT_TOOLS * 5) {
            tracker.record_call(&format!("tool_{i}"), 0);
        }
        assert!(
            tracker.recent_tools.len() <= MAX_RECENT_TOOLS,
            "recent_tools grew past its bound: {}",
            tracker.recent_tools.len()
        );
    }

    #[test]
    fn test_normal_usage_no_findings() {
        let mut tracker = DoWTracker::new(100, 1_000_000, 3_600_000);
        let findings = tracker.record_call("read_file", 50);
        assert!(findings.is_empty());
    }
}
