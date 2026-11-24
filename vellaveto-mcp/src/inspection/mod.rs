// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Shared response inspection for prompt injection detection and DLP scanning.
//!
//! This module provides pattern-based detection of:
//! - **Prompt injection attempts** in MCP tool responses (OWASP MCP06)
//! - **Secret exfiltration** via tool call parameters and responses (OWASP ASI03)
//! - **Tool description attacks** in `tools/list` responses (OWASP ASI02)
//! - **Multimodal injection** via images and documents (requires `multimodal` feature)
//!
//! Both the stdio proxy and HTTP proxy use these functions to scan content
//! before relaying it to/from the agent.
//!
//! # Modules
//!
//! - [`scanner_base`] - Common scanner infrastructure (IMP-002)
//! - [`injection`] - Prompt injection pattern detection
//! - [`dlp`] - Data Loss Prevention / secret scanning
//! - [`tool_description`] - Tool description injection scanning
//! - [`multimodal`] - Image/document injection detection (feature-gated)
//! - [`tool_param_scan`] - Single-pass tool-call parameter scan (jailbreak,
//!   token leakage, memory-query poisoning)
//! - [`util`] - Shared utilities (base64 decoding, transformations)

pub mod cross_call_dlp;
pub mod dlp;
pub mod injection;
pub mod multimodal;
pub mod scanner_base;
pub mod tool_description;
pub mod tool_param_scan;
pub mod util;
pub mod verified_cross_call_dlp;
pub mod verified_dlp_core;

// Re-export all public items from submodules for backwards compatibility
pub use dlp::{
    active_pattern_count, dlp_pattern_health, is_dlp_available, scan_notification_for_secrets,
    scan_parameters_for_secrets, scan_response_for_secrets, scan_text_for_secrets,
    validate_dlp_patterns, DlpFinding, DLP_PATTERNS,
};
pub use injection::{
    injection_pattern_count, inspect_for_injection, is_injection_available,
    sanitize_for_injection_scan, scan_notification_for_injection, scan_response_for_injection,
    validate_injection_patterns, InjectionScanner, DEFAULT_INJECTION_PATTERNS,
    INJECTION_DETECTION_UNAVAILABLE,
};
pub use scanner_base::{
    extract_notification_text, extract_response_text, normalize_text, traverse_json_strings,
    traverse_json_strings_with_keys, ScanFinding, ScannerType, MAX_SCAN_DEPTH,
};
pub use tool_description::{
    collect_schema_descriptions, scan_tool_descriptions, scan_tool_descriptions_with_scanner,
    ToolDescriptionFinding,
};

// Multimodal content safety
pub use multimodal::{
    scan_blob_for_injection, ContentType, MultimodalConfig, MultimodalError,
    MultimodalInjectionFinding, MultimodalScanResult, MultimodalScanner, StegoIndicator,
};
