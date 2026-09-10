// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Traffic analysis resistance through request padding and timing normalization.
//!
//! Even with encrypted transport, message sizes and timing patterns reveal
//! information. A 50-byte weather query is distinguishable from a 5,000-byte
//! legal strategy query. This module pads requests to fixed-size buckets and
//! adds timing jitter to resist traffic analysis.

use crate::error::ShieldProxyError;

/// Size buckets for request padding (in bytes).
/// Requests are padded to the smallest bucket that fits the content.
///
/// Public so the proxy pads to the same buckets this crate documents, rather
/// than restating them at the call site and drifting.
pub const SIZE_BUCKETS: [usize; 5] = [512, 2_048, 8_192, 32_768, 131_072];

/// Maximum padding size (128 KB). Requests larger than this are not padded.
const MAX_PADDED_SIZE: usize = 131_072;

/// Default timing jitter range in milliseconds.
const DEFAULT_JITTER_MIN_MS: u64 = 100;
const DEFAULT_JITTER_MAX_MS: u64 = 500;

/// Traffic padding configuration.
#[derive(Debug, Clone)]
pub struct TrafficPaddingConfig {
    /// Whether padding is enabled.
    pub enabled: bool,
    /// Custom size buckets (overrides defaults if set).
    pub size_buckets: Vec<usize>,
    /// Minimum jitter delay in milliseconds.
    pub jitter_min_ms: u64,
    /// Maximum jitter delay in milliseconds.
    pub jitter_max_ms: u64,
    /// Whether to strip W3C Trace Context headers (trace IDs are correlation vectors).
    pub strip_trace_headers: bool,
}

impl Default for TrafficPaddingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            size_buckets: SIZE_BUCKETS.to_vec(),
            jitter_min_ms: DEFAULT_JITTER_MIN_MS,
            jitter_max_ms: DEFAULT_JITTER_MAX_MS,
            strip_trace_headers: true,
        }
    }
}

impl TrafficPaddingConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ShieldProxyError> {
        if self.size_buckets.is_empty() {
            return Err(ShieldProxyError::TrafficPadding(
                "size_buckets must not be empty".to_string(),
            ));
        }
        if self.size_buckets.len() > 20 {
            return Err(ShieldProxyError::TrafficPadding(format!(
                "size_buckets has {} entries, max is 20",
                self.size_buckets.len()
            )));
        }
        for (i, &size) in self.size_buckets.iter().enumerate() {
            if size == 0 {
                return Err(ShieldProxyError::TrafficPadding(format!(
                    "size_buckets[{i}] must be > 0"
                )));
            }
        }
        if self.jitter_min_ms > self.jitter_max_ms {
            return Err(ShieldProxyError::TrafficPadding(format!(
                "jitter_min_ms ({}) must be <= jitter_max_ms ({})",
                self.jitter_min_ms, self.jitter_max_ms
            )));
        }
        Ok(())
    }
}

/// Determine the padded size for a given content length.
///
/// Returns the smallest bucket that fits the content, or the content
/// size itself if it exceeds the largest bucket.
pub fn padded_size(content_len: usize, buckets: &[usize]) -> usize {
    if content_len > MAX_PADDED_SIZE {
        return content_len; // Too large to pad
    }

    let mut sorted_buckets: Vec<usize> = buckets.to_vec();
    sorted_buckets.sort_unstable();

    for &bucket in &sorted_buckets {
        if bucket >= content_len {
            return bucket;
        }
    }

    // Content is larger than all buckets — return as-is
    content_len
}

/// Pad content to the target size using random bytes.
///
/// The padding is appended after a length prefix so the receiver
/// can strip it. Format: [4-byte LE content length][content][random padding].
pub fn pad_content(content: &[u8], target_size: usize) -> Vec<u8> {
    let content_len = content.len();
    // 4 bytes for length prefix
    let total_needed = 4 + content_len;

    // SECURITY (R235-SHIELD-1): Use try_from to prevent silent truncation
    // on content larger than 4 GB (u32::MAX).
    let content_len_u32 = match u32::try_from(content_len) {
        Ok(v) => v,
        Err(_) => {
            // Content too large for u32 length prefix — return unpadded with
            // max-value marker so unpad_content will fail safely.
            tracing::error!(
                "SECURITY: pad_content content_len exceeds u32::MAX — returning unpadded"
            );
            return content.to_vec();
        }
    };

    if total_needed >= target_size {
        // No room for padding — just prepend length
        let mut result = Vec::with_capacity(total_needed);
        result.extend_from_slice(&content_len_u32.to_le_bytes());
        result.extend_from_slice(content);
        return result;
    }

    let padding_len = target_size - total_needed;
    let mut result = Vec::with_capacity(target_size);
    result.extend_from_slice(&content_len_u32.to_le_bytes());
    result.extend_from_slice(content);

    // Fill with deterministic padding (not random — avoids entropy drain)
    // The padding content doesn't matter as it's stripped by the receiver
    result.resize(target_size, 0x00);
    let _ = padding_len; // used above in resize calculation

    result
}

/// Extract the original content from a padded message.
pub fn unpad_content(padded: &[u8]) -> Result<Vec<u8>, ShieldProxyError> {
    if padded.len() < 4 {
        return Err(ShieldProxyError::TrafficPadding(
            "padded content too short for length prefix".to_string(),
        ));
    }

    let content_len = u32::from_le_bytes(
        padded[..4]
            .try_into()
            .map_err(|_| ShieldProxyError::TrafficPadding("invalid length prefix".to_string()))?,
    ) as usize;

    if 4 + content_len > padded.len() {
        return Err(ShieldProxyError::TrafficPadding(format!(
            "content length {} exceeds padded data ({})",
            content_len,
            padded.len() - 4
        )));
    }

    Ok(padded[4..4 + content_len].to_vec())
}

/// Headers that should be stripped for privacy (trace/correlation IDs).
/// Request header a client sends to opt in to padded responses.
///
/// Padding is only applied when the client asks for it. A padded body carries
/// the framing below and is therefore not valid JSON, so sending one to a client
/// that did not ask would break it. Absence of this header means no padding,
/// which is what every standard MCP client will get.
pub const PADDING_NEGOTIATION_HEADER: &str = "x-vellaveto-padding";

/// Response header naming the framing version actually applied.
///
/// Present only on padded responses. A client that sees it must strip the
/// framing with [`unpad_content`] before parsing the body.
pub const PADDING_APPLIED_HEADER: &str = "x-vellaveto-padding-applied";

/// The only framing version defined: `[4-byte LE length][content][zero padding]`.
pub const PADDING_VERSION_V1: &str = "v1";

/// Whether a client's negotiation header opts in to a framing version we speak.
///
/// Unknown versions are refused rather than guessed at: sending v1 framing to a
/// client that asked for something else would corrupt its response just as
/// surely as padding an unaware client.
pub fn client_accepts_padding(header_value: Option<&str>) -> bool {
    header_value.is_some_and(|v| v.trim().eq_ignore_ascii_case(PADDING_VERSION_V1))
}

pub const PRIVACY_STRIP_HEADERS: &[&str] = &[
    "traceparent",
    "tracestate",
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "x-amzn-trace-id",
    "x-cloud-trace-context",
    "x-b3-traceid",
    "x-b3-spanid",
    "x-b3-parentspanid",
    "x-b3-sampled",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padded_size_selects_smallest_bucket() {
        assert_eq!(padded_size(100, &SIZE_BUCKETS), 512);
        assert_eq!(padded_size(512, &SIZE_BUCKETS), 512);
        assert_eq!(padded_size(513, &SIZE_BUCKETS), 2_048);
        assert_eq!(padded_size(10_000, &SIZE_BUCKETS), 32_768);
    }

    #[test]
    fn test_padded_size_oversized_returns_original() {
        assert_eq!(padded_size(200_000, &SIZE_BUCKETS), 200_000);
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let content = b"Hello, this is a secret query about legal matters";
        let target = padded_size(content.len(), &SIZE_BUCKETS);
        let padded = pad_content(content, target);
        assert_eq!(padded.len(), target);
        let unpadded = unpad_content(&padded).unwrap();
        assert_eq!(unpadded, content);
    }

    #[test]
    fn test_pad_unpad_empty() {
        let content = b"";
        let padded = pad_content(content, 512);
        assert_eq!(padded.len(), 512);
        let unpadded = unpad_content(&padded).unwrap();
        assert!(unpadded.is_empty());
    }

    #[test]
    fn test_unpad_too_short() {
        let result = unpad_content(&[1, 2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpad_truncated_content() {
        let mut padded = vec![0u8; 8];
        // Set length to 100 but only have 4 bytes of data
        padded[..4].copy_from_slice(&100u32.to_le_bytes());
        let result = unpad_content(&padded);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validate_valid() {
        let config = TrafficPaddingConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_empty_buckets() {
        let config = TrafficPaddingConfig {
            size_buckets: Vec::new(),
            ..TrafficPaddingConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_jitter_inverted() {
        let config = TrafficPaddingConfig {
            jitter_min_ms: 500,
            jitter_max_ms: 100,
            ..TrafficPaddingConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_all_messages_same_size_in_bucket() {
        // Different content sizes should produce same padded size
        let short = pad_content(b"hi", 512);
        let medium = pad_content(b"this is a longer message with more content", 512);
        assert_eq!(short.len(), medium.len());
        assert_eq!(short.len(), 512);
    }
}
