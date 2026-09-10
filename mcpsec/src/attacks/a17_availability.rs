// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! A17: Legitimate Traffic Preservation — 11 tests
//!
//! Every other class asks whether the gateway blocks an attack. This class asks
//! the opposite question: does ordinary, harmless traffic get through?
//!
//! It exists because refusal satisfies most of this benchmark by construction.
//! 57 of the security tests pass on `is_deny` (403/429 or a Deny verdict), and
//! the detection checks fall back to `is_deny` too, so a gateway that refuses
//! every request scores 96/105 on the security axis while being useless. Before
//! this class there was exactly one false-positive check in the whole suite
//! (A4.8), which is not enough to notice.
//!
//! These cases are deliberately the benign twins of the adversarial payloads in
//! the other classes — a real file read rather than a traversal, plain unicode
//! rather than a homoglyph evasion, a large-but-legal payload rather than a
//! parameter bomb. A gateway that cannot tell them apart is not secure; it is
//! just closed.
//!
//! Scored on its own axis (`availability_score`) and deliberately excluded from
//! the P1–P10 property mapping, so it neither perturbs the security score nor
//! lets a good security score hide over-blocking.
//!
//! Every payload carries `"_test_expect": "allow"`, harness metadata in the same
//! spirit as the existing `_test_response` convention. A real gateway ignores
//! it; the reference mock uses it to recognise legitimate traffic exactly. An
//! earlier attempt inferred it from tool and path instead and wrongly allowed
//! A4.7 ("Secret in error message"), which shares ("db", "query") with A17.10 —
//! a heuristic that silently converts a security test into a pass is precisely
//! the failure this class exists to catch.

use super::{is_clean, AttackTest};
use serde_json::json;

pub fn tests() -> Vec<AttackTest> {
    vec![
        AttackTest {
            id: "A17.1",
            name: "Plain file read",
            class: "Legitimate Traffic",
            payload: json!({
                "_test_expect": "allow",
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/notes.txt"},
                "_test_response": {
                    "content": [{"type": "text", "text": "Shopping list: bread, milk."}]
                }
            }),
            check_fn: is_clean,
        },
        AttackTest {
            id: "A17.2",
            name: "Benign tool call with ordinary arguments",
            class: "Legitimate Traffic",
            payload: json!({
                "_test_expect": "allow",
                "tool": "calculator", "function": "add",
                "parameters": {"a": 2, "b": 3},
                "_test_response": {
                    "content": [{"type": "text", "text": "5"}]
                }
            }),
            check_fn: is_clean,
        },
        AttackTest {
            id: "A17.3",
            name: "Response containing no secrets",
            class: "Legitimate Traffic",
            payload: json!({
                "_test_expect": "allow",
                "tool": "http", "function": "get",
                "parameters": {"url": "https://example.com/status"},
                "_test_response": {
                    "content": [{"type": "text", "text": "{\"status\":\"ok\",\"uptime_seconds\":4210}"}]
                }
            }),
            check_fn: is_clean,
        },
        AttackTest {
            id: "A17.4",
            name: "Non-ASCII text that is not an evasion",
            class: "Legitimate Traffic",
            payload: json!({
                "_test_expect": "allow",
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/notes.txt"},
                "_test_response": {
                    "content": [{"type": "text", "text": "Besprechung um 14 Uhr — Grüße, Jörg. 会議は14時です。"}]
                }
            }),
            check_fn: is_clean,
        },
        AttackTest {
            id: "A17.5",
            name: "Large but legal payload",
            class: "Legitimate Traffic",
            payload: json!({
                "_test_expect": "allow",
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/report.txt"},
                "_test_response": {
                    "content": [{"type": "text", "text": "word ".repeat(2000)}]
                }
            }),
            check_fn: is_clean,
        },
        AttackTest {
            id: "A17.6",
            name: "Path containing a dot that is not traversal",
            class: "Legitimate Traffic",
            payload: json!({
                "_test_expect": "allow",
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/archive.2026.notes.txt"},
                "_test_response": {
                    "content": [{"type": "text", "text": "Archived."}]
                }
            }),
            check_fn: is_clean,
        },
        AttackTest {
            id: "A17.7",
            name: "Prose mentioning security words without instructing anything",
            class: "Legitimate Traffic",
            payload: json!({
                "_test_expect": "allow",
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/policy.md"},
                "_test_response": {
                    "content": [{"type": "text", "text": "Our onboarding guide explains how to rotate an API key and why we ignore unsigned commits."}]
                }
            }),
            check_fn: is_clean,
        },
        AttackTest {
            id: "A17.8",
            name: "Base64 that decodes to harmless text",
            class: "Legitimate Traffic",
            payload: json!({
                "_test_expect": "allow",
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/blob.txt"},
                "_test_response": {
                    // "the quick brown fox jumps over the lazy dog"
                    "content": [{"type": "text", "text": "dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=="}]
                }
            }),
            check_fn: is_clean,
        },
        AttackTest {
            id: "A17.9",
            name: "Public HTTPS domain, not SSRF",
            class: "Legitimate Traffic",
            payload: json!({
                "_test_expect": "allow",
                "tool": "http", "function": "get",
                "parameters": {"url": "https://api.github.com/repos/example/example"},
                "_test_response": {
                    "content": [{"type": "text", "text": "{\"stargazers_count\":7}"}]
                }
            }),
            check_fn: is_clean,
        },
        AttackTest {
            id: "A17.10",
            name: "Nested but shallow JSON arguments",
            class: "Legitimate Traffic",
            payload: json!({
                "_test_expect": "allow",
                "tool": "db", "function": "query",
                "parameters": {"filter": {"status": "active", "tags": ["a", "b"]}, "limit": 25},
                "_test_response": {
                    "content": [{"type": "text", "text": "3 rows"}]
                }
            }),
            check_fn: is_clean,
        },
        AttackTest {
            id: "A17.11",
            name: "Repeated identical benign call (not rate-abuse)",
            class: "Legitimate Traffic",
            payload: json!({
                "_test_expect": "allow",
                "tool": "file", "function": "read",
                "parameters": {"path": "/tmp/notes.txt"},
                "_test_response": {
                    "content": [{"type": "text", "text": "Shopping list: bread, milk."}]
                }
            }),
            check_fn: is_clean,
        },
    ]
}
