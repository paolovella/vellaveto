// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Core types for the Vellaveto MCP tool firewall.
//!
//! This crate defines the foundational data structures shared across all
//! Vellaveto components: [`Action`](core::Action), [`Policy`](core::Policy),
//! [`Verdict`](core::Verdict), [`EvaluationContext`](identity::EvaluationContext),
//! identity types, ABAC attributes, compliance mappings, and wire formats.
//!
//! `vellaveto-types` is a leaf crate with no internal dependencies — all other
//! Vellaveto crates depend on it.

pub mod abac;
pub mod acis;
pub mod asset_inventory;
pub mod audit_store;
pub mod capability;
pub mod command;
pub mod compliance;
pub mod core;
pub mod deployment;
pub mod did_plc;
pub mod discovery;
pub mod etdi;
pub mod evidence_pack;
pub mod extension;
pub mod gateway;
pub mod governance;
pub mod identity;
pub mod json_rpc;
pub mod metering;
pub mod minja;
pub mod nhi;
pub mod policy_lifecycle;
pub mod posture;
pub mod projector;
pub mod protocol_version;
pub mod provenance;
pub mod security_context_token;
pub mod shield;
pub mod signing_domain;
pub mod task;
pub mod threat;
pub mod time_util;
pub mod transport;
pub mod unicode;
pub mod uri_util;
pub mod verification;
pub mod verified_transport_context;
pub mod zk_audit;

#[cfg(test)]
mod tests;

// Re-export everything for backward compatibility.
// External crates import types from the crate root.
pub use self::core::*;
pub use abac::*;
pub use acis::*;
pub use asset_inventory::*;
pub use audit_store::*;
pub mod delegation_token;
pub mod output_contract;
pub mod supply_chain;
pub use capability::*;
pub use command::*;
pub use compliance::*;
pub use deployment::*;
pub use did_plc::*;
pub use discovery::*;
pub use etdi::*;
pub use evidence_pack::*;
pub use extension::*;
pub use gateway::*;
pub use governance::*;
pub use identity::*;
pub use json_rpc::*;
pub use metering::*;
pub use minja::*;
pub use nhi::*;
pub use policy_lifecycle::*;
pub use projector::*;
pub use protocol_version::*;
pub use provenance::*;
pub use shield::*;
pub use task::*;
pub use threat::*;
pub use transport::*;
pub use verification::*;
pub use verified_transport_context::*;
pub use zk_audit::*;
