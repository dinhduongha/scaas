// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `scaas-rpc`: the one network crate (CLI-RPC-01, docs/clients/scaas-rpc.md; spec docs/superpowers/specs/2026-11-17-scaas-rpc.md).
//! The endpoint list and its read and write rules (ARCH-POS-15: failover by default, strict majority as an option), a bounded
//! transport, a reader per chain family (EVM first), the scaas-node client. It holds no key and signs nothing. Compiles for
//! wasm32, not run there. UNAUDITED.
#![forbid(unsafe_code)]

pub mod endpoint;
pub mod error;
pub mod http;
pub mod pool;

pub use endpoint::{Class, Endpoint, EndpointAuth, Label, ListConfig, NodeList, Policy, Purpose, Secret};
pub use error::{EndpointFailure, FailureKind, RpcError};
