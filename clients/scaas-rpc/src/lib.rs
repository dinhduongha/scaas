// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `scaas-rpc`: the one network crate (CLI-RPC-01, docs/clients/scaas-rpc.md; spec docs/superpowers/specs/2026-11-17-scaas-rpc.md).
//! The endpoint list and its read and write rules (ARCH-POS-15: failover by default, strict majority as an option), a bounded
//! transport, a reader per chain family (EVM first), the scaas-node client. It holds no key and signs nothing. Compiles for
//! wasm32, not run there. UNAUDITED.
#![forbid(unsafe_code)]

#[cfg(feature = "algorand")]
pub mod algorand;
#[cfg(feature = "aptos")]
pub mod aptos;
#[cfg(feature = "arweave")]
pub mod arweave;
#[cfg(feature = "bitcoin")]
pub mod bitcoin;
#[cfg(feature = "ton")]
pub mod boc;
#[cfg(feature = "cosmos")]
pub mod cosmos;
pub mod endpoint;
pub mod error;
#[cfg(feature = "evm")]
pub mod evm;
pub mod family;
#[cfg(feature = "evm")]
pub mod hedera;
pub mod http;
#[cfg(feature = "near")]
pub mod near;
#[cfg(feature = "node-client")]
pub mod node;
pub mod pool;
#[cfg(feature = "solana")]
pub mod solana;
#[cfg(feature = "soroban")]
pub mod soroban;
#[cfg(feature = "substrate")]
pub mod substrate;
#[cfg(feature = "sui")]
pub mod sui;
#[cfg(feature = "ton")]
pub mod ton;

pub use endpoint::{
    Class, Endpoint, EndpointAuth, Fanout, Label, ListConfig, NodeList, Policy, Purpose, Secret,
};
pub use error::{EndpointFailure, FailureKind, RpcError};
