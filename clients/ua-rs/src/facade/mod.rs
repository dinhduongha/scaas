// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The facades (spec §10): `ua-rs` holds the key and gives the ABI; every proof, transcript, statement and encryption stays in
//! the prover crates. Zether and PQZ are separate modules, handles and features; neither calls the other. UNAUDITED.
#[cfg(feature = "pqz")]
pub mod pqz;
#[cfg(feature = "zether")]
pub mod zether;
