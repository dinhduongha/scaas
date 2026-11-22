// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk plan T20g: links the SDK's wasm-bindgen exports (`scaas_sdk::wasm`, spec §16.4) into one cdylib.
#![forbid(unsafe_code)]
pub use scaas_sdk::wasm::*;
