// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The JS / TS binding (spec §16.4; plan T20g; feature `wasm`): wasm-bindgen exports for `wasm32-unknown-unknown` of the same
//! list as UniFFI's surface (`binding_list!`, one more arm: [`wasm_surface!`]), the calls `binding.rs` exports beside that list
//! (the object accessors, the free functions; `tests/binding.rs` holds the two sets of names equal), and the one adapter of the
//! app's JS store and authenticator.
//!
//! The JS side: each module call returns a `Promise`; records and enums are plain JS objects (`serde-wasm-bindgen`: an enum
//! externally tagged, a 64-bit integer a `BigInt`, names as in Rust); an error rejects with an `Error` whose `message` is the
//! code (spec §15). Objects other than the module objects (`Prepared`, `PreparedOrder`, `RegistryWrite`, `SeedBackup`) and
//! secrets are numbered handles: `release(handle)` drops the binding's reference (a secret's last one zeroes it); every handle
//! a call returns, inside a record too (each serialization makes a new one), is the app's to release. A secret's
//! bytes cross only by the copy calls `secret_write` (the caller's `Uint8Array` zeroed before it returns) and `secret_read`.
//!
//! Without wasm threads only (refused below): the platform traits are `Send + Sync` and hold JS objects here, which is sound only
//! on one thread. The serde helpers ([`handle`], the remote types) build on every target, so the derives of the records hold
//! wherever the feature is on; the exports are wasm32's. UNAUDITED.
#[cfg(all(target_arch = "wasm32", target_feature = "atomics"))]
compile_error!("feature `wasm` holds JS objects in Send + Sync platform traits: wasm threads (atomics) are not supported");

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

/// The last handle given and the objects held by handle.
type Handles = (u32, HashMap<u32, Box<dyn Any>>);

thread_local! {
    static HANDLES: RefCell<Handles> = RefCell::new((0, HashMap::new()));
}

/// A new handle for `v` (from 1). After the counter wraps, a number still held is skipped, never overwritten (review B5).
pub(crate) fn put<T: 'static>(v: Arc<T>) -> u32 {
    HANDLES.with(|h| {
        let mut h = h.borrow_mut();
        loop {
            h.0 = h.0.wrapping_add(1).max(1);
            if !h.1.contains_key(&h.0) {
                break;
            }
        }
        let id = h.0;
        h.1.insert(id, Box::new(v));
        id
    })
}

/// The object of handle `id` (`None`: unknown, released, or of another type).
pub(crate) fn get<T: 'static>(id: u32) -> Option<Arc<T>> {
    HANDLES.with(|h| {
        h.borrow()
            .1
            .get(&id)
            .and_then(|b| b.downcast_ref::<Arc<T>>())
            .cloned()
    })
}

/// Drops the binding's reference of handle `id`; whether it was held.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(crate) fn release_handle(id: u32) -> bool {
    HANDLES.with(|h| h.borrow_mut().1.remove(&id).is_some())
}

/// `serde(with)` for a record's `Arc<T>` field (a secret or an object): its handle.
pub mod handle {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::sync::Arc;

    pub fn serialize<S: Serializer, T: 'static>(v: &Arc<T>, s: S) -> Result<S::Ok, S::Error> {
        super::put(v.clone()).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: 'static>(d: D) -> Result<Arc<T>, D::Error> {
        let id = u32::deserialize(d)?;
        super::get(id).ok_or_else(|| serde::de::Error::custom("Argument"))
    }
}

/// `scaas-rpc`'s `Class` for serde (its own derive reads lowercase text only).
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(remote = "scaas_rpc::Class")]
pub enum ClassDef {
    Named,
    Default,
    Discovered,
}

/// `scaas-rpc`'s `Policy` for serde.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(remote = "scaas_rpc::Policy")]
pub enum PolicyDef {
    Failover,
    StrictMajority,
}

/// `serde(with)` for an endpoint's `Option<EndpointAuth>`: the credential is text in and never back out (the empty string), as
/// on every binding.
pub mod endpoint_auth {
    use scaas_rpc::endpoint::Secret;
    use scaas_rpc::EndpointAuth;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    enum Auth {
        Bearer(String),
        Hmac(String),
        Header { name: String, value: String },
    }

    pub fn serialize<S: Serializer>(v: &Option<EndpointAuth>, s: S) -> Result<S::Ok, S::Error> {
        v.as_ref()
            .map(|a| match a {
                EndpointAuth::Bearer(_) => Auth::Bearer(String::new()),
                EndpointAuth::Hmac(_) => Auth::Hmac(String::new()),
                EndpointAuth::Header { name, .. } => Auth::Header {
                    name: name.clone(),
                    value: String::new(),
                },
            })
            .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<EndpointAuth>, D::Error> {
        Ok(Option::<Auth>::deserialize(d)?.map(|a| match a {
            Auth::Bearer(t) => EndpointAuth::Bearer(Secret::new(t)),
            Auth::Hmac(t) => EndpointAuth::Hmac(Secret::new(t)),
            Auth::Header { name, value } => EndpointAuth::Header {
                name,
                value: Secret::new(value),
            },
        }))
    }
}

// the opaque-call marker: `true`, lifted only in a build with `opaque-calls` (spec §13.2), as on every binding
#[cfg(feature = "evm")]
impl serde::Serialize for crate::wallet::AllowOpaqueCall {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bool(true)
    }
}

#[cfg(feature = "evm")]
impl<'de> serde::Deserialize<'de> for crate::wallet::AllowOpaqueCall {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let b = bool::deserialize(d)?;
        #[cfg(feature = "opaque-calls")]
        if b {
            return Ok(crate::wallet::AllowOpaqueCall::new());
        }
        let _ = b;
        Err(serde::de::Error::custom("OpaqueCallRefused"))
    }
}

#[cfg(target_arch = "wasm32")]
mod js;
#[cfg(target_arch = "wasm32")]
pub use js::*;
