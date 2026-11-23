// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The wasm-bindgen exports of feature `wasm` (spec §16.4): see the parent module.
#![allow(clippy::too_many_arguments)]
#[cfg(feature = "account")]
#[allow(unused_imports)]
use crate::account::{msig::*, smart::*, *};
#[cfg(feature = "admin")]
#[allow(unused_imports)]
use crate::admin::{delay::*, *};
#[cfg(any(feature = "zether", feature = "pqz"))]
use crate::confidential::*;
#[cfg(feature = "dex")]
use crate::dex::*;
#[cfg(feature = "evm")]
use crate::op::*;
use crate::platform::*;
use crate::vault::*;
#[cfg(feature = "wallet")]
use crate::wallet::*;
#[cfg(feature = "evm")]
use crate::UaLine;
use crate::{ChainProfile, GasTable, Limits, SdkError};
use async_trait::async_trait;
use js_sys::{Function, Promise, Reflect, Uint8Array};
use scaas_ua::wallet::SecretBytes;
use serde::de::DeserializeOwned;
use serde::Serialize;
#[allow(unused_imports)]
use serde_json::Value;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{future_to_promise, JsFuture};

/// An SDK error as the rejected `Error`: its message is the code.
fn err(e: SdkError) -> JsValue {
    js_sys::Error::new(&e.to_string()).into()
}

fn to_js<T: Serialize + ?Sized>(v: &T) -> Result<JsValue, JsValue> {
    let s = serde_wasm_bindgen::Serializer::new()
        .serialize_large_number_types_as_bigints(true)
        .serialize_maps_as_objects(true);
    v.serialize(&s).map_err(|_| err(SdkError::Internal))
}

/// The deepest a JS value nests (arrays, maps, plain objects) before it is lifted: serde_json's own limit, which the native
/// bindings' JSON text has (review T26 C-6; `serde_wasm_bindgen` recurses without one, and a stack overflow kills the
/// instance).
const JS_DEPTH: usize = 128;

/// Whether `v` nests at most `left` levels; a typed array, a string, a number or a big integer is a leaf.
fn shallow(v: &JsValue, left: usize) -> bool {
    let within = |items: js_sys::Array| left > 0 && items.iter().all(|x| shallow(&x, left - 1));
    if let Some(a) = v.dyn_ref::<js_sys::Array>() {
        within(a.clone())
    } else if let Some(m) = v.dyn_ref::<js_sys::Map>() {
        within(js_sys::Array::from(m.values().as_ref()))
    } else if v.is_object() && !js_sys::ArrayBuffer::is_view(v) && !v.is_function() {
        within(js_sys::Object::values(v.unchecked_ref()))
    } else {
        true
    }
}

/// Whether every key of the JS object `got` is in `known` (the lifted value serialized back) at every depth, `left` levels
/// at most; a key whose value is null or undefined may be absent there (a skipped `None`); only plain objects and arrays are
/// compared (review T26 C-3).
fn keys_known(got: &JsValue, known: &JsValue, left: usize) -> bool {
    let plain = |v: &JsValue| {
        v.is_object()
            && !v.is_function()
            && !js_sys::ArrayBuffer::is_view(v)
            && v.dyn_ref::<js_sys::Map>().is_none()
    };
    if left == 0 || !plain(got) || !plain(known) {
        return true;
    }
    if let (Some(a), Some(b)) = (
        got.dyn_ref::<js_sys::Array>(),
        known.dyn_ref::<js_sys::Array>(),
    ) {
        return a
            .iter()
            .zip(b.iter())
            .all(|(x, y)| keys_known(&x, &y, left - 1));
    }
    js_sys::Object::keys(got.unchecked_ref::<js_sys::Object>())
        .iter()
        .all(|k| {
            let v = Reflect::get(got, &k).unwrap_or(JsValue::UNDEFINED);
            if v.is_null() || v.is_undefined() {
                return true;
            }
            match Reflect::get(known, &k) {
                Ok(kv) if !kv.is_undefined() => keys_known(&v, &kv, left - 1),
                _ => false,
            }
        })
}

/// A JS value as `T`: nested beyond [`JS_DEPTH`] `Argument`, before any lift; a refused opaque-call marker is
/// `OpaqueCallRefused` (as on every binding), by the marker's own flag (review T26 C-12: never by the error's text), any
/// other refusal `Argument`.
fn from_js<T: DeserializeOwned>(v: JsValue) -> Result<T, SdkError> {
    if !shallow(&v, JS_DEPTH) {
        return Err(SdkError::Argument);
    }
    super::OPAQUE_REFUSED.with(|r| r.set(false));
    let out = serde_wasm_bindgen::from_value(v);
    let refused = super::OPAQUE_REFUSED.with(|r| r.replace(false));
    out.map_err(|_| match refused {
        true => SdkError::OpaqueCallRefused,
        false => SdkError::Argument,
    })
}

/// The type a list entry names, for the choice below of how a value of it crosses: an `Arc<T>` (a secret or an object) as a
/// handle, anything else through serde. The choice is method resolution's (autoref): the handle impls take `&W<…>`, the serde
/// ones `&&W<T>`, so a handle type never reaches serde.
pub struct W<T>(PhantomData<T>);

pub trait LiftHandle {
    type Out;
    fn lift(&self, v: JsValue) -> Result<Self::Out, SdkError>;
}
impl<T: 'static> LiftHandle for W<Arc<T>> {
    type Out = Arc<T>;
    fn lift(&self, v: JsValue) -> Result<Arc<T>, SdkError> {
        super::get(from_js::<u32>(v)?).ok_or(SdkError::Argument)
    }
}
pub trait LiftSerde {
    type Out;
    fn lift(&self, v: JsValue) -> Result<Self::Out, SdkError>;
}
impl<T: DeserializeOwned> LiftSerde for &W<T> {
    type Out = T;
    fn lift(&self, v: JsValue) -> Result<T, SdkError> {
        from_js(v)
    }
}

pub trait LowerHandle {
    type In;
    fn lower(&self, v: Self::In) -> Result<JsValue, JsValue>;
}
impl<T: 'static> LowerHandle for W<Arc<T>> {
    type In = Arc<T>;
    fn lower(&self, v: Arc<T>) -> Result<JsValue, JsValue> {
        Ok(super::put(v).into())
    }
}
pub trait LowerHandles {
    type In;
    fn lower(&self, v: Self::In) -> Result<JsValue, JsValue>;
}
impl<T: 'static> LowerHandles for W<Vec<Arc<T>>> {
    type In = Vec<Arc<T>>;
    fn lower(&self, v: Vec<Arc<T>>) -> Result<JsValue, JsValue> {
        to_js(&v.into_iter().map(super::put).collect::<Vec<_>>())
    }
}
pub trait LowerHandleOpt {
    type In;
    fn lower(&self, v: Self::In) -> Result<JsValue, JsValue>;
}
impl<T: 'static> LowerHandleOpt for W<Option<Arc<T>>> {
    type In = Option<Arc<T>>;
    fn lower(&self, v: Option<Arc<T>>) -> Result<JsValue, JsValue> {
        Ok(v.map_or(JsValue::UNDEFINED, |v| super::put(v).into()))
    }
}
pub trait LowerSerde {
    type In;
    fn lower(&self, v: Self::In) -> Result<JsValue, JsValue>;
}
impl<T: Serialize> LowerSerde for &W<T> {
    type In = T;
    fn lower(&self, v: T) -> Result<JsValue, JsValue> {
        to_js(&v)
    }
}

/// The module objects and their calls from the one list: each call a method returning a `Promise` (the page's event loop runs
/// the SDK, spec §14), one `impl` block per call so that its `cfg` applies before wasm-bindgen reads it.
macro_rules! wasm_surface {
    ($(
        $(#[doc = $doc:literal])*
        $(#[cfg($oc:meta)])?
        object $obj:ident = $inner:path {
            $( $(#[$fm:meta])* async $f:ident / $fb:ident ( $($a:ident : $t:ty),* ) -> $r:ty ; )*
        }
    )*) => {
        $(
            $(#[doc = $doc])*
            $(#[cfg($oc)])?
            #[wasm_bindgen]
            pub struct $obj {
                m: Arc<$inner>,
            }

            $(#[cfg($oc)])?
            const _: () = {
            $(
                $(#[$fm])*
                #[wasm_bindgen]
                impl $obj {
                    pub fn $f(&self, $($a: JsValue),*) -> Promise {
                        let m = self.m.clone();
                        future_to_promise(async move {
                            $( let $a: $t = (&W::<$t>(PhantomData)).lift($a).map_err(err)?; )*
                            let r: $r = m.$f($($a),*).await.map_err(err)?;
                            (&W::<$r>(PhantomData)).lower(r)
                        })
                    }
                }
            )*
            };
        )*
    };
}

crate::binding_list::binding_list!(wasm_surface);

/// Free functions over JS values, as `binding.rs` exports them: `fn name(args) -> T = body;` with `body` a `Result<T, SdkError>`.
macro_rules! free {
    ($( $(#[$m:meta])* fn $name:ident ( $($a:ident : $t:ty),* ) -> $r:ty = $body:expr ; )*) => {
        $(
            $(#[$m])*
            #[wasm_bindgen]
            pub fn $name($($a: JsValue),*) -> Result<JsValue, JsValue> {
                $( let $a: $t = (&W::<$t>(PhantomData)).lift($a).map_err(err)?; )*
                let r: Result<$r, SdkError> = $body;
                (&W::<$r>(PhantomData)).lower(r.map_err(err)?)
            }
        )*
    };
}

free! {
    fn api_version() -> u32 = Ok(crate::API_VERSION);
    fn features() -> u64 = Ok(crate::features());
    fn secret_new(len: u32) -> Arc<SecretBytes> =
        usize::try_from(len).map_err(|_| SdkError::Argument).and_then(|l| Ok(Arc::new(SecretBytes::new(l)?)));
    fn secret_id(s: Arc<SecretBytes>) -> u64 = Ok(s.id());
    fn secret_len(s: Arc<SecretBytes>) -> u32 = Ok(u32::try_from(s.len()).unwrap_or(u32::MAX));
    fn limits_default() -> Limits = Ok(Limits::default());
    fn store_policy_default() -> StorePolicy = Ok(StorePolicy::default());
    fn is_uuid4(s: String) -> bool = Ok(keystore::is_uuid4(&s));
    fn label_ok(label: String) -> bool = Ok(keystore::label_ok(&label));
    fn new_label_ok(label: String) -> bool = Ok(keystore::new_label_ok(&label));
    fn accounts_json(rows: Vec<AccountRow>) -> String = Ok(keystore::accounts_json(&rows));
    fn rev_of(bytes: Vec<u8>) -> u64 = Ok(store::rev_of(&bytes));
    fn op_state_is_terminal(state: crate::OpState) -> bool = Ok(state.is_terminal());
    fn gas_table_parse(text: String) -> GasTable = GasTable::parse(&text);
    fn gas_rows_default() -> crate::GasRows = Ok(crate::GasRows::default());
    #[cfg(all(feature = "account", feature = "evm"))]
    fn register_attrs_default() -> RegisterAttrs = Ok(RegisterAttrs::default());
    #[cfg(all(feature = "account", feature = "evm"))]
    fn msig_structure(members: Vec<MsigMemberArgs>, threshold: u16) -> MsigStructureArgs =
        crate::account::msig::msig_structure(members, threshold);
    #[cfg(all(feature = "account", feature = "evm"))]
    fn msig_structure_ua(args: MsigStructureArgs) -> String = args.ua();
    #[cfg(all(feature = "account", feature = "evm"))]
    fn smart_account_address(factory: String, implementation: String, first_key: SubjectKeyArgs, guardian: String) -> String =
        crate::account::smart_account_address(&factory, &implementation, &first_key, &guardian);
    #[cfg(all(feature = "account", feature = "evm"))]
    fn subject_key_args_secp256k1(address: String) -> SubjectKeyArgs = SubjectKeyArgs::secp256k1(&address);
    #[cfg(all(feature = "account", feature = "evm"))]
    fn registration_blob_from_json(text: String) -> RegistrationBlob = RegistrationBlob::from_json(&text);
    #[cfg(all(feature = "account", feature = "evm"))]
    fn registration_blob_to_json(blob: RegistrationBlob) -> String = blob.to_json();
    #[cfg(feature = "wallet")]
    fn signed_op_blob_from_json(text: String) -> SignedOpBlob = SignedOpBlob::from_json(&text);
    #[cfg(feature = "wallet")]
    fn signed_op_blob_to_json(blob: SignedOpBlob) -> String = blob.to_json();
    #[cfg(feature = "evm")]
    fn ua_line_key_target(line: crate::UaLine) -> String = Ok(line.key_target());
    #[cfg(feature = "evm")]
    fn ua_line_pqz_target(line: crate::UaLine) -> String = line.pqz_target();
}

// the objects other than the module objects, by handle: `<object>_<method>(handle)`, as `binding.rs`'s methods
free! {
    #[cfg(feature = "evm")]
    fn prepared_id(p: Arc<Prepared>) -> String = Ok(p.id());
    #[cfg(feature = "evm")]
    fn prepared_chain(p: Arc<Prepared>) -> String = Ok(p.chain());
    #[cfg(feature = "evm")]
    fn prepared_entry(p: Arc<Prepared>) -> String = Ok(p.entry());
    #[cfg(feature = "evm")]
    fn prepared_review(p: Arc<Prepared>) -> Vec<ReviewField> = Ok(p.review());
    #[cfg(feature = "evm")]
    fn prepared_opaque(p: Arc<Prepared>) -> bool = Ok(p.opaque());
    #[cfg(feature = "evm")]
    fn prepared_signer(p: Arc<Prepared>) -> KeyRef = Ok(p.signer());
    #[cfg(feature = "evm")]
    fn prepared_expires_at(p: Arc<Prepared>) -> u64 = Ok(p.expires_at());
    #[cfg(feature = "dex")]
    fn prepared_order_id(p: Arc<PreparedOrder>) -> String = Ok(p.id());
    #[cfg(feature = "dex")]
    fn prepared_order_chain(p: Arc<PreparedOrder>) -> String = Ok(p.chain());
    #[cfg(feature = "dex")]
    fn prepared_order_review(p: Arc<PreparedOrder>) -> Vec<ReviewField> = Ok(p.review());
    #[cfg(feature = "dex")]
    fn prepared_order_signer(p: Arc<PreparedOrder>) -> KeyRef = Ok(p.signer());
    #[cfg(all(feature = "account", feature = "evm"))]
    fn registry_write_id(w: Arc<RegistryWrite>) -> String = Ok(w.id());
    #[cfg(all(feature = "account", feature = "evm"))]
    fn registry_write_chain(w: Arc<RegistryWrite>) -> String = Ok(w.chain());
    #[cfg(all(feature = "account", feature = "evm"))]
    fn registry_write_entry(w: Arc<RegistryWrite>) -> String = Ok(w.entry());
    #[cfg(all(feature = "account", feature = "evm"))]
    fn registry_write_ua(w: Arc<RegistryWrite>) -> String = Ok(w.ua());
    #[cfg(all(feature = "account", feature = "evm"))]
    fn registry_write_review(w: Arc<RegistryWrite>) -> Vec<ReviewField> = Ok(w.review());
    #[cfg(all(feature = "account", feature = "evm"))]
    fn registry_write_calldata(w: Arc<RegistryWrite>) -> String = Ok(w.calldata());
    #[cfg(all(feature = "account", feature = "evm"))]
    fn registry_write_payer(w: Arc<RegistryWrite>) -> KeyRef = Ok(w.payer());
    #[cfg(all(feature = "account", feature = "evm"))]
    fn registry_write_registration_gas(w: Arc<RegistryWrite>) -> Option<RegistrationGas> = Ok(w.registration_gas());
    fn seed_backup_reveal(b: Arc<SeedBackup>) -> Arc<SecretBytes> = b.reveal();
    fn seed_backup_challenge(b: Arc<SeedBackup>) -> Vec<u32> = b.challenge();
    fn seed_backup_verify(b: Arc<SeedBackup>, answers: Arc<SecretBytes>) -> bool = b.verify(answers);
}

/// The SDK's wasm linear memory (a page's script can read it anyway): for a check that a secret leaves no copy there, as the
/// smoke does after `secret_read` (spec §16.4, review B3).
#[wasm_bindgen]
pub fn wasm_memory() -> JsValue {
    wasm_bindgen::memory()
}

/// Drops the binding's reference of a handle (a secret's last one zeroes it); whether it was held.
#[wasm_bindgen]
pub fn release(handle: u32) -> bool {
    super::release_handle(handle)
}

/// The copy call in (spec §5, §16.4): `bytes` into secret `handle` (its length exactly), then `bytes` zeroed; `Argument`
/// otherwise.
#[wasm_bindgen]
pub fn secret_write(handle: u32, bytes: &mut [u8]) -> Result<(), JsValue> {
    let s = super::get::<SecretBytes>(handle).ok_or_else(|| err(SdkError::Argument));
    let r =
        s.and_then(|s| scaas_ua::wallet::secret_write(s.id(), bytes).map_err(|e| err(e.into())));
    bytes.fill(0);
    r
}

/// The copy call out: secret `handle` into the caller's `into` (at least its length; the caller zeroes it once done); its
/// length. One copy straight into the JS array from a buffer of the SDK's own that is zeroed on drop, so no plaintext stays
/// in freed wasm memory (review B3; a `&mut [u8]` argument would leave wasm-bindgen's unzeroed temporary behind).
#[wasm_bindgen]
pub fn secret_read(handle: u32, into: &Uint8Array) -> Result<u32, JsValue> {
    let s = super::get::<SecretBytes>(handle).ok_or_else(|| err(SdkError::Argument))?;
    let mut buf = zeroize::Zeroizing::new(vec![0u8; s.len()]);
    let n = scaas_ua::wallet::secret_read(s.id(), &mut buf).map_err(|e| err(e.into()))?;
    let n32 = u32::try_from(n).map_err(|_| err(SdkError::Internal))?;
    if into.length() < n32 {
        return Err(err(SdkError::Argument));
    }
    into.subarray(0, n32)
        .copy_from(buf.get(..n).ok_or_else(|| err(SdkError::Internal))?);
    Ok(n32)
}

#[wasm_bindgen]
impl Sdk {
    /// The seed module (spec §6).
    pub fn vault(&self) -> Vault {
        Vault { m: self.m.vault() }
    }
    /// The account module (spec §7).
    #[cfg(feature = "account")]
    pub fn account(&self) -> Account {
        Account {
            m: self.m.account(),
        }
    }
    /// The wallet module (spec §8).
    #[cfg(feature = "wallet")]
    pub fn wallet(&self) -> Wallet {
        Wallet { m: self.m.wallet() }
    }
    /// The operations module (spec §13).
    #[cfg(feature = "evm")]
    pub fn op(&self) -> Op {
        Op { m: self.m.op() }
    }
    /// The confidential module (spec §9).
    #[cfg(any(feature = "zether", feature = "pqz"))]
    pub fn confidential(&self) -> Confidential {
        Confidential {
            m: self.m.confidential(),
        }
    }
    /// The DEX module (spec §10).
    #[cfg(feature = "dex")]
    pub fn dex(&self) -> Dex {
        Dex { m: self.m.dex() }
    }
    /// The admin module (spec §11).
    #[cfg(feature = "admin")]
    pub fn admin(&self) -> Admin {
        Admin { m: self.m.admin() }
    }
    /// A subscription to the SDK's events (spec §14).
    pub fn subscribe(&self) -> Subscription {
        Subscription {
            m: self.m.subscribe(),
        }
    }
    /// The limits in force.
    pub fn limits(&self) -> Result<JsValue, JsValue> {
        to_js(self.m.limits())
    }
}

/// A subscription to the SDK's events (spec §14): a bounded queue, `Lagged { missed }` for a slow reader.
#[wasm_bindgen]
pub struct Subscription {
    m: Arc<crate::Subscription>,
}

#[wasm_bindgen]
impl Subscription {
    /// The next event, or `undefined` within `timeout_ms`.
    pub fn next(&self, timeout_ms: u32) -> Promise {
        let m = self.m.clone();
        future_to_promise(async move {
            match m.next(u64::from(timeout_ms)).await {
                Some(e) => to_js(&e),
                None => Ok(JsValue::UNDEFINED),
            }
        })
    }
}

#[wasm_bindgen]
impl Vault {
    /// Locks `seed`: the ids of the hidden sets abandoned with it.
    pub fn lock(&self, seed: String) -> Promise {
        let m = self.m.clone();
        future_to_promise(async move { to_js(&m.lock(seed).await) })
    }
    /// Locks every seed.
    pub fn lock_all(&self) -> Promise {
        let m = self.m.clone();
        future_to_promise(async move { to_js(&m.lock_all().await) })
    }
    /// The memory protection of an unlocked seed's arena.
    pub fn memory_protection(&self, seed: String) -> Result<JsValue, JsValue> {
        let p = self.m.memory_protection(seed).map_err(err)?;
        let n = |v: usize| u64::try_from(v).unwrap_or(u64::MAX);
        to_js(
            &serde_json::json!({ "chunks": n(p.chunks), "locked": n(p.locked), "no_dump": n(p.no_dump) }),
        )
    }
    /// Whether a word (a secret, by handle) is on the BIP-39 list.
    pub fn word_in_list(&self, word: u32) -> Result<bool, JsValue> {
        let w = super::get::<SecretBytes>(word).ok_or_else(|| err(SdkError::Argument))?;
        Ok(self.m.word_in_list(w))
    }
    /// Root (c)'s typed data for the account `account_hex` and set `set` (spec §6.6).
    #[cfg(feature = "classical-roots")]
    pub fn key_derivation_typed_data(
        &self,
        account_hex: String,
        set: u32,
    ) -> Result<String, JsValue> {
        self.m
            .key_derivation_typed_data(account_hex, set)
            .map_err(err)
    }
    /// A 65-byte signature from its compact form (a secret in, a secret out; handles).
    #[cfg(feature = "classical-roots")]
    pub fn signature_from_compact(&self, sig: u32) -> Result<u32, JsValue> {
        let s = super::get::<SecretBytes>(sig).ok_or_else(|| err(SdkError::Argument))?;
        Ok(super::put(self.m.signature_from_compact(s).map_err(err)?))
    }
}

#[cfg(feature = "evm")]
#[wasm_bindgen]
impl Op {
    /// Whether `part` is a valid partial of the prepared operation `prepared` (a handle) of its group (spec §5.4).
    pub fn bls_multi_part_ok(&self, prepared: u32, part: JsValue) -> Result<bool, JsValue> {
        let p = super::get::<Prepared>(prepared).ok_or_else(|| err(SdkError::Argument))?;
        Ok(self.m.bls_multi_part_ok(&p, &from_js(part).map_err(err)?))
    }
    /// Member `member`'s PoP part for its group's registration.
    pub fn bls_multi_pop_part(&self, member: JsValue) -> Result<JsValue, JsValue> {
        to_js(
            &self
                .m
                .bls_multi_pop_part(from_js(member).map_err(err)?)
                .map_err(err)?,
        )
    }
    /// Whether `part` is a valid PoP part of the group `key_data` (`0x` hex).
    pub fn bls_multi_pop_part_ok(&self, key_data: String, part: JsValue) -> Result<bool, JsValue> {
        Ok(self
            .m
            .bls_multi_pop_part_ok(&key_data, &from_js(part).map_err(err)?))
    }
}

#[cfg(feature = "admin")]
#[wasm_bindgen]
impl Admin {
    /// A creation's CREATE3 addresses (`scaas-ua` `create3_address`).
    pub fn create3_address(
        &self,
        factory: String,
        creator_id: String,
        contract_class: u16,
        kind: u16,
        salt: String,
    ) -> Result<JsValue, JsValue> {
        to_js(
            &self
                .m
                .create3_address(factory, creator_id, contract_class, kind, salt)
                .map_err(err)?,
        )
    }
}

/// `f` as a `Send` future: the page has one thread (wasm threads are refused by the parent module), so a JS value never
/// crosses one.
struct Local<F>(F);
// SAFETY: wasm32 without atomics runs one thread; nothing of `F` can be reached from another.
#[allow(unsafe_code)]
unsafe impl<F> Send for Local<F> {}
impl<F: Future> Future for Local<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        // SAFETY: `Local` is a transparent wrapper; `F` is never moved out of the pinned `Local`.
        #[allow(unsafe_code)]
        let f = unsafe { self.map_unchecked_mut(|l| &mut l.0) };
        f.poll(cx)
    }
}

/// A JS object of the app: its methods called by name.
#[derive(Clone)]
struct JsObj(JsValue);
// SAFETY: as `Local`: one thread.
#[allow(unsafe_code)]
unsafe impl Send for JsObj {}
#[allow(unsafe_code)]
unsafe impl Sync for JsObj {}

impl JsObj {
    /// `this.<name>(...args)`, its value or the value its promise resolves to; the thrown or rejected value as `Err`.
    async fn call(&self, name: &str, args: &[JsValue]) -> Result<JsValue, JsValue> {
        let f: Function = Reflect::get(&self.0, &JsValue::from_str(name))?.dyn_into()?;
        let argv = js_sys::Array::new();
        for a in args {
            argv.push(a);
        }
        let r = f.apply(&self.0, &argv)?;
        JsFuture::from(Promise::resolve(&r)).await
    }
}

/// The code a JS store or authenticator rejected with: an `Error`'s `message`, or a thrown string.
fn code(e: &JsValue) -> String {
    e.as_string()
        .or_else(|| {
            Reflect::get(e, &JsValue::from_str("message"))
                .ok()
                .and_then(|m| m.as_string())
        })
        .unwrap_or_default()
}

fn store_err(e: JsValue) -> StoreError {
    match code(&e).as_str() {
        "Conflict" => StoreError::Conflict,
        "Io" => StoreError::Io,
        "Unavailable" => StoreError::Unavailable,
        _ => StoreError::Unexpected,
    }
}

fn auth_err(e: JsValue) -> AuthError {
    match code(&e).as_str() {
        "Refused" => AuthError::Refused,
        "Cancelled" => AuthError::Cancelled,
        "Unavailable" => AuthError::Unavailable,
        _ => AuthError::Unexpected,
    }
}

/// The app's JS store (spec §6.9, §16.4): `get(name, reason)`, `put_if(name, prev_rev, bytes, policy)`, `delete(name)`,
/// `lock(name)`, `unlock(token)`, each returning a value or a promise; a rejection with `Conflict`, `Io` or `Unavailable` is
/// that error, anything else `Unexpected`.
struct JsStore(JsObj);

/// The store's lock: released when the SDK drops it, on the page's event loop.
struct Release(JsValue, JsObj);
// SAFETY: as `Local`: one thread.
#[allow(unsafe_code)]
unsafe impl Send for Release {}
#[allow(unsafe_code)]
unsafe impl Sync for Release {}
impl Drop for Release {
    fn drop(&mut self) {
        let (token, store) = (self.0.clone(), self.1.clone());
        wasm_bindgen_futures::spawn_local(async move {
            let _ = store.call("unlock", &[token]).await;
        });
    }
}

#[async_trait]
impl SecureStore for JsStore {
    async fn get(&self, name: String, reason: String) -> Result<Option<StoredItem>, StoreError> {
        Local(async move {
            let v = self
                .0
                .call("get", &[name.into(), reason.into()])
                .await
                .map_err(store_err)?;
            if v.is_null() || v.is_undefined() {
                return Ok(None);
            }
            from_js(v).map(Some).map_err(|_| StoreError::Unexpected)
        })
        .await
    }
    async fn put_if(
        &self,
        name: String,
        prev_rev: Option<u64>,
        bytes: Vec<u8>,
        policy: StorePolicy,
    ) -> Result<(), StoreError> {
        Local(async move {
            let rev = to_js(&prev_rev).map_err(|_| StoreError::Unexpected)?;
            let policy = to_js(&policy).map_err(|_| StoreError::Unexpected)?;
            let bytes: JsValue = Uint8Array::from(bytes.as_slice()).into();
            self.0
                .call("put_if", &[name.into(), rev, bytes, policy])
                .await
                .map_err(store_err)?;
            Ok(())
        })
        .await
    }
    async fn delete(&self, name: String) -> Result<(), StoreError> {
        Local(async move {
            self.0
                .call("delete", &[name.into()])
                .await
                .map_err(store_err)?;
            Ok(())
        })
        .await
    }
    async fn lock(&self, name: String) -> Result<Arc<StoreLock>, StoreError> {
        Local(async move {
            let token = self
                .0
                .call("lock", &[name.into()])
                .await
                .map_err(store_err)?;
            Ok(StoreLock::new(Box::new(Release(token, self.0.clone()))))
        })
        .await
    }
}

/// The app's JS authenticator (spec §6.10, §16.4): `create_passkey(rp_id, user_name, exclude)`, `get_assertion(req, prf_out)`,
/// `platform_secret(handle, salt, reason, policy, out)`, `p256_generate(policy)`, `p256_sign(handle, ua_msg, reason)`; a PRF
/// output or platform secret is written by `secret_write` into the secret handle it is given (`prf_out`, `out`), released after
/// the call. A rejection with `Refused`, `Cancelled` or `Unavailable` is that error, anything else `Unexpected`.
struct JsAuth(JsObj);

impl JsAuth {
    async fn call<T: DeserializeOwned>(
        &self,
        name: &str,
        args: &[JsValue],
    ) -> Result<T, AuthError> {
        from_js(self.0.call(name, args).await.map_err(auth_err)?).map_err(|_| AuthError::Unexpected)
    }
}

/// A secret lent to the app's authenticator by handle for one call: released when the call ends, returns early or is dropped
/// (review B4).
struct Held(u32);

impl Held {
    fn new(s: Arc<SecretBytes>) -> Held {
        Held(super::put(s))
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        super::release_handle(self.0);
    }
}

fn arg<T: Serialize>(v: &T) -> Result<JsValue, AuthError> {
    to_js(v).map_err(|_| AuthError::Unexpected)
}

#[async_trait]
impl Authenticator for JsAuth {
    async fn create_passkey(
        &self,
        rp_id: String,
        user_name: String,
        exclude: Vec<Vec<u8>>,
    ) -> Result<PasskeyCreated, AuthError> {
        Local(async move {
            self.call(
                "create_passkey",
                &[rp_id.into(), user_name.into(), arg(&exclude)?],
            )
            .await
        })
        .await
    }
    async fn get_assertion(
        &self,
        req: AssertionRequest,
        prf_out: Arc<SecretBytes>,
    ) -> Result<Assertion, AuthError> {
        Local(async move {
            let req = arg(&req)?;
            let h = Held::new(prf_out);
            self.call("get_assertion", &[req, h.0.into()]).await
        })
        .await
    }
    async fn platform_secret(
        &self,
        handle: String,
        salt: Vec<u8>,
        reason: String,
        policy: Option<KeyPolicy>,
        out: Arc<SecretBytes>,
    ) -> Result<(), AuthError> {
        Local(async move {
            let (salt, policy) = (arg(&salt)?, arg(&policy)?);
            let h = Held::new(out);
            self.0
                .call(
                    "platform_secret",
                    &[handle.into(), salt, reason.into(), policy, h.0.into()],
                )
                .await
                .map(|_| ())
                .map_err(auth_err)
        })
        .await
    }
    async fn p256_generate(&self, policy: KeyPolicy) -> Result<SePublic, AuthError> {
        Local(async move { self.call("p256_generate", &[arg(&policy)?]).await }).await
    }
    async fn p256_sign(
        &self,
        handle: String,
        ua_msg: Vec<u8>,
        reason: String,
    ) -> Result<Vec<u8>, AuthError> {
        Local(async move {
            self.call("p256_sign", &[handle.into(), arg(&ua_msg)?, reason.into()])
                .await
        })
        .await
    }
}

/// A binding's configuration (spec §4), as `binding.rs`'s: the load check's `expect_api` and `need_features` (spec §16.3), the
/// profiles, the passkey RP ID, the limits, the module gas tables.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingConfig {
    expect_api: u32,
    need_features: u64,
    profiles: Vec<ChainProfile>,
    rp_id: Option<String>,
    limits: Limits,
    gas_tables: Vec<GasTable>,
}

/// Opens the SDK (spec §4) over the app's JS store and authenticator (`undefined`: none), on the page's event loop.
#[wasm_bindgen]
pub fn open(config: JsValue, store: JsValue, authenticator: JsValue) -> Promise {
    future_to_promise(async move {
        let c: BindingConfig = from_js(config.clone()).map_err(err)?;
        // review T26 C-3: `serde_wasm_bindgen` reads a record's own fields by name and never sees another key, so
        // `deny_unknown_fields` cannot refuse one: the configuration (no handle in it) is serialized back and every key of
        // the app's object must be in it, at every depth (a misspelt `pinnedReads` would take its default)
        if !keys_known(&config, &to_js(&c)?, JS_DEPTH) {
            return Err(err(SdkError::Argument));
        }
        crate::load_check(c.expect_api, c.need_features).map_err(err)?;
        let authenticator = (!authenticator.is_undefined() && !authenticator.is_null())
            .then(|| Arc::new(JsAuth(JsObj(authenticator))) as Arc<dyn Authenticator>);
        let config = crate::SdkConfig {
            profiles: c.profiles,
            store: Arc::new(JsStore(JsObj(store))),
            authenticator,
            rp_id: c.rp_id,
            runtime: crate::RuntimeChoice::Own,
            limits: c.limits,
            clock: None,
            gas_tables: c.gas_tables,
        };
        let sdk = crate::Sdk::open(config).await.map_err(err)?;
        Ok(Sdk { m: sdk }.into())
    })
}
