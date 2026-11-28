// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! A recording fake of the crate's chain port: views answered from a table by (contract, item, arguments), every read and
//! every write recorded, writes refused unless a test allows them (the no-reaction assertions count them).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use async_trait::async_trait;
use pqchat_core::net::{Net, Signature, Unsigned};
use pqchat_core::PqChatError;
use scaas_sdk::app_core::{AppCall, AppQuote, AppRelay};
use scaas_sdk::op::KeyRef;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Default)]
pub struct FakeNet {
    /// (contract, item, arguments as JSON text) → answer; a `None` argument key answers any arguments
    answers: Mutex<HashMap<(String, String, String), Value>>,
    pub reads: Mutex<Vec<(String, String, Value)>>,
    pub writes: Mutex<Vec<(String, String, Value)>>,
    /// a prepare answers a quote (the SDK's operation, never sent) instead of refusing
    pub accept: AtomicBool,
    /// a prepare carrying more wraps than this is refused as the SDK refuses a quote that does not fit (`GasAboveTxCap`)
    pub wrap_cap: Mutex<Option<usize>>,
    /// CLI-SDK-36: every signing call the crate made through the port
    pub signs: AtomicU64,
    /// the quotes asked before a signature: (contract, item, arguments)
    pub quotes: Mutex<Vec<(String, String, Value)>>,
    /// the writes relayed by the gateways: (contract, item, arguments)
    pub relayed: Mutex<Vec<(String, String, Value)>>,
    /// contract → its runtime code hash (`code_hash`); another address answers the empty code's
    pub codes: Mutex<HashMap<String, String>>,
}

/// keccak-256 of the empty code: an address without code.
pub const NO_CODE: &str = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

/// A prepared write as the fake answers it: nothing in it is sent.
pub fn call(chain: &str, contract: &str, payer: &KeyRef) -> AppCall {
    use scaas_sdk::op::{SubmitPath, SubmitQuote};
    AppCall {
        review: vec![],
        quote: scaas_sdk::wallet::NativeQuote {
            key: payer.clone(),
            chain: chain.into(),
            from: String::new(),
            to: contract.into(),
            value: "0".into(),
            data: "0x".into(),
            quote: SubmitQuote {
                path: SubmitPath::SelfRelay {
                    payer: payer.clone(),
                },
                payer: None,
                gas_limit: 0,
                regular_gas: 0,
                gas: None,
                gas_from: None,
                max_fee_per_gas: "0".into(),
                max_priority_fee_per_gas: "0".into(),
                max_cost: "0".into(),
                fee_to_relayer: "0".into(),
                gateways: vec![],
                tx_nonce: 0,
                tx_type: 2,
            },
            delegated: false,
        },
    }
}

impl FakeNet {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn answer(&self, contract: &str, item: &str, args: Value, out: Value) {
        self.answers.lock().unwrap().insert(
            (contract.to_ascii_lowercase(), item.into(), args.to_string()),
            out,
        );
    }
    /// Every answer of `from` given by `to` too (a replica holding the home's records).
    pub fn mirror(&self, from: &str, to: &str) {
        let (from, to) = (from.to_ascii_lowercase(), to.to_ascii_lowercase());
        let mut a = self.answers.lock().unwrap();
        let copies: Vec<_> = a
            .iter()
            .filter(|(k, _)| k.0 == from)
            .map(|(k, v)| ((to.clone(), k.1.clone(), k.2.clone()), v.clone()))
            .collect();
        a.extend(copies);
    }
    /// The answer `answer` set for `(contract, item, args)`.
    pub fn answer_of(&self, contract: &str, item: &str, args: Value) -> Value {
        self.answers.lock().unwrap()[&(
            contract.to_ascii_lowercase(),
            item.to_string(),
            args.to_string(),
        )]
            .clone()
    }
    /// `contract`'s runtime code hash set to `hash`.
    pub fn code(&self, contract: &str, hash: &str) {
        self.codes
            .lock()
            .unwrap()
            .insert(contract.to_ascii_lowercase(), hash.into());
    }
    pub fn reads_of(&self, item: &str) -> usize {
        self.reads
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.1 == item)
            .count()
    }
    pub fn writes(&self) -> usize {
        self.writes.lock().unwrap().len()
    }
    /// The writes prepared of `item`, their arguments.
    pub fn writes_of(&self, item: &str) -> Vec<Value> {
        self.writes
            .lock()
            .unwrap()
            .iter()
            .filter(|w| w.1 == item)
            .map(|w| w.2.clone())
            .collect()
    }
}

#[async_trait]
impl Net for FakeNet {
    async fn read(
        &self,
        _chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        // the mark exists for every item read (no read without one)
        pqchat_core::net::trust(item)?;
        self.reads
            .lock()
            .unwrap()
            .push((contract.to_ascii_lowercase(), item.into(), args.clone()));
        let k = (
            contract.to_ascii_lowercase(),
            item.to_string(),
            args.to_string(),
        );
        self.answers
            .lock()
            .unwrap()
            .get(&k)
            .cloned()
            .ok_or(PqChatError::Internal)
    }
    async fn code_hash(&self, _chain: &str, contract: &str) -> Result<String, PqChatError> {
        let c = contract.to_ascii_lowercase();
        self.reads
            .lock()
            .unwrap()
            .push((c.clone(), "code".into(), Value::Null));
        Ok(self
            .codes
            .lock()
            .unwrap()
            .get(&c)
            .cloned()
            .unwrap_or(NO_CODE.into()))
    }
    async fn prepare(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        let n = args["wraps"].as_array().map_or(0, Vec::len);
        self.writes
            .lock()
            .unwrap()
            .push((contract.to_ascii_lowercase(), item.into(), args));
        if self.wrap_cap.lock().unwrap().is_some_and(|c| n > c) {
            return Err(PqChatError::Sdk(scaas_sdk::SdkError::GasAboveTxCap));
        }
        if !self.accept.load(Ordering::SeqCst) {
            return Err(PqChatError::Internal);
        }
        Ok(call(chain, contract, payer))
    }
    async fn quote(
        &self,
        _chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        _payer: &KeyRef,
        _signer: &KeyRef,
    ) -> Result<AppQuote, PqChatError> {
        self.quotes
            .lock()
            .unwrap()
            .push((contract.to_ascii_lowercase(), item.into(), args));
        Ok(AppQuote {
            review: vec![],
            quote: None,
        })
    }
    async fn sign(&self, u: Unsigned) -> Result<Signature, PqChatError> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        pqchat_core::net::sign_now(u).await
    }
    async fn relay(
        &self,
        _chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<AppRelay, PqChatError> {
        self.relayed
            .lock()
            .unwrap()
            .push((contract.to_ascii_lowercase(), item.into(), args));
        Ok(AppRelay {
            queued: self.accept.load(Ordering::SeqCst),
            refused: vec![],
            unreachable: 0,
        })
    }
    async fn submit(&self, _call: AppCall) -> Result<String, PqChatError> {
        let mut w = self.writes.lock().unwrap();
        w.push((String::new(), "submit".into(), Value::Null));
        // a prepare the fake answers is sent too (an operation id of its own)
        if self.accept.load(Ordering::SeqCst) {
            return Ok(format!("op-{}", w.len()));
        }
        Err(PqChatError::Internal)
    }
}

/// A port that counts the crate's signing calls over another port (CLI-SDK-36's test on a real chain).
pub struct Counting {
    pub inner: std::sync::Arc<dyn Net>,
    pub signs: AtomicU64,
}

#[async_trait]
impl Net for Counting {
    async fn read(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        self.inner.read(chain, contract, item, args).await
    }
    async fn read_latest(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        self.inner.read_latest(chain, contract, item, args).await
    }
    async fn code_hash(&self, chain: &str, contract: &str) -> Result<String, PqChatError> {
        self.inner.code_hash(chain, contract).await
    }
    async fn read_majority(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<(Value, usize), PqChatError> {
        self.inner.read_majority(chain, contract, item, args).await
    }
    async fn prepare(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        self.inner.prepare(chain, contract, item, args, payer).await
    }
    async fn submit(&self, call: AppCall) -> Result<String, PqChatError> {
        self.inner.submit(call).await
    }
    async fn quote(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        payer: &KeyRef,
        signer: &KeyRef,
    ) -> Result<AppQuote, PqChatError> {
        self.inner
            .quote(chain, contract, item, args, payer, signer)
            .await
    }
    async fn sign(&self, u: Unsigned) -> Result<Signature, PqChatError> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(u).await
    }
    async fn relay(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<AppRelay, PqChatError> {
        self.inner.relay(chain, contract, item, args).await
    }
}
