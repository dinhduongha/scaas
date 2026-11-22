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
use pqchat_core::net::Net;
use pqchat_core::PqChatError;
use scaas_sdk::app_core::AppCall;
use scaas_sdk::op::KeyRef;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
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
}

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
