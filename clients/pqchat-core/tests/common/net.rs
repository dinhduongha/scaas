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
use std::sync::Mutex;

#[derive(Default)]
pub struct FakeNet {
    /// (contract, item, arguments as JSON text) → answer; a `None` argument key answers any arguments
    answers: Mutex<HashMap<(String, String, String), Value>>,
    pub reads: Mutex<Vec<(String, String, Value)>>,
    pub writes: Mutex<Vec<(String, String, Value)>>,
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
        _chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        _payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        self.writes
            .lock()
            .unwrap()
            .push((contract.to_ascii_lowercase(), item.into(), args));
        Err(PqChatError::Internal)
    }
    async fn submit(&self, _call: AppCall) -> Result<String, PqChatError> {
        self.writes
            .lock()
            .unwrap()
            .push((String::new(), "submit".into(), Value::Null));
        Err(PqChatError::Internal)
    }
}
