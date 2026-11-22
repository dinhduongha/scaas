// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Test helpers shared by the crate's tests: a log capture and faulty stores.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use pqchat_core::{Item, MemoryStore, PqChatStore, StoreFault};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tracing_core::field::{Field, Visit};
use tracing_core::span::{Attributes, Id, Record};
use tracing_core::{Event, Metadata, Subscriber};

/// Every event of the crate as one line: its fields' names and values, its message.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

struct Line(String);
impl Visit for Line {
    fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
        let _ = write!(self.0, " {}={v:?}", f.name());
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, e: &Event<'_>) {
        let mut l = Line(e.metadata().target().to_string());
        e.record(&mut l);
        self.0.lock().unwrap().push(l.0);
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

/// `f`'s result and every log line it caused.
pub fn logs<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    let c = Capture::default();
    let d = tracing_core::Dispatch::new(c.clone());
    let out = tracing_core::dispatcher::with_default(&d, f);
    let lines = c.0.lock().unwrap().clone();
    (out, lines)
}

/// A store that fails on load, on replace, or whose item changes before every replace.
pub struct Faulty {
    inner: MemoryStore,
    fail_load: bool,
    fail_replace: bool,
    race: bool,
    pub replaces: AtomicU64,
}

impl Faulty {
    fn new(fail_load: bool, fail_replace: bool, race: bool) -> Self {
        Faulty {
            inner: MemoryStore::new(),
            fail_load,
            fail_replace,
            race,
            replaces: AtomicU64::new(0),
        }
    }
    pub fn load() -> Self {
        Self::new(true, false, false)
    }
    pub fn replace() -> Self {
        Self::new(false, true, false)
    }
    pub fn racing() -> Self {
        Self::new(false, false, true)
    }
    pub fn inner(&self) -> &MemoryStore {
        &self.inner
    }
}

impl PqChatStore for Faulty {
    fn load(&self, key: &str) -> Result<Option<Item>, StoreFault> {
        if self.fail_load {
            return Err(StoreFault);
        }
        self.inner.load(key)
    }
    fn replace(&self, key: &str, expected: u64, value: &[u8]) -> Result<bool, StoreFault> {
        self.replaces.fetch_add(1, Ordering::SeqCst);
        if self.fail_replace {
            return Err(StoreFault);
        }
        if self.race {
            // another writer lands first
            let cur = self.inner.load(key)?.map_or(0, |i| i.revision);
            assert!(self.inner.replace(key, cur, b"\"other\"")?);
        }
        self.inner.replace(key, expected, value)
    }
}
