// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Watching (spec §14, §8.4; R17): `watch(account, chains)` polls every `Limits::watch_poll_ms`, at most `Limits::max_watch`
//! `(account, chain, token)` triples per poll (round robin: the rest next poll). A triple's poll reads the token's balance at
//! the profile's final block (`BalanceChanged` when it moved) and one span window of its logs past the triple's cursor
//! (`HistoryAdded`); the cursor lives in `sdk.state`. Only an account a keystore row names is watched, so no event and no
//! cursor names a hidden set's account (a hidden set is never written). Each poll first reads `sdk.state`'s `rev`:
//! `StateChanged` when another process moved it. No websockets. UNAUDITED.
use crate::op::{evm, final_block, state};
use crate::vault::AccountRow;
use crate::wallet::balances::id_word;
use crate::wallet::history::{listed, scan};
use crate::wallet::tokens::selector;
use crate::{Event, Sdk, SdkError};
use alloy::primitives::{Address, Bytes, B256, U256};
use scaas_rpc::evm::LOG_RANGE_MAX;
use scaas_rpc::pool::ReadError;
use scaas_rpc::Purpose;
use std::collections::HashMap;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, PoisonError};

/// `sdk.state`'s `rev` not read yet.
pub(crate) const REV_UNSEEN: u64 = u64::MAX;

/// The watched pairs and what the polls saw.
#[derive(Default)]
pub(crate) struct Watching {
    /// `(account, chain)`, the account lower case
    pairs: Vec<(String, String)>,
    /// the first triple of the next poll
    next: usize,
    /// the last balance read by triple key
    last: HashMap<String, U256>,
    started: bool,
}

fn rows_id(r: &AccountRow) -> &str {
    match r {
        AccountRow::Ua { ua, .. } | AccountRow::Key { ua, .. } => ua,
        AccountRow::Native { address, .. } => address,
        AccountRow::Watch { watch, .. } => watch,
    }
}

impl Sdk {
    /// Watches `account` (a `0x` address or UA that an account row of the keystore names) on `chains` (EVM profiles) and
    /// starts the poll loop once. `Argument`: an id no row names (a hidden set's account is never watched) or a bad id;
    /// `ChainUnknown`.
    pub async fn watch(self: &Arc<Self>, account: String, chains: Vec<String>) -> Result<(), SdkError> {
        let sdk = self.clone();
        self.spawn(async move {
            id_word(&account)?;
            for c in &chains {
                evm(&sdk, c)?;
            }
            let account = account.to_ascii_lowercase();
            let ks = sdk.load_keystore().await?.keystore;
            if !ks
                .seeds
                .iter()
                .flat_map(|s| &s.accounts)
                .any(|r| rows_id(r).eq_ignore_ascii_case(&account))
            {
                return Err(SdkError::Argument);
            }
            let _ = sdk
                .state_seen
                .compare_exchange(REV_UNSEEN, state::rev(&sdk).await?, SeqCst, SeqCst);
            let start = {
                let mut w = sdk.watching.lock().unwrap_or_else(PoisonError::into_inner);
                for c in chains {
                    let p = (account.clone(), c);
                    if !w.pairs.contains(&p) {
                        w.pairs.push(p);
                    }
                }
                !std::mem::replace(&mut w.started, true)
            };
            if start {
                start_loop(&sdk);
            }
            Ok(())
        })
        .await
    }

    /// `sdk.state`'s `rev` now (R17; 0 when none is written).
    pub async fn state_rev(&self) -> Result<u64, SdkError> {
        state::rev(self).await
    }

    /// One watch poll now (the loop runs one every `Limits::watch_poll_ms`; Rust-only). A triple whose read fails is read again
    /// next poll; the first failure is returned after the others ran.
    pub async fn poll(&self) -> Result<(), SdkError> {
        let rev = state::rev(self).await?;
        let seen = self.state_seen.swap(rev, SeqCst);
        if seen != REV_UNSEEN && seen != rev {
            self.emit(Event::StateChanged { rev });
        }
        let pairs = self
            .watching
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pairs
            .clone();
        let mut triples = vec![];
        for (account, chain) in pairs {
            for t in listed(self, &chain).await? {
                triples.push((account.clone(), chain.clone(), t));
            }
        }
        let n = triples.len();
        let take = n.min(self.limits.max_watch as usize);
        let first = {
            let mut w = self.watching.lock().unwrap_or_else(PoisonError::into_inner);
            let first = if n == 0 { 0 } else { w.next % n };
            w.next = if n == 0 { 0 } else { (first + take) % n };
            first
        };
        let mut err = None;
        for (account, chain, token) in triples.into_iter().cycle().skip(first).take(take) {
            if let Err(e) = self.poll_triple(&account, &chain, token).await {
                err.get_or_insert(e);
            }
        }
        err.map_or(Ok(()), Err)
    }

    async fn poll_triple(&self, account: &str, chain: &str, token: Address) -> Result<(), SdkError> {
        let (word, _) = id_word(account)?;
        let (profile, _, pool) = evm(self, chain)?;
        let key = format!("{chain}|{account}|{}", crate::op::hex(token.as_slice()));
        let mut data = selector("balanceOfUA(bytes32)");
        data.extend_from_slice(&word);
        let (p, data) = (&pool, &data);
        let a = pool
            .read_at_block(final_block(&profile), Purpose::Plain, |at| async move {
                let w = p.call_at(&at, token, Bytes::from(data.clone())).await?;
                if w.len() != 32 {
                    return Err(ReadError::Failure(scaas_rpc::EndpointFailure::new(
                        at.endpoint,
                        scaas_rpc::FailureKind::AnswerMalformed,
                        "a balance of no word",
                    )));
                }
                Ok(U256::from_be_slice(&w))
            })
            .await?;
        let moved = {
            let mut w = self.watching.lock().unwrap_or_else(PoisonError::into_inner);
            w.last.insert(key.clone(), a.value).is_some_and(|v| v != a.value)
        };
        if moved {
            self.emit(Event::BalanceChanged {
                account: account.into(),
                chain: chain.into(),
                token: crate::op::hex(token.as_slice()),
            });
        }
        let fin = a.number;
        let Some(cur) = state::cursor(self, &key).await? else {
            // first watched: from now on (the past is `history`'s)
            return state::put_cursor(self, &key, fin).await;
        };
        if fin <= cur {
            return Ok(());
        }
        let to = fin.min(cur.saturating_add(LOG_RANGE_MAX));
        let items = scan(&pool, &[token], B256::from(word), cur + 1, to).await?;
        state::put_cursor(self, &key, to).await?;
        if !items.is_empty() {
            self.emit(Event::HistoryAdded {
                account: account.into(),
                chain: chain.into(),
                items,
            });
        }
        Ok(())
    }

    /// Notes the `rev` the SDK itself wrote over `prev`: no `StateChanged` for it, unless another process wrote since the poll.
    pub(crate) fn note_state_rev(&self, prev: Option<u64>, new: u64) {
        let _ = self
            .state_seen
            .compare_exchange(prev.unwrap_or(0), new, SeqCst, SeqCst);
    }
}

/// The poll loop on the SDK's runtime, holding the SDK weakly (it ends when the SDK goes).
fn start_loop(sdk: &Arc<Sdk>) {
    let weak = Arc::downgrade(sdk);
    let ms = sdk.limits.watch_poll_ms.max(1);
    let run = async move {
        loop {
            #[cfg(not(target_arch = "wasm32"))]
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            #[cfg(target_arch = "wasm32")]
            wasmtimer::tokio::sleep(std::time::Duration::from_millis(ms)).await;
            let Some(sdk) = weak.upgrade() else { return };
            // a failed poll is read again at the next one
            let _ = sdk.poll().await;
        }
    };
    #[cfg(not(target_arch = "wasm32"))]
    if let Some(rt) = &sdk.rt {
        rt.handle.spawn(run);
    }
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(run);
}
