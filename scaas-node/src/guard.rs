//! Money safety before every simulation and signature (PAY-FIX2, NODE-JOB-01, -19, -20, NODE-GW-07). A lane is
//! `msg.sender` of everything it signs, and it holds fee income in tokens, so:
//!
//! - a `call` job runs only when its selector is a row of the call table and its target meets the row's rule —
//!   never a registered token or the token factory (a `transfer` of the lane's own balance is no row);
//! - a token's order entry (`mtxCancelOrder`, `mtxInvalidateNonces`, `mtxWrap`, a `metatx` job naming its `entry`)
//!   runs only on a registered token (or a listed DEX) bound to this chain;
//! - a meta-transaction runs only on a contract bound to this chain (`chainUid()`, the salt every signature on it
//!   commits to); a `MetaTransfer` only on a registered token (answering `chainUid()` costs nothing to deploy); a
//!   self-call only with a selector, fee mode and mode bits the contract's published allowlist accepts
//!   (`mtxSelectors()`, `supportedModes()`);
//! - `mtxSettle` gas is sized by a simulation that settles every planned settlement (success is not monotonic in gas,
//!   P2b-2), and a contract signer's meta-tx gets at least the ERC-1271 floor (P1b note c);
//! - gas follows the chain's fork, read from its `latest` header: under Amsterdam (EIP-7928 `blockAccessListHash`
//!   present) the two-dimensional model (EIP-7825 + EIP-8037): regular gas ≤ 2^24 per transaction, enforced by the
//!   chain's own simulation and checked here for the calldata floor, the gas limit (regular + state) bounded by
//!   `max_gas_per_tx`, the chain's current block gas limit (read, never assumed) and 2^32 − 1; before it (Osaka, L2s,
//!   anvil) the whole gas limit ≤ 2^24 as before.
//!
//! Pure rules first (unit- and mutation-tested), then the cached chain reads (`Guard`).
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use alloy::primitives::{Address, Bytes};
use alloy::sol_types::SolValue;
use tracing::warn;

use crate::abi::IToken;
use crate::chain::{BlockGas, Chain, SimError};
use crate::config::ChainCfg;
use crate::metatx::{Mtx, MODE_FEE_MASK};
use crate::submit::Work;

pub const SEL_MTX_SETTLE: [u8; 4] = [0x04, 0x03, 0xb1, 0x3c];
pub const SEL_MTX_INVALIDATE_NONCES: [u8; 4] = [0xdb, 0xac, 0x32, 0xd0];
pub const SEL_MTX_CANCEL_ORDER: [u8; 4] = [0x93, 0xcb, 0x3e, 0x81];
pub const SEL_MTX_WRAP: [u8; 4] = [0x3e, 0xd1, 0x8b, 0xa8];

/// What a call-table row requires of its target (job-api.md §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// The chain's `SmartKeyAccountFactory` (`account_factory`).
    AccountFactory,
    /// Self-authenticating (`SmartKeyAccount`, `MandateWallet`): any contract bound to this chain that is not a
    /// registered token or the token factory; the target checks the owner's or delegate's signature.
    SelfAuth,
    /// A DEX on the chain's DEX list (`dex`), bound to this chain.
    Dex,
}

/// The call table as built in P5: the rows whose contracts exist (`cast sig` of the Solidity signatures; pinned
/// against the KAT calldata). `mtxExecuteAsOwner` is one selector on `SmartKeyAccount` and `MandateWallet`, so it takes
/// the wallet's rule. Every other selector is refused.
pub const CALL_TABLE: [([u8; 4], &str, Rule); 10] = [
    ([0x45, 0x9b, 0x5b, 0x50], "SmartKeyAccountFactory.deploy", Rule::AccountFactory),
    ([0xfd, 0xf2, 0xd3, 0x38], "mtxExecuteAsOwner", Rule::SelfAuth),
    ([0x3a, 0x5b, 0x07, 0x08], "HederaMandateWallet.mtxExecuteAsOwnerRaw", Rule::SelfAuth),
    ([0x1d, 0xef, 0xeb, 0x10], "MandateWallet.mtxPayUnderMandate", Rule::SelfAuth),
    ([0xb5, 0x34, 0xf2, 0x74], "MandateWallet.mtxRevoke", Rule::SelfAuth),
    (SEL_MTX_SETTLE, "SCaaSDex.mtxSettle", Rule::Dex),
    (<crate::abi::ISCaaSDex::mtxExchangeCall as alloy::sol_types::SolCall>::SELECTOR, "SCaaSDex.mtxExchange", Rule::Dex),
    (<crate::abi::ISCaaSDex::mtxExchangeViaCall as alloy::sol_types::SolCall>::SELECTOR, "SCaaSDex.mtxExchangeVia", Rule::Dex),
    ([0x2d, 0xe6, 0x21, 0xd2], "SCaaSDex.mtxCancelOrders", Rule::Dex),
    (SEL_MTX_INVALIDATE_NONCES, "SCaaSDex.mtxInvalidateNonces", Rule::Dex),
];

/// The token entries a `metatx` job may name (job-api.md, order and wrap entries).
pub const ENTRIES: [[u8; 4]; 3] = [SEL_MTX_CANCEL_ORDER, SEL_MTX_INVALIDATE_NONCES, SEL_MTX_WRAP];

/// 21 000 intrinsic (pre-Amsterdam; EIP-2780 makes it 15,000, so the floor only grows the margin) + the 400 k `SmartKeyAccount` ERC-1271 cap the contract must still hold at the call (×64/63)
/// + `SigCheck`'s 5 000 margin (P1b note c): a contract signer's meta-tx never gets less. Entries get no floor (P5
///   review m6, closed): a starved `SigCheck` reverts `SigCheckGasStarved`, so their estimate already covers the call.
pub const ERC1271_FLOOR: u64 = 21_000 + 400_000 * 64 / 63 + 5_000;

/// EIP-7825 under Amsterdam (EIP-8037): the cap on a transaction's REGULAR gas (intrinsic, calldata floor and
/// execution). State gas (new slots 97,920, code 1,530 per byte) comes on top, so the gas LIMIT may exceed it.
pub const MAX_TX_GAS: u64 = 1 << 24;
/// EIP-8037 `TX_MAX_TOTAL_GAS_LIMIT`: the largest gas limit (regular + state) a transaction may carry (Nethermind 2.2.0
/// `Eip8037Constants`, PR #13627).
pub const MAX_TX_TOTAL_GAS: u64 = u32::MAX as u64;

/// The EIP-7976 calldata floor of a call to another account, which counts as regular gas: 12,000 (EIP-2780) + 3,000
/// (cold recipient, EIP-8038) + 64 per calldata byte. Measured on the SCaaS testnet: a 220,415 B transaction paid exactly
/// 14,121,560 = 15,000 + 64 · 220,415, and every input over 261,909 B was refused at any gas limit
/// (`pqz-core/nethermind/runs/2026-10-21-glamsterdam-gas-impact.md`).
pub fn calldata_floor(len: usize) -> u64 {
    15_000 + 64 * len as u64
}

/// The gas limit cap of one transaction: `max_gas_per_tx`, the chain's block gas limit (EIP-8037 reserves `tx.gas` in
/// the block's state dimension: a larger limit is never included) and EIP-8037's 2^32 − 1; before Amsterdam EIP-7825's
/// 2^24 caps the whole limit.
pub fn total_cap(max_gas_per_tx: u64, block: BlockGas) -> u64 {
    let c = max_gas_per_tx.min(block.limit).min(MAX_TX_TOTAL_GAS);
    if block.amsterdam { c } else { c.min(MAX_TX_GAS) }
}

const FEE_CLASS_ABSOLUTE: u8 = 1;
const FEE_CLASS_AMOUNT: u8 = 2;

pub fn row(sel: [u8; 4]) -> Option<(&'static str, Rule)> {
    CALL_TABLE.iter().find(|r| r.0 == sel).map(|r| (r.1, r.2))
}

/// What the node knows of a `call` target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Facts {
    pub token: bool,
    pub token_factory: bool,
    pub account_factory: bool,
    pub dex: bool,
    /// `chainUid()` equals this chain's (NODE-GW-07).
    pub bound: bool,
}

pub fn allowed(rule: Rule, f: &Facts) -> bool {
    f.bound
        && !f.token
        && !f.token_factory
        && match rule {
            Rule::AccountFactory => f.account_factory,
            Rule::SelfAuth => true,
            Rule::Dex => f.dex,
        }
}

/// A contract's published allowlist: `(selector, fee class, amount argument)` and `supportedModes()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    pub rows: Vec<([u8; 4], u8, u8)>,
    pub supported: u32,
}

/// NODE-JOB-20 intake of a self-call, as `MetaTxBase._checkCall` decides it, before any simulation: the selector is
/// allowlisted, an `AMOUNT` selector carries its basis argument, an `ABSOLUTE` selector takes no `PERCENT` fee, and
/// the mode has no bit the contract does not support. (The static ABI length is the contract's own check.)
pub fn self_call_ok(t: &Table, data: &[u8], mode: u32) -> Result<(), String> {
    let Some(sel) = data.get(..4) else { return Err("SELECTOR_NOT_ALLOWED: data shorter than a selector".into()) };
    let Some(&(_, class, arg)) = t.rows.iter().find(|r| r.0 == sel) else {
        return Err(format!("SELECTOR_NOT_ALLOWED: 0x{} is not on the contract's allowlist", alloy::hex::encode(sel)));
    };
    if class != FEE_CLASS_ABSOLUTE && class != FEE_CLASS_AMOUNT {
        return Err("SELECTOR_NOT_ALLOWED: unknown fee class".into());
    }
    if class == FEE_CLASS_AMOUNT && data.len() < 36 + 32 * usize::from(arg) {
        return Err("SELECTOR_NOT_ALLOWED: data shorter than its fee basis".into());
    }
    if class == FEE_CLASS_ABSOLUTE && (mode & MODE_FEE_MASK) >> 4 == 1 {
        return Err("SELECTOR_NOT_ALLOWED: a PERCENT fee on an ABSOLUTE selector".into());
    }
    if mode & !t.supported != 0 {
        return Err(format!("SELECTOR_NOT_ALLOWED: mode {mode:#x} outside supportedModes {:#x}", t.supported));
    }
    Ok(())
}

/// The gas limit of a simulated estimate (regular + state): +20 %, at least the ERC-1271 floor for a contract signer,
/// at most `cap` ([`total_cap`]). Above 2^24 is fine under Amsterdam: the chain gives execution at most 2^24 of it and
/// the rest is the state-gas reservoir (EIP-8037).
pub fn gas_limit(estimate: u64, contract_signer: bool, cap: u64) -> u64 {
    let g = estimate.saturating_add(estimate / 5);
    (if contract_signer { g.max(ERC1271_FLOOR) } else { g }).min(cap)
}

/// `mtxSettle` returned `ok` for every settlement it was given.
pub fn settled_all(ret: &[u8]) -> bool {
    <Vec<bool> as SolValue>::abi_decode(ret).is_ok_and(|v| !v.is_empty() && v.iter().all(|x| *x))
}

/// The next gas to try for `mtxSettle`: ×1.5, capped at `max`; `None` once at the cap.
pub fn next_gas(g: u64, max: u64) -> Option<u64> {
    (g < max).then(|| g.saturating_add(g / 2).min(max))
}

/// `mtxInvalidateNonces` (token or DEX) whose simulation says the lane is already at or past the asked minimum
/// (`MinNonceNotIncreasing`): what it was sent for already holds, so the job is done, never dead (MT-8).
pub fn already_invalidated(data: &[u8], reason: &str) -> bool {
    data.get(..4) == Some(&SEL_MTX_INVALIDATE_NONCES[..]) && reason.starts_with("MinNonceNotIncreasing(")
}

/// Why the guard refused: a rule (the job is dead with this reason) or an unreadable chain (try again).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Policy(String),
    Transport(String),
}

impl From<Refusal> for SimError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::Policy(s) => SimError::Revert(s),
            Refusal::Transport(s) => SimError::Transport(s),
        }
    }
}

/// The chain reads behind the rules, cached: implementations are immutable, so a contract's `chainUid()` and
/// allowlist never change (a contract that is not bound yet is asked again).
pub struct Guard {
    pub tokens: Arc<RwLock<Vec<Address>>>,
    token_factory: Option<Address>,
    account_factory: Option<Address>,
    dexes: Vec<Address>,
    bound: Mutex<HashSet<Address>>,
    tables: Mutex<HashMap<Address, Arc<Table>>>,
}

impl Guard {
    pub fn new(cfg: &ChainCfg, tokens: Arc<RwLock<Vec<Address>>>) -> Self {
        Self {
            tokens,
            token_factory: cfg.token_factory,
            account_factory: cfg.account_factory,
            dexes: cfg.dex.into_iter().collect(),
            bound: Default::default(),
            tables: Default::default(),
        }
    }

    /// A token of the chain's registered list (refreshed from the client, review T4 m1); an unreadable list is none.
    fn registered(&self, a: Address) -> bool {
        self.tokens.read().is_ok_and(|t| t.contains(&a))
    }

    pub async fn check(&self, chain: &Chain, w: &Work) -> Result<(), Refusal> {
        let not_served = |to: Address| Refusal::Policy(format!("TOKEN_NOT_SERVED: {to:#x} is not a registered token of this chain"));
        if w.meta.is_some() {
            // review T4 I1: a transfer or payment only on a registered token
            if !matches!(Mtx::from_calldata(&w.data), Some((Mtx::Call(_), _))) && !self.registered(w.to) {
                return Err(not_served(w.to));
            }
            self.require_bound(chain, w.to).await?;
            if let Some((Mtx::Call(m), _)) = Mtx::from_calldata(&w.data) {
                let t = self.table(chain, w.to).await?;
                self_call_ok(&t, &m.data, m.mode).map_err(Refusal::Policy)?;
            }
            return Ok(());
        }
        let sel: [u8; 4] = match w.data.get(..4) {
            Some(s) => s.try_into().expect("4 bytes"),
            None => return Err(Refusal::Policy("CALL_TARGET_REFUSED: no selector".into())),
        };
        if w.entry {
            if !ENTRIES.contains(&sel) {
                return Err(Refusal::Policy("CALL_TARGET_REFUSED: not an order or wrap entry".into()));
            }
            if !self.registered(w.to) && !self.dexes.contains(&w.to) {
                return Err(not_served(w.to));
            }
            return self.require_bound(chain, w.to).await;
        }
        let Some((name, rule)) = row(sel) else {
            return Err(Refusal::Policy(format!("CALL_TARGET_REFUSED: 0x{} is not in the call table", alloy::hex::encode(sel))));
        };
        let facts = Facts {
            token: self.tokens.read().map(|t| t.contains(&w.to)).unwrap_or(true),
            token_factory: self.token_factory == Some(w.to),
            account_factory: self.account_factory == Some(w.to),
            dex: self.dexes.contains(&w.to),
            bound: self.bound(chain, w.to).await?,
        };
        if allowed(rule, &facts) {
            Ok(())
        } else {
            Err(Refusal::Policy(format!("CALL_TARGET_REFUSED: {name} on {:#x}", w.to)))
        }
    }

    async fn require_bound(&self, chain: &Chain, to: Address) -> Result<(), Refusal> {
        if self.bound(chain, to).await? {
            Ok(())
        } else {
            Err(Refusal::Policy(format!("CHAIN_UID_MISMATCH: {to:#x} is not bound to this chain (NODE-GW-07)")))
        }
    }

    /// `chainUid()` of `to` equals this chain's; a contract without one is not bound.
    async fn bound(&self, chain: &Chain, to: Address) -> Result<bool, Refusal> {
        if self.bound.lock().is_ok_and(|b| b.contains(&to)) {
            return Ok(true);
        }
        let uid = chain.uid().await.map_err(|e| Refusal::Transport(format!("chain_uid: {e:#}")))?;
        let ok = match chain.call_view(to, IToken::chainUidCall {}).await {
            Ok(u) => u == uid,
            Err(SimError::Revert(_)) => false,
            Err(SimError::Transport(e)) => return Err(Refusal::Transport(format!("chainUid(): {e}"))),
        };
        if ok {
            if let Ok(mut b) = self.bound.lock() {
                b.insert(to);
            }
        }
        Ok(ok)
    }

    async fn table(&self, chain: &Chain, to: Address) -> Result<Arc<Table>, Refusal> {
        if let Some(t) = self.tables.lock().ok().and_then(|t| t.get(&to).cloned()) {
            return Ok(t);
        }
        let read = |e: SimError| match e {
            SimError::Revert(r) => Refusal::Policy(format!("SELECTOR_NOT_ALLOWED: no published allowlist: {r}")),
            SimError::Transport(r) => Refusal::Transport(format!("mtxSelectors(): {r}")),
        };
        let s = chain.call_view(to, IToken::mtxSelectorsCall {}).await.map_err(read)?;
        let supported = chain.call_view(to, IToken::supportedModesCall {}).await.map_err(read)?;
        let rows = s.selectors.iter().zip(&s.feeClass).zip(&s.amountArg).map(|((sel, c), a)| (sel.0, *c, *a)).collect();
        let t = Arc::new(Table { rows, supported });
        if let Ok(mut m) = self.tables.lock() {
            m.insert(to, t.clone());
        }
        Ok(t)
    }
}

/// Simulated gas → the gas limit, for the EVM submitter and the lane runner alike. Regular gas: a calldata floor over
/// 2^24 is refused before any RPC; an execution over 2^24 makes the chain's own simulation fail (`Chain::simulate`
/// reads that as a refusal). The estimate (regular + state, `eth_estimateGas`) must fit `max` (`max_gas_per_tx`) and
/// the chain's block gas limit; `mtxSettle` is sized until every planned settlement settles; a contract signer's
/// meta-tx gets at least the ERC-1271 floor.
pub async fn gas(chain: &Chain, w: &Work, max: u64) -> Result<u64, SimError> {
    let block = chain.block_gas().await.map_err(|e| SimError::Transport(format!("block gas limit: {e:#}")))?;
    let floor = calldata_floor(w.data.len());
    if block.amsterdam && floor > MAX_TX_GAS {
        return Err(SimError::Revert(format!(
            "calldata floor {floor} above the 2^24 regular gas of a transaction ({} B; EIP-7976, EIP-7825)", w.data.len())));
    }
    let est = chain.simulate(w.to, w.data.clone()).await?;
    if est > max {
        return Err(SimError::Revert(format!("gas {est} above max_gas_per_tx {max}")));
    }
    if est > block.limit {
        return Err(SimError::Revert(format!("gas {est} above the chain's block gas limit {}", block.limit)));
    }
    if !block.amsterdam && est > MAX_TX_GAS {
        return Err(SimError::Revert(format!("gas {est} above the 2^24 gas limit of a transaction (EIP-7825, before Amsterdam)")));
    }
    let max = total_cap(max, block);
    let g = if !w.entry && w.meta.is_none() && w.data.get(..4) == Some(&SEL_MTX_SETTLE[..]) {
        settle_gas(chain, w.to, &w.data, est, max).await?
    } else {
        let contract_signer = match &w.meta {
            Some(m) => chain.has_code(m.from).await.map_err(|e| SimError::Transport(format!("eth_getCode: {e:#}")))?,
            None => false,
        };
        gas_limit(est, contract_signer, max)
    };
    if g >= block.limit {
        // review L1 (controller 2026-10-22): accepted, but the transaction fills a whole block's gas reservation
        warn!(to = %w.to, gas = g, estimate = est, block = block.limit, "gas limit equals the chain's block gas limit");
    }
    Ok(g)
}

/// Size `mtxSettle` gas by simulation (P2b-2, NODE-DEX-15): from the estimate +20 %, raise ×1.5 until every planned
/// settlement settles, never past `max`. A whole-call revert is the job's answer as it is (never retried with more gas:
/// `SigCheckGasStarved` is forgeable by a hook-token destination); a transport error is transient, never a size. At the
/// cap the refusal names the settlements still failing (review P5 m4: a state failure looks the same as too little gas).
pub async fn settle_gas(chain: &Chain, to: Address, data: &Bytes, estimate: u64, max: u64) -> Result<u64, SimError> {
    let mut g = gas_limit(estimate, false, max);
    loop {
        let ret = chain.call_with_gas(to, data.clone(), g).await?;
        if settled_all(&ret) {
            return Ok(g);
        }
        let Some(next) = next_gas(g, max) else {
            let failing: Vec<usize> = <Vec<bool> as SolValue>::abi_decode(&ret)
                .map(|v| v.iter().enumerate().filter(|(_, ok)| !**ok).map(|(i, _)| i).collect())
                .unwrap_or_default();
            return Err(SimError::Revert(format!(
                "mtxSettle does not settle every settlement within {max} gas: settlements {failing:?} fail at the cap \
                 (a state failure, or more gas than the cap)")));
        };
        g = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::{SolCall, SolError};

    /// Every row's selector is the `cast sig` of its Solidity signature, and the KAT calldata starts with it.
    #[test]
    fn the_call_table_is_pinned() {
        let kat = |f: &str, k: &str| -> Vec<u8> {
            let p = format!("{}/../smartcontracts/evm/test/vectors/{f}", env!("CARGO_MANIFEST_DIR"));
            let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
            alloy::hex::decode(&v[k].as_str().unwrap()[2..]).unwrap()
        };
        assert_eq!(kat("dex_order_kat.json", "settle_calldata")[..4], SEL_MTX_SETTLE);
        assert_eq!(kat("dex_order_kat.json", "cancel_orders_calldata")[..4], CALL_TABLE[8].0);
        assert_eq!(kat("dex_order_kat.json", "invalidate_calldata")[..4], SEL_MTX_INVALIDATE_NONCES);
        assert_eq!(kat("trade_kat.json", "cancel_calldata")[..4], SEL_MTX_CANCEL_ORDER);
        assert_eq!(crate::abi::ISCaaSDex::mtxSettleCall::SELECTOR, SEL_MTX_SETTLE);
        assert_eq!(IToken::mtxWrapCall::SELECTOR, SEL_MTX_WRAP);
        let sig = |s: &str| -> [u8; 4] { alloy::primitives::keccak256(s)[..4].try_into().unwrap() };
        assert_eq!(CALL_TABLE[0].0, sig("deploy((uint8,bytes32,bytes32,bytes32,bytes32),address)"));
        assert_eq!(CALL_TABLE[1].0, sig("mtxExecuteAsOwner(bytes,uint256,uint256,bytes)"));
        assert_eq!(CALL_TABLE[2].0, sig("mtxExecuteAsOwnerRaw(bytes,uint256,uint256,bytes)"));
        assert_eq!(CALL_TABLE[3].0, sig("mtxPayUnderMandate(address,address,uint256,bytes32,uint64,uint256,bytes)"));
        assert_eq!(CALL_TABLE[4].0, sig("mtxRevoke(address,uint64,uint256,bytes)"));
        // C6-2: the tagged `ExchangeLeg` (sellToken, shape, order bytes, sig, sellFill, receiveFill)
        let plan = "(bytes32,(address,uint8,bytes,bytes,uint256,uint256)[],address[])";
        assert_eq!(CALL_TABLE[6].0, sig(&format!("mtxExchange({plan},(address,bytes)[])")));
        assert_eq!(CALL_TABLE[7].0, sig(&format!("mtxExchangeVia({plan},address,bytes)")));
        assert_eq!(CALL_TABLE[6].0, crate::abi::ISCaaSDex::mtxExchangeCall::SELECTOR);
        assert_eq!(CALL_TABLE[7].0, crate::abi::ISCaaSDex::mtxExchangeViaCall::SELECTOR);
        // no token transfer, approval or meta-tx entry is a row: those reach a token only as `metatx` jobs
        for s in ["transfer(address,uint256)", "approve(address,uint256)", "transferFrom(address,address,uint256)"] {
            assert!(row(sig(s)).is_none(), "{s}");
        }
        assert!(row(IToken::mtxExecuteCall::SELECTOR).is_none() && row(IToken::mtxExecuteTransferCall::SELECTOR).is_none());
        assert!(row(SEL_MTX_CANCEL_ORDER).is_none() && row(SEL_MTX_WRAP).is_none());
        // and each row keeps its rule
        let rules: Vec<Rule> = CALL_TABLE.iter().map(|r| r.2).collect();
        assert_eq!(rules, [Rule::AccountFactory, Rule::SelfAuth, Rule::SelfAuth, Rule::SelfAuth, Rule::SelfAuth,
            Rule::Dex, Rule::Dex, Rule::Dex, Rule::Dex, Rule::Dex]);
    }

    /// An entry job carries only an order or wrap entry; anything else is refused before any chain read.
    #[tokio::test]
    async fn an_entry_job_is_only_an_entry() {
        let cfg = ChainCfg { evm_chain_number: 7, rpc_urls: vec!["http://127.0.0.1:9".into()], ..Default::default() };
        let chain = Chain::with_signer(&cfg, alloy::signers::local::PrivateKeySigner::random()).unwrap();
        let g = Guard::new(&cfg, Default::default());
        let w = |data: Vec<u8>| Work { job_id: Some(1), to: Address::repeat_byte(1), data: data.into(), valid_until: 0, meta: None, entry: true };
        let transfer = IToken::transferCall { to: Address::repeat_byte(2), value: alloy::primitives::U256::from(1) }.abi_encode();
        assert!(matches!(g.check(&chain, &w(transfer)).await, Err(Refusal::Policy(r)) if r.starts_with("CALL_TARGET_REFUSED")));
        assert!(matches!(g.check(&chain, &w(vec![])).await, Err(Refusal::Policy(_))));
        // review T4 I1: an entry on a contract that is neither a registered token nor a listed DEX
        let cancel = [&SEL_MTX_CANCEL_ORDER[..], &[0u8; 32]].concat();
        assert!(matches!(g.check(&chain, &w(cancel.clone())).await, Err(Refusal::Policy(r)) if r.starts_with("TOKEN_NOT_SERVED")));
        // on a registered token it passes the selector check and then needs the chain (unreachable: transient)
        let g = Guard::new(&cfg, Arc::new(RwLock::new(vec![Address::repeat_byte(1)])));
        assert!(matches!(g.check(&chain, &w(cancel.clone())).await, Err(Refusal::Transport(_))));
        let g = Guard::new(&ChainCfg { dex: Some(Address::repeat_byte(1)), ..cfg.clone() }, Default::default());
        assert!(matches!(g.check(&chain, &w(cancel)).await, Err(Refusal::Transport(_))), "or on a listed DEX");
    }

    #[test]
    fn each_rule_needs_its_target() {
        let bound = Facts { bound: true, ..Default::default() };
        assert!(allowed(Rule::SelfAuth, &bound));
        assert!(!allowed(Rule::SelfAuth, &Facts { bound: false, ..bound }), "NODE-GW-07");
        assert!(!allowed(Rule::SelfAuth, &Facts { token: true, ..bound }), "never a registered token");
        assert!(!allowed(Rule::SelfAuth, &Facts { token_factory: true, ..bound }), "never the token factory");
        assert!(!allowed(Rule::Dex, &bound), "only a listed DEX");
        assert!(allowed(Rule::Dex, &Facts { dex: true, ..bound }));
        assert!(!allowed(Rule::Dex, &Facts { dex: true, token: true, ..bound }));
        assert!(!allowed(Rule::Dex, &Facts { dex: true, bound: false, ..bound }));
        assert!(!allowed(Rule::AccountFactory, &bound), "only the account factory");
        assert!(allowed(Rule::AccountFactory, &Facts { account_factory: true, ..bound }));
        assert!(!allowed(Rule::AccountFactory, &Facts { account_factory: true, bound: false, ..bound }));
    }

    #[test]
    fn self_calls_follow_the_published_allowlist() {
        let t = Table { rows: vec![([1, 2, 3, 4], 1, 0), ([5, 6, 7, 8], 2, 1)], supported: 0xF3 };
        let data = |sel: [u8; 4], words: usize| [&sel[..], &vec![0u8; 32 * words]].concat();
        self_call_ok(&t, &data([1, 2, 3, 4], 1), 0x21).unwrap();
        assert!(self_call_ok(&t, &data([9, 9, 9, 9], 1), 0).is_err(), "not allowlisted");
        assert!(self_call_ok(&t, &[1, 2, 3], 0).is_err(), "short");
        assert!(self_call_ok(&t, &data([1, 2, 3, 4], 1), 0x10).is_err(), "PERCENT on ABSOLUTE");
        self_call_ok(&t, &data([1, 2, 3, 4], 1), 0x20).unwrap();
        self_call_ok(&t, &data([5, 6, 7, 8], 2), 0x10).unwrap();
        assert!(self_call_ok(&t, &data([5, 6, 7, 8], 1), 0x10).is_err(), "AMOUNT basis argument missing");
        let narrow = Table { supported: 0x03, ..t.clone() };
        assert!(self_call_ok(&narrow, &data([1, 2, 3, 4], 1), 0x20).is_err(), "fee bits outside supportedModes");
        self_call_ok(&narrow, &data([1, 2, 3, 4], 1), 0x03).unwrap();
        let odd = Table { rows: vec![([1, 2, 3, 4], 3, 0)], supported: 0xF3 };
        assert!(self_call_ok(&odd, &data([1, 2, 3, 4], 1), 0).is_err(), "unknown fee class");
    }

    #[test]
    fn gas_floor_and_settle_sizing() {
        assert_eq!(ERC1271_FLOOR, 432_349);
        let ams = |limit| BlockGas { limit, amsterdam: true };
        let cap = total_cap(u64::MAX, ams(200_000_000));
        assert_eq!(gas_limit(100_000, false, cap), 120_000);
        assert_eq!(gas_limit(100_000, true, cap), ERC1271_FLOOR);
        assert_eq!(gas_limit(1_000_000, true, cap), 1_200_000);
        assert_eq!(gas_limit(MAX_TX_GAS, false, cap), MAX_TX_GAS + MAX_TX_GAS / 5, "Amsterdam: a limit past 2^24 is kept");
        assert_eq!(gas_limit(190_000_000, false, cap), 200_000_000, "the padded estimate is clamped to the cap");
        assert_eq!(gas_limit(u64::MAX, true, total_cap(u64::MAX, ams(u64::MAX))), MAX_TX_TOTAL_GAS, "EIP-8037: 2^32 - 1");
        assert_eq!(total_cap(50_000_000, ams(30_000_000)), 30_000_000, "the block gas limit binds");
        assert_eq!(total_cap(50_000_000, ams(200_000_000)), 50_000_000, "max_gas_per_tx binds");
        let osaka = BlockGas { limit: 200_000_000, amsterdam: false };
        assert_eq!(total_cap(50_000_000, osaka), MAX_TX_GAS, "before Amsterdam the whole limit stays under 2^24");
        assert_eq!(gas_limit(MAX_TX_GAS, false, total_cap(u64::MAX, osaka)), MAX_TX_GAS);
        assert_eq!(calldata_floor(220_415), 14_121_560, "measured on the SCaaS testnet");
        assert!(calldata_floor(261_909) <= MAX_TX_GAS && calldata_floor(261_910) > MAX_TX_GAS, "261,909 B per transaction");
        assert_eq!(next_gas(1_000, 3_000), Some(1_500));
        assert_eq!(next_gas(2_500, 3_000), Some(3_000));
        assert_eq!(next_gas(3_000, 3_000), None);
        let ok = |v: Vec<bool>| <Vec<bool> as SolValue>::abi_encode(&v);
        assert!(settled_all(&ok(vec![true, true])));
        assert!(!settled_all(&ok(vec![true, false])), "an empty MatchFailed is out of gas: more gas, never invalid");
        assert!(!settled_all(&ok(vec![])));
        assert!(!settled_all(&[1, 2, 3]));
    }

    /// An RPC answering `answer` to every `eth_call`; `(url, gas of each eth_call)`.
    async fn rpc(answer: serde_json::Value) -> (String, Arc<Mutex<Vec<u64>>>) {
        let gases: Arc<Mutex<Vec<u64>>> = Default::default();
        let g = gases.clone();
        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<serde_json::Value>| {
            let (answer, g) = (answer.clone(), g.clone());
            async move {
                let gas = r["params"][0]["gas"].as_str().map_or(0, |x| u64::from_str_radix(&x[2..], 16).unwrap());
                g.lock().unwrap().push(gas);
                let mut out = serde_json::json!({"jsonrpc": "2.0", "id": r["id"]});
                let key = if answer.get("code").is_some() { "error" } else { "result" };
                out[key] = answer;
                axum::Json(out)
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, gases)
    }

    /// Settle sizing on the chain: a transport error is transient (the job goes back to the queue), never a size; at
    /// the cap the refusal names the settlements still failing (review P5 m4).
    #[tokio::test]
    async fn settle_sizing_tells_transport_from_size_and_names_what_fails() {
        let chain = |url: &str| {
            let cfg = ChainCfg { evm_chain_number: 7, rpc_urls: vec![url.into()], ..Default::default() };
            Chain::with_signer(&cfg, alloy::signers::local::PrivateKeySigner::random()).unwrap()
        };
        let (to, data) = (Address::repeat_byte(0xd0), Bytes::from(SEL_MTX_SETTLE.to_vec()));
        let (url, gases) = rpc(serde_json::json!({"code": -32603, "message": "upstream unavailable"})).await;
        assert!(matches!(settle_gas(&chain(&url), to, &data, 100_000, 3_000_000).await, Err(SimError::Transport(_))));
        assert_eq!(gases.lock().unwrap().len(), 1, "no ladder on a transport error");
        let ret = format!("0x{}", alloy::hex::encode(<Vec<bool> as SolValue>::abi_encode(&vec![true, false, true])));
        let (url, gases) = rpc(serde_json::json!(ret)).await;
        let Err(SimError::Revert(r)) = settle_gas(&chain(&url), to, &data, 100_000, 300_000).await else { panic!() };
        assert!(r.contains("settlements [1] fail at the cap"), "{r}");
        assert_eq!(*gases.lock().unwrap(), vec![120_000, 180_000, 270_000, 300_000]);
    }

    #[test]
    fn an_invalidation_already_done_is_success() {
        let reason = crate::abi::decode_revert(
            &IToken::MinNonceNotIncreasing { current: alloy::primitives::U256::from(9), requested: alloy::primitives::U256::from(5) }.abi_encode());
        let inv = [&SEL_MTX_INVALIDATE_NONCES[..], &[0u8; 128]].concat();
        assert!(already_invalidated(&inv, &reason));
        assert!(!already_invalidated(&[&SEL_MTX_CANCEL_ORDER[..], &[0u8; 128]].concat(), &reason));
        assert!(!already_invalidated(&inv, "MinNonceAboveCap(MinNonceAboveCap { requested: 1 })"));
    }
}
