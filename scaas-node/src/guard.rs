//! Money safety before every simulation and signature (PAY-FIX2, NODE-JOB-01, -19, -20, NODE-GW-07). A lane is
//! `msg.sender` of everything it signs, and it holds fee income in tokens, so:
//!
//! - a job runs only as a named entry: its selector is a row of the entry table (`crate::typed`) on the contract kind it
//!   names, and the target meets that kind's rule — a token entry on a registered token, a wallet's or account's on any
//!   bound contract that is no token or factory, a DEX entry on a listed DEX, a registry or factory entry on the configured
//!   one (a `transfer` of the lane's own balance is no row; there is no hex path);
//! - a meta-transaction runs only on a contract bound to this chain (`chainUid()`, the salt every signature on it
//!   commits to); a `MetaTransfer` only on a registered token (answering `chainUid()` costs nothing to deploy);
//! - a signature that can be checked here is (the typed digest, computed locally): a native signer that recovers to
//!   someone else and has no code is refused before any simulation;
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

use alloy::primitives::{Address, Bytes, B256};
use alloy::sol_types::{SolCall, SolValue};
use tracing::warn;

use crate::abi::{IMtxRelayFee, ISCaaSDex, IToken, IUALedger};
use crate::chain::{BlockGas, Chain, SimError};
use crate::config::ChainCfg;
use crate::metatx::{Mtx, UaMtx};
use crate::submit::Work;
use crate::typed;

pub const SEL_MTX_SETTLE: [u8; 4] = ISCaaSDex::mtxSettleCall::SELECTOR;
pub const SEL_MTX_INVALIDATE_NONCES: [u8; 4] = [0xdb, 0xac, 0x32, 0xd0];
/// `uaInvalidateNonces(bytes32,uint256,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))`.
pub const SEL_UA_INVALIDATE_NONCES: [u8; 4] = crate::abi::ITokenUa::uaInvalidateNoncesCall::SELECTOR;

/// What a contract kind requires of its target (job-api.md §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// A registered token (`token`, `zether`, `pqz`).
    Token,
    /// The chain's `SmartKeyAccountFactory` (`account_factory`).
    AccountFactory,
    /// Self-authenticating (`SmartKeyAccount`, `MandateWallet`): any contract bound to this chain that is not a
    /// registered token or the token factory; the target checks the owner's or delegate's signature.
    SelfAuth,
    /// A DEX on the chain's DEX list (`dex`), bound to this chain.
    Dex,
    /// The chain's `UARegistry` (`ua_registry`), bound to this chain: its writes (UA-8, ruling R-node; `registerMsig` since typed-signing R1, `registerWebAuthn` / `registerMuSig2` / `registerFrost` since R1b).
    UaRegistry,
}

/// The rule of a contract kind (`typed::Row::contracts`).
pub fn rule_of(contract: &str) -> Option<Rule> {
    Some(match contract {
        "token" | "zether" | "pqz" => Rule::Token,
        "wallet" | "account" => Rule::SelfAuth,
        "dex" => Rule::Dex,
        "registry" => Rule::UaRegistry,
        "factory" => Rule::AccountFactory,
        _ => return None,
    })
}

/// The allow-list: every selector the node sends, with its table row. `MtxRelayFee.relay` / `uaRelay` come from the
/// `RelayFee` rows (the token's `mtxRelayFee` only ever runs under the router). Anything else is refused.
pub fn row(sel: [u8; 4], contract: &str) -> Option<&'static typed::Row> {
    typed::rows().iter().find(|r| r.sent == sel && !r.entry.is_empty() && r.contracts.contains(&contract))
}

/// The refusal of a relayed PQ registration (`register` with its `R_REG` proof) whose gas estimate is over the
/// per-transaction cap ([`total_cap`]: `max_gas_per_tx`, the block gas limit) or that the chain's estimate refuses for
/// gas: the client splits it into `register` without `pqzPop`, then `storePqzPop` (ruling R-node).
pub const UA_REGISTER_SPLIT: &str = "UA_REGISTER_SPLIT";

/// `register` / `registerMsig` calldata with a non-empty `pqzPop`.
pub fn pq_register(data: &[u8]) -> bool {
    use alloy::sol_types::SolCall;
    crate::abi::IUARegistry::registerCall::abi_decode(data).is_ok_and(|c| !c.pqzPop.is_empty())
        || crate::abi::IUARegistry::registerMsigCall::abi_decode(data).is_ok_and(|c| !c.pqzPop.is_empty())
}

/// Forge's minimum relayer CALL gas of a `SmartKeyAccount`-signed `mtxExecute` after the split (the ERC-1271 call two
/// frames below the token: token → `MtxPipelineLib` → wallet, ≥ (400,000 · 64/63 + 5,000) · 64/63): 446,904
/// (`smartcontracts/evm/runs/2026-10-27-metatx-split-node-floor.txt`, `test_minGas_smartKeyAccountMtxExecute`, Task 8).
/// It is execution gas only (`call{gas: g}`): no intrinsic, no calldata.
pub const ERC1271_CALL_GAS: u64 = 446_904;

/// The gas floor of a contract signer's meta-tx whose calldata is `len` bytes (P1b note c; T17 fix 1): 21,000
/// intrinsic (pre-Amsterdam; EIP-2780 lowers it, which only grows the margin) + 64 gas per calldata byte (the EIP-7976
/// floor rate, the dearest calldata price, as `calldata_floor`) + `ERC1271_CALL_GAS` + 10 % of it (a larger proof or
/// key set grows the prefix). Entries get no floor (P5 review m6, closed): a starved `SigCheck` reverts
/// `SigCheckGasStarved`, so their estimate already covers the call.
pub fn erc1271_floor(len: usize) -> u64 {
    21_000 + 64 * len as u64 + ERC1271_CALL_GAS + ERC1271_CALL_GAS / 10
}

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

/// What the node knows of a `call` target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Facts {
    pub token: bool,
    pub token_factory: bool,
    pub account_factory: bool,
    pub dex: bool,
    pub ua_registry: bool,
    /// `chainUid()` equals this chain's (NODE-GW-07).
    pub bound: bool,
}

pub fn allowed(rule: Rule, f: &Facts) -> bool {
    if rule == Rule::Token {
        return f.bound && f.token;
    }
    f.bound
        && !f.token
        && !f.token_factory
        && match rule {
            Rule::Token => false,
            Rule::AccountFactory => f.account_factory,
            Rule::SelfAuth => true,
            Rule::Dex => f.dex,
            Rule::UaRegistry => f.ua_registry,
        }
}

/// The chain's relay-fee router (CTR-MTX-27) and the node's policy for it (`params.relay_fee`, `RelayParams`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFee {
    pub router: Address,
    /// `MtxRelayExecutor`: the router's first `CREATE` (constructor, nonce 1), so derived, never configured.
    pub executor: Address,
    pub params: crate::config::RelayParams,
    /// `relay_fee.min_wei_value = { "<token>" = wei per base unit }`: the node's floor price of a fee token.
    pub min_wei_value: HashMap<Address, Price>,
}

impl RelayFee {
    /// `None` without `params.relay_fee.router`; a router that is not an address is a startup error.
    pub fn from_cfg(cfg: &ChainCfg) -> anyhow::Result<Option<Self>> {
        let params = cfg.relay_params()?;
        let prices = cfg.params.get("relay_fee").and_then(|t| t.get("min_wei_value"));
        let Some(r) = params.router.as_deref() else {
            // fix 1 (review minor 2): set but unusable is a startup error
            if prices.is_some() {
                anyhow::bail!("params.relay_fee.min_wei_value is set without params.relay_fee.router");
            }
            return Ok(None);
        };
        let router = crate::metatx::addr(r).map_err(|e| anyhow::anyhow!("params.relay_fee.router: {e:#}"))?;
        let mut min_wei_value = HashMap::new();
        if let Some(v) = prices {
            let table = v.as_table().ok_or_else(|| anyhow::anyhow!("params.relay_fee.min_wei_value must be a table of token = wei"))?;
            for (k, n) in table {
                let token = crate::metatx::addr(k).map_err(|e| anyhow::anyhow!("params.relay_fee.min_wei_value.{k}: {e:#}"))?;
                let price = parse_price(n).ok_or_else(|| anyhow::anyhow!(
                    "params.relay_fee.min_wei_value.{k} must be a non-negative integer (wei per base unit) or \"<wei>/<10^k>\" \
                     (wei per 10^k base units), not {n}"))?;
                if min_wei_value.insert(token, price).is_some() {
                    anyhow::bail!("params.relay_fee.min_wei_value names token {token:#x} twice");
                }
            }
        }
        Ok(Some(Self { router, executor: router.create(1), params, min_wei_value }))
    }
}

/// `min_wei_value`'s value: an integer or decimal string (wei per base unit), or `"<wei>/<per>"` with `per` a power of
/// ten (wei per `per` base units).
fn parse_price(n: &toml::Value) -> Option<Price> {
    let dec = |s: &str| (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse::<u128>().ok()).flatten();
    match n {
        toml::Value::Integer(i) => Some(Price { wei: u128::try_from(*i).ok()?, per: 1 }),
        toml::Value::String(s) => match s.split_once('/') {
            None => Some(Price { wei: dec(s)?, per: 1 }),
            Some((w, p)) => {
                let per = dec(p)?;
                let t = per.to_string();
                (t.starts_with('1') && t[1..].bytes().all(|b| b == b'0')).then_some(Price { wei: dec(w)?, per })
            }
        },
        _ => None,
    }
}

/// A relay-fee call (`relay` or `uaRelay`, CTR-MTX-27) with its payer and payee as ids.
struct RelayCall {
    target: Address,
    token: Address,
    from: B256,
    payee: B256,
    value: alloy::primitives::U256,
    ua: bool,
}

fn relay_call(data: &[u8]) -> Option<RelayCall> {
    use IMtxRelayFee::{relayCall, uaRelayCall};
    if let Ok(c) = relayCall::abi_decode(data) {
        return Some(RelayCall { target: c.target, token: c.token, from: c.from.into_word(), payee: c.payee.into_word(), value: c.value, ua: false });
    }
    let c = uaRelayCall::abi_decode(data).ok()?;
    Some(RelayCall { target: c.target, token: c.token, from: c.from, payee: c.payee, value: c.value, ua: true })
}

/// NODE-LANE (CTR-MTX-27) intake of a `relay` / `uaRelay` call before any simulation: the target is the router; the fee
/// token is registered; the payee is never the executor (the router's own `_shape`, refused here before gas is spent; the
/// token's `RelayFee` struct binds the rest: from, target, callDataHash, payee, value, validUntil, relayer = the router); the
/// fee reaches this lane (open mode or bound to it) and is at least `min_amount`, else the job is refused unless
/// `relay_bound_payee` (a sponsored job). Returns the inner target, which must be bound to this chain. The gas side
/// is [`relay_fee_covers`], after the simulation.
pub fn relay_call_ok(rf: &RelayFee, lane: Address, to: Address, data: &[u8], registered: impl Fn(Address) -> bool)
    -> Result<Address, String>
{
    if to != rf.router {
        return Err(format!("CALL_TARGET_REFUSED: MtxRelayFee.relay on {to:#x}, not params.relay_fee.router"));
    }
    let c = relay_call(data).ok_or_else(|| "BAD_PAYLOAD: not a relay / uaRelay call".to_string())?;
    if !registered(c.token) {
        return Err(format!("TOKEN_NOT_SERVED: {:#x} is not a registered token of this chain", c.token));
    }
    if c.payee == rf.executor.into_word() {
        return Err("RELAY_FEE_SHAPE: the payee is the router's executor".into());
    }
    let amount = u128::try_from(c.value).unwrap_or(u128::MAX);
    crate::adapter::relay_fee_ours(c.payee == rf.router.into_word(), c.payee == lane.into_word(), amount, &rf.params)
        .map_err(|e| format!("RELAY_FEE_REFUSED: {e}"))?;
    Ok(c.target)
}

/// The fee covers the lane's known cost (owner rule: the relayer never loses): a relay fee that reaches this lane must
/// be worth, at the token's `relay_fee.min_wei_value`, at least [`relay_quote`] of the simulated call. A UA payer's
/// verify costs what its kind costs (a P-256 passkey cap 0.4 M gas, a Solidity PQ verify 1.4–6 M), so a `uaRelay` whose
/// token has no price is refused; an address payer's `relay` keeps T17's `min_amount` rule (owner ruling 2026-10-28,
/// item 7) unless its token has a price. A sponsored fee (bound elsewhere, `relay_bound_payee`) is not priced. Any other
/// call passes.
pub fn relay_fee_covers(rf: &RelayFee, lane: Address, data: &[u8], gas: u64, ceiling: u128, l1_fee: u128) -> Result<(), Refusal> {
    let Some((c, price)) = relay_price(rf, lane, data)? else { return Ok(()) };
    let quote = relay_quote(gas, ceiling, l1_fee);
    let amount = u128::try_from(c.value).unwrap_or(u128::MAX);
    if !price_covers(&price, amount, quote) {
        // the quote follows the fees of the moment (review minor 3): a retry, never a kill
        return Err(Refusal::Transport(format!("RELAY_FEE_REFUSED: fee {amount} x min_wei_value {}/{} wei is below the quote \
            {quote} wei (gas limit {gas} x fee ceiling {ceiling} + {FEE_HEADROOM} x L1 fee {l1_fee})", price.wei, price.per)));
    }
    Ok(())
}

/// The relay-fee call and its token's price when the job is priced (the fee reaches this lane); `None` when it is not
/// (not a relay-fee call, a sponsored fee, an address payer on an unpriced token); a UA payer on an unpriced token is
/// refused.
fn relay_price(rf: &RelayFee, lane: Address, data: &[u8]) -> Result<Option<(RelayCall, Price)>, Refusal> {
    let Some(c) = relay_call(data) else { return Ok(None) };
    if c.payee != rf.router.into_word() && c.payee != lane.into_word() {
        return Ok(None);
    }
    match rf.min_wei_value.get(&c.token).copied() {
        Some(p) => Ok(Some((c, p))),
        None if c.ua => Err(Refusal::Policy(format!("RELAY_FEE_REFUSED: params.relay_fee.min_wei_value has no price for token \
            {:#x} (a UA payer's verify gas depends on its kind)", c.token))),
        None => Ok(None),
    }
}

/// Fix 1 (review I1): a priced relay-fee job's fee ceiling is `FEE_HEADROOM` x the max fee per gas of its first send.
pub const FEE_HEADROOM: u128 = 2;

/// The OP-stack `GasPriceOracle` predeploy.
pub const GAS_PRICE_ORACLE: Address = alloy::primitives::address!("420000000000000000000000000000000000000F");

pub fn fee_ceiling(max_fee: u128) -> u128 {
    max_fee.saturating_mul(FEE_HEADROOM)
}

/// The lane's cost of a relay-fee job at most: its gas limit × its fee ceiling, plus `FEE_HEADROOM` × the L1 data fee
/// of an OP-stack chain (0 elsewhere; the L1 base fee moves as the L2 one does).
pub fn relay_quote(gas: u64, ceiling: u128, l1_fee: u128) -> u128 {
    u128::from(gas).saturating_mul(ceiling).saturating_add(l1_fee.saturating_mul(FEE_HEADROOM))
}

/// `relay_fee.min_wei_value`: `wei` per `per` base units (`per` a power of ten).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Price {
    pub wei: u128,
    pub per: u128,
}

/// `floor(amount × wei / per) >= quote`, exact (`amount × wei >= quote × per` in 256 bits).
pub fn price_covers(p: &Price, amount: u128, quote: u128) -> bool {
    use alloy::primitives::U256;
    U256::from(amount) * U256::from(p.wei) >= U256::from(quote) * U256::from(p.per)
}

/// The in-flight hold key of subject `id` on `token` (review I2).
pub fn subject_key(token: Address, id: B256) -> B256 {
    alloy::primitives::keccak256([&b"scaas.node.subject"[..], token.as_slice(), id.as_slice()].concat())
}

/// The gas limit of a simulated estimate (regular + state): +20 %, at least `floor` (`erc1271_floor` for a contract signer),
/// at most `cap` ([`total_cap`]). Above 2^24 is fine under Amsterdam: the chain gives execution at most 2^24 of it and
/// the rest is the state-gas reservoir (EIP-8037).
pub fn gas_limit(estimate: u64, floor: u64, cap: u64) -> u64 {
    estimate.saturating_add(estimate / 5).max(floor).min(cap)
}

/// `mtxSettle` returned `ok` for every settlement it was given.
pub fn settled_all(ret: &[u8]) -> bool {
    <Vec<bool> as SolValue>::abi_decode(ret).is_ok_and(|v| !v.is_empty() && v.iter().all(|x| *x))
}

/// A failed plan's revert data that means "out of gas": empty, or an `InteractionFailed` whose inner reason is empty
/// (an interaction that ran out of gas inside a later batch plan surfaces wrapped, not as an empty revert).
pub fn reason_is_out_of_gas(data: &[u8]) -> bool {
    use crate::abi::ISCaaSDex::InteractionFailed;
    data.is_empty() || <InteractionFailed as alloy::sol_types::SolError>::abi_decode(data).is_ok_and(|e| e.reason.is_empty())
}

/// The next gas to try for `mtxSettle`: ×1.5, capped at `max`; `None` once at the cap.
pub fn next_gas(g: u64, max: u64) -> Option<u64> {
    (g < max).then(|| g.saturating_add(g / 2).min(max))
}

/// `mtxInvalidateNonces` (token or DEX) whose simulation says the lane is already at or past the asked minimum
/// (`MinNonceNotIncreasing`): what it was sent for already holds, so the job is done, never dead (MT-8).
pub fn already_invalidated(data: &[u8], reason: &str) -> bool {
    let sel = data.get(..4);
    (sel == Some(&SEL_MTX_INVALIDATE_NONCES[..]) || sel == Some(&SEL_UA_INVALIDATE_NONCES[..])) && reason.starts_with("MinNonceNotIncreasing(")
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

/// The chain reads behind the rules, cached: implementations are immutable, so a contract's `chainUid()` never changes
/// (a contract that is not bound yet is asked again).
pub struct Guard {
    pub tokens: Arc<RwLock<Vec<Address>>>,
    relay_fee: Option<RelayFee>,
    max_pay_meta_bytes: usize,
    token_factory: Option<Address>,
    account_factory: Option<Address>,
    ua_registry: Option<Address>,
    dexes: Vec<Address>,
    bound: Mutex<HashSet<Address>>,
    /// Tokens whose UA ledger is on (`registry() ≠ 0`).
    ua_ledger: Mutex<HashSet<Address>>,
    /// `params.l1_fee = "op-stack"`: relay-fee quotes add `GasPriceOracle.getL1Fee`.
    op_stack: bool,
}

impl Guard {
    pub fn new(cfg: &ChainCfg, tokens: Arc<RwLock<Vec<Address>>>) -> anyhow::Result<Self> {
        Ok(Self {
            relay_fee: RelayFee::from_cfg(cfg)?,
            max_pay_meta_bytes: cfg.relay_params()?.max_pay_meta_bytes,
            tokens,
            token_factory: cfg.token_factory,
            account_factory: cfg.account_factory,
            ua_registry: cfg.ua_registry,
            dexes: cfg.dex.into_iter().collect(),
            bound: Default::default(),
            ua_ledger: Default::default(),
            op_stack: match cfg.params.get("l1_fee") {
                None => false,
                Some(v) if v.as_str() == Some("op-stack") => true,
                Some(v) => anyhow::bail!("params.l1_fee must be \"op-stack\" (the chain charges an OP-stack L1 data fee), not {v}"),
            },
        })
    }

    /// The chain's `MtxRelayFee` router (`params.relay_fee.router`), if any.
    pub fn router(&self) -> Option<Address> {
        self.relay_fee.as_ref().map(|r| r.router)
    }

    /// A token of the chain's registered list (refreshed from the client, review T4 m1); an unreadable list is none.
    fn registered(&self, a: Address) -> bool {
        self.tokens.read().is_ok_and(|t| t.contains(&a))
    }

    pub async fn check(&self, chain: &Chain, w: &Work) -> Result<(), Refusal> {
        if w.entry {
            self.check_named(chain, w).await?;
        } else if let Some(r) = &w.meta {
            self.check_transfer(chain, w, r.ua).await?;
        } else {
            return Err(Refusal::Policy("CALL_TARGET_REFUSED: not a named entry".into()));
        }
        self.check_signature(chain, w).await
    }

    fn not_served(to: Address) -> Refusal {
        Refusal::Policy(format!("TOKEN_NOT_SERVED: {to:#x} is not a registered token of this chain"))
    }

    /// CTR-MTX-27: never pay the router or its executor outside a relay (the coins would sit where any relay can move
    /// them, or nowhere).
    fn check_payee(&self, payee: Option<B256>) -> Result<(), Refusal> {
        if let (Some(to), Some(rf)) = (payee, &self.relay_fee) {
            if to == rf.router.into_word() || to == rf.executor.into_word() {
                return Err(Refusal::Policy(format!("PAYEE_REFUSED: a plain pay to the relay-fee router / executor {to:#x}")));
            }
        }
        Ok(())
    }

    /// A transfer struct (review T4 I1): a registered token; a UA one needs the token's UA ledger on.
    async fn check_transfer(&self, chain: &Chain, w: &Work, ua: bool) -> Result<(), Refusal> {
        if !self.registered(w.to) {
            return Err(Self::not_served(w.to));
        }
        let (payee, pay_meta) = if ua {
            (match UaMtx::from_calldata(&w.data) { Some((UaMtx::Transfer(t), _)) => Some(t.to), _ => None },
             IUALedger::uaPayMetaCall::abi_decode(&w.data).ok().map(|c| c.meta.len()))
        } else {
            (match Mtx::from_calldata(&w.data) { Some((Mtx::Transfer(t), _)) => Some(t.to.into_word()), _ => None },
             IToken::mtxPayMetaCall::abi_decode(&w.data).ok().map(|c| c.meta.len()))
        };
        if payee.is_none() {
            return Err(Refusal::Policy("CALL_TARGET_REFUSED: not a transfer".into()));
        }
        self.check_payee(payee)?;
        if let Some(n) = pay_meta.filter(|n| *n > self.max_pay_meta_bytes) {
            return Err(Refusal::Policy(format!("PAY_META_TOO_LONG: meta is {n} B, above max_pay_meta_bytes {}", self.max_pay_meta_bytes)));
        }
        self.require_bound(chain, w.to).await?;
        if ua {
            // no published UA allowlist to read: the UA path's fee class and kind are the simulation's
            return self.require_ua_ledger(chain, w.to).await;
        }
        Ok(())
    }

    /// The allow-list: the selector is a row on the contract kind the op names, the target meets that kind's rule.
    async fn check_named(&self, chain: &Chain, w: &Work) -> Result<(), Refusal> {
        let sel: [u8; 4] = match w.data.get(..4) {
            Some(s) => s.try_into().expect("4 bytes"),
            None => return Err(Refusal::Policy("CALL_TARGET_REFUSED: no selector".into())),
        };
        let contract = w.typed.as_ref().map_or("", |t| t.contract);
        let refused = |what: String| Refusal::Policy(format!("CALL_TARGET_REFUSED: {what}"));
        let Some(row) = row(sel, contract) else {
            return Err(refused(format!("0x{} is no named entry of a {contract:?} contract", alloy::hex::encode(sel))));
        };
        if sel == IMtxRelayFee::relayCall::SELECTOR || sel == IMtxRelayFee::uaRelayCall::SELECTOR {
            let Some(rf) = &self.relay_fee else {
                return Err(refused("no params.relay_fee.router on this chain".into()));
            };
            let target = relay_call_ok(rf, chain.address(), w.to, &w.data, |a| self.registered(a)).map_err(Refusal::Policy)?;
            return self.require_bound(chain, target).await;
        }
        let Some(rule) = rule_of(contract) else { return Err(refused(format!("unknown contract kind {contract:?}"))) };
        self.check_payee(w.typed.as_ref().and_then(|t| t.payee))?;
        if rule == Rule::Token {
            if !self.registered(w.to) {
                return Err(Self::not_served(w.to));
            }
            self.require_bound(chain, w.to).await?;
            if row.ua() {
                return self.require_ua_ledger(chain, w.to).await;
            }
            return Ok(());
        }
        let facts = Facts {
            token: self.tokens.read().map(|t| t.contains(&w.to)).unwrap_or(true),
            token_factory: self.token_factory == Some(w.to),
            account_factory: self.account_factory == Some(w.to),
            dex: self.dexes.contains(&w.to),
            ua_registry: self.ua_registry == Some(w.to),
            bound: self.bound(chain, w.to).await?,
        };
        if allowed(rule, &facts) {
            Ok(())
        } else {
            Err(refused(format!("{} on {:#x}", row.entry, w.to)))
        }
    }

    /// The gateway pre-check, on every path: the local typed digest against a native signature. Recovered to the signer ⇒
    /// good. Recovered to anyone else ⇒ the signer may be a contract (ERC-1271), its simulation answers; an account without
    /// code is `BAD_SIGNATURE`, nothing simulated or sent. A signer the node cannot read (`signer` None) and any signature that
    /// is not 65 bytes are the simulation's.
    async fn check_signature(&self, chain: &Chain, w: &Work) -> Result<(), Refusal> {
        let Some(t) = &w.typed else { return Ok(()) };
        let Some((who, sig)) = &t.signer else { return Ok(()) };
        // 65 bytes only: a 64-byte Hedera account signature (HIP-632, CTR-MTX-25) is no ecrecover input; the contract judges it
        if sig.len() != 65 {
            return Ok(());
        }
        let uid = chain.uid().await.map_err(|e| Refusal::Transport(format!("chain_uid: {e:#}")))?;
        let Some(d) = t.digest_on(chain.number, uid) else { return Ok(()) };
        if typed::recovers(d, sig, *who) {
            return Ok(());
        }
        match chain.is_contract_at(*who).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(Refusal::Policy(format!("BAD_SIGNATURE: not {who:#x}'s over the typed digest {d:#x} ({} domain)", t.contract))),
            Err(e) => Err(Refusal::Transport(format!("eth_getCode: {e:#}"))),
        }
    }

    /// The subject a job can lower the balance of, as its hold key, and whether the job is a relay-fee job.
    /// A meta-transaction lowers its signer's balance on its token; a relay-fee job its payer's on the fee token. Other
    /// ways to lower it (DEX legs, `mtxWrap`, a plain ERC-20 transfer, another relayer) are the recorded residual.
    pub fn subject(&self, w: &Work) -> Option<(B256, bool)> {
        if let Some(r) = &w.meta {
            return Some((subject_key(r.token, r.from), false));
        }
        if !self.is_relay(w) {
            return None;
        }
        relay_call(&w.data).map(|c| (subject_key(c.token, c.from), true))
    }

    /// `w` is a call on this chain's relay-fee router: its fee side is [`Guard::relay_covers`].
    pub fn is_relay(&self, w: &Work) -> bool {
        self.relay_fee.as_ref().is_some_and(|rf| w.meta.is_none() && w.to == rf.router)
    }

    /// `w` is a priced relay-fee job (its fee must cover the quote); a UA payer without a price is refused.
    pub fn relay_priced(&self, lane: Address, w: &Work) -> Result<bool, Refusal> {
        match &self.relay_fee {
            Some(rf) if self.is_relay(w) => Ok(relay_price(rf, lane, &w.data)?.is_some()),
            _ => Ok(false),
        }
    }

    /// The fee side of a priced relay-fee job ([`relay_fee_covers`]) at its fee ceiling and L1 data fee.
    pub fn relay_covers(&self, lane: Address, w: &Work, gas: u64, ceiling: u128, l1_fee: u128) -> Result<(), Refusal> {
        match &self.relay_fee {
            Some(rf) if self.is_relay(w) => relay_fee_covers(rf, lane, &w.data, gas, ceiling, l1_fee),
            _ => Ok(()),
        }
    }

    /// This chain charges an OP-stack L1 data fee (`params.l1_fee = "op-stack"`).
    pub fn op_stack(&self) -> bool {
        self.op_stack
    }

    /// The L1 data fee of the signed transaction `raw` (review I3): `GasPriceOracle.getL1Fee` on an OP-stack chain, 0
    /// elsewhere. An oracle that does not answer refuses the job (its cost is unknown).
    pub async fn l1_fee(&self, chain: &Chain, raw: &[u8]) -> Result<u128, Refusal> {
        if !self.op_stack {
            return Ok(0);
        }
        match chain.call_view(GAS_PRICE_ORACLE, crate::abi::IGasPriceOracle::getL1FeeCall { _data: raw.to_vec().into() }).await {
            Ok(f) => Ok(u128::try_from(f).unwrap_or(u128::MAX)),
            Err(SimError::Revert(e)) => Err(Refusal::Policy(format!(
                "RELAY_FEE_REFUSED: an OP-stack chain whose GasPriceOracle.getL1Fee does not answer ({e}): the L1 data fee is unknown"))),
            Err(SimError::Transport(e)) => Err(Refusal::Transport(format!("getL1Fee: {e}"))),
        }
    }

    /// `ua_metatx` needs the token's UA ledger on (`registry() ≠ 0`, CTR-UA-18; job-api.md `token.features ∋ ua`);
    /// the registry is an immutable of the implementation, so a yes is cached.
    async fn require_ua_ledger(&self, chain: &Chain, to: Address) -> Result<(), Refusal> {
        if self.ua_ledger.lock().is_ok_and(|b| b.contains(&to)) {
            return Ok(());
        }
        let off = |why: String| Refusal::Policy(format!("FEATURE_UNSUPPORTED: {to:#x} has no UA ledger ({why})"));
        match chain.call_view(to, IUALedger::registryCall {}).await {
            Ok(r) if r != Address::ZERO => {
                if let Ok(mut b) = self.ua_ledger.lock() {
                    b.insert(to);
                }
                Ok(())
            }
            Ok(_) => Err(off("registry() = 0".into())),
            Err(SimError::Revert(e)) => Err(off(format!("registry(): {e}"))),
            Err(SimError::Transport(e)) => Err(Refusal::Transport(format!("registry(): {e}"))),
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
}

/// The typed digest of `w`, computed here (no chain view: only the cached `chain_uid`): the dedup key, on `w.typed`. On `w.meta`
/// the digest its `MetaTransactionExecuted` will carry: the same, but for a receiver fee, which lands as its payment.
pub async fn fill_digest(chain: &Chain, w: &mut Work) -> Result<(), SimError> {
    let Some(t) = w.typed.as_mut() else { return Ok(()) };
    if t.digest.is_some() || t.struct_hash.is_none() {
        return Ok(());
    }
    let uid = chain.uid().await.map_err(|e| SimError::Transport(format!("{e:#}")))?;
    t.digest = t.digest_on(chain.number, uid);
    if let Some(m) = &mut w.meta {
        m.digest = t.lane_digest_on(chain.number, uid);
    }
    Ok(())
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
    // ruling R-node: a relayed PQ registration that does not fit one transaction is refused with its own code
    let split = w.meta.is_none() && pq_register(&w.data);
    let refuse = |why: String| SimError::Revert(format!(
        "{UA_REGISTER_SPLIT}: {why}; send register without pqzPop, then storePqzPop"));
    let est = match chain.simulate(w.to, w.data.clone()).await {
        Err(SimError::Revert(r)) if split && r.contains("exceeds allowance") => return Err(refuse(r)),
        r => r?,
    };
    if split && est > total_cap(max, block) {
        return Err(refuse(format!("gas {est} above the transaction cap {} (max_gas_per_tx {max}, block gas limit {})",
            total_cap(max, block), block.limit)));
    }
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
    let g = if w.meta.is_none() && w.data.get(..4) == Some(&SEL_MTX_SETTLE[..]) {
        settle_gas(chain, w.to, &w.data, est, max).await?
    } else {
        let contract_signer = match &w.meta {
            // a derived UA has no code: its verify is held by the registry (`UAVerifyGas` when starved), so the
            // estimate already covers it; a native id that is a contract gets the ERC-1271 floor on either path (an
            // EIP-7702 designator is an EOA, own key only: no floor, owner ruling 2026-10-30 D1)
            Some(m) => match crate::metatx::native(&m.from) {
                Some(a) => chain.is_contract_at(a).await.map_err(|e| SimError::Transport(format!("eth_getCode: {e:#}")))?,
                None => false,
            },
            None => false,
        };
        gas_limit(est, if contract_signer { erc1271_floor(w.data.len()) } else { 0 }, max)
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
    let mut g = gas_limit(estimate, 0, max);
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

    /// The plain rows' selectors are the `cast sig` of their Solidity signatures and the sol! bindings', and the DEX KAT calldata
    /// (contract-generated) starts with them. Selectors only: same-typed arguments in the wrong order pass here; the names and
    /// order are pinned against forge's ABI by `plain_rows_match_the_forge_abi` (`tests/e2e.rs`). Every typed row is pinned by
    /// `typed_ops_kat_every_entry`.
    #[test]
    fn the_plain_rows_are_pinned() {
        use crate::abi::{IMtxRelayFee as R, ISCaaSDex as D, IUARegistry as U};
        let kat = |f: &str, k: &str| -> Vec<u8> {
            let p = format!("{}/../smartcontracts/evm/test/vectors/{f}", env!("CARGO_MANIFEST_DIR"));
            let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
            alloy::hex::decode(&v[k].as_str().unwrap()[2..]).unwrap()
        };
        let sel = |entry: &str, contract: &str| typed::rows().iter().find(|r| r.entry == entry && !r.typed && r.contracts.contains(&contract))
            .unwrap_or_else(|| panic!("{entry}")).selector;
        for (k, c) in [("settle_calldata", D::mtxSettleCall::SELECTOR), ("exchange_calldata", D::mtxExchangeCall::SELECTOR),
            ("exchange_via_calldata", D::mtxExchangeViaCall::SELECTOR), ("hybrid_calldata", D::mtxHybridCall::SELECTOR),
            ("hybrid_via_calldata", D::mtxHybridViaCall::SELECTOR), ("exchange_batch_calldata", D::mtxExchangeBatchCall::SELECTOR)] {
            assert_eq!(kat("dex_order_kat.json", k)[..4], c, "{k}");
            assert!(row(c, "dex").is_some(), "{k} is allowed");
        }
        assert_eq!(kat("dex_order_kat.json", "cancel_orders_calldata")[..4], D::mtxCancelOrdersCall::SELECTOR);
        assert_eq!(kat("dex_order_kat.json", "invalidate_calldata")[..4], SEL_MTX_INVALIDATE_NONCES);
        assert_eq!(sel("mtxSettle", "dex"), SEL_MTX_SETTLE);
        assert_eq!(sel("mtxCancelOrders", "dex"), D::mtxCancelOrdersCall::SELECTOR);
        assert_eq!(sel("mtxExchange", "dex"), D::mtxExchangeCall::SELECTOR);
        assert_eq!(sel("mtxExchangeVia", "dex"), D::mtxExchangeViaCall::SELECTOR);
        assert_eq!(sel("mtxExchangeBatch", "dex"), D::mtxExchangeBatchCall::SELECTOR);
        assert_eq!(sel("mtxHybrid", "dex"), D::mtxHybridCall::SELECTOR);
        assert_eq!(sel("mtxHybridVia", "dex"), D::mtxHybridViaCall::SELECTOR);
        assert_eq!(sel("register", "registry"), U::registerCall::SELECTOR);
        assert_eq!(sel("registerMsig", "registry"), U::registerMsigCall::SELECTOR);
        assert_eq!(sel("registerWebAuthn", "registry"), U::registerWebAuthnCall::SELECTOR);
        assert_eq!(sel("registerMuSig2", "registry"), U::registerMuSig2Call::SELECTOR);
        assert_eq!(sel("registerFrost", "registry"), U::registerFrostCall::SELECTOR);
        assert_eq!(sel("setKemKey", "registry"), U::setKemKeyCall::SELECTOR);
        assert_eq!(sel("storePqzPop", "registry"), U::storePqzPopCall::SELECTOR);
        assert_eq!(sel("setPqzKey", "registry"), U::setPqzKeyCall::SELECTOR);
        assert_eq!(sel("acceptMembership", "registry"), U::acceptMembershipCall::SELECTOR);
        let cast = |s: &str| -> [u8; 4] { alloy::primitives::keccak256(s)[..4].try_into().unwrap() };
        assert_eq!(sel("deploy", "factory"), cast("deploy((uint8,bytes32,bytes32,bytes32,bytes32),address)"));
        assert_eq!(sel("mtxExecuteAsOwner", "wallet"), cast("mtxExecuteAsOwner(bytes,uint256,uint256,bytes)"));
        assert_eq!(sel("mtxExecuteAsOwnerRaw", "wallet"), cast("mtxExecuteAsOwnerRaw(bytes,uint256,uint256,bytes)"));
        assert_eq!(sel("mtxPayUnderMandate", "wallet"), cast("mtxPayUnderMandate(address,address,uint256,bytes32,uint64,uint256,bytes)"));
        assert_eq!(sel("mtxRevoke", "wallet"), cast("mtxRevoke(address,uint64,uint256,bytes)"));
        assert_eq!(R::relayCall::SELECTOR, cast("relay(address,bytes,address,address,address,uint256,uint256,bytes)"));
        let ua_sig = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";
        assert_eq!(R::uaRelayCall::SELECTOR, cast(&format!("uaRelay(address,bytes,address,bytes32,bytes32,uint256,uint256,{ua_sig})")));
        assert_eq!(SEL_UA_INVALIDATE_NONCES, cast(&format!("uaInvalidateNonces(bytes32,uint256,uint256,{ua_sig})")));
        assert_eq!(rule_of("registry"), Some(Rule::UaRegistry));
        assert_eq!(rule_of("nothing"), None);
    }

    /// `(url, chain config, methods seen)`: an RPC answering every `eth_call` with `chain_uid` (so `chainUid()` binds and
    /// `registry()` is non-zero), every `eth_getCode` empty, no `eth_estimateGas`.
    async fn bound(uid: B256) -> (ChainCfg, Arc<Mutex<Vec<String>>>) {
        let seen: Arc<Mutex<Vec<String>>> = Default::default();
        let s2 = seen.clone();
        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<serde_json::Value>| {
            let s2 = s2.clone();
            async move {
                let m = r["method"].as_str().unwrap().to_string();
                s2.lock().unwrap().push(m.clone());
                let result = match m.as_str() {
                    "eth_call" => serde_json::json!(format!("{uid:#x}")),
                    "eth_getCode" => serde_json::json!("0x"),
                    _ => serde_json::Value::Null,
                };
                axum::Json(serde_json::json!({"jsonrpc": "2.0", "id": r["id"], "result": result}))
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (ChainCfg { evm_chain_number: 31337, rpc_urls: vec![url], chain_uid: Some(uid), ..Default::default() }, seen)
    }

    fn signer() -> alloy::signers::local::PrivateKeySigner {
        alloy::signers::local::PrivateKeySigner::random()
    }

    /// Both directions, through the guard: every entry of `typed_ops.json` (read from the file, its selector from the
    /// vector) passes on its kind's target, and is refused on a target its kind's rule excludes (a missing row breaks
    /// relaying silently); every selector outside the table is refused on every kind (an extra row opens a path).
    #[tokio::test]
    async fn guard_allows_every_named_entry_only() {
        use crate::typed::testkit::{op_of, vectors};
        let v = vectors();
        let uid: B256 = v["ops"]["Unwrap"]["domains"]["token"]["domain"]["salt"].as_str().unwrap().parse().unwrap();
        let (cfg, _) = bound(uid).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let (mut sent, mut relayed, mut refused) = (0, 0, 0);
        for (name, o) in v["ops"].as_object().unwrap() {
            for (kind, d) in o["domains"].as_object().unwrap() {
                let Some(mut op) = op_of(name, kind, &v) else {
                    relayed += usize::from(!d["abi"].is_null());
                    continue;
                };
                if name == "PayUnderMandate" || name == "DelegateRevoke" {
                    op["envelope"]["nonce"] = serde_json::json!("0");
                    op["envelope"]["batch"] = serde_json::json!(match name.as_str() {
                        "PayUnderMandate" => typed::mandate_pay_lane(&typed::testkit::hex(&op["args"]["entryRef"])),
                        _ => typed::mandate_revoke_lane(op["args"]["token"].as_str().unwrap().parse().unwrap(),
                            op["args"]["epoch"].as_str().unwrap().parse().unwrap()),
                    }.to_string());
                }
                let (mut w, _) = crate::submit::work_of_op(Some(1), &op, None).unwrap_or_else(|e| panic!("{name}: {e:#}"));
                if matches!(name.as_str(), "PayUnderMandate" | "DelegateRevoke" | "ReceiverFee" | "UAReceiverFee") {
                    w.typed.as_mut().unwrap().signer = None; // the vector's lane 7, its one key for payer and payee
                }
                assert_eq!(format!("0x{}", alloy::hex::encode(&w.data[..4])), d["selector"].as_str().unwrap(), "{name}");
                let listed = ChainCfg { dex: (kind == "dex").then_some(w.to), ..cfg.clone() };
                let right = Guard::new(&listed, Arc::new(RwLock::new(
                    if rule_of(kind) == Some(Rule::Token) { vec![w.to] } else { vec![] }))).unwrap();
                right.check(&chain, &w).await.unwrap_or_else(|e| panic!("{name} on {kind} is a missing row: {e:?}"));
                sent += 1;
                // the kind's rule excludes the other target: a token entry on an unregistered contract, a wallet's on a
                // registered token, a DEX entry on an unlisted address
                let wrong = Guard::new(&cfg, Arc::new(RwLock::new(
                    if rule_of(kind) == Some(Rule::Token) { vec![] } else { vec![w.to] }))).unwrap();
                let e = wrong.check(&chain, &w).await.unwrap_err();
                assert!(matches!(&e, Refusal::Policy(r) if r.starts_with("TOKEN_NOT_SERVED") || r.starts_with("CALL_TARGET_REFUSED")), "{name} on {kind}: {e:?}");
                refused += 1;
            }
        }
        assert_eq!((sent, relayed, refused), (123, 6, 123), "the walk reached every row with an entry; the relay fees: submit.rs");
        assert_eq!(typed::rows().iter().filter(|r| !r.entry.is_empty()).count(), 97, "table rows");
        // the wallet's flat builders (owner 2026-11-01): allowed on a bound contract, never on a registered token
        let wallet = Guard::new(&cfg, Default::default()).unwrap();
        let token = Guard::new(&cfg, Arc::new(RwLock::new(vec![Address::repeat_byte(0x77)]))).unwrap();
        let (a, s) = (format!("{:#x}", Address::repeat_byte(0x77)), format!("0x{}", "11".repeat(65)));
        for op in [serde_json::json!({"entry": "mtxPayUnderMandate", "struct": "mtxPayUnderMandate", "token": a, "args": {"token": a, "payee": a, "amount": "5",
                "entryRef": format!("{:#x}", B256::repeat_byte(1)), "epoch": "2", "validUntil": "1800000300", "sig": s}}),
            serde_json::json!({"entry": "mtxRevoke", "token": a, "args": {"token": a, "epoch": "2", "validUntil": "1800000300", "sig": s}})] {
            let (w, _) = crate::submit::work_of_op(Some(1), &op, None).unwrap();
            wallet.check(&chain, &w).await.unwrap();
            assert!(matches!(token.check(&chain, &w).await, Err(Refusal::Policy(r)) if r.starts_with("CALL_TARGET_REFUSED")));
        }
        // selectors with no row: refused on every kind, on a target that would otherwise pass
        let target = Address::repeat_byte(0x31);
        let g = Guard::new(&ChainCfg { dex: Some(target), ..cfg.clone() }, Arc::new(RwLock::new(vec![target]))).unwrap();
        let cast = |s: &str| -> Vec<u8> { alloy::primitives::keccak256(s)[..4].to_vec() };
        for s in ["transfer(address,uint256)", "approve(address,uint256)", "transferFrom(address,address,uint256)",
            "mint(address,uint256)", "cancelNonce(uint256)",
            "mtxExecute((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)",
            "mtxBatch((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address)[],bytes[])",
            "mtxTrade((address,address,uint256,uint256,uint256,uint256,address,address,address,uint8,uint256,uint256,uint256),bytes,(uint256,uint256,uint256,address))",
            "mtxWrap(address,(address,address,uint256,uint256,uint256,uint256,address,address,address,uint8,uint256,uint256,uint256),bytes)",
            "mtxRelayFee(address,address,bytes32,address,uint256,uint256,bytes)",
            "uaRelayFee(bytes32,address,bytes32,bytes32,uint256,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))"] {
            for kind in ["token", "zether", "pqz", "wallet", "account", "dex", "registry", "factory"] {
                let t = typed::Typed { contract: kind, domain_of: target, struct_hash: None, lane_hash: None, signer: None, payee: None, digest: None };
                let w = Work { job_id: Some(1), to: target, data: cast(s).into(), valid_until: 0, meta: None, entry: true, typed: Some(t) };
                let e = g.check(&chain, &w).await.unwrap_err();
                assert!(matches!(&e, Refusal::Policy(r) if r.starts_with("CALL_TARGET_REFUSED")), "{s} on {kind}: {e:?}");
            }
        }
    }

    /// Item of the lane, not of `Typed`: after `fill_digest` a receiver fee is keyed by its outer digest and `classify` compares
    /// the payment's, what the chain emits; an ordinary op has one digest for both.
    #[tokio::test]
    async fn fill_digest_keeps_the_key_and_what_the_chain_emits_apart() {
        use crate::typed::testkit::{op_of, vectors};
        let v = vectors();
        let d = &v["ops"]["ReceiverFee"]["domains"]["token"];
        let uid: B256 = d["domain"]["salt"].as_str().unwrap().parse().unwrap();
        let (cfg, _) = bound(uid).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let (mut w, _) = crate::submit::work_of_op(Some(1), &op_of("ReceiverFee", "token", &v).unwrap(), None).unwrap();
        fill_digest(&chain, &mut w).await.unwrap();
        let t = w.typed.clone().unwrap();
        assert_eq!(format!("{:#x}", w.digest().unwrap()), d["digest"].as_str().unwrap(), "the in-flight key: the vector's outer digest");
        assert_eq!(w.meta.unwrap().digest, t.lane_digest_on(31337, uid), "the job compares the payment's");
        assert_ne!(w.meta.unwrap().digest, w.digest());
        let (mut w, _) = crate::submit::work_of_op(Some(1), &op_of("Unwrap", "token", &v).unwrap(), None).unwrap();
        fill_digest(&chain, &mut w).await.unwrap();
        assert_eq!(w.meta.unwrap().digest, w.digest());
    }

    /// A 64-byte Hedera signature (HIP-632, CTR-MTX-25) on a codeless account is the contract's to judge; the same account with a
    /// wrong 65-byte one is `BAD_SIGNATURE` (the control), and no code is read for the 64 bytes.
    #[tokio::test]
    async fn a_signature_that_is_not_65_bytes_is_the_contracts() {
        let uid = B256::repeat_byte(0x24);
        let (cfg, seen) = bound(uid).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let token = Address::repeat_byte(0x31);
        let g = Guard::new(&cfg, Arc::new(RwLock::new(vec![token]))).unwrap();
        let t = crate::metatx::MetaTransfer { from: Address::repeat_byte(1), to: Address::repeat_byte(2), value: alloy::primitives::U256::from(1),
            entryRef: B256::ZERO, batch: alloy::primitives::U256::ZERO, nonce: alloy::primitives::U256::ZERO,
            validUntil: alloy::primitives::U256::from(4_000_000_000u64), mode: 0, relayer: Address::ZERO, fee: alloy::primitives::U256::ZERO, feeRecipient: Address::ZERO };
        let m = Mtx::Transfer(t);
        let work = |sig: Vec<u8>| Work { job_id: Some(1), to: token, data: m.calldata(sig.clone().into()), valid_until: 4_000_000_000,
            meta: Some(crate::submit::MetaRef::of(token, &m, None)), entry: false,
            typed: Some(crate::submit::transfer_typed(None, token, m.struct_hash(), Some((m.from(), sig.into()))).unwrap()) };
        g.check(&chain, &work(vec![0xab; 64])).await.unwrap();
        assert!(seen.lock().unwrap().iter().all(|c| c != "eth_getCode"), "64 bytes: not even a code read");
        let e = g.check(&chain, &work(vec![0xab; 65])).await.unwrap_err();
        assert!(matches!(&e, Refusal::Policy(r) if r.starts_with("BAD_SIGNATURE")), "{e:?}");
    }

    /// A job that is neither a named entry nor a transfer never runs; a transfer struct's selector is the transfer's.
    #[tokio::test]
    async fn work_without_a_row_is_refused_before_any_chain_read() {
        let cfg = ChainCfg { evm_chain_number: 7, rpc_urls: vec!["http://127.0.0.1:9".into()], ..Default::default() };
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let g = Guard::new(&cfg, Default::default()).unwrap();
        let w = |data: Vec<u8>, entry: bool| Work { job_id: Some(1), to: Address::repeat_byte(1), data: data.into(), valid_until: 0, meta: None, entry, typed: None };
        let transfer = IToken::transferCall { to: Address::repeat_byte(2), value: alloy::primitives::U256::from(1) }.abi_encode();
        assert!(matches!(g.check(&chain, &w(transfer.clone(), true)).await, Err(Refusal::Policy(r)) if r.starts_with("CALL_TARGET_REFUSED")));
        assert!(matches!(g.check(&chain, &w(transfer, false)).await, Err(Refusal::Policy(r)) if r.starts_with("CALL_TARGET_REFUSED")));
        assert!(matches!(g.check(&chain, &w(vec![], true)).await, Err(Refusal::Policy(_))));
    }

    #[test]
    fn each_rule_needs_its_target() {
        let bound = Facts { bound: true, ..Default::default() };
        assert!(allowed(Rule::Token, &Facts { token: true, ..bound }));
        assert!(!allowed(Rule::Token, &bound), "only a registered token");
        assert!(!allowed(Rule::Token, &Facts { token: true, bound: false, ..bound }), "NODE-GW-07");
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
        assert!(!allowed(Rule::UaRegistry, &bound), "only the configured registry");
        assert!(allowed(Rule::UaRegistry, &Facts { ua_registry: true, ..bound }));
        assert!(!allowed(Rule::UaRegistry, &Facts { ua_registry: true, bound: false, ..bound }), "NODE-GW-07");
        assert!(!allowed(Rule::UaRegistry, &Facts { ua_registry: true, token: true, ..bound }));
    }

    /// Spec §9 / R8 (T17 fix 1): the floor covers forge's measured minimum relayer call gas of a `SmartKeyAccount`-signed
    /// `mtxExecute` (two frames above the ERC-1271 call), the intrinsic 21,000, the job's calldata at 64 gas a byte and
    /// a 10 % margin.
    #[test]
    fn erc1271_floor_covers_forge_minimum() {
        let log = std::fs::read_to_string(format!(
            "{}/../smartcontracts/evm/runs/2026-10-27-metatx-split-node-floor.txt", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let tag = "min gas, SmartKeyAccount-signed mtxExecute (relayer's call gas):";
        let measured: u64 = log.lines().find_map(|l| l.trim().strip_prefix(tag)).unwrap().trim().parse().unwrap();
        assert_eq!(measured, ERC1271_CALL_GAS, "Task 8's figure");
        const { assert!(ERC1271_CALL_GAS >= (400_000 * 64 / 63 + 5_000) * 64 / 63, "two frames above the 400 k cap") };
        for len in [0usize, 708, 4_000] {
            let f = erc1271_floor(len);
            assert!(f >= 21_000 + 64 * len as u64 + measured + measured / 10, "{len}: {f}");
        }
        assert_eq!(erc1271_floor(0), 512_594);
        assert_eq!(erc1271_floor(708), 512_594 + 45_312);
    }

    #[test]
    fn gas_floor_and_settle_sizing() {
        let fl = erc1271_floor(100);
        let ams = |limit| BlockGas { limit, amsterdam: true };
        let cap = total_cap(u64::MAX, ams(200_000_000));
        assert_eq!(gas_limit(100_000, 0, cap), 120_000);
        assert_eq!(gas_limit(100_000, fl, cap), fl);
        assert_eq!(gas_limit(1_000_000, fl, cap), 1_200_000);
        assert_eq!(gas_limit(MAX_TX_GAS, 0, cap), MAX_TX_GAS + MAX_TX_GAS / 5, "Amsterdam: a limit past 2^24 is kept");
        assert_eq!(gas_limit(190_000_000, 0, cap), 200_000_000, "the padded estimate is clamped to the cap");
        assert_eq!(gas_limit(u64::MAX, fl, total_cap(u64::MAX, ams(u64::MAX))), MAX_TX_TOTAL_GAS, "EIP-8037: 2^32 - 1");
        assert_eq!(total_cap(50_000_000, ams(30_000_000)), 30_000_000, "the block gas limit binds");
        assert_eq!(total_cap(50_000_000, ams(200_000_000)), 50_000_000, "max_gas_per_tx binds");
        let osaka = BlockGas { limit: 200_000_000, amsterdam: false };
        assert_eq!(total_cap(50_000_000, osaka), MAX_TX_GAS, "before Amsterdam the whole limit stays under 2^24");
        assert_eq!(gas_limit(MAX_TX_GAS, 0, total_cap(u64::MAX, osaka)), MAX_TX_GAS);
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

    #[test]
    fn a_wrapped_empty_interaction_revert_is_out_of_gas() {
        use crate::abi::ISCaaSDex::InteractionFailed;
        let e = |r: &[u8]| InteractionFailed { index: alloy::primitives::U256::from(1), target: Address::repeat_byte(7), reason: r.to_vec().into() }.abi_encode();
        assert!(reason_is_out_of_gas(&[]));
        assert!(reason_is_out_of_gas(&e(&[])));
        assert!(!reason_is_out_of_gas(&e(&[1, 2])));
        assert!(!reason_is_out_of_gas(&[1, 2, 3]));
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
        assert!(already_invalidated(&[&SEL_UA_INVALIDATE_NONCES[..], &[0u8; 128]].concat(), &reason));
        assert!(!already_invalidated(&[&[0x93, 0xcb, 0x3e, 0x81][..], &[0u8; 128]].concat(), &reason));
        assert!(!already_invalidated(&inv, "MinNonceAboveCap(MinNonceAboveCap { requested: 1 })"));
    }
}
