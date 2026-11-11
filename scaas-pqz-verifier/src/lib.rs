// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `scaas-pqz-verifier`: the reference PQZ verifier (off-chain) of the PQZ verifier mode (3f spec §11.2). **UNAUDITED.**
//!
//! A separately operated trust role: a token in `OFFCHAIN` mode names this verifier's UA, and the verifier signs a
//! `PqzVerdict` (spec §5) for a proof only when pqz-ffi, byte for byte the precompile, answers `…01` on the statement the
//! token's own view rebuilds from state, and every key that statement names passes spec §6 (3g KV-12). It verifies
//! public bytes only and decrypts nothing (ARCH-POS-13). A refusal is a named error, never a signature.

pub mod abi;
pub mod chain;
pub mod http;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::hex;
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::{Eip712Domain, SolCall, SolStruct, SolValue};
use pqz_ffi::stmt::{self, Form};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use abi::{IPqzToken, IUARegistry, PqzBurnArgs, PqzMultiArgs, PqzTransferArgs, PqzVerdict, Unwrap};
use chain::{Chain, ChainError};

pub use pqz_ffi::{Word, INVALID, VALID};

/// pqz-ffi's verdict on a precompile input `u8(op) ‖ be32(len) ‖ statement ‖ proof`; in production `pqz_ffi::precompile`.
pub type Pqz = Arc<dyn Fn(&[u8]) -> Result<Word, pqz_ffi::Error> + Send + Sync>;

/// The probe's statement (spec §4.2, the typo guard before a verifier transfer): no token builds these bytes, so its
/// verdict fits no operation.
pub const PROBE_STATEMENT: &[u8] = b"SCAAS-PQZ-VERIFIER-PROBE-V1";
/// JSON nesting allowed below the request object: `op` → `args` → `legs` → a leg.
pub const MAX_DEPTH: usize = 4;
const PQZ_MLWE: u16 = 0x0142;
const OFFCHAIN: u8 = 1;
const HEADER: usize = stmt::HEADER_BYTES;
const PK: usize = stmt::PK_BYTES;
/// The verified-key cache's bound; full, it starts over (the ownership record is kept).
const CACHE_MAX: usize = 1 << 16;
/// The 45-byte EIP-1167 proxy around the release address that heads every factory instance's code (`ChainEnvCode`).
const PROXY_HEAD: [u8; 10] = hex!("363d3d373d3d3d363d73");
const PROXY_TAIL: [u8; 15] = hex!("5af43d82803e903d91602b57fd5bf3");

/// `PURPOSE_PQZ_VERDICT` (`UAKinds`).
pub fn purpose_pqz_verdict() -> B256 {
    keccak256("scaas.ua.purpose.pqz-verdict.v1")
}

/// `keyHashOf(0x0142, key)` (`UAKinds`): `keccak256(groupTag("pqz-mlwe") ‖ key)`.
pub fn pqz_key_hash(key: &[u8]) -> B256 {
    keccak256([keccak256("scaas.ua.group.pqz-mlwe.v1").as_slice(), key].concat())
}

/// Every statement length of this build's set that a token builds (its `STMT_*`: op 1 with and without the auditor,
/// burn / refresh, the disclosures, op 7 at every built `(M, auditorOn)`); `R_REG`'s is no token's.
pub fn statement_lengths() -> Vec<usize> {
    let mut v = vec![Form::Transfer.stmt_len(), Form::Transfer0.stmt_len(), Form::Burn.stmt_len(), Form::DiscloseSender.stmt_len()];
    for &m in stmt::built_legs(&stmt::PQZL_ID) {
        v.extend([stmt::multi_len(m, false), stmt::multi_len(m, true)]);
    }
    v
}

/// The request body limit (spec §11.2), set from this build's set: the largest statement and `MAX_PROOF` (PQZL), doubled
/// for hex, plus 4 KiB; `op.args` carries the operation's ciphertext parts once more (at most a statement's bytes), so
/// the statement counts twice.
pub fn body_limit() -> usize {
    2 * (2 * statement_lengths().into_iter().max().unwrap_or(0) + stmt::MAX_PROOF_PQZL) + 4096
}

/// The service's own configuration (`pqz-verifier.example.toml`); no secret in it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    pub rpc_url: String,
    pub keystore: PathBuf,
    /// the name of the environment variable that holds the keystore's password
    pub keystore_password_env: String,
    pub valid_minutes: u64,
    pub concurrency: usize,
    pub queue: usize,
    pub rate_per_minute: u32,
    /// release (implementation) address → parameter set
    pub releases: BTreeMap<Address, String>,
}

impl Config {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let c: Self = toml::from_str(s)?;
        anyhow::ensure!(!c.releases.is_empty(), "no release configured");
        for (a, set) in &c.releases {
            anyhow::ensure!(set == stmt::SET, "release {a}: set {set}; this build verifies {} only", stmt::SET);
        }
        anyhow::ensure!((1..=60).contains(&c.valid_minutes), "valid_minutes: 1..=60");
        anyhow::ensure!(c.concurrency >= 1 && c.queue >= c.concurrency, "need 1 <= concurrency <= queue");
        anyhow::ensure!(c.rate_per_minute >= 1, "rate_per_minute: at least 1");
        Ok(c)
    }
}

/// A named refusal (the HTTP status follows from `error`, `http.rs`).
#[derive(Debug, Serialize)]
pub struct Refusal {
    pub error: &'static str,
    pub detail: String,
}

pub fn refuse(error: &'static str, detail: impl Into<String>) -> Refusal {
    Refusal { error, detail: detail.into() }
}

/// `POST /v1/pqz-verdict`: named fields only.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VerdictRequest {
    pub token: Address,
    pub chain_id: u64,
    pub op: Op,
    pub statement: Bytes,
    pub proof: Bytes,
    pub pqz_verifier_epoch: u32,
}

/// The operation as its named fields: `entry` one of the proof-carrying entries (a direct call and its signed
/// `UAEnvelope` form share the name; `binding` 0 = direct, else the envelope's binding) or `verifyTransferAmount`;
/// `args` the entry's argument struct; `amount` and `recipient` for `mtxUnshield`, `unwrap` for `mtxUnshieldUnwrap`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Op {
    pub entry: String,
    pub args: serde_json::Value,
    #[serde(default)]
    pub binding: B256,
    pub amount: Option<U256>,
    pub recipient: Option<B256>,
    pub unwrap: Option<Unwrap>,
}

/// `verifyTransferAmount`'s statement arguments (`disclosureStatement`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DisclosureArgs {
    pub entry_ref: B256,
    pub leg: U256,
    pub amount: U256,
    pub kind: u8,
    pub key_version: u64,
}

/// `POST /v1/pqz-verdict/probe`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProbeRequest {
    pub token: Address,
    pub chain_id: u64,
}

/// The answer: the verdict and the verifier's `UASig` (a native EOA: `signature` only).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Signed {
    pub pqz_verdict: PqzVerdict,
    pub pqz_verdict_sig: WireSig,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireSig {
    pub key_data: Bytes,
    pub signature: Bytes,
    pub members: Vec<serde_json::Value>,
}

/// The `PqzVerdict` digest in the token's own domain (`"SCaaS PqzToken"`, `"1"`, chainId, the token, salt `chainUid`).
pub fn verdict_digest(v: &PqzVerdict, chain_uid: B256) -> B256 {
    let d = Eip712Domain::new(Some("SCaaS PqzToken".into()), Some("1".into()), Some(v.chainId), Some(v.token), Some(chain_uid));
    v.eip712_signing_hash(&d)
}

enum Plan {
    Multi(PqzMultiArgs),
    Single(PqzTransferArgs),
    Burn(PqzBurnArgs, U256, B256),
    Unwrap(PqzBurnArgs, Unwrap),
    Disclose(DisclosureArgs),
}

fn args<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> Result<T, Refusal> {
    serde_json::from_value(v).map_err(|e| refuse("BAD_REQUEST", format!("op.args: {e}")))
}

fn fields(entry: &str, ok: bool) -> Result<(), Refusal> {
    if ok { Ok(()) } else { Err(refuse("BAD_REQUEST", format!("op: not the fields of {entry}"))) }
}

impl Plan {
    fn of(op: Op) -> Result<(Self, B256), Refusal> {
        let Op { entry, args: a, binding, amount, recipient, unwrap } = op;
        let e = entry.as_str();
        let plain = amount.is_none() && recipient.is_none() && unwrap.is_none();
        let plan = match e {
            "mtxConfidentialTransfer" | "mtxConfidentialTransferCompact" => {
                fields(e, plain)?;
                Plan::Multi(args(a)?)
            }
            "mtxConfidentialTransferSingle" | "mtxConfidentialTransferSingleCompact" => {
                fields(e, plain)?;
                Plan::Single(args(a)?)
            }
            "mtxUnshield" => match (amount, recipient, unwrap) {
                (Some(m), Some(r), None) => Plan::Burn(args(a)?, m, r),
                _ => return Err(fields(e, false).unwrap_err()),
            },
            "mtxUnshieldUnwrap" => match (amount, recipient, unwrap) {
                (None, None, Some(x)) => Plan::Unwrap(args(a)?, x),
                _ => return Err(fields(e, false).unwrap_err()),
            },
            "verifyTransferAmount" => {
                fields(e, plain && binding.is_zero())?;
                Plan::Disclose(args(a)?)
            }
            _ => return Err(refuse("UNKNOWN_ENTRY", e)),
        };
        Ok((plan, binding))
    }

    /// The precompile op of the statement.
    fn op(&self) -> u8 {
        match self {
            Plan::Multi(_) => stmt::OP_TRANSFER_MULTI,
            Plan::Single(_) => stmt::OP_TRANSFER,
            Plan::Burn(..) | Plan::Unwrap(..) => stmt::OP_BURN,
            Plan::Disclose(d) if d.kind == 0 => stmt::OP_DISCLOSE_SENDER,
            Plan::Disclose(_) => stmt::OP_DISCLOSE_RECEIVER,
        }
    }

    /// The token's statement view for this operation.
    fn view(&self, binding: B256) -> Vec<u8> {
        match self {
            Plan::Multi(t) => IPqzToken::transferStatementCall { t: t.clone(), binding }.abi_encode(),
            Plan::Single(t) => IPqzToken::transferSingleStatementCall { t: t.clone(), binding }.abi_encode(),
            Plan::Burn(b, amount, recipient) => {
                IPqzToken::burnStatementCall { b: b.clone(), amount: *amount, recipient: *recipient, binding }.abi_encode()
            }
            Plan::Unwrap(b, x) => IPqzToken::unshieldUnwrapStatementCall { b: b.clone(), x: x.clone(), binding }.abi_encode(),
            Plan::Disclose(d) => IPqzToken::disclosureStatementCall {
                entryRef: d.entry_ref,
                leg: d.leg,
                amount: d.amount,
                kind: d.kind,
                keyVersion: d.key_version,
            }
            .abi_encode(),
        }
    }
}

/// A factory instance: its registry and `chainUid` from its code (`ChainEnvCode`).
struct Token {
    at: Address,
    registry: Address,
    chain_uid: B256,
}

#[derive(Default)]
struct Keys {
    /// `(ua, version, pqzKeyHash)` that passed spec §6 (3g KV-12: never keyed by `ua` alone)
    ok: HashSet<(B256, u64, B256)>,
    /// `pqzKeyHash` → the one `(ua, version)` this verifier accepted it for (single ownership across UAs and versions)
    owner: HashMap<B256, (B256, u64)>,
}

pub struct Service {
    chain: Arc<dyn Chain>,
    pqz: Pqz,
    signer: PrivateKeySigner,
    ua: B256,
    chain_id: u64,
    releases: HashSet<Address>,
    valid_secs: u64,
    work: Semaphore,
    keys: Mutex<Keys>,
}

fn chain_refusal(what: &str, e: ChainError) -> Refusal {
    match e {
        ChainError::Revert(d) => refuse("CHAIN_READ_REVERTED", format!("{what}: {d}")),
        ChainError::Rpc(m) => refuse("RPC_UNAVAILABLE", format!("{what}: {m}")),
    }
}

/// The owner of leg `leg` of an op blob `R ‖ v_f` (`PqzCore._legOf` / `_bundleShape`; the bundle packed at
/// `PACK_BITS` = q's bit length): `R = salt ‖ u_0 … u_{G−1} ‖ (v_j ‖ [v_{a,j}] ‖ UA_j)_{j<M}`.
fn leg_owner(blob: &[u8], leg: U256) -> Option<B256> {
    let group = (u64::BITS - stmt::Q.leading_zeros()) as usize / 2;
    let (pkp, vp) = (PK / 32 * group, stmt::V_BYTES / 32 * group);
    let r = &blob[..blob.len().checked_sub(vp)?];
    if r.len() < 16 + pkp {
        return None;
    }
    let g = (r.len() - 16) / pkp;
    let rem = r.len() - 16 - pkp * g;
    let (m, ls) = [1usize, 0].into_iter().find_map(|a| {
        let ls = 32 + vp * (1 + a);
        let m = rem / ls;
        (m != 0 && m <= 8 && rem == ls * m && stmt::groups(m, a == 1) == g).then_some((m, ls))
    })?;
    let j = usize::try_from(leg).ok().filter(|&j| j < m)?;
    let end = 16 + pkp * g + ls * (j + 1);
    Some(B256::from_slice(&r[end - 32..end]))
}

impl Service {
    pub fn new(chain: Arc<dyn Chain>, pqz: Pqz, signer: PrivateKeySigner, cfg: &Config, chain_id: u64) -> Self {
        Self {
            chain,
            pqz,
            ua: signer.address().into_word(),
            signer,
            chain_id,
            releases: cfg.releases.keys().copied().collect(),
            valid_secs: cfg.valid_minutes * 60,
            work: Semaphore::new(cfg.concurrency),
            keys: Mutex::default(),
        }
    }

    /// The verifier UA: the signer's address as a native id.
    pub fn ua(&self) -> B256 {
        self.ua
    }

    async fn read<C: SolCall>(&self, to: Address, c: C) -> Result<C::Return, Refusal> {
        let out = self.chain.call(to, c.abi_encode().into()).await.map_err(|e| chain_refusal(C::SIGNATURE, e))?;
        C::abi_decode_returns(&out).map_err(|e| refuse("CHAIN_READ_FAILED", format!("{}: {e}", C::SIGNATURE)))
    }

    async fn code(&self, at: Address) -> Result<Bytes, Refusal> {
        self.chain.code(at).await.map_err(|e| chain_refusal("eth_getCode", e))
    }

    /// pqz-ffi's verdict, off the async workers, at most `concurrency` at once.
    async fn run(&self, input: Vec<u8>) -> Result<Word, Refusal> {
        let _slot = self.work.acquire().await.map_err(|_| refuse("BUSY", "closing"))?;
        let pqz = self.pqz.clone();
        match tokio::task::spawn_blocking(move || pqz(&input)).await {
            Ok(Ok(w)) => Ok(w),
            // over MAX_INPUT: the precompile reverts, no …01
            Ok(Err(pqz_ffi::Error::Revert)) => Ok(INVALID),
            Ok(Err(pqz_ffi::Error::NodeFault)) | Err(_) => Err(refuse("VERIFIER_FAULT", "pqz-ffi gave no result")),
        }
    }

    async fn token(&self, at: Address) -> Result<Token, Refusal> {
        let c = self.code(at).await?;
        if c.len() < 138 || c[..10] != PROXY_HEAD || c[30..45] != PROXY_TAIL {
            return Err(refuse("NOT_A_TOKEN", format!("{at}: not a factory instance")));
        }
        let release = Address::from_slice(&c[10..30]);
        if !self.releases.contains(&release) {
            return Err(refuse("UNKNOWN_RELEASE", format!("{at}: release {release} is not configured")));
        }
        Ok(Token { at, chain_uid: B256::from_slice(&c[45..77]), registry: Address::from_slice(&c[77..97]) })
    }

    /// Spec §11.2: sign only when every check passes.
    pub async fn verdict(&self, req: VerdictRequest) -> Result<Signed, Refusal> {
        if req.chain_id != self.chain_id {
            return Err(refuse("CHAIN_MISMATCH", format!("chain {}, not {}", req.chain_id, self.chain_id)));
        }
        let (plan, binding) = Plan::of(req.op)?;
        let st = &req.statement[..];
        // the set from the statement itself: one of its lengths, its word 32 the set's PQZL id
        if !statement_lengths().contains(&st.len()) {
            return Err(refuse("STATEMENT_LENGTH", format!("{} B is no {} statement", st.len(), stmt::SET)));
        }
        if st[32..64] != stmt::PQZL_ID {
            return Err(refuse("STATEMENT_PROOF_SYSTEM", "the statement's word 32 is not the set's PQZL id"));
        }
        let t = self.token(req.token).await?;
        let cfg = self.read(t.at, IPqzToken::pqzVerifyConfigCall {}).await?;
        if cfg.pqzVerifyMode != OFFCHAIN {
            return Err(refuse("NOT_OFFCHAIN", format!("{}: pqzVerifyMode {}", t.at, cfg.pqzVerifyMode)));
        }
        if cfg.verifier != self.ua {
            return Err(refuse("NOT_THIS_VERIFIER", format!("{}: verifier {}", t.at, cfg.verifier)));
        }
        if cfg.pqzVerifierEpoch != req.pqz_verifier_epoch {
            return Err(refuse("EPOCH_MISMATCH", format!("the token's epoch is {}", cfg.pqzVerifierEpoch)));
        }
        if self.read(t.at, IPqzToken::proofSystemIdCall {}).await? != B256::from(stmt::PQZL_ID) {
            return Err(refuse("PROOF_SYSTEM", "the token's proofSystemId is not the set's PQZL id"));
        }
        // the statement the token's own view builds at the current state, byte for byte
        let out = self.chain.call(t.at, plan.view(binding).into()).await.map_err(|e| match e {
            ChainError::Revert(d) => refuse("STATEMENT_VIEW_REVERTED", d.to_string()),
            e => chain_refusal("statement view", e),
        })?;
        let rebuilt = Bytes::abi_decode(&out).map_err(|e| refuse("CHAIN_READ_FAILED", format!("statement view: {e}")))?;
        // round 3t (CTR-PQZ-36, Fable P3-4: one source): the fee word the proof was built over (word 256) against the view's,
        // by name before the byte compare; the fee is the token's, not this service's policy
        if rebuilt.get(256..288) != st.get(256..288) {
            let w = |b: &[u8]| b.get(256..288).map(alloy::primitives::U256::from_be_slice).unwrap_or_default();
            return Err(refuse("FEE_WORD_MISMATCH", format!("the statement's fee word is {}, the token's is {} (its verifier fee {}): \
                rebuild the statement from the token's view and prove again", w(st), w(&rebuilt), cfg.verifierFee)));
        }
        if rebuilt[..] != *st {
            return Err(refuse("STATEMENT_MISMATCH", "the token's view builds other bytes at the current state"));
        }
        if self.run(stmt::input(plan.op(), st, &req.proof)).await? != VALID {
            return Err(refuse("VERDICT_ZERO", "pqz-ffi does not accept the proof"));
        }
        for (ua, version, off) in self.named_keys(&plan, st, &t).await? {
            self.check_key(t.registry, ua, version, &st[off..off + PK]).await?;
        }
        self.sign(&t, keccak256(st), keccak256(&req.proof), cfg.pqzVerifierEpoch).await
    }

    /// Spec §4.2's probe: a verdict over [`PROBE_STATEMENT`] and an empty proof at the token's current epoch.
    pub async fn probe(&self, req: ProbeRequest) -> Result<Signed, Refusal> {
        if req.chain_id != self.chain_id {
            return Err(refuse("CHAIN_MISMATCH", format!("chain {}, not {}", req.chain_id, self.chain_id)));
        }
        let t = self.token(req.token).await?;
        let cfg = self.read(t.at, IPqzToken::pqzVerifyConfigCall {}).await?;
        self.sign(&t, keccak256(PROBE_STATEMENT), keccak256(b""), cfg.pqzVerifierEpoch).await
    }

    async fn current(&self, t: &Token, ua: B256) -> Result<u64, Refusal> {
        Ok(self.read(t.registry, IUARegistry::pqzKeyOfCall { ua }).await?.version)
    }

    /// The keys the statement names, `(ua, version, offset)`: the sender at the args' `keyVersion`, the receiver or every
    /// leg and the auditor at their current version (`PqzCore._receiver`, `_legs`); a disclosure's key owner at its
    /// `keyVersion` (`PqzCore.disclosureBuffer`).
    async fn named_keys(&self, plan: &Plan, st: &[u8], t: &Token) -> Result<Vec<(B256, u64, usize)>, Refusal> {
        let mut k = match plan {
            Plan::Burn(b, ..) | Plan::Unwrap(b, _) => return Ok(vec![(b.fromUA, b.keyVersion, HEADER)]),
            Plan::Disclose(d) => {
                let owner = if d.kind == 2 {
                    self.read(t.at, IPqzToken::auditorUACall {}).await?
                } else {
                    let blob = self.read(t.at, IPqzToken::pqzEntryBlobCall { entryRef: d.entry_ref }).await?;
                    leg_owner(&blob, d.leg).ok_or_else(|| refuse("UNKNOWN_ENTRY", "no such leg in the entry"))?
                };
                return Ok(vec![(owner, d.key_version, stmt::DISC_WORDS * 32)]);
            }
            Plan::Single(a) => vec![(a.fromUA, a.keyVersion, HEADER), (a.toUA, self.current(t, a.toUA).await?, HEADER + PK)],
            Plan::Multi(a) => {
                let mut k = vec![(a.fromUA, a.keyVersion, HEADER)];
                for l in &a.legs {
                    let v = self.current(t, l.ua).await?;
                    k.push((l.ua, v, HEADER + k.len() * PK));
                }
                k
            }
        };
        if st[stmt::H_AUDITOR_ON * 32..][..32] == B256::with_last_byte(1)[..] {
            let a = self.read(t.at, IPqzToken::auditorUACall {}).await?;
            let v = self.current(t, a).await?;
            k.push((a, v, HEADER + k.len() * PK));
        }
        Ok(k)
    }

    /// Spec §6 and 3g KV-12 for key `pk` of `(ua, version)`: one owner (the registry's `keyOwner`, and this verifier's
    /// own record across UAs and versions); then once per `(ua, version, pqzKeyHash)`: the record holds `pk`, its `pqzPop`
    /// bytes are stored and hash to its `pqzPopHash` (a hash-only record is refused), and they verify as `R_REG` over
    /// that version's message.
    async fn check_key(&self, registry: Address, ua: B256, version: u64, pk: &[u8]) -> Result<(), Refusal> {
        let h = pqz_key_hash(pk);
        let owner = self.read(registry, IUARegistry::keyOwnerCall { keyHash: h }).await?;
        if owner != B256::ZERO && owner != ua {
            return Err(refuse("KEY_OWNED_ELSEWHERE", format!("key {h} is {owner}'s")));
        }
        if self.known(ua, version, h)? {
            return Ok(());
        }
        let at = self.read(registry, IUARegistry::pqzKeyAtCall { ua, version }).await?;
        if at.ptr == Address::ZERO {
            return Err(refuse("KEY_NOT_STORED", format!("{ua} version {version}")));
        }
        if self.code(at.ptr).await?.get(1..) != Some(pk) {
            return Err(refuse("KEY_MISMATCH", format!("{ua} version {version}: the record holds another key")));
        }
        let pop = self.read(registry, IUARegistry::pqzPopOfCall { ua, version }).await?;
        if pop.is_empty() {
            return Err(refuse("POP_NOT_STORED", format!("{ua} version {version}: only the proof's hash is stored")));
        }
        if keccak256(&pop) != at.pqzPopHash {
            return Err(refuse("POP_HASH", format!("{ua} version {version}")));
        }
        let message = self.rreg_message(registry, ua, version, h).await?;
        let rreg = [Form::Register.op_tag().as_slice(), &stmt::PQZL_ID, message.as_slice(), pk].concat();
        if self.run(stmt::input(stmt::OP_REGISTER, &rreg, &pop)).await? != VALID {
            return Err(refuse("POP_INVALID", format!("{ua} version {version}: R_REG does not verify")));
        }
        self.remember(ua, version, h)
    }

    fn elsewhere(k: &Keys, ua: B256, version: u64, h: B256) -> Result<(), Refusal> {
        match k.owner.get(&h) {
            Some(&(u, v)) if (u, v) != (ua, version) => {
                Err(refuse("KEY_OWNED_ELSEWHERE", format!("key {h} is {u}'s version {v} here")))
            }
            _ => Ok(()),
        }
    }

    fn known(&self, ua: B256, version: u64, h: B256) -> Result<bool, Refusal> {
        let k = self.keys.lock().unwrap();
        Self::elsewhere(&k, ua, version, h)?;
        Ok(k.ok.contains(&(ua, version, h)))
    }

    fn remember(&self, ua: B256, version: u64, h: B256) -> Result<(), Refusal> {
        let mut k = self.keys.lock().unwrap();
        Self::elsewhere(&k, ua, version, h)?;
        // ponytail: the ownership record lives in memory and is lost on restart; persist it if one verifier must keep
        // refusing a key reused across UAs after a restart
        if k.ok.len() >= CACHE_MAX {
            k.ok.clear();
        }
        k.ok.insert((ua, version, h));
        k.owner.insert(h, (ua, version));
        Ok(())
    }

    /// The `R_REG` message of `(ua, version)`, as `storePqzPop` checks it, by the registry's own digest views: v ≥ 1 over
    /// `UAPqzKeyVersion`; version 0 from `setPqzKey` (a stored signature) over `UAPqzKey`; version 0 from `register`
    /// (none) over the portable record with its initial KEM commitment. One path is never evidence for another.
    async fn rreg_message(&self, reg: Address, ua: B256, version: u64, h: B256) -> Result<B256, Refusal> {
        let pqz_key = keccak256("scaas.ua.purpose.pqz-key.v1");
        let (purpose, digest) = if version != 0 {
            (pqz_key, self.read(reg, IUARegistry::pqzKeyVersionDigestCall { ua, version, pqzKeyHash: h }).await?)
        } else if !self.read(reg, IUARegistry::pqzKeySigOfCall { ua, version: 0 }).await?.is_empty() {
            (pqz_key, self.read(reg, IUARegistry::pqzKeyDigestCall { ua, pqzKeyHash: h }).await?)
        } else {
            let kind = self.read(reg, IUARegistry::kindOfCall { ua }).await?;
            let a = self.read(reg, IUARegistry::registrationOfCall { ua }).await?.attrs;
            let kem = if a.kemPkHash != B256::ZERO {
                // a hash-committed KEM key: UAKinds.kemRecordHash(ua, 0, scheme, kemPkHash)
                let th = keccak256("UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)");
                keccak256((th, ua, 0u64, U256::from(a.kem.scheme), a.kemPkHash).abi_encode())
            } else {
                self.read(reg, IUARegistry::kemRecordHashCall { ua, version: 0, kem: a.kem }).await?
            };
            let d = IUARegistry::portableRecordDigestCall { ua, kind, pqzKeyHash: h, kemRecordHash: kem };
            (keccak256("scaas.ua.purpose.pop.v2"), self.read(reg, d).await?)
        };
        self.read(reg, IUARegistry::uaMessageCall { kind: PQZ_MLWE, purposeTag: purpose, digest }).await
    }

    /// The verdict, its `UAAuth` digest by the registry (`uaAuthDigest`, the registry's rule for a native EOA), the
    /// 65-byte low-s signature; logged with the token and both hashes.
    async fn sign(&self, t: &Token, statement_hash: B256, proof_hash: B256, epoch: u32) -> Result<Signed, Refusal> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let v = PqzVerdict {
            token: t.at,
            chainId: U256::from(self.chain_id),
            proofSystemId: stmt::PQZL_ID.into(),
            statementHash: statement_hash,
            proofHash: proof_hash,
            pqzVerifierEpoch: epoch,
            validUntil: now + self.valid_secs,
        };
        let digest = verdict_digest(&v, t.chain_uid);
        let call = IUARegistry::uaAuthDigestCall { ua: self.ua, purposeTag: purpose_pqz_verdict(), digest };
        let auth = self.read(t.registry, call).await?;
        let sig = self.signer.sign_hash_sync(&auth).map_err(|e| refuse("SIGNER_FAULT", e.to_string()))?;
        tracing::info!(token = %t.at, statement_hash = %statement_hash, proof_hash = %proof_hash, epoch,
            valid_until = v.validUntil, "pqz verdict signed");
        Ok(Signed {
            pqz_verdict: v,
            pqz_verdict_sig: WireSig { key_data: Bytes::new(), signature: sig.as_bytes().to_vec().into(), members: vec![] },
        })
    }
}
