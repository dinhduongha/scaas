// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PQZ verdicts (spec §9.3, CTR-PQZ-29; plan T16): a verifier-mode token's debit carries the `PqzSignedVerdict` of the
//! verifier the token names. The SDK asks the profile's verifiers (`ChainProfile.verifiers` with its own policy, owner
//! 2026-11-19, T16-a) through `scaas-rpc`'s `VerifierClient` and checks the answer before it is attached: every field of the
//! `PqzVerdict` against the token's state read at the profile's final block (`pqzVerifierUA`, `pqzVerifierEpoch`, `psid`, by
//! `STATE_LAYOUT`, storage only), the statement and proof hashes, `validUntil` against the SDK's clock, and its signer: the
//! verifier UA's registry record read at the same block by the same rules as the words it serves (R1 to R4, owner 2026-11-19,
//! T16-c), its key the signature's, `UA(key)` the token's verifier, the signature over `uaMessage(kind, pqz-verdict, digest)`
//! verified by `scaas-ua`. Refused, unreachable or not checking: `VerdictRefused`, and nothing is attached or sent.
//!
//! A native-id verifier (an EOA, `UAKinds.inNativeSpace`) signs the registry's `uaAuthDigest(verifier, pqz-verdict, digest)`
//! (`UARegistry._native`): its code read at the same block must be empty (an account with code answers ERC-1271 by a call, not
//! checked here) and the low-s ECDSA signature must recover the verifier's address under the token's registry's domain
//! (P-T16-3). The registry's generation is an immutable of its code, not a storage word: the signature is accepted under the
//! generation-1 or the generation-2 domain of that registry; the token's own check decides on chain. An `msig` verifier stays
//! `VerdictRefused` (fail closed). UNAUDITED.
use super::words::{add, be, class_kind, map_slot, rec_slot, word, CLASS_TOKEN, PURPOSE, W};
use crate::op::{addr20, evm, final_block, hex, unhex};
use crate::{Sdk, SdkError};
use alloy::primitives::{Address, B256};
use scaas_rpc::evm::EvmPool;
use scaas_rpc::pool::{ReadAt, ReadError};
use scaas_ua::facade::pqz::STATE_LAYOUT;
use serde_json::{json, Value};

/// The PQZ kinds of the factory record (R5).
const PQZ_KINDS: [u16; 4] = [4, 5, 12, 13];
/// `UAStore.Layout.records` (registry slot 0): `kind(16) ‖ registeredAt(40) ‖ keyPtr(160) ‖ index(40)` from the low end.
const REG_RECORDS_SLOT: u64 = 0;

/// What one endpoint returned for a verdict's check, unchecked.
#[derive(Debug, Clone, PartialEq)]
struct Raw {
    rec: W,
    code: Vec<u8>,
    psid: W,
    verifier: W,
    epoch: W,
    /// the verifier UA's registry record and the code at its key pointer
    record: W,
    key_code: Vec<u8>,
    /// the token's registry; a native-id verifier's own code
    registry: [u8; 20],
    native_code: Vec<u8>,
}

/// `STATE_LAYOUT`'s namespace slot and `(byte, width)` of `label` under the `scaas.pqz` root.
fn slot_of(label: &str) -> (W, usize, usize) {
    let r = STATE_LAYOUT
        .iter()
        .find(|r| r.0 == label)
        .map_or((0, 0, 0), |r| (r.1, r.3, r.4));
    (add(&super::pqz::root(), r.0), r.1, r.2)
}

async fn fetch(
    pool: &EvmPool,
    at: ReadAt<B256>,
    factory: Address,
    token: Address,
) -> Result<Raw, ReadError> {
    let at = &at;
    let rec = word(pool, at, factory, &rec_slot(&token.into_array())).await?;
    let code = pool.code_at(at, token).await?.to_vec();
    let psid = word(pool, at, token, &slot_of("psid").0).await?;
    let verifier = word(pool, at, token, &slot_of("pqzVerifierUA").0).await?;
    let epoch = word(pool, at, token, &slot_of("pqzVerifierEpoch").0).await?;
    let (mut record, mut key_code, mut registry, mut native_code) =
        ([0; 32], vec![], [0; 20], vec![]);
    if native(&verifier) {
        native_code = pool
            .code_at(at, Address::from_slice(&verifier[12..]))
            .await?
            .to_vec();
    }
    if let Some((_, env)) = scaas_ua::factory::clone_env(&code) {
        registry = env.registry;
        record = word(
            pool,
            at,
            Address::from(env.registry),
            &map_slot(&verifier, &be(REG_RECORDS_SLOT)),
        )
        .await?;
        let ptr = Address::from_slice(&record[5..25]);
        if !ptr.is_zero() {
            key_code = pool.code_at(at, ptr).await?.to_vec();
        }
    }
    Ok(Raw {
        rec,
        code,
        psid,
        verifier,
        epoch,
        record,
        key_code,
        registry,
        native_code,
    })
}

/// A native id: the top 96 bits zero (`UAKinds.inNativeSpace`).
fn native(ua: &W) -> bool {
    ua.iter().take(12).all(|b| *b == 0)
}

/// A verdict request (spec §9.3): the verifier's named fields of the operation (`op`: `{entry, args, binding?, amount?,
/// recipient?, unwrap?}`, the proof-carrying entry and its argument struct, as `POST /v1/pqz-verdict` takes them), the
/// statement the token rebuilds and the proof, `0x` hex.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(frb_expand, doc = frb_hint!(opaque))]
pub struct PqzVerdictRequest {
    pub chain: String,
    pub token: String,
    pub op: Value,
    pub statement: String,
    pub proof: String,
}

/// The verdict of `r`, checked (module doc): the `PqzSignedVerdict` an entry takes last, `{pqzVerdict, sig}`.
/// `VerdictRefused` on every failure past the token's own checks; `TokenUncatalogued`, `ProfileMismatch`, `ChainUnknown`, the
/// pool's codes before any verifier is asked.
pub(crate) async fn request(sdk: &Sdk, r: &PqzVerdictRequest) -> Result<Value, SdkError> {
    let (profile, chain_id, pool) = evm(sdk, &r.chain)?;
    let factory = Address::from(addr20(
        &profile
            .factory
            .clone()
            .ok_or(SdkError::Argument)?
            .to_ascii_lowercase(),
    )?);
    let t = addr20(&r.token.to_ascii_lowercase())?;
    let uid: W = unhex(&profile.chain_uid)?
        .try_into()
        .map_err(|_| SdkError::Argument)?;
    let (stmt, proof) = (unhex(&r.statement)?, unhex(&r.proof)?);
    let pool = &pool;
    let a = pool
        .read_at_block(final_block(&profile), PURPOSE, |at| {
            fetch(pool, at, factory, Address::from(t))
        })
        .await?;
    let x = a.value;
    // R5, R2: the token's own checks, as the words it serves
    let (class, kind) = class_kind(&x.rec);
    if class != CLASS_TOKEN || !PQZ_KINDS.contains(&kind) {
        return Err(SdkError::TokenUncatalogued);
    }
    let (_, env) = scaas_ua::factory::clone_env(&x.code).ok_or(SdkError::TokenUncatalogued)?;
    if env.chain_uid != uid {
        return Err(SdkError::ProfileMismatch);
    }
    let (_, eb, ew) = slot_of("pqzVerifierEpoch");
    let epoch = x
        .epoch
        .get(32 - eb - ew..32 - eb)
        .unwrap_or_default()
        .iter()
        .fold(0u64, |a, b| (a << 8) | u64::from(*b));
    // no verifier named (a PRECOMPILE token, or one revoked): no verdict to ask for
    if x.verifier == [0; 32] {
        return Err(SdkError::VerdictRefused);
    }
    let client = sdk.verifiers(&r.chain)?;
    let req = json!({"token": hex(&t), "chainId": chain_id, "op": r.op, "statement": r.statement,
        "proof": r.proof, "pqzVerifierEpoch": epoch});
    let answer = client
        .verdict(&req)
        .await
        .map_err(|_| SdkError::VerdictRefused)?;
    checked(
        &answer,
        &x,
        &t,
        chain_id,
        &uid,
        epoch,
        &stmt,
        &proof,
        sdk.now(),
    )
    .ok_or(SdkError::VerdictRefused)
}

/// The answer's `PqzVerdict` and its signer checked against the token's state `x` (module doc); `None` on any mismatch.
#[allow(clippy::too_many_arguments)]
fn checked(
    answer: &Value,
    x: &Raw,
    token: &[u8; 20],
    chain_id: u64,
    uid: &W,
    epoch: u64,
    stmt: &[u8],
    proof: &[u8],
    now: u64,
) -> Option<Value> {
    let v = answer.get("pqzVerdict")?;
    let s = answer.get("pqzVerdictSig")?;
    let str_of = |o: &Value, k: &str| {
        o.get(k)
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
    };
    let num = |k: &str| match v.get(k)? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    };
    let fields = [
        ("token", hex(token)),
        ("proofSystemId", hex(&x.psid)),
        ("statementHash", hex(&scaas_ua::keccak256(stmt))),
        ("proofHash", hex(&scaas_ua::keccak256(proof))),
    ];
    if fields
        .iter()
        .any(|(k, want)| str_of(v, k).as_deref() != Some(want.as_str()))
        || num("chainId")? != chain_id
        || num("pqzVerifierEpoch")? != epoch
        || num("validUntil")? < now
    {
        return None;
    }
    // the signer: a single derived key, the token's verifier, by its registry record at the same block
    let (key_data, sig) = (
        unhex(&str_of(s, "keyData")?).ok()?,
        unhex(&str_of(s, "signature")?).ok()?,
    );
    if s.get("members")
        .and_then(Value::as_array)
        .is_none_or(|m| !m.is_empty())
    {
        return None;
    }
    let digest = scaas_ua::wallet::pqz_verdict_typed_data(token, chain_id, uid, v)
        .ok()?
        .digest()
        .ok()?;
    let purpose = scaas_ua::purpose_tag("pqz-verdict").ok()?;
    if native(&x.verifier) {
        // P-T16-3: an EOA signs the registry's `uaAuthDigest`; no key data, no code
        let addr: [u8; 20] = x.verifier.get(12..)?.try_into().ok()?;
        let refused = !key_data.is_empty()
            || !x.native_code.is_empty()
            || ![1, 2].iter().any(|g| {
                let d = scaas_ua::Domain {
                    generation: *g,
                    chain_id,
                    registry: x.registry,
                    chain_uid: *uid,
                };
                scaas_ua::verify::native_ecdsa(
                    &addr,
                    &scaas_ua::ua_auth_digest(&d, &x.verifier, &purpose, &digest),
                    &sig,
                )
            });
        return (!refused).then(|| json!({"pqzVerdict": v, "sig": {"keyData": "0x", "signature": hex(&sig), "members": []}}));
    }
    let kind = u16::from_be_bytes([x.record[30], x.record[31]]);
    if kind == 0 || x.key_code.split_first() != Some((&0, key_data.as_slice())) {
        return None;
    }
    if scaas_ua::derive_ua(kind, &key_data, false).ok()? != x.verifier {
        return None;
    }
    let msg = scaas_ua::ua_message(kind, &purpose, &digest).ok()?;
    if !scaas_ua::verify::verify(kind, &key_data, &msg, &sig, false) {
        return None;
    }
    Some(
        json!({"pqzVerdict": v, "sig": {"keyData": hex(&key_data), "signature": hex(&sig), "members": []}}),
    )
}

impl super::Confidential {
    /// The checked verdict of a verifier-mode PQZ operation (spec §9.3): the `PqzSignedVerdict` to attach, `{pqzVerdict,
    /// sig}`. `VerdictRefused` when the token names no verifier, the profile lists none, every verifier refused or was
    /// unreachable, or the answer does not check (another signer, another statement, proof, epoch or token, past its
    /// `validUntil`); nothing is attached then.
    pub async fn request_verdict(&self, r: PqzVerdictRequest) -> Result<Value, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk.spawn(async move { request(&sdk, &r).await }).await
    }
}
