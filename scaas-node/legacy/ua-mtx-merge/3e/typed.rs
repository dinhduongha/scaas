//! The EVM named entries (typed-signing N1, owner Option B): one table, one parser. A job's `op` object is explicit JSON
//! (`{entry, contract, token, envelope, args, signature | auth}`, job-api.md); [`Op::parse`] reads it once into typed
//! values and both the typed EIP-712 struct hash and the calldata come from those values, so what is hashed is what is
//! sent (no chain view: the digest is the in-flight key, `Typed::digest_on`).
//!
//! The table is data, one generic encoder over it (as `clients/zether-prover/src/typed.rs`, C7): a row added is a row hashed,
//! encoded and allowed. `typed_ops_kat_every_entry` pins every row against `smartcontracts/vectors/typed/typed_ops.json`
//! (type string, struct hash, digest, selector, calldata); the plain rows have no vector, their selectors are pinned in
//! `guard.rs`.
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use alloy::dyn_abi::{DynSolType, DynSolValue as Val};
use alloy::primitives::{keccak256, Address, Bytes, Signature, B256, U256};
use alloy::sol_types::SolCall;
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Map, Value};

use crate::abi::IMtxRelayFee;
use crate::metatx::{addr, check_mode, native, uint, MODE_RESTRICT_FEE_RECIPIENT, MODE_RESTRICT_RELAYER};

/// The envelope after `from` (`MetaTxLib.Envelope` without it); `E` in a row's fields expands to it.
const ENV: [&str; 7] = ["batch", "nonce", "validUntil", "mode", "relayer", "fee", "feeRecipient"];
const E_FIELDS: &str = "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient";

const T: &[&str] = &["token", "zether", "pqz"];
/// The ordered cancel on ids (Q2): the token kinds, the mandate wallet (Q6) and the router.
const TWG: &[&str] = &["token", "zether", "pqz", "wallet", "gov_router"];
/// The chain's `GovernanceRouter` (spec 2026-11-02-governance §3.2, §12.7): its typed entries only, none on a governed contract.
const GR: &[&str] = &["gov_router"];
const ZP: &[&str] = &["zether", "pqz"];
const Z: &[&str] = &["zether"];
const P: &[&str] = &["pqz"];
const W: &[&str] = &["wallet"];
const A: &[&str] = &["account"];
const D: &[&str] = &["dex"];
const REG: &[&str] = &["registry"];
const FACT: &[&str] = &["factory"];

/// The EIP-712 domain name of a contract kind (the `domains.<kind>` of `typed_ops.json`); `None` for a kind that signs nothing.
pub fn domain_name(contract: &str) -> Option<&'static str> {
    Some(match contract {
        "token" => "SCaaS MetaToken",
        "zether" => "SCaaS ZetherToken",
        "pqz" => "SCaaS PqzToken",
        "wallet" => "SCaaS MandateWallet",
        "account" => "SCaaS SmartKeyAccount",
        "dex" => "SCaaS Dex",
        "gov_router" => "SCaaS GovernanceRouter",
        _ => return None,
    })
}

/// Every struct a row nests. `Unwrap` here is the payout of an unshield-unwrap, not the op of that name.
const NESTED: &[(&str, &str)] = &[
    ("G1", "bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1"),
    ("ZetherSingle", "uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,G1 yFrom,G1 yTo,G1 cOut,G1 dOut,G1 cDeb,G1 cAud"),
    ("ZetherLeg", "G1 yTo,G1 cOut,G1 cAud,G1 dAud"),
    ("ZetherMulti", "uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,uint256 decoyFee,G1 yFrom,G1 dOut,G1 cDeb,ZetherLeg[] legs,bytes sealedMemo"),
    ("ZetherBurn", "uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes32 beneficiaryUA,G1 yFrom"),
    ("PqzTransferArgs", "uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes sealedMemo"),
    ("PqzLeg", "bytes32 ua,bytes v,bytes vAuditor"),
    ("PqzMultiArgs", "uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo"),
    ("PqzBurnArgs", "uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 beneficiaryUA,bytes u,bytes vFrom"),
    ("Unwrap", "address underlying,bytes32 recipient,uint256 amount,uint256 minOut"),
    ("MetaTransfer", "address from,address to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient"),
    ("UAMetaTransfer", "bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient"),
    ("TradeOrder", "address from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil"),
    ("UATradeOrder", "bytes32 from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,bytes32 destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil"),
    ("WrapOrder", "address from,address wrappedToken,uint256 amount,uint256 minMinted,uint256 minFill,uint256 fee,address relayer,address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil"),
    ("UAWrapOrder", "bytes32 from,address wrappedToken,uint256 amount,uint256 minMinted,uint256 minFill,uint256 fee,address relayer,bytes32 destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil"),
    ("DexOrder", "address sellToken,TradeOrder order"),
    // the calldata-only structs: `UASig`, the account's `AccountSig`, the registry's and the DEX's
    ("InnerSig", "uint16 index,bytes sig"),
    ("MemberSig", "uint16 index,InnerSig[] members,bytes sig"),
    ("UASig", "bytes keyData,bytes signature,MemberSig[] members"),
    ("AccountSig", "uint256 keyIndex,bytes32[] proof,bytes signature"),
    ("SubjectKey", "uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash"),
    ("KemKey", "uint8 scheme,bytes mlkemEk,bytes32 x25519"),
    ("UAAttrs", "bytes pqzKey,bytes32 pqzPopHash,KemKey kem,bytes32 kemPkHash"),
    ("MsigMember", "uint16 kind,bytes32 id,uint16 weight"),
    ("MsigStructure", "uint16 threshold,MsigMember[] members"),
    ("WebAuthnKey", "bytes32 x,bytes32 y,bytes32 rpIdHash"),
    ("MuSig2Key", "bytes aggKey,bytes[] memberKeys"),
    ("FrostMember", "bytes[] commitments,bytes r,bytes32 z"),
    ("FrostKey", "bytes groupKey,uint16 threshold,FrostMember[] members"),
    ("DexLeg", "address sellToken,uint8 shape,TradeOrder order,UATradeOrder uaOrder,bytes sig,UASig auth,uint256 fill"),
    ("Settlement", "bytes32 ref,DexLeg taker,DexLeg[] makers"),
    ("ExchangeLeg", "address sellToken,uint8 shape,TradeOrder order,UATradeOrder uaOrder,bytes sig,UASig auth,uint256 sellFill,uint256 receiveFill"),
    ("Interaction", "address target,bytes data"),
    ("ExchangePlan", "bytes32 ref,ExchangeLeg[] legs,address[] extraTokens"),
    ("HybridPlan", "bytes32 ref,DexLeg taker,DexLeg[] makers,uint256 outsideSell,uint256 outsideFloor,address[] extraTokens"),
    // `IGovernance.GrantTerms`: flat, so a decode is one level deep; its `hashStruct` is the signed word, the struct the argument
    ("GrantTerms", "uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope"),
];

/// `(struct, entry, contract kinds, fields, plan)`. `E` = the envelope fields. The plan is the entry's arguments in order;
/// empty = `E`, the fields between `from` and the envelope, the signature. Tokens: `E`; a field; `name:Type`, an argument
/// that is not signed; `(a,b)`, a tuple of fields; `[x]`, a one-element array; `$`, the whole struct; `wrap!x`, a `UAWrapOrder`
/// field as the `UATradeOrder` it is cancelled through; `@`, the signature: `UASig` on a merged entry (a `UA*` struct, `auth`),
/// `AccountSig` on the account's own entries (`auth`), `bytes` on the address entries left (`signature`); `@bytes` / `@ua` where
/// the entry differs.
///
/// ua-mtx-merge (CTR-MTX-30): one signed entry per operation, `mtx<Op>(UAEnvelope, …, UASig)` signing `UA<Op>`, for a native id
/// (an address zero-padded, its own key) and a derived UA alike; the address forms of merged operations and the `ua<Op>` names
/// are in `legacy/ua-mtx-merge/`. The address entries left: the five wraps (`Envelope`, `bytes`), `SmartKeyAccount`'s own, the
/// DEX's outside-token cancel and invalidation, the two Zether owner statements (signed as `UASig` of `ua`, no envelope).
const TYPED: &[(&str, &str, &[&str], &str, &str)] = &[
    ("CancelNonce", "mtxCancelNonce", A, "address from,uint256 lane,E", "E lane @bytes"),
    ("UACancelNonce", "mtxCancelNonce", TWG, "bytes32 from,uint256 lane,E", ""),
    ("UABurn", "mtxBurn", T, "bytes32 from,uint256 amount,E", ""),
    ("Wrap", "mtxWrap", T, "address from,uint256 amount,E", ""),
    ("WrapLeg", "mtxWrapLeg", T, "address from,address underlying,uint256 amount,E", ""),
    ("UAUnwrap", "mtxUnwrap", T, "bytes32 from,uint256 wrapped,address recipient,uint256 minOut,E", ""),
    ("UAUnwrapLeg", "mtxUnwrapLeg", T, "bytes32 from,address underlying,uint256 wrapped,address recipient,uint256 minOut,E", ""),
    ("AddReserve", "mtxAddReserve", T, "address from,address underlying,uint256 amount,E", ""),
    ("WrapToUA", "mtxWrapToUA", T, "address from,address underlying,uint256 amount,bytes32 to,E", ""),
    ("UAUnwrapToUA", "mtxUnwrapToUA", T, "bytes32 from,address underlying,uint256 wrapped,bytes32 to,uint256 minOut,E", ""),
    ("UAShield", "mtxShield", ZP, "bytes32 from,bytes32 toUA,uint256 amount,E", ""),
    ("WrapShield", "mtxWrapShield", ZP, "address from,address underlying,uint256 amountIn,bytes32 toUA,E", ""),
    ("UARollOver", "mtxRollOver", ZP, "bytes32 from,bytes32 ua,uint256 n,E", ""),
    ("UAPrepareAcc", "mtxPrepareAcc", P, "bytes32 from,bytes32 ua,uint256 half,E", ""),
    // the mandate wallets in the merged form (Q6, MD-11): owner and delegate are ids
    ("UASetMandate", "mtxSetMandate", W, "bytes32 from,address token,bytes32 delegate,uint128 maxPerPayment,uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry,E", ""),
    ("UASetPayee", "mtxSetPayee", W, "bytes32 from,address token,bytes32 payee,bool allowed,E", ""),
    ("UARevokeMandate", "mtxRevokeMandate", W, "bytes32 from,address token,E", ""),
    ("UAPayUnderMandate", "mtxPayUnderMandate", W, "bytes32 from,address token,bytes32 payee,uint256 amount,bytes32 entryRef,uint64 epoch,E", ""),
    ("UADelegateRevoke", "mtxDelegateRevoke", W, "bytes32 from,address token,uint64 epoch,E", ""),
    ("UAExecute", "mtxExecute", W, "bytes32 from,address target,uint256 value,bytes data,E", ""),
    ("AddKey", "mtxAddKey", A, "address from,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash,E", ""),
    ("RemoveKey", "mtxRemoveKey", A, "address from,uint256 index,E", ""),
    ("RotateKey", "mtxRotateKey", A, "address from,uint256 index,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash,E", ""),
    ("SetGuardian", "mtxSetGuardian", A, "address from,address guardian,E", ""),
    ("CancelRecovery", "mtxCancelRecovery", A, "address from,E", ""),
    ("Execute", "mtxExecute", A, "address from,address target,uint256 value,bytes data,E", ""),
    ("UAPqzTransferSingle", "mtxConfidentialTransferSingle", P, "bytes32 from,PqzTransferArgs args,bytes proof,bytes accHint,E", PQZ_PLAN),
    ("UAPqzTransferSingleCompact", "mtxConfidentialTransferSingleCompact", P, "bytes32 from,PqzTransferArgs args,bytes proof,bytes accHint,E", PQZ_PLAN),
    ("UAPqzTransfer", "mtxConfidentialTransfer", P, "bytes32 from,PqzMultiArgs args,bytes proof,bytes accHint,E", PQZ_PLAN),
    ("UAPqzTransferCompact", "mtxConfidentialTransferCompact", P, "bytes32 from,PqzMultiArgs args,bytes proof,bytes accHint,E", PQZ_PLAN),
    ("UAPqzUnshield", "mtxUnshield", P, "bytes32 from,PqzBurnArgs args,uint256 amount,bytes32 recipient,bytes proof,bytes accHint,E", PQZ_BURN_PLAN),
    ("UAPqzUnshieldUnwrap", "mtxUnshieldUnwrap", P, "bytes32 from,PqzBurnArgs args,Unwrap unwrap,bytes proof,bytes accHint,E", PQZ_UNWRAP_PLAN),
    ("UAZetherTransferSingle", "mtxConfidentialTransferSingle", Z, "bytes32 from,ZetherSingle args,bytes proof,E", ""),
    ("UAZetherTransfer", "mtxConfidentialTransfer", Z, "bytes32 from,ZetherMulti args,bytes proof,E", ""),
    ("UAZetherTransferCompact", "mtxConfidentialTransferCompact", Z, "bytes32 from,ZetherMulti args,bytes proof,E", ""),
    ("UAZetherUnshield", "mtxUnshield", Z, "bytes32 from,ZetherBurn args,uint256 amount,bytes32 recipient,bytes proof,E", ""),
    ("UAZetherUnshieldUnwrap", "mtxUnshieldUnwrap", Z, "bytes32 from,ZetherBurn args,Unwrap unwrap,bytes proof,E", ""),
    ("UARollOverSigned", "mtxRollOverSigned", Z, "bytes32 from,bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock,E", OWNER_ROLL_PLAN),
    ("UASetRollOverMode", "mtxSetRollOverMode", Z, "bytes32 from,bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock,E", OWNER_MODE_PLAN),
    ("UARollOverBatch", "mtxRollOverBatch", Z, "bytes32 from,bytes32[] uas,E", ""),
    ("UAReceiverFee", "mtxPayReceiverFee", T, "UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil", "payment payerSig:UASig fee feeRecipient validUntil @"),
    ("UARelayFee", "mtxRelayFee", T, "bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 validUntil,address relayer", "from target callDataHash payee value validUntil @"),
    ("UAWrapOrder", "mtxWrapOrder", T, "bytes32 from,address wrappedToken,uint256 amount,uint256 minMinted,uint256 minFill,uint256 fee,address relayer,bytes32 destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil", "underlying:address $ @"),
    ("CancelUAOrder", "mtxCancelOrder", T, "UATradeOrder order", "order @"),
    ("CancelUAWrapOrder", "mtxCancelOrder", T, "UAWrapOrder order", "wrap!order @"),
    ("CancelDexOrder", "mtxCancelOrders", D, "DexOrder order", "[order] [@]"),
    ("ZetherRollOver", "mtxRollOverSigned", Z, "bytes32 ua,uint64 accSeq,uint64 expectedPendingSeq,uint64 validUntilBlock", "ua expectedPendingSeq validUntilBlock @ua"),
    ("ZetherSetRollOverMode", "mtxSetRollOverMode", Z, "bytes32 ua,uint8 mode,uint64 modeNonce,uint64 validUntilBlock", "ua mode validUntilBlock @ua"),
    ("PqzAuth", "", P, "uint8 op,bytes32 opTag,bytes32 psid,uint256 chainId,address token,address registry,bytes32 from,bytes32 to,bytes32 beneficiary,uint256 fee,uint256 amount,bytes32 recipient,uint64 sendCounter,uint64 p,uint256 validUntilBlock,bool auditorOn,uint256 shieldIn,bytes32 chainUid,bytes32 binding,uint128 salt,bytes32 memoHash,bytes32 bodyHash", ""),
    // the `GovernanceRouter`'s closed table (spec §3.2, ua-mtx-merge T7): `mtx<Op>`, `target` the first op word, fee mode `NONE`
    ("UAGrantRole", "mtxGrantRole", GR, "bytes32 from,address target,uint8 bit,bytes32 account,E", ""),
    ("UARevokeRole", "mtxRevokeRole", GR, "bytes32 from,address target,uint8 bit,bytes32 account,E", ""),
    ("UASetGrant", "mtxSetGrant", GR, "bytes32 from,address target,uint8 bit,bytes32 holder,GrantTerms terms,E", ""),
    ("UACancelGrant", "mtxCancelGrant", GR, "bytes32 from,address target,uint8 bit,bytes32 account,E", ""),
    ("UADisableFeature", "mtxDisableFeature", GR, "bytes32 from,address target,uint8 bit,E", ""),
    ("UATransferOwnership", "mtxTransferOwnership", GR, "bytes32 from,address target,bytes32 newOwner,E", ""),
    ("UAAcceptOwnership", "mtxAcceptOwnership", GR, "bytes32 from,address target,E", ""),
    ("UARenounceOwnership", "mtxRenounceOwnership", GR, "bytes32 from,address target,E", ""),
    ("UARenounceRole", "mtxRenounceRole", GR, "bytes32 from,address target,uint8 bit,E", ""),
    ("UAMint", "mtxMint", GR, "bytes32 from,address target,address to,uint256 amount,E", ""),
    ("UAMintToUA", "mtxMintToUA", GR, "bytes32 from,address target,bytes32 to,uint256 amount,E", ""),
    ("UADisableWrap", "mtxDisableWrap", GR, "bytes32 from,address target,address leg,bytes32 reason,E", ""),
    ("UAProposeRate", "mtxProposeRate", GR, "bytes32 from,address target,address leg,uint96 num,uint96 den,E", ""),
    ("UACancelRate", "mtxCancelRate", GR, "bytes32 from,address target,E", ""),
    ("UAExecuteRate", "mtxExecuteRate", GR, "bytes32 from,address target,E", ""),
    ("UASetMarket", "mtxSetMarket", GR, "bytes32 from,address target,address base,address quote,bool listed,E", ""),
    ("UASetExchangeTarget", "mtxSetExchangeTarget", GR, "bytes32 from,address target,address exchangeTarget,bool listed,E", ""),
    ("UASetListedOnly", "mtxSetListedOnly", GR, "bytes32 from,address target,bool on,E", ""),
    ("UASetFeeSplit", "mtxSetFeeSplit", GR, "bytes32 from,address target,uint32 relayerSharePpm,address treasury,E", ""),
    // the controls of the regulated kinds 8-13 (plan T32; regulated-kinds spec §3.1, Q8): the direct entry's parameters;
    // `UAOperatorTransfer` names the moved account `account` (CTR-GOV-20: `from` is the signer). Vectors: plan T34
    ("UAFreeze", "mtxFreeze", GR, "bytes32 from,address target,bytes32 account,bytes32 ref,bytes32 recordId,E", ""),
    ("UAUnfreeze", "mtxUnfreeze", GR, "bytes32 from,address target,bytes32 account,bytes32 ref,E", ""),
    ("UAForceTransfer", "mtxForceTransfer", GR, "bytes32 from,address target,bytes32 recordId,uint256 amount,E", ""),
    ("UAPause", "mtxPause", GR, "bytes32 from,address target,bytes32 ref,uint64 until,E", ""),
    ("UAUnpause", "mtxUnpause", GR, "bytes32 from,address target,bytes32 ref,E", ""),
    ("UARecordOrder", "mtxRecordOrder", GR, "bytes32 from,address target,bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,uint256 maxAmount,uint64 freezeUntil,E", ""),
    ("UARevokeOrder", "mtxRevokeOrder", GR, "bytes32 from,address target,bytes32 recordId,bytes32 reasonRef,E", ""),
    ("UAOperatorTransfer", "mtxOperatorTransfer", GR, "bytes32 from,address target,bytes32 account,bytes32 to,uint256 amount,bytes32 ref,E", ""),
    // not rows of the vector file: the DEX's (`dex_order_kat.json`) and the token's on ids (`uatrade_kat.json`), one name per kind
    ("InvalidateNonces", "mtxInvalidateNonces", D, "address from,uint256 batch,uint256 minNonce", "from batch minNonce @"),
    ("UAInvalidateNonces", "mtxInvalidateNonces", T, "bytes32 from,uint256 batch,uint256 minNonce", "from batch minNonce @"),
];
const PQZ_PLAN: &str = "E args proof pqzAuth:UASig accHint @";
const PQZ_BURN_PLAN: &str = "E args (amount,recipient) proof pqzAuth:UASig accHint @";
const PQZ_UNWRAP_PLAN: &str = "E args unwrap proof pqzAuth:UASig accHint @";
const OWNER_ROLL_PLAN: &str = "E ua expectedPendingSeq validUntilBlock ownerSig:UASig @";
const OWNER_MODE_PLAN: &str = "E ua rollOverMode validUntilBlock ownerSig:UASig @";

/// `(entry, contract kinds, arguments)`: entries that sign no typed struct of their own; every argument is named JSON.
const PLAIN: &[(&str, &[&str], &str)] = &[
    ("deploy", FACT, "SubjectKey firstKey,address guardian"),
    // `SmartKeyAccount`'s owner path; the mandate wallet's `mtxExecuteAsOwner(Raw)` and flat builders (`mtxPayUnderMandate`,
    // `mtxRevoke`) are second entries of operations with a named one (MD-11 (a)): `legacy/ua-mtx-merge/typed.rs`
    ("mtxExecuteAsOwner", A, "bytes data,uint256 nonce,uint256 validUntil,bytes sig"),
    ("register", REG, "uint16 kind,bytes keyData,UAAttrs attrs,bytes pop,bytes pqzPop"),
    ("registerMsig", REG, "MsigStructure structure,UAAttrs attrs,MemberSig[] pop,bytes pqzPop"),
    ("registerWebAuthn", REG, "WebAuthnKey key,UAAttrs attrs,bytes pop,bytes pqzPop"),
    ("registerMuSig2", REG, "uint16 kind,MuSig2Key key,UAAttrs attrs,bytes pop,bytes pqzPop"),
    ("registerFrost", REG, "uint16 kind,FrostKey key,UAAttrs attrs,bytes pop,bytes pqzPop"),
    ("setKemKey", REG, "bytes32 ua,uint64 version,KemKey kem,UASig sig"),
    ("storePqzPop", REG, "bytes32 ua,bytes pqzPop"),
    ("setPqzKey", REG, "bytes32 ua,bytes pqzKey,bytes32 pqzPopHash,UASig sig"),
    ("acceptMembership", REG, "bytes32 ua,MemberSig memberSig"),
    ("mtxSettle", D, "Settlement[] s"),
    ("mtxExchange", D, "ExchangePlan p,Interaction[] interactions"),
    ("mtxExchangeVia", D, "ExchangePlan p,address executor,bytes data"),
    ("mtxExchangeBatch", D, "ExchangePlan[] ps,Interaction[][] interactions"),
    ("mtxHybrid", D, "HybridPlan p,Interaction[] interactions"),
    ("mtxHybridVia", D, "HybridPlan p,address executor,bytes data"),
    ("mtxCancelOrders", D, "DexOrder[] orders,bytes[] sigs"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    Bytes,
    Ua,
    Account,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Env,
    Field(String),
    Extra(String, String),
    Group(Vec<String>),
    List(Box<Tok>),
    Whole,
    WrapAsTrade(String),
    Sign(Sig),
}

#[derive(Debug)]
pub struct Row {
    /// The struct (typed), or the entry (plain).
    pub name: &'static str,
    pub entry: &'static str,
    pub contracts: &'static [&'static str],
    /// `(type, name)`, envelope expanded.
    pub fields: Vec<(String, String)>,
    /// The fields end with the envelope, `from` first: `envelope` in the job.
    pub enveloped: bool,
    pub typed: bool,
    plan: Vec<Tok>,
    pub sig: Option<Sig>,
    /// The entry's own selector.
    pub selector: [u8; 4],
    /// What the node sends: the router's `relay` / `uaRelay` for a relay fee, else `selector`.
    pub sent: [u8; 4],
}

impl Row {
    /// A merged entry (CTR-MTX-30): a `UA*` struct, its subject a `bytes32` id, `UASig`; a `ua_metatx` job (R43). The address
    /// entries left (the wraps, `SmartKeyAccount`'s, the DEX's, the Zether owner statements) are `metatx` jobs.
    pub fn ua(&self) -> bool {
        self.typed && (self.name.starts_with("UA") || self.name.starts_with("CancelUA"))
    }

    fn relay_fee(&self) -> bool {
        self.name == "UARelayFee"
    }

    /// The EIP-712 `encodeType` string.
    pub fn type_string(&self) -> String {
        type_string(self.name, &self.fields)
    }
}

fn fields_of(s: &str) -> Vec<(String, String)> {
    let s = s.strip_suffix(",E").map_or(s.to_string(), |h| format!("{h},{E_FIELDS}"));
    s.split(',')
        .map(|f| {
            let (t, n) = f.split_once(' ').unwrap_or_else(|| panic!("field {f:?}"));
            (t.to_string(), n.to_string())
        })
        .collect()
}

fn tok(t: &str, sig: Sig) -> Tok {
    if t == "E" {
        return Tok::Env;
    }
    if t == "$" {
        return Tok::Whole;
    }
    if let Some(n) = t.strip_prefix("wrap!") {
        return Tok::WrapAsTrade(n.into());
    }
    if let Some(l) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        return Tok::List(Box::new(tok(l, sig)));
    }
    if let Some(g) = t.strip_prefix('(').and_then(|x| x.strip_suffix(')')) {
        return Tok::Group(g.split(',').map(str::to_string).collect());
    }
    match t {
        "@" => Tok::Sign(sig),
        "@bytes" => Tok::Sign(Sig::Bytes),
        "@ua" => Tok::Sign(Sig::Ua),
        _ => match t.split_once(':') {
            Some((n, ty)) => Tok::Extra(n.into(), ty.into()),
            None => Tok::Field(t.into()),
        },
    }
}

fn abi_type(ty: &str) -> String {
    if let Some(el) = ty.strip_suffix("[]") {
        return format!("{}[]", abi_type(el));
    }
    match nested(ty) {
        Some(f) => format!("({})", f.iter().map(|x| abi_type(&x.0)).collect::<Vec<_>>().join(",")),
        None => ty.to_string(),
    }
}

fn sig_type(s: Sig) -> &'static str {
    match s {
        Sig::Bytes => "bytes",
        Sig::Ua => "UASig",
        Sig::Account => "AccountSig",
    }
}

fn tok_abi(t: &Tok, fields: &[(String, String)]) -> String {
    let of = |n: &str| abi_type(&fields.iter().find(|f| f.1 == n).unwrap_or_else(|| panic!("no field {n}")).0);
    match t {
        Tok::Env => format!("({},uint256,uint256,uint256,uint32,address,uint256,address)", fields[0].0),
        Tok::Field(n) => of(n),
        Tok::Extra(_, ty) => abi_type(ty),
        Tok::Group(g) => format!("({})", g.iter().map(|n| of(n)).collect::<Vec<_>>().join(",")),
        Tok::List(x) => format!("{}[]", tok_abi(x, fields)),
        Tok::Whole => format!("({})", fields.iter().map(|f| abi_type(&f.0)).collect::<Vec<_>>().join(",")),
        // `TradeOrder` / `UATradeOrder`, 13 words: `dex` = the wrapper
        Tok::WrapAsTrade(n) => abi_type(if of(n).starts_with("(bytes32") { "UATradeOrder" } else { "TradeOrder" }),
        Tok::Sign(s) => abi_type(sig_type(*s)),
    }
}

fn selector(entry: &str, plan: &[Tok], fields: &[(String, String)]) -> [u8; 4] {
    let args: Vec<String> = plan.iter().map(|t| tok_abi(t, fields)).collect();
    keccak256(format!("{entry}({})", args.join(",")))[..4].try_into().expect("4 bytes")
}

fn build() -> Vec<Row> {
    let mut rows = Vec::new();
    for (name, entry, contracts, f, plan) in TYPED {
        let fields = fields_of(f);
        let enveloped = fields.len() > ENV.len() && fields[fields.len() - ENV.len()..].iter().map(|x| x.1.as_str()).eq(ENV);
        let sig = if name.starts_with("UA") || name.starts_with("CancelUA") {
            Sig::Ua
        } else if *contracts == A {
            Sig::Account
        } else {
            Sig::Bytes
        };
        let plan: Vec<Tok> = if entry.is_empty() {
            vec![]
        } else if plan.is_empty() {
            let mid = fields[1..fields.len() - ENV.len()].iter().map(|x| Tok::Field(x.1.clone()));
            std::iter::once(Tok::Env).chain(mid).chain([Tok::Sign(sig)]).collect()
        } else {
            plan.split(' ').map(|t| tok(t, sig)).collect()
        };
        let s = selector(entry, &plan, &fields);
        let sent = match *name {
            "UARelayFee" => IMtxRelayFee::relayCall::SELECTOR,
            _ => s,
        };
        let sig = plan.iter().find_map(|t| match t {
            Tok::Sign(s) => Some(*s),
            Tok::List(x) => match **x {
                Tok::Sign(s) => Some(s),
                _ => None,
            },
            _ => None,
        });
        rows.push(Row { name, entry, contracts, fields, enveloped, typed: true, plan, sig, selector: s, sent });
    }
    for (entry, contracts, f) in PLAIN {
        let fields = fields_of(f);
        let plan: Vec<Tok> = fields.iter().map(|x| Tok::Field(x.1.clone())).collect();
        let s = selector(entry, &plan, &fields);
        rows.push(Row { name: entry, entry, contracts, fields, enveloped: false, typed: false, plan, sig: None, selector: s, sent: s });
    }
    rows
}

static ROWS: LazyLock<Vec<Row>> = LazyLock::new(build);
static NESTED_MAP: LazyLock<HashMap<&'static str, Vec<(String, String)>>> =
    LazyLock::new(|| NESTED.iter().map(|(n, f)| (*n, fields_of(f))).collect());

pub fn rows() -> &'static [Row] {
    &ROWS
}

/// The fields of a nested struct, `(type, name)`.
pub fn nested(ty: &str) -> Option<&'static Vec<(String, String)>> {
    NESTED_MAP.get(ty)
}

fn deps(fields: &[(String, String)], out: &mut BTreeSet<&'static str>) {
    for (t, _) in fields {
        let base = t.trim_end_matches("[]");
        if let Some((name, f)) = NESTED_MAP.get_key_value(base) {
            if out.insert(name) {
                deps(f, out);
            }
        }
    }
}

fn type_string(name: &str, fields: &[(String, String)]) -> String {
    let one = |n: &str, f: &[(String, String)]| {
        format!("{n}({})", f.iter().map(|(t, x)| format!("{t} {x}")).collect::<Vec<_>>().join(","))
    };
    let mut d = BTreeSet::new();
    deps(fields, &mut d);
    let mut s = one(name, fields);
    for n in d {
        s += &one(n, &NESTED_MAP[n]);
    }
    s
}

/// `encodeData` of one value: a nested struct by its hash, an array by the hash of its words, `bytes` by its keccak.
fn word(ty: &str, v: &Val) -> B256 {
    if let Some(el) = ty.strip_suffix("[]") {
        let a = v.as_array().expect("parsed as an array");
        return keccak256(a.iter().flat_map(|x| word(el, x).0).collect::<Vec<u8>>());
    }
    if let Some(f) = nested(ty) {
        return hash_tuple(ty, f, v.as_tuple().expect("parsed as a tuple"));
    }
    match v {
        Val::Bytes(b) => keccak256(b),
        other => B256::from_slice(&other.abi_encode()),
    }
}

fn pos(fields: &[(String, String)], n: &str) -> Option<usize> {
    fields.iter().position(|f| f.1 == n)
}

/// `hashStruct`: `MetaTxLib.canon` is here, one place for an envelope and a nested payment: a struct with `mode`, `relayer`
/// and `feeRecipient` hashes the fields its mode does not bind as 0.
fn hash_tuple(name: &str, fields: &[(String, String)], vals: &[Val]) -> B256 {
    let canon = match (pos(fields, "mode"), pos(fields, "relayer"), pos(fields, "feeRecipient")) {
        (Some(m), Some(r), Some(f)) => Some((vals[m].as_uint().map_or(0u32, |x| x.0.saturating_to()), r, f)),
        _ => None,
    };
    let mut buf = keccak256(type_string(name, fields)).to_vec();
    for (i, (ty, _)) in fields.iter().enumerate() {
        let unbound = canon.is_some_and(|(m, r, f)| {
            (i == r && m & MODE_RESTRICT_RELAYER == 0) || (i == f && m & MODE_RESTRICT_FEE_RECIPIENT == 0)
        });
        buf.extend(if unbound { B256::ZERO } else { word(ty, &vals[i]) });
    }
    keccak256(buf)
}

/// `msig` has at most 16 members (CTR-UA-09), so a `MemberSig[]` or an `InnerSig[]` has at most 16 slots. The two levels of the type bound the
/// depth of a decode; this bounds its width: the registry copies a list to memory before its first index check, 16 × 16 at most here.
const MSIG_MAX_SLOTS: usize = 16;

fn fixed(v: &[u8]) -> Val {
    let mut w = B256::ZERO;
    w[..v.len()].copy_from_slice(v);
    Val::FixedBytes(w, v.len())
}

/// One JSON value as its Solidity type, strictly: canonical decimal strings (small uints may be numbers), `0x`-hex of the
/// exact length, addresses of 20 bytes (a dirty word is refused here, never forwarded), every field of a struct and no other.
pub fn parse(ty: &str, j: &Value, path: &str) -> Result<Val> {
    let bad = |what: &str| anyhow!("BAD_PAYLOAD: {path}: {what}");
    let text = || j.as_str().ok_or_else(|| bad("not a string"));
    let hex = || -> Result<Vec<u8>> {
        let s = text()?.strip_prefix("0x").ok_or_else(|| bad("not 0x-hex"))?;
        alloy::hex::decode(s).map_err(|_| bad("not 0x-hex"))
    };
    if let Some(el) = ty.strip_suffix("[]") {
        let a = j.as_array().ok_or_else(|| bad("not an array"))?;
        if matches!(el, "MemberSig" | "InnerSig") && a.len() > MSIG_MAX_SLOTS {
            return Err(bad("more than 16 slots"));
        }
        let v: Result<Vec<Val>> = a.iter().enumerate().map(|(i, x)| parse(el, x, &format!("{path}[{i}]"))).collect();
        return Ok(Val::Array(v?));
    }
    if let Some(f) = nested(ty) {
        let o = j.as_object().ok_or_else(|| bad("not an object"))?;
        return Ok(Val::Tuple(take(f, o, path)?));
    }
    Ok(match ty {
        "address" => Val::Address(addr(text()?).map_err(|e| bad(&e.to_string()))?),
        "bool" => Val::Bool(j.as_bool().ok_or_else(|| bad("not a bool"))?),
        "bytes" => Val::Bytes(hex()?),
        _ => {
            if let Some(n) = ty.strip_prefix("bytes") {
                let b = hex()?;
                if n.parse() != Ok(b.len()) {
                    return Err(bad(&format!("not {ty}")));
                }
                fixed(&b)
            } else {
                let bits: usize = ty.strip_prefix("uint").and_then(|n| n.parse().ok()).ok_or_else(|| bad("unknown type"))?;
                let v = match j.as_u64() {
                    Some(n) if bits <= 32 => U256::from(n),
                    _ => uint(text()?).map_err(|e| bad(&e.to_string()))?,
                };
                if bits < 256 && v >> bits != U256::ZERO {
                    return Err(bad(&format!("above {ty}")));
                }
                Val::Uint(v, bits)
            }
        }
    })
}

fn take(fields: &[(String, String)], o: &Map<String, Value>, path: &str) -> Result<Vec<Val>> {
    if let Some(k) = o.keys().find(|k| pos(fields, k).is_none()) {
        bail!("BAD_PAYLOAD: {path}.{k}: unknown field");
    }
    fields.iter().map(|(t, n)| {
        let p = format!("{path}.{n}");
        parse(t, o.get(n).ok_or_else(|| anyhow!("BAD_PAYLOAD: {p}: missing"))?, &p)
    }).collect()
}

/// The inverse of [`parse`]: a value as the explicit JSON of its type.
pub fn to_json(ty: &str, v: &Val) -> Value {
    if let Some(el) = ty.strip_suffix("[]") {
        return Value::Array(v.as_array().unwrap_or_default().iter().map(|x| to_json(el, x)).collect());
    }
    if let Some(f) = nested(ty) {
        let t = v.as_tuple().unwrap_or_default();
        return Value::Object(f.iter().zip(t).map(|((ty, n), x)| (n.clone(), to_json(ty, x))).collect());
    }
    match v {
        Val::Address(a) => json!(format!("{a:#x}")),
        Val::Bool(b) => json!(b),
        Val::Bytes(b) => json!(format!("0x{}", alloy::hex::encode(b))),
        Val::FixedBytes(w, n) => json!(format!("0x{}", alloy::hex::encode(&w[..*n]))),
        Val::Uint(u, bits) if *bits <= 32 => json!(u.saturating_to::<u64>()),
        Val::Uint(u, _) => json!(u.to_string()),
        _ => Value::Null,
    }
}

/// A plain entry's calldata as its named op, `{entry, contract, token, args, validUntil}`: what the venue hands the client.
pub fn call_op(contract: &str, target: Address, data: &[u8], valid_until: &str) -> Result<Value> {
    let sel = data.get(..4).ok_or_else(|| anyhow!("no selector"))?;
    let row = rows().iter().find(|r| !r.typed && r.selector == sel && r.contracts.contains(&contract))
        .ok_or_else(|| anyhow!("no plain {contract} entry 0x{}", alloy::hex::encode(sel)))?;
    let args = decode_args(&row.fields, &data[4..])?;
    let mut op = json!({"entry": row.entry, "contract": contract, "token": format!("{target:#x}"), "args": args, "validUntil": valid_until});
    if rows().iter().filter(|r| r.entry == row.entry && r.contracts.contains(&contract)).count() > 1 {
        op["struct"] = json!(row.name);
    }
    Ok(op)
}

fn decode_args(fields: &[(String, String)], data: &[u8]) -> Result<Value> {
    let sig = format!("({})", fields.iter().map(|f| abi_type(&f.0)).collect::<Vec<_>>().join(","));
    let v = DynSolType::parse(&sig)?.abi_decode_sequence(data)?;
    let t = v.as_tuple().ok_or_else(|| anyhow!("not a tuple"))?;
    Ok(Value::Object(fields.iter().zip(t).map(|((ty, n), x)| (n.clone(), to_json(ty, x))).collect()))
}

/// One row's values, parsed once; the hash and the calldata below read only these.
#[derive(Debug)]
pub struct Assembled {
    vals: HashMap<String, Val>,
    sig: Option<Val>,
    pub struct_hash: Option<B256>,
    /// The entry's calldata (a relay fee's direct `mtxRelayFee`: the node sends the router's, [`router_call`]).
    pub data: Vec<u8>,
}

fn word_of(v: &Val) -> Option<B256> {
    match v {
        Val::Address(a) => Some(a.into_word()),
        Val::FixedBytes(w, 32) => Some(*w),
        _ => None,
    }
}

/// An unbound `relayer` is sent as 0, an unbound `feeRecipient` as this node's (R84, NODE-LANE-10): the digest ignores both.
fn normalize(fields: &[(String, String)], vals: &mut [Val], fee_recipient: Option<Address>) -> Result<()> {
    let (Some(m), Some(r), Some(f)) = (pos(fields, "mode"), pos(fields, "relayer"), pos(fields, "feeRecipient")) else { return Ok(()) };
    let mode: u32 = vals[m].as_uint().map_or(0, |x| x.0.saturating_to());
    check_mode(mode).map_err(|e| anyhow!("BAD_PAYLOAD: {e}"))?;
    if mode & MODE_RESTRICT_RELAYER == 0 {
        vals[r] = Val::Address(Address::ZERO);
    }
    if mode & MODE_RESTRICT_FEE_RECIPIENT == 0 {
        vals[f] = Val::Address(fee_recipient.unwrap_or(Address::ZERO));
    }
    Ok(())
}

fn emit(t: &Tok, row: &Row, a: &Assembled) -> Result<Val> {
    let get = |n: &str| a.vals.get(n).cloned().ok_or_else(|| anyhow!("BAD_PAYLOAD: {n}: missing"));
    Ok(match t {
        Tok::Env => {
            let mut e = vec![get("from")?];
            for n in ENV {
                e.push(get(n)?);
            }
            Val::Tuple(e)
        }
        Tok::Field(n) | Tok::Extra(n, _) => get(n)?,
        Tok::Group(g) => Val::Tuple(g.iter().map(|n| get(n)).collect::<Result<_>>()?),
        Tok::List(x) => Val::Array(vec![emit(x, row, a)?]),
        Tok::Whole => Val::Tuple(row.fields.iter().map(|f| get(&f.1)).collect::<Result<_>>()?),
        Tok::WrapAsTrade(n) => {
            let mut w = get(n)?.as_tuple().ok_or_else(|| anyhow!("wrap order"))?.to_vec();
            w.insert(7, w[1].clone());
            Val::Tuple(w)
        }
        Tok::Sign(_) => a.sig.clone().ok_or_else(|| anyhow!("BAD_PAYLOAD: no signature"))?,
    })
}

fn extras(row: &Row) -> Vec<(&str, &str)> {
    row.plan.iter().filter_map(|t| match t {
        Tok::Extra(n, ty) => Some((n.as_str(), ty.as_str())),
        _ => None,
    }).collect()
}

/// Reads `envelope`, `args` and the signature of a row, every field once, and builds what it signs and what it sends.
pub fn assemble(row: &Row, envelope: Option<&Value>, args: &Value, sig: Option<&Value>, fee_recipient: Option<Address>) -> Result<Assembled> {
    let a = args.as_object().ok_or_else(|| anyhow!("BAD_PAYLOAD: args is not an object"))?;
    let empty = Map::new();
    let e = match (row.enveloped, envelope) {
        (true, Some(e)) => e.as_object().ok_or_else(|| anyhow!("BAD_PAYLOAD: envelope is not an object"))?,
        (true, None) => bail!("BAD_PAYLOAD: {} needs an envelope", row.entry),
        (false, Some(_)) => bail!("BAD_PAYLOAD: {} takes no envelope", row.entry),
        (false, None) => &empty,
    };
    let in_env = |n: &str| row.enveloped && (n == "from" || ENV.contains(&n));
    let ext = extras(row);
    if let Some(k) = e.keys().find(|k| !in_env(k)) {
        bail!("BAD_PAYLOAD: envelope.{k}: unknown field");
    }
    if let Some(k) = a.keys().find(|k| in_env(k) || !(pos(&row.fields, k).is_some() || ext.iter().any(|x| x.0 == *k))) {
        if matches!(k.as_str(), "data" | "calldata") {
            bail!("HEX_DATA_REFUSED: args.{k}: {} takes explicit named fields", row.entry);
        }
        bail!("BAD_PAYLOAD: args.{k}: unknown field");
    }
    let mut vals: Vec<Val> = Vec::new();
    for (ty, n) in &row.fields {
        let (src, p) = if in_env(n) { (e.get(n), "envelope") } else { (a.get(n), "args") };
        let p = format!("{p}.{n}");
        vals.push(parse(ty, src.ok_or_else(|| anyhow!("BAD_PAYLOAD: {p}: missing"))?, &p)?);
    }
    if row.typed {
        normalize(&row.fields, &mut vals, fee_recipient)?;
    }
    if let Some(i) = pos(&row.fields, "payment") {
        let (pty, _) = &row.fields[i];
        if let Val::Tuple(t) = &mut vals[i] {
            normalize(&NESTED_MAP[pty.as_str()], t, fee_recipient)?;
        }
    }
    let struct_hash = row.typed.then(|| hash_tuple(row.name, &row.fields, &vals));
    let mut map: HashMap<String, Val> = row.fields.iter().map(|f| f.1.clone()).zip(vals).collect();
    for (n, ty) in ext {
        let p = format!("args.{n}");
        map.insert(n.to_string(), parse(ty, a.get(n).ok_or_else(|| anyhow!("BAD_PAYLOAD: {p}: missing"))?, &p)?);
    }
    let sig = match (row.sig, sig) {
        (Some(s), Some(v)) => Some(parse(sig_type(s), v, "signature")?),
        (None, None) => None,
        (Some(_), None) => bail!("BAD_PAYLOAD: {} without its signature", row.entry),
        (None, Some(_)) => bail!("BAD_PAYLOAD: {} takes its signature in args", row.entry),
    };
    let mut out = Assembled { vals: map, sig, struct_hash, data: Vec::new() };
    let params: Vec<Val> = row.plan.iter().map(|t| emit(t, row, &out)).collect::<Result<_>>()?;
    out.data = [&row.selector[..], &Val::Tuple(params).abi_encode_sequence().unwrap_or_default()].concat();
    Ok(out)
}

/// The relay-fee router's call of an assembled `RelayFee` / `UARelayFee` (CTR-MTX-27): `relay` / `uaRelay(target, callData,
/// token, from, payee, value, validUntil, sig)`.
pub fn router_call(row: &Row, a: &Assembled, target: Address, call_data: Bytes, token: Address) -> Result<Vec<u8>> {
    let tail = Val::Tuple(vec![
        Val::Address(target), Val::Bytes(call_data.to_vec()), Val::Address(token),
        a.vals["from"].clone(), a.vals["payee"].clone(), a.vals["value"].clone(), a.vals["validUntil"].clone(),
        a.sig.clone().ok_or_else(|| anyhow!("BAD_PAYLOAD: no signature"))?,
    ]);
    Ok([&row.sent[..], &tail.abi_encode_sequence().unwrap_or_default()].concat())
}

/// What the guard and the in-flight set need of a built op; made only with its calldata, in [`Op::parse`] or for the transfer
/// structs from the same parsed struct as the calldata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Typed {
    /// The contract kind (`domains.<kind>`): names the rule and the EIP-712 domain.
    pub contract: &'static str,
    /// The domain's `verifyingContract`: the target; a wrap order's underlying; a relay fee's fee token.
    pub domain_of: Address,
    /// `None`: a plain entry, no typed digest.
    pub struct_hash: Option<B256>,
    /// The struct `MetaTransactionExecuted` reports when it is not `struct_hash`: a receiver fee's payment.
    pub lane_hash: Option<B256>,
    /// `(native signer, signature)` when the signer is known here (the guard recovers a 65-byte one, any other length is the
    /// contract's); `None`: a derived UA, a member set, a key of an account.
    pub signer: Option<(Address, Bytes)>,
    /// A payment's payee as an id: never the relay-fee router or executor.
    pub payee: Option<B256>,
    /// Filled by `Chain`-side code from `digest_on` (`Work` is built without a chain).
    pub digest: Option<B256>,
    /// The subject (`from`, an order's, a payment's payer) is a derived UA: it signs merged entries only (B, `_uaAllowed`).
    pub derived_signer: bool,
    /// A derived `from` or `to` (the subject, a `to`, a payment's payer or payee): the token's UA ledger must be on (R44, step
    /// 7a); an all-native op runs at `registry() == 0` (R9).
    pub derived_side: bool,
}

impl Typed {
    /// The typed digest in the salted domain `(name, "1", chainId, domain_of, chain_uid)`, computed here, no chain view.
    pub fn digest_on(&self, chain_id: u64, chain_uid: B256) -> Option<B256> {
        self.hashed(self.struct_hash?, chain_id, chain_uid)
    }

    /// The digest the op's lane reports on chain, what `classify` compares: the payment's for a receiver fee.
    pub fn lane_digest_on(&self, chain_id: u64, chain_uid: B256) -> Option<B256> {
        self.hashed(self.lane_hash.or(self.struct_hash)?, chain_id, chain_uid)
    }

    fn hashed(&self, h: B256, chain_id: u64, chain_uid: B256) -> Option<B256> {
        let name = domain_name(self.contract)?;
        let sep = crate::dex::domain(name, chain_id, self.domain_of, chain_uid).separator();
        Some(keccak256([&[0x19, 0x01][..], sep.as_slice(), h.as_slice()].concat()))
    }
}

/// The 65-byte native signature `sig` recovers to `who` over `digest`.
pub fn recovers(digest: B256, sig: &[u8], who: Address) -> bool {
    Signature::from_raw(sig).ok().and_then(|s| s.recover_address_from_prehash(&digest).ok()) == Some(who)
}

/// `MandateWallet.mandatePayLane(entryRef)`.
pub fn mandate_pay_lane(entry_ref: &[u8]) -> U256 {
    U256::from_be_bytes(keccak256([&b"scaas.mandate.pay"[..], entry_ref].concat()).0)
}

/// `MandateWallet.mandateRevokeLane(token, epoch)`.
pub fn mandate_revoke_lane(token: Address, epoch: u64) -> U256 {
    U256::from_be_bytes(keccak256([&b"scaas.mandate.revoke"[..], token.as_slice(), &epoch.to_be_bytes()].concat()).0)
}

/// One op read: the target, the bytes sent and what was signed, from one parse.
#[derive(Debug)]
pub struct Op {
    pub row: &'static Row,
    pub to: Address,
    pub data: Bytes,
    pub typed: Typed,
    /// `(from as an id, batch, nonce)` of a nonce envelope: the subject the node reads back (R80).
    pub lane: Option<(B256, U256, U256)>,
    pub valid_until: u64,
}

const OP_KEYS: [&str; 10] = ["entry", "contract", "struct", "token", "envelope", "args", "signature", "auth", "call", "validUntil"];

fn find(entry: &str, contract: Option<&str>, name: Option<&str>) -> Result<(&'static Row, &'static str)> {
    let hits: Vec<&'static Row> = rows().iter()
        .filter(|r| !entry.is_empty() && r.entry == entry)
        .filter(|r| contract.is_none_or(|c| r.contracts.contains(&c)))
        .filter(|r| name.is_none_or(|n| r.name == n))
        .collect();
    match hits[..] {
        [] => bail!("UNKNOWN_ENTRY: {entry:?} (contract {contract:?}, struct {name:?}) is no named entry"),
        [r] => match (contract, r.contracts) {
            (Some(c), l) => Ok((r, l.iter().find(|x| **x == c).expect("filtered"))),
            (None, [c]) => Ok((r, c)),
            (None, _) => bail!("ENTRY_AMBIGUOUS: {entry} is on several contract kinds: name op.contract"),
        },
        _ => bail!("ENTRY_AMBIGUOUS: {entry} is several structs: name op.struct or op.contract"),
    }
}

impl Op {
    /// `op` as job-api.md: the only way a named entry reaches a lane or the gateway.
    pub fn parse(op: &Value, fee_recipient: Option<Address>) -> Result<Self> {
        if op.is_string() {
            return Err(hex_refused("op"));
        }
        let o = op.as_object().ok_or_else(|| anyhow!("BAD_PAYLOAD: op is not an object"))?;
        if o.get("call").is_some_and(Value::is_string) {
            return Err(hex_refused("op.call"));
        }
        for k in o.keys() {
            if matches!(k.as_str(), "data" | "calldata") {
                bail!("HEX_DATA_REFUSED: op.{k}: name the entry and its fields, the node builds the calldata");
            }
            if !OP_KEYS.contains(&k.as_str()) {
                bail!("BAD_PAYLOAD: op.{k}: unknown field");
            }
        }
        let text = |k: &str| o.get(k).map(|v| v.as_str().ok_or_else(|| anyhow!("BAD_PAYLOAD: op.{k} is not a string"))).transpose();
        let entry = text("entry")?.ok_or_else(|| anyhow!("BAD_PAYLOAD: op.entry missing"))?;
        let (row, contract) = find(entry, text("contract")?, text("struct")?)?;
        let token = addr(text("token")?.ok_or_else(|| anyhow!("BAD_PAYLOAD: op.token missing"))?).map_err(|e| anyhow!("BAD_PAYLOAD: op.token: {e}"))?;
        let empty = json!({});
        let mut args = o.get("args").unwrap_or(&empty).clone();
        let sig = o.get(if row.sig == Some(Sig::Bytes) { "signature" } else { "auth" });
        if o.contains_key(if row.sig == Some(Sig::Bytes) { "auth" } else { "signature" }) {
            bail!("BAD_PAYLOAD: {entry} takes its signature as {}", if row.sig == Some(Sig::Bytes) { "signature" } else { "auth" });
        }
        let inner = match (row.relay_fee(), o.get("call")) {
            (true, Some(c)) => {
                if args.get("target").is_some() || args.get("callDataHash").is_some() {
                    bail!("BAD_PAYLOAD: args.target and args.callDataHash come from op.call");
                }
                // no `fee_recipient`: the payer hashed these bytes (`callDataHash`), the lane must not rewrite them; an unbound
                // `relayer` / `feeRecipient` of the inner call goes as 0, which is what the client hashes (job-api.md §5.3)
                let c = Op::parse(c, None)?;
                if c.row.relay_fee() {
                    bail!("BAD_PAYLOAD: a relay fee does not relay a relay fee");
                }
                args["target"] = json!(format!("{:#x}", c.to));
                args["callDataHash"] = json!(format!("{:#x}", keccak256(&c.data)));
                Some(c)
            }
            (true, None) => bail!("BAD_PAYLOAD: a relay fee needs op.call"),
            (false, Some(_)) => bail!("BAD_PAYLOAD: {entry} takes no op.call"),
            (false, None) => None,
        };
        let a = assemble(row, o.get("envelope"), &args, sig, fee_recipient)?;
        let (data, to) = match &inner {
            Some(c) => {
                let router = a.vals["relayer"].as_address().expect("address");
                (router_call(row, &a, c.to, c.data.clone(), token)?, router)
            }
            None => (a.data.clone(), token),
        };
        let valid_until = deadline(o, &a)?;
        let at = |t: &Val, i: usize| t.as_tuple().and_then(|x| x.get(i).cloned());
        let order = a.vals.get("order");
        // who signed: `from`, `ua`, the order's `from` (a `DexOrder`'s inner order), the payment's payee
        let order_from = order.and_then(|t| match at(t, 0) {
            Some(x @ (Val::Address(_) | Val::FixedBytes(..))) if row.name != "CancelDexOrder" => Some(x),
            _ => at(t, 1).and_then(|x| at(&x, 0)),
        });
        let who = a.vals.get("from").cloned().or_else(|| a.vals.get("ua").filter(|_| !row.enveloped).cloned())
            .or_else(|| order_from.clone())
            .or_else(|| a.vals.get("payment").and_then(|p| at(p, 1)));
        let native_sig = match (row.sig, a.sig.as_ref()) {
            (Some(Sig::Bytes), Some(Val::Bytes(b))) => Some(Bytes::from(b.clone())),
            (Some(Sig::Ua), Some(Val::Tuple(t))) if t[0] == Val::Bytes(vec![]) && t[2] == Val::Array(vec![]) =>
                t[1].as_bytes().map(|b| Bytes::from(b.to_vec())),
            _ => None,
        };
        let signer = who.as_ref().and_then(word_of).and_then(|w| native(&w)).zip(native_sig);
        let payee = a.vals.get("payment").and_then(|p| at(p, 1)).as_ref().and_then(word_of);
        // R44 / B: which sides are derived ids (an address is native by type)
        let derived = |v: Option<Val>| v.as_ref().and_then(word_of).is_some_and(|w| native(&w).is_none());
        let derived_signer = derived(a.vals.get("from").cloned()) || derived(order_from)
            || derived(a.vals.get("payment").and_then(|p| at(p, 0)));
        let derived_side = derived_signer || derived(a.vals.get("to").cloned()) || payee.is_some_and(|w| native(&w).is_none());
        let lane_hash = pos(&row.fields, "payment").and_then(|i| {
            let ty = row.fields[i].0.as_str();
            Some(hash_tuple(ty, nested(ty)?, a.vals["payment"].as_tuple()?))
        });
        let lane = if row.enveloped { lane_of(&a.vals) } else { a.vals.get("payment").and_then(payment_lane) };
        if matches!(row.name, "UAPayUnderMandate" | "UADelegateRevoke") {
            mandate_shape(row, &a)?;
        }
        let domain_of = match extras(row).iter().any(|x| x.0 == "underlying") {
            true => a.vals["underlying"].as_address().expect("address"),
            false => token,
        };
        let typed = Typed { contract, domain_of, struct_hash: a.struct_hash, lane_hash, signer, payee, digest: None, derived_signer, derived_side };
        Ok(Op { row, to, data: data.into(), typed, lane, valid_until })
    }
}

/// `UAPayUnderMandate` on `mandatePayLane(entryRef)`, `UADelegateRevoke` on `mandateRevokeLane(token, epoch)`, both nonce 0 (C5 review):
/// a revoke is the kill switch, it must not queue behind a pending nonce on a shared lane.
fn mandate_shape(row: &Row, a: &Assembled) -> Result<()> {
    let u = |n: &str| a.vals[n].as_uint().map_or(U256::ZERO, |x| x.0);
    let lane = if row.name == "UAPayUnderMandate" {
        mandate_pay_lane(a.vals["entryRef"].as_fixed_bytes().map_or(&[][..], |x| x.0))
    } else {
        mandate_revoke_lane(a.vals["token"].as_address().expect("address"), u("epoch").saturating_to())
    };
    if u("batch") != lane || u("nonce") != U256::ZERO {
        bail!("MANDATE_LANE: {} runs on its own lane at nonce 0 (batch {lane})", row.name);
    }
    Ok(())
}

fn lane_of(v: &HashMap<String, Val>) -> Option<(B256, U256, U256)> {
    Some((word_of(v.get("from")?)?, v.get("batch")?.as_uint()?.0, v.get("nonce")?.as_uint()?.0))
}

fn payment_lane(p: &Val) -> Option<(B256, U256, U256)> {
    let t = p.as_tuple()?;
    Some((word_of(&t[0])?, t[4].as_uint()?.0, t[5].as_uint()?.0))
}

/// A job's deadline: what the chain enforces on the op (the envelope, a fee's, the sooner of a receiver fee and its payment)
/// and `op.validUntil`, the job's own, whichever comes first: a job deadline narrows a signed one, never extends it. A cancel
/// has no enforced deadline, so its order's `validUntil` is used only when the job names none.
fn deadline(o: &Map<String, Value>, a: &Assembled) -> Result<u64> {
    let job = o.get("validUntil").map(|v| {
        let s = v.as_str().ok_or_else(|| anyhow!("BAD_PAYLOAD: op.validUntil is not a string"))?;
        uint(s).map_err(|e| anyhow!("BAD_PAYLOAD: op.validUntil: {e}"))
    }).transpose()?;
    let nested = |k: &str, i: usize| a.vals.get(k).and_then(|t| t.as_tuple()).and_then(|t| t.get(i)).and_then(|v| v.as_uint()).map(|x| x.0);
    let own = a.vals.get("validUntil").and_then(|v| v.as_uint()).map(|x| x.0);
    let enforced = own.into_iter().chain(nested("payment", 6)).min();
    let t = match (enforced, job) {
        (Some(x), Some(y)) => x.min(y),
        (Some(x), None) | (None, Some(x)) => x,
        (None, None) => nested("order", 12).or(nested("order", 11)).ok_or_else(|| anyhow!("BAD_PAYLOAD: op.validUntil missing"))?,
    };
    Ok(t.saturating_to())
}

/// Hex `data` / `calldata` outside a named field: the name of the refusal every job kind and the gateway share.
pub fn hex_refused(what: &str) -> anyhow::Error {
    anyhow!("HEX_DATA_REFUSED: {what}: send a named op, the node builds the calldata")
}

#[cfg(test)]
pub mod testkit {
    use super::*;

    pub fn vectors() -> Value {
        // ua-mtx-merge T14: the regenerated rows (MD-7 as amended: 68 structs; T34: 76); the old ones are in the vectors' legacy place
        serde_json::from_str(include_str!("../../smartcontracts/vectors/typed/typed_ops.json")).unwrap()
    }

    pub fn row_of(name: &str, contract: &str) -> &'static Row {
        rows().iter().find(|r| r.typed && r.name == name && r.contracts.contains(&contract))
            .unwrap_or_else(|| panic!("no row {name} on {contract}"))
    }

    /// `(envelope, args, signature value)` of a vector row, as a client sends them.
    pub fn split(row: &Row, name: &str, kind: &str, v: &Value) -> (Option<Value>, Value, Option<Value>) {
        let o = &v["ops"][name];
        let d = &o["domains"][kind];
        let mut args = o["message"].as_object().unwrap().clone();
        let mut env = Map::new();
        if row.enveloped {
            for k in ["from"].into_iter().chain(ENV) {
                env.insert(k.to_string(), args.remove(k).unwrap());
            }
        }
        if let Some(x) = d.get("extra").and_then(Value::as_object) {
            args.extend(x.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        if row.name == "UAReceiverFee" {
            let s = args["payerSig"].clone();
            args.insert("payerSig".into(), json!({"keyData": "0x", "signature": s, "members": []}));
        }
        if extras(row).iter().any(|x| x.0 == "underlying") {
            args.insert("underlying".into(), d["domain"]["verifyingContract"].clone());
        }
        let s = d["signature"].clone();
        let sig = row.sig.map(|k| match k {
            Sig::Bytes => s.clone(),
            Sig::Ua => json!({"keyData": "0x", "signature": s, "members": []}),
            Sig::Account => json!({"keyIndex": "0", "proof": [], "signature": s}),
        });
        (row.enveloped.then_some(Value::Object(env)), Value::Object(args), sig)
    }

    /// A vector row as a job's `op`; `None`: no entry (`PqzAuth`) or the router's rows (`relay_fee_call_object`).
    pub fn op_of(name: &str, kind: &str, v: &Value) -> Option<Value> {
        let row = row_of(name, kind);
        if row.entry.is_empty() || row.relay_fee() {
            return None;
        }
        let (env, args, sig) = split(row, name, kind, v);
        let d = &v["ops"][name]["domains"][kind];
        let mut op = json!({"entry": row.entry, "contract": kind, "struct": row.name,
            "token": d["domain"]["verifyingContract"], "args": args, "validUntil": "1800000300"});
        if let Some(e) = env {
            op["envelope"] = e;
        }
        if let Some(s) = sig {
            op[if row.sig == Some(Sig::Bytes) { "signature" } else { "auth" }] = s;
        }
        Some(op)
    }

    /// The calldata read back into the op that built it, by the row's plan alone (the digest-only fields stay out).
    pub fn op_from_calldata(row: &Row, data: &[u8]) -> (Option<Value>, Value, Option<Value>) {
        let tys: Vec<String> = row.plan.iter().map(|t| tok_abi(t, &row.fields)).collect();
        let v = DynSolType::parse(&format!("({})", tys.join(","))).unwrap().abi_decode_sequence(&data[4..]).unwrap();
        let vals = v.as_tuple().unwrap();
        let (mut env, mut args, mut sig) = (Map::new(), Map::new(), None);
        let ty_of = |n: &str| row.fields.iter().find(|f| f.1 == n).unwrap().0.clone();
        for (t, x) in row.plan.iter().zip(vals) {
            let list0 = |x: &Val| x.as_array().unwrap()[0].clone();
            match t {
                Tok::Env => {
                    let e = x.as_tuple().unwrap();
                    env.insert("from".into(), to_json(&row.fields[0].0, &e[0]));
                    for (i, n) in ENV.iter().enumerate() {
                        env.insert(n.to_string(), to_json(&ty_of(n), &e[i + 1]));
                    }
                }
                Tok::Field(n) => { args.insert(n.clone(), to_json(&ty_of(n), x)); }
                Tok::Extra(n, ty) => { args.insert(n.clone(), to_json(ty, x)); }
                Tok::Group(g) => for (n, y) in g.iter().zip(x.as_tuple().unwrap()) {
                    args.insert(n.clone(), to_json(&ty_of(n), y));
                },
                Tok::Whole => for ((ty, n), y) in row.fields.iter().zip(x.as_tuple().unwrap()) {
                    args.insert(n.clone(), to_json(ty, y));
                },
                Tok::WrapAsTrade(n) => {
                    let mut w = x.as_tuple().unwrap().to_vec();
                    assert_eq!(w.remove(7), w[1], "dex = the wrapper");
                    args.insert(n.clone(), to_json(&ty_of(n), &Val::Tuple(w)));
                }
                Tok::List(b) => match &**b {
                    Tok::Field(n) => { args.insert(n.clone(), to_json(&ty_of(n), &list0(x))); }
                    _ => sig = Some(to_json("bytes", &list0(x))),
                },
                Tok::Sign(s) => sig = Some(to_json(sig_type(*s), x)),
            }
        }
        (row.enveloped.then_some(Value::Object(env)), Value::Object(args), sig)
    }

    pub fn hex(s: &Value) -> Vec<u8> {
        alloy::hex::decode(&s.as_str().unwrap()[2..]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    const FEE: Option<Address> = None;

    fn domain_of(d: &Value) -> (u64, Address, B256) {
        let g = |k: &str| d["domain"][k].as_str().unwrap();
        (g("chainId").parse().unwrap(), g("verifyingContract").parse().unwrap(), g("salt").parse().unwrap())
    }

    fn typed(contract: &'static str, domain_of: Address, h: B256) -> Typed {
        Typed { contract, domain_of, struct_hash: Some(h), lane_hash: None, signer: None, payee: None, digest: None, derived_signer: false, derived_side: false }
    }

    /// Every row and domain of `typed_ops.json`: encodeType, struct hash, digest, entry selector, calldata; the signature
    /// recovers to the vector's key over the node's digest. Counted, so a row the walk skips fails here.
    #[test]
    fn typed_ops_kat_every_entry() {
        let v = vectors();
        let key: Address = v["key"]["address"].as_str().unwrap().parse().unwrap();
        let (mut structs, mut domains, mut calldata) = (0, 0, 0);
        for (name, o) in v["ops"].as_object().unwrap() {
            structs += 1;
            for (kind, d) in o["domains"].as_object().unwrap() {
                let row = row_of(name, kind);
                let (env, args, sig) = split(row, name, kind, &v);
                assert_eq!(row.type_string(), o["typeString"].as_str().unwrap(), "{name}");
                let a = assemble(row, env.as_ref(), &args, sig.as_ref(), FEE).unwrap_or_else(|e| panic!("{name} on {kind}: {e:#}"));
                let h = a.struct_hash.unwrap();
                assert_eq!(format!("{h:#x}"), o["structHash"].as_str().unwrap(), "{name}");
                let (chain_id, at, uid) = domain_of(d);
                let contract = row.contracts.iter().find(|c| *c == kind).unwrap();
                let digest = typed(contract, at, h).digest_on(chain_id, uid).unwrap();
                assert_eq!(format!("{digest:#x}"), d["digest"].as_str().unwrap(), "{name} on {kind}");
                assert!(recovers(digest, &hex(&d["signature"]), key), "{name} on {kind}");
                domains += 1;
                if row.entry.is_empty() {
                    continue;
                }
                assert_eq!(format!("0x{}", alloy::hex::encode(row.selector)), d["selector"].as_str().unwrap(), "{name} on {kind}: {}", d["abi"]);
                assert_eq!(alloy::hex::encode(&a.data), &d["calldata"].as_str().unwrap()[2..], "{name} on {kind}: {}", d["abi"]);
                calldata += 1;
            }
        }
        // plan T34: (68, 101, 100) -> (76, 109, 108), the router's eight regulated controls' vector rows
        assert_eq!((structs, domains, calldata), (76, 109, 108), "every row was walked");
        // plan T32: 70 -> 78, the router's eight regulated controls (their vector rows plan T34's)
        assert_eq!(rows().iter().filter(|r| r.typed).count(), 78, "76 vector rows, the two invalidations (DEX, token)");
        assert_eq!(rows().iter().filter(|r| !r.typed).count(), 18, "the wallet's three flat builders are gone (MD-11 (a))");
    }

    /// ua-mtx-merge T14 (Q2, R19): the `mtxCancelNonce` row is per kind: the ordered `UACancelNonce` (`bytes32 from`, `UASig`) on the
    /// three token domains, the mandate wallet and the router; `CancelNonce` (`address from`, `bytes`) on `SmartKeyAccount` only.
    #[test]
    fn cancel_row_split_per_kind() {
        let on = |kind: &str| rows().iter().filter(|r| r.entry == "mtxCancelNonce" && r.contracts.contains(&kind)).map(|r| r.name).collect::<Vec<_>>();
        for k in ["token", "zether", "pqz", "wallet", "gov_router"] {
            assert_eq!(on(k), ["UACancelNonce"], "{k}");
        }
        assert_eq!(on("account"), ["CancelNonce"]);
        assert!(on("dex").is_empty() && on("registry").is_empty());
        let (ua, a) = (row_of("UACancelNonce", "token"), row_of("CancelNonce", "account"));
        assert_eq!((ua.fields[0].0.as_str(), ua.sig, ua.ua()), ("bytes32", Some(Sig::Ua), true));
        assert_eq!((a.fields[0].0.as_str(), a.sig, a.ua()), ("address", Some(Sig::Bytes), false));
    }

    /// ua-mtx-merge T14 (R12, R38): `mtxInvalidateNonces` per kind: the token's on ids (`bytes32 from`, `UASig`), the DEX's on addresses
    /// (`address from`, `bytes`); one entry name, two rows, never the other kind's.
    #[test]
    fn invalidate_row_split_per_kind() {
        let on = |kind: &str| rows().iter().filter(|r| r.entry == "mtxInvalidateNonces" && r.contracts.contains(&kind)).map(|r| r.name).collect::<Vec<_>>();
        for k in ["token", "zether", "pqz"] {
            assert_eq!(on(k), ["UAInvalidateNonces"], "{k}");
        }
        assert_eq!(on("dex"), ["InvalidateNonces"]);
        let (t, d) = (row_of("UAInvalidateNonces", "token"), row_of("InvalidateNonces", "dex"));
        assert_eq!((t.fields[0].0.as_str(), t.sig), ("bytes32", Some(Sig::Ua)));
        assert_eq!((d.fields[0].0.as_str(), d.sig), ("address", Some(Sig::Bytes)));
        let cast = |s: &str| -> [u8; 4] { keccak256(s)[..4].try_into().unwrap() };
        assert_eq!(t.selector, cast("mtxInvalidateNonces(bytes32,uint256,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))"));
        assert_eq!(d.selector, cast("mtxInvalidateNonces(address,uint256,uint256,bytes)"));
    }

    /// Regulated-kinds spec §3.1, §7 (plan T35): the router's eight control rows are the ops `scaas_ua::regulated` signs, each way
    /// — the same `UA<Op>` type string (`UAOperatorTransfer` with `account`, CTR-GOV-20), the entry `mtx<Op>`, a merged `UASig`
    /// entry with an envelope on `gov_router` alone, and a `typed_ops.json` row in the router's domain; no other `gov_router` row
    /// is a regulated control, and none of the eight is a row of a token kind (the direct controls are `BIT` entries).
    #[test]
    fn router_control_rows() {
        use scaas_ua::regulated::{type_string as ua_type, REGULATED_OPS};
        let v = vectors();
        for (op, _) in REGULATED_OPS {
            let r = row_of(op, "gov_router");
            assert_eq!(r.type_string(), ua_type(op).unwrap(), "{op}");
            assert_eq!(r.entry, format!("mtx{}", &op[2..]), "{op}");
            assert_eq!(r.contracts, ["gov_router"], "{op}: the router's alone");
            assert!(r.ua() && r.enveloped && r.sig == Some(Sig::Ua), "{op}");
            assert!(v["ops"][op]["domains"]["gov_router"].is_object(), "{op}: no typed_ops.json row");
        }
        let controls = ["mtxFreeze", "mtxUnfreeze", "mtxForceTransfer", "mtxPause", "mtxUnpause", "mtxRecordOrder", "mtxRevokeOrder",
            "mtxOperatorTransfer"];
        let ours: BTreeSet<&str> = rows().iter().filter(|r| controls.contains(&r.entry)).map(|r| r.name).collect();
        assert_eq!(ours, REGULATED_OPS.iter().map(|(n, _)| *n).collect(), "the router's control rows, both directions");
        assert_eq!(row_of("UAOperatorTransfer", "gov_router").fields[2], ("bytes32".into(), "account".into()));
    }

    /// The selectors a list of `MandateWallet.sol` names, read from its source: `X.selector` (its last segment) and the `_REVOKE_*`
    /// constants, in the body of `function <f>` (to its closing brace at four spaces).
    fn wallet_list(src: &str, f: &str) -> BTreeSet<String> {
        let i = src.find(f).unwrap_or_else(|| panic!("{f}"));
        let body = &src[i..i + src[i..].find("\n    }\n").unwrap()];
        let ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.';
        body.split(|c: char| !ident(c)).filter_map(|t| match t.strip_suffix(".selector") {
            Some(x) => x.rsplit('.').next().map(str::to_string),
            None => t.starts_with("_REVOKE_").then(|| t.to_string()),
        }).collect()
    }

    /// Q6 / MD-11 (d), both directions against the wallet's own lists: every wallet row is a merged `UA<Op>` entry (`ua_metatx`, `UASig`,
    /// `bytes32 from`) whose operation is on `mtxSelectors()` (`_mtxRule`, a native subject), and every row but the cancel on `_uaAllowed`
    /// (a derived subject, B); every operation on either list has its row. No address row and no plain row is left on the wallet.
    #[test]
    fn wallet_rows_are_ua_structs() {
        let src = std::fs::read_to_string(format!("{}/../smartcontracts/evm/src/wallet/MandateWallet.sol", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let (native, derived) = (wallet_list(&src, "function mtxSelectors()"), wallet_list(&src, "function _uaAllowed("));
        assert_eq!(native.len(), 7, "{native:?}");
        // the row's operation: what `mtx<Op>` self-calls (`MandateWallet.sol`); the cancel bumps the lane itself
        let op_of_row = |n: &str| match n {
            "UAPayUnderMandate" => "payUnderMandate",
            "UADelegateRevoke" => "_REVOKE_SIGNED",
            "UASetMandate" => "setMandate",
            "UASetPayee" => "setPayee",
            "UARevokeMandate" => "_REVOKE_OWNER",
            "UAExecute" => "execute",
            "UACancelNonce" => "cancelNonce",
            other => panic!("{other}: a wallet row the wallet does not list"),
        };
        let wallet: Vec<&Row> = rows().iter().filter(|r| !r.entry.is_empty() && r.contracts.contains(&"wallet")).collect();
        for r in &wallet {
            assert!(r.typed && r.ua() && r.enveloped && r.sig == Some(Sig::Ua) && r.fields[0] == ("bytes32".into(), "from".into()), "{}", r.name);
        }
        let ops = |skip: &str| wallet.iter().filter(|r| r.name != skip).map(|r| op_of_row(r.name).to_string()).collect::<BTreeSet<_>>();
        assert_eq!(ops(""), native, "_mtxRule, both directions");
        assert_eq!(ops("UACancelNonce"), derived, "_uaAllowed, both directions");
        assert_eq!(wallet.len(), 7);
    }

    /// MD-11 (a): the wallet's flat builders and `mtxExecuteAsOwner(Raw)` are second entries of operations that have their named entry:
    /// no row, refused by name, never built. The account keeps `mtxExecuteAsOwner`.
    #[test]
    fn wallet_flat_builders_refused_by_name() {
        let w = format!("{:#x}", Address::repeat_byte(0x77));
        let z = format!("{:#x}", Address::ZERO);
        let s = format!("0x{}", "11".repeat(65));
        let err = |op: Value| Op::parse(&op, FEE).unwrap_err().to_string();
        let flat = json!({"token": z, "payee": z, "amount": "5", "entryRef": format!("{:#x}", B256::repeat_byte(1)), "epoch": "2", "validUntil": "1800000300", "sig": s});
        assert!(err(json!({"entry": "mtxPayUnderMandate", "struct": "mtxPayUnderMandate", "token": w, "args": flat})).starts_with("UNKNOWN_ENTRY"));
        assert!(err(json!({"entry": "mtxPayUnderMandate", "token": w, "args": flat})).contains("needs an envelope"), "the named entry's shape");
        assert!(err(json!({"entry": "mtxRevoke", "token": w, "args": {"token": z, "epoch": "2", "validUntil": "1800000300", "sig": s}})).starts_with("UNKNOWN_ENTRY"));
        let own = |entry: &str, contract: &str| json!({"entry": entry, "contract": contract, "token": w,
            "args": {"data": "0x", "nonce": "0", "validUntil": "1800000300", "sig": s}});
        assert!(err(own("mtxExecuteAsOwnerRaw", "wallet")).starts_with("UNKNOWN_ENTRY"));
        assert!(err(own("mtxExecuteAsOwner", "wallet")).starts_with("UNKNOWN_ENTRY"));
        Op::parse(&own("mtxExecuteAsOwner", "account"), FEE).unwrap();
        assert!(rows().iter().all(|r| r.typed || !r.contracts.contains(&"wallet")), "no plain wallet row");
    }

    /// `SmartKeyAccount` keeps its address entries (Q6): `Envelope` with `address from`, `AccountSig` (the cancel: `bytes`), a `metatx`
    /// job; `mtxExecuteAsOwner` on the account only; none of its structs on another kind.
    #[test]
    fn account_keeps_address_rows() {
        let acct: BTreeSet<&str> = rows().iter().filter(|r| r.contracts.contains(&"account")).map(|r| r.name).collect();
        assert_eq!(acct, ["AddKey", "CancelNonce", "CancelRecovery", "Execute", "RemoveKey", "RotateKey", "SetGuardian", "mtxExecuteAsOwner"]
            .into_iter().collect());
        for r in rows().iter().filter(|r| r.contracts.contains(&"account")) {
            assert_eq!(r.contracts, ["account"], "{}: the account's alone", r.name);
            assert!(!r.ua(), "{}", r.name);
            if r.typed {
                assert_eq!(r.fields[0], ("address".into(), "from".into()), "{}", r.name);
                assert_eq!(r.sig, Some(if r.name == "CancelNonce" { Sig::Bytes } else { Sig::Account }), "{}", r.name);
            }
        }
    }

    /// One parse, two outputs: every field of every op moves the digest exactly when it moves the bytes sent (an unbound
    /// `relayer` / `feeRecipient` moves neither), and the bytes read back parse to the same digest. The two digest-only fields
    /// are named, and they are why the in-flight key is held with the bytes.
    #[test]
    fn digest_and_calldata_cannot_diverge() {
        let v = vectors();
        fn leaves(j: &Value, at: String, out: &mut Vec<String>) {
            match j {
                Value::Object(o) => o.iter().for_each(|(k, x)| leaves(x, format!("{at}/{k}"), out)),
                Value::Array(a) => a.iter().enumerate().for_each(|(i, x)| leaves(x, format!("{at}/{i}"), out)),
                _ => out.push(at),
            }
        }
        fn nudge(j: &Value) -> Value {
            match j {
                Value::Bool(b) => json!(!b),
                Value::Number(n) => json!(n.as_u64().unwrap() ^ 1),
                Value::String(s) if s.starts_with("0x") && s.len() > 2 => {
                    let mut c: Vec<char> = s.chars().collect();
                    let l = c.len() - 1;
                    c[l] = if c[l] == '0' { '1' } else { '0' };
                    json!(c.into_iter().collect::<String>())
                }
                Value::String(s) if s == "0x" => json!("0x00"),
                Value::String(s) => json!(uint(s).unwrap().saturating_add(U256::from(1)).to_string()),
                x => x.clone(),
            }
        }
        let mut walked = 0;
        for (name, o) in v["ops"].as_object().unwrap() {
            for kind in o["domains"].as_object().unwrap().keys() {
                let Some(mut op) = op_of(name, kind, &v) else { continue };
                let row = row_of(name, kind);
                if name == "UAPayUnderMandate" || name == "UADelegateRevoke" {
                    continue; // their lanes: `mandate_ops_run_on_their_own_lane_at_nonce_zero`
                }
                let base = Op::parse(&op, FEE).unwrap_or_else(|e| panic!("{name}: {e:#}"));
                let (env, args, sig) = op_from_calldata(row, &base.data);
                assert_eq!(env.as_ref(), op.get("envelope"), "{name}");
                let mut back = args.as_object().unwrap().clone();
                for (k, x) in op["args"].as_object().unwrap() {
                    if k == "accSeq" || k == "modeNonce" {
                        back.insert(k.clone(), x.clone());
                    }
                }
                assert_eq!(Value::Object(back).to_string().to_lowercase(), op["args"].to_string().to_lowercase(), "{name} args from the bytes");
                assert_eq!(sig.as_ref(), op.get("signature").or(op.get("auth")), "{name} signature from the bytes");
                // what the entry takes unsigned moves the bytes alone, by definition: `pqzAuth`, `ownerSig`, `payerSig`, `underlying`
                let unsigned = extras(row);
                let mut ls = Vec::new();
                for (k, part) in [("envelope", op.get("envelope")), ("args", op.get("args"))] {
                    let Some(Value::Object(o)) = part else { continue };
                    o.iter().filter(|(n, _)| !unsigned.iter().any(|x| x.0 == n.as_str()))
                        .for_each(|(n, x)| leaves(x, format!("/{k}/{n}"), &mut ls));
                }
                for l in ls {
                    let saved = op.pointer(&l).unwrap().clone();
                    *op.pointer_mut(&l).unwrap() = nudge(&saved);
                    let moved = Op::parse(&op, FEE);
                    *op.pointer_mut(&l).unwrap() = saved;
                    // a nudge the parser refuses (a mode bit) sends nothing
                    let Ok(m) = moved else { continue };
                    walked += 1;
                    let digest_only = matches!(row.name, "ZetherRollOver" | "ZetherSetRollOverMode") && m.data == base.data;
                    assert!(digest_only || (m.typed.struct_hash != base.typed.struct_hash) == (m.data != base.data),
                        "{name}: {l} moved one output only");
                }
            }
        }
        assert!(walked > 1_200, "{walked}"); // 1,238 leaves over the 68 merged rows (ua-mtx-merge T14; 1,500 over the 112 before)
    }

    /// Nested `msig` (spec 2026-11-02-msig-nested): a slot is `{index, members: [{index, sig}], sig}`. The old `keyData` and a list under an
    /// inner slot are refused by the type: its two levels are the depth bound of the decode, the parse recurses over the type, not the JSON.
    #[test]
    fn member_sig_json_is_two_levels() {
        let good = json!({"index": 0, "members": [{"index": 1, "sig": "0x01"}], "sig": "0x"});
        assert_eq!(to_json("MemberSig", &parse("MemberSig", &good, "s").unwrap()), good);
        let flat = json!({"index": 3, "members": [], "sig": "0xab"});
        assert_eq!(to_json("MemberSig", &parse("MemberSig", &flat, "s").unwrap()), flat);
        let err = |j: &Value| parse("MemberSig", j, "s").unwrap_err().to_string();
        assert_eq!(err(&json!({"index": 0, "keyData": "0x", "sig": "0x"})), "BAD_PAYLOAD: s.keyData: unknown field");
        assert_eq!(err(&json!({"index": 0, "members": [{"index": 0, "members": [], "sig": "0x"}], "sig": "0x"})),
            "BAD_PAYLOAD: s.members[0].members: unknown field");
        assert_eq!(err(&json!({"index": 0, "members": "0x", "sig": "0x"})), "BAD_PAYLOAD: s.members: not an array", "a packed list");
        let mut deep = json!({"index": 0, "sig": "0x"});
        for _ in 0..100_000 {
            let mut o = Map::new();
            o.insert("index".into(), json!(0));
            o.insert("members".into(), Value::Array(vec![deep]));
            o.insert("sig".into(), json!("0x"));
            deep = Value::Object(o);
        }
        assert!(err(&deep).ends_with("unknown field"), "a hostile depth stops at the type's");
        std::mem::forget(deep); // serde_json's drop recurses over the 100,000 levels
    }

    /// At most 16 slots at each level (`msig` has 16 members), checked before the elements are read: a list past that can only be refused on
    /// chain, after its calldata was copied to memory.
    #[test]
    fn member_sig_lists_are_bounded() {
        let inner = |n: usize| Value::Array((0..n).map(|i| json!({"index": i, "sig": "0x"})).collect());
        let outer = |n: usize, l: Value| Value::Array((0..n).map(|i| json!({"index": i, "members": l, "sig": "0x"})).collect());
        parse("MemberSig[]", &outer(16, inner(16)), "m").unwrap();
        let err = |j: Value| parse("MemberSig[]", &j, "m").unwrap_err().to_string();
        assert_eq!(err(outer(17, inner(0))), "BAD_PAYLOAD: m: more than 16 slots");
        assert_eq!(err(outer(1, inner(17))), "BAD_PAYLOAD: m[0].members: more than 16 slots");
        let bad = Value::Array(vec![json!("not a slot"); 17]);
        assert_eq!(err(bad), "BAD_PAYLOAD: m: more than 16 slots", "before any element is read");
    }

    /// The typed bytes a job builds are `abi.encode(MemberSig[])`, the stored form, nested too, and a blob that claims more than it holds
    /// is an error, not a walk: `abi_decode` follows the same two levels.
    #[test]
    fn nested_sig_bytes_are_the_stored_form() {
        use alloy::sol_types::SolValue;
        let slots = json!([{"index": 0, "members": [{"index": 1, "sig": "0x01"}, {"index": 2, "sig": "0x02"}], "sig": "0x"},
            {"index": 3, "members": [], "sig": "0xab"}]);
        let sig = json!({"keyData": "0x", "signature": "0x", "members": slots});
        let auth = crate::abi::UASig::abi_decode(&parse("UASig", &sig, "auth").unwrap().abi_encode()).unwrap();
        let ours = scaas_ua::ua8::encode_member_sigs(&[
            scaas_ua::ua8::MemberSig { index: 0, members: vec![scaas_ua::ua8::InnerSig { index: 1, sig: vec![1] }, scaas_ua::ua8::InnerSig { index: 2, sig: vec![2] }], sig: vec![] },
            scaas_ua::ua8::MemberSig { index: 3, members: vec![], sig: vec![0xab] }]);
        assert_eq!(auth.members.abi_encode(), ours);
        let mut hostile = ours.clone();
        hostile[32 + 31] = 0xff; // 255 slots claimed
        assert!(<Vec<crate::abi::MemberSig>>::abi_decode(&hostile).is_err());
    }

    #[test]
    fn hex_fields_are_refused_by_name_and_a_declared_bytes_field_is_not() {
        let v = vectors();
        let good = op_of("UAUnwrap", "token", &v).unwrap();
        Op::parse(&good, FEE).unwrap();
        for k in ["data", "calldata"] {
            let mut o = good.clone();
            o[k] = json!("0x1234");
            assert!(Op::parse(&o, FEE).unwrap_err().to_string().starts_with("HEX_DATA_REFUSED"), "op.{k}");
            let mut o = good.clone();
            o["args"][k] = json!("0x1234");
            assert!(Op::parse(&o, FEE).unwrap_err().to_string().starts_with("HEX_DATA_REFUSED"), "args.{k}");
        }
        Op::parse(&op_of("UAExecute", "wallet", &v).unwrap(), FEE).unwrap();
        Op::parse(&op_of("Execute", "account", &v).unwrap(), FEE).unwrap();
    }

    /// The router's rows (spec 2026-11-02-governance §3.2): every op is named JSON, `target` a named field the node signs and sends; a
    /// hex form is refused by name, and no generic entry, no governed contract and no other domain takes a router struct.
    #[test]
    fn router_ops_are_named_and_refuse_hex() {
        let v = vectors();
        let good = op_of("UASetGrant", "gov_router", &v).unwrap();
        let p = Op::parse(&good, FEE).unwrap();
        assert_eq!((p.typed.contract, p.row.entry), ("gov_router", "mtxSetGrant"));
        assert_eq!(p.to, good["token"].as_str().unwrap().parse::<Address>().unwrap(), "sent to the router");
        let err = |f: &dyn Fn(&mut Value)| {
            let mut o = good.clone();
            f(&mut o);
            Op::parse(&o, FEE).unwrap_err().to_string()
        };
        for k in ["data", "calldata"] {
            assert!(err(&|o| o[k] = json!("0x1234")).starts_with("HEX_DATA_REFUSED"), "op.{k}");
            assert!(err(&|o| o["args"][k] = json!("0x1234")).starts_with("HEX_DATA_REFUSED"), "args.{k}");
        }
        assert!(Op::parse(&json!("0xdeadbeef"), FEE).unwrap_err().to_string().starts_with("HEX_DATA_REFUSED"), "op as hex");
        let packed = format!("0x{}", "00".repeat(9 * 32));
        assert_eq!(err(&|o| o["args"]["terms"] = json!(packed)), "BAD_PAYLOAD: args.terms: not an object", "GrantTerms as a blob");
        assert!(err(&|o| o["contract"] = json!("token")).starts_with("UNKNOWN_ENTRY"), "no governed contract has the entry");
        assert!(err(&|o| o["contract"] = json!("dex")).starts_with("UNKNOWN_ENTRY"));
        for generic in ["mtxExecute", "mtxBatch", "uaExecute", "uaBatch", "executeMetaTransaction"] {
            assert!(err(&|o| o["entry"] = json!(generic)).starts_with("UNKNOWN_ENTRY"), "{generic} is no row");
        }
        assert!(err(&|o| { o["args"].as_object_mut().unwrap().remove("target"); }).contains("args.target: missing"));
        let other = Address::repeat_byte(0x42);
        let mut moved = good.clone();
        moved["args"]["target"] = json!(format!("{other:#x}"));
        let m = Op::parse(&moved, FEE).unwrap();
        assert_ne!(m.typed.struct_hash, p.typed.struct_hash, "target is a signed word");
        assert_eq!(m.to, p.to, "and never where the job is sent");
        // every router struct is on the router's domain only
        for r in rows().iter().filter(|r| r.contracts.contains(&"gov_router")) {
            assert!(r.contracts == GR || matches!(r.name, "CancelNonce" | "UACancelNonce"), "{}", r.name);
        }
    }

    /// `GrantTerms` is decoded by its type: one level, nine named fields, each bounded by its width; a hostile depth or length stops at
    /// the first field that is not its type, before anything is built.
    #[test]
    fn grant_terms_decode_is_bounded() {
        let v = vectors();
        let terms = v["ops"]["UASetGrant"]["message"]["terms"].clone();
        assert_eq!(to_json("GrantTerms", &parse("GrantTerms", &terms, "t").unwrap()), terms);
        let err = |f: &dyn Fn(&mut Value)| {
            let mut t = terms.clone();
            f(&mut t);
            parse("GrantTerms", &t, "t").unwrap_err().to_string()
        };
        assert_eq!(err(&|t| t["extra"] = json!(1)), "BAD_PAYLOAD: t.extra: unknown field");
        assert_eq!(err(&|t| { t.as_object_mut().unwrap().remove("scope"); }), "BAD_PAYLOAD: t.scope: missing");
        assert_eq!(err(&|t| t["min"] = json!("340282366920938463463374607431768211456")), "BAD_PAYLOAD: t.min: above uint128");
        assert_eq!(err(&|t| t["window"] = json!(1u64 << 32)), "BAD_PAYLOAD: t.window: above uint32");
        assert_eq!(err(&|t| t["validUntil"] = json!("18446744073709551616")), "BAD_PAYLOAD: t.validUntil: above uint64");
        assert_eq!(err(&|t| t["scope"] = json!(format!("0x{}", "11".repeat(33)))), "BAD_PAYLOAD: t.scope: not bytes32");
        assert_eq!(err(&|t| t["delegable"] = json!("true")), "BAD_PAYLOAD: t.delegable: not a bool");
        let mut deep = json!("0x");
        for _ in 0..100_000 {
            let mut o = Map::new();
            o.insert("scope".into(), deep); // never `json!`: it serializes its argument, a recursion over every level
            deep = Value::Object(o);
        }
        let mut t = terms.clone();
        t["scope"] = deep;
        assert_eq!(parse("GrantTerms", &t, "t").unwrap_err().to_string(), "BAD_PAYLOAD: t.scope: not a string", "a hostile depth stops at the type's");
        std::mem::forget(t); // serde_json's drop recurses over the 100,000 levels
    }

    /// One change from a passing op, one named error each.
    #[test]
    fn an_op_is_exact() {
        let v = vectors();
        let good = op_of("UAUnwrap", "token", &v).unwrap();
        let err = |f: &dyn Fn(&mut Value)| {
            let mut o = good.clone();
            f(&mut o);
            Op::parse(&o, FEE).unwrap_err().to_string()
        };
        assert!(err(&|o| o["entry"] = json!("mtxNoSuch")).starts_with("UNKNOWN_ENTRY"));
        assert!(err(&|o| o["entry"] = json!("")).starts_with("UNKNOWN_ENTRY"), "PqzAuth is no entry");
        assert!(err(&|o| o["contract"] = json!("wallet")).starts_with("UNKNOWN_ENTRY"));
        assert!(err(&|o| { o.as_object_mut().unwrap().remove("contract"); }).starts_with("ENTRY_AMBIGUOUS"));
        assert!(err(&|o| o["args"]["underlying"] = json!(format!("{:#x}", Address::ZERO))).contains("args.underlying: unknown field"), "mtxUnwrapLeg's field");
        assert!(err(&|o| { o["args"].as_object_mut().unwrap().remove("minOut"); }).contains("args.minOut: missing"));
        assert!(err(&|o| o["envelope"]["mode"] = json!(4)).contains("unknown mode"));
        assert!(err(&|o| o["envelope"]["extra"] = json!(1)).contains("envelope.extra: unknown field"));
        assert!(err(&|o| o["args"]["batch"] = json!("1")).contains("args.batch: unknown field"), "an envelope field in args");
        assert!(err(&|o| o["args"]["wrapped"] = json!("0x10")).contains("not a canonical uint256"));
        assert!(err(&|o| o["args"]["wrapped"] = json!(16)).contains("args.wrapped"), "a uint256 is a string");
        // the dirty word of a padded address never reaches a leg
        let dirty = format!("0x{:0>64}", "ff");
        assert!(err(&|o| o["args"]["recipient"] = json!(dirty)).contains("args.recipient"));
        assert!(err(&|o| { o["signature"] = o.as_object_mut().unwrap().remove("auth").unwrap(); }).contains("takes its signature as auth"));
        assert!(err(&|o| { o.as_object_mut().unwrap().remove("auth"); }).contains("without its signature"));
        assert!(err(&|o| o["auth"] = json!(format!("0x{}", "11".repeat(65)))).contains("signature: not an object"), "a UASig, never bytes");
        assert!(err(&|o| o["call"] = json!({})).contains("takes no op.call"));
    }

    /// `MetaTxLib.canon` for the envelope and for a nested payment; an unbound relayer is never sent as the wire value.
    #[test]
    fn unbound_fields_stay_out_of_the_digest_and_off_the_wire() {
        let v = vectors();
        let mut op = op_of("UAUnwrap", "token", &v).unwrap();
        op["envelope"]["mode"] = json!(0x20);
        let ours = Address::repeat_byte(0x99);
        let a = Op::parse(&op, Some(ours)).unwrap();
        op["envelope"]["relayer"] = json!(format!("{:#x}", Address::repeat_byte(0x66)));
        op["envelope"]["feeRecipient"] = json!(format!("{:#x}", Address::repeat_byte(0x77)));
        let b = Op::parse(&op, Some(ours)).unwrap();
        assert_eq!(a.typed.struct_hash, b.typed.struct_hash);
        assert_eq!(a.data, b.data, "the wire value is overwritten");
        let (env, ..) = op_from_calldata(a.row, &a.data);
        let env = env.unwrap();
        assert_eq!(env["relayer"], json!(format!("{:#x}", Address::ZERO)));
        assert_eq!(env["feeRecipient"], json!(format!("{ours:#x}")));
        let mut op = op_of("UAReceiverFee", "token", &v).unwrap();
        let base = Op::parse(&op, FEE).unwrap().typed.struct_hash;
        op["args"]["payment"]["feeRecipient"] = json!(format!("{:#x}", Address::repeat_byte(0x77)));
        assert_eq!(Op::parse(&op, FEE).unwrap().typed.struct_hash, base, "mode 1 does not bind it");
    }

    /// C5 review: pay on `mandatePayLane(ref)`, revoke on `mandateRevokeLane(token, epoch)`, nonce 0. The lanes are forge's
    /// (`mandate_kat.json`, the merged entries: `batch` beside the signed `args`), not this file's formula.
    #[test]
    fn mandate_ops_run_on_their_own_lane_at_nonce_zero() {
        let k: Value = serde_json::from_str(&std::fs::read_to_string(format!(
            "{}/../smartcontracts/evm/test/vectors/mandate_kat.json", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap();
        let word = |k: &Value, i: usize| hex(&k["args"])[32 * i..32 * (i + 1)].to_vec();
        // `payUnderMandate(token, payee, amount, entryRef, epoch)`
        assert_eq!(mandate_pay_lane(&word(&k["pay"], 3)).to_string(), k["pay"]["batch"].as_str().unwrap());
        // `revoke(token, epoch)`
        let token = Address::from_slice(&word(&k["revoke"], 0)[12..]);
        let epoch = u64::from_be_bytes(word(&k["revoke"], 1)[24..].try_into().unwrap());
        assert_eq!(mandate_revoke_lane(token, epoch).to_string(), k["revoke"]["batch"].as_str().unwrap());
        let v = vectors();
        let lane_of = |op: &Value| mandate_pay_lane(&hex(&op["args"]["entryRef"])).to_string();
        let mut pay = op_of("UAPayUnderMandate", "wallet", &v).unwrap();
        assert!(Op::parse(&pay, FEE).unwrap_err().to_string().starts_with("MANDATE_LANE"), "the vector's lane 7");
        pay["envelope"]["batch"] = json!(lane_of(&pay));
        pay["envelope"]["nonce"] = json!("0");
        Op::parse(&pay, FEE).unwrap();
        pay["envelope"]["nonce"] = json!("1");
        assert!(Op::parse(&pay, FEE).unwrap_err().to_string().starts_with("MANDATE_LANE"), "nonce 0 only");
        let mut rev = op_of("UADelegateRevoke", "wallet", &v).unwrap();
        let token: Address = rev["args"]["token"].as_str().unwrap().parse().unwrap();
        let epoch: u64 = rev["args"]["epoch"].as_str().unwrap().parse().unwrap();
        assert!(Op::parse(&rev, FEE).unwrap_err().to_string().starts_with("MANDATE_LANE"));
        rev["envelope"]["batch"] = json!(mandate_revoke_lane(token, epoch).to_string());
        rev["envelope"]["nonce"] = json!("0");
        Op::parse(&rev, FEE).unwrap();
        rev["args"]["epoch"] = json!((epoch + 1).to_string());
        assert!(Op::parse(&rev, FEE).unwrap_err().to_string().starts_with("MANDATE_LANE"), "another epoch is another lane");
        // forge's pay calldata is what the node builds from the same fields: `mtxPayUnderMandate(UAEnvelope, …, UASig)`
        let p = &k["pay"];
        let s = |f: &str| p[f].as_str().unwrap().to_string();
        let op = json!({"entry": "mtxPayUnderMandate", "contract": "wallet", "token": k["verifying_contract"], "envelope": {"from": s("from"),
            "batch": s("batch"), "nonce": s("nonce"), "validUntil": s("valid_until"), "mode": s("mode").parse::<u32>().unwrap(),
            "relayer": s("relayer"), "fee": s("fee"), "feeRecipient": s("fee_recipient")},
            "args": {"token": format!("{token:#x}", token = Address::from_slice(&word(p, 0)[12..])), "payee": format!("0x{}", alloy::hex::encode(word(p, 1))),
                "amount": U256::from_be_slice(&word(p, 2)).to_string(), "entryRef": format!("0x{}", alloy::hex::encode(word(p, 3))),
                "epoch": U256::from_be_slice(&word(p, 4)).to_string()},
            "auth": {"keyData": "0x", "signature": s("signature"), "members": []}});
        let built = Op::parse(&op, FEE).unwrap();
        assert_eq!(format!("0x{}", alloy::hex::encode(&built.data)), s("calldata"), "forge's calldata");
        assert_eq!(format!("{:#x}", built.typed.struct_hash.unwrap()), s("struct_hash"));
    }

    /// forge's digests of the two invalidations, which `typed_ops.json` has no row for: the DEX's (`dex_order_kat.json`, the bytes
    /// too) and the token's on ids (`uatrade_kat.json`, R12 / R38).
    #[test]
    fn invalidate_digests_match_the_vectors() {
        use crate::abi::ISCaaSDex;
        let file = |f: &str| -> Value {
            serde_json::from_str(&std::fs::read_to_string(format!("{}/../smartcontracts/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()
        };
        let chain = |k: &Value| k["chain_id"].as_str().unwrap().parse::<u64>().unwrap();
        let d = file("evm/test/vectors/dex_order_kat.json");
        let data = &d["invalidate_calldata"];
        let c = ISCaaSDex::mtxInvalidateNoncesCall::abi_decode(&hex(data)).unwrap();
        let op = json!({"entry": "mtxInvalidateNonces", "contract": "dex", "token": d["dex"],
            "args": {"from": format!("{:#x}", c.from), "batch": c.batch.to_string(), "minNonce": c.newMin.to_string()},
            "signature": format!("0x{}", alloy::hex::encode(&c.sig)), "validUntil": "1800000300"});
        let p = Op::parse(&op, FEE).unwrap();
        assert_eq!(p.data.to_vec(), hex(data), "the bytes too");
        assert_eq!(format!("{:#x}", p.typed.digest_on(chain(&d), d["salt"].as_str().unwrap().parse().unwrap()).unwrap()),
            d["invalidate_digest"].as_str().unwrap().to_lowercase());
        let u = file("vectors/ua/uatrade_kat.json");
        let rows_ = u["rows"].as_array().unwrap();
        assert!(!rows_.is_empty());
        for r in rows_ {
            let m = &r["invalidate"]["message"];
            let op = json!({"entry": "mtxInvalidateNonces", "contract": "token", "token": r["invalidate"]["domain"]["verifyingContract"],
                "args": m, "auth": {"keyData": "0x", "signature": "0x", "members": []}, "validUntil": "1800000300"});
            let p = Op::parse(&op, FEE).unwrap();
            assert_eq!(p.data[..4], crate::guard::SEL_TOKEN_INVALIDATE_NONCES);
            let h = p.typed.digest_on(u["chainId"].as_u64().unwrap(), u["chainUid"].as_str().unwrap().parse().unwrap());
            assert_eq!(format!("{:#x}", h.unwrap()), r["invalidateDigest"].as_str().unwrap(), "{}", r["name"]);
        }
    }

    /// A job deadline narrows what is signed, never extends it; a cancel has none of its own.
    #[test]
    fn a_job_deadline_never_outlives_the_signed_one() {
        let v = vectors();
        let mut op = op_of("UAUnwrap", "token", &v).unwrap();
        let signed = 1_800_000_300u64;
        for (job, want) in [(signed + 100, signed), (signed - 100, signed - 100)] {
            op["validUntil"] = json!(job.to_string());
            assert_eq!(Op::parse(&op, FEE).unwrap().valid_until, want, "{job}");
        }
        op.as_object_mut().unwrap().remove("validUntil");
        assert_eq!(Op::parse(&op, FEE).unwrap().valid_until, signed);
        let mut fee = op_of("UAReceiverFee", "token", &v).unwrap();
        fee.as_object_mut().unwrap().remove("validUntil");
        let outer: u64 = fee["args"]["validUntil"].as_str().unwrap().parse().unwrap();
        fee["args"]["payment"]["validUntil"] = json!((outer + 5).to_string());
        assert_eq!(Op::parse(&fee, FEE).unwrap().valid_until, outer, "the sooner: the fee's");
        fee["args"]["payment"]["validUntil"] = json!((outer - 5).to_string());
        assert_eq!(Op::parse(&fee, FEE).unwrap().valid_until, outer - 5, "the sooner: the payment's");
        let mut c = op_of("CancelUAOrder", "token", &v).unwrap();
        c["validUntil"] = json!((signed + 100).to_string());
        assert_eq!(Op::parse(&c, FEE).unwrap().valid_until, signed + 100, "the chain enforces no deadline on a cancel");
    }

    /// `classify` compares what the chain emits: a receiver fee lands as its payment's `MetaTransfer`, not the outer struct.
    #[test]
    fn a_receiver_fee_is_recognised_by_its_payment_digest() {
        let v = vectors();
        let d = &v["ops"]["UAReceiverFee"]["domains"]["token"];
        let op = op_of("UAReceiverFee", "token", &v).unwrap();
        let p = Op::parse(&op, FEE).unwrap();
        let (chain, at, uid) = domain_of(d);
        let wire = v["ops"]["UAReceiverFee"]["message"]["payment"].clone();
        let m = crate::metatx::UaMtx::from_wire(None, &wire).unwrap();
        let dom = crate::metatx::Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id: chain, verifying_contract: at, salt: uid };
        assert_eq!(p.typed.lane_digest_on(chain, uid), Some(m.digest(&dom)), "the sol! struct, another path");
        assert_ne!(p.typed.lane_digest_on(chain, uid), p.typed.digest_on(chain, uid), "the in-flight key stays the outer op");
        let plain = Op::parse(&op_of("UAUnwrap", "token", &v).unwrap(), FEE).unwrap();
        assert_eq!(plain.typed.lane_digest_on(chain, uid), plain.typed.digest_on(chain, uid));
    }

    /// CTR-MTX-27: `call` is a named op, not hex: the router's calldata carries its bytes, `callDataHash` their hash, and the
    /// row's own vector calldata is the router's. Refused: no `call`, a `call` beside the hash, a hex `call`.
    #[test]
    fn relay_fee_call_object() {
        let v = vectors();
        for (name, kind) in [("UARelayFee", "token"), ("UARelayFee", "pqz"), ("UARelayFee", "zether")] {
            let d = &v["ops"][name]["domains"][kind];
            let row = row_of(name, kind);
            let (_, args, sig) = split(row, name, kind, &v);
            let a = assemble(row, None, &args, sig.as_ref(), FEE).unwrap();
            let (target, token) = (args["target"].as_str().unwrap().parse().unwrap(), d["domain"]["verifyingContract"].as_str().unwrap().parse().unwrap());
            let call = hex(&d["relayedCall"]);
            let r = router_call(row, &a, target, call.into(), token).unwrap();
            assert_eq!(alloy::hex::encode(r), &d["routerCalldata"].as_str().unwrap()[2..], "{name} on {kind}");
            // the job: the inner op is a named entry; hash, target and the bytes follow it
            let inner = op_of("UABurn", "token", &v).unwrap();
            let burn = Op::parse(&inner, FEE).unwrap();
            let mut a2 = args.clone();
            let o = a2.as_object_mut().unwrap();
            o.remove("target");
            o.remove("callDataHash");
            let mut op = json!({"entry": row.entry, "contract": kind, "token": format!("{token:#x}"), "args": a2, "call": inner});
            op["auth"] = sig.clone().unwrap();
            let p = Op::parse(&op, FEE).unwrap_or_else(|e| panic!("{name}: {e:#}"));
            assert_eq!(p.to, args["relayer"].as_str().unwrap().parse::<Address>().unwrap(), "the signed router");
            assert_eq!(p.data[..4], row.sent);
            assert_ne!(p.data[..4], row.selector, "never the direct entry");
            let c = IMtxRelayFee::relayCall::abi_decode(&p.data).unwrap();
            assert_eq!((c.target, c.callData.to_vec(), c.token), (burn.to, burn.data.to_vec(), token));
            // the payer hashed the inner bytes: a node's `fee_recipient` leaves them alone
            let ours = Some(Address::repeat_byte(0x99));
            let mut open_inner = inner.clone();
            open_inner["envelope"]["mode"] = json!(0);
            let hashed = Op::parse(&open_inner, None).unwrap().data;
            assert_ne!(Op::parse(&open_inner, ours).unwrap().data, hashed, "the control: a top-level op takes the lane's feeRecipient");
            let mut unbound = op.clone();
            unbound["call"] = open_inner;
            let sent = Op::parse(&unbound, ours).unwrap();
            assert_eq!(sent.data, Op::parse(&unbound, None).unwrap().data, "the relayed bytes do not follow the lane's fee_recipient");
            assert!(sent.data.windows(hashed.len()).any(|w| w == &hashed[..]), "the router carries the bytes the payer hashed");
            let moved = {
                let mut o2 = op.clone();
                o2["call"]["args"]["amount"] = json!("1");
                Op::parse(&o2, FEE).unwrap()
            };
            assert_ne!(moved.typed.struct_hash, p.typed.struct_hash, "the signed hash follows the inner bytes");
            assert_ne!(moved.data, p.data);
            let mut bad = op.clone();
            bad.as_object_mut().unwrap().remove("call");
            assert!(Op::parse(&bad, FEE).unwrap_err().to_string().contains("needs op.call"));
            let mut bad = op.clone();
            bad["args"]["callDataHash"] = args["callDataHash"].clone();
            assert!(Op::parse(&bad, FEE).unwrap_err().to_string().contains("come from op.call"));
            let mut bad = op.clone();
            bad["call"] = json!({"target": "0x01", "calldata": "0x1234"});
            assert!(Op::parse(&bad, FEE).unwrap_err().to_string().starts_with("HEX_DATA_REFUSED"));
            bad["call"] = json!("0x1234");
            assert!(Op::parse(&bad, FEE).unwrap_err().to_string().starts_with("HEX_DATA_REFUSED"), "op.call as hex");
        }
    }

    /// A signer the node can check, by row shape; a bad signature recovers to someone else.
    #[test]
    fn the_signer_is_found_where_the_row_keeps_it() {
        let v = vectors();
        let key: Address = v["key"]["address"].as_str().unwrap().parse().unwrap();
        let payee = Address::from_word(v["ops"]["UAReceiverFee"]["message"]["payment"]["to"].as_str().unwrap().parse().unwrap());
        for (name, kind, who) in [("Wrap", "token", Some(key)), ("UAUnwrap", "token", Some(key)), ("CancelUAOrder", "token", Some(key)),
            ("CancelDexOrder", "dex", Some(key)), ("UAWrapOrder", "token", Some(key)), ("UAReceiverFee", "token", Some(payee)),
            ("UACancelNonce", "token", Some(key)), ("UASetPayee", "wallet", Some(key)), ("AddKey", "account", None)] {
            let op = op_of(name, kind, &v).unwrap();
            let s = Op::parse(&op, FEE).unwrap_or_else(|e| panic!("{name}: {e:#}")).typed.signer;
            assert_eq!(s.as_ref().map(|x| x.0), who, "{name}");
        }
    }

    /// A venue job is named JSON and encodes back to the same bytes.
    #[test]
    fn call_op_round_trips_a_plain_entry() {
        let k: Value = serde_json::from_str(&std::fs::read_to_string(format!(
            "{}/../smartcontracts/evm/test/vectors/dex_order_kat.json", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap();
        for key in ["settle_calldata", "exchange_calldata", "exchange_via_calldata", "hybrid_calldata", "hybrid_via_calldata",
            "exchange_batch_calldata"] {
            let raw = hex(&k[key]);
            let op = call_op("dex", Address::repeat_byte(0xd0), &raw, "1800000300").unwrap_or_else(|e| panic!("{key}: {e:#}"));
            let p = Op::parse(&op, FEE).unwrap_or_else(|e| panic!("{key}: {e:#}"));
            assert_eq!(p.data.to_vec(), raw, "{key}");
            assert_eq!((p.to, p.valid_until, p.typed.struct_hash, p.lane), (Address::repeat_byte(0xd0), 1_800_000_300, None, None));
        }
    }
}
