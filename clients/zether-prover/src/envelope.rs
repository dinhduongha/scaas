//! Relaying a Zether op through the token's one meta-transaction base (zether.md §12, CTR-ZTH-34): the subject signs a
//! `MetaTransaction` whose `data` is the real calldata of an allowlisted Zether function, in the token's salted domain
//! `("SCaaS ZetherToken", "1", chainId, token, chainUid)`; the proof binds the envelope through `envelopeBinding`.
//!
//! Relayed flow: build `m` without data → `binding = envelope_binding(m)` → prove with
//! `Binding::Relayed(binding)` → `m.data = transfer_call(...)` → sign `digest(m)`.
//!
//! ua-mtx-merge (CTR-MTX-30, R35, CTR-ZTH-51): a proof relayed through a merged entry (`mtx<Op>(UAEnvelope, …, UASig)`) or the
//! generic `mtxExecute(UAMetaTransaction, UASig)` binds [`ua_envelope_binding`] (`SCAAS-ZETHER-UA-ENVELOPE-V1`, `from` a
//! `bytes32` id: a padded native address or a derived UA); [`envelope_binding`] is `executeMetaTransaction`'s only.

use crate::abi::{self, Tok};
use crate::curve::keccak256;

pub const MODE_RESTRICT_RELAYER: u32 = 0x01;
pub const MODE_RESTRICT_FEE_RECIPIENT: u32 = 0x02;
pub const MODE_FEE_NONE: u32 = 0x00;
pub const MODE_FEE_FIXED: u32 = 0x20;

pub const METATX_TYPE: &str = "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

/// `MetaTxLib.MetaTransaction` (CTR-MTX-15): no `to`, no `value`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaTx {
    pub from: [u8; 20],
    pub data: Vec<u8>,
    /// 2D-nonce lane (random per `entryRef`, chosen by the client).
    pub batch: [u8; 32],
    pub nonce: u64,
    pub valid_until: u64,
    pub mode: u32,
    pub relayer: [u8; 20],
    pub fee: u128,
    pub fee_recipient: [u8; 20],
}

fn u128w(v: u128) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[16..].copy_from_slice(&v.to_be_bytes());
    o
}

impl MetaTx {
    /// `MetaTxLib.canon`: unbound relayer / feeRecipient hash as `address(0)`.
    pub fn canon(&self) -> ([u8; 20], [u8; 20]) {
        canon(self.mode, &self.relayer, &self.fee_recipient)
    }

    pub fn struct_hash(&self) -> [u8; 32] {
        let (r, f) = self.canon();
        keccak256(
            &[
                keccak256(METATX_TYPE.as_bytes()),
                abi::addr(&self.from),
                keccak256(&self.data),
                self.batch,
                abi::u256(self.nonce),
                abi::u256(self.valid_until),
                abi::u256(self.mode as u64),
                abi::addr(&r),
                u128w(self.fee),
                abi::addr(&f),
            ]
            .concat(),
        )
    }
}

/// `MetaTxLib.UAMetaTransaction` (CTR-UA-19/26): [`MetaTx`] with `from` the subject's `bytes32` id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UAMetaTx {
    pub from: [u8; 32],
    pub data: Vec<u8>,
    pub batch: [u8; 32],
    pub nonce: u64,
    pub valid_until: u64,
    pub mode: u32,
    pub relayer: [u8; 20],
    pub fee: u128,
    pub fee_recipient: [u8; 20],
}

pub const UA_METATX_TYPE: &str = "UAMetaTransaction(bytes32 from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

impl UAMetaTx {
    /// `MetaTxLib.hashStruct(UAMetaTransaction)`: unbound relayer / feeRecipient hash as `address(0)`.
    pub fn struct_hash(&self) -> [u8; 32] {
        let (r, f) = canon(self.mode, &self.relayer, &self.fee_recipient);
        keccak256(
            &[
                keccak256(UA_METATX_TYPE.as_bytes()),
                self.from,
                keccak256(&self.data),
                self.batch,
                abi::u256(self.nonce),
                abi::u256(self.valid_until),
                abi::u256(self.mode as u64),
                abi::addr(&r),
                u128w(self.fee),
                abi::addr(&f),
            ]
            .concat(),
        )
    }
}

fn canon(mode: u32, relayer: &[u8; 20], fee_recipient: &[u8; 20]) -> ([u8; 20], [u8; 20]) {
    let r = if mode & MODE_RESTRICT_RELAYER != 0 { *relayer } else { [0; 20] };
    let f = if mode & MODE_RESTRICT_FEE_RECIPIENT != 0 { *fee_recipient } else { [0; 20] };
    (r, f)
}

/// The token's salted EIP-712 domain (CTR-MTX-02, CTR-GEN-05).
pub fn domain_separator(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20]) -> [u8; 32] {
    keccak256(
        &[
            keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(b"SCaaS ZetherToken"),
            keccak256(b"1"),
            abi::u256(chain_id),
            abi::addr(token),
            *chain_uid,
        ]
        .concat(),
    )
}

/// EIP-712 digest the subject's signing key signs (`mtxDigest(m)` on the token).
pub fn digest(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20], m: &MetaTx) -> [u8; 32] {
    let mut b = vec![0x19, 0x01];
    b.extend(domain_separator(chain_id, chain_uid, token));
    b.extend(m.struct_hash());
    keccak256(&b)
}

/// `mtxDigest(UAMetaTransaction)`: what the subject signs for the generic merged entry `mtxExecute(m, auth)`.
pub fn ua_digest(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20], m: &UAMetaTx) -> [u8; 32] {
    let mut b = vec![0x19, 0x01];
    b.extend(domain_separator(chain_id, chain_uid, token));
    b.extend(m.struct_hash());
    keccak256(&b)
}

/// The token's `envelopeBinding(UAMetaTransaction)` view (CTR-ZTH-51, R35): tag `SCAAS-ZETHER-UA-ENVELOPE-V1`, `from` the
/// `bytes32` id, every other envelope field except `data`, plus `chainUid`. Every merged entry and `mtxExecute`.
pub fn ua_envelope_binding(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20], m: &UAMetaTx) -> [u8; 32] {
    let (r, f) = canon(m.mode, &m.relayer, &m.fee_recipient);
    keccak256(
        &[
            keccak256(b"SCAAS-ZETHER-UA-ENVELOPE-V1"),
            abi::u256(chain_id),
            *chain_uid,
            abi::addr(token),
            m.from,
            m.batch,
            abi::u256(m.nonce),
            abi::u256(m.valid_until),
            abi::u256(m.mode as u64),
            abi::addr(&r),
            u128w(m.fee),
            abi::addr(&f),
        ]
        .concat(),
    )
}

/// `executeMetaTransaction`'s binding (CTR-ZTH-06, the address tag) — every envelope field except `data`, plus `chainUid`.
pub fn envelope_binding(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20], m: &MetaTx) -> [u8; 32] {
    let (r, f) = m.canon();
    keccak256(
        &[
            keccak256(b"SCAAS-ZETHER-ENVELOPE-V1"),
            abi::u256(chain_id),
            *chain_uid,
            abi::addr(token),
            abi::addr(&m.from),
            m.batch,
            abi::u256(m.nonce),
            abi::u256(m.valid_until),
            abi::u256(m.mode as u64),
            abi::addr(&r),
            u128w(m.fee),
            abi::addr(&f),
        ]
        .concat(),
    )
}

/// The binding word of a direct `mtxUnshieldUnwrap` (under `ZTX_V1_DIRECT`): its leg and `minOut` (`min_out` as
/// the 32-byte ABI word). Controller ruling, pending the owner.
pub fn unwrap_binding(underlying: &[u8; 20], min_out: &[u8; 32]) -> [u8; 32] {
    keccak256(&[keccak256(b"SCAAS-ZETHER-UNWRAP-V1"), abi::addr(underlying), *min_out].concat())
}

pub fn selector(sig: &str) -> [u8; 4] {
    keccak256(sig.as_bytes())[..4].try_into().unwrap()
}

const G1: &str = "(bytes32,bytes32,bytes32,bytes32)";

/// `abi` signature of `ZetherSingle` (`IZetherToken`, typed-signing Appendix X.2).
pub fn single_type() -> String {
    format!("(uint64,uint64,uint256,bytes16,bytes32,{G1},{G1},{G1},{G1},{G1},{G1})")
}

/// `abi` signature of `ZetherMulti`.
pub fn multi_type() -> String {
    format!("(uint64,uint64,uint256,bytes16,bytes32,uint256,{G1},{G1},{G1},({G1},{G1},{G1},{G1})[],bytes)")
}

/// `abi` signature of `ZetherBurn`.
pub fn burn_type() -> String {
    format!("(uint64,uint64,uint256,bytes32,{G1})")
}

fn salt_word(salt: &[u8]) -> Tok {
    let mut w = [0u8; 32];
    w[..16].copy_from_slice(salt);
    Tok::Word(w)
}

/// `be32(accSeq) ‖ be32(sendCounter) ‖ be32(validUntilBlock)`: the head of every packed payload (zether.md §10).
const P_HEAD: usize = 96;
const POINT: usize = 128;

/// The ABI tokens of `ZetherSingle` from the packed `payload` (`head ‖ salt16 ‖ 6 points`); a static struct, inline.
fn single_toks(payload: &[u8], beneficiary: &[u8; 32]) -> Vec<Tok> {
    let mut toks = abi::words(&payload[..P_HEAD]);
    toks.push(salt_word(&payload[P_HEAD..P_HEAD + 16]));
    toks.push(Tok::Word(*beneficiary));
    toks.extend(abi::words(&payload[P_HEAD + 16..]));
    toks
}

/// The leg count `M` and the end of the legs of a packed multi `payload`, `None` when `M` does not fit, the arithmetic
/// overflows, or the length is not `legs_end` or at least `legs_end + 16` (a sealed memo after its salt). Checked before any
/// slice, so a corrupted `M` is refused instead of wrapping or panicking.
pub(crate) fn multi_legs(payload: &[u8]) -> Option<(usize, usize)> {
    let m = usize::try_from(abi::word_u64(payload, 112)?).ok()?;
    let legs_end = m.checked_mul(4 * POINT)?.checked_add(176 + 3 * POINT)?;
    (payload.len() == legs_end || payload.len() >= legs_end.checked_add(16)?).then_some((m, legs_end))
}

/// `ZetherMulti` from the packed `payload` (`head ‖ salt16 ‖ be32(M) ‖ be32(decoyFee) ‖ 3 points ‖ M · 4 points [‖ salt16 ‖
/// sealed]`); a dynamic struct, one tuple token.
fn multi_tok(payload: &[u8], beneficiary: &[u8; 32]) -> Tok {
    let (m, legs_end) = multi_legs(payload).expect("a multi payload (the caller's own, or checked by `multi_legs`)");
    let pts = 176 + 3 * POINT;
    let sealed = if payload.len() > legs_end { payload[legs_end + 16..].to_vec() } else { Vec::new() };
    let mut t = abi::words(&payload[..P_HEAD]);
    t.push(salt_word(&payload[P_HEAD..P_HEAD + 16]));
    t.push(Tok::Word(*beneficiary));
    t.extend(abi::words(&payload[144..pts]));
    t.push(Tok::Array(m as u64, payload[pts..legs_end].to_vec()));
    t.push(Tok::Bytes(sealed));
    Tok::Tuple(abi::encode(&t))
}

/// `ZetherBurn` from the packed `payload` (`head ‖ Y_f`); static, inline.
fn burn_toks(payload: &[u8], beneficiary: &[u8; 32]) -> Vec<Tok> {
    let mut toks = abi::words(&payload[..P_HEAD]);
    toks.push(Tok::Word(*beneficiary));
    toks.extend(abi::words(&payload[P_HEAD..]));
    toks
}

fn call(sig: &str, toks: &[Tok]) -> Vec<u8> {
    let mut d = selector(sig).to_vec();
    d.extend(abi::encode(toks));
    d
}

/// The signed fields of a merged entry around the op (`MetaTxLib.UAEnvelope`): `bytes32 from, batch, nonce, validUntil, mode,
/// relayer, fee, feeRecipient`.
pub const UA_ENV_TYPE: &str = "(bytes32,uint256,uint256,uint256,uint32,address,uint256,address)";

/// `IUARegistry.UASig`: `(bytes keyData, bytes signature, MemberSig[] members)`, `MemberSig (uint16 index, InnerSig[] members,
/// bytes sig)`, `InnerSig (uint16 index, bytes sig)`.
pub const UA_SIG_TYPE: &str = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";

/// An `msig` slot's inner signature (CTR-UA-33).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InnerSig {
    pub index: u16,
    pub sig: Vec<u8>,
}

/// One `msig` slot: a signing member's `sig`, or a nested `msig` member's `members`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemberSig {
    pub index: u16,
    pub members: Vec<InnerSig>,
    pub sig: Vec<u8>,
}

/// A UA's signature, explicit (TS-D12): a native id only `signature`; a derived single key `keyData` (empty for the stored
/// kinds) + `signature`; an `msig` only `members`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UASig {
    pub key_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub members: Vec<MemberSig>,
}

/// `UASig` as one dynamic tuple token. An array of dynamic tuples is its length then the tuples `encode`d as one (offsets
/// relative to the first element).
pub fn ua_sig_tok(s: &UASig) -> Tok {
    let tuple = |t: &[Tok]| Tok::Tuple(abi::encode(t));
    let inner = |i: &InnerSig| tuple(&[Tok::Word(abi::u256(i.index.into())), Tok::Bytes(i.sig.clone())]);
    let member = |m: &MemberSig| {
        let inners: Vec<Tok> = m.members.iter().map(inner).collect();
        tuple(&[Tok::Word(abi::u256(m.index.into())), Tok::Array(inners.len() as u64, abi::encode(&inners)), Tok::Bytes(m.sig.clone())])
    };
    let members: Vec<Tok> = s.members.iter().map(member).collect();
    tuple(&[Tok::Bytes(s.key_data.clone()), Tok::Bytes(s.signature.clone()), Tok::Array(members.len() as u64, abi::encode(&members))])
}

/// Calldata of `mtxConfidentialTransferSingle(ZetherSingle t, bytes proof)` from the prover's packed `payload`
/// (`head ‖ salt16 ‖ 6 points`): the direct call and, unchanged, the envelope's `data`. The proof alone authorizes the
/// spend (UA-6).
pub fn transfer_single_call(payload: &[u8], proof: &[u8], beneficiary: &[u8; 32]) -> Vec<u8> {
    let mut toks = single_toks(payload, beneficiary);
    toks.push(Tok::Bytes(proof.to_vec()));
    call(&format!("mtxConfidentialTransferSingle({},bytes)", single_type()), &toks)
}

/// `mtxConfidentialTransferSingle(UAEnvelope e, ZetherSingle t, bytes proof, UASig auth)`: the merged relayed entry (R35);
/// `env` the eight `UAEnvelope` words.
pub fn named_transfer_single_call(env: &[Tok], payload: &[u8], proof: &[u8], beneficiary: &[u8; 32], auth: &UASig) -> Vec<u8> {
    let mut toks = env.to_vec();
    toks.extend(single_toks(payload, beneficiary));
    toks.extend([Tok::Bytes(proof.to_vec()), ua_sig_tok(auth)]);
    call(&format!("mtxConfidentialTransferSingle({UA_ENV_TYPE},{},bytes,{UA_SIG_TYPE})", single_type()), &toks)
}

/// Calldata of `mtxConfidentialTransfer` / `…Compact` (`name`) `(ZetherMulti t, bytes proof)` from the packed `payload`.
pub fn transfer_multi_call(name: &str, payload: &[u8], proof: &[u8], beneficiary: &[u8; 32]) -> Vec<u8> {
    call(&format!("{name}({},bytes)", multi_type()), &[multi_tok(payload, beneficiary), Tok::Bytes(proof.to_vec())])
}

/// `{name}(UAEnvelope e, ZetherMulti t, bytes proof, UASig auth)`.
pub fn named_transfer_multi_call(name: &str, env: &[Tok], payload: &[u8], proof: &[u8], beneficiary: &[u8; 32], auth: &UASig) -> Vec<u8> {
    let mut toks = env.to_vec();
    toks.extend([multi_tok(payload, beneficiary), Tok::Bytes(proof.to_vec()), ua_sig_tok(auth)]);
    call(&format!("{name}({UA_ENV_TYPE},{},bytes,{UA_SIG_TYPE})", multi_type()), &toks)
}

/// `mtxUnshield(ZetherBurn b, uint256 amount, bytes32 recipient, bytes proof)` from the packed `payload` (`head ‖ Y_f`),
/// `to` the recipient id: a padded address or a derived SIGNING UA (CTR-ZTH-51).
pub fn unshield_call(payload: &[u8], proof: &[u8], beneficiary: &[u8; 32], to: &[u8; 32], amount: u64) -> Vec<u8> {
    let mut toks = burn_toks(payload, beneficiary);
    toks.extend([Tok::Word(abi::u256(amount)), Tok::Word(*to), Tok::Bytes(proof.to_vec())]);
    call(&format!("mtxUnshield({},uint256,bytes32,bytes)", burn_type()), &toks)
}

/// `mtxUnshield(UAEnvelope e, ZetherBurn b, uint256 amount, bytes32 recipient, bytes proof, UASig auth)`.
pub fn named_unshield_call(env: &[Tok], payload: &[u8], proof: &[u8], beneficiary: &[u8; 32], to: &[u8; 32], amount: u64, auth: &UASig) -> Vec<u8> {
    let mut toks = env.to_vec();
    toks.extend(burn_toks(payload, beneficiary));
    toks.extend([Tok::Word(abi::u256(amount)), Tok::Word(*to), Tok::Bytes(proof.to_vec()), ua_sig_tok(auth)]);
    call(&format!("mtxUnshield({UA_ENV_TYPE},{},uint256,bytes32,bytes,{UA_SIG_TYPE})", burn_type()), &toks)
}

/// `mtxUnshieldUnwrap(UAEnvelope e, ZetherBurn b, Unwrap x, bytes proof, UASig auth)`, `Unwrap {address underlying; bytes32
/// recipient; uint256 amount; uint256 minOut}` (a direct call's proof binds it through `unwrap_binding`).
pub fn named_unshield_unwrap_call(env: &[Tok], payload: &[u8], proof: &[u8], beneficiary: &[u8; 32], x: [[u8; 32]; 4], auth: &UASig) -> Vec<u8> {
    let mut toks = env.to_vec();
    toks.extend(burn_toks(payload, beneficiary));
    toks.extend(x.map(Tok::Word));
    toks.extend([Tok::Bytes(proof.to_vec()), ua_sig_tok(auth)]);
    call(&format!("mtxUnshieldUnwrap({UA_ENV_TYPE},{},(address,bytes32,uint256,uint256),bytes,{UA_SIG_TYPE})", burn_type()), &toks)
}
