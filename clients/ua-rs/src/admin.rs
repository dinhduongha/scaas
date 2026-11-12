// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Round 3r (CTR-GOV-23, spec 2026-11-10-admin-not-owner.md §5.4, §5.6, §7): the `GovernanceRouter`'s 18 admin ops (the three
//! of a governed contract's admin, the 15 of `OpenFactory`'s and a `ComplianceRegistry`'s admin), so a PQ or `msig` admin signs
//! them through ua-rs: their type strings, struct hashes (an `Env` nested, each array the `keccak256` of its words, a `string`
//! the `keccak256` of its bytes) and digests in the router's domain (`MetaTxLib.canon`'s zeroing of an unbound `relayer` /
//! `feeRecipient`), and the factory's release approval keys (`approvalOf`, `revokeApproval`). Pinned by
//! `smartcontracts/vectors/typed/typed_ops.json` (clientkeys; the keys checked on the factory by forge). The contract decides;
//! nothing here is a check of record. UNAUDITED.
use crate::regulated::{Envelope, RouterOpError};
use crate::{address_word, keccak, keccak256, word};

const ENVELOPE: &str =
    "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient";
pub const ENV_TYPE: &str = "Env(address registry,address smartKeyAccountImpl,bool hedera,address[] deps,bytes32[] params,address[] libs,bytes32[] libCodeHashes)";
/// CTR-GOV-27: `setChainEntries`'s named struct, nested in `UASetChainEntries`.
pub const CHAIN_ENTRIES_TYPE: &str = "ChainEntries(address relayFeeRouter,bytes32 relayFeeRouterCodeHash,bytes32 relayFeeExecutorCodeHash,address complianceRegistry,bytes32 complianceRegistryCodeHash,address smartKeyAccountFactory,bytes32 smartKeyAccountFactoryCodeHash,address zetherStatements,bytes32 zetherStatementsCodeHash)";

/// The 18 ops and their params after `bytes32 from,address target`, the router entry's in order (spec §5.4, owner naming
/// 2026-11-11).
pub const ADMIN_OPS: [(&str, &str); 18] = [
    ("UATransferAdmin", "bytes32 newAdmin,bytes32 chainUid"),
    ("UAAcceptAdmin", ""),
    ("UARenounceAdmin", "bytes32 chainUid"),
    ("UAPublishTokenEnv", "uint8 kind,uint16 envVersion,bytes32 chainUid,Env env"),
    ("UAPublishDexEnv", "uint16 envVersion,bytes32 chainUid,Env env"),
    ("UAPublishClassEnv", "uint16 contractClass,uint16 kind,uint16 envVersion,bytes32 chainUid,Env env"),
    ("UADeprecateToken", "uint8 kind,uint64 version,bytes32 chainUid,string reason"),
    ("UADeprecateDex", "uint64 version,bytes32 chainUid,string reason"),
    ("UADeprecateRelease", "uint16 contractClass,uint16 kind,uint64 version,bytes32 chainUid,string reason"),
    ("UASetTokenKindEnabled", "uint8 kind,bool on,bytes32 chainUid"),
    ("UASetClassKindEnabled", "uint16 contractClass,uint16 kind,bool on,bytes32 chainUid"),
    ("UASetKycProvider", "bytes32 provider,bool enabled"),
    ("UASetCompliance", "bytes32[] accounts,uint64[] flags,uint64[] until"),
    ("UASetChainEntries", "ChainEntries entries,bytes32 chainUid"),
    ("UAApproveTokenRelease", "uint8 kind,uint64 version,uint16 envVersion,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until"),
    ("UAApproveDexRelease", "uint64 version,uint16 envVersion,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until"),
    ("UAApproveRelease", "uint16 contractClass,uint16 kind,uint64 version,uint16 envVersion,bytes4 initSelector,bytes4 interfaceId,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until"),
    ("UARevokeApproval", "bytes32 key,bytes32 chainUid"),
];

/// A release env (`IOpenFactory.Env`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env {
    pub registry: [u8; 20],
    pub smart_key_account_impl: [u8; 20],
    pub hedera: bool,
    pub deps: Vec<[u8; 20]>,
    pub params: Vec<[u8; 32]>,
    pub libs: Vec<[u8; 20]>,
    pub lib_code_hashes: Vec<[u8; 32]>,
}

/// One param: a static field as its ABI word (`bytes4` left-aligned), a `string`, an array as its elements' words, an `Env`,
/// the nine words of a `ChainEntries` in its field order (CTR-GOV-27).
#[derive(Debug, Clone, Copy)]
pub enum Param<'a> {
    Word([u8; 32]),
    Text(&'a str),
    Words(&'a [[u8; 32]]),
    Env(&'a Env),
    ChainEntries(&'a [[u8; 32]; 9]),
}

fn params_of(op: &str) -> Option<&'static str> {
    ADMIN_OPS.iter().find(|(n, _)| *n == op).map(|(_, p)| *p)
}

/// `UA<Op>(bytes32 from,address target,<params>,<E>)`, then `Env(…)` when a param is one.
pub fn type_string(op: &str) -> Option<String> {
    params_of(op).map(|p| {
        let sep = if p.is_empty() { "" } else { "," };
        let env = if p.contains("Env env") { ENV_TYPE } else { "" };
        let ce = if p.contains("ChainEntries entries") { CHAIN_ENTRIES_TYPE } else { "" };
        format!("{op}(bytes32 from,address target,{p}{sep}{ENVELOPE}){env}{ce}")
    })
}

/// A static word fits its type: `uintN` / `bool` / `address` with the high bytes 0, `bytes4` with the low 28.
fn fits(ty: &str, w: &[u8; 32]) -> bool {
    let high = |n: usize| w[..32 - n].iter().all(|b| *b == 0);
    match ty {
        "bytes32" | "uint256" => true,
        "bytes4" => w[4..].iter().all(|b| *b == 0),
        "address" => high(20),
        "bool" => high(1) && w[31] <= 1,
        t => t.strip_prefix("uint").and_then(|b| b.parse::<usize>().ok()).is_some_and(|b| high(b / 8)),
    }
}

fn words_hash(ws: &[[u8; 32]]) -> [u8; 32] {
    keccak(&ws.iter().map(|w| &w[..]).collect::<Vec<_>>())
}

/// `hashStruct(Env)`.
pub fn env_hash(e: &Env) -> [u8; 32] {
    let addrs = |a: &[[u8; 20]]| words_hash(&a.iter().map(address_word).collect::<Vec<_>>());
    keccak(&[&keccak256(ENV_TYPE.as_bytes()), &address_word(&e.registry), &address_word(&e.smart_key_account_impl),
        &word(e.hedera as u64), &addrs(&e.deps), &words_hash(&e.params), &addrs(&e.libs), &words_hash(&e.lib_code_hashes)])
}

/// `hashStruct(ChainEntries)`: its typehash and the nine words (an address field with its high 12 bytes 0).
pub fn chain_entries_hash(w: &[[u8; 32]; 9]) -> Result<[u8; 32], RouterOpError> {
    let ty: Vec<&str> = CHAIN_ENTRIES_TYPE[13..CHAIN_ENTRIES_TYPE.len() - 1].split(',').map(|f| f.split_once(' ').unwrap().0).collect();
    if !ty.iter().zip(w).all(|(t, x)| fits(t, x)) {
        return Err(RouterOpError::Range);
    }
    let mut words = vec![keccak256(CHAIN_ENTRIES_TYPE.as_bytes())];
    words.extend_from_slice(w);
    Ok(words_hash(&words))
}

/// `hashStruct(UA<Op>)` over `params` (one per field, in order, each of its field's shape), `relayer` hashed as 0 unless
/// `mode & 1`, `feeRecipient` as 0 unless `mode & 2` (`MetaTxLib.canon`).
pub fn struct_hash(op: &str, e: &Envelope, target: &[u8; 20], params: &[Param]) -> Result<[u8; 32], RouterOpError> {
    let list = params_of(op).ok_or(RouterOpError::UnknownOp)?;
    let types: Vec<&str> = list.split(',').filter(|f| !f.is_empty()).map(|f| f.split_once(' ').map_or(f, |(t, _)| t)).collect();
    if types.len() != params.len() {
        return Err(RouterOpError::Params);
    }
    let canon = |bound: bool, a: &[u8; 20]| if bound { address_word(a) } else { [0; 32] };
    let mut words: Vec<[u8; 32]> = vec![keccak256(type_string(op).unwrap().as_bytes()), e.from, address_word(target)];
    for (ty, p) in types.iter().zip(params) {
        words.push(match (ty.strip_suffix("[]"), p) {
            (None, Param::Word(w)) if *ty != "string" && *ty != "Env" && *ty != "ChainEntries" => {
                if fits(ty, w) { *w } else { return Err(RouterOpError::Range) }
            }
            (None, Param::ChainEntries(c)) if *ty == "ChainEntries" => chain_entries_hash(c)?,
            (None, Param::Text(s)) if *ty == "string" => keccak256(s.as_bytes()),
            (None, Param::Env(v)) if *ty == "Env" => env_hash(v),
            (Some(el), Param::Words(ws)) if ws.iter().all(|w| fits(el, w)) => words_hash(ws),
            (Some(_), Param::Words(_)) => return Err(RouterOpError::Range),
            _ => return Err(RouterOpError::Params),
        });
    }
    words.extend([e.batch, e.nonce, e.valid_until, word(e.mode as u64), canon(e.mode & 1 != 0, &e.relayer), e.fee,
        canon(e.mode & 2 != 0, &e.fee_recipient)]);
    Ok(words_hash(&words))
}

/// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`, the router's domain (`regulated::router_domain_separator`).
pub fn digest(op: &str, domain_separator: &[u8; 32], e: &Envelope, target: &[u8; 20], params: &[Param])
    -> Result<[u8; 32], RouterOpError>
{
    Ok(keccak(&[&[0x19, 0x01], domain_separator, &struct_hash(op, e, target, params)?]))
}

/// The factory's approval key (spec §5.6 table): `keccak256(abi.encode(tag, chainUid, factory, <fields>, initcodeHash,
/// implArgsHash))`, one tag per deploy domain.
fn release_key(tag: &str, chain_uid: &[u8; 32], factory: &[u8; 20], fields: &[[u8; 32]], initcode_hash: &[u8; 32],
    impl_args_hash: &[u8; 32]) -> [u8; 32]
{
    let mut w = vec![keccak256(tag.as_bytes()), *chain_uid, address_word(factory)];
    w.extend_from_slice(fields);
    w.extend([*initcode_hash, *impl_args_hash]);
    words_hash(&w)
}

/// `deployTokenImplementation`'s key (`kind` the `TokenKind`).
pub fn token_release_key(chain_uid: &[u8; 32], factory: &[u8; 20], kind: u8, version: u64, env_version: u16,
    initcode_hash: &[u8; 32], impl_args_hash: &[u8; 32]) -> [u8; 32]
{
    release_key("scaas.factory.release.token", chain_uid, factory,
        &[word(kind as u64), word(version), word(env_version as u64)], initcode_hash, impl_args_hash)
}

/// `deployDexImplementation`'s key.
pub fn dex_release_key(chain_uid: &[u8; 32], factory: &[u8; 20], version: u64, env_version: u16, initcode_hash: &[u8; 32],
    impl_args_hash: &[u8; 32]) -> [u8; 32]
{
    release_key("scaas.factory.release.dex", chain_uid, factory, &[word(version), word(env_version as u64)], initcode_hash,
        impl_args_hash)
}

/// `deployImplementation`'s key (the `ReleaseId` in place, then `initSelector` and `interfaceId` left-aligned).
#[allow(clippy::too_many_arguments)]
pub fn class_release_key(chain_uid: &[u8; 32], factory: &[u8; 20], contract_class: u16, kind: u16, version: u64,
    env_version: u16, init_selector: [u8; 4], interface_id: [u8; 4], initcode_hash: &[u8; 32], impl_args_hash: &[u8; 32])
    -> [u8; 32]
{
    let left = |b: [u8; 4]| {
        let mut w = [0u8; 32];
        w[..4].copy_from_slice(&b);
        w
    };
    release_key("scaas.factory.release.class", chain_uid, factory,
        &[word(contract_class as u64), word(kind as u64), word(version), word(env_version as u64), left(init_selector),
            left(interface_id)], initcode_hash, impl_args_hash)
}
