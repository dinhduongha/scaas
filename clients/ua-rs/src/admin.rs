// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Round 3r (CTR-GOV-23, spec 2026-11-10-admin-not-owner.md §5.4, §5.6, §7): the `GovernanceRouter`'s 18 admin ops (the three
//! of a governed contract's admin, the 15 of `OpenFactory`'s and a `ComplianceRegistry`'s admin), so a PQ or `msig` admin signs
//! them through ua-rs: their type strings, struct hashes (an `Env` nested, each array the `keccak256` of its words, a `string`
//! the `keccak256` of its bytes) and digests in the router's domain (`MetaTxLib.canon`'s zeroing of an unbound `relayer` /
//! `feeRecipient`), and the factory's release approval keys (`approvalOf`, `revokeApproval`). Pinned by
//! `smartcontracts/vectors/typed/typed_ops.json` (clientkeys; the keys checked on the factory by forge). The contract decides;
//! nothing here is a check of record. UNAUDITED.
use crate::regulated::{router_ops, router_struct_hash, Envelope, FieldWord, RouterOp};
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
    // CTR-GOV-28 (owner 2026-11-13): the registry's chain word last
    ("UASetKycProvider", "bytes32 provider,bool enabled,bytes32 chainUid"),
    ("UASetCompliance", "bytes32[] accounts,uint64[] flags,uint64[] until,bytes32 chainUid"),
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

/// `IOpenFactory.ChainEntries` (CTR-GOV-27), nested in `UASetChainEntries`, its fields in `CHAIN_ENTRIES_TYPE`'s order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainEntries {
    pub relay_fee_router: [u8; 20],
    pub relay_fee_router_code_hash: [u8; 32],
    pub relay_fee_executor_code_hash: [u8; 32],
    pub compliance_registry: [u8; 20],
    pub compliance_registry_code_hash: [u8; 32],
    pub smart_key_account_factory: [u8; 20],
    pub smart_key_account_factory_code_hash: [u8; 32],
    pub zether_statements: [u8; 20],
    pub zether_statements_code_hash: [u8; 32],
}

/// One of the 18 admin ops (`ADMIN_OPS`), hashed by `struct_hash` / `digest` here.
pub trait AdminOp: RouterOp {}

router_ops! { AdminOp;
    UATransferAdmin { new_admin: [u8; 32], chain_uid: [u8; 32] }
    UAAcceptAdmin {}
    UARenounceAdmin { chain_uid: [u8; 32] }
    UAPublishTokenEnv { kind: u8, env_version: u16, chain_uid: [u8; 32], env: Env }
    UAPublishDexEnv { env_version: u16, chain_uid: [u8; 32], env: Env }
    UAPublishClassEnv { contract_class: u16, kind: u16, env_version: u16, chain_uid: [u8; 32], env: Env }
    UADeprecateToken { kind: u8, version: u64, chain_uid: [u8; 32], reason: String }
    UADeprecateDex { version: u64, chain_uid: [u8; 32], reason: String }
    UADeprecateRelease { contract_class: u16, kind: u16, version: u64, chain_uid: [u8; 32], reason: String }
    UASetTokenKindEnabled { kind: u8, on: bool, chain_uid: [u8; 32] }
    UASetClassKindEnabled { contract_class: u16, kind: u16, on: bool, chain_uid: [u8; 32] }
    UASetKycProvider { provider: [u8; 32], enabled: bool, chain_uid: [u8; 32] }
    UASetCompliance { accounts: Vec<[u8; 32]>, flags: Vec<u64>, until: Vec<u64>, chain_uid: [u8; 32] }
    UASetChainEntries { entries: ChainEntries, chain_uid: [u8; 32] }
    UAApproveTokenRelease { kind: u8, version: u64, env_version: u16, initcode_hash: [u8; 32], impl_args_hash: [u8; 32],
        chain_uid: [u8; 32], factory: [u8; 20], admin_generation: u32, until: u64 }
    UAApproveDexRelease { version: u64, env_version: u16, initcode_hash: [u8; 32], impl_args_hash: [u8; 32], chain_uid: [u8; 32],
        factory: [u8; 20], admin_generation: u32, until: u64 }
    UAApproveRelease { contract_class: u16, kind: u16, version: u64, env_version: u16, init_selector: [u8; 4], interface_id: [u8; 4],
        initcode_hash: [u8; 32], impl_args_hash: [u8; 32], chain_uid: [u8; 32], factory: [u8; 20], admin_generation: u32, until: u64 }
    UARevokeApproval { key: [u8; 32], chain_uid: [u8; 32] }
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

fn words_hash(ws: &[[u8; 32]]) -> [u8; 32] {
    keccak(&ws.iter().map(|w| &w[..]).collect::<Vec<_>>())
}

/// `hashStruct(Env)`.
pub fn env_hash(e: &Env) -> [u8; 32] {
    let addrs = |a: &[[u8; 20]]| words_hash(&a.iter().map(address_word).collect::<Vec<_>>());
    keccak(&[&keccak256(ENV_TYPE.as_bytes()), &address_word(&e.registry), &address_word(&e.smart_key_account_impl),
        &word(e.hedera as u64), &addrs(&e.deps), &words_hash(&e.params), &addrs(&e.libs), &words_hash(&e.lib_code_hashes)])
}
impl FieldWord for Env {
    fn field_word(&self) -> [u8; 32] {
        env_hash(self)
    }
}

/// `hashStruct(ChainEntries)`: its typehash and the nine fields' words.
pub fn chain_entries_hash(c: &ChainEntries) -> [u8; 32] {
    words_hash(&[keccak256(CHAIN_ENTRIES_TYPE.as_bytes()), c.relay_fee_router.field_word(), c.relay_fee_router_code_hash,
        c.relay_fee_executor_code_hash, c.compliance_registry.field_word(), c.compliance_registry_code_hash,
        c.smart_key_account_factory.field_word(), c.smart_key_account_factory_code_hash, c.zether_statements.field_word(),
        c.zether_statements_code_hash])
}
impl FieldWord for ChainEntries {
    fn field_word(&self) -> [u8; 32] {
        chain_entries_hash(self)
    }
}

/// `hashStruct(UA<Op>)` of one of the 18 typed admin ops, `relayer` hashed as 0 unless `mode & 1`, `feeRecipient` as 0
/// unless `mode & 2` (`MetaTxLib.canon`).
pub fn struct_hash<O: AdminOp>(op: &O, e: &Envelope, target: &[u8; 20]) -> [u8; 32] {
    router_struct_hash(&type_string(O::NAME).expect("an AdminOp is in ADMIN_OPS"), e, target, op.field_words())
}

/// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`, the router's domain (`regulated::router_domain_separator`).
pub fn digest<O: AdminOp>(op: &O, domain_separator: &[u8; 32], e: &Envelope, target: &[u8; 20]) -> [u8; 32] {
    keccak(&[&[0x19, 0x01], domain_separator, &struct_hash(op, e, target)])
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
