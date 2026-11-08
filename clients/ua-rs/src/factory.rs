// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The factory's chain-neutral creation address off chain (chain-neutral releases spec §2.1, §4, §6.4; CTR-TOK-29; clientkeys
//! `factory.js`): the CREATE3 address of a creation depends only on the factory, the creator's UA id, the class, the kind and
//! the salt, so a signer shows it before a `UACreateToken` / `UACreateDex` / `UACreateInstance` (ua-mtx-merge T76). Pinned by
//! `smartcontracts/vectors/factory/create3_kat.json` (forge, `test/v2/Create3Kat.t.sol`). The address says nothing about the
//! version, the code or the configuration on a chain: those are read per chain (`infoOf(addr)`, spec §4.3). UNAUDITED.
use crate::{keccak, word};

/// `PUSH8 363d3d37363d34f0 RETURNDATASIZE MSTORE PUSH1 8 PUSH1 24 RETURN`: deposits the proxy's runtime.
pub const PROXY_INITCODE: [u8; 16] = [0x67, 0x36, 0x3d, 0x3d, 0x37, 0x36, 0x3d, 0x34, 0xf0, 0x3d, 0x52, 0x60, 0x08, 0x60, 0x18, 0xf3];
/// `keccak256(PROXY_INITCODE)`.
pub const PROXY_INITCODE_HASH: [u8; 32] = [
    0x21, 0xc3, 0x5d, 0xbe, 0x1b, 0x34, 0x4a, 0x24, 0x88, 0xcf, 0x33, 0x21, 0xd6, 0xce, 0x54, 0x2f, 0x8e, 0x9f, 0x30, 0x55, 0x44,
    0xff, 0x09, 0xe4, 0x99, 0x3a, 0x62, 0x31, 0x9a, 0x49, 0x7c, 0x1f,
];
/// The factory's classes (`OpenFactory.CLASS_TOKEN`, `CLASS_DEX`; generic classes from 3, T70).
pub const CLASS_TOKEN: u16 = 1;
pub const CLASS_DEX: u16 = 2;

/// A creation's CREATE3 salt `s`, its CREATE2 proxy and the instance the proxy creates at its nonce 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Create3 {
    pub s: [u8; 32],
    pub proxy: [u8; 20],
    pub instance: [u8; 20],
}

/// `s = keccak256(abi.encode(creatorId, contractClass, kind, salt))`.
pub fn create3_salt(creator_id: &[u8; 32], contract_class: u16, kind: u16, salt: &[u8; 32]) -> [u8; 32] {
    keccak(&[creator_id, &word(u64::from(contract_class)), &word(u64::from(kind)), salt])
}

/// The address of a creation by `factory`: the proxy `keccak256(0xff ‖ factory ‖ s ‖ keccak256(PROXY_INITCODE))[12..]`, the
/// instance `keccak256(rlp([proxy, 1]))[12..] = keccak256(0xd6 0x94 ‖ proxy ‖ 0x01)[12..]`.
pub fn create3_address(factory: &[u8; 20], creator_id: &[u8; 32], contract_class: u16, kind: u16, salt: &[u8; 32]) -> Create3 {
    let s = create3_salt(creator_id, contract_class, kind, salt);
    let last20 = |h: [u8; 32]| -> [u8; 20] {
        let mut a = [0u8; 20];
        a.copy_from_slice(&h[12..]);
        a
    };
    let proxy = last20(keccak(&[&[0xff], factory, &s, &PROXY_INITCODE_HASH]));
    let instance = last20(keccak(&[&[0xd6, 0x94], &proxy, &[0x01]]));
    Create3 { s, proxy, instance }
}

/// The EIP-1167 proxy every clone of a chain-neutral release starts with: `363d3d373d3d3d363d73 ‖ implementation ‖
/// 5af43d82803e903d91602b57fd5bf3`, 45 bytes; its `ChainEnv` follows (chain-neutral spec §2; `create3_kat.json` pins both).
pub const PROXY_HEAD: [u8; 10] = [0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73];
pub const PROXY_TAIL: [u8; 15] = [0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60, 0x2b, 0x57, 0xfd, 0x5b, 0xf3];
const MAX_DEPS: usize = 4;
const MAX_PARAMS: usize = 2;

/// A clone's `ChainEnv`: `chainUid ‖ registry ‖ govRouter ‖ smartKeyAccountImpl ‖ hedera ‖ nDeps ‖ deps ‖ nParams ‖ params`
/// (at most 4 deps, 2 params). The reference readers check `--registry` against `registry` (owner 2026-11-08).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainEnv {
    pub chain_uid: [u8; 32],
    pub registry: [u8; 20],
    pub gov_router: [u8; 20],
    pub smart_key_account_impl: [u8; 20],
    pub hedera: bool,
    pub deps: Vec<[u8; 20]>,
    pub params: Vec<[u8; 32]>,
}

/// The env's bytes as the factory appends them (clientkeys `chainEnvBytes`).
pub fn env_bytes(e: &ChainEnv) -> Vec<u8> {
    let mut b = [&e.chain_uid[..], &e.registry, &e.gov_router, &e.smart_key_account_impl, &[u8::from(e.hedera), e.deps.len() as u8]].concat();
    e.deps.iter().for_each(|d| b.extend_from_slice(d));
    b.push(e.params.len() as u8);
    e.params.iter().for_each(|p| b.extend_from_slice(p));
    b
}

/// A clone's runtime: the proxy of `implementation`, then the env (clientkeys `cloneRuntime`).
pub fn clone_runtime(implementation: &[u8; 20], e: &ChainEnv) -> Vec<u8> {
    [&PROXY_HEAD[..], implementation, &PROXY_TAIL, &env_bytes(e)].concat()
}

/// A runtime's implementation and `ChainEnv` when it is exactly a clone of a chain-neutral release: the proxy, then one env
/// within its bounds (`hedera` 0 or 1, at most 4 deps and 2 params) and nothing after; `None` for any other code.
pub fn clone_env(runtime: &[u8]) -> Option<([u8; 20], ChainEnv)> {
    let take = |at: &mut usize, n: usize| -> Option<&[u8]> {
        let s = runtime.get(*at..at.checked_add(n)?)?;
        *at += n;
        Some(s)
    };
    let mut at = 0;
    (take(&mut at, 10)? == PROXY_HEAD).then_some(())?;
    let implementation: [u8; 20] = take(&mut at, 20)?.try_into().ok()?;
    (take(&mut at, 15)? == PROXY_TAIL).then_some(())?;
    let chain_uid = take(&mut at, 32)?.try_into().ok()?;
    let registry = take(&mut at, 20)?.try_into().ok()?;
    let gov_router = take(&mut at, 20)?.try_into().ok()?;
    let smart_key_account_impl = take(&mut at, 20)?.try_into().ok()?;
    let hedera = match take(&mut at, 1)? {
        [0] => false,
        [1] => true,
        _ => return None,
    };
    let n_deps = usize::from(*take(&mut at, 1)?.first()?);
    (n_deps <= MAX_DEPS).then_some(())?;
    let deps = (0..n_deps).map(|_| take(&mut at, 20)?.try_into().ok()).collect::<Option<Vec<[u8; 20]>>>()?;
    let n_params = usize::from(*take(&mut at, 1)?.first()?);
    (n_params <= MAX_PARAMS).then_some(())?;
    let params = (0..n_params).map(|_| take(&mut at, 32)?.try_into().ok()).collect::<Option<Vec<[u8; 32]>>>()?;
    (at == runtime.len()).then_some(())?;
    Some((implementation, ChainEnv { chain_uid, registry, gov_router, smart_key_account_impl, hedera, deps, params }))
}
