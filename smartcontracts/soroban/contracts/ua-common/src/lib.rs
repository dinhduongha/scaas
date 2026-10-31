//! Types, the registry client and the digests shared by the UA-Soroban contracts (spec §2, §4, §5): the registry, the
//! token, the mandate, the DEX and the relay-fee router.
#![no_std]
use soroban_sdk::{contractclient, contracttype, crypto::Hash, xdr::ToXdr, Address, Bytes, BytesN, Env, Symbol, Val, Vec};

/// A holder: a native Soroban address or a derived UA id (never a native one, spec §2).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Holder {
    Addr(Address),
    Ua(BytesN<32>),
}

/// Who checked a part of a record: UA-8 P11.3 code points 0 / 1 / 2 (`portable.json` `checked`).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Checked {
    None,
    Chain,
    Relayer(Address),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UaAttrs {
    pub pqz_key: Bytes,
    pub pqz_pop_hash: BytesN<32>,
    pub kem_version: u64,
    pub kem_pk: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registration {
    pub kind: u32,
    pub key_data: Bytes,
    pub attrs: UaAttrs,
    pub pop: Bytes,
    pub pop_checked: Checked,
    pub pqz_pop_checked: Checked,
    pub proven: bool,
    pub signable: bool,
    pub index: u32,
    pub ledger: u32,
}

/// A DEX order (spec §5.3).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Order {
    pub maker: Holder,
    pub destination: Holder,
    pub relayer: Address,
    pub sell_token: Address,
    pub sell_amount: i128,
    pub buy_token: Address,
    pub buy_amount: i128,
    pub max_fee_ppm: u32,
    pub expiry: u64,
    pub salt: u64,
}

/// What the tokens, the mandate and the DEX call on the registry (spec §4).
#[contractclient(name = "UaRegistryClient")]
pub trait UaRegistryApi {
    fn require_authorized(env: Env, ua: BytesN<32>, purpose: BytesN<32>, digest: BytesN<32>, auth: Bytes);
    fn receivable(env: Env, ua: BytesN<32>) -> bool;
    fn record_of(env: Env, ua: BytesN<32>) -> Option<Registration>;
}

const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hex"),
    }
}

/// 64 lowercase hex digits → 32 bytes, at compile time.
pub const fn h32(s: &str) -> [u8; 32] {
    let s = s.as_bytes();
    assert!(s.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nib(s[2 * i]) << 4 | nib(s[2 * i + 1]);
        i += 1;
    }
    out
}

/// `keccak256("scaas.ua.purpose.<name>.v<n>")`: the purposeTags of CTR-UA-12 (pinned by `kinds.json`).
pub const PURPOSE_METATX: [u8; 32] = h32("659f1188c729a1ac7e7f664f5bdf6be9f45677d902d8cc3cf2c018ac7449c18f");
pub const PURPOSE_METATX_CANCEL: [u8; 32] = h32("db7b4c83541295f8e4a820e0b06fdb28d5f35d14e7ce801208eb23ecf9af6183");
pub const PURPOSE_TRADE: [u8; 32] = h32("c9e1f4425dfd623d47306639b52fc06a544c0894eddfea71bd35af4fa4fdc29f");
pub const PURPOSE_MEMBER: [u8; 32] = h32("fbd8600564b68d09f75fe5d3e6acb8fe3c5a3a4cb20da6988723433beff5212a");
pub const PURPOSE_POP_V2: [u8; 32] = h32("0ffb2c52d2a16294393778508b3fff52351664d2c5bbe5deb3d3278f56281f93");
pub const PURPOSE_KEM: [u8; 32] = h32("99f2818f111f001f1f71ec2f8756cff7e9858c0fcb204b353c21f95b2ff3f2b8");
pub const PURPOSE_PQZ_KEY: [u8; 32] = h32("8f354ac3b315d85e2c32c80857a1600c5aebe8bbe14a265d56079725a6602330");

/// typed-signing TS-D1 (owner 2026-10-31 decisions 2 + 8), byte-identical to EVM `UAKinds`: the portable records are
/// EIP-712 structs under `EIP712Domain(string name,string version)` = ("SCaaS UA Portable", "1"), no chain id, contract
/// or salt (a record registers a UA on every chain, CTR-UA-07); `kind` is `uint16`. Pinned by `portable.json` `typed`.
pub const PORTABLE_DOMAIN_SEPARATOR: [u8; 32] = h32("9a2c390d4dc940ccdb5fa6b21e673e87159bdd99aeef22ea791bcea9efc64ca1");
/// `keccak256("UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)")`.
pub const UA_KEM_RECORD_TYPEHASH: [u8; 32] = h32("0ab7989827627b89c268e88a0a0b06b62aefa70b0a466014931ca44acfa9a201");
/// `keccak256("UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)" ‖ UAKemRecord type)`.
pub const UA_PORTABLE_RECORD_TYPEHASH: [u8; 32] = h32("0c1553cfab3c35326558484df79963dced75ead85272d2a85985f264757bfe7f");
/// `keccak256("UARegistration(UAPortableRecord record,bytes32 pqzPopHash)" ‖ UAKemRecord type ‖ UAPortableRecord type)`.
pub const UA_REGISTRATION_TYPEHASH: [u8; 32] = h32("c78b548ceb2fadf1f0a895f79f88b517327c120f0f9ab345f02981441048c87e");

/// A `uint` ABI word (`abi.encode` of `uint8` / `uint16` / `uint64`).
fn uint_word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn keccak_words(env: &Env, words: &[&[u8; 32]]) -> Hash<32> {
    let mut b = Bytes::new(env);
    for w in words {
        b.extend_from_array(w);
    }
    env.crypto().keccak256(&b)
}

/// `keccak256(0x1901 ‖ PORTABLE_DOMAIN_SEPARATOR ‖ structHash)`: what `eth_signTypedData_v4` returns for the record.
pub fn portable_digest(env: &Env, struct_hash: &BytesN<32>) -> Hash<32> {
    let mut b = Bytes::from_array(env, &[0x19, 0x01]);
    b.extend_from_array(&PORTABLE_DOMAIN_SEPARATOR);
    b.extend_from_array(&struct_hash.to_array());
    env.crypto().keccak256(&b)
}

/// `hashStruct(UAKemRecord{ua, version, scheme, kemPkHash})`; "no KEM key" is the zero record `{ua, 0, 0, 0}`.
pub fn kem_record_hash(env: &Env, ua: &BytesN<32>, version: u64, scheme: u8, kem_pk_hash: &BytesN<32>) -> BytesN<32> {
    let (v, s) = (uint_word(version), uint_word(scheme as u64));
    keccak_words(env, &[&UA_KEM_RECORD_TYPEHASH, &ua.to_array(), &v, &s, &kem_pk_hash.to_array()]).into()
}

/// `hashStruct(UAPortableRecord{ua, kind, pqzKeyHash, kem})`, `kem_hash = kem_record_hash` of the initial KEM record.
pub fn portable_record_hash(env: &Env, ua: &BytesN<32>, kind: u32, pqz_key_hash: &BytesN<32>, kem_hash: &BytesN<32>) -> BytesN<32> {
    let k = uint_word(kind as u64);
    keccak_words(env, &[&UA_PORTABLE_RECORD_TYPEHASH, &ua.to_array(), &k, &pqz_key_hash.to_array(), &kem_hash.to_array()]).into()
}

/// typed(`UARegistration{record, pqzPopHash}`), `record_hash = portable_record_hash`: the `pop` signs
/// `ua_message(kind, PURPOSE_POP_V2, ·)` of it; a native `evm-eoa` msig member signs it itself (TS-D4).
pub fn registration_digest(env: &Env, record_hash: &BytesN<32>, pqz_pop_hash: &BytesN<32>) -> Hash<32> {
    let s = keccak_words(env, &[&UA_REGISTRATION_TYPEHASH, &record_hash.to_array(), &pqz_pop_hash.to_array()]);
    portable_digest(env, &s.into())
}

/// NET-SOR-16's op digest (spec §2): `sha256(xdr(Vec[Symbol("scaas_metaop_v1"), network_id, contract, Symbol(fn),
/// Vec(args)]))`, the entry's arguments without `auth`. The token passes its own address; `ua_trade` passes itself with
/// function `"ua_order"` (spec §5.3).
pub fn op_digest(env: &Env, contract: &Address, function: &str, args: Vec<Val>) -> BytesN<32> {
    let v = (Symbol::new(env, "scaas_metaop_v1"), env.ledger().network_id(), contract.clone(), Symbol::new(env, function), args);
    env.crypto().sha256(&v.to_xdr(env)).into()
}

fn keccak_of(env: &Env, prefix: &[u8], words: &[&BytesN<32>]) -> BytesN<32> {
    let mut b = Bytes::from_slice(env, prefix);
    for w in words {
        b.append(&Bytes::from_array(env, &w.to_array()));
    }
    env.crypto().keccak256(&b).into()
}

/// CTR-MTX-03: `keccak256("scaas.pay.lane" ‖ pay_ref)`, as EVM `payLane`.
pub fn pay_lane(env: &Env, pay_ref: &BytesN<32>) -> BytesN<32> {
    keccak_of(env, b"scaas.pay.lane", &[pay_ref])
}

/// CTR-MTX-26: `keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`.
pub fn meta_pay_id(env: &Env, salt: &BytesN<32>, meta: &Bytes) -> BytesN<32> {
    keccak_of(env, b"scaas.pay.meta", &[salt, &env.crypto().keccak256(meta).to_bytes()])
}
