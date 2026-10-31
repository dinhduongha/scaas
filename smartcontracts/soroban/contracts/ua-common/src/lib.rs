//! Types, the registry client and the digests shared by the UA-Soroban contracts (spec §2, §4, §5): the registry, the
//! token, the mandate, the DEX and the relay-fee router.
#![no_std]
use soroban_sdk::{contractclient, contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env, Symbol, Val, Vec};

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
