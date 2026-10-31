//! T0 spike (plan UA-Soroban T0, spec §10 T0, S13a): cost models of the UA-Soroban calls and of the BLS12-381 building blocks of a
//! classical Zether verifier at Protocol 30. This crate is the registry side (`register`, `msig`, `require_authorized`,
//! `receivable`); `ua-spike-token` is the token side of `ua_pay` (spec §5.1). Each model does the host work of the call
//! it stands for; it is not the registry, the token or a verifier. Never deployed outside the spike.
#![no_std]
#![allow(deprecated)] // events().publish

use soroban_sdk::{
    contract, contractimpl, contracttype,
    crypto::bls12_381::{Bls12381Fr, Bls12381G1Affine, Bls12381G2Affine},
    Address, Bytes, BytesN, Env, Symbol, Vec, U256,
};

const DAY: u32 = 17_280;
pub const K_WEBAUTHN: u32 = 0x0100;
pub const K_MLDSA44: u32 = 0x0130;
pub const K_MLDSA65: u32 = 0x0131;
pub const K_MSIG: u32 = 0x0120;

// spec §4 types
#[contracttype]
#[derive(Clone)]
pub enum Checked {
    None,
    Chain,
    Relayer(Address),
}

#[contracttype]
#[derive(Clone)]
pub struct UaAttrs {
    pub pqz_key: Bytes,
    pub pqz_pop_hash: BytesN<32>,
    pub kem_version: u64,
    pub kem_pk: Bytes,
}

#[contracttype]
#[derive(Clone)]
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

/// The `UaRegistered` data (owner ruling 2026-10-30): the `Registration` with `pop` replaced by `pop_hash`.
#[contracttype]
pub struct RegisteredEvent {
    pub kind: u32,
    pub key_data: Bytes,
    pub attrs: UaAttrs,
    pub pop_hash: BytesN<32>,
    pub pop_checked: Checked,
    pub pqz_pop_checked: Checked,
    pub proven: bool,
    pub signable: bool,
    pub index: u32,
    pub ledger: u32,
    pub checked: Checked,
}

#[contracttype]
pub enum Key {
    Ua(BytesN<32>),
    Key(BytesN<32>),
    List(u32, u32),
    Count(u32),
}

pub fn h(env: &Env, data: &Bytes) -> BytesN<32> {
    env.crypto().keccak256(data).into()
}

fn hs(env: &Env, s: &str) -> BytesN<32> {
    h(env, &Bytes::from_slice(env, s.as_bytes()))
}

/// keccak256(s) of a purpose name: the purposeTag of CTR-UA-12.
pub fn purpose(env: &Env, name: &str) -> BytesN<32> {
    hs(env, name)
}

fn tag_name(kind: u32) -> &'static str {
    match kind {
        K_WEBAUTHN => "scaas.ua.webauthn-p256.v1",
        K_MLDSA44 => "scaas.ua.mldsa44.v1",
        K_MLDSA65 => "scaas.ua.mldsa65.v1",
        K_MSIG => "scaas.ua.msig.v1",
        _ => panic!("kind"),
    }
}

/// keccak256(TAG(kind) ‖ x): the CTR-UA-04 id when x is the key data, pq_msg when x is ua_msg (CTR-UA-23).
pub fn tagged(env: &Env, kind: u32, x: &Bytes) -> BytesN<32> {
    let mut m = Bytes::from_array(env, &hs(env, tag_name(kind)).to_array());
    m.append(x);
    h(env, &m)
}

/// ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest) (CTR-UA-12).
pub fn ua_msg(env: &Env, kind: u32, purpose: &BytesN<32>, digest: &BytesN<32>) -> BytesN<32> {
    let mut m = Bytes::from_array(env, &hs(env, "scaas.ua.msg.v1").to_array());
    m.append(&Bytes::from_array(env, &hs(env, tag_name(kind)).to_array()));
    m.append(&Bytes::from_array(env, &purpose.to_array()));
    m.append(&Bytes::from_array(env, &digest.to_array()));
    h(env, &m)
}

fn bump(env: &Env, k: &Key) {
    env.storage().persistent().extend_ttl(k, 30 * DAY, 60 * DAY);
}

fn put<V: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(env: &Env, k: &Key, v: &V) {
    env.storage().persistent().set(k, v);
    bump(env, k);
}

fn mldsa_verify(env: &Env, kind: u32, pk: &Bytes, msg: &Bytes, sig: &Bytes) {
    let ctx = Bytes::new(env);
    match kind {
        K_MLDSA44 => env.crypto().ml_dsa_44_verify(
            &pk.clone().try_into().unwrap(),
            msg,
            &sig.clone().try_into().unwrap(),
            &ctx,
        ),
        K_MLDSA65 => env.crypto().ml_dsa_65_verify(
            &pk.clone().try_into().unwrap(),
            msg,
            &sig.clone().try_into().unwrap(),
            &ctx,
        ),
        _ => panic!("kind"),
    }
}

/// The `register` writes after its checks: `Ua(id)` (the full `Registration`), `List(kind, i)`, `Count(kind)` and the
/// `UaRegistered` event (topics `ua`, `kind`; data the record with `pop_hash = keccak256(pop)` for `pop`, and
/// `checked`: spec §4, owner ruling 2026-10-30).
fn store(env: &Env, id: &BytesN<32>, kind: u32, key_data: Bytes, pop: Bytes) {
    let count_key = Key::Count(kind);
    let i: u32 = env.storage().persistent().get(&count_key).unwrap_or(0);
    let rec = Registration {
        kind,
        key_data,
        attrs: UaAttrs {
            pqz_key: Bytes::new(env),
            pqz_pop_hash: BytesN::from_array(env, &[0; 32]),
            kem_version: 0,
            kem_pk: Bytes::new(env),
        },
        pop,
        pop_checked: Checked::Chain,
        pqz_pop_checked: Checked::None,
        proven: true,
        signable: true,
        index: i,
        ledger: env.ledger().sequence(),
    };
    put(env, &Key::Ua(id.clone()), &rec);
    put(env, &Key::List(kind, i), id);
    put(env, &count_key, &(i + 1));
    let ev = RegisteredEvent {
        kind,
        key_data: rec.key_data,
        attrs: rec.attrs,
        pop_hash: h(env, &rec.pop),
        pop_checked: rec.pop_checked,
        pqz_pop_checked: rec.pqz_pop_checked,
        proven: rec.proven,
        signable: rec.signable,
        index: rec.index,
        ledger: rec.ledger,
        checked: Checked::Chain,
    };
    env.events().publish((Symbol::new(env, "UaRegistered"), id.clone(), kind), ev);
}

// --- ABI words (abi.encode of the EVM structures, spec §3) ---
fn word(b: &Bytes, off: u32) -> u32 {
    let mut w = [0u8; 4];
    b.slice(off + 28..off + 32).copy_into_slice(&mut w);
    u32::from_be_bytes(w)
}

fn put_word(env: &Env, out: &mut Bytes, v: u32) {
    let mut w = [0u8; 32];
    w[28..].copy_from_slice(&v.to_be_bytes());
    out.append(&Bytes::from_array(env, &w));
}

fn pad32(n: u32) -> u32 {
    (n + 31) / 32 * 32
}

fn put_dyn(env: &Env, out: &mut Bytes, b: &Bytes) {
    put_word(env, out, b.len());
    out.append(b);
    out.append(&Bytes::from_slice(env, &[0u8; 32][..(pad32(b.len()) - b.len()) as usize]));
}

/// The dynamic `bytes` whose offset word sits at `head`, offsets relative to `base`.
fn dyn_at(b: &Bytes, base: u32, head: u32) -> Bytes {
    let o = base + word(b, head);
    b.slice(o + 32..o + 32 + word(b, o))
}

/// Decodes `abi.encode(MemberSig[])` (`{u16 index, bytes keyData, bytes sig}`, UA8-D5), canonical only: the decoded
/// members are re-encoded and compared with the input (as EVM m3).
fn member_sigs(env: &Env, auth: &Bytes) -> Vec<(u32, Bytes, Bytes)> {
    assert!(word(auth, 0) == 32, "Pop");
    let n = word(auth, 32);
    assert!(n <= 16, "Pop");
    let mut out = Vec::new(env);
    for i in 0..n {
        let t = 64 + word(auth, 64 + 32 * i);
        out.push_back((word(auth, t), dyn_at(auth, t, t + 32), dyn_at(auth, t, t + 64)));
    }
    let mut enc = Bytes::new(env);
    put_word(env, &mut enc, 32);
    put_word(env, &mut enc, n);
    let mut off = 32 * n;
    for (_, kd, sig) in out.iter() {
        put_word(env, &mut enc, off);
        off += 96 + 32 + pad32(kd.len()) + 32 + pad32(sig.len());
    }
    for (idx, kd, sig) in out.iter() {
        put_word(env, &mut enc, idx);
        put_word(env, &mut enc, 96);
        put_word(env, &mut enc, 96 + 32 + pad32(kd.len()));
        put_dyn(env, &mut enc, &kd);
        put_dyn(env, &mut enc, &sig);
    }
    assert!(enc == *auth, "Pop: not canonical");
    out
}

pub const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding of 32 bytes (43 characters).
pub fn b64url32(x: &[u8; 32]) -> [u8; 43] {
    let mut out = [0u8; 43];
    let (mut o, mut i) = (0, 0);
    while i < 32 {
        let n = (x[i] as u32) << 16 | (*x.get(i + 1).unwrap_or(&0) as u32) << 8 | *x.get(i + 2).unwrap_or(&0) as u32;
        for j in 0..4 {
            if o < 43 {
                out[o] = B64[(n >> (18 - 6 * j) & 63) as usize];
                o += 1;
            }
        }
        i += 3;
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// The S3 `webauthn-p256` check (spec §3): key data `x ‖ y ‖ rpIdHash`, `auth` =
/// `abi.encode(bytes authenticatorData, string clientDataJSON, uint256 r, uint256 s)`.
fn webauthn_check(env: &Env, kd: &Bytes, m: &BytesN<32>, auth: &Bytes) {
    let authenticator_data = dyn_at(auth, 0, 0);
    let client_data_json = dyn_at(auth, 0, 32);
    let sig: BytesN<64> = auth.slice(64..128).try_into().unwrap();
    let mut key = Bytes::from_array(env, &[4u8]);
    key.append(&kd.slice(0..64));
    let key: BytesN<65> = key.try_into().unwrap();
    // client data: type, challenge = base64url(ua_msg), crossOrigin absent or false, no topOrigin
    let n = client_data_json.len() as usize;
    assert!(n <= 1024);
    let mut cdj = [0u8; 1024];
    client_data_json.copy_into_slice(&mut cdj[..n]);
    let cdj = &cdj[..n];
    let pre = b"{\"type\":\"webauthn.get\",\"challenge\":\"";
    assert!(n > pre.len() + 44 && &cdj[..pre.len()] == pre);
    assert!(cdj[pre.len()..pre.len() + 43] == b64url32(&m.to_array()) && cdj[pre.len() + 43] == b'"');
    assert!(!contains(cdj, b"\"crossOrigin\":true") && !contains(cdj, b"\"topOrigin\""));
    // authenticator data: rpIdHash, UP and UV
    assert!(authenticator_data.len() >= 37);
    assert!(authenticator_data.slice(0..32) == kd.slice(64..96));
    assert!(authenticator_data.get(32).unwrap() & 0x05 == 0x05);
    let mut signed = authenticator_data.clone();
    signed.append(&env.crypto().sha256(&client_data_json).to_bytes().into());
    env.crypto().secp256r1_verify(&key, &env.crypto().sha256(&signed), &sig);
}

/// A big-endian u16 at `off`.
fn word2(b: &Bytes, off: u32) -> u32 {
    (b.get(off).unwrap() as u32) << 8 | b.get(off + 1).unwrap() as u32
}

// --- BLS12-381 fixed valid points (the generators) ---
const G1_GEN: [u8; 96] = hex96(
    b"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\
      08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
);
// X_c1 ‖ X_c0 ‖ Y_c1 ‖ Y_c0
const G2_GEN: [u8; 192] = hex192(
    b"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e\
      024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8\
      0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be\
      0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
);

const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hex"),
    }
}

/// Decodes hex, skipping the whitespace a `\` line continuation leaves.
const fn unhex<const N: usize>(s: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let (mut i, mut o) = (0, 0);
    while i < s.len() {
        if s[i] == b' ' {
            i += 1;
            continue;
        }
        out[o] = nib(s[i]) << 4 | nib(s[i + 1]);
        o += 1;
        i += 2;
    }
    assert!(o == N);
    out
}
const fn hex96(s: &[u8]) -> [u8; 96] {
    unhex::<96>(s)
}
const fn hex192(s: &[u8]) -> [u8; 192] {
    unhex::<192>(s)
}

fn g1(env: &Env) -> Bls12381G1Affine {
    Bls12381G1Affine::from_bytes(BytesN::from_array(env, &G1_GEN))
}
fn g2(env: &Env) -> Bls12381G2Affine {
    Bls12381G2Affine::from_bytes(BytesN::from_array(env, &G2_GEN))
}
fn fr(env: &Env, i: u32) -> Bls12381Fr {
    // a fixed full-width scalar per index (< r)
    Bls12381Fr::from_u256(U256::from_parts(env, 0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321, i as u64, 0x5555_aaaa))
}

/// G1 MSM of `n` points, each a fresh host object (the verifier reads its points from the proof / generator bytes).
fn msm(env: &Env, n: u32, s: &Bls12381Fr) -> Bls12381G1Affine {
    let (mut vp, mut vs) = (Vec::new(env), Vec::new(env));
    for _ in 0..n {
        vp.push_back(g1(env));
        vs.push_back(s.clone());
    }
    env.crypto().bls12_381().g1_msm(vp, vs)
}

/// The Zether Fiat-Shamir transcript (ZetherTranscript.sol): absorb = 1 keccak over `st ‖ header ‖ data`,
/// challenge = 3 keccak (st2, hi, lo) and a 512-bit reduction (here: two Fr reductions, one mul, one add).
struct Tr<'a> {
    env: &'a Env,
    st: BytesN<32>,
}

static ZEROS: [u8; 8192] = [0u8; 8192];

impl<'a> Tr<'a> {
    fn absorb(&mut self, len: u32) {
        let mut m = Bytes::from_array(self.env, &self.st.to_array());
        m.append(&Bytes::from_slice(self.env, &ZEROS[..(len as usize + 8)]));
        self.st = h(self.env, &m);
    }
    fn challenge(&mut self) -> Bls12381Fr {
        let mut m = Bytes::from_array(self.env, &self.st.to_array());
        m.push_back(1);
        self.st = h(self.env, &m);
        let mut a = Bytes::from_array(self.env, &self.st.to_array());
        let mut b2 = a.clone();
        a.push_back(2);
        b2.push_back(3);
        let hi = Bls12381Fr::from_bytes(h(self.env, &a));
        let lo = Bls12381Fr::from_bytes(h(self.env, &b2));
        let two256 = fr(self.env, 0);
        hi * two256 + lo
    }
}

const P: u32 = 96; // a Soroban G1 point
const NB: u32 = 64;
const KB: u32 = 6; // log2(64)

/// One Bulletproof range proof of 64 bits (ZetherVerifier.sol `verifyRange`): transcript, 7 inversions, the scalar
/// loops of `_bp1` / `_sVector` / `_bpVectorScalars` / `_bp2`, then the MSMs of 5 and 2n + 2k + 4 = 144 points.
fn range(env: &Env, t: &mut Tr) {
    t.absorb(2 * P + 4);
    let y = t.challenge();
    let z = t.challenge();
    t.absorb(2 * P);
    let x = t.challenge();
    t.absorb(96);
    let w = t.challenge();
    let mut u = Vec::new(env);
    for _ in 0..KB {
        t.absorb(2 * P);
        u.push_back(t.challenge());
    }
    // _bp1: Σy^i, δ
    let (mut sum_y, mut yi) = (fr(env, 1), fr(env, 1));
    for _ in 0..NB {
        sum_y = sum_y + yi.clone();
        yi = yi * y.clone();
    }
    let z2 = z.clone() * z.clone();
    let delta = (z.clone() - z2.clone()) * sum_y - z2.clone() * z.clone() * fr(env, 2);
    let _ = msm(env, 5, &(delta + x.clone() * x.clone()));
    // _sVector
    let mut s0 = fr(env, 1);
    let mut u_inv = Vec::new(env);
    for j in 0..KB {
        let ui = u.get(j).unwrap().inv();
        s0 = s0 * ui.clone();
        u_inv.push_back(ui);
    }
    let mut s = Vec::new(env);
    s.push_back(s0);
    for i in 1..NB {
        let lg = 31 - i.leading_zeros();
        let uj = u.get(KB - 1 - lg).unwrap();
        let v = s.get(i - (1 << lg)).unwrap() * (uj.clone() * uj);
        s.push_back(v);
    }
    // _bpVectorScalars
    let y_inv = y.inv();
    let (a, bb) = (fr(env, 3), fr(env, 4));
    let (mut y_inv_i, mut two_i) = (fr(env, 1), fr(env, 1));
    let mut sc = Vec::new(env);
    for i in 0..NB {
        let si = s.get(i).unwrap();
        sc.push_back(fr(env, 0) - (z.clone() + a.clone() * si));
        let inner = z2.clone() * two_i.clone() - bb.clone() * s.get(NB - 1 - i).unwrap();
        sc.push_back(z.clone() + y_inv_i.clone() * inner);
        y_inv_i = y_inv_i * y_inv.clone();
        two_i = two_i.clone() + two_i;
    }
    // _bp2: L/R scalars, then the MSM
    let mut acc = w;
    for j in 0..KB {
        acc = acc + u.get(j).unwrap() * u.get(j).unwrap() + u_inv.get(j).unwrap() * u_inv.get(j).unwrap();
    }
    let _ = msm(env, 2 * NB + 2 * KB + 4, &acc);
}

#[contract]
pub struct UaSpike;

#[contractimpl]
impl UaSpike {
    /// The S3 ML-DSA-44 / -65 check (CAP-0087, empty context) over pq_msg(`msg`), `msg` a ua_msg; panics on failure.
    pub fn verify_only(env: Env, kind: u32, pk: Bytes, msg: Bytes, sig: Bytes) {
        let pq: Bytes = tagged(&env, kind, &msg).into();
        mldsa_verify(&env, kind, &pk, &pq, &sig);
    }

    /// Spike set-up only: writes the record `register` would have written for the CTR-UA-04 id of `key_data`;
    /// `pop` None ⇒ empty (the CLI takes no empty `Bytes` argument).
    pub fn seed(env: Env, kind: u32, key_data: Bytes, pop: Option<Bytes>) -> BytesN<32> {
        let id = tagged(&env, kind, &key_data);
        store(&env, &id, kind, key_data, pop.unwrap_or_else(|| Bytes::new(&env)));
        id
    }

    /// `register` of an `mldsa65` UA: id, one verify of the PoP over pq_msg(`msg`), the record with key data **and**
    /// pop (≈ 5.3 KB), `Key`, `List`, `Count`, the record-sized `UaRegistered` event. `msg` stands for the
    /// `uaMessage(kind, PURPOSE_POP_V2, registrationDigest)` the real `register` computes (a few keccaks, not modelled).
    pub fn register_model(env: Env, pk: BytesN<1952>, msg: Bytes, sig: BytesN<3309>) -> BytesN<32> {
        let kd: Bytes = pk.clone().into();
        let id = tagged(&env, K_MLDSA65, &kd);
        if env.storage().persistent().has(&Key::Ua(id.clone())) {
            panic!("AlreadyRegistered");
        }
        let kh = h(&env, &kd);
        if env.storage().persistent().has(&Key::Key(kh.clone())) {
            panic!("KeyInUse");
        }
        let pq: Bytes = tagged(&env, K_MLDSA65, &msg).into();
        env.crypto().ml_dsa_65_verify(&pk, &pq, &sig, &Bytes::new(&env));
        put(&env, &Key::Key(kh), &id);
        store(&env, &id, K_MLDSA65, kd, sig.into());
        id
    }

    /// `register` of an `msig` (spec §3): `key_data` = CTR-UA-09 `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖
    /// bytes32 id ‖ u16 weight)`, ids strictly increasing; `pop` = `abi.encode(MemberSig[])`, canonical, each
    /// registered member's `keyData` empty (owner ruling 2026-10-30). Each member's record is read, its key taken
    /// from the record, and its signature verified over
    /// `pq_msg(ua_msg(kind, member, keccak256(structureUA ‖ msg)))`, until the threshold weight. The record keeps `pop`.
    /// `msg` stands for the msig's own `uaMessage(MSIG, PURPOSE_POP_V2, registrationDigest)`.
    pub fn msig_model(env: Env, key_data: Bytes, msg: BytesN<32>, pop: Bytes) -> BytesN<32> {
        let (threshold, count) = (word2(&key_data, 0), word2(&key_data, 2));
        assert!(count >= 1 && count <= 16 && key_data.len() == 4 + 36 * count, "KeyData");
        let id = tagged(&env, K_MSIG, &key_data);
        if env.storage().persistent().has(&Key::Ua(id.clone())) {
            panic!("AlreadyRegistered");
        }
        let mut prev: Option<BytesN<32>> = None;
        for i in 0..count {
            let mid: BytesN<32> = key_data.slice(6 + 36 * i..38 + 36 * i).try_into().unwrap();
            assert!(prev.map_or(true, |p| p.to_array() < mid.to_array()), "KeyData: ids not increasing");
            prev = Some(mid);
        }
        let mut sd = Bytes::from_array(&env, &id.to_array());
        sd.append(&Bytes::from_array(&env, &msg.to_array()));
        let member_digest = h(&env, &sd);
        let member = purpose(&env, "scaas.ua.purpose.member.v1");
        let (mut weight, mut last) = (0u32, None::<u32>);
        for (idx, kd, sig) in member_sigs(&env, &pop).iter() {
            assert!(idx < count && last.map_or(true, |l| l < idx), "Pop: member index");
            last = Some(idx);
            let o = 4 + 36 * idx;
            let kind = word2(&key_data, o);
            let mid: BytesN<32> = key_data.slice(o + 2..o + 34).try_into().unwrap();
            let k = Key::Ua(mid);
            let rec: Registration = env.storage().persistent().get(&k).expect("MemberUnknown");
            bump(&env, &k);
            assert!(rec.kind == kind, "MemberUnknown");
            assert!(kd.is_empty(), "Pop: keyData of a registered member");
            let pq: Bytes = tagged(&env, kind, &ua_msg(&env, kind, &member, &member_digest).into()).into();
            mldsa_verify(&env, kind, &rec.key_data, &pq, &sig);
            weight += word2(&key_data, o + 34);
        }
        assert!(weight >= threshold, "Pop: weight");
        store(&env, &id, K_MSIG, key_data, pop);
        id
    }

    /// `require_authorized` (spec §4) for a `webauthn-p256` UA: the record (`NotRegistered`), `signable`
    /// (`Unauthorized`), its TTL, then the S3 check over `ua_msg(kind, purpose, digest)`.
    pub fn require_authorized(env: Env, ua: BytesN<32>, purpose: BytesN<32>, digest: BytesN<32>, auth: Bytes) {
        let k = Key::Ua(ua);
        let rec: Registration = env.storage().persistent().get(&k).expect("NotRegistered");
        assert!(rec.signable, "Unauthorized");
        bump(&env, &k);
        assert!(rec.kind == K_WEBAUTHN, "NotVerifiable (spike: webauthn-p256 only)");
        webauthn_check(&env, &rec.key_data, &ua_msg(&env, rec.kind, &purpose, &digest), &auth);
    }

    /// `receivable(ua)` (spec §4): the record's `signable`.
    pub fn receivable(env: Env, ua: BytesN<32>) -> bool {
        env.storage().persistent().get::<_, Registration>(&Key::Ua(ua)).map_or(false, |r| r.signable)
    }

    pub fn bls_g1_msm(env: Env, n: u32) -> BytesN<96> {
        let (mut vp, mut vs) = (Vec::new(&env), Vec::new(&env));
        for i in 0..n {
            vp.push_back(g1(&env));
            vs.push_back(fr(&env, i));
        }
        env.crypto().bls12_381().g1_msm(vp, vs).to_bytes()
    }

    pub fn bls_g2_msm(env: Env, n: u32) -> BytesN<192> {
        let (mut vp, mut vs) = (Vec::new(&env), Vec::new(&env));
        for i in 0..n {
            vp.push_back(g2(&env));
            vs.push_back(fr(&env, i));
        }
        env.crypto().bls12_381().g2_msm(vp, vs).to_bytes()
    }

    /// Pairing check over `n_pairs` pairs (G1, G2), (−G1, G2), …; true for an even count.
    pub fn bls_pairing(env: Env, n_pairs: u32) -> bool {
        let (mut vp1, mut vp2) = (Vec::new(&env), Vec::new(&env));
        for i in 0..n_pairs {
            vp1.push_back(if i % 2 == 0 { g1(&env) } else { -g1(&env) });
            vp2.push_back(g2(&env));
        }
        env.crypto().bls12_381().pairing_check(vp1, vp2)
    }

    /// `n` × (G1 add, G1 mul, G2 add, G2 mul).
    pub fn bls_add_mul(env: Env, n: u32) -> BytesN<96> {
        let bls = env.crypto().bls12_381();
        let (mut a, mut b) = (g1(&env), g2(&env));
        for i in 0..n {
            a = bls.g1_mul(&bls.g1_add(&a, &g1(&env)), &fr(&env, i));
            b = bls.g2_mul(&bls.g2_add(&b, &g2(&env)), &fr(&env, i));
        }
        a.to_bytes()
    }

    /// `n` × (Fr mul, add, inv).
    pub fn bls_fr_ops(env: Env, n: u32) -> BytesN<32> {
        let mut x = fr(&env, 7);
        for i in 0..n {
            x = (x * fr(&env, i) + fr(&env, 1)).inv();
        }
        x.to_bytes()
    }

    /// The host work of ZetherVerifier.sol `verifyTransfer` (m = 1) / `verifyTransferMulti` (m > 1), auditor on,
    /// with Soroban's 96-byte points: transcript keccaks, the Σ MSMs, m + 1 (m = 1: 2) range proofs. A cost model over
    /// fixed valid points, not a verifier. Not modelled: the token's ciphertext reads / writes and g1_add updates.
    pub fn zether_transfer_model(env: Env, m: u32) -> u32 {
        assert!(m >= 1 && m <= 8); // the transcript absorbs slice ZEROS (8 KiB): m <= 8
        let mut t = Tr { env: &env, st: h(&env, &Bytes::from_slice(&env, b"SCAAS-ZETHER-TRANSCRIPT-V1")) };
        let single = m == 1;
        let (stmt, sigma) = if single { (512 + 9 * P, 10 * P) } else { (512 + 6 * P + 32 + 4 * P * m, (6 + 5 * m) * P) };
        t.absorb(stmt);
        t.absorb(sigma);
        let c = t.challenge();
        // point-distinctness keccaks: Y_f vs Y_t (single); Y_f, each Y_tj, C_aud_j / D_aud_j (multi)
        let extra = if single { 2 } else { 1 + 3 * m };
        for _ in 0..extra {
            let _ = h(&env, &Bytes::from_slice(&env, &ZEROS[..P as usize]));
        }
        let mut sizes: Vec<u32> = Vec::new(&env);
        if single {
            for s in [3u32, 3, 4, 4, 6, 4, 4, 4] {
                sizes.push_back(s); // E1 E2 E3 E4 E5 E6 E7 E8
            }
        } else {
            for s in [3u32, 3, 4, 6, 4] {
                sizes.push_back(s); // E1 E2 E4 E5 E8
            }
            for _ in 0..m {
                for s in [4u32, 4, 3, 4] {
                    sizes.push_back(s); // E3_j E6_j E6'_j E7_j
                }
            }
        }
        let mut msms = 0;
        for s in sizes.iter() {
            let _ = msm(&env, s, &c);
            msms += 1;
        }
        let ranges = if single { 2 } else { m + 1 };
        for _ in 0..ranges {
            range(&env, &mut t);
            msms += 2;
        }
        msms
    }
}

#[cfg(test)]
mod test;
