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
    // B0 (ua8-soroban, U8S-D3): the real registry's `Signer` and the Part B entries
    Signer(BytesN<32>),
    PqzK(BytesN<32>),
    PqzP(BytesN<32>),
    Kem(BytesN<32>, u64),
    KemMax(BytesN<32>),
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
        put(&env, &Key::Signer(id.clone()), &(kind, key_data.clone())); // B0: what the real registry's member checks read
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

// --- B0 (plan ua8-soroban B0; C11, C12, UA8-D21): the UA-8 Part B calls on Soroban ---
// Models of `register` with PQZ / KEM attributes, `store_pqz_pop`, `set_kem_key`, `set_pqz_key`: the real arguments,
// the real digests (UA8-D1, constant tags as in `ua-registry/src/digest.rs`), the real verifies, the U8S-D3 entries and
// the U8S-D4 events. Every keccak256 a real call makes is made here, and no other (tags are constants).

const fn c32(s: &[u8]) -> [u8; 32] {
    unhex::<32>(s)
}
const MSG_TAG: [u8; 32] = c32(b"30a5cfd6b1d0889ef4a90d8488fa5e6e615322735899e23243d69087b6b66349");
const T_MLDSA44: [u8; 32] = c32(b"e16239d49e9fe951af81c8b23998f020775e322bc4ff6de72e681bb29a02eee0");
const T_MLDSA65: [u8; 32] = c32(b"226b3748e9e7f43e6976391a3082716487793bbfa41cbc55b27ecf55ac4a2f27");
const T_MSIG: [u8; 32] = c32(b"0c74d89236d93351f72ba09e86363f0ce977ca1f492ea24ebf6314231157fdd4");
const P_MEMBER: [u8; 32] = c32(b"fbd8600564b68d09f75fe5d3e6acb8fe3c5a3a4cb20da6988723433beff5212a");
const P_POP_V2: [u8; 32] = c32(b"0ffb2c52d2a16294393778508b3fff52351664d2c5bbe5deb3d3278f56281f93");
const P_KEM: [u8; 32] = c32(b"99f2818f111f001f1f71ec2f8756cff7e9858c0fcb204b353c21f95b2ff3f2b8");
const P_PQZ_KEY: [u8; 32] = c32(b"8f354ac3b315d85e2c32c80857a1600c5aebe8bbe14a265d56079725a6602330");
const KEM_RECORD_TAG: [u8; 32] = c32(b"29f8f9b02ee4297dbc83229b662caeac7f44f90cc2c68e2106abc8e91a805643");
const PQZ_KEY_RECORD_TAG: [u8; 32] = c32(b"33277d3cc9f2c17a36c673363ff0167a98d43e39a7aafa719523120c269379b3");
const GROUP_MLDSA65: [u8; 32] = c32(b"ce664790de9584777bd32d6bbce84b26b1a479d86be05f03ba5120eae90d40b2");
const GROUP_PQZ: [u8; 32] = c32(b"0b46b017252788e1ba969e603cf986c143943e1d6d1176004a6f577a298a53e4");
/// keccak256(""): an empty proof is no proof (ruling A6-m).
const EMPTY_HASH: [u8; 32] = c32(b"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
/// The four parameter sets' PQZ key lengths (`portable.json` `sets`: n2048-kmax1024 … n2816-kmax65536).
const PQZ_KEY_LENGTHS: [u32; 4] = [16_384, 18_432, 20_480, 22_528];
const KEM_PK_LENGTH: u32 = 1_601;

fn kc(env: &Env, parts: &[&[u8]]) -> BytesN<32> {
    let mut b = Bytes::new(env);
    for p in parts {
        b.extend_from_slice(p);
    }
    h(env, &b)
}

/// keccak256(prefix ‖ b).
fn kb(env: &Env, prefix: &[u8; 32], b: &Bytes) -> BytesN<32> {
    let mut m = Bytes::from_array(env, prefix);
    m.append(b);
    h(env, &m)
}

fn tag32(kind: u32) -> [u8; 32] {
    match kind {
        K_MLDSA44 => T_MLDSA44,
        K_MLDSA65 => T_MLDSA65,
        K_MSIG => T_MSIG,
        _ => panic!("KindDisabled"),
    }
}

fn w64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// CTR-UA-12 `ua_message`.
fn umsg(env: &Env, kind: u32, purpose: &[u8; 32], digest: &BytesN<32>) -> BytesN<32> {
    kc(env, &[&MSG_TAG, &tag32(kind), purpose, &digest.to_array()])
}

/// CTR-UA-23: the PQ kinds verify over `pq_msg = keccak256(TAG(kind) ‖ ua_msg)`.
fn pq_verify(env: &Env, kind: u32, pk: &Bytes, m: &BytesN<32>, sig: &Bytes) {
    let pq: Bytes = kc(env, &[&tag32(kind), &m.to_array()]).into();
    mldsa_verify(env, kind, pk, &pq, sig);
}

/// A PQZ / KEM holder (UA-6 U3): `mldsa44`, `mldsa65`, or an `msig` whose PQ members (0x0130–0x0133) reach the threshold.
fn holder(kind: u32, kd: &Bytes) -> bool {
    if kind != K_MSIG {
        return kind == K_MLDSA44 || kind == K_MLDSA65;
    }
    let (threshold, count) = (word2(kd, 0), word2(kd, 2));
    let mut pq = 0;
    for i in 0..count {
        let o = 4 + 36 * i;
        if (0x0130..=0x0133).contains(&word2(kd, o)) {
            pq += word2(kd, o + 34);
        }
    }
    pq >= threshold
}

/// The `register` step 6 (`check_members`): each member's `Signer` entry, its kind.
fn b0_members(env: &Env, kd: &Bytes) {
    let (_, count) = (word2(kd, 0), word2(kd, 2));
    assert!(count >= 1 && count <= 16 && kd.len() == 4 + 36 * count, "KeyData");
    let mut prev: Option<BytesN<32>> = None;
    for i in 0..count {
        let o = 4 + 36 * i;
        let mid: BytesN<32> = kd.slice(o + 2..o + 34).try_into().unwrap();
        assert!(prev.map_or(true, |p| p.to_array() < mid.to_array()), "KeyData: ids not increasing");
        let k = Key::Signer(mid.clone());
        let (kind, _): (u32, Bytes) = env.storage().persistent().get(&k).expect("MemberUnknown");
        bump(env, &k);
        assert!(kind == word2(kd, o), "MemberUnknown");
        prev = Some(mid);
    }
}

/// `check_msig(…, portable = true)`: member signatures over `member_digest(ua, m)` under purpose `member`, each key
/// read from `Signer(id)`, then the U8S-D1 minimal rule (T >= N and T − w_min < N).
fn b0_msig(env: &Env, ua: &BytesN<32>, kd: &Bytes, m: &BytesN<32>, sigs: &Bytes) {
    let md = kc(env, &[&ua.to_array(), &m.to_array()]);
    let (threshold, count) = (word2(kd, 0), word2(kd, 2));
    let (mut t, mut w_min, mut last) = (0u32, u32::MAX, None::<u32>);
    for (idx, mkd, sig) in member_sigs(env, sigs).iter() {
        assert!(idx < count && last.map_or(true, |l| l < idx), "Pop: member index");
        last = Some(idx);
        assert!(mkd.is_empty(), "Pop: keyData of a registered member");
        let o = 4 + 36 * idx;
        let kind = word2(kd, o);
        let k = Key::Signer(kd.slice(o + 2..o + 34).try_into().unwrap());
        let (_, key): (u32, Bytes) = env.storage().persistent().get(&k).expect("Pop");
        bump(env, &k);
        pq_verify(env, kind, &key, &umsg(env, kind, &P_MEMBER, &md), &sig);
        let w = word2(kd, o + 34);
        t += w;
        w_min = w_min.min(w);
    }
    assert!(t >= threshold && t - w_min < threshold, "Pop: weight or not minimal");
}

/// The signature of a stored record (`pop`, KEM sig, PQZ-key sig) over `ua_message(kind, purpose, digest)`.
fn b0_sig(env: &Env, kind: u32, kd: &Bytes, ua: &BytesN<32>, purpose: &[u8; 32], digest: &BytesN<32>, sig: &Bytes) {
    let m = umsg(env, kind, purpose, digest);
    if kind == K_MSIG {
        b0_msig(env, ua, kd, &m, sig);
    } else {
        pq_verify(env, kind, kd, &m, sig);
    }
}

/// CTR-UA-32 key rules: version ≥ 1, scheme byte 1, 1,601 B.
fn kem_rules(version: u64, kem_pk: &Bytes) {
    assert!(version >= 1, "KemVersion");
    assert!(kem_pk.len() >= 1 && kem_pk.get(0).unwrap() == 1, "KemScheme");
    assert!(kem_pk.len() == KEM_PK_LENGTH, "KemKeyLength");
}

/// `keccak256(KEM_RECORD_TAG ‖ ua ‖ uint256(version) ‖ keccak256(kem_pk))` (UA8-D1).
fn kem_record_digest(env: &Env, ua: &BytesN<32>, version: u64, kem_pk: &Bytes) -> BytesN<32> {
    kc(env, &[&KEM_RECORD_TAG, &ua.to_array(), &w64(version), &h(env, kem_pk).to_array()])
}

/// PQZ key length (`KeyData`) and proof-hash rules (`PqzPopHash`); returns `key_hash(0x0142, key)`.
fn pqz_rules(env: &Env, key: &Bytes, pop_hash: &BytesN<32>) -> BytesN<32> {
    assert!(PQZ_KEY_LENGTHS.contains(&key.len()), "KeyData: PQZ key length");
    let ph = pop_hash.to_array();
    assert!(ph != [0; 32] && ph != EMPTY_HASH, "PqzPopHash");
    kb(env, &GROUP_PQZ, key)
}

/// `UaPqzKeySet` / `UaKemKeySet` / `UaPqzPopStored` data (U8S-D4: hashes; the bytes stay in state).
#[contracttype]
pub struct PqzKeySetEvent {
    pub pqz_key_hash: BytesN<32>,
    pub pqz_pop_hash: BytesN<32>,
    pub sig_hash: BytesN<32>,
    pub checked: Checked,
}

#[contracttype]
pub struct KemKeySetEvent {
    pub kem_pk_hash: BytesN<32>,
    pub sig_hash: BytesN<32>,
    pub checked: Checked,
}

/// What the B0 models store in `PqzK(ua)`: (key, pqz_pop_hash, sig, checked). U8S-D3 names (key, sig, checked); the
/// 32-byte proof hash is kept here as the worst case (B3 decides where a `set_pqz_key` proof hash lives).
type PqzKey = (Bytes, BytesN<32>, Bytes, Checked);

#[contractimpl]
impl UaSpike {
    /// `register` with PQZ / KEM attributes (spec §3 order, U8S-D3–D7) for `mldsa65` or an `msig` of ML-DSA members.
    /// `pqz_pop` empty = the split form (`store_pqz_pop` later). Writes `Ua(id)` (attrs without key bytes), `Key`
    /// (single key), `List`, `Count`, `Signer`, `PqzK`, `PqzP` (when given), `Kem(id, v)`, `KemMax`; `UaRegistered`.
    pub fn register_pqz_kem_model(
        env: Env,
        kind: u32,
        key_data: Bytes,
        attrs: UaAttrs,
        pop: Bytes,
        pqz_pop: Bytes,
    ) -> BytesN<32> {
        match kind {
            K_MLDSA65 => assert!(key_data.len() == 1952, "KeyData"),
            K_MSIG => {}
            _ => panic!("KindDisabled (spike: mldsa65, msig)"),
        }
        let id = kb(&env, &tag32(kind), &key_data);
        assert!(!env.storage().persistent().has(&Key::Ua(id.clone())), "AlreadyRegistered");
        let kh = if kind == K_MSIG {
            None
        } else {
            let kh = kb(&env, &GROUP_MLDSA65, &key_data);
            assert!(!env.storage().persistent().has(&Key::Key(kh.clone())), "KeyInUse");
            Some(kh)
        };
        if kind == K_MSIG {
            b0_members(&env, &key_data);
        }
        let zero = BytesN::from_array(&env, &[0; 32]);
        let has_pqz = !attrs.pqz_key.is_empty();
        let has_kem = attrs.kem_version != 0 || !attrs.kem_pk.is_empty();
        assert!(!(has_pqz || has_kem) || holder(kind, &key_data), "PqzHolder / KemHolder");
        let pqz_key_hash = if has_pqz {
            pqz_rules(&env, &attrs.pqz_key, &attrs.pqz_pop_hash)
        } else {
            assert!(attrs.pqz_pop_hash == zero, "PqzPopHash");
            zero.clone()
        };
        let kem_hash = if has_kem {
            kem_rules(attrs.kem_version, &attrs.kem_pk);
            kem_record_digest(&env, &id, attrs.kem_version, &attrs.kem_pk)
        } else {
            zero.clone()
        };
        if !pqz_pop.is_empty() {
            assert!(has_pqz && h(&env, &pqz_pop) == attrs.pqz_pop_hash, "PqzPopHash");
        }
        let portable = kc(&env, &[&P_POP_V2, &id.to_array(), &pqz_key_hash.to_array(), &kem_hash.to_array()]);
        let reg = kc(&env, &[&portable.to_array(), &attrs.pqz_pop_hash.to_array()]);
        b0_sig(&env, kind, &key_data, &id, &P_POP_V2, &reg, &pop);

        let count_key = Key::Count(kind);
        let i: u32 = env.storage().persistent().get(&count_key).unwrap_or(0);
        put(&env, &Key::List(kind, i), &id);
        put(&env, &count_key, &(i + 1));
        if let Some(kh) = kh {
            put(&env, &Key::Key(kh), &id);
        }
        put(&env, &Key::Signer(id.clone()), &(kind, key_data.clone()));
        if has_pqz {
            let v: PqzKey = (attrs.pqz_key.clone(), attrs.pqz_pop_hash.clone(), Bytes::new(&env), Checked::Chain);
            put(&env, &Key::PqzK(id.clone()), &v);
        }
        if !pqz_pop.is_empty() {
            put(&env, &Key::PqzP(id.clone()), &pqz_pop);
        }
        if has_kem {
            put(&env, &Key::Kem(id.clone(), attrs.kem_version), &(attrs.kem_pk.clone(), Bytes::new(&env), Checked::Chain));
            put(&env, &Key::KemMax(id.clone()), &attrs.kem_version);
        }
        let stored = UaAttrs {
            pqz_key: Bytes::new(&env),
            pqz_pop_hash: attrs.pqz_pop_hash,
            kem_version: attrs.kem_version,
            kem_pk: Bytes::new(&env),
        };
        let rec = Registration {
            kind,
            key_data,
            attrs: stored,
            pop,
            pop_checked: Checked::Chain,
            pqz_pop_checked: Checked::None,
            proven: false,
            signable: true,
            index: i,
            ledger: env.ledger().sequence(),
        };
        put(&env, &Key::Ua(id.clone()), &rec);
        env.storage().instance().extend_ttl(30 * DAY, 60 * DAY);
        let ev = RegisteredEvent {
            kind,
            key_data: rec.key_data,
            attrs: rec.attrs,
            pop_hash: h(&env, &rec.pop),
            pop_checked: rec.pop_checked,
            pqz_pop_checked: rec.pqz_pop_checked,
            proven: rec.proven,
            signable: rec.signable,
            index: rec.index,
            ledger: rec.ledger,
            checked: Checked::Chain,
        };
        env.events().publish((Symbol::new(&env, "UaRegistered"), id.clone(), kind), ev);
        id
    }

    /// `store_pqz_pop` (U8S-D6): anyone; the proof must hash to the record's `pqz_pop_hash`; a no-op when stored.
    pub fn store_pqz_pop_model(env: Env, ua: BytesN<32>, pqz_pop: Bytes) {
        let k = Key::Ua(ua.clone());
        let rec: Registration = env.storage().persistent().get(&k).expect("NotRegistered");
        bump(&env, &k);
        let ph = rec.attrs.pqz_pop_hash;
        assert!(ph.to_array() != [0; 32] && h(&env, &pqz_pop) == ph, "PqzPopHash");
        if env.storage().persistent().has(&Key::PqzP(ua.clone())) {
            return;
        }
        put(&env, &Key::PqzP(ua.clone()), &pqz_pop);
        env.events().publish((Symbol::new(&env, "UaPqzPopStored"), ua), ph);
    }

    /// `set_kem_key` (U8S-D7, CTR-UA-32): holder, version once, key rules, the UA's signature (portable msig rule) over
    /// `ua_message(kind, PURPOSE_KEM, kem_record_digest)`; `Kem(ua, v)`, `KemMax`; `UaKemKeySet`.
    pub fn set_kem_key_model(env: Env, ua: BytesN<32>, version: u64, kem_pk: Bytes, sig: Bytes) {
        let k = Key::Ua(ua.clone());
        let rec: Registration = env.storage().persistent().get(&k).expect("NotRegistered");
        bump(&env, &k);
        assert!(holder(rec.kind, &rec.key_data), "KemHolder");
        kem_rules(version, &kem_pk);
        let kk = Key::Kem(ua.clone(), version);
        assert!(version != rec.attrs.kem_version && !env.storage().persistent().has(&kk), "KemVersion");
        let d = kem_record_digest(&env, &ua, version, &kem_pk);
        b0_sig(&env, rec.kind, &rec.key_data, &ua, &P_KEM, &d, &sig);
        let mk = Key::KemMax(ua.clone());
        let max: u64 = env.storage().persistent().get(&mk).unwrap_or(rec.attrs.kem_version);
        if version > max {
            put(&env, &mk, &version);
        }
        let ev = KemKeySetEvent { kem_pk_hash: h(&env, &kem_pk), sig_hash: h(&env, &sig), checked: Checked::Chain };
        put(&env, &kk, &(kem_pk, sig, Checked::Chain));
        env.events().publish((Symbol::new(&env, "UaKemKeySet"), ua, version), ev);
    }

    /// `set_pqz_key` (U8S-D6, EVM ruling A1-I1): holder, write-once (`PqzKeySet`), key and proof-hash rules, the UA's
    /// signature over `ua_message(kind, PURPOSE_PQZ_KEY, keccak256(pqzKeyDigest ‖ pqzPopHash))`; `PqzK`; `UaPqzKeySet`.
    pub fn set_pqz_key_model(env: Env, ua: BytesN<32>, pqz_key: Bytes, pqz_pop_hash: BytesN<32>, sig: Bytes) {
        let k = Key::Ua(ua.clone());
        let rec: Registration = env.storage().persistent().get(&k).expect("NotRegistered");
        bump(&env, &k);
        assert!(holder(rec.kind, &rec.key_data), "PqzHolder");
        let pk = Key::PqzK(ua.clone());
        assert!(rec.attrs.pqz_pop_hash.to_array() == [0; 32] && !env.storage().persistent().has(&pk), "PqzKeySet");
        let kh = pqz_rules(&env, &pqz_key, &pqz_pop_hash);
        let key_digest = kc(&env, &[&PQZ_KEY_RECORD_TAG, &ua.to_array(), &kh.to_array()]);
        let rd = kc(&env, &[&key_digest.to_array(), &pqz_pop_hash.to_array()]);
        b0_sig(&env, rec.kind, &rec.key_data, &ua, &P_PQZ_KEY, &rd, &sig);
        let ev = PqzKeySetEvent {
            pqz_key_hash: kh,
            pqz_pop_hash: pqz_pop_hash.clone(),
            sig_hash: h(&env, &sig),
            checked: Checked::Chain,
        };
        let v: PqzKey = (pqz_key, pqz_pop_hash, sig, Checked::Chain);
        put(&env, &pk, &v);
        env.events().publish((Symbol::new(&env, "UaPqzKeySet"), ua), ev);
    }

    /// `n` keccak256 calls over `len` zero bytes (`len` ≤ 8192): the per-hash cost for the digest headroom.
    pub fn keccak_model(env: Env, n: u32, len: u32) -> BytesN<32> {
        let mut x = BytesN::from_array(&env, &[0; 32]);
        for _ in 0..n {
            x = h(&env, &Bytes::from_slice(&env, &ZEROS[..len as usize]));
        }
        x
    }
}

#[cfg(test)]
mod test;
