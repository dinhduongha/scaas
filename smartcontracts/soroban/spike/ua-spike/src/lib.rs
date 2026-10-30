//! T0 spike (plan UA-Soroban T0, spec §10 T0, S13a): cost models of the UA-Soroban calls and of the BLS12-381 building blocks of a
//! classical Zether verifier at Protocol 30. Each model does the host work of the call it stands for; it is not the
//! registry, the token or a verifier. Never deployed outside the spike.
#![no_std]
#![allow(deprecated)] // events().publish: the spike's events only need their size

use soroban_sdk::{
    contract, contractimpl, contracttype,
    crypto::bls12_381::{Bls12381Fr, Bls12381G1Affine, Bls12381G2Affine},
    Bytes, BytesN, Env, Vec, U256,
};

const DAY: u32 = 17_280;
const K_WEBAUTHN: u32 = 0x0100;
const K_MLDSA44: u32 = 0x0130;
const K_MLDSA65: u32 = 0x0131;
const K_MSIG: u32 = 0x0120;

#[contracttype]
pub enum Key {
    Ua(BytesN<32>),
    Key(BytesN<32>),
    List(u32, u32),
    Count(u32),
    UaBal(BytesN<32>),
    Bal(BytesN<32>),
    UaNonce(BytesN<32>, BytesN<32>),
}

#[contracttype]
pub struct Rec {
    pub kind: u32,
    pub key_data: Bytes,
    pub pop: Bytes,
}

fn h(env: &Env, data: &Bytes) -> BytesN<32> {
    env.crypto().keccak256(data).into()
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

/// TAG(kind) ‖ x, hashed: the CTR-UA-04 id when x is the key data, pq_msg when x is ua_msg (CTR-UA-23).
fn tagged(env: &Env, kind: u32, x: &Bytes) -> BytesN<32> {
    let mut m = Bytes::from_array(env, &h(env, &Bytes::from_slice(env, tag_name(kind).as_bytes())).to_array());
    m.append(x);
    h(env, &m)
}

/// ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest) (CTR-UA-12).
fn ua_msg(env: &Env, kind: u32, purpose: &str, digest: &BytesN<32>) -> BytesN<32> {
    let mut m = Bytes::from_array(env, &h(env, &Bytes::from_slice(env, b"scaas.ua.msg.v1")).to_array());
    m.append(&Bytes::from_array(env, &h(env, &Bytes::from_slice(env, tag_name(kind).as_bytes())).to_array()));
    m.append(&Bytes::from_array(env, &h(env, &Bytes::from_slice(env, purpose.as_bytes())).to_array()));
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

/// Stores a record under a new list position (the `register` writes after its checks).
fn store(env: &Env, id: &BytesN<32>, rec: &Rec) {
    let count_key = Key::Count(rec.kind);
    let i: u32 = env.storage().persistent().get(&count_key).unwrap_or(0);
    put(env, &Key::Ua(id.clone()), rec);
    put(env, &Key::List(rec.kind, i), id);
    put(env, &count_key, &(i + 1));
    env.events().publish((soroban_sdk::symbol_short!("UaReg"), id.clone(), rec.kind), rec.key_data.len());
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding of 32 bytes (43 characters).
fn b64url32(x: &[u8; 32]) -> [u8; 43] {
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

    /// Spike set-up only: writes a record (and a UA balance) as `register` would have. `id` None ⇒ the CTR-UA-04 id.
    pub fn seed(env: Env, id: Option<BytesN<32>>, kind: u32, key_data: Bytes, pop: Bytes) -> BytesN<32> {
        let id = id.unwrap_or_else(|| tagged(&env, kind, &key_data));
        put(&env, &Key::Ua(id.clone()), &Rec { kind, key_data, pop });
        put(&env, &Key::UaBal(id.clone()), &1_000_000_000i128);
        id
    }

    /// `register` of an `mldsa65` UA: id, one verify of the PoP over pq_msg(`msg`), the record with key data **and**
    /// pop (≈ 5.3 KB), `Key`, `List`, `Count`, an event.
    pub fn register_model(env: Env, pk: BytesN<1952>, msg: Bytes, sig: BytesN<3309>) -> BytesN<32> {
        let kd: Bytes = pk.clone().into();
        let id = tagged(&env, K_MLDSA65, &kd);
        let key = Key::Ua(id.clone());
        if env.storage().persistent().has(&key) {
            panic!("AlreadyRegistered");
        }
        let kh = h(&env, &kd);
        if env.storage().persistent().has(&Key::Key(kh.clone())) {
            panic!("KeyInUse");
        }
        let pq: Bytes = tagged(&env, K_MLDSA65, &msg).into();
        env.crypto().ml_dsa_65_verify(&pk, &pq, &sig, &Bytes::new(&env));
        put(&env, &Key::Key(kh), &id);
        store(&env, &id, &Rec { kind: K_MLDSA65, key_data: kd, pop: sig.into() });
        id
    }

    /// `register` of an `n`-member `mldsa65` `msig`: reads the `n` member records, `n` verifies, writes the record
    /// whose `pop` holds the `n` signatures (CTR-UA-09 key data: 4 + 36n bytes).
    pub fn msig_model(
        env: Env,
        n: u32,
        member_ids: Vec<BytesN<32>>,
        pk: BytesN<1952>,
        msg: Bytes,
        sig: BytesN<3309>,
    ) -> BytesN<32> {
        assert!(member_ids.len() == n);
        let mut kd = Bytes::from_array(&env, &[0, n as u8, 0, n as u8]);
        let mut pop = Bytes::new(&env);
        // each member signs pq_msg of its own kind (CTR-UA-23); the spike reuses one vector signature per member
        let pq: Bytes = tagged(&env, K_MLDSA65, &msg).into();
        for id in member_ids.iter() {
            let k = Key::Ua(id.clone());
            let rec: Rec = env.storage().persistent().get(&k).expect("MemberUnknown");
            bump(&env, &k);
            assert!(rec.kind == K_MLDSA65);
            kd.append(&Bytes::from_array(&env, &[1, 0x31]));
            kd.append(&id.clone().into());
            kd.append(&Bytes::from_array(&env, &[0, 1]));
            env.crypto().ml_dsa_65_verify(&pk, &pq, &sig, &Bytes::new(&env));
            pop.append(&sig.clone().into());
        }
        let id = tagged(&env, K_MSIG, &kd);
        if env.storage().persistent().has(&Key::Ua(id.clone())) {
            panic!("AlreadyRegistered");
        }
        store(&env, &id, &Rec { kind: K_MSIG, key_data: kd, pop });
        id
    }

    /// `ua_pay` of a passkey UA: the WebAuthn checks of spec §3, `secp256r1_verify`, the 96-byte record read, two
    /// balance writes, the pay-lane write, three events.
    pub fn ua_pay_model(
        env: Env,
        key: BytesN<65>,
        rp_id_hash: BytesN<32>,
        authenticator_data: Bytes,
        client_data_json: Bytes,
        sig: BytesN<64>,
        digest: BytesN<32>,
    ) {
        let mut kd: Bytes = key.clone().into();
        kd = kd.slice(1..);
        kd.append(&rp_id_hash.clone().into());
        let ua = tagged(&env, K_WEBAUTHN, &kd);
        let rk = Key::Ua(ua.clone());
        let rec: Rec = env.storage().persistent().get(&rk).expect("NotRegistered");
        bump(&env, &rk);
        assert!(rec.kind == K_WEBAUTHN && rec.key_data == kd);
        // client data: type, challenge = base64url(ua_msg), crossOrigin absent or false, no topOrigin
        let m = ua_msg(&env, K_WEBAUTHN, "scaas.ua.purpose.metatx.v1", &digest);
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
        assert!(authenticator_data.slice(0..32) == Bytes::from(rp_id_hash));
        assert!(authenticator_data.get(32).unwrap() & 0x05 == 0x05);
        let mut signed = authenticator_data.clone();
        signed.append(&env.crypto().sha256(&client_data_json).to_bytes().into());
        env.crypto().secp256r1_verify(&key, &env.crypto().sha256(&signed), &sig);
        // lane = payLane(pay_ref), nonce 0; two balances; three events
        let lane = h(&env, &digest.clone().into());
        let nk = Key::UaNonce(ua.clone(), lane);
        if env.storage().persistent().get::<_, u64>(&nk).unwrap_or(0) != 0 {
            panic!("BadNonce");
        }
        put(&env, &nk, &1u64);
        let bk = Key::UaBal(ua.clone());
        let bal: i128 = env.storage().persistent().get(&bk).unwrap_or(0);
        put(&env, &bk, &(bal - 1));
        let tk = Key::Bal(digest.clone());
        let to: i128 = env.storage().persistent().get(&tk).unwrap_or(0);
        put(&env, &tk, &(to + 1));
        let e = env.events();
        e.publish((soroban_sdk::symbol_short!("transfer"), ua.clone(), digest.clone()), 1i128);
        e.publish((soroban_sdk::symbol_short!("UaPay"), ua.clone()), digest.clone());
        e.publish((soroban_sdk::symbol_short!("UaNonce"), ua), 0u64);
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
        assert!(m >= 1 && m <= 16);
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
