// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Moved from ua-spike; see README.md. Not built.
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

