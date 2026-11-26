// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! A TreeKEM session's secrets behind handles (spec docs/superpowers/specs/2026-11-23-pqchat-treekem.md §5, §8, §10; plan T2;
//! feature `app-core`): the path secrets and node keys, the committer's seed-derived `ps[0]` over its full `pathContext`, the
//! path ciphertext, `genesisCtx`, the epoch schedule without `init`, `K`, the tree wrap (epoch 0's and a Welcome), the info
//! and the marker (C33), creation in order, building a commit, and the replay of §10 (the joiner, the own-commit
//! reproduction, the compromise warning, the info in force after a gap). As clientkeys `src/treekem.js`; held to
//! `smartcontracts/vectors/pqchat/tree-secrets.json`. The tree's signed records (`PqChatCommit`, `PqChatTreeLeave`,
//! `PqChatTreeRemove`) are prepared here, reviewed, then signed on PqChat's dedicated path (spec §15): [`PreparedCommit`],
//! [`TreePrepared`]. Every key an encapsulation takes passed its check first: a registry record ([`KemRecord`]) where no
//! signed tree hash covers it (spec §8 step 5), the hash that entered the root otherwise, then the admission check.
//!
//! **App-agnostic** (owner 2026-11-23): every label and the app's step above `K` come from a [`TreeScope`]; PqChat's is
//! [`PQCHAT_TREE`]. **No secret byte leaves** (scaas-sdk C1, A-3): path secrets, node secrets, the joiner and `K` stay in
//! the secret store; out come handles ([`KeyHandle`] for `K`, [`KemKeyPair`] for a held node), public keys, ciphertexts,
//! records and states. The entries with fixed randomness are feature `vectors` only. UNAUDITED.
use super::aead::{aead_open, aead_seal, hkdf_sha256, Alg};
use super::appkey::{rng, AppKeys, KemWrap, KeyHandle, KeyUsage, Origin};
use super::eip712::TypedData;
use super::kem::KemKeyPair;
use super::pqchat_keys::{canonical_content, canonical_of_text, pad};
use super::signer::Signer;
use super::tree_public::{
    admit_kem_key, array_hash, b32, b32j, bytes, ct_targets_hash, direct_path, genesis_ctx, hx,
    kem_record_key, list, path_list_hash, refuse, struct_hash, tree_id, u32j, u64j, Add, Changes,
    KemRecord, Leaf, Node, Remove, Tree, TreeError, Typed, PATH_REFRESH_BOUND_MAX, TREE_ADMINS_MAX,
    TREE_CHANGES_MAX, TREE_LEAVES_MAX, ZERO,
};
use super::{Error, Result};
use crate::keccak256;
use crate::ua_portable::UASig;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// `sealedInfo` at most 12 + 4,096 + 16 B, at creation too (codex-r2-13).
pub const TREE_INFO_MAX: usize = 4124;

// ------------------------------------------------------------------ the scope

/// A tree's labels under `prefix` (`<prefix>/path`, `/node`, …) and the app's parts: its info label above `K`
/// (`HKDF(K, info ‖ sessionId ‖ epochId)`), its records' typed data, its UA purpose and its ids (`id(tag, words)`).
pub struct TreeScope {
    pub prefix: &'static str,
    pub info: &'static [u8],
    pub typed: Typed,
    pub purpose: fn() -> [u8; 32],
    pub id: fn(&str, &[[u8; 32]]) -> [u8; 32],
}

/// PqChat's instance: `scaas/pqchat/v1/tree/…`, mode 0's info label, PqChat's records, purpose and ids.
pub const PQCHAT_TREE: TreeScope = TreeScope {
    prefix: "scaas/pqchat/v1/tree",
    info: super::pqchat_keys::INFO,
    typed: super::pqchat::typed,
    purpose: super::pqchat::purpose,
    id: super::pqchat::id,
};

impl TreeScope {
    fn l(&self, s: &str) -> Vec<u8> {
        format!("{}/{s}", self.prefix).into_bytes()
    }
    pub fn tag_path(&self) -> [u8; 32] {
        keccak256(&self.l("path-context"))
    }
    pub fn tag_context(&self) -> [u8; 32] {
        keccak256(&self.l("context"))
    }
    pub fn wrap_label(&self) -> Vec<u8> {
        self.l("wrap")
    }
    pub fn session_id(&self, creator: &[u8; 32], nonce: u64) -> [u8; 32] {
        (self.id)("session", &[*creator, word(nonce)])
    }
    pub fn epoch_id(&self, session: &[u8; 32], author: &[u8; 32], nonce: u64) -> [u8; 32] {
        (self.id)("epoch", &[*session, *author, word(nonce)])
    }
}

fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    if let Some(t) = w.get_mut(24..) {
        t.copy_from_slice(&v.to_be_bytes());
    }
    w
}
fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}
type Secret = Zeroizing<[u8; 32]>;
fn s32(v: &[u8]) -> Result<Secret> {
    Ok(Zeroizing::new(v.try_into().map_err(|_| Error::Argument)?))
}
/// `H(ikm, info) = HKDF-SHA-256(ikm, salt empty, info, 32)`.
fn h(ikm: &[u8], info: &[u8]) -> Result<Secret> {
    s32(&hkdf_sha256(ikm, &[], info, 32)?)
}

// ------------------------------------------------------------------ public derivations

/// `pathContext = keccak256(abi.encode(TAG_TREE_PATH, treeId, parentEpochId, parentTreeHash, author, nonce, leaf, keyId,
/// hash(removes), hash(adds), keccak256(abi.encodePacked(ctTargets))))` of a commit record (spec §5, R4, C17).
pub fn path_context(sc: &TreeScope, rec: &Value, ct_targets: &[u32]) -> Result<[u8; 32]> {
    let removes = rec
        .get("removes")
        .and_then(Value::as_array)
        .ok_or(Error::Argument)?;
    let adds = rec
        .get("adds")
        .and_then(Value::as_array)
        .ok_or(Error::Argument)?;
    let words = [
        sc.tag_path(),
        b32j(rec, "treeId")?,
        b32j(rec, "parentEpochId")?,
        b32j(rec, "parentTreeHash")?,
        b32j(rec, "author")?,
        word(u64j(rec, "nonce")?),
        word(u32j(rec, "leaf")?.into()),
        word(u64j(rec, "keyId")?),
        array_hash(sc.typed, "TreeRemove", removes)?,
        array_hash(sc.typed, "TreeAdd", adds)?,
        ct_targets_hash(ct_targets),
    ];
    Ok(keccak256(&words.concat()))
}

/// The context fields of an epoch (`ctx_e`'s inputs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochFields {
    pub tree_id: [u8; 32],
    pub epoch_id: [u8; 32],
    pub epoch: u64,
    pub parent_epoch_id: [u8; 32],
    pub parent_tree_hash: [u8; 32],
    pub tree_hash: [u8; 32],
    pub admins: Vec<[u8; 32]>,
}

impl EpochFields {
    /// Epoch 0 (C29): `genesisCtx` for `treeId`, `epochId = sessionId`, the rest 0.
    pub fn genesis(sc: &TreeScope, session: &Value) -> Result<EpochFields> {
        Ok(EpochFields {
            tree_id: genesis_ctx(sc.typed, session)?,
            epoch_id: sc.session_id(&b32j(session, "creator")?, u64j(session, "nonce")?),
            epoch: 0,
            parent_epoch_id: ZERO,
            parent_tree_hash: ZERO,
            tree_hash: ZERO,
            admins: list(session, "admins", b32)?,
        })
    }
    /// A commit's, from its record.
    pub fn commit(sc: &TreeScope, rec: &Value) -> Result<EpochFields> {
        Ok(EpochFields {
            tree_id: b32j(rec, "treeId")?,
            epoch_id: sc.epoch_id(
                &b32j(rec, "sessionId")?,
                &b32j(rec, "author")?,
                u64j(rec, "nonce")?,
            ),
            epoch: u64j(rec, "epoch")?,
            parent_epoch_id: b32j(rec, "parentEpochId")?,
            parent_tree_hash: b32j(rec, "parentTreeHash")?,
            tree_hash: b32j(rec, "treeHash")?,
            admins: list(rec, "admins", b32)?,
        })
    }
    /// `ctx_e = keccak256(abi.encode(TAG_TREE_CONTEXT, treeId, epochId, epoch, parentEpochId, parentTreeHash, treeHash,
    /// keccak256(abi.encodePacked(admins))))`.
    pub fn context(&self, sc: &TreeScope) -> [u8; 32] {
        let words = [
            sc.tag_context(),
            self.tree_id,
            self.epoch_id,
            word(self.epoch),
            self.parent_epoch_id,
            self.parent_tree_hash,
            self.tree_hash,
            keccak256(&self.admins.concat()),
        ];
        keccak256(&words.concat())
    }
}

/// The filtered path of a commit from its list alone: the distinct common ancestors of the author's leaf and each target, in
/// list order. `None` when a target is not under the author's direct path.
pub fn path_from_list(author_leaf: u32, ct_targets: &[u32], leaves: u32) -> Option<Vec<u32>> {
    // B-5: a leaf outside the tree has no path (and `2 * leaf` stays in range)
    if author_leaf >= leaves {
        return None;
    }
    let up = direct_path(2 * author_leaf, leaves);
    let mut p: Vec<u32> = Vec::new();
    for &t in ct_targets {
        let mut below = direct_path(t, leaves);
        below.push(t);
        let node = *up.iter().find(|x| below.contains(x))?;
        if t == 2 * author_leaf {
            return None;
        }
        if p.last() != Some(&node) {
            p.push(node);
        }
    }
    let distinct: BTreeSet<u32> = p.iter().copied().collect();
    (distinct.len() == p.len()).then_some(p)
}

/// A path ciphertext (`PathCt`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathCt {
    pub mlkem_ct: Vec<u8>,
    pub x25519_eph: [u8; 32],
    pub sealed_secret: Vec<u8>,
}

impl PathCt {
    pub fn from_json(v: &Value) -> Result<PathCt> {
        Ok(PathCt {
            mlkem_ct: bytes(v.get("mlkemCt").ok_or(Error::Argument)?)?,
            x25519_eph: b32j(v, "x25519Eph")?,
            sealed_secret: bytes(v.get("sealedSecret").ok_or(Error::Argument)?)?,
        })
    }
    pub fn to_json(&self) -> Value {
        json!({"mlkemCt": hx(&self.mlkem_ct), "x25519Eph": hx(&self.x25519_eph), "sealedSecret": hx(&self.sealed_secret)})
    }
    pub fn hash(&self, sc: &TreeScope) -> Result<[u8; 32]> {
        struct_hash(sc.typed, "PathCt", &self.to_json())
    }
}

/// Where a path ciphertext sits: the session's tree, the commit's epoch, the path node and the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtAt {
    pub tree_id: [u8; 32],
    pub epoch_id: [u8; 32],
    pub node: u32,
    pub target: u32,
}

impl CtAt {
    fn aad(&self) -> Vec<u8> {
        [
            &self.tree_id[..],
            &self.epoch_id,
            &be32(self.node),
            &be32(self.target),
        ]
        .concat()
    }
    fn kek(&self, sc: &TreeScope, ss: &[u8], kem_pk: &[u8]) -> Result<Secret> {
        h(
            ss,
            &[&sc.l("ct")[..], &self.aad(), &keccak256(kem_pk)].concat(),
        )
    }
}

fn wrap_aad(ctx_id: &[u8; 32], epoch_id: &[u8; 32], member: &[u8; 32], key_id: u64) -> Vec<u8> {
    [&ctx_id[..], epoch_id, member, &key_id.to_be_bytes()].concat()
}
fn wrap_json(member: &[u8; 32], key_id: u64, w: &KemWrap) -> Value {
    json!({"member": hx(member), "keyId": key_id, "mlkemCt": hx(&w.mlkem_ct), "x25519Eph": hx(&w.x25519_eph),
           "sealedKey": hx(&w.sealed_key)})
}
fn wrap_of(v: &Value) -> Result<KemWrap> {
    Ok(KemWrap {
        mlkem_ct: bytes(v.get("mlkemCt").ok_or(Error::Argument)?)?,
        x25519_eph: b32j(v, "x25519Eph")?,
        sealed_key: bytes(v.get("sealedKey").ok_or(Error::Argument)?)?,
    })
}
pub fn wrap_hash(sc: &TreeScope, wrap: &Value) -> Result<[u8; 32]> {
    struct_hash(sc.typed, "Wrap", wrap)
}

// ------------------------------------------------------------------ the secrets (private: bytes never leave)

/// `ps[0..=m]`: `ps[k+1] = H(ps[k], …/path)`; `ps[m]` is the commit secret.
fn path_secrets(sc: &TreeScope, ps0: Secret, m: usize) -> Result<Vec<Secret>> {
    let mut ps = vec![ps0];
    for _ in 0..m {
        let next = h(&ps.last().ok_or(Error::Argument)?[..], &sc.l("path"))?;
        ps.push(next);
    }
    Ok(ps)
}
/// The node key of a path secret: the KEM key of `HKDF(ps, …/node, 96 B)`, its seed in a store of its own.
fn node_key(sc: &TreeScope, ps: &[u8]) -> Result<KemKeyPair> {
    KemKeyPair::ephemeral(&hkdf_sha256(ps, &[], &sc.l("node"), 96)?)
}
/// `ps[0] = HKDF(kemSeed(ua, keyId), …/commit ‖ pathContext, 32)`.
fn first_path_secret(sc: &TreeScope, kem: &KemKeyPair, ctx: &[u8; 32]) -> Result<Secret> {
    s32(&kem.seed_hkdf(&[&sc.l("commit")[..], ctx].concat(), 32)?)
}
fn joiner_secret(
    sc: &TreeScope,
    commit_secret: &[u8],
    tree_id: &[u8; 32],
    epoch_id: &[u8; 32],
) -> Result<Secret> {
    h(
        commit_secret,
        &[&sc.l("joiner")[..], tree_id, epoch_id].concat(),
    )
}
/// A path-less Add's joiner (the path-less delta §4.1, R20): `H(next_e, …/add-joiner ‖ treeId ‖ epochId ‖ hash(adds))`.
fn add_joiner_secret(
    sc: &TreeScope,
    next: &[u8],
    tree_id: &[u8; 32],
    epoch_id: &[u8; 32],
    adds_hash: &[u8; 32],
) -> Result<Secret> {
    h(
        next,
        &[&sc.l("add-joiner")[..], tree_id, epoch_id, adds_hash].concat(),
    )
}
/// An epoch's branches of `S_e` (the path-less delta §4.1, C43): `K_e = H(S_e, …/key)`, `next_e = H(S_e, …/next)` and the
/// published `confirmTag = H(S_e, …/confirm ‖ ctx_e)` (epoch 0: `‖ genesisCtx`). `S_e` itself is dropped here (F-6).
struct Sched {
    k: Secret,
    next: Secret,
    tag: [u8; 32],
}
/// `S_e = H(joiner, …/epoch ‖ ctx_e)` and its three branches.
fn schedule_s(sc: &TreeScope, joiner: &[u8], f: &EpochFields) -> Result<(Secret, Sched)> {
    let ctx = f.context(sc);
    let s = h(joiner, &[&sc.l("epoch")[..], &ctx].concat())?;
    let tag_ctx = if f.epoch == 0 { f.tree_id } else { ctx };
    let sched = Sched {
        k: h(&s[..], &sc.l("key"))?,
        next: h(&s[..], &sc.l("next"))?,
        tag: *h(&s[..], &[&sc.l("confirm")[..], &tag_ctx].concat())?,
    };
    Ok((s, sched))
}
fn schedule(sc: &TreeScope, joiner: &[u8], f: &EpochFields) -> Result<Sched> {
    Ok(schedule_s(sc, joiner, f)?.1)
}
/// The most tries of a path-less Add's nonce (C47).
pub const ADD_NONCE_TRIES: u32 = 8;
/// A path-less Add's nonce (C47): the first 8 B, big-endian, of `H(kemSeed, …/add-nonce ‖ treeId ‖ parentEpochId ‖
/// parentTreeHash ‖ hash(adds) ‖ u32be(try))`; `TreeAddNonce` for a `try` at or above [`ADD_NONCE_TRIES`].
fn add_nonce(sc: &TreeScope, kem: &KemKeyPair, parent: &[[u8; 32]; 4], try_: u32) -> Result<u64> {
    if try_ >= ADD_NONCE_TRIES {
        return refuse(TreeError::AddNonce);
    }
    let [tree_id, parent_epoch_id, parent_tree_hash, adds_hash] = parent;
    let info = [
        &sc.l("add-nonce")[..],
        tree_id,
        parent_epoch_id,
        parent_tree_hash,
        adds_hash,
        &be32(try_),
    ]
    .concat();
    let o = kem.seed_hkdf(&info, 32)?;
    let b: [u8; 8] = o.get(..8).and_then(|x| x.try_into().ok()).ok_or(Error::Argument)?;
    Ok(u64::from_be_bytes(b))
}
/// The own-commit test of a path-less record (C47, the delta §6.5): whether a `try` of the device's seed gives its nonce.
fn add_nonce_reproduced(sc: &TreeScope, kem: &KemKeyPair, c: &Value) -> Result<bool> {
    let adds = c.get("adds").and_then(Value::as_array).ok_or(Error::Argument)?;
    let parent = [
        b32j(c, "treeId")?,
        b32j(c, "parentEpochId")?,
        b32j(c, "parentTreeHash")?,
        array_hash(sc.typed, "TreeAdd", adds)?,
    ];
    let nonce = u64j(c, "nonce")?;
    for t in 0..ADD_NONCE_TRIES {
        if add_nonce(sc, kem, &parent, t)? == nonce {
            return Ok(true);
        }
    }
    Ok(false)
}
/// The admins' warning threshold (C46, the delta §6.4): `W(0)` = [`PATHLESS_WARN_LEAVES`], `W(N) = max(1, N − ⌈N/4⌉)`.
pub const PATHLESS_WARN_LEAVES: u32 = 20;
pub fn warn_at(n: u32) -> u32 {
    if n == 0 {
        PATHLESS_WARN_LEAVES
    } else {
        (n - n.div_ceil(4)).max(1)
    }
}
fn seal_path_secret(
    sc: &TreeScope,
    at: &CtAt,
    kem_pk: &[u8],
    secret: &[u8],
    m: &[u8; 32],
    e: &[u8; 32],
) -> Result<(Secret, Secret, PathCt)> {
    let (mlkem_ct, x25519_eph, ss) = super::kem::encaps(kem_pk, m, e)?;
    let kek = at.kek(sc, &ss[..], kem_pk)?;
    let sealed_secret = aead_seal(Alg::Aes256Gcm, &kek, &[0; 12], &at.aad(), secret)?;
    Ok((
        ss,
        kek,
        PathCt {
            mlkem_ct,
            x25519_eph,
            sealed_secret,
        },
    ))
}
/// `None` when it does not open ("opening failed").
fn open_path_secret(sc: &TreeScope, at: &CtAt, key: &KemKeyPair, ct: &PathCt) -> Option<Secret> {
    let ss = key.decaps(&ct.mlkem_ct, &ct.x25519_eph).ok()?;
    let kek = at.kek(sc, &ss[..], &key.kem_pk()).ok()?;
    let pt = aead_open(Alg::Aes256Gcm, &kek, &[0; 12], &at.aad(), &ct.sealed_secret).ok()?;
    s32(&pt).ok()
}
fn info_key(sc: &TreeScope, k: &[u8], session: &[u8; 32], epoch: &[u8; 32]) -> Result<Secret> {
    h(k, &[sc.info, session, epoch].concat())
}
/// Mode 0's form under the scope's info key: a full info (the canonical JSON of `info`, never empty) or, for `None`, the
/// marker "unchanged" (empty content, 284 B). `TreeInfoSize` above [`TREE_INFO_MAX`].
fn seal_info(
    sc: &TreeScope,
    k: &[u8],
    session: &[u8; 32],
    epoch: &[u8; 32],
    info: Option<&[u8]>,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    let canon = match info {
        Some(j) => canonical_of_text(j)?,
        None => Zeroizing::new(String::new()),
    };
    let pt = Zeroizing::new(pad(canon.as_bytes())?);
    if 12 + pt.len() + 16 > TREE_INFO_MAX {
        return refuse(TreeError::InfoSize);
    }
    let key = info_key(sc, k, session, epoch)?;
    let n: &[u8; 12] = nonce.try_into().map_err(|_| Error::Argument)?;
    let ct = aead_seal(Alg::Aes256GcmSiv, &key, n, &[], &pt)?;
    Ok([nonce, &ct].concat())
}

/// An opened `sealedInfo`: the marker, or a full info's canonical JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Info {
    Marker,
    Json(String),
}

fn open_info(
    sc: &TreeScope,
    k: &[u8],
    session: &[u8; 32],
    epoch: &[u8; 32],
    sealed: &[u8],
) -> Option<Info> {
    if sealed.len() > TREE_INFO_MAX {
        return None;
    }
    let key = info_key(sc, k, session, epoch).ok()?;
    let n: &[u8; 12] = sealed.get(..12)?.try_into().ok()?;
    let pt = aead_open(Alg::Aes256GcmSiv, &key, n, &[], sealed.get(12..)?).ok()?;
    if super::pqchat_keys::unpad(&pt).ok()?.is_empty() {
        return Some(Info::Marker);
    }
    let c = canonical_content(&pt).ok()?;
    Some(Info::Json(String::from_utf8(c.to_vec()).ok()?))
}

/// Randomness by name (the vectors' `rnd(<step>/<name>, n)`; the OS RNG in a release entry).
pub type Rand<'a> = &'a mut dyn FnMut(&str, usize) -> Result<Zeroizing<Vec<u8>>>;
fn os_rand(_: &str, n: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut v = Zeroizing::new(vec![0u8; n]);
    rng(&mut v)?;
    Ok(v)
}
fn r32(rand: Rand, name: &str) -> Result<Secret> {
    s32(&rand(name, 32)?)
}

// ------------------------------------------------------------------ creation and commits

/// A created session (C29): the record to sign (with `wrapHashes` and `sealedInfo`), its ids, the wraps of epoch 0 and `K_0`.
pub struct Genesis {
    pub record: Value,
    pub session_id: [u8; 32],
    pub genesis_ctx: [u8; 32],
    pub tree_id: [u8; 32],
    pub wraps: Vec<Value>,
    pub k: KeyHandle,
}

/// What a commit is built from: the head the forward walk verified ([`Prepared`]: its tree, id, number, tree hash and admins,
/// spec §15, C26, B2-9; never a tree the caller assembles), the author's leaf and its KEM key (its seed derives `ps[0]`), the
/// Removes and the Adds with each added key's registry record, the admins and the info (`None`: the marker). `key_of(node)`
/// gives a target of the parent tree: a node's key, a leaf's key, or on an epoch-0 head a leaf's registry record; each is
/// checked here ([`TargetKey`]).
pub struct CommitInput<'a> {
    pub parent: &'a Prepared,
    pub session_id: [u8; 32],
    pub tree_id: [u8; 32],
    pub author: [u8; 32],
    pub leaf: u32,
    pub key_id: u64,
    pub kem: &'a KemKeyPair,
    pub removes: Vec<Remove>,
    pub adds: Vec<(Add, KemRecord)>,
    pub admins: Vec<[u8; 32]>,
    pub info: Option<&'a [u8]>,
    pub key_of: &'a mut dyn FnMut(u32) -> Result<TargetKey>,
}

/// A target's key as the caller fetched it (spec §8 steps 4, 5): bytes (`treeNodeKey`, `kemKeyAt`) that a signed tree hash
/// covers, or a leaf's registry record where none does yet (every leaf of an epoch-0 head).
pub enum TargetKey {
    Key(Vec<u8>),
    Record(Box<KemRecord>),
}

/// Target `x`'s key of the parent tree, checked inside the boundary: a node's against its `keyHash`; a leaf's against its
/// `kemHash`, and on an epoch-0 head first authenticated by its registry record (`TreeKemRecord`); a mismatch `TreeKeyHash`.
fn target_key(tree: &Tree, parent_epoch: u64, x: u32, k: TargetKey) -> Result<Vec<u8>> {
    let (key, want) = match (tree.node(x), k) {
        (Node::Leaf(l), TargetKey::Record(r)) => (kem_record_key(&l.ua, l.key_id, &r)?, l.kem_hash),
        (Node::Leaf(l), TargetKey::Key(k)) if parent_epoch > 0 => (k, l.kem_hash),
        (Node::Parent(h), TargetKey::Key(k)) if parent_epoch > 0 => (k, *h),
        _ => return refuse(TreeError::KemRecord),
    };
    if keccak256(&key) != want {
        return refuse(TreeError::KeyHash);
    }
    Ok(key)
}

/// The head's handle (the path-less delta §4.1 lifetime, §6.5): the epoch's id and tree hash, and its `next` secret, held
/// only here and only while this epoch is the device's head: a replay keeps one, of the last epoch it holds.
pub struct TreeHead {
    pub epoch_id: [u8; 32],
    pub tree_hash: [u8; 32],
    pub next: KeyHandle,
}

/// A built commit: the record (unsigned, in the type's field order), its pieces, the tree after it, `K_e` and the new head.
pub struct BuiltCommit {
    pub record: Value,
    pub epoch_id: [u8; 32],
    pub path_context: [u8; 32],
    pub ct_targets: Vec<u32>,
    pub ct_hashes: Vec<[u8; 32]>,
    pub node_keys: Vec<Vec<u8>>,
    pub cts: Vec<PathCt>,
    pub wraps: Vec<Value>,
    pub tree: Tree,
    pub k: KeyHandle,
    pub head: TreeHead,
}

impl AppKeys {
    fn tree_key(&self, k: &[u8]) -> Result<KeyHandle> {
        self.make(k, KeyUsage::Derive, Origin::Tree, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn tree_wrap(
        &self,
        sc: &TreeScope,
        joiner: &KeyHandle,
        ctx_id: &[u8; 32],
        epoch_id: &[u8; 32],
        member: &[u8; 32],
        key_id: u64,
        kem_pk: &[u8],
        m: &[u8; 32],
        e: &[u8; 32],
    ) -> Result<Value> {
        let aad = wrap_aad(ctx_id, epoch_id, member, key_id);
        let w = self.wrap_with(joiner, &sc.wrap_label(), &aad, kem_pk, m, e)?;
        Ok(wrap_json(member, key_id, &w))
    }

    /// The joiner secret of a tree wrap (`ctx_id`: `genesisCtx` for epoch 0, `treeId` for a Welcome); `None` when it does
    /// not open.
    fn tree_unwrap(
        &self,
        sc: &TreeScope,
        kem: &KemKeyPair,
        wrap: &Value,
        ctx_id: &[u8; 32],
        epoch_id: &[u8; 32],
    ) -> Option<Secret> {
        let aad = wrap_aad(
            ctx_id,
            epoch_id,
            &b32j(wrap, "member").ok()?,
            u64j(wrap, "keyId").ok()?,
        );
        let hd = self
            .kem_unwrap(
                kem,
                &wrap_of(wrap).ok()?,
                &sc.wrap_label(),
                &aad,
                KeyUsage::Derive,
            )
            .ok()?;
        self.bytes(&hd).ok()
    }

    /// Creation in order (C29, codex-r2-4): `genesisCtx` → `joiner_0`, `K_0` → the wraps and `sealedInfo` → the record with
    /// their hashes → `treeId`. `session` is the record without `wrapHashes` and `sealedInfo`; `kems[i]` the registry record of
    /// `members[i]`'s key (authenticated here, `TreeKemRecord`, then admitted, `KemCheck`; spec §8 step 5); `info` the
    /// canonical JSON of the session info. The signature is the caller's. Randomness from the OS.
    pub fn tree_create_genesis(
        &self,
        sc: &TreeScope,
        session: &Value,
        kems: &[KemRecord],
        info: &[u8],
    ) -> Result<Genesis> {
        self.create_genesis(sc, session, kems, info, &mut os_rand)
    }

    fn create_genesis(
        &self,
        sc: &TreeScope,
        session: &Value,
        kems: &[KemRecord],
        info: &[u8],
        rand: Rand,
    ) -> Result<Genesis> {
        let f = EpochFields::genesis(sc, session)?;
        let members = list(session, "members", |m| {
            Ok((b32j(m, "ua")?, u64j(m, "keyId")?))
        })?;
        if members.len() != kems.len() {
            return Err(Error::Argument);
        }
        let mut kem_pks = Vec::new();
        for ((ua, key_id), r) in members.iter().zip(kems) {
            let k = kem_record_key(ua, *key_id, r)?;
            admit_kem_key(&k)?;
            kem_pks.push(k);
        }
        // the cold tree's own refusals before anything is signed (B-4): at most TREE_LEAVES_MAX keys, one leaf per key
        let cold: Vec<Leaf> = members
            .iter()
            .zip(&kem_pks)
            .map(|((ua, key_id), k)| Leaf {
                ua: *ua,
                key_id: *key_id,
                kem_hash: keccak256(k),
            })
            .collect();
        Tree::cold(&cold)?;
        let joiner = self.make(
            &r32(rand, "joiner-0")?[..],
            KeyUsage::Derive,
            Origin::Drawn,
            None,
        )?;
        let sch = schedule(sc, &self.bytes(&joiner)?[..], &f)?;
        let k = sch.k;
        let mut wraps = Vec::new();
        for (i, ((ua, key_id), kem_pk)) in members.iter().zip(&kem_pks).enumerate() {
            let (m, e) = (
                r32(rand, &format!("wrap/{i}/mlkem-m"))?,
                r32(rand, &format!("wrap/{i}/x25519-ephemeral"))?,
            );
            wraps.push(self.tree_wrap(
                sc,
                &joiner,
                &f.tree_id,
                &f.epoch_id,
                ua,
                *key_id,
                kem_pk,
                &m,
                &e,
            )?);
        }
        let nonce = rand("sealed-info-nonce", 12)?;
        let sealed = seal_info(sc, &k[..], &f.epoch_id, &f.epoch_id, Some(info), &nonce)?;
        let mut record = session.clone();
        let obj = record.as_object_mut().ok_or(Error::Argument)?;
        let hashes = wraps
            .iter()
            .map(|w| Ok(hx(&wrap_hash(sc, w)?)))
            .collect::<Result<Vec<_>>>()?;
        obj.insert("wrapHashes".into(), json!(hashes));
        obj.insert("sealedInfo".into(), json!(hx(&sealed)));
        // epoch 0's tag (C43, F-7): after genesisCtx, outside it
        obj.insert("confirmTag".into(), json!(hx(&sch.tag)));
        Ok(Genesis {
            session_id: f.epoch_id,
            genesis_ctx: f.tree_id,
            tree_id: tree_id(sc.typed, &record)?,
            record,
            wraps,
            k: self.tree_key(&k[..])?,
        })
    }

    /// Builds a commit inside the boundary (spec §5, §8): the nonce drawn here at random and returned in the record (C17;
    /// the caller stores it before anything leaves), the path from the author's seed, the path ciphertexts to every target
    /// (each key admitted, `KemCheck`), the Welcome wraps, the record, the tree after it and `K_e`. Randomness from the OS.
    pub fn tree_build_commit(&self, sc: &TreeScope, a: CommitInput) -> Result<BuiltCommit> {
        let mut n = [0u8; 8];
        rng(&mut n)?;
        self.build_commit(sc, a, u64::from_be_bytes(n), &mut os_rand)
    }

    fn build_commit(
        &self,
        sc: &TreeScope,
        a: CommitInput,
        nonce: u64,
        rand: Rand,
    ) -> Result<BuiltCommit> {
        let pr = a.parent;
        let tree = &pr.tree;
        // the tree the parent's signed hash covers and the author's own leaf key (F-4): `pathContext` binds both (the first holds
        // by construction of `Prepared` since B2-9; kept as a check)
        if tree.tree_hash() != pr.parent_tree_hash {
            return refuse(TreeError::Parent);
        }
        if tree.leaf(a.leaf).map(|l| l.kem_hash) != Some(keccak256(&a.kem.kem_pk())) {
            return refuse(TreeError::KeyHash);
        }
        // each added key authenticated by its registry record and named by the Add's kemHash (spec §8 step 5)
        let mut add_keys = Vec::new();
        for (x, r) in &a.adds {
            let k = kem_record_key(&x.ua, x.key_id, r)?;
            if keccak256(&k) != x.kem_hash {
                return refuse(TreeError::KeyHash);
            }
            add_keys.push(k);
        }
        let add_recs: Vec<Add> = a.adds.iter().map(|(x, _)| x.clone()).collect();
        let ch = Changes {
            author: a.author,
            leaf: a.leaf,
            key_id: a.key_id,
            removes: a.removes.clone(),
            adds: add_recs.clone(),
            pathless: false,
        };
        let p = tree.filtered_path_after(&ch)?;
        let ct_targets: Vec<u32> = p.iter().flat_map(|q| q.targets.iter().copied()).collect();
        let removes: Vec<Value> = a.removes.iter().map(Remove::to_json).collect();
        let adds: Vec<Value> = add_recs.iter().map(Add::to_json).collect();
        let mut rec = json!({
            "sessionId": hx(&a.session_id), "author": hx(&a.author), "nonce": nonce, "epoch": pr.parent_epoch + 1,
            "parentEpochId": hx(&pr.parent_epoch_id), "treeId": hx(&a.tree_id), "parentTreeHash": hx(&pr.parent_tree_hash),
            "leaf": a.leaf, "keyId": a.key_id, "removes": removes, "adds": adds,
        });
        let ctx = path_context(sc, &rec, &ct_targets)?;
        let ps = path_secrets(sc, first_path_secret(sc, a.kem, &ctx)?, p.len())?;
        let mut node_keys = Vec::new();
        for s in ps.iter().take(p.len()) {
            node_keys.push(node_key(sc, &s[..])?.kem_pk());
        }
        let node_key_hashes: Vec<[u8; 32]> = node_keys.iter().map(|k| keccak256(k)).collect();
        let epoch_id = sc.epoch_id(&a.session_id, &a.author, nonce);
        let mut cts = Vec::new();
        for (q, s) in p.iter().zip(&ps) {
            for &t in &q.targets {
                let j = cts.len();
                let kem_pk = match add_recs.iter().position(|x| 2 * x.leaf == t) {
                    Some(i) => add_keys.get(i).cloned().ok_or(Error::Argument)?,
                    None => target_key(tree, pr.parent_epoch, t, (a.key_of)(t)?)?,
                };
                super::tree_public::admit_kem_key(&kem_pk)?;
                let at = CtAt {
                    tree_id: a.tree_id,
                    epoch_id,
                    node: q.node,
                    target: t,
                };
                let (m, e) = (
                    r32(rand, &format!("ct/{j}/mlkem-m"))?,
                    r32(rand, &format!("ct/{j}/x25519-ephemeral"))?,
                );
                cts.push(seal_path_secret(sc, &at, &kem_pk, &s[..], &m, &e)?.2);
            }
        }
        let ct_hashes = cts.iter().map(|c| c.hash(sc)).collect::<Result<Vec<_>>>()?;
        let applied = tree.apply_commit(&ch, &node_key_hashes)?;
        // what the contract judges at acceptance, before anything is signed (§8, §9, D-5)
        tree.judge_commit(&applied.tree, &ch, &a.admins, &pr.parent_admins)?;
        let obj = rec.as_object_mut().ok_or(Error::Argument)?;
        obj.insert("leaves".into(), json!(applied.tree.leaves));
        obj.insert(
            "admins".into(),
            json!(a.admins.iter().map(|x| hx(x)).collect::<Vec<_>>()),
        );
        obj.insert(
            "nodeKeyHashes".into(),
            json!(node_key_hashes.iter().map(|x| hx(x)).collect::<Vec<_>>()),
        );
        obj.insert("ctCount".into(), json!(ct_targets.len()));
        obj.insert(
            "ctListHash".into(),
            json!(hx(&path_list_hash(sc.typed, &ct_targets, &ct_hashes)?)),
        );
        obj.insert("treeHash".into(), json!(hx(&applied.tree_hash)));
        let commit_secret = ps.get(p.len()).ok_or(Error::Argument)?;
        let joiner = joiner_secret(sc, &commit_secret[..], &a.tree_id, &epoch_id)?;
        let joiner_h = self.make(&joiner[..], KeyUsage::Derive, Origin::Derived, None)?;
        let f = EpochFields {
            tree_id: a.tree_id,
            epoch_id,
            epoch: pr.parent_epoch + 1,
            parent_epoch_id: pr.parent_epoch_id,
            parent_tree_hash: pr.parent_tree_hash,
            tree_hash: applied.tree_hash,
            admins: a.admins.clone(),
        };
        let sch = schedule(sc, &joiner[..], &f)?;
        let k = &sch.k;
        let mut wraps = Vec::new();
        for (i, (x, kem_pk)) in add_recs.iter().zip(&add_keys).enumerate() {
            let (m, e) = (
                r32(rand, &format!("welcome/{i}/mlkem-m"))?,
                r32(rand, &format!("welcome/{i}/x25519-ephemeral"))?,
            );
            wraps.push(self.tree_wrap(
                sc, &joiner_h, &a.tree_id, &epoch_id, &x.ua, x.key_id, kem_pk, &m, &e,
            )?);
        }
        let nonce12 = rand("sealed-info-nonce", 12)?;
        let sealed = seal_info(sc, &k[..], &a.session_id, &epoch_id, a.info, &nonce12)?;
        let hashes = wraps
            .iter()
            .map(|w| Ok(hx(&wrap_hash(sc, w)?)))
            .collect::<Result<Vec<_>>>()?;
        obj.insert("wrapHashes".into(), json!(hashes));
        obj.insert("sealedInfo".into(), json!(hx(&sealed)));
        obj.insert("pathless".into(), json!(false));
        obj.insert("confirmTag".into(), json!(hx(&sch.tag)));
        Ok(BuiltCommit {
            record: rec,
            epoch_id,
            path_context: ctx,
            ct_targets: applied.ct_targets.clone(),
            ct_hashes,
            node_keys,
            cts,
            wraps,
            head: self.tree_head(epoch_id, applied.tree_hash, &sch.next[..])?,
            tree: applied.tree,
            k: self.tree_key(&k[..])?,
        })
    }

    fn tree_head(&self, epoch_id: [u8; 32], tree_hash: [u8; 32], next: &[u8]) -> Result<TreeHead> {
        Ok(TreeHead {
            epoch_id,
            tree_hash,
            next: self.make(next, KeyUsage::Derive, Origin::Derived, None)?,
        })
    }

    /// Builds a path-less Add inside the boundary (the path-less delta §4.1 construction order, §6.5): on the head the
    /// forward walk verified (`a.parent`) and the device's handle of that head (`head`: refused `TreeHandle` unless its
    /// `epochId` and `treeHash` are the record's `parentEpochId` and `parentTreeHash`, claude-19), the Adds' keys
    /// authenticated, the nonce `addNonce` at `try_` (C47) unless the vectors give one, the tree after the Adds, the head's
    /// admin list, `joiner = H(next, …/add-joiner …)`, the Welcome wraps, `sealedInfo` and the tag; `pathless` true.
    fn build_pathless(
        &self,
        sc: &TreeScope,
        a: PathlessInput,
        head: &TreeHead,
        nonce: Nonce,
        rand: Rand,
    ) -> Result<BuiltCommit> {
        let pr = a.parent;
        let tree = &pr.tree;
        if head.epoch_id != pr.parent_epoch_id || head.tree_hash != pr.parent_tree_hash {
            return refuse(TreeError::Handle);
        }
        if tree.tree_hash() != pr.parent_tree_hash {
            return refuse(TreeError::Parent);
        }
        if tree.leaf(a.leaf).map(|l| l.kem_hash) != Some(keccak256(&a.kem.kem_pk())) {
            return refuse(TreeError::KeyHash);
        }
        let mut add_keys = Vec::new();
        for (x, r) in &a.adds {
            let k = kem_record_key(&x.ua, x.key_id, r)?;
            if keccak256(&k) != x.kem_hash {
                return refuse(TreeError::KeyHash);
            }
            add_keys.push(k);
        }
        let add_recs: Vec<Add> = a.adds.iter().map(|(x, _)| x.clone()).collect();
        let adds: Vec<Value> = add_recs.iter().map(Add::to_json).collect();
        let adds_hash = array_hash(sc.typed, "TreeAdd", &adds)?;
        let nonce = match nonce {
            Nonce::Given(n) => n,
            Nonce::Try(t) => add_nonce(
                sc,
                a.kem,
                &[a.tree_id, pr.parent_epoch_id, pr.parent_tree_hash, adds_hash],
                t,
            )?,
        };
        let ch = Changes {
            author: a.author,
            leaf: a.leaf,
            key_id: a.key_id,
            removes: Vec::new(),
            adds: add_recs.clone(),
            pathless: true,
        };
        let applied = tree.apply_commit(&ch, &[])?;
        let admins = pr.parent_admins.clone();
        tree.judge_commit(&applied.tree, &ch, &admins, &pr.parent_admins)?;
        let epoch_id = sc.epoch_id(&a.session_id, &a.author, nonce);
        let mut rec = json!({
            "sessionId": hx(&a.session_id), "author": hx(&a.author), "nonce": nonce, "epoch": pr.parent_epoch + 1,
            "parentEpochId": hx(&pr.parent_epoch_id), "treeId": hx(&a.tree_id), "parentTreeHash": hx(&pr.parent_tree_hash),
            "leaf": a.leaf, "keyId": a.key_id, "leaves": applied.tree.leaves,
            "admins": admins.iter().map(|x| hx(x)).collect::<Vec<_>>(), "removes": [], "adds": adds,
            "nodeKeyHashes": [], "ctCount": 0, "ctListHash": hx(&path_list_hash(sc.typed, &[], &[])?),
            "treeHash": hx(&applied.tree_hash),
        });
        let next = self.bytes(&head.next)?;
        let joiner = add_joiner_secret(sc, &next[..], &a.tree_id, &epoch_id, &adds_hash)?;
        let joiner_h = self.make(&joiner[..], KeyUsage::Derive, Origin::Derived, None)?;
        let f = EpochFields::commit(sc, &rec)?;
        let sch = schedule(sc, &joiner[..], &f)?;
        let mut wraps = Vec::new();
        for (i, (x, kem_pk)) in add_recs.iter().zip(&add_keys).enumerate() {
            admit_kem_key(kem_pk)?;
            let (m, e) = (
                r32(rand, &format!("welcome/{i}/mlkem-m"))?,
                r32(rand, &format!("welcome/{i}/x25519-ephemeral"))?,
            );
            wraps.push(self.tree_wrap(
                sc, &joiner_h, &a.tree_id, &epoch_id, &x.ua, x.key_id, kem_pk, &m, &e,
            )?);
        }
        let nonce12 = rand("sealed-info-nonce", 12)?;
        let sealed = seal_info(sc, &sch.k[..], &a.session_id, &epoch_id, a.info, &nonce12)?;
        let hashes = wraps
            .iter()
            .map(|w| Ok(hx(&wrap_hash(sc, w)?)))
            .collect::<Result<Vec<_>>>()?;
        let obj = rec.as_object_mut().ok_or(Error::Argument)?;
        obj.insert("wrapHashes".into(), json!(hashes));
        obj.insert("sealedInfo".into(), json!(hx(&sealed)));
        obj.insert("pathless".into(), json!(true));
        obj.insert("confirmTag".into(), json!(hx(&sch.tag)));
        Ok(BuiltCommit {
            record: rec,
            epoch_id,
            path_context: ZERO,
            ct_targets: Vec::new(),
            ct_hashes: Vec::new(),
            node_keys: Vec::new(),
            cts: Vec::new(),
            wraps,
            head: self.tree_head(epoch_id, applied.tree_hash, &sch.next[..])?,
            tree: applied.tree,
            k: self.tree_key(&sch.k[..])?,
        })
    }
}

/// What a path-less Add is built from (the path-less delta §6.5): the head the forward walk verified, the author's leaf and
/// KEM key (its seed derives the nonce), the Adds with each added key's registry record and the info (`None`: the marker).
/// The admin list is the head's; there are no Removes.
pub struct PathlessInput<'a> {
    pub parent: &'a Prepared,
    pub session_id: [u8; 32],
    pub tree_id: [u8; 32],
    pub author: [u8; 32],
    pub leaf: u32,
    pub key_id: u64,
    pub kem: &'a KemKeyPair,
    pub adds: Vec<(Add, KemRecord)>,
    pub info: Option<&'a [u8]>,
}

/// A path-less Add's nonce: `addNonce` at a `try` (C47), or one the vectors give (an insider's record, a refusal row).
enum Nonce {
    Try(u32),
    #[cfg_attr(not(feature = "vectors"), allow(dead_code))]
    Given(u64),
}

// ------------------------------------------------------------------ the signing operations (spec §15; T26 A-5)

/// A line of a review: a field's name and its value as shown (`0x` hex, a number, a list joined by `, `, a struct as JSON).
pub type ReviewLine = (String, String);

fn show(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(show).collect::<Vec<_>>().join(", "),
        x => x.to_string(),
    }
}

/// A tree record prepared for its signature (prepare → review → sign, as the SDK's T26 A-5): the record built here from
/// named fields, its review (every field in the type's order, then what the operation adds) and its typed digest;
/// [`TreePrepared::sign`] signs exactly that record, once, on PqChat's dedicated path ([`super::pqchat::TREE_RECORDS`]),
/// the key opened only there. No call signs a tree record's digest supplied from outside.
pub struct TreePrepared {
    td: TypedData,
    purpose: [u8; 32],
    review: Vec<ReviewLine>,
}

impl TreePrepared {
    fn new(sc: &TreeScope, name: &str, rec: Value, more: Vec<ReviewLine>) -> Result<TreePrepared> {
        let td = (sc.typed)(name, rec)?;
        let v = td.to_value();
        let mut review = vec![("record".to_string(), name.to_string())];
        let fields = v
            .get("types")
            .and_then(|t| t.get(name))
            .and_then(Value::as_array);
        for f in fields.into_iter().flatten() {
            let n = f
                .get("name")
                .and_then(Value::as_str)
                .ok_or(Error::Argument)?;
            let x = v
                .get("message")
                .and_then(|m| m.get(n))
                .ok_or(Error::Argument)?;
            review.push((n.to_string(), show(x)));
        }
        review.extend(more);
        // what the signature is under: the scope's domain and purpose (B-2)
        let purpose = (sc.purpose)();
        review.push((
            "domain".into(),
            show(v.get("domain").unwrap_or(&Value::Null)),
        ));
        review.push(("purpose".into(), hx(&purpose)));
        Ok(TreePrepared {
            td,
            purpose,
            review,
        })
    }
    /// What the signer is shown before it signs.
    pub fn review(&self) -> &[ReviewLine] {
        &self.review
    }
    /// The typed digest the signature covers.
    pub fn digest(&self) -> Result<[u8; 32]> {
        self.td.digest()
    }
    /// The record as it is signed (its named fields, `0x` hex).
    pub fn record(&self) -> Value {
        self.td
            .to_value()
            .get("message")
            .cloned()
            .unwrap_or(Value::Null)
    }
    /// The single UA key's `UASig` over the prepared record under the scope's purpose (a native key or an `msig`: `Argument`).
    pub fn sign(self, key: &dyn Signer) -> Result<UASig> {
        super::pqchat::sign_tree(key, &self.td, &self.purpose)
    }
}

/// A commit built inside the boundary and prepared for its author's signature (spec §15, codex-12): its pieces and its
/// record ([`BuiltCommit`]), the review (every field of the record, whether the admins change, the session info or the
/// marker) and the digest; [`PreparedCommit::sign`] returns the pieces with the signature over exactly their record.
pub struct PreparedCommit {
    built: BuiltCommit,
    rec: TreePrepared,
}

impl PreparedCommit {
    /// The record and the pieces (public bytes) and `K_e`'s handle.
    pub fn built(&self) -> &BuiltCommit {
        &self.built
    }
    pub fn review(&self) -> &[ReviewLine] {
        self.rec.review()
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        self.rec.digest()
    }
    /// The author's signature over the record built here, with the pieces built with it.
    pub fn sign(self, key: &dyn Signer) -> Result<(BuiltCommit, UASig)> {
        let sig = self.rec.sign(key)?;
        Ok((self.built, sig))
    }
}

/// `PqChatTreeLeave`'s named fields (spec §6): `member` leaves the session `treeId`, naming `epochId` (the head or an
/// ancestor within [`EXIT_LAG_MAX`]; applied at the head, C9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeLeave {
    pub session_id: [u8; 32],
    pub tree_id: [u8; 32],
    pub epoch_id: [u8; 32],
    pub member: [u8; 32],
    pub nonce: u64,
}

/// `PqChatTreeRemove`'s named fields (spec §6): the admin `admin` removes `members`, naming `epochId` (the head or an
/// ancestor within [`EXIT_LAG_MAX`]; applied at the head, C9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeRemove {
    pub session_id: [u8; 32],
    pub tree_id: [u8; 32],
    pub epoch_id: [u8; 32],
    pub next_epoch: u64,
    pub members: Vec<[u8; 32]>,
    pub admin: [u8; 32],
    pub nonce: u64,
}

/// A `treeLeave` prepared for the leaver's signature: the review names the session by `treeId`, says the UA cannot come
/// back (C30, R14) and that the leave applies if it lands within the lag (spec §9).
pub fn tree_prepare_leave(sc: &TreeScope, l: &TreeLeave) -> Result<TreePrepared> {
    let rec = json!({"sessionId": hx(&l.session_id), "treeId": hx(&l.tree_id), "epochId": hx(&l.epoch_id),
        "member": hx(&l.member), "nonce": l.nonce});
    let back = "this UA can never come back to this session (R14)".to_string();
    let within = applies_within(&format!("the epoch it names ({})", hx(&l.epoch_id)));
    TreePrepared::new(
        sc,
        "PqChatTreeLeave",
        rec,
        vec![("cannotComeBack".into(), back), within],
    )
}

/// A `treeRemove` prepared for the admin's signature: the review names the session by `treeId`, says the removed UAs
/// cannot come back (C30, R14) and that the removal applies if it lands within the lag of epoch `nextEpoch - 1` (spec §9).
pub fn tree_prepare_remove(sc: &TreeScope, r: &TreeRemove) -> Result<TreePrepared> {
    let members: Vec<String> = r.members.iter().map(|m| hx(m)).collect();
    let rec = json!({"sessionId": hx(&r.session_id), "treeId": hx(&r.tree_id), "epochId": hx(&r.epoch_id),
        "nextEpoch": r.next_epoch, "members": members, "admin": hx(&r.admin), "nonce": r.nonce});
    let back = "the removed UAs can never come back to this session (R14)".to_string();
    let within = applies_within(&format!("epoch {}", r.next_epoch.saturating_sub(1)));
    TreePrepared::new(
        sc,
        "PqChatTreeRemove",
        rec,
        vec![("cannotComeBack".into(), back), within],
    )
}

/// The exit review's line (spec §9, sc-E-3, sc-F-6; F-4 / B2-10): an exit is applied at the head whenever it lands within
/// [`EXIT_LAG_MAX`] epochs of the epoch it names, and it cannot be withdrawn.
fn applies_within(named: &str) -> ReviewLine {
    (
        "appliesWithin".into(),
        format!(
            "applies if it lands within {EXIT_LAG_MAX} epochs of {named}; it cannot be withdrawn"
        ),
    )
}

impl AppKeys {
    /// The typed commit-signing operation (spec §15, codex-12): [`AppKeys::tree_build_commit`] (the target keys checked, the
    /// nonce drawn, the path, the list, the pieces and the record built here), then the record prepared for the author's
    /// signature with its review. Randomness from the OS.
    pub fn tree_prepare_commit(&self, sc: &TreeScope, a: CommitInput) -> Result<PreparedCommit> {
        let mut n = [0u8; 8];
        rng(&mut n)?;
        self.prepare_commit(sc, a, u64::from_be_bytes(n), &mut os_rand)
    }

    fn prepare_commit(
        &self,
        sc: &TreeScope,
        a: CommitInput,
        nonce: u64,
        rand: Rand,
    ) -> Result<PreparedCommit> {
        let changed = a.admins != a.parent.parent_admins;
        let info = match a.info {
            Some(j) => canonical_of_text(j)?.to_string(),
            None => "unchanged (the marker)".to_string(),
        };
        let built = self.build_commit(sc, a, nonce, rand)?;
        let more = vec![
            ("adminsChanged".to_string(), changed.to_string()),
            ("sessionInfo".to_string(), info),
        ];
        let rec = TreePrepared::new(sc, "PqChatCommit", built.record.clone(), more)?;
        Ok(PreparedCommit { built, rec })
    }

    /// The typed operation of a path-less Add (the path-less delta §6.5; one operation per kind): [`PathlessInput`] on the
    /// device's handle of the head (`TreeHandle` for another), the nonce `addNonce` at `try_` (C47: the lowest whose record
    /// is not in state for this parent and these Adds; `TreeAddNonce` from [`ADD_NONCE_TRIES`] on), built here, then prepared
    /// for the author's signature with its review (§6.4: "adds without refreshing the group's keys; n of N since the last
    /// refresh"). The new handle is [`BuiltCommit::head`]. Randomness from the OS.
    pub fn tree_prepare_pathless(
        &self,
        sc: &TreeScope,
        a: PathlessInput,
        head: &TreeHead,
        try_: u32,
    ) -> Result<PreparedCommit> {
        self.prepare_pathless(sc, a, head, Nonce::Try(try_), &mut os_rand)
    }

    fn prepare_pathless(
        &self,
        sc: &TreeScope,
        a: PathlessInput,
        head: &TreeHead,
        nonce: Nonce,
        rand: Rand,
    ) -> Result<PreparedCommit> {
        let info = match a.info {
            Some(j) => canonical_of_text(j)?.to_string(),
            None => "unchanged (the marker)".to_string(),
        };
        let built = self.build_pathless(sc, a, head, nonce, rand)?;
        let (n, cap) = (built.tree.since_path, built.tree.path_bound);
        let line = if cap > 0 {
            format!("adds without refreshing the group's keys; {n} of {cap} since the last refresh")
        } else {
            format!("adds without refreshing the group's keys; {n} since the last refresh")
        };
        let more = vec![
            ("pathless".to_string(), line),
            ("sessionInfo".to_string(), info),
        ];
        let rec = TreePrepared::new(sc, "PqChatCommit", built.record.clone(), more)?;
        Ok(PreparedCommit { built, rec })
    }
}

// ------------------------------------------------------------------ the views a device reads (spec §6)

/// A read of the home's views; its `Display` is the read's name as the vectors log it (`commitOf(3)`). The reads by number stand
/// for the contract's by id (`epochsOf` at that number); an exit's record comes without `treeId` (the session's), with its sig.
#[derive(Clone, Copy, Debug)]
pub enum View<'a> {
    SessionOf,
    TreeOf,
    TreeLeaves,
    TreeNodes,
    TreeNodeKey(u32),
    EpochsOf,
    CommitOf(u64),
    PathListOf(u64),
    PathCtAt(u64, usize),
    WrapAt(u64, usize),
    GoneOf(&'a [u8; 32]),
    LeaveCount(u64),
    LeaveAt(u64, usize),
    RemovalCount(u64),
    RemovalAt(u64, usize),
    GoneOwnKeyOf(&'a [u8; 32], &'a [u8; 32]),
    GoneKeyOf(&'a [u8; 32]),
    KemKeyAt(&'a [u8; 32], u64),
}

impl core::fmt::Display for View<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            View::SessionOf => write!(f, "sessionOf()"),
            View::TreeOf => write!(f, "treeOf()"),
            View::TreeLeaves => write!(f, "treeLeaves()"),
            View::TreeNodes => write!(f, "treeNodes()"),
            View::TreeNodeKey(x) => write!(f, "treeNodeKey({x})"),
            View::EpochsOf => write!(f, "epochsOf()"),
            View::CommitOf(n) => write!(f, "commitOf({n})"),
            View::PathListOf(n) => write!(f, "pathListOf({n})"),
            View::PathCtAt(n, j) => write!(f, "pathCtAt({n},{j})"),
            View::WrapAt(n, i) => write!(f, "wrapAt({n},{i})"),
            View::GoneOf(u) => write!(f, "goneOf({})", hx(*u)),
            View::LeaveCount(n) => write!(f, "leaveCount({n})"),
            View::LeaveAt(n, i) => write!(f, "leaveAt({n},{i})"),
            View::RemovalCount(n) => write!(f, "removalCount({n})"),
            View::RemovalAt(n, i) => write!(f, "removalAt({n},{i})"),
            View::GoneOwnKeyOf(u, k) => write!(f, "goneOwnKeyOf({},{})", hx(*u), hx(*k)),
            View::GoneKeyOf(k) => write!(f, "goneKeyOf({})", hx(*k)),
            View::KemKeyAt(u, k) => write!(f, "kemKeyAt({},{k})", hx(*u)),
        }
    }
}

/// The home's views (JSON in the contract views' shape, as clientkeys' `reader`; `kemKeyAt` the registry's `{kemPk, sig}`), and
/// the registry's records of the signers (signature checks, never session reads): a UA's `(kind, key data)` (the first
/// structure of an `msig`, its id), whether slot `index` of an `msig` is accepted on the registry (`msigStateOf(ua).accepted`,
/// permanent; CTR-UA-74 step 4: the version a record names gives the enabled word), an `msig`'s structure by version, and a UA's
/// registration for its version-0 KEM key.
pub trait TreeReader {
    fn read(&mut self, v: View) -> Result<Value>;
    fn ua_key_of(&self, ua: &[u8; 32]) -> Option<(u16, Vec<u8>)>;
    fn accepted(&self, ua: &[u8; 32], index: u16) -> bool;
    /// The registry's `msigAt(ua, version)` (CTR-UA-74): that version's structure (every slot, disabled ones included) and its
    /// `enabled` word (big-endian, bit i = slot i); `None` for the empty answer (a version never stored, another id). What a kept
    /// record of an `msig` is verified by: the version its tag names, never another (the reader rule).
    fn msig_at(&self, ua: &[u8; 32], version: u64) -> Option<(Vec<u8>, [u8; 32])>;
    /// A UA's registration (`registrationOf`: its attributes and `pop`), the record of its version-0 KEM key (§8 step 5);
    /// `None` when the reader has none (that key is then `TreeKemRecord`).
    fn registration(&self, ua: &[u8; 32]) -> Option<(crate::ua_portable::UAAttrs, Vec<u8>)>;
}

/// A record's signature for its signer's kind, as the contract's `requirePortable` judges it (F-3): a single key of each
/// holder kind and WebAuthn by its `signature`, an `msig` by its kept `members` (`abi.encode(MemberSig[])`), minimal, each slot
/// accepted, over its structure at the version its `signature` (the tag) names (CTR-UA-74, the reader rule; never another
/// version, never the current one). `sig`: hex (a single key's signature) or `{signature, members}`. Anything else:
/// `TreeReadCorrupted`. Returns every `(msig, version)` the signature names (C-4, R-1: the signer's tag and each signing `msig`
/// member slot's; none for a single key), for [`Walk`]'s order check (step 6).
fn verified(
    sc: &TreeScope,
    rd: &dyn TreeReader,
    name: &str,
    rec: &Value,
    signer: &[u8; 32],
    sig: &Value,
) -> Result<Named> {
    let ok = (|| {
        let (kind, key_data) = rd.ua_key_of(signer)?;
        let digest = (sc.typed)(name, rec.clone()).ok()?.digest().ok()?;
        let s = match sig {
            Value::String(_) => UASig {
                signature: bytes(sig).ok()?,
                ..UASig::default()
            },
            v => {
                let m = bytes(v.get("members")?).ok()?;
                UASig {
                    key_data: vec![],
                    signature: bytes(v.get("signature")?).ok()?,
                    members: if m.is_empty() {
                        vec![]
                    } else {
                        crate::ua_portable::decode_member_sigs(&m)?
                    },
                }
            }
        };
        let members = |id: [u8; 32]| rd.ua_key_of(&id);
        // CTR-UA-74: an `msig` by the version its tag names (`msigAt`), as mode 0's records; no current structure is read
        let at = |id: [u8; 32], v: Option<u64>| {
            v.and_then(|v| rd.msig_at(&id, v).map(|(d, en)| (d, en, v)))
        };
        let accepted = |id: [u8; 32], i: u16| rd.accepted(&id, i);
        let named = crate::ua_portable::named_versions(kind, &key_data, signer, &s, &members, &at)?;
        Some(
            crate::ua_portable::check_portable_current(
                kind,
                &key_data,
                signer,
                &(sc.purpose)(),
                &digest,
                &s,
                &members,
                &at,
                Some(&accepted),
            )
            .map(|()| named),
        )
    })();
    match ok {
        Some(Ok(v)) => Ok(v),
        // spec §10 step 5 (C-7): a signer kind the contract accepts that this reader cannot verify is a defect of the reader
        Some(Err(crate::UAError::NotVerifiable)) => Err(Error::Ua(crate::UAError::NotVerifiable)),
        _ => corrupt(),
    }
}
/// The key of `(ua, keyId)` a cold tree's leaf takes (§8 steps 3 and 5, C-1, F-2, B2-5): the registry's `kemKeyAt`
/// `{kemPk, sig}`, authenticated by its record ([`kem_record_key`]): a version above 0 by `setKemKey`'s kept signature, version 0
/// by the registration's proof of possession. A key that fails: `TreeKemRecord`.
fn kem_at(rd: &mut dyn TreeReader, ua: &[u8; 32], key_id: u64) -> Result<Vec<u8>> {
    let v = rd.read(View::KemKeyAt(ua, key_id))?;
    let (kem_pk, sig) = served((|| {
        Some((bytes(v.get("kemPk")?).ok()?, bytes(v.get("sig")?).ok()?))
    })())?;
    let (kind, key_data) = rd.ua_key_of(ua).ok_or(Error::Tree(TreeError::KemRecord))?;
    let rec = if key_id > 0 {
        KemRecord::Version {
            kind,
            key_data,
            kem_pk,
            sig,
        }
    } else {
        let (attrs, pop) = rd
            .registration(ua)
            .ok_or(Error::Tree(TreeError::KemRecord))?;
        KemRecord::Registration {
            kind,
            key_data,
            attrs,
            pop,
            kem_pk,
        }
    };
    kem_record_key(ua, key_id, &rec)
}
fn corrupt<T>() -> Result<T> {
    refuse(TreeError::ReadCorrupted)
}
/// A served value that does not decode: a lying read (B-9).
fn served<T>(v: Option<T>) -> Result<T> {
    v.ok_or(Error::Tree(TreeError::ReadCorrupted))
}

/// The most epochs an exit may name below the head it is applied at (C9, the spec check sc-E-2).
pub const EXIT_LAG_MAX: u64 = 16;
/// The most exits one head keeps: each newly flags a UA with a leaf or a keyless admin (A-4).
const EXITS_MAX: u64 = TREE_LEAVES_MAX as u64 + TREE_ADMINS_MAX as u64;

/// The `gone` register of a walk: per UA its kind (1 left, 2 removed) and the epoch it was applied at.
type Gone = BTreeMap<[u8; 32], (u8, u64)>;
/// CTR-UA-74 step 6: per `msig` (a signer, or an `msig` member a signature names: C-4, R-1) the highest structure version the
/// records named so far along the walk (only versions ≥ 1 are kept: 0 is every floor's). A record names a version at or above it; the records kept under one head are judged order-free.
type Versions = BTreeMap<[u8; 32], u64>;
/// The `(msig, version)`s one record names ([`verified`]).
type Named = Vec<([u8; 32], u64)>;
/// Each `(msig, v)` a record names ([`verified`]: its signer's and each signing `msig` member's) against `floor` (the versions
/// before its slot), raised into `slot`; one below: a lying read.
fn version_up(floor: &Versions, slot: &mut Versions, named: &[([u8; 32], u64)]) -> Result<()> {
    for (ua, v) in named {
        if *v < floor.get(ua).copied().unwrap_or(0) {
            return corrupt();
        }
        if *v > 0 {
            let e = slot.entry(*ua).or_insert(*v);
            *e = (*e).max(*v);
        }
    }
    Ok(())
}

/// The checkpoint (C26, the spec check sc-F-3): the session's `treeId`, the pinned epoch, the hash of the record that won
/// there, the public tree after its commit (its no-return sets included), the `gone` register before its exits
/// (`(ua, kind, epoch)`, by UA), the exits applied at it (`(ua, kind)`, sorted) and, before its exits, each `msig`'s highest
/// structure version the records named, a signing `msig` member's too (`(ua, version)`, by UA, versions ≥ 1 only; CTR-UA-74 step 6). A walk can start from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    pub tree_id: [u8; 32],
    pub epoch: u64,
    pub hash: [u8; 32],
    pub tree: Tree,
    pub gone: Vec<([u8; 32], u8, u64)>,
    pub exits: Vec<([u8; 32], u8)>,
    pub msig_versions: Vec<([u8; 32], u64)>,
}

impl Pin {
    /// The JSON form of clientkeys' `pinAt` (the vectors' `pin`).
    pub fn to_json(&self) -> Value {
        json!({
            "treeId": hx(&self.tree_id), "epoch": self.epoch, "hash": hx(&self.hash), "tree": self.tree.to_json(),
            "gone": self.gone.iter().map(|(u, k, e)| json!([hx(u), k, e])).collect::<Vec<_>>(),
            "exits": self.exits.iter().map(|(u, k)| json!([hx(u), k])).collect::<Vec<_>>(),
            "msigVersions": self.msig_versions.iter().map(|(u, v)| json!([hx(u), v])).collect::<Vec<_>>(),
        })
    }
    /// [`Pin::to_json`]'s form back (`Argument` for anything else).
    pub fn from_json(v: &Value) -> Result<Pin> {
        let kind = |x: &Value| {
            x.as_u64()
                .and_then(|k| u8::try_from(k).ok())
                .ok_or(Error::Argument)
        };
        let at = |x: &Value, i: usize| x.get(i).ok_or(Error::Argument).cloned();
        Ok(Pin {
            tree_id: b32j(v, "treeId")?,
            epoch: u64j(v, "epoch")?,
            hash: b32j(v, "hash")?,
            tree: Tree::from_json(v.get("tree").ok_or(Error::Argument)?)?,
            gone: list(v, "gone", |x| {
                Ok((
                    b32(&at(x, 0)?)?,
                    kind(&at(x, 1)?)?,
                    at(x, 2)?.as_u64().ok_or(Error::Argument)?,
                ))
            })?,
            exits: list(v, "exits", |x| Ok((b32(&at(x, 0)?)?, kind(&at(x, 1)?)?)))?,
            msig_versions: list(v, "msigVersions", |x| {
                Ok((b32(&at(x, 0)?)?, at(x, 1)?.as_u64().ok_or(Error::Argument)?))
            })?,
        })
    }
}

/// The forward walk of §8 step 2 and §10 steps 2, 4 and 5 (C25): the session record, the snapshot, then every record from
/// the cold tree of the signed members (each key authenticated by its registry record, C-1) or from the public tree of a
/// checkpoint to the head, each checked before it is applied, with the exits kept under each epoch. Per epoch: its record,
/// admins and the commit's targets; the tree after its commit, the `gone` register before its exits and the exits applied at it
/// only at the start, the head and the epochs `keep` names (every epoch for [`tree_pins`]), so a long session never holds a
/// tree per epoch (E-3, B2-2); the ids below a pin from verified records only (C-3).
struct Walk {
    s0: Value,
    sid: [u8; 32],
    tree_id: [u8; 32],
    gctx: [u8; 32],
    leaves: Vec<Value>,
    ids: Vec<[u8; 32]>,
    head: u64,
    /// the epoch the walk starts at: 0, or the checkpoint's
    n0: u64,
    /// the ids below `n0`, each from the verified record above it (C-3)
    below: std::cell::RefCell<BTreeMap<u64, [u8; 32]>>,
    recs: BTreeMap<u64, Value>,
    trees: BTreeMap<u64, Tree>,
    admins: BTreeMap<u64, Vec<[u8; 32]>>,
    gone_at: BTreeMap<u64, Gone>,
    exits: BTreeMap<u64, Vec<([u8; 32], u8)>>,
    /// per kept epoch the `msig` versions before its exits (CTR-UA-74 step 6)
    versions_at: BTreeMap<u64, Versions>,
    targets: BTreeMap<u64, Vec<u32>>,
    /// the tree at the head after its exits
    tree: Tree,
}

fn at<T: Clone>(v: &[T], n: u64) -> Result<T> {
    usize::try_from(n)
        .ok()
        .and_then(|i| v.get(i))
        .cloned()
        .ok_or(Error::Argument)
}
/// A served leaf as `(ua, keyId, kemHash)`, a blank one all zero.
fn leaf_view(l: &Value) -> Option<([u8; 32], u64, [u8; 32])> {
    let ua = b32j(l, "ua").ok()?;
    if ua == ZERO {
        return Some((ZERO, 0, ZERO));
    }
    Some((ua, u64j(l, "keyId").ok()?, b32j(l, "kemHash").ok()?))
}
fn holds(t: &Tree, ua: &[u8; 32]) -> bool {
    (0..t.leaves).any(|i| t.leaf(i).is_some_and(|l| l.ua == *ua))
}

/// The leaves `ua` holds in `t`.
fn leaves_of(t: &Tree, ua: &[u8; 32]) -> usize {
    (0..t.leaves)
        .filter(|i| t.leaf(*i).is_some_and(|l| l.ua == *ua))
        .count()
}

impl Walk {
    /// `keep`: the epochs besides the start and the head whose tree, register and exits the walk holds (`None`: every one).
    fn new(
        sc: &TreeScope,
        rd: &mut dyn TreeReader,
        pin: Option<&Pin>,
        keep: Option<&[u64]>,
    ) -> Result<Walk> {
        let s = rd.read(View::SessionOf)?;
        let s0 = served(s.get("record").cloned())?;
        let creator = served(b32j(&s0, "creator").ok())?;
        // B-5, B2-7: the signed members and the info bounded before anything is read for them (the info as a commit's, C-5)
        let bounded = (|| {
            Some(
                s0.get("members")?.as_array()?.len() <= TREE_LEAVES_MAX as usize
                    && (1..=TREE_INFO_MAX).contains(&bytes(s0.get("sealedInfo")?).ok()?.len())
                    && u32j(&s0, "pathRefreshBound").ok()? <= PATH_REFRESH_BOUND_MAX
                    && b32j(&s0, "confirmTag").is_ok(),
            )
        })();
        if bounded != Some(true) {
            return corrupt();
        }
        let v0 = verified(
            sc,
            &*rd,
            "PqChatSession",
            &s0,
            &creator,
            served(s.get("sig"))?,
        )?;
        if u64j(&s0, "groupMode")? != 1 {
            return refuse(TreeError::ModeEntry);
        }
        let t = rd.read(View::TreeOf)?;
        let leaves = served(rd.read(View::TreeLeaves)?.as_array().cloned())?;
        let nodes = served(rd.read(View::TreeNodes)?.as_array().cloned())?;
        let ids = served(
            rd.read(View::EpochsOf)?
                .as_array()
                .and_then(|a| a.iter().map(|x| b32(x).ok()).collect::<Option<Vec<_>>>()),
        )?;
        let sid = sc.session_id(&creator, u64j(&s0, "nonce")?);
        if ids.first() != Some(&sid) {
            return corrupt();
        }
        let head = ids.len() as u64 - 1;
        let mut w = Walk {
            sid,
            tree_id: tree_id(sc.typed, &s0)?,
            gctx: genesis_ctx(sc.typed, &s0)?,
            recs: BTreeMap::from([(0, s0.clone())]),
            s0,
            leaves,
            ids,
            head,
            n0: pin.map_or(0, |p| p.epoch),
            below: Default::default(),
            trees: BTreeMap::new(),
            admins: BTreeMap::new(),
            gone_at: BTreeMap::new(),
            exits: BTreeMap::new(),
            versions_at: BTreeMap::new(),
            targets: BTreeMap::new(),
            tree: Tree::default(),
        };
        let (n0, mut tree, mut gone, mut versions) = match pin {
            Some(p) => {
                if p.tree_id != w.tree_id || head < p.epoch {
                    return refuse(TreeError::Checkpoint);
                }
                if p.epoch > 0 {
                    let (c, _) = w.commit_at(sc, rd, p.epoch)?;
                    w.recs.insert(p.epoch, c);
                }
                if w.record_hash(sc, p.epoch)? != p.hash {
                    return refuse(TreeError::Conflict);
                }
                let g: Gone = p.gone.iter().map(|(u, k, e)| (*u, (*k, *e))).collect();
                // CTR-UA-74 step 6: never below the versions the pin saw
                let v: Versions = p.msig_versions.iter().copied().collect();
                (p.epoch, p.tree.clone(), g, v)
            }
            None => {
                let mut v = Versions::new();
                version_up(&Versions::new(), &mut v, &v0)?;
                (0, w.cold(rd)?, Gone::new(), v)
            }
        };
        let mut n = n0;
        loop {
            if n > n0 {
                let (c, v) = w.commit_at(sc, rd, n)?;
                version_up(&versions.clone(), &mut versions, &v)?;
                let (next, targets) = w.apply(sc, &tree, &c, n)?;
                tree = next;
                for ua in &tree.gone_ua {
                    gone.entry(*ua).or_insert((2, n));
                }
                w.recs.insert(n, c);
                w.targets.insert(n, targets);
            }
            let admins = list(w.rec(n)?, "admins", b32)?;
            let kept = n == n0 || n == head || keep.is_none_or(|k| k.contains(&n));
            if kept {
                w.trees.insert(n, tree.clone());
                w.gone_at.insert(n, gone.clone());
                w.versions_at.insert(n, versions.clone());
            }
            w.admins.insert(n, admins);
            let ex = w.exits_at(sc, rd, n, &tree, &gone, &mut versions)?;
            if pin.is_some_and(|p| n == n0 && !p.exits.iter().all(|e| ex.contains(e))) {
                return corrupt();
            }
            for (ua, kind) in &ex {
                gone.entry(*ua).or_insert((*kind, n));
            }
            tree.mark_gone(&ex.iter().map(|x| x.0).collect::<Vec<_>>());
            if kept {
                w.exits.insert(n, ex);
            }
            if n == head {
                break;
            }
            n += 1;
        }
        w.tree = tree;
        if !w
            .snapshot_agrees(&t, &nodes, pin.is_none())
            .unwrap_or(false)
        {
            return refuse(if head == 0 {
                TreeError::GenesisLeaves
            } else {
                TreeError::HeadRoot
            });
        }
        Ok(w)
    }

    /// The cold tree rebuilt from the signed member list (codex-r2-1), each key authenticated by its registry record
    /// ([`kem_at`], C-1); a list the contract refuses (one key at two leaves): a lying read.
    fn cold(&self, rd: &mut dyn TreeReader) -> Result<Tree> {
        let members = served(
            list(&self.s0, "members", |m| {
                Ok((b32j(m, "ua")?, u64j(m, "keyId")?))
            })
            .ok(),
        )?;
        let mut leaves = Vec::new();
        for (ua, key_id) in members {
            let k = kem_at(rd, &ua, key_id)?;
            leaves.push(Leaf {
                ua,
                key_id,
                kem_hash: keccak256(&k),
            });
        }
        Tree::cold_with(&leaves, u32j(&self.s0, "pathRefreshBound")?)
            .map_err(|_| Error::Tree(TreeError::ReadCorrupted))
    }

    /// The record at number `n` whose id is `id` (a verified record's `parentEpochId`): its id recomputed, its number, session
    /// and signature (C-3, below a checkpoint).
    fn record_below(
        &self,
        sc: &TreeScope,
        rd: &mut dyn TreeReader,
        n: u64,
        id: [u8; 32],
    ) -> Result<Value> {
        let v = rd.read(View::CommitOf(n))?;
        let c = served(v.get("record").cloned())?;
        let ok = (|| {
            Some(
                u64j(&c, "epoch").ok()? == n
                    && b32j(&c, "sessionId").ok()? == self.sid
                    && sc.epoch_id(
                        &self.sid,
                        &b32j(&c, "author").ok()?,
                        u64j(&c, "nonce").ok()?,
                    ) == id,
            )
        })();
        if ok != Some(true) {
            return corrupt();
        }
        verified(
            sc,
            &*rd,
            "PqChatCommit",
            &c,
            &b32j(&c, "author")?,
            served(v.get("sig"))?,
        )?;
        Ok(c)
    }

    /// The id at number `m` from verified data only (C-3): epoch 0's is the session's; at or above the walk's start the id
    /// list its records were checked against; below a checkpoint each record's `parentEpochId` down from the pinned record,
    /// every one read and checked.
    fn id_at(&self, sc: &TreeScope, rd: &mut dyn TreeReader, m: u64) -> Result<[u8; 32]> {
        if m == 0 {
            return Ok(self.sid);
        }
        if m >= self.n0 {
            return at(&self.ids, m);
        }
        let mut k = self.n0;
        while k > m {
            let known = self.below.borrow().contains_key(&(k - 1));
            if !known {
                let above = if k == self.n0 {
                    self.rec(k)?.clone()
                } else {
                    let id = self
                        .below
                        .borrow()
                        .get(&k)
                        .copied()
                        .ok_or(Error::Argument)?;
                    self.record_below(sc, rd, k, id)?
                };
                let parent = b32j(&above, "parentEpochId")?;
                self.below.borrow_mut().insert(k - 1, parent);
            }
            k -= 1;
        }
        self.below.borrow().get(&m).copied().ok_or(Error::Argument)
    }

    /// The number an exit `r` names: of the session, `h` or an ancestor within [`EXIT_LAG_MAX`], by verified ids (C-3).
    fn named(&self, sc: &TreeScope, rd: &mut dyn TreeReader, h: u64, r: &Value) -> Result<u64> {
        let (sid, id) = served((|| {
            Some((b32j(r, "sessionId").ok()?, b32j(r, "epochId").ok()?))
        })())?;
        if sid != self.sid {
            return corrupt();
        }
        for m in (h.saturating_sub(EXIT_LAG_MAX)..=h).rev() {
            if self.id_at(sc, rd, m)? == id {
                return Ok(m);
            }
        }
        corrupt()
    }

    /// Commit `n`'s record: its id at its number, `sessionId`, `treeId`, the bounds of C10 and C24 before anything is
    /// allocated (sc-F-7, B-5), then its author's signature; and the `(msig, version)`s it names ([`verified`]).
    fn commit_at(&self, sc: &TreeScope, rd: &mut dyn TreeReader, n: u64) -> Result<(Value, Named)> {
        let v = rd.read(View::CommitOf(n))?;
        let c = served(v.get("record").cloned())?;
        let ok = (|| -> Option<bool> {
            let author = b32j(&c, "author").ok()?;
            let leaves = u64j(&c, "leaves").ok()?;
            let len = |k: &str| c.get(k).and_then(Value::as_array).map(Vec::len);
            let below = |x: &Value| u64j(x, "leaf").is_ok_and(|l| l < leaves);
            let changes = c.get("removes")?.as_array()?.iter();
            Some(
                u64j(&c, "epoch").ok()? == n
                    && b32j(&c, "sessionId").ok()? == self.sid
                    && sc.epoch_id(&self.sid, &author, u64j(&c, "nonce").ok()?)
                        == at(&self.ids, n).ok()?
                    && b32j(&c, "treeId").ok()? == self.tree_id
                    && leaves.is_power_of_two()
                    && leaves <= u64::from(TREE_LEAVES_MAX)
                    && u64j(&c, "leaf").ok()? < leaves
                    && len("removes")? + len("adds")? <= TREE_CHANGES_MAX
                    && len("admins")? <= TREE_ADMINS_MAX
                    && len("nodeKeyHashes")? as u32 <= leaves.trailing_zeros()
                    && len("wrapHashes")? == len("adds")?
                    && u64j(&c, "ctCount").ok()? < leaves
                    && (1..=TREE_INFO_MAX).contains(&bytes(c.get("sealedInfo")?).ok()?.len())
                    && c.get("pathless")?.is_boolean()
                    && b32j(&c, "confirmTag").is_ok()
                    && changes.chain(c.get("adds")?.as_array()?).all(below),
            )
        })()
        .unwrap_or(false);
        if !ok {
            return corrupt();
        }
        let author = b32j(&c, "author")?;
        let version = verified(sc, &*rd, "PqChatCommit", &c, &author, served(v.get("sig"))?)?;
        Ok((c, version))
    }

    /// Commit `n` on the tree built so far: its parent's id and tree, then every acceptance check of §8 on the record and the
    /// walk's state ([`Tree::apply_commit`], [`Tree::judge_commit`]), its size, `treeHash`, `ctCount` and the empty list's
    /// hash. Anything that fails: a lying read. Returns the tree after it and its targets.
    fn apply(&self, sc: &TreeScope, tree: &Tree, c: &Value, n: u64) -> Result<(Tree, Vec<u32>)> {
        let lie = |e: Error| match e {
            Error::Tree(_) | Error::Argument => Error::Tree(TreeError::ReadCorrupted),
            x => x,
        };
        if b32j(c, "parentEpochId")? != at(&self.ids, n - 1)?
            || b32j(c, "parentTreeHash")? != tree.tree_hash()
        {
            return corrupt();
        }
        let ch = Changes::from_json(c).map_err(lie)?;
        let nkh = list(c, "nodeKeyHashes", b32).map_err(lie)?;
        let applied = tree.apply_commit(&ch, &nkh).map_err(lie)?;
        let admins = list(c, "admins", b32).map_err(lie)?;
        let head_admins = self.admins.get(&(n - 1)).ok_or(Error::Argument)?;
        tree.judge_commit(&applied.tree, &ch, &admins, head_admins)
            .map_err(lie)?;
        let ct_count = u64j(c, "ctCount")?;
        if u64::from(applied.tree.leaves) != u64j(c, "leaves")?
            || applied.tree_hash != b32j(c, "treeHash")?
            || applied.ct_targets.len() as u64 != ct_count
            || (ct_count == 0 && b32j(c, "ctListHash")? != path_list_hash(sc.typed, &[], &[])?)
        {
            return corrupt();
        }
        Ok((applied.tree, applied.ct_targets))
    }

    /// §10 step 5: the exits kept under epoch `h`, each one an exit applied at `h` exactly when the contract could have
    /// accepted it there, judged order-free among those kept under `h` (on `tree`, `h`'s admins and the `gone` register
    /// before them): its signature for its signer's kind and the pinned `treeId`; an epoch named `h` or an ancestor within
    /// [`EXIT_LAG_MAX`], numbered from verified data ([`Walk::named`], C-3); a leave by a UA live at `h`; a removal by an admin
    /// of `h`, of UAs live at `h` or in its admins, strictly sorted, `nextEpoch` the named number plus one; nobody gone before
    /// `h`. Together (B2-6): no UA exits twice under one head (A-4), the leaves they owe fit one commit (C21), and the last
    /// admin with a leaf goes by a removal only when no member keeps a leaf (C24 read with C38). Each signer's structure version
    /// at or above `versions` before them (CTR-UA-74 step 6), which they raise.
    fn exits_at(
        &self,
        sc: &TreeScope,
        rd: &mut dyn TreeReader,
        h: u64,
        tree: &Tree,
        gone: &Gone,
        versions: &mut Versions,
    ) -> Result<Vec<([u8; 32], u8)>> {
        let floor = versions.clone();
        let before = |ua: &[u8; 32]| gone.get(ua).is_some_and(|g| g.1 < h);
        let admins = self.admins.get(&h).ok_or(Error::Argument)?;
        let count = |v: Value| served(v.as_u64().filter(|k| *k <= EXITS_MAX));
        let mut out = Vec::new();
        for i in 0..count(rd.read(View::LeaveCount(h))?)? {
            let v = rd.read(View::LeaveAt(h, i as usize))?;
            let r0 = served(v.get("record"))?;
            let (r, member) = served((|| {
                let member = b32j(r0, "member").ok()?;
                let r = json!({"sessionId": r0.get("sessionId")?, "treeId": hx(&self.tree_id),
                    "epochId": r0.get("epochId")?, "member": hx(&member), "nonce": r0.get("nonce")?.as_u64()?});
                Some((r, member))
            })())?;
            self.named(sc, rd, h, &r)?;
            if !holds(tree, &member) || before(&member) {
                return corrupt();
            }
            let ver = verified(
                sc,
                &*rd,
                "PqChatTreeLeave",
                &r,
                &member,
                served(v.get("sig"))?,
            )?;
            version_up(&floor, versions, &ver)?;
            out.push((member, 1));
        }
        for i in 0..count(rd.read(View::RemovalCount(h))?)? {
            let v = rd.read(View::RemovalAt(h, i as usize))?;
            let r0 = served(v.get("record"))?;
            let (r, admin, members, next) = served((|| {
                let admin = b32j(r0, "admin").ok()?;
                let members = list(r0, "members", b32).ok()?;
                let next = r0.get("nextEpoch")?.as_u64()?;
                let r = json!({"sessionId": r0.get("sessionId")?, "treeId": hx(&self.tree_id),
                    "epochId": r0.get("epochId")?, "nextEpoch": next,
                    "members": members.iter().map(|m| hx(m)).collect::<Vec<_>>(), "admin": hx(&admin),
                    "nonce": r0.get("nonce")?.as_u64()?});
                Some((r, admin, members, next))
            })())?;
            let n = self.named(sc, rd, h, &r)?;
            let ok = next == n + 1
                && !members.is_empty()
                && members.windows(2).all(|x| x.first() < x.get(1))
                && admins.contains(&admin)
                && !before(&admin)
                && members
                    .iter()
                    .all(|m| (holds(tree, m) || admins.contains(m)) && !before(m));
            if !ok {
                return corrupt();
            }
            let ver = verified(
                sc,
                &*rd,
                "PqChatTreeRemove",
                &r,
                &admin,
                served(v.get("sig"))?,
            )?;
            version_up(&floor, versions, &ver)?;
            out.extend(members.into_iter().map(|m| (m, 2)));
        }
        let goes: BTreeSet<[u8; 32]> = out.iter().map(|x| x.0).collect();
        let leafy = |u: &[u8; 32]| admins.contains(u) && holds(tree, u);
        let stays = |u: &[u8; 32]| !goes.contains(u) && !before(u);
        let member_stays = (0..tree.leaves).any(|i| tree.leaf(i).is_some_and(|l| stays(&l.ua)));
        let owed: usize = out.iter().map(|(u, _)| leaves_of(tree, u)).sum();
        if goes.len() != out.len()
            || owed > TREE_CHANGES_MAX
            || (admins.iter().any(leafy)
                && !admins.iter().any(|u| leafy(u) && stays(u))
                && member_stays
                && !out.iter().any(|(u, k)| *k == 1 && leafy(u)))
        {
            return corrupt();
        }
        Ok(out)
    }

    /// The served snapshot against the walk's tree at the head (a list of `used` leaves or of every position; E-4), and
    /// `treeOf.owed` against the leaves the head's exits the walk read owe (R2-D-1 of the T4-T9 re-check: an endpoint that
    /// serves the true `treeOf` and hides an exit record is a lying read, so a strict-majority `treeOf` covers the exits).
    fn snapshot_agrees(&self, t: &Value, nodes: &[Value], cold: bool) -> Option<bool> {
        let w = self.trees.get(&self.head)?;
        let owed: usize = self
            .exits
            .get(&self.head)?
            .iter()
            .map(|(u, _)| leaves_of(w, u))
            .sum();
        let leaf = |i: usize| {
            u32::try_from(i).ok().map(|i| {
                w.leaf(i)
                    .map_or((ZERO, 0, ZERO), |l| (l.ua, l.key_id, l.kem_hash))
            })
        };
        let n = self.leaves.len();
        Some(
            b32j(t, "treeId").ok()? == self.tree_id
                && u32j(t, "leaves").ok()? == w.leaves
                && u32j(t, "used").ok()? == w.used
                && u32j(t, "sincePath").ok()? == w.since_path
                && b32j(t, "treeHash").ok()? == w.tree_hash()
                && u64j(t, "owed").ok()? == owed as u64
                && (!cold || b32j(t, "genesisTreeHash").ok()? == self.trees.get(&0)?.tree_hash())
                && n >= w.used as usize
                && n <= w.leaves as usize
                && self
                    .leaves
                    .iter()
                    .enumerate()
                    .all(|(i, l)| leaf_view(l).is_some() && leaf_view(l) == leaf(i))
                && nodes.len() == super::tree_public::node_width(w.leaves) as usize
                && nodes.iter().enumerate().all(|(x, nd)| {
                    x % 2 == 0
                        || b32j(nd, "keyHash").ok()
                            == Some(match w.node(x as u32) {
                                Node::Parent(k) => *k,
                                _ => ZERO,
                            })
                }),
        )
    }

    fn rec(&self, n: u64) -> Result<&Value> {
        self.recs.get(&n).ok_or(Error::Argument)
    }
    fn record_hash(&self, sc: &TreeScope, n: u64) -> Result<[u8; 32]> {
        if n == 0 {
            return struct_hash(sc.typed, "PqChatSession", &self.s0);
        }
        struct_hash(sc.typed, "PqChatCommit", self.rec(n)?)
    }
    /// The checkpoint at epoch `n` of this walk.
    fn pin_at(&self, sc: &TreeScope, n: u64) -> Result<Pin> {
        let mut exits = self.exits.get(&n).cloned().ok_or(Error::Argument)?;
        exits.sort();
        Ok(Pin {
            tree_id: self.tree_id,
            epoch: n,
            hash: self.record_hash(sc, n)?,
            tree: self.trees.get(&n).cloned().ok_or(Error::Argument)?,
            gone: self
                .gone_at
                .get(&n)
                .ok_or(Error::Argument)?
                .iter()
                .map(|(u, (k, e))| (*u, *k, *e))
                .collect(),
            exits,
            msig_versions: self
                .versions_at
                .get(&n)
                .ok_or(Error::Argument)?
                .iter()
                .map(|(u, v)| (*u, *v))
                .collect(),
        })
    }
    /// A walk from the cold tree against the device's checkpoint: never below it, the record that won there the pinned one
    /// (`TreeConflict`: the majority read of C26), and the walk at that number holds the pinned tree, register and every
    /// pinned exit (fewer is a lying read, sc-F-3).
    fn check_pin(&self, sc: &TreeScope, store: Option<&Pin>) -> Result<()> {
        let Some(s) = store else { return Ok(()) };
        if s.tree_id != self.tree_id || self.head < s.epoch {
            return refuse(TreeError::Checkpoint);
        }
        let p = self.pin_at(sc, s.epoch)?;
        if p.hash != s.hash {
            return refuse(TreeError::Conflict);
        }
        if p.tree != s.tree
            || p.gone != s.gone
            || p.msig_versions != s.msig_versions
            || !s.exits.iter().all(|e| p.exits.contains(e))
        {
            return corrupt();
        }
        Ok(())
    }
    fn admins_at(&self, n: u64) -> Result<Vec<[u8; 32]>> {
        self.admins.get(&n).cloned().ok_or(Error::Argument)
    }
}

/// The public tree a commit is built on (§8 steps 1 to 3, C25, C26): the tree the forward walk reached at the head (from the
/// checkpoint, or from the cold tree of the signed members; at an epoch-0 head the cold tree itself, B-1), its no-return sets
/// and the exits of the head included, and the parent's id, number, tree hash and admins; the pin of the head. Made only by
/// [`tree_prepare`] (B2-9): its fields are read, never set, outside this module.
pub struct Prepared {
    tree: Tree,
    parent_epoch_id: [u8; 32],
    parent_epoch: u64,
    parent_tree_hash: [u8; 32],
    parent_admins: Vec<[u8; 32]>,
    pin: Pin,
}

impl Prepared {
    pub fn tree(&self) -> &Tree {
        &self.tree
    }
    pub fn parent_epoch_id(&self) -> [u8; 32] {
        self.parent_epoch_id
    }
    pub fn parent_epoch(&self) -> u64 {
        self.parent_epoch
    }
    pub fn parent_tree_hash(&self) -> [u8; 32] {
        self.parent_tree_hash
    }
    pub fn parent_admins(&self) -> &[[u8; 32]] {
        &self.parent_admins
    }
    pub fn pin(&self) -> &Pin {
        &self.pin
    }
}

/// [`Prepared`] from the views, by the forward walk from `store` (its tree and exits) or from the cold tree; never a served
/// snapshot. A record that fails the walk: `TreeReadCorrupted`.
pub fn tree_prepare(
    sc: &TreeScope,
    rd: &mut dyn TreeReader,
    store: Option<&Pin>,
) -> Result<Prepared> {
    let w = Walk::new(sc, rd, store, Some(&[]))?;
    Ok(Prepared {
        parent_epoch_id: at(&w.ids, w.head)?,
        parent_epoch: w.head,
        parent_tree_hash: w.tree.tree_hash(),
        parent_admins: w.admins_at(w.head)?,
        pin: w.pin_at(sc, w.head)?,
        tree: w.tree,
    })
}

/// The checkpoint of every epoch of the walk from the cold tree (a test's comparison: a walk from any of them reaches the
/// same head; clientkeys `pinsOf`).
pub fn tree_pins(sc: &TreeScope, rd: &mut dyn TreeReader) -> Result<Vec<Pin>> {
    let w = Walk::new(sc, rd, None, None)?;
    (0..=w.head).map(|n| w.pin_at(sc, n)).collect()
}

/// The epochs whose public tree the walk from `pin` (or from the cold tree) holds when it is done: its start and the head
/// (E-3, B2-2: never a tree per epoch). A test's measure (feature `vectors`).
#[cfg(feature = "vectors")]
pub fn tree_walk_trees(
    sc: &TreeScope,
    rd: &mut dyn TreeReader,
    pin: Option<&Pin>,
) -> Result<Vec<u64>> {
    Ok(Walk::new(sc, rd, pin, Some(&[]))?
        .trees
        .keys()
        .copied()
        .collect())
}

/// The key of target `x` of `tree`, fetched and checked against the hash that entered the root (`TreeKeyHash`, codex-1): a
/// leaf's from the registry, a node's from the home.
pub fn key_of(rd: &mut dyn TreeReader, tree: &Tree, x: u32) -> Result<Vec<u8>> {
    let (k, want) = match tree.node(x) {
        Node::Leaf(l) => {
            let v = rd.read(View::KemKeyAt(&l.ua, l.key_id))?;
            (served(v.get("kemPk").cloned())?, l.kem_hash)
        }
        Node::Parent(kh) => (rd.read(View::TreeNodeKey(x))?, *kh),
        Node::Blank => return refuse(TreeError::KeyHash),
    };
    // B-9: a served key that does not decode is a lying read
    let k = served(bytes(&k).ok())?;
    if keccak256(&k) != want {
        return refuse(TreeError::KeyHash);
    }
    Ok(k)
}

// ------------------------------------------------------------------ replay (§10)

/// A device's leaf key: its UA, the key's version and the KEM key (its seed reproduces the device's own commits).
pub struct TreeDevice<'a> {
    pub ua: [u8; 32],
    pub key_id: u64,
    pub kem: &'a KemKeyPair,
}

/// An epoch's state for a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Followed,
    /// with the reason: "opening failed", "list", "wrong target", "target not held", "node key mismatch", "welcome disagrees",
    /// "tag" (the derived confirmation is not the signed one: claude-21, F-7), "parent not followed", "welcome may not match"
    /// (a path-less joiner in its first run, F-1); a commit without its author's right is a lying read (C25), never this
    NotFollowed(&'static str),
    /// its own `(ua, keyId)` committed what its seed does not reproduce (R10, fable-r2-1; a path-less record by its nonce, C47)
    Compromise,
    /// C45 (the path-less delta §6.2): a path-less epoch whose tag fails at a device anchored in its run; the device keeps the
    /// chain's key, takes no info, and the epoch's added leaves are under review
    AuthorDidNotHold,
}

/// What a followed epoch's `sealedInfo` did to the info in force (C33); `NotTaken`: a good tag with a `sealedInfo` that does
/// not open (F-8), no info in force from that epoch on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InfoTook {
    Full,
    Changed,
    Ignored,
    Marker,
    NotTaken,
}

/// One epoch of the device's secret range. No `next` here: only the head's handle holds it ([`Replay::head`]).
pub struct EpochRow {
    pub epoch: u64,
    pub epoch_id: [u8; 32],
    /// its record's author (epoch 0: the creator) and the admins after it (R2-C-3 of the T4-T9 re-check: the room's sync)
    pub author: [u8; 32],
    pub admins: Vec<[u8; 32]>,
    pub state: State,
    pub k: Option<KeyHandle>,
    pub info: Option<InfoTook>,
    pub in_force: Option<String>,
    pub flagged: bool,
}

/// The compromise warning of a commit (R10, codex-r3-3, fable-r3-5): what it added and removed, whether it changed the
/// admins, and which of its added leaves are still in the tree at the head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    pub epoch: u64,
    pub adds: Vec<(u32, [u8; 32], u64)>,
    pub removes: Vec<Remove>,
    pub admins_changed: bool,
    pub leaves_left: Vec<u32>,
}

/// A C45 state (the path-less delta §6.2), shown to every member: the epoch, its author, the leaves it added and which of
/// them are still in the tree at the head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suspect {
    pub epoch: u64,
    pub author: [u8; 32],
    pub adds: Vec<(u32, [u8; 32], u64)>,
    pub leaves_left: Vec<u32>,
}

/// A roster entry: `(ua, keyId)` of a leaf, `None` blank.
pub type Roster = Vec<Option<([u8; 32], u64)>>;

/// A replay's result.
pub struct Replay {
    pub leaf: u32,
    pub join_epoch: u64,
    pub end_epoch: Option<u64>,
    /// by epoch, the epochs of the secret range: the forward walk's leaves (§10 step 4, C25; E-3: never the whole history)
    pub rosters: BTreeMap<u64, Roster>,
    pub epochs: Vec<EpochRow>,
    pub warnings: Vec<Warning>,
    /// the C45 states (the path-less delta §6.2)
    pub suspects: Vec<Suspect>,
    /// the leaves under review (F-3): every still-live leaf a warning or a C45 state names, ascending
    pub review: Vec<u32>,
    /// the walk's `sincePath` at the head and whether this device is warned (R18, C46: an admin at `sincePath ≥ W(N)`)
    pub since_path: u32,
    pub path_warning: bool,
    /// the node keys the device holds after the range (its leaf's key is its own, not here)
    pub held: BTreeMap<u32, KemKeyPair>,
    /// the head's handle with its `next` (the path-less delta §4.1), when the device holds the head's epoch; whether it is
    /// anchored in the run
    pub head: Option<TreeHead>,
    pub anchored: bool,
    pub pin: Pin,
    /// the info in force after the range and its flag (C33), and whether the device followed the head: kept by a resume
    /// that finds no new epoch (C-4 of the T4-T9 review)
    pub in_force: Option<String>,
    pub flagged: bool,
    pub head_followed: bool,
    /// a resume's: the nodes its commits replaced, until [`Replay::adopt`] moves the rest of `from`'s node keys in
    replaced: Option<BTreeSet<u32>>,
    /// its node keys moved into a later replay: a resume from it is refused (`TreePeriod`, R2-C-2 of the T4-T9 re-check)
    consumed: bool,
}

impl Replay {
    /// A resume's replay takes `from`'s node keys it keeps on (all but the nodes its commits replaced) once the caller keeps
    /// it (D-5, U-a of the T4-T9 re-check: after the caller's last step that can fail, so a refusal, a missed read or a
    /// failed store write leaves `from` whole); `from` is consumed. Nothing for a replay that was not resumed.
    pub fn adopt(&mut self, from: &mut Replay) {
        if let Some(replaced) = self.replaced.take() {
            let mut held = std::mem::take(&mut from.held);
            held.retain(|x, _| !replaced.contains(x));
            held.append(&mut self.held);
            self.held = held;
            from.consumed = true;
        }
    }

    /// The info a device seals in a commit of its own (C33): the full info in force only when it followed the head and
    /// holds one not flagged; otherwise the marker (`None`). A changed info is the admin's own action, never this.
    pub fn info_to_seal(&self) -> Option<&str> {
        (self.head_followed && !self.flagged)
            .then_some(self.in_force.as_deref())
            .flatten()
    }
}

struct Piece {
    n: u64,
    own: bool,
    j: Option<usize>,
    targets: Vec<u32>,
    ct: Option<PathCt>,
    wrap: Option<Value>,
}

/// The chain a device holds into the next epoch: the epoch's `next` and whether it is anchored in the run (C45).
struct Chain {
    next: Secret,
    anchored: bool,
}

struct Opened {
    state: State,
    k: Option<Secret>,
    info: Option<Info>,
    derived: Vec<(u32, KemKeyPair)>,
    chain: Option<Chain>,
}
fn not(reason: &'static str) -> Opened {
    Opened {
        state: State::NotFollowed(reason),
        k: None,
        info: None,
        derived: Vec::new(),
        chain: None,
    }
}
fn compromise() -> Opened {
    Opened {
        state: State::Compromise,
        ..not("")
    }
}
/// The tag decides the key state, `sealedInfo` only the info (C12 as amended, F-8): followed, `info` `None` when it does
/// not open ("followed, info not taken").
fn taken(sc: &TreeScope, a: &Walk, epoch_id: &[u8; 32], sealed: &[u8], sch: Sched, anchored: bool) -> Opened {
    Opened {
        state: State::Followed,
        info: open_info(sc, &sch.k[..], &a.sid, epoch_id, sealed),
        k: Some(sch.k),
        derived: Vec::new(),
        chain: Some(Chain {
            next: sch.next,
            anchored,
        }),
    }
}

impl AppKeys {
    /// A device's replay of a tree session from the home's state alone (§10): the forward walk from the cold tree (C25), the
    /// checkpoint compared with it (C26), the key's one period, the secret range's pieces all read before anything is opened
    /// (C22), then per epoch its state, `K` (a handle for each epoch from `keys_from` on, so a long session never fills the
    /// arena, B-3), the info in force (C33), the compromise warnings, the C45 states and the next pin. `Ok(None)`: the key is
    /// in no period of this session. Refusals by name (`TreeError`); a record or piece that fails a signed hash, a signature or
    /// the walk: `TreeReadCorrupted`, before any decapsulation.
    pub fn tree_replay(
        &self,
        sc: &TreeScope,
        rd: &mut dyn TreeReader,
        dev: &TreeDevice,
        store: Option<&Pin>,
        keys_from: u64,
    ) -> Result<Option<Replay>> {
        self.replay(sc, rd, dev, store, None, keys_from)
    }

    /// [`AppKeys::tree_replay`] resumed from the device's previous replay `from` (spec §10 step 3, E-3, B2-2): the walk starts at
    /// its pin, and only the epochs after it are read and opened, with the node keys it held, its head's `next` and the info in force there, so
    /// the device pays the history once. `from` a replay whose key is still in the tree and that no resume consumed
    /// (`TreePeriod` else). C-6: every read comes before the secrets (C22), so a refusal, a failed or a lying read leaves
    /// `from` as it was (its node keys and pin); on success its node keys move into the new replay, which replaces it.
    pub fn tree_resume(
        &self,
        sc: &TreeScope,
        rd: &mut dyn TreeReader,
        dev: &TreeDevice,
        from: &mut Replay,
        keys_from: u64,
    ) -> Result<Option<Replay>> {
        let r = self.tree_resume_kept(sc, rd, dev, from, None, keys_from)?;
        Ok(r.map(|mut r| {
            r.adopt(from);
            r
        }))
    }

    /// [`AppKeys::tree_resume`] with `from` left whole: the caller moves its node keys in by [`Replay::adopt`] once it keeps
    /// the new replay (its pin stored), so nothing it drops has consumed `from`. `store`, the device's checkpoint: a `from`
    /// whose pin is below it is refused (`TreeCheckpoint`, R2-C-2 of the T4-T9 re-check: a resume never lowers it).
    pub fn tree_resume_kept(
        &self,
        sc: &TreeScope,
        rd: &mut dyn TreeReader,
        dev: &TreeDevice,
        from: &Replay,
        store: Option<&Pin>,
        keys_from: u64,
    ) -> Result<Option<Replay>> {
        if store.is_some_and(|p| from.pin.epoch < p.epoch) {
            return refuse(TreeError::Checkpoint);
        }
        self.replay(sc, rd, dev, None, Some(from), keys_from)
    }

    fn replay(
        &self,
        sc: &TreeScope,
        rd: &mut dyn TreeReader,
        dev: &TreeDevice,
        store: Option<&Pin>,
        from: Option<&Replay>,
        keys_from: u64,
    ) -> Result<Option<Replay>> {
        if from.is_some_and(|f| f.consumed) {
            return refuse(TreeError::Period);
        }
        let kem_hash = keccak256(&dev.kem.kem_pk());
        let a = match &from {
            Some(f) => Walk::new(sc, rd, Some(&f.pin), Some(&[]))?,
            None => {
                let keep: Vec<u64> = store.map(|p| p.epoch).into_iter().collect();
                let a = Walk::new(sc, rd, None, Some(&keep))?;
                a.check_pin(sc, store)?;
                a
            }
        };
        let (head, n0) = (a.head, a.n0);
        let mine_at = |t: &Tree, l: u32| {
            t.leaf(l)
                .is_some_and(|x| x.ua == dev.ua && x.key_id == dev.key_id && x.kem_hash == kem_hash)
        };
        let (leaf, join_epoch, end_epoch, wrap_index) = match &from {
            Some(f) => {
                // the period resumed: the pinned tree holds the device's leaf; its Remove, if any, a record of this walk
                let t0 = a.trees.get(&n0).ok_or(Error::Argument)?;
                if f.end_epoch.is_some() || !mine_at(t0, f.leaf) {
                    return refuse(TreeError::Period);
                }
                let mut end = None;
                for n in n0 + 1..=head {
                    let removes = list(a.rec(n)?, "removes", Remove::from_json)?;
                    if removes
                        .iter()
                        .any(|r| r.leaf == f.leaf && r.ua == dev.ua && r.key_id == dev.key_id)
                    {
                        end = Some(n);
                        break;
                    }
                }
                (f.leaf, f.join_epoch, end, None)
            }
            None => {
                let (leaf, join_epoch, end_epoch, wrap_index) =
                    self.period(&a, rd, sc, dev, &kem_hash)?;
                let Some(leaf) = leaf else { return Ok(None) };
                (leaf, join_epoch, end_epoch, Some(wrap_index))
            }
        };
        let last = end_epoch.map_or(head, |e| e - 1);
        let first = if from.is_some() { n0 + 1 } else { join_epoch };
        // 4. the rosters of the secret range: the walk's leaves, from its first tree through each record's Removes and Adds
        let mut rosters: BTreeMap<u64, Roster> = BTreeMap::new();
        {
            let t0 = a.trees.get(&n0).ok_or(Error::Argument)?;
            let mut ros: Roster = (0..t0.leaves)
                .map(|i| t0.leaf(i).map(|l| (l.ua, l.key_id)))
                .collect();
            if first <= n0 {
                rosters.insert(n0, ros.clone());
            }
            for n in n0 + 1..=last {
                let c = a.rec(n)?;
                for r in list(c, "removes", Remove::from_json)? {
                    if let Some(x) = ros.get_mut(r.leaf as usize) {
                        *x = None;
                    }
                }
                ros.resize(u32j(c, "leaves")? as usize, None);
                for x in list(c, "adds", Add::from_json)? {
                    if let Some(y) = ros.get_mut(x.leaf as usize) {
                        *y = Some((x.ua, x.key_id));
                    }
                }
                if n >= first {
                    rosters.insert(n, ros.clone());
                }
            }
        }
        // 6. the secret range's pieces, by public data only, all read before anything is opened (C22); a record whose
        // `ctCount` is 0 (a path-less Add, the last live leaf's commit) has no list: the record and, at the join, the wrap
        let mut plan: Vec<Piece> = Vec::new();
        for n in first..=last {
            if n == 0 {
                let wrap = rd.read(View::WrapAt(0, leaf as usize))?;
                let want = list(&a.s0, "wrapHashes", b32)?;
                // B-9: a wrap that does not decode is a lying read
                if Some(served(wrap_hash(sc, &wrap).ok())?) != want.get(leaf as usize).copied() {
                    return corrupt();
                }
                plan.push(Piece {
                    n,
                    own: false,
                    j: None,
                    targets: Vec::new(),
                    ct: None,
                    wrap: Some(wrap),
                });
                continue;
            }
            let c = a.rec(n)?.clone();
            let own = b32j(&c, "author")? == dev.ua
                && u64j(&c, "keyId")? == dev.key_id
                && u32j(&c, "leaf")? == leaf;
            let (targets, hashes) = if u64j(&c, "ctCount")? == 0 {
                (Vec::new(), Vec::new())
            } else {
                let l = rd.read(View::PathListOf(n))?;
                let targets = served(
                    list(&l, "ctTargets", |v| {
                        v.as_u64()
                            .and_then(|x| u32::try_from(x).ok())
                            .ok_or(Error::Argument)
                    })
                    .ok(),
                )?;
                let hashes = served(list(&l, "ctHashes", b32).ok())?;
                if Some(&targets) != a.targets.get(&n)
                    || hashes.len() as u64 != u64j(&c, "ctCount")?
                    || path_list_hash(sc.typed, &targets, &hashes)? != b32j(&c, "ctListHash")?
                {
                    return corrupt();
                }
                (targets, hashes)
            };
            let mut p = Piece {
                n,
                own,
                j: None,
                targets,
                ct: None,
                wrap: None,
            };
            if !own {
                let mut mine = direct_path(2 * leaf, u32j(&c, "leaves")?);
                mine.push(2 * leaf);
                p.j = p.targets.iter().position(|x| mine.contains(x));
                if let Some(j) = p.j {
                    let ct = served(PathCt::from_json(&rd.read(View::PathCtAt(n, j))?).ok())?;
                    if Some(ct.hash(sc)?) != hashes.get(j).copied() {
                        return corrupt();
                    }
                    p.ct = Some(ct);
                }
            }
            if let (true, Some(wrap_index)) = (n == join_epoch, wrap_index) {
                let wrap = rd.read(View::WrapAt(n, wrap_index))?;
                let want = list(&c, "wrapHashes", b32)?;
                if Some(served(wrap_hash(sc, &wrap).ok())?) != want.get(wrap_index).copied() {
                    return corrupt();
                }
                p.wrap = Some(wrap);
            }
            plan.push(p);
        }
        // the secrets, from those bytes only (resumed: the node keys held and the info in force at the pin). C-4, D-6 of the
        // T4-T9 review: `from`'s node keys are only looked up here (`base`, less the nodes a later commit replaced), the new
        // ones kept apart (`own`); they move out of `from` only by `Replay::adopt`, so a refusal leaves it whole
        let empty = BTreeMap::new();
        let base = from.map_or(&empty, |f| &f.held);
        let (mut in_force, mut flagged, mut head_followed) = from
            .map_or((None, false, false), |f| {
                (f.in_force.clone(), f.flagged, f.head_followed)
            });
        let mut own: BTreeMap<u32, KemKeyPair> = BTreeMap::new();
        let mut gone_nodes: std::collections::BTreeSet<u32> = Default::default();
        // the path-less delta §4.1: the head's `next` of `from`, looked up only (its handle stays `from`'s)
        let mut chain = match from.and_then(|f| f.head.as_ref().map(|hd| (hd, f.anchored))) {
            Some((hd, anchored)) => Some(Chain {
                next: s32(&self.bytes(&hd.next)?[..])?,
                anchored,
            }),
            None => None,
        };
        let top = a.trees.get(&head).ok_or(Error::Argument)?;
        let live = |x: &Add| {
            top.leaf(x.leaf)
                .is_some_and(|l| l.ua == x.ua && l.key_id == x.key_id && l.kem_hash == x.kem_hash)
        };
        let mut epochs = Vec::new();
        let mut warnings = Vec::new();
        let mut suspects = Vec::new();
        for p in plan {
            let n = p.n;
            let c = a.rec(n)?.clone();
            let pathless = n > 0 && c.get("pathless").and_then(Value::as_bool) == Some(true);
            let res = if n == 0 {
                self.open_genesis(sc, &a, dev, &p)?
            } else if pathless {
                self.pathless_commit(sc, &a, dev, &p, &c, chain.as_ref())?
            } else if p.own {
                self.own_commit(sc, &a, dev, &p, &c)?
            } else {
                let held = |x: u32| {
                    own.get(&x)
                        .or_else(|| base.get(&x).filter(|_| !gone_nodes.contains(&x)))
                };
                self.others_commit(sc, &a, dev, &p, &c, leaf, &held)?
            };
            if n > 0 {
                // a path-less Add blanks only its new leaves' direct paths, the root included (C6); a path commit also the
                // author's
                let leaves_n = u32j(&c, "leaves")?;
                let mut xs = Vec::new();
                if !pathless {
                    xs.push(u32j(&c, "leaf")?);
                    xs.extend(list(&c, "removes", |v| u32j(v, "leaf"))?);
                }
                xs.extend(list(&c, "adds", |v| u32j(v, "leaf"))?);
                for x in xs {
                    for y in direct_path(2 * x, leaves_n) {
                        own.remove(&y);
                        gone_nodes.insert(y);
                    }
                }
            }
            let Opened {
                state,
                k,
                info: opened,
                derived,
                chain: next_chain,
            } = res;
            chain = next_chain;
            own.extend(derived);
            let mut info = None;
            match (state, opened) {
                (State::Followed, Some(opened)) => {
                    let author = if n == 0 { ZERO } else { b32j(&c, "author")? };
                    let admin = n == 0 || a.admins_at(n - 1)?.contains(&author);
                    match opened {
                        Info::Marker => info = Some(InfoTook::Marker),
                        Info::Json(j) => match &in_force {
                            None => {
                                flagged = !(admin || author == dev.ua);
                                in_force = Some(j);
                                info = Some(InfoTook::Full);
                            }
                            Some(cur) if *cur != j => {
                                if admin {
                                    in_force = Some(j);
                                    flagged = false;
                                    info = Some(InfoTook::Changed);
                                } else {
                                    info = Some(InfoTook::Ignored);
                                }
                            }
                            Some(_) => {
                                if admin {
                                    flagged = false;
                                }
                                info = Some(InfoTook::Full);
                            }
                        },
                    }
                }
                (st, _) => {
                    // a device that did not follow an epoch, or did not take its info, has no info in force from that
                    // epoch on (fable-r3-1; the delta's F-8 and C45)
                    in_force = None;
                    flagged = false;
                    if st == State::Followed {
                        info = Some(InfoTook::NotTaken);
                    }
                }
            }
            let adds_of = || list(&c, "adds", Add::from_json);
            if state == State::Compromise {
                let adds = adds_of()?;
                // C-2, B2-7: an added leaf is left when the walk's head tree still holds that Add's key at its leaf (a pair has
                // one period, C28); the served `joinEpoch` decides nothing
                warnings.push(Warning {
                    epoch: n,
                    adds: adds.iter().map(|x| (x.leaf, x.ua, x.key_id)).collect(),
                    removes: list(&c, "removes", Remove::from_json)?,
                    admins_changed: list(&c, "admins", b32)? != a.admins_at(n - 1)?,
                    leaves_left: adds.iter().filter(|x| live(x)).map(|x| x.leaf).collect(),
                });
            }
            if state == State::AuthorDidNotHold {
                let adds = adds_of()?;
                suspects.push(Suspect {
                    epoch: n,
                    author: b32j(&c, "author")?,
                    adds: adds.iter().map(|x| (x.leaf, x.ua, x.key_id)).collect(),
                    leaves_left: adds.iter().filter(|x| live(x)).map(|x| x.leaf).collect(),
                });
            }
            head_followed = n == head && state == State::Followed;
            let (author, admins) = if n == 0 {
                (b32j(&a.s0, "creator")?, list(&a.s0, "admins", b32)?)
            } else {
                (b32j(&c, "author")?, a.admins_at(n)?)
            };
            epochs.push(EpochRow {
                epoch: n,
                epoch_id: at(&a.ids, n)?,
                author,
                admins,
                state,
                k: match k {
                    Some(k) if n >= keys_from => Some(self.tree_key(&k[..])?),
                    _ => None,
                },
                info,
                in_force: in_force.clone(),
                flagged,
            });
        }
        if last < head {
            // the key's period ended before the head: the device does not follow it
            head_followed = false;
        }
        let pin = a.pin_at(sc, head)?;
        let review: BTreeSet<u32> = warnings
            .iter()
            .flat_map(|w| w.leaves_left.iter())
            .chain(suspects.iter().flat_map(|s| s.leaves_left.iter()))
            .copied()
            .collect();
        let is_admin = a.admins_at(head)?.contains(&dev.ua);
        let path_warning =
            is_admin && end_epoch.is_none() && top.since_path >= warn_at(top.path_bound);
        let (since_path, top_hash) = (top.since_path, top.tree_hash());
        let anchored = chain.as_ref().is_some_and(|c| c.anchored);
        let head_handle = match chain {
            Some(ch) if last == head => Some(self.tree_head(at(&a.ids, head)?, top_hash, &ch.next[..])?),
            _ => None,
        };
        Ok(Some(Replay {
            leaf,
            join_epoch,
            end_epoch,
            rosters,
            epochs,
            warnings,
            suspects,
            review: review.into_iter().collect(),
            since_path,
            path_warning,
            held: own,
            head: head_handle,
            anchored,
            pin,
            in_force,
            flagged,
            head_followed,
            replaced: from.map(|_| gone_nodes),
            consumed: false,
        }))
    }

    /// §10 step 3, the key's one period (C28, R16): its leaf and join from the served leaves (or its end from the key views),
    /// each checked against the walk: the join by its kind (the cold tree's member, or the Add of its epoch), the end by its
    /// Remove. `(None, ..)`: the key is in no period of this session. Returns the leaf, the join, the end and the wrap's index.
    fn period(
        &self,
        a: &Walk,
        rd: &mut dyn TreeReader,
        _sc: &TreeScope,
        dev: &TreeDevice,
        kem_hash: &[u8; 32],
    ) -> Result<(Option<u32>, u64, Option<u64>, usize)> {
        let head = a.head;
        let found = a.leaves.iter().position(|l| {
            b32j(l, "ua").ok() == Some(dev.ua)
                && u64j(l, "keyId").ok() == Some(dev.key_id)
                && b32j(l, "kemHash").ok() == Some(*kem_hash)
        });
        let (join_epoch, end_epoch) = match found {
            Some(i) => (
                served(a.leaves.get(i).and_then(|l| u64j(l, "joinEpoch").ok()))?,
                None,
            ),
            None => {
                let mut g = rd.read(View::GoneOwnKeyOf(&dev.ua, kem_hash))?;
                if g.get("gone") != Some(&json!(true)) {
                    g = rd.read(View::GoneKeyOf(kem_hash))?;
                }
                if g.get("gone") != Some(&json!(true)) {
                    return Ok((None, 0, None, 0));
                }
                // B-9: a period that does not decode is a lying read
                let (j, e) = served((|| {
                    Some((u64j(&g, "joinEpoch").ok()?, u64j(&g, "endEpoch").ok()?))
                })())?;
                if !(e > j && e <= head) {
                    return refuse(TreeError::Period);
                }
                (j, Some(e))
            }
        };
        if join_epoch > head {
            return refuse(TreeError::Period);
        }
        // the join by its kind, the end by its Remove
        let (wrap_index, leaf) = if join_epoch == 0 {
            let members = list(&a.s0, "members", |m| {
                Ok((b32j(m, "ua")?, u64j(m, "keyId")?))
            })?;
            let i = members
                .iter()
                .position(|m| *m == (dev.ua, dev.key_id))
                .ok_or(Error::Tree(TreeError::Period))?;
            let li = u32::try_from(i).map_err(|_| Error::Argument)?;
            let cold = a.trees.get(&0).ok_or(Error::Argument)?;
            if cold.leaf(li).map(|l| l.kem_hash) != Some(*kem_hash) {
                return refuse(TreeError::Period);
            }
            (i, li)
        } else {
            let adds = list(a.rec(join_epoch)?, "adds", Add::from_json)?;
            let i = adds
                .iter()
                .position(|x| x.ua == dev.ua && x.key_id == dev.key_id && x.kem_hash == *kem_hash)
                .ok_or(Error::Tree(TreeError::Period))?;
            (i, adds.get(i).map(|x| x.leaf).ok_or(Error::Argument)?)
        };
        if found.is_some_and(|i| i as u64 != u64::from(leaf)) {
            return refuse(TreeError::Period);
        }
        if let Some(e) = end_epoch {
            let removes = list(a.rec(e)?, "removes", Remove::from_json)?;
            if !removes
                .iter()
                .any(|r| r.leaf == leaf && r.ua == dev.ua && r.key_id == dev.key_id)
            {
                return refuse(TreeError::Period);
            }
        }
        Ok((Some(leaf), join_epoch, end_epoch, wrap_index))
    }

    fn open_genesis(
        &self,
        sc: &TreeScope,
        a: &Walk,
        dev: &TreeDevice,
        p: &Piece,
    ) -> Result<Opened> {
        let wrap = p.wrap.as_ref().ok_or(Error::Argument)?;
        let Some(joiner) = self.tree_unwrap(sc, dev.kem, wrap, &a.gctx, &a.sid) else {
            return Ok(not("opening failed"));
        };
        let sch = schedule(sc, &joiner[..], &EpochFields::genesis(sc, &a.s0)?)?;
        // epoch 0's tag in the session record (C43, F-7): a genesis wrap that does not match it is not followed
        if sch.tag != b32j(&a.s0, "confirmTag")? {
            return Ok(not("tag"));
        }
        let sealed = bytes(a.s0.get("sealedInfo").ok_or(Error::Argument)?)?;
        Ok(taken(sc, a, &a.sid, &sealed, sch, true))
    }

    /// The tail of a path commit's processing: the joiner, the Welcome when there is one, the schedule, the tag (claude-21:
    /// "not followed (tag)"), then the info.
    fn finish(
        &self,
        sc: &TreeScope,
        a: &Walk,
        c: &Value,
        p: &Piece,
        dev: &TreeDevice,
        commit_secret: &[u8],
    ) -> Result<Opened> {
        let epoch_id = at(&a.ids, p.n)?;
        let joiner = joiner_secret(sc, commit_secret, &a.tree_id, &epoch_id)?;
        if let Some(w) = &p.wrap {
            match self.tree_unwrap(sc, dev.kem, w, &a.tree_id, &epoch_id) {
                // both secrets compared in constant time (B-10)
                Some(x)
                    if x.len() == joiner.len()
                        && x.iter()
                            .zip(joiner.iter())
                            .fold(0u8, |d, (p, q)| d | (p ^ q))
                            == 0 => {}
                _ => return Ok(not("welcome disagrees")),
            }
        }
        let sch = schedule(sc, &joiner[..], &EpochFields::commit(sc, c)?)?;
        if sch.tag != b32j(c, "confirmTag")? {
            return Ok(not("tag"));
        }
        let sealed = bytes(c.get("sealedInfo").ok_or(Error::Argument)?)?;
        Ok(taken(sc, a, &epoch_id, &sealed, sch, true))
    }

    /// A path-less Add (the path-less delta §4.1, §6.2, §6.3, §6.5). Its own `(ua, keyId)` first: reproduced only when a
    /// `try` of the seed gives its nonce, else the compromise warning (C47), with or without the epoch state. A joiner at its
    /// join opens its wrap (unanchored); a device holding the parent's `next` (`chain`) derives the joiner secret; the tag
    /// then decides: good, followed; failing at an anchored device, [`State::AuthorDidNotHold`] with the chain's key kept
    /// (C45); at an unanchored one "welcome may not match" (F-1); at the join "tag".
    fn pathless_commit(
        &self,
        sc: &TreeScope,
        a: &Walk,
        dev: &TreeDevice,
        p: &Piece,
        c: &Value,
        chain: Option<&Chain>,
    ) -> Result<Opened> {
        if p.own && !add_nonce_reproduced(sc, dev.kem, c)? {
            return Ok(compromise());
        }
        let epoch_id = at(&a.ids, p.n)?;
        let f = EpochFields::commit(sc, c)?;
        let tag = b32j(c, "confirmTag")?;
        let sealed = bytes(c.get("sealedInfo").ok_or(Error::Argument)?)?;
        if let Some(w) = &p.wrap {
            let Some(joiner) = self.tree_unwrap(sc, dev.kem, w, &a.tree_id, &epoch_id) else {
                return Ok(not("opening failed"));
            };
            let sch = schedule(sc, &joiner[..], &f)?;
            if sch.tag != tag {
                return Ok(not("tag"));
            }
            return Ok(taken(sc, a, &epoch_id, &sealed, sch, false));
        }
        let Some(ch) = chain else {
            return Ok(not("parent not followed"));
        };
        let adds = c.get("adds").and_then(Value::as_array).ok_or(Error::Argument)?;
        let adds_hash = array_hash(sc.typed, "TreeAdd", adds)?;
        let joiner = add_joiner_secret(sc, &ch.next[..], &a.tree_id, &epoch_id, &adds_hash)?;
        let sch = schedule(sc, &joiner[..], &f)?;
        if sch.tag == tag {
            return Ok(taken(sc, a, &epoch_id, &sealed, sch, ch.anchored));
        }
        if !ch.anchored {
            return Ok(not("welcome may not match"));
        }
        Ok(Opened {
            state: State::AuthorDidNotHold,
            k: Some(sch.k),
            info: None,
            derived: Vec::new(),
            chain: Some(Chain {
                next: sch.next,
                anchored: true,
            }),
        })
    }

    /// Another member's commit: the one ciphertext over its leaf, upward with the key comparison (§10).
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn others_commit<'k>(
        &self,
        sc: &TreeScope,
        a: &Walk,
        dev: &TreeDevice,
        p: &Piece,
        c: &Value,
        leaf: u32,
        held: &dyn Fn(u32) -> Option<&'k KemKeyPair>,
    ) -> Result<Opened> {
        let leaves = u32j(c, "leaves")?;
        let nkh = list(c, "nodeKeyHashes", b32)?;
        let path = match path_from_list(u32j(c, "leaf")?, &p.targets, leaves) {
            Some(x) if x.len() == nkh.len() => x,
            _ => return Ok(not("list")),
        };
        let Some(j) = p.j else {
            return Ok(not("wrong target"));
        };
        let t = *p.targets.get(j).ok_or(Error::Argument)?;
        let up = direct_path(t, leaves);
        let Some(k) = path.iter().position(|x| up.contains(x)) else {
            return Ok(not("list"));
        };
        let key = if t == 2 * leaf {
            Some(dev.kem)
        } else {
            held(t)
        };
        let Some(key) = key else {
            return Ok(not("target not held"));
        };
        let at_ = CtAt {
            tree_id: a.tree_id,
            epoch_id: at(&a.ids, p.n)?,
            node: *path.get(k).ok_or(Error::Argument)?,
            target: t,
        };
        let Some(secret) =
            p.ct.as_ref()
                .and_then(|ct| open_path_secret(sc, &at_, key, ct))
        else {
            return Ok(not("opening failed"));
        };
        let ps = path_secrets(sc, secret, path.len() - k)?;
        let mut derived = Vec::new();
        for i in 0..path.len() - k {
            let nk = node_key(sc, &ps.get(i).ok_or(Error::Argument)?[..])?;
            if Some(keccak256(&nk.kem_pk())) != nkh.get(k + i).copied() {
                return Ok(not("node key mismatch"));
            }
            derived.push((*path.get(k + i).ok_or(Error::Argument)?, nk));
        }
        let mut r = self.finish(sc, a, c, p, dev, &ps.last().ok_or(Error::Argument)?[..])?;
        if r.state == State::Followed {
            r.derived = derived;
        }
        Ok(r)
    }

    /// Its own commit: `ps[0]` from the seed; reproduced is both tests, the node keys and the tag (codex-r3-4, claude-21; for
    /// the last live leaf the tag alone), else the compromise warning, never "not followed" (R10, fable-r2-1).
    fn own_commit(
        &self,
        sc: &TreeScope,
        a: &Walk,
        dev: &TreeDevice,
        p: &Piece,
        c: &Value,
    ) -> Result<Opened> {
        let nkh = list(c, "nodeKeyHashes", b32)?;
        let path = match path_from_list(u32j(c, "leaf")?, &p.targets, u32j(c, "leaves")?) {
            Some(x) if x.len() == nkh.len() => x,
            _ => return Ok(compromise()),
        };
        let ctx = path_context(sc, c, &p.targets)?;
        let ps = path_secrets(sc, first_path_secret(sc, dev.kem, &ctx)?, path.len())?;
        let mut derived = Vec::new();
        for (k, x) in path.iter().enumerate() {
            let nk = node_key(sc, &ps.get(k).ok_or(Error::Argument)?[..])?;
            if Some(keccak256(&nk.kem_pk())) != nkh.get(k).copied() {
                return Ok(compromise());
            }
            derived.push((*x, nk));
        }
        let mut r = self.finish(sc, a, c, p, dev, &ps.last().ok_or(Error::Argument)?[..])?;
        if r.state == State::Followed {
            r.derived = derived;
            Ok(r)
        } else {
            Ok(compromise())
        }
    }
}

// ------------------------------------------------------------------ test-only entries (feature `vectors`)

/// `ps[0..=m]` and the node keys of `ps[0..m]` (a vector's comparison).
#[cfg(feature = "vectors")]
pub type PathAndKeys = (Vec<Vec<u8>>, Vec<Vec<u8>>);
/// `(S, K, next, confirmTag)` (a vector's comparison).
#[cfg(feature = "vectors")]
pub type VectorsSchedule = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Test-only entry points (feature `vectors`, never in a release build): fixed randomness, and the secrets a vector compares.
#[cfg(feature = "vectors")]
impl AppKeys {
    /// [`AppKeys::tree_create_genesis`] with `rand(name, n)` for the joiner, the wraps' encapsulations and the info nonce.
    pub fn vectors_tree_create_genesis(
        &self,
        sc: &TreeScope,
        session: &Value,
        kems: &[KemRecord],
        info: &[u8],
        rand: Rand,
    ) -> Result<Genesis> {
        self.create_genesis(sc, session, kems, info, rand)
    }
    /// [`AppKeys::tree_prepare_commit`] with a given nonce and `rand(name, n)`.
    pub fn vectors_tree_prepare_commit(
        &self,
        sc: &TreeScope,
        a: CommitInput,
        nonce: u64,
        rand: Rand,
    ) -> Result<PreparedCommit> {
        self.prepare_commit(sc, a, nonce, rand)
    }
    /// [`AppKeys::tree_build_commit`] with a given nonce and `rand(name, n)`.
    pub fn vectors_tree_build_commit(
        &self,
        sc: &TreeScope,
        a: CommitInput,
        nonce: u64,
        rand: Rand,
    ) -> Result<BuiltCommit> {
        self.build_commit(sc, a, nonce, rand)
    }
    /// `ps[0..=m]` of the seed of `kem` over `path_context`, and the node keys of `ps[0..m]`.
    pub fn vectors_tree_path(
        &self,
        sc: &TreeScope,
        kem: &KemKeyPair,
        path_context: &[u8; 32],
        m: usize,
    ) -> Result<PathAndKeys> {
        let ps = path_secrets(sc, first_path_secret(sc, kem, path_context)?, m)?;
        let keys = ps
            .iter()
            .take(m)
            .map(|s| Ok(node_key(sc, &s[..])?.kem_pk()))
            .collect::<Result<Vec<_>>>()?;
        Ok((ps.iter().map(|s| s.to_vec()).collect(), keys))
    }
    /// A path ciphertext with fixed `m`, `e`: `(ss, kek, ct)`.
    pub fn vectors_tree_seal_path_secret(
        &self,
        sc: &TreeScope,
        at: &CtAt,
        kem_pk: &[u8],
        secret: &[u8],
        m: &[u8; 32],
        e: &[u8; 32],
    ) -> Result<(Vec<u8>, Vec<u8>, PathCt)> {
        let (ss, kek, ct) = seal_path_secret(sc, at, kem_pk, secret, m, e)?;
        Ok((ss.to_vec(), kek.to_vec(), ct))
    }
    /// The opened path secret of `ct` by `key`, `None` when it does not open.
    pub fn vectors_tree_open_path_secret(
        &self,
        sc: &TreeScope,
        at: &CtAt,
        key: &KemKeyPair,
        ct: &PathCt,
    ) -> Option<Vec<u8>> {
        open_path_secret(sc, at, key, ct).map(|s| s.to_vec())
    }
    /// `(S, K, next, confirmTag)` of a joiner secret and an epoch's fields.
    pub fn vectors_tree_schedule(
        &self,
        sc: &TreeScope,
        joiner: &[u8],
        f: &EpochFields,
    ) -> Result<VectorsSchedule> {
        let (s, x) = schedule_s(sc, joiner, f)?;
        Ok((s.to_vec(), x.k.to_vec(), x.next.to_vec(), x.tag.to_vec()))
    }
    /// [`AppKeys::tree_prepare_pathless`] with `rand(name, n)` and, for an insider's or a refusal row, a given nonce.
    pub fn vectors_tree_prepare_pathless(
        &self,
        sc: &TreeScope,
        a: PathlessInput,
        head: &TreeHead,
        try_: u32,
        nonce: Option<u64>,
        rand: Rand,
    ) -> Result<PreparedCommit> {
        let n = nonce.map_or(Nonce::Try(try_), Nonce::Given);
        self.prepare_pathless(sc, a, head, n, rand)
    }
    /// `addNonce` of `kem`'s seed over `[treeId, parentEpochId, parentTreeHash, hash(adds)]` at `try_` (C47).
    pub fn vectors_tree_add_nonce(
        &self,
        sc: &TreeScope,
        kem: &KemKeyPair,
        parent: &[[u8; 32]; 4],
        try_: u32,
    ) -> Result<u64> {
        add_nonce(sc, kem, parent, try_)
    }
    /// A path-less Add's joiner secret from a `next` (the path-less delta §4.1).
    pub fn vectors_tree_add_joiner(
        &self,
        sc: &TreeScope,
        next: &[u8],
        tree_id: &[u8; 32],
        epoch_id: &[u8; 32],
        adds_hash: &[u8; 32],
    ) -> Result<Vec<u8>> {
        Ok(add_joiner_secret(sc, next, tree_id, epoch_id, adds_hash)?.to_vec())
    }
    /// A `sealedInfo` opened under the epoch key `k`.
    pub fn vectors_tree_open_info(
        &self,
        sc: &TreeScope,
        k: &KeyHandle,
        session: &[u8; 32],
        epoch: &[u8; 32],
        sealed: &[u8],
    ) -> Option<Info> {
        open_info(sc, &self.bytes(k).ok()?[..], session, epoch, sealed)
    }
}
