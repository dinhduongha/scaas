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
    KemRecord, Leaf, Node, Remove, Tree, TreeError, Typed, ZERO,
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
/// `S_e = H(joiner, …/epoch ‖ ctx_e)`, `K_e = H(S_e, …/key)`.
fn schedule(sc: &TreeScope, joiner: &[u8], f: &EpochFields) -> Result<(Secret, Secret)> {
    let s = h(joiner, &[&sc.l("epoch")[..], &f.context(sc)].concat())?;
    let k = h(&s[..], &sc.l("key"))?;
    Ok((s, k))
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

/// What a commit is built from: the parent tree and head (its admins for the review), the author's leaf and its KEM key (its
/// seed derives `ps[0]`), the Removes and the Adds with each added key's registry record, the admins and the info (`None`:
/// the marker). `key_of(node)` gives a target of the parent tree: a node's key, a leaf's key, or on an epoch-0 head a leaf's
/// registry record; each is checked here ([`TargetKey`]).
pub struct CommitInput<'a> {
    pub tree: &'a Tree,
    pub parent_epoch_id: [u8; 32],
    pub parent_epoch: u64,
    pub parent_tree_hash: [u8; 32],
    pub parent_admins: Vec<[u8; 32]>,
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
    Record(KemRecord),
}

/// Target `x`'s key of the parent tree, checked inside the boundary: a node's against its `keyHash`; a leaf's against its
/// `kemHash`, and on an epoch-0 head first authenticated by its registry record (`TreeKemRecord`); a mismatch `TreeKeyHash`.
fn target_key(tree: &Tree, parent_epoch: u64, x: u32, k: TargetKey) -> Result<Vec<u8>> {
    let (key, want) = match (tree.node(x), k) {
        (Node::Leaf(l), TargetKey::Record(r)) => (kem_record_key(&l.ua, l.key_id, &r)?, l.kem_hash),
        (Node::Leaf(l), TargetKey::Key(k)) if parent_epoch > 0 => (k, l.kem_hash),
        (Node::Parent(h), TargetKey::Key(k)) => (k, *h),
        _ => return refuse(TreeError::KemRecord),
    };
    if keccak256(&key) != want {
        return refuse(TreeError::KeyHash);
    }
    Ok(key)
}

/// A built commit: the record (unsigned, in the type's field order), its pieces, the tree after it and `K_e`.
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
        let joiner = self.make(
            &r32(rand, "joiner-0")?[..],
            KeyUsage::Derive,
            Origin::Drawn,
            None,
        )?;
        let (_, k) = schedule(sc, &self.bytes(&joiner)?[..], &f)?;
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
        };
        let p = a.tree.filtered_path_after(&ch)?;
        let ct_targets: Vec<u32> = p.iter().flat_map(|q| q.targets.iter().copied()).collect();
        let removes: Vec<Value> = a.removes.iter().map(Remove::to_json).collect();
        let adds: Vec<Value> = add_recs.iter().map(Add::to_json).collect();
        let mut rec = json!({
            "sessionId": hx(&a.session_id), "author": hx(&a.author), "nonce": nonce, "epoch": a.parent_epoch + 1,
            "parentEpochId": hx(&a.parent_epoch_id), "treeId": hx(&a.tree_id), "parentTreeHash": hx(&a.parent_tree_hash),
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
                    None => target_key(a.tree, a.parent_epoch, t, (a.key_of)(t)?)?,
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
        let applied = a.tree.apply_commit(&ch, &node_key_hashes)?;
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
            epoch: a.parent_epoch + 1,
            parent_epoch_id: a.parent_epoch_id,
            parent_tree_hash: a.parent_tree_hash,
            tree_hash: applied.tree_hash,
            admins: a.admins.clone(),
        };
        let (_, k) = schedule(sc, &joiner[..], &f)?;
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
        Ok(BuiltCommit {
            record: rec,
            epoch_id,
            path_context: ctx,
            ct_targets: applied.ct_targets.clone(),
            ct_hashes,
            node_keys,
            cts,
            wraps,
            tree: applied.tree,
            k: self.tree_key(&k[..])?,
        })
    }
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
        for f in v["types"][name].as_array().into_iter().flatten() {
            let n = f["name"].as_str().ok_or(Error::Argument)?;
            review.push((n.to_string(), show(&v["message"][n])));
        }
        review.extend(more);
        Ok(TreePrepared {
            td,
            purpose: (sc.purpose)(),
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
        self.td.to_value()["message"].clone()
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

/// `PqChatTreeLeave`'s named fields (spec §6): `member` leaves the session `treeId` at its head `epochId`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeLeave {
    pub session_id: [u8; 32],
    pub tree_id: [u8; 32],
    pub epoch_id: [u8; 32],
    pub member: [u8; 32],
    pub nonce: u64,
}

/// `PqChatTreeRemove`'s named fields (spec §6): the admin `admin` removes `members` at the head `epochId`.
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

/// A `treeLeave` prepared for the leaver's signature: the review names the session by `treeId` and says the UA cannot come
/// back (C30, R14).
pub fn tree_prepare_leave(sc: &TreeScope, l: &TreeLeave) -> Result<TreePrepared> {
    let rec = json!({"sessionId": hx(&l.session_id), "treeId": hx(&l.tree_id), "epochId": hx(&l.epoch_id),
        "member": hx(&l.member), "nonce": l.nonce});
    let back = "this UA can never come back to this session (R14)".to_string();
    TreePrepared::new(
        sc,
        "PqChatTreeLeave",
        rec,
        vec![("cannotComeBack".into(), back)],
    )
}

/// A `treeRemove` prepared for the admin's signature: the review names the session by `treeId` and says the removed UAs
/// cannot come back (C30, R14).
pub fn tree_prepare_remove(sc: &TreeScope, r: &TreeRemove) -> Result<TreePrepared> {
    let members: Vec<String> = r.members.iter().map(|m| hx(m)).collect();
    let rec = json!({"sessionId": hx(&r.session_id), "treeId": hx(&r.tree_id), "epochId": hx(&r.epoch_id),
        "nextEpoch": r.next_epoch, "members": members, "admin": hx(&r.admin), "nonce": r.nonce});
    let back = "the removed UAs can never come back to this session (R14)".to_string();
    TreePrepared::new(
        sc,
        "PqChatTreeRemove",
        rec,
        vec![("cannotComeBack".into(), back)],
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
        let changed = a.admins != a.parent_admins;
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
}

// ------------------------------------------------------------------ the views a device reads (spec §6)

/// A read of the home's views; its `Display` is the read's name as the vectors log it (`commitOf(3)`).
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
    GoneRecord(&'a [u8; 32]),
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
            View::GoneRecord(u) => write!(f, "goneRecord({})", hx(*u)),
            View::GoneOwnKeyOf(u, k) => write!(f, "goneOwnKeyOf({},{})", hx(*u), hx(*k)),
            View::GoneKeyOf(k) => write!(f, "goneKeyOf({})", hx(*k)),
            View::KemKeyAt(u, k) => write!(f, "kemKeyAt({},{k})", hx(*u)),
        }
    }
}

/// The home's views (JSON in the contract views' shape, as clientkeys' `reader`), and the registry's signing key of a UA
/// (`(kind, key)`, a signature check, never a session read).
pub trait TreeReader {
    fn read(&mut self, v: View) -> Result<Value>;
    fn ua_key_of(&mut self, ua: &[u8; 32]) -> Option<(u16, Vec<u8>)>;
}

fn verified(
    sc: &TreeScope,
    rd: &mut dyn TreeReader,
    name: &str,
    rec: &Value,
    signer: &[u8; 32],
    sig: &Value,
) -> Result<()> {
    let ok = (|| {
        let (kind, pk) = rd.ua_key_of(signer)?;
        let digest = (sc.typed)(name, rec.clone()).ok()?.digest().ok()?;
        let m = crate::ua_message(kind, &(sc.purpose)(), &digest).ok()?;
        let sig = bytes(sig).ok()?;
        (crate::ua_of(kind, &pk).ok()? == *signer && crate::pq::verify(kind, &pk, &m, &sig))
            .then_some(())
    })();
    ok.ok_or(Error::Tree(TreeError::ReadCorrupted))
}
fn corrupt<T>() -> Result<T> {
    refuse(TreeError::ReadCorrupted)
}
fn kem_hash_of(v: &Value) -> Result<[u8; 32]> {
    Ok(keccak256(&bytes(v)?))
}

/// The checkpoint (C26): the session's `treeId`, the pinned epoch and the hash of the record that won there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    pub tree_id: [u8; 32],
    pub epoch: u64,
    pub hash: [u8; 32],
}

/// The head of §10 steps 1 and 2: the session record, the snapshot, the anchored head; commit records read on demand.
struct Anchor {
    s0: Value,
    sid: [u8; 32],
    tree_id: [u8; 32],
    gctx: [u8; 32],
    t: Value,
    leaves: Vec<Value>,
    nodes: Vec<Value>,
    ids: Vec<[u8; 32]>,
    head: u64,
    recs: BTreeMap<u64, Value>,
    cold: Option<Tree>,
}

fn at<T: Clone>(v: &[T], n: u64) -> Result<T> {
    usize::try_from(n)
        .ok()
        .and_then(|i| v.get(i))
        .cloned()
        .ok_or(Error::Argument)
}

impl Anchor {
    fn new(sc: &TreeScope, rd: &mut dyn TreeReader) -> Result<Anchor> {
        let s = rd.read(View::SessionOf)?;
        let s0 = s.get("record").cloned().ok_or(Error::Argument)?;
        let creator = b32j(&s0, "creator")?;
        verified(
            sc,
            rd,
            "PqChatSession",
            &s0,
            &creator,
            s.get("sig").ok_or(Error::Argument)?,
        )?;
        if u64j(&s0, "groupMode")? != 1 {
            return refuse(TreeError::ModeEntry);
        }
        let arr = |v: Value| v.as_array().cloned().ok_or(Error::Argument);
        let t = rd.read(View::TreeOf)?;
        let leaves = arr(rd.read(View::TreeLeaves)?)?;
        let nodes = arr(rd.read(View::TreeNodes)?)?;
        let ids = arr(rd.read(View::EpochsOf)?)?
            .iter()
            .map(b32)
            .collect::<Result<Vec<_>>>()?;
        let head = (ids.len() as u64).checked_sub(1).ok_or(Error::Argument)?;
        let mut a = Anchor {
            sid: sc.session_id(&creator, u64j(&s0, "nonce")?),
            tree_id: tree_id(sc.typed, &s0)?,
            gctx: genesis_ctx(sc.typed, &s0)?,
            recs: BTreeMap::from([(0, s0.clone())]),
            s0,
            t,
            leaves,
            nodes,
            ids,
            head,
            cold: None,
        };
        let view = |l: Option<&Leaf>| {
            l.map_or(
                json!({"ua": hx(&ZERO), "keyId": 0, "kemHash": hx(&ZERO)}),
                Leaf::to_json,
            )
        };
        if head == 0 {
            let g = a.genesis(rd)?;
            let want: Vec<Value> = (0..g.leaves).map(|i| view(g.leaf(i))).collect();
            let got = a
                .leaves
                .iter()
                .map(|l| {
                    Ok(view(
                        (b32j(l, "ua")? != ZERO)
                            .then(|| Leaf::from_json(l))
                            .transpose()?
                            .as_ref(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            if want != got || b32j(&a.t, "genesisTreeHash")? != g.tree_hash() {
                return refuse(TreeError::GenesisLeaves);
            }
        } else {
            let snap = a.snapshot()?.tree_hash();
            let rec = a.read(sc, rd, head)?;
            if snap != b32j(&rec, "treeHash")? || b32j(&a.t, "treeHash")? != b32j(&rec, "treeHash")?
            {
                return refuse(TreeError::HeadRoot);
            }
        }
        Ok(a)
    }

    /// Commit `n`'s record, checked against the id list, the tree and its author's signature.
    fn read(&mut self, sc: &TreeScope, rd: &mut dyn TreeReader, n: u64) -> Result<Value> {
        if let Some(r) = self.recs.get(&n) {
            return Ok(r.clone());
        }
        let v = rd.read(View::CommitOf(n))?;
        let c = v.get("record").cloned().ok_or(Error::Argument)?;
        let author = b32j(&c, "author")?;
        if u64j(&c, "epoch")? != n
            || sc.epoch_id(&self.sid, &author, u64j(&c, "nonce")?) != at(&self.ids, n)?
            || b32j(&c, "treeId")? != self.tree_id
        {
            return corrupt();
        }
        verified(
            sc,
            rd,
            "PqChatCommit",
            &c,
            &author,
            v.get("sig").ok_or(Error::Argument)?,
        )?;
        self.recs.insert(n, c.clone());
        Ok(c)
    }
    fn rec(&self, n: u64) -> Result<&Value> {
        self.recs.get(&n).ok_or(Error::Argument)
    }

    /// The cold tree rebuilt from the signed member list and the registry's keys (codex-r2-1), read once.
    fn genesis(&mut self, rd: &mut dyn TreeReader) -> Result<Tree> {
        if let Some(g) = &self.cold {
            return Ok(g.clone());
        }
        let members = list(&self.s0, "members", |m| {
            Ok((b32j(m, "ua")?, u64j(m, "keyId")?))
        })?;
        let mut leaves = Vec::new();
        for (ua, key_id) in members {
            let k = rd.read(View::KemKeyAt(&ua, key_id))?;
            leaves.push(Leaf {
                ua,
                key_id,
                kem_hash: kem_hash_of(&k)?,
            });
        }
        let g = Tree::cold(&leaves)?;
        self.cold = Some(g.clone());
        Ok(g)
    }

    /// The tree of the snapshot: its leaves and each parent's `keyHash` (codex-r2-6).
    fn snapshot(&self) -> Result<Tree> {
        let n = u32::try_from(self.leaves.len()).map_err(|_| Error::Argument)?;
        let mut t = Tree {
            leaves: n,
            used: u32j(&self.t, "used")?,
            nodes: vec![Node::Blank; super::tree_public::node_width(n) as usize],
            ..Tree::default()
        };
        for (i, l) in self.leaves.iter().enumerate() {
            if b32j(l, "ua")? != ZERO {
                if let Some(s) = t.nodes.get_mut(2 * i) {
                    *s = Node::Leaf(Leaf::from_json(l)?);
                }
            }
        }
        for (x, nd) in self.nodes.iter().enumerate() {
            let k = b32j(nd, "keyHash")?;
            if x % 2 == 1 && k != ZERO {
                if let Some(s) = t.nodes.get_mut(x) {
                    *s = Node::Parent(k);
                }
            }
        }
        Ok(t)
    }

    fn record_hash(&mut self, sc: &TreeScope, rd: &mut dyn TreeReader, n: u64) -> Result<[u8; 32]> {
        if n == 0 {
            return struct_hash(sc.typed, "PqChatSession", &self.s0);
        }
        let r = self.read(sc, rd, n)?;
        struct_hash(sc.typed, "PqChatCommit", &r)
    }
    /// Never below the pinned epoch, and the record that won there is the pinned one (C26, fable-r2-4, codex-r3-2).
    fn check_pin(
        &mut self,
        sc: &TreeScope,
        rd: &mut dyn TreeReader,
        store: Option<&Pin>,
    ) -> Result<()> {
        let Some(p) = store else { return Ok(()) };
        if p.tree_id != self.tree_id || self.head < p.epoch {
            return refuse(TreeError::Checkpoint);
        }
        if self.record_hash(sc, rd, p.epoch)? != p.hash {
            return refuse(TreeError::Conflict);
        }
        Ok(())
    }
    fn pin(&mut self, sc: &TreeScope, rd: &mut dyn TreeReader) -> Result<Pin> {
        Ok(Pin {
            tree_id: self.tree_id,
            epoch: self.head,
            hash: self.record_hash(sc, rd, self.head)?,
        })
    }
    fn admins_at(&self, n: u64) -> Result<Vec<[u8; 32]>> {
        list(self.rec(n)?, "admins", b32)
    }
}

/// The public tree a commit is built on (§8): the checkpoint, the anchored head (the cold tree rebuilt at epoch 0), the
/// head's `gone` UAs, and the parent's id, number, tree hash and admins.
pub struct Prepared {
    pub tree: Tree,
    pub parent_epoch_id: [u8; 32],
    pub parent_epoch: u64,
    pub parent_tree_hash: [u8; 32],
    pub parent_admins: Vec<[u8; 32]>,
    pub pin: Pin,
}

/// [`Prepared`] from the views.
pub fn tree_prepare(
    sc: &TreeScope,
    rd: &mut dyn TreeReader,
    store: Option<&Pin>,
) -> Result<Prepared> {
    let mut a = Anchor::new(sc, rd)?;
    a.check_pin(sc, rd, store)?;
    let mut tree = a.snapshot()?;
    let mut uas: Vec<[u8; 32]> = Vec::new();
    for l in (0..tree.leaves).filter_map(|i| tree.leaf(i)) {
        if !uas.contains(&l.ua) {
            uas.push(l.ua);
        }
    }
    for ua in uas {
        if u64j(&rd.read(View::GoneOf(&ua))?, "kind")? != 0 {
            tree.gone_ua.insert(ua);
        }
    }
    let parent_tree_hash = if a.head == 0 {
        tree.tree_hash()
    } else {
        b32j(a.rec(a.head)?, "treeHash")?
    };
    Ok(Prepared {
        parent_epoch_id: at(&a.ids, a.head)?,
        parent_epoch: a.head,
        parent_tree_hash,
        parent_admins: a.admins_at(a.head)?,
        pin: a.pin(sc, rd)?,
        tree,
    })
}

/// The key of target `x` of `tree`, fetched and checked against the hash that entered the root (`TreeKeyHash`, codex-1): a
/// leaf's from the registry, a node's from the home.
pub fn key_of(rd: &mut dyn TreeReader, tree: &Tree, x: u32) -> Result<Vec<u8>> {
    let (k, want) = match tree.node(x) {
        Node::Leaf(l) => (rd.read(View::KemKeyAt(&l.ua, l.key_id))?, l.kem_hash),
        Node::Parent(kh) => (rd.read(View::TreeNodeKey(x))?, *kh),
        Node::Blank => return refuse(TreeError::KeyHash),
    };
    let k = bytes(&k)?;
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
    /// with the reason: "opening failed", "rights", "list", "wrong target", "target not held", "node key mismatch",
    /// "welcome disagrees", "info does not open"
    NotFollowed(&'static str),
    /// its own `(ua, keyId)` committed what its seed does not reproduce (R10, fable-r2-1)
    Compromise,
}

/// What a followed epoch's `sealedInfo` did to the info in force (C33).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InfoTook {
    Full,
    Changed,
    Ignored,
    Marker,
}

/// One epoch of the device's secret range.
pub struct EpochRow {
    pub epoch: u64,
    pub epoch_id: [u8; 32],
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

/// A roster entry: `(ua, keyId)` of a leaf, `None` blank.
pub type Roster = Vec<Option<([u8; 32], u64)>>;

/// A replay's result.
pub struct Replay {
    pub leaf: u32,
    pub join_epoch: u64,
    pub end_epoch: Option<u64>,
    /// the right of the commit that took the key out (§10 step 4); nothing is opened there
    pub end_rightful: Option<bool>,
    /// by epoch, from the join's parent to the head (§10 step 4)
    pub rosters: BTreeMap<u64, Roster>,
    pub epochs: Vec<EpochRow>,
    pub warnings: Vec<Warning>,
    /// the node keys the device holds after the range (its leaf's key is its own, not here)
    pub held: BTreeMap<u32, KemKeyPair>,
    pub pin: Pin,
}

impl Replay {
    /// The info a device seals in a commit of its own (C33): the full info in force only when it followed the head and
    /// holds one not flagged; otherwise the marker (`None`). A changed info is the admin's own action, never this.
    pub fn info_to_seal(&self) -> Option<&str> {
        let e = self.epochs.last()?;
        (e.epoch == self.pin.epoch && e.state == State::Followed && !e.flagged)
            .then_some(e.in_force.as_deref())
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

struct Opened {
    state: State,
    k: Option<Secret>,
    info: Option<Info>,
    derived: Vec<(u32, KemKeyPair)>,
}
fn not(reason: &'static str) -> Opened {
    Opened {
        state: State::NotFollowed(reason),
        k: None,
        info: None,
        derived: Vec::new(),
    }
}
fn compromise() -> Opened {
    Opened {
        state: State::Compromise,
        ..not("")
    }
}

impl AppKeys {
    /// A device's replay of a tree session from the home's state alone (§10): the anchored head, the key's one period, the
    /// public range's records, the rosters by undo, the rights, the secret range's pieces all read before anything is opened
    /// (C22), then per epoch its state, `K` (a handle), the info in force (C33), the compromise warnings and the next pin.
    /// `Ok(None)`: the key is in no period of this session. Refusals by name (`TreeError`); bytes that fail a signed hash or
    /// a signature: `TreeReadCorrupted`, before any decapsulation.
    pub fn tree_replay(
        &self,
        sc: &TreeScope,
        rd: &mut dyn TreeReader,
        dev: &TreeDevice,
        store: Option<&Pin>,
    ) -> Result<Option<Replay>> {
        let kem_hash = keccak256(&dev.kem.kem_pk());
        let mut a = Anchor::new(sc, rd)?;
        let head = a.head;
        // 3. the key's one period (C28, R16)
        let found = a.leaves.iter().position(|l| {
            b32j(l, "ua").ok() == Some(dev.ua)
                && u64j(l, "keyId").ok() == Some(dev.key_id)
                && b32j(l, "kemHash").ok() == Some(kem_hash)
        });
        let (join_epoch, end_epoch) = match found {
            Some(i) => (
                u64j(a.leaves.get(i).ok_or(Error::Argument)?, "joinEpoch")?,
                None,
            ),
            None => {
                let mut g = rd.read(View::GoneOwnKeyOf(&dev.ua, &kem_hash))?;
                if g.get("gone") != Some(&json!(true)) {
                    g = rd.read(View::GoneKeyOf(&kem_hash))?;
                }
                if g.get("gone") != Some(&json!(true)) {
                    return Ok(None);
                }
                (u64j(&g, "joinEpoch")?, Some(u64j(&g, "endEpoch")?))
            }
        };
        // the public range: the join's parent to the head, records only (codex-r3-1)
        let lo = join_epoch.saturating_sub(1);
        for n in lo.max(1)..=head {
            a.read(sc, rd, n)?;
        }
        let gtree_hash = if lo == 0 && head >= 1 {
            a.genesis(rd)?.tree_hash()
        } else {
            ZERO
        };
        for n in lo + 1..=head {
            let r = a.rec(n)?;
            let parent_hash = if n == 1 {
                gtree_hash
            } else {
                b32j(a.rec(n - 1)?, "treeHash")?
            };
            if b32j(r, "parentEpochId")? != at(&a.ids, n - 1)?
                || b32j(r, "parentTreeHash")? != parent_hash
            {
                return corrupt();
            }
        }
        a.check_pin(sc, rd, store)?;
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
            if a.genesis(rd)?.leaf(li).map(|l| l.kem_hash) != Some(kem_hash) {
                return refuse(TreeError::Period);
            }
            (i, li)
        } else {
            let adds = list(a.rec(join_epoch)?, "adds", Add::from_json)?;
            let i = adds
                .iter()
                .position(|x| x.ua == dev.ua && x.key_id == dev.key_id && x.kem_hash == kem_hash)
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
        let last = end_epoch.map_or(head, |e| e - 1);
        // 4. the rosters by undo from the anchored head (C25, codex-r3-1)
        let mut rosters: BTreeMap<u64, Roster> = BTreeMap::new();
        let mut r: Roster = a
            .leaves
            .iter()
            .map(|l| Ok((b32j(l, "ua")? != ZERO).then_some((b32j(l, "ua")?, u64j(l, "keyId")?))))
            .collect::<Result<_>>()?;
        rosters.insert(head, r.clone());
        let members_n =
            a.s0.get("members")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
        let cold_size = members_n.max(1).next_power_of_two();
        for n in (lo + 1..=head).rev() {
            let c = a.rec(n)?;
            for x in list(c, "adds", Add::from_json)? {
                if let Some(s) = r.get_mut(x.leaf as usize) {
                    *s = None;
                }
            }
            for x in list(c, "removes", Remove::from_json)? {
                if let Some(s) = r.get_mut(x.leaf as usize) {
                    *s = Some((x.ua, x.key_id));
                }
            }
            let size = if n == 1 {
                cold_size
            } else {
                u32j(a.rec(n - 1)?, "leaves")? as usize
            };
            r.truncate(size);
            rosters.insert(n - 1, r.clone());
        }
        if lo == 0 {
            let want: Roster = list(&a.s0, "members", |m| {
                Ok(Some((b32j(m, "ua")?, u64j(m, "keyId")?)))
            })?;
            if rosters
                .get(&0)
                .map(|r0| r0.iter().take(want.len()).cloned().collect::<Roster>())
                != Some(want)
            {
                return refuse(TreeError::Roster);
            }
        }
        // 5. rights against the parent's roster and admins, with the evidence of a UA a non-admin drops (codex-r2-6)
        let mut evidence: BTreeMap<[u8; 32], Option<u64>> = BTreeMap::new();
        let mut right: BTreeMap<u64, bool> = BTreeMap::new();
        let mut ns: Vec<u64> = (join_epoch.max(1)..=last).collect();
        ns.extend(end_epoch);
        for n in ns {
            let ok = self.rightful(sc, rd, &mut a, &rosters, &mut evidence, n)?;
            right.insert(n, ok);
        }
        // 6. the secret range's pieces, by public data only, all read before anything is opened (C22)
        let mut plan: Vec<Piece> = Vec::new();
        for n in join_epoch..=last {
            if n == 0 {
                let wrap = rd.read(View::WrapAt(0, leaf as usize))?;
                let want = list(&a.s0, "wrapHashes", b32)?;
                if Some(wrap_hash(sc, &wrap)?) != want.get(leaf as usize).copied() {
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
            let l = rd.read(View::PathListOf(n))?;
            let targets = list(&l, "ctTargets", |v| {
                v.as_u64()
                    .and_then(|x| u32::try_from(x).ok())
                    .ok_or(Error::Argument)
            })?;
            let hashes = list(&l, "ctHashes", b32)?;
            if targets.len() as u64 != u64j(&c, "ctCount")?
                || path_list_hash(sc.typed, &targets, &hashes)? != b32j(&c, "ctListHash")?
            {
                return corrupt();
            }
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
                    let ct = PathCt::from_json(&rd.read(View::PathCtAt(n, j))?)?;
                    if Some(ct.hash(sc)?) != hashes.get(j).copied() {
                        return corrupt();
                    }
                    p.ct = Some(ct);
                }
            }
            if n == join_epoch {
                let wrap = rd.read(View::WrapAt(n, wrap_index))?;
                let want = list(&c, "wrapHashes", b32)?;
                if Some(wrap_hash(sc, &wrap)?) != want.get(wrap_index).copied() {
                    return corrupt();
                }
                p.wrap = Some(wrap);
            }
            plan.push(p);
        }
        // the secrets, from those bytes only
        let mut held: BTreeMap<u32, KemKeyPair> = BTreeMap::new();
        let mut in_force: Option<String> = None;
        let mut flagged = false;
        let mut epochs = Vec::new();
        let mut warnings = Vec::new();
        for p in plan {
            let n = p.n;
            let c = a.rec(n)?.clone();
            let res = if n == 0 {
                self.open_genesis(sc, &a, dev, &p)?
            } else if right.get(&n) != Some(&true) {
                not("rights")
            } else if p.own {
                self.own_commit(sc, &a, dev, &p, &c)?
            } else {
                self.others_commit(sc, &a, dev, &p, &c, leaf, &held)?
            };
            if n > 0 {
                let leaves_n = u32j(&c, "leaves")?;
                let mut xs = vec![u32j(&c, "leaf")?];
                xs.extend(list(&c, "removes", |v| u32j(v, "leaf"))?);
                xs.extend(list(&c, "adds", |v| u32j(v, "leaf"))?);
                for x in xs {
                    for y in direct_path(2 * x, leaves_n) {
                        held.remove(&y);
                    }
                }
            }
            let Opened {
                state,
                k,
                info: opened,
                derived,
            } = res;
            held.extend(derived);
            let mut info = None;
            if state == State::Followed {
                let author = if n == 0 { ZERO } else { b32j(&c, "author")? };
                let admin = n == 0 || a.admins_at(n - 1)?.contains(&author);
                match opened {
                    Some(Info::Marker) | None => info = Some(InfoTook::Marker),
                    Some(Info::Json(j)) => match &in_force {
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
            } else {
                // a device that did not follow an epoch has no info in force from that epoch on (fable-r3-1)
                in_force = None;
                flagged = false;
            }
            if state == State::Compromise {
                let adds = list(&c, "adds", Add::from_json)?;
                let live = |x: &Add| {
                    a.leaves.get(x.leaf as usize).is_some_and(|l| {
                        b32j(l, "ua").ok() == Some(x.ua)
                            && u64j(l, "keyId").ok() == Some(x.key_id)
                            && u64j(l, "joinEpoch").ok() == Some(n)
                    })
                };
                warnings.push(Warning {
                    epoch: n,
                    adds: adds.iter().map(|x| (x.leaf, x.ua, x.key_id)).collect(),
                    removes: list(&c, "removes", Remove::from_json)?,
                    admins_changed: list(&c, "admins", b32)? != a.admins_at(n - 1)?,
                    leaves_left: adds.iter().filter(|x| live(x)).map(|x| x.leaf).collect(),
                });
            }
            epochs.push(EpochRow {
                epoch: n,
                epoch_id: at(&a.ids, n)?,
                state,
                k: k.map(|k| self.tree_key(&k[..])).transpose()?,
                info,
                in_force: in_force.clone(),
                flagged,
            });
        }
        let end_rightful = end_epoch.and_then(|e| right.get(&e).copied());
        Ok(Some(Replay {
            leaf,
            join_epoch,
            end_epoch,
            end_rightful,
            rosters,
            epochs,
            warnings,
            held,
            pin: a.pin(sc, rd)?,
        }))
    }

    /// Commit `n`'s right against the parent's roster and admins: a non-admin keeps the admins, adds only its own UA and
    /// removes only its own UA's leaves or a UA with the evidence of its leave or removal before `n`.
    fn rightful(
        &self,
        sc: &TreeScope,
        rd: &mut dyn TreeReader,
        a: &mut Anchor,
        rosters: &BTreeMap<u64, Roster>,
        evidence: &mut BTreeMap<[u8; 32], Option<u64>>,
        n: u64,
    ) -> Result<bool> {
        let c = a.rec(n)?.clone();
        let author = b32j(&c, "author")?;
        let me = rosters
            .get(&(n - 1))
            .and_then(|r| r.get(u32j(&c, "leaf").ok()? as usize).cloned())
            .flatten();
        if me != Some((author, u64j(&c, "keyId")?)) {
            return Ok(false);
        }
        let admins = a.admins_at(n - 1)?;
        if admins.contains(&author) {
            return Ok(true);
        }
        if list(&c, "admins", b32)? != admins
            || list(&c, "adds", Add::from_json)?
                .iter()
                .any(|x| x.ua != author)
        {
            return Ok(false);
        }
        for x in list(&c, "removes", Remove::from_json)? {
            if x.ua == author {
                continue;
            }
            if let std::collections::btree_map::Entry::Vacant(v) = evidence.entry(x.ua) {
                v.insert(self.gone_evidence(sc, rd, a, &x.ua)?);
            }
            if !matches!(evidence.get(&x.ua), Some(Some(e)) if *e < n) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The epoch of a UA's signed `treeLeave` / `treeRemove` that the home holds, checked against this session, or `None`.
    fn gone_evidence(
        &self,
        sc: &TreeScope,
        rd: &mut dyn TreeReader,
        a: &Anchor,
        ua: &[u8; 32],
    ) -> Result<Option<u64>> {
        let g = rd.read(View::GoneOf(ua))?;
        let (kind, epoch) = (u64j(&g, "kind")?, u64j(&g, "epoch")?);
        if kind == 0 || !a.recs.contains_key(&epoch) {
            return Ok(None);
        }
        let ev = rd.read(View::GoneRecord(ua))?;
        let r = ev.get("record").cloned().unwrap_or(Value::Null);
        let ok = (|| -> Result<bool> {
            Ok(b32j(&r, "sessionId")? == a.sid
                && b32j(&r, "treeId")? == a.tree_id
                && b32j(&r, "epochId")? == at(&a.ids, epoch)?
                && if kind == 1 {
                    b32j(&r, "member")? == *ua
                } else {
                    list(&r, "members", b32)?.contains(ua)
                        && a.admins_at(epoch)?.contains(&b32j(&r, "admin")?)
                })
        })()
        .unwrap_or(false);
        if !ok {
            return Ok(None);
        }
        let (name, signer) = if kind == 1 {
            ("PqChatTreeLeave", b32j(&r, "member")?)
        } else {
            ("PqChatTreeRemove", b32j(&r, "admin")?)
        };
        verified(
            sc,
            rd,
            name,
            &r,
            &signer,
            ev.get("sig").ok_or(Error::Argument)?,
        )?;
        Ok(Some(epoch))
    }

    fn open_genesis(
        &self,
        sc: &TreeScope,
        a: &Anchor,
        dev: &TreeDevice,
        p: &Piece,
    ) -> Result<Opened> {
        let wrap = p.wrap.as_ref().ok_or(Error::Argument)?;
        let Some(joiner) = self.tree_unwrap(sc, dev.kem, wrap, &a.gctx, &a.sid) else {
            return Ok(not("opening failed"));
        };
        let (_, k) = schedule(sc, &joiner[..], &EpochFields::genesis(sc, &a.s0)?)?;
        let sealed = bytes(a.s0.get("sealedInfo").ok_or(Error::Argument)?)?;
        Ok(match open_info(sc, &k[..], &a.sid, &a.sid, &sealed) {
            Some(info) => Opened {
                state: State::Followed,
                k: Some(k),
                info: Some(info),
                derived: Vec::new(),
            },
            None => not("info does not open"),
        })
    }

    /// The tail of a commit's processing: the joiner, the Welcome when there is one, the schedule, the confirmation (C12).
    fn finish(
        &self,
        sc: &TreeScope,
        a: &Anchor,
        c: &Value,
        p: &Piece,
        dev: &TreeDevice,
        commit_secret: &[u8],
    ) -> Result<Opened> {
        let epoch_id = at(&a.ids, p.n)?;
        let joiner = joiner_secret(sc, commit_secret, &a.tree_id, &epoch_id)?;
        if let Some(w) = &p.wrap {
            match self.tree_unwrap(sc, dev.kem, w, &a.tree_id, &epoch_id) {
                Some(x) if *x == *joiner => {}
                _ => return Ok(not("welcome disagrees")),
            }
        }
        let (_, k) = schedule(sc, &joiner[..], &EpochFields::commit(sc, c)?)?;
        let sealed = bytes(c.get("sealedInfo").ok_or(Error::Argument)?)?;
        Ok(match open_info(sc, &k[..], &a.sid, &epoch_id, &sealed) {
            Some(info) => Opened {
                state: State::Followed,
                k: Some(k),
                info: Some(info),
                derived: Vec::new(),
            },
            None => not("info does not open"),
        })
    }

    /// Another member's commit: the one ciphertext over its leaf, upward with the key comparison (§10).
    #[allow(clippy::too_many_arguments)]
    fn others_commit(
        &self,
        sc: &TreeScope,
        a: &Anchor,
        dev: &TreeDevice,
        p: &Piece,
        c: &Value,
        leaf: u32,
        held: &BTreeMap<u32, KemKeyPair>,
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
            held.get(&t)
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

    /// Its own commit: `ps[0]` from the seed; reproduced is both tests, the node keys and the info (codex-r3-4), else the
    /// compromise warning, never "not followed" (R10, fable-r2-1).
    fn own_commit(
        &self,
        sc: &TreeScope,
        a: &Anchor,
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
    /// `(S, K)` of a joiner secret and an epoch's fields.
    pub fn vectors_tree_schedule(
        &self,
        sc: &TreeScope,
        joiner: &[u8],
        f: &EpochFields,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let (s, k) = schedule(sc, joiner, f)?;
        Ok((s.to_vec(), k.to_vec()))
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
