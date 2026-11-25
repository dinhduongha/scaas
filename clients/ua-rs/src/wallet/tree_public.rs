// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The public side of a TreeKEM session (`groupMode = 1`; spec docs/superpowers/specs/2026-11-23-pqchat-treekem.md §4, §6,
//! §8; plan T2, feature `app-core`): the tree math of RFC 9420 Appendix C, resolution, the filtered path, `ctTargets` and the
//! target that covers a leaf, `th`, a commit's Removes, Adds and path applied with the contract's refusals (the no-return
//! sets of C28, R14, R16), the record hashes, `treeId`, `genesisCtx` and the key admission check. No secret here: plain
//! functions over public bytes, as clientkeys `src/pqchat-tree.js`; held to `smartcontracts/vectors/pqchat/tree.json`.
//! The tree is app-agnostic (owner 2026-11-23): the records are hashed through a scope's `typed` (`tree::TreeScope`).
//! UNAUDITED.
use super::eip712::TypedData;
use super::{Error, Result};
use crate::keccak256;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// `used ≤ TREE_LEAVES_MAX` (owner, 2026-11-23).
pub const TREE_LEAVES_MAX: u32 = 512; // R8: 256 -> 512 (owner 2026-11-25), depth 9
/// The contract's other bounds of a commit (C10, C24; `PqGroupBase`, `PqGroupTree._treeBounds`): Adds plus Removes, the admin
/// list, the live leaves of one UA after the commit (D-5).
pub const TREE_CHANGES_MAX: usize = 20; // C10: 32 -> 20 (owner 2026-11-25)
pub const TREE_ADMINS_MAX: usize = 32;
pub const KEYS_PER_UA_MAX: usize = 8;
pub const ZERO: [u8; 32] = [0; 32];
const KEM_PK_LEN: usize = 1601;

/// A tree session's named refusals (spec §8, §10, §11): the contract's (`PqChat…`) and the client's (`Tree…`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeError {
    Shape,
    Leaf,
    KeyLive,
    RemovedKept,
    Return,
    KeyReturn,
    OwnKeyReturn,
    Targets,
    Parent,
    ModeEntry,
    /// bytes that fail a signed hash or a signature: refused at the read boundary, before any decapsulation (codex-r2-15)
    ReadCorrupted,
    GenesisLeaves,
    HeadRoot,
    Checkpoint,
    Conflict,
    Period,
    Roster,
    /// a fetched key that is not the one its hash entered the root with (codex-1)
    KeyHash,
    InfoSize,
    /// a node key derived from a path secret that is not the one the commit signed (`nodeKeyHashes`)
    KeyMismatch,
    /// a target whose secret this state does not hold
    NotHeld,
    /// a KEM key its registry record does not authenticate (spec §8 step 5, codex-1)
    KemRecord,
    /// a changed admin list with no admin that holds a live leaf after the commit (C24)
    Admins,
    /// a commit that is not plain by an author outside the head's admins (§9, C8)
    NotAdmin,
}

impl TreeError {
    pub fn code(&self) -> &'static str {
        match self {
            TreeError::Shape => "PqChatShape",
            TreeError::Leaf => "PqChatTreeLeaf",
            TreeError::KeyLive => "PqChatTreeKeyLive",
            TreeError::RemovedKept => "PqChatRemovedKept",
            TreeError::Return => "PqChatTreeReturn",
            TreeError::KeyReturn => "PqChatTreeKeyReturn",
            TreeError::OwnKeyReturn => "PqChatTreeOwnKeyReturn",
            TreeError::Targets => "PqChatTreeTargets",
            TreeError::Parent => "PqChatTreeParent",
            TreeError::ModeEntry => "PqChatModeEntry",
            TreeError::ReadCorrupted => "TreeReadCorrupted",
            TreeError::GenesisLeaves => "TreeGenesisLeaves",
            TreeError::HeadRoot => "TreeHeadRoot",
            TreeError::Checkpoint => "TreeCheckpoint",
            TreeError::Conflict => "TreeConflict",
            TreeError::Period => "TreePeriod",
            TreeError::Roster => "TreeRoster",
            TreeError::KeyHash => "TreeKeyHash",
            TreeError::InfoSize => "TreeInfoSize",
            TreeError::KeyMismatch => "TreeKeyMismatch",
            TreeError::NotHeld => "TreeNotHeld",
            TreeError::KemRecord => "TreeKemRecord",
            TreeError::Admins => "PqChatTreeAdmins",
            TreeError::NotAdmin => "PqChatNotAdmin",
        }
    }
}

pub(super) fn refuse<T>(e: TreeError) -> Result<T> {
    Err(Error::Tree(e))
}

// ------------------------------------------------------------------ RFC 9420 Appendix C (n = the number of leaves)

/// The count of trailing one bits of `x`.
pub fn level(x: u32) -> u32 {
    x.trailing_ones()
}
pub fn node_width(n: u32) -> u32 {
    if n == 0 {
        0
    } else {
        2 * (n - 1) + 1
    }
}
pub fn root(n: u32) -> u32 {
    if n <= 1 {
        0
    } else {
        (1u32 << (31 - node_width(n).leading_zeros())) - 1
    }
}
/// `None` for a leaf.
pub fn left(x: u32) -> Option<u32> {
    let k = level(x);
    (k > 0 && k < 31).then(|| x ^ (1 << (k - 1)))
}
pub fn right(x: u32) -> Option<u32> {
    let k = level(x);
    (k > 0 && k < 31).then(|| x ^ (3 << (k - 1)))
}
/// `None` for the root.
pub fn parent(x: u32, n: u32) -> Option<u32> {
    let k = level(x);
    if x == root(n) || k >= 30 {
        return None;
    }
    let b = (x >> (k + 1)) & 1;
    Some((x | (1 << k)) ^ (b << (k + 1)))
}
pub fn sibling(x: u32, n: u32) -> Option<u32> {
    let p = parent(x, n)?;
    if x < p {
        right(p)
    } else {
        left(p)
    }
}
/// The ancestors of `x` up to the root, the root included (empty for a node outside the tree).
pub fn direct_path(x: u32, n: u32) -> Vec<u32> {
    let (r, mut out, mut y) = (root(n), Vec::new(), x);
    while y != r && out.len() < 32 {
        match parent(y, n) {
            Some(p) => {
                out.push(p);
                y = p;
            }
            None => return Vec::new(),
        }
    }
    out
}
/// The sibling of `x` and of each node of its direct path but the root.
pub fn copath(x: u32, n: u32) -> Vec<u32> {
    let mut up = vec![x];
    up.extend(direct_path(x, n));
    up.pop();
    up.into_iter().filter_map(|y| sibling(y, n)).collect()
}

// ------------------------------------------------------------------ the tree

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub ua: [u8; 32],
    pub key_id: u64,
    pub kem_hash: [u8; 32],
}

/// A node: blank, a leaf, or a parent with its key's hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Blank,
    Leaf(Leaf),
    Parent([u8; 32]),
}

/// A tree and its no-return sets (C28, R14, R16; never cleared): `gone_ua` the UAs that left or were removed; the pair set
/// `gone_own_key` (per UA the `kemHash`es taken out of its leaves while it stayed a member); the session-wide `gone_key`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tree {
    pub leaves: u32,
    pub used: u32,
    pub nodes: Vec<Node>,
    pub gone_ua: BTreeSet<[u8; 32]>,
    pub gone_own_key: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
    pub gone_key: BTreeSet<[u8; 32]>,
}

/// A Remove of a commit (`TreeRemove`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remove {
    pub leaf: u32,
    pub ua: [u8; 32],
    pub key_id: u64,
}

/// An Add of a commit (`TreeAdd`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Add {
    pub leaf: u32,
    pub ua: [u8; 32],
    pub key_id: u64,
    pub via: [u8; 32],
    pub kem_hash: [u8; 32],
}

/// The author's leaf and a commit's Removes and Adds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Changes {
    pub author: [u8; 32],
    pub leaf: u32,
    pub key_id: u64,
    pub removes: Vec<Remove>,
    pub adds: Vec<Add>,
}

/// One step of a filtered path: the path node, its copath child and that child's resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathStep {
    pub node: u32,
    pub child: u32,
    pub targets: Vec<u32>,
}

/// The ciphertext of a commit that a leaf opens: its index in the list, the path level, the path node and the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cover {
    pub index: usize,
    pub level: usize,
    pub node: u32,
    pub target: u32,
}

/// A commit applied: the tree after it, its `ctTargets` and its root hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    pub tree: Tree,
    pub ct_targets: Vec<u32>,
    pub tree_hash: [u8; 32],
}

fn size_for(used: u32) -> u32 {
    used.max(1).next_power_of_two()
}

fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    if let Some(t) = w.get_mut(24..) {
        t.copy_from_slice(&v.to_be_bytes());
    }
    w
}

impl Tree {
    pub fn node(&self, x: u32) -> &Node {
        self.nodes.get(x as usize).unwrap_or(&Node::Blank)
    }
    fn set(&mut self, x: u32, n: Node) {
        if let Some(s) = self.nodes.get_mut(x as usize) {
            *s = n;
        }
    }
    pub fn leaf(&self, i: u32) -> Option<&Leaf> {
        match self.node(i.checked_mul(2)?) {
            Node::Leaf(l) => Some(l),
            _ => None,
        }
    }
    fn live(&self) -> impl Iterator<Item = &Leaf> {
        self.nodes.iter().step_by(2).filter_map(|n| match n {
            Node::Leaf(l) => Some(l),
            _ => None,
        })
    }

    /// The cold tree of a session (§8): leaf `i` = `members[i]` with its registry `kemHash`, every parent blank.
    pub fn cold(members: &[Leaf]) -> Result<Tree> {
        let used = u32::try_from(members.len()).map_err(|_| Error::Tree(TreeError::Shape))?;
        if used > TREE_LEAVES_MAX {
            return refuse(TreeError::Shape);
        }
        let leaves = size_for(used);
        let mut t = Tree {
            leaves,
            used,
            nodes: vec![Node::Blank; node_width(leaves) as usize],
            ..Tree::default()
        };
        for (i, m) in (0u32..).zip(members) {
            if t.live().any(|n| n.kem_hash == m.kem_hash) {
                return refuse(TreeError::KeyLive);
            }
            t.set(2 * i, Node::Leaf(m.clone()));
        }
        Ok(t)
    }

    /// Marks UAs `gone` (a landed `treeLeave` or `treeRemove`, C28).
    pub fn mark_gone(&mut self, uas: &[[u8; 32]]) {
        self.gone_ua.extend(uas.iter().copied());
    }

    /// RFC 9420 §4.1.2 without unmerged leaves, in ascending node index.
    pub fn resolution(&self, x: u32) -> Vec<u32> {
        if *self.node(x) != Node::Blank {
            return vec![x];
        }
        match (left(x), right(x)) {
            (Some(l), Some(r)) => {
                let mut v = self.resolution(l);
                v.extend(self.resolution(r));
                v
            }
            _ => Vec::new(),
        }
    }

    /// The filtered path of leaf `leaf`: each ancestor whose copath child resolves to something, upward.
    pub fn filtered_path(&self, leaf: u32) -> Vec<PathStep> {
        let mut out = Vec::new();
        let mut below = 2 * leaf;
        for node in direct_path(below, self.leaves) {
            if let Some(child) = sibling(below, self.leaves) {
                let targets = self.resolution(child);
                if !targets.is_empty() {
                    out.push(PathStep {
                        node,
                        child,
                        targets,
                    });
                }
            }
            below = node;
        }
        out
    }

    /// The targets of a commit's path ciphertexts: by path level upward, then by ascending target.
    pub fn ct_targets(&self, leaf: u32) -> Vec<u32> {
        self.filtered_path(leaf)
            .into_iter()
            .flat_map(|p| p.targets)
            .collect()
    }

    /// The ciphertext of `author`'s commit that leaf `leaf` opens; `None` for the author itself and for a blank leaf.
    pub fn cover_of(&self, author: u32, leaf: u32) -> Option<Cover> {
        if leaf == author || self.leaf(leaf).is_none() {
            return None;
        }
        let mut mine = direct_path(2 * leaf, self.leaves);
        mine.push(2 * leaf);
        let mut index = 0;
        for (k, p) in self.filtered_path(author).into_iter().enumerate() {
            for target in p.targets {
                if mine.contains(&target) {
                    return Some(Cover {
                        index,
                        level: k,
                        node: p.node,
                        target,
                    });
                }
                index += 1;
            }
        }
        None
    }

    /// Every node's `th` (RFC 9420 §7.8, typed: `TreeLeaf`, `TreeParent`; an empty subtree 0).
    pub fn node_hashes(&self) -> Vec<[u8; 32]> {
        let mut h = vec![ZERO; node_width(self.leaves) as usize];
        if !h.is_empty() {
            self.fill(root(self.leaves), &mut h);
        }
        h
    }
    fn fill(&self, x: u32, h: &mut [[u8; 32]]) -> [u8; 32] {
        let v = match (left(x), right(x)) {
            (Some(l), Some(r)) => {
                let (hl, hr) = (self.fill(l, h), self.fill(r, h));
                match self.node(x) {
                    Node::Blank if hl == ZERO && hr == ZERO => ZERO,
                    Node::Parent(k) => parent_hash(k, &hl, &hr),
                    _ => parent_hash(&ZERO, &hl, &hr),
                }
            }
            _ => match self.node(x) {
                Node::Leaf(l) => leaf_hash(x / 2, l),
                _ => ZERO,
            },
        };
        if let Some(s) = h.get_mut(x as usize) {
            *s = v;
        }
        v
    }
    pub fn tree_hash(&self) -> [u8; 32] {
        if self.leaves == 0 {
            return ZERO;
        }
        self.node_hashes()
            .get(root(self.leaves) as usize)
            .copied()
            .unwrap_or(ZERO)
    }

    fn blank_path(&mut self, x: u32) {
        for y in direct_path(x, self.leaves) {
            self.set(y, Node::Blank);
        }
    }

    /// The Removes and Adds of a commit with the refusals of §8: the tree after them, its path not yet set.
    fn apply_changes(&self, c: &Changes) -> Result<Tree> {
        if c.removes.len() + c.adds.len() > TREE_CHANGES_MAX {
            return refuse(TreeError::Shape);
        }
        let mut t = self.clone();
        match t.leaf(c.leaf) {
            Some(me) if c.leaf < t.leaves && me.ua == c.author && me.key_id == c.key_id => {
                if t.gone_ua.contains(&me.ua) {
                    return refuse(TreeError::RemovedKept);
                }
            }
            _ => return refuse(TreeError::Leaf),
        }
        let mut out = Vec::new();
        for r in &c.removes {
            let n = match t.leaf(r.leaf) {
                Some(n)
                    if r.leaf != c.leaf
                        && r.leaf < t.leaves
                        && n.ua == r.ua
                        && n.key_id == r.key_id =>
                {
                    n.clone()
                }
                _ => return refuse(TreeError::Leaf),
            };
            t.set(2 * r.leaf, Node::Blank);
            t.blank_path(2 * r.leaf);
            out.push(n);
        }
        for a in &c.adds {
            if t.gone_ua.contains(&a.ua) {
                return refuse(TreeError::Return);
            }
            if t.live().any(|n| n.kem_hash == a.kem_hash) {
                return refuse(TreeError::KeyLive);
            }
            if a.leaf > t.used
                || *t.node(2 * a.leaf) != Node::Blank
                || (a.leaf == t.used && t.used == TREE_LEAVES_MAX)
            {
                return refuse(TreeError::Leaf);
            }
            if a.leaf == t.used {
                t.used += 1;
                if t.used > t.leaves {
                    t.leaves *= 2;
                    t.nodes.resize(node_width(t.leaves) as usize, Node::Blank);
                }
            }
            t.set(
                2 * a.leaf,
                Node::Leaf(Leaf {
                    ua: a.ua,
                    key_id: a.key_id,
                    kem_hash: a.kem_hash,
                }),
            );
            t.blank_path(2 * a.leaf);
        }
        // on the tree after the Adds (fable-r3-4): a UA left with no leaf is gone; each removed key at its level (R16)
        for n in &out {
            if !t.live().any(|m| m.ua == n.ua) {
                t.gone_ua.insert(n.ua);
            }
        }
        for n in &out {
            if t.gone_ua.contains(&n.ua) {
                t.gone_key.insert(n.kem_hash);
            } else {
                t.gone_own_key.entry(n.ua).or_default().insert(n.kem_hash);
            }
        }
        if t.live().any(|n| t.gone_ua.contains(&n.ua)) {
            return refuse(TreeError::RemovedKept);
        }
        if c.adds
            .iter()
            .any(|a| t.live().filter(|n| n.ua == a.ua).count() > KEYS_PER_UA_MAX)
        {
            return refuse(TreeError::Shape);
        }
        for a in &c.adds {
            if t.gone_key.contains(&a.kem_hash) {
                return refuse(TreeError::KeyReturn);
            }
            if t.gone_own_key
                .get(&a.ua)
                .is_some_and(|s| s.contains(&a.kem_hash))
            {
                return refuse(TreeError::OwnKeyReturn);
            }
        }
        Ok(t)
    }

    /// The filtered path of the author's leaf on the tree after `c`'s Removes and Adds: what its commit keys.
    pub fn filtered_path_after(&self, c: &Changes) -> Result<Vec<PathStep>> {
        Ok(self.apply_changes(c)?.filtered_path(c.leaf))
    }

    /// A commit applied in the contract's order (§8): Removes, Adds, the `gone` UAs after the Adds, the author's filtered
    /// path keyed by `node_key_hashes` (its length the walk's, `PqChatTreeTargets`), the rest of its direct path blanked.
    pub fn apply_commit(&self, c: &Changes, node_key_hashes: &[[u8; 32]]) -> Result<Applied> {
        let mut t = self.apply_changes(c)?;
        let p = t.filtered_path(c.leaf);
        if p.len() != node_key_hashes.len() {
            return refuse(TreeError::Targets);
        }
        t.blank_path(2 * c.leaf);
        for (q, k) in p.iter().zip(node_key_hashes) {
            t.set(q.node, Node::Parent(*k));
        }
        let tree_hash = t.tree_hash();
        Ok(Applied {
            ct_targets: p.into_iter().flat_map(|q| q.targets).collect(),
            tree: t,
            tree_hash,
        })
    }

    /// The admin list and the rights of a commit `c` (§8, §9; `PqGroupTree._walkJudge`, `_keepsAdmins`) on this tree (the
    /// head's, its `gone_ua` the UAs gone there) and `after` ([`Tree::apply_commit`]'s): `admins` strictly sorted, at most
    /// [`TREE_ADMINS_MAX`] (`PqChatShape`), none gone or left with no leaf by the commit (`PqChatRemovedKept`); a list other
    /// than the head's less those UAs keeps one admin with a live leaf (`PqChatTreeAdmins`); the commit is plain (it keeps the
    /// admins in that sense, adds only its author's UA, removes only its author's leaves or a gone UA's) or its author is in
    /// `head_admins` (`PqChatNotAdmin`, C8). Dropping a gone admin is plain (F-2, E-2).
    pub fn judge_commit(
        &self,
        after: &Tree,
        c: &Changes,
        admins: &[[u8; 32]],
        head_admins: &[[u8; 32]],
    ) -> Result<()> {
        if admins.len() > TREE_ADMINS_MAX || admins.windows(2).any(|w| w.first() >= w.get(1)) {
            return refuse(TreeError::Shape);
        }
        let out = |u: &[u8; 32]| after.gone_ua.contains(u);
        if admins.iter().any(out) {
            return refuse(TreeError::RemovedKept);
        }
        let kept: Vec<[u8; 32]> = head_admins.iter().filter(|x| !out(x)).copied().collect();
        let keeps = admins == kept.as_slice();
        if !keeps && !admins.iter().any(|x| after.live().any(|n| n.ua == *x)) {
            return refuse(TreeError::Admins);
        }
        let plain = keeps
            && c.adds.iter().all(|x| x.ua == c.author)
            && c.removes
                .iter()
                .all(|x| x.ua == c.author || self.gone_ua.contains(&x.ua));
        if !plain && !head_admins.contains(&c.author) {
            return refuse(TreeError::NotAdmin);
        }
        Ok(())
    }

    /// A tree from the JSON form of `tree.json` (`leaves`, `used`, `nodes`, the no-return sets), bounded before it is used
    /// (B-5): `leaves` a power of two at most [`TREE_LEAVES_MAX`] (or 0 with no node), `used ≤ leaves`, one node per position.
    pub fn from_json(j: &Value) -> Result<Tree> {
        let (leaves, used) = (u32j(j, "leaves")?, u32j(j, "used")?);
        let width = j.get("nodes").and_then(Value::as_array).map(Vec::len);
        if !(leaves == 0 || leaves.is_power_of_two() && leaves <= TREE_LEAVES_MAX)
            || used > leaves
            || width != Some(node_width(leaves) as usize)
        {
            return refuse(TreeError::Shape);
        }
        let nodes = j
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or(Error::Argument)?
            .iter()
            .map(|n| {
                if n.is_null() {
                    Ok(Node::Blank)
                } else if let Some(k) = n.get("keyHash") {
                    Ok(Node::Parent(b32(k)?))
                } else {
                    Ok(Node::Leaf(Leaf::from_json(n)?))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let set = |k: &str| -> Result<BTreeSet<[u8; 32]>> {
            j.get(k)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(b32)
                .collect()
        };
        let mut gone_own_key = BTreeMap::new();
        for (ua, ks) in j
            .get("goneOwnKey")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let ks = ks
                .as_array()
                .into_iter()
                .flatten()
                .map(b32)
                .collect::<Result<_>>()?;
            gone_own_key.insert(b32(&json!(ua))?, ks);
        }
        Ok(Tree {
            leaves,
            used,
            nodes,
            gone_ua: set("goneUa")?,
            gone_own_key,
            gone_key: set("goneKey")?,
        })
    }

    /// The JSON form of `tree.json`, the sets sorted.
    pub fn to_json(&self) -> Value {
        let set = |s: &BTreeSet<[u8; 32]>| s.iter().map(|x| json!(hx(x))).collect::<Vec<_>>();
        json!({
            "leaves": self.leaves,
            "used": self.used,
            "nodes": self.nodes.iter().map(|n| match n {
                Node::Blank => Value::Null,
                Node::Leaf(l) => l.to_json(),
                Node::Parent(k) => json!({"keyHash": hx(k)}),
            }).collect::<Vec<_>>(),
            "goneUa": set(&self.gone_ua),
            "goneOwnKey": self.gone_own_key.iter().map(|(u, ks)| (hx(u), json!(set(ks)))).collect::<serde_json::Map<_, _>>(),
            "goneKey": set(&self.gone_key),
        })
    }
}

/// `hashStruct(TreeLeaf)` of leaf index `leaf`.
pub fn leaf_hash(leaf: u32, l: &Leaf) -> [u8; 32] {
    let th = keccak256(b"TreeLeaf(uint32 leaf,bytes32 ua,uint64 keyId,bytes32 kemHash)");
    keccak256(
        &[
            &th[..],
            &word(leaf.into()),
            &l.ua,
            &word(l.key_id),
            &l.kem_hash,
        ]
        .concat(),
    )
}
/// `hashStruct(TreeParent)`.
pub fn parent_hash(key_hash: &[u8; 32], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let th = keccak256(b"TreeParent(bytes32 keyHash,bytes32 left,bytes32 right)");
    keccak256(&[&th[..], key_hash, left, right].concat())
}

/// `keccak256(abi.encodePacked(ctTargets))`, each entry 4 B big-endian (§5, §7).
pub fn ct_targets_hash(list: &[u32]) -> [u8; 32] {
    keccak256(
        &list
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect::<Vec<_>>(),
    )
}

// ------------------------------------------------------------------ JSON forms

pub(super) fn hx(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + 2 * b.len());
    s.push_str("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
pub(super) fn bytes(v: &Value) -> Result<Vec<u8>> {
    v.as_str()
        .and_then(super::eip712::from_hex)
        .ok_or(Error::Argument)
}
pub(super) fn b32(v: &Value) -> Result<[u8; 32]> {
    bytes(v)?.try_into().map_err(|_| Error::Argument)
}
pub(super) fn u64j(v: &Value, k: &str) -> Result<u64> {
    v.get(k).and_then(Value::as_u64).ok_or(Error::Argument)
}
pub(super) fn u32j(v: &Value, k: &str) -> Result<u32> {
    u32::try_from(u64j(v, k)?).map_err(|_| Error::Argument)
}
pub(super) fn b32j(v: &Value, k: &str) -> Result<[u8; 32]> {
    b32(v.get(k).ok_or(Error::Argument)?)
}
pub(super) fn list<T>(v: &Value, k: &str, f: impl Fn(&Value) -> Result<T>) -> Result<Vec<T>> {
    v.get(k)
        .and_then(Value::as_array)
        .ok_or(Error::Argument)?
        .iter()
        .map(f)
        .collect()
}

impl Leaf {
    pub fn from_json(v: &Value) -> Result<Leaf> {
        Ok(Leaf {
            ua: b32j(v, "ua")?,
            key_id: u64j(v, "keyId")?,
            kem_hash: b32j(v, "kemHash")?,
        })
    }
    pub fn to_json(&self) -> Value {
        json!({"ua": hx(&self.ua), "keyId": self.key_id, "kemHash": hx(&self.kem_hash)})
    }
}
impl Remove {
    pub fn from_json(v: &Value) -> Result<Remove> {
        Ok(Remove {
            leaf: u32j(v, "leaf")?,
            ua: b32j(v, "ua")?,
            key_id: u64j(v, "keyId")?,
        })
    }
    pub fn to_json(&self) -> Value {
        json!({"leaf": self.leaf, "ua": hx(&self.ua), "keyId": self.key_id})
    }
}
impl Add {
    pub fn from_json(v: &Value) -> Result<Add> {
        Ok(Add {
            leaf: u32j(v, "leaf")?,
            ua: b32j(v, "ua")?,
            key_id: u64j(v, "keyId")?,
            via: b32j(v, "via")?,
            kem_hash: b32j(v, "kemHash")?,
        })
    }
    pub fn to_json(&self) -> Value {
        json!({"leaf": self.leaf, "ua": hx(&self.ua), "keyId": self.key_id, "via": hx(&self.via), "kemHash": hx(&self.kem_hash)})
    }
}
impl Changes {
    /// The changes of a commit record (or of a `tree.json` commit row): `author`, `leaf`, `keyId`, `removes`, `adds`.
    pub fn from_json(v: &Value) -> Result<Changes> {
        Ok(Changes {
            author: b32j(v, "author")?,
            leaf: u32j(v, "leaf")?,
            key_id: u64j(v, "keyId")?,
            removes: list(v, "removes", Remove::from_json)?,
            adds: list(v, "adds", Add::from_json)?,
        })
    }
}

// ------------------------------------------------------------------ records (§6), treeId and genesisCtx (§5)

/// A record's typed data: the scope's builder (`PqChat`'s [`super::pqchat::typed`] for its instance).
pub type Typed = fn(&str, Value) -> Result<TypedData>;

pub fn struct_hash(typed: Typed, name: &str, v: &Value) -> Result<[u8; 32]> {
    typed(name, v.clone())?.struct_hash()
}
/// The EIP-712 hash of an array of structs: keccak256 of their struct hashes (`hash(removes)`, `hash(adds)`).
pub fn array_hash(typed: Typed, name: &str, items: &[Value]) -> Result<[u8; 32]> {
    let mut all = Vec::with_capacity(32 * items.len());
    for x in items {
        all.extend(struct_hash(typed, name, x)?);
    }
    Ok(keccak256(&all))
}
/// `ctListHash = hashStruct(PathList)`; of two empty arrays when `ctCount` is 0 (codex-r2-14).
pub fn path_list_hash(
    typed: Typed,
    ct_targets: &[u32],
    ct_hashes: &[[u8; 32]],
) -> Result<[u8; 32]> {
    let hs: Vec<String> = ct_hashes.iter().map(|h| hx(h)).collect();
    struct_hash(
        typed,
        "PathList",
        &json!({"ctTargets": ct_targets, "ctHashes": hs}),
    )
}
/// `treeId = hashStruct(PqChatSession)` of the signed session record (C16).
pub fn tree_id(typed: Typed, session: &Value) -> Result<[u8; 32]> {
    struct_hash(typed, "PqChatSession", session)
}
/// The `TreeGenesis` fields: the session's without `wrapHashes` and `sealedInfo` (C29).
pub const GENESIS_FIELDS: [&str; 7] = [
    "creator",
    "nonce",
    "homeChain",
    "homeChatContract",
    "admins",
    "members",
    "groupMode",
];
/// `genesisCtx = hashStruct(TreeGenesis)`, each field given (`PqChatShape` otherwise).
pub fn genesis_ctx(typed: Typed, session: &Value) -> Result<[u8; 32]> {
    let mut g = serde_json::Map::new();
    for f in GENESIS_FIELDS {
        let v = session.get(f).ok_or(Error::Tree(TreeError::Shape))?;
        g.insert(f.into(), v.clone());
    }
    struct_hash(typed, "TreeGenesis", &Value::Object(g))
}

// ------------------------------------------------------------------ the key admission check (§8, C19, C32)

/// `p = 2^255 − 19`, little-endian.
const P25519: [u8; 32] = {
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};
/// The small-order X25519 values that are canonical: 0, 1, the two of order 8, p − 1 (little-endian).
const SMALL_ORDER: [[u8; 32]; 5] = [
    [0; 32],
    {
        let mut o = [0; 32];
        o[0] = 1;
        o
    },
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    {
        let mut p = [0xff; 32];
        p[0] = 0xec;
        p[31] = 0x7f;
        p
    },
];

/// The public admission check of a scheme-1 `kemPk` (the contract's, clientkeys' and this one): scheme byte 1, 1,601 B,
/// every `ek` coefficient below 3,329 (P14), `pk_X` canonical (bit 255 clear, below p) and of none of the five small orders.
/// `None` when admitted, else the reason (the names of `tree.json`'s `admission` rows). A rule on bytes only (R15).
pub fn kem_admission(kem_pk: &[u8]) -> Option<&'static str> {
    if kem_pk.first() != Some(&1) {
        return Some("wrong scheme byte");
    }
    if kem_pk.len() != KEM_PK_LEN {
        return Some("wrong length");
    }
    let Some(ek) = kem_pk.get(1..1569) else {
        return Some("wrong length");
    };
    if !super::kem::ek_modulus_ok(ek) {
        return Some("modulus check");
    }
    let Some(x) = kem_pk
        .get(1569..)
        .and_then(|x| <[u8; 32]>::try_from(x).ok())
    else {
        return Some("wrong length");
    };
    if x[31] & 0x80 != 0 {
        return Some("pkX bit 255");
    }
    // little-endian compare from the top byte
    if x.iter().rev().cmp(P25519.iter().rev()) != std::cmp::Ordering::Less {
        return Some("pkX not below p");
    }
    if SMALL_ORDER.contains(&x) {
        return Some("pkX small order");
    }
    None
}
/// [`kem_admission`] as a refusal: `KemCheck`.
pub fn admit_kem_key(kem_pk: &[u8]) -> Result<()> {
    match kem_admission(kem_pk) {
        None => Ok(()),
        Some(_) => Err(Error::KemCheck),
    }
}

/// A UA's KEM key as the caller read it from the registry (spec §8 step 5, codex-1; the reads are the SDK's, none here): a
/// version above 0 is `kemKeyAt(ua, version)` with its kept signature and the UA's registration key; version 0 is
/// `registrationOf(ua)` (its `attrs` holding the key in full or as the hash commit, its `pop`) with `kemKeyAt(ua, 0)`'s key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KemRecord {
    Version {
        kind: u16,
        key_data: Vec<u8>,
        kem_pk: Vec<u8>,
        sig: Vec<u8>,
    },
    Registration {
        kind: u16,
        key_data: Vec<u8>,
        attrs: crate::ua_portable::UAAttrs,
        pop: Vec<u8>,
        kem_pk: Vec<u8>,
    },
}

impl KemRecord {
    /// The key the record names, not yet authenticated ([`kem_record_key`] is the check).
    pub fn kem_pk(&self) -> &[u8] {
        match self {
            KemRecord::Version { kem_pk, .. } | KemRecord::Registration { kem_pk, .. } => kem_pk,
        }
    }
}

/// The key of `(ua, version)` once its registry record authenticates it, in one call (spec §8 step 5): the registration key
/// data hashes to `ua`; a version above 0 by its kept signature over `kemRecordDigest(ua, version, kemPk)` under that key; version
/// 0 by the registration's proof of possession over its committed key (in full, or `kemPkHash`, the key hashing to it).
/// Anything else, a record of another form than its version included: `TreeKemRecord`. Only a key that passed reaches an
/// encapsulation (the admission check follows, `KemCheck`).
pub fn kem_record_key(ua: &[u8; 32], version: u64, rec: &KemRecord) -> Result<Vec<u8>> {
    let none = |_: [u8; 32]| None;
    let ok = match rec {
        KemRecord::Version {
            kind,
            key_data,
            kem_pk,
            sig,
        } => {
            // version 0 is the registration's: `KemVersion` there
            crate::ua_portable::check_kem_record(*kind, key_data, ua, version, kem_pk, sig, &none)
                .is_ok()
        }
        KemRecord::Registration {
            kind,
            key_data,
            attrs,
            pop,
            kem_pk,
        } => {
            let committed = if attrs.kem_pk_hash == ZERO {
                attrs.kem.kem_pk() == *kem_pk
            } else {
                keccak256(kem_pk) == attrs.kem_pk_hash
            };
            version == 0
                && !kem_pk.is_empty()
                && committed
                && crate::derive_ua(*kind, key_data, false).ok() == Some(*ua)
                && crate::ua_portable::check_registration(*kind, key_data, attrs, pop, &[], &none)
                    .is_ok()
        }
    };
    if !ok {
        return refuse(TreeError::KemRecord);
    }
    Ok(rec.kem_pk().to_vec())
}
