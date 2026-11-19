//! Keccak-256 binary Merkle tree over the n column leaves (padded with zero digests to a power of two) and its pruned
//! multiproof: level by level over the sorted opened indices, a sibling digest is sent only when it is not computable.
//!
//! Role tags (three-key round, K3-4b, T-35 / Fable 3w u2-7; PQZH_ID v4): every Keccak-256 input of the protocol starts
//! with one byte naming its role, so no two roles ever hash the same input: a leaf `TAG_LEAF ‖ salt ‖ column`, a node
//! `TAG_NODE ‖ left ‖ right`, and in the transcript an absorb `TAG_ABSORB ‖ state ‖ data`, a squeeze `TAG_SQUEEZE ‖
//! state ‖ be64(counter)`, the PoW `TAG_POW ‖ state ‖ be64(nonce)`. The transcript seed starts with the ASCII label
//! (`'S'`), no tag value.

use sha3::{Digest, Keccak256};

pub type H = [u8; 32];

pub const TAG_LEAF: u8 = 0;
pub const TAG_NODE: u8 = 1;
pub const TAG_ABSORB: u8 = 2;
pub const TAG_SQUEEZE: u8 = 3;
pub const TAG_POW: u8 = 4;

/// a column leaf: keccak(TAG_LEAF ‖ salt ‖ column bytes)
pub fn leaf(salt: &[u8], col: &[u8]) -> H {
    keccak(&[&[TAG_LEAF], salt, col])
}

/// an inner node: keccak(TAG_NODE ‖ left ‖ right)
pub fn node(l: &H, r: &H) -> H {
    keccak(&[&[TAG_NODE], l, r])
}

pub fn keccak(parts: &[&[u8]]) -> H {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub struct Tree {
    levels: Vec<Vec<H>>,
}

pub fn depth(n: usize) -> usize {
    n.next_power_of_two().trailing_zeros() as usize
}

impl Tree {
    pub fn new(mut leaves: Vec<H>) -> Tree {
        leaves.resize(leaves.len().next_power_of_two(), [0; 32]);
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let l = levels.last().unwrap();
            let next = l.chunks(2).map(|c| node(&c[0], &c[1])).collect();
            levels.push(next);
        }
        Tree { levels }
    }
    pub fn root(&self) -> H {
        self.levels.last().unwrap()[0]
    }
    /// sibling digests for the sorted distinct indices, in the verifier's consumption order
    pub fn multiproof(&self, idx: &[usize]) -> Vec<H> {
        let mut out = Vec::new();
        let mut cur: Vec<usize> = idx.to_vec();
        for l in &self.levels[..self.levels.len() - 1] {
            let mut next = Vec::new();
            let mut i = 0;
            while i < cur.len() {
                let x = cur[i];
                if x % 2 == 0 && i + 1 < cur.len() && cur[i + 1] == x + 1 {
                    i += 2;
                } else {
                    out.push(l[x ^ 1]);
                    i += 1;
                }
                next.push(x / 2);
            }
            cur = next;
        }
        out
    }
}

/// recompute the root from (index, leaf) pairs (sorted, distinct) and sibling digests taken from `sib`
pub fn root_from(
    mut cur: Vec<(usize, H)>,
    depth: usize,
    mut sib: impl FnMut() -> Option<H>,
) -> Option<H> {
    for _ in 0..depth {
        let mut next = Vec::with_capacity(cur.len());
        let mut i = 0;
        while i < cur.len() {
            let (x, h) = cur[i];
            if x % 2 == 0 && i + 1 < cur.len() && cur[i + 1].0 == x + 1 {
                next.push((x / 2, node(&h, &cur[i + 1].1)));
                i += 2;
            } else {
                let s = sib()?;
                next.push((
                    x / 2,
                    if x % 2 == 0 {
                        node(&h, &s)
                    } else {
                        node(&s, &h)
                    },
                ));
                i += 1;
            }
        }
        cur = next;
    }
    (cur.len() == 1 && cur[0].0 == 0).then_some(cur[0].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiproof_roundtrip() {
        let n = 1000;
        let leaves: Vec<H> = (0..n as u32).map(|i| keccak(&[&i.to_be_bytes()])).collect();
        let t = Tree::new(leaves.clone());
        for idx in [
            vec![0usize],
            vec![3, 4, 5, 999],
            (0..n).step_by(7).collect::<Vec<_>>(),
        ] {
            let mp = t.multiproof(&idx);
            let mut it = mp.iter().copied();
            let r = root_from(
                idx.iter().map(|&i| (i, leaves[i])).collect(),
                depth(n),
                || it.next(),
            );
            assert_eq!(r, Some(t.root()));
            assert!(it.next().is_none());
            let mut bad = leaves[idx[0]];
            bad[0] ^= 1;
            let mut it = mp.iter().copied();
            let mut v: Vec<(usize, H)> = idx.iter().map(|&i| (i, leaves[i])).collect();
            v[0].1 = bad;
            assert_ne!(root_from(v, depth(n), || it.next()), Some(t.root()));
        }
    }

    /// T-35: a node is not the untagged hash of its children, nor the transcript's absorb of them, nor a leaf of the same
    /// bytes; the root of two leaves is `TAG_NODE ‖ l ‖ r`'s hash (fails if the tag is dropped or shared)
    #[test]
    fn role_tags_separate_node_leaf_absorb() {
        let (l, r) = (keccak(&[b"l"]), keccak(&[b"r"]));
        let t = Tree::new(vec![l, r]);
        let mut pre = vec![TAG_NODE];
        pre.extend_from_slice(&l);
        pre.extend_from_slice(&r);
        assert_eq!(t.root(), keccak(&[&pre]));
        assert_ne!(t.root(), keccak(&[&l, &r]));
        assert_ne!(t.root(), keccak(&[&[TAG_ABSORB], &l, &r]));
        assert_ne!(t.root(), leaf(&l, &r));
        let tags = [TAG_LEAF, TAG_NODE, TAG_ABSORB, TAG_SQUEEZE, TAG_POW];
        assert!(
            tags.iter()
                .enumerate()
                .all(|(i, a)| tags[i + 1..].iter().all(|b| a != b))
                && !tags.contains(&b'S')
        );
    }
}
