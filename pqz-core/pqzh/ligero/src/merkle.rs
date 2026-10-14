//! Keccak-256 binary Merkle tree over the n column leaves (padded with zero digests to a power of two) and its pruned
//! multiproof: level by level over the sorted opened indices, a sibling digest is sent only when it is not computable.

use sha3::{Digest, Keccak256};

pub type H = [u8; 32];

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
            let next = l.chunks(2).map(|c| keccak(&[&c[0], &c[1]])).collect();
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
pub fn root_from(mut cur: Vec<(usize, H)>, depth: usize, mut sib: impl FnMut() -> Option<H>) -> Option<H> {
    for _ in 0..depth {
        let mut next = Vec::with_capacity(cur.len());
        let mut i = 0;
        while i < cur.len() {
            let (x, h) = cur[i];
            if x % 2 == 0 && i + 1 < cur.len() && cur[i + 1].0 == x + 1 {
                next.push((x / 2, keccak(&[&h, &cur[i + 1].1])));
                i += 2;
            } else {
                let s = sib()?;
                next.push((x / 2, if x % 2 == 0 { keccak(&[&h, &s]) } else { keccak(&[&s, &h]) }));
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
        for idx in [vec![0usize], vec![3, 4, 5, 999], (0..n).step_by(7).collect::<Vec<_>>()] {
            let mp = t.multiproof(&idx);
            let mut it = mp.iter().copied();
            let r = root_from(idx.iter().map(|&i| (i, leaves[i])).collect(), depth(n), || it.next());
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
}
