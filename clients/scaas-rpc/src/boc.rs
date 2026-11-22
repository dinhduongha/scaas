// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! A bounded reader of TON bags of cells (BoC, `serialized_boc#b5ee9c72`, one root) for the getter stacks of `ton`
//! (rpc T24.ton-seqno, spec §8.7 rule 4): at most [`CELLS_MAX`] cells, every cell at most 1023 bits and 4 references, each
//! reference to a later cell (no cycle), depth at most [`DEPTH_MAX`] (TON's own limit, counted without recursion), the cells'
//! size field exact and nothing after the cells but the CRC its flag announces; a cell with a level (a pruned branch, a Merkle
//! proof) or stored hashes is refused. No cell hash is computed (spec §8.7 rule 6) and the CRC is not checked (the stack is the
//! endpoint's word either way). Plus the one cell this crate writes: an `addr_std` slice as a getter's argument. UNAUDITED.
use std::sync::Arc;

/// The most cells a BoC may hold (the node adapter's bound, `boc_parse`).
pub const CELLS_MAX: usize = 4096;
/// The deepest cell tree read: TON's own limit (a leaf has depth 0).
pub const DEPTH_MAX: usize = 1024;

/// One cell: its data (`bits` long, the completion tag stripped), its references, whether it is exotic (a library cell).
#[derive(Debug, PartialEq)]
pub struct Cell {
    pub data: Vec<u8>,
    pub bits: usize,
    pub refs: Vec<Arc<Cell>>,
    pub exotic: bool,
}

impl Cell {
    /// Bit `k` of the data.
    fn bit(&self, k: usize) -> bool {
        self.data[k / 8] & (0x80 >> (k % 8)) != 0
    }

    /// `n` bits from bit `k`, big-endian (`n` at most 8).
    fn byte_at(&self, k: usize, n: usize) -> u8 {
        (0..n).fold(0, |a, j| (a << 1) | u8::from(self.bit(k + j)))
    }
}

/// A big-endian field of `b` (at most 8 bytes) at most `max`.
fn uint(b: &[u8], max: usize, what: &'static str) -> Result<usize, &'static str> {
    let v = b.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x));
    usize::try_from(v).ok().filter(|v| *v <= max).ok_or(what)
}

/// The BoC's root cell.
pub fn parse(b: &[u8]) -> Result<Arc<Cell>, &'static str> {
    let mut p = 0usize;
    let mut take = |n: usize| -> Result<&[u8], &'static str> {
        let s = b
            .get(p..p.checked_add(n).ok_or("BoC truncated")?)
            .ok_or("BoC truncated")?;
        p += n;
        Ok(s)
    };
    if take(4)? != [0xb5, 0xee, 0x9c, 0x72] {
        return Err("not a BoC");
    }
    let flags = take(1)?[0];
    let (has_idx, has_crc, size) = (flags & 0x80 != 0, flags & 0x40 != 0, usize::from(flags & 7));
    let off = usize::from(take(1)?[0]);
    if !(1..=4).contains(&size) || !(1..=8).contains(&off) {
        return Err("BoC header");
    }
    let cells = uint(take(size)?, CELLS_MAX, "BoC cell count")?;
    let roots = uint(take(size)?, cells, "BoC root count")?;
    let absent = uint(take(size)?, cells, "BoC absent count")?;
    let total = uint(take(off)?, b.len(), "BoC cells size")?;
    if cells == 0 || roots != 1 || absent != 0 {
        return Err("BoC counts");
    }
    let root = uint(take(size)?, cells - 1, "BoC root index")?;
    if has_idx {
        take(cells * off)?;
    }
    let mut raw = Vec::with_capacity(cells);
    let mut used = 0usize;
    for _ in 0..cells {
        let d = take(2)?;
        let (d1, d2) = (d[0], usize::from(d[1]));
        if d1 & 0xf0 != 0 {
            return Err("a BoC cell with a level or stored hashes");
        }
        let n = usize::from(d1 & 7);
        if n > 4 {
            return Err("a BoC cell with more than 4 references");
        }
        let mut data = take(d2.div_ceil(2))?.to_vec();
        let bits = if d2 % 2 == 1 {
            let last = data.last_mut().ok_or("a padded BoC cell without data")?;
            if *last == 0 {
                return Err("a BoC cell without its completion tag");
            }
            let tz = last.trailing_zeros() as usize;
            *last &= !(1u8 << tz);
            data.len() * 8 - tz - 1
        } else {
            data.len() * 8
        };
        let refs = (0..n)
            .map(|_| uint(take(size)?, cells - 1, "a BoC reference past the last cell"))
            .collect::<Result<Vec<_>, _>>()?;
        used += 2 + data.len() + n * size;
        raw.push((data, bits, refs, d1 & 8 != 0));
    }
    if used != total {
        return Err("BoC cells size");
    }
    if has_crc {
        take(4)?;
    }
    if p != b.len() {
        return Err("bytes after the BoC");
    }
    // the last cell first: every reference is to a later cell, already built, its depth known
    let mut built: Vec<Option<(Arc<Cell>, usize)>> = vec![None; cells];
    for (i, (data, bits, refs, exotic)) in raw.into_iter().enumerate().rev() {
        let mut depth = 0;
        let mut children = Vec::with_capacity(refs.len());
        for r in refs {
            // a reference to this cell or an earlier one (a cycle) finds no cell built
            let (c, d) = built[r]
                .clone()
                .ok_or("a BoC reference to an earlier cell")?;
            depth = depth.max(d + 1);
            children.push(c);
        }
        if depth > DEPTH_MAX {
            return Err("a BoC deeper than 1024");
        }
        built[i] = Some((
            Arc::new(Cell {
                data,
                bits,
                refs: children,
                exotic,
            }),
            depth,
        ));
    }
    built[root].take().map(|(c, _)| c).ok_or("BoC root")
}

/// The `addr_std` a cell holds alone (tag `10`, no anycast, workchain, 256-bit account: 267 bits, no reference), else none.
pub fn std_address(c: &Cell) -> Option<(i8, [u8; 32])> {
    if c.bits != 267 || !c.refs.is_empty() || c.exotic || c.byte_at(0, 3) != 0b100 {
        return None;
    }
    let wc = c.byte_at(3, 8) as i8;
    let mut h = [0u8; 32];
    for (k, b) in h.iter_mut().enumerate() {
        *b = c.byte_at(11 + 8 * k, 8);
    }
    Some((wc, h))
}

/// A one-cell BoC holding the `addr_std` of `wc:h` (a getter's slice argument): size 1, offsets 1, no index, no CRC.
pub fn address_slice(wc: i8, h: &[u8; 32]) -> Vec<u8> {
    // 267 bits `10 0 wc h` and the completion tag: 34 bytes
    let mut bits = [0u8; 34];
    let mut put = |k: usize, v: bool| {
        if v {
            bits[k / 8] |= 0x80 >> (k % 8);
        }
    };
    put(0, true);
    for j in 0..8 {
        put(3 + j, (wc as u8) & (0x80 >> j) != 0);
    }
    for (k, b) in h.iter().enumerate() {
        for j in 0..8 {
            put(11 + 8 * k + j, b & (0x80 >> j) != 0);
        }
    }
    put(267, true);
    let mut b = vec![0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 1, 1, 0, 36, 0, 0, 67];
    b.extend(bits);
    b
}
