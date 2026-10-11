//! Minimal Solidity `abi.encode` for static 32-byte words and dynamic `bytes` / `bytes[]`.

pub enum Tok {
    Word([u8; 32]),
    Bytes(Vec<u8>),
}

pub fn u256(v: u64) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[24..].copy_from_slice(&v.to_be_bytes());
    o
}

pub fn addr(a: &[u8; 20]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[12..].copy_from_slice(a);
    o
}

fn padded(b: &[u8]) -> Vec<u8> {
    let mut o = u256(b.len() as u64).to_vec();
    o.extend_from_slice(b);
    o.resize(32 + b.len().div_ceil(32) * 32, 0);
    o
}

pub fn encode(toks: &[Tok]) -> Vec<u8> {
    let mut head = Vec::with_capacity(32 * toks.len());
    let mut tail = Vec::new();
    for t in toks {
        match t {
            Tok::Word(w) => head.extend_from_slice(w),
            Tok::Bytes(b) => {
                head.extend_from_slice(&u256((32 * toks.len() + tail.len()) as u64));
                tail.extend(padded(b));
            }
        }
    }
    head.extend(tail);
    head
}

/// The `uint64` in the 32-byte word at `at`, `None` when out of range or wider.
pub fn word_u64(b: &[u8], at: usize) -> Option<u64> {
    word_at(b, at)
}

fn word_at(b: &[u8], at: usize) -> Option<u64> {
    let w = b.get(at..at.checked_add(32)?)?;
    if w[..24].iter().any(|&x| x != 0) {
        return None;
    }
    Some(u64::from_be_bytes(w[24..].try_into().unwrap()))
}

/// Return data of `accountState(bytes32)` (`IZetherToken.AccountState`, a dynamic tuple):
/// `([accC, accD, pendingC, pendingD], accSeq)`. `None` when malformed.
pub fn decode_account_state(ret: &[u8]) -> Option<([Vec<u8>; 4], u64)> {
    // Every word is RPC-controlled: all offset arithmetic is checked (review I6).
    let base = usize::try_from(word_at(ret, 0)?).ok()?;
    let field = |i: usize| -> Option<Vec<u8>> {
        let at = base.checked_add(usize::try_from(word_at(ret, base.checked_add(32 * i)?)?).ok()?)?;
        let len = usize::try_from(word_at(ret, at)?).ok()?;
        let start = at.checked_add(32)?;
        Some(ret.get(start..start.checked_add(len)?)?.to_vec())
    };
    Some(([field(0)?, field(1)?, field(2)?, field(3)?], word_at(ret, base.checked_add(128)?)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_state_roundtrip() {
        let pts = [vec![1u8; 64], vec![2; 64], vec![3; 64], vec![0; 64]];
        let mut toks: Vec<Tok> = pts.iter().cloned().map(Tok::Bytes).collect();
        toks.extend([7u64, 9, 4, 0, 1].map(|w| Tok::Word(u256(w))));
        let mut ret = u256(32).to_vec();
        ret.extend(encode(&toks));
        assert_eq!(decode_account_state(&ret), Some((pts, 7)));
        assert_eq!(decode_account_state(&ret[..ret.len() - 1]), None);
        // RPC-controlled words that would overflow an offset or length: None, never a panic (review I6).
        let mut evil = ret.clone();
        evil[320 + 24..352].copy_from_slice(&u64::MAX.to_be_bytes()); // length of accC (word 10)
        assert_eq!(decode_account_state(&evil), None);
        let mut evil = ret.clone();
        evil[24..32].copy_from_slice(&(u64::MAX - 8).to_be_bytes()); // tuple offset
        assert_eq!(decode_account_state(&evil), None);
    }

    #[test]
    fn matches_solidity_layout() {
        // abi.encode(bytes(hex"aabb"), uint256(7), bytes(""))
        let e = encode(&[Tok::Bytes(vec![0xaa, 0xbb]), Tok::Word(u256(7)), Tok::Bytes(vec![])]);
        let h = hex::encode(e);
        let want = [
            "0000000000000000000000000000000000000000000000000000000000000060",
            "0000000000000000000000000000000000000000000000000000000000000007",
            "00000000000000000000000000000000000000000000000000000000000000a0",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "aabb000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ]
        .concat();
        assert_eq!(h, want);
    }
}
