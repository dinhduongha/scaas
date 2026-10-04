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

#[cfg(test)]
mod tests {
    use super::*;

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
