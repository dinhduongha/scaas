//! Key-data validation (accounts.md §1.6 "Validation at registration"): the unique canonical encoding of a valid key or
//! structure, else `UAError::KeyData`. Never panics: every length is checked before it is sliced.
use crate::{in_native_space, is_member, is_native, kind_info, Result, UAError};
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::{BigInteger, PrimeField, Zero};

const SECP_N: [u8; 32] = hex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const BN_R: [u8; 32] = hex32("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}
const fn nibble(c: u8) -> u8 {
    if c <= b'9' { c - b'0' } else { c - b'a' + 10 }
}

fn need(ok: bool, reason: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(UAError::KeyData(reason)) }
}

/// Big-endian bytes (exactly the field's width) → the element, `None` unless canonical (< modulus).
fn fe<F: PrimeField>(b: &[u8]) -> Option<F> {
    let f = F::from_be_bytes_mod_order(b);
    (f.into_bigint().to_bytes_be() == b).then_some(f)
}

fn on_curve_in_subgroup<P: SWCurveConfig>(p: &Affine<P>) -> Result<()> {
    need(p.is_on_curve(), "curve")?;
    need(p.is_in_correct_subgroup_assuming_on_curve(), "subgroup")
}

fn secp_compressed(b: &[u8]) -> Result<()> {
    need(b.len() == 33 && (b[0] == 2 || b[0] == 3), "prefix")?;
    need(k256::PublicKey::from_sec1_bytes(b).is_ok(), "curve")
}

fn p256_point(xy: &[u8]) -> Result<()> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 4;
    sec1[1..].copy_from_slice(xy);
    need(p256::PublicKey::from_sec1_bytes(&sec1).is_ok(), "curve")
}

fn ed25519_key(b: &[u8]) -> Result<()> {
    let enc: [u8; 32] = b.try_into().map_err(|_| UAError::KeyData("length"))?;
    let p = curve25519_dalek::edwards::CompressedEdwardsY(enc).decompress().ok_or(UAError::KeyData("curve"))?;
    // dalek accepts y ≥ p and a negative zero x; the re-encoding is canonical, so compare
    need(p.compress().to_bytes() == enc, "canonical")?;
    need(!p.is_small_order(), "small-order")
}

fn bn_g1(b: &[u8]) -> Result<()> {
    use ark_bn254::{Fq, G1Affine};
    let (Some(x), Some(y)) = (fe::<Fq>(&b[..32]), fe::<Fq>(&b[32..64])) else { return Err(UAError::KeyData("range")) };
    need(!(x.is_zero() && y.is_zero()), "identity")?;
    need(G1Affine::new_unchecked(x, y).is_on_curve(), "curve")
}

fn bn_g2(b: &[u8]) -> Result<()> {
    use ark_bn254::{Fq, Fq2, G2Affine};
    let w: Vec<Option<Fq>> = (0..4).map(|i| fe::<Fq>(&b[32 * i..32 * i + 32])).collect();
    let (Some(xi), Some(xr), Some(yi), Some(yr)) = (w[0], w[1], w[2], w[3]) else { return Err(UAError::KeyData("range")) };
    need(!(xi.is_zero() && xr.is_zero() && yi.is_zero() && yr.is_zero()), "identity")?;
    // EIP-197 order: imaginary part first
    on_curve_in_subgroup(&G2Affine::new_unchecked(Fq2::new(xr, xi), Fq2::new(yr, yi)))
}

fn bls_fp(b: &[u8]) -> Result<ark_bls12_381::Fq> {
    need(b[..16].iter().all(|x| *x == 0), "padding")?;
    fe::<ark_bls12_381::Fq>(&b[16..64]).ok_or(UAError::KeyData("range"))
}

fn bls_g1(b: &[u8]) -> Result<()> {
    let (x, y) = (bls_fp(&b[..64])?, bls_fp(&b[64..128])?);
    need(!(x.is_zero() && y.is_zero()), "identity")?;
    on_curve_in_subgroup(&ark_bls12_381::G1Affine::new_unchecked(x, y))
}

fn bls_g2(b: &[u8]) -> Result<()> {
    use ark_bls12_381::{Fq2, G2Affine};
    let (x0, x1, y0, y1) = (bls_fp(&b[..64])?, bls_fp(&b[64..128])?, bls_fp(&b[128..192])?, bls_fp(&b[192..256])?);
    need(!(x0.is_zero() && x1.is_zero() && y0.is_zero() && y1.is_zero()), "identity")?;
    // EIP-2537 order: c0 first
    on_curve_in_subgroup(&G2Affine::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1)))
}

fn u16_at(d: &[u8], o: usize) -> Result<usize> {
    d.get(o..o + 2).map(|s| ((s[0] as usize) << 8) | s[1] as usize).ok_or(UAError::KeyData("length"))
}

/// `Q ‖ u16 n ‖ n × P_i`, 2 ≤ n ≤ 16, P_i strictly increasing.
fn musig2(d: &[u8], point: fn(&[u8]) -> Result<()>, size: usize) -> Result<()> {
    let n = u16_at(d, size)?;
    need((2..=16).contains(&n), "n")?;
    need(d.len() == size + 2 + n * size, "length")?;
    point(&d[..size])?;
    for i in 0..n {
        let o = size + 2 + i * size;
        point(&d[o..o + size])?;
        if i > 0 {
            need(d[o - size..o] < d[o..o + size], "order")?;
        }
    }
    Ok(())
}

/// `Y ‖ u16 t ‖ u16 n ‖ n × (t × C_ik ‖ R_i ‖ μ_i)`, 2 ≤ t ≤ n ≤ 16, μ_i < order.
fn frost(d: &[u8], point: fn(&[u8]) -> Result<()>, size: usize, order: &[u8; 32]) -> Result<()> {
    let (t, n) = (u16_at(d, size)?, u16_at(d, size + 2)?);
    need(t >= 2 && t <= n && n <= 16, "threshold")?;
    let per = (t + 1) * size + 32;
    need(d.len() == size + 4 + n * per, "length")?;
    point(&d[..size])?;
    for i in 0..n {
        let o = size + 4 + i * per;
        for j in 0..=t {
            point(&d[o + j * size..o + (j + 1) * size])?; // t commitments, then R_i
        }
        need(d[o + (t + 1) * size..o + per] < order[..], "scalar")?;
    }
    Ok(())
}

/// `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)` (CTR-UA-09).
fn msig(d: &[u8], hedera_native: bool) -> Result<()> {
    let (threshold, count) = (u16_at(d, 0)?, u16_at(d, 2)?);
    need((1..=16).contains(&count), "count")?;
    need(d.len() == 4 + 36 * count, "length")?;
    let mut total = 0usize;
    for i in 0..count {
        let o = 4 + 36 * i;
        let kind = u16_at(d, o)? as u16;
        let id: &[u8; 32] = d[o + 2..o + 34].try_into().expect("32 bytes");
        let weight = u16_at(d, o + 34)?;
        need(is_member(kind, hedera_native), "member-kind")?;
        need(weight >= 1, "weight")?;
        need(is_native(kind) == in_native_space(id), "member-id")?;
        if i > 0 {
            need(d[o - 34..o - 2] < d[o + 2..o + 34], "order")?;
        }
        total += weight;
    }
    need(threshold >= 1 && threshold <= total, "threshold")
}

/// `0x09 ‖ 512 × 14-bit h_i` (big-endian bit packing), each `h_i < 12289`.
fn fndsa(d: &[u8]) -> Result<()> {
    need(d[0] == 0x09, "header")?;
    for i in 0..512 {
        let mut v = 0u32;
        for j in 0..14 {
            let k = i * 14 + j;
            v = (v << 1) | ((d[1 + k / 8] >> (7 - k % 8)) & 1) as u32;
        }
        need(v < 12289, "coefficient")?;
    }
    Ok(())
}

/// `Ok` iff `key_data` is the unique canonical encoding of a valid key or structure of `kind`.
pub fn validate_key_data(kind: u16, d: &[u8], hedera_native: bool) -> Result<()> {
    let k = kind_info(kind)?;
    if k.native {
        return Err(UAError::KindNotDerived(kind));
    }
    if !k.lengths.is_empty() {
        need(k.lengths.contains(&d.len()), "length")?;
    }
    match kind {
        0x0100 => p256_point(&d[..64]),
        0x0101 => p256_point(d),
        0x0102 => ed25519_key(d),
        0x0103 => secp_compressed(&[&[2u8][..], d].concat()),
        0x0104 | 0x0140 => bn_g1(d),
        0x0105 | 0x0141 => bls_g1(d),
        0x0106 => bls_g2(d),
        0x0107 => bn_g2(d),
        0x0110 => musig2(d, secp_compressed, 33),
        0x0111 => frost(d, secp_compressed, 33, &SECP_N),
        0x0112 => musig2(d, bn_g1, 64),
        0x0113 => frost(d, bn_g1, 64, &BN_R),
        0x0120 => msig(d, hedera_native),
        0x0132 => fndsa(d),
        _ => Ok(()), // mldsa44/65, slhdsa128s, pqz-mlwe: the length is the whole check
    }
}
