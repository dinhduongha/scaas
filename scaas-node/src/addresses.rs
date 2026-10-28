//! Dạng chuẩn địa chỉ theo họ mạng — bản Rust của Odoo `dms_blockchain/lib/addresses.py::canonical` (R61).
//! Khoá chung: `tests/api/addresses.json` (sinh từ bản Python). Store so byte-exact, nên mọi địa chỉ vào store
//! (token, contract của policy) đi qua đây trước.
//!
//! Khác bản Python một chỗ, cố ý: TON user-friendly có ký tự ngoài bảng base64 bị từ chối (Python bỏ qua nó).
use alloy::primitives::Address;
use anyhow::{anyhow, bail, ensure, Result};

/// `bech32_prefix`: cosmos `params.prefix`; `ton_testnet`: `Some(network == "-3")` cho chain TON.
pub fn canonical(family: &str, value: &str, bech32_prefix: Option<&str>, ton_testnet: Option<bool>) -> Result<String> {
    let v = value.trim();
    ensure!(!v.is_empty(), "empty address");
    match family {
        "evm" => evm(v),
        "hedera" => match v.strip_prefix("0.0.") {
            Some(n) if (1..=19).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()) => {
                let n: u64 = n.parse().map_err(|_| anyhow!("Hedera account number too large"))?;
                Ok(format!("{:#x}", Address::left_padding_from(&n.to_be_bytes())))
            }
            _ => evm(v),
        },
        "sui" | "aptos" => {
            let h = v.strip_prefix("0x").filter(|h| (1..=64).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or_else(|| anyhow!("not a {family} address: {v:?}"))?;
            Ok(format!("0x{:0>64}", h.to_ascii_lowercase()))
        }
        "soroban" => {
            let raw = b32decode(v)?;
            ensure!(raw.len() == 35, "strkey length");
            ensure!(crate::signer::crc16_xmodem(&raw[..33]) == u16::from_le_bytes([raw[33], raw[34]]), "strkey checksum");
            ensure!(matches!(raw[0], 0x30 | 0x10), "only G… account or C… contract strkeys");
            Ok(v.to_string())
        }
        "cosmos" => {
            let (hrp, data) = bech32_decode(v)?;
            let len = data.len();
            if let Some(p) = bech32_prefix.filter(|p| !p.is_empty() && *p != hrp) {
                bail!("bech32 prefix {hrp:?}, expected {p:?}");
            }
            ensure!(len == 20 || len == 32, "cosmos address is 20 (account) or 32 (contract) bytes");
            Ok(v.to_ascii_lowercase())
        }
        "ton" => ton(v, ton_testnet),
        "solana" => {
            let n = bs58::decode(v).into_vec().map_err(|e| anyhow!("not base58: {e}"))?.len();
            ensure!(n == 32, "a Solana address is base58 of 32 bytes");
            Ok(v.to_string())
        }
        other => bail!("unknown network family {other:?}"),
    }
}

/// `eip712.parse_address`: `0x` + 40 hex; trộn hoa-thường thì phải đúng EIP-55. Trả chữ thường.
fn evm(v: &str) -> Result<String> {
    let body = v.strip_prefix("0x").filter(|b| b.len() == 40 && b.bytes().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow!("not an EVM address: {v:?}"))?;
    let a: Address = body.parse()?;
    let mixed = body != body.to_ascii_lowercase() && body != body.to_ascii_uppercase();
    ensure!(!mixed || a.to_checksum(None) == v, "bad EIP-55 checksum: {v:?}");
    Ok(format!("{a:#x}"))
}

fn ton(v: &str, testnet: Option<bool>) -> Result<String> {
    if let Some((wc, h)) = v.split_once(':') {
        let digits = wc.strip_prefix('-').unwrap_or(wc);
        if (1..=3).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit())
            && h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Ok(format!("{}:{}", wc.parse::<i32>()?, h.to_ascii_lowercase()));
        }
    }
    let raw = crate::adapters::ton::b64decode(v)?;
    ensure!(raw.len() == 36, "TON address length");
    ensure!(crate::signer::crc16_xmodem(&raw[..34]) == u16::from_be_bytes([raw[34], raw[35]]), "TON address checksum");
    ensure!(matches!(raw[0] & 0x7f, 0x11 | 0x51), "TON address tag");
    if testnet.is_some_and(|t| t != (raw[0] & 0x80 != 0)) {
        bail!("TON address network flag does not match the chain");
    }
    Ok(format!("{}:{}", raw[1] as i8, alloy::hex::encode(&raw[2..34])))
}

/// RFC 4648 base32 chữ hoa, không padding, bit thừa phải bằng 0 (`addresses._b32decode`).
fn b32decode(s: &str) -> Result<Vec<u8>> {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut acc, mut bits, mut out) = (0u64, 0u32, Vec::new());
    for c in s.bytes() {
        let v = A.iter().position(|&x| x == c).ok_or_else(|| anyhow!("not base32"))? as u64;
        acc = (acc << 5 | v) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    ensure!(bits < 5 && acc & ((1 << bits) - 1) == 0, "non-canonical base32");
    Ok(out)
}

/// BIP-173: trả `(hrp, bytes dữ liệu)`.
pub(crate) fn bech32_decode(v: &str) -> Result<(String, Vec<u8>)> {
    ensure!(v == v.to_ascii_lowercase() || v == v.to_ascii_uppercase(), "mixed-case bech32");
    let v = v.to_ascii_lowercase();
    let pos = v.rfind('1').filter(|&p| p >= 1 && p + 7 <= v.len() && v.len() <= 90)
        .ok_or_else(|| anyhow!("bech32 shape"))?;
    let (hrp, rest) = (&v[..pos], &v[pos + 1..]);
    const CS: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let data: Vec<u8> = rest.bytes().map(|c| CS.iter().position(|&x| x == c).map(|i| i as u8))
        .collect::<Option<_>>().ok_or_else(|| anyhow!("bech32 characters"))?;
    ensure!(hrp.bytes().all(|c| (33..=126).contains(&c)), "bech32 characters");
    let mut all: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    all.push(0);
    all.extend(hrp.bytes().map(|c| c & 31));
    all.extend(&data);
    ensure!(crate::adapters::cosmos::polymod(&all) == 1, "bech32 checksum");
    let five = &data[..data.len() - 6];
    let total = five.len() * 5;
    // 5 → 8 bit, no padding: at most 4 spare bits, all zero.
    let spare = total % 8;
    let last = five.last().copied().unwrap_or(0);
    ensure!(spare < 5 && (last as u32) & ((1 << spare) - 1) == 0, "bech32 padding");
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::with_capacity(total / 8));
    for &d in five {
        acc = (acc << 5 | d as u32) & 0xfff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok((hrp.to_string(), out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_odoo_vectors() {
        let v: serde_json::Value = serde_json::from_str(include_str!("../tests/api/addresses.json")).unwrap();
        for c in v["cases"].as_array().unwrap() {
            let s = |k: &str| c[k].as_str();
            let got = canonical(s("family").unwrap(), s("value").unwrap(), s("bech32_prefix"), c["testnet"].as_bool());
            match (s("ok"), got) {
                (Some(want), Ok(g)) => assert_eq!(g, want, "{c}"),
                (None, Err(_)) => {}
                (want, got) => panic!("{c}: want {want:?}, got {got:?}"),
            }
        }
    }
}
