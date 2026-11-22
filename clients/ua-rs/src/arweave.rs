// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ANS-104 data items as `arbundles` builds them, and `ar://<id>` (CLI-UAL-64, CLI-UAL-65; feature `fam-arweave`; chains-arweave
//! plan T17). Layout: signature type (2 B little-endian), signature, owner, target and anchor (a presence byte 0 or 1, then
//! 32 B), tag count and tag bytes length (8 B little-endian each), the Avro tags, data. The signed message is the SHA-384 deep
//! hash of `["dataitem", "1", <type as decimal text>, owner, target, anchor, <raw tag bytes>, data]`; the id is SHA-256 of the
//! signature (base64url, 43 characters). Types: 2 (ed25519 over the 48 bytes), 3 (secp256k1, EIP-191 `personal_sign` over the
//! 48 bytes, `r ‖ s ‖ v` with `v ∈ {27, 28}` and low `s`, the uncompressed owner) and 4 (ed25519 over the deep hash's
//! lowercase hex text, as `arbundles`' Solana signers sign: the cross-check of plan T16 found it); no type 1, no other type.
//! [`DataItem`] has no public constructor: it is what [`DataItem::parse`] verified or what `ua-rs` built and verified
//! (`wallet::AppKeys::seal_for_arweave`). No Arweave crate (CLI-SDK-33 (31)). Byte formats: clientkeys `src/arweave.js`,
//! `smartcontracts/vectors/arweave/`. UNAUDITED.
use sha2::{Digest, Sha256, Sha384};

/// The smallest item.
pub const MIN_ITEM: usize = 80;
pub const MAX_TAGS: usize = 128;
pub const MAX_NAME: usize = 1024;
pub const MAX_VALUE: usize = 3072;
pub const MAX_TAG_BYTES: usize = 4096;

/// A data item's signature type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigType {
    /// 2: ed25519 over the 48 bytes, a 32-byte owner
    Ed25519 = 2,
    /// 3: secp256k1 over EIP-191 of the 48 bytes, a 65-byte owner
    Ethereum = 3,
    /// 4: ed25519 over the 48 bytes' lowercase hex text (Solana's), a 32-byte owner
    Solana = 4,
}

impl SigType {
    pub fn from_u16(t: u16) -> Result<Self, ArweaveError> {
        match t {
            2 => Ok(SigType::Ed25519),
            3 => Ok(SigType::Ethereum),
            4 => Ok(SigType::Solana),
            _ => Err(ArweaveError::SignatureType),
        }
    }
    pub fn sig_len(self) -> usize {
        match self {
            SigType::Ethereum => 65,
            _ => 64,
        }
    }
    pub fn owner_len(self) -> usize {
        match self {
            SigType::Ethereum => 65,
            _ => 32,
        }
    }
}

/// Why an item, its tags or an `ar://` URL was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArweaveError {
    SignatureType,
    ItemShort,
    Presence,
    Owner,
    TagCount,
    TagBounds,
    TagTruncated,
    TagBlockNegative,
    TagTrailing,
    TagNonCanonical,
    /// a target, an anchor or a tag where none may be (C9)
    ItemShape,
    Signature,
    ArUrl,
}

impl ArweaveError {
    pub fn code(&self) -> &'static str {
        match self {
            ArweaveError::SignatureType => "SignatureType",
            ArweaveError::ItemShort => "ItemShort",
            ArweaveError::Presence => "Presence",
            ArweaveError::Owner => "Owner",
            ArweaveError::TagCount => "TagCount",
            ArweaveError::TagBounds => "TagBounds",
            ArweaveError::TagTruncated => "TagTruncated",
            ArweaveError::TagBlockNegative => "TagBlockNegative",
            ArweaveError::TagTrailing => "TagTrailing",
            ArweaveError::TagNonCanonical => "TagNonCanonical",
            ArweaveError::ItemShape => "ItemShape",
            ArweaveError::Signature => "Signature",
            ArweaveError::ArUrl => "ArUrl",
        }
    }
}

impl std::fmt::Display for ArweaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ArweaveError {}

// ---------------------------------------------------------------- the deep hash

/// A deep hash input: a blob or a list.
pub enum Chunk<'a> {
    Blob(&'a [u8]),
    List(Vec<Chunk<'a>>),
}

/// SHA-384 deep hash: a blob `SHA384(SHA384("blob" ‖ len) ‖ SHA384(data))`; a list `acc = SHA384("list" ‖ count)`, then
/// `acc = SHA384(acc ‖ deep_hash(item))` per item.
pub fn deep_hash(c: &Chunk) -> [u8; 48] {
    match c {
        Chunk::Blob(b) => {
            let tag = Sha384::digest(format!("blob{}", b.len()).as_bytes());
            Sha384::new()
                .chain_update(tag)
                .chain_update(Sha384::digest(b))
                .finalize()
                .into()
        }
        Chunk::List(items) => {
            let mut acc: [u8; 48] =
                Sha384::digest(format!("list{}", items.len()).as_bytes()).into();
            for i in items {
                acc = Sha384::new()
                    .chain_update(acc)
                    .chain_update(deep_hash(i))
                    .finalize()
                    .into();
            }
            acc
        }
    }
}

// ---------------------------------------------------------------- Avro tags

/// One tag: a name and a value, both bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

fn write_long(out: &mut Vec<u8>, n: u64) {
    let mut m = n << 1; // zigzag of a non-negative count or length
    loop {
        let b = (m & 0x7f) as u8;
        m >>= 7;
        if m == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// The tag bytes: an empty list is 0 bytes; else one block of `tags.len()` pairs, then the terminator 0.
pub fn encode_tags(tags: &[Tag]) -> Vec<u8> {
    if tags.is_empty() {
        return vec![];
    }
    let mut out = vec![];
    write_long(&mut out, tags.len() as u64);
    for t in tags {
        write_long(&mut out, t.name.len() as u64);
        out.extend_from_slice(&t.name);
        write_long(&mut out, t.value.len() as u64);
        out.extend_from_slice(&t.value);
    }
    out.push(0);
    out
}

/// The strict reader: positive blocks only (`TagBlockNegative`), the terminator and nothing after it (`TagTrailing`), `count`
/// tags (`TagCount`), names and values non-empty and in bounds (`TagBounds`), and the bytes exactly [`encode_tags`]' output
/// (`TagNonCanonical`: the signature covers the raw bytes, so one item has one encoding).
pub fn decode_tags(buf: &[u8], count: u64) -> Result<Vec<Tag>, ArweaveError> {
    decode_strict(buf, count)
}

/// One varint at `*pos` (zigzag, at most 10 bytes).
fn long_at(buf: &[u8], pos: &mut usize) -> Result<i128, ArweaveError> {
    let mut m: u128 = 0;
    for shift in (0..70).step_by(7) {
        let b = *buf.get(*pos).ok_or(ArweaveError::TagTruncated)?;
        *pos += 1;
        m |= u128::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            let v = (m >> 1) as i128;
            return Ok(if m & 1 == 1 { -v - 1 } else { v });
        }
    }
    Err(ArweaveError::TagTruncated)
}

fn decode_strict(buf: &[u8], count: u64) -> Result<Vec<Tag>, ArweaveError> {
    if count == 0 && buf.is_empty() {
        return Ok(vec![]);
    }
    if count == 0 || buf.is_empty() {
        return Err(ArweaveError::TagCount);
    }
    let mut pos = 0usize;
    let mut tags = vec![];
    loop {
        let n = long_at(buf, &mut pos)?;
        if n == 0 {
            break;
        }
        if n < 0 {
            return Err(ArweaveError::TagBlockNegative);
        }
        if tags.len() as i128 + n > MAX_TAGS as i128 {
            return Err(ArweaveError::TagCount);
        }
        for _ in 0..n {
            let mut field = |max: usize| -> Result<Vec<u8>, ArweaveError> {
                let len = long_at(buf, &mut pos)?;
                if len < 1 || len > max as i128 {
                    return Err(ArweaveError::TagBounds);
                }
                let b = buf
                    .get(pos..pos + len as usize)
                    .ok_or(ArweaveError::TagTruncated)?
                    .to_vec();
                pos += len as usize;
                Ok(b)
            };
            let name = field(MAX_NAME)?;
            let value = field(MAX_VALUE)?;
            tags.push(Tag { name, value });
        }
    }
    if pos != buf.len() {
        return Err(ArweaveError::TagTrailing);
    }
    if tags.len() as u64 != count {
        return Err(ArweaveError::TagCount);
    }
    if encode_tags(&tags) != buf {
        return Err(ArweaveError::TagNonCanonical);
    }
    Ok(tags)
}

// ---------------------------------------------------------------- signing and verifying

const EIP191: &[u8] = b"\x19Ethereum Signed Message:\n48";

/// The 48 bytes an item's signature covers.
pub fn signed_message(
    t: SigType,
    owner: &[u8],
    target: Option<&[u8; 32]>,
    anchor: Option<&[u8; 32]>,
    raw_tags: &[u8],
    data: &[u8],
) -> [u8; 48] {
    let ty = (t as u16).to_string();
    deep_hash(&Chunk::List(vec![
        Chunk::Blob(b"dataitem"),
        Chunk::Blob(b"1"),
        Chunk::Blob(ty.as_bytes()),
        Chunk::Blob(owner),
        Chunk::Blob(target.map_or(&[][..], |x| &x[..])),
        Chunk::Blob(anchor.map_or(&[][..], |x| &x[..])),
        Chunk::Blob(raw_tags),
        Chunk::Blob(data),
    ]))
}

fn hex_text(b: &[u8]) -> Vec<u8> {
    const H: &[u8; 16] = b"0123456789abcdef";
    b.iter()
        .flat_map(|x| [H[(x >> 4) as usize], H[(x & 15) as usize]])
        .collect()
}

fn eip191(msg: &[u8; 48]) -> [u8; 32] {
    crate::keccak256(&[EIP191, &msg[..]].concat())
}

#[cfg(any(feature = "app-core", feature = "vectors"))]
/// The owner (public key) of a type's 32-byte secret: ed25519's 32 bytes, secp256k1's uncompressed 65.
pub(crate) fn owner_of(t: SigType, secret: &[u8; 32]) -> Option<Vec<u8>> {
    match t {
        SigType::Ethereum => {
            let sk = k256::ecdsa::SigningKey::from_slice(secret).ok()?;
            Some(sk.verifying_key().to_sec1_point(false).as_bytes().to_vec())
        }
        _ => Some(
            ed25519_dalek::SigningKey::from_bytes(secret)
                .verifying_key()
                .to_bytes()
                .to_vec(),
        ),
    }
}

#[cfg(any(feature = "app-core", feature = "vectors"))]
/// A type's signature of the message: ed25519 over the bytes (2) or their hex text (4); secp256k1 RFC 6979, low `s`, `v` 27
/// or 28 over EIP-191 of the bytes (3).
pub(crate) fn sign_message(t: SigType, secret: &[u8; 32], msg: &[u8; 48]) -> Option<Vec<u8>> {
    match t {
        SigType::Ethereum => {
            let sk = k256::ecdsa::SigningKey::from_slice(secret).ok()?;
            let (sig, rec) = sk.sign_prehash_recoverable(&eip191(msg));
            let mut out = sig.to_bytes().to_vec();
            out.push(27 + rec.to_byte());
            Some(out)
        }
        SigType::Ed25519 => {
            use ed25519_dalek::Signer as _;
            Some(
                ed25519_dalek::SigningKey::from_bytes(secret)
                    .sign(msg)
                    .to_bytes()
                    .to_vec(),
            )
        }
        SigType::Solana => {
            use ed25519_dalek::Signer as _;
            Some(
                ed25519_dalek::SigningKey::from_bytes(secret)
                    .sign(&hex_text(msg))
                    .to_bytes()
                    .to_vec(),
            )
        }
    }
}

/// Whether `sig` is the type's signature of `msg` by `owner` (type 3: `v ∈ {27, 28}`, low `s`, the recovered key the owner).
pub fn verify_message(t: SigType, owner: &[u8], msg: &[u8; 48], sig: &[u8]) -> bool {
    match t {
        SigType::Ethereum => {
            use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
            if sig.len() != 65 || !(sig[64] == 27 || sig[64] == 28) {
                return false;
            }
            let Ok(s) = Signature::from_slice(&sig[..64]) else {
                return false;
            };
            if s.normalize_s() != s {
                return false;
            }
            let Some(rec) = RecoveryId::from_byte(sig[64] - 27) else {
                return false;
            };
            VerifyingKey::recover_from_prehash(&eip191(msg), &s, rec)
                .is_ok_and(|vk| vk.to_sec1_point(false).as_bytes() == owner)
        }
        SigType::Ed25519 => crate::verify::ed25519(owner, msg, sig),
        SigType::Solana => crate::verify::ed25519(owner, &hex_text(msg), sig),
    }
}

// ---------------------------------------------------------------- base64url and ar://

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url, unpadded.
pub fn b64url(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = c
            .iter()
            .enumerate()
            .fold(0u32, |a, (i, x)| a | u32::from(*x) << (16 - 8 * i));
        for i in 0..=c.len() {
            out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// The 32 bytes of an id: exactly 43 canonical base64url characters (the last one of `AEIMQUYcgkosw048`), else `ArUrl`.
pub fn id_bytes(id: &str) -> Result<[u8; 32], ArweaveError> {
    let s = id.as_bytes();
    if s.len() != 43 || !b"AEIMQUYcgkosw048".contains(&s[42]) {
        return Err(ArweaveError::ArUrl);
    }
    let mut bits: u64 = 0;
    let (mut n, mut out) = (0u32, Vec::with_capacity(33));
    for c in s {
        let v = B64.iter().position(|x| x == c).ok_or(ArweaveError::ArUrl)? as u64;
        bits = bits << 6 | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
            bits &= (1 << n) - 1;
        }
    }
    if bits != 0 {
        return Err(ArweaveError::ArUrl);
    }
    out.try_into().map_err(|_| ArweaveError::ArUrl)
}

/// The id of `ar://<id>`: the scheme in lower case, [`id_bytes`]' form, nothing after it (`ArUrl`).
pub fn parse_ar_url(url: &str) -> Result<[u8; 32], ArweaveError> {
    id_bytes(url.strip_prefix("ar://").ok_or(ArweaveError::ArUrl)?)
}

// ---------------------------------------------------------------- items

/// A verified data item: its bytes and where its fields lie. No public constructor (`ua-rs` built it, or
/// [`DataItem::parse`] verified it).
#[derive(Clone, PartialEq, Eq)]
pub struct DataItem {
    bytes: Vec<u8>,
    t: SigType,
    owner_at: usize,
    data_at: usize,
    shape_c9: bool,
    id: [u8; 32],
}

impl std::fmt::Debug for DataItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataItem")
            .field("type", &self.t)
            .field("id", &b64url(&self.id))
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[cfg(any(feature = "app-core", feature = "vectors"))]
/// The unsigned layout around a zero signature: the header with the signature's place, and the signed message.
pub(crate) fn assemble(
    t: SigType,
    sig: &[u8],
    owner: &[u8],
    target: Option<&[u8; 32]>,
    anchor: Option<&[u8; 32]>,
    tags: &[Tag],
    data: &[u8],
) -> Result<Vec<u8>, ArweaveError> {
    if owner.len() != t.owner_len() || sig.len() != t.sig_len() {
        return Err(ArweaveError::Owner);
    }
    if tags.len() > MAX_TAGS {
        return Err(ArweaveError::TagCount);
    }
    if tags.iter().any(|g| {
        g.name.is_empty()
            || g.value.is_empty()
            || g.name.len() > MAX_NAME
            || g.value.len() > MAX_VALUE
    }) {
        return Err(ArweaveError::TagBounds);
    }
    let raw = encode_tags(tags);
    if raw.len() > MAX_TAG_BYTES {
        return Err(ArweaveError::TagBounds);
    }
    let mut out =
        Vec::with_capacity(2 + sig.len() + owner.len() + 66 + 16 + raw.len() + data.len());
    out.extend_from_slice(&(t as u16).to_le_bytes());
    out.extend_from_slice(sig);
    out.extend_from_slice(owner);
    for x in [target, anchor] {
        match x {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(v);
            }
            None => out.push(0),
        }
    }
    out.extend_from_slice(&(tags.len() as u64).to_le_bytes());
    out.extend_from_slice(&(raw.len() as u64).to_le_bytes());
    out.extend_from_slice(&raw);
    out.extend_from_slice(data);
    Ok(out)
}

#[cfg(any(feature = "app-core", feature = "vectors"))]
/// An item of `t` over `data` with the 32-byte `secret`, signed, then verified by [`DataItem::parse`] (the signature
/// checked before the item is returned).
pub(crate) fn build(
    t: SigType,
    secret: &[u8; 32],
    data: &[u8],
    target: Option<&[u8; 32]>,
    anchor: Option<&[u8; 32]>,
    tags: &[Tag],
) -> Result<DataItem, ArweaveError> {
    let owner = owner_of(t, secret).ok_or(ArweaveError::Owner)?;
    let raw = encode_tags(tags);
    let msg = signed_message(t, &owner, target, anchor, &raw, data);
    let sig = sign_message(t, secret, &msg).ok_or(ArweaveError::Signature)?;
    DataItem::parse(assemble(t, &sig, &owner, target, anchor, tags, data)?)
}

impl DataItem {
    /// The verifying parser (spec §7.2): at least 80 bytes, types 2, 3, 4 only, presence bytes 0 or 1, at most 128 tags and
    /// 4,096 tag bytes read by the strict Avro reader; the signature verified before the item is returned.
    pub fn parse(bytes: Vec<u8>) -> Result<DataItem, ArweaveError> {
        if bytes.len() < MIN_ITEM {
            return Err(ArweaveError::ItemShort);
        }
        let t = SigType::from_u16(u16::from_le_bytes([bytes[0], bytes[1]]))?;
        let mut p = 2usize;
        let mut take = |n: usize| -> Result<&[u8], ArweaveError> {
            let s = bytes.get(p..p + n).ok_or(ArweaveError::ItemShort)?;
            p += n;
            Ok(s)
        };
        let sig = take(t.sig_len())?;
        let owner = take(t.owner_len())?;
        let mut opt = || -> Result<Option<[u8; 32]>, ArweaveError> {
            match take(1)?[0] {
                0 => Ok(None),
                1 => Ok(Some(
                    take(32)?.try_into().map_err(|_| ArweaveError::ItemShort)?,
                )),
                _ => Err(ArweaveError::Presence),
            }
        };
        let target = opt()?;
        let anchor = opt()?;
        let count = u64::from_le_bytes(take(8)?.try_into().map_err(|_| ArweaveError::ItemShort)?);
        let len = u64::from_le_bytes(take(8)?.try_into().map_err(|_| ArweaveError::ItemShort)?);
        if count > MAX_TAGS as u64 {
            return Err(ArweaveError::TagCount);
        }
        if len > MAX_TAG_BYTES as u64 {
            return Err(ArweaveError::TagBounds);
        }
        let raw = take(len as usize)?;
        let tags = decode_strict(raw, count)?;
        let data_at = p;
        let (sig, owner, raw) = (sig.to_vec(), owner.to_vec(), raw.to_vec());
        let msg = signed_message(
            t,
            &owner,
            target.as_ref(),
            anchor.as_ref(),
            &raw,
            &bytes[data_at..],
        );
        if !verify_message(t, &owner, &msg, &sig) {
            return Err(ArweaveError::Signature);
        }
        Ok(DataItem {
            id: Sha256::digest(&sig).into(),
            t,
            owner_at: 2 + t.sig_len(),
            data_at,
            shape_c9: target.is_none() && anchor.is_none() && tags.is_empty(),
            bytes,
        })
    }

    /// [`DataItem::parse`] of a kept item, which carries no target, no anchor and no tag (C9; `ItemShape`).
    pub fn parse_c9(bytes: Vec<u8>) -> Result<DataItem, ArweaveError> {
        let it = Self::parse(bytes)?;
        if !it.shape_c9 {
            return Err(ArweaveError::ItemShape);
        }
        Ok(it)
    }

    /// The item's bytes, as posted.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    pub fn sig_type(&self) -> SigType {
        self.t
    }
    /// SHA-256 of the signature.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    /// The id in base64url (43 characters).
    pub fn id_b64(&self) -> String {
        b64url(&self.id)
    }
    /// `ar://<id>`.
    pub fn url(&self) -> String {
        format!("ar://{}", self.id_b64())
    }
    pub fn owner(&self) -> &[u8] {
        &self.bytes[self.owner_at..self.owner_at + self.t.owner_len()]
    }
    pub fn data(&self) -> &[u8] {
        &self.bytes[self.data_at..]
    }
    /// No target, no anchor, no tag (C9).
    pub fn is_c9(&self) -> bool {
        self.shape_c9
    }
}

/// Test-only (feature `vectors`, never in a release build): an item with a caller's key, for the vector rows with tags, a
/// target and an anchor.
#[cfg(feature = "vectors")]
pub fn vectors_build(
    t: SigType,
    secret: &[u8; 32],
    data: &[u8],
    target: Option<&[u8; 32]>,
    anchor: Option<&[u8; 32]>,
    tags: &[Tag],
) -> Result<DataItem, ArweaveError> {
    build(t, secret, data, target, anchor, tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_tag_list_is_no_bytes_and_one_tag_one_block() {
        assert!(encode_tags(&[]).is_empty());
        let t = [Tag {
            name: b"a".to_vec(),
            value: b"bc".to_vec(),
        }];
        assert_eq!(encode_tags(&t), [2, 2, b'a', 4, b'b', b'c', 0]);
        assert_eq!(decode_strict(&encode_tags(&t), 1).unwrap(), t);
    }

    #[test]
    fn ids_round_trip_and_refuse_noncanonical_ends() {
        let id = [0xabu8; 32];
        let s = b64url(&id);
        assert_eq!(s.len(), 43);
        assert_eq!(id_bytes(&s).unwrap(), id);
        let mut bad = s.clone().into_bytes();
        bad[42] = b'B';
        assert_eq!(
            id_bytes(std::str::from_utf8(&bad).unwrap()),
            Err(ArweaveError::ArUrl)
        );
    }
}
