//! UA ids on NEAR (accounts.md §1.6, spec §3.3): derived ids `UA(kind, keyData) = keccak256(TAG(kind) ‖ keyData)` for
//! the kinds a NEAR token accepts, the native kind `0x0017 near-account`, `msig` key data, and `KeyRecord`, the key a
//! subject account holds (its UA kind and canonical key data).
use near_sdk::{env, near, AccountId};

pub const KIND_NEAR_ACCOUNT: u16 = 0x0017;
pub const KIND_WEBAUTHN_P256: u16 = 0x0100;
pub const KIND_ED25519: u16 = 0x0102;
pub const KIND_SECP256K1: u16 = 0x0108;
pub const KIND_MSIG: u16 = 0x0120;

/// Members per `msig`: floor(250 Tgas / 20.005 Tgas per P-256 verify, `runs/2026-10-28-p256-spike.txt`) = 12, so an
/// all-passkey msig entry auth (12 × 20.005 = 240.1) plus a passkey payment (20.0) and the rest of the largest wrapper
/// (2.3) burns ≈ 262 Tgas < 300 (ruling R1; Task 9 measures it). Below the registry's 16.
pub const MSIG_MAX_MEMBERS: usize = 12;

type R<T> = Result<T, &'static str>;

/// `kind_tag` (kinds.json `tag`) of the derived kinds accepted on NEAR.
fn tag(kind: u16) -> Option<&'static str> {
    Some(match kind {
        KIND_WEBAUTHN_P256 => "scaas.ua.webauthn-p256.v1",
        KIND_ED25519 => "scaas.ua.ed25519.v1",
        KIND_SECP256K1 => "scaas.ua.secp256k1.v1",
        KIND_MSIG => "scaas.ua.msig.v1",
        _ => return None,
    })
}

/// `keccak256(keccak256(kind_tag) ‖ key_data)`; panics on a kind NEAR does not accept (check `KeyRecord::validate`).
pub fn ua_of(kind: u16, key_data: &[u8]) -> [u8; 32] {
    let t = env::keccak256_array(tag(kind).expect("kind not accepted on NEAR").as_bytes());
    env::keccak256_array([&t[..], key_data].concat())
}

/// CTR-UA-03: a derived id has a non-zero top 96 bits.
fn derived_ok(id: &[u8; 32]) -> bool {
    id[..12] != [0; 12]
}

/// Kind `0x0017`: a 64-lower-case-hex (implicit) account is its raw 32 bytes, any other id (named, ETH-implicit `0x…`)
/// `sha256(account id)`. `AccountId` refuses upper case, so the two forms cannot be confused.
pub fn native_id(account: &AccountId) -> [u8; 32] {
    let s = account.as_bytes();
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    if s.len() == 64 && s.iter().all(|c| nib(*c).is_some()) {
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = nib(s[2 * i]).unwrap() << 4 | nib(s[2 * i + 1]).unwrap();
        }
        return id;
    }
    env::sha256_array(s)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub kind: u16,
    pub id: [u8; 32],
    pub weight: u16,
}

pub struct Msig {
    pub threshold: u16,
    pub members: Vec<Member>,
}

/// `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)`, big-endian, ids strictly increasing;
/// members: `near-account` (counts only as the predecessor) or a single-key kind NEAR verifies.
pub fn parse_msig(d: &[u8]) -> R<Msig> {
    let u16be = |i: usize| u16::from_be_bytes([d[i], d[i + 1]]);
    if d.len() < 4 {
        return Err("msig key data too short");
    }
    let (threshold, count) = (u16be(0), u16be(2) as usize);
    if count == 0 || count > MSIG_MAX_MEMBERS {
        return Err("msig member count out of range");
    }
    if d.len() != 4 + 36 * count {
        return Err("msig key data length");
    }
    let mut members: Vec<Member> = Vec::with_capacity(count);
    for i in 0..count {
        let o = 4 + 36 * i;
        let m = Member { kind: u16be(o), id: d[o + 2..o + 34].try_into().unwrap(), weight: u16be(o + 34) };
        match m.kind {
            KIND_NEAR_ACCOUNT => {}
            KIND_WEBAUTHN_P256 | KIND_ED25519 | KIND_SECP256K1 if derived_ok(&m.id) => {}
            _ => return Err("msig member kind not accepted"),
        }
        if m.weight == 0 {
            return Err("msig member weight 0");
        }
        if members.last().is_some_and(|p| p.id >= m.id) {
            return Err("msig members not strictly increasing");
        }
        members.push(m);
    }
    let total: u32 = members.iter().map(|m| m.weight as u32).sum();
    if threshold == 0 || threshold as u32 > total {
        return Err("msig threshold out of range");
    }
    Ok(Msig { threshold, members })
}

/// A key of a subject account: its UA kind and canonical key data (ed25519 `pk` 32, secp256k1 `x ‖ y` 64,
/// webauthn-p256 `x ‖ y ‖ rpIdHash` 96, msig as `parse_msig`). Its UA id is `ua_of(kind, key_data)`.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    pub kind: u16,
    pub key_data: Vec<u8>,
}

impl KeyRecord {
    pub fn validate(&self) -> R<()> {
        let ok = match self.kind {
            KIND_ED25519 => self.key_data.len() == 32,
            KIND_SECP256K1 => self.key_data.len() == 64,
            KIND_WEBAUTHN_P256 => self.key_data.len() == 96,
            KIND_MSIG => parse_msig(&self.key_data).is_ok(),
            _ => return Err("key kind not accepted on NEAR"),
        };
        if !ok {
            return Err("key data");
        }
        if !derived_ok(&self.id()) {
            return Err("UA id in the native space (CTR-UA-03)");
        }
        Ok(())
    }

    pub fn id(&self) -> [u8; 32] {
        ua_of(self.kind, &self.key_data)
    }

    /// A passkey can sign only for an origin the subject lists.
    pub fn needs_origin(&self) -> bool {
        match self.kind {
            KIND_WEBAUTHN_P256 => true,
            KIND_MSIG => parse_msig(&self.key_data).is_ok_and(|m| m.members.iter().any(|x| x.kind == KIND_WEBAUTHN_P256)),
            _ => false,
        }
    }
}
