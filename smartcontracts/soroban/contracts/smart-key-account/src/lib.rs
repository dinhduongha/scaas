//! SmartKeyAccount, account chủ thể nhiều khoá (R31 + R32): passkey P-256 WebAuthn và khoá ed25519 dẫn xuất từ seed. Host gọi
//! `__check_auth` với `signature_payload` = sha256(HashIdPreimage::SorobanAuthorization) — nonce/hạn/replay do
//! host giữ (không tuần tự, R30). Thêm/xoá khoá cần chính account uỷ quyền (một khoá hiện có ký).
//! Guardian + trễ khôi phục: seam (R8-2).
#![no_std]
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype, crypto::Hash, panic_with_error, Bytes, BytesN, Env, Map,
    Vec,
};

const DAY: u32 = 17_280;
const MAX_CLIENT_DATA: usize = 1024;
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    UnknownKey = 1,
    WrongKeyKind = 2,
    BadClientData = 3,
    BadAuthenticatorData = 4,
    LastKey = 5,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Passkey {
    /// SEC1 không nén (0x04 ‖ x ‖ y).
    pub public_key: BytesN<65>,
    pub rp_id_hash: BytesN<32>,
    /// Ví dụ `https://shop.example` — so nguyên văn với `"origin"` trong clientDataJSON (review S17).
    pub origin: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Key {
    Ed25519(BytesN<32>),
    Passkey(Passkey),
}

#[contracttype]
#[derive(Clone)]
pub struct WebAuthnSig {
    pub key_id: u32,
    pub authenticator_data: Bytes,
    pub client_data_json: Bytes,
    /// r ‖ s, s ≤ n/2 (host từ chối high-s — CAP-51; client chuẩn hoá — review S5).
    pub signature: BytesN<64>,
    /// Gom lô (R31): rỗng ⇒ challenge = payload; ngược lại challenge = gốc Merkle.
    pub proof: Vec<BytesN<32>>,
}

#[contracttype]
#[derive(Clone)]
pub enum Signature {
    Ed25519(u32, BytesN<64>),
    WebAuthn(WebAuthnSig),
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Keys,
    Next,
}

fn keys(env: &Env) -> Map<u32, Key> {
    env.storage().instance().get(&DataKey::Keys).unwrap_or_else(|| Map::new(env))
}

fn save(env: &Env, m: &Map<u32, Key>) {
    env.storage().instance().set(&DataKey::Keys, m);
    env.storage().instance().extend_ttl(30 * DAY, 60 * DAY);
}

/// Lá `sha256(sha256(0x00 ‖ payload))` (chặn second-preimage — review S26), cặp sắp xếp như OpenZeppelin.
pub fn merkle_root(env: &Env, payload: &BytesN<32>, proof: &Vec<BytesN<32>>) -> BytesN<32> {
    let mut leaf = Bytes::from_array(env, &[0u8]);
    leaf.append(&payload.clone().into());
    let inner: Bytes = env.crypto().sha256(&leaf).into();
    let mut node: BytesN<32> = env.crypto().sha256(&inner).into();
    for sib in proof.iter() {
        let (a, b) = if node < sib { (node, sib) } else { (sib, node) };
        let mut cat: Bytes = a.into();
        cat.append(&b.into());
        node = env.crypto().sha256(&cat).into();
    }
    node
}

pub fn base64url(input: &[u8; 32], out: &mut [u8; 43]) {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let (mut buf, mut bits, mut j) = (0u32, 0u32, 0usize);
    for &b in input {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 6 {
            out[j] = A[((buf >> (bits - 6)) & 63) as usize];
            j += 1;
            bits -= 6;
        }
    }
    if bits > 0 {
        out[j] = A[((buf << (6 - bits)) & 63) as usize];
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
}

/// `"<field>":"<value>"` có mặt nguyên văn. clientDataJSON do trình duyệt sinh và authenticator ký: giá trị đã được
/// escape JSON nên một origin/challenge không thể giả một cặp khoá-giá trị khác.
fn has_field(hay: &[u8], field: &[u8], value: &[u8]) -> bool {
    let mut pat = [0u8; 256];
    let n = field.len() + value.len() + 5;
    if n > pat.len() {
        return false;
    }
    pat[0] = b'"';
    pat[1..1 + field.len()].copy_from_slice(field);
    let mut i = 1 + field.len();
    pat[i..i + 3].copy_from_slice(b"\":\"");
    i += 3;
    pat[i..i + value.len()].copy_from_slice(value);
    i += value.len();
    pat[i] = b'"';
    contains(hay, &pat[..n])
}

fn verify_webauthn(env: &Env, pk: &Passkey, payload: &BytesN<32>, sig: &WebAuthnSig) {
    let challenge = if sig.proof.is_empty() { payload.clone() } else { merkle_root(env, payload, &sig.proof) };
    let cd_len = sig.client_data_json.len() as usize;
    if cd_len > MAX_CLIENT_DATA || pk.origin.len() as usize > 200 {
        panic_with_error!(env, Error::BadClientData);
    }
    let mut cd = [0u8; MAX_CLIENT_DATA];
    sig.client_data_json.copy_into_slice(&mut cd[..cd_len]);
    let mut b64 = [0u8; 43];
    base64url(&challenge.to_array(), &mut b64);
    let mut origin = [0u8; 200];
    let olen = pk.origin.len() as usize;
    pk.origin.copy_into_slice(&mut origin[..olen]);
    let cd = &cd[..cd_len];
    if !has_field(cd, b"type", b"webauthn.get") || !has_field(cd, b"challenge", &b64)
        || !has_field(cd, b"origin", &origin[..olen])
    {
        panic_with_error!(env, Error::BadClientData);
    }
    let ad = &sig.authenticator_data;
    if ad.len() < 37 || ad.slice(0..32) != Bytes::from(pk.rp_id_hash.clone()) {
        panic_with_error!(env, Error::BadAuthenticatorData);
    }
    let flags = ad.get(32).unwrap_or(0);
    if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 {
        panic_with_error!(env, Error::BadAuthenticatorData);
    }
    let mut msg = ad.clone();
    msg.append(&env.crypto().sha256(&sig.client_data_json).into());
    let digest: Hash<32> = env.crypto().sha256(&msg);
    env.crypto().secp256r1_verify(&pk.public_key, &digest, &sig.signature);
}

#[contract]
pub struct SmartKeyAccount;

#[contractimpl]
impl SmartKeyAccount {
    /// Deploy không cần quyền: cùng khoá đầu ⇒ cùng hành vi (địa chỉ do salt của người deploy).
    pub fn __constructor(env: Env, first: Key) {
        let mut m = Map::new(&env);
        m.set(0u32, first);
        save(&env, &m);
        env.storage().instance().set(&DataKey::Next, &1u32);
    }

    pub fn keys(env: Env) -> Map<u32, Key> {
        keys(&env)
    }

    pub fn add_key(env: Env, key: Key) -> u32 {
        env.current_contract_address().require_auth();
        let id: u32 = env.storage().instance().get(&DataKey::Next).unwrap_or(1);
        let mut m = keys(&env);
        m.set(id, key);
        save(&env, &m);
        env.storage().instance().set(&DataKey::Next, &(id + 1));
        id
    }

    pub fn remove_key(env: Env, key_id: u32) {
        env.current_contract_address().require_auth();
        let mut m = keys(&env);
        if !m.contains_key(key_id) {
            panic_with_error!(&env, Error::UnknownKey);
        }
        if m.len() == 1 {
            panic_with_error!(&env, Error::LastKey);
        }
        m.remove(key_id);
        save(&env, &m);
    }
}

#[contractimpl]
impl CustomAccountInterface for SmartKeyAccount {
    type Signature = Signature;
    type Error = Error;

    #[allow(non_snake_case)]
    fn __check_auth(env: Env, signature_payload: Hash<32>, signature: Signature, _contexts: Vec<Context>) -> Result<(), Error> {
        let m = keys(&env);
        let payload: BytesN<32> = signature_payload.into();
        match signature {
            Signature::Ed25519(id, sig) => match m.get(id).ok_or(Error::UnknownKey)? {
                Key::Ed25519(pk) => env.crypto().ed25519_verify(&pk, &payload.into(), &sig),
                _ => return Err(Error::WrongKeyKind),
            },
            Signature::WebAuthn(sig) => match m.get(sig.key_id).ok_or(Error::UnknownKey)? {
                Key::Passkey(pk) => verify_webauthn(&env, &pk, &payload, &sig),
                _ => return Err(Error::WrongKeyKind),
            },
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;
