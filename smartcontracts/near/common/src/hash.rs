//! Hashes of the signed forms (spec §3.5): the op text and the NEP-413 hash an ed25519 key signs.
use near_sdk::{borsh, env, AccountId};

/// NEP-413 prefix tag `2^31 + 413`, written u32 LE before the payload.
pub const NEP413_TAG: u32 = (1 << 31) + 413;

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The signed text, NET-ALL-23 first build: `"scaas.metaop.v1:" ‖ hex(digest)`.
pub fn signed_text(digest: &[u8; 32]) -> String {
    format!("scaas.metaop.v1:{}", hex(digest))
}

/// `sha256(u32 LE 2^31+413 ‖ Borsh { message = signed_text, nonce = digest, recipient, callback_url = None })`.
pub fn nep413_hash(digest: &[u8; 32], recipient: &AccountId) -> [u8; 32] {
    let mut b = NEP413_TAG.to_le_bytes().to_vec();
    borsh::to_writer(&mut b, &(signed_text(digest), digest, recipient.as_str(), None::<String>)).expect("borsh");
    env::sha256_array(b)
}
