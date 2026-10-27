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

/// CTR-MTX-26 `metaPayId(salt, meta) = keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`, byte-for-byte EVM.
pub fn meta_pay_id(salt: &[u8; 32], meta: &[u8]) -> [u8; 32] {
    env::keccak256_array([&b"scaas.pay.meta"[..], salt, &env::keccak256_array(meta)].concat())
}

/// CTR-MTX-10 `payLane(p) = keccak256("scaas.pay.lane" ‖ p)`.
pub fn pay_lane(p: &[u8; 32]) -> [u8; 32] {
    env::keccak256_array([&b"scaas.pay.lane"[..], p].concat())
}

/// CTR-MTX-27 `ref = keccak256("scaas.relayfee" ‖ network ‖ target ‖ keccak256(call) ‖ salt)`; `salt` = the payment
/// op's payer-signed `extra` (spec §2 row 8).
pub fn relay_ref(network: &[u8; 32], target: &[u8], call: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    env::keccak256_array([&b"scaas.relayfee"[..], network, target, &env::keccak256_array(call), salt].concat())
}
