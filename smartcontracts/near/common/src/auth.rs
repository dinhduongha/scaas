//! Signature checks (spec §3.5): ed25519 by `env::ed25519_verify` over the NEP-413 hash, secp256k1 by `env::ecrecover`
//! over the op digest (malleability flag set: high s refused), P-256 passkeys by `webauthn::verify` (challenge = the op
//! digest), `msig` from its key data. Only SCaaS key records sign (spec §3.3, R7): a NEAR access key never does, and a
//! `near-account` msig member counts only as the call's predecessor.
use crate::hash::nep413_hash;
use crate::ua::{self, KeyRecord, KIND_ED25519, KIND_MSIG, KIND_NEAR_ACCOUNT, KIND_SECP256K1, KIND_WEBAUTHN_P256};
use crate::webauthn::{self, AuthError};
use near_sdk::{env, near, AccountId, Gas};

type R<T> = Result<T, &'static str>;

/// `Msig.sigs`: (member index in `key_data`, that member's signature), indexes strictly increasing.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Auth {
    Ed25519 { key: [u8; 32], sig: [u8; 64] },
    Secp256k1 { key: [u8; 64], sig: [u8; 64], v: u8 },
    Passkey { key: [u8; 64], authenticator_data: Vec<u8>, client_data_json: Vec<u8>, sig: [u8; 64] },
    Msig { key_data: Vec<u8>, sigs: Vec<(u8, Auth)> },
}

impl Auth {
    /// The key record this auth signs as (a passkey's rpIdHash from its authenticatorData).
    pub fn key(&self) -> R<KeyRecord> {
        let (kind, key_data) = match self {
            Auth::Ed25519 { key, .. } => (KIND_ED25519, key.to_vec()),
            Auth::Secp256k1 { key, .. } => (KIND_SECP256K1, key.to_vec()),
            Auth::Passkey { key, authenticator_data: ad, .. } => {
                (KIND_WEBAUTHN_P256, [&key[..], ad.get(..32).ok_or("passkey authenticatorData")?].concat())
            }
            Auth::Msig { key_data, .. } => (KIND_MSIG, key_data.clone()),
        };
        Ok(KeyRecord { kind, key_data })
    }
}

/// One ed25519 (`ed25519_verify`) or secp256k1 (`ecrecover`) signature, incl. its msig member checks (< 0.5 Tgas).
pub const GAS_SIG_KEY: Gas = Gas::from_tgas(1);
/// One P-256 passkey signature: 20.005 Tgas per verify at opt-level 3 (Task 1, `runs/2026-10-28-p256-spike.txt`) × 1.25.
pub const GAS_SIG_PASSKEY: Gas = Gas::from_tgas(25);

/// The verify gas a call checking `auth` budgets (ruling T8-I2; the DEX legs, the relay router's hold): one figure per
/// signature by kind, an msig's member signatures summed (a `near-account` member signs as the predecessor, free).
pub fn sig_gas(auth: &Auth) -> Gas {
    fn g(a: &Auth) -> u64 {
        match a {
            Auth::Passkey { .. } => GAS_SIG_PASSKEY.as_gas(),
            Auth::Ed25519 { .. } | Auth::Secp256k1 { .. } => GAS_SIG_KEY.as_gas(),
            Auth::Msig { sigs, .. } => sigs.iter().map(|(_, a)| g(a)).fold(0, u64::saturating_add),
        }
    }
    Gas::from_gas(g(auth))
}

/// Largest `client_data_json` / `authenticator_data` of a passkey signature that `sig_gas` budgets (review T8-M4,
/// controller ruling). The budget is a fixed 25 Tgas per passkey, but the verify cost grows with these sizes (scan and
/// sha256 of clientDataJSON, sha256 of authenticatorData ‖ hash); real assertions are ≈ 400 B. Without the cap a signer
/// could pad assertions until the budgeted call runs out of gas.
pub const PASSKEY_FIELD_MAX: usize = 1024;

/// Every passkey signature of `auth` (directly or as an msig member) within `PASSKEY_FIELD_MAX`.
pub fn passkey_fields(auth: &Auth) -> R<()> {
    match auth {
        Auth::Passkey { authenticator_data: ad, client_data_json: cd, .. } => {
            if cd.len() > PASSKEY_FIELD_MAX || ad.len() > PASSKEY_FIELD_MAX {
                return Err("passkey clientDataJSON / authenticatorData over 1024 bytes");
            }
            Ok(())
        }
        Auth::Msig { sigs, .. } => sigs.iter().try_for_each(|(_, a)| passkey_fields(a)),
        Auth::Ed25519 { .. } | Auth::Secp256k1 { .. } => Ok(()),
    }
}

/// `auth` signs `digest` for `recipient` (the token). `origins`: the subject's passkey origins, or `None` for a lazily
/// opened account, whose passkeys may sign from any origin (each assertion's own). Returns the origins of the
/// assertions checked under `None`.
pub fn verify(
    auth: &Auth,
    digest: &[u8; 32],
    recipient: &AccountId,
    predecessor: &AccountId,
    origins: Option<&[String]>,
) -> R<Vec<String>> {
    let Auth::Msig { key_data, sigs } = auth else {
        return Ok(leaf(auth, digest, recipient, origins)?.into_iter().collect());
    };
    let m = ua::parse_msig(key_data)?;
    let caller = ua::native_id(predecessor);
    let mut weight: u32 =
        m.members.iter().filter(|x| x.kind == KIND_NEAR_ACCOUNT && x.id == caller).map(|x| x.weight as u32).sum();
    let mut seen = Vec::new();
    let mut last: Option<u8> = None;
    for (i, a) in sigs {
        if last.is_some_and(|l| *i <= l) {
            return Err("msig signatures not in member order");
        }
        last = Some(*i);
        let mbr = m.members.get(*i as usize).ok_or("msig member index")?;
        if mbr.kind == KIND_NEAR_ACCOUNT {
            return Err("a near-account msig member counts only as the predecessor");
        }
        if matches!(a, Auth::Msig { .. }) {
            return Err("msig inside msig");
        }
        let k = a.key()?;
        if k.kind != mbr.kind || ua::ua_of(k.kind, &k.key_data) != mbr.id {
            return Err("msig member key mismatch");
        }
        if let Some(o) = leaf(a, digest, recipient, origins)? {
            if !seen.contains(&o) {
                seen.push(o);
            }
        }
        weight += mbr.weight as u32;
    }
    if weight < m.threshold as u32 {
        return Err("msig threshold not met");
    }
    Ok(seen)
}

fn leaf(auth: &Auth, digest: &[u8; 32], recipient: &AccountId, origins: Option<&[String]>) -> R<Option<String>> {
    match auth {
        Auth::Ed25519 { key, sig } => {
            env::ed25519_verify(sig, nep413_hash(digest, recipient), key).then_some(None).ok_or("ed25519 signature")
        }
        Auth::Secp256k1 { key, sig, v } => {
            // `true`: refuses high s (and r, s out of range); v is the recovery id.
            (*v <= 1 && env::ecrecover(digest, sig, *v, true) == Some(*key))
                .then_some(None)
                .ok_or("secp256k1 signature (low s, recovery id 0 / 1)")
        }
        Auth::Passkey { key, authenticator_data: ad, client_data_json: cd, sig } => {
            let rp: [u8; 32] = ad.get(..32).ok_or("passkey authenticatorData")?.try_into().unwrap();
            let own = match origins {
                Some(_) => None,
                None => Some(webauthn::origin(cd, digest).ok_or("passkey clientDataJSON (type, challenge or origin)")?),
            };
            let list = origins.unwrap_or_else(|| std::slice::from_ref(own.as_ref().unwrap()));
            webauthn::verify(key, digest, ad, cd, sig, &rp, list).map_err(|e| match e {
                AuthError::ClientData => "passkey clientDataJSON (type, challenge or origin)",
                AuthError::AuthenticatorData => "passkey authenticatorData (rpIdHash or UP / UV flags)",
                AuthError::HighS => "passkey signature high s",
                AuthError::BadKey => "passkey key",
                AuthError::BadSignature => "passkey signature",
            })?;
            Ok(own)
        }
        Auth::Msig { .. } => Err("msig inside msig"),
    }
}
