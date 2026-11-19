// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The classic-curve signers (spec §3, §5.1; T3a), on k256 / p256 0.14 (`crypto-bigint` 0.7, RUSTSEC-2026-0387 fixed):
//! `0x0101` ECDSA P-256 over `sha256(ua_msg)`, RFC 6979 (no extra entropy), low-s, `r ‖ s`; `0x0102` ed25519 over `ua_msg`;
//! `0x0103` BIP-340 over `ua_msg`, `aux` 32 bytes from the OS RNG; `0x0108` ECDSA secp256k1 over `ua_msg` with no prehash,
//! RFC 6979, low-s, `r ‖ s ‖ v` (v ∈ {27, 28}). Native keys: secp256k1 `r ‖ s ‖ v` or ed25519 over the key-proof digest or a
//! raw digest behind [`AllowRawDigest`]. A UA key signs only the `ua_msg` it builds itself from a purpose of `PURPOSES` (or
//! `pop` v2) and its own kind (CLI-SGN-29). Every operation reads its secret through `Handle::with`, under the store's read
//! guard with the generation check (spec §8.2). The PQ kinds sign through `pqsign` (T3b), the pairing kinds through
//! `pairing` (T3c). UNAUDITED.
use super::signer::{AllowRawDigest, KeyRef, SigRole, SignRequest, Signer};
use super::{derive, pairing, pqsign, Error, NativeKey, NativeScheme, Network, Result, UaKey};
use crate::{
    keccak256, member_digest, purpose_tag, ua_message, ua_portable::portable_record_purposes,
    UAError, PURPOSES,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

const KEY_PROOF_PREFIX: &[u8] = b"scaas-subject-key-proof-v1";

/// The raw-message bound (CLI-UAL-44; spec 2026-11-17-ua-rs-native §8): Aptos's 64 KiB transaction limit plus its prefix, with
/// room; Solana's 1,232-byte and Hedera's 6 KiB limits lie below.
pub const MAX_RAW_MESSAGE: usize = 131_072;
/// The off-chain envelopes a SCaaS family verifies (Solana OCMS v1, Aptos AIP-62 `fullMessage`): never through the raw path, so
/// `sign_message` opens no SCaaS payload to blind signing. A family envelope added later with another prefix joins this list.
const ENVELOPES: [&[u8]; 2] = [b"\xffsolana offchain", b"APTOS\n"];

/// A signature scheme of T3a.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    /// secp256k1 ECDSA over a 32-byte digest, `r ‖ s ‖ v`.
    Secp256k1,
    /// P-256 ECDSA over `sha256(message)`, `r ‖ s`.
    P256,
    Ed25519,
    Bip340,
}

/// The scheme of UA kind `kind`: `Argument` for a MuSig2 participant (it signs through its session), every kind with no key
/// of its own, the PQ kinds (`pqsign`) and the pairing kinds (`pairing`).
fn ua_scheme(kind: u16) -> Result<Scheme> {
    match kind {
        0x0101 => Ok(Scheme::P256),
        0x0102 => Ok(Scheme::Ed25519),
        0x0103 => Ok(Scheme::Bip340),
        0x0108 => Ok(Scheme::Secp256k1),
        _ => Err(Error::Argument),
    }
}

fn arr32(s: &[u8]) -> Result<&[u8; 32]> {
    s.try_into().map_err(|_| Error::Argument)
}

/// The scheme's signature of `msg` with the 32-byte `secret`; `aux` for BIP-340 only (required there).
fn sign_scheme(
    scheme: Scheme,
    secret: &[u8],
    msg: &[u8],
    aux: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    match scheme {
        Scheme::Secp256k1 => {
            let sk = k256::ecdsa::SigningKey::from_slice(secret).map_err(|_| Error::Argument)?;
            // RFC 6979 with no additional data; k256 normalises to low-s and flips the recovery id with it
            let (sig, rec) = sk.sign_prehash_recoverable(arr32(msg)?);
            let mut out = sig.to_bytes().to_vec();
            out.push(27 + rec.to_byte());
            Ok(out)
        }
        Scheme::P256 => {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let sk = p256::ecdsa::SigningKey::from_slice(secret).map_err(|_| Error::Argument)?;
            let sig: p256::ecdsa::Signature = sk
                .sign_prehash(&Sha256::digest(msg))
                .map_err(|_| Error::Argument)?;
            // p256 does not normalise (NORMALIZE_S = false); the chains refuse high s
            Ok(sig.normalize_s().to_bytes().to_vec())
        }
        Scheme::Ed25519 => {
            use ed25519_dalek::Signer as _;
            Ok(ed25519_dalek::SigningKey::from_bytes(arr32(secret)?)
                .sign(msg)
                .to_bytes()
                .to_vec())
        }
        Scheme::Bip340 => {
            let sk = k256::schnorr::SigningKey::from_slice(secret).map_err(|_| Error::Argument)?;
            let sig = sk
                .sign_raw(msg, aux.ok_or(Error::Argument)?)
                .map_err(|_| Error::Argument)?
                .to_bytes();
            // BIP-340 Sign's last step (k256 runs it under `debug_assertions` only): a faulty signature never leaves (T21 L08)
            if !crate::verify::bip340(&sk.verifying_key().to_bytes(), arr32(msg)?, &sig) {
                return Err(Error::Argument);
            }
            Ok(sig.to_vec())
        }
    }
}

/// 32 bytes of the OS RNG (`rand_core` 0.6 `OsRng`); under feature `vectors` a test can make it fail
/// ([`vectors_fail_os_rng`]).
pub(super) fn os_aux() -> Result<[u8; 32]> {
    #[cfg(feature = "vectors")]
    if vectors::FAIL_RNG.with(std::cell::Cell::get) {
        return Err(Error::Rng);
    }
    let mut aux = [0u8; 32];
    OsRng.try_fill_bytes(&mut aux).map_err(|_| Error::Rng)?;
    Ok(aux)
}

/// The registry's role of a purpose: `verifyPop` for the portable record purposes (`ua_portable::portable_record_purposes`).
fn role_of(purpose: &[u8; 32]) -> SigRole {
    if portable_record_purposes().contains(purpose) {
        SigRole::Pop
    } else {
        SigRole::Authorization
    }
}

/// `purpose` a tag of `PURPOSES` (v1) or a portable record purpose (`pop` v2, `pqz-scoped-key`), else `UAPurposeUnknown`.
pub(super) fn check_purpose(purpose: &[u8; 32]) -> Result<()> {
    let known = portable_record_purposes().contains(purpose)
        || PURPOSES
            .iter()
            .any(|p| purpose_tag(p).is_ok_and(|t| t == *purpose));
    if !known {
        return Err(Error::Ua(UAError::PurposeUnknown));
    }
    Ok(())
}

/// The request of `sign_ua` for a key of `kind` (the `UASig` builder's too); `0x0100` (an authenticator) is asked
/// `WebAuthn` with the same `ua_msg`.
pub(super) fn ua_request(kind: u16, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<SignRequest> {
    check_purpose(purpose)?;
    Ok(request(
        kind,
        ua_message(kind, purpose, digest)?,
        role_of(purpose),
    ))
}

fn request(kind: u16, ua_msg: [u8; 32], role: SigRole) -> SignRequest {
    if kind == 0x0100 {
        SignRequest::WebAuthn { challenge: ua_msg }
    } else {
        SignRequest::UaMsg { kind, ua_msg, role }
    }
}

/// The request of a sealed container's sender of `kind` (spec §6.3, MD-10): `uaMessage(kind, seal, digest)` under the off-chain
/// purpose, role `Authorization`; only the container builder (`seal`) asks it: `check_purpose` refuses that purpose everywhere else.
pub(super) fn seal_request(kind: u16, digest: &[u8; 32]) -> Result<SignRequest> {
    Ok(request(
        kind,
        ua_message(kind, &crate::seal_purpose_tag(), digest)?,
        SigRole::Authorization,
    ))
}

/// CTR-UA-46: the request of a single key over app `app_id`'s portable record, `uaMessage(kind, app_purpose(app_id), digest)`, role
/// `Pop` (the registry's `requirePortableApp` checks it with the kind's `verifyPop`, as every portable record); `app_id` 0 refused.
pub(super) fn app_request(kind: u16, app_id: &[u8; 32], digest: &[u8; 32]) -> Result<SignRequest> {
    Ok(request(
        kind,
        ua_message(kind, &crate::ua_portable::app_purpose(app_id)?, digest)?,
        SigRole::Pop,
    ))
}

/// The request of `sign_member` for a key of `kind` (the `msig` builder's too): always `Authorization`.
pub(super) fn member_request(
    kind: u16,
    structure_ua: &[u8; 32],
    structure_ua_msg: &[u8; 32],
) -> Result<SignRequest> {
    let digest = member_digest(structure_ua, structure_ua_msg);
    Ok(request(
        kind,
        ua_message(kind, &purpose_tag("member")?, &digest)?,
        SigRole::Authorization,
    ))
}

impl UaKey {
    fn ua_request(&self, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<SignRequest> {
        ua_request(self.kind, purpose, digest)
    }

    fn member_request(
        &self,
        structure_ua: &[u8; 32],
        structure_ua_msg: &[u8; 32],
    ) -> Result<SignRequest> {
        member_request(self.kind, structure_ua, structure_ua_msg)
    }

    /// The signature of `req` (a `UaMsg` of this key's kind); the randomness fixed only by the `vectors` entry points (BIP-340
    /// and scaas Schnorr `aux`, the PQ kinds' `rnd` / `opt_rand` / Falcon's 88 bytes), else from the OS RNG. The BLS kinds
    /// sign under the domain of the request's role.
    fn sign_ua_msg(&self, req: &SignRequest, fixed: Option<&[u8]>) -> Result<Vec<u8>> {
        let SignRequest::UaMsg { kind, ua_msg, role } = req else {
            return Err(Error::Argument);
        };
        if *kind != self.kind {
            return Err(Error::Argument);
        }
        if pqsign::is_pq(self.kind) {
            return self
                .secret
                .with(|s| pqsign::sign(self.kind, s, ua_msg, fixed))?;
        }
        if pairing::is_pairing(self.kind) {
            return self
                .secret
                .with(|s| pairing::sign(self.kind, s, &self.key_data, ua_msg, *role, fixed))?;
        }
        let scheme = ua_scheme(self.kind)?;
        let aux = match (scheme, fixed) {
            (Scheme::Bip340, None) => Some(os_aux()?),
            (_, f) => f.map(arr32).transpose()?.copied(),
        };
        self.secret
            .with(|s| sign_scheme(scheme, s, ua_msg, aux.as_ref()))?
    }

    /// The signature of `ua_msg = uaMessage(kind, purpose, digest)`; `purpose` a tag of `PURPOSES` or `pop` v2.
    pub fn sign_ua(&self, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<Vec<u8>> {
        self.sign_ua_msg(&self.ua_request(purpose, digest)?, None)
    }

    /// CTR-UA-46: the signature of `uaMessage(kind, app_purpose(app_id), digest)`, app `app_id`'s portable record (role `Pop`).
    pub fn sign_ua_app(&self, app_id: &[u8; 32], digest: &[u8; 32]) -> Result<Vec<u8>> {
        self.sign_ua_msg(&app_request(self.kind, app_id, digest)?, None)
    }

    /// As an `msig` member: the signature of `uaMessage(kind, member, memberDigest(structure_ua, structure_ua_msg))`.
    pub fn sign_member(
        &self,
        structure_ua: &[u8; 32],
        structure_ua_msg: &[u8; 32],
    ) -> Result<Vec<u8>> {
        self.sign_ua_msg(&self.member_request(structure_ua, structure_ua_msg)?, None)
    }
}

impl Signer for UaKey {
    fn key_ref(&self) -> KeyRef {
        KeyRef::Ua {
            kind: self.kind,
            key_data: self.key_data.clone(),
        }
    }
    fn sign_request(&self, req: &SignRequest) -> Result<Vec<u8>> {
        self.sign_ua_msg(req, None)
    }
}

impl NativeKey {
    /// The address as the network prints it (clientkeys `describe`); `None` for `ton` and `hedera_ed25519`.
    pub fn address(&self) -> Option<String> {
        derive::native_address(self.network, self.coin_type, &self.public_key)
    }

    /// A Bitcoin key's witness program (ua-rs-native spec §5.1): `(0, HASH160(pk))` (P2WPKH) or `(1, x(Q))` (P2TR), for the
    /// app's `scriptPubKey` and a regtest address; `None` on every other network.
    pub fn witness_program(&self) -> Option<(u8, Vec<u8>)> {
        derive::witness_program(self.network, &self.public_key)
    }

    /// The key proof: the signature of `keccak256("scaas-subject-key-proof-v1" ‖ challenge)`.
    pub fn sign_key_proof(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        sign_key_proof_by(self, challenge)
    }

    /// A raw 32-byte digest, only with the marker value (CLI-SGN-40).
    pub fn sign_digest(&self, digest: &[u8; 32], allow: AllowRawDigest) -> Result<Vec<u8>> {
        sign_digest_by(self, digest, allow)
    }

    /// A native chain's message (1 to [`MAX_RAW_MESSAGE`] bytes), only with the marker value (CLI-UAL-44): Ed25519 (RFC 8032) and
    /// sr25519 keys; `Argument` for a secp256k1 or Taproot key, an empty or over-long message, or one that starts with an off-chain
    /// envelope a SCaaS family verifies (`0xff ‖ "solana offchain"`, `"APTOS\n"`). The caller builds it in-process from its own
    /// encoder's transaction (CLI-SGN-54).
    pub fn sign_message(&self, message: &[u8], allow: AllowRawDigest) -> Result<Vec<u8>> {
        sign_message_by(self, message, allow)
    }

    /// NEAR (spec §8.1, CLI-UAL-63 (13)): ed25519 over `sha256(tx_borsh)`, the Borsh `Transaction` the app's encoder made.
    /// `Argument` for a NEP-461 tagged payload: first four bytes, little-endian, at or above 2^30 (2^30 to 2^31 − 1 on-chain
    /// actions such as a NEP-366 delegate action, 2^31 and up off-chain messages such as NEP-413; T13 C6). A `Transaction` starts
    /// with its `signer_id`'s Borsh length, at most 64.
    pub fn sign_near_transaction(&self, tx_borsh: &[u8], _: AllowRawDigest) -> Result<Vec<u8>> {
        if tx_borsh
            .get(..4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .is_some_and(|b| u32::from_le_bytes(b) >= NEP461_MIN)
        {
            return Err(Error::Argument);
        }
        self.envelope(Network::Near, tx_borsh, |t| Sha256::digest(t).to_vec())
    }

    /// Sui: ed25519 over `blake2b-256(0x00 0x00 0x00 ‖ tx_bcs)` (intent `TransactionData`, `V0`, app `Sui`).
    pub fn sign_sui_transaction(&self, tx_bcs: &[u8], _: AllowRawDigest) -> Result<Vec<u8>> {
        use blake2::Digest as _;
        self.envelope(Network::Sui, tx_bcs, |t| {
            blake2::Blake2b::<blake2::digest::consts::U32>::digest([&[0u8; 3][..], t].concat())
                .to_vec()
        })
    }

    /// Stellar: ed25519 over `sha256(network_id ‖ 0x00000002 ‖ tx_xdr)` (`ENVELOPE_TYPE_TX`; `network_id` = `sha256(passphrase)`).
    pub fn sign_stellar_transaction(
        &self,
        network_id: &[u8; 32],
        tx_xdr: &[u8],
        _: AllowRawDigest,
    ) -> Result<Vec<u8>> {
        self.envelope(Network::Stellar, tx_xdr, |t| {
            Sha256::digest([&network_id[..], &[0, 0, 0, 2], t].concat()).to_vec()
        })
    }

    /// The SS58 address of a Polkadot key at `prefix` (0 to 16,383, not 46 or 47; spec §7.4); `Argument` on any other network.
    pub fn ss58_address(&self, prefix: u16) -> Result<String> {
        if self.network != Network::Polkadot {
            return Err(Error::Argument);
        }
        super::substrate::ss58(&self.public_key, prefix)
    }

    /// Hedera Ed25519: ed25519 over the transaction's `bodyBytes` as given.
    pub fn sign_hedera_transaction(&self, body_bytes: &[u8], _: AllowRawDigest) -> Result<Vec<u8>> {
        self.envelope(Network::HederaEd25519, body_bytes, <[u8]>::to_vec)
    }

    /// The envelope calls' common part: this key's network only, 1 to [`MAX_RAW_MESSAGE`] bytes, the built bytes signed as the
    /// scheme's message (no GRAM / TON call: CLI-UAL-63 (14)).
    fn envelope(
        &self,
        network: Network,
        tx: &[u8],
        build: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> Result<Vec<u8>> {
        if self.network != network || tx.is_empty() || tx.len() > MAX_RAW_MESSAGE {
            return Err(Error::Argument);
        }
        self.sign_request(&SignRequest::RawMessage { message: build(tx) })
    }
}

/// The lowest prefix NEP-461 reserves (on-chain actions from 2^30, off-chain messages from 2^31): no Borsh `Transaction` starts
/// at or above it.
const NEP461_MIN: u32 = 1 << 30;

/// [`NativeKey::sign_key_proof`] by any [`Signer`] (spec §9.4).
pub fn sign_key_proof_by(key: &dyn Signer, challenge: &[u8]) -> Result<Vec<u8>> {
    key.sign_request(&SignRequest::KeyProof {
        digest: keccak256(&[KEY_PROOF_PREFIX, challenge].concat()),
    })
}

/// [`NativeKey::sign_digest`] by any [`Signer`] (spec §9.4), only with the marker value (CLI-SGN-40).
pub fn sign_digest_by(key: &dyn Signer, digest: &[u8; 32], _: AllowRawDigest) -> Result<Vec<u8>> {
    key.sign_request(&SignRequest::RawDigest { digest: *digest })
}

/// [`NativeKey::sign_message`] by any [`Signer`], only with the marker value; the bound and the envelope refusal hold for every
/// signer (a `UaKey` refuses the request: `Argument`).
pub fn sign_message_by(key: &dyn Signer, message: &[u8], _: AllowRawDigest) -> Result<Vec<u8>> {
    message_ok(message)?;
    key.sign_request(&SignRequest::RawMessage {
        message: message.to_vec(),
    })
}

/// The raw-message checks of [`sign_message_by`]: 1 to [`MAX_RAW_MESSAGE`] bytes, no SCaaS off-chain envelope. No first-byte rule
/// beyond the envelopes: on an Ed25519 or sr25519 key `0x05` or `0x19 0x01` is chain data (a Substrate call of pallet 5, a Solana
/// message with five signers), and no secp256k1 key reaches this call (CLI-UAL-63 (11) withdrawn, T13 C1).
fn message_ok(message: &[u8]) -> Result<()> {
    if message.is_empty()
        || message.len() > MAX_RAW_MESSAGE
        || ENVELOPES.iter().any(|p| message.starts_with(p))
    {
        return Err(Error::Argument);
    }
    Ok(())
}

/// The bytes a native key of `network` signs for `req` (ua-rs-native spec §4.2): a raw digest on every network; a key proof on
/// the networks with a SCaaS family; an EIP-712 digest or a transaction's sighash on the secp256k1 networks of the nine; a raw
/// message on an Ed25519 or sr25519 key. `Argument` for any other request.
pub(super) fn native_bytes(network: Network, req: &SignRequest) -> Result<Vec<u8>> {
    let scheme = network.scheme();
    let evm = scheme == NativeScheme::Secp256k1Ecdsa && network.key_proof();
    match req {
        SignRequest::RawDigest { digest } => Ok(digest.to_vec()),
        SignRequest::KeyProof { digest } if network.key_proof() => Ok(digest.to_vec()),
        SignRequest::Eip712 {
            domain_separator,
            struct_hash,
            ..
        } if evm => Ok(super::eip712::eip712_digest(domain_separator, struct_hash).to_vec()),
        SignRequest::Transaction { sighash, .. } if evm => Ok(sighash.to_vec()),
        SignRequest::RawMessage { message }
            if matches!(scheme, NativeScheme::Ed25519 | NativeScheme::Sr25519) =>
        {
            Ok(message.clone())
        }
        _ => Err(Error::Argument),
    }
}

impl Signer for NativeKey {
    fn key_ref(&self) -> KeyRef {
        KeyRef::Native {
            network: self.network,
            coin_type: self.coin_type,
            address: self.address(),
            public_key: self.public_key.clone(),
        }
    }
    /// The requests of [`native_bytes`], in the network's scheme: secp256k1 `r ‖ s ‖ v`, ed25519 64 bytes.
    fn sign_request(&self, req: &SignRequest) -> Result<Vec<u8>> {
        let bytes = native_bytes(self.network, req)?;
        let scheme = match self.network.scheme() {
            NativeScheme::Secp256k1Ecdsa => Scheme::Secp256k1,
            NativeScheme::Ed25519 => Scheme::Ed25519,
            NativeScheme::Bip340Taproot => {
                let aux = os_aux()?;
                return self.secret.with(|s| taproot_sign(s, &bytes, &aux, None))?;
            }
            NativeScheme::Sr25519 => {
                let r = os_aux()?;
                return self
                    .secret
                    .with(|s| super::substrate::sign(s, &bytes, r, &self.public_key))?;
            }
        };
        self.secret.with(|s| sign_scheme(scheme, s, &bytes, None))?
    }
}

/// BIP-86 key-path signature (spec §5.2): `d = d0` or `n − d0` (even `y` of `P`), BIP-340 `Sign(d + t mod n, msg, aux)`, then
/// BIP-340 Verify against `check` (the output key `x(Q)` in the release path): a faulty signature never leaves. The base scalar
/// `d0` (a `NonZeroScalar`: `Zeroize` but no `Drop`, T13 C3) and the negated and tweaked scalars are wiped as they drop, on every
/// exit (k256's `schnorr::SigningKey` wipes its own on drop, plan T0).
fn taproot_sign(
    d0: &[u8],
    msg: &[u8],
    aux: &[u8; 32],
    check: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    use k256::elliptic_curve::sec1::ToSec1Point as _;
    use k256::elliptic_curve::PrimeField as _;
    let d0 =
        zeroize::Zeroizing::new(k256::NonZeroScalar::try_from(d0).map_err(|_| Error::Argument)?);
    let p = k256::PublicKey::from_secret_scalar(&d0).to_sec1_point(true);
    let x: [u8; 32] = p
        .as_bytes()
        .get(1..33)
        .ok_or(Error::Argument)?
        .try_into()
        .map_err(|_| Error::Argument)?;
    let out = derive::taproot_tweak(&x)?;
    let t = Option::<k256::Scalar>::from(k256::Scalar::from_repr(out.tweak.into()))
        .ok_or(Error::Argument)?;
    // the negated and tweaked scalars live in this block only (wiped as they drop, before signing)
    let sk = {
        let d = zeroize::Zeroizing::new(if p.as_bytes().first() == Some(&3) {
            -**d0
        } else {
            **d0
        });
        let tweaked = zeroize::Zeroizing::new(*d + t);
        let bytes = zeroize::Zeroizing::new(tweaked.to_repr());
        k256::schnorr::SigningKey::from_bytes(&bytes).map_err(|_| Error::Argument)?
    };
    let sig = sk
        .sign_raw(msg, aux)
        .map_err(|_| Error::Argument)?
        .to_bytes();
    if !crate::verify::bip340(check.unwrap_or(&out.output_key), arr32(msg)?, &sig) {
        return Err(Error::Argument);
    }
    Ok(sig.to_vec())
}

/// Test-only entry points (feature `vectors`, never in a release build): fixed `aux`, the requests, a raw secret.
#[cfg(feature = "vectors")]
mod vectors {
    use super::*;

    impl NativeKey {
        /// [`NativeKey::sign_digest`] with fixed randomness: the Taproot `aux` (the release path draws it from the OS RNG).
        pub fn vectors_sign_digest_fixed(
            &self,
            digest: &[u8; 32],
            r: &[u8; 32],
        ) -> Result<Vec<u8>> {
            match self.network.scheme() {
                NativeScheme::Bip340Taproot => {
                    self.secret.with(|s| taproot_sign(s, digest, r, None))?
                }
                NativeScheme::Sr25519 => self
                    .secret
                    .with(|s| crate::wallet::substrate::sign(s, digest, *r, &self.public_key))?,
                _ => self.sign_digest(digest, AllowRawDigest),
            }
        }
        /// [`NativeKey::sign_message`] with fixed randomness: the sr25519 `r` (ed25519 ignores it), the same checks.
        pub fn vectors_sign_message_fixed(&self, message: &[u8], r: &[u8; 32]) -> Result<Vec<u8>> {
            match self.network.scheme() {
                NativeScheme::Sr25519 => {
                    message_ok(message)?;
                    self.secret.with(|s| {
                        crate::wallet::substrate::sign(s, message, *r, &self.public_key)
                    })?
                }
                _ => self.sign_message(message, AllowRawDigest),
            }
        }
        /// The sr25519 signer with its self-verify against `claimed_public_key` (the fault hook: a wrong key gives `Argument`).
        pub fn vectors_sr25519_sign_check(
            &self,
            message: &[u8],
            r: &[u8; 32],
            claimed_public_key: &[u8; 32],
        ) -> Result<Vec<u8>> {
            self.secret
                .with(|s| crate::wallet::substrate::sign(s, message, *r, claimed_public_key))?
        }
    }

    thread_local! {
        pub(super) static FAIL_RNG: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    /// While `on`, this thread's `os_aux()` fails (`Error::Rng`): a release signer must return it, never panic.
    pub fn vectors_fail_os_rng(on: bool) {
        FAIL_RNG.with(|f| f.set(on));
    }
    /// How often the last one-shot RNG this thread used was read (1 per signature and per soft step).
    pub fn vectors_one_shot_reads() -> u32 {
        crate::wallet::substrate::vectors::one_shot_reads()
    }
    impl NativeKey {}

    /// The release Taproot signer over a raw internal secret (BIP-341 `keyPathSpending` rows): negate, tweak, BIP-340, self-check.
    pub fn vectors_taproot_sign(
        internal_secret: &[u8; 32],
        sighash: &[u8; 32],
        aux: &[u8; 32],
    ) -> Result<Vec<u8>> {
        taproot_sign(internal_secret, sighash, aux, None)
    }

    /// [`vectors_taproot_sign`] with its self-check against `output_key` (the fault hook: a wrong key must give `Argument`).
    pub fn vectors_taproot_sign_check(
        internal_secret: &[u8; 32],
        sighash: &[u8; 32],
        aux: &[u8; 32],
        output_key: &[u8; 32],
    ) -> Result<Vec<u8>> {
        taproot_sign(internal_secret, sighash, aux, Some(output_key))
    }

    impl UaKey {
        /// `sign_ua` with fixed randomness: BIP-340 and scaas Schnorr `aux` (32 B), ML-DSA `rnd` (32 B, zero = deterministic), SLH-DSA
        /// `opt_rand` (16 B, `PK.seed` = deterministic), Falcon nonce ‖ sampler seed (88 B).
        pub fn vectors_sign_ua_fixed(
            &self,
            purpose: &[u8; 32],
            digest: &[u8; 32],
            fixed: &[u8],
        ) -> Result<Vec<u8>> {
            self.sign_ua_msg(&self.ua_request(purpose, digest)?, Some(fixed))
        }
        /// A raw `ua_msg` of this key's kind with fixed randomness (pq_kat.json signs a `pop` v1 message `sign_ua` refuses).
        pub fn vectors_sign_ua_msg(&self, ua_msg: &[u8; 32], fixed: &[u8]) -> Result<Vec<u8>> {
            let req = SignRequest::UaMsg {
                kind: self.kind,
                ua_msg: *ua_msg,
                role: SigRole::Authorization,
            };
            self.sign_ua_msg(&req, Some(fixed))
        }
        /// The request `sign_ua` signs.
        pub fn vectors_request(
            &self,
            purpose: &[u8; 32],
            digest: &[u8; 32],
        ) -> Result<SignRequest> {
            self.ua_request(purpose, digest)
        }
        /// The request `sign_member` signs.
        pub fn vectors_member_request(
            &self,
            structure_ua: &[u8; 32],
            structure_ua_msg: &[u8; 32],
        ) -> Result<SignRequest> {
            self.member_request(structure_ua, structure_ua_msg)
        }
    }
}

#[cfg(feature = "vectors")]
pub use vectors::{
    vectors_fail_os_rng, vectors_one_shot_reads, vectors_taproot_sign, vectors_taproot_sign_check,
};

/// The scheme primitive of `kind` over `msg` with a raw `secret` (feature `vectors`: the external answers): `0x0101` signs
/// `sha256(msg)`; `0x0108` and the native EVM kind `0x0001` sign the 32-byte `msg` as it is; `0x0102` ed25519; `0x0103`
/// BIP-340 with `aux` (required).
#[cfg(feature = "vectors")]
pub fn sign_raw(kind: u16, secret: &[u8], msg: &[u8], aux: Option<&[u8; 32]>) -> Result<Vec<u8>> {
    let scheme = if kind == 0x0001 {
        Scheme::Secp256k1
    } else {
        ua_scheme(kind)?
    };
    sign_scheme(scheme, secret, msg, aux)
}
