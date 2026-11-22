// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The raw native entry (spec §8.6, CLI-SDK-16; plan T19; feature `raw-native`): an app's own encoder of a non-EVM chain has a
//! seed's native key sign what it built, under the marker [`AllowRawNative`]. Every rule is enforced here, before `scaas-ua` is
//! called, each refusal `RawDigestRefused`: (1) no EVM key (`evm`, `hedera_ecdsa`: an EVM transaction is `EvmTx` only) and no UA
//! or account key; (2) NEAR, Sui, Stellar and Hedera Ed25519 only through `scaas-ua`'s envelope calls (the app passes the
//! transaction bytes), never a bare digest or message; (3) no GRAM (`ton`) key; (4) the off-chain envelopes a SCaaS family
//! verifies (Solana `0xff ‖ "solana offchain"`, Aptos `APTOS\n`) refused; no first-byte rule beyond them (a `0x05` payload signs);
//! (5) a bare 32-byte digest only for a Bitcoin key (its BIP-143 / BIP-341 sighash). The caller's obligations are CLI-SGN-54's:
//! the preimage built in this process from the transaction the user reviewed. UNAUDITED.
use super::native::{derive, NativeKeyRef};
use super::Wallet;
use crate::op::{hex, unhex};
use crate::SdkError;
use scaas_ua::wallet::AllowRawDigest;

/// The marker of the raw entry (spec §8.6): a value only a build with `raw-native` can make.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AllowRawNative(());

impl AllowRawNative {
    pub fn new() -> Self {
        AllowRawNative(())
    }
}

impl Default for AllowRawNative {
    fn default() -> Self {
        Self::new()
    }
}

/// What the app's encoder built (hex, `0x`), by kind.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
pub enum NativeSignRequest {
    /// a Bitcoin sighash (BIP-143 / BIP-341), 32 bytes
    Digest32 { digest: String },
    /// a chain's message signed as the scheme's message (Solana, Aptos, Polkadot, Cosmos is not covered)
    Message { message: String },
    /// NEAR: the Borsh `Transaction`
    NearTransaction { tx_borsh: String },
    /// Sui: the BCS `TransactionData`
    SuiTransaction { tx_bcs: String },
    /// Stellar: the network id (`sha256(passphrase)`) and the XDR transaction
    StellarTransaction { network_id: String, tx_xdr: String },
    /// Hedera Ed25519: the transaction's `bodyBytes`
    HederaTransaction { body_bytes: String },
}

/// The networks whose keys sign only through an envelope call.
const ENVELOPE: [&str; 4] = ["near", "sui", "stellar", "hedera_ed25519"];
/// The off-chain envelopes refused before `scaas-ua` (rule 4).
const OFFCHAIN: [&[u8]; 2] = [b"\xffsolana offchain", b"APTOS\n"];

/// The tests' count of `scaas-ua` sign calls made by this entry: digest, message, envelope.
#[cfg(test)]
pub(crate) static CALLS: [std::sync::atomic::AtomicU32; 3] = [
    std::sync::atomic::AtomicU32::new(0),
    std::sync::atomic::AtomicU32::new(0),
    std::sync::atomic::AtomicU32::new(0),
];

fn count(_i: usize) {
    #[cfg(test)]
    if let Some(c) = CALLS.get(_i) {
        c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Rules 1 to 5 over the key's network and the request, before any key is opened.
fn allowed(network: &str, req: &NativeSignRequest) -> Result<(), SdkError> {
    use NativeSignRequest::*;
    let refuse = Err(SdkError::RawDigestRefused);
    // a UA or account key is no native network's: refused by the same rule
    if scaas_ua::wallet::Network::from_name(network).is_none()
        || matches!(network, "evm" | "hedera_ecdsa" | "ton")
    {
        return refuse;
    }
    let envelope = ENVELOPE.contains(&network);
    match req {
        Digest32 { .. } if network.starts_with("bitcoin_") => Ok(()),
        Digest32 { .. } => refuse,
        Message { message } => {
            let m = unhex(message)?;
            if envelope
                || network.starts_with("bitcoin_")
                || OFFCHAIN.iter().any(|p| m.starts_with(p))
            {
                return refuse;
            }
            Ok(())
        }
        NearTransaction { .. } if network == "near" => Ok(()),
        SuiTransaction { .. } if network == "sui" => Ok(()),
        StellarTransaction { .. } if network == "stellar" => Ok(()),
        HederaTransaction { .. } if network == "hedera_ed25519" => Ok(()),
        _ => refuse,
    }
}

impl Wallet {
    /// Signs what an app's encoder built for a non-EVM chain (spec §8.6) with a seed's native key: the signature, `0x` hex.
    /// `RawDigestRefused` by rules 1 to 5 (before any key is opened); `WalletLocked`, `FeatureMissing`, `Argument`.
    pub async fn native_sign(
        &self,
        key: NativeKeyRef,
        request: NativeSignRequest,
        _allow: AllowRawNative,
    ) -> Result<String, SdkError> {
        use NativeSignRequest::*;
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                allowed(&key.network, &request)?;
                let (_s, k) = derive(&sdk, &key)?;
                let sig = match &request {
                    Digest32 { digest } => {
                        let d: [u8; 32] =
                            unhex(digest)?.try_into().map_err(|_| SdkError::Argument)?;
                        count(0);
                        k.sign_digest(&d, AllowRawDigest)?
                    }
                    Message { message } => {
                        count(1);
                        k.sign_message(&unhex(message)?, AllowRawDigest)?
                    }
                    NearTransaction { tx_borsh } => {
                        count(2);
                        k.sign_near_transaction(&unhex(tx_borsh)?, AllowRawDigest)?
                    }
                    SuiTransaction { tx_bcs } => {
                        count(2);
                        k.sign_sui_transaction(&unhex(tx_bcs)?, AllowRawDigest)?
                    }
                    StellarTransaction { network_id, tx_xdr } => {
                        let id: [u8; 32] = unhex(network_id)?
                            .try_into()
                            .map_err(|_| SdkError::Argument)?;
                        count(2);
                        k.sign_stellar_transaction(&id, &unhex(tx_xdr)?, AllowRawDigest)?
                    }
                    HederaTransaction { body_bytes } => {
                        count(2);
                        k.sign_hedera_transaction(&unhex(body_bytes)?, AllowRawDigest)?
                    }
                };
                Ok(hex(&sig))
            })
            .await
    }
}

#[cfg(test)]
#[path = "raw_tests.rs"]
mod tests;
