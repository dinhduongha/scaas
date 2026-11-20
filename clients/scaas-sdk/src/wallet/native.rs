// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Native keys of every network `scaas-ua` has (spec §8.5; plan T19): a seed's key by its derivation, its public key and
//! address. Bitcoin (P2WPKH, P2TR), NEAR and Polkadot need the feature `native-networks` (`FeatureMissing` without it); the
//! other networks are always here. Signing a non-EVM chain's transaction is the raw entry's (`raw-native`, spec §8.6). UNAUDITED.
use super::Wallet;
use crate::op::hex;
use crate::{Sdk, SdkError};
use scaas_ua::wallet::{NativeKey, Network};
use std::sync::Arc;

/// The networks the feature `native-networks` adds.
pub(crate) const EXTRA_NETWORKS: [&str; 4] = ["bitcoin_p2wpkh", "bitcoin_p2tr", "near", "polkadot"];

/// A seed's native key by its derivation: `network` a `scaas-ua` name; Bitcoin's `change` chain (0 receive, 1 change); a
/// `coin_type` in place of the network's (Bitcoin 0 / 1, Stellar's Pi Network); Polkadot's junction `path` (`//hard/soft`).
///
/// Without the feature `raw-native` the raw entry does not exist (spec §8.6: no build without it can reach it):
#[cfg_attr(
    not(feature = "raw-native"),
    doc = "```compile_fail\nlet _ = scaas_sdk::wallet::AllowRawNative::new();\n```"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NativeKeyRef {
    pub seed: String,
    pub network: String,
    pub index: u32,
    pub change: Option<u32>,
    pub coin_type: Option<u32>,
    pub path: Option<String>,
}

/// A native key's public parts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NativeAddress {
    pub network: String,
    /// hex, no `0x`
    pub public_key: String,
    /// as the network prints it; `None` for `ton` and `hedera_ed25519`
    pub address: Option<String>,
    /// a Polkadot key's SS58 address at the prefix asked
    pub ss58: Option<String>,
    /// a Bitcoin key's witness program: its version and program (hex, no `0x`)
    pub witness_version: Option<u8>,
    pub witness_program: Option<String>,
}

/// The key of `k` and its seed (kept open beside it). `FeatureMissing`: a network of [`EXTRA_NETWORKS`] without the feature;
/// `Argument`: an unknown network, a `change` off Bitcoin, a `path` off Polkadot.
pub(crate) fn derive(
    sdk: &Sdk,
    k: &NativeKeyRef,
) -> Result<(Arc<crate::vault::OpenSeed>, NativeKey), SdkError> {
    let n = Network::from_name(&k.network).ok_or(SdkError::Argument)?;
    if EXTRA_NETWORKS.contains(&k.network.as_str()) && !cfg!(feature = "native-networks") {
        return Err(SdkError::FeatureMissing);
    }
    let s = sdk.open_seed(&k.seed)?;
    let key = match (&k.path, k.change) {
        (Some(p), None) if n == Network::Polkadot => s.wallet.polkadot_key(p)?,
        (None, Some(c)) if k.network.starts_with("bitcoin_") => {
            s.wallet.bitcoin_key(n, k.coin_type, c, k.index)?
        }
        (None, None) => s.wallet.native_key(n, k.index, k.coin_type)?,
        _ => return Err(SdkError::Argument),
    };
    Ok((s, key))
}

impl Wallet {
    /// The public key and address of a seed's native key (spec §8.5); `ss58_prefix` for a Polkadot key's SS58 form at another
    /// prefix. `WalletLocked`, `FeatureMissing`, `Argument`.
    pub async fn native_address(
        &self,
        key: NativeKeyRef,
        ss58_prefix: Option<u16>,
    ) -> Result<NativeAddress, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (_s, k) = derive(&sdk, &key)?;
                let ss58 = ss58_prefix.map(|p| k.ss58_address(p)).transpose()?;
                let w = k.witness_program();
                Ok(NativeAddress {
                    network: key.network,
                    public_key: hex(&k.public_key()).trim_start_matches("0x").to_string(),
                    address: k.address(),
                    ss58,
                    witness_version: w.as_ref().map(|(v, _)| *v),
                    witness_program: w.map(|(_, p)| hex(&p).trim_start_matches("0x").to_string()),
                })
            })
            .await
    }
}
