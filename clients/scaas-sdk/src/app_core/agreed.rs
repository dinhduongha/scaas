// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The agreed app read (CTR-CHAT-23 option d, owner 2026-11-23): an app core asks strict majority (CLI-RPC-05) for the reads it
//! chooses, whatever its chain's list policy; never forced on the list or on another read.
use super::{AppCore, By};
use crate::SdkError;
use scaas_rpc::Purpose;
use std::sync::Arc;

impl AppCore {
    /// [`AppCore::read_app`] as an agreed read: the same complete answer at one block from ⌊n/2⌋ + 1 of the chain's endpoints
    /// (CLI-RPC-05, with CLI-RPC-06: always a read that feeds a decryption, as `read_app`, T26 B-17). The list needs two endpoints or more and a pinned `chain_uid` (`Argument`);
    /// no majority is `EndpointNoMajority`.
    pub async fn read_app_agreed(
        self: &Arc<Self>,
        chain: String,
        contract: String,
        entry: String,
        args: String,
    ) -> Result<String, SdkError> {
        self.read_app_by(
            chain,
            contract,
            entry,
            args,
            Purpose::FeedsDecryption,
            By::Agreed,
        )
        .await
    }

    /// [`AppCore::read_app`] at the latest block instead of the profile's final one (a sender's view of what it already
    /// sent, the TreeKEM spec's C37: a piece landed and not final is waited for, never sent twice); a read that feeds a
    /// decryption, as `read_app`.
    pub async fn read_app_latest(
        self: &Arc<Self>,
        chain: String,
        contract: String,
        entry: String,
        args: String,
    ) -> Result<String, SdkError> {
        self.read_app_by(
            chain,
            contract,
            entry,
            args,
            Purpose::FeedsDecryption,
            By::Latest,
        )
        .await
    }

    /// [`AppCore::read_app_agreed`] over the chain's **named** endpoints only (R13 of the TreeKEM spec: a strict majority of at
    /// least 3 named endpoints, discovered and default ones do not count; `AgreementNeedsThree` with fewer).
    pub async fn read_app_agreed_named(
        self: &Arc<Self>,
        chain: String,
        contract: String,
        entry: String,
        args: String,
    ) -> Result<String, SdkError> {
        self.read_app_by(
            chain,
            contract,
            entry,
            args,
            Purpose::FeedsDecryption,
            By::Named,
        )
        .await
    }
}
