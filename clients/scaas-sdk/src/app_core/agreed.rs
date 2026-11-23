// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The agreed app read (CTR-CHAT-23 option d, owner 2026-11-23): an app core asks strict majority (CLI-RPC-05) for the reads it
//! chooses, whatever its chain's list policy; never forced on the list or on another read.
use super::AppCore;
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
        self.read_app_by(chain, contract, entry, args, Purpose::FeedsDecryption, true)
            .await
    }
}
