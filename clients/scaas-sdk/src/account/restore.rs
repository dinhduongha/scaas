// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Seed recovery (spec §7 "Seed recovery"): a gap scan per kind over the registry. The candidates are derived by `scaas-ua`
//! (`discover_candidates`, nothing stored); each is read with `isRegistered(ua)` on the chain's registry; the scan runs `gap`
//! past the last registered index; the reads go round the profile's RPC list, one endpoint after the other, so no one endpoint
//! sees the whole candidate set. What it finds becomes UA rows (one change, the MAC rewritten). UNAUDITED.
use super::{add_rows, Account, AccountInfo};
use crate::vault::AccountRow;
use crate::SdkError;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes};
use alloy::rpc::types::TransactionRequest;
use scaas_rpc::evm::{EvmPool, SimError};

/// `restore`: seed `seed` on chain `chain` (a profile key): the UA keys `kinds` of wallet `account`, `gap` (at most 1024, the
/// usual 20) past the last registered index.
#[derive(Debug, Clone)]
pub struct Restore {
    pub seed: String,
    pub chain: String,
    pub kinds: Vec<u16>,
    pub account: u32,
    pub gap: u32,
}

/// `discover_candidates`' bound.
const GAP_MAX: u32 = 1024;

fn rpc_error(e: SimError) -> SdkError {
    match e {
        SimError::Revert(_) => SdkError::Rpc(scaas_rpc::RpcError::Revert {
            endpoint: 0,
            data: vec![],
            reason: String::new(),
        }),
        SimError::Transport(_) => SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
            last: None,
            failover_revert: None,
        }),
    }
}

/// The chain's profile, its registry and chain id: `ChainUnknown` without the profile.
fn evm_chain(sdk: &crate::Sdk, key: &str) -> Result<(crate::ChainProfile, u64), SdkError> {
    let chain = sdk
        .chains
        .iter()
        .find(|c| c.profile.key == key)
        .ok_or(SdkError::ChainUnknown)?;
    Ok((
        chain.profile.clone(),
        chain.profile.chain_id.ok_or(SdkError::Argument)?,
    ))
}

impl Account {
    /// The rows of seed `seed`, each EVM native row marked when its code on chain `chain` is an EIP-7702 designator
    /// (`0xef0100 ‖ address`, CLI-SGN-40 rule 3): shown with the mark and warned; the SDK builds no type-4 transaction, so it
    /// offers no clearing (CLI-SDK-31).
    pub async fn marks(&self, seed: String, chain: String) -> Result<Vec<AccountInfo>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (_, _, pool) = sdk.evm(&chain)?;
                let e = sdk.entry(&seed).await?;
                let verified = sdk.open_seed(&seed).is_ok();
                let mut out = Vec::with_capacity(e.accounts.len());
                for r in &e.accounts {
                    let mut i = super::info(&seed, r, verified);
                    if let AccountRow::Native {
                        network, address, ..
                    } = r
                    {
                        if network == "evm" {
                            let who: Address = address.parse().map_err(|_| SdkError::Argument)?;
                            let code = pool.code(who).await.map_err(rpc_error)?;
                            i.delegated = code.len() == 23 && code.starts_with(&[0xef, 0x01, 0x00]);
                        }
                    }
                    out.push(i);
                }
                Ok(out)
            })
            .await
    }

    /// The gap scan (spec §7): returns the rows added (a registered UA already in the list is not added twice).
    /// `ChainUnknown`: no such profile; `Argument`: a profile with no registry or chain id, `gap` 0 or above 1024.
    pub async fn restore(&self, req: Restore) -> Result<Vec<AccountInfo>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                if req.gap == 0 || req.gap > GAP_MAX {
                    return Err(SdkError::Argument);
                }
                let (profile, chain_id) = evm_chain(&sdk, &req.chain)?;
                let uid = profile.chain_uid.parse().map_err(|_| SdkError::Argument)?;
                let registry: Address = profile
                    .registry
                    .as_deref()
                    .and_then(|r| r.parse().ok())
                    .ok_or(SdkError::Argument)?;
                // one pool per endpoint: the reads go round the list
                let pools = profile
                    .rpc
                    .iter()
                    .map(|e| {
                        let l = crate::list(std::slice::from_ref(e), scaas_rpc::Policy::Failover)?;
                        Ok(EvmPool::connect(l, chain_id, Some(uid))?)
                    })
                    .collect::<Result<Vec<_>, SdkError>>()?;
                let open = sdk.open_seed(&req.seed)?;
                let sel = scaas_ua::keccak256(b"isRegistered(bytes32)");
                let mut reads = 0usize;
                let mut found = Vec::new();
                for kind in &req.kinds {
                    // ponytail: the candidates are re-derived from 0 when the scan grows; derivation is cheap next to a read
                    let (mut scanned, mut until) = (0usize, req.gap);
                    while scanned < until as usize {
                        let cands = open.wallet.discover_candidates(*kind, req.account, until)?;
                        if cands.len() <= scanned {
                            break; // the EIP-2333 kinds: index 0 alone
                        }
                        for (i, ua) in cands.iter().skip(scanned) {
                            let pool = pools
                                .get(reads % pools.len().max(1))
                                .ok_or(SdkError::Argument)?;
                            reads += 1;
                            let data: Vec<u8> =
                                sel.iter().take(4).chain(ua.iter()).copied().collect();
                            let tx = TransactionRequest::default()
                                .with_to(registry)
                                .with_input(Bytes::from(data));
                            let out = pool.call_tx(tx).await.map_err(rpc_error)?;
                            // one ABI `bool` word, exactly 1 (closing review P3: never a longer or shorter answer's last byte)
                            let registered = out.len() == 32
                                && out.get(..31).is_some_and(|h| h.iter().all(|b| *b == 0))
                                && out.last() == Some(&1);
                            if registered {
                                found.push(AccountRow::Ua {
                                    id: crate::vault::uuid4()?,
                                    name: format!("Restored {kind:#06x} {i}"),
                                    kind: u64::from(*kind),
                                    account: u64::from(req.account),
                                    index: u64::from(*i),
                                    ua: super::hex(ua),
                                });
                                until = until
                                    .max(i.saturating_add(1).saturating_add(req.gap))
                                    .min(GAP_MAX);
                            }
                        }
                        scanned = cands.len();
                    }
                }
                add_rows(&sdk, &req.seed, found, true).await
            })
            .await
    }
}
