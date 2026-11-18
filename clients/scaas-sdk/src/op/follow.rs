// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Following (spec §13.5, CLI-SDK-18): terminal only on a chain fact from a decisive read at the profile's final block `f` (an
//! agreed read, or under failover the first endpoint when it is not `discovered`): the executed event of the operation's digest
//! (`Landed`), its lane nonce spent without that event (`Consumed`), `validUntil` below `f`'s timestamp with the nonce unspent
//! (`Expired`). Everything else is `InFlight` with what is known: a gateway's refusal, every node giving up, a failed or
//! replaced self-relay transaction are none of them an end (the signed operation is public and may still land).
use super::state::{self, Row};
use super::{dec, evm, final_block, nonce_call, unhex, InFlight, Op, OpState};
use crate::events::Event;
use crate::SdkError;
use alloy::primitives::{Address, B256, U256};
use alloy::rpc::types::Filter;
use scaas_rpc::evm::{TxState, LOG_RANGE_MAX};
use scaas_rpc::pool::ReadError;
use scaas_rpc::{Class, Policy, Purpose};

fn detail_of(s: &str) -> InFlight {
    match s {
        "Queued" => InFlight::Queued,
        "GivenUpByEveryNode" => InFlight::GivenUpByEveryNode,
        "Sent" => InFlight::Sent,
        "BroadcastRejected" => InFlight::BroadcastRejected,
        "TxIncluded" => InFlight::TxIncluded,
        "TxFinalFailed" => InFlight::TxFinalFailed,
        "TxReplaced" => InFlight::TxReplaced,
        _ => InFlight::Signed,
    }
}

/// The stored state of a row.
fn stored(row: &Row) -> OpState {
    match (row.state.as_str(), &row.landed) {
        ("landed", Some((block, hash))) => OpState::Landed {
            block: *block,
            hash: hash.clone(),
        },
        ("consumed", _) => OpState::Consumed,
        ("expired", _) => OpState::Expired,
        _ => OpState::InFlight {
            detail: detail_of(&row.detail),
        },
    }
}

/// The executed event of the contract kind: `MetaTransactionExecuted` on `SmartKeyAccount` (`MetaTxBase`),
/// `UAMetaTransactionExecuted` on tokens, `MandateWallet` and `GovernanceRouter`; `digest` is the second data word of both.
fn executed_topic(kind: &str) -> B256 {
    let sig: &[u8] = if kind == "account" {
        b"MetaTransactionExecuted(address,address,uint256,uint256,bytes32,address,uint256)"
    } else {
        b"UAMetaTransactionExecuted(bytes32,address,uint256,uint256,bytes32,address,uint256)"
    };
    B256::from(scaas_ua::keccak256(sig))
}

/// The facts at the final block: the block and hash of the digest's event, the lane nonce spent, the block's timestamp.
type Facts = (Option<(u64, String)>, bool, u64);

impl Op {
    /// The operation's state now (spec §13.5), its row updated and `Event::OpState` emitted when it changed. A terminal state
    /// is final: it is not read again. `Argument`: no such operation.
    pub async fn state(&self, op: String) -> Result<OpState, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let mut row = state::row(&sdk, &op).await?;
                let was = stored(&row);
                if was.is_terminal() {
                    return Ok(was);
                }
                let (profile, _, pool) = evm(&sdk, &row.chain)?;
                let choice = final_block(&profile);
                let now = if row.kind == "native" {
                    native_state(&pool, &row, choice).await
                } else {
                    let contract: Address = row.contract.parse().map_err(|_| SdkError::Argument)?;
                    let digest: B256 = row.digest.parse().map_err(|_| SdkError::Argument)?;
                    let lane = if row.from.is_empty() {
                        None
                    } else {
                        Some((
                            unhex(&row.from)?,
                            dec(&row.batch.clone().into())?,
                            dec(&row.nonce.clone().into())?,
                        ))
                    };
                    let filter = Filter::new()
                        .address(contract)
                        .event_signature(executed_topic(&row.kind));
                    let (kind, from_block) = (row.kind.clone(), row.from_block);
                    let (lane, filter, kind) = (&lane, &filter, kind.as_str());
                    let pool = &pool;
                    let a = pool
                        .read_at_block(choice, Purpose::Plain, |at| async move {
                            let mut landed = None;
                            let mut lo = from_block.min(at.number);
                            while lo <= at.number && landed.is_none() {
                                let hi = at.number.min(lo.saturating_add(LOG_RANGE_MAX - 1));
                                for l in pool.logs_at(&at, lo, hi, filter).await? {
                                    if l.data.get(32..64) == Some(digest.as_slice()) {
                                        landed = Some((
                                            l.block_number.unwrap_or(at.number),
                                            format!("{:#x}", l.block_hash.unwrap_or_default()),
                                        ));
                                    }
                                }
                                lo = hi.saturating_add(1);
                            }
                            let spent = match lane {
                                Some((from, batch, nonce)) => {
                                    let w = pool
                                        .call_at(&at, contract, nonce_call(kind, from, *batch))
                                        .await?;
                                    if w.len() != 32 {
                                        return Err(ReadError::Failure(
                                            scaas_rpc::EndpointFailure::new(
                                                at.endpoint,
                                                scaas_rpc::FailureKind::AnswerMalformed,
                                                "a nonce view of no word",
                                            ),
                                        ));
                                    }
                                    U256::from_be_slice(&w) > *nonce
                                }
                                None => false,
                            };
                            Ok::<Facts, ReadError>((landed, spent, pool.timestamp_at(&at).await?))
                        })
                        .await?;
                    let strict = pool.pool().policy() == Policy::StrictMajority;
                    let decisive =
                        strict || (a.members == [0] && pool.pool().class(0) != Class::Discovered);
                    let (landed, spent, ts) = a.value;
                    match landed {
                        Some((block, hash)) if decisive => OpState::Landed { block, hash },
                        _ if decisive && lane.is_some() && spent => OpState::Consumed,
                        _ if decisive && lane.is_some() && row.valid_until < ts => OpState::Expired,
                        _ => OpState::InFlight {
                            detail: tx_detail(pool, &row, choice).await,
                        },
                    }
                };
                if now != was {
                    match &now {
                        OpState::Landed { block, hash } => {
                            row.state = "landed".into();
                            row.landed = Some((*block, hash.clone()));
                        }
                        OpState::Consumed => row.state = "consumed".into(),
                        OpState::Expired => row.state = "expired".into(),
                        OpState::InFlight { detail } => row.detail = format!("{detail:?}"),
                    }
                    state::put(&sdk, &row).await?;
                    sdk.emit(Event::OpState {
                        op: row.op.clone(),
                        state: now.clone(),
                    });
                }
                Ok(now)
            })
            .await
    }
}

/// An EVM native send (no operation nonce) by `tx_state`'s own terminal facts (spec §13.5): final and successful is
/// `Landed`; final and failed, or replaced, is `Consumed` (the account's nonce spent without the transfer).
async fn native_state(
    pool: &scaas_rpc::evm::EvmPool,
    row: &Row,
    choice: scaas_rpc::pool::BlockChoice,
) -> OpState {
    let (Some(id), Some(payer), Some(nonce)) = (
        row.tx_id.as_deref().and_then(|t| t.parse::<B256>().ok()),
        row.payer.as_deref().and_then(|p| p.parse::<Address>().ok()),
        row.tx_nonce,
    ) else {
        return stored(row);
    };
    match pool.tx_state(id, payer, nonce, choice).await {
        Ok(TxState::Final {
            success: true,
            number,
            hash,
        }) => OpState::Landed {
            block: number,
            hash: format!("{hash:#x}"),
        },
        Ok(TxState::Final { .. } | TxState::Replaced { .. }) => OpState::Consumed,
        Ok(TxState::Included { .. }) => OpState::InFlight {
            detail: InFlight::TxIncluded,
        },
        _ => stored(row),
    }
}

/// A self-relay transaction's state as the detail (never an end of the operation); else the row's last detail.
async fn tx_detail(
    pool: &scaas_rpc::evm::EvmPool,
    row: &Row,
    choice: scaas_rpc::pool::BlockChoice,
) -> InFlight {
    let last = detail_of(&row.detail);
    let (Some(id), Some(payer), Some(nonce)) = (
        row.tx_id.as_deref().and_then(|t| t.parse::<B256>().ok()),
        row.payer.as_deref().and_then(|p| p.parse::<Address>().ok()),
        row.tx_nonce,
    ) else {
        return last;
    };
    match pool.tx_state(id, payer, nonce, choice).await {
        Ok(TxState::Final { success: false, .. }) => InFlight::TxFinalFailed,
        Ok(TxState::Replaced { .. }) => InFlight::TxReplaced,
        Ok(TxState::Final { .. } | TxState::Included { .. }) => InFlight::TxIncluded,
        _ => last,
    }
}
