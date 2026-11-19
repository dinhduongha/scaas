// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `sdk.state`'s operation rows (spec §13.4): public data only, `{"rev": N, "ops": [row …]}`, each change a read-modify-write
//! under the store's lock at the read `rev` (`StoreConflict` after three tries), as the keystore's (§6.3).
use crate::vault::{StoreError, StorePolicy};
use crate::{Sdk, SdkError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const STATE: &str = "sdk.state";
/// The item's size contract (spec §6.9).
const STATE_MAX: usize = 16 << 20;
const TRIES: usize = 3;

/// One operation as written ahead (spec §13.4). `state`: `signed`, `sent`, or the terminal `landed` / `consumed` / `expired`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Row {
    pub op: String,
    pub chain: String,
    /// the contract function (`mtxCancelNonce`, …) and the signed struct
    pub entry: String,
    #[serde(rename = "struct")]
    pub name: String,
    pub kind: String,
    pub contract: String,
    /// the subject id (`bytes32`, or the account's address), the lane, its nonce: the nonce view's arguments
    pub from: String,
    pub batch: String,
    pub nonce: String,
    pub valid_until: u64,
    pub digest: String,
    /// the named-entry job `op` (gateway) or `null`
    pub op_json: Value,
    pub calldata: String,
    /// the signed transaction of a self-relay (hex) and its id
    pub raw: Option<String>,
    pub tx_id: Option<String>,
    pub tx_nonce: Option<u64>,
    /// `gateway` or `self`
    pub path: String,
    pub payer: Option<String>,
    /// the first block a log of the operation may be in: the profile's final block when it was signed (P2-5: never the
    /// head, which an endpoint ahead on a fork may name)
    pub from_block: u64,
    pub state: String,
    /// the last `InFlight` detail's name
    pub detail: String,
    /// the terminal fact of `landed`
    pub landed: Option<(u64, String)>,
    /// the signed `relayer` is bound (mode bit 0): only that relayer may send it
    pub relayer_bound: bool,
    /// a self-relay's confirmed gas limit: the signed calldata's simulation above it is `SimRefused`
    #[serde(default)]
    pub gas_limit: Option<u64>,
    /// the signer's kind and the unsigned calldata's length at `submit`: a gateway operation's self-relay `resend` recomputes
    /// its gas from the stored signed calldata with them (owner 2026-11-19, Q5)
    #[serde(default)]
    pub signer_kind: Option<u16>,
    #[serde(default)]
    pub unsigned_len: Option<u64>,
    /// when the row became terminal, on the SDK's clock (unix seconds): kept `Limits::state_retention_secs` after it
    #[serde(default)]
    pub ended_at: Option<u64>,
    /// the signed message, canonical (public: the calldata holds it): a retry is the same message but its `validUntil`
    #[serde(default)]
    pub message: serde_json::Value,
}

impl Row {
    /// `landed`, `reverted`, `consumed` or `expired`: a chain fact ended it.
    pub(crate) fn terminal(&self) -> bool {
        matches!(
            self.state.as_str(),
            "landed" | "reverted" | "consumed" | "expired"
        )
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    rev: u64,
    ops: Vec<Row>,
}

fn io(e: StoreError) -> SdkError {
    match e {
        StoreError::Conflict => SdkError::StoreConflict,
        _ => SdkError::VaultIo,
    }
}

async fn load(sdk: &Sdk) -> Result<(Option<u64>, State), SdkError> {
    let item = sdk
        .store
        .get(STATE.into(), "the operations".into())
        .await
        .map_err(io)?;
    match item {
        None => Ok((None, State::default())),
        Some(i) => Ok((
            Some(i.rev),
            serde_json::from_slice(&i.bytes).map_err(|_| SdkError::VaultFormat)?,
        )),
    }
}

/// Every row.
pub(crate) async fn rows(sdk: &Sdk) -> Result<Vec<Row>, SdkError> {
    Ok(load(sdk).await?.1.ops)
}

/// The row of operation `op` (`Argument`: none).
pub(crate) async fn row(sdk: &Sdk, op: &str) -> Result<Row, SdkError> {
    rows(sdk)
        .await?
        .into_iter()
        .find(|r| r.op == op)
        .ok_or(SdkError::Argument)
}

/// Writes `row` (replacing the row of its `op`), under the lock at the read `rev`; the terminal rows past their retention are
/// pruned in the same write, never a non-terminal one (T13b ruling 2).
pub(crate) async fn put(sdk: &Sdk, row: &Row) -> Result<(), SdkError> {
    for _ in 0..TRIES {
        let _lock = sdk.store.lock(STATE.into()).await.map_err(io)?;
        let (rev, mut st) = load(sdk).await?;
        match st.ops.iter_mut().find(|r| r.op == row.op) {
            Some(r) => *r = row.clone(),
            None => st.ops.push(row.clone()),
        }
        let (now, keep) = (sdk.now(), sdk.limits.state_retention_secs);
        st.ops
            .retain(|r| !r.terminal() || r.ended_at.is_none_or(|e| e.saturating_add(keep) > now));
        st.rev = st.rev.checked_add(1).ok_or(SdkError::Argument)?;
        let bytes = serde_json::to_vec(&st).map_err(|_| SdkError::Internal)?;
        if bytes.len() > STATE_MAX {
            return Err(SdkError::VaultIo);
        }
        match sdk
            .store
            .put_if(STATE.into(), rev, bytes, StorePolicy::default())
            .await
        {
            Err(StoreError::Conflict) => continue,
            r => return r.map_err(io),
        }
    }
    Err(SdkError::StoreConflict)
}
