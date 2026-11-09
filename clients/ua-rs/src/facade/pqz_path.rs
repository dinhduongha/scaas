// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The PQZ proof path's word parsers (no-oracle spec §4.14; proof-path spec §2.2 and §3.2 on `ua-mtx-merge`; plan T20d). Public
//! data only, nothing decrypted; every refusal is `Argument`. T20d1: an op blob's 3h tail, read by path (A)'s entry parse for
//! `R`. UNAUDITED.
use super::pqz_pack::VP;
use crate::wallet::{Error, Result};

/// The most key versions an op blob's tail names (op 7: 8 legs and the auditor).
const KV_MAX: usize = 9;

/// An op blob's 3h tail (proof-path spec §3.2, `PqzCore.rOf`), read from the data's last byte: `… ‖ P(v_f) ‖ ownTag(32) ‖
/// kv(8·n) ‖ u8(n)`, `n ≤ 9`; `r_len` is the length of `R`, the data before `P(v_f)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tail {
    pub(crate) r_len: usize,
}

/// [`Tail`] of an op blob's data (its SSTORE2 code less the leading byte); `Argument` when it does not fit.
pub(crate) fn tail(d: &[u8]) -> Result<Tail> {
    let n = *d.last().ok_or(Error::Argument)? as usize;
    if n > KV_MAX {
        return Err(Error::Argument);
    }
    let at = d.len().checked_sub(33 + 8 * n).ok_or(Error::Argument)?;
    let r_len = at.checked_sub(VP).ok_or(Error::Argument)?;
    Ok(Tail { r_len })
}
