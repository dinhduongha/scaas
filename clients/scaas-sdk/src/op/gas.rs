// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The gas of a quote without a signature (owner 2026-11-18, ruling 1; spec §13.3): a quote never makes or sends a signature.
//! An operation with a pinned figure takes it; any other takes the estimate of its unsigned form (the entry with an empty
//! signature) when the chain answers one, else `GasUnquoted`. Both with the margin. `submit` then signs once, simulates the
//! signed calldata and refuses it (`GasUnquoted`, nothing written or sent) when it needs more gas than the quote the user
//! confirmed.

/// The pinned execution gas by `(entry, domain kind)`: `smartcontracts/evm/test/vectors/plus_zero_gas.json` (moved only with
/// old → new in a contracts commit), the largest of the kind's rows (`normal` / `wrapped`).
const PINNED: &[(&str, &str, u64)] = &[
    ("mtxExecuteTransfer", "token", 97_947), // uaExecuteTransfer_wrapped
    ("mtxExecuteTransfer", "zether", 139_535), // uaExecuteTransfer_wrappedZether
    ("mtxExecuteTransfer", "pqz", 265_112),  // uaExecuteTransfer_{normal,wrapped}Pqz
    ("mtxCancelNonce", "gov_router", 72_600), // mtxCancelNonce_router
];

/// The transaction's base cost and calldata at the highest price per byte (EIP-7976's floor, 64 gas a byte).
const INTRINSIC: u64 = 21_000;
const PER_BYTE: u64 = 64;

/// The stated margin: the figure plus half of it.
pub(crate) fn with_margin(g: u64) -> u64 {
    g.saturating_add(g / 2)
}

/// The quote's gas of a pinned operation whose unsigned calldata is `len` bytes, with the margin; `None`: not pinned.
pub(crate) fn pinned(entry: &str, kind: &str, len: usize) -> Option<u64> {
    let (_, _, g) = PINNED.iter().find(|(e, k, _)| *e == entry && *k == kind)?;
    let bytes = u64::try_from(len)
        .unwrap_or(u64::MAX)
        .saturating_mul(PER_BYTE);
    Some(with_margin(
        g.saturating_add(INTRINSIC).saturating_add(bytes),
    ))
}
