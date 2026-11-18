// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T8f: the DEX rows (`dex`): the outside-token cancel (a `DexOrder`, its signature in a one-element list) and the nonce
//! invalidation. A copy of `scaas-node/src/typed.rs` `TYPED`, held equal by `tests/entries.rs`.
use super::Def;

const D: &[&str] = &["dex"];

pub(super) const ROWS: &[Def] = &[
    (
        "CancelDexOrder",
        "mtxCancelOrders",
        D,
        "DexOrder order",
        "[order] [@]",
    ),
    (
        "InvalidateNonces",
        "mtxInvalidateNonces",
        D,
        "address from,uint256 batch,uint256 minNonce",
        "from batch minNonce @",
    ),
];
