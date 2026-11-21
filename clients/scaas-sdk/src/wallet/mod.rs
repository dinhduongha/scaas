// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `wallet` (spec §8; CLI-SDK-08, CLI-SDK-09, CLI-SDK-15, CLI-SDK-16; plan T11): the profile's checks, tokens, balances and the
//! EVM native send. A gateway or a token whose `chain_uid` is not the profile's is refused (`ProfileMismatch`) before it is used;
//! a token off the profile's reviewed list is `unlisted`, its name and symbol bounded and stripped, never shown without the
//! mark. Values are decimal strings of the smallest unit; no floating point. UNAUDITED.
pub(crate) mod balances;
pub(crate) mod families;
pub(crate) mod history;
pub(crate) mod native;
mod native_evm;
pub(crate) mod ops;
#[cfg(feature = "raw-native")]
mod raw;
pub(crate) mod tokens;

pub use balances::{Balances, TokenBalance};
pub use history::{Cursor, HistoryItem, HistoryPage, OpItem};
pub use native::{NativeAddress, NativeKeyRef};
pub use native_evm::{NativeQuote, NativeSend};
pub use ops::*;
#[cfg(feature = "raw-native")]
pub use raw::{AllowRawNative, NativeSignRequest};
pub use tokens::TokenInfo;

use crate::Sdk;
use std::sync::Arc;

/// The wallet module.
#[derive(Clone)]
pub struct Wallet {
    pub(crate) sdk: Arc<Sdk>,
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl Sdk {
    /// The wallet module (spec §8).
    pub fn wallet(self: &Arc<Self>) -> Arc<Wallet> {
        Arc::new(Wallet { sdk: self.clone() })
    }
}
