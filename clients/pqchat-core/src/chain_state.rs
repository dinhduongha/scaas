// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Own sender chains (UA-7 §6.3, CLI-PQC-09, spec §7): this device's id and, per own chain `(epoch, device)`, the next counter,
//! from 0, written to the store **before** the send: a crash between the write and the send skips a counter and never reuses
//! one. `CounterExhausted` once a chain's next counter is 2^64 − 1 (a rekey gives a new chain).
use crate::model::hex;
use crate::{Items, PqChat, PqChatError};

const DEVICE: &str = "device";

/// The store item of the own chain `(epoch, device)`: the counter its next send takes.
pub fn own_key(epoch: &str, device: &str) -> String {
    format!(
        "own/{}/{}",
        epoch.to_ascii_lowercase(),
        device.to_ascii_lowercase()
    )
}

impl PqChat {
    /// This device's id, `0x` + 32 hex: kept in the store, made once, a UUID v4 from 16 bytes of the OS generator (spec §13
    /// O8; T9 binds it to the device's anchor).
    pub fn device(&self) -> Result<String, PqChatError> {
        if let Some(d) = Items(&*self.store).get::<String>(DEVICE)? {
            return Ok(d);
        }
        let mut b = [0u8; 16];
        getrandom::getrandom(&mut b).map_err(|_| PqChatError::Internal)?;
        let new = hex(uuid::Builder::from_random_bytes(b).into_uuid().as_bytes());
        // a racing first call keeps the id written first
        Items(&*self.store).update::<String, _>(DEVICE, |d| Ok(d.unwrap_or_else(|| new.clone())))
    }

    /// The counter the next send of the own chain `(epoch, device)` takes (a read).
    pub fn next_counter(&self, epoch: &str, device: &str) -> Result<u64, PqChatError> {
        Ok(Items(&*self.store)
            .get::<u64>(&own_key(epoch, device))?
            .unwrap_or(0))
    }

    /// The own chain's next counter, taken: written as used before it is returned.
    pub(crate) fn take_counter(&self, epoch: &str, device: &str) -> Result<u64, PqChatError> {
        let next = Items(&*self.store).update::<u64, _>(&own_key(epoch, device), |n| {
            let n = n.unwrap_or(0);
            if n == u64::MAX {
                return Err(PqChatError::CounterExhausted);
            }
            Ok(n + 1)
        })?;
        Ok(next - 1)
    }
}
