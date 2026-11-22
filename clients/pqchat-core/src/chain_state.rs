// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Own sender chains (UA-7 §6.3, CLI-PQC-09, spec §7): this device's id and, per own chain `(epoch, device)`, the next counter,
//! from 0, written to the store **before** the send: a crash between the write and the send skips a counter and never reuses
//! one. `CounterExhausted` once a chain's next counter is 2^64 − 1 (a rekey gives a new chain).
use crate::device::{new_id, DeviceItem, DEVICE};
use crate::{Items, PqChat, PqChatError};

/// The store item of the own chain `(epoch, device)`: the counter its next send takes.
pub fn own_key(epoch: &str, device: &str) -> String {
    format!(
        "own/{}/{}",
        epoch.to_ascii_lowercase(),
        device.to_ascii_lowercase()
    )
}

impl PqChat {
    /// This device's id, `0x` + 32 hex: the one [`PqChat::start_device`] bound to the app's anchor, else made once and kept
    /// (a UUID v4 from 16 bytes of the OS generator, spec §13 O8).
    pub fn device(&self) -> Result<String, PqChatError> {
        if let Some(d) = Items(&*self.store).get::<DeviceItem>(DEVICE)? {
            return Ok(d.id);
        }
        let new = new_id()?;
        // a racing first call keeps the id written first
        let d = Items(&*self.store).update::<DeviceItem, _>(DEVICE, |d| {
            Ok(d.unwrap_or_else(|| DeviceItem {
                id: new.clone(),
                anchor: None,
            }))
        })?;
        Ok(d.id)
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
