// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The device id and its anchor (CLI-PQC-09, CTR-CHAT-12, Fable K18): the app keeps a random anchor for its store in the
//! platform's non-backed-up secret storage and gives it at start; the store keeps the device id with the anchor it was made
//! under. A missing anchor, or one other than the store's (a restore, a copied data directory, a cloned phone), makes a new
//! device id, and so does a lost store; the own chains are keyed by the device id, so no counter is used twice. The anchor
//! is compared as given (an id, not a key; no hash in the crate, CLI-PQC-01) in the store the app encrypts at rest.
use crate::model::hex;
use crate::{Items, PqChat, PqChatError};

pub(crate) const DEVICE: &str = "device";

/// The store's device item.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DeviceItem {
    pub id: String,
    pub anchor: Option<String>,
}

/// A new device id, `0x` + 32 hex: a UUID v4 from 16 bytes of the OS generator (spec §13 O8).
pub(crate) fn new_id() -> Result<String, PqChatError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| PqChatError::Internal)?;
    Ok(hex(uuid::Builder::from_random_bytes(b)
        .into_uuid()
        .as_bytes()))
}

impl PqChat {
    /// At start, with the app's anchor (`None`: the platform holds none): the device id kept when the store's anchor is the
    /// same, else a new one made and kept with this anchor.
    pub fn start_device(&self, anchor: Option<String>) -> Result<String, PqChatError> {
        let fresh = new_id()?;
        let d = Items(&*self.store).update::<DeviceItem, _>(DEVICE, |d| match d {
            Some(d) if d.anchor.is_some() && d.anchor == anchor => Ok(d),
            _ => Ok(DeviceItem {
                id: fresh.clone(),
                anchor: anchor.clone(),
            }),
        })?;
        Ok(d.id)
    }
}
