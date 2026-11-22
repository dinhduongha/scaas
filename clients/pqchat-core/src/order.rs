// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Conversation order (UA-7 P19): a message names the heads its sender has seen as `parents`, at most 8, strictly sorted; a
//! reader orders by `parents`, then the content's `ts`, then `messageId`.
use crate::PqChatError;

/// At most this many parents (UA-7 §4.2).
pub const PARENTS_MAX: usize = 8;

/// `heads` as a message's `parents`: lower case, sorted, de-duplicated; above [`PARENTS_MAX`] the newest (the last given) kept.
pub fn parents(heads: &[String]) -> Result<Vec<String>, PqChatError> {
    let mut v: Vec<String> = heads.iter().map(|h| h.to_ascii_lowercase()).collect();
    if v.iter().any(|h| h.len() != 66 || !h.starts_with("0x")) {
        return Err(PqChatError::ContentInvalid);
    }
    if v.len() > PARENTS_MAX {
        v.drain(..v.len() - PARENTS_MAX);
    }
    v.sort();
    v.dedup();
    Ok(v)
}
