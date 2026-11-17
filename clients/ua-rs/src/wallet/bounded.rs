// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The one JSON reader of outside input (spec §9.3): the length bound first, then the nesting depth counted by a flat scan
//! (no recursion, strings and escapes skipped; `crate::json::bounded`), and only then `serde_json`, whose own recursion the depth
//! bound keeps far below its limit. Every later decoder (typed data, `Expect`, transactions, vault, manifest, containers, facade commands)
//! reads through it with its caps. UNAUDITED.
use super::{Error, Result};
use serde_json::Value;

/// `bytes` as JSON if `bytes.len() ≤ max_len` and no array or object nests deeper than `max_depth` (`[1]` is depth 1),
/// else `Argument`; malformed JSON is `Argument`. The scan is `crate::json`'s (feature `json`, which `wallet` holds), shared with
/// its JSON calls (T21 L48).
pub fn json(bytes: &[u8], max_len: usize, max_depth: usize) -> Result<Value> {
    crate::json::bounded(bytes, max_len, max_depth).ok_or(Error::Argument)
}

/// Test-only (feature `vectors`): how many inputs on this thread passed both bounds and reached `serde_json` (T11: an input
/// past a cap must never reach it, which a decoder's own refusal of the parsed value would hide); `crate::json`'s calls count too.
#[cfg(feature = "vectors")]
pub fn vectors_parsed() -> usize {
    crate::json::vectors_parsed()
}

/// Every string of a JSON value (its depth bounded by [`json`]) zeroized: what a decoder of secrets runs after its read.
pub(crate) fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => zeroize::Zeroize::zeroize(s),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}
