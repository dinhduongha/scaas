// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The one JSON reader of outside input (spec §9.3): the length bound first, then the nesting depth counted by a flat scan
//! (no recursion, strings and escapes skipped), and only then `serde_json`, whose own recursion the depth bound keeps far
//! below its limit. Every later decoder (typed data, `Expect`, transactions, vault, manifest, containers, facade commands)
//! reads through it with its caps. UNAUDITED.
use super::{Error, Result};
use serde_json::Value;

/// `bytes` as JSON if `bytes.len() ≤ max_len` and no array or object nests deeper than `max_depth` (`[1]` is depth 1),
/// else `Argument`; malformed JSON is `Argument`.
pub fn json(bytes: &[u8], max_len: usize, max_depth: usize) -> Result<Value> {
    if bytes.len() > max_len {
        return Err(Error::Argument);
    }
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for &b in bytes {
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > max_depth {
                    return Err(Error::Argument);
                }
            }
            b']' | b'}' => depth = depth.checked_sub(1).ok_or(Error::Argument)?,
            _ => {}
        }
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Argument)
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
