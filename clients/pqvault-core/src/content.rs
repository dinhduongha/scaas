// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! What a ciphertext holds (spec §6.4, §6.6, §6.8): canonical JSON (UA-7 P49: keys sorted by UTF-16 code units, no
//! whitespace, integers within ±(2^53 − 1) only), written into a zeroizing buffer of a fixed capacity, the padding buckets
//! (zeroizing too), and the item's bounds; the typed item and the merge are [`crate::item`]'s. Pure: no key, no network. A
//! decoder here is bounded by length and depth. UNAUDITED.
use serde_json::Value;
use zeroize::Zeroizing;

/// The largest safe integer of JSON (2^53 − 1).
const SAFE: u64 = (1 << 53) - 1;
/// The deepest a plaintext's JSON nests (an item is three levels: object, `urls`, an url).
const DEPTH: usize = 8;
/// An item's padding buckets (UA-7 §6.5); `sealedInfo`'s start at 1,024.
const BUCKETS: [usize; 4] = [256, 1024, 4096, 16384];
pub const BUCKET_MAX: usize = 16384;

/// A refusal of this module: the content is not what a writer may write (`Shape`), or bytes read are not what a writer writes
/// (`Unreadable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bad {
    Shape,
    Unreadable,
}

fn depth_ok(v: &Value, d: usize) -> bool {
    if d > DEPTH {
        return false;
    }
    match v {
        Value::Array(a) => a.iter().all(|x| depth_ok(x, d + 1)),
        Value::Object(o) => o.values().all(|x| depth_ok(x, d + 1)),
        _ => true,
    }
}

/// A zeroizing output buffer of [`BUCKET_MAX`] bytes that never reallocates (a write past it is `Shape`): no copy of what it
/// holds is left behind in freed memory.
pub(crate) struct Out(Zeroizing<Vec<u8>>);

impl Out {
    pub(crate) fn new() -> Out {
        Out(Zeroizing::new(Vec::with_capacity(BUCKET_MAX)))
    }
    pub(crate) fn put(&mut self, b: &[u8]) -> Result<(), Bad> {
        if self.0.len() + b.len() > BUCKET_MAX {
            return Err(Bad::Shape);
        }
        self.0.extend_from_slice(b);
        Ok(())
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The JSON string literal of the UTF-8 bytes `s`, as serde_json writes it: `"` and `\` escaped, `\b \t \n \f \r`, any other
/// control byte `\u00xx` (lower-case hex), every other byte as it is.
pub(crate) fn escape(s: &[u8], out: &mut Out) -> Result<(), Bad> {
    out.put(b"\"")?;
    for &c in s {
        match c {
            b'"' => out.put(b"\\\"")?,
            b'\\' => out.put(b"\\\\")?,
            8 => out.put(b"\\b")?,
            9 => out.put(b"\\t")?,
            10 => out.put(b"\\n")?,
            12 => out.put(b"\\f")?,
            13 => out.put(b"\\r")?,
            0..=0x1f => {
                let hex = |n: u8| HEX.get(usize::from(n)).copied().unwrap_or(b'0');
                out.put(&[b'\\', b'u', b'0', b'0', hex(c >> 4), hex(c & 15)])?
            }
            _ => out.put(&[c])?,
        }
    }
    out.put(b"\"")
}

/// The bytes of a JSON string literal's inside `s` as [`escape`] writes it, into a zeroizing buffer of `s`'s length (an
/// unescaped text is never longer: it never reallocates); `None` for an escape `escape` does not write.
pub(crate) fn unescape(s: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len()));
    let mut i = 0;
    while let Some(&c) = s.get(i) {
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let b = match *s.get(i + 1)? {
            b'"' => b'"',
            b'\\' => b'\\',
            b'b' => 8,
            b't' => 9,
            b'n' => 10,
            b'f' => 12,
            b'r' => 13,
            b'u' => {
                let h = std::str::from_utf8(s.get(i + 2..i + 6)?).ok()?;
                let x = u8::try_from(u16::from_str_radix(h, 16).ok()?).ok()?;
                i += 4;
                x
            }
            _ => return None,
        };
        out.push(b);
        i += 2;
    }
    Some(out)
}

/// `v`'s canonical JSON into `out`: `Shape` for a number that is not a safe integer or a value nesting deeper than 8.
pub(crate) fn write_value(v: &Value, out: &mut Out) -> Result<(), Bad> {
    write_value_at(v, 0, out)
}

/// [`write_value`] of a value nested `d` levels inside the document (an item's field at 1, a history value at 3): the whole
/// document nests at most 8 (review C-7).
pub(crate) fn write_value_at(v: &Value, d: usize, out: &mut Out) -> Result<(), Bad> {
    if !depth_ok(v, d) {
        return Err(Bad::Shape);
    }
    write(v, out)
}

fn write(v: &Value, out: &mut Out) -> Result<(), Bad> {
    match v {
        Value::Number(n) => {
            let ok = n
                .as_u64()
                .map(|x| x <= SAFE)
                .or_else(|| n.as_i64().map(|x| x.unsigned_abs() <= SAFE))
                .unwrap_or(false);
            if !ok {
                return Err(Bad::Shape);
            }
            out.put(n.to_string().as_bytes())?;
        }
        Value::String(s) => escape(s.as_bytes(), out)?,
        Value::Bool(true) => out.put(b"true")?,
        Value::Bool(false) => out.put(b"false")?,
        Value::Null => out.put(b"null")?,
        Value::Array(a) => {
            out.put(b"[")?;
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.put(b",")?;
                }
                write(x, out)?;
            }
            out.put(b"]")?;
        }
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.put(b"{")?;
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.put(b",")?;
                }
                escape(k.as_bytes(), out)?;
                out.put(b":")?;
                write(o.get(*k).ok_or(Bad::Shape)?, out)?;
            }
            out.put(b"}")?;
        }
    }
    Ok(())
}

/// Canonical JSON of `v` (a value that holds no secret: `sealedInfo`'s, a test's): `Shape` for a number that is not a safe
/// integer, a value nesting deeper than 8, or one past 16,384 B.
pub fn canonical(v: &Value) -> Result<String, Bad> {
    let mut out = Out::new();
    write_value(v, &mut out)?;
    String::from_utf8(out.bytes().to_vec()).map_err(|_| Bad::Shape)
}

/// The value of canonical JSON bytes, else `Unreadable` (bytes another writer could have written differently: re-serialised
/// and compared).
pub fn parse_canonical(b: &[u8]) -> Result<Value, Bad> {
    let v: Value = serde_json::from_slice(b).map_err(|_| Bad::Unreadable)?;
    match canonical(&v) {
        Ok(s) if s.as_bytes() == b => Ok(v),
        _ => Err(Bad::Unreadable),
    }
}

fn pad_to(c: &[u8], n: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; n]);
    let len = u32::try_from(c.len()).unwrap_or(u32::MAX).to_be_bytes();
    if let Some(h) = out.get_mut(..4) {
        h.copy_from_slice(&len);
    }
    if let Some(b) = out.get_mut(4..4 + c.len()) {
        b.copy_from_slice(c);
    }
    out
}

/// `pad(c) = be32(len c) ‖ c ‖ zeros` to the smallest bucket of 256, 1,024, 4,096, 16,384 B; above: `Shape`.
pub fn pad(c: &[u8]) -> Result<Zeroizing<Vec<u8>>, Bad> {
    let n = BUCKETS
        .iter()
        .find(|b| **b >= c.len() + 4)
        .ok_or(Bad::Shape)?;
    Ok(pad_to(c, *n))
}

/// `sealedInfo`'s padding (spec §6.4, CLI-PQV-09): to 1,024 B, else the next power of two, at most 16,384 B.
pub fn pad_info(c: &[u8]) -> Result<Zeroizing<Vec<u8>>, Bad> {
    let need = c.len() + 4;
    if need > BUCKET_MAX {
        return Err(Bad::Shape);
    }
    Ok(pad_to(c, need.next_power_of_two().max(1024)))
}

/// The content of a padded plaintext (a part of it, no copy); anything `pad` (or `pad_info` with `info`) would not write is
/// `Unreadable`.
pub fn unpad(p: &[u8], info: bool) -> Result<&[u8], Bad> {
    let n = p
        .get(..4)
        .and_then(|h| <[u8; 4]>::try_from(h).ok())
        .map(u32::from_be_bytes)
        .ok_or(Bad::Unreadable)? as usize;
    let c = p
        .get(4..4usize.checked_add(n).ok_or(Bad::Unreadable)?)
        .ok_or(Bad::Unreadable)?;
    let again = if info { pad_info(c) } else { pad(c) };
    match again {
        Ok(q) if q[..] == *p => Ok(c),
        _ => Err(Bad::Unreadable),
    }
}

// ------------------------------------------------------------------ items (spec §6.8)

/// The item types `pqvault-core` writes; any other read is kept verbatim and shown unsupported, never acted on.
pub const TYPES: [&str; 9] = [
    "login", "note", "card", "identity", "sshKey", "totp", "file", "vaultRef", "deleted",
];

fn len_in(v: Option<&Value>, lo: usize, hi: usize) -> bool {
    v.and_then(Value::as_str)
        .is_some_and(|s| (lo..=hi).contains(&s.len()))
}
fn opt_len(v: Option<&Value>, hi: usize) -> bool {
    v.is_none_or(|x| x.as_str().is_some_and(|s| s.len() <= hi))
}

/// The bounds a writer holds an item to (spec §6.8): `type` 1–32 ASCII letters and one this client writes; `title` 1–256 B
/// (not on a tombstone, which has no other field); `folder` ≤ 128 B; `tags` ≤ 16 of ≤ 64 B; `ts` a safe integer; a login's
/// `urls` ≤ 16 of ≤ 2,048 B each with a `match`; a note's `mediaType` `text/plain` or `text/markdown`. `Shape` otherwise.
pub fn check_item(v: &Value) -> Result<(), Bad> {
    let o = v.as_object().ok_or(Bad::Shape)?;
    let ty = o.get("type").and_then(Value::as_str).ok_or(Bad::Shape)?;
    if !(1..=32).contains(&ty.len())
        || !ty.bytes().all(|b| b.is_ascii_alphabetic())
        || !TYPES.contains(&ty)
    {
        return Err(Bad::Shape);
    }
    if ty == "deleted" {
        return if o.len() == 1 {
            Ok(())
        } else {
            Err(Bad::Shape)
        };
    }
    let tags_ok = o.get("tags").is_none_or(|t| {
        t.as_array().is_some_and(|a| {
            a.len() <= 16 && a.iter().all(|x| x.as_str().is_some_and(|s| s.len() <= 64))
        })
    });
    let ok = len_in(o.get("title"), 1, 256)
        && opt_len(o.get("folder"), 128)
        && tags_ok
        && o.get("ts")
            .is_none_or(|t| t.as_u64().is_some_and(|x| x <= SAFE));
    let typed = match ty {
        "login" => o.get("urls").is_none_or(|u| {
            u.as_array().is_some_and(|a| {
                a.len() <= 16
                    && a.iter().all(|x| {
                        len_in(x.get("url"), 1, 2048)
                            && x.get("match").and_then(Value::as_str).is_some()
                    })
            })
        }),
        "note" => {
            matches!(
                o.get("mediaType").and_then(Value::as_str),
                Some("text/plain" | "text/markdown")
            ) && o.get("hideBody").is_none_or(Value::is_boolean)
        }
        "vaultRef" => {
            o.get("vaultId").and_then(Value::as_str).is_some()
                && matches!(
                    o.get("state").and_then(Value::as_str),
                    Some("accepted" | "declined")
                )
        }
        _ => true,
    };
    (ok && typed).then_some(()).ok_or(Bad::Shape)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_by_utf16_and_refuses_unsafe_numbers() {
        // U+FF5E sorts after U+1F600 in UTF-8 bytes order but before it in UTF-16 code units
        let v = json!({"\u{1F600}": 1, "\u{FF5E}": 2, "a": [true, null, "x\n"]});
        assert_eq!(
            canonical(&v).as_deref(),
            Ok("{\"a\":[true,null,\"x\\n\"],\"\u{1F600}\":1,\"\u{FF5E}\":2}")
        );
        assert_eq!(
            canonical(&json!({"n": 9007199254740991u64})).map(|_| ()),
            Ok(())
        );
        assert_eq!(
            canonical(&json!({"n": 9007199254740992u64})),
            Err(Bad::Shape)
        );
        assert_eq!(canonical(&json!({"n": 1.5})), Err(Bad::Shape));
        assert_eq!(canonical(&json!([[[[[[[[[1]]]]]]]]])), Err(Bad::Shape));
        assert_eq!(canonical(&json!([[[[[[[[1]]]]]]]])).map(|_| ()), Ok(()));
    }

    /// Review C-9: integer-like keys sort by UTF-16 code units too; clientkeys' `canonicalJson` writes the same string.
    #[test]
    fn integer_like_keys_in_utf16_order() {
        assert_eq!(
            canonical(&json!({"2": 2, "10": 1, " ": 3, "a": 4})).as_deref(),
            Ok("{\" \":3,\"10\":1,\"2\":2,\"a\":4}")
        );
    }

    #[test]
    fn parse_canonical_refuses_other_spellings() {
        assert!(parse_canonical(b"{\"a\":1,\"b\":2}").is_ok());
        assert_eq!(parse_canonical(b"{\"b\":2,\"a\":1}"), Err(Bad::Unreadable));
        assert_eq!(parse_canonical(b"{\"a\": 1}"), Err(Bad::Unreadable));
        assert_eq!(parse_canonical(b"{\"a\":1.0}"), Err(Bad::Unreadable));
    }

    #[test]
    fn pad_buckets_and_unpad_refusals() {
        assert_eq!(pad(&[1; 252]).map(|p| p.len()), Ok(256));
        assert_eq!(pad(&[1; 253]).map(|p| p.len()), Ok(1024));
        assert_eq!(pad(&[1; 16380]).map(|p| p.len()), Ok(16384));
        assert_eq!(pad(&[1; 16381]), Err(Bad::Shape));
        assert_eq!(pad_info(&[1; 2]).map(|p| p.len()), Ok(1024));
        assert_eq!(pad_info(&[1; 1021]).map(|p| p.len()), Ok(2048));
        assert_eq!(pad_info(&[1; 16380]).map(|p| p.len()), Ok(16384));
        assert_eq!(pad_info(&[1; 16381]), Err(Bad::Shape));
        let p = pad(b"abc").unwrap_or_default();
        assert_eq!(unpad(&p, false).as_deref(), Ok(&b"abc"[..]));
        let mut q = p.clone();
        q[200] = 1;
        assert_eq!(unpad(&q, false), Err(Bad::Unreadable));
        // a length past the buffer
        let mut q = p.clone();
        q[2] = 1;
        assert_eq!(unpad(&q, false), Err(Bad::Unreadable));
        // a length that pad would write in a smaller bucket
        let big = pad(&[1; 300]).unwrap_or_default();
        let mut q = big.clone();
        q[2] = 0;
        q[3] = 3;
        assert_eq!(unpad(&q, false), Err(Bad::Unreadable));
        // a 256-B plaintext is not what pad_info writes
        assert_eq!(unpad(&p, true), Err(Bad::Unreadable));
        assert!(unpad(&p[..3], false).is_err());
    }

    #[test]
    fn item_bounds() {
        let ok =
            json!({"type": "login", "title": "t", "urls": [{"url": "https://a", "match": "host"}]});
        assert_eq!(check_item(&ok), Ok(()));
        for bad in [
            json!({"type": "login", "title": ""}),
            json!({"type": "login", "title": "x".repeat(257)}),
            json!({"type": "lo-gin", "title": "t"}),
            json!({"type": "spaceship", "title": "t"}),
            json!({"type": "note", "title": "t", "mediaType": "text/html"}),
            json!({"type": "note", "title": "t", "mediaType": "text/plain", "hideBody": "yes"}),
            json!({"type": "deleted", "title": "t"}),
            json!({"type": "login", "title": "t", "tags": vec!["a"; 17]}),
            json!({"type": "login", "title": "t", "urls": [{"url": "x".repeat(2049), "match": "host"}]}),
            json!({"type": "login", "title": "t", "ts": 9007199254740992u64}),
        ] {
            assert_eq!(check_item(&bad), Err(Bad::Shape), "{bad}");
        }
        assert_eq!(check_item(&json!({"type": "deleted"})), Ok(()));
    }
}
