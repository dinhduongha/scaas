// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The oracles of ua-rs's libFuzzer targets (ua-rs-sign T11; spec §9.3), one binary, the target named by `UA_FUZZ_TARGET`
//! (`run.sh` sets it). On every input each target checks (a failed check prints a FINDING and aborts: a libFuzzer crash;
//! a panic aborts too, `panic = "abort"`):
//! - no panic;
//! - the same input twice gives the same result;
//! - the JSON decoders: an input longer than the decoder's cap, or nesting deeper than its depth cap (counted here by a scan
//!   of our own, not the crate's), is refused and never reaches `serde_json` (`bounded::vectors_parsed`: a decoder's later
//!   refusal of the parsed value would hide a missing bound);
//! - an accepted value written back and read again gives the same value (`to_json` / `to_value` / `to_wire`);
//! - `kem_pk`: only a scheme-1 key of exactly 1,601 bytes is accepted; `mnemonic`: none past 1 KiB or 24 words; `sealed`: the
//!   wire form is accepted exactly when it holds its fixed fields and a tag at version and scheme 1, and never opens to a key
//!   it was not sealed to.
//!
//! - T12: `container_expect`, `members`, `accepted` (the container open's JSON inputs across the C ABI) and `uasig` (the `UASig`
//!   request) under their caps.
//!
//! The Zether and PQZ command decoders (`zether_cmd`, `pqz_cmd`) come with their facades (T14, T15). UNAUDITED.
use scaas_ua::wallet::{
    bounded, kem_encaps, vectors_backup_payload, AcceptedJson, ContainerExpectJson, EvmTx, Expect, KemKeyPair, Manifest, MembersJson,
    Sealed, SealedContainer, TypedData, UaSigRequest, Vault, Wallet,
};
use std::fmt::Debug;
use std::sync::OnceLock;

/// `(target, length cap, depth cap)` of each JSON decoder (the crate's constants, spec §9.3).
const TYPED: (usize, usize) = (64 * 1024, 8);
const EXPECT: (usize, usize) = (16 * 1024, 4);
const TX: (usize, usize) = (16 * 1024, 4);
const VAULT: (usize, usize) = (2 << 20, 2);
const MANIFEST: (usize, usize) = (1 << 20, 3);
const PAYLOAD: (usize, usize) = (1 << 20, 4);
const CONTAINER: (usize, usize) = (4 << 20, 7);
const LOOKUP: (usize, usize) = (16 * 1024, 4);
const UASIG: (usize, usize) = (64 * 1024, 6);
/// `version ‖ scheme ‖ mlkemCt (1,568) ‖ x25519Eph (32)` and a 16-byte tag.
const SEALED_MIN: usize = 2 + 1568 + 32 + 16;

static TARGET: OnceLock<String> = OnceLock::new();

fn die(msg: &str) -> ! {
    eprintln!("ua-fuzz FINDING ({}): {msg}", TARGET.get().map_or("?", String::as_str));
    std::process::abort()
}

/// The deepest nesting of `[` / `{` outside strings (a `\` escapes the next byte in a string); an extra closer ends the scan.
fn depth(b: &[u8]) -> usize {
    let (mut d, mut max, mut s, mut esc) = (0usize, 0usize, false, false);
    for &c in b {
        if s {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                s = false;
            }
            continue;
        }
        match c {
            b'"' => s = true,
            b'[' | b'{' => {
                d += 1;
                max = max.max(d);
            }
            b']' | b'}' => match d.checked_sub(1) {
                Some(x) => d = x,
                None => break,
            },
            _ => {}
        }
    }
    max
}

/// `dec(data)` twice under the caps' oracle; the accepted value.
fn json<T: PartialEq + Debug>(data: &[u8], (len, deep): (usize, usize), dec: impl Fn(&[u8]) -> scaas_ua::wallet::Result<T>) -> Option<T> {
    let before = bounded::vectors_parsed();
    let r = dec(data);
    let reached = bounded::vectors_parsed() - before;
    if reached > 1 {
        die(&format!("{reached} parses of one input"));
    }
    if (data.len() > len || depth(data) > deep) && (reached != 0 || r.is_ok()) {
        die(&format!("past its cap ({} B, depth {}) and {}", data.len(), depth(data), if r.is_ok() { "accepted" } else { "parsed" }));
    }
    if dec(data) != r {
        die("not deterministic");
    }
    r.ok()
}

fn same<T: PartialEq + Debug>(a: &T, b: scaas_ua::wallet::Result<T>, what: &str) {
    if b.as_ref() != Ok(a) {
        die(&format!("{what}: written back and read again differs: {b:?}"));
    }
}

fn one(t: &str, data: &[u8]) {
    match t {
        "typed_data" => {
            if let Some(td) = json(data, TYPED, TypedData::from_json) {
                same(&td, TypedData::from_json(td.to_value().to_string().as_bytes()), "typed_data");
                let _ = td.digest();
            }
        }
        "expect" => {
            json(data, EXPECT, Expect::from_json);
        }
        "tx" => {
            json(data, TX, EvmTx::from_json);
        }
        "vault" => {
            if let Some(v) = json(data, VAULT, Vault::from_json) {
                same(&v, Vault::from_json(v.to_json().as_bytes()), "vault");
            }
        }
        "manifest" => {
            if let Some(m) = json(data, MANIFEST, Manifest::from_json) {
                same(&m, Manifest::from_json(m.to_json().as_bytes()), "manifest");
            }
            // the backup / link payload (`BackupPayload`, read inside restore_backup and from_link): written back, it reads
            // back to the same text
            if let Some(p) = json(data, PAYLOAD, vectors_backup_payload) {
                same(&p, vectors_backup_payload(p.as_bytes()), "payload");
            }
        }
        "container" => {
            if let Some(c) = json(data, CONTAINER, SealedContainer::from_json) {
                same(&c, SealedContainer::from_json(c.to_json().as_bytes()), "container");
            }
        }
        "sealed" => {
            let r = Sealed::from_wire(data);
            let fits = data.len() >= SEALED_MIN && data.get(..2) == Some(&[1, 1][..]);
            if r.is_ok() != fits {
                die(&format!("from_wire {} a {}-byte input", if fits { "refused" } else { "accepted" }, data.len()));
            }
            if let Ok(s) = r {
                if s.to_wire() != data {
                    die("to_wire(from_wire(x)) != x");
                }
                static KEY: OnceLock<KemKeyPair> = OnceLock::new();
                let key = KEY.get_or_init(|| KemKeyPair::vectors_ephemeral(&[7; 96]).unwrap_or_else(|_| die("no key")));
                if key.open("scaas/test/v1", b"", &s).is_ok() {
                    die("a seal not made to this key opened");
                }
            }
        }
        "kem_pk" => {
            if kem_encaps(data).is_ok() && (data.len() != 1601 || data.first() != Some(&1)) {
                die(&format!("a {}-byte kemPk of scheme {:?} accepted", data.len(), data.first()));
            }
        }
        "mnemonic" => {
            let Ok(s) = std::str::from_utf8(data) else { return };
            let r = Wallet::from_mnemonic(s, "").map(|_| ());
            if r.is_ok() && (s.len() > 1024 || s.split_whitespace().count() > 24) {
                die(&format!("a mnemonic of {} B, {} words accepted", s.len(), s.split_whitespace().count()));
            }
            if Wallet::from_mnemonic(s, "").map(|_| ()) != r {
                die("not deterministic");
            }
        }
        "container_expect" => {
            json(data, LOOKUP, ContainerExpectJson::from_json);
        }
        "members" => {
            json(data, LOOKUP, MembersJson::from_json);
        }
        "accepted" => {
            json(data, LOOKUP, AcceptedJson::from_json);
        }
        "uasig" => {
            // no key handles: a parsed request signs nothing (every key position is past the empty list)
            if let Some(r) = json(data, UASIG, UaSigRequest::from_json) {
                if r.sign(&[]).is_ok() {
                    die("a UASig built with no key");
                }
            }
        }
        _ => die(
            "UA_FUZZ_TARGET: typed_data | expect | tx | vault | manifest | container | sealed | kem_pk | mnemonic | container_expect | \
             members | accepted | uasig",
        ),
    }
}

/// libFuzzer's entry point.
///
/// # Safety
/// libFuzzer passes `size` readable bytes at `data`.
#[no_mangle]
pub unsafe extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    let t = TARGET.get_or_init(|| std::env::var("UA_FUZZ_TARGET").unwrap_or_default());
    let input = if size == 0 { &[][..] } else { std::slice::from_raw_parts(data, size) };
    one(t, input);
    0
}
