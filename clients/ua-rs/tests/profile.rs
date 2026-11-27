// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! user-profiles plan UP2 (spec 2026-11-27-user-profiles §7.1, §7.2, §7.5, §10.1, §17 G2, G8, G15): the profile arena
//! `ProfileKeys` and `ExportKey` reproduce clientkeys' rows (smartcontracts/vectors/profile/{envelope,items,export}.json) byte
//! for byte through handles only, and refuse by name. Not here (SDK tasks): the envelope, manifest and anchor JSON, the
//! `kdf` object's `alg` / `v` fields, the per-device maximum, the import's header and length refusals (UP5, UP6, UP10).
//! Every test that runs an Argon2id or reads the run counter holds `KDF` (the counter and the forced out-of-memory hook are
//! process-wide). The default set (64 MiB) runs once in this file: the first `pass` row's wrap.
use base64ct::{Base64, Encoding};
use scaas_ua::wallet::{Argon2Params, Error, ExportKey, MemoryProtection, ProfileKeys};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{Mutex, MutexGuard};

static KDF: Mutex<()> = Mutex::new(());
fn kdf_lock() -> MutexGuard<'static, ()> {
    KDF.lock().unwrap_or_else(|e| e.into_inner())
}

fn v(name: &str) -> Value {
    let f = format!(
        "{}/../../smartcontracts/vectors/profile/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap()
}
fn rows<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}
fn b(v: &Value) -> &[u8] {
    v.as_str().unwrap().as_bytes()
}
fn a32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().unwrap()
}
fn a12(v: &Value) -> [u8; 12] {
    unhex(v).try_into().unwrap()
}
fn unb64(v: &Value) -> Vec<u8> {
    Base64::decode_vec(s(v)).unwrap()
}
/// A `kdf` object's parameters and salt.
fn kdf(k: &Value) -> (Argon2Params, Vec<u8>) {
    let n = |f: &str| k[f].as_u64().unwrap() as u32;
    let salt = Base64::decode_vec(s(&k["salt"])).unwrap_or_default();
    (
        Argon2Params {
            m_kib: n("m"),
            t: n("t"),
            p: n("p"),
        },
        salt,
    )
}
fn with_dek(dek: &[u8; 32]) -> ProfileKeys {
    let k = ProfileKeys::new();
    k.vectors_set_dek(dek).unwrap();
    k
}
fn rnd(name: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    for i in 0..n.div_ceil(32) {
        out.extend_from_slice(&scaas_ua::keccak256(
            format!("scaas/profile/vectors/{name}/{i}").as_bytes(),
        ));
    }
    out.truncate(n);
    out
}

// ------------------------------------------------------------------ the envelope (§7.1)

#[test]
fn pass_rows() {
    let _g = kdf_lock();
    let e = v("envelope");
    let subs = rows(&e, "sub_keys");
    for r in rows(&e, "pass") {
        let case = s(&r["case"]);
        let (p, salt) = kdf(&r["kdf"]);
        assert_eq!(salt, unhex(&r["salt"]), "{case}");
        let k = with_dek(&a32(&r["dek"]));
        let runs = ProfileKeys::kdf_runs();
        let (stretched, kek, wrap) = k
            .vectors_wrap_pass(
                b(&r["passphrase"]),
                &salt,
                p,
                b(&r["public_json"]),
                &a12(&r["nonce"]),
            )
            .unwrap();
        assert_eq!(
            ProfileKeys::kdf_runs(),
            runs + 1,
            "{case}: one Argon2id run"
        );
        assert_eq!(stretched, unhex(&r["argon2id"]), "{case}");
        assert_eq!(kek, unhex(&r["kek_pass"]), "{case}");
        assert_eq!(wrap, unhex(&r["pass"]), "{case}");
        assert_eq!(Base64::encode_string(&wrap), s(&r["pass_b64"]), "{case}");
        let sub = subs.iter().find(|x| x["case"] == r["case"]).unwrap();
        let want: Vec<Vec<u8>> = ["dek", "k_label", "k_item", "k_name"]
            .iter()
            .map(|f| unhex(&sub[*f]))
            .collect();
        assert_eq!(k.vectors_reveal().unwrap().to_vec(), want, "{case}");
        if r["set"] == "default" {
            continue; // the 64 MiB set runs once in this file
        }
        // the wrap opens to the row's DEK_p from the passphrase alone; the typed passphrase checks against it
        let o = ProfileKeys::new();
        o.open_pass(b(&r["passphrase"]), &salt, p, b(&r["public_json"]), &wrap)
            .unwrap();
        assert_eq!(o.vectors_reveal().unwrap()[0], unhex(&r["dek"]), "{case}");
        o.check_pass(b(&r["passphrase"]), &salt, p, b(&r["public_json"]), &wrap)
            .unwrap();
        assert_eq!(
            o.check_pass(b"another passphrase", &salt, p, b(&r["public_json"]), &wrap),
            Err(Error::Aead)
        );
        let n = ProfileKeys::new();
        assert_eq!(
            n.open_pass(b"another passphrase", &salt, p, b(&r["public_json"]), &wrap),
            Err(Error::Aead),
            "{case}: a wrong passphrase"
        );
        // a random wrap of the same DEK_p opens too, and differs from the fixed-nonce one
        let w2 = o
            .wrap_pass(b(&r["passphrase"]), &salt, p, b(&r["public_json"]))
            .unwrap();
        assert_ne!(w2, wrap);
        n.open_pass(b(&r["passphrase"]), &salt, p, b(&r["public_json"]), &w2)
            .unwrap();
        assert_eq!(n.vectors_reveal().unwrap()[0], unhex(&r["dek"]));
    }
}

#[test]
fn platform_rows() {
    let e = v("envelope");
    for r in rows(&e, "platform") {
        let k = with_dek(&a32(&r["dek"]));
        let pubj = b(&r["public_json"]);
        let (k_plat, wrap) = k
            .vectors_wrap_platform(&unhex(&r["secret"]), pubj, &a12(&r["nonce"]))
            .unwrap();
        assert_eq!(k_plat, unhex(&r["k_plat"]));
        assert_eq!(wrap, unhex(&r["wrap"]));
        let o = ProfileKeys::new();
        o.open_platform(&unhex(&r["secret"]), pubj, &wrap).unwrap();
        assert_eq!(o.vectors_reveal().unwrap()[0], unhex(&r["dek"]));
        // an app that left the lent buffer zero (or gave none) is refused, on both sides
        for bad in [vec![0u8; 32], vec![]] {
            assert_eq!(k.wrap_platform(&bad, pubj), Err(Error::Argument));
            assert_eq!(
                ProfileKeys::new().open_platform(&bad, pubj, &wrap),
                Err(Error::Argument)
            );
        }
        let mut other = unhex(&r["secret"]);
        other[0] ^= 1;
        assert_eq!(
            ProfileKeys::new().open_platform(&other, pubj, &wrap),
            Err(Error::Aead)
        );
    }
}

#[test]
fn sub_key_rows() {
    let e = v("envelope");
    for r in rows(&e, "sub_keys") {
        let k = with_dek(&a32(&r["dek"]));
        let want: Vec<Vec<u8>> = ["dek", "k_label", "k_item", "k_name"]
            .iter()
            .map(|f| unhex(&r[*f]))
            .collect();
        assert_eq!(k.vectors_reveal().unwrap().to_vec(), want, "{}", r["case"]);
    }
}

fn dek_of(e: &Value, key: &str, val: &Value) -> [u8; 32] {
    a32(&rows(e, "sub_keys").iter().find(|x| x[key] == *val).unwrap()["dek"])
}

#[test]
fn label_rows() {
    let e = v("envelope");
    for r in rows(&e, "labels") {
        let case = s(&r["case"]);
        let k = with_dek(&dek_of(&e, "k_label", &r["k_label"]));
        let sealed = k
            .vectors_seal_label(s(&r["id"]), b(&r["plaintext"]), &a12(&r["nonce"]))
            .unwrap();
        assert_eq!(sealed, unhex(&r["sealed"]), "{case}");
        assert_eq!(
            Base64::encode_string(&sealed),
            s(&r["sealed_b64"]),
            "{case}"
        );
        assert_eq!(
            &k.open_label(s(&r["id"]), &sealed).unwrap()[..],
            b(&r["plaintext"])
        );
        assert_eq!(
            k.open_label(s(&r["other_id"]), &sealed),
            Err(Error::Aead),
            "{case}: a label moved to another id"
        );
        let fresh = k.seal_label(s(&r["id"]), b(&r["plaintext"])).unwrap();
        assert_ne!(fresh, sealed);
        assert_eq!(
            &k.open_label(s(&r["id"]), &fresh).unwrap()[..],
            b(&r["plaintext"])
        );
    }
}

fn pass_row<'a>(e: &'a Value, public: &Value) -> &'a Value {
    rows(e, "pass")
        .iter()
        .find(|x| x["public_json"] == *public)
        .unwrap()
}

#[test]
fn envelope_file_rows() {
    let _g = kdf_lock();
    let e = v("envelope");
    let mut opened = 0;
    for r in rows(&e, "files") {
        let f: Value = serde_json::from_str(s(&r["file"])).unwrap();
        if f["state"] == "unprotected" {
            assert!(f.get("pass").is_none() && f.get("label").is_none());
            continue;
        }
        let pr = pass_row(&e, &r["public_json"]);
        let (p, salt) = kdf(&f["kdf"]);
        let k = ProfileKeys::new();
        k.open_pass(
            b(&pr["passphrase"]),
            &salt,
            p,
            b(&r["public_json"]),
            &unb64(&f["pass"]),
        )
        .unwrap();
        assert_eq!(k.vectors_reveal().unwrap()[0], unhex(&r["dek"]));
        let label: Value =
            serde_json::from_slice(&k.open_label(s(&f["id"]), &unb64(&f["label"])).unwrap())
                .unwrap();
        assert_eq!(label["hidden"], f.get("name").is_none());
        if let Some(n) = f.get("name") {
            assert_eq!(label["name"], *n);
        }
        if let Some(pl) = f.get("platform") {
            let row = &rows(&e, "platform")[0];
            assert_eq!(row["k_plat"], r["k_plat"]);
            let o = ProfileKeys::new();
            o.open_platform(
                &unhex(&row["secret"]),
                b(&r["public_json"]),
                &unb64(&pl["wrap"]),
            )
            .unwrap();
            assert_eq!(o.vectors_reveal().unwrap()[0], unhex(&r["dek"]));
        }
        opened += 1;
    }
    assert_eq!(opened, 2);
}

#[test]
fn wrap_refusal_rows() {
    let _g = kdf_lock();
    let e = v("envelope");
    for r in rows(&e, "wrap_refusals") {
        let case = s(&r["case"]);
        assert_eq!(r["error"], "Aead");
        let wrap = unhex(&r["wrap"]);
        let (bad, good) = (b(&r["public_json"]), b(&r["control_public_json"]));
        if r["domain"] == "scaas.profile.wrap" {
            let pr = rows(&e, "pass")
                .iter()
                .find(|x| x["kek_pass"] == r["kek"])
                .unwrap();
            // the KEK of the control (its salt, its parameters): only the public JSON in the AD changes
            let (p, salt) = kdf(&pr["kdf"]);
            let pass = b(&pr["passphrase"]);
            let k = ProfileKeys::new();
            assert_eq!(
                k.open_pass(pass, &salt, p, bad, &wrap),
                Err(Error::Aead),
                "{case}"
            );
            k.open_pass(pass, &salt, p, good, &wrap).unwrap();
            assert_eq!(k.vectors_reveal().unwrap()[0], unhex(&r["dek"]), "{case}");
        } else {
            let pl = rows(&e, "platform")
                .iter()
                .find(|x| x["k_plat"] == r["kek"])
                .unwrap();
            let secret = unhex(&pl["secret"]);
            let k = ProfileKeys::new();
            assert_eq!(
                k.open_platform(&secret, bad, &wrap),
                Err(Error::Aead),
                "{case}"
            );
            k.open_platform(&secret, good, &wrap).unwrap();
            assert_eq!(k.vectors_reveal().unwrap()[0], unhex(&r["dek"]), "{case}");
        }
    }
}

#[test]
fn name_hint_rows() {
    let _g = kdf_lock();
    let e = v("envelope");
    for r in rows(&e, "name_hint") {
        let (f, c): (Value, Value) = (
            serde_json::from_str(s(&r["file"])).unwrap(),
            serde_json::from_str(s(&r["control_file"])).unwrap(),
        );
        assert_ne!(f["name"], c["name"]);
        assert_eq!(f["pass"], c["pass"]);
        let pr = pass_row(&e, &r["public_json"]);
        let (p, salt) = kdf(&f["kdf"]);
        let k = ProfileKeys::new();
        k.open_pass(
            b(&pr["passphrase"]),
            &salt,
            p,
            b(&r["public_json"]),
            &unb64(&f["pass"]),
        )
        .unwrap();
        assert_eq!(k.vectors_reveal().unwrap()[0], unhex(&r["dek"]));
    }
}

// ------------------------------------------------------------------ the sealed store (§7.2), G2

fn items_keys(i: &Value) -> ProfileKeys {
    let k = with_dek(&a32(&i["keys"]["dek"]));
    let got = k.vectors_reveal().unwrap();
    assert_eq!(got[2], unhex(&i["keys"]["k_item"]));
    assert_eq!(got[3], unhex(&i["keys"]["k_name"]));
    k
}

#[test]
fn item_rows() {
    let i = v("items");
    let k = items_keys(&i);
    for r in rows(&i, "items") {
        let case = s(&r["case"]);
        let (part, item, rev) = (s(&r["part"]), s(&r["item"]), r["rev"].as_u64().unwrap());
        let pt = unhex(&r["plaintext"]);
        let sealed = k
            .vectors_seal_item(part, item, rev, &pt, &a12(&r["nonce"]))
            .unwrap();
        assert_eq!(sealed, unhex(&r["sealed"]), "{case}");
        assert_eq!(
            format!(
                "{{\"rev\":{rev},\"sealed\":\"{}\"}}",
                Base64::encode_string(&sealed)
            ),
            s(&r["file_json"]),
            "{case}"
        );
        assert_eq!(&k.open_item(part, item, rev, &sealed).unwrap()[..], &pt[..]);
        assert_eq!(
            k.item_file(part, item).unwrap(),
            s(&r["file_name"]),
            "{case}"
        );
    }
}

/// G2: an item moved to another name, part or rev fails its tag; the item in place opens.
#[test]
fn item_refusal_rows() {
    let i = v("items");
    let k = items_keys(&i);
    for r in rows(&i, "item_refusals") {
        let case = s(&r["case"]);
        assert_eq!(r["error"], "Aead");
        let sealed = unhex(&r["sealed"]);
        let c = &r["control"];
        assert_eq!(
            &k.open_item(
                s(&c["part"]),
                s(&c["item"]),
                c["rev"].as_u64().unwrap(),
                &sealed
            )
            .unwrap()[..],
            &unhex(&c["plaintext"])[..],
            "{case}: control"
        );
        assert_eq!(
            k.open_item(
                s(&r["part"]),
                s(&r["item"]),
                r["rev"].as_u64().unwrap(),
                &sealed
            ),
            Err(Error::Aead),
            "{case}"
        );
    }
}

/// G2: two seals of one (part, name, rev, plaintext) differ, by the rows' two nonces and by `seal_item`'s own draws.
#[test]
fn two_seals_differ() {
    let i = v("items");
    let k = items_keys(&i);
    let t = &i["two_seals"];
    let (part, item, rev) = (s(&t["part"]), s(&t["item"]), t["rev"].as_u64().unwrap());
    let pt = unhex(&t["plaintext"]);
    for n in ["a", "b"] {
        let sealed = k
            .vectors_seal_item(part, item, rev, &pt, &a12(&t[format!("nonce_{n}")]))
            .unwrap();
        assert_eq!(sealed, unhex(&t[format!("sealed_{n}")]));
    }
    let (x, y) = (
        k.seal_item(part, item, rev, &pt).unwrap(),
        k.seal_item(part, item, rev, &pt).unwrap(),
    );
    assert_ne!(x, y, "two seals of one item are equal");
    assert_ne!(x[..12], y[..12]);
    for z in [&x, &y] {
        assert_eq!(&k.open_item(part, item, rev, z).unwrap()[..], &pt[..]);
    }
}

// ------------------------------------------------------------------ export chunks (§10.1)

const CHUNK: usize = 1_048_576;
const STEP: usize = CHUNK + 16;

#[test]
fn export_key_rows() {
    let _g = kdf_lock();
    let x = v("export");
    for r in rows(&x, "keys") {
        let (p, salt) = kdf(&r["kdf"]);
        let k = ExportKey::derive(b(&r["passphrase"]), &salt, p).unwrap();
        assert_eq!(k.vectors_reveal().unwrap(), unhex(&r["k_x"]));
    }
}

fn be32(n: usize) -> [u8; 4] {
    (n as u32).to_be_bytes()
}
fn header(k: &Value, prefix: &[u8]) -> Vec<u8> {
    format!(
        "{{\"format\":\"scaas.profile-export\",\"v\":1,\"kdf\":{},\"nonce_prefix\":\"{}\",\"chunk\":1048576}}",
        serde_json::to_string(k).unwrap(),
        Base64::encode_string(prefix)
    )
    .into_bytes()
}
fn payload(r: &Value) -> Vec<u8> {
    let (l, st) = (b(&r["label"]), unhex(&r["settings"]));
    let mut p = [&be32(l.len())[..], l, &be32(st.len()), &st].concat();
    let items = rows(r, "items");
    p.extend_from_slice(&(items.len() as u16).to_be_bytes());
    for it in items {
        let name = s(&it[0]);
        let bytes = match &it[1] {
            Value::String(_) => unhex(&it[1]),
            f => rnd(s(&f["filler"]), f["len"].as_u64().unwrap() as usize),
        };
        p.extend_from_slice(&(name.len() as u16).to_be_bytes());
        p.extend_from_slice(name.as_bytes());
        p.extend_from_slice(&be32(bytes.len()));
        p.extend_from_slice(&bytes);
    }
    p
}

/// Every export file row by sealing its chunks: the whole small file, and for 1 MiB, 1 MiB + 1 and 2 MiB of payload the
/// file's length, SHA-256, chunk count, first and last 64 bytes; each chunk opens back.
#[test]
fn export_file_rows() {
    let _g = kdf_lock();
    let x = v("export");
    for r in rows(&x, "files") {
        let case = s(&r["case"]);
        let pl = payload(r);
        assert_eq!(
            pl.len() as u64,
            r["payload_len"].as_u64().unwrap(),
            "{case}"
        );
        if r.get("payload").is_some() {
            assert_eq!(pl, unhex(&r["payload"]), "{case}");
        }
        let prefix: [u8; 7] = unhex(&r["nonce_prefix"]).try_into().unwrap();
        let h = header(&r["kdf"], &prefix);
        assert_eq!(h.len() as u64, r["header_len"].as_u64().unwrap(), "{case}");
        let (p, salt) = kdf(&r["kdf"]);
        let k = ExportKey::derive(b(&r["passphrase"]), &salt, p).unwrap();
        let pieces: Vec<&[u8]> = pl.chunks(CHUNK).collect();
        let n = pieces.len();
        let mut file = [&b"SCAASPX1"[..], &be32(h.len()), &h].concat();
        for (i, c) in pieces.iter().enumerate() {
            file.extend_from_slice(&k.seal_chunk(&prefix, i as u32, i + 1 == n, &h, c).unwrap());
        }
        assert_eq!(n as u64, r["chunks"].as_u64().unwrap(), "{case}");
        assert_eq!(file.len() as u64, r["file_len"].as_u64().unwrap(), "{case}");
        assert_eq!(
            Sha256::digest(&file)[..],
            unhex(&r["file_sha256"])[..],
            "{case}"
        );
        assert_eq!(file[..64], unhex(&r["first64"])[..], "{case}");
        assert_eq!(file[file.len() - 64..], unhex(&r["last64"])[..], "{case}");
        if r.get("file").is_some() {
            assert_eq!(file, unhex(&r["file"]), "{case}");
        }
        let body = &file[12 + h.len()..];
        let back: Vec<u8> = body
            .chunks(STEP)
            .enumerate()
            .flat_map(|(i, c)| {
                k.open_chunk(&prefix, i as u32, i + 1 == n, &h, c)
                    .unwrap()
                    .to_vec()
            })
            .collect();
        assert_eq!(back, pl, "{case}");
    }
}

/// The import's chunk-level refusals (reason `tag`): a truncated, reordered or extended file, a cleared last flag, a changed
/// header byte, a wrong passphrase each fail `open_chunk` (`Aead`) on some chunk; the unedited base file opens. The header
/// and length refusals of the same rows are the SDK's import (UP10).
#[test]
fn export_chunk_refusal_rows() {
    let _g = kdf_lock();
    let x = v("export");
    let base_file = |name: &str| -> Vec<u8> {
        let r = rows(&x, "files")
            .iter()
            .find(|f| f["case"] == name)
            .unwrap();
        let pl = payload(r);
        let prefix: [u8; 7] = unhex(&r["nonce_prefix"]).try_into().unwrap();
        let h = header(&r["kdf"], &prefix);
        let (p, salt) = kdf(&r["kdf"]);
        let k = ExportKey::derive(b(&r["passphrase"]), &salt, p).unwrap();
        let n = pl.len().div_ceil(CHUNK);
        let mut f = [&b"SCAASPX1"[..], &be32(h.len()), &h].concat();
        for (i, c) in pl.chunks(CHUNK).enumerate() {
            f.extend_from_slice(&k.seal_chunk(&prefix, i as u32, i + 1 == n, &h, c).unwrap());
        }
        f
    };
    // every chunk of `f` under the passphrase, as an import walks them: the first refusal
    let walk = |f: &[u8], pass: &[u8]| -> Result<(), Error> {
        let hl = u32::from_be_bytes(f[8..12].try_into().unwrap()) as usize;
        let h = &f[12..12 + hl];
        let hv: Value = serde_json::from_slice(h).unwrap();
        let prefix: [u8; 7] = Base64::decode_vec(s(&hv["nonce_prefix"]))
            .unwrap()
            .try_into()
            .unwrap();
        let (p, salt) = kdf(&hv["kdf"]);
        let k = ExportKey::derive(pass, &salt, p)?;
        let body = &f[12 + hl..];
        let n = body.len().div_ceil(STEP);
        for (i, c) in body.chunks(STEP).enumerate() {
            k.open_chunk(&prefix, i as u32, i + 1 == n, h, c)?;
        }
        Ok(())
    };
    let mut seen = 0;
    for r in rows(&x, "refusals") {
        if r["reason"] != "tag" {
            continue;
        }
        let case = s(&r["case"]);
        let f = match r.get("base") {
            Some(base) => {
                let mut f = base_file(s(base));
                // the control: the unedited base opens under its own passphrase
                walk(&f, b"export passphrase, typed twice").unwrap();
                let e = &r["edit"];
                let body = 12 + u32::from_be_bytes(f[8..12].try_into().unwrap()) as usize;
                match e["op"].as_str() {
                    None => {}
                    Some("truncate") => f.truncate(f.len() - e["n"].as_u64().unwrap() as usize),
                    Some("replace") => {
                        let o = e["offset"].as_u64().unwrap() as usize;
                        let h = unhex(&e["hex"]);
                        f[o..o + h.len()].copy_from_slice(&h);
                    }
                    Some("drop_chunk") => {
                        let i = body + STEP * e["i"].as_u64().unwrap() as usize;
                        f.drain(i..(i + STEP).min(f.len()));
                    }
                    Some("swap_chunks") => {
                        let (i, j) = (e["i"].as_u64().unwrap(), e["j"].as_u64().unwrap());
                        let (a, c) = (body + STEP * i as usize, body + STEP * j as usize);
                        let (x1, x2) = (f[a..a + STEP].to_vec(), f[c..c + STEP].to_vec());
                        f[a..a + STEP].copy_from_slice(&x2);
                        f[c..c + STEP].copy_from_slice(&x1);
                    }
                    Some("append_chunk") => {
                        let i = body + STEP * e["i"].as_u64().unwrap() as usize;
                        let c = f[i..(i + STEP).min(f.len())].to_vec();
                        f.extend_from_slice(&c);
                    }
                    Some(op) => panic!("{case}: edit {op}"),
                }
                f
            }
            None => unhex(&r["file"]),
        };
        assert_eq!(walk(&f, b(&r["passphrase"])), Err(Error::Aead), "{case}");
        seen += 1;
    }
    assert_eq!(seen, 8);
}

/// `seal_chunk` refuses what no export writes: an empty or oversized chunk, a short chunk before the last, a 65th chunk
/// (the payload's 64 MiB bound, `ProfileExportTooLarge` at the SDK), a header above 4,096 bytes.
#[test]
fn export_chunk_bounds() {
    let _g = kdf_lock();
    let x = v("export");
    let r = &rows(&x, "keys")[0];
    let (p, salt) = kdf(&r["kdf"]);
    let k = ExportKey::derive(b(&r["passphrase"]), &salt, p).unwrap();
    let (pre, h, full) = ([7u8; 7], b"{}".to_vec(), vec![1u8; CHUNK]);
    assert!(k.seal_chunk(&pre, 63, true, &h, &full).is_ok());
    assert!(k.seal_chunk(&pre, 0, false, &h, &full).is_ok());
    assert!(k.seal_chunk(&pre, 0, true, &h, b"x").is_ok());
    for (i, last, pt, hd) in [
        (0u32, true, &b""[..], &h[..]),
        (0, true, &vec![1u8; CHUNK + 1][..], &h[..]),
        (0, false, &b"x"[..], &h[..]),
        (64, true, &b"x"[..], &h[..]),
        (0, true, &b"x"[..], &vec![b' '; 4097][..]),
    ] {
        assert_eq!(k.seal_chunk(&pre, i, last, hd, pt), Err(Error::Argument));
    }
    let c = k.seal_chunk(&pre, 0, false, &h, &full).unwrap();
    assert_eq!(
        k.open_chunk(&pre, 0, true, &h, &c),
        Err(Error::Aead),
        "the flag"
    );
    assert_eq!(
        k.open_chunk(&pre, 1, false, &h, &c),
        Err(Error::Aead),
        "the index"
    );
    assert_eq!(
        k.open_chunk(&pre, 0, false, b"{ }", &c),
        Err(Error::Aead),
        "the header"
    );
    assert_eq!(
        k.open_chunk(&pre, 0, false, &h, &c[1..]),
        Err(Error::Aead),
        "the length"
    );
    assert_eq!(
        &k.open_chunk(&pre, 0, false, &h, &c).unwrap()[..],
        &full[..]
    );
}

// ------------------------------------------------------------------ KDF bounds and out of memory (§7.5), G8

/// Each bound row, each field alone: refused (`Argument`) before any Argon2id runs, at every entry that runs one; the accepted
/// rows pass the check (not run: 1 GiB). The `alg` / `v` rows are the `kdf` object's JSON fields (the SDK's parse, UP6); the
/// test set without `test-hooks` is the lib test of a build without the feature.
#[test]
fn kdf_bound_rows() {
    let _g = kdf_lock();
    let e = v("envelope");
    let dek = a32(&rows(&e, "pass")[1]["dek"]);
    let pubj = b(&rows(&e, "pass")[1]["public_json"]);
    let wrap = unhex(&rows(&e, "pass")[1]["pass"]);
    let mut refused = 0;
    for r in rows(&e, "kdf_bounds") {
        let case = s(&r["case"]);
        if r["kdf"]["alg"] != "argon2id" || r["kdf"]["v"] != 1 {
            continue;
        }
        let (p, salt) = kdf(&r["kdf"]);
        let test_set = p.m_kib == 8192 && p.t == 1;
        if test_set && r["test_hooks"] == false {
            continue;
        }
        if r.get("error").is_none() {
            assert_eq!(ProfileKeys::kdf_check(p, &salt), Ok(()), "{case}");
            continue;
        }
        let runs = ProfileKeys::kdf_runs();
        assert_eq!(
            ProfileKeys::kdf_check(p, &salt),
            Err(Error::Argument),
            "{case}"
        );
        if salt.len() == 16 {
            // the dummy run draws its own salt: only the parameters' rows reach it
            assert_eq!(ProfileKeys::dummy_kdf(p), Err(Error::Argument), "{case}");
        }
        assert_eq!(
            ExportKey::derive(b"pass phrase", &salt, p).err(),
            Some(Error::Argument),
            "{case}"
        );
        assert_eq!(
            ProfileKeys::new().open_pass(b"pass phrase", &salt, p, pubj, &wrap),
            Err(Error::Argument),
            "{case}"
        );
        let k = with_dek(&dek);
        assert_eq!(
            k.wrap_pass(b"pass phrase", &salt, p, pubj),
            Err(Error::Argument),
            "{case}"
        );
        assert_eq!(
            k.check_pass(b"pass phrase", &salt, p, pubj, &wrap),
            Err(Error::Argument),
            "{case}"
        );
        assert_eq!(ProfileKeys::kdf_runs(), runs, "{case}: an Argon2id ran");
        refused += 1;
    }
    assert_eq!(refused, 8);
    // the positive control: the test set runs, counted
    let runs = ProfileKeys::kdf_runs();
    ProfileKeys::dummy_kdf(ProfileKeys::KDF_TEST).unwrap();
    assert_eq!(ProfileKeys::kdf_runs(), runs + 1);
}

/// Argon2id's own `OutOfMemory` (forced by the hook) is `KdfOutOfMemory` at every entry, never `Argument`; counted as a run.
#[test]
fn kdf_out_of_memory() {
    let _g = kdf_lock();
    let e = v("envelope");
    let r = &rows(&e, "pass")[1];
    let (p, salt) = kdf(&r["kdf"]);
    let (pass, pubj, wrap) = (b(&r["passphrase"]), b(&r["public_json"]), unhex(&r["pass"]));
    let runs = ProfileKeys::kdf_runs();
    ProfileKeys::force_kdf_oom(true);
    let k = with_dek(&a32(&r["dek"]));
    let got = [
        ProfileKeys::dummy_kdf(p).err(),
        ExportKey::derive(pass, &salt, p).err(),
        ProfileKeys::new()
            .open_pass(pass, &salt, p, pubj, &wrap)
            .err(),
        k.wrap_pass(pass, &salt, p, pubj).err(),
        k.check_pass(pass, &salt, p, pubj, &wrap).err(),
    ];
    ProfileKeys::force_kdf_oom(false);
    assert_eq!(got, [Some(Error::KdfOutOfMemory); 5]);
    assert_eq!(Error::KdfOutOfMemory.code(), "KdfOutOfMemory");
    assert_eq!(ProfileKeys::kdf_runs(), runs + 5);
    // the control: the hook off, the same call opens
    ProfileKeys::new()
        .open_pass(pass, &salt, p, pubj, &wrap)
        .unwrap();
}

// ------------------------------------------------------------------ the arena (§7.1, G15)

/// G15: an open profile's arena holds its keys; `lock()` wipes it (every chunk released zero, none left) and every later call
/// is `WalletLocked`, before any KDF; a second key or open on an open arena is `Argument`; drop wipes as lock.
#[test]
fn lock_wipes_the_arena() {
    let _g = kdf_lock();
    let e = v("envelope");
    let r = &rows(&e, "pass")[1];
    let (p, salt) = kdf(&r["kdf"]);
    let (pass, pubj, wrap) = (b(&r["passphrase"]), b(&r["public_json"]), unhex(&r["pass"]));
    let fresh = ProfileKeys::new();
    assert_eq!(
        fresh.seal_item("sdk", "settings", 1, b"x"),
        Err(Error::WalletLocked)
    );
    assert_eq!(fresh.item_file("sdk", "settings"), Err(Error::WalletLocked));

    let k = ProfileKeys::new();
    k.open_pass(pass, &salt, p, pubj, &wrap).unwrap();
    assert!(
        k.memory_protection().chunks >= 1,
        "the arena holds the keys"
    );
    let sealed = k.seal_item("sdk", "settings", 1, b"x").unwrap();
    let label = k.seal_label("id", b"{}").unwrap();
    let runs = ProfileKeys::kdf_runs();
    assert_eq!(k.create_dek(), Err(Error::Argument));
    assert_eq!(
        k.open_pass(pass, &salt, p, pubj, &wrap),
        Err(Error::Argument)
    );
    assert_eq!(ProfileKeys::kdf_runs(), runs, "a KDF ran on an open arena");

    let before = scaas_ua::wallet::vectors_chunks_released();
    k.lock();
    let after = scaas_ua::wallet::vectors_chunks_released();
    assert_eq!(
        k.memory_protection(),
        MemoryProtection::default(),
        "lock() left the arena"
    );
    assert!(after.0 > before.0, "lock() released the arena's chunks");
    assert_eq!(after.1, 0, "a chunk released with a non-zero byte");

    let runs = ProfileKeys::kdf_runs();
    let locked = [
        k.create_dek(),
        k.seal_item("sdk", "settings", 1, b"x").map(drop),
        k.open_item("sdk", "settings", 1, &sealed).map(drop),
        k.item_file("sdk", "settings").map(drop),
        k.seal_label("id", b"{}").map(drop),
        k.open_label("id", &label).map(drop),
        k.wrap_pass(pass, &salt, p, pubj).map(drop),
        k.open_pass(pass, &salt, p, pubj, &wrap),
        k.check_pass(pass, &salt, p, pubj, &wrap),
        k.wrap_platform(&[1u8; 32], pubj).map(drop),
        k.open_platform(&[1u8; 32], pubj, &wrap),
    ];
    assert_eq!(locked, [Err(Error::WalletLocked); 11]);
    assert_eq!(ProfileKeys::kdf_runs(), runs, "a KDF ran after lock()");

    // drop wipes as lock
    let d = ProfileKeys::new();
    d.create_dek().unwrap();
    d.seal_item("sdk", "settings", 1, b"x").unwrap();
    let before = scaas_ua::wallet::vectors_chunks_released();
    drop(d);
    let after = scaas_ua::wallet::vectors_chunks_released();
    assert!(after.0 > before.0, "drop released the arena's chunks");
    assert_eq!(after.1, 0, "a chunk released with a non-zero byte");
}

/// A drawn DEK_p round-trips through its pass wrap into a second arena: the profile's lifecycle at the test set.
#[test]
fn create_wrap_open() {
    let _g = kdf_lock();
    let (p, salt) = (ProfileKeys::KDF_TEST, [9u8; 16]);
    let k = ProfileKeys::new();
    k.create_dek().unwrap();
    let w = k
        .wrap_pass(b"pass phrase", &salt, p, b"{\"pub\":1}")
        .unwrap();
    assert_eq!(w.len(), 60);
    let sealed = k.seal_item("sdk", "keystore", 3, b"secret").unwrap();
    let o = ProfileKeys::new();
    o.open_pass(b"pass phrase", &salt, p, b"{\"pub\":1}", &w)
        .unwrap();
    assert_eq!(
        &o.open_item("sdk", "keystore", 3, &sealed).unwrap()[..],
        b"secret"
    );
    assert_eq!(
        o.item_file("sdk", "keystore").unwrap(),
        k.item_file("sdk", "keystore").unwrap()
    );
    // another profile's key opens nothing of this one
    let other = ProfileKeys::new();
    other.create_dek().unwrap();
    assert_eq!(
        other.open_item("sdk", "keystore", 3, &sealed),
        Err(Error::Aead)
    );
    assert_ne!(
        other.item_file("sdk", "keystore").unwrap(),
        k.item_file("sdk", "keystore").unwrap()
    );
}
