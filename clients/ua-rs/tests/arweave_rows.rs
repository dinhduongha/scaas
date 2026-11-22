// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! chains-arweave plan T17 (features `app-core`, `fam-arweave`, test-only `vectors`): every clientkeys row built byte for byte
//! by `ua-rs` from the same inputs: the items of types 2, 3, 4 with tags, a target and an anchor; the sealed objects; the
//! wrongly framed objects `open_file` refuses (len, pad, sha256) beside their control; the reader's length and `ctSha256`
//! check; the upload keys (the secp256k1 counter path by its fixture); `seal_for_arweave`'s items.
use scaas_ua::arweave::{vectors_build, SigType, Tag};
use scaas_ua::file::{check_object, ObjectError, CAP};
use scaas_ua::wallet::{
    aead_seal, vectors_sign_count, vectors_upload_key, Alg, AppKeys, Error, KeyUsage, Wallet,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const MNEMONIC: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

fn vec(p: &str) -> Value {
    let f = format!(
        "{}/../../smartcontracts/vectors/{p}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap()
}
fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn a32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().unwrap()
}
fn opt32(v: &Value) -> Option<[u8; 32]> {
    (!v.is_null()).then(|| a32(v))
}
fn ty(v: &Value) -> SigType {
    SigType::from_u16(v.as_u64().unwrap() as u16).unwrap()
}
/// clientkeys' `rnd(name, n)`: keccak256("scaas/arweave/vectors/<name>/<i>") blocks.
fn rnd(name: &str, n: usize) -> Vec<u8> {
    let mut out = vec![];
    let mut i = 0;
    while out.len() < n {
        out.extend(scaas_ua::keccak256(
            format!("scaas/arweave/vectors/{name}/{i}").as_bytes(),
        ));
        i += 1;
    }
    out.truncate(n);
    out
}
fn keys() -> (Wallet, AppKeys) {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let k = w.app_keys();
    (w, k)
}

#[test]
fn every_item_row_built_byte_for_byte() {
    for r in vec("arweave/items.json")["items"].as_array().unwrap() {
        let tags: Vec<Tag> = r["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| Tag {
                name: unhex(&t["name"]),
                value: unhex(&t["value"]),
            })
            .collect();
        let it = vectors_build(
            ty(&r["type"]),
            &a32(&r["secret"]),
            &unhex(&r["data"]),
            opt32(&r["target"]).as_ref(),
            opt32(&r["anchor"]).as_ref(),
            &tags,
        )
        .unwrap();
        assert_eq!(it.bytes(), &unhex(&r["item"])[..], "{}", r["name"]);
        assert_eq!(it.id_b64(), r["id"].as_str().unwrap());
    }
}

#[test]
fn sealed_objects_frames_and_checks() {
    let (_w, k) = keys();
    let v = vec("arweave/objects.json");
    let key = a32(&v["fileKey"]);
    for r in v["sealed"].as_array().unwrap() {
        let file = rnd(
            r["fileSeed"].as_str().unwrap(),
            r["size"].as_u64().unwrap() as usize,
        );
        let s = k
            .vectors_seal_file(k.vectors_import(&key, KeyUsage::File).unwrap(), &file)
            .unwrap();
        assert_eq!(
            s.object.len() as u64,
            r["objectLength"].as_u64().unwrap(),
            "{}",
            r["name"]
        );
        assert_eq!(s.ct_sha256.to_vec(), unhex(&r["ctSha256"]), "{}", r["name"]);
        assert_eq!(s.object[..32].to_vec(), unhex(&r["head"]));
        assert_eq!(s.object[s.object.len() - 16..].to_vec(), unhex(&r["tail"]));
        assert_eq!(s.sha256.to_vec(), unhex(&r["sha256"]));
        assert_eq!(
            &k.open_file(&s.key, &s.object, s.size, &s.sha256, &s.ct_sha256)
                .unwrap()[..],
            &file[..]
        );
    }
    // the frames a lying sender builds, each encrypted under the file key; the control opens
    let file = rnd("file/5 bytes", 5);
    let h = k.vectors_import(&key, KeyUsage::File).unwrap();
    for r in v["frames"].as_array().unwrap() {
        let mut fr = vec![0u8; 1 << 16];
        fr[..8].copy_from_slice(&5u64.to_be_bytes());
        fr[8..13].copy_from_slice(&file);
        if let Some(len) = r["frame"]["len"].as_u64() {
            fr[..8].copy_from_slice(&len.to_be_bytes());
        }
        if let Some(at) = r["frame"]["padAt"].as_u64() {
            fr[at as usize] = r["frame"]["padValue"].as_u64().unwrap() as u8;
        }
        let object = aead_seal(Alg::Aes256Gcm, &key, &[0; 12], &[], &fr).unwrap();
        assert_eq!(
            Sha256::digest(&object).to_vec(),
            unhex(&r["ctSha256"]),
            "{}",
            r["name"]
        );
        let got = k.open_file(&h, &object, 5, &a32(&r["sha256"]), &a32(&r["ctSha256"]));
        match r["code"].as_str() {
            None => assert_eq!(&got.unwrap()[..], &file[..], "{}", r["name"]),
            Some(c) => assert_eq!(got.unwrap_err().code(), c, "{}", r["name"]),
        }
    }
    // the reader's check before decryption, each beside its control
    let good = k
        .vectors_seal_file(k.vectors_import(&key, KeyUsage::File).unwrap(), &file)
        .unwrap()
        .object;
    let ct: [u8; 32] = Sha256::digest(&good).into();
    for r in v["checks"]["rows"].as_array().unwrap() {
        let mut o = good.clone();
        match r["change"].as_str() {
            Some("drop-last") => drop(o.pop()),
            Some("append-zero") => o.push(0),
            Some("flip-1000") => o[1000] ^= 1,
            _ => {}
        }
        let want = match r["code"].as_str() {
            None => Ok(()),
            Some("FileLength") => Err(ObjectError::Length),
            Some(_) => Err(ObjectError::HashMismatch),
        };
        assert_eq!(check_object(&o, 5, &ct, CAP), want, "{}", r["name"]);
    }
}

#[test]
fn upload_keys_and_seal_for_arweave_rows() {
    let (_w, k) = keys();
    let v = vec("arweave/upload.json");
    let root = a32(&v["appRoot"]);
    for r in v["rows"].as_array().unwrap() {
        let (seed, owner, counter) = vectors_upload_key(
            &root,
            &a32(&r["fileKey"]),
            ty(&r["type"]),
            &a32(&r["ctSha256"]),
            r["refuseFirst"].as_bool().unwrap_or(false),
        )
        .unwrap();
        assert_eq!(seed.to_vec(), unhex(&r["secret"]), "{}", r["name"]);
        assert_eq!(owner, unhex(&r["owner"]), "{}", r["name"]);
        assert_eq!(
            u64::from(counter),
            r["counter"].as_u64().unwrap(),
            "{}",
            r["name"]
        );
    }
    let root_h = k.vectors_import(&root, KeyUsage::Derive).unwrap();
    for r in v["sealForArweave"].as_array().unwrap() {
        let file = rnd(
            r["fileSeed"].as_str().unwrap(),
            r["size"].as_u64().unwrap() as usize,
        );
        let before = vectors_sign_count();
        let a = k
            .vectors_seal_for_arweave(
                &root_h,
                k.vectors_import(&a32(&r["fileKey"]), KeyUsage::File)
                    .unwrap(),
                &file,
                ty(&r["type"]),
            )
            .unwrap();
        assert!(vectors_sign_count() > before);
        assert_eq!(a.ct_sha256.to_vec(), unhex(&r["ctSha256"]), "{}", r["name"]);
        assert_eq!(a.item.id_b64(), r["id"].as_str().unwrap(), "{}", r["name"]);
        assert_eq!(a.url, r["url"].as_str().unwrap());
        let header = &a.item.bytes()[..a.item.bytes().len() - a.item.data().len()];
        assert_eq!(header.to_vec(), unhex(&r["header"]), "{}", r["name"]);
        assert_eq!(
            Sha256::digest(a.item.bytes()).to_vec(),
            unhex(&r["itemSha256"])
        );
        assert_eq!(a.sha256.to_vec(), unhex(&r["sha256"]));
    }
    // a root that is not a Derive handle is refused
    let data = k.vectors_import(&root, KeyUsage::Data).unwrap();
    let fk = k.vectors_import(&[9; 32], KeyUsage::File).unwrap();
    assert_eq!(
        k.vectors_seal_for_arweave(&data, fk, b"x", SigType::Ed25519)
            .err()
            .unwrap(),
        Error::AppKeyUsage
    );
}
