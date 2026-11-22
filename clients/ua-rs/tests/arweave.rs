// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! chains-arweave plan T17 (feature `fam-arweave`): clientkeys' rows of smartcontracts/vectors/arweave/ and pqchat/ar-urls.json
//! reproduced by `ua-rs`: the deep hash, the verifying parser over every item (id, message, owner, data, tags), its
//! refusals beside their controls, the C9 shape, buckets at every edge, `ar://` URLs; and, with `app-core`, the default build's
//! `seal_for_arweave` (a fresh key per call, the item verified, the object opening by `open_file`).
use scaas_ua::arweave::{
    deep_hash, encode_tags, parse_ar_url, signed_message, Chunk, DataItem, SigType, Tag,
};
use scaas_ua::file::{bucket, CAP_64, CAP_WASM32};
use serde_json::Value;

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
fn tags(r: &Value) -> Vec<Tag> {
    r["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| Tag {
            name: unhex(&t["name"]),
            value: unhex(&t["value"]),
        })
        .collect()
}
fn opt32(v: &Value) -> Option<[u8; 32]> {
    (!v.is_null()).then(|| unhex(v).try_into().unwrap())
}

#[test]
fn deep_hash_rows() {
    fn conv(v: &Value, keep: &mut Vec<Vec<u8>>) {
        match v {
            Value::Array(a) => a.iter().for_each(|x| conv(x, keep)),
            x => keep.push(unhex(x)),
        }
    }
    fn chunk<'a>(v: &Value, bytes: &mut std::slice::Iter<'a, Vec<u8>>) -> Chunk<'a> {
        match v {
            Value::Array(a) => Chunk::List(a.iter().map(|x| chunk(x, bytes)).collect()),
            _ => Chunk::Blob(bytes.next().unwrap()),
        }
    }
    for r in vec("arweave/items.json")["deepHash"].as_array().unwrap() {
        let mut keep = vec![];
        conv(&r["value"], &mut keep);
        let c = chunk(&r["value"], &mut keep.iter());
        assert_eq!(deep_hash(&c).to_vec(), unhex(&r["hash"]), "{}", r["name"]);
    }
}

#[test]
fn every_item_row_parses_with_its_id_message_and_fields() {
    let v = vec("arweave/items.json");
    for r in v["items"].as_array().unwrap() {
        let name = r["name"].as_str().unwrap();
        let t = SigType::from_u16(r["type"].as_u64().unwrap() as u16).unwrap();
        let it = DataItem::parse(unhex(&r["item"])).unwrap();
        assert_eq!(it.sig_type(), t, "{name}");
        assert_eq!(it.id_b64(), r["id"].as_str().unwrap(), "{name}");
        assert_eq!(it.owner(), &unhex(&r["owner"])[..], "{name}");
        assert_eq!(it.data(), &unhex(&r["data"])[..], "{name}");
        assert_eq!(encode_tags(&tags(r)), unhex(&r["rawTags"]), "{name}");
        let msg = signed_message(
            t,
            &unhex(&r["owner"]),
            opt32(&r["target"]).as_ref(),
            opt32(&r["anchor"]).as_ref(),
            &unhex(&r["rawTags"]),
            &unhex(&r["data"]),
        );
        assert_eq!(msg.to_vec(), unhex(&r["message"]), "{name}");
        assert_eq!(it.is_c9(), name.ends_with("no tags"), "{name}");
        assert_eq!(
            DataItem::parse_c9(unhex(&r["item"])).is_ok(),
            name.ends_with("no tags"),
            "{name}"
        );
    }
}

#[test]
fn every_refusal_row_is_refused_by_name_beside_its_control() {
    let v = vec("arweave/items.json");
    for r in v["refusals"].as_array().unwrap() {
        let e = DataItem::parse(unhex(&r["item"])).unwrap_err();
        assert_eq!(e.code(), r["code"].as_str().unwrap(), "{}", r["name"]);
    }
    for r in v["items"].as_array().unwrap() {
        assert!(
            DataItem::parse(unhex(&r["item"])).is_ok(),
            "control {}",
            r["name"]
        );
    }
}

#[test]
fn bucket_rows_at_every_edge() {
    for r in vec("arweave/objects.json")["buckets"].as_array().unwrap() {
        let size = r["size"].as_u64().unwrap();
        for (cap, want) in [(CAP_64, &r["bucket64"]), (CAP_WASM32, &r["bucketWasm32"])] {
            assert_eq!(bucket(size, cap), want.as_u64(), "{size} under {cap}");
        }
    }
}

#[test]
fn ar_url_rows() {
    let v = vec("pqchat/ar-urls.json");
    for r in v["urls"].as_array().unwrap() {
        let url = r["url"].as_str().unwrap();
        assert_eq!(
            parse_ar_url(url).is_ok(),
            r["ok"].as_bool().unwrap(),
            "{}",
            r["name"]
        );
    }
    let up = vec("arweave/upload.json");
    let id = parse_ar_url(v["file"]["url"].as_str().unwrap()).unwrap();
    assert_eq!(
        scaas_ua::arweave::b64url(&id),
        up["sealForArweave"][0]["id"].as_str().unwrap()
    );
}

/// The default build (`app-core` and `fam-arweave`): `seal_for_arweave` gives a verified C9 item over the object, a fresh file
/// key per call, the object opening by `open_file`; above the store's cap `FileTooLarge`.
#[cfg(feature = "app-core")]
#[test]
fn seal_for_arweave_seals_signs_and_opens() {
    use scaas_ua::wallet::{Error, Wallet};
    use sha2::{Digest, Sha256};
    let w = Wallet::from_mnemonic(
        "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better",
        "",
    )
    .unwrap();
    let k = w.app_keys();
    let root = k.app_root_key(&[1; 32], &[2; 32]).unwrap();
    for t in [SigType::Ed25519, SigType::Ethereum, SigType::Solana] {
        let a = k.seal_for_arweave(&root, b"attachment", t, CAP_64).unwrap();
        let b = k.seal_for_arweave(&root, b"attachment", t, CAP_64).unwrap();
        assert_ne!(
            a.item.id(),
            b.item.id(),
            "a fresh file key, another object and upload key"
        );
        assert_ne!(a.item.owner(), b.item.owner());
        assert!(a.item.is_c9());
        assert_eq!(a.url, a.item.url());
        assert_eq!(a.ct_sha256, <[u8; 32]>::from(Sha256::digest(a.item.data())));
        let again = DataItem::parse_c9(a.item.bytes().to_vec()).unwrap();
        assert_eq!(again.id(), a.item.id(), "the kept item reloads");
        assert_eq!(
            &k.open_file(&a.key, a.item.data(), a.size, &a.sha256)
                .unwrap()[..],
            b"attachment"
        );
    }
    let big = vec![0u8; 65_529];
    assert_eq!(
        k.seal_for_arweave(&root, &big, SigType::Ed25519, 1 << 16)
            .err()
            .unwrap(),
        Error::FileTooLarge,
        "above the store's largest bucket"
    );
    assert!(
        k.seal_for_arweave(&root, &big, SigType::Ed25519, 1 << 17)
            .is_ok(),
        "control"
    );
    // the root must be a Derive handle: a file key is refused
    let f = k.seal_file(b"x").unwrap();
    assert_eq!(
        k.seal_for_arweave(&f.key, b"y", SigType::Ed25519, CAP_64)
            .err()
            .unwrap(),
        Error::AppKeyUsage
    );
}
