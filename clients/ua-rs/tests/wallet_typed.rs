// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T4: the EIP-712 hasher (faithful: the values as supplied, spec §5.3, C-04), the SCaaS builders' canonical step
//! (unbound `relayer` / `feeRecipient` zeroed, nested too, never on `Any`), and the `Expect` policy in front of
//! `NativeKey::sign_typed` (MD-9: one variant per clientkeys `check*`, `PolicyRefused`; the checked path refuses a non-zero
//! unbound `relayer` / `feeRecipient`, owner 2026-11-05, spec §5.4), against smartcontracts/vectors/{typed/typed_ops.json,
//! ua/portable.json, ua/nested.json, ua/sign.json} (written by clientkeys). UNAUDITED.
use scaas_ua::ua8::PORTABLE_DOMAIN_SEPARATOR;
use scaas_ua::verify::native_ecdsa;
use scaas_ua::wallet::{pqz_verdict_typed_data, scaas_typed_data, ua_sig, Error, Expect, Network, TypedData, Wallet};
use scaas_ua::pay::{meta_pay_id_v2, PayMeta};
use scaas_ua::ua8::is_portable_purpose;
use scaas_ua::{keccak256, pay_lane, purpose_tag, ua_auth_digest, ua_auth_domain_separator, Domain};
use serde_json::{json, Value};

fn load(path: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn b20(v: &Value) -> [u8; 20] {
    bytes(v).try_into().unwrap()
}
fn chain_id(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}
fn td(v: &Value) -> Result<TypedData, Error> {
    TypedData::from_json(&serde_json::to_vec(v).unwrap())
}
fn digest(v: &Value) -> Result<[u8; 32], Error> {
    td(v)?.digest()
}
fn expect(v: &Value) -> Result<Expect, Error> {
    Expect::from_json(&serde_json::to_vec(v).unwrap())
}
fn wallet() -> Wallet {
    let k = load("ua/keys.json");
    let m = arr(&k, "mnemonics").iter().find(|m| m["id"] == "pq_kat").unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
/// The 20 address bytes of the vector wallet's EVM key 0.
fn evm_address(w: &Wallet) -> [u8; 20] {
    let a = w.native_key(Network::Evm, 0, None).unwrap().address().unwrap();
    hex::decode(a.trim_start_matches("0x")).unwrap().try_into().unwrap()
}
const DOMAIN_NAMES: [&str; 7] = [
    "SCaaS MetaToken", "SCaaS ZetherToken", "SCaaS PqzToken", "SCaaS MandateWallet", "SCaaS SmartKeyAccount", "SCaaS Dex",
    "SCaaS GovernanceRouter",
];

/// `typed/typed_ops.json`: every signed struct (86: ua-mtx-merge's merged-entry rows, T76's router creations and 3f's three PQZ
/// verifier ops) in every domain
/// it is signed in: `encodeType`, `structHash`, the domain separator and the digest from the row's typed data; the SCaaS builder
/// of the row's primary type (`scaas_typed_data`, the op table) gives the same digest in each of its domains and, in every other
/// SCaaS domain name, refuses or builds another struct (`UARollOver`: the Zether row and the PQZ row `UAPqzRollOver`, group 3g);
/// each row's ECDSA signature recovers to the row's key over that digest.
#[test]
fn typed_ops_json_rows() {
    let t = load("typed/typed_ops.json");
    let key = b20(&t["key"]["address"]);
    let (mut ops, mut rows) = (0, 0);
    for (name, op) in t["ops"].as_object().unwrap() {
        ops += 1;
        let mut names = vec![];
        let primary = op["primaryType"].as_str().unwrap_or(name); // a row names its primary type where it is not the row name
        for d in op["domains"].as_object().unwrap().values() {
            let v = json!({"types": op["types"], "primaryType": primary, "domain": d["domain"], "message": op["message"]});
            let x = td(&v).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(x.encode_type(), op["typeString"].as_str().unwrap(), "{name}");
            assert_eq!(x.struct_hash().unwrap(), b32(&op["structHash"]), "{name}");
            assert_eq!(x.domain_separator().unwrap(), b32(&d["domainSeparator"]), "{name}");
            let dg = x.digest().unwrap();
            assert_eq!(dg, b32(&d["digest"]), "{name}");
            assert!(native_ecdsa(&key, &dg, &bytes(&d["signature"])), "{name}");
            let dom = &d["domain"];
            let n = dom["name"].as_str().unwrap();
            let built = scaas_typed_data(primary, Some(n), &b20(&dom["verifyingContract"]), chain_id(&dom["chainId"]), &b32(&dom["salt"]),
                &op["message"])
            .unwrap_or_else(|e| panic!("{name} in {n}: {e:?}"));
            assert_eq!(built.digest().unwrap(), dg, "{name} in {n}: the builder");
            names.push(n.to_string());
            rows += 1;
        }
        let dom = &op["domains"].as_object().unwrap().values().next().unwrap()["domain"];
        for other in DOMAIN_NAMES.iter().filter(|n| !names.contains(&n.to_string())) {
            match scaas_typed_data(primary, Some(other), &b20(&dom["verifyingContract"]), 1, &[0; 32], &op["message"]) {
                Ok(x) => assert_ne!(x.encode_type(), op["typeString"].as_str().unwrap(), "{name} is not signed in {other}"),
                Err(e) => assert_eq!(e, Error::Argument, "{name} is not signed in {other}"),
            }
        }
    }
    assert_eq!((ops, rows), (86, 120));
}

/// `ua/portable.json` and `ua/nested.json`: the typed data of every registration, KEM record, PQZ key record and acceptance hashes
/// to the row's digest in the portable domain (no chainId); `sign.json` `chainSeparation.portable` too.
#[test]
fn portable_json_typed_rows() {
    let mut n = 0;
    for f in ["ua/portable.json", "ua/nested.json"] {
        let p = load(f);
        for (table, field) in [
            ("registrations", "registrationDigest"), ("afterAcceptance", "registrationDigest"), ("kemRecords", "digest"),
            ("pqzKeyRecords", "recordDigest"), ("memberships", "digest"),
        ] {
            for r in p[table].as_array().map_or(&[][..], |a| a.as_slice()) {
                let x = td(&r["typedData"]).unwrap_or_else(|e| panic!("{f} {table} {}: {e:?}", r["name"]));
                assert_eq!(x.domain_separator().unwrap(), PORTABLE_DOMAIN_SEPARATOR);
                assert_eq!(x.digest().unwrap(), b32(&r[field]), "{f} {table} {}", r["name"]);
                n += 1;
            }
        }
    }
    let s = load("ua/sign.json");
    for r in arr(&s["chainSeparation"], "portable") {
        assert_eq!(digest(&r["td"]).unwrap(), b32(&r["digest"]));
        n += 1;
    }
    // portable 61, nested 25 (T66a, CTR-UA-32: no msig KEM record, so 12 portable KEM records and none nested), chainSeparation 1
    assert_eq!(n, 27 + 12 + 16 + 6 + 16 + 1 + 4 + 4 + 1);
}

/// `sign.json` `typed.generic`: negative `int` (two's complement), `uint256[]`, `Item[2]`, `Item[]`, `string`, `bytes`, `bool`,
/// `bytes4`, missing fields as zeros; `typed.refusals` (the generic row with one change each): an unknown field, `int8` out of
/// range, a fixed array of the wrong length, a bool as a string, a `bytes4` of three bytes, each `Argument`.
#[test]
fn sign_json_typed_rows() {
    let s = load("ua/sign.json");
    for r in arr(&s["typed"], "generic") {
        assert_eq!(digest(&r["td"]).unwrap(), b32(&r["digest"]), "{}", r["id"]);
    }
    for r in arr(&s["typed"], "refusals") {
        assert_eq!(digest(&r["td"]).err(), Some(Error::Argument), "{}", r["id"]);
    }
    assert_eq!((arr(&s["typed"], "generic").len(), arr(&s["typed"], "refusals").len()), (3, 5));
}

fn basket(s: &Value) -> Value {
    arr(&s["typed"], "generic").iter().find(|r| r["id"] == "arrays-negative-int").unwrap()["td"].clone()
}

/// A field not in its struct's type is refused, at the top and in a nested struct (as clientkeys `hashStruct`); the row as
/// generated passes (positive control).
#[test]
fn unknown_field_refused() {
    let s = load("ua/sign.json");
    let v = basket(&s);
    assert!(digest(&v).is_ok());
    let mut top = v.clone();
    top["message"]["extra"] = json!("1");
    assert_eq!(digest(&top).err(), Some(Error::Argument));
    let mut nested = v.clone();
    nested["message"]["pair"][0]["extra"] = json!("1");
    assert_eq!(digest(&nested).err(), Some(Error::Argument));
    let mut domain = v.clone();
    domain["domain"]["extra"] = json!("1");
    assert_eq!(digest(&domain).err(), Some(Error::Argument));
}

fn types_td(types: Value, primary: &str, message: Value) -> Value {
    let mut t = types;
    t["EIP712Domain"] = json!([{"name": "name", "type": "string"}]);
    json!({"types": t, "primaryType": primary, "domain": {"name": "x"}, "message": message})
}

/// Type references form no cycle (`A → B → A`, `A → A[]`, `A → A` refused) and an acyclic chain passes.
#[test]
fn cyclic_types_refused() {
    let ok = types_td(json!({"A": [{"name": "b", "type": "B"}], "B": [{"name": "x", "type": "uint8"}]}), "A", json!({}));
    assert!(digest(&ok).is_ok());
    for types in [
        json!({"A": [{"name": "b", "type": "B"}], "B": [{"name": "a", "type": "A"}]}),
        json!({"A": [{"name": "a", "type": "A[]"}]}),
        json!({"A": [{"name": "a", "type": "A"}]}),
        json!({"A": [{"name": "x", "type": "uint8"}], "B": [{"name": "c", "type": "C"}], "C": [{"name": "b", "type": "B[2]"}]}),
    ] {
        assert_eq!(td(&types_td(types.clone(), "A", json!({}))).err(), Some(Error::Argument), "{types}");
    }
}

/// `intN` is two's complement in a 32-byte word: -1 is all ones, `int8` -128 and 127 are its ends (-129 and 128 refused),
/// `int256` its minimum; as a JSON number or a decimal string.
#[test]
fn negative_int_two_complement() {
    let one = |ty: &str, v: Value| {
        let x = td(&types_td(json!({"S": [{"name": "v", "type": ty}]}), "S", json!({"v": v})))?;
        x.struct_hash()
    };
    let expect = |ty: &str, word: [u8; 32]| keccak256(&[&keccak256(format!("S({ty} v)").as_bytes())[..], &word].concat());
    let mut w = [0xffu8; 32];
    assert_eq!(one("int256", json!("-1")).unwrap(), expect("int256", w));
    assert_eq!(one("int8", json!(-1)).unwrap(), expect("int8", w));
    w[31] = 0x80;
    assert_eq!(one("int8", json!(-128)).unwrap(), expect("int8", w));
    let mut m = [0u8; 32];
    m[31] = 0x7f;
    assert_eq!(one("int8", json!("127")).unwrap(), expect("int8", m));
    assert_eq!(one("int8", json!(-129)).err(), Some(Error::Argument));
    assert_eq!(one("int8", json!(128)).err(), Some(Error::Argument));
    let mut min = [0u8; 32];
    min[0] = 0x80;
    let int256_min = "-57896044618658097711785492504343953926634992332820282019728792003956564819968";
    assert_eq!(one("int256", json!(int256_min)).unwrap(), expect("int256", min));
    assert_eq!(one("int256", json!("-57896044618658097711785492504343953926634992332820282019728792003956564819969")).err(),
        Some(Error::Argument));
    assert_eq!(one("uint8", json!(-1)).err(), Some(Error::Argument));
    assert_eq!(one("uint8", json!(256)).err(), Some(Error::Argument));
    assert_eq!(one("int8", json!("")).err(), Some(Error::Argument));
}

/// The caps of spec §9.3 (typed data): 64 KiB, JSON depth 8, 32 struct types, 64 fields, type references 8 deep, arrays of
/// 1,024; each at its cap passes, one past it is `Argument`.
#[test]
fn typed_data_bounds() {
    // size: a string field padded to the cap
    let sized = |n: usize| {
        let base = serde_json::to_vec(&types_td(json!({"S": [{"name": "s", "type": "string"}]}), "S", json!({"s": ""}))).unwrap();
        let v = types_td(json!({"S": [{"name": "s", "type": "string"}]}), "S", json!({"s": "a".repeat(n - base.len())}));
        let b = serde_json::to_vec(&v).unwrap();
        assert_eq!(b.len(), n);
        TypedData::from_json(&b).map(|_| ())
    };
    assert!(sized(64 * 1024).is_ok());
    assert_eq!(sized(64 * 1024 + 1).err(), Some(Error::Argument));
    // JSON depth: a value nested in arrays of the message ([[..]] inside {"message": {"v": ...}})
    let deep = |n: usize| {
        let ty = format!("uint8{}", "[]".repeat(n));
        let mut v = json!([]);
        for _ in 1..n {
            v = json!([v]);
        }
        td(&types_td(json!({"S": [{"name": "v", "type": ty}]}), "S", json!({"v": v}))).map(|_| ())
    };
    assert!(deep(6).is_ok()); // {td {message {v [[[[[[ = 8
    assert_eq!(deep(7).err(), Some(Error::Argument));
    // struct types (EIP712Domain counts)
    let many = |n: usize| {
        let mut t = serde_json::Map::new();
        for i in 0..n - 1 {
            t.insert(format!("T{i}"), json!([{"name": "x", "type": "uint8"}]));
        }
        td(&types_td(Value::Object(t), "T0", json!({}))).map(|_| ())
    };
    assert!(many(32).is_ok());
    assert_eq!(many(33).err(), Some(Error::Argument));
    // fields
    let fields = |n: usize| {
        let f: Vec<Value> = (0..n).map(|i| json!({"name": format!("f{i}"), "type": "uint8"})).collect();
        td(&types_td(json!({"S": f}), "S", json!({}))).map(|_| ())
    };
    assert!(fields(64).is_ok());
    assert_eq!(fields(65).err(), Some(Error::Argument));
    // reference depth: S0 → S1 → … (a struct with only atoms is depth 1)
    let chain = |n: usize| {
        let mut t = serde_json::Map::new();
        for i in 0..n - 1 {
            t.insert(format!("S{i}"), json!([{"name": "x", "type": format!("S{}", i + 1)}]));
        }
        t.insert(format!("S{}", n - 1), json!([{"name": "x", "type": "uint8"}]));
        td(&types_td(Value::Object(t), "S0", json!({}))).map(|_| ())
    };
    assert!(chain(8).is_ok());
    assert_eq!(chain(9).err(), Some(Error::Argument));
    // array length, dynamic and fixed
    let items = |n: usize| digest(&types_td(json!({"S": [{"name": "v", "type": "uint8[]"}]}), "S", json!({"v": vec![1; n]})));
    assert!(items(1024).is_ok());
    assert_eq!(items(1025).err(), Some(Error::Argument));
    let fixed = |k: usize| td(&types_td(json!({"S": [{"name": "v", "type": format!("uint8[{k}]")}]}), "S", json!({}))).map(|_| ());
    assert!(fixed(1024).is_ok());
    assert_eq!(fixed(1025).err(), Some(Error::Argument));
}

/// The `EIP712Domain` type is the fields present in `domain`, in EIP-712 order: a supplied `EIP712Domain` in another order, or
/// naming a field the domain lacks, is refused; a domain field outside the five is refused.
#[test]
fn eip712_domain_order() {
    let s = load("ua/sign.json");
    let v = basket(&s);
    assert!(digest(&v).is_ok());
    let mut swapped = v.clone();
    swapped["types"]["EIP712Domain"] = json!([{"name": "version", "type": "string"}, {"name": "name", "type": "string"},
        {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}]);
    assert_eq!(digest(&swapped).err(), Some(Error::Argument));
    let mut salt = v.clone();
    salt["types"]["EIP712Domain"].as_array_mut().unwrap().push(json!({"name": "salt", "type": "bytes32"}));
    assert_eq!(digest(&salt).err(), Some(Error::Argument));
    // with no EIP712Domain type, the present fields in order
    let mut none = v.clone();
    none["types"].as_object_mut().unwrap().remove("EIP712Domain");
    assert_eq!(digest(&none).unwrap(), digest(&v).unwrap());
}

/// `sign.json` `typed.canon`: each SCaaS builder (clientkeys `metaTxTypedData` … `uaReceiverFeeTypedData`, here
/// `scaas_typed_data`) zeroes an unbound `relayer` / `feeRecipient` (`mode & 1`, `mode & 2`), nested ones too; its digest is the
/// row's, its message the row's `zeroed`; the faithful hash of the unzeroed typed data is another digest.
#[test]
fn sign_json_canon_rows() {
    let s = load("ua/sign.json");
    let mut n = 0;
    for r in arr(&s["typed"], "canon") {
        let i = &r["input"];
        let primary = r["zeroed"]["primaryType"].as_str().unwrap();
        let built = scaas_typed_data(primary, i["name"].as_str(), &b20(&i["contract"]), chain_id(&i["chainId"]), &b32(&i["chainUid"]),
            &i["message"])
        .unwrap_or_else(|e| panic!("{}: {e:?}", r["id"]));
        assert_eq!(built.digest().unwrap(), b32(&r["digest"]), "{}", r["id"]);
        assert_eq!(built.to_value()["message"], r["zeroed"]["message"], "{}", r["id"]);
        assert_eq!(digest(&r["zeroed"]).unwrap(), b32(&r["digest"]), "{}", r["id"]);
        // the builder's value is the row's; the same typed data with the input's message as supplied hashes elsewhere
        assert_eq!(digest(&r["td"]).unwrap(), b32(&r["digest"]), "{}", r["id"]);
        let mut supplied = r["td"].clone();
        supplied["message"] = i["message"].clone();
        assert_ne!(digest(&supplied).unwrap(), b32(&r["digest"]), "{}: the faithful hash of the supplied value", r["id"]);
        n += 1;
    }
    assert_eq!(n, 6);
}

/// The builders zero a nested `UAMetaTransfer`'s unbound `relayer` and `feeRecipient` inside a `UAReceiverFee`; the outer struct (no
/// `mode`) keeps its `feeRecipient`; with `mode = 3` the nested pair is bound and kept.
#[test]
fn nested_metatransfer_zeroed() {
    let pay = |mode: u32| {
        json!({"payment": {"from": format!("0x{}", "ac".repeat(32)), "to": format!("0x{}", "5e".repeat(32)),
            "value": "500", "mode": mode, "relayer": "0x000000000000000000000000000000000000beef",
            "feeRecipient": "0x0000000000000000000000000000000000000fee"},
            "fee": "10", "feeRecipient": "0x0000000000000000000000000000000000000fee", "validUntil": "1800000000"})
    };
    let zero = "0x0000000000000000000000000000000000000000";
    let build = |m: &Value| scaas_typed_data("UAReceiverFee", Some("SCaaS MetaToken"), &[0x5c; 20], 7622, &[1; 32], m).unwrap();
    let z = build(&pay(0)).to_value();
    assert_eq!((z["message"]["payment"]["relayer"].as_str(), z["message"]["payment"]["feeRecipient"].as_str()), (Some(zero), Some(zero)));
    assert_eq!(z["message"]["feeRecipient"], "0x0000000000000000000000000000000000000fee");
    let k = build(&pay(3)).to_value();
    assert_eq!(k["message"]["payment"]["relayer"], "0x000000000000000000000000000000000000beef");
    assert_eq!(k["message"]["payment"]["feeRecipient"], "0x0000000000000000000000000000000000000fee");
    // the faithful hash of the supplied value differs from the built one
    let mut supplied = z.clone();
    supplied["message"] = pay(0);
    assert_ne!(digest(&supplied).unwrap(), build(&pay(0)).digest().unwrap());
    // the same field names in an unrelated domain are not SCaaS records: no builder
    assert_eq!(scaas_typed_data("Order", Some("Other Exchange"), &[1; 20], 1, &[0; 32], &json!({})).err(), Some(Error::Argument));
}

/// `sign.json` `policy` (clientkeys `expectDigest` over the `check*` functions): every accepted row signs, through
/// `NativeKey::sign_typed`, the digest the row approves (the signature recovers to the vector wallet's EVM key over it); every
/// refused row is `PolicyRefused` and signs nothing.
#[test]
fn sign_json_policy_rows() {
    let s = load("ua/sign.json");
    let w = wallet();
    let key = w.native_key(Network::Evm, 0, None).unwrap();
    let address = evm_address(&w);
    let (mut signed, mut refused) = (0, 0);
    for r in arr(&s, "policy") {
        let x = td(&r["td"]).unwrap_or_else(|e| panic!("{}: {e:?}", r["id"]));
        let got = expect(&r["expect"]).and_then(|e| key.sign_typed(&x, e));
        if r["refused"].is_string() {
            assert_eq!(got.err(), Some(Error::PolicyRefused), "{}", r["id"]);
            refused += 1;
        } else {
            let sig = got.unwrap_or_else(|e| panic!("{}: {e:?}", r["id"]));
            assert!(native_ecdsa(&address, &b32(&r["digest"]), &sig), "{}", r["id"]);
            signed += 1;
        }
    }
    assert_eq!((signed, refused), (10, 14));
}

fn policy_row<'a>(s: &'a Value, id: &str) -> &'a Value {
    arr(s, "policy").iter().find(|r| r["id"] == id).unwrap()
}

/// The checked path never zeroes: a server typed data whose unbound `relayer` (mode bit 1 clear) or `feeRecipient` (bit 2 clear) is
/// non-zero is refused, on an op (`UABurn`) and on a payment; the same value bound by its mode bit is signed (positive controls).
#[test]
fn checked_path_refuses_nonzero_unbound_relayer_and_fee_recipient() {
    let s = load("ua/sign.json");
    let w = wallet();
    let key = w.native_key(Network::Evm, 0, None).unwrap();
    let address = evm_address(&w);
    let run = |r: &Value, edit: &dyn Fn(&mut Value)| {
        let mut v = r["td"].clone();
        edit(&mut v["message"]);
        let x = td(&v).unwrap();
        key.sign_typed(&x, expect(&r["expect"]).unwrap()).map(|sig| (x.digest().unwrap(), sig))
    };
    let burn = policy_row(&s, "op UABurn");
    let (d, sig) = run(burn, &|_| {}).unwrap();
    assert!(native_ecdsa(&address, &d, &sig), "positive control");
    let beef = json!("0x000000000000000000000000000000000000beef");
    assert_eq!(run(burn, &|m| m["relayer"] = beef.clone()).err(), Some(Error::PolicyRefused), "relayer, mode 0");
    assert_eq!(run(burn, &|m| m["feeRecipient"] = beef.clone()).err(), Some(Error::PolicyRefused), "feeRecipient, mode 0");
    let (d, sig) = run(burn, &|m| {
        m["mode"] = json!(1);
        m["relayer"] = beef.clone();
    })
    .unwrap();
    assert!(native_ecdsa(&address, &d, &sig), "a relayer bound by mode 1 is signed as supplied");
    let pay = policy_row(&s, "payment");
    assert!(run(pay, &|_| {}).is_ok(), "positive control");
    assert_eq!(run(pay, &|m| m["feeRecipient"] = beef.clone()).err(), Some(Error::PolicyRefused), "feeRecipient, mode 1");
    assert_eq!(run(pay, &|m| {
        m["mode"] = json!(0);
    })
    .err(), Some(Error::PolicyRefused), "relayer non-zero once mode 0 leaves it unbound");
}

/// An unrelated contract's struct with `mode` / `relayer` / `feeRecipient` (`Order` of "Other Exchange", mode 0, both non-zero)
/// through `Any`: hashed and signed as supplied (the row's signature byte for byte, RFC 6979), never canonicalised; `Any`
/// without its marker is refused; no SCaaS check accepts it.
#[test]
fn unrelated_order_through_any_is_signed_as_supplied() {
    let s = load("ua/sign.json");
    let r = arr(&s["typed"], "generic").iter().find(|r| r["id"] == "unrelated-order-any").unwrap();
    let w = wallet();
    let key = w.native_key(Network::Evm, 0, None).unwrap();
    assert_eq!(key.address().as_deref(), r["signer"]["address"].as_str());
    let x = td(&r["td"]).unwrap();
    assert_eq!(x.digest().unwrap(), b32(&r["digest"]));
    assert_ne!(b32(&r["digest"]), b32(&r["canonicalDigest"]));
    let sig = key.sign_typed(&x, expect(&json!({"check": "Any", "allowAnyTypedData": true})).unwrap()).unwrap();
    assert_eq!(hex::encode(&sig), hex::encode(bytes(&r["signature"])));
    assert_eq!(expect(&json!({"check": "Any"})).err(), Some(Error::PolicyRefused));
    assert_eq!(expect(&json!({"check": "Any", "allowAnyTypedData": "true"})).err(), Some(Error::PolicyRefused));
    let burn = policy_row(&s, "op UABurn");
    assert_eq!(key.sign_typed(&x, expect(&burn["expect"]).unwrap()).err(), Some(Error::PolicyRefused));
}

/// `Expect` JSON is bounded (16 KiB, depth 4, spec §9.3); an unknown check or a missing input is `Argument`; a native key of an
/// ed25519 network signs no typed data.
#[test]
fn expect_bounds_and_forms() {
    let s = load("ua/sign.json");
    let burn = policy_row(&s, "op UABurn");
    assert!(expect(&burn["expect"]).is_ok());
    let mut big = burn["expect"].clone();
    big["message"]["pad"] = json!("a".repeat(16 * 1024));
    assert_eq!(expect(&big).err(), Some(Error::Argument));
    let mut deep = burn["expect"].clone();
    deep["message"]["x"] = json!({"y": {"z": {}}});
    assert_eq!(expect(&deep).err(), Some(Error::Argument));
    assert_eq!(expect(&json!({"check": "Nothing"})).err(), Some(Error::Argument));
    let mut missing = burn["expect"].clone();
    missing.as_object_mut().unwrap().remove("now");
    assert_eq!(expect(&missing).err(), Some(Error::Argument));
    let w = wallet();
    let sol = w.native_key(Network::Solana, 0, None).unwrap();
    let x = td(&burn["td"]).unwrap();
    assert_eq!(sol.sign_typed(&x, expect(&json!({"check": "Any", "allowAnyTypedData": true})).unwrap()).err(), Some(Error::Argument));
}

/// `chainSeparation.typed` (owner 2026-11-05): the same `UAMetaTransfer` in a token domain hashes per chain to the row's digest,
/// 7622 and 22776 apart.
#[test]
fn chain_separation_typed_digests() {
    let s = load("ua/sign.json");
    let rows = arr(&s["chainSeparation"], "typed");
    let ds: Vec<[u8; 32]> = rows.iter().map(|r| digest(&r["td"]).unwrap()).collect();
    for (r, d) in rows.iter().zip(&ds) {
        assert_eq!(*d, b32(&r["digest"]));
    }
    assert_eq!(ds.len(), 2);
    assert_ne!(ds[0], ds[1]);
}

/// A payment on its request lane, nonce 0, with a near deadline (`now < validUntil ≤ now + maxWindow`, CLI-SGN-05); another lane,
/// another nonce, a past or a far deadline is refused (the row as generated passes: positive control).
#[test]
fn payment_lane_nonce_and_deadline() {
    let s = load("ua/sign.json");
    let w = wallet();
    let key = w.native_key(Network::Evm, 0, None).unwrap();
    let r = policy_row(&s, "payment");
    let run = |edit: &dyn Fn(&mut Value), e: &dyn Fn(&mut Value)| {
        let (mut v, mut x) = (r["td"].clone(), r["expect"].clone());
        edit(&mut v["message"]);
        e(&mut x);
        key.sign_typed(&td(&v).unwrap(), expect(&x).unwrap()).map(|_| ())
    };
    assert!(run(&|_| {}, &|_| {}).is_ok(), "positive control");
    let now = r["expect"]["now"].as_u64().unwrap();
    for (what, m) in [
        ("another lane", json!({"batch": "1"})),
        ("nonce 1", json!({"nonce": "1"})),
        ("deadline now", json!({"validUntil": now.to_string()})),
        ("deadline past the day", json!({"validUntil": (now + 86_401).to_string()})),
    ] {
        let set = |msg: &mut Value| {
            for (k, v) in m.as_object().unwrap() {
                msg[k] = v.clone();
            }
        };
        assert_eq!(run(&set, &|_| {}).err(), Some(Error::PolicyRefused), "{what}");
    }
    assert!(run(&|m| m["validUntil"] = json!((now + 86_400).to_string()), &|_| {}).is_ok(), "the window's end");
    assert_eq!(run(&|_| {}, &|x| x["maxWindow"] = json!(100)).err(), Some(Error::PolicyRefused), "a shorter window");
}

/// clientkeys `requireWhole`: the client's message names every field of the op (an omitted field is not "expect zero"), and a
/// relayer or fee recipient it names needs its mode bit, else canonical zeroing would drop it and leave the call open to any relayer.
#[test]
fn op_requires_the_whole_message() {
    let s = load("ua/sign.json");
    let w = wallet();
    let key = w.native_key(Network::Evm, 0, None).unwrap();
    let r = policy_row(&s, "op UABurn");
    let run = |e: &dyn Fn(&mut Value)| {
        let mut x = r["expect"].clone();
        e(&mut x);
        key.sign_typed(&td(&r["td"]).unwrap(), expect(&x).unwrap()).map(|_| ())
    };
    assert!(run(&|_| {}).is_ok(), "positive control");
    assert!(run(&|x| x["message"]["relayer"] = json!(ZERO)).is_ok(), "a zero relayer named needs no bit");
    assert_eq!(run(&|x| x["message"]["relayer"] = json!("0x000000000000000000000000000000000000beef")).err(), Some(Error::PolicyRefused));
    assert_eq!(run(&|x| x["message"]["feeRecipient"] = json!("0x0000000000000000000000000000000000000fee")).err(), Some(Error::PolicyRefused));
    assert_eq!(run(&|x| {
        x["message"].as_object_mut().unwrap().remove("amount");
    })
    .err(), Some(Error::PolicyRefused), "the amount omitted");
}
const ZERO: &str = "0x0000000000000000000000000000000000000000";

/// A 256-bit big-endian word in decimal (a uint field as the checks read it).
fn dec(w: &[u8; 32]) -> String {
    let (mut x, mut out) = (w.to_vec(), vec![]);
    while x.iter().any(|b| *b != 0) {
        let mut r = 0u32;
        for b in x.iter_mut() {
            let v = (r << 8) | u32::from(*b);
            (*b, r) = ((v / 10) as u8, v % 10);
        }
        out.push(b'0' + r as u8);
    }
    out.reverse();
    if out.is_empty() { "0".into() } else { String::from_utf8(out).unwrap() }
}

/// Group 3g (KV-10, ua-mtx-merge): the PQZ `UARollOver` (row `UAPqzRollOver`, with `keyVersion`) and Zether's are two structs of
/// one primary type: the builder takes the domain's and needs a domain to choose, and `checkOp` approves only the op it was asked
/// for (the Zether op never the PQZ struct, nor the reverse).
#[test]
fn pqz_rollover_is_its_own_op() {
    let t = load("typed/typed_ops.json");
    let w = wallet(); // a key handle lives as long as its wallet
    let key = w.native_key(Network::Evm, 0, None).unwrap();
    let hx = |b: &[u8]| format!("0x{}", hex::encode(b));
    for (row, other, dom, name) in [("UAPqzRollOver", "UARollOver", "pqz", "SCaaS PqzToken"), ("UARollOver", "UAPqzRollOver", "zether", "SCaaS ZetherToken")] {
        let r = &t["ops"][row];
        let d = &r["domains"][dom]["domain"];
        let (contract, uid, chain) = (b20(&d["verifyingContract"]), b32(&d["salt"]), chain_id(&d["chainId"]));
        let built = scaas_typed_data("UARollOver", Some(name), &contract, chain, &uid, &r["message"]).unwrap();
        assert_eq!(built.encode_type(), r["typeString"].as_str().unwrap(), "{row}: the domain's struct");
        assert_eq!(scaas_typed_data("UARollOver", None, &contract, chain, &uid, &r["message"]).err(), Some(Error::Argument), "{row}: no domain");
        let x = td(&json!({"types": r["types"], "primaryType": "UARollOver", "domain": d, "message": r["message"]})).unwrap();
        let m = &r["message"];
        let own: serde_json::Map<String, Value> =
            m.as_object().unwrap().iter().filter(|(k, _)| ["from", "ua", "keyVersion", "n"].contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
        let now = m["validUntil"].as_str().unwrap().parse::<u64>().unwrap() - 60;
        let op = |name: &str| {
            expect(&json!({"check": "Op", "op": name, "contract": hx(&contract), "chainId": chain, "chainUid": hx(&uid), "message": own,
                "maxFee": m["fee"], "feeRecipient": m["feeRecipient"], "relayer": m["relayer"], "now": now}))
            .unwrap()
        };
        assert!(key.sign_typed(&x, op(row)).is_ok(), "{row}: positive control");
        assert_eq!(key.sign_typed(&x, op(other)).err(), Some(Error::PolicyRefused), "{other} does not approve {row}");
    }
}

/// A SCaaS sell token's order is a `UATradeOrder` (ua-mtx-merge R12): `ua` is the default without `outside`; `ua: false` without
/// `outside` (the token's address `TradeOrder`, which left) is refused, as is `ua` with `outside`.
#[test]
fn trade_order_takes_the_ua_struct() {
    let s = load("ua/sign.json");
    let w = wallet(); // a key handle lives as long as its wallet
    let key = w.native_key(Network::Evm, 0, None).unwrap();
    let r = policy_row(&s, "trade order");
    let run = |extra: Value| {
        let mut e = r["expect"].clone();
        e.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        key.sign_typed(&td(&r["td"]).unwrap(), expect(&e).unwrap()).map(|_| ())
    };
    assert!(run(json!({})).is_ok(), "positive control: ua by default");
    assert!(run(json!({"ua": true})).is_ok(), "ua named");
    assert_eq!(run(json!({"ua": false})).err(), Some(Error::PolicyRefused), "the address TradeOrder");
    assert_eq!(run(json!({"ua": true, "outside": true})).err(), Some(Error::PolicyRefused), "ua outside");
}

/// `PayMeta` v2 (CTR-MTX-26 Change; clientkeys `payMeta`, `decodeMetaBody`): the server's payment carries `metaPayId(meta)` on its
/// lane, and each schema's body is read strictly before anything is signed: 1 a UTF-8 note, 2 `abi.encode(string, uint64)` in
/// canonical form, 3 exactly 96 bytes, an unknown schema opaque; the salt, `schema == 0` iff no body and the `payNo` rules are
/// `metaPayId`'s. Each case changes one thing of the row's metadata and re-points the payment at its id.
#[test]
fn pay_meta_v2_body_rules() {
    let s = load("ua/sign.json");
    let w = wallet(); // a key handle lives as long as its wallet
    let key = w.native_key(Network::Evm, 0, None).unwrap();
    let r = policy_row(&s, "pay-meta");
    let base = r["expect"]["meta"].clone();
    let run = |meta: &Value| {
        let mut e = r["expect"].clone();
        e["meta"] = meta.clone();
        let m = PayMeta { salt: b32(&meta["salt"]), pay_no: meta["payNo"].as_str().unwrap().into(),
            schema: meta["schema"].as_u64().unwrap() as u16, body: bytes(&meta["body"]) };
        let id = meta_pay_id_v2(&m).unwrap_or([0x11; 32]); // a meta metaPayId refuses: any id
        let mut t = r["td"].clone();
        t["message"]["entryRef"] = json!(format!("0x{}", hex::encode(id)));
        t["message"]["batch"] = json!(dec(&pay_lane(&id)));
        key.sign_typed(&td(&t).unwrap(), expect(&e).unwrap()).map(|_| ())
    };
    let with = |k: &str, v: Value| {
        let mut m = base.clone();
        m[k] = v;
        m
    };
    let body = |schema: u64, b: String| {
        let mut m = with("schema", json!(schema));
        m["body"] = json!(b);
        m
    };
    let w = |n: usize| format!("{n:064x}");
    // schema 2's body: `abi.encode(string creditorRef, uint64 dueDate)` with the head word `off`, then `tail`
    let s2 = |off: usize, text: &[u8], tail: &str| {
        format!("0x{}{}{}{:0<p$}{tail}", w(off), w(7), w(text.len()), hex::encode(text), p = text.len().div_ceil(32) * 64)
    };
    let refused = Some(Error::PolicyRefused);
    assert!(run(&base).is_ok(), "positive control: the row's note");
    // the request's `entryRef`, when given, must be the metadata's id
    let entry = |id: &str| {
        let mut e = r["expect"].clone();
        e["entryRef"] = json!(id);
        key.sign_typed(&td(&r["td"]).unwrap(), expect(&e).unwrap()).map(|_| ())
    };
    assert!(entry(r["td"]["message"]["entryRef"].as_str().unwrap()).is_ok(), "the request's id");
    assert_eq!(entry(&format!("0x{}", "22".repeat(32))).err(), Some(Error::PolicyRefused), "another request's id");
    assert!(run(&body(2, s2(64, b"INV-1", ""))).is_ok(), "a canonical structured reference");
    assert_eq!(run(&body(2, s2(96, b"INV-1", ""))).err(), refused, "another offset");
    assert_eq!(run(&body(2, s2(64, b"INV-1", &"00".repeat(32)))).err(), refused, "trailing bytes");
    assert_eq!(run(&body(2, s2(64, &[0xff], ""))).err(), refused, "a reference not UTF-8");
    assert_eq!(run(&body(1, "0xff".into())).err(), refused, "a note not UTF-8");
    assert!(run(&body(3, format!("0x{}", "00".repeat(96)))).is_ok(), "a bound call, 96 bytes");
    assert_eq!(run(&body(3, format!("0x{}", "00".repeat(64)))).err(), refused, "a bound call of 64 bytes");
    assert!(run(&body(9, "0x01".into())).is_ok(), "an unknown schema: opaque data");
    assert_eq!(run(&body(0, "0x01".into())).err(), refused, "schema 0 with a body");
    assert_eq!(run(&with("payNo", json!("INV\u{202e}1"))).err(), refused, "a bidi override in payNo");
    assert_eq!(run(&with("salt", json!(format!("0x{}", "00".repeat(32))))).err(), refused, "salt 0");
}

/// Group 3f (PQZ verifier mode spec §5.1, §11.3): `pqz/verdict.json` (forge-written, `PqzVerdictVectors.t.sol`). Every row's
/// `PqzVerdict` from `pqz_verdict_typed_data` in the token's domain: type string and typehash, domain separator, struct hash and
/// digest; `proofHash` the keccak256 of the set's `proof_pqzl.json` proof bytes; the registry's `uaAuthDigest` under `pqz-verdict`;
/// the EOA verifier's 65-byte signature recovers to its id and is what ua-rs signs with that key (`ua_sig`, RFC 6979), byte for byte.
#[test]
fn verdict_json_rows() {
    let f = load("pqz/verdict.json");
    let (d, g) = (&f["domain"], &f["registryDomain"]);
    let (contract, chain, uid) = (b20(&d["verifyingContract"]), chain_id(&d["chainId"]), b32(&d["salt"]));
    let purpose = purpose_tag("pqz-verdict").unwrap();
    assert_eq!((f["purpose"].as_str(), purpose), (Some("scaas.ua.purpose.pqz-verdict.v1"), b32(&f["purposeTag"])));
    assert!(!is_portable_purpose(&purpose), "a native verifier signs UAAuth, never the typed digest itself");
    let reg = Domain { generation: g["version"].as_str().unwrap().parse().unwrap(), chain_id: chain_id(&g["chainId"]),
        registry: b20(&g["verifyingContract"]), chain_uid: b32(&g["salt"]) };
    assert_eq!((d["name"].as_str(), g["name"].as_str()), (Some("SCaaS PqzToken"), Some("SCaaS UARegistry")));
    assert_eq!(ua_auth_domain_separator(&reg), b32(&g["separator"]));
    let id = b32(&f["verifierUA"]);
    let mut secret = [0u8; 32];
    secret[24..].copy_from_slice(&f["verifierKey"].as_u64().unwrap().to_be_bytes());
    let w = wallet();
    let key = w.import_native_key(Network::Evm, &secret).unwrap();
    assert_eq!(evm_address_of(&key.address().unwrap()), id[12..], "the verifier's id is its key's address");
    let set = f["set"].as_str().unwrap();
    let proofs = load(&format!("pqz/{}proof_pqzl.json", if set == "n2048-kmax1024" { String::new() } else { format!("{set}/") }));
    let want: Vec<&Value> = arr(&proofs, "rows").iter().filter(|r| r["form"] != "REGISTER").collect();
    assert_eq!(f["proofSystemId"].as_str().unwrap().trim_start_matches("0x"), proofs["proof_system_id"].as_str().unwrap());
    assert_eq!(arr(&f, "rows").len(), want.len());
    for (i, (r, p)) in arr(&f, "rows").iter().zip(&want).enumerate() {
        assert_eq!(r["form"], p["form"], "row {i}");
        assert_eq!(keccak256(&bytes(&p["proof"])), b32(&r["proofHash"]), "row {i}: proofHash of the proof's bytes");
        assert_eq!(hex::encode(b32(&r["statementHash"])), p["stmt_keccak"].as_str().unwrap(), "row {i}");
        let m = json!({"token": d["verifyingContract"], "chainId": d["chainId"], "proofSystemId": f["proofSystemId"],
            "statementHash": r["statementHash"], "proofHash": r["proofHash"], "pqzVerifierEpoch": r["pqzVerifierEpoch"],
            "validUntil": r["validUntil"]});
        let td = pqz_verdict_typed_data(&contract, chain, &uid, &m).unwrap();
        assert_eq!(td.encode_type(), f["typeString"].as_str().unwrap());
        assert_eq!(keccak256(td.encode_type().as_bytes()), b32(&f["typehash"]));
        assert_eq!(td.domain_separator().unwrap(), b32(&d["separator"]), "row {i}");
        assert_eq!(td.struct_hash().unwrap(), b32(&r["structHash"]), "row {i}");
        let dg = td.digest().unwrap();
        assert_eq!(dg, b32(&r["digest"]), "row {i}");
        let auth = ua_auth_digest(&reg, &id, &purpose, &dg);
        assert_eq!(auth, b32(&r["uaAuthDigest"]), "row {i}");
        assert!(native_ecdsa(&id[12..].try_into().unwrap(), &auth, &bytes(&r["signature"])), "row {i}");
        let sig = ua_sig(&key, Some(&reg), &purpose, &dg).unwrap();
        assert!(sig.key_data.is_empty() && sig.members.is_empty(), "row {i}");
        assert_eq!(hex::encode(&sig.signature), hex::encode(bytes(&r["signature"])), "row {i}: ua-rs signs the row's signature");
    }
}
fn evm_address_of(a: &str) -> Vec<u8> {
    hex::decode(a.trim_start_matches("0x")).unwrap()
}

/// `pqz_verdict_typed_data` (clientkeys `pqzVerdictTypedData`): every field signed, `token` and `chainId` must repeat the domain,
/// the ranges and the fields of the struct; the verdict is in no other SCaaS builder (`scaas_typed_data`).
#[test]
fn pqz_verdict_builder_rules() {
    let (contract, chain, uid) = ([0x7a; 20], 7622, [0xc1; 32]);
    let m = json!({"token": format!("0x{}", "7a".repeat(20)), "chainId": 7622, "proofSystemId": format!("0x{}", "5e".repeat(32)),
        "statementHash": format!("0x{}", "51".repeat(32)), "proofHash": format!("0x{}", "9f".repeat(32)), "pqzVerifierEpoch": 3,
        "validUntil": 1800000900u64});
    let digest = |m: &Value| pqz_verdict_typed_data(&contract, chain, &uid, m).and_then(|t| t.digest());
    let base = digest(&m).unwrap();
    let td = pqz_verdict_typed_data(&contract, chain, &uid, &m).unwrap();
    assert_eq!(td.primary_type(), "PqzVerdict");
    assert_eq!(td.to_value()["domain"], json!({"name": "SCaaS PqzToken", "version": "1", "chainId": "7622",
        "verifyingContract": format!("0x{}", "7a".repeat(20)), "salt": format!("0x{}", "c1".repeat(32))}));
    let with = |k: &str, v: Value| {
        let mut x = m.clone();
        x[k] = v;
        x
    };
    for (k, v) in [("proofSystemId", json!(format!("0x{}", "00".repeat(32)))), ("statementHash", json!(format!("0x{}", "00".repeat(32)))),
        ("proofHash", json!(format!("0x{}", "00".repeat(32)))), ("pqzVerifierEpoch", json!(4)), ("validUntil", json!(1800000901u64))]
    {
        assert_ne!(digest(&with(k, v)).unwrap(), base, "{k} is signed");
    }
    // the token and the chain repeat the domain; the same verdict on another token is another digest
    assert_eq!(digest(&with("token", json!(format!("0x{}", "7b".repeat(20))))).err(), Some(Error::Argument));
    assert_eq!(digest(&with("chainId", json!(1))).err(), Some(Error::Argument));
    assert_eq!(digest(&with("token", json!(format!("0x{}", "7A".repeat(20))))).unwrap(), base, "the address in any case");
    assert_eq!(digest(&with("chainId", json!("7622"))).unwrap(), base, "a decimal string");
    let other = pqz_verdict_typed_data(&[0x7b; 20], chain, &uid, &with("token", json!(format!("0x{}", "7b".repeat(20))))).unwrap();
    assert_ne!(other.digest().unwrap(), base);
    // the ranges and the fields
    assert_eq!(digest(&with("pqzVerifierEpoch", json!(1u64 << 32))).err(), Some(Error::Argument));
    assert_eq!(digest(&with("validUntil", json!("18446744073709551616"))).err(), Some(Error::Argument));
    assert_eq!(digest(&with("ua", json!(format!("0x{}", "00".repeat(32))))).err(), Some(Error::Argument));
    assert_eq!(scaas_typed_data("PqzVerdict", Some("SCaaS PqzToken"), &contract, chain, &uid, &m).err(), Some(Error::Argument));
}

/// The router's three PQZ verifier ops (group 3f, spec §4.2, §4.3; the `gov_router` rows of typed_ops.json): a non-zero unbound
/// `relayer` / `feeRecipient` is hashed as 0 by the builder (the row: mode 1, the relayer bound); the mode, `target` and `next` are
/// signed.
#[test]
fn pqz_verifier_router_ops_canon() {
    let t = load("typed/typed_ops.json");
    let junk = json!(format!("0x{}", "ba".repeat(20)));
    let zero = json!(format!("0x{}", "00".repeat(20)));
    for name in ["UAPqzSetVerifier", "UAPqzCancelVerifier", "UAPqzRevokeVerifier"] {
        let r = &t["ops"][name];
        let d = &r["domains"]["gov_router"];
        assert_eq!(r["domains"].as_object().unwrap().len(), 1, "{name}: the router's domain only");
        let dom = &d["domain"];
        let build = |m: &Value| {
            scaas_typed_data(name, Some("SCaaS GovernanceRouter"), &b20(&dom["verifyingContract"]), chain_id(&dom["chainId"]), &b32(&dom["salt"]), m)
                .unwrap()
                .digest()
                .unwrap()
        };
        let with = |pairs: &[(&str, &Value)]| {
            let mut x = r["message"].clone();
            for (k, v) in pairs {
                x[*k] = (*v).clone();
            }
            x
        };
        assert_eq!(r["message"]["mode"], 1, "{name}: fee mode NONE, the relayer bound");
        assert_eq!(build(&with(&[("feeRecipient", &junk)])), b32(&d["digest"]), "{name}: an unbound feeRecipient signs as 0");
        let open = build(&with(&[("mode", &json!(0)), ("relayer", &junk), ("feeRecipient", &junk)]));
        assert_eq!(open, build(&with(&[("mode", &json!(0)), ("relayer", &zero), ("feeRecipient", &zero)])), "{name}: mode 0");
        assert_ne!(open, b32(&d["digest"]), "{name}: the mode is signed");
        assert_ne!(build(&with(&[("relayer", &junk)])), b32(&d["digest"]), "{name}: a bound relayer is signed");
        assert_ne!(build(&with(&[("target", &junk)])), b32(&d["digest"]), "{name}: target is signed");
    }
    let r = &t["ops"]["UAPqzSetVerifier"];
    let dom = &r["domains"]["gov_router"]["domain"];
    let mut m = r["message"].clone();
    m["next"] = json!(format!("0x{}", "00".repeat(32)));
    let x = scaas_typed_data("UAPqzSetVerifier", None, &b20(&dom["verifyingContract"]), chain_id(&dom["chainId"]), &b32(&dom["salt"]), &m).unwrap();
    assert_ne!(x.digest().unwrap(), b32(&r["domains"]["gov_router"]["digest"]), "next is signed");
}
