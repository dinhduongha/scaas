// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Round 3r (spec 2026-11-10-admin-not-owner.md §5.4, §5.6, §8): `scaas_ua::admin` against the router's 18 admin rows of
//! `typed/typed_ops.json` (clientkeys; forge runs them on a real router): type string, struct hash, digest, a non-zero unbound
//! `relayer` / `feeRecipient` hashed as 0; the three approval rows' `approvalKey` (checked on the factory by forge).
use scaas_ua::admin::{
    class_release_key, dex_release_key, digest, struct_hash, token_release_key, type_string, Env, Param, ADMIN_OPS,
};
use scaas_ua::regulated::{router_domain_separator, Envelope, RouterOpError};
use serde_json::Value;

fn load(path: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
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
fn num(v: &Value) -> u128 {
    v.as_u64().map(u128::from).unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}
fn uint_word(v: &Value) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&num(v).to_be_bytes());
    w
}
/// A static field's ABI word by its type (`bytes4` left-aligned).
fn static_word(ty: &str, v: &Value) -> [u8; 32] {
    let mut w = [0u8; 32];
    match ty {
        "bytes32" => b32(v),
        "address" => {
            w[12..].copy_from_slice(&b20(v));
            w
        }
        "bool" => {
            w[31] = v.as_bool().unwrap() as u8;
            w
        }
        "bytes4" => {
            w[..4].copy_from_slice(&bytes(v));
            w
        }
        _ => uint_word(v),
    }
}
fn envelope(m: &Value) -> Envelope {
    Envelope {
        from: b32(&m["from"]),
        batch: uint_word(&m["batch"]),
        nonce: uint_word(&m["nonce"]),
        valid_until: uint_word(&m["validUntil"]),
        mode: num(&m["mode"]) as u32,
        relayer: b20(&m["relayer"]),
        fee: uint_word(&m["fee"]),
        fee_recipient: b20(&m["feeRecipient"]),
    }
}
fn addrs(v: &Value) -> Vec<[u8; 20]> {
    v.as_array().unwrap().iter().map(b20).collect()
}
fn words(v: &Value) -> Vec<[u8; 32]> {
    v.as_array().unwrap().iter().map(b32).collect()
}
fn env(v: &Value) -> Env {
    Env {
        registry: b20(&v["registry"]),
        smart_key_account_impl: b20(&v["smartKeyAccountImpl"]),
        hedera: v["hedera"].as_bool().unwrap(),
        deps: addrs(&v["deps"]),
        params: words(&v["params"]),
        libs: addrs(&v["libs"]),
        lib_code_hashes: words(&v["libCodeHashes"]),
    }
}

/// The op's params by the field names of its type string, in their owned shapes (`Param` borrows them).
enum Own {
    W([u8; 32]),
    T(String),
    A(Vec<[u8; 32]>),
    E(Env),
}
fn own(op: &str, m: &Value) -> Vec<Own> {
    let (_, list) = ADMIN_OPS.iter().find(|(n, _)| *n == op).unwrap();
    list.split(',').filter(|f| !f.is_empty()).map(|f| {
        let (ty, name) = f.split_once(' ').unwrap();
        let v = &m[name];
        match ty.strip_suffix("[]") {
            Some(el) => Own::A(v.as_array().unwrap().iter().map(|x| static_word(el, x)).collect()),
            None if ty == "string" => Own::T(v.as_str().unwrap().to_string()),
            None if ty == "Env" => Own::E(env(v)),
            None => Own::W(static_word(ty, v)),
        }
    }).collect()
}
fn params(o: &[Own]) -> Vec<Param<'_>> {
    o.iter().map(|p| match p {
        Own::W(w) => Param::Word(*w),
        Own::T(s) => Param::Text(s),
        Own::A(a) => Param::Words(a),
        Own::E(e) => Param::Env(e),
    }).collect()
}

/// Every one of the 18 rows: type string, struct hash and digest; a non-zero relayer and fee recipient left unbound give the
/// canonical digest (`UAApproveTokenRelease` is mode 0: both unbound; every other row mode 1: the fee recipient).
#[test]
fn typed_ops_admin_rows() {
    let v = load("typed/typed_ops.json");
    for (op, _) in ADMIN_OPS {
        let r = &v["ops"][op];
        assert_eq!(type_string(op).unwrap(), r["typeString"].as_str().unwrap(), "{op}");
        let m = &r["message"];
        let d = &r["domains"]["gov_router"];
        let dom = &d["domain"];
        let ds = router_domain_separator(num(&dom["chainId"]) as u64, &b20(&dom["verifyingContract"]), &b32(&dom["salt"]));
        let (e, target) = (envelope(m), b20(&m["target"]));
        let o = own(op, m);
        let p = params(&o);
        assert_eq!(struct_hash(op, &e, &target, &p).unwrap(), b32(&r["structHash"]), "{op}");
        assert_eq!(digest(op, &ds, &e, &target, &p).unwrap(), b32(&d["digest"]), "{op}");
        let unbound = Envelope {
            relayer: if e.mode & 1 == 0 { [0xab; 20] } else { e.relayer },
            fee_recipient: if e.mode & 2 == 0 { [0xba; 20] } else { e.fee_recipient },
            ..e
        };
        assert_eq!(digest(op, &ds, &unbound, &target, &p).unwrap(), b32(&d["digest"]), "{op}: unbound hashes as 0");
    }
    assert_eq!(v["ops"]["UAApproveTokenRelease"]["message"]["mode"], 0, "the row with both unbound");
}

/// A changed word, a wrong count, a word over its type and a shape for another field are refused or change the hash.
#[test]
fn admin_struct_hash_refusals() {
    let v = load("typed/typed_ops.json");
    let m = &v["ops"]["UADeprecateToken"]["message"];
    let (e, t) = (envelope(m), b20(&m["target"]));
    let o = own("UADeprecateToken", m);
    let p = params(&o);
    let h = struct_hash("UADeprecateToken", &e, &t, &p).unwrap();
    let mut q = p.clone();
    q[2] = Param::Text("another reason");
    assert_ne!(struct_hash("UADeprecateToken", &e, &t, &q).unwrap(), h);
    assert_eq!(struct_hash("UADeprecateToken", &e, &t, &p[..2]), Err(RouterOpError::Params));
    let mut big = [0u8; 32];
    big[30] = 1; // 256 in a uint8
    let mut q = p.clone();
    q[0] = Param::Word(big);
    assert_eq!(struct_hash("UADeprecateToken", &e, &t, &q), Err(RouterOpError::Range));
    let mut q = p.clone();
    q[2] = Param::Word([0; 32]);
    assert_eq!(struct_hash("UADeprecateToken", &e, &t, &q), Err(RouterOpError::Params));
    assert_eq!(struct_hash("UAOwnerOp", &e, &t, &[]), Err(RouterOpError::UnknownOp));
    let m = &v["ops"]["UASetCompliance"]["message"];
    let o = own("UASetCompliance", m);
    let mut p = params(&o);
    let wide = [[0xff; 32]];
    p[1] = Param::Words(&wide); // a flag over uint64
    assert_eq!(struct_hash("UASetCompliance", &envelope(m), &b20(&m["target"]), &p), Err(RouterOpError::Range));
}

/// The approval rows' `approvalKey`, from the row's own fields.
#[test]
fn typed_ops_approval_keys() {
    let v = load("typed/typed_ops.json");
    let f = |op: &str, name: &str| v["ops"][op]["message"][name].clone();
    let w4 = |x: Value| -> [u8; 4] { bytes(&x).try_into().unwrap() };
    let op = "UAApproveTokenRelease";
    let k = token_release_key(&b32(&f(op, "chainUid")), &b20(&f(op, "factory")), num(&f(op, "kind")) as u8,
        num(&f(op, "version")) as u64, num(&f(op, "envVersion")) as u16, &b32(&f(op, "initcodeHash")),
        &b32(&f(op, "implArgsHash")));
    assert_eq!(k, b32(&v["ops"][op]["approvalKey"]), "{op}");
    let op = "UAApproveDexRelease";
    let k = dex_release_key(&b32(&f(op, "chainUid")), &b20(&f(op, "factory")), num(&f(op, "version")) as u64,
        num(&f(op, "envVersion")) as u16, &b32(&f(op, "initcodeHash")), &b32(&f(op, "implArgsHash")));
    assert_eq!(k, b32(&v["ops"][op]["approvalKey"]), "{op}");
    let op = "UAApproveRelease";
    let k = class_release_key(&b32(&f(op, "chainUid")), &b20(&f(op, "factory")), num(&f(op, "contractClass")) as u16,
        num(&f(op, "kind")) as u16, num(&f(op, "version")) as u64, num(&f(op, "envVersion")) as u16,
        w4(f(op, "initSelector")), w4(f(op, "interfaceId")), &b32(&f(op, "initcodeHash")), &b32(&f(op, "implArgsHash")));
    assert_eq!(k, b32(&v["ops"][op]["approvalKey"]), "{op}");
}
