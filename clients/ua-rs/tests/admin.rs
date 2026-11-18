// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Round 3r (spec 2026-11-10-admin-not-owner.md §5.4, §5.6, §8): `scaas_ua::admin` against the router's 18 admin rows of
//! `typed/typed_ops.json` (clientkeys; forge runs them on a real router): type string, struct hash, digest, a non-zero unbound
//! `relayer` / `feeRecipient` hashed as 0, each op built as its typed struct from the row's named fields (T21 L45; under
//! feature `vectors` also against the named op table, `scaas_typed_data`); the three approval rows' `approvalKey` (checked on
//! the factory by forge).
use scaas_ua::admin::*;
use scaas_ua::regulated::{router_domain_separator, Envelope, RouterOp};
use serde_json::Value;

fn load(path: &str) -> Value {
    let path = format!(
        "{}/../../smartcontracts/vectors/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
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
    v.as_u64()
        .map(u128::from)
        .unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}
fn uint_word(v: &Value) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&num(v).to_be_bytes());
    w
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
fn nums(v: &Value) -> Vec<u64> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| num(x) as u64)
        .collect()
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
fn chain_entries(v: &Value) -> ChainEntries {
    ChainEntries {
        relay_fee_router: b20(&v["relayFeeRouter"]),
        relay_fee_router_code_hash: b32(&v["relayFeeRouterCodeHash"]),
        relay_fee_executor_code_hash: b32(&v["relayFeeExecutorCodeHash"]),
        compliance_registry: b20(&v["complianceRegistry"]),
        compliance_registry_code_hash: b32(&v["complianceRegistryCodeHash"]),
        smart_key_account_factory: b20(&v["smartKeyAccountFactory"]),
        smart_key_account_factory_code_hash: b32(&v["smartKeyAccountFactoryCodeHash"]),
        zether_statements: b20(&v["zetherStatements"]),
        zether_statements_code_hash: b32(&v["zetherStatementsCodeHash"]),
    }
}

/// A Rust field name in the type string's form (`chain_uid` -> `chainUid`).
fn camel(f: &str) -> String {
    let mut out = String::new();
    let mut up = false;
    for c in f.chars() {
        if c == '_' {
            up = true;
        } else {
            out.push(if up { c.to_ascii_uppercase() } else { c });
            up = false;
        }
    }
    out
}

/// One row: the struct's fields are the type string's, by name and order; type string, struct hash and digest; a non-zero
/// relayer and fee recipient left unbound give the canonical digest. Under `vectors`: the named op table agrees.
fn check<O: AdminOp>(op: &O, r: &Value) {
    let name = O::NAME;
    let (_, list) = ADMIN_OPS.iter().find(|(n, _)| *n == name).unwrap();
    let names: Vec<&str> = list
        .split(',')
        .filter(|f| !f.is_empty())
        .map(|f| f.split_once(' ').unwrap().1)
        .collect();
    assert_eq!(
        O::FIELDS.iter().map(|f| camel(f)).collect::<Vec<_>>(),
        names,
        "{name}: the struct's fields"
    );
    assert_eq!(
        type_string(name).unwrap(),
        r["typeString"].as_str().unwrap(),
        "{name}"
    );
    let m = &r["message"];
    let d = &r["domains"]["gov_router"];
    let dom = &d["domain"];
    let ds = router_domain_separator(
        num(&dom["chainId"]) as u64,
        &b20(&dom["verifyingContract"]),
        &b32(&dom["salt"]),
    );
    let (e, target) = (envelope(m), b20(&m["target"]));
    assert_eq!(
        struct_hash(op, &e, &target),
        b32(&r["structHash"]),
        "{name}"
    );
    assert_eq!(digest(op, &ds, &e, &target), b32(&d["digest"]), "{name}");
    let unbound = Envelope {
        relayer: if e.mode & 1 == 0 {
            [0xab; 20]
        } else {
            e.relayer
        },
        fee_recipient: if e.mode & 2 == 0 {
            [0xba; 20]
        } else {
            e.fee_recipient
        },
        ..e
    };
    assert_eq!(
        digest(op, &ds, &unbound, &target),
        b32(&d["digest"]),
        "{name}: unbound hashes as 0"
    );
    #[cfg(feature = "vectors")]
    {
        let td = scaas_ua::wallet::scaas_typed_data(
            name,
            Some("SCaaS GovernanceRouter"),
            &b20(&dom["verifyingContract"]),
            num(&dom["chainId"]) as u64,
            &b32(&dom["salt"]),
            m,
        )
        .unwrap();
        assert_eq!(
            td.digest().unwrap(),
            digest(op, &ds, &e, &target),
            "{name}: the named op table"
        );
    }
}

/// Every one of the 18 rows, each op built by name from the row's message (`UAApproveTokenRelease` is mode 0: both unbound;
/// every other row mode 1: the fee recipient).
#[test]
fn typed_ops_admin_rows() {
    let v = load("typed/typed_ops.json");
    let mut done = 0;
    for (op, _) in ADMIN_OPS {
        let r = &v["ops"][op];
        let m = &r["message"];
        let b = |f: &str| b32(&m[f]);
        let n = |f: &str| num(&m[f]) as u64;
        let a = |f: &str| b20(&m[f]);
        let t = |f: &str| m[f].as_str().unwrap().to_string();
        let flag = |f: &str| m[f].as_bool().unwrap();
        let w4 = |f: &str| -> [u8; 4] { bytes(&m[f]).try_into().unwrap() };
        match op {
            "UATransferAdmin" => check(
                &UATransferAdmin {
                    new_admin: b("newAdmin"),
                    chain_uid: b("chainUid"),
                },
                r,
            ),
            "UAAcceptAdmin" => check(&UAAcceptAdmin {}, r),
            "UARenounceAdmin" => check(
                &UARenounceAdmin {
                    chain_uid: b("chainUid"),
                },
                r,
            ),
            "UAPublishTokenEnv" => check(
                &UAPublishTokenEnv {
                    kind: n("kind") as u8,
                    env_version: n("envVersion") as u16,
                    chain_uid: b("chainUid"),
                    env: env(&m["env"]),
                },
                r,
            ),
            "UAPublishDexEnv" => check(
                &UAPublishDexEnv {
                    env_version: n("envVersion") as u16,
                    chain_uid: b("chainUid"),
                    env: env(&m["env"]),
                },
                r,
            ),
            "UAPublishClassEnv" => check(
                &UAPublishClassEnv {
                    contract_class: n("contractClass") as u16,
                    kind: n("kind") as u16,
                    env_version: n("envVersion") as u16,
                    chain_uid: b("chainUid"),
                    env: env(&m["env"]),
                },
                r,
            ),
            "UADeprecateToken" => check(
                &UADeprecateToken {
                    kind: n("kind") as u8,
                    version: n("version"),
                    chain_uid: b("chainUid"),
                    reason: t("reason"),
                },
                r,
            ),
            "UADeprecateDex" => check(
                &UADeprecateDex {
                    version: n("version"),
                    chain_uid: b("chainUid"),
                    reason: t("reason"),
                },
                r,
            ),
            "UADeprecateRelease" => check(
                &UADeprecateRelease {
                    contract_class: n("contractClass") as u16,
                    kind: n("kind") as u16,
                    version: n("version"),
                    chain_uid: b("chainUid"),
                    reason: t("reason"),
                },
                r,
            ),
            "UASetTokenKindEnabled" => check(
                &UASetTokenKindEnabled {
                    kind: n("kind") as u8,
                    on: flag("on"),
                    chain_uid: b("chainUid"),
                },
                r,
            ),
            "UASetClassKindEnabled" => check(
                &UASetClassKindEnabled {
                    contract_class: n("contractClass") as u16,
                    kind: n("kind") as u16,
                    on: flag("on"),
                    chain_uid: b("chainUid"),
                },
                r,
            ),
            "UASetKycProvider" => check(
                &UASetKycProvider {
                    provider: b("provider"),
                    enabled: flag("enabled"),
                    chain_uid: b("chainUid"),
                },
                r,
            ),
            "UASetCompliance" => check(
                &UASetCompliance {
                    accounts: words(&m["accounts"]),
                    flags: nums(&m["flags"]),
                    until: nums(&m["until"]),
                    chain_uid: b("chainUid"),
                },
                r,
            ),
            "UASetChainEntries" => check(
                &UASetChainEntries {
                    entries: chain_entries(&m["entries"]),
                    chain_uid: b("chainUid"),
                },
                r,
            ),
            "UAApproveTokenRelease" => check(
                &UAApproveTokenRelease {
                    kind: n("kind") as u8,
                    version: n("version"),
                    env_version: n("envVersion") as u16,
                    initcode_hash: b("initcodeHash"),
                    impl_args_hash: b("implArgsHash"),
                    chain_uid: b("chainUid"),
                    factory: a("factory"),
                    admin_generation: n("adminGeneration") as u32,
                    until: n("until"),
                },
                r,
            ),
            "UAApproveDexRelease" => check(
                &UAApproveDexRelease {
                    version: n("version"),
                    env_version: n("envVersion") as u16,
                    initcode_hash: b("initcodeHash"),
                    impl_args_hash: b("implArgsHash"),
                    chain_uid: b("chainUid"),
                    factory: a("factory"),
                    admin_generation: n("adminGeneration") as u32,
                    until: n("until"),
                },
                r,
            ),
            "UAApproveRelease" => check(
                &UAApproveRelease {
                    contract_class: n("contractClass") as u16,
                    kind: n("kind") as u16,
                    version: n("version"),
                    env_version: n("envVersion") as u16,
                    init_selector: w4("initSelector"),
                    interface_id: w4("interfaceId"),
                    initcode_hash: b("initcodeHash"),
                    impl_args_hash: b("implArgsHash"),
                    chain_uid: b("chainUid"),
                    factory: a("factory"),
                    admin_generation: n("adminGeneration") as u32,
                    until: n("until"),
                },
                r,
            ),
            "UARevokeApproval" => check(
                &UARevokeApproval {
                    key: b("key"),
                    chain_uid: b("chainUid"),
                },
                r,
            ),
            _ => panic!("{op}: no typed op"),
        }
        done += 1;
    }
    assert_eq!(done, 18);
    assert_eq!(
        v["ops"]["UAApproveTokenRelease"]["message"]["mode"], 0,
        "the row with both unbound"
    );
}

/// A changed field changes the hash: the reason text, a compliance flag, one `ChainEntries` field.
#[test]
fn admin_struct_hash_fields_bind() {
    let v = load("typed/typed_ops.json");
    let m = &v["ops"]["UADeprecateToken"]["message"];
    let (e, t) = (envelope(m), b20(&m["target"]));
    let op = UADeprecateToken {
        kind: num(&m["kind"]) as u8,
        version: num(&m["version"]) as u64,
        chain_uid: b32(&m["chainUid"]),
        reason: m["reason"].as_str().unwrap().to_string(),
    };
    let h = struct_hash(&op, &e, &t);
    assert_eq!(h, b32(&v["ops"]["UADeprecateToken"]["structHash"]));
    assert_ne!(
        struct_hash(
            &UADeprecateToken {
                reason: "another reason".into(),
                ..op.clone()
            },
            &e,
            &t
        ),
        h
    );
    let m = &v["ops"]["UASetCompliance"]["message"];
    let (e, t) = (envelope(m), b20(&m["target"]));
    let op = UASetCompliance {
        accounts: words(&m["accounts"]),
        flags: nums(&m["flags"]),
        until: nums(&m["until"]),
        chain_uid: b32(&m["chainUid"]),
    };
    let h = struct_hash(&op, &e, &t);
    assert_eq!(h, b32(&v["ops"]["UASetCompliance"]["structHash"]));
    let mut flags = op.flags.clone();
    flags[0] ^= 1;
    assert_ne!(
        struct_hash(
            &UASetCompliance {
                flags,
                ..op.clone()
            },
            &e,
            &t
        ),
        h
    );
    // the flags and the until lists are distinct in the row, so a swap is a different digest
    assert_ne!(
        struct_hash(
            &UASetCompliance {
                flags: op.until.clone(),
                until: op.flags.clone(),
                ..op
            },
            &e,
            &t
        ),
        h
    );
    let c = chain_entries(&v["ops"]["UASetChainEntries"]["message"]["entries"]);
    assert_ne!(
        chain_entries_hash(&ChainEntries {
            compliance_registry: [1; 20],
            ..c.clone()
        }),
        chain_entries_hash(&c)
    );
}

/// The approval rows' `approvalKey`, from the row's own fields.
#[test]
fn typed_ops_approval_keys() {
    let v = load("typed/typed_ops.json");
    let f = |op: &str, name: &str| v["ops"][op]["message"][name].clone();
    let w4 = |x: Value| -> [u8; 4] { bytes(&x).try_into().unwrap() };
    let op = "UAApproveTokenRelease";
    let k = token_release_key(
        &b32(&f(op, "chainUid")),
        &b20(&f(op, "factory")),
        num(&f(op, "kind")) as u8,
        num(&f(op, "version")) as u64,
        num(&f(op, "envVersion")) as u16,
        &b32(&f(op, "initcodeHash")),
        &b32(&f(op, "implArgsHash")),
    );
    assert_eq!(k, b32(&v["ops"][op]["approvalKey"]), "{op}");
    let op = "UAApproveDexRelease";
    let k = dex_release_key(
        &b32(&f(op, "chainUid")),
        &b20(&f(op, "factory")),
        num(&f(op, "version")) as u64,
        num(&f(op, "envVersion")) as u16,
        &b32(&f(op, "initcodeHash")),
        &b32(&f(op, "implArgsHash")),
    );
    assert_eq!(k, b32(&v["ops"][op]["approvalKey"]), "{op}");
    let op = "UAApproveRelease";
    let k = class_release_key(
        &b32(&f(op, "chainUid")),
        &b20(&f(op, "factory")),
        num(&f(op, "contractClass")) as u16,
        num(&f(op, "kind")) as u16,
        num(&f(op, "version")) as u64,
        num(&f(op, "envVersion")) as u16,
        w4(f(op, "initSelector")),
        w4(f(op, "interfaceId")),
        &b32(&f(op, "initcodeHash")),
        &b32(&f(op, "implArgsHash")),
    );
    assert_eq!(k, b32(&v["ops"][op]["approvalKey"]), "{op}");
}

/// CTR-GOV-27: `UASetChainEntries` nests `ChainEntries` (its type string last; the field's word its `hashStruct`).
#[test]
fn chain_entries_nested() {
    let e = Envelope {
        from: [1; 32],
        batch: [0; 32],
        nonce: [0; 32],
        valid_until: [0; 32],
        mode: 0,
        relayer: [0; 20],
        fee: [0; 32],
        fee_recipient: [0; 20],
    };
    let c = ChainEntries {
        relay_fee_router: [1; 20],
        ..Default::default()
    };
    let op = UASetChainEntries {
        entries: c.clone(),
        chain_uid: [7; 32],
    };
    assert_eq!(op.field_words()[0], chain_entries_hash(&c));
    assert_ne!(
        struct_hash(&op, &e, &[2; 20]),
        struct_hash(
            &UASetChainEntries {
                entries: ChainEntries::default(),
                ..op.clone()
            },
            &e,
            &[2; 20]
        )
    );
    assert!(type_string("UASetChainEntries")
        .unwrap()
        .ends_with(CHAIN_ENTRIES_TYPE));
    assert_eq!(
        ChainEntries::default(),
        ChainEntries {
            relay_fee_router: [0; 20],
            ..c
        }
    );
}
