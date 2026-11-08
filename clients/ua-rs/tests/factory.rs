// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T20b second sync: the factory's chain-neutral creation address (chain-neutral releases spec §2.1, §4, §6.4; CTR-TOK-29), the
//! CREATE3 predictor a signer shows before a `UACreateToken` / `UACreateDex` / `UACreateInstance`, against
//! `smartcontracts/vectors/factory/create3_kat.json` (written by forge, `test/v2/Create3Kat.t.sol`; clientkeys `factory.js` reads
//! the same rows). UNAUDITED.
use scaas_ua::factory::{clone_env, clone_runtime, create3_address, create3_salt, env_bytes, Create3, PROXY_INITCODE, PROXY_INITCODE_HASH};
use scaas_ua::keccak256;
use serde_json::Value;

fn kat() -> Value {
    let p = format!("{}/../../smartcontracts/vectors/factory/create3_kat.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn fixed<const N: usize>(v: &Value) -> [u8; N] {
    bytes(v).try_into().unwrap()
}
fn small(v: &Value) -> u16 {
    v.as_u64().unwrap().try_into().unwrap()
}

/// The proxy's init code and its hash are the pinned ones; every row `(factory, creatorId, contractClass, kind, salt)` gives the
/// row's `s`, CREATE2 proxy and CREATE3 instance (a native and a derived creator, classes 1 to 3, a zero and a non-zero salt);
/// one changed input at a time gives another address.
#[test]
fn create3_kat_rows() {
    let k = kat();
    assert_eq!(PROXY_INITCODE.to_vec(), bytes(&k["proxyInitCode"]));
    assert_eq!(PROXY_INITCODE_HASH, fixed::<32>(&k["proxyInitCodeHash"]));
    assert_eq!(keccak256(&PROXY_INITCODE), PROXY_INITCODE_HASH);
    let factory: [u8; 20] = fixed(&k["factory"]);
    let rows = k["rows"].as_array().unwrap();
    for r in rows {
        let (id, class, kind, salt) = (fixed::<32>(&r["creatorId"]), small(&r["contractClass"]), small(&r["kind"]), fixed::<32>(&r["salt"]));
        let s = create3_salt(&id, class, kind, &salt);
        assert_eq!(s, fixed::<32>(&r["s"]), "s");
        let Create3 { s: s2, proxy, instance } = create3_address(&factory, &id, class, kind, &salt);
        assert_eq!((s2, proxy, instance), (s, fixed::<20>(&r["proxy"]), fixed::<20>(&r["instance"])), "{r}");
        let other = |f: &[u8; 20], i: &[u8; 32], c: u16, kd: u16, sl: &[u8; 32]| create3_address(f, i, c, kd, sl).instance;
        let mut flip = id;
        flip[31] ^= 1;
        assert_ne!(other(&factory, &flip, class, kind, &salt), instance, "another creator");
        assert_ne!(other(&factory, &id, class ^ 1, kind, &salt), instance, "another class");
        assert_ne!(other(&factory, &id, class, kind ^ 1, &salt), instance, "another kind");
        let mut fsalt = salt;
        fsalt[0] ^= 1;
        assert_ne!(other(&factory, &id, class, kind, &fsalt), instance, "another salt");
        let mut ff = factory;
        ff[19] ^= 1;
        assert_ne!(other(&ff, &id, class, kind, &salt), instance, "another factory");
    }
    assert_eq!(rows.len(), 6);
}

/// The clone's runtime and its `ChainEnv` (chain-neutral spec §2, §6.4; owner 2026-11-08: the reference readers check `--registry`
/// against it): every KAT env (plain, PQZ, Zether, PqChat) parses from its clone's runtime (the init code less its 10-byte
/// prefix) to the env's fields, and builds back to the same bytes; a runtime that is not that proxy, or an env cut short,
/// lengthened, or past its bounds, is no env.
#[test]
fn chain_env_kat_rows() {
    let k = kat();
    let implementation: [u8; 20] = fixed(&k["implementation"]);
    for e in k["envs"].as_array().unwrap() {
        let (env, init) = (bytes(&e["env"]), bytes(&e["cloneInitCode"]));
        assert_eq!(env.len() as u64, e["envLength"].as_u64().unwrap());
        let runtime = &init[10..];
        assert_eq!(keccak256(runtime), fixed::<32>(&e["cloneRuntimeHash"]), "{}", e["name"]);
        let (imp, c) = clone_env(runtime).unwrap_or_else(|| panic!("{}", e["name"]));
        assert_eq!(imp, implementation);
        assert_eq!((c.chain_uid.to_vec(), c.registry.to_vec()), (env[..32].to_vec(), env[32..52].to_vec()), "{}", e["name"]);
        assert_eq!((c.gov_router.to_vec(), c.smart_key_account_impl.to_vec()), (env[52..72].to_vec(), env[72..92].to_vec()));
        assert_eq!(env_bytes(&c), env, "{}: the env builds back", e["name"]);
        assert_eq!(clone_runtime(&imp, &c), runtime.to_vec(), "{}: the runtime builds back", e["name"]);
        // not an env: another proxy byte, one byte short or long, the implementation's own code
        let mut head = runtime.to_vec();
        head[0] ^= 1;
        assert!(clone_env(&head).is_none(), "another proxy head");
        let mut tail = runtime.to_vec();
        tail[30] ^= 1;
        assert!(clone_env(&tail).is_none(), "another proxy tail");
        assert!(clone_env(&runtime[..runtime.len() - 1]).is_none(), "one byte short");
        assert!(clone_env(&[runtime, &[0][..]].concat()).is_none(), "one byte more");
        assert!(clone_env(&runtime[..45]).is_none(), "the proxy alone");
        assert!(clone_env(&[]).is_none(), "no code");
    }
    // the bounds: at most 4 deps and 2 params, `hedera` a bool
    let c = clone_env(&bytes(&k["envs"][0]["cloneInitCode"])[10..]).unwrap().1;
    let at = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut rt = clone_runtime(&implementation, &c);
        f(&mut rt);
        clone_env(&rt)
    };
    assert!(at(&|_| {}).is_some(), "positive control");
    assert!(at(&|rt| rt[45 + 92] = 2).is_none(), "hedera 2");
    assert!(at(&|rt| {
        rt[45 + 93] = 5;
        rt.splice(45 + 94..45 + 94, [0u8; 100]);
    })
    .is_none(), "five deps");
}
