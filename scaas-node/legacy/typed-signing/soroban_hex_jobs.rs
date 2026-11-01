//! Superseded by N2 (`ua8-soroban`, owner's explicit parameters of 2026-10-31): the Soroban `ua_metatx` hex XDR `op.args` and the
//! `op.extra.call` XDR of `signed_op`, as they stood in `src/adapters/soroban.rs`. Reference only; nothing builds this file.

// ---------------------------------------- host_call

/// Lời gọi host + auth entry từ op `signed_op`. Mặc định lời gọi = invocation chủ thể đã ký; `extra.call` (XDR hex
/// `InvokeContractArgs`) + `extra.auth` (chữ ký bổ sung) cho thao tác nhiều bên như DEX `settle` (R8-5).
pub fn host_call(network: &[u8; 32], op: &Value) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>)> {
    let s = |v: &Value, k: &str| v[k].as_str().map(str::to_owned).ok_or_else(|| anyhow!("op.{k} missing"));
    let (main, signed) = auth_entry(network, &s(op, "payload")?, &s(op, "from")?, &s(op, "signature")?)?;
    let contract = ScAddress::from_str(&s(op, "contract")?).map_err(|_| anyhow!("bad contract"))?;
    let mut auth = vec![main];
    for a in op["extra"]["auth"].as_array().into_iter().flatten() {
        auth.push(auth_entry(network, &s(a, "payload")?, &s(a, "from")?, &s(a, "signature")?)?.0);
    }
    let call = match op["extra"]["call"].as_str() {
        Some(x) => InvokeContractArgs::from_xdr(unhex(x)?, Limits::len(65_536))?,
        None => signed,
    };
    if call.contract_address != contract {
        bail!("op targets {} but its call is to {}", op["contract"], call.contract_address);
    }
    Ok((call, auth))
}


// ---------------------------------------- signed_call, pay_meta_job

/// The signed invocation of `op.payload`.
fn signed_call(network: &[u8; 32], op: &Value) -> Result<InvokeContractArgs> {
    let s = |k: &str| op[k].as_str().ok_or_else(|| anyhow!("op.{k} missing"));
    Ok(auth_entry(network, s("payload")?, s("from")?, s("signature")?)?.1)
}

/// Pay-meta job: the signed invocation is the token's `pay_meta`; `op.salt` / `op.meta` must be the signed
/// arguments (the auth entry covers them), `op.pay_ref` (when given) the commitment, `meta` within the cap.
pub fn pay_meta_job(network: &[u8; 32], op: &Value, max_meta: usize) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>)> {
    let (call, auth) = host_call(network, op)?;
    let signed = signed_call(network, op)?;
    if signed.function_name.0.as_slice() != b"pay_meta" || signed.args.len() != 6 {
        bail!("pay-meta job must sign pay_meta(from, to, amount, salt, meta, valid_until)");
    }
    if call != signed {
        bail!("the executed call is not the signed pay_meta");
    }
    let (salt, meta) = (op_bytes(op, "salt")?, op_bytes(op, "meta")?);
    if meta.len() > max_meta {
        bail!("meta is {} B, above max_pay_meta_bytes {max_meta}", meta.len());
    }
    if bytes_arg(&signed.args[3]) != Some(&salt[..]) || bytes_arg(&signed.args[4]) != Some(&meta[..]) {
        bail!("op.salt / op.meta differ from the signed pay_meta arguments");
    }
    if !op["pay_ref"].is_null() && op_bytes(op, "pay_ref")? != meta_pay_id(&salt, &meta) {
        bail!("pay_ref != metaPayId(salt, meta)");
    }
    Ok((call, auth))
}


// ---------------------------------------- relay_fee_job

/// Relay-fee job: `extra.call` is the router's `relay(payer, target, func, args, salt, token, to, amount,
/// valid_until, relayer)`; the payer's signed root is the same call with the eight `require_auth_for_args`
/// arguments (no payer, no relayer) and the token's `pay` (carrying `ref`) as sub-invocation. Checks the policy,
/// `ref` against the call bytes, the relayer against this lane (`relayer` is the transaction source) and the signed
/// tree against the executed call. Soroban does not satisfy `relayer.require_auth()` from the transaction source
/// alone: the returned auth carries an explicit `SourceAccount` entry rooted at the same call.
pub fn relay_fee_job(
    network: &[u8; 32],
    op: &Value,
    lane: &ScAddress,
    policy: &RelayFeePolicy,
) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>, [u8; 32])> {
    let (call, mut auth) = host_call(network, op)?;
    if op["extra"]["call"].is_null() {
        bail!("relay-fee job needs extra.call (the router call)");
    }
    let SorobanCredentials::Address(cred) = &auth[0].credentials else { bail!("payer entry has no address credentials") };
    let SorobanAuthorizedFunction::ContractFn(root) = &auth[0].root_invocation.function else { bail!("signed root is not a contract call") };
    if call.function_name.0.as_slice() != b"relay" || call.args.len() != 10 || root.function_name.0.as_slice() != b"relay" {
        bail!("relay-fee job must call relay(payer, target, func, args, salt, token, to, amount, valid_until, relayer)");
    }
    if root.contract_address != call.contract_address || root.args.as_slice() != &call.args[1..9] {
        bail!("the signed root is not this relay call");
    }
    if policy.router.as_ref() != Some(&call.contract_address) {
        bail!("relay target is not the configured router");
    }
    if call.args[0] != ScVal::Address(cred.address.clone()) {
        bail!("payer argument is not the signer");
    }
    if call.args[9] != ScVal::Address(lane.clone()) {
        bail!("relayer argument is not this lane");
    }
    if pays_router(&call, policy) {
        bail!("the relayed call pays or approves the relay-fee router or its executor (CTR-MTX-27)");
    }
    let (ScVal::Address(target), ScVal::Symbol(func), ScVal::Vec(Some(inner))) = (&call.args[1], &call.args[2], &call.args[3]) else {
        bail!("relay target / func / args malformed");
    };
    let salt: [u8; 32] = bytes_arg(&call.args[4]).and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("salt is 32 bytes"))?;
    let ScVal::Address(token) = &call.args[5] else { bail!("token argument malformed") };
    if !policy.tokens.contains(token) {
        bail!("token is not registered on this chain");
    }
    let amount = scval_i128(&call.args[7]).and_then(|a| u128::try_from(a).ok()).ok_or_else(|| anyhow!("amount argument malformed or negative"))?;
    // open mode: `to` is the router (it forwards to the relayer, this lane); a bound payee is `to` itself
    let to = &call.args[6];
    if policy.executor.get().is_some_and(|x| *to == ScVal::Address(x.clone())) {
        bail!("the fee is bound to the router's executor (BadPayee)");
    }
    crate::adapter::relay_fee_ours(*to == ScVal::Address(call.contract_address.clone()), *to == ScVal::Address(lane.clone()), amount, &policy.params)?;
    let rf = relay_ref(network, target, func, inner.as_slice(), &salt);
    if op_bytes(op, "ref")? != rf {
        bail!("op.ref != relay_ref(target, func, args, salt)");
    }
    // The signed tree must contain exactly the payment that commits to `ref`.
    let pays = auth[0].root_invocation.sub_invocations.iter().filter(|s| match &s.function {
        SorobanAuthorizedFunction::ContractFn(f) => {
            f.contract_address == *token
                && f.function_name.0.as_slice() == b"pay"
                && f.args.len() == 5
                && f.args[0] == call.args[0]
                && f.args[1] == call.args[6]
                && f.args[2] == call.args[7]
                && bytes_arg(&f.args[3]) == Some(&rf[..])
                && f.args[4] == call.args[8]
        }
        _ => false,
    });
    if pays.count() != 1 {
        bail!("the payer's signature does not carry token.pay(payer, to, amount, ref, valid_until)");
    }
    auth.push(source_entry(&call));
    Ok((call, auth, rf))
}


// ---------------------------------------- UaFn, UA_FNS, ua_call

/// One allow-listed `ua_metatx` function (spec §9.1): its contract class, arity (with `auth`, the last argument; `settle`
/// has two order auths) and the indexes of `valid_until` (`None`: the orders' `expiry`), `relayer` (`Option<Address>`;
/// `ua_relay`'s an `Address`), the UA signer `from` (`BytesN<32>`, `mtx_revoke`'s `by` a `Holder`; `None` with a lane =
/// the mandate's owner), its `lane` (the nonce follows it) and `pay_ref`.
struct UaFn {
    name: &'static str,
    class: Class,
    arity: usize,
    valid_until: Option<usize>,
    relayer: Option<usize>,
    from: Option<usize>,
    lane: Option<usize>,
    pay_ref: Option<usize>,
}

#[allow(clippy::too_many_arguments)]
const fn uf(name: &'static str, class: Class, arity: usize, valid_until: Option<usize>, relayer: Option<usize>, from: Option<usize>,
            lane: Option<usize>, pay_ref: Option<usize>) -> UaFn {
    UaFn { name, class, arity, valid_until, relayer, from, lane, pay_ref }
}

/// The contracts' signatures (T5–T8, T6b's `epoch` in the delegate entries).
const UA_FNS: [UaFn; 13] = [
    uf("ua_transfer", Class::Token, 8, Some(5), Some(6), Some(0), Some(3), None),
    uf("ua_pay", Class::Token, 7, Some(4), Some(5), Some(0), None, Some(3)),
    uf("ua_pay_meta", Class::Token, 8, Some(5), Some(6), Some(0), None, None),
    uf("ua_burn", Class::Token, 7, Some(4), Some(5), Some(0), Some(2), None),
    uf("ua_cancel_nonce", Class::Token, 4, Some(2), None, Some(0), None, None),
    uf("ua_relay", Class::Router, 11, Some(8), Some(9), Some(0), None, None),
    uf("settle", Class::Dex, 5, None, None, None, None, None),
    uf("ua_cancel", Class::Dex, 2, None, None, None, None, None),
    uf("mtx_set_mandate", Class::Mandate, 11, Some(8), Some(9), None, Some(6), None),
    uf("mtx_set_payee", Class::Mandate, 8, Some(5), Some(6), None, Some(3), None),
    uf("mtx_revoke", Class::Mandate, 8, Some(5), Some(6), Some(1), Some(3), None),
    uf("mtx_withdraw", Class::Mandate, 8, Some(5), Some(6), None, Some(3), None),
    uf("mtx_mandate_pay", Class::Mandate, 8, Some(5), Some(6), None, None, Some(3)),
];

/// SOR-D14's op: `{contract, function, args: "<hex XDR ScVec>" (every argument, `auth` included), auth?: [{payload,
/// from, signature}]}` ⇒ the call and its table row (function first, then arity).
fn ua_call(op: &Value) -> Result<(InvokeContractArgs, &'static UaFn)> {
    let s = |k: &str| op[k].as_str().ok_or_else(|| anyhow!("op.{k} missing"));
    // decision (C): the kind is `job.kind`; an `op.kind` here is a misrouted job, never ignored
    if op.get("kind").is_some_and(|k| !k.is_null()) {
        bail!("a ua_metatx op carries no op.kind (got {})", op["kind"]);
    }
    let function = s("function")?;
    let f = UA_FNS.iter().find(|f| f.name == function).ok_or_else(|| anyhow!("{function:?} is not a ua_metatx function"))?;
    let contract = match ScAddress::from_str(s("contract")?) {
        Ok(a @ ScAddress::Contract(_)) => a,
        _ => bail!("op.contract is not a Soroban contract address (C…)"),
    };
    let raw = op_bytes(op, "args")?;
    let args = ScVec::from_xdr(&raw, Limits { depth: 64, len: raw.len() })?;
    if args.len() != f.arity {
        bail!("{function} takes {} arguments, not {}", f.arity, args.len());
    }
    Ok((InvokeContractArgs { contract_address: contract, function_name: ScSymbol(function.try_into()?), args: args.0 }, f))
}


// ---------------------------------------- the pay_ref length check of ua_metatx_job

    if let Some(i) = f.pay_ref {
        if a.get(i).and_then(bytes_arg).map(<[u8]>::len) != Some(32) {
            bail!("{}: pay_ref is 32 bytes", f.name);
        }
    }

// ---------------------------------------- the test helpers relay_job*

    fn relay_job(token_pay_ref: &[u8], relayer: &str, target_in_call: &str, op_ref: &[u8]) -> Value {
        relay_job_with(token_pay_ref, relayer, target_in_call, op_ref, sym("revoke"))
    }

    fn relay_job_with(token_pay_ref: &[u8], relayer: &str, target_in_call: &str, op_ref: &[u8], func: ScVal) -> Value {
        relay_job_to(token_pay_ref, relayer, target_in_call, op_ref, func, WALLET2)
    }

    /// `to` = the payee: the router (open mode, the default), the lane, or anyone else (bound).
    fn relay_job_to(token_pay_ref: &[u8], relayer: &str, target_in_call: &str, op_ref: &[u8], func: ScVal, payee: &str) -> Value {
        relay_job_args(token_pay_ref, relayer, target_in_call, op_ref, func, payee, vec![addr(CONTRACT), addr(OWNER)])
    }

    /// `relay_job_to` with the target call's arguments given.
    fn relay_job_args(token_pay_ref: &[u8], relayer: &str, target_in_call: &str, op_ref: &[u8], func: ScVal, payee: &str,
                      args: Vec<ScVal>) -> Value {
        let token = CONTRACT;
        let to = addr(payee);
        let signed = vec![addr(WALLET), func, vecv(args.clone()), byt(&SALT), addr(token), to.clone(), i128v(7), ScVal::U64(1_800_000_300)];
        let pay = inv(token, "pay", vec![addr(OWNER), to.clone(), i128v(7), byt(token_pay_ref), ScVal::U64(1_800_000_300)], vec![]);
        let root = inv(WALLET2, "relay", signed.clone(), vec![pay]);
        let mut full = vec![addr(OWNER)];
        let mut sg = signed;
        sg[0] = addr(target_in_call);
        full.extend(sg);
        full.push(addr(relayer));
        let call = InvokeContractArgs {
            contract_address: ScAddress::from_str(WALLET2).unwrap(),
            function_name: ScSymbol("relay".try_into().unwrap()),
            args: full.try_into().unwrap(),
        };
        json!({"kind": "relay_fee", "payload": payload(NET7, root), "from": OWNER, "signature": sig(), "contract": WALLET2,
               "valid_until": 1_800_000_300u64, "ref": format!("0x{}", hex(op_ref)),
               "extra": {"call": hex(&call.to_xdr(Limits::none()).unwrap())}})
    }

// ---------------------------------------- the test helper ua_op, auth_arg

    fn ua_op(contract: &str, function: &str, args: Vec<ScVal>) -> Value {
        let a = ScVec(args.try_into().unwrap()).to_xdr(Limits::none()).unwrap();
        json!({"contract": contract, "function": function, "args": format!("0x{}", hex(&a))})
    }
    fn auth_arg() -> ScVal {
        byt(&[0xaa; 8])
    }

// ---------------------------------------- soroban_relay_fee_job_checks_ref, the assertions on extra.call

        // The relayer argument is not this lane (the router marker).
        assert!(bad(relay_job(&rf, FROM, WALLET, &rf)));
        // The executed call differs from the signed one.
        assert!(bad(relay_job(&rf, LANE, CONTRACT, &rf)));
        // No explicit call: refused.
        let mut bare = ok.clone();
        bare["extra"] = json!({});
        assert!(bad(bare));

// ---------------------------------------- ua_metatx_digest_matches_ua_ops_vectors

    /// SOR-D14: the shared `ua-ops.json` rows rebuilt as jobs give the vector's op digest (the job id); `ua_relay`'s is
    /// the inner `token.ua_pay` with `pay_ref = ref` and `relayer = Some(router)`.
    #[test]
    fn ua_metatx_digest_matches_ua_ops_vectors() {
        let v: Value = serde_json::from_str(include_str!("../../../smartcontracts/soroban/vectors/ua-ops.json")).unwrap();
        let net = network_id(v["network"]["passphrase"].as_str().unwrap());
        let c = &v["contracts"];
        let at = |k: &str| sc(c[k].as_str().unwrap());
        let policy = RelayFeePolicy { router: Some(at("router")), tokens: vec![at("token")], params: rp(5), dex: Some(at("dex")),
                                      executor: OnceLock::new(), ua_registry: None, relayers: OnceLock::new() };
        let xdr = |s: &Value| ScVal::from_xdr(strip(s), Limits::none()).unwrap();
        let mut n = 0;
        for e in v["entries"].as_array().unwrap() {
            if e["name"] == "ua_order" {
                continue; // `ua_trade`'s order digest: signed by the maker, run by the DEX, never a job
            }
            for row in e["perKind"].as_array().unwrap() {
                let mut args: Vec<ScVal> = row["args"].as_array().unwrap().iter().map(|a| xdr(&a["xdr"])).collect();
                let auth = xdr(&row["authXdr"]);
                let (contract, function) = if e["name"] == "ua_relay" {
                    let r = &e["relay"];
                    assert_eq!(args[3], byt(&strip(&r["ref"])), "the vector's pay_ref is its relay ref");
                    let inner = r["args"].as_array().unwrap().iter().map(|a| xdr(&a["xdr"])).collect();
                    args = vec![args[0].clone(), addr(r["target"].as_str().unwrap()), sym(r["func"].as_str().unwrap()), vecv(inner),
                                byt(&strip(&r["salt"])), addr(e["contract"].as_str().unwrap()), args[1].clone(), args[2].clone(),
                                args[4].clone(), addr(LANE)];
                    (c["router"].as_str().unwrap(), "ua_relay")
                } else {
                    (e["contract"].as_str().unwrap(), e["fn"].as_str().unwrap())
                };
                args.push(auth);
                let (call, _, digest) = ua_metatx_job(&net, &ua_op(contract, function, args), &lane(), &policy)
                    .unwrap_or_else(|x| panic!("{} {}: {x:#}", e["name"], row["kind"]));
                assert_eq!(call.contract_address.to_string(), contract);
                assert_eq!(format!("0x{}", hex(&digest)), row["digest"].as_str().unwrap(), "{} {}", e["name"], row["kind"]);
                n += 1;
            }
        }
        assert_eq!(n, 12 * 7, "every job row of the vector file");
    }


// ---------------------------------------- the proptests over XDR bytes

            // A well-formed job with one byte of its call mutated.
            let rf = [1u8; 32];
            let mut v = relay_job(&rf, LANE, WALLET, &rf);
            let mut c = unhex(v["extra"]["call"].as_str().unwrap()).unwrap();
            let n = c.len();
            c[i % n] = b;
            v["extra"]["call"] = json!(hex(&c));
            let _ = relay_fee_job(&NET7, &v, &lane, &policy());
        }

        /// A well-formed `ua_metatx` op with one byte of its arguments mutated: refused or built, never a panic.
        #[test]
        fn ua_metatx_job_never_panics(k in 0usize..13, i in any::<usize>(), b in any::<u8>()) {
            let mut ops = ua_ops(addr(LANE));
            ops.push((WALLET2, "ua_relay", ua_relay_args(h_addr(WALLET2), LANE)));
            let (c, f, args) = ops.swap_remove(k % ops.len());
            let mut a = ScVec(args.try_into().unwrap()).to_xdr(Limits::none()).unwrap();
            let n = a.len();
            a[i % n] = b;
            let o = json!({"contract": c, "function": f, "args": hex(&a)});
            let _ = ua_metatx_job(&NET7, &o, &lane(), &policy());
            let _ = job_tx(&NET7, Some("ua_metatx"), &o, &lane(), &policy());
        }


