//! cw-multi-test: token meta-tx (adr036 + passkey), anti-lock (R62), allowance R26, mandate R25, DEX R35,
//! và vector chéo với Odoo (`test_fam_cosmos.py`) và adapter Rust (`adapters/cosmos.rs`).
// Test helpers mirror the signed-op fields one-to-one; bundling them would hide what each test signs.
#![allow(clippy::too_many_arguments, clippy::type_complexity)]
use scaas_metaop::{adr036_doc, base64url, meta_pay_id, pay_lane, passkey_account, relay_ref, secp256k1_account, sha256, Auth, MetaOp, DOMAIN};
use cosmwasm_std::{to_json_vec, StdResult, Addr, Api, Binary, CanonicalAddr, HexBinary, Uint128};
use cw_multi_test::{App, AppBuilder, AppResponse, BankKeeper, ContractWrapper, Executor, MockApiBech32};
use k256::ecdsa::signature::hazmat::PrehashSigner;

type TApp = App<BankKeeper, MockApiBech32>;

fn app() -> TApp {
    AppBuilder::default().with_api(MockApiBech32::new("wasm")).build(|_, _, _| {})
}

struct K1(k256::ecdsa::SigningKey);
impl K1 {
    fn new(seed: u8) -> Self {
        Self(k256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).unwrap())
    }
    fn pk(&self) -> Vec<u8> {
        self.0.verifying_key().to_encoded_point(true).as_bytes().to_vec()
    }
    fn addr(&self, app: &TApp) -> Addr {
        app.api().addr_humanize(&CanonicalAddr::from(secp256k1_account(&self.pk()))).unwrap()
    }
    fn sign_hash(&self, h: &[u8; 32]) -> Vec<u8> {
        let s: k256::ecdsa::Signature = self.0.sign_prehash(h).unwrap();
        s.normalize_s().unwrap_or(s).to_bytes().to_vec()
    }
    fn auth(&self, payload: &[u8], from: &str) -> Auth {
        Auth {
            scheme: "adr036".into(),
            pubkey: self.pk().into(),
            signature: self.sign_hash(&sha256(&adr036_doc(from, payload))).into(),
            authenticator_data: None,
            client_data_json: None,
        }
    }
}

fn op(app: &TApp, contract: &Addr, kind: &str, from: &Addr, to: &str, amount: u128, lane: u8, nonce: u64) -> MetaOp {
    MetaOp {
        amount: Uint128::new(amount),
        contract: contract.to_string(),
        domain: DOMAIN.into(),
        extra: String::new(),
        from: from.to_string(),
        lane: HexBinary::from(vec![lane; 32]),
        network: app.block_info().chain_id,
        nonce,
        op: kind.into(),
        pay_ref: HexBinary::from(vec![lane ^ 0x5a; 32]),
        relayer: String::new(),
        to: to.into(),
        valid_until: app.block_info().time.seconds() + 600,
    }
}

fn relay_msg(payload: &[u8], auth: Auth) -> scaas_token::ExecuteMsg {
    scaas_token::ExecuteMsg::Relay { payload: payload.to_vec().into(), auth }
}

struct World {
    app: TApp,
    t1: Addr,
    t2: Addr,
    relayer: Addr,
    alice: K1,
    bob: K1,
}

fn token(app: &mut TApp, code: u64, admin: &Addr, sym: &str, holders: &[(&Addr, u128)]) -> Addr {
    let init = scaas_token::InstantiateMsg {
        name: sym.into(),
        symbol: sym.into(),
        decimals: 6,
        initial_balances: holders
            .iter()
            .map(|(a, n)| scaas_token::Balance { address: a.to_string(), amount: Uint128::new(*n) })
            .collect(),
        minter: Some(admin.to_string()),
    };
    app.instantiate_contract(code, admin.clone(), &init, &[], sym, None).unwrap()
}

fn world() -> World {
    let mut app = app();
    let code = app.store_code(Box::new(ContractWrapper::new(scaas_token::execute, scaas_token::instantiate, scaas_token::query)));
    let admin = app.api().addr_make("admin");
    let relayer = app.api().addr_make("relayer");
    let (alice, bob) = (K1::new(7), K1::new(9));
    let (a, b) = (alice.addr(&app), bob.addr(&app));
    let t1 = token(&mut app, code, &admin, "TOKA", &[(&a, 1_000_000), (&b, 1_000_000)]);
    let t2 = token(&mut app, code, &admin, "TOKB", &[(&a, 1_000_000), (&b, 1_000_000)]);
    World { app, t1, t2, relayer, alice, bob }
}

fn balance(app: &TApp, token: &Addr, who: &str) -> u128 {
    let r: scaas_token::BalanceResponse =
        app.wrap().query_wasm_smart(token, &scaas_token::QueryMsg::Balance { address: who.into() }).unwrap();
    r.balance.u128()
}

fn attr(res: &AppResponse, ty: &str, key: &str) -> Option<String> {
    res.events.iter().filter(|e| e.ty == ty).flat_map(|e| &e.attributes).find(|a| a.key == key).map(|a| a.value.clone())
}

fn relay(w: &mut World, token: &Addr, payload: &[u8], auth: Auth) -> StdResult<AppResponse> {
    let t = token.clone();
    w.app.execute_contract(w.relayer.clone(), t, &relay_msg(payload, auth), &[])
}

#[test]
fn pay_by_signature_moves_funds_and_emits_events_once() {
    let mut w = world();
    let (a, payee) = (w.alice.addr(&w.app), w.app.api().addr_make("payee"));
    let p = to_json_vec(&op(&w.app, &w.t1, "pay", &a, payee.as_str(), 250, 1, 0)).unwrap();
    let auth = w.alice.auth(&p, a.as_str());
    let t1 = w.t1.clone();
    // Front-run bằng `Pay` trực tiếp cùng `pay_ref` không đốt được khoản của Alice (không khoá pay_ref toàn cục).
    let grief = scaas_token::ExecuteMsg::Pay { to: payee.to_string(), amount: Uint128::new(1), pay_ref: HexBinary::from(vec![1 ^ 0x5a; 32]) };
    w.app.execute_contract(w.bob.addr(&w.app), t1.clone(), &grief, &[]).unwrap();
    let res = relay(&mut w, &t1, &p, auth.clone()).unwrap();
    assert_eq!(balance(&w.app, &w.t1, payee.as_str()), 251);
    assert_eq!(balance(&w.app, &w.t1, a.as_str()), 1_000_000 - 250);
    assert_eq!(attr(&res, "wasm-payment_settled", "pay_ref"), Some(format!("0x{}", "5b".repeat(32))));
    assert_eq!(attr(&res, "wasm-payment_settled", "to").as_deref(), Some(payee.as_str()));
    assert_eq!(attr(&res, "wasm-meta_tx_executed", "digest"), Some(format!("0x{}", HexBinary::from(sha256(&p)).to_hex())));
    // Replay: nonce đã tiêu.
    assert!(relay(&mut w, &t1, &p, auth).unwrap_err().to_string().contains("nonce"));
}

#[test]
fn domain_expiry_relayer_and_key_binding_are_enforced() {
    let mut w = world();
    let (a, payee) = (w.alice.addr(&w.app), w.app.api().addr_make("payee").to_string());
    let (t1, t2) = (w.t1.clone(), w.t2.clone());
    let cases: Vec<(&str, Box<dyn Fn(&mut MetaOp)>)> = vec![
        ("another network", Box::new(|o| o.network = "other-1".into())),
        ("another contract", Box::new(move |o| o.contract = t2.to_string())),
        ("expired", Box::new(|o| o.valid_until = 1)),
        ("domain", Box::new(|o| o.domain = "scaas.metaop.v0".into())),
        ("another relayer", Box::new(|o| o.relayer = "wasm1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcjxgyj".into())),
    ];
    for (why, f) in cases {
        let mut o = op(&w.app, &t1, "pay", &a, &payee, 10, 2, 0);
        f(&mut o);
        let p = to_json_vec(&o).unwrap();
        let auth = w.alice.auth(&p, a.as_str());
        let e = relay(&mut w, &t1, &p, auth).unwrap_err();
        assert!(e.to_string().contains(why), "{why}: {e:?}");
    }
    // Bob ký thay `from = alice`: khoá không sở hữu địa chỉ.
    let p = to_json_vec(&op(&w.app, &t1, "pay", &a, &payee, 10, 3, 0)).unwrap();
    let mut forged = w.bob.auth(&p, a.as_str());
    assert!(relay(&mut w, &t1, &p, forged.clone()).unwrap_err().to_string().contains("does not own"));
    // Khoá đúng, chữ ký trên payload khác.
    forged.pubkey = w.alice.pk().into();
    assert!(relay(&mut w, &t1, &p, forged).unwrap_err().to_string().contains("bad signature"));
    // Khoá lạ trong JSON bị từ chối (parse chặt).
    let mut raw = String::from_utf8(p.clone()).unwrap();
    raw.insert_str(1, r#""fee":"1","#);
    let auth = w.alice.auth(raw.as_bytes(), a.as_str());
    assert!(relay(&mut w, &t1, raw.as_bytes(), auth).is_err());
}

/// R62 anti-lock: X ký trên token 1, Y trên token 2; X bị giữ lại; Y thành công; rồi X thành công.
/// Thêm: hai lane trên CÙNG contract không chặn nhau (nonce theo lane).
#[test]
fn anti_lock_withheld_op_never_blocks_others() {
    let mut w = world();
    let (a, payee) = (w.alice.addr(&w.app), w.app.api().addr_make("payee").to_string());
    let (t1, t2) = (w.t1.clone(), w.t2.clone());
    let x = to_json_vec(&op(&w.app, &t1, "pay", &a, &payee, 11, 4, 0)).unwrap();
    let y = to_json_vec(&op(&w.app, &t2, "pay", &a, &payee, 22, 4, 0)).unwrap();
    let (ax, ay) = (w.alice.auth(&x, a.as_str()), w.alice.auth(&y, a.as_str()));
    relay(&mut w, &t2, &y, ay).unwrap();
    assert_eq!(balance(&w.app, &t2, &payee), 22);
    relay(&mut w, &t1, &x, ax).unwrap();
    assert_eq!(balance(&w.app, &t1, &payee), 11);
    // Cùng contract, lane khác: lane 6 đi trước lane 5.
    let l5 = to_json_vec(&op(&w.app, &t1, "pay", &a, &payee, 1, 5, 0)).unwrap();
    let l6 = to_json_vec(&op(&w.app, &t1, "pay", &a, &payee, 2, 6, 0)).unwrap();
    let (a5, a6) = (w.alice.auth(&l5, a.as_str()), w.alice.auth(&l6, a.as_str()));
    relay(&mut w, &t1, &l6, a6).unwrap();
    relay(&mut w, &t1, &l5, a5).unwrap();
    assert_eq!(balance(&w.app, &t1, &payee), 14);
}

#[test]
fn passkey_scheme_pays_from_its_derived_address() {
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    let mut w = world();
    let sk = p256::ecdsa::SigningKey::from_bytes(&[3u8; 32].into()).unwrap();
    let pk = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
    let from = w.app.api().addr_humanize(&CanonicalAddr::from(passkey_account(&pk))).unwrap();
    let admin = w.app.api().addr_make("admin");
    let t1 = w.t1.clone();
    w.app
        .execute_contract(admin, t1.clone(), &scaas_token::ExecuteMsg::Mint { recipient: from.to_string(), amount: Uint128::new(100) }, &[])
        .unwrap();
    let payee = w.app.api().addr_make("payee").to_string();
    let p = to_json_vec(&op(&w.app, &t1, "pay", &from, &payee, 40, 7, 0)).unwrap();
    let mut ad = vec![0xab; 32];
    ad.extend_from_slice(&[0x05, 0, 0, 0, 1]);
    let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://pay.example"}}"#, base64url(&sha256(&p)));
    let mut msg = ad.clone();
    msg.extend_from_slice(&sha256(cdj.as_bytes()));
    let sig: p256::ecdsa::Signature = sk.sign_prehash(&sha256(&msg)).unwrap();
    let sig = sig.normalize_s().unwrap_or(sig);
    let auth = Auth {
        scheme: "passkey".into(),
        pubkey: pk.into(),
        signature: sig.to_bytes().to_vec().into(),
        authenticator_data: Some(ad.clone().into()),
        client_data_json: Some(cdj.clone()),
    };
    // Khoá nén (cùng điểm) không được dùng: một khoá chỉ có một địa chỉ.
    let mut compressed = auth.clone();
    compressed.pubkey = sk.verifying_key().to_encoded_point(true).as_bytes().to_vec().into();
    assert!(relay(&mut w, &t1, &p, compressed).unwrap_err().to_string().contains("uncompressed"));
    // Challenge của thao tác khác bị từ chối.
    let mut wrong = auth.clone();
    wrong.client_data_json = Some(cdj.replace("webauthn.get", "webauthn.create"));
    assert!(relay(&mut w, &t1, &p, wrong).is_err());
    relay(&mut w, &t1, &p, auth).unwrap();
    assert_eq!(balance(&w.app, &t1, &payee), 40);
}

fn mandate_code(app: &mut TApp) -> u64 {
    app.store_code(Box::new(ContractWrapper::new(scaas_mandate::execute, scaas_mandate::instantiate, scaas_mandate::query)))
}

#[test]
fn allowance_only_to_contracts_and_transfer_from_only_by_contracts() {
    let mut w = world();
    let a = w.alice.addr(&w.app);
    let t1 = w.t1.clone();
    let user = w.app.api().addr_make("user");
    let incr = |s: &Addr| scaas_token::ExecuteMsg::IncreaseAllowance { spender: s.to_string(), amount: Uint128::new(5) };
    assert!(w.app.execute_contract(a.clone(), t1.clone(), &incr(&user), &[]).is_err());
    // Spender là contract (t2): được phép; nó kéo được tiền, tài khoản thường thì không.
    let t2 = w.t2.clone();
    w.app.execute_contract(a.clone(), t1.clone(), &incr(&t2), &[]).unwrap();
    let pull = scaas_token::ExecuteMsg::TransferFrom { owner: a.to_string(), recipient: user.to_string(), amount: Uint128::new(5) };
    assert!(w.app.execute_contract(user.clone(), t1.clone(), &pull, &[]).is_err());
    w.app.execute_contract(t2.clone(), t1.clone(), &pull, &[]).unwrap();
    assert_eq!(balance(&w.app, &t1, user.as_str()), 5);
    assert!(w.app.execute_contract(t2, t1, &pull, &[]).is_err(), "allowance spent");
}

#[test]
fn mandate_caps_payees_refs_expiry_and_revoke() {
    let mut w = world();
    let code = mandate_code(&mut w.app);
    let owner = w.alice.addr(&w.app);
    let (delegate, stranger) = (K1::new(42), K1::new(43));
    let payee = w.app.api().addr_make("payee");
    let now = w.app.block_info().time.seconds();
    let t1 = w.t1.clone();
    let init = scaas_mandate::InstantiateMsg {
        owner: owner.to_string(),
        token: t1.to_string(),
        delegate_pubkey: delegate.pk().into(),
        max_per_payment: Uint128::new(100),
        max_per_period: Uint128::new(150),
        period_secs: 86_400,
        payees: vec![payee.to_string()],
        expires_at: now + 200_000,
    };
    let m = w.app.instantiate_contract(code, owner.clone(), &init, &[], "mandate", None).unwrap();
    let send = scaas_token::ExecuteMsg::Send { contract: m.to_string(), amount: Uint128::new(1000), msg: Binary::default() };
    w.app.execute_contract(owner.clone(), t1.clone(), &send, &[]).unwrap();
    let chain = w.app.block_info().chain_id;
    let pay = |w: &mut World, to: &Addr, amount: u128, r: u8, key: &K1| {
        let msg = scaas_mandate::MandatePay {
            amount: Uint128::new(amount),
            contract: m.to_string(),
            domain: scaas_mandate::DOMAIN.into(),
            network: chain.clone(),
            pay_ref: HexBinary::from(vec![r; 32]),
            to: to.to_string(),
            valid_until: w.app.block_info().time.seconds() + 60,
        };
        let sig = key.sign_hash(&sha256(&to_json_vec(&msg).unwrap()));
        let x = scaas_mandate::ExecuteMsg::PayUnderMandate {
            to: to.to_string(),
            amount: Uint128::new(amount),
            pay_ref: msg.pay_ref,
            valid_until: msg.valid_until,
            signature: sig.into(),
        };
        let r = w.relayer.clone();
        w.app.execute_contract(r, m.clone(), &x, &[])
    };
    let res = pay(&mut w, &payee, 100, 1, &delegate).unwrap();
    assert_eq!(attr(&res, "wasm-payment_settled", "from").as_deref(), Some(m.as_str()));
    assert_eq!(balance(&w.app, &t1, payee.as_str()), 100);
    assert!(pay(&mut w, &payee, 100, 1, &delegate).is_err(), "pay_ref once");
    assert!(pay(&mut w, &payee, 101, 2, &delegate).is_err(), "per payment cap");
    assert!(pay(&mut w, &payee, 60, 3, &delegate).is_err(), "per period cap");
    assert!(pay(&mut w, &owner, 10, 4, &delegate).is_err(), "payee");
    assert!(pay(&mut w, &payee, 10, 5, &stranger).is_err(), "delegate key");
    pay(&mut w, &payee, 50, 6, &delegate).unwrap();
    w.app.update_block(|b| b.time = b.time.plus_seconds(86_400));
    pay(&mut w, &payee, 10, 7, &delegate).unwrap();
    // Thu hồi: chỉ owner; sau đó không chi được nữa.
    let rv = scaas_mandate::ExecuteMsg::Revoke {};
    let r = w.relayer.clone();
    assert!(w.app.execute_contract(r, m.clone(), &rv, &[]).is_err());
    w.app.execute_contract(owner, m.clone(), &rv, &[]).unwrap();
    assert!(pay(&mut w, &payee, 10, 8, &delegate).is_err(), "revoked");
}

struct Dex {
    addr: Addr,
    fees: Addr,
}

fn dex(w: &mut World, fee_on: bool) -> Dex {
    let code = w.app.store_code(Box::new(ContractWrapper::new(scaas_dex::execute, scaas_dex::instantiate, scaas_dex::query)));
    let admin = w.app.api().addr_make("admin");
    let fees = w.app.api().addr_make("fees");
    let init = scaas_dex::InstantiateMsg { admin: admin.to_string(), fee_recipient: fees.to_string() };
    let addr = w.app.instantiate_contract(code, admin.clone(), &init, &[], "dex", None).unwrap();
    let mk = scaas_dex::ExecuteMsg::SetMarket {
        token_a: w.t2.to_string(),
        token_b: w.t1.to_string(),
        market: scaas_dex::Market { fee_on, maker_ppm: 1_000, taker_ppm: 2_000 },
    };
    w.app.execute_contract(admin, addr.clone(), &mk, &[]).unwrap();
    Dex { addr, fees }
}

fn leg(w: &World, d: &Dex, key: &K1, sell: &Addr, amount: u128, buy: &Addr, min: u128, max_fee: u32, lane: u8) -> scaas_dex::Leg {
    let params = to_json_vec(&scaas_dex::OrderParams {
        buy_amount_min: Uint128::new(min),
        buy_token: buy.to_string(),
        dex: d.addr.to_string(),
        max_fee_ppm: max_fee,
    })
    .unwrap();
    let from = key.addr(&w.app);
    let mut o = op(&w.app, sell, "trade", &from, d.addr.as_str(), amount, lane, 0);
    o.relayer = d.addr.to_string();
    o.extra = HexBinary::from(sha256(&params)).to_hex();
    let payload = to_json_vec(&o).unwrap();
    scaas_dex::Leg { auth: key.auth(&payload, from.as_str()), payload: payload.into(), params: params.into() }
}

fn settle(w: &mut World, d: &Dex, maker: scaas_dex::Leg, taker: scaas_dex::Leg) -> StdResult<AppResponse> {
    let r = w.relayer.clone();
    w.app.execute_contract(r, d.addr.clone(), &scaas_dex::ExecuteMsg::Settle { maker, taker }, &[])
}

#[test]
fn dex_settles_two_signed_orders_with_fees_and_limits() {
    let mut w = world();
    let d = dex(&mut w, true);
    let (t1, t2) = (w.t1.clone(), w.t2.clone());
    let (a, b) = (w.alice.addr(&w.app).to_string(), w.bob.addr(&w.app).to_string());
    // Alice bán 1000 A lấy ≥ 1990 B; Bob bán 2000 B lấy ≥ 990 A.
    let m = leg(&w, &d, &w.alice, &t1, 1000, &t2, 1990, 1_000, 10);
    let t = leg(&w, &d, &w.bob, &t2, 2000, &t1, 990, 2_000, 11);
    // Phí trên mức đã ký ⇒ từ chối.
    let low = leg(&w, &d, &w.bob, &t2, 2000, &t1, 990, 1_999, 12);
    assert!(settle(&mut w, &d, m.clone(), low).is_err());
    // Giới hạn giá: Alice đòi 1999 B, sau phí maker chỉ nhận 1998.
    let greedy = leg(&w, &d, &w.alice, &t1, 1000, &t2, 1999, 1_000, 13);
    assert!(settle(&mut w, &d, greedy, t.clone()).unwrap_err().to_string().contains("price limit"));
    settle(&mut w, &d, m.clone(), t.clone()).unwrap();
    assert_eq!(balance(&w.app, &t2, &a), 1_000_000 + 2000 - 2);
    assert_eq!(balance(&w.app, &t1, &b), 1_000_000 + 1000 - 2);
    assert_eq!(balance(&w.app, &t1, &a), 1_000_000 - 1000);
    assert_eq!(balance(&w.app, &t2, d.fees.as_str()), 2);
    assert_eq!(balance(&w.app, &t1, d.fees.as_str()), 2);
    assert_eq!(balance(&w.app, &t1, d.addr.as_str()), 0, "DEX keeps nothing");
    assert!(settle(&mut w, &d, m, t).unwrap_err().to_string().contains("already filled"));
}

#[test]
fn dex_cancel_by_signed_revoke_and_no_direct_pull() {
    let mut w = world();
    let d = dex(&mut w, false);
    let (t1, t2) = (w.t1.clone(), w.t2.clone());
    let m = leg(&w, &d, &w.alice, &t1, 1000, &t2, 2000, 0, 20);
    let t = leg(&w, &d, &w.bob, &t2, 2000, &t1, 1000, 0, 21);
    // Alice huỷ: ký `revoke` trên đúng lane/nonce của lệnh.
    let a = w.alice.addr(&w.app);
    let rv = to_json_vec(&op(&w.app, &t1, "revoke", &a, "", 0, 20, 0)).unwrap();
    let auth = w.alice.auth(&rv, a.as_str());
    relay(&mut w, &t1, &rv, auth).unwrap();
    assert!(settle(&mut w, &d, m.clone(), t.clone()).unwrap_err().to_string().contains("nonce"));
    // Không ai ngoài DEX dùng được chân `trade` (relayer bị ràng vào DEX).
    let mut w2 = world();
    let d2 = dex(&mut w2, false);
    let (t1b, t2b) = (w2.t1.clone(), w2.t2.clone());
    let m2 = leg(&w2, &d2, &w2.alice, &t1b, 1000, &t2b, 2000, 0, 22);
    assert!(relay(&mut w2, &t1b, &m2.payload, m2.auth.clone()).is_err());
    let t2 = leg(&w2, &d2, &w2.bob, &t2b, 2000, &t1b, 1000, 0, 23);
    settle(&mut w2, &d2, m2, t2).unwrap();
}

/// Anti-lock: token gửi thẳng vào DEX (DEX không giữ số dư giữa các tx) chỉ admin `sweep` ra được.
#[test]
fn dex_admin_sweeps_stray_balance() {
    let mut w = world();
    let d = dex(&mut w, false);
    let t1 = w.t1.clone();
    let a = w.alice.addr(&w.app);
    let give = scaas_token::ExecuteMsg::Transfer { recipient: d.addr.to_string(), amount: Uint128::new(77) };
    w.app.execute_contract(a.clone(), t1.clone(), &give, &[]).unwrap();
    assert_eq!(balance(&w.app, &t1, d.addr.as_str()), 77);
    let sweep = scaas_dex::ExecuteMsg::Sweep { token: t1.to_string(), recipient: a.to_string(), amount: Uint128::new(77) };
    assert!(w.app.execute_contract(a.clone(), d.addr.clone(), &sweep, &[]).unwrap_err().to_string().contains("unauthorized"));
    let admin = w.app.api().addr_make("admin");
    w.app.execute_contract(admin, d.addr.clone(), &sweep, &[]).unwrap();
    assert_eq!(balance(&w.app, &t1, d.addr.as_str()), 0);
    assert_eq!(balance(&w.app, &t1, a.as_str()), 1_000_000);
}

/// Vector chéo: cùng bytes/digest/doc/địa chỉ ở `dms_blockchain/tests/test_fam_cosmos.py` và
/// `scaas-node/src/adapters/cosmos.rs` (khoá lane 0 Cosmos của "abandon … art", prefix `wasm`).
#[test]
fn cross_implementation_vector() {
    let api = MockApiBech32::new("wasm");
    let sk = k256::ecdsa::SigningKey::from_bytes(
        &<[u8; 32]>::try_from(HexBinary::from_hex("8088c2ed2149c34f6d6533b774da4e1692eb5cb426fdbaef6898eeda489630b7").unwrap().as_slice())
            .unwrap()
            .into(),
    )
    .unwrap();
    let key = K1(sk);
    let from = api.addr_humanize(&CanonicalAddr::from(secp256k1_account(&key.pk()))).unwrap();
    let to = api.addr_humanize(&CanonicalAddr::from(vec![0x33u8; 20])).unwrap();
    let contract = api.addr_humanize(&CanonicalAddr::from(vec![0x44u8; 32])).unwrap();
    let o = MetaOp {
        amount: Uint128::new(1000),
        contract: contract.to_string(),
        domain: DOMAIN.into(),
        extra: String::new(),
        from: from.to_string(),
        lane: HexBinary::from(vec![0x11; 32]),
        network: "scaas-1".into(),
        nonce: 0,
        op: "pay".into(),
        pay_ref: HexBinary::from(vec![0x22; 32]),
        relayer: String::new(),
        to: to.to_string(),
        valid_until: 2_000_000_000,
    };
    let p = to_json_vec(&o).unwrap();
    let doc = adr036_doc(from.as_str(), &p);
    let sig = key.sign_hash(&sha256(&doc));
    assert!(api.secp256k1_verify(&sha256(&doc), &sig, &key.pk()).unwrap());
    // CTR-MTX-27 `ref` of a call on `contract` (canonical 0x44 × 32), read by `adapters/cosmos.rs` too.
    let relay = br#"{"record":{"note":"hello"}}"#;
    let got = format!(
        "from={from}\nto={to}\ncontract={contract}\npayload={}\ndigest={}\ndoc_sha256={}\nsig={}\nrelay_chain=scaas-1\nrelay_msg={}\nrelay_ref={}",
        String::from_utf8(p.clone()).unwrap(),
        HexBinary::from(sha256(&p)).to_hex(),
        HexBinary::from(sha256(&doc)).to_hex(),
        Binary::from(sig.clone()).to_base64(),
        String::from_utf8(relay.to_vec()).unwrap(),
        HexBinary::from(relay_ref("scaas-1", &[0x44; 32], relay)).to_hex()
    );
    println!("{got}");
    assert_eq!(got, include_str!("vector.txt").trim_end());
}

// ------------------------------------------------------------------ CTR-MTX-26: RelayPayMeta

fn paymeta_rows() -> Vec<serde_json::Value> {
    serde_json::from_str(include_str!("../../../vectors/metatx/paymeta.json")).unwrap()
}

fn unhex(v: &serde_json::Value) -> Vec<u8> {
    HexBinary::from_hex(v.as_str().unwrap().trim_start_matches("0x")).unwrap().to_vec()
}

fn b32(v: &[u8]) -> [u8; 32] {
    v.try_into().unwrap()
}

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", HexBinary::from(b).to_hex())
}

/// The full error chain (cw-multi-test wraps a sub-message's error in its caller's context).
fn why(r: StdResult<AppResponse>) -> String {
    format!("{:?}", r.expect_err("expected an error"))
}

/// The pay op of a pay-meta: `pay_ref = metaPayId(salt, meta)`, `lane = payLane(pay_ref)`, `nonce = 0`.
fn meta_op(w: &World, from: &Addr, to: &str, amount: u128, salt: &[u8; 32], meta: &[u8]) -> MetaOp {
    let id = meta_pay_id(salt, meta);
    let mut o = op(&w.app, &w.t1, "pay", from, to, amount, 0, 0);
    o.pay_ref = HexBinary::from(id);
    o.lane = HexBinary::from(pay_lane(&id));
    o
}

fn pay_meta(w: &mut World, sender: &Addr, o: &MetaOp, key: &K1, salt: &[u8], meta: &[u8]) -> StdResult<AppResponse> {
    let p = to_json_vec(o).unwrap();
    let msg = scaas_token::ExecuteMsg::RelayPayMeta {
        payload: p.clone().into(),
        auth: key.auth(&p, &o.from),
        salt: HexBinary::from(salt),
        meta: Binary::from(meta),
    };
    let t1 = w.t1.clone();
    w.app.execute_contract(sender.clone(), t1, &msg, &[])
}

/// Rule 1: every row's `payId` / `payLane`, `long_body_4096` included (a hash vector only).
#[test]
fn pay_meta_vectors_match() {
    let rows = paymeta_rows();
    assert_eq!(rows.len(), 6);
    for r in &rows {
        let id = meta_pay_id(&b32(&unhex(&r["salt"])), &unhex(&r["meta"]));
        assert_eq!(hex0x(&id), r["payId"].as_str().unwrap(), "{}", r["name"]);
        assert_eq!(hex0x(&pay_lane(&id)), r["payLane"].as_str().unwrap(), "{}", r["name"]);
    }
}

/// Every row but the hash-only `long_body_4096` settles on chain, `payment_meta` before `payment_settled`.
#[test]
fn pay_meta_emits_meta_then_settled() {
    let mut w = world();
    let (a, payee) = (w.alice.addr(&w.app), w.app.api().addr_make("payee"));
    let rows: Vec<_> = paymeta_rows().into_iter().filter(|r| r["name"] != "long_body_4096").collect();
    for (i, r) in rows.iter().enumerate() {
        let (salt, meta) = (b32(&unhex(&r["salt"])), unhex(&r["meta"]));
        let o = meta_op(&w, &a, payee.as_str(), 10, &salt, &meta);
        let alice = K1::new(7);
        let relayer = w.relayer.clone();
        let res = pay_meta(&mut w, &relayer, &o, &alice, &salt, &meta).unwrap();
        let pos = |ty: &str| res.events.iter().position(|e| e.ty == ty).unwrap_or_else(|| panic!("no {ty}"));
        assert!(pos("wasm-payment_meta") < pos("wasm-payment_settled"), "{}", r["name"]);
        assert_eq!(attr(&res, "wasm-payment_meta", "pay_id").as_deref(), r["payId"].as_str());
        assert_eq!(attr(&res, "wasm-payment_meta", "meta").as_deref(), r["meta"].as_str());
        assert_eq!(attr(&res, "wasm-payment_settled", "pay_ref").as_deref(), r["payId"].as_str());
        assert_eq!(attr(&res, "wasm-meta_tx_executed", "lane").as_deref(), r["payLane"].as_str().map(|l| &l[2..]));
        assert_eq!(balance(&w.app, &w.t1, payee.as_str()), 10 * (i as u128 + 1));
    }
}

/// Review focus 4: `(salt, meta)` not hashing to `pay_ref`, a wrong lane / nonce / op, a second pay-meta of the same
/// `(payer, payId)` are refused; rule 6: another payer's 0-amount pay-meta of the same `payId` does not block it.
#[test]
fn cosmos_pay_meta_mismatch_and_replay() {
    let mut w = world();
    let (a, payee) = (w.alice.addr(&w.app), w.app.api().addr_make("payee").to_string());
    let relayer = w.relayer.clone();
    let row = &paymeta_rows()[0];
    let (salt, meta) = (b32(&unhex(&row["salt"])), unhex(&row["meta"]));
    let good = meta_op(&w, &a, &payee, 25, &salt, &meta);
    const SHAPE: &str = "pay-meta: pay_ref / lane / nonce are not metaPayId(salt, meta) / payLane(pay_ref) / 0";
    let alice = K1::new(7);
    // (salt, meta) that do not hash to pay_ref.
    assert!(why(pay_meta(&mut w, &relayer, &good, &alice, &[1; 32], &meta)).contains(SHAPE));
    assert!(why(pay_meta(&mut w, &relayer, &good, &alice, &salt, b"other")).contains(SHAPE));
    let mut o = good.clone();
    o.lane = HexBinary::from(vec![3; 32]);
    assert!(why(pay_meta(&mut w, &relayer, &o, &alice, &salt, &meta)).contains(SHAPE));
    let mut o = good.clone();
    o.nonce = 1;
    assert!(why(pay_meta(&mut w, &relayer, &o, &alice, &salt, &meta)).contains(SHAPE));
    let mut o = good.clone();
    o.op = "revoke".into();
    assert!(why(pay_meta(&mut w, &relayer, &o, &alice, &salt, &meta)).contains("pay-meta: op is not pay"));
    assert!(why(pay_meta(&mut w, &relayer, &good, &alice, &salt[..31], &meta)).contains("pay-meta: salt is 32 bytes"));
    assert_eq!(balance(&w.app, &w.t1, &payee), 0);
    // Rule 6: Bob's 0-amount pay-meta with Alice's (salt, meta) uses Bob's own lane, never Alice's.
    let b = w.bob.addr(&w.app);
    let grief = meta_op(&w, &b, &payee, 0, &salt, &meta);
    let bob = K1::new(9);
    pay_meta(&mut w, &relayer, &grief, &bob, &salt, &meta).unwrap();
    pay_meta(&mut w, &relayer, &good, &alice, &salt, &meta).unwrap();
    assert_eq!(balance(&w.app, &w.t1, &payee), 25);
    // Replay of the same (payer, payId), by pay-meta or by the plain relay on the same lane.
    assert!(why(pay_meta(&mut w, &relayer, &good, &alice, &salt, &meta)).contains("metaop: nonce already used or out of order"));
    let p = to_json_vec(&good).unwrap();
    let auth = w.alice.auth(&p, a.as_str());
    let t1 = w.t1.clone();
    assert!(why(relay(&mut w, &t1, &p, auth)).contains("metaop: nonce already used or out of order"));
    assert_eq!(balance(&w.app, &w.t1, &payee), 25);
}

// ------------------------------------------------------------------ CTR-MTX-27: relayfee + relayexec

/// Test-only target: `{"record":{…}}` stores the sender it sees, `{"fail":{}}` errors, `{"call":{contract, msg}}`
/// forwards `msg` (base64) to `contract`.
fn probe_execute(deps: cosmwasm_std::DepsMut, _: cosmwasm_std::Env, info: cosmwasm_std::MessageInfo, msg: serde_json::Value) -> StdResult<cosmwasm_std::Response> {
    if msg.get("fail").is_some() {
        return Err(cosmwasm_std::StdError::msg("probe: failed"));
    }
    if let Some(c) = msg.get("call") {
        let inner = Binary::from_base64(c["msg"].as_str().unwrap())?;
        let m = cosmwasm_std::WasmMsg::Execute { contract_addr: c["contract"].as_str().unwrap().into(), msg: inner, funds: vec![] };
        return Ok(cosmwasm_std::Response::new().add_message(m));
    }
    deps.storage.set(b"sender", info.sender.as_bytes());
    Ok(cosmwasm_std::Response::new())
}

fn probe_instantiate(_: cosmwasm_std::DepsMut, _: cosmwasm_std::Env, _: cosmwasm_std::MessageInfo, _: serde_json::Value) -> StdResult<cosmwasm_std::Response> {
    Ok(cosmwasm_std::Response::new())
}

fn probe_query(deps: cosmwasm_std::Deps, _: cosmwasm_std::Env, _: serde_json::Value) -> StdResult<Binary> {
    cosmwasm_std::to_json_binary(&deps.storage.get(b"sender").map(|s| String::from_utf8(s).unwrap()))
}

struct Rf {
    router: Addr,
    exec: Addr,
    probe: Addr,
}

fn rf(w: &mut World) -> Rf {
    let exec_code = w.app.store_code(Box::new(ContractWrapper::new(scaas_relayexec::execute, scaas_relayexec::instantiate, scaas_relayexec::query)));
    let router_code = w.app.store_code(Box::new(
        ContractWrapper::new(scaas_relayfee::execute, scaas_relayfee::instantiate, scaas_relayfee::query).with_reply(scaas_relayfee::reply),
    ));
    let probe_code = w.app.store_code(Box::new(ContractWrapper::new(probe_execute, probe_instantiate, probe_query)));
    let admin = w.app.api().addr_make("admin");
    let init = scaas_relayfee::InstantiateMsg { executor_code_id: exec_code };
    let router = w.app.instantiate_contract(router_code, admin.clone(), &init, &[], "relayfee", None).unwrap();
    let exec: Addr = w.app.wrap().query_wasm_smart(&router, &scaas_relayfee::QueryMsg::Executor {}).unwrap();
    let probe = w.app.instantiate_contract(probe_code, admin, &serde_json::json!({}), &[], "probe", None).unwrap();
    Rf { router, exec, probe }
}

fn seen(w: &World, probe: &Addr) -> Option<String> {
    w.app.wrap().query_wasm_smart(probe, &serde_json::json!({"sender": {}})).unwrap()
}

fn canon(w: &World, a: &Addr) -> Vec<u8> {
    w.app.api().addr_canonicalize(a.as_str()).unwrap().to_vec()
}

/// A router-bound payment on `token` for the call `(target, msg)`: `pay_ref = ref`, `lane = payLane(ref)`, nonce 0,
/// `relayer = router`.
fn fee_op(w: &World, r: &Rf, token: &Addr, from: &Addr, target: &Addr, msg: &[u8], to: &str, amount: u128) -> MetaOp {
    let rr = relay_ref(&w.app.block_info().chain_id, &canon(w, target), msg);
    let mut o = op(&w.app, token, "pay", from, to, amount, 0, 0);
    o.pay_ref = HexBinary::from(rr);
    o.lane = HexBinary::from(pay_lane(&rr));
    o.relayer = r.router.to_string();
    o
}

fn relay_fee(w: &mut World, r: &Rf, sender: &Addr, target: &Addr, msg: &[u8], o: &MetaOp, key: &K1) -> StdResult<AppResponse> {
    let p = to_json_vec(o).unwrap();
    let m = scaas_relayfee::ExecuteMsg::Relay {
        target: target.to_string(),
        msg: msg.to_vec().into(),
        token: o.contract.clone(),
        payload: p.clone().into(),
        auth: key.auth(&p, &o.from),
    };
    w.app.execute_contract(sender.clone(), r.router.clone(), &m, &[])
}

fn lane_nonce(w: &World, token: &Addr, owner: &Addr, lane: &HexBinary) -> u64 {
    w.app.wrap().query_wasm_smart(token, &scaas_token::QueryMsg::Nonce { owner: owner.to_string(), lane: lane.clone() }).unwrap()
}

const RECORD: &[u8] = br#"{"record":{"note":"hello"}}"#;

#[test]
fn relay_fee_open_mode_pays_sender() {
    let mut w = world();
    let r = rf(&mut w);
    let (a, relayer, t1, t2) = (w.alice.addr(&w.app), w.relayer.clone(), w.t1.clone(), w.t2.clone());
    let o = fee_op(&w, &r, &t1, &a, &r.probe, RECORD, r.router.as_str(), 30);
    let alice = K1::new(7);
    let res = relay_fee(&mut w, &r, &relayer, &r.probe.clone(), RECORD, &o, &alice).unwrap();
    assert_eq!(balance(&w.app, &t1, relayer.as_str()), 30);
    assert_eq!(balance(&w.app, &t1, a.as_str()), 1_000_000 - 30);
    assert_eq!(balance(&w.app, &t1, r.router.as_str()), 0, "the router holds nothing");
    assert_eq!(balance(&w.app, &t1, r.exec.as_str()), 0, "the executor holds nothing");
    assert_eq!(seen(&w, &r.probe).as_deref(), Some(r.exec.as_str()));
    let ev = |k: &str| attr(&res, "wasm-relay_fee_paid", k);
    assert_eq!(ev("ref"), Some(hex0x(o.pay_ref.as_slice())));
    assert_eq!(ev("target").as_deref(), Some(r.probe.as_str()));
    assert_eq!(ev("token").as_deref(), Some(t1.as_str()));
    assert_eq!(ev("payer").as_deref(), Some(a.as_str()));
    assert_eq!(ev("payee").as_deref(), Some(relayer.as_str()));
    assert_eq!(ev("amount").as_deref(), Some("30"));
    assert_eq!(attr(&res, "wasm-payment_settled", "pay_ref"), Some(hex0x(o.pay_ref.as_slice())));
    // The same ref is paid once (pay lane).
    assert!(why(relay_fee(&mut w, &r, &relayer, &r.probe.clone(), RECORD, &o, &alice)).contains("metaop: nonce already used or out of order"));
    // A SCaaS fee-less signed entry as the target: Alice's signed `revoke` of lane 40 on t1, paid in t2.
    let rv = to_json_vec(&op(&w.app, &t1, "revoke", &a, "", 0, 40, 0)).unwrap();
    let call = cosmwasm_std::to_json_vec(&relay_msg(&rv, w.alice.auth(&rv, a.as_str()))).unwrap();
    let o = fee_op(&w, &r, &t2, &a, &t1, &call, r.router.as_str(), 5);
    relay_fee(&mut w, &r, &relayer, &t1, &call, &o, &alice).unwrap();
    assert_eq!(lane_nonce(&w, &t1, &a, &HexBinary::from(vec![40; 32])), 1, "revoke ran");
    assert_eq!(balance(&w.app, &t2, relayer.as_str()), 5);
}

#[test]
fn relay_fee_bound_payee() {
    let mut w = world();
    let r = rf(&mut w);
    let (a, relayer, t1) = (w.alice.addr(&w.app), w.relayer.clone(), w.t1.clone());
    let treasury = w.app.api().addr_make("treasury");
    let o = fee_op(&w, &r, &t1, &a, &r.probe, RECORD, treasury.as_str(), 12);
    let alice = K1::new(7);
    let res = relay_fee(&mut w, &r, &relayer, &r.probe.clone(), RECORD, &o, &alice).unwrap();
    assert_eq!(balance(&w.app, &t1, treasury.as_str()), 12);
    assert_eq!((balance(&w.app, &t1, relayer.as_str()), balance(&w.app, &t1, r.router.as_str())), (0, 0));
    assert_eq!(attr(&res, "wasm-relay_fee_paid", "payee").as_deref(), Some(treasury.as_str()));
    assert!(res.events.iter().all(|e| !(e.ty == "wasm" && e.attributes.iter().any(|x| x.value == "transfer"))), "no forward");
    // Rule 4: never pay the executor.
    let o = fee_op(&w, &r, &t1, &a, &r.probe, br#"{"record":{"n":2}}"#, r.exec.as_str(), 12);
    assert!(why(relay_fee(&mut w, &r, &relayer, &r.probe.clone(), br#"{"record":{"n":2}}"#, &o, &alice)).contains("relayfee: the payment is not bound to this call"));
}

/// Rule 9: call first, then payment; either failing reverts both.
#[test]
fn relay_fee_target_failure_reverts_all() {
    let mut w = world();
    let r = rf(&mut w);
    let (a, relayer, t1) = (w.alice.addr(&w.app), w.relayer.clone(), w.t1.clone());
    let alice = K1::new(7);
    let fail = br#"{"fail":{}}"#;
    let o = fee_op(&w, &r, &t1, &a, &r.probe, fail, r.router.as_str(), 30);
    assert!(why(relay_fee(&mut w, &r, &relayer, &r.probe.clone(), fail, &o, &alice)).contains("probe: failed"));
    assert_eq!(balance(&w.app, &t1, a.as_str()), 1_000_000);
    assert_eq!(lane_nonce(&w, &t1, &a, &o.lane), 0, "payment unspent");
    // The call succeeds but the payment fails (more than Alice holds): the call is reverted too.
    let o = fee_op(&w, &r, &t1, &a, &r.probe, RECORD, r.router.as_str(), 2_000_000);
    assert!(why(relay_fee(&mut w, &r, &relayer, &r.probe.clone(), RECORD, &o, &alice)).contains("insufficient balance"));
    assert_eq!(seen(&w, &r.probe), None, "the call was reverted");
    assert_eq!(lane_nonce(&w, &t1, &a, &o.lane), 0);
}

/// Rule 7 / R18: the target sees the executor; a `msg` that is a token `Relay` of another router-bound payment fails.
#[test]
fn relay_fee_target_sees_executor() {
    let mut w = world();
    let r = rf(&mut w);
    let (a, b, relayer, t1) = (w.alice.addr(&w.app), w.bob.addr(&w.app), w.relayer.clone(), w.t1.clone());
    // Bob's router-bound payment (for a call of his own), smuggled as Alice's call's bytes.
    let bob_pay = fee_op(&w, &r, &t1, &b, &r.probe, br#"{"record":{"bob":1}}"#, relayer.as_str(), 500);
    let bp = to_json_vec(&bob_pay).unwrap();
    let call = cosmwasm_std::to_json_vec(&relay_msg(&bp, w.bob.auth(&bp, b.as_str()))).unwrap();
    let o = fee_op(&w, &r, &t1, &a, &t1, &call, r.router.as_str(), 1);
    let alice = K1::new(7);
    assert!(why(relay_fee(&mut w, &r, &relayer, &t1, &call, &o, &alice)).contains("metaop: bound to another relayer"));
    assert_eq!(balance(&w.app, &t1, b.as_str()), 1_000_000);
    assert_eq!(balance(&w.app, &t1, a.as_str()), 1_000_000);
}

#[test]
fn relayexec_only_router() {
    let mut w = world();
    let r = rf(&mut w);
    let router: Addr = w.app.wrap().query_wasm_smart(&r.exec, &scaas_relayexec::QueryMsg::Router {}).unwrap();
    assert_eq!(router, r.router);
    let exec = scaas_relayexec::ExecuteMsg::Exec { target: r.probe.to_string(), msg: RECORD.to_vec().into() };
    let relayer = w.relayer.clone();
    assert!(why(w.app.execute_contract(relayer.clone(), r.exec.clone(), &exec, &[])).contains("relayexec: only the router"));
    assert_eq!(seen(&w, &r.probe), None);
    // Rule 4: neither contract takes funds.
    let coins = cosmwasm_std::coins(5, "ucosm");
    w.app.init_modules(|router, _, storage| router.bank.init_balance(storage, &relayer, coins.clone())).unwrap();
    let a = w.alice.addr(&w.app);
    let t1 = w.t1.clone();
    let o = fee_op(&w, &r, &t1, &a, &r.probe, RECORD, r.router.as_str(), 1);
    let p = to_json_vec(&o).unwrap();
    let m = scaas_relayfee::ExecuteMsg::Relay {
        target: r.probe.to_string(),
        msg: RECORD.to_vec().into(),
        token: t1.to_string(),
        payload: p.clone().into(),
        auth: w.alice.auth(&p, a.as_str()),
    };
    assert!(why(w.app.execute_contract(relayer.clone(), r.router.clone(), &m, &coins)).contains("relayfee: funds are not accepted"));
    assert!(why(w.app.execute_contract(relayer, r.exec.clone(), &exec, &coins)).contains("relayexec: funds are not accepted"));
}

/// Review focus 3 / R17: a router-bound payment sent to the token by anyone but the router is refused.
#[test]
fn cosmos_router_bound_pay_refused_direct() {
    let mut w = world();
    let r = rf(&mut w);
    let (a, t1) = (w.alice.addr(&w.app), w.t1.clone());
    let o = fee_op(&w, &r, &t1, &a, &r.probe, RECORD, r.router.as_str(), 30);
    let p = to_json_vec(&o).unwrap();
    let auth = w.alice.auth(&p, a.as_str());
    assert!(why(relay(&mut w, &t1, &p, auth.clone())).contains("metaop: bound to another relayer"));
    let exec = r.exec.clone();
    assert!(why(w.app.execute_contract(exec, t1.clone(), &relay_msg(&p, auth), &[])).contains("metaop: bound to another relayer"));
    assert_eq!(balance(&w.app, &t1, a.as_str()), 1_000_000);
}

/// Pinned `ref` vector (also in `vector.txt` and `adapters/cosmos.rs`); the router's view equals the helper.
#[test]
fn relay_ref_vectors() {
    let want = "50cec647f4efc209e1cbce63d6bcb18cb29648784b9060a5f6df52f471088b16";
    assert_eq!(HexBinary::from(relay_ref("scaas-1", &[0x44; 32], RECORD)).to_hex(), want);
    assert_ne!(relay_ref("scaas-2", &[0x44; 32], RECORD), relay_ref("scaas-1", &[0x44; 32], RECORD));
    let mut w = world();
    let r = rf(&mut w);
    let q = scaas_relayfee::QueryMsg::RelayRef { target: r.probe.to_string(), msg: RECORD.to_vec().into() };
    let got: HexBinary = w.app.wrap().query_wasm_smart(&r.router, &q).unwrap();
    assert_eq!(got.as_slice(), relay_ref(&w.app.block_info().chain_id, &canon(&w, &r.probe), RECORD));
}

/// Rule 2: the target is an instantiated contract at relay time, checked before any token movement.
#[test]
fn relay_fee_target_must_be_contract() {
    let mut w = world();
    let r = rf(&mut w);
    let (a, relayer, t1) = (w.alice.addr(&w.app), w.relayer.clone(), w.t1.clone());
    let alice = K1::new(7);
    let account = w.app.api().addr_make("plain-account");
    let future = w.app.api().addr_humanize(&CanonicalAddr::from(vec![0x77; 32])).unwrap();
    for target in [account, future] {
        let o = fee_op(&w, &r, &t1, &a, &target, RECORD, r.router.as_str(), 30);
        assert!(why(relay_fee(&mut w, &r, &relayer, &target, RECORD, &o, &alice)).contains("relayfee: target is not an instantiated contract"));
        assert_eq!(lane_nonce(&w, &t1, &a, &o.lane), 0);
    }
    assert_eq!(balance(&w.app, &t1, a.as_str()), 1_000_000);
}

#[test]
fn relay_fee_shape_refusals() {
    let mut w = world();
    let r = rf(&mut w);
    let (a, relayer, t1) = (w.alice.addr(&w.app), w.relayer.clone(), w.t1.clone());
    let alice = K1::new(7);
    let good = fee_op(&w, &r, &t1, &a, &r.probe, RECORD, r.router.as_str(), 30);
    let other_ref = relay_ref(&w.app.block_info().chain_id, &canon(&w, &r.probe), br#"{"record":{}}"#);
    let cases: Vec<Box<dyn Fn(&mut MetaOp)>> = vec![
        Box::new(move |o| o.pay_ref = HexBinary::from(other_ref)),
        Box::new(|o| o.lane = HexBinary::from(vec![1; 32])),
        Box::new(|o| o.nonce = 1),
        Box::new(|o| o.relayer = String::new()),
        Box::new(|o| o.op = "revoke".into()),
    ];
    for f in cases {
        let mut o = good.clone();
        f(&mut o);
        assert!(why(relay_fee(&mut w, &r, &relayer, &r.probe.clone(), RECORD, &o, &alice)).contains("relayfee: the payment is not bound to this call"));
    }
    // Other call bytes than the signed ref.
    assert!(why(relay_fee(&mut w, &r, &relayer, &r.probe.clone(), br#"{"record":{}}"#, &good, &alice)).contains("relayfee: the payment is not bound to this call"));
    // A payment signed on another chain: the router's ref uses this chain's id, so it does not match either.
    let mut o = good.clone();
    o.network = "other-1".into();
    assert!(why(relay_fee(&mut w, &r, &relayer, &r.probe.clone(), RECORD, &o, &alice)).contains("metaop: signed for another network"));
    assert_eq!(seen(&w, &r.probe), None);
    relay_fee(&mut w, &r, &relayer, &r.probe.clone(), RECORD, &good, &alice).unwrap();
}

/// Rule 6: an attacker's 0-amount router payment with the victim's ref does not block the victim's payment.
#[test]
fn relay_fee_attacker_cannot_pre_burn_ref() {
    let mut w = world();
    let r = rf(&mut w);
    let (a, b, relayer, t1) = (w.alice.addr(&w.app), w.bob.addr(&w.app), w.relayer.clone(), w.t1.clone());
    let grief = fee_op(&w, &r, &t1, &b, &r.probe, RECORD, r.router.as_str(), 0);
    let victim = fee_op(&w, &r, &t1, &a, &r.probe, RECORD, r.router.as_str(), 30);
    assert_eq!(grief.pay_ref, victim.pay_ref);
    let bob = K1::new(9);
    relay_fee(&mut w, &r, &b, &r.probe.clone(), RECORD, &grief, &bob).unwrap();
    let alice = K1::new(7);
    relay_fee(&mut w, &r, &relayer, &r.probe.clone(), RECORD, &victim, &alice).unwrap();
    assert_eq!(balance(&w.app, &t1, relayer.as_str()), 30);
}

/// CTR-MTX-27 conformance: re-entry into the router (a target calling `Relay` back) is refused.
#[test]
fn relay_fee_reentry_refused() {
    let mut w = world();
    let r = rf(&mut w);
    let (a, b, relayer, t1) = (w.alice.addr(&w.app), w.bob.addr(&w.app), w.relayer.clone(), w.t1.clone());
    let inner = fee_op(&w, &r, &t1, &b, &r.probe, RECORD, r.router.as_str(), 1);
    let ip = to_json_vec(&inner).unwrap();
    let nested = scaas_relayfee::ExecuteMsg::Relay {
        target: r.probe.to_string(),
        msg: RECORD.to_vec().into(),
        token: t1.to_string(),
        payload: ip.clone().into(),
        auth: w.bob.auth(&ip, b.as_str()),
    };
    let call = serde_json::to_vec(&serde_json::json!({"call": {"contract": r.router.as_str(),
        "msg": Binary::from(cosmwasm_std::to_json_vec(&nested).unwrap()).to_base64()}})).unwrap();
    let o = fee_op(&w, &r, &t1, &a, &r.probe, &call, r.router.as_str(), 1);
    let alice = K1::new(7);
    assert!(why(relay_fee(&mut w, &r, &relayer, &r.probe.clone(), &call, &o, &alice)).contains("relayfee: re-entry"));
    // The lock does not outlive a relay: the nested payment works on its own afterwards.
    let bob = K1::new(9);
    relay_fee(&mut w, &r, &relayer, &r.probe.clone(), RECORD, &inner, &bob).unwrap();
}
