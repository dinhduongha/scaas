//! cw-multi-test: token meta-tx (adr036 + passkey), anti-lock (R62), allowance R26, mandate R25, DEX R35,
//! và vector chéo với Odoo (`test_fam_cosmos.py`) và adapter Rust (`adapters/cosmos.rs`).
// Test helpers mirror the signed-op fields one-to-one; bundling them would hide what each test signs.
#![allow(clippy::too_many_arguments, clippy::type_complexity)]
use scaas_metaop::{adr036_doc, base64url, passkey_account, secp256k1_account, sha256, Auth, MetaOp, DOMAIN};
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
    let got = format!(
        "from={from}\nto={to}\ncontract={contract}\npayload={}\ndigest={}\ndoc_sha256={}\nsig={}",
        String::from_utf8(p.clone()).unwrap(),
        HexBinary::from(sha256(&p)).to_hex(),
        HexBinary::from(sha256(&doc)).to_hex(),
        Binary::from(sig.clone()).to_base64()
    );
    println!("{got}");
    assert_eq!(got, include_str!("vector.txt").trim_end());
}
