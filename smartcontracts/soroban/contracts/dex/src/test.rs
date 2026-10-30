extern crate std;
use std::{vec, vec::Vec as StdVec};

use super::*;
use ed25519_dalek::Signer as _;
use scaas_token::{Token, TokenClient};
use scaas_ua_common::{h32, op_digest, UaAttrs, PURPOSE_METATX, PURPOSE_POP_V2, PURPOSE_TRADE};
use scaas_ua_registry::{UaRegistry, UaRegistryClient as RegClient};
use serde_json::Value;
use soroban_sdk::testutils::{Address as _, AuthorizedFunction, Ledger, MockAuth, MockAuthInvoke};
use soroban_sdk::xdr::{Limits, ReadXdr as _, ScVal};
use soroban_sdk::{String, Symbol, TryFromVal, Val, Vec as SVec};

const NOW: u64 = 1_800_000_000;

struct T {
    env: Env,
    dex: DexClient<'static>,
    a: TokenClient<'static>,
    b: TokenClient<'static>,
    alice: Address,
    bob: Address,
    fees: Address,
    relayer: Address,
    no: Bytes,
}

fn setup(fee_on: bool) -> T {
    let env = Env::default();
    env.ledger().with_mut(|l| {
        l.timestamp = NOW;
        l.sequence_number = 10;
    });
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let mk = |s: &str| {
        let id = env.register(Token, (admin.clone(), 7u32, String::from_str(&env, s), String::from_str(&env, s), None::<Address>));
        TokenClient::new(&env, &id)
    };
    let (a, b) = (mk("A"), mk("B"));
    let fees = Address::generate(&env);
    let dex = DexClient::new(&env, &env.register(Dex, (admin.clone(), fees.clone(), None::<Address>)));
    dex.set_market(&a.address, &b.address, &Market { maker_fee_ppm: 1_000, taker_fee_ppm: 2_000, fee_on });
    let (alice, bob) = (Address::generate(&env), Address::generate(&env));
    a.mint(&alice, &1_000_000);
    b.mint(&bob, &1_000_000);
    a.approve(&alice, &dex.address, &1_000_000, &1_000);
    b.approve(&bob, &dex.address, &1_000_000, &1_000);
    let (relayer, no) = (Address::generate(&env), Bytes::new(&env));
    T { env, dex, a, b, alice, bob, fees, relayer, no }
}

impl T {
    /// alice sells A for B at 1 A = 2 B.
    fn ask(&self, sell: i128, fee: u32) -> Order {
        let me = Holder::Addr(self.alice.clone());
        Order { maker: me.clone(), destination: me, relayer: self.relayer.clone(), sell_token: self.a.address.clone(),
                sell_amount: sell, buy_token: self.b.address.clone(), buy_amount: 2 * sell, max_fee_ppm: fee,
                expiry: NOW + 60, salt: 1 }
    }
    /// bob buys A with B, paying at most `price` B per A.
    fn bid(&self, want_a: i128, price: i128, fee: u32) -> Order {
        let me = Holder::Addr(self.bob.clone());
        Order { maker: me.clone(), destination: me, relayer: self.relayer.clone(), sell_token: self.b.address.clone(),
                sell_amount: want_a * price, buy_token: self.a.address.clone(), buy_amount: want_a, max_fee_ppm: fee,
                expiry: NOW + 60, salt: 2 }
    }
    fn settle(&self, m: &Order, t: &Order, fill: i128) {
        self.dex.settle(m, t, &fill, &self.no, &self.no);
    }
    fn try_settle(&self, m: &Order, t: &Order, fill: i128) -> soroban_sdk::Error {
        code(self.dex.try_settle(m, t, &fill, &self.no, &self.no))
    }
}

fn code(e: Result<Result<(), soroban_sdk::ConversionError>, Result<soroban_sdk::Error, soroban_sdk::InvokeError>>) -> soroban_sdk::Error {
    e.err().unwrap().unwrap()
}

#[test]
fn settles_both_signed_orders_with_fees() {
    let t = setup(true);
    let (ask, bid) = (t.ask(1_000, 10_000), t.bid(1_000, 3, 10_000));
    t.settle(&ask, &bid, 400);
    // The relayer authorised the whole call, both makers exactly their own order (require_auth_for_args).
    let auths = t.env.auths();
    let signed: StdVec<_> = auths.iter().map(|(who, inv)| {
        let AuthorizedFunction::Contract((_, f, args)) = &inv.function else { panic!() };
        assert_eq!(*f, Symbol::new(&t.env, "settle"));
        (who.clone(), args.len())
    }).collect();
    assert_eq!(signed, vec![(t.relayer.clone(), 5), (t.alice.clone(), 1), (t.bob.clone(), 1)]);
    // Fees round down: 0.1 % of 800 and 0.2 % of 400 are 0.
    assert_eq!(t.b.balance(&t.alice), 800);
    assert_eq!(t.a.balance(&t.bob), 400);
    assert_eq!((t.b.balance(&t.fees), t.a.balance(&t.fees)), (0, 0));
    let t = setup(true);
    let (ask, bid) = (t.ask(100_000, 10_000), t.bid(100_000, 3, 10_000));
    t.settle(&ask, &bid, 100_000);
    // alice gets 200 000 B minus 0.1 %, bob gets 100 000 A minus 0.2 %.
    assert_eq!(t.b.balance(&t.alice), 200_000 - 200);
    assert_eq!(t.a.balance(&t.bob), 100_000 - 200);
    assert_eq!((t.b.balance(&t.fees), t.a.balance(&t.fees)), (200, 200));
    assert_eq!(t.b.balance(&t.bob), 1_000_000 - 200_000, "bob paid the maker's price, not his limit");
    assert_eq!((t.a.balance(&t.dex.address), t.b.balance(&t.dex.address)), (0, 0), "the DEX keeps nothing");
}

#[test]
fn partial_fills_never_overfill() {
    let t = setup(false);
    let (ask, bid) = (t.ask(1_000, 0), t.bid(5_000, 2, 0));
    t.settle(&ask, &bid, 600);
    assert_eq!(t.dex.filled(&t.dex.order_hash(&ask)), 600);
    assert_eq!(t.try_settle(&ask, &bid, 401), Error::Overfill.into());
    t.settle(&ask, &bid, 400);
    assert_eq!(t.a.balance(&t.bob), 1_000);
    assert_eq!(t.try_settle(&ask, &bid, 1), Error::Overfill.into());
}

#[test]
fn price_limits_and_expiry() {
    let t = setup(false);
    // bob only pays 1 B per A: below alice's 2.
    assert_eq!(t.try_settle(&t.ask(1_000, 0), &t.bid(1_000, 1, 0), 10), Error::PriceLimit.into());
    let mut ask = t.ask(1_000, 0);
    ask.expiry = NOW - 1;
    assert_eq!(t.try_settle(&ask, &t.bid(1_000, 3, 0), 10), Error::Expired.into());
    let mut bid = t.bid(1_000, 3, 0);
    bid.buy_token = t.b.address.clone();
    assert_eq!(t.try_settle(&t.ask(1_000, 0), &bid, 10), Error::TokenMismatch.into());
    assert_eq!(t.try_settle(&t.ask(1_000, 0), &t.bid(1_000, 3, 0), 0), Error::BadAmount.into());
}

#[test]
fn fee_inside_signed_max_and_under_cap() {
    let t = setup(true);
    // alice accepts at most 0.05 % but the market charges makers 0.1 %.
    assert_eq!(t.try_settle(&t.ask(1_000, 500), &t.bid(1_000, 3, 10_000), 10), Error::FeeAboveSigned.into());
    let m = Market { maker_fee_ppm: 10_001, taker_fee_ppm: 0, fee_on: true };
    assert!(t.dex.try_set_market(&t.a.address, &t.b.address, &m).is_err());
    // Fees off: a zero max fee is fine.
    let t = setup(false);
    t.settle(&t.ask(1_000, 0), &t.bid(1_000, 3, 0), 10);
}

#[test]
fn cancelled_order_never_settles() {
    let t = setup(false);
    let ask = t.ask(1_000, 0);
    t.dex.cancel(&ask);
    assert_eq!(t.env.auths()[0].0, t.alice);
    assert_eq!(t.try_settle(&ask, &t.bid(1_000, 3, 0), 1), Error::Overfill.into());
}

#[test]
fn unknown_market_is_refused() {
    let t = setup(false);
    let other = t.env.register(Token, (t.alice.clone(), 7u32, String::from_str(&t.env, "C"), String::from_str(&t.env, "C"), None::<Address>));
    let mut ask = t.ask(10, 0);
    ask.buy_token = other.clone();
    let mut bid = t.bid(10, 3, 0);
    bid.sell_token = other;
    assert_eq!(t.try_settle(&ask, &bid, 1), Error::UnknownMarket.into());
}

#[test]
fn taker_must_name_a_positive_price() {
    let t = setup(false);
    let mut bid = t.bid(1_000, 3, 0);
    bid.buy_amount = 0;
    assert_eq!(t.try_settle(&t.ask(1_000, 0), &bid, 10), Error::BadAmount.into());
}

#[test]
fn same_token_order_cannot_match_itself() {
    let t = setup(false);
    t.dex.set_market(&t.a.address, &t.a.address, &Market { maker_fee_ppm: 0, taker_fee_ppm: 0, fee_on: false });
    let mut o = t.ask(1_000, 0);
    o.buy_token = t.a.address.clone();
    o.buy_amount = 1_000;
    assert_eq!(t.try_settle(&o, &o, 600), Error::TokenMismatch.into());
}

#[test]
fn eighteen_decimal_amounts_do_not_overflow() {
    let t = setup(false);
    let e18: i128 = 1_000_000_000_000_000_000;
    t.a.mint(&t.alice, &(1_000 * e18));
    t.b.mint(&t.bob, &(3_000 * e18));
    t.a.approve(&t.alice, &t.dex.address, &(1_000 * e18), &1_000);
    t.b.approve(&t.bob, &t.dex.address, &(3_000 * e18), &1_000);
    // 100 A × 200 B at 18 decimals: the i128 product 1e20 × 2e20 overflows.
    t.settle(&t.ask(100 * e18, 0), &t.bid(100 * e18, 3, 0), 100 * e18);
    assert_eq!(t.b.balance(&t.alice), 200 * e18);
}

#[test]
fn native_leg_with_auth_is_refused() {
    let t = setup(false);
    let junk = Bytes::from_array(&t.env, &[1]);
    let r = t.dex.try_settle(&t.ask(1_000, 0), &t.bid(1_000, 3, 0), &10, &junk, &t.no);
    assert_eq!(code(r), Error::BadAuth.into());
}

// ---------------------------------------------------------------- UA legs (spec §5.3, SOR-D10)
//
// The real `UaRegistry` and tokens bound to it at `ua-ops.json`'s ids and network id, in-test ed25519 UAs. No
// `mock_all_auths` once set up: the relayer and each native maker are mocked for exactly the call (`settle_as`), a UA
// signs for real.

const OPS: &str = include_str!("../../../vectors/ua-ops.json");
const ED25519: u32 = 0x0102;
/// `keccak256("scaas.ua.msg.v1")` and `TAG(ed25519)` (CTR-UA-12, `kinds.json`).
const MSG_TAG: [u8; 32] = h32("30a5cfd6b1d0889ef4a90d8488fa5e6e615322735899e23243d69087b6b66349");
const ED_TAG: [u8; 32] = h32("65ca73d2d290503a4785188712dd0b971b5fbf3113c1dc87185a46021b5131bc");

fn hx(v: &Value) -> StdVec<u8> {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn ops() -> Value {
    serde_json::from_str(OPS).unwrap()
}

fn keccak(env: &Env, parts: &[&[u8]]) -> [u8; 32] {
    let mut b = Bytes::new(env);
    for p in parts {
        b.extend_from_slice(p);
    }
    env.crypto().keccak256(&b).to_array()
}

/// The contract address `C…` whose 32-byte id is `byte` repeated (the vectors' buy token is `0x77…`).
fn contract_at(env: &Env, byte: u8) -> Address {
    let mut x = vec![0, 0, 0, 0x12, 0, 0, 0, 1];
    x.extend([byte; 32]);
    Address::try_from_val(env, &ScVal::from_xdr(x, Limits::none()).unwrap()).unwrap()
}

fn tok(e: scaas_token::Error) -> soroban_sdk::Error {
    e.into()
}

/// An in-test ed25519 UA, registered by its real `pop` (CTR-UA-07).
struct Ua {
    sk: ed25519_dalek::SigningKey,
    id: BytesN<32>,
}

impl Ua {
    fn h(&self) -> Holder {
        Holder::Ua(self.id.clone())
    }
}

struct U {
    env: Env,
    reg: RegClient<'static>,
    dex: DexClient<'static>,
    /// Sold by the UA makers (the vectors' token id); `b` is bought (the vectors' `0x77…` id).
    a: TokenClient<'static>,
    b: TokenClient<'static>,
    admin: Address,
    fees: Address,
    relayer: Address,
    /// A native taker holding 1 000 000 B, the DEX approved.
    bob: Address,
}

fn ua_setup(fee_on: bool) -> U {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let o = ops();
    env.ledger().with_mut(|l| {
        l.sequence_number = 100;
        l.timestamp = NOW;
        l.network_id = hx(&o["network"]["networkId"]).try_into().unwrap();
    });
    let id = |k: &str| Address::from_str(&env, o["contracts"][k].as_str().unwrap());
    let reg = RegClient::new(&env, &env.register_at(&id("registry"), UaRegistry, (SVec::<Address>::new(&env),)));
    let admin = Address::generate(&env);
    let s = |x: &str| String::from_str(&env, x);
    let r = Some(reg.address.clone());
    let a = TokenClient::new(&env, &env.register_at(&id("token"), Token, (admin.clone(), 7u32, s("A"), s("A"), r.clone())));
    let b = TokenClient::new(&env, &env.register_at(&contract_at(&env, 0x77), Token, (admin.clone(), 7u32, s("B"), s("B"), r.clone())));
    let fees = Address::generate(&env);
    let dex = DexClient::new(&env, &env.register_at(&id("dex"), Dex, (admin.clone(), fees.clone(), r)));
    let (relayer, bob) = (Address::generate(&env), Address::generate(&env));
    // Set-up only; every call under test below mocks exactly its own authorities.
    env.mock_all_auths();
    dex.set_market(&a.address, &b.address, &Market { maker_fee_ppm: 1_000, taker_fee_ppm: 2_000, fee_on });
    b.mint(&bob, &1_000_000);
    b.approve(&bob, &dex.address, &1_000_000, &1_000);
    env.set_auths(&[]);
    U { env, reg, dex, a, b, admin, fees, relayer, bob }
}

impl U {
    fn ua(&self, seed: u8) -> Ua {
        let env = &self.env;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let kd = Bytes::from_array(env, &sk.verifying_key().to_bytes());
        let id = self.reg.ua_of(&ED25519, &kd);
        let z = [0u8; 32];
        let reg_digest = keccak(env, &[&keccak(env, &[&PURPOSE_POP_V2, &id.to_array(), &z, &z]), &z]);
        let pop = sk.sign(&keccak(env, &[&MSG_TAG, &ED_TAG, &PURPOSE_POP_V2, &reg_digest])).to_bytes();
        self.reg.register(&ED25519, &kd, &no_attrs(env), &Bytes::from_array(env, &pop), &Bytes::new(env), &None);
        Ua { sk, id }
    }

    /// `amount` of `token` into `ua`'s UA balance (the admin mocked for exactly this mint).
    fn fund(&self, token: &TokenClient, ua: &BytesN<32>, amount: i128) {
        let env = &self.env;
        let args: SVec<Val> = (ua, amount).into_val(env);
        env.mock_auths(&[MockAuth { address: &self.admin, invoke: &MockAuthInvoke { contract: &token.address, fn_name: "mint_to_ua", args, sub_invokes: &[] } }]);
        token.mint_to_ua(ua, &amount);
    }

    /// `maker` sells `sell` A for `2 × sell` B, proceeds to `dest`.
    fn ask(&self, maker: Holder, sell: i128, dest: Holder) -> Order {
        Order { maker, destination: dest, relayer: self.relayer.clone(), sell_token: self.a.address.clone(),
                sell_amount: sell, buy_token: self.b.address.clone(), buy_amount: 2 * sell, max_fee_ppm: 10_000,
                expiry: NOW + 60, salt: 1 }
    }

    /// bob buys up to `want` A at 2 B each, proceeds to `dest`.
    fn bid(&self, want: i128, dest: Holder) -> Order {
        Order { maker: Holder::Addr(self.bob.clone()), destination: dest, relayer: self.relayer.clone(),
                sell_token: self.b.address.clone(), sell_amount: 2 * want, buy_token: self.a.address.clone(),
                buy_amount: want, max_fee_ppm: 10_000, expiry: NOW + 60, salt: 2 }
    }

    /// `u`'s signature over `op_digest(contract, f, args)` under `purpose`.
    fn sign(&self, u: &Ua, purpose: [u8; 32], contract: &Address, f: &str, args: SVec<Val>) -> Bytes {
        let d = op_digest(&self.env, contract, f, args).to_array();
        Bytes::from_array(&self.env, &u.sk.sign(&keccak(&self.env, &[&MSG_TAG, &ED_TAG, &purpose, &d])).to_bytes())
    }

    /// The UA maker's order signature for `dex`: the sell token's `ua_trade` digest, purpose `trade`.
    fn sign_order(&self, u: &Ua, dex: &Address, o: &Order) -> Bytes {
        self.sign(u, PURPOSE_TRADE, &o.sell_token, "ua_order", (dex, o).into_val(&self.env))
    }

    /// `settle` on `dex` with the relayer(s) the orders name and each native maker mocked for exactly this call.
    fn settle(&self, dex: &DexClient, m: &Order, t: &Order, fill: i128, ma: &Bytes, ta: &Bytes) -> Result<(), soroban_sdk::Error> {
        let mut rs = vec![m.relayer.clone()];
        if t.relayer != m.relayer {
            rs.push(t.relayer.clone());
        }
        self.settle_as(&rs, dex, m, t, fill, ma, ta)
    }

    /// `settle` with `relayers` (not necessarily the ones the orders name) and each native maker mocked.
    #[allow(clippy::too_many_arguments)]
    fn settle_as(&self, relayers: &[Address], dex: &DexClient, m: &Order, t: &Order, fill: i128, ma: &Bytes, ta: &Bytes) -> Result<(), soroban_sdk::Error> {
        let env = &self.env;
        let all: SVec<Val> = (m, t, fill, ma, ta).into_val(env);
        let mut who: StdVec<(Address, SVec<Val>)> = relayers.iter().map(|r| (r.clone(), all.clone())).collect();
        for o in [m, t] {
            if let Holder::Addr(a) = &o.maker {
                who.push((a.clone(), (o.clone(),).into_val(env)));
            }
        }
        let inv: StdVec<MockAuthInvoke> =
            who.iter().map(|(_, args)| MockAuthInvoke { contract: &dex.address, fn_name: "settle", args: args.clone(), sub_invokes: &[] }).collect();
        let mocks: StdVec<MockAuth> = who.iter().zip(&inv).map(|((a, _), i)| MockAuth { address: a, invoke: i }).collect();
        env.mock_auths(&mocks);
        match dex.try_settle(m, t, &fill, ma, ta) {
            Ok(_) => Ok(()),
            Err(Ok(e)) => Err(e),
            Err(Err(e)) => panic!("settle: {e:?}"),
        }
    }

    /// A second DEX instance with the same market.
    fn other_dex(&self, registry: Option<Address>) -> DexClient<'static> {
        let env = &self.env;
        let d = DexClient::new(env, &env.register(Dex, (self.admin.clone(), self.fees.clone(), registry)));
        let m = Market { maker_fee_ppm: 0, taker_fee_ppm: 0, fee_on: false };
        let args: SVec<Val> = (&self.a.address, &self.b.address, &m).into_val(env);
        env.mock_auths(&[MockAuth { address: &self.admin, invoke: &MockAuthInvoke { contract: &d.address, fn_name: "set_market", args, sub_invokes: &[] } }]);
        d.set_market(&self.a.address, &self.b.address, &m);
        d
    }
}

fn no_attrs(env: &Env) -> UaAttrs {
    UaAttrs { pqz_key: Bytes::new(env), pqz_pop_hash: BytesN::from_array(env, &[0; 32]), kem_version: 0, kem_pk: Bytes::new(env) }
}

/// Property 5 (T7): one UA signature fills an order in three settles up to `sell_amount`; a fourth is `Overfill`; another
/// DEX instance cannot use it; and the token's own `UaPulled` bound holds when the DEX's `filled` would not.
#[test]
fn ua_trade_dex_only_partial_fill_no_resign() {
    let s = ua_setup(false);
    let env = &s.env;
    let u = s.ua(1);
    s.fund(&s.a, &u.id, 1_000);
    let ask = s.ask(u.h(), 300, u.h());
    let auth = s.sign_order(&u, &s.dex.address, &ask);
    let bid = s.bid(1_000, Holder::Addr(s.bob.clone()));
    let no = Bytes::new(env);
    // Another DEX instance: the signature names the first one, so the token refuses it.
    let d2 = s.other_dex(None);
    assert!(s.settle(&d2, &ask, &bid, 100, &auth, &no).is_err());
    for fill in [100, 120, 80] {
        s.settle(&s.dex, &ask, &bid, fill, &auth, &no).unwrap();
    }
    assert_eq!(s.dex.filled(&s.dex.order_hash(&ask)), 300);
    assert_eq!((s.a.ua_balance(&u.id), s.a.balance(&s.bob), s.b.ua_balance(&u.id)), (700, 300, 600));
    assert_eq!(s.settle(&s.dex, &ask, &bid, 1, &auth, &no), Err(Error::Overfill.into()));
    // The DEX's `filled` lost (as if its storage were wrong): the token's `UaPulled` still refuses, and the whole
    // settle rolls back.
    let h = s.dex.order_hash(&ask);
    env.as_contract(&s.dex.address, || env.storage().persistent().set(&Key::Filled(h.clone()), &0i128));
    assert_eq!(s.settle(&s.dex, &ask, &bid, 1, &auth, &no), Err(tok(scaas_token::Error::BadOrder)));
    assert_eq!((s.dex.filled(&h), s.a.ua_balance(&u.id), s.b.balance(&s.bob)), (0, 700, 1_000_000 - 600));
}

#[test]
fn dex_ua_maker_native_taker_settles() {
    let s = ua_setup(true);
    let env = &s.env;
    let u = s.ua(1);
    s.fund(&s.a, &u.id, 100_000);
    let ask = s.ask(u.h(), 100_000, u.h());
    let auth = s.sign_order(&u, &s.dex.address, &ask);
    let bid = s.bid(100_000, Holder::Addr(s.bob.clone()));
    let no = Bytes::new(env);
    // The UA leg needs its signature; the native leg must carry none.
    assert!(s.settle(&s.dex, &ask, &bid, 100_000, &no, &no).is_err());
    assert_eq!(s.settle(&s.dex, &ask, &bid, 100_000, &auth, &auth), Err(Error::BadAuth.into()));
    s.settle(&s.dex, &ask, &bid, 100_000, &auth, &no).unwrap();
    // The UA gets 200 000 B minus 0.1 % in its UA balance, bob 100 000 A minus 0.2 %.
    assert_eq!((s.a.ua_balance(&u.id), s.b.ua_balance(&u.id)), (0, 200_000 - 200));
    assert_eq!((s.a.balance(&s.bob), s.b.balance(&s.bob)), (100_000 - 200, 1_000_000 - 200_000));
    assert_eq!((s.a.balance(&s.fees), s.b.balance(&s.fees)), (200, 200));
    assert_eq!((s.a.balance(&s.dex.address), s.b.balance(&s.dex.address)), (0, 0), "the DEX keeps nothing");
    // The pool holds exactly the UA balances.
    assert_eq!((s.a.balance(&s.a.address), s.b.balance(&s.b.address)), (0, 200_000 - 200));
}

/// NET-SOR-10: an order names its relayer, and only that relayer's submission settles it.
#[test]
fn dex_native_orders_bind_relayer() {
    let s = ua_setup(false);
    let env = &s.env;
    let alice = Address::generate(env);
    env.mock_all_auths();
    s.a.mint(&alice, &1_000);
    s.a.approve(&alice, &s.dex.address, &1_000, &1_000);
    env.set_auths(&[]);
    let ask = s.ask(Holder::Addr(alice.clone()), 100, Holder::Addr(alice.clone()));
    let bid = s.bid(100, Holder::Addr(s.bob.clone()));
    let no = Bytes::new(env);
    let other = Address::generate(env);
    assert!(s.settle_as(&[other.clone()], &s.dex, &ask, &bid, 50, &no, &no).is_err());
    // Each order binds its own relayer: a taker naming `other` needs `other` too.
    let bid_other = Order { relayer: other.clone(), ..bid.clone() };
    assert!(s.settle_as(&[s.relayer.clone()], &s.dex, &ask, &bid_other, 50, &no, &no).is_err());
    assert_eq!(s.dex.filled(&s.dex.order_hash(&ask)), 0);
    s.settle(&s.dex, &ask, &bid, 50, &no, &no).unwrap();
    s.settle(&s.dex, &ask, &bid_other, 50, &no, &no).unwrap();
    assert_eq!((s.a.balance(&s.bob), s.b.balance(&alice)), (100, 200));
}

/// SOR-D10: `ua_cancel` (purpose `trade` over `op_digest(dex, "ua_cancel", (order,))`) sets `filled = sell_amount`.
#[test]
fn dex_ua_cancel_sets_filled() {
    let s = ua_setup(false);
    let env = &s.env;
    let u = s.ua(1);
    s.fund(&s.a, &u.id, 1_000);
    let ask = s.ask(u.h(), 300, u.h());
    let order_auth = s.sign_order(&u, &s.dex.address, &ask);
    let cancel = s.sign(&u, PURPOSE_TRADE, &s.dex.address, "ua_cancel", (&ask,).into_val(env));
    let no = Bytes::new(env);
    let bid = s.bid(1_000, Holder::Addr(s.bob.clone()));
    s.settle(&s.dex, &ask, &bid, 100, &order_auth, &no).unwrap();
    // Not a cancel signature: the order's own, a `metatx` one, another UA's.
    assert!(s.dex.try_ua_cancel(&ask, &order_auth).is_err());
    let metatx = s.sign(&u, PURPOSE_METATX, &s.dex.address, "ua_cancel", (&ask,).into_val(env));
    assert!(s.dex.try_ua_cancel(&ask, &metatx).is_err());
    let v = s.ua(2);
    assert!(s.dex.try_ua_cancel(&ask, &s.sign(&v, PURPOSE_TRADE, &s.dex.address, "ua_cancel", (&ask,).into_val(env))).is_err());
    // A DEX without a registry cannot verify it.
    let d2 = s.other_dex(None);
    assert_eq!(code(d2.try_ua_cancel(&ask, &cancel)), Error::UaLedgerOff.into());
    // Each entry for its own holder kind.
    assert_eq!(code(s.dex.try_cancel(&ask)), Error::BadAuth.into());
    let native = s.ask(Holder::Addr(s.bob.clone()), 300, u.h());
    assert_eq!(code(s.dex.try_ua_cancel(&native, &cancel)), Error::BadAuth.into());
    assert_eq!(s.dex.filled(&s.dex.order_hash(&ask)), 100);
    s.dex.ua_cancel(&ask, &cancel);
    assert_eq!(s.dex.filled(&s.dex.order_hash(&ask)), 300);
    assert_eq!(s.settle(&s.dex, &ask, &bid, 1, &order_auth, &no), Err(Error::Overfill.into()));
}

/// Proceeds go to each order's `destination`: a UA maker's to a native address, a native taker's to a UA.
#[test]
fn dex_ua_destination_receives_proceeds() {
    let s = ua_setup(false);
    let env = &s.env;
    let (u, v) = (s.ua(1), s.ua(2));
    s.fund(&s.a, &u.id, 1_000);
    let carol = Address::generate(env);
    let ask = s.ask(u.h(), 1_000, Holder::Addr(carol.clone()));
    let auth = s.sign_order(&u, &s.dex.address, &ask);
    let bid = s.bid(1_000, v.h());
    s.settle(&s.dex, &ask, &bid, 400, &auth, &Bytes::new(env)).unwrap();
    assert_eq!((s.b.balance(&carol), s.b.ua_balance(&u.id)), (800, 0));
    assert_eq!((s.a.ua_balance(&v.id), s.a.balance(&s.bob), s.a.ua_balance(&u.id)), (400, 0, 600));
    // A destination UA that is not registered: the whole settle fails.
    let ghost = Holder::Ua(BytesN::from_array(env, &[0x42; 32]));
    let bid2 = Order { destination: ghost, salt: 3, ..bid };
    assert!(s.settle(&s.dex, &ask, &bid2, 100, &auth, &Bytes::new(env)).is_err());
    assert_eq!(s.dex.filled(&s.dex.order_hash(&ask)), 400);
}

fn arg_vals(env: &Env, p: &Value) -> SVec<Val> {
    let mut v = SVec::new(env);
    for a in p["args"].as_array().unwrap() {
        let sc = ScVal::from_xdr(hx(&a["xdr"]), Limits::none()).unwrap();
        v.push_back(Val::try_from_val(env, &sc).unwrap());
    }
    v
}

/// The vectors' relayer is a `G…` account, which `mock_auths` cannot stand in for: it is made the transaction's source
/// account and authorises `dex.settle(args)` by a `SourceAccount` entry.
fn settle_by_source(env: &Env, dex: &DexClient, m: &Order, t: &Order, fill: i128, ma: &Bytes, ta: &Bytes) -> Result<(), soroban_sdk::Error> {
    use soroban_sdk::xdr::{
        InvokeContractArgs, ScAddress, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
        SorobanCredentials,
    };
    let ScAddress::Account(acct) = ScAddress::from(&m.relayer) else { panic!("relayer not an account") };
    env.host().set_source_account(acct).unwrap();
    let args: SVec<Val> = (m, t, fill, ma, ta).into_val(env);
    let root = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: (&dex.address).into(),
            function_name: "settle".try_into().unwrap(),
            args: args.iter().map(|v| ScVal::try_from_val(env, &v).unwrap()).collect::<StdVec<_>>().try_into().unwrap(),
        }),
        sub_invocations: Default::default(),
    };
    env.set_auths(&[SorobanAuthorizationEntry { credentials: SorobanCredentials::SourceAccount, root_invocation: root }]);
    match dex.try_settle(m, t, &fill, ma, ta) {
        Ok(_) => Ok(()),
        Err(Ok(e)) => Err(e),
        Err(Err(e)) => panic!("settle: {e:?}"),
    }
}

/// SOR-D12: the DEX, the token and the registry at `ua-ops.json`'s ids and network id. Per kind, the `ua_order` row
/// (the `ua_trade` digest) and the `ua_cancel` row (the DEX's) name the same order; both digests are recomputed, the
/// order's `auth` fills half of it in a real `settle` against an in-test UA taker (the vectors' relayer submitting),
/// and the cancel `auth` runs as `ua_cancel`.
#[test]
fn ua_ops_vectors_ua_trade_rows() {
    let s = ua_setup(false);
    let env = &s.env;
    let v = s.ua(9);
    let o = ops();
    for r in o["registrations"].as_array().unwrap() {
        let kind = r["kind"].as_u64().unwrap() as u32;
        let ua = s.reg.register(&kind, &Bytes::from_slice(env, &hx(&r["keyData"])), &no_attrs(env), &Bytes::from_slice(env, &hx(&r["pop"])), &Bytes::new(env), &None);
        assert_eq!(ua.to_array().to_vec(), hx(&r["ua"]), "{}", r["name"]);
    }
    let row = |name: &str| o["entries"].as_array().unwrap().iter().find(|e| e["name"] == name).unwrap().clone();
    let (ord, can) = (row("ua_order"), row("ua_cancel"));
    assert_eq!((ord["contract"].as_str(), ord["purpose"].as_str()), (o["contracts"]["token"].as_str(), Some("trade")));
    assert_eq!((can["contract"].as_str(), can["purpose"].as_str()), (o["contracts"]["dex"].as_str(), Some("trade")));
    let (op, cp) = (ord["perKind"].as_array().unwrap(), can["perKind"].as_array().unwrap());
    assert_eq!(op.len(), 7);
    for (i, (p, c)) in op.iter().zip(cp).enumerate() {
        assert_eq!(p["kind"], c["kind"]);
        let (pa, ca) = (arg_vals(env, p), arg_vals(env, c));
        assert_eq!(op_digest(env, &s.a.address, "ua_order", pa.clone()).to_array().to_vec(), hx(&p["digest"]), "{}", p["kind"]);
        assert_eq!(op_digest(env, &s.dex.address, "ua_cancel", ca.clone()).to_array().to_vec(), hx(&c["digest"]), "{}", c["kind"]);
        assert_eq!(Address::try_from_val(env, &pa.get(0).unwrap()).unwrap(), s.dex.address);
        let ask = Order::try_from_val(env, &pa.get(1).unwrap()).unwrap();
        assert_eq!(Order::try_from_val(env, &ca.get(0).unwrap()).unwrap(), ask, "{}", c["kind"]);
        let Holder::Ua(ua) = ask.maker.clone() else { panic!() };
        assert_eq!(ua.to_array().to_vec(), hx(&p["ua"]));
        assert_eq!((ask.buy_token.clone(), ask.destination.clone()), (s.b.address.clone(), ask.maker.clone()));
        s.fund(&s.a, &ua, ask.sell_amount);
        s.fund(&s.b, &v.id, ask.buy_amount);
        let bid = Order { maker: v.h(), destination: v.h(), relayer: ask.relayer.clone(), sell_token: ask.buy_token.clone(),
                          sell_amount: ask.buy_amount, buy_token: ask.sell_token.clone(), buy_amount: ask.sell_amount,
                          max_fee_ppm: 0, expiry: NOW + 60, salt: i as u64 };
        let bid_auth = s.sign_order(&v, &s.dex.address, &bid);
        let auth = Bytes::from_slice(env, &hx(&p["auth"]));
        let got = s.a.ua_balance(&v.id);
        settle_by_source(env, &s.dex, &ask, &bid, ask.sell_amount / 2, &auth, &bid_auth).unwrap_or_else(|e| panic!("{} settle: {e:?}", p["kind"]));
        assert_eq!((s.b.ua_balance(&ua), s.a.ua_balance(&v.id) - got), (ask.buy_amount / 2, ask.sell_amount / 2), "{}", p["kind"]);
        s.dex.ua_cancel(&ask, &Bytes::from_slice(env, &hx(&c["auth"])));
        assert_eq!(s.dex.filled(&s.dex.order_hash(&ask)), ask.sell_amount, "{}", c["kind"]);
        assert_eq!(settle_by_source(env, &s.dex, &ask, &bid, 1, &auth, &bid_auth), Err(Error::Overfill.into()));
    }
}
