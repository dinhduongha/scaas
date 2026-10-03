extern crate std;

use super::*;
use bamboo_token::{Token, TokenClient};
use soroban_sdk::testutils::{Address as _, AuthorizedFunction, Ledger};
use soroban_sdk::{String, Symbol};

const NOW: u64 = 1_800_000_000;

struct T {
    env: Env,
    dex: DexClient<'static>,
    a: TokenClient<'static>,
    b: TokenClient<'static>,
    alice: Address,
    bob: Address,
    fees: Address,
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
        let id = env.register(Token, (admin.clone(), 7u32, String::from_str(&env, s), String::from_str(&env, s)));
        TokenClient::new(&env, &id)
    };
    let (a, b) = (mk("A"), mk("B"));
    let fees = Address::generate(&env);
    let dex = DexClient::new(&env, &env.register(Dex, (admin.clone(), fees.clone())));
    dex.set_market(&a.address, &b.address, &Market { maker_fee_ppm: 1_000, taker_fee_ppm: 2_000, fee_on });
    let (alice, bob) = (Address::generate(&env), Address::generate(&env));
    a.mint(&alice, &1_000_000);
    b.mint(&bob, &1_000_000);
    a.approve(&alice, &dex.address, &1_000_000, &1_000);
    b.approve(&bob, &dex.address, &1_000_000, &1_000);
    T { env, dex, a, b, alice, bob, fees }
}

impl T {
    /// alice sells A for B at 1 A = 2 B.
    fn ask(&self, sell: i128, fee: u32) -> Order {
        Order { maker: self.alice.clone(), sell_token: self.a.address.clone(), sell_amount: sell,
                buy_token: self.b.address.clone(), buy_amount: 2 * sell, max_fee_ppm: fee, expiry: NOW + 60, salt: 1 }
    }
    /// bob buys A with B, paying at most `price` B per A.
    fn bid(&self, want_a: i128, price: i128, fee: u32) -> Order {
        Order { maker: self.bob.clone(), sell_token: self.b.address.clone(), sell_amount: want_a * price,
                buy_token: self.a.address.clone(), buy_amount: want_a, max_fee_ppm: fee, expiry: NOW + 60, salt: 2 }
    }
}

fn code(e: Result<Result<(), soroban_sdk::ConversionError>, Result<soroban_sdk::Error, soroban_sdk::InvokeError>>) -> soroban_sdk::Error {
    e.err().unwrap().unwrap()
}

#[test]
fn settles_both_signed_orders_with_fees() {
    let t = setup(true);
    let (ask, bid) = (t.ask(1_000, 10_000), t.bid(1_000, 3, 10_000));
    t.dex.settle(&ask, &bid, &400);
    // Both makers authorised exactly their own order (require_auth_for_args).
    let auths = t.env.auths();
    let signed: std::vec::Vec<_> = auths.iter().map(|(who, inv)| {
        let AuthorizedFunction::Contract((_, f, args)) = &inv.function else { panic!() };
        assert_eq!(*f, Symbol::new(&t.env, "settle"));
        (who.clone(), args.len())
    }).collect();
    assert_eq!(signed, std::vec![(t.alice.clone(), 1), (t.bob.clone(), 1)]);
    // Fees round down: 0.1 % of 800 and 0.2 % of 400 are 0.
    assert_eq!(t.b.balance(&t.alice), 800);
    assert_eq!(t.a.balance(&t.bob), 400);
    assert_eq!((t.b.balance(&t.fees), t.a.balance(&t.fees)), (0, 0));
    let t = setup(true);
    let (ask, bid) = (t.ask(100_000, 10_000), t.bid(100_000, 3, 10_000));
    t.dex.settle(&ask, &bid, &100_000);
    // alice gets 200 000 B minus 0.1 %, bob gets 100 000 A minus 0.2 %.
    assert_eq!(t.b.balance(&t.alice), 200_000 - 200);
    assert_eq!(t.a.balance(&t.bob), 100_000 - 200);
    assert_eq!((t.b.balance(&t.fees), t.a.balance(&t.fees)), (200, 200));
    assert_eq!(t.b.balance(&t.bob), 1_000_000 - 200_000, "bob paid the maker's price, not his limit");
}

#[test]
fn partial_fills_never_overfill() {
    let t = setup(false);
    let (ask, bid) = (t.ask(1_000, 0), t.bid(5_000, 2, 0));
    t.dex.settle(&ask, &bid, &600);
    assert_eq!(t.dex.filled(&t.dex.order_hash(&ask)), 600);
    assert_eq!(code(t.dex.try_settle(&ask, &bid, &401)), Error::Overfill.into());
    t.dex.settle(&ask, &bid, &400);
    assert_eq!(t.a.balance(&t.bob), 1_000);
    assert_eq!(code(t.dex.try_settle(&ask, &bid, &1)), Error::Overfill.into());
}

#[test]
fn price_limits_and_expiry() {
    let t = setup(false);
    // bob only pays 1 B per A: below alice's 2.
    assert_eq!(code(t.dex.try_settle(&t.ask(1_000, 0), &t.bid(1_000, 1, 0), &10)), Error::PriceLimit.into());
    let mut ask = t.ask(1_000, 0);
    ask.expiry = NOW - 1;
    assert_eq!(code(t.dex.try_settle(&ask, &t.bid(1_000, 3, 0), &10)), Error::Expired.into());
    let mut bid = t.bid(1_000, 3, 0);
    bid.buy_token = t.b.address.clone();
    assert_eq!(code(t.dex.try_settle(&t.ask(1_000, 0), &bid, &10)), Error::TokenMismatch.into());
    assert_eq!(code(t.dex.try_settle(&t.ask(1_000, 0), &t.bid(1_000, 3, 0), &0)), Error::BadAmount.into());
}

#[test]
fn fee_inside_signed_max_and_under_cap() {
    let t = setup(true);
    // alice accepts at most 0.05 % but the market charges makers 0.1 %.
    assert_eq!(code(t.dex.try_settle(&t.ask(1_000, 500), &t.bid(1_000, 3, 10_000), &10)), Error::FeeAboveSigned.into());
    let m = Market { maker_fee_ppm: 10_001, taker_fee_ppm: 0, fee_on: true };
    assert!(t.dex.try_set_market(&t.a.address, &t.b.address, &m).is_err());
    // Fees off: a zero max fee is fine.
    let t = setup(false);
    t.dex.settle(&t.ask(1_000, 0), &t.bid(1_000, 3, 0), &10);
}

#[test]
fn cancelled_order_never_settles() {
    let t = setup(false);
    let ask = t.ask(1_000, 0);
    t.dex.cancel(&ask);
    assert_eq!(t.env.auths()[0].0, t.alice);
    assert_eq!(code(t.dex.try_settle(&ask, &t.bid(1_000, 3, 0), &1)), Error::Overfill.into());
}

#[test]
fn unknown_market_is_refused() {
    let t = setup(false);
    let other = t.env.register(Token, (t.alice.clone(), 7u32, String::from_str(&t.env, "C"), String::from_str(&t.env, "C")));
    let mut ask = t.ask(10, 0);
    ask.buy_token = other.clone();
    let mut bid = t.bid(10, 3, 0);
    bid.sell_token = other;
    assert_eq!(code(t.dex.try_settle(&ask, &bid, &1)), Error::UnknownMarket.into());
}
