extern crate std;

use super::*;
use scaas_token::{Token, TokenClient};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::String;

const NOW: u64 = 1_800_000_000;

struct T {
    env: Env,
    token: TokenClient<'static>,
    w: MandateWalletClient<'static>,
    owner: Address,
    delegate: Address,
    payee: Address,
}

fn setup() -> T {
    let env = Env::default();
    env.ledger().with_mut(|l| {
        l.timestamp = NOW;
        l.sequence_number = 10;
    });
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let tid = env.register(Token, (admin, 7u32, String::from_str(&env, "B"), String::from_str(&env, "B")));
    let token = TokenClient::new(&env, &tid);
    let owner = Address::generate(&env);
    let wid = env.register(MandateWallet, (owner.clone(),));
    let w = MandateWalletClient::new(&env, &wid);
    token.mint(&wid, &1_000);
    let (delegate, payee) = (Address::generate(&env), Address::generate(&env));
    w.set_mandate(&tid, &delegate, &100, &150, &3600, &(NOW + 86_400));
    w.set_payee(&tid, &payee, &true);
    T { env, token, w, owner, delegate, payee }
}

fn r(env: &Env, b: u8) -> BytesN<32> {
    BytesN::from_array(env, &[b; 32])
}

#[test]
fn delegate_pays_within_caps_and_period_resets() {
    let t = setup();
    let e = &t.env;
    t.w.pay_under_mandate(&t.token.address, &t.payee, &100, &r(e, 1), &(NOW + 60));
    assert_eq!(e.auths()[0].0, t.delegate, "the delegate authorises, not the owner");
    assert_eq!(t.token.balance(&t.payee), 100);
    assert!(t.token.ref_used(&r(e, 1)));
    let err = |res: Result<Result<(), _>, Result<soroban_sdk::Error, _>>| res.err().unwrap().unwrap();
    assert_eq!(err(t.w.try_pay_under_mandate(&t.token.address, &t.payee, &101, &r(e, 2), &(NOW + 60))), Error::OverPaymentCap.into());
    assert_eq!(err(t.w.try_pay_under_mandate(&t.token.address, &t.payee, &60, &r(e, 2), &(NOW + 60))), Error::OverPeriodCap.into());
    assert_eq!(err(t.w.try_pay_under_mandate(&t.token.address, &t.payee, &10, &r(e, 1), &(NOW + 60))), Error::RefAlreadyPaid.into());
    let stranger = Address::generate(e);
    assert_eq!(err(t.w.try_pay_under_mandate(&t.token.address, &stranger, &10, &r(e, 3), &(NOW + 60))), Error::PayeeNotAllowed.into());
    e.ledger().with_mut(|l| l.timestamp = NOW + 3600);
    t.w.pay_under_mandate(&t.token.address, &t.payee, &60, &r(e, 2), &(NOW + 3700));
    assert_eq!(t.token.balance(&t.payee), 160);
    // Signature expiry is enforced by the token.
    assert!(t.w.try_pay_under_mandate(&t.token.address, &t.payee, &1, &r(e, 4), &(NOW + 10)).is_err());
    e.ledger().with_mut(|l| l.timestamp = NOW + 86_401);
    assert_eq!(err(t.w.try_pay_under_mandate(&t.token.address, &t.payee, &1, &r(e, 5), &(NOW + 90_000))), Error::MandateExpired.into());
}

#[test]
fn owner_or_delegate_revokes_nobody_else() {
    let t = setup();
    let e = &t.env;
    let stranger = Address::generate(e);
    assert!(t.w.try_revoke(&t.token.address, &stranger).is_err());
    t.w.revoke(&t.token.address, &t.delegate);
    assert_eq!(t.w.mandate(&t.token.address), None);
    assert!(t.w.try_pay_under_mandate(&t.token.address, &t.payee, &1, &r(e, 1), &(NOW + 60)).is_err());
    t.w.set_mandate(&t.token.address, &t.delegate, &10, &10, &60, &(NOW + 60));
    t.w.revoke(&t.token.address, &t.owner);
    assert_eq!(e.auths()[0].0, t.owner);
}

#[test]
fn bad_mandates_are_refused_and_owner_withdraws() {
    let t = setup();
    let e = &t.env;
    assert!(t.w.try_set_mandate(&t.token.address, &t.delegate, &10, &10, &0, &(NOW + 60)).is_err());
    assert!(t.w.try_set_mandate(&t.token.address, &t.delegate, &11, &10, &60, &(NOW + 60)).is_err());
    t.w.withdraw(&t.token.address, &t.owner, &400);
    assert_eq!(e.auths()[0].0, t.owner);
    assert_eq!((t.token.balance(&t.owner), t.token.balance(&t.w.address)), (400, 600));
}

#[test]
fn unbounded_period_never_overflows() {
    let t = setup();
    let e = &t.env;
    t.w.set_mandate(&t.token.address, &t.delegate, &100, &150, &u64::MAX, &(NOW + 86_400));
    t.w.pay_under_mandate(&t.token.address, &t.payee, &100, &r(e, 1), &(NOW + 60));
    e.ledger().with_mut(|l| l.timestamp = NOW + 80_000);
    let err = |res: Result<Result<(), _>, Result<soroban_sdk::Error, _>>| res.err().unwrap().unwrap();
    assert_eq!(err(t.w.try_pay_under_mandate(&t.token.address, &t.payee, &60, &r(e, 2), &(NOW + 80_060))), Error::OverPeriodCap.into());
}
