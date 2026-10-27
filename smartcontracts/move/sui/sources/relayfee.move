/// CTR-MTX-27 on Sui (spec §7.2): a token fee to the relayer for one fee-less signed entry of this package.
/// Move has no dynamic call, so each wrapped entry has a static wrapper `relay_<entry>` that runs the entry by
/// name and then the payer's router payment (`meta::pay_routed`) in the same transaction: any abort of either
/// aborts both. Wrapped today: `meta::manage`, `mandate::revoke_with_sig`, `dex::cancel`,
/// `dex::invalidate_nonces`; a new target is a new wrapper in a new package (NET-SUI-15: the package is immutable).
///
/// `ref = keccak256("scaas.relayfee" ‖ network ‖ package ‖ keccak256(call) ‖ salt)`: `network` = the paying
/// account's network bytes (the root's), `package` = this package's original id (32 bytes), `call` = BCS of the
/// entry's name (`vector<u8>`, e.g. `b"meta::manage"`) followed by the BCS of every argument in order (an object
/// as its id address, the entry's `Auth` included), `salt` = the payment's `extra` (32 bytes, signed by the
/// payer). No sender and no lane in `ref`: any relayer may submit. The payment is the payer's plain pay with
/// `pay_ref = ref`, `lane = payLane(ref)`, `nonce = 0`, `relayer = marker` (the shared `RelayFee` object's
/// address), all derived on chain, so the payer's signature verifies only for this call through this router.
module scaas::relayfee;

use scaas::auth::Auth;
use scaas::dex::{Self, Market, Order};
use scaas::mandate::{Self, Mandate};
use scaas::meta::{Self, Account};
use std::bcs;
use std::type_name;
use sui::clock::Clock;
use sui::event;
use sui::hash::keccak256;

const REF_DOMAIN: vector<u8> = b"scaas.relayfee";

#[error]
const ECallRefused: vector<u8> = b"The wrapped entry refused the call; nothing is paid.";

/// The router marker: one shared object, created in `init`. No transaction sender is an object, so the plain
/// pay entries refuse a payment bound to it (`meta::EWrongRelayer`); it is never paid (open mode pays the sender).
public struct RelayFee has key { id: UID }

/// `token` = the payment's `Registry<T>` id; `payer` = the paying account's owner; `payee` = who was paid.
public struct RelayFeePaid has copy, drop {
    ref: vector<u8>,
    target: address,
    token: ID,
    payer: address,
    payee: address,
    amount: u64,
}

fun init(ctx: &mut TxContext) { transfer::share_object(RelayFee { id: object::new(ctx) }) }

/// `target` of every ref: this package's original id.
public fun package(): address { type_name::original_id<RelayFee>() }

public fun relay_ref(network: vector<u8>, call: vector<u8>, salt: vector<u8>): vector<u8> {
    let mut b = REF_DOMAIN;
    b.append(network);
    b.append(package().to_bytes());
    b.append(keccak256(&call));
    b.append(salt);
    keccak256(&b)
}

/// `meta::manage` on `account`, paid from the same account (one `&mut` per object in a PTB command).
public fun relay_manage<T>(
    rf: &RelayFee,
    account: &mut Account<T>,
    action: u8,
    scheme: u8,
    public_key: vector<u8>,
    rp_id_hash: vector<u8>,
    origin: vector<u8>,
    guardian: address,
    valid_until: u64,
    a: Auth,
    to: address,
    amount: u128,
    pay_valid_until: u64,
    extra: vector<u8>,
    pay_auth: Auth,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let mut c = call(b"meta::manage", object::id_address(account));
    c.append(bcs::to_bytes(&action));
    c.append(bcs::to_bytes(&scheme));
    c.append(bcs::to_bytes(&public_key));
    c.append(bcs::to_bytes(&rp_id_hash));
    c.append(bcs::to_bytes(&origin));
    c.append(bcs::to_bytes(&guardian));
    c.append(bcs::to_bytes(&valid_until));
    c.append(bcs::to_bytes(&a));
    let r = relay_ref(meta::account_network(account), c, extra);
    meta::manage(account, action, scheme, public_key, rp_id_hash, origin, guardian, valid_until, a, clock);
    pay(rf, account, r, to, amount, pay_valid_until, extra, pay_auth, clock, ctx);
}

/// `mandate::revoke_with_sig` (the delegate's kill switch), paid from any account.
public fun relay_revoke_with_sig<T, P>(
    rf: &RelayFee,
    m: &mut Mandate<T>,
    valid_until: u64,
    a: Auth,
    account: &mut Account<P>,
    to: address,
    amount: u128,
    pay_valid_until: u64,
    extra: vector<u8>,
    pay_auth: Auth,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let mut c = call(b"mandate::revoke_with_sig", object::id_address(m));
    c.append(bcs::to_bytes(&valid_until));
    c.append(bcs::to_bytes(&a));
    let r = relay_ref(meta::account_network(account), c, extra);
    mandate::revoke_with_sig(m, valid_until, a, clock, ctx);
    pay(rf, account, r, to, amount, pay_valid_until, extra, pay_auth, clock, ctx);
}

/// `dex::cancel`, paid from the maker's account it names; a refused cancel (`false`) aborts with `ECallRefused`.
public fun relay_cancel<X>(
    rf: &RelayFee,
    market: &mut Market,
    account: &mut Account<X>,
    order: Order,
    a: Auth,
    to: address,
    amount: u128,
    pay_valid_until: u64,
    extra: vector<u8>,
    pay_auth: Auth,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let mut c = call(b"dex::cancel", object::id_address(market));
    c.append(bcs::to_bytes(&object::id_address(account)));
    c.append(bcs::to_bytes(&order));
    c.append(bcs::to_bytes(&a));
    let r = relay_ref(meta::account_network(account), c, extra);
    assert!(dex::cancel(market, account, order, a), ECallRefused);
    pay(rf, account, r, to, amount, pay_valid_until, extra, pay_auth, clock, ctx);
}

/// `dex::invalidate_nonces`, paid from the maker's account it names.
public fun relay_invalidate_nonces<X>(
    rf: &RelayFee,
    market: &mut Market,
    account: &mut Account<X>,
    min_nonce: u128,
    a: Auth,
    to: address,
    amount: u128,
    pay_valid_until: u64,
    extra: vector<u8>,
    pay_auth: Auth,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let mut c = call(b"dex::invalidate_nonces", object::id_address(market));
    c.append(bcs::to_bytes(&object::id_address(account)));
    c.append(bcs::to_bytes(&min_nonce));
    c.append(bcs::to_bytes(&a));
    let r = relay_ref(meta::account_network(account), c, extra);
    dex::invalidate_nonces(market, account, min_nonce, a);
    pay(rf, account, r, to, amount, pay_valid_until, extra, pay_auth, clock, ctx);
}

/// `bcs(name) ‖ bcs(first object id)`.
fun call(name: vector<u8>, object: address): vector<u8> {
    let mut c = bcs::to_bytes(&name);
    c.append(bcs::to_bytes(&object));
    c
}

fun pay<P>(
    rf: &RelayFee,
    account: &mut Account<P>,
    r: vector<u8>,
    to: address,
    amount: u128,
    valid_until: u64,
    extra: vector<u8>,
    a: Auth,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let payee = meta::pay_routed(account, object::id_address(rf), to, amount, r, valid_until, extra, a, clock, ctx);
    event::emit(RelayFeePaid {
        ref: r, target: package(), token: meta::registry_id(account), payer: meta::owner(account), payee,
        amount: amount as u64,
    });
}

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) { init(ctx) }

#[test_only]
public fun relay_fee_paid_for_testing(ref: vector<u8>, token: ID, payer: address, payee: address, amount: u64): RelayFeePaid {
    RelayFeePaid { ref, target: package(), token, payer, payee, amount }
}
