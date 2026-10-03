/// Mandate (R25 trên Sui): tiền của MỘT người trả nằm trong object; khoá `delegate` (custody của
/// platform) chỉ tiêu được trong giới hạn chủ đặt — trần mỗi lần, trần mỗi kỳ, payee, hạn, mỗi `pay_ref`
/// một lần — kiểm ở đây, on-chain. Thao tác của chủ là tx native: trên Sui chủ thể không có sequence
/// tài khoản, nên tx của chủ không khoá contract nào khác (R30).
module bamboo::mandate;

use bamboo::auth::{Self, Auth};
use bamboo::meta::{Self, Registry};
use sui::balance::Balance;
use sui::clock::Clock;
use sui::coin::{Self, Coin};
use sui::event;
use sui::table::{Self, Table};
use sui::vec_set::{Self, VecSet};

const OP_MANDATE_PAY: u8 = 2;
const OP_REVOKE: u8 = 3;

#[error]
const ENotOwner: vector<u8> = b"Only the mandate owner may do this.";
#[error]
const EBadMandate: vector<u8> = b"Invalid mandate limits or delegate key.";
#[error]
const ERevoked: vector<u8> = b"Mandate revoked.";
#[error]
const EMandateExpired: vector<u8> = b"Mandate expired.";
#[error]
const EPayee: vector<u8> = b"Payee not allowed.";
#[error]
const EOverPaymentCap: vector<u8> = b"Amount above the per-payment cap.";
#[error]
const EOverPeriodCap: vector<u8> = b"Amount above what is left in this period.";
#[error]
const ERefPaid: vector<u8> = b"This pay_ref was already paid.";
#[error]
const EBadSignature: vector<u8> = b"Delegate signature does not verify.";
#[error]
const EInsufficient: vector<u8> = b"Mandate balance too low.";

public struct Mandate<phantom T> has key {
    id: UID,
    registry: ID,
    network: vector<u8>,
    owner: address,
    delegate_scheme: u8,
    delegate_key: vector<u8>,
    balance: Balance<T>,
    expiry: u64,
    period: u64,
    period_start: u64,
    max_per_payment: u64,
    max_per_period: u64,
    spent_in_period: u64,
    payees: VecSet<address>,
    refs: Table<vector<u8>, bool>,
    revoked: bool,
}

public struct MandateCreated has copy, drop { mandate: ID, owner: address, delegate: address }

public struct MandateRevoked has copy, drop { mandate: ID, by: address }

public struct PaidUnderMandate has copy, drop { mandate: ID, payee: address, amount: u64, pay_ref: vector<u8> }

/// `expiry`, `period` tính bằng giây. Delegate là khoá custody (ed25519/secp256k1/secp256r1), không passkey.
public fun create<T>(
    registry: &Registry<T>,
    c: Coin<T>,
    delegate_scheme: u8,
    delegate_key: vector<u8>,
    max_per_payment: u64,
    max_per_period: u64,
    period: u64,
    expiry: u64,
    payees: vector<address>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    // period == 0 sẽ reset trần kỳ ở mọi lần trả (review W5 của MandateWallet).
    assert!(
        delegate_scheme != auth::passkey() && auth::key_ok(delegate_scheme, &delegate_key)
            && period > 0 && max_per_payment > 0 && max_per_payment <= max_per_period,
        EBadMandate,
    );
    let id = object::new(ctx);
    let delegate = auth::address_of(delegate_scheme, &delegate_key);
    event::emit(MandateCreated { mandate: id.to_inner(), owner: ctx.sender(), delegate });
    transfer::share_object(Mandate<T> {
        id,
        registry: object::id(registry),
        network: meta::network(registry),
        owner: ctx.sender(),
        delegate_scheme,
        delegate_key,
        balance: c.into_balance(),
        expiry,
        period,
        period_start: clock.timestamp_ms() / 1000,
        max_per_payment,
        max_per_period,
        spent_in_period: 0,
        payees: vec_set::from_keys(payees),
        refs: table::new(ctx),
        revoked: false,
    });
}

public fun deposit<T>(m: &mut Mandate<T>, c: Coin<T>) { m.balance.join(c.into_balance()); }

public fun withdraw<T>(m: &mut Mandate<T>, amount: u64, ctx: &mut TxContext) {
    assert!(ctx.sender() == m.owner, ENotOwner);
    assert!(m.balance.value() >= amount, EInsufficient);
    transfer::public_transfer(coin::take(&mut m.balance, amount, ctx), m.owner);
}

public fun set_payee<T>(m: &mut Mandate<T>, payee: address, allowed: bool, ctx: &TxContext) {
    assert!(ctx.sender() == m.owner, ENotOwner);
    if (allowed && !m.payees.contains(&payee)) m.payees.insert(payee);
    if (!allowed && m.payees.contains(&payee)) m.payees.remove(&payee);
}

public fun revoke<T>(m: &mut Mandate<T>, ctx: &TxContext) {
    assert!(ctx.sender() == m.owner, ENotOwner);
    m.revoked = true;
    event::emit(MandateRevoked { mandate: object::id(m), by: ctx.sender() });
}

/// Delegate ký `MetaOp{op: mandate_pay, contract: mandate, from: owner, lane: pay_ref, nonce: 0}`;
/// ai cũng nộp được (relayer). `pay_ref` một lần là chống replay.
public fun pay<T>(
    m: &mut Mandate<T>,
    payee: address,
    amount: u128,
    pay_ref: vector<u8>,
    valid_until: u64,
    relayer: address,
    a: Auth,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(!m.revoked, ERevoked);
    let now = clock.timestamp_ms() / 1000;
    assert!(now <= m.expiry, EMandateExpired);
    assert!(m.payees.contains(&payee), EPayee);
    let amt = meta::amount_u64(amount);
    assert!(amt <= m.max_per_payment, EOverPaymentCap);
    assert!(!m.refs.contains(pay_ref), ERefPaid);
    let op = meta::new_op(
        m.network, object::id_address(m), OP_MANDATE_PAY, m.owner, payee, amount,
        pay_ref, pay_ref, 0, valid_until, relayer, zero32(),
    );
    let digest = meta::check(&op, clock, ctx);
    assert!(auth::verify(m.delegate_scheme, &m.delegate_key, &vector[], &vector[], &digest, &a), EBadSignature);
    if (now >= m.period_start + m.period) {
        m.period_start = now;
        m.spent_in_period = 0;
    };
    assert!(m.spent_in_period + amt <= m.max_per_period, EOverPeriodCap);
    m.spent_in_period = m.spent_in_period + amt;
    m.refs.add(pay_ref, true);
    assert!(m.balance.value() >= amt, EInsufficient);
    transfer::public_transfer(coin::take(&mut m.balance, amt, ctx), payee);
    meta::emit_executed(m.registry, object::id(m), m.owner, digest, pay_ref, 0);
    meta::emit_settled(m.registry, m.owner, payee, amt, pay_ref);
    event::emit(PaidUnderMandate { mandate: object::id(m), payee, amount: amt, pay_ref });
}

/// Kill switch của platform: delegate tự thu hồi quyền của nó (nộp qua relayer).
public fun revoke_with_sig<T>(m: &mut Mandate<T>, valid_until: u64, a: Auth, clock: &Clock, ctx: &TxContext) {
    let op = meta::new_op(
        m.network, object::id_address(m), OP_REVOKE, m.owner, @0x0, 0,
        zero32(), zero32(), 0, valid_until, @0x0, zero32(),
    );
    let digest = meta::check(&op, clock, ctx);
    assert!(auth::verify(m.delegate_scheme, &m.delegate_key, &vector[], &vector[], &digest, &a), EBadSignature);
    m.revoked = true;
    event::emit(MandateRevoked { mandate: object::id(m), by: auth::address_of(m.delegate_scheme, &m.delegate_key) });
}

public fun balance<T>(m: &Mandate<T>): u64 { m.balance.value() }

public fun is_revoked<T>(m: &Mandate<T>): bool { m.revoked }

public fun spent_in_period<T>(m: &Mandate<T>): u64 { m.spent_in_period }

fun zero32(): vector<u8> { x"0000000000000000000000000000000000000000000000000000000000000000" }
