/// Token meta-tx cấp contract trên Sui (R30, R64). Tiền của chủ thể nằm trong `Account<T>` (shared,
/// derived từ `Registry<T>` theo địa chỉ chủ ⇒ id tính offline, một account mỗi chủ × coin type).
/// Chủ thể chỉ KÝ `MetaOp`; relayer gửi tx từ lane của chính nó. Không sequence của chủ thể, không
/// allowance: số dư chỉ đổi qua `relay_pay` (chữ ký chủ) hoặc `take`/`put` của module cùng package.
module bamboo::meta;

use bamboo::auth::{Self, Auth};
use std::bcs;
use std::type_name;
use sui::balance::Balance;
use sui::clock::Clock;
use sui::coin::{Self, Coin};
use sui::derived_object;
use sui::event;
use sui::hash::blake2b256;
use sui::table::{Self, Table};

const DOMAIN: vector<u8> = b"bamboo.metaop.v1";
const OPEN_DOMAIN: vector<u8> = b"bamboo.open.v1";
const OP_PAY: u8 = 0;
const U64_MAX: u128 = 0xffffffffffffffff;

#[error]
const ENetwork: vector<u8> = b"Network is set once and must not be empty.";
#[error]
const ENoNetwork: vector<u8> = b"Root network is not set yet.";
#[error]
const EPasskeyNeedsAssertion: vector<u8> = b"Passkey accounts are opened with open_passkey.";
#[error]
const EBadSignature: vector<u8> = b"Signature does not verify for this account and payload.";
#[error]
const EExpired: vector<u8> = b"Signed payload expired.";
#[error]
const EWrongRelayer: vector<u8> = b"Payload is bound to another relayer.";
#[error]
const EBadNonce: vector<u8> = b"Nonce is not the next one in this lane.";
#[error]
const EBadField: vector<u8> = b"pay_ref, lane and extra are 32 bytes.";
#[error]
const EBadAmount: vector<u8> = b"Amount must be in (0, u64::MAX].";
#[error]
const EInsufficient: vector<u8> = b"Account balance too low.";

public struct AdminCap has key { id: UID }

public struct Root has key {
    id: UID,
    network: vector<u8>,
}

/// "Token" của Odoo: `blockchain.token.address` = id object này.
public struct Registry<phantom T> has key {
    id: UID,
    network: vector<u8>,
}

public struct Account<phantom T> has key {
    id: UID,
    registry: ID,
    network: vector<u8>,
    owner: address,
    scheme: u8,
    public_key: vector<u8>,
    rp_id_hash: vector<u8>,
    origin: vector<u8>,
    balance: Balance<T>,
    lanes: Table<vector<u8>, u64>,
}

/// Payload ký `MetaOp` v1 (round-3 §D.0). Ví ký `personal_digest(bcs(MetaOp))`.
public struct MetaOp has copy, drop {
    domain: vector<u8>,
    network: vector<u8>,
    contract: address,
    op: u8,
    from: address,
    to: address,
    amount: u128,
    pay_ref: vector<u8>,
    lane: vector<u8>,
    nonce: u64,
    valid_until: u64,
    relayer: address,
    extra: vector<u8>,
}

public struct RegistryCreated has copy, drop { registry: ID, coin_type: std::ascii::String }

public struct AccountOpened has copy, drop { registry: ID, account: ID, owner: address, scheme: u8 }

public struct Deposited has copy, drop { registry: ID, account: ID, amount: u64 }

/// `contract` = registry (token của Odoo); `target` = object đã kiểm chữ ký (account / mandate).
public struct MetaTransactionExecuted has copy, drop {
    contract: ID,
    target: ID,
    from: address,
    digest: vector<u8>,
    lane: vector<u8>,
    nonce: u64,
}

public struct PaymentSettled has copy, drop {
    contract: ID,
    from: address,
    to: address,
    amount: u64,
    pay_ref: vector<u8>,
}

fun init(ctx: &mut TxContext) {
    transfer::transfer(AdminCap { id: object::new(ctx) }, ctx.sender());
    transfer::share_object(Root { id: object::new(ctx), network: vector[] });
}

/// Một lần: chuỗi mạng (`blockchain.chain.network_key` của Odoo) vào miền ký của mọi account sau này.
public fun set_network(_: &AdminCap, root: &mut Root, network: vector<u8>) {
    assert!(root.network.is_empty() && !network.is_empty(), ENetwork);
    root.network = network;
}

/// Một registry mỗi coin type (derived từ Root theo TypeName — lần hai bị chain từ chối).
public fun new_registry<T>(root: &mut Root) {
    assert!(!root.network.is_empty(), ENoNetwork);
    let tn = type_name::with_defining_ids<T>();
    let id = derived_object::claim(&mut root.id, tn);
    event::emit(RegistryCreated { registry: id.to_inner(), coin_type: tn.into_string() });
    transfer::share_object(Registry<T> { id, network: root.network });
}

/// Ai cũng mở được cho một khoá ed25519/secp256k1/secp256r1: tham số duy nhất là khoá, và chủ =
/// hash(cờ ‖ khoá). Passkey cần thêm origin/rpIdHash ⇒ `open_passkey`.
public fun open<T>(registry: &mut Registry<T>, scheme: u8, public_key: vector<u8>, ctx: &mut TxContext) {
    assert!(scheme != auth::passkey(), EPasskeyNeedsAssertion);
    open_inner(registry, scheme, public_key, vector[], vector[], ctx)
}

/// Passkey (RS7-2): origin/rpIdHash lấy từ CHÍNH assertion trên challenge mở account ⇒ không ai mở
/// trước account của người khác với origin sai (account derived là duy nhất — mở sai là khoá tiền).
public fun open_passkey<T>(registry: &mut Registry<T>, public_key: vector<u8>, a: Auth, ctx: &mut TxContext) {
    let challenge = open_challenge(registry, &public_key);
    let (rp, origin) = (auth::rp_id_hash_of(&a), auth::origin_of(&a));
    assert!(auth::verify(auth::passkey(), &public_key, &rp, &origin, &challenge, &a), EBadSignature);
    open_inner(registry, auth::passkey(), public_key, rp, origin, ctx)
}

public fun open_challenge<T>(registry: &Registry<T>, public_key: &vector<u8>): vector<u8> {
    let mut b = OPEN_DOMAIN;
    b.append(object::id(registry).to_bytes());
    b.append(*public_key);
    blake2b256(&b)
}

fun open_inner<T>(
    registry: &mut Registry<T>,
    scheme: u8,
    public_key: vector<u8>,
    rp_id_hash: vector<u8>,
    origin: vector<u8>,
    ctx: &mut TxContext,
) {
    let owner = auth::address_of(scheme, &public_key);
    let id = derived_object::claim(&mut registry.id, owner);
    let reg = object::id(registry);
    event::emit(AccountOpened { registry: reg, account: id.to_inner(), owner, scheme });
    transfer::share_object(Account<T> {
        id,
        registry: reg,
        network: registry.network,
        owner,
        scheme,
        public_key,
        rp_id_hash,
        origin,
        balance: sui::balance::zero(),
        lanes: table::new(ctx),
    });
}

/// Id account của `owner` — cùng công thức Odoo/relayer tính offline.
public fun account_address<T>(registry: &Registry<T>, owner: address): address {
    derived_object::derive_address(object::id(registry), owner)
}

public fun deposit<T>(account: &mut Account<T>, c: Coin<T>) {
    let amount = c.value();
    account.balance.join(c.into_balance());
    event::emit(Deposited { registry: account.registry, account: object::id(account), amount });
}

/// Meta-tx `pay`: network/contract/from lấy từ chính account — relayer chỉ đưa phần còn lại, và mọi
/// trường đều nằm trong bytes đã ký.
public fun relay_pay<T>(
    account: &mut Account<T>,
    to: address,
    amount: u128,
    pay_ref: vector<u8>,
    lane: vector<u8>,
    nonce: u64,
    valid_until: u64,
    relayer: address,
    extra: vector<u8>,
    a: Auth,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let op = new_op(
        account.network, object::id_address(account), OP_PAY, account.owner, to, amount,
        pay_ref, lane, nonce, valid_until, relayer, extra,
    );
    let digest = check(&op, clock, ctx);
    assert!(verify_by(account, &digest, &a), EBadSignature);
    let next = if (account.lanes.contains(lane)) account.lanes.remove(lane) else 0;
    assert!(next == nonce, EBadNonce);
    account.lanes.add(lane, nonce + 1);
    let amt = amount_u64(amount);
    assert!(account.balance.value() >= amt, EInsufficient);
    transfer::public_transfer(coin::take(&mut account.balance, amt, ctx), to);
    emit_executed(account.registry, object::id(account), account.owner, digest, lane, nonce);
    emit_settled(account.registry, account.owner, to, amt, pay_ref);
}

// ------------------------------------------------------------------ package (mandate, dex)

public(package) fun new_op(
    network: vector<u8>,
    contract: address,
    op: u8,
    from: address,
    to: address,
    amount: u128,
    pay_ref: vector<u8>,
    lane: vector<u8>,
    nonce: u64,
    valid_until: u64,
    relayer: address,
    extra: vector<u8>,
): MetaOp {
    MetaOp { domain: DOMAIN, network, contract, op, from, to, amount, pay_ref, lane, nonce, valid_until, relayer, extra }
}

/// Hạn, relayer, độ dài trường ⇒ digest personal-message của op.
public(package) fun check(op: &MetaOp, clock: &Clock, ctx: &TxContext): vector<u8> {
    assert!(op.pay_ref.length() == 32 && op.lane.length() == 32 && op.extra.length() == 32, EBadField);
    assert!(clock.timestamp_ms() / 1000 <= op.valid_until, EExpired);
    assert!(op.relayer == @0x0 || op.relayer == ctx.sender(), EWrongRelayer);
    op_digest(op)
}

public fun op_digest(op: &MetaOp): vector<u8> { auth::personal_digest(bcs::to_bytes(op)) }

public(package) fun verify_by<T>(account: &Account<T>, digest: &vector<u8>, a: &Auth): bool {
    auth::verify(account.scheme, &account.public_key, &account.rp_id_hash, &account.origin, digest, a)
}

public(package) fun amount_u64(amount: u128): u64 {
    assert!(amount > 0 && amount <= U64_MAX, EBadAmount);
    amount as u64
}

public(package) fun take<T>(account: &mut Account<T>, amount: u64): Balance<T> {
    assert!(account.balance.value() >= amount, EInsufficient);
    account.balance.split(amount)
}

public(package) fun put<T>(account: &mut Account<T>, b: Balance<T>) { account.balance.join(b); }

public(package) fun emit_executed(contract: ID, target: ID, from: address, digest: vector<u8>, lane: vector<u8>, nonce: u64) {
    event::emit(MetaTransactionExecuted { contract, target, from, digest, lane, nonce });
}

public(package) fun emit_settled(contract: ID, from: address, to: address, amount: u64, pay_ref: vector<u8>) {
    event::emit(PaymentSettled { contract, from, to, amount, pay_ref });
}

// ------------------------------------------------------------------ views

public fun owner<T>(a: &Account<T>): address { a.owner }

public fun balance<T>(a: &Account<T>): u64 { a.balance.value() }

public fun registry_id<T>(a: &Account<T>): ID { a.registry }

public fun network<T>(r: &Registry<T>): vector<u8> { r.network }

public fun root_network(r: &Root): vector<u8> { r.network }

public fun lane_nonce<T>(a: &Account<T>, lane: vector<u8>): u64 {
    if (a.lanes.contains(lane)) *a.lanes.borrow(lane) else 0
}

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) { init(ctx) }
