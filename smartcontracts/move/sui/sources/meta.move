/// Token meta-tx cấp contract trên Sui (R30, R64). Tiền của chủ thể nằm trong `Account<T>` (shared,
/// derived từ `Registry<T>` theo địa chỉ chủ ⇒ id tính offline, một account mỗi chủ × coin type).
/// Chủ thể chỉ KÝ `MetaOp`; relayer gửi tx từ lane của chính nó. Không sequence của chủ thể, không
/// allowance: số dư chỉ đổi qua `relay_pay` (chữ ký chủ) hoặc `take`/`put` của module cùng package.
module scaas::meta;

use scaas::auth::{Self, Auth};
use std::bcs;
use std::type_name;
use sui::balance::Balance;
use sui::clock::Clock;
use sui::coin::{Self, Coin};
use sui::derived_object;
use sui::event;
use sui::hash::{blake2b256, keccak256};
use sui::table::{Self, Table};
use sui::transfer::Receiving;

const DOMAIN: vector<u8> = b"scaas.metaop.v1";
const OPEN_DOMAIN: vector<u8> = b"scaas.open.v1";
const KEYOP_DOMAIN: vector<u8> = b"scaas.keyop.v1";
const OP_PAY: u8 = 0;
/// CTR-MTX-26 (spec §6.2): `payId = keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`,
/// `payLane(p) = keccak256("scaas.pay.lane" ‖ p)` — byte for byte the EVM derivation.
const PAY_META_DOMAIN: vector<u8> = b"scaas.pay.meta";
const PAY_LANE_DOMAIN: vector<u8> = b"scaas.pay.lane";
const U64_MAX: u128 = 0xffffffffffffffff;
/// Vòng đời khoá (round-3 §C "Vòng đời khoá", §C.3): thao tác `manage` ký bởi một khoá hiện có.
const ADD_KEY: u8 = 0;
const REMOVE_KEY: u8 = 1;
const ADD_ORIGIN: u8 = 2;
const REMOVE_ORIGIN: u8 = 3;
const SET_GUARDIAN: u8 = 4;
const CANCEL_RECOVERY: u8 = 5;
const MAX_KEYS: u64 = 8;
const MAX_ORIGINS: u64 = 8;
/// `RECOVERY_DELAY` của `SmartKeyAccount` EVM (round-3 §C): guardian chờ 2 ngày, khoá hiện có huỷ được.
const RECOVERY_DELAY_S: u64 = 172_800;

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
#[error]
const EKeyOp: vector<u8> = b"Bad key operation (unknown action, key, origin, duplicate or limit).";
#[error]
const ELastKey: vector<u8> = b"An account never drops to zero keys (or a passkey to zero origins).";
#[error]
const ENotGuardian: vector<u8> = b"Only the account guardian may do this.";
#[error]
const ERecovery: vector<u8> = b"No recovery pending, or its delay has not passed.";

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

/// Một khoá được uỷ quyền. `rp_id_hash` chỉ cho passkey (cờ 6), rỗng với khoá khác.
public struct Key has copy, drop, store {
    scheme: u8,
    public_key: vector<u8>,
    rp_id_hash: vector<u8>,
}

public struct Recovery has copy, drop, store {
    key: Key,
    origin: vector<u8>,
    eta: u64,
}

/// `owner` = địa chỉ của khoá ĐẦU TIÊN (id derived theo nó, không đổi); `keys` là các khoá ký được hiện tại
/// (review M1: thêm/xoay/xoá bằng chữ ký một khoá hiện có, guardian khôi phục sau trễ — round-3 §C, §C.3).
public struct Account<phantom T> has key {
    id: UID,
    registry: ID,
    network: vector<u8>,
    owner: address,
    keys: vector<Key>,
    origins: vector<vector<u8>>,
    guardian: address,
    recovery: Option<Recovery>,
    key_nonce: u64,
    balance: Balance<T>,
    lanes: Table<vector<u8>, u64>,
}

/// Thao tác vòng đời khoá, ký personal-message bởi một khoá hiện có. `nonce` = `key_nonce` của account.
public struct KeyOp has copy, drop {
    domain: vector<u8>,
    network: vector<u8>,
    account: address,
    action: u8,
    scheme: u8,
    public_key: vector<u8>,
    rp_id_hash: vector<u8>,
    origin: vector<u8>,
    guardian: address,
    nonce: u64,
    valid_until: u64,
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

public struct KeyOpExecuted has copy, drop { account: ID, action: u8, nonce: u64 }

public struct RecoveryStarted has copy, drop { account: ID, guardian: address, eta: u64 }

public struct Recovered has copy, drop { account: ID, guardian: address }

/// `contract` = registry (token của Odoo); `target` = object đã kiểm chữ ký (account / mandate).
public struct MetaTransactionExecuted has copy, drop {
    contract: ID,
    target: ID,
    from: address,
    digest: vector<u8>,
    lane: vector<u8>,
    nonce: u64,
}

/// CTR-MTX-26: emitted by `relay_pay_meta` right before its `PaymentSettled`. The contract never parses `meta`.
public struct PaymentMeta has copy, drop {
    contract: ID,
    pay_id: vector<u8>,
    meta: vector<u8>,
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
    assert!(auth::verify(auth::passkey(), &public_key, &rp, &vector[origin], &challenge, &a), EBadSignature);
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
        keys: vector[Key { scheme, public_key, rp_id_hash }],
        origins: if (origin.is_empty()) vector[] else vector[origin],
        guardian: @0x0,
        recovery: option::none(),
        key_nonce: 0,
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

/// Coin<T> gửi thẳng tới id account (transfer-to-object, vd. ví nhận/người nhận phí là account) ⇒ ai cũng kéo
/// được vào số dư (review M2: không coin nào kẹt ở id object).
public fun receive<T>(account: &mut Account<T>, r: Receiving<Coin<T>>) {
    let c = transfer::public_receive(&mut account.id, r);
    deposit(account, c)
}

/// Object khác loại gửi nhầm tới id account ⇒ chuyển cho `owner` (địa chỉ ví Sui của khoá đầu tiên).
/// `ponytail:` chủ đã mất khoá đầu thì nhận ở ví đó vẫn kẹt — mở `Account<U>` rồi `deposit` thủ công nếu cần.
public fun forward<T, O: key + store>(account: &mut Account<T>, r: Receiving<O>) {
    transfer::public_transfer(transfer::public_receive(&mut account.id, r), account.owner)
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
    settle(account, &op, digest, &a, to, option::none(), ctx);
}

/// CTR-MTX-26 (spec §6.2): `relay_pay` with `pay_ref = metaPayId(salt, meta)`, `lane = payLane(pay_ref)`,
/// `nonce = 0` derived on chain ⇒ the same signed `MetaOp` as a plain pay of that `pay_ref`, and a
/// `(payer, payId)` pays at most once (the payer's own lane table). `PaymentMeta` before `PaymentSettled`.
public fun relay_pay_meta<T>(
    account: &mut Account<T>,
    to: address,
    amount: u128,
    salt: vector<u8>,
    meta: vector<u8>,
    valid_until: u64,
    relayer: address,
    extra: vector<u8>,
    a: Auth,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let pay_ref = meta_pay_id(salt, meta);
    let op = new_op(
        account.network, object::id_address(account), OP_PAY, account.owner, to, amount,
        pay_ref, pay_lane(pay_ref), 0, valid_until, relayer, extra,
    );
    let digest = check(&op, clock, ctx);
    settle(account, &op, digest, &a, to, option::some(meta), ctx);
}

/// CTR-MTX-27 (spec §7.2): the router's payment, called only by `scaas::relayfee` right after the wrapped
/// entry. `pay_ref` is the ref the router computed from the call; lane `payLane(pay_ref)`, nonce 0 and
/// relayer = `marker` (the shared `RelayFee` object) are fixed here, so the payer's signature verifies only for
/// a payment signed for exactly this call through the router. Open mode (`to == marker`) pays the submitter;
/// the marker itself is never paid. Returns the payee.
public(package) fun pay_routed<T>(
    account: &mut Account<T>,
    marker: address,
    to: address,
    amount: u128,
    pay_ref: vector<u8>,
    valid_until: u64,
    extra: vector<u8>,
    a: Auth,
    clock: &Clock,
    ctx: &mut TxContext,
): address {
    let op = new_op(
        account.network, object::id_address(account), OP_PAY, account.owner, to, amount,
        pay_ref, pay_lane(pay_ref), 0, valid_until, marker, extra,
    );
    let digest = check_fields(&op, clock);
    let payee = if (to == marker) ctx.sender() else to;
    settle(account, &op, digest, &a, payee, option::none(), ctx);
    payee
}

/// `relay_pay`'s body (relayer already checked): signature, lane nonce, move to `payee`, events.
fun settle<T>(
    account: &mut Account<T>,
    op: &MetaOp,
    digest: vector<u8>,
    a: &Auth,
    payee: address,
    meta: Option<vector<u8>>,
    ctx: &mut TxContext,
) {
    assert!(verify_by(account, &digest, a), EBadSignature);
    let (lane, nonce) = (op.lane, op.nonce);
    let next = if (account.lanes.contains(lane)) account.lanes.remove(lane) else 0;
    assert!(next == nonce, EBadNonce);
    account.lanes.add(lane, nonce + 1);
    let amt = amount_u64(op.amount);
    assert!(account.balance.value() >= amt, EInsufficient);
    transfer::public_transfer(coin::take(&mut account.balance, amt, ctx), payee);
    emit_executed(account.registry, object::id(account), account.owner, digest, lane, nonce);
    meta.do!(|m| event::emit(PaymentMeta { contract: account.registry, pay_id: op.pay_ref, meta: m }));
    emit_settled(account.registry, account.owner, payee, amt, op.pay_ref);
}

/// CTR-MTX-26 `metaPayId(salt, meta)`; `salt` is 32 bytes.
public fun meta_pay_id(salt: vector<u8>, meta: vector<u8>): vector<u8> {
    assert!(salt.length() == 32, EBadField);
    let mut b = PAY_META_DOMAIN;
    b.append(salt);
    b.append(keccak256(&meta));
    keccak256(&b)
}

/// `payLane(p)`: the 32-byte lane of a pay-meta / router payment.
public fun pay_lane(p: vector<u8>): vector<u8> {
    let mut b = PAY_LANE_DOMAIN;
    b.append(p);
    keccak256(&b)
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
    let digest = check_fields(op, clock);
    assert!(op.relayer == @0x0 || op.relayer == ctx.sender(), EWrongRelayer);
    digest
}

/// Độ dài trường, hạn ⇒ digest (relayer do bên gọi kiểm: `check`, hoặc `pay_routed` cố định = marker).
fun check_fields(op: &MetaOp, clock: &Clock): vector<u8> {
    assert!(op.pay_ref.length() == 32 && op.lane.length() == 32 && op.extra.length() == 32, EBadField);
    assert!(clock.timestamp_ms() / 1000 <= op.valid_until, EExpired);
    op_digest(op)
}

public fun op_digest(op: &MetaOp): vector<u8> { auth::personal_digest(bcs::to_bytes(op)) }

/// Một khoá bất kỳ của account ký được `digest` (≤ `MAX_KEYS`; passkey chỉ thử khi chữ ký có phần WebAuthn).
public(package) fun verify_by<T>(account: &Account<T>, digest: &vector<u8>, a: &Auth): bool {
    let web = auth::is_webauthn(a);
    account.keys.any!(|k| (k.scheme == auth::passkey()) == web
        && auth::verify(k.scheme, &k.public_key, &k.rp_id_hash, &account.origins, digest, a))
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

// ------------------------------------------------------------------ vòng đời khoá (review M1)

public fun keyop_digest<T>(
    account: &Account<T>,
    action: u8,
    scheme: u8,
    public_key: vector<u8>,
    rp_id_hash: vector<u8>,
    origin: vector<u8>,
    guardian: address,
    valid_until: u64,
): vector<u8> {
    let op = KeyOp {
        domain: KEYOP_DOMAIN, network: account.network, account: object::id_address(account), action, scheme,
        public_key, rp_id_hash, origin, guardian, nonce: account.key_nonce, valid_until,
    };
    auth::personal_digest(bcs::to_bytes(&op))
}

/// Thêm/xoá khoá, thêm/xoá origin WebAuthn, đặt guardian, huỷ khôi phục — ký bởi MỘT khoá hiện có, ai nộp cũng
/// được (relayer hay chủ thể). Không bao giờ còn 0 khoá; account còn passkey thì không còn 0 origin.
public fun manage<T>(
    account: &mut Account<T>,
    action: u8,
    scheme: u8,
    public_key: vector<u8>,
    rp_id_hash: vector<u8>,
    origin: vector<u8>,
    guardian: address,
    valid_until: u64,
    a: Auth,
    clock: &Clock,
) {
    assert!(clock.timestamp_ms() / 1000 <= valid_until, EExpired);
    let digest = keyop_digest(account, action, scheme, public_key, rp_id_hash, origin, guardian, valid_until);
    assert!(verify_by(account, &digest, &a), EBadSignature);
    let key = Key { scheme, public_key, rp_id_hash };
    if (action == ADD_KEY) {
        add_key(account, key, origin);
    } else if (action == REMOVE_KEY) {
        let (found, i) = account.keys.index_of(&key);
        assert!(found, EKeyOp);
        assert!(account.keys.length() > 1, ELastKey);
        account.keys.remove(i);
        check_origins(account);
    } else if (action == ADD_ORIGIN) {
        add_origin(account, origin);
    } else if (action == REMOVE_ORIGIN) {
        let (found, i) = account.origins.index_of(&origin);
        assert!(found, EKeyOp);
        account.origins.remove(i);
        check_origins(account);
    } else if (action == SET_GUARDIAN) {
        account.guardian = guardian;
        account.recovery = option::none();
    } else {
        assert!(action == CANCEL_RECOVERY && account.recovery.is_some(), EKeyOp);
        account.recovery = option::none();
    };
    event::emit(KeyOpExecuted { account: object::id(account), action, nonce: account.key_nonce });
    account.key_nonce = account.key_nonce + 1;
}

/// Guardian (tx native của chính guardian) đề xuất một khoá mới; có hiệu lực sau `RECOVERY_DELAY_S` nếu không
/// khoá hiện có nào huỷ (`manage(CANCEL_RECOVERY)`). Đề xuất mới thay đề xuất cũ.
public fun start_recovery<T>(
    account: &mut Account<T>,
    scheme: u8,
    public_key: vector<u8>,
    rp_id_hash: vector<u8>,
    origin: vector<u8>,
    clock: &Clock,
    ctx: &TxContext,
) {
    assert!(account.guardian != @0x0 && ctx.sender() == account.guardian, ENotGuardian);
    let key = Key { scheme, public_key, rp_id_hash };
    assert!(key_valid(&key), EKeyOp);
    let eta = clock.timestamp_ms() / 1000 + RECOVERY_DELAY_S;
    account.recovery = option::some(Recovery { key, origin, eta });
    event::emit(RecoveryStarted { account: object::id(account), guardian: account.guardian, eta });
}

public fun finish_recovery<T>(account: &mut Account<T>, clock: &Clock, ctx: &TxContext) {
    assert!(account.guardian != @0x0 && ctx.sender() == account.guardian, ENotGuardian);
    assert!(account.recovery.is_some() && clock.timestamp_ms() / 1000 >= account.recovery.borrow().eta, ERecovery);
    let Recovery { key, origin, eta: _ } = account.recovery.extract();
    add_key(account, key, origin);
    account.key_nonce = account.key_nonce + 1; // chữ ký vòng đời đang chờ (của khoá cũ) hết hiệu lực
    event::emit(Recovered { account: object::id(account), guardian: account.guardian });
}

fun key_valid(k: &Key): bool {
    auth::key_ok(k.scheme, &k.public_key) && (k.rp_id_hash.length() == if (k.scheme == auth::passkey()) 32 else 0)
}

fun add_key<T>(account: &mut Account<T>, key: Key, origin: vector<u8>) {
    assert!(key_valid(&key) && !account.keys.contains(&key) && account.keys.length() < MAX_KEYS, EKeyOp);
    if (!origin.is_empty() && !account.origins.contains(&origin)) add_origin(account, origin);
    account.keys.push_back(key);
    check_origins(account);
}

fun add_origin<T>(account: &mut Account<T>, origin: vector<u8>) {
    assert!(
        !origin.is_empty() && origin.length() <= 256 && !origin.contains(&34) && !account.origins.contains(&origin)
            && account.origins.length() < MAX_ORIGINS,
        EKeyOp,
    );
    account.origins.push_back(origin);
}

fun check_origins<T>(account: &Account<T>) {
    assert!(!account.origins.is_empty() || !account.keys.any!(|k| k.scheme == auth::passkey()), ELastKey);
}

// ------------------------------------------------------------------ views

public fun owner<T>(a: &Account<T>): address { a.owner }

public fun balance<T>(a: &Account<T>): u64 { a.balance.value() }

public fun registry_id<T>(a: &Account<T>): ID { a.registry }

public fun network<T>(r: &Registry<T>): vector<u8> { r.network }

public fun account_network<T>(a: &Account<T>): vector<u8> { a.network }

public fun root_network(r: &Root): vector<u8> { r.network }

public fun key_count<T>(a: &Account<T>): u64 { a.keys.length() }

public fun has_origin<T>(a: &Account<T>, origin: vector<u8>): bool { a.origins.contains(&origin) }

public fun key_nonce<T>(a: &Account<T>): u64 { a.key_nonce }

public fun lane_nonce<T>(a: &Account<T>, lane: vector<u8>): u64 {
    if (a.lanes.contains(lane)) *a.lanes.borrow(lane) else 0
}

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) { init(ctx) }

#[test_only]
public fun payment_meta_for_testing(contract: ID, pay_id: vector<u8>, meta: vector<u8>): PaymentMeta {
    PaymentMeta { contract, pay_id, meta }
}

#[test_only]
public fun payment_settled_for_testing(contract: ID, from: address, to: address, amount: u64, pay_ref: vector<u8>): PaymentSettled {
    PaymentSettled { contract, from, to, amount, pay_ref }
}
