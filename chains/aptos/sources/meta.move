/// Meta-tx cấp contract trên Aptos (R30, spec §3–§5.1). Mỗi chủ thể có MỘT `Account` (named object derived từ
/// `Root` theo địa chỉ chủ ⇒ địa chỉ tính offline, chain ép một account mỗi chủ). Số dư = các primary fungible store
/// của CHÍNH địa chỉ Account (RS11-2): không sổ nội bộ, mọi FA gửi tới đều chi được. Chủ thể chỉ KÝ `MetaOp`; relayer
/// gửi tx từ lane của nó và tự trả phí. Không sequence của chủ thể, không allowance: tiền chỉ ra qua `relay_pay` (chữ
/// ký chủ) hoặc signer của Account mà chỉ module cùng package (`mandate`, `dex`) xin được.
module bamboo::meta {
    use std::bcs;
    use std::hash::sha3_256;
    use std::option::{Self, Option};
    use std::signer;
    use aptos_std::table::{Self, Table};
    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::{Self, ExtendRef, Object, ObjectCore};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;
    use bamboo::auth;
    use bamboo::p256;

    const DOMAIN: vector<u8> = b"bamboo.metaop.v1";
    const KEYOP_DOMAIN: vector<u8> = b"bamboo.keyop.v1";
    const ROOT_SEED: vector<u8> = b"bamboo.root";
    const OP_PAY: u8 = 0;
    const U64_MAX: u128 = 0xffffffffffffffff;
    /// Vòng đời khoá (round-3 §C): `manage_*`.
    const ADD_KEY: u8 = 0;
    const REMOVE_KEY: u8 = 1;
    const ADD_ORIGIN: u8 = 2;
    const REMOVE_ORIGIN: u8 = 3;
    const SET_GUARDIAN: u8 = 4;
    const CANCEL_RECOVERY: u8 = 5;
    const MAX_KEYS: u64 = 8;
    const MAX_ORIGINS: u64 = 8;
    /// `RECOVERY_DELAY` của `SubjectAccount` EVM: guardian chờ 2 ngày, khoá hiện có / chủ huỷ được.
    const RECOVERY_DELAY_S: u64 = 172_800;

    /// Chữ ký không hợp lệ với account và payload này.
    const EBAD_SIGNATURE: u64 = 1;
    /// Payload đã hết hạn.
    const EEXPIRED: u64 = 2;
    /// Payload gắn với relayer khác.
    const EWRONG_RELAYER: u64 = 3;
    /// Nonce không phải nonce kế tiếp của lane.
    const EBAD_NONCE: u64 = 4;
    /// pay_ref, lane, extra phải 32 byte.
    const EBAD_FIELD: u64 = 5;
    /// Số tiền phải trong (0, u64::MAX].
    const EBAD_AMOUNT: u64 = 6;
    /// Số dư account không đủ.
    const EINSUFFICIENT: u64 = 7;
    /// Khoá đầu tiên phải dẫn ra auth key hiện tại của chủ.
    const EFIRST_KEY: u64 = 8;
    /// Thao tác khoá sai (hành động, khoá, origin, trùng hoặc vượt giới hạn).
    const EKEY_OP: u64 = 9;
    /// Account không bao giờ còn 0 khoá (passkey không bao giờ còn 0 origin).
    const ELAST_KEY: u64 = 10;
    /// Chỉ guardian của account.
    const ENOT_GUARDIAN: u64 = 11;
    /// Không có khôi phục đang chờ, hoặc chưa hết trễ.
    const ERECOVERY: u64 = 12;
    /// Account chưa tồn tại.
    const ENO_ACCOUNT: u64 = 13;
    /// Chỉ chủ của account.
    const ENOT_OWNER: u64 = 14;
    /// Chỉ admin (chủ object code của package).
    const ENOT_ADMIN: u64 = 15;
    /// Account đã tồn tại.
    const EEXISTS: u64 = 16;

    struct Root has key {
        extend: ExtendRef,
    }

    /// `scheme` 0 = ed25519 (32 byte), 2 = WebAuthn P-256 (65 byte, `rp_id_hash` 32 byte, `table` = `p256::table`
    /// tính một lần lúc đăng ký — mỗi chữ ký passkey sau đó rẻ hơn ~400 gas; rỗng với ed25519).
    struct Key has copy, drop, store {
        scheme: u8,
        public_key: vector<u8>,
        rp_id_hash: vector<u8>,
        table: vector<u256>,
    }

    struct Recovery has copy, drop, store {
        key: Key,
        origin: vector<u8>,
        ready_at: u64,
    }

    /// `valid_until` = max hạn của các op đã dùng lane ⇒ `prune` an toàn sau mốc này (RS11-4).
    struct Lane has copy, drop, store {
        next: u64,
        valid_until: u64,
    }

    struct Account has key {
        owner: address,
        keys: vector<Key>,
        origins: vector<vector<u8>>,
        guardian: address,
        recovery: Option<Recovery>,
        key_nonce: u64,
        lanes: Table<vector<u8>, Lane>,
        extend: ExtendRef,
    }

    /// Payload ký v1 (spec §4.1, 310 byte BCS). `digest = sha3_256(bcs(MetaOp))`.
    struct MetaOp has copy, drop {
        domain: vector<u8>,
        chain_id: u8,
        contract: address,
        asset: address,
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

    /// Thao tác vòng đời khoá, ký bởi MỘT khoá hiện có. `nonce` = `key_nonce` của account.
    struct KeyOp has copy, drop {
        domain: vector<u8>,
        chain_id: u8,
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

    #[event]
    struct AccountOpened has drop, store { account: address, owner: address, scheme: u8 }

    #[event]
    /// `contract` = tài sản (metadata FA = `blockchain.token.address` của Odoo); `account` = object đã kiểm chữ ký
    /// (Account / Mandate).
    struct MetaTransactionExecuted has drop, store {
        contract: address,
        account: address,
        from: address,
        digest: vector<u8>,
        lane: vector<u8>,
        nonce: u64,
    }

    #[event]
    struct PaymentSettled has drop, store {
        contract: address,
        from: address,
        to: address,
        amount: u64,
        pay_ref: vector<u8>,
    }

    #[event]
    struct KeyOpExecuted has drop, store { account: address, action: u8, nonce: u64 }

    #[event]
    struct RecoveryStarted has drop, store { account: address, guardian: address, ready_at: u64 }

    #[event]
    struct Recovered has drop, store { account: address, guardian: address }

    fun init_module(publisher: &signer) {
        let c = object::create_named_object(publisher, ROOT_SEED);
        move_to(&object::generate_signer(&c), Root { extend: object::generate_extend_ref(&c) });
    }

    // ------------------------------------------------------------------ địa chỉ (cùng công thức Odoo/relayer)

    #[view]
    public fun root(): address { object::create_object_address(&@bamboo, ROOT_SEED) }

    #[view]
    public fun account_of(owner: address): address {
        let seed = b"acct";
        seed.append(bcs::to_bytes(&owner));
        object::create_object_address(&root(), seed)
    }

    /// Signer của Root — `mandate`/`dex` tạo object con bằng nó.
    package fun root_signer(): signer acquires Root {
        object::generate_signer_for_extending(&Root[root()].extend)
    }

    /// Admin = chủ object code của package (deploy bằng `deploy-object`; production: multisig). Bản `--dev` của test
    /// publish ở tài khoản thường ⇒ admin = chính địa chỉ đó.
    package fun assert_admin(s: &signer) {
        let a = signer::address_of(s);
        let ok = if (object::is_object(@bamboo)) {
            object::is_owner(object::address_to_object<ObjectCore>(@bamboo), a)
        } else a == @bamboo;
        assert!(ok, ENOT_ADMIN);
    }

    // ------------------------------------------------------------------ mở account

    /// Ai cũng mở được cho một khoá ed25519 dẫn ra auth key HIỆN TẠI của chủ (kể cả tài khoản stateless — AIP-115):
    /// kẻ gian không mở trước được account của nạn nhân với khoá sai (account derived là duy nhất).
    public entry fun open(owner: address, public_key: vector<u8>) acquires Root {
        assert!(auth::scheme_of(&public_key) == auth::ed25519(), EFIRST_KEY);
        assert!(auth::proves(&account::get_authentication_key(owner), &public_key), EFIRST_KEY);
        create_account(owner, key_of(auth::ed25519(), public_key, vector[]), vector[]);
    }

    fun create_account(owner: address, key: Key, origin: vector<u8>): address acquires Root {
        let addr = account_of(owner);
        assert!(!exists<Account>(addr), EEXISTS);
        let seed = b"acct";
        seed.append(bcs::to_bytes(&owner));
        let c = object::create_named_object(&root_signer(), seed);
        let s = object::generate_signer(&c);
        event::emit(AccountOpened { account: addr, owner, scheme: key.scheme });
        move_to(&s, Account {
            owner,
            keys: vector[key],
            origins: if (origin.is_empty()) vector[] else vector[origin],
            guardian: @0x0,
            recovery: option::none(),
            key_nonce: 0,
            lanes: table::new(),
            extend: object::generate_extend_ref(&c),
        });
        addr
    }

    /// Lần chi đầu tiên mở account (spec §3.3): khoá ký phải dẫn ra auth key hiện tại của chủ. Passkey: rpIdHash và
    /// origin lấy từ CHÍNH assertion đang được kiểm (chỉ passkey của chủ ký được nó).
    fun open_lazily(owner: address, public_key: &vector<u8>, envelope: &vector<u8>) acquires Root {
        assert!(auth::proves(&account::get_authentication_key(owner), public_key), EFIRST_KEY);
        let scheme = auth::scheme_of(public_key);
        let (rp, origin) = if (scheme == auth::webauthn()) auth::webauthn_origin(envelope) else (vector[], vector[]);
        create_account(owner, key_of(scheme, *public_key, rp), origin);
    }

    // ------------------------------------------------------------------ pay

    /// Meta-tx `pay` (spec §5.1). `contract`/`from` dựng từ `owner`, `chain_id` đọc on-chain: relayer không đổi được
    /// trường nào mà chữ ký vẫn qua.
    public entry fun relay_pay(
        lane: &signer,
        owner: address,
        asset: Object<Metadata>,
        to: address,
        amount: u128,
        pay_ref: vector<u8>,
        lane_id: vector<u8>,
        nonce: u64,
        valid_until: u64,
        relayer: address,
        extra: vector<u8>,
        public_key: vector<u8>,
        sig: vector<u8>,
        envelope: vector<u8>,
    ) acquires Root, Account {
        let digest = pay_checked(signer::address_of(lane), owner, asset, to, amount, pay_ref, lane_id, nonce,
            valid_until, relayer, extra, public_key, sig, envelope);
        let addr = account_of(owner);
        if (!exists<Account>(addr)) open_lazily(owner, &public_key, &envelope);
        let acct = &mut Account[addr];
        let l = acct.lanes.borrow_mut_with_default(lane_id, Lane { next: 0, valid_until: 0 });
        l.next = nonce + 1;
        if (valid_until > l.valid_until) l.valid_until = valid_until;
        let amt = amount as u64;
        primary_fungible_store::transfer(&object::generate_signer_for_extending(&acct.extend), asset, to, amt);
        let asset_addr = object::object_address(&asset);
        emit_executed(asset_addr, addr, owner, digest, lane_id, nonce);
        emit_settled(asset_addr, owner, to, amt, pay_ref);
    }

    #[view]
    /// Mọi kiểm tra của `relay_pay`, không ghi state; trả digest hoặc abort đúng mã của `relay_pay`. Relayer gọi nó thay
    /// mô phỏng khi Account chưa mở: REST `simulate` của aptos-node 9.6.0 treo với tx vừa tạo object Account vừa chi
    /// từ primary store có sẵn của nó (tx thật chạy bình thường — spec §16).
    public fun pay_check(
        lane: address,
        owner: address,
        asset: Object<Metadata>,
        to: address,
        amount: u128,
        pay_ref: vector<u8>,
        lane_id: vector<u8>,
        nonce: u64,
        valid_until: u64,
        relayer: address,
        extra: vector<u8>,
        public_key: vector<u8>,
        sig: vector<u8>,
        envelope: vector<u8>,
    ): vector<u8> acquires Account {
        pay_checked(lane, owner, asset, to, amount, pay_ref, lane_id, nonce, valid_until, relayer, extra, public_key, sig,
            envelope)
    }

    /// Miền/hạn/relayer/khoá/phong bì/chữ ký/nonce/số dư của một `pay`. Account chưa có: khoá phải dẫn ra auth key
    /// hiện tại của chủ (§3.3) và chữ ký kiểm với origin/rpIdHash của chính assertion.
    fun pay_checked(
        lane: address,
        owner: address,
        asset: Object<Metadata>,
        to: address,
        amount: u128,
        pay_ref: vector<u8>,
        lane_id: vector<u8>,
        nonce: u64,
        valid_until: u64,
        relayer: address,
        extra: vector<u8>,
        public_key: vector<u8>,
        sig: vector<u8>,
        envelope: vector<u8>,
    ): vector<u8> acquires Account {
        let addr = account_of(owner);
        let op = new_op(addr, object::object_address(&asset), OP_PAY, owner, to, amount, pay_ref, lane_id, nonce,
            valid_until, relayer, extra);
        let digest = check_at(&op, lane);
        if (exists<Account>(addr)) {
            let acct = &Account[addr];
            assert!(verify_by(acct, &public_key, DOMAIN, &digest, &sig, &envelope), EBAD_SIGNATURE);
            let next = if (acct.lanes.contains(lane_id)) acct.lanes.borrow(lane_id).next else 0;
            assert!(next == nonce, EBAD_NONCE);
        } else {
            assert!(auth::proves(&account::get_authentication_key(owner), &public_key), EFIRST_KEY);
            let (rp, origin) = auth::webauthn_origin(&envelope);
            assert!(
                auth::verify(&public_key, DOMAIN, &digest, &sig, &envelope, &rp, &vector[origin], &vector[], chain_id::get()),
                EBAD_SIGNATURE,
            );
            assert!(nonce == 0, EBAD_NONCE);
        };
        assert!(primary_fungible_store::balance(addr, asset) >= amount_u64(amount), EINSUFFICIENT);
        digest
    }

    /// Không cần quyền (RS11-4): xoá lane đã hết hạn — mọi op từng dùng nó đã hết hạn nên không replay được; Odoo
    /// không phát lại lane. Phí lưu trữ hoàn cho người gửi tx (động cơ dọn — L10).
    public entry fun prune(owner: address, lanes: vector<vector<u8>>) acquires Account {
        let acct = &mut Account[account_of(owner)];
        let now = timestamp::now_seconds();
        lanes.for_each(|k| {
            if (acct.lanes.contains(k) && acct.lanes.borrow(k).valid_until < now) {
                acct.lanes.remove(k);
            }
        });
    }

    // ------------------------------------------------------------------ package (mandate, dex)

    package fun new_op(
        contract: address,
        asset: address,
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
        MetaOp {
            domain: DOMAIN, chain_id: chain_id::get(), contract, asset, op, from, to, amount, pay_ref, lane, nonce,
            valid_until, relayer, extra,
        }
    }

    /// Độ dài trường, hạn, relayer ⇒ digest của op.
    package fun check(op: &MetaOp, lane: &signer): vector<u8> { check_at(op, signer::address_of(lane)) }

    fun check_at(op: &MetaOp, lane: address): vector<u8> {
        assert!(op.pay_ref.length() == 32 && op.lane.length() == 32 && op.extra.length() == 32, EBAD_FIELD);
        assert!(timestamp::now_seconds() <= op.valid_until, EEXPIRED);
        assert!(op.relayer == @0x0 || op.relayer == lane, EWRONG_RELAYER);
        sha3_256(bcs::to_bytes(op))
    }

    public fun op_digest(op: &MetaOp): vector<u8> { sha3_256(bcs::to_bytes(op)) }

    /// `public_key` phải là một khoá của account và ký `digest` (nhãn `label` trong phong bì signMessage).
    fun verify_by(
        acct: &Account,
        public_key: &vector<u8>,
        label: vector<u8>,
        digest: &vector<u8>,
        sig: &vector<u8>,
        envelope: &vector<u8>,
    ): bool {
        let (found, i) = acct.keys.find(|k| k.public_key == *public_key);
        found && auth::verify(public_key, label, digest, sig, envelope, &acct.keys[i].rp_id_hash, &acct.origins,
            &acct.keys[i].table, chain_id::get())
    }

    /// Khoá của account `addr` ký `digest` — cho `mandate`/`dex`.
    package fun verify_signed(
        addr: address,
        public_key: &vector<u8>,
        label: vector<u8>,
        digest: &vector<u8>,
        sig: &vector<u8>,
        envelope: &vector<u8>,
    ): bool acquires Account {
        exists<Account>(addr) && verify_by(&Account[addr], public_key, label, digest, sig, envelope)
    }

    /// Signer của account (chi từ primary store của nó) — chỉ module cùng package.
    package fun signer_of(addr: address): signer acquires Account {
        assert!(exists<Account>(addr), ENO_ACCOUNT);
        object::generate_signer_for_extending(&Account[addr].extend)
    }

    package fun amount_u64(amount: u128): u64 {
        assert!(amount > 0 && amount <= U64_MAX, EBAD_AMOUNT);
        amount as u64
    }

    package fun emit_executed(contract: address, account: address, from: address, digest: vector<u8>, lane: vector<u8>, nonce: u64) {
        event::emit(MetaTransactionExecuted { contract, account, from, digest, lane, nonce });
    }

    package fun emit_settled(contract: address, from: address, to: address, amount: u64, pay_ref: vector<u8>) {
        event::emit(PaymentSettled { contract, from, to, amount, pay_ref });
    }

    // ------------------------------------------------------------------ vòng đời khoá (RS11-3)

    #[view]
    public fun keyop_digest(
        owner: address,
        action: u8,
        scheme: u8,
        public_key: vector<u8>,
        rp_id_hash: vector<u8>,
        origin: vector<u8>,
        guardian: address,
        valid_until: u64,
    ): vector<u8> acquires Account {
        let addr = account_of(owner);
        let op = KeyOp {
            domain: KEYOP_DOMAIN, chain_id: chain_id::get(), account: addr, action, scheme, public_key, rp_id_hash,
            origin, guardian, nonce: Account[addr].key_nonce, valid_until,
        };
        sha3_256(bcs::to_bytes(&op))
    }

    /// Đường 1: một khoá hiện có ký `KeyOp` (relayer hay ai nộp cũng được, không gas cho chủ).
    public entry fun manage_signed(
        owner: address,
        action: u8,
        scheme: u8,
        public_key: vector<u8>,
        rp_id_hash: vector<u8>,
        origin: vector<u8>,
        guardian: address,
        valid_until: u64,
        signer_key: vector<u8>,
        sig: vector<u8>,
        envelope: vector<u8>,
    ) acquires Account {
        assert!(timestamp::now_seconds() <= valid_until, EEXPIRED);
        let addr = account_of(owner);
        assert!(exists<Account>(addr), ENO_ACCOUNT);
        let digest = keyop_digest(owner, action, scheme, public_key, rp_id_hash, origin, guardian, valid_until);
        assert!(verify_by(&Account[addr], &signer_key, KEYOP_DOMAIN, &digest, &sig, &envelope), EBAD_SIGNATURE);
        apply(addr, action, key_of(scheme, public_key, rp_id_hash), origin, guardian);
    }

    /// Đường 2: chính chủ gửi tx native. Chủ thể có tài khoản Aptos passkey/keyless/MultiKey (khoá không dẫn ra được
    /// trong Move) gắn khoá bằng đường này; account chưa có thì `ADD_KEY` mở nó với khoá đó. Tx quản trị một lần, không
    /// nằm trên đường thanh toán nên không phạm R30.
    public entry fun manage_native(
        owner: &signer,
        action: u8,
        scheme: u8,
        public_key: vector<u8>,
        rp_id_hash: vector<u8>,
        origin: vector<u8>,
        guardian: address,
    ) acquires Root, Account {
        let o = signer::address_of(owner);
        let addr = account_of(o);
        let key = key_of(scheme, public_key, rp_id_hash);
        if (!exists<Account>(addr)) {
            assert!(action == ADD_KEY && key_valid(&key) && origin_ok(&key, &origin), EKEY_OP);
            create_account(o, key, origin);
            return
        };
        apply(addr, action, key, origin, guardian);
    }

    fun apply(addr: address, action: u8, key: Key, origin: vector<u8>, guardian: address) acquires Account {
        let acct = &mut Account[addr];
        if (action == ADD_KEY) {
            add_key(acct, key, origin);
        } else if (action == REMOVE_KEY) {
            let (found, i) = acct.keys.index_of(&key);
            assert!(found, EKEY_OP);
            assert!(acct.keys.length() > 1, ELAST_KEY);
            acct.keys.remove(i);
            check_origins(acct);
        } else if (action == ADD_ORIGIN) {
            add_origin(acct, origin);
        } else if (action == REMOVE_ORIGIN) {
            let (found, i) = acct.origins.index_of(&origin);
            assert!(found, EKEY_OP);
            acct.origins.remove(i);
            check_origins(acct);
        } else if (action == SET_GUARDIAN) {
            acct.guardian = guardian;
            acct.recovery = option::none();
        } else {
            assert!(action == CANCEL_RECOVERY && acct.recovery.is_some(), EKEY_OP);
            acct.recovery = option::none();
        };
        event::emit(KeyOpExecuted { account: addr, action, nonce: acct.key_nonce });
        acct.key_nonce += 1;
    }

    /// Đường 3: guardian (tx native) đề xuất khoá mới; hiệu lực sau `RECOVERY_DELAY_S` nếu không bị huỷ. Đề xuất mới
    /// thay đề xuất cũ.
    public entry fun start_recovery(
        guardian: &signer,
        owner: address,
        scheme: u8,
        public_key: vector<u8>,
        rp_id_hash: vector<u8>,
        origin: vector<u8>,
    ) acquires Account {
        let addr = account_of(owner);
        let acct = &mut Account[addr];
        assert!(acct.guardian != @0x0 && signer::address_of(guardian) == acct.guardian, ENOT_GUARDIAN);
        let key = key_of(scheme, public_key, rp_id_hash);
        assert!(key_valid(&key) && origin_ok(&key, &origin), EKEY_OP);
        let ready_at = timestamp::now_seconds() + RECOVERY_DELAY_S;
        acct.recovery = option::some(Recovery { key, origin, ready_at });
        event::emit(RecoveryStarted { account: addr, guardian: acct.guardian, ready_at });
    }

    public entry fun finish_recovery(guardian: &signer, owner: address) acquires Account {
        let addr = account_of(owner);
        let acct = &mut Account[addr];
        assert!(acct.guardian != @0x0 && signer::address_of(guardian) == acct.guardian, ENOT_GUARDIAN);
        assert!(acct.recovery.is_some() && timestamp::now_seconds() >= acct.recovery.borrow().ready_at, ERECOVERY);
        let Recovery { key, origin, ready_at: _ } = acct.recovery.extract();
        add_key(acct, key, origin);
        acct.key_nonce += 1; // chữ ký vòng đời đang chờ của khoá cũ hết hiệu lực
        event::emit(Recovered { account: addr, guardian: acct.guardian });
    }

    /// Khoá passkey kèm bảng `p256::table` (rỗng nếu khoá không nằm trên đường cong ⇒ `key_valid` từ chối).
    fun key_of(scheme: u8, public_key: vector<u8>, rp_id_hash: vector<u8>): Key {
        let table = if (scheme == auth::webauthn()) p256::table(&public_key) else vector[];
        Key { scheme, public_key, rp_id_hash, table }
    }

    fun key_valid(k: &Key): bool {
        let s = auth::scheme_of(&k.public_key);
        s == k.scheme && (s == auth::ed25519() || (s == auth::webauthn() && !k.table.is_empty()))
            && k.rp_id_hash.length() == (if (s == auth::webauthn()) 32 else 0)
    }

    /// Passkey cần một origin (đã có trong account hoặc đi kèm).
    fun origin_ok(k: &Key, origin: &vector<u8>): bool { k.scheme != auth::webauthn() || !origin.is_empty() }

    fun add_key(acct: &mut Account, key: Key, origin: vector<u8>) {
        assert!(key_valid(&key) && !acct.keys.contains(&key) && acct.keys.length() < MAX_KEYS, EKEY_OP);
        if (!origin.is_empty() && !acct.origins.contains(&origin)) add_origin(acct, origin);
        acct.keys.push_back(key);
        check_origins(acct);
    }

    fun add_origin(acct: &mut Account, origin: vector<u8>) {
        assert!(
            !origin.is_empty() && origin.length() <= 256 && !origin.contains(&34) && !acct.origins.contains(&origin)
                && acct.origins.length() < MAX_ORIGINS,
            EKEY_OP,
        );
        acct.origins.push_back(origin);
    }

    fun check_origins(acct: &Account) {
        assert!(!acct.origins.is_empty() || !acct.keys.any(|k| k.scheme == auth::webauthn()), ELAST_KEY);
    }

    // ------------------------------------------------------------------ views

    #[view]
    public fun exists_at(owner: address): bool { exists<Account>(account_of(owner)) }

    #[view]
    public fun owner_of(addr: address): address acquires Account { Account[addr].owner }

    #[view]
    public fun key_count(owner: address): u64 acquires Account { Account[account_of(owner)].keys.length() }

    #[view]
    public fun has_key(owner: address, public_key: vector<u8>): bool acquires Account {
        Account[account_of(owner)].keys.any(|k| k.public_key == public_key)
    }

    #[view]
    public fun has_origin(owner: address, origin: vector<u8>): bool acquires Account {
        Account[account_of(owner)].origins.contains(&origin)
    }

    #[view]
    public fun key_nonce(owner: address): u64 acquires Account { Account[account_of(owner)].key_nonce }

    #[view]
    public fun lane_nonce(owner: address, lane: vector<u8>): u64 acquires Account {
        let a = &Account[account_of(owner)];
        if (a.lanes.contains(lane)) a.lanes.borrow(lane).next else 0
    }

    #[view]
    public fun guardian(owner: address): address acquires Account { Account[account_of(owner)].guardian }

    #[test_only]
    public fun init_for_test(publisher: &signer) { init_module(publisher) }
}
