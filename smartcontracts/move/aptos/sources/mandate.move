/// Mandate (R25 trên Aptos, spec §5.2, RS11-11): tiền của MỘT người trả nằm ở primary store của object Mandate
/// (L7: mọi FA gửi tới đều được tính); khoá `delegate` (custody của platform) chỉ tiêu được trong giới hạn chủ đặt —
/// trần mỗi lần, trần mỗi kỳ, payee, hạn, mỗi `pay_ref` một lần — kiểm on-chain. Chủ MỞ mandate bằng chữ ký khoá
/// Account (không tx native, không sequence của chủ — R30); cấp vốn = một `pay` thường tới địa chỉ Mandate.
module scaas::mandate {
    use std::bcs;
    use std::hash::sha3_256;
    use aptos_std::table::{Self, Table};
    use aptos_framework::chain_id;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::{Self, ExtendRef, Object};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;
    use scaas::auth;
    use scaas::meta;

    const DOMAIN: vector<u8> = b"scaas.mandate.v1";
    const METAOP_LABEL: vector<u8> = b"scaas.metaop.v1";
    const OP_MANDATE_PAY: u8 = 2;
    const OP_REVOKE: u8 = 3;

    /// Giới hạn mandate hoặc khoá delegate không hợp lệ.
    const EBAD_MANDATE: u64 = 1;
    /// Mandate đã thu hồi.
    const EREVOKED: u64 = 2;
    /// Mandate hết hạn.
    const EMANDATE_EXPIRED: u64 = 3;
    /// Payee không được phép.
    const EPAYEE: u64 = 4;
    /// Vượt trần mỗi lần.
    const EOVER_PAYMENT_CAP: u64 = 5;
    /// Vượt phần còn lại của kỳ.
    const EOVER_PERIOD_CAP: u64 = 6;
    /// pay_ref này đã trả.
    const EREF_PAID: u64 = 7;
    /// Chữ ký không hợp lệ.
    const EBAD_SIGNATURE: u64 = 8;
    /// Số dư mandate không đủ.
    const EINSUFFICIENT: u64 = 9;
    /// Chữ ký mở mandate đã hết hạn.
    const EEXPIRED: u64 = 10;
    /// Mandate còn hiệu lực: chưa hoàn tiền được.
    const ELIVE: u64 = 11;

    struct Mandate has key {
        owner: address,
        delegate_key: vector<u8>,
        expiry: u64,
        period: u64,
        period_start: u64,
        max_per_payment: u64,
        max_per_period: u64,
        spent_in_period: u64,
        payees: vector<address>,
        /// pay_ref ⇒ valid_until của op đã trả (prunable sau hạn).
        refs: Table<vector<u8>, u64>,
        revoked: bool,
        extend: ExtendRef,
    }

    /// Chủ ký bằng một khoá Account. Không nonce: object named chỉ tạo được một lần.
    struct MandateInit has copy, drop {
        domain: vector<u8>,
        chain_id: u8,
        account: address,
        mandate: address,
        seed: vector<u8>,
        delegate_key: vector<u8>,
        max_per_payment: u64,
        max_per_period: u64,
        period: u64,
        expiry: u64,
        payees: vector<address>,
        valid_until: u64,
    }

    #[event]
    struct MandateOpened has drop, store { mandate: address, owner: address, delegate_key: vector<u8> }

    #[event]
    struct MandateRevoked has drop, store { mandate: address }

    #[event]
    struct PaidUnderMandate has drop, store { mandate: address, payee: address, amount: u64, pay_ref: vector<u8> }

    #[view]
    public fun mandate_of(owner: address, seed: vector<u8>): address {
        object::create_object_address(&meta::root(), seed_bytes(owner, seed))
    }

    fun seed_bytes(owner: address, seed: vector<u8>): vector<u8> {
        let b = b"mandate";
        b.append(bcs::to_bytes(&owner));
        b.append(bcs::to_bytes(&seed));
        b
    }

    #[view]
    public fun init_digest(
        owner: address,
        seed: vector<u8>,
        delegate_key: vector<u8>,
        max_per_payment: u64,
        max_per_period: u64,
        period: u64,
        expiry: u64,
        payees: vector<address>,
        valid_until: u64,
    ): vector<u8> {
        let m = MandateInit {
            domain: DOMAIN, chain_id: chain_id::get(), account: meta::account_of(owner), mandate: mandate_of(owner, seed),
            seed, delegate_key, max_per_payment, max_per_period, period, expiry, payees, valid_until,
        };
        sha3_256(bcs::to_bytes(&m))
    }

    /// `period == 0` sẽ reset trần kỳ ở mọi lần trả (review W5 của MandateWallet) ⇒ từ chối.
    package entry fun open(
        owner: address,
        seed: vector<u8>,
        delegate_key: vector<u8>,
        max_per_payment: u64,
        max_per_period: u64,
        period: u64,
        expiry: u64,
        payees: vector<address>,
        valid_until: u64,
        public_key: vector<u8>,
        sig: vector<u8>,
        envelope: vector<u8>,
    ) {
        let now = timestamp::now_seconds();
        assert!(now <= valid_until, EEXPIRED);
        assert!(
            auth::scheme_of(&delegate_key) == auth::ed25519() && period > 0 && max_per_payment > 0
                && max_per_payment <= max_per_period && expiry > now,
            EBAD_MANDATE,
        );
        let d = init_digest(owner, seed, delegate_key, max_per_payment, max_per_period, period, expiry, payees, valid_until);
        assert!(meta::verify_signed(meta::account_of(owner), &public_key, DOMAIN, &d, &sig, &envelope), EBAD_SIGNATURE);
        let c = object::create_named_object(&meta::root_signer(), seed_bytes(owner, seed));
        let s = object::generate_signer(&c);
        let addr = std::signer::address_of(&s);
        event::emit(MandateOpened { mandate: addr, owner, delegate_key });
        move_to(&s, Mandate {
            owner, delegate_key, expiry, period, period_start: now, max_per_payment, max_per_period,
            spent_in_period: 0, payees, refs: table::new(), revoked: false, extend: object::generate_extend_ref(&c),
        });
    }

    /// Delegate ký `MetaOp{op: mandate_pay, contract: mandate, from: owner, lane: pay_ref, nonce: 0}`; ai nộp cũng
    /// được (relayer). `pay_ref` một lần là chống replay.
    package entry fun pay(
        lane: &signer,
        mandate: address,
        asset: Object<Metadata>,
        to: address,
        amount: u128,
        pay_ref: vector<u8>,
        valid_until: u64,
        relayer: address,
        public_key: vector<u8>,
        sig: vector<u8>,
        envelope: vector<u8>,
    ) {
        let m = &mut Mandate[mandate];
        assert!(!m.revoked, EREVOKED);
        let now = timestamp::now_seconds();
        assert!(now <= m.expiry, EMANDATE_EXPIRED);
        assert!(m.payees.contains(&to), EPAYEE);
        let amt = meta::amount_u64(amount);
        assert!(amt <= m.max_per_payment, EOVER_PAYMENT_CAP);
        assert!(!m.refs.contains(pay_ref), EREF_PAID);
        let op = meta::new_op(mandate, object::object_address(&asset), OP_MANDATE_PAY, m.owner, to, amount, pay_ref,
            pay_ref, 0, valid_until, relayer, zero32());
        let digest = meta::check(&op, lane);
        assert!(
            public_key == m.delegate_key
                && auth::verify(&public_key, METAOP_LABEL, &digest, &sig, &envelope, &vector[], &vector[], &vector[], chain_id::get()),
            EBAD_SIGNATURE,
        );
        // So bằng phép trừ (Sui L6): `now ≥ period_start`, `spent ≤ max_per_period` ⇒ không tràn.
        if (now - m.period_start >= m.period) {
            m.period_start = now;
            m.spent_in_period = 0;
        };
        assert!(amt <= m.max_per_period - m.spent_in_period, EOVER_PERIOD_CAP);
        m.spent_in_period += amt;
        m.refs.add(pay_ref, valid_until);
        assert!(primary_fungible_store::balance(mandate, asset) >= amt, EINSUFFICIENT);
        primary_fungible_store::transfer(&object::generate_signer_for_extending(&m.extend), asset, to, amt);
        let asset_addr = object::object_address(&asset);
        meta::emit_executed(asset_addr, mandate, m.owner, digest, pay_ref, 0);
        meta::emit_settled(asset_addr, m.owner, to, amt, pay_ref);
        event::emit(PaidUnderMandate { mandate, payee: to, amount: amt, pay_ref });
    }

    /// Thu hồi: delegate (kill switch của platform) HOẶC một khoá Account của chủ ký `MetaOp{op: revoke}`.
    package entry fun revoke_signed(
        lane: &signer,
        mandate: address,
        valid_until: u64,
        public_key: vector<u8>,
        sig: vector<u8>,
        envelope: vector<u8>,
    ) {
        let m = &mut Mandate[mandate];
        let op = meta::new_op(mandate, @0x0, OP_REVOKE, m.owner, @0x0, 0, zero32(), zero32(), 0, valid_until, @0x0, zero32());
        let digest = meta::check(&op, lane);
        let by_delegate = public_key == m.delegate_key
            && auth::verify(&public_key, METAOP_LABEL, &digest, &sig, &envelope, &vector[], &vector[], &vector[], chain_id::get());
        assert!(
            by_delegate || meta::verify_signed(meta::account_of(m.owner), &public_key, METAOP_LABEL, &digest, &sig, &envelope),
            EBAD_SIGNATURE,
        );
        m.revoked = true;
        event::emit(MandateRevoked { mandate });
    }

    /// Không cần quyền: sau thu hồi hoặc hết hạn, toàn bộ `asset` của mandate về Account của chủ (tiền không kẹt).
    public entry fun refund(mandate: address, asset: Object<Metadata>) {
        let m = &Mandate[mandate];
        assert!(m.revoked || timestamp::now_seconds() > m.expiry, ELIVE);
        let bal = primary_fungible_store::balance(mandate, asset);
        if (bal > 0) {
            primary_fungible_store::transfer(&object::generate_signer_for_extending(&m.extend), asset,
                meta::account_of(m.owner), bal);
        }
    }

    /// Không cần quyền (L10): xoá `pay_ref` sau hạn op + `PRUNE_DELAY_S` (cùng quy tắc lane của `meta`, review M2).
    public entry fun prune(mandate: address, refs: vector<vector<u8>>) {
        let m = &mut Mandate[mandate];
        let now = timestamp::now_seconds();
        refs.for_each(|r| {
            if (m.refs.contains(r) && meta::prunable(*m.refs.borrow(r), now)) {
                m.refs.remove(r);
            }
        });
    }

    #[view]
    public fun is_revoked(mandate: address): bool { Mandate[mandate].revoked }

    #[view]
    public fun spent_in_period(mandate: address): u64 { Mandate[mandate].spent_in_period }

    #[view]
    public fun ref_used(mandate: address, pay_ref: vector<u8>): bool { Mandate[mandate].refs.contains(pay_ref) }

    fun zero32(): vector<u8> { x"0000000000000000000000000000000000000000000000000000000000000000" }
}
