/// CTR-MTX-27 on Aptos (spec §7.2): a token fee to the relayer for one fee-less signed entry of this package.
/// Move has no dynamic call, so each wrapped entry has a static wrapper `relay_<entry>` that runs the entry by name
/// and then the payer's router payment (`meta::pay_routed`) in the same transaction: any abort of either aborts both.
/// Wrapped today: `meta::manage_signed`, `mandate::open`, `mandate::revoke_signed`, `dex::cancel_signed`,
/// `dex::invalidate_nonces_signed`; a new target is a new wrapper in a package upgrade.
///
/// `ref = keccak256("scaas.relayfee" ‖ chain_id (1 byte) ‖ @scaas (32) ‖ keccak256(call) ‖ salt (32))`: `chain_id`
/// the one the `MetaOp` domain carries, `call` = BCS of the entry's name (`vector<u8>`, e.g. `b"meta::manage_signed"`)
/// followed by the BCS of every argument in order (the entry's signature included, the lane signer excluded),
/// `salt` = the payment's `extra` (32 bytes, signed by the payer). No sender and no lane in `ref`: any relayer may
/// submit. The payment is the payer's plain pay with `pay_ref = ref`, `lane = payLane(ref)`, `nonce = 0`,
/// `relayer = marker()`, all derived on chain, so the payer's signature verifies only for this call through this
/// router. The payer is any Account (the call's signer or not): Aptos resources are reached by address.
///
/// Stateless: `marker()` is a derived address that holds nothing and that no transaction can sign for, so the module
/// needs no `init_module` and works when added by an upgrade.
module scaas::relayfee {
    use std::bcs;
    use aptos_std::aptos_hash::keccak256;
    use aptos_framework::chain_id;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::{Self, Object};
    use scaas::dex;
    use scaas::mandate;
    use scaas::meta;

    const REF_DOMAIN: vector<u8> = b"scaas.relayfee";
    const MARKER_SEED: vector<u8> = b"scaas.relayfee";

    /// The wrapped entry refused the call (a cancel of an order already closed); nothing is paid.
    const ECALL_REFUSED: u64 = 1;

    #[event]
    /// `target` = this package; `token` = the payment's asset (FA metadata); `payer` = the paying Account's owner;
    /// `payee` = who was paid (the submitting lane in open mode).
    struct RelayFeePaid has drop, store {
        ref: vector<u8>,
        target: address,
        token: address,
        payer: address,
        payee: address,
        amount: u64,
    }

    #[view]
    /// The router marker, the payment's relayer: `object::create_object_address(&@scaas, b"scaas.relayfee")`. No lane
    /// is this address, so `relay_pay` / `relay_pay_meta` refuse a router-bound payment (`meta::EWRONG_RELAYER`).
    public fun marker(): address { object::create_object_address(&@scaas, MARKER_SEED) }

    #[view]
    public fun relay_ref(call: vector<u8>, salt: vector<u8>): vector<u8> {
        let b = REF_DOMAIN;
        b.append(bcs::to_bytes(&chain_id::get()));
        b.append(bcs::to_bytes(&@scaas));
        b.append(keccak256(call));
        b.append(salt);
        keccak256(b)
    }

    /// `meta::manage_signed`, then the payment.
    package entry fun relay_manage_signed(
        lane: &signer,
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
        payer: address,
        asset: Object<Metadata>,
        to: address,
        amount: u128,
        pay_valid_until: u64,
        extra: vector<u8>,
        pay_key: vector<u8>,
        pay_sig: vector<u8>,
        pay_envelope: vector<u8>,
    ) {
        let c = bcs::to_bytes(&b"meta::manage_signed");
        c.append(bcs::to_bytes(&owner));
        c.append(bcs::to_bytes(&action));
        c.append(bcs::to_bytes(&scheme));
        c.append(bcs::to_bytes(&public_key));
        c.append(bcs::to_bytes(&rp_id_hash));
        c.append(bcs::to_bytes(&origin));
        c.append(bcs::to_bytes(&guardian));
        c.append(bcs::to_bytes(&valid_until));
        sig_bytes(&mut c, &signer_key, &sig, &envelope);
        meta::manage_signed(owner, action, scheme, public_key, rp_id_hash, origin, guardian, valid_until, signer_key,
            sig, envelope);
        pay(lane, c, payer, asset, to, amount, pay_valid_until, extra, pay_key, pay_sig, pay_envelope);
    }

    /// `mandate::open`, then the payment.
    package entry fun relay_mandate_open(
        lane: &signer,
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
        payer: address,
        asset: Object<Metadata>,
        to: address,
        amount: u128,
        pay_valid_until: u64,
        extra: vector<u8>,
        pay_key: vector<u8>,
        pay_sig: vector<u8>,
        pay_envelope: vector<u8>,
    ) {
        let c = bcs::to_bytes(&b"mandate::open");
        c.append(bcs::to_bytes(&owner));
        c.append(bcs::to_bytes(&seed));
        c.append(bcs::to_bytes(&delegate_key));
        c.append(bcs::to_bytes(&max_per_payment));
        c.append(bcs::to_bytes(&max_per_period));
        c.append(bcs::to_bytes(&period));
        c.append(bcs::to_bytes(&expiry));
        c.append(bcs::to_bytes(&payees));
        c.append(bcs::to_bytes(&valid_until));
        sig_bytes(&mut c, &public_key, &sig, &envelope);
        mandate::open(owner, seed, delegate_key, max_per_payment, max_per_period, period, expiry, payees, valid_until,
            public_key, sig, envelope);
        pay(lane, c, payer, asset, to, amount, pay_valid_until, extra, pay_key, pay_sig, pay_envelope);
    }

    /// `mandate::revoke_signed` (the owner's or the delegate's kill switch), then the payment.
    package entry fun relay_revoke_signed(
        lane: &signer,
        mandate: address,
        valid_until: u64,
        public_key: vector<u8>,
        sig: vector<u8>,
        envelope: vector<u8>,
        payer: address,
        asset: Object<Metadata>,
        to: address,
        amount: u128,
        pay_valid_until: u64,
        extra: vector<u8>,
        pay_key: vector<u8>,
        pay_sig: vector<u8>,
        pay_envelope: vector<u8>,
    ) {
        let c = bcs::to_bytes(&b"mandate::revoke_signed");
        c.append(bcs::to_bytes(&mandate));
        c.append(bcs::to_bytes(&valid_until));
        sig_bytes(&mut c, &public_key, &sig, &envelope);
        mandate::revoke_signed(lane, mandate, valid_until, public_key, sig, envelope);
        pay(lane, c, payer, asset, to, amount, pay_valid_until, extra, pay_key, pay_sig, pay_envelope);
    }

    /// `dex::cancel_signed`, then the payment; a cancel of an order already closed aborts with `ECALL_REFUSED`.
    package entry fun relay_cancel_signed(
        lane: &signer,
        market: address,
        order: vector<u8>,
        pk: vector<u8>,
        sig: vector<u8>,
        env: vector<u8>,
        payer: address,
        asset: Object<Metadata>,
        to: address,
        amount: u128,
        pay_valid_until: u64,
        extra: vector<u8>,
        pay_key: vector<u8>,
        pay_sig: vector<u8>,
        pay_envelope: vector<u8>,
    ) {
        let c = bcs::to_bytes(&b"dex::cancel_signed");
        c.append(bcs::to_bytes(&market));
        c.append(bcs::to_bytes(&order));
        sig_bytes(&mut c, &pk, &sig, &env);
        assert!(dex::cancel(market, order, pk, sig, env), ECALL_REFUSED);
        pay(lane, c, payer, asset, to, amount, pay_valid_until, extra, pay_key, pay_sig, pay_envelope);
    }

    /// `dex::invalidate_nonces_signed`, then the payment.
    package entry fun relay_invalidate_nonces_signed(
        lane: &signer,
        market: address,
        maker: address,
        min_nonce: u128,
        pk: vector<u8>,
        sig: vector<u8>,
        env: vector<u8>,
        payer: address,
        asset: Object<Metadata>,
        to: address,
        amount: u128,
        pay_valid_until: u64,
        extra: vector<u8>,
        pay_key: vector<u8>,
        pay_sig: vector<u8>,
        pay_envelope: vector<u8>,
    ) {
        let c = bcs::to_bytes(&b"dex::invalidate_nonces_signed");
        c.append(bcs::to_bytes(&market));
        c.append(bcs::to_bytes(&maker));
        c.append(bcs::to_bytes(&min_nonce));
        sig_bytes(&mut c, &pk, &sig, &env);
        dex::invalidate_nonces_signed(market, maker, min_nonce, pk, sig, env);
        pay(lane, c, payer, asset, to, amount, pay_valid_until, extra, pay_key, pay_sig, pay_envelope);
    }

    /// The entry's own authorisation, its last three arguments: `bcs(public_key) ‖ bcs(sig) ‖ bcs(envelope)`.
    fun sig_bytes(c: &mut vector<u8>, public_key: &vector<u8>, sig: &vector<u8>, envelope: &vector<u8>) {
        c.append(bcs::to_bytes(public_key));
        c.append(bcs::to_bytes(sig));
        c.append(bcs::to_bytes(envelope));
    }

    fun pay(
        lane: &signer,
        call: vector<u8>,
        payer: address,
        asset: Object<Metadata>,
        to: address,
        amount: u128,
        valid_until: u64,
        extra: vector<u8>,
        public_key: vector<u8>,
        sig: vector<u8>,
        envelope: vector<u8>,
    ) {
        let r = relay_ref(call, extra);
        let payee = meta::pay_routed(lane, marker(), payer, asset, to, amount, r, valid_until, extra, public_key, sig,
            envelope);
        event::emit(RelayFeePaid {
            ref: r, target: @scaas, token: object::object_address(&asset), payer, payee, amount: amount as u64,
        });
    }

    #[test_only]
    public fun relay_fee_paid_for_testing(ref: vector<u8>, token: address, payer: address, payee: address, amount: u64): RelayFeePaid {
        RelayFeePaid { ref, target: @scaas, token, payer, payee, amount }
    }
}
