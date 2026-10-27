/// Gói lại từng entry được relay của `scaas` — mỗi lời gọi phải là lỗi biên dịch (visibility).
module wrapcheck::wrap {
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::Object;

    public entry fun relay_pay(l: &signer, o: address, a: Object<Metadata>, v: vector<u8>) {
        scaas::meta::relay_pay(l, o, a, o, 1, v, v, 0, 0, o, v, v, v, v);
    }

    public entry fun mandate_pay(l: &signer, m: address, a: Object<Metadata>, v: vector<u8>) {
        scaas::mandate::pay(l, m, a, m, 1, v, 0, m, v, v, v);
    }

    public entry fun mandate_revoke(l: &signer, m: address, v: vector<u8>) {
        scaas::mandate::revoke_signed(l, m, 0, v, v, v);
    }

    public entry fun mandate_open(o: address, v: vector<u8>) {
        scaas::mandate::open(o, v, v, 1, 1, 1, 1, vector[], 0, v, v, v);
    }

    public entry fun settle(l: &signer, m: address, v: vector<u8>) {
        scaas::dex::settle(l, m, v, v, v, v, v, v, v, v, 1, 1, v);
    }

    public entry fun cancel(m: address, v: vector<u8>) {
        scaas::dex::cancel_signed(m, v, v, v, v);
    }

    public entry fun invalidate(m: address, v: vector<u8>) {
        scaas::dex::invalidate_nonces_signed(m, m, 1, v, v, v);
    }

    public entry fun manage_signed(o: address, v: vector<u8>) {
        scaas::meta::manage_signed(o, 0, 0, v, v, v, o, 0, v, v, v);
    }

    public entry fun relay_pay_meta(l: &signer, o: address, a: Object<Metadata>, v: vector<u8>) {
        scaas::meta::relay_pay_meta(l, o, a, o, 1, v, v, 0, o, v, v, v, v);
    }

    /// CTR-MTX-27: the router payment is package-only (called by `relayfee` alone).
    public fun pay_routed(l: &signer, o: address, a: Object<Metadata>, v: vector<u8>): address {
        scaas::meta::pay_routed(l, o, o, a, o, 1, v, 0, v, v, v, v)
    }

    public entry fun relay_manage_signed(l: &signer, o: address, a: Object<Metadata>, v: vector<u8>) {
        scaas::relayfee::relay_manage_signed(l, o, 0, 0, v, v, v, o, 0, v, v, v, o, a, o, 1, 0, v, v, v, v);
    }

    public entry fun relay_mandate_open(l: &signer, o: address, a: Object<Metadata>, v: vector<u8>) {
        scaas::relayfee::relay_mandate_open(l, o, v, v, 1, 1, 1, 1, vector[], 0, v, v, v, o, a, o, 1, 0, v, v, v, v);
    }

    public entry fun relay_revoke_signed(l: &signer, o: address, a: Object<Metadata>, v: vector<u8>) {
        scaas::relayfee::relay_revoke_signed(l, o, 0, v, v, v, o, a, o, 1, 0, v, v, v, v);
    }

    public entry fun relay_cancel_signed(l: &signer, o: address, a: Object<Metadata>, v: vector<u8>) {
        scaas::relayfee::relay_cancel_signed(l, o, v, v, v, v, o, a, o, 1, 0, v, v, v, v);
    }

    public entry fun relay_invalidate_nonces_signed(l: &signer, o: address, a: Object<Metadata>, v: vector<u8>) {
        scaas::relayfee::relay_invalidate_nonces_signed(l, o, o, 1, v, v, v, o, a, o, 1, 0, v, v, v, v);
    }

    /// Review I1: kiểm theo bảng do người gọi đưa ⇒ chỉ trong package.
    public fun verify_with(v: vector<u8>): bool {
        scaas::p256::verify_with(&vector[], &v, &v)
    }
}
