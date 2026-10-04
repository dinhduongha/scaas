/// Gói lại từng entry được relay của `bamboo` — mỗi lời gọi phải là lỗi biên dịch (visibility).
module wrapcheck::wrap {
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::Object;

    public entry fun relay_pay(l: &signer, o: address, a: Object<Metadata>, v: vector<u8>) {
        bamboo::meta::relay_pay(l, o, a, o, 1, v, v, 0, 0, o, v, v, v, v);
    }

    public entry fun mandate_pay(l: &signer, m: address, a: Object<Metadata>, v: vector<u8>) {
        bamboo::mandate::pay(l, m, a, m, 1, v, 0, m, v, v, v);
    }

    public entry fun mandate_revoke(l: &signer, m: address, v: vector<u8>) {
        bamboo::mandate::revoke_signed(l, m, 0, v, v, v);
    }

    public entry fun mandate_open(o: address, v: vector<u8>) {
        bamboo::mandate::open(o, v, v, 1, 1, 1, 1, vector[], 0, v, v, v);
    }

    public entry fun settle(l: &signer, m: address, v: vector<u8>) {
        bamboo::dex::settle(l, m, v, v, v, v, v, v, v, v, 1, 1, v);
    }

    public entry fun cancel(m: address, v: vector<u8>) {
        bamboo::dex::cancel_signed(m, v, v, v, v);
    }

    public entry fun invalidate(m: address, v: vector<u8>) {
        bamboo::dex::invalidate_nonces_signed(m, m, 1, v, v, v);
    }

    public entry fun manage_signed(o: address, v: vector<u8>) {
        bamboo::meta::manage_signed(o, 0, 0, v, v, v, o, 0, v, v, v);
    }
}
