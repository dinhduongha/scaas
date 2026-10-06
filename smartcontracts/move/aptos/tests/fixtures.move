#[test_only]
/// Môi trường test: chain id 4 (localnet), giờ = 100 s, tài khoản stateless bật (AIP-115), FA thử do 0xcafe tạo
/// (địa chỉ metadata = `create_object_address(0xcafe, tên)` — gen_vectors.py tính cùng công thức).
module scaas::fixtures {
    use std::features;
    use std::option;
    use std::string;
    use aptos_framework::account;
    use aptos_framework::chain_id;
    use aptos_framework::fungible_asset::{Self, Metadata, MintRef};
    use aptos_framework::object::{Self, Object};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;
    use scaas::meta;

    struct Mint has key { r: MintRef }

    public fun setup(fx: &signer, b: &signer) { setup_chain(fx, b, 4) }

    public fun setup_chain(fx: &signer, b: &signer, id: u8) {
        timestamp::set_time_has_started_for_testing(fx);
        timestamp::update_global_time_for_test_secs(100);
        chain_id::initialize_for_test(fx, id);
        let std = account::create_signer_for_test(@std);
        features::change_feature_flags_for_testing(&std, vector[features::get_default_account_resource_feature()], vector[]);
        meta::init_for_test(b);
    }

    public fun asset(name: vector<u8>): Object<Metadata> {
        let creator = account::create_signer_for_test(@0xcafe);
        let c = object::create_named_object(&creator, name);
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &c, option::none(), string::utf8(name), string::utf8(name), 6, string::utf8(b""), string::utf8(b""),
        );
        move_to(&object::generate_signer(&c), Mint { r: fungible_asset::generate_mint_ref(&c) });
        object::object_from_constructor_ref<Metadata>(&c)
    }

    public fun mint(asset: Object<Metadata>, to: address, amount: u64) {
        primary_fungible_store::mint(&Mint[object::object_address(&asset)].r, to, amount);
    }

    public fun bal(asset: Object<Metadata>, who: address): u64 { primary_fungible_store::balance(who, asset) }

    public fun set_now(s: u64) { timestamp::update_global_time_for_test_secs(s) }
}
