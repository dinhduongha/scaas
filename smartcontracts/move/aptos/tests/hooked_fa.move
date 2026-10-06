#[test_only]
/// FA dispatchable (AIP-73) có hook withdraw đếm số lần gọi: chứng minh `primary_fungible_store::transfer` mà
/// `relay_pay` dùng đi QUA hook của tài sản (spec §3.2, plan Task 2).
module scaas::hooked_fa {
    use std::features;
    use std::option;
    use std::string;
    use aptos_framework::account;
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::function_info;
    use aptos_framework::fungible_asset::{Self, FungibleAsset, Metadata, MintRef, TransferRef};
    use aptos_framework::object::{Self, Object};
    use aptos_framework::primary_fungible_store;

    struct Calls has key { withdraws: u64, mint: MintRef }

    /// Tạo FA `HOOK` (0xcafe, như fixtures::asset) với hook withdraw của module này. `b` = signer của @scaas.
    public fun create(fx: &signer, b: &signer): Object<Metadata> {
        features::change_feature_flags_for_testing(fx, vector[features::get_function_value_dispatch_feature()], vector[]);
        let creator = account::create_signer_for_test(@0xcafe);
        let c = object::create_named_object(&creator, b"HOOK");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &c, option::none(), string::utf8(b"HOOK"), string::utf8(b"HOOK"), 6, string::utf8(b""), string::utf8(b""),
        );
        let withdraw = function_info::new_function_info(b, string::utf8(b"hooked_fa"), string::utf8(b"withdraw"));
        dispatchable_fungible_asset::register_dispatch_functions(&c, option::some(withdraw), option::none(), option::none());
        move_to(&object::generate_signer(&c), Calls { withdraws: 0, mint: fungible_asset::generate_mint_ref(&c) });
        object::object_from_constructor_ref<Metadata>(&c)
    }

    public fun withdraw<T: key>(store: Object<T>, amount: u64, transfer_ref: &TransferRef): FungibleAsset {
        let m = fungible_asset::transfer_ref_metadata(transfer_ref);
        Calls[object::object_address(&m)].withdraws += 1;
        fungible_asset::withdraw_with_ref(transfer_ref, store, amount)
    }

    public fun mint(asset: Object<Metadata>, to: address, amount: u64) {
        primary_fungible_store::mint(&Calls[object::object_address(&asset)].mint, to, amount);
    }

    public fun withdraws(asset: Object<Metadata>): u64 { Calls[object::object_address(&asset)].withdraws }
}
