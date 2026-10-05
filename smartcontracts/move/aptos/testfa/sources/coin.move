/// FA thử cho e2e localnet (không deploy ngoài localnet).
module testfa::coin {
    use std::option;
    use std::signer;
    use std::string::utf8;
    use aptos_framework::fungible_asset::{Self, MintRef};
    use aptos_framework::object;
    use aptos_framework::primary_fungible_store;

    struct Refs has key { mint: MintRef }

    public entry fun create(creator: &signer, symbol: vector<u8>) {
        let c = object::create_named_object(creator, symbol);
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &c, option::none(), utf8(symbol), utf8(symbol), 6, utf8(b""), utf8(b""),
        );
        move_to(&object::generate_signer(&c), Refs { mint: fungible_asset::generate_mint_ref(&c) });
    }

    public entry fun mint(creator: &signer, symbol: vector<u8>, to: address, amount: u64) {
        let meta = object::create_object_address(&signer::address_of(creator), symbol);
        primary_fungible_store::mint(&Refs[meta].mint, to, amount)
    }
}
