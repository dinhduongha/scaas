/// Bối cảnh chung của mọi test: cùng chuỗi tx ⇒ cùng id object ⇒ vector chữ ký (`vectors.move`,
/// sinh bởi `scripts/gen_vectors.py`) khớp.
#[test_only]
module scaas::fixtures;

use scaas::dex::{Self, Dex};
use scaas::meta::{Self, Account, AdminCap, Registry, Root};
use scaas::relayfee::{Self, RelayFee};
use scaas::vectors as v;
use sui::clock::{Self, Clock};
use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::test_scenario::{Self as ts, Scenario};

public struct EUR has drop {}

public struct USD has drop {}

const ADMIN: address = @0xad;

public fun admin(): address { ADMIN }

/// tx1 init (meta, relayfee) · tx2 network + registry SUI/EUR + DEX. Trả scenario ở đầu tx3 (sender ADMIN).
public fun setup(): Scenario {
    let mut sc = ts::begin(ADMIN);
    meta::init_for_testing(sc.ctx());
    relayfee::init_for_testing(sc.ctx());
    sc.next_tx(ADMIN);
    let mut root = sc.take_shared<Root>();
    let cap = sc.take_from_sender<AdminCap>();
    meta::set_network(&cap, &mut root, b"localnet");
    meta::new_registry<SUI>(&mut root);
    meta::new_registry<EUR>(&mut root);
    dex::create(&cap, &root, sc.ctx());
    sc.return_to_sender(cap);
    ts::return_shared(root);
    sc.next_tx(ADMIN);
    sc
}

/// tx3: account của alice (SUI, EUR), bob (SUI, EUR), carol (SUI), dave passkey (SUI). Trả ở đầu tx4.
public fun setup_accounts(): Scenario {
    let mut sc = setup();
    let mut a = sc.take_shared<Registry<SUI>>();
    let mut b = sc.take_shared<Registry<EUR>>();
    meta::open(&mut a, 0, v::alice_pk(), sc.ctx());
    meta::open(&mut b, 0, v::alice_pk(), sc.ctx());
    meta::open(&mut a, 1, v::bob_pk(), sc.ctx());
    meta::open(&mut b, 1, v::bob_pk(), sc.ctx());
    meta::open(&mut a, 2, v::carol_pk(), sc.ctx());
    meta::open_passkey(&mut a, v::dave_pk(), v::d_open(), sc.ctx());
    ts::return_shared(a);
    ts::return_shared(b);
    sc.next_tx(ADMIN);
    sc
}

/// Thị trường EUR/SUI (niêm yết, phí tắt). Trả ở đầu tx kế (sender @0x7e1).
public fun list_eur_sui(sc: &mut Scenario) { list<EUR, SUI>(sc) }

public fun list<A, B>(sc: &mut Scenario) {
    sc.next_tx(ADMIN);
    let mut d = sc.take_shared<Dex>();
    let cap = sc.take_from_sender<AdminCap>();
    dex::list_market<A, B>(&cap, &mut d, true, false, 0, 0, @0xfee, sc.ctx());
    sc.return_to_sender(cap);
    ts::return_shared(d);
    sc.next_tx(@0x7e1);
}

public fun acct<T>(sc: &mut Scenario, owner: address): Account<T> {
    let reg = ts::most_recent_id_shared<Registry<T>>().destroy_some();
    let id = object::id_from_address(sui::derived_object::derive_address(reg, owner));
    sc.take_shared_by_id<Account<T>>(id)
}

public fun fund<T>(sc: &mut Scenario, owner: address, amount: u64) {
    let mut a = acct<T>(sc, owner);
    meta::deposit(&mut a, coin::mint_for_testing<T>(amount, sc.ctx()));
    ts::return_shared(a);
    let s = sc.ctx().sender();
    sc.next_tx(s);
}

public fun clock_at(sc: &mut Scenario, seconds: u64): Clock {
    let mut c = clock::create_for_testing(sc.ctx());
    c.set_for_testing(seconds * 1000);
    c
}

/// Tổng Coin<T> `who` đang giữ (sau `next_tx`).
public fun held<T>(sc: &mut Scenario, who: address): u64 {
    let ids = ts::ids_for_address<Coin<T>>(who);
    let mut total = 0;
    ids.do!(|id| {
        let c = sc.take_from_address_by_id<Coin<T>>(who, id);
        total = total + c.value();
        ts::return_to_address(who, c);
    });
    total
}

#[test]
fun print_ids() {
    let mut sc = setup();
    let root = sc.take_shared<Root>();
    std::debug::print(&object::id(&root));
    ts::return_shared(root);
    let d = sc.take_shared<Dex>();
    std::debug::print(&object::id(&d));
    std::debug::print(&dex::market_address<EUR, SUI>(&d));
    std::debug::print(&dex::market_address<USD, SUI>(&d));
    ts::return_shared(d);
    let a = sc.take_shared<Registry<SUI>>();
    std::debug::print(&object::id(&a));
    ts::return_shared(a);
    let b = sc.take_shared<Registry<EUR>>();
    std::debug::print(&object::id(&b));
    ts::return_shared(b);
    let rf = sc.take_shared<RelayFee>();
    std::debug::print(&object::id(&rf));
    ts::return_shared(rf);
    sc.end();
}
