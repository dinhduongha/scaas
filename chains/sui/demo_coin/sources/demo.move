/// Coin thử (6 chữ số) — TreasuryCap về người publish. Chỉ dùng cho e2e.
module demo_coin::demo;

use sui::coin;

public struct DEMO has drop {}

#[allow(deprecated_usage)]
fun init(w: DEMO, ctx: &mut TxContext) {
    let (cap, meta) = coin::create_currency(w, 6, b"DEMO", b"Demo", b"", option::none(), ctx);
    transfer::public_freeze_object(meta);
    transfer::public_transfer(cap, ctx.sender());
}
