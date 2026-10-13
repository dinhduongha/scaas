use pqzh::{OP_REGISTER, OP_TRANSFER, Params, client, prove, rel};

#[test]
fn size_breakdown() {
    let s = client::setup();
    let p = Params::DEFAULT;
    for (op, st, w) in [(OP_REGISTER, &s.reg_stmt, &s.reg_wit), (OP_TRANSFER, &s.tx_stmt, &s.tx_wit)] {
        let pr = prove(op, st, w, [1; 32], &p).unwrap();
        eprintln!("op {op}: {:?}", rel::breakdown(&pr));
    }
}
