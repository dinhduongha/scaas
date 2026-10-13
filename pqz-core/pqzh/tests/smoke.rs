use pqzh::{OP_REGISTER, OP_TRANSFER, Params, client, prove, verify};

#[test]
fn honest_reg_and_tx() {
    let s = client::setup();
    let p = Params::DEFAULT;
    let t = std::time::Instant::now();
    let pr = prove(OP_REGISTER, &s.reg_stmt, &s.reg_wit, [1; 32], &p).unwrap();
    eprintln!("reg proof {} B, {:?}", pr.len(), t.elapsed());
    assert!(verify(OP_REGISTER, &s.reg_stmt, &pr, &p));
    let t = std::time::Instant::now();
    let pt = prove(OP_TRANSFER, &s.tx_stmt, &s.tx_wit, [2; 32], &p).unwrap();
    eprintln!("tx proof {} B, {:?}", pt.len(), t.elapsed());
    assert!(verify(OP_TRANSFER, &s.tx_stmt, &pt, &p));
}
