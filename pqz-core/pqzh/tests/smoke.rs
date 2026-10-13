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

#[test]
fn zk_honest_and_hiding() {
    let s = client::setup();
    let mut p = Params::DEFAULT;
    p.zk = true;
    p.max_proof = usize::MAX; // measured size in runs/; here only soundness of the hiding path
    for (op, st, w) in [(OP_REGISTER, &s.reg_stmt, &s.reg_wit), (OP_TRANSFER, &s.tx_stmt, &s.tx_wit)] {
        let a = prove(op, st, w, [1; 32], &p).unwrap();
        let b = prove(op, st, w, [2; 32], &p).unwrap();
        eprintln!("zk op {op}: {} B", a.len());
        assert_ne!(a, b, "hiding proofs depend on the prover's randomness");
        assert!(verify(op, st, &a, &p) && verify(op, st, &b, &p));
        let mut bad = a.clone();
        bad[a.len() / 2] ^= 1;
        assert!(!verify(op, st, &bad, &p));
        let mut plain = p;
        plain.zk = false;
        assert!(!verify(op, st, &a, &plain), "a hiding proof is not a plain proof");
    }
}
