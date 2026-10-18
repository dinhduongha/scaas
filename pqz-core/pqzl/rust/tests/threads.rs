//! Review Focus 4: no globals, so concurrent use needs no lock. The sequential run is the vectors' (tests/vectors.rs:
//! `reprove_byte_equal` re-proves every PQZL row to its bytes, `all_pqzl_proofs_verify` / `sv_diff::vectors_verify_fast`
//! accept them, the negative.json rows are rejected by both verifiers); here the same operations run on 8 threads at
//! once and must give the same proofs and verdicts.
use std::sync::Mutex;

use pqzl::Ctx;

mod common;
use common::Row;

const THREADS: usize = 8;

/// `Ctx` moves between threads (`Send`); it needs no `Sync`: every call takes `&mut self`
fn send<T: Send>() {}

/// every operation on row r: the vector's proof, verify and verify_fast accept it
fn honest(c: &mut Ctx, r: &Row, prove: bool) {
    if prove {
        assert_eq!(c.prove(r.op, &r.stmt, &r.wit, &r.rnd32).as_deref(), Ok(&r.proof[..]), "{} prove", r.name);
    }
    assert!(c.verify(r.op, &r.stmt, &r.proof), "{} verify", r.name);
    assert!(c.verify_fast(r.op, &r.stmt, &r.proof), "{} verify_fast", r.name);
}

fn negative(c: &mut Ctx, (op, st, pf): &(u8, Vec<u8>, Vec<u8>)) {
    assert!(!c.verify(*op, st, pf) && !c.verify_fast(*op, st, pf), "negative row accepted");
}

/// 8 threads, a `Ctx` each: thread t proves and verifies (both verifiers) every PQZL row, starting at row t so that
/// different relations run at the same moment, and verifies its eighth of negative.json; then 8 threads share one
/// `Ctx` handed out by a `Mutex` (the `&mut` hand-off): thread t proves and verifies its eighth of the rows and
/// verifies its eighth of the negative rows, each operation taking the `Ctx` in turn, so the caches built by one
/// thread serve the others
#[test]
fn concurrent_eq_sequential() {
    send::<Ctx>();
    let rows = common::pqzl_rows();
    let negs: Vec<(u8, Vec<u8>, Vec<u8>)> = common::negative_inputs()
        .iter()
        .filter_map(|(_, b)| common::split(b).map(|(op, s, p)| (op, s.to_vec(), p.to_vec())))
        .collect();
    let n = rows.len();
    std::thread::scope(|sc| {
        for t in 0..THREADS {
            let (rows, negs) = (&rows, &negs);
            sc.spawn(move || {
                let mut c = Ctx::new();
                for k in 0..n {
                    honest(&mut c, &rows[(t + k) % n], true);
                }
                negs.iter().skip(t).step_by(THREADS).for_each(|x| negative(&mut c, x));
            });
        }
    });
    println!("separate Ctx: {THREADS} threads x {n} rows (prove, verify, verify_fast) + {} negative rows: equal", negs.len());

    let shared = Mutex::new(Ctx::new());
    let with = |f: &dyn Fn(&mut Ctx)| f(&mut shared.lock().unwrap());
    std::thread::scope(|sc| {
        for t in 0..THREADS {
            let (rows, negs, with) = (&rows, &negs, &with);
            sc.spawn(move || {
                rows.iter().skip(t).step_by(THREADS).for_each(|r| with(&|c| honest(c, r, true)));
                negs.iter().skip(t).step_by(THREADS).for_each(|x| with(&|c| negative(c, x)));
            });
        }
    });
    println!("one Ctx handed between {THREADS} threads: {n} rows (prove, verify, verify_fast) + {} negative rows: equal",
             negs.len());
}
