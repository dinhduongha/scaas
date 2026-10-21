//! B-1 regression fixture (review B's B-1 = review A's A-1; features `c-oracle`, `test-hooks`): review A's cheating
//! prover (`scratchpad/reviewA/poc`, a patched copy of `tbox::prove`, now the `set_cheat` hook of this crate). It
//! publishes a z3 / z4 that are not `y + β·R·s` and cancels their V-folded error through the coefficients 0 and d/2 of
//! g, with V seeded from hz: before B-1 (V3 / V4 drawn before `tg`) that V was the verifier's and all four verifiers
//! accepted modes 1 and 2 on all 14 relation codes. Since B-1 V comes from the hash after `tg`, which depends on g:
//! every mode must be rejected by Rust `verify` / `verify_fast` and C `pqz_verify` / `pqz_verify_fast`. Mode 0 (the
//! hook off) must give the vectors' honest proof, so the cheating proofs differ from honest ones only by the cheat.
use pqzl::c_oracle::{c_verify, c_verify_fast};
use pqzl::{set_cheat, Ctx};

mod common;

#[test]
fn cheating_prover_rejected() {
    let rows = common::pqzl_rows();
    let mut seen = std::collections::HashSet::new();
    let mut ctx = Box::new(Ctx::new());
    let mut accepted = Vec::new();
    for r in rows.iter().filter(|r| seen.insert(r.code)) {
        let mut line = format!("{:<20} code {:#04x}:", r.name, r.code);
        for mode in [0u32, 3, 1, 2] {
            set_cheat(mode);
            let res = ctx.prove(r.op, &r.stmt, &r.wit, &r.rnd32);
            set_cheat(0);
            let p = res.unwrap_or_else(|e| panic!("{} mode {mode}: prove {e:?}", r.name));
            let v = [
                ctx.verify(r.op, &r.stmt, &p),
                ctx.verify_fast(r.op, &r.stmt, &p),
                c_verify(r.op, &r.stmt, &p),
                c_verify_fast(r.op, &r.stmt, &p),
            ];
            line += &format!(" m{mode} {v:?};");
            if mode == 0 {
                assert_eq!(p, r.proof, "{}: mode 0 is not the honest prover", r.name);
                assert_eq!(v, [true; 4], "{}: honest proof rejected", r.name);
            } else if v.iter().any(|&x| x) {
                accepted.push(format!("{} mode {mode} {v:?}", r.name));
            }
        }
        println!("{line}");
    }
    println!("VERDICT: B-1 cheating prover {} ({} accepted)", if accepted.is_empty() { "rejected" } else { "FORGES" }, accepted.len());
    assert!(accepted.is_empty(), "cheating proofs accepted (verify, verify_fast, C verify, C verify_fast): {accepted:?}");
}
