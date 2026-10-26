//! P6-FS binding test (lazer#28; feature `test-hooks`), as `pqzl/sz/fs_bind.c` for the C core: observes which seed
//! each Fiat–Shamir challenge of `verify` and `verify_fast` is derived from (`fs_trace_take`). Since the R0 review fix
//! (R1-C8) on three relation shapes (R_REG, R_TX, R_TXM M = 8 audited) and with a fifth mutation, the final challenge c
//! (kind 9: one coefficient changed; R0-C3's filtered c is recomputed from the transcript), which must be rejected.
//! Per shape: one honest proof
//! with a fixed rnd32 and three re-encodings of it with one field changed (`test_mutate`, r1 = 0, r2 = 0x105:
//! poly 0, coefficient 5, sign +): h (kind 7; r1 & 12 == 0, so not coefficient 0 or 32), z3 (kind 14, within Bz3),
//! z4 (kind 5 at the bound, (r1 >> 8) even), tg (kind 15, B-1: the commitment to g, coefficient +1). The V4 / V3
//! seeds (kinds 2 / 3) must differ between the honest and the z3-, z4- and tg-changed proofs, the mu seed (kind 5)
//! between the honest and the h-changed proof; a missing record (the verifier rejected before the challenge) is a
//! failure, never "differ"; the honest proof verifies and the tg-changed one does not.
//! `verify_fast` must report the SV-tagged kinds 12 / 13 / 15 (another path records the untagged ones: MISSING).
//! Observation only: no proof meant to verify is built or searched for.
use pqzl::{fs_trace_take, test_mutate, Ctx, OP_REGISTER};

mod common;

fn seed(r: &[(u8, [u8; 32], u64)], kind: u8) -> Option<[u8; 32]> {
    r.iter().find(|x| x.0 == kind).map(|x| x.1)
}

fn hex4(s: Option<[u8; 32]>) -> String {
    s.map_or("none".into(), |s| s[..4].iter().map(|b| format!("{b:02x}")).collect())
}

/// the relation shapes the binding is checked on (review R1-C8: not only R_REG, M = 0, nbin = 0): R_REG, R_TX (one
/// leg, the binary part) and R_TXM M = 8 with the auditor (code 0x7b: groups, the auditor copies' windows)
const CODES: [u8; 3] = [OP_REGISTER, 1, 0x7b];

#[test]
fn fs_bind() {
    let rows = common::pqzl_rows();
    let mut ctx = Ctx::new();
    let (mut fails, mut checks) = (Vec::new(), 0);
    for code in CODES {
        let r = rows.iter().find(|r| r.code == code).unwrap_or_else(|| panic!("a row of relation {code:#x}"));
        let honest = ctx.prove(r.op, &r.stmt, &r.wit, &r.rnd32).expect("honest proof");
        let muts: Vec<(&str, Vec<u8>)> = [("h", 7), ("z3", 14), ("z4", 5), ("tg", 15), ("c", 9)]
            .into_iter()
            .map(|(n, k)| {
                let p = test_mutate(code, &honest, k, 0, 0x105).unwrap().expect("mutation re-encodes");
                assert_ne!(p, honest, "{code:#x}: mutation {n} changed nothing");
                (n, p)
            })
            .collect();
        fs_trace_take();
        for (vn, fast) in [("verify", false), ("verify_fast", true)] {
            let mut run = |p: &[u8]| {
                let ok = if fast { ctx.verify_fast(r.op, &r.stmt, p) } else { ctx.verify(r.op, &r.stmt, p) };
                (ok, fs_trace_take())
            };
            let (ok, hon) = run(&honest);
            checks += 1;
            println!("P6-FS {} {vn} honest: {}", r.name, if ok { "ACCEPT" } else { "REJECT (FAIL)" });
            if !ok {
                fails.push(format!("{} {vn} honest rejected", r.name));
            }
            for (mn, p) in &muts {
                let (okm, mt) = run(p);
                // tg (B-1) and the final challenge c (R0-C3: the eta-filtered c is recomputed from the transcript) must
                // be rejected
                if matches!(*mn, "tg" | "c") {
                    checks += 1;
                    if okm {
                        fails.push(format!("{} {vn} {mn}-mutated accepted", r.name));
                    }
                }
                let kinds: &[(u8, &str)] = match *mn {
                    "h" => &[(5, "mu seed")],
                    "c" => &[],
                    _ => &[(2, "V4 seed"), (3, "V3 seed")],
                };
                for &(k, kn) in kinds {
                    let t = k + if fast { 10 } else { 0 }; // verify_fast must report sv.rs's tagged kinds
                    let (a, b) = (seed(&hon, t), seed(&mt, t));
                    checks += 1;
                    let res = match (a, b) {
                        (Some(a), Some(b)) if a != b => "differ",
                        (Some(_), Some(_)) => "EQUAL (FAIL)",
                        _ => "MISSING (FAIL)",
                    };
                    println!(
                        "P6-FS {} {vn} {mn}-mutated ({}) kind {t} {kn}: honest {} mutated {} -> {res}",
                        r.name,
                        if okm { "accepted" } else { "rejected" },
                        hex4(a),
                        hex4(b)
                    );
                    if res != "differ" {
                        fails.push(format!("{} {vn} {mn} kind {t} {res}", r.name));
                    }
                }
            }
        }
    }
    println!("VERDICT: P6-FS Fiat-Shamir binding (lazer#28) {} ({} failed checks of {checks})", if fails.is_empty() { "ok" } else { "FAIL" }, fails.len());
    assert!(fails.is_empty(), "P6-FS binding failed: {fails:?}");
}
