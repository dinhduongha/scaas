//! P6-ANON S4, LH-2: op 7 `R_TXM` statements across the C core, pqz-stmt and Ligero (ffi/vectors/lh2.sh).
//!
//!   lh2 <C dir> <Ligero dir> <out dir>
//!
//! C dir: pqz_bench.c's op 7 statements and witnesses (`dump_setup DIR txm`: txm<M>[_0]_{stmt,wit}.bin, filler opTag
//! and recipientsHash, PQZL's id). Each gets the op 7 opTag and recipientsHash = keccak256(UA_0 ‖ … ‖ UA_{M−1}) with
//! UA_j = 0x1000 + j (the hashed-only words; the witness stays valid), then, under every id whose built leg counts
//! contain M: `pqz_stmt::parse_multi` + `encode` give the same bytes, `pqz_ffi::prove` (PQZL: the C core; PQZH:
//! Ligero) proves it and the precompile accepts (PQZL: the generic verifier agrees), and a flipped recipientsHash bit is
//! rejected. The PQZH-id copies (M ≤ 4) go to <out dir> for xcheck/kat_multi.py (pqz_kat.py rebuilds the statement and
//! re-encrypts every ciphertext from the C witness).
//! Ligero dir: the Ligero crate's `client::setup_multi` statements (`examples/dump_setup`, PQZH id): proved and
//! verified as they are by Ligero, and with PQZL's id by the C core (generic and specialised verifier).
//! One JSON line per (statement, id); exit 1 on any failure.
#[cfg(not(feature = "prove"))]
fn main() {
    eprintln!("lh2 needs --features prove");
    std::process::exit(2);
}

#[cfg(feature = "prove")]
fn main() {
    use pqz_ffi::stmt::{self as st, built_legs, OP_TAG_TRANSFER_MULTI, OP_TRANSFER_MULTI, PQZH_ID, PQZL_ID};
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (cdir, ldir, out) = (&a[0], &a[1], &a[2]);
    let keccak = |b: &[u8]| pqz_ffi::selftest::keccak(&[b]);
    let mut fails = 0;
    let mut n = 0;
    let mut check = |src: &str, name: &str, s: &[u8], w: &[u8]| {
        let m = st::word_u64(s[32 * st::H_LEGS..32 * st::H_LEGS + 32].try_into().unwrap()).unwrap() as usize;
        for (sys, id) in [("pqzl", PQZL_ID), ("pqzh", PQZH_ID)] {
            if !built_legs(&id).contains(&m) {
                continue;
            }
            let mut s = s.to_vec();
            s[32..64].copy_from_slice(&id);
            let round = st::parse_multi(&s).ok().and_then(|x| x.encode().ok()) == Some(s.clone());
            let p = pqz_ffi::prove(OP_TRANSFER_MULTI, &s, w, &[0x5d; 32]);
            let (len, valid, generic, tampered) = match &p {
                Ok(p) => {
                    let ok = pqz_ffi::precompile(&st::input(OP_TRANSFER_MULTI, &s, p)) == Ok(pqz_ffi::VALID);
                    let g = (id == PQZL_ID).then(|| pqz_ffi::pqzl::verify_generic(OP_TRANSFER_MULTI, &s, p) == Ok(true));
                    let mut t = s.clone();
                    t[32 * st::H_RECIPIENTS_HASH + 31] ^= 1;
                    let bad = pqz_ffi::precompile(&st::input(OP_TRANSFER_MULTI, &t, p)) == Ok(pqz_ffi::INVALID);
                    (p.len(), ok, g, bad)
                }
                Err(_) => (0, false, None, false),
            };
            let ok = round && valid && generic != Some(false) && tampered;
            fails += !ok as usize;
            n += 1;
            println!(
                "{{\"src\": \"{src}\", \"stmt\": \"{name}\", \"id\": \"{sys}\", \"stmt_bytes\": {}, \"parse_encode_equal\": {round}, \"proof_bytes\": {len}, \"valid\": {valid}, \"generic\": {}, \"recipientsHash_flip_rejected\": {tampered}, \"ok\": {ok}}}",
                s.len(),
                generic.map_or("null".into(), |g| g.to_string())
            );
            if src == "c" && id == PQZH_ID {
                std::fs::write(format!("{out}/{name}_stmt.bin"), &s).unwrap();
                std::fs::write(format!("{out}/{name}_wit.bin"), w).unwrap();
            }
        }
    };
    for (src, dir) in [("c", cdir), ("ligero", ldir)] {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok()?.strip_suffix("_stmt.bin").map(String::from))
            .filter(|n| n.starts_with("txm"))
            .collect();
        names.sort();
        for name in names {
            let mut s = std::fs::read(format!("{dir}/{name}_stmt.bin")).unwrap();
            let w = std::fs::read(format!("{dir}/{name}_wit.bin")).unwrap();
            if src == "c" {
                let m = st::word_u64(s[32 * st::H_LEGS..32 * st::H_LEGS + 32].try_into().unwrap()).unwrap() as usize;
                let uas: Vec<u8> = (0..m).flat_map(|j| st::u64_word(0x1000 + j as u64)).collect();
                s[..32].copy_from_slice(&OP_TAG_TRANSFER_MULTI);
                let h = 32 * st::H_RECIPIENTS_HASH;
                s[h..h + 32].copy_from_slice(&keccak(&uas));
            }
            check(src, &name, &s, &w);
        }
    }
    println!("{{\"lh2\": \"{}\", \"cases\": {n}, \"fails\": {fails}}}", if fails == 0 && n > 0 { "ok" } else { "FAIL" });
    std::process::exit((fails != 0 || n == 0) as i32);
}
