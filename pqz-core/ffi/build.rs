//! Builds libpqz (the PQZL C core) as build.sh does: the same sources, `-std=gnu11 -O2 -fno-builtin -fno-math-errno
//! -ffp-contract=off`, the specialised verifier (`-DPQZ_SV`), native with `-fstack-protector-strong`; wasm32
//! freestanding (`-DPQZ_FREESTANDING`, src/freestanding) with pqz_wasm_rt.c's 128-bit helpers only (their shifts are
//! branch-free, the prover shifts by secret amounts; Rust's compiler_builtins provides mem*). Then the symbol scan
//! (../check_symbols.sh) on the archive: no malloc, stdio, libm, GMP, MPFR. Also turns the self-test proofs
//! (selftest/*.hex) into bytes for include_bytes!.
use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    let core = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("..");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let wasm = env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "wasm32";

    // lazer.h as build.sh's lazer_h() assembles it
    let inc = out.join("include");
    fs::create_dir_all(&inc).unwrap();
    let rd = |p: &str| fs::read_to_string(core.join(p)).unwrap();
    let h = format!(
        "{}\n#ifndef LAZER_CONFIG_H\n#define LAZER_CONFIG_H\n{}#endif\n\n{}\n/* PQZ: no CRT moduli tables (upstream \
         moduli.h); generated rings name them, the fork ignores them */\n#define moduli_d64 ((const modulus_srcptr *)0)\n\
         #define moduli_d128 ((const modulus_srcptr *)0)\n",
        rd("lazer/lazer-in1.h"),
        rd("lazer/config.h"),
        rd("lazer/lazer-in2.h")
    );
    fs::write(inc.join("lazer.h"), h).unwrap();

    let mut b = cc::Build::new();
    b.no_default_flags(true).cargo_warnings(false);
    if !wasm {
        b.compiler(env::var("CC").unwrap_or("clang".into()));
    }
    for f in ["-std=gnu11", "-O2", "-fno-builtin", "-fno-math-errno", "-ffp-contract=off", "-DPQZ_SV", "-Wall", "-Wextra", "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-sign-compare"] {
        b.flag(f);
    }
    b.include(&inc).include(core.join("src")).include(core.join("lazer")).include(core.join("params"));
    for f in ["pqz_lazer", "pqz_ntt", "pqz_arena", "pqz_rel", "pqz_keys", "pqz_sv"] {
        b.file(core.join(format!("src/{f}.c")));
    }
    if wasm {
        for f in ["--target=wasm32-unknown-unknown", "-ffreestanding", "-DPQZ_FREESTANDING"] {
            b.flag(f);
        }
        b.include(core.join("src/freestanding"));
        b.file("csrc/wasm_ti3.c");
    } else {
        for f in ["-fPIC", "-fstack-protector-strong", "-ffunction-sections", "-fdata-sections"] {
            b.flag(f);
        }
    }
    // feature `fuzz` (pqz-core/fuzz): ASan + UBSan (minus the upstream nits of STATUS.md Open 4, as sv/fuzz.sh),
    // libFuzzer coverage, the test hooks; the sanitizer runtime is linked by the fuzz target, so no symbol scan
    let fuzz = env::var_os("CARGO_FEATURE_FUZZ").is_some();
    if fuzz {
        for f in ["-g", "-fno-omit-frame-pointer", "-DPQZ_TEST_HOOKS", "-fsanitize=address,undefined,fuzzer-no-link",
                  "-fno-sanitize=vla-bound,pointer-overflow", "-fno-sanitize-recover=all"] {
            b.flag(f);
        }
    }
    b.compile("pqz");

    if !fuzz {
        let st = std::process::Command::new(core.join("check_symbols.sh")).arg(out.join("libpqz.a")).output().unwrap();
        if !st.status.success() {
            panic!("check_symbols.sh: {}", String::from_utf8_lossy(&st.stderr));
        }
    }

    for name in ["pqzl_reg", "pqzh_reg"] {
        let src = Path::new("selftest").join(format!("{name}.hex"));
        let hex = fs::read_to_string(&src).unwrap_or_default();
        let hex: Vec<u8> = hex.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
        let nib = |c: u8| (c as char).to_digit(16).expect("selftest hex") as u8;
        let bin: Vec<u8> = hex.chunks(2).map(|p| nib(p[0]) << 4 | nib(p[1])).collect();
        fs::write(out.join(format!("{name}.bin")), bin).unwrap();
        println!("cargo:rerun-if-changed={}", src.display());
    }
    for d in ["src", "lazer", "params", "check_symbols.sh"] {
        println!("cargo:rerun-if-changed={}", core.join(d).display());
    }
    println!("cargo:rerun-if-changed=csrc");
}
