//! Feature `c-oracle` (dev / test only): builds the PQZL C core (../src, ../lazer, the parameter set's headers
//! pqz-core/params/sets/<set>/ named by the `set-<set>` feature) as the oracle, with
//! build.sh's flags, as pqz-ffi's build.rs does (native only): `-std=gnu11 -O2 -fno-builtin -fno-math-errno
//! -ffp-contract=off -DPQZ_SV`, plus `-DPQZ_TXM_OVERSIZE` with feature `oversize` and `-DPQZ_TEST_HOOKS` with feature
//! `test-hooks` (pqz_test_mutate; the hooks' other knobs keep their libpqz values). Without `c-oracle` nothing is built.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "c-oracle")]
    oracle::build();
}

#[cfg(feature = "c-oracle")]
mod oracle {
    use std::path::PathBuf;
    use std::{env, fs};

    pub fn build() {
        let core = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(".."); // pqz-core/pqzl
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        let feat = |f: &str| env::var_os(format!("CARGO_FEATURE_{f}")).is_some();

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
        b.compiler(env::var("CC").unwrap_or("clang".into()));
        for f in ["-std=gnu11", "-O2", "-fno-builtin", "-fno-math-errno", "-ffp-contract=off", "-DPQZ_SV", "-Wall", "-Wextra",
                  "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-sign-compare", "-fPIC", "-fstack-protector-strong",
                  "-ffunction-sections", "-fdata-sections"] {
            b.flag(f);
        }
        if feat("OVERSIZE") {
            b.flag("-DPQZ_TXM_OVERSIZE");
        }
        if feat("TEST_HOOKS") {
            b.flag("-DPQZ_TEST_HOOKS");
        }
        let set = ["n2048-kmax1024", "n2304-kmax4096"]
            .into_iter()
            .find(|s| feat(&format!("SET_{}", s.to_uppercase().replace('-', "_"))))
            .expect("one set-<set> feature");
        let setdir = core.join("../params/sets").join(set);
        b.include(&inc).include(core.join("src")).include(core.join("lazer")).include(&setdir);
        for f in ["pqz_lazer", "pqz_ntt", "pqz_arena", "pqz_rel", "pqz_keys", "pqz_sv"] {
            b.file(core.join(format!("src/{f}.c")));
        }
        b.file(core.join("rust/tests/oracle_shim.c")); // test entry points (never part of the core)
        b.compile("pqz");
        println!("cargo:rerun-if-changed={}", core.join("rust/tests/oracle_shim.c").display());
        for d in ["src", "lazer"] {
            println!("cargo:rerun-if-changed={}", core.join(d).display());
        }
        println!("cargo:rerun-if-changed={}", setdir.display());
    }
}
