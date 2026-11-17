// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Feature `pq`: builds the vendored PQClean Falcon-padded-512 / -1024 (vendor/pqclean-falcon-seeded, MD-8) and sets
//! `cfg(scaas_falcon)`. Not on wasm32: PQClean's C needs a libc (`stdlib.h`, `malloc` in fips202.c) that
//! wasm32-unknown-unknown lacks (T0), so the Falcon kinds are `KindUnavailable` there and their signatures do not verify
//! (spec §12).

fn main() {
    println!("cargo::rustc-check-cfg=cfg(scaas_falcon)");
    #[cfg(feature = "pq")]
    falcon();
}

#[cfg(feature = "pq")]
fn falcon() {
    use std::env;
    use std::path::Path;
    println!("cargo::rerun-if-changed=vendor/pqclean-falcon-seeded");
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32") {
        return;
    }
    let root = Path::new("vendor/pqclean-falcon-seeded");
    let out = Path::new(&env::var("OUT_DIR").expect("OUT_DIR")).to_path_buf();
    for (logn, dir) in [("9", "falcon-padded-512"), ("10", "falcon-padded-1024")] {
        let d = root.join(dir);
        let mut b = cc::Build::new();
        b.out_dir(out.join(dir)).include(root).include(&d).define("FNDSA_LOGN", logn).file(root.join("seeded.c"));
        for f in ["codec.c", "common.c", "fft.c", "fpr.c", "keygen.c", "rng.c", "sign.c", "vrfy.c"] {
            b.file(d.join(f));
        }
        b.compile(&format!("scaas_ua_{}", dir.replace('-', "_")));
    }
    cc::Build::new().out_dir(out.join("fips202")).include(root).file(root.join("fips202.c")).compile("scaas_ua_fips202");
    println!("cargo::rustc-cfg=scaas_falcon");
}
