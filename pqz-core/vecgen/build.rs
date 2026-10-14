//! Links the C core as ../build.sh builds it (libpqz.a in ../build/native: run `../build.sh native` first; build.sh
//! runs the symbol scan). No flags of its own, so the generator's PQZL bytes are libpqz's.
fn main() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../build/native");
    let lib = dir.join("libpqz.a");
    assert!(lib.exists(), "{} missing: run pqz-core/build.sh native first", lib.display());
    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=static=pqz");
    println!("cargo:rerun-if-changed={}", lib.display());
}
