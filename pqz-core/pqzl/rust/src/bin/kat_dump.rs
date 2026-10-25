//! The arithmetic-layer KAT (`pqzl/kat/lazer_dump.c`'s cases and JSON) from the Rust port, on stdout:
//!   cargo run --release --bin kat_dump > kat-rust.json
//!   python3 -I ../kat/check.py ../../params/sets/<set>/lazer-3330e48-kat.json kat-rust.json
fn main() {
    match pqzl::testkit::kat_json() {
        Ok(j) => print!("{j}"),
        Err(e) => {
            eprintln!("kat_dump: {e:?}");
            std::process::exit(1);
        }
    }
}
