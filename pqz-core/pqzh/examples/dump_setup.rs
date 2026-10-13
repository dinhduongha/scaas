//! Dump client::setup()'s statements and witnesses (R_REG, R_TX) for the byte cross-check with pqz-core
//! (xcheck/run.sh): `cargo run --release --example dump_setup -- DIR`.
fn main() {
    let dir = std::env::args().nth(1).expect("DIR");
    let s = pqzh::client::setup();
    for (n, b) in [("reg_stmt", &s.reg_stmt), ("reg_wit", &s.reg_wit), ("tx_stmt", &s.tx_stmt), ("tx_wit", &s.tx_wit)] {
        std::fs::write(format!("{dir}/{n}.bin"), b).unwrap();
    }
}
