// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The timing measurement of tests/fndsa/timing.rs natively (falcon-rs, `fpemu`, the code wasm32 runs; Fable audit of
//! vendor-falcon-rs). A measurement tool, not a gate: ignored; run it only on an idle machine and with the owner's word:
//! `cargo test --release --features pq --test fndsa_timing -- --ignored --nocapture` (`FNDSA_TIMING_SCALE`, default 1).
//! UNAUDITED.
#[allow(dead_code)] // verify
#[path = "../src/falcon/soft.rs"]
mod soft;
#[path = "fndsa/timing.rs"]
mod timing;

#[test]
#[ignore = "a timing measurement, not a gate"]
fn falcon_rs_timing() {
    let t0 = std::time::Instant::now();
    let now = move || t0.elapsed().as_secs_f64() * 1e9;
    let scale = std::env::var("FNDSA_TIMING_SCALE").map_or(1, |s| s.parse().unwrap());
    println!("{}", timing::run(&now, scale));
}
