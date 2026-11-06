// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
fn main() {
    cxx_build::bridges(["src/lib.rs", "src/wallet.rs"]).std("c++17").compile("scaas_ua_cxx_bridge");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/wallet.rs");
}
