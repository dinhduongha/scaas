fn main() {
    cxx_build::bridge("src/lib.rs").std("c++17").compile("scaas_ua_cxx_bridge");
    println!("cargo:rerun-if-changed=src/lib.rs");
}
