# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T1 mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t1-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

L = "clients/scaas-sdk/src/lib.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --no-default-features --features vault,file-store "
MUTANTS = [
    ("drop the chain_uid check", [(L, "if !config::is_word_hex(&p.chain_uid) {", "if false {")],
     T + "--test config open_refuses_a_profile_without_chain_uid"),
    ("swap two feature bits", [(L, "pub const ACCOUNT: u64 = 1 << 1;", "pub const ACCOUNT: u64 = 1 << 2;"),
                               (L, "pub const WALLET: u64 = 1 << 2;", "pub const WALLET: u64 = 1 << 1;")],
     T + "--test config features_bits_match_the_build"),
    ("enable scaas-ua's defaults", [("clients/scaas-sdk/Cargo.toml", 'scaas-ua = { path = "../ua-rs", default-features = false }',
                                     'scaas-ua = { path = "../ua-rs" }')],
     "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --test feature_tree"),
]

if __name__ == "__main__":
    main("t1", MUTANTS)
