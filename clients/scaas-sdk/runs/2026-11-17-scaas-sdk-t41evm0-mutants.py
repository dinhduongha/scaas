# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T41.evm step 0 (the SDK feature `evm`) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t41evm0-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

L = "clients/scaas-sdk/src/lib.rs"
SC = "clients/scaas-sdk/Cargo.toml"
FM = "clients/scaas-sdk/src/wallet/families/mod.rs"
SOL = "clients/scaas-sdk/src/wallet/families/solana.rs"
ALG = "clients/scaas-sdk/src/wallet/families/algorand.rs"
NE = "vault,account,wallet,file-store,mlock,near,algorand,cosmos,aptos,solana,soroban,sui,ton,native-networks,raw-native"
SDK = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 "
NOEVM = SDK + f"--no-default-features --features {NE} "
MUTANTS = [
    # the open-time refusal of an EVM profile without `evm`
    ("an EVM profile opened without evm", [(L, "            if p.family == Family::Evm && !cfg!(feature = \"evm\") {\n                return Err(SdkError::FeatureMissing);\n            }\n", "")],
     NOEVM + "--test evm_feature an_evm_profile_needs_the_evm_feature"),
    ("the EVM refusal in every build", [(L, "if p.family == Family::Evm && !cfg!(feature = \"evm\") {", "if p.family == Family::Evm {")],
     SDK + "--test evm_feature an_evm_profile_needs_the_evm_feature"),
    # the feature bit
    ("the evm bit never set", [(L, "        (cfg!(feature = \"evm\"), EVM),\n", "")], SDK + "--test evm_feature an_evm_profile_needs_the_evm_feature"),
    # the manifest: evm without its row, alloy back in account / wallet
    ("evm without fam-evm", [(SC, '"dep:alloy", "scaas-ua/fam-evm"]', '"dep:alloy"]')], SDK + "--test feature_tree family_features_enable_their_rows"),
    ("alloy back in wallet", [(SC, 'wallet = ["vault"]\n', 'wallet = ["vault", "dep:alloy"]\n')], NOEVM + "--test feature_tree alloy_only_under_evm"),
    ("alloy's providers back in account", [(SC, 'account = ["vault"]\n', 'account = ["vault", "scaas-rpc/evm"]\n')],
     NOEVM + "--test feature_tree alloy_only_under_evm"),
    # the decimals that replace alloy's U256 in the family reads
    ("a decimal above 2^256 - 1 taken", [(FM, "(t.len() < 78 || (t.len() == 78 && t <= U256_MAX))", "t.len() <= 78")],
     NOEVM + "--lib u256_decimals"),
    ("a sum's carry dropped", [(SOL, "    if carry > 0 {\n        out.push(b'0' + carry);\n    }\n", "")], NOEVM + "--lib dec_add_carries_and_caps"),
    ("a box word's high bytes dropped", [(ALG, "    let mut n = b.to_vec();", "    let mut n = b.get(b.len().saturating_sub(8)..).unwrap_or(b).to_vec();")],
     NOEVM + "--lib be_dec_words"),
]

if __name__ == "__main__":
    main("t41evm0", MUTANTS)
