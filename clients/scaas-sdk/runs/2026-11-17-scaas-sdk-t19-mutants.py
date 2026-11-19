# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T19 (native networks, the raw entry) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t19-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

R = "clients/scaas-sdk/src/wallet/raw.rs"
M = "clients/scaas-sdk/src/wallet/mod.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
RAW = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F},native-networks,raw-native --lib "
DOC = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --doc"
MUTANTS = [
    ("an EVM key on the raw path", [(R, "|| matches!(network, \"evm\" | \"hedera_ecdsa\" | \"ton\")", "|| matches!(network, \"ton\")")], RAW + "wallet::raw::tests::raw_refuses_evm_keys"),
    ("the SDK's OCMS refusal dropped", [(R, "|| OFFCHAIN.iter().any(|p| m.starts_with(p))", "|| OFFCHAIN.iter().skip(1).any(|p| m.starts_with(p))")], RAW + "wallet::raw::tests::raw_refuses_offchain_envelopes_in_the_sdk"),
    ("a 0x05 first-byte refusal back", [(R, "            if envelope\n                || network.starts_with(\"bitcoin_\")", "            if envelope\n                || m.first() == Some(&5)\n                || network.starts_with(\"bitcoin_\")")], RAW + "wallet::raw::tests::raw_signs_leading_0x05"),
    ("a Sui key routed to sign_digest", [(R, "Digest32 { .. } if network.starts_with(\"bitcoin_\") => Ok(()),", "Digest32 { .. } if network.starts_with(\"bitcoin_\") || network == \"sui\" => Ok(()),")], RAW + "wallet::raw::tests::raw_envelope_families"),
    ("a GRAM key accepted", [(R, "|| matches!(network, \"evm\" | \"hedera_ecdsa\" | \"ton\")", "|| matches!(network, \"evm\" | \"hedera_ecdsa\")")], RAW + "wallet::raw::tests::raw_refuses_gram"),
    ("the raw call in the default surface", [(M, "#[cfg(feature = \"raw-native\")]\nmod raw;", "mod raw;"), (M, "#[cfg(feature = \"raw-native\")]\npub use raw::", "pub use raw::")], DOC),
]

if __name__ == "__main__":
    main("t19", MUTANTS)
