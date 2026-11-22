# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T42 (per-row Cargo features) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t42-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

W = "clients/ua-rs/src/wallet/mod.rs"
TX = "clients/ua-rs/src/wallet/tx.rs"
UA = "clients/ua-rs/Cargo.toml"
SC = "clients/scaas-sdk/Cargo.toml"
E = "clients/scaas-sdk/src/error.rs"
# the core build: wallet, no family
CORE = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --no-default-features --features wallet --test core_only "
TREE = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --test feature_tree "
MUTANTS = [
    # a family's gate dropped: its network reachable without the feature
    ("a native network derived without its row", [(W, "        network.require()?;\n        network.coin_ok(coin_type)?;", "        network.coin_ok(coin_type)?;")],
     CORE + "a_family_that_is_off_is_feature_missing"),
    ("a Polkadot path derived without fam-dot", [(W, "        Network::Polkadot.require()?;\n        let junctions", "        let junctions")],
     CORE + "a_family_that_is_off_is_feature_missing"),
    ("the EVM transaction built without fam-evm", [(TX, "        Network::Evm.require()?;\n", "")],
     CORE + "a_family_that_is_off_is_feature_missing"),
    ("a row read as built whatever the feature", [(W, '"fam-sui" => cfg!(feature = "fam-sui"),', '"fam-sui" => true,')],
     CORE + "every_network_names_its_feature"),
    ("Hedera's ECDSA side under fam-hedera", [(W, "Network::Evm | Network::HederaEcdsa => \"fam-evm\",\n            Network::HederaEd25519 => \"fam-hedera\",",
                                                "Network::Evm => \"fam-evm\",\n            Network::HederaEcdsa | Network::HederaEd25519 => \"fam-hedera\",")],
     CORE + "every_network_names_its_feature"),
    # the SDK feature not enabling its ua-rs feature
    ("the SDK's near without fam-near", [(SC, ', "scaas-ua/fam-near"]', "]")], TREE + "family_features_enable_their_rows"),
    ("native-networks without fam-btc", [(SC, '"scaas-ua/fam-btc", ', "")], TREE + "family_features_enable_their_rows"),
    # chain code in the core
    ("alloy-rlp back in the core", [(UA, 'wallet = [\n  "pq",\n', 'wallet = [\n  "pq",\n  "dep:alloy-rlp",\n')], TREE + "ua_rows_and_the_core"),
    ("schnorrkel back in the core", [(UA, 'wallet = [\n  "pq",\n', 'wallet = [\n  "pq",\n  "dep:schnorrkel",\n')], TREE + "ua_rows_and_the_core"),
    # an xcheck-* crate reachable from the default build
    ("an xcheck feature on by default", [(UA, '  "fam-arweave",\n]', '  "fam-arweave",\n  "xcheck-near",\n]'),
                                        (UA, "fam-arweave = []\n", "fam-arweave = []\nxcheck-near = []\n")], TREE + "ua_rows_and_the_core"),
    ("a row off by default", [(UA, '  "fam-btc",\n  "fam-arweave",\n]', '  "fam-arweave",\n]')], TREE + "ua_rows_and_the_core"),
    # the SDK's one list of names
    ("ua-rs' FeatureMissing passed through as Ua", [(E, "            scaas_ua::wallet::Error::FeatureMissing => SdkError::FeatureMissing,\n", "")],
     TREE + "ua_feature_missing_is_the_sdks"),
]

if __name__ == "__main__":
    main("t42", MUTANTS)
