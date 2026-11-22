# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T23, zether-prover's 12- to 24-word seeds (spec §25 Q-K15):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t23-mutants.py check | run [name...]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

K = "clients/zether-prover/src/keys.rs"
Z = "cd clients/zether-prover && ../../scripts/capped cargo test --locked --offline -j2 --test r33_keys -- --exact "
S = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features zether --test confidential -- --exact "
# no mutant for "fewer than 12 words": bip39's parse refuses every count but 12, 15, 18, 21, 24 first (equivalent)
MUTANTS = [
    ("the 24-word rule restored", [(K, "if !(12..=24).contains(&n) {", "if n != 24 {")], Z + "bip39_seed_and_word_counts"),
    ("the 24-word rule restored (the SDK's row)", [(K, "if !(12..=24).contains(&n) {", "if n != 24 {")], S + "short_seed_zether_key_is_the_provers"),
    ("no short-seed flag", [(K, "Ok((Zeroizing::new(m.to_seed(passphrase)), n < 24))", "Ok((Zeroizing::new(m.to_seed(passphrase)), false))")], Z + "bip39_seed_and_word_counts"),
]

if __name__ == "__main__":
    main("t23", MUTANTS)
