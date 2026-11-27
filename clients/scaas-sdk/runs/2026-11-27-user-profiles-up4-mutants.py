# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles UP4 mutants (SDK store codes, rev_of's sealed bound, test-hooks a test feature):
python3 clients/scaas-sdk/runs/2026-11-27-user-profiles-up4-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-27-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

V = "clients/scaas-sdk/src/vault/mod.rs"
S = "clients/scaas-sdk/src/vault/store.rs"
F = "scripts/check_test_features.py"
LIB = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 --lib -- --exact ")
# the script's own test-hooks control (SDK graph with test-hooks forced) as an assertion: its output has no test-runner line
FEAT = ("python3 -I -c \"import subprocess, sys; o = subprocess.run([sys.executable, '-I', 'scripts/check_test_features.py'], "
        "capture_output=True, text=True).stdout; assert any('with test-hooks forced' in l and l.endswith('True') "
        "for l in o.splitlines()), 'test_hooks_control'\"")
MUTANTS = [
    ("vault::io collapsing every new store code to VaultIo",
     [(V, "        StoreError::VaultFormat => SdkError::VaultFormat,\n"
          "        StoreError::ProfileLocked => SdkError::ProfileLocked,\n"
          "        StoreError::ProfilePassphraseRequired => SdkError::ProfilePassphraseRequired,\n"
          "        StoreError::ProfileRollback => SdkError::ProfileRollback,\n"
          "        StoreError::ProfileDamaged => SdkError::ProfileDamaged,\n"
          "        StoreError::Io | StoreError::Unavailable | StoreError::Unexpected => SdkError::VaultIo,\n",
       "        _ => SdkError::VaultIo,\n")],
     LIB + "vault::tests::store_codes_map_by_name"),
    ("rev_of keeping the 16 MiB cap for sealed items",
     [(S, "    let max = if sealed {\n        SEALED_MAX\n",
       "    let max = if sealed {\n        super::keystore::MAX_BYTES\n")],
     LIB + "vault::store::tests::rev_of_sealed_bound"),
    ("test-hooks missing from the script's test features",
     [(F, 'TEST = ("vectors", "hazmat", "test-hooks")\n', 'TEST = ("vectors", "hazmat")\n')],
     FEAT),
]

if __name__ == "__main__":
    mutants_lib.main("up4", MUTANTS)
