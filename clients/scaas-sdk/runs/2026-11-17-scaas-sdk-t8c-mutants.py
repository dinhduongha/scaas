# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T8c mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t8c-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

M = "clients/ua-rs/src/wallet/entries/mod.rs"
K = "clients/ua-rs/src/wallet/entries/pqz.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test entries "
MUTANTS = [
    ("swap two arguments of mtxUnshield (PQZ)", [(K, '"E args (amount,recipient) proof', '"E args (recipient,amount) proof')], UA + "entries_pqz"),
    ("a wrong selector on mtxPrepareAcc", [(K, '"UAPrepareAcc", "mtxPrepareAcc",', '"UAPrepareAcc", "mtxPrepare",')], UA + "entries_pqz"),
    ("drop the unsigned pqzAuth of the debits", [(K, 'const PQZ_PLAN: &str = "E args proof pqzAuth:UASig accHint @ verdict";', 'const PQZ_PLAN: &str = "E args proof accHint @ verdict";')], UA + "entries_pqz"),
    ("drop the verdict of the debits", [(K, 'const PQZ_PLAN: &str = "E args proof pqzAuth:UASig accHint @ verdict";', 'const PQZ_PLAN: &str = "E args proof pqzAuth:UASig accHint @";')], UA + "entries_pqz"),
    ("a signed verdict left out of the job", [(M, "a.iter()\n                .any(|f| f != &Val::Raw(vec![]) && f != &Val::List(vec![]))", "a.is_empty()")], UA + "entries_pqz"),
]

if __name__ == "__main__":
    main("t8c", MUTANTS)
