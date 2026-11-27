# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles KH mutants (owner 2026-11-27, O15, CLI-UPR-32: ua-rs's `key-handles`, `user-profile` with no signing code),
against the nm gate clients/ua-rs/runs/2026-11-27-key-handles-nm.py:
python3 clients/scaas-sdk/runs/2026-11-27-user-profiles-kh-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-27-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

UA = "clients/ua-rs/Cargo.toml"
NM = "clients/ua-rs/runs/2026-11-27-key-handles-nm.py"
# the gate's cargo builds go through scripts/capped (its default CAP)
GATE = "python3 " + NM
MUTANTS = [
    ("user-profile enables wallet again",
     [(UA, 'user-profile = ["key-handles"]\n', 'user-profile = ["key-handles", "wallet"]\n')],
     GATE),
    ("the signing pattern matches nothing (the positive control)",
     [(NM, 'SIGNING = re.compile(\n', 'SIGNING = re.compile("(?!)") or re.compile(\n')],
     GATE),
]

if __name__ == "__main__":
    mutants_lib.main("kh", MUTANTS)
