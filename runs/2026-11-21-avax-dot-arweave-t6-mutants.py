# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T6 mutants (PqChatStore's deploy path; forkcheck's case fields it uses):
python3 runs/2026-11-21-avax-dot-arweave-t6-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

D = "smartcontracts/evm/script/deploy_pqchatstore.py"
F = "smartcontracts/evm/script/forkcheck.py"
TD = "cd smartcontracts/evm && python3 -I script/test_deploy_pqchatstore.py "
TF = "python3 -I smartcontracts/evm/script/test_forkcheck.py "
MUTANTS = [
    (
        "the code-hash check skipped",
        [(D, '    if have != rel["runtimeCodeHash"].lower():', "    if False:")],
        TD + "deployed_code_hash_differs_refused",
        "FAIL deployed_code_hash_differs_refused",
    ),
    (
        "the init-code hash check skipped",
        [(D, '    if keccak(a["bytecode"]["object"]) != rel["initCodeHash"].lower():', "    if False:")],
        TD + "local_init_hash_differs_refused",
        "FAIL local_init_hash_differs_refused",
    ),
    (
        "salt not 0",
        [(D, 'SALT = "00" * 32', 'SALT = "00" * 31 + "01"')],
        TD + "release_pins_the_create2_address",
        "FAIL release_pins_the_create2_address",
    ),
    (
        "a case's revert data not compared",
        [(F, '        elif not c["ok"] and "revert" in c and', "        elif False and")],
        TF + "case_from_revert_logs",
        "FAIL case_from_revert_logs",
    ),
    (
        "a case's logs not compared",
        [(F, '        elif "logs" in c and', "        elif False and")],
        TF + "case_from_revert_logs",
        "FAIL case_from_revert_logs",
    ),
]

if __name__ == "__main__":
    main("t6", MUTANTS)
