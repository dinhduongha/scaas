# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Avalanche / Polkadot / Arweave plan T5 mutants (PqChatStore): python3 runs/2026-11-21-avax-dot-arweave-t5-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

C = "smartcontracts/evm/src/pqchat/PqChatStore.sol"
T = "cd smartcontracts/evm && ../../scripts/capped forge test --match-path test/pqchat/PqChatStore.t.sol --match-test "
MUTANTS = [
    ("the bound 32 above", [(C, "BLOB_MAX = 24_576;", "BLOB_MAX = 24_608;")], T + "test_env24417Refused", "test_env24417Refused"),
    ("the bound 32 below", [(C, "BLOB_MAX = 24_576;", "BLOB_MAX = 24_544;")], T + "test_env24416Accepted", "test_env24416Accepted"),
    ("the clamp at 17", [(C, "STORED_RANGE_MAX = 16;", "STORED_RANGE_MAX = 17;")], T + "test_storedRange_clampsTo16",
     "test_storedRange_clampsTo16"),
    ("a hint's list keyed wrong", [(C, "address[] storage list = _s().stored[hint];", "address[] storage list = _s().stored[bytes8(0)];")],
     T + "test_listsArePerHint", "test_listsArePerHint"),
    ("v not checked", [(C, "if (v != 1 || payload.length", "if (payload.length")], T + "test_vNot1Refused", "test_vNot1Refused"),
]

if __name__ == "__main__":
    main("t5", MUTANTS)
