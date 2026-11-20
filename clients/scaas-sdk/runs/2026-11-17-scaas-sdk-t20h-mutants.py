# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T20h (the Go binding) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t20h-mutants.py check | run [name]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

B = "clients/scaas-sdk/src/binding.rs"
X = "clients/scaas-sdk/bindings/go/fix_generated.py"
GO = "cd clients/scaas-sdk/bindings/go && bash run.sh"
FX = "cd clients/scaas-sdk/bindings/go && python3 -I test_fix_generated.py"
MUTANTS = [
    (
        "the PRF output names another secret",
        [(B, "self.0.get_assertion(req, prf_out.id()).await", "self.0.get_assertion(req, prf_out.id() + 1).await")],
        GO,
        "TestStoreAuthenticatorPanicAndErrors",
    ),
    (
        "the store's write drops the expected revision",
        [(B, "self.0.put_if(name, prev_rev, bytes, policy).await", "self.0.put_if(name, None, bytes, policy).await")],
        GO,
        "TestStoreAuthenticatorPanicAndErrors",
    ),
    (
        "the fixup leaves the bool lowering",
        [(X, 'return LOWER.sub(r"\\1\\2 != 0", t)', "return t")],
        FX,
    ),
]

if __name__ == "__main__":
    main("t20h", MUTANTS)
