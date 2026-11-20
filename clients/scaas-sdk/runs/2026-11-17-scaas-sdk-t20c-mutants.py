# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T20c (the C# binding) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t20c-mutants.py check | run [name]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

B = "clients/scaas-sdk/src/binding.rs"
CS = (
    "cd clients/scaas-sdk/bindings/cs && bash ../lib.sh uniffi && ../../../../scripts/capped dotnet test --filter "
    "StoreAuthenticatorPanicAndExceptions; rc=$?; dotnet build-server shutdown >/dev/null 2>&1; exit $rc"
)
MUTANTS = [
    (
        "the PRF output names another secret",
        [(B, "self.0.get_assertion(req, prf_out.id()).await", "self.0.get_assertion(req, prf_out.id() + 1).await")],
        CS,
    ),
    (
        "the store's write drops the expected revision",
        [(B, "self.0.put_if(name, prev_rev, bytes, policy).await", "self.0.put_if(name, None, bytes, policy).await")],
        CS,
    ),
]

if __name__ == "__main__":
    main("t20c", MUTANTS)
