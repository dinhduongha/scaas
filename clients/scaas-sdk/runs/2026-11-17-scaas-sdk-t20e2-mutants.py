# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T20e2 (the Java binding) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t20e2-mutants.py check | run [name]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

B = "clients/scaas-sdk/src/binding.rs"
X = "clients/scaas-sdk/bindings/java/fix_generated.py"
JV = (
    'cd clients/scaas-sdk/bindings/java && JAVA_HOME="$(git rev-parse --git-common-dir)/../scratchpad/tools/jdk-25" '
    "bash run.sh"
)
FX = "cd clients/scaas-sdk/bindings/java && python3 -I test_fix_generated.py"
MUTANTS = [
    (
        "the PRF output names another secret",
        [(B, "self.0.get_assertion(req, prf_out.id()).await", "self.0.get_assertion(req, prf_out.id() + 1).await")],
        JV,
        "AuthenticatorRefused",
    ),
    (
        "the store's write drops the expected revision",
        [(B, "self.0.put_if(name, prev_rev, bytes, policy).await", "self.0.put_if(name, None, bytes, policy).await")],
        JV,
        "StoreConflict",
    ),
    (
        "the fixup leaves a bound value over the converter's own",
        [(X, 'lines[i], bound, indent = re.sub(r"\\bvar value\\b", "var value_", line), True, depth', "bound, indent = True, depth")],
        FX,
    ),
]

if __name__ == "__main__":
    main("t20e2", MUTANTS)
