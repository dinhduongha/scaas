# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13, owner 2026-11-19 T3: a policy refusal never asks the device mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13policy-mutants.py check | run [name...]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

X = "clients/scaas-sdk/src/op/external.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
L = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib -- --exact "
MUTANTS = [
    ("the device asked before the policy's dry run passes",
     [(X, "    if !asked.load(Ordering::SeqCst) {\n        // refused before any device would be asked: the policy's (or the typed data's) own error\n        return Err(dry.err().map_or(SdkError::Internal, SdkError::from));\n    }",
          "    let _ = (asked.load(Ordering::SeqCst), dry);")],
     L + "op::tests::policy_refusal_asks_no_device"),
]

if __name__ == "__main__":
    main("t13policy", MUTANTS)
