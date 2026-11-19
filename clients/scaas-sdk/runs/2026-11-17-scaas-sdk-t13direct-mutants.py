# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13: the SmartKeyAccount deploy and completeRecovery as SDK calls (native sends) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13direct-mutants.py check | run [name...]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/account/smart.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
E = f"cd clients/scaas-sdk && CAPPED_MEM=6G ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test e2e -- --ignored --exact "
MUTANTS = [
    ("deploy without the guardian (its word left zero)",
     [(S, "        args.extend_from_slice(&addr20(&guardian.to_ascii_lowercase())?);",
          "        let _ = addr20(&guardian.to_ascii_lowercase())?;\n        args.extend_from_slice(&[0; 20]);")],
     E + "guardian_recovery_via_execute"),
    ("completeRecovery of another key (kind word 1)",
     [(S, '        let data = direct_call("completeRecovery((uint8,bytes32,bytes32,bytes32,bytes32))", &key_words(&new_key)?);',
          '        let mut w = key_words(&new_key)?;\n        w[31] = 1;\n        let data = direct_call("completeRecovery((uint8,bytes32,bytes32,bytes32,bytes32))", &w);')],
     E + "guardian_recovery_via_execute"),
]

if __name__ == "__main__":
    main("t13direct", MUTANTS)
