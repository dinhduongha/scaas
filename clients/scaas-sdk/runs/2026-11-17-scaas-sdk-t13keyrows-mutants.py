# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13, owner 2026-11-19 T2: a passkey or secure-element key row registered through the SDK mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13keyrows-mutants.py check | run [name...]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

R = "clients/scaas-sdk/src/account/register.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
L = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib -- --exact "
MUTANTS = [
    ("the device asked over another digest than the registration's",
     [(R, "    let answer = crate::op::external::answer(sdk, &row, &tag, &hp.registration_digest).await?;",
          "    let answer = crate::op::external::answer(sdk, &row, &tag, &[0; 32]).await?;")],
     L + "op::tests::key_rows_register"),
    ("a KEM key asked for a key row taken silently",
     [(R, "    if attrs.kem || attrs.pqz_key {\n        return Err(SdkError::Argument);\n    }\n    let Key::External",
          "    let _ = attrs;\n    let Key::External")],
     L + "op::tests::key_rows_register"),
]

if __name__ == "__main__":
    main("t13keyrows", MUTANTS)
