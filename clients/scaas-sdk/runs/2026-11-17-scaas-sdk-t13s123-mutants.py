# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13, owner rulings S1-S3, P1, P2 (2026-11-19) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13s123-mutants.py check | run [name...]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

R = "clients/scaas-sdk/src/account/register.rs"
S = "clients/scaas-sdk/src/account/smart.rs"
B = "clients/scaas-sdk/src/op/submit.rs"
P = "clients/ua-rs/src/wallet/policy.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test "
U = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test sign_scaas "
MUTANTS = [
    ("S2: storePqzPop landed when proven (pqzKeyAt.proven), not when stored",
     [(R, '        Landed::PqzPop(_) => selector("pqzPopOf(bytes32,uint64)"),',
          '        Landed::PqzPop(_) => selector("pqzKeyAt(bytes32,uint64)"),'),
      (R, "            (off % 32 == 0 && out.len() >= off + 32 + len).then_some(len > 0)\n        }\n        // `(KemKey",
          "            let _ = (off, len);\n            Some(word(out, 2)? == U256::from(1))\n        }\n        // `(KemKey")],
     T + "account_ops store_pqz_pop_landed_when_stored"),
    ("S3: keyIndex fixed to 0",
     [(B, '"keyIndex": p.t.key_index.to_string()', '"keyIndex": "0"')],
     T + "wallet_ops smart_execute_decoded_only"),
    ("P2: a signer in no slot is Argument",
     [(S, "{ SdkError::Argument } else { SdkError::SignerNotAccountKey }", "{ SdkError::Argument } else { SdkError::Argument }")],
     T + "wallet_ops smart_execute_decoded_only"),
    ("P1 ua-rs: sign_scaas under metatx, not scaas_purpose's tag",
     [(P, "    super::uasig::ua_sig(key, None, &scaas_purpose(td)?, &digest)",
          "    let _ = scaas_purpose;\n    super::uasig::ua_sig(key, None, &crate::purpose_tag(\"metatx\")?, &digest)")],
     U + "external_key_dry_run_then_answer"),
]

if __name__ == "__main__":
    main("t13s123", MUTANTS)
