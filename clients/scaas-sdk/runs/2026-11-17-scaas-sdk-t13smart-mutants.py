# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13 part 2: SmartKeyAccount and guardian recovery mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13smart-mutants.py check | run [name...]
A first run's "any contract's domain taken as an account's" survived: `kind_of` already refuses a domain without a row of
that struct name (only `account` has these rows), so the SDK's own kind check was dead code and is gone."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/account/smart.rs"
P = "clients/ua-rs/src/wallet/policy.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test wallet_ops "
U = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test sign_scaas "
MUTANTS = [
    ("accept an undecoded Execute on SmartKeyAccount",
     [(S, "            SmartCall::Opaque { allow: None, .. } => return Err(SdkError::OpaqueCallRefused),\n", "")],
     T + "smart_execute_decoded_only"),
    ("from the zero address, not the account", [(S, "        m.insert(\"from\".into(), json!(hex(&account)));", "        m.insert(\"from\".into(), json!(hex(&[0u8; 20])));")],
     T + "smart_execute_decoded_only"),
    ("ua-rs: an account's Execute checked as a mandate wallet's", [(P, "                \"Execute\" => \"Execute\",", "                \"Execute\" => \"UAExecute\",")],
     U + "account_execute_signs_only_the_decoded_recovery"),
    ("ua-rs: initiateRecovery under another selector", [(P, "b\"initiateRecovery((uint8,bytes32,bytes32,bytes32,bytes32))\"", "b\"initiateRecovery(bytes32)\"")],
     U + "account_execute_signs_only_the_decoded_recovery"),
]

if __name__ == "__main__":
    main("t13smart", MUTANTS)
