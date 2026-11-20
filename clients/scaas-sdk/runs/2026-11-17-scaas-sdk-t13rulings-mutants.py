# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13: the owner's rulings R1-R4 of 2026-11-19 on sponsored registration (CLI-SDK-30) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13rulings-mutants.py check | run [name...]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/account/sponsor.rs"
R = "clients/scaas-sdk/src/account/register.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test account_ops "
MUTANTS = [
    ("R1: no size bound", [(S, "text.len() > BLOB_MAX\n            || ", "")], T + "registration_blob_size_cap"),
    ("R1: the old 64 KiB cap", [(S, "pub const BLOB_MAX: usize = 768 * 1024;", "pub const BLOB_MAX: usize = 64 * 1024;")],
     T + "sponsored_registration_checks"),
    ("R2: an unknown field inside the arguments read", [(S, "#[serde(deny_unknown_fields, rename_all = \"camelCase\")]\npub struct AttrsArgs",
                                                       "#[serde(rename_all = \"camelCase\")]\npub struct AttrsArgs")],
     T + "sponsored_registration_checks"),
    ("R3: no registry skips the receiver check", [(R, "    let Some(registry) = profile.registry.as_deref() else {\n        return Err(SdkError::ReceiverUnregistered);",
                                                  "    let Some(registry) = profile.registry.as_deref() else {\n        return Ok(());")],
     T + "pay_to_unregistered_derived_ua"),
    ("R4: a write not put back on a signing failure", [(R, "                    Err(e) => {\n                        sdk.registry_writes",
                                                       "                    Err(e) if false => {\n                        sdk.registry_writes"),
                                                      (R, "                        return Err(e);\n                    }\n                };",
                                                       "                        return Err(e);\n                    }\n                    Err(e) => return Err(e),\n                };")],
     T + "registry_write_kept_on_signing_failure"),
]

if __name__ == "__main__":
    main("t13rulings", MUTANTS)
