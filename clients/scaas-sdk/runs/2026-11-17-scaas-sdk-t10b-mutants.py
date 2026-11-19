# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk T10b mutants (owner 2026-11-18, ruling 1): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t10b-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

Q = "clients/scaas-sdk/src/op/quote.rs"
S = "clients/scaas-sdk/src/op/submit.rs"
G = "clients/scaas-sdk/src/op/gas.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
U = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib op::tests::"
MUTANTS = [
    # the ruling's two
    ("quote signs", [(Q, "let unsigned = super::submit::unsigned(&prepared)?;", "let unsigned = super::submit::sign(&sdk, &prepared)?;")],
     U + "quote_makes_no_signature"),
    ("submit signs twice", [(S, "let built = sign(&sdk, &prepared)?;", "let _ = sign(&sdk, &prepared)?;\n                let built = sign(&sdk, &prepared)?;")],
     U + "submit_signs_once_on_each_path"),
    # each check of the task
    ("submit skips the simulation's gas check", [(S, "> quote.gas_limit\n", "> u64::MAX\n")], U + "submit_refuses_more_gas_than_quoted"),
    ("a refused unsigned form quoted at a guess", [(Q, "Err(SimError::Revert(_)) => return Err(SdkError::GasUnquoted),",
                                                      "Err(SimError::Revert(_)) => 1_000_000,")], U + "unsigned_form_refused_is_gas_unquoted"),
    ("no margin", [(G, "g.saturating_add(g / 2)", "g")], U + "quote_shows_and_caps"),
]

if __name__ == "__main__":
    main("t10b", MUTANTS)
