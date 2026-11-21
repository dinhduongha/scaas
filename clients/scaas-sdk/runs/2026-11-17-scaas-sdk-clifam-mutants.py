# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The CLI profile file's `family_params` (plan T24, CLI-SDK-17): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-clifam-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

C = "clients/scaas-cli/src/config.rs"
M = "clients/scaas-cli/Cargo.toml"
T = "cd clients/scaas-cli && ../../scripts/capped cargo test --locked --offline -j2 --bin scaas "
MUTANTS = [
    ("the params dropped on the way to the SDK",
     [(C, "            family_params: p.family_params.map(fam),\n", "            family_params: None,\n")],
     T + "family_params_are_read_by_name"),
    ("an unknown Cosmos field accepted",
     [(C, "#[serde(deny_unknown_fields)]\nstruct CosmosFam {", "struct CosmosFam {")],
     T + "family_params_are_read_by_name"),
    ("the CLI's SDK without Aptos reads",
     [(M, '  "cosmos",\n  "aptos",\n', '  "cosmos",\n')],
     T + "family_profiles_open_and_read"),
    ("the rest policy ignored",
     [(C, "            rest_policy: pol(c.rest_policy),", "            rest_policy: Policy::Failover,")],
     T + "family_params_are_read_by_name"),
]

if __name__ == "__main__":
    main("clifam", MUTANTS)
