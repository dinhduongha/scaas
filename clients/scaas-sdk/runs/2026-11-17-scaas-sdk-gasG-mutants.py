# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of the owner's rulings G1 and G3 of 2026-11-19 ("approved all 6 as proposed"): `ua_extra` when
either party the entry debits is a derived UA (G1); the calldata part recomputed from the signed calldata, never below the
quote, refused above `max_gas` (G3): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasG-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

G = "clients/scaas-sdk/src/op/gas.rs"
U = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib "
G1 = "        if signer != NATIVE_EVM || op.attached.is_some_and(|k| k != Some(NATIVE_EVM)) {\n"
MUTANTS = [
    # G1: either party debited
    ("G1: the attached owner ignored (signer only, as before)", [(G, G1, "        if signer != NATIVE_EVM {\n")],
     U + "gas_ua_extra_for_a_derived_signer"),
    ("G1: an attached signature of unknown kind read as native",
     [(G, G1, "        if signer != NATIVE_EVM || op.attached.is_some_and(|k| k.is_some_and(|k| k != NATIVE_EVM)) {\n")],
     U + "gas_ua_extra_for_a_derived_signer"),
    ("G1: a native attached owner counted", [(G, G1, "        if signer != NATIVE_EVM || op.attached.is_some() {\n")],
     U + "gas_ua_extra_for_a_derived_signer"),
    ("G1: added twice when both are derived",
     [(G, "            g = g.saturating_add(b.ua_extra.unwrap_or(0));\n",
       "            g = g.saturating_add(b.ua_extra.unwrap_or(0));\n"
       "            if signer != NATIVE_EVM && op.attached.is_some() {\n"
       "                g = g.saturating_add(b.ua_extra.unwrap_or(0));\n"
       "            }\n")],
     U + "gas_ua_extra_for_a_derived_signer"),
]

if __name__ == "__main__":
    main("gasG", MUTANTS)
