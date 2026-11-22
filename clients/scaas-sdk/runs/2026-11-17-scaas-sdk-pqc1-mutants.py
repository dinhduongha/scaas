# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core T1's SDK rows (the `pqchat_*` entries, V1, `read_app`): each new decryption or verification check of the SDK and
the two owed by the handoff (S1's `wrapHashes` order, V1 accepting a non-minimal `msig`):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-pqc1-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

PK = "clients/scaas-sdk/src/pqchat_keys.rs"
PR = "clients/scaas-sdk/src/pqchat_records.rs"
AC = "clients/scaas-sdk/src/app_core.rs"
UP = "clients/ua-rs/src/ua_portable.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features app-core,pqchat-records,vectors --test pqchat_keys "
MUTANTS = [
    (
        "S1's wrapHashes reversed",
        [(PR, "    wraps\n        .iter()\n        .map(|w| {", "    wraps\n        .iter()\n        .rev()\n        .map(|w| {")],
        T + "sealed_info_rows_and_s1",
    ),
    (
        "V1 accepting a non-minimal msig",
        [
            (
                UP,
                "    if !msig_slots_minimal(d, &slots.iter().map(|s| s.index).collect::<Vec<_>>())? {",
                "    if false && !msig_slots_minimal(d, &slots.iter().map(|s| s.index).collect::<Vec<_>>())? {",
            )
        ],
        T + "v1_msig_minimal_and_accepted",
    ),
    (
        "V1 counting a slot not accepted",
        [
            (
                AC,
                "*b = enabled.get(i).copied().unwrap_or(0) & accepted.get(i).copied().unwrap_or(0);",
                "*b = enabled.get(i).copied().unwrap_or(0);",
            )
        ],
        T + "v1_msig_minimal_and_accepted",
    ),
    (
        "K2's unwrap without the member check",
        [(PK, "        if me != member {", "        if false && me != member {")],
        T + "wraps_p14_and_the_account_unwrap",
    ),
    (
        "K6 without PqChat's prefix",
        [(PK, "        self.label(pk::HINT)?;\n", "")],
        T + "refusals_one_change_at_a_time",
    ),
    # not listed: read_app's nesting bound (16) equals alloy 1.7.3's own type recursion limit: with the bound raised, 17 tuple
    # levels and 17 array dimensions are still refused (the run of 2026-11-21 recorded it surviving), so the mutant is
    # equivalent; the test pins both edges (16 read, 17 refused) and the SDK keeps its own bound for another alloy version
    # not listed: S5's account check (`KeyRef::Ua` only) is repeated by the signer's type (`Key::Ua` or `Argument`), so
    # dropping either is equivalent
    (
        "read_app reading a state-changing entry",
        [(AC, "            StateMutability::View | StateMutability::Pure\n", "            StateMutability::View | StateMutability::Pure | StateMutability::NonPayable\n")],
        T + "read_app_named_json",
    ),
]

if __name__ == "__main__":
    main("pqc1", MUTANTS)
