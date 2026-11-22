# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk bindings on the merge of sdk-complete e90f26685 (decisions CLI-SDK-33 (49)) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-bind49-mutants.py check | run [name]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

L = "clients/scaas-sdk/src/binding_list.rs"
J = "clients/scaas-sdk/src/wasm/js.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots,uniffi"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features " + F + " --test binding "
MUTANTS = [
    (
        "a merged Account call left out of the binding list",
        [
            (
                L,
                "                #[cfg(feature = \"evm\")] async ua_line / ua_line_blocking (chain: String, ua: String)"
                " -> UaLine;\n",
                "",
            )
        ],
        T + "every_async_call_has_a_blocking_twin",
    ),
    (
        "UaLine's method without its JS export",
        [
            (
                J,
                "    #[cfg(feature = \"evm\")]\n    fn ua_line_key_target(line: crate::UaLine) -> String = "
                "Ok(line.key_target());\n",
                "",
            )
        ],
        T + "wasm_exports_every_binding_call",
    ),
]

if __name__ == "__main__":
    main("bind49", MUTANTS)
