# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T20g (the JS / TS binding) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t20g-mutants.py check | run [name]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

J = "clients/scaas-sdk/src/wasm/js.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
JS = (
    'cd clients/scaas-sdk/bindings/js && WASM_BINDGEN="$(git rev-parse --git-common-dir)/../scratchpad/tools/wasm-bindgen/'
    'bin/wasm-bindgen" bash run.sh'
)
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features " + F
MUTANTS = [
    ("the copy call leaves the caller's array", [(J, "    bytes.fill(0);\n", "")], JS),
    (
        "the store's write drops the expected revision",
        [(J, "let rev = to_js(&prev_rev)", "let rev = to_js(&None::<u64>)")],
        JS,
    ),
    (
        "the PRF output names another secret",
        [
            (
                J,
                'self.call("get_assertion", &[req, h.0.into()])',
                'self.call("get_assertion", &[req, (h.0 + 1).into()])',
            )
        ],
        JS,
    ),
    (
        "a handle object's call without its JS export",
        [(J, "    fn prepared_entry(p: Arc<Prepared>) -> String = Ok(p.entry());\n", "")],
        T + ",uniffi --test binding wasm_exports_every_binding_call",
    ),
]

if __name__ == "__main__":
    main("t20g", MUTANTS)
