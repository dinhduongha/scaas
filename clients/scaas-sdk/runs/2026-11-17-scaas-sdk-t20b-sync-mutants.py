# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T20b (the sync C++ surface) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t20b-sync-mutants.py check | run [name]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

B = "clients/scaas-sdk/src/binding.rs"
S = "clients/scaas-sdk/src/sync_cpp.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features " + F
MUTANTS = [
    (
        "one twin dropped from the list",
        [(B, "        async seeds / seeds_blocking () -> Vec<SeedInfo>;\n", "")],
        T + ",uniffi --test binding every_async_call_has_a_blocking_twin",
    ),
    (
        "the cancel token ignored",
        [
            (
                S,
                "            Some(c) => tokio::select! {",
                "            Some(_c) => sdk.spawn(f).await,\n            #[allow(unreachable_patterns)]\n            Some(c) => tokio::select! {",
            )
        ],
        T + ",sync-api --test binding sync::cancel_token_cancels",
    ),
    (
        "a twin awaits on the caller's thread (no spawn)",
        [(S, "            None => sdk.spawn(f).await,", "            None => f.await,")],
        T + ",sync-api --test binding sync::a_panic_is_internal",
    ),
    (
        "a twin blocks a runtime thread",
        [
            (
                S,
                "    if tokio::runtime::Handle::try_current().is_ok() {\n        return Err(SdkError::Internal);\n    }\n    let h = sdk.rt",
                "    let h = sdk.rt",
            )
        ],
        T + ",sync-api --test binding sync::a_twin_on_a_runtime_thread_is_refused",
    ),
]

if __name__ == "__main__":
    main("t20b-sync", MUTANTS)
