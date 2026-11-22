# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk bindings, Fable's review B1-B12 (2026-11-20) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-review-b-mutants.py check | run [name]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

B = "clients/scaas-sdk/src/binding.rs"
J = "clients/scaas-sdk/src/wasm/js.rs"
G = "clients/scaas-sdk/bindings/go/copycall/copycall.go"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features " + F
JS = (
    'cd clients/scaas-sdk/bindings/js && WASM_BINDGEN="$(git rev-parse --git-common-dir)/../scratchpad/tools/wasm-bindgen/'
    'bin/wasm-bindgen" bash run.sh'
)
MUTANTS = [
    (
        "B1: a lock that cannot run answers empty",
        [
            (
                B,
                "crate::sync_cpp::block(&self.sdk, None, async move { Ok(m.lock(seed).await) })\n    }",
                "Ok(crate::sync_cpp::block(&self.sdk, None, async move { Ok(m.lock(seed).await) }).unwrap_or_default())\n    }",
            )
        ],
        T + ",sync-api --test binding sync::a_lock_that_cannot_run_is_internal",
    ),
    (
        "B11: the opening without the load check",
        [(B, "        crate::load_check(self.expect_api, self.need_features)?;\n", "")],
        T + ",sync-api --test binding sync::the_opening_runs_the_load_check",
    ),
    (
        "B2: a refused marker as UniFFI's internal error",
        [
            (
                B,
                "fn marker(_b: bool) -> uniffi::Result<AllowOpaqueCall> {\n    Err(SdkError::OpaqueCallRefused.into())",
                'fn marker(_b: bool) -> uniffi::Result<AllowOpaqueCall> {\n    Err(uniffi::deps::anyhow::anyhow!("OpaqueCallRefused"))',
            )
        ],
        T + ",uniffi --lib binding::tests::a_refused_lift_is_the_sdk_code",
    ),
    (
        "B7: a sync call of a module object without its export",
        [
            (
                B,
                "    pub fn bls_multi_pop_part_ok(&self, key_data: String",
                "    pub fn bls_multi_pop_ok(&self, key_data: String",
            )
        ],
        T + ",uniffi --test binding every_sync_call_is_exported",
    ),
    (
        "B8: a module object's JS method missing",
        [(J, "    pub fn lock_all(&self) -> Promise {", "    pub fn lock_every(&self) -> Promise {")],
        T + ",uniffi --test binding wasm_exports_every_binding_call",
    ),
    (
        "B3: JS secret_read through a plain buffer",
        [(J, "let mut buf = zeroize::Zeroizing::new(vec![0u8; s.len()]);", "let mut buf = vec![0u8; s.len()];")],
        JS,
        "copy calls",
    ),
    (
        "B12: the Go copy call leaves the caller's slice",
        [(G, "\tfor i := range b {\n\t\tb[i] = 0\n\t}\n", "")],
        "cd clients/scaas-sdk/bindings/go && bash run.sh",
        "TestCopyCalls",
    ),
]

if __name__ == "__main__":
    main("review-b", MUTANTS)
