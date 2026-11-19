# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk: a native PQZ auditor refused (PqzAuditorNative) and AuditorConsent's per-domain message (controller call, owner
auto-run 2026-11-19): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t20c-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

ADMIN = "clients/scaas-sdk/src/admin.rs"
GEN = "clients/clientkeys/scripts/typed-ops-vectors.mjs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
SDK_ADMIN = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib admin::tests"
# the generator mutated: regenerate in place, run the consent reader, then put the vector back byte for byte
V = "smartcontracts/vectors/typed/typed_ops.json"
CK = (f"d=$(mktemp -d) && cp {V} $d/keep && node clients/clientkeys/scripts/typed-ops-vectors.mjs && "
      f"(cd clients/clientkeys && node --test test/auditor.test.js); rc=$?; cp $d/keep {V}; rm -rf $d; exit $rc")
SDK_MSIG = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib msig_auditor_pqz_consent"
MUTANTS = [
    ("the SDK signs a native PQZ auditor's consent (no up-front refusal)",
     [(ADMIN, 'if want == "pqz" && matches!(req.signer, KeyRef::Native { .. } | KeyRef::Imported { .. }) {',
       'if false {')], SDK_ADMIN),
    ("the generator: the Zether domain's consent names the PQZ token again",
     [(GEN, 'const own = name === "AuditorConsent" ? { ...message, token: at.contract } : message;',
       'const own = message;')], CK),
    ("an msig auditor's consent refused (no msig path)",
     [(ADMIN, "if let KeyRef::Msig { ua, slots } = &req.signer {", "if let (false, KeyRef::Msig { ua, slots }) = (true, &req.signer) {")],
     SDK_MSIG),
]

if __name__ == "__main__":
    main("t20c", MUTANTS)
