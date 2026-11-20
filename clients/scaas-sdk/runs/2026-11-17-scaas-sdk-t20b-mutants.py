# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T20 (the whole FRB surface) and the native auditor's PQZ consent mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t20b-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

SEEDS = "clients/scaas-sdk/src/vault/seeds.rs"
L = "clients/scaas-sdk/bindings/dart/lib/scaas_sdk.dart"
ADMIN = "clients/scaas-sdk/src/admin.rs"
POLICY = "clients/ua-rs/src/wallet/policy.rs"
# an SDK source changed, the generated files not: the drift check (which scans the SDK crate) is red; regenerated files put back
GEN = "bash clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh --check"
DART = "cd clients/scaas-sdk/bindings/dart && bash ./run.sh"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
SDK_ADMIN = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib admin::tests"
UA = ("cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test wallet_uasig "
      "native_auditor_consent_signs_the_registry_form")
MUTANTS = [
    ("a stale generated file (an SDK doc line)",
     [(SEEDS, "    /// The seeds of the keystore, in display order.", "    /// The seeds of the keystore, in display order (stale).")], GEN),
    ("a binding without its load check",
     [(L, "  checkAbi(expectApi: expectApi, needFeatures: needFeatures);\n}", "}")], DART),
    ("a native auditor's PQZ consent signed (PqzAuditorNative dropped)",
     [(ADMIN, 'if want == "pqz" && matches!(req.signer,', 'if false && want == "pqz" && matches!(req.signer,')],
     SDK_ADMIN),
    ("the Zether consent over another epoch",
     [(ADMIN, '"token": hex(&token), "epoch": req.epoch});', '"token": hex(&token), "epoch": req.epoch + 1});')], SDK_ADMIN),
    ("ua-rs: the native consent under metatx",
     [(POLICY, '&crate::purpose_tag("auditor-consent")?,', '&crate::purpose_tag("metatx")?,')], UA),
    ("ua-rs: the native consent of another auditor accepted",
     [(POLICY, 'if auditor != Some(format!("0x{own}")) {', 'if false && auditor != Some(format!("0x{own}")) {')], UA),
    ("ua-rs: sign_scaas signs a native consent bare",
     [(POLICY, 'if td.primary_type() == "AuditorConsent" {\n            return Err(Error::Argument);',
       'if false {\n            return Err(Error::Argument);')], UA),
    ("ua-rs: the native consent without its check",
     [(POLICY, "    let digest = td.digest()?;\n    if check(td, &expect)? != digest {\n        return Err(Error::PolicyRefused);\n    }\n    let id",
       "    let digest = td.digest()?;\n    let id")], UA),
]

if __name__ == "__main__":
    main("t20b", MUTANTS)
