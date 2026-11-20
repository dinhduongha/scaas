# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T16 part 2 (verdicts, the profile's verifiers, the PQZ rows without a proof) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t16b-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

V = "clients/scaas-sdk/src/confidential/verdict.rs"
P = "clients/scaas-sdk/src/confidential/pqz.rs"
O = "clients/scaas-sdk/src/op/prepared.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test confidential_pqz "
MUTANTS = [
    # the plan's two
    ("attach an unchecked verdict", [(V, "    checked(\n        &answer,\n        &x,\n        &t,\n        chain_id,\n        &uid,\n        epoch,\n        &stmt,\n        &proof,\n        sdk.now(),\n    )\n    .ok_or(SdkError::VerdictRefused)",
                                      "    Ok(json!({\"pqzVerdict\": answer[\"pqzVerdict\"], \"sig\": answer[\"pqzVerdictSig\"]}))")],
     T + "verdict_checked_before_attach"),
    ("send without a verdict on a refusal", [(V, "    let answer = client\n        .verdict(&req)\n        .await\n        .map_err(|_| SdkError::VerdictRefused)?;",
                                              "    let Ok(answer) = client.verdict(&req).await else {\n        return Ok(json!({}));\n    };")],
     T + "verdict_unreachable_sends_nothing"),
    # each check
    ("the signature not verified", [(V, "if !scaas_ua::verify::verify(kind, &key_data, &msg, &sig, false, false) {", "if false {")],
     T + "verdict_checked_before_attach"),
    ("the signer's key not the registry's (T16-c)", [(V, "if kind == 0 || x.key_code.split_first() != Some((&0, key_data.as_slice())) {", "if false {")],
     T + "verdict_checked_before_attach"),
    ("the epoch not compared", [(V, "|| num(\"pqzVerifierEpoch\")? != epoch", "")],
     T + "verdict_checked_before_attach"),
    ("validUntil not compared", [(V, "|| num(\"validUntil\")? < now", "")],
     T + "verdict_checked_before_attach"),
    ("a token naming no verifier still asks", [(V, "if x.verifier == [0; 32] {\n        return Err(SdkError::VerdictRefused);\n    }", "")],
     T + "verdict_unreachable_sends_nothing"),
    ("the verifier list's policy ignored (T16-a)", [("clients/scaas-sdk/src/lib.rs", "p.verifier_policy,", "scaas_rpc::Policy::Failover,")],
     T + "verdict_verifiers_strict_majority"),
    ("a PQZ row accepted on a Zether token", [(P, "        if p.t.kind != \"pqz\" {\n            return Err(SdkError::Argument);\n        }\n        Ok(p)", "        Ok(p)")],
     T + "pqz_plain_pairs"),
    ("UAPqzRollOver signed as its row name", [(O, "let primary = if d.name == \"UAPqzRollOver\" {\n            \"UARollOver\"\n        } else {\n            d.name\n        };", "let primary = d.name;")],
     T + "pqz_plain_pairs"),
]

if __name__ == "__main__":
    main("t16b", MUTANTS)
