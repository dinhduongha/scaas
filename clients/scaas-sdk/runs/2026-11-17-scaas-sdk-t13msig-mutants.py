# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13: `msig` (registry reads, the three writes landed by the record, signing as an msig) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13msig-mutants.py check | run [name...]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

M = "clients/scaas-sdk/src/account/msig.rs"
R = "clients/scaas-sdk/src/account/register.rs"
FO = "clients/scaas-sdk/src/op/follow.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
L = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib -- --exact "
MUTANTS = [
    ("a slot not accepted signs (no outer check)",
     [(M, "        if !v.active(s.index()) {\n            return Err(SdkError::MsigSlotInactive);\n        }",
          "        let _ = s;")],
     L + "account::msig::tests::msig_minimal_sets"),
    ("an inner leaf not accepted signs",
     [(M, "            if members.iter().any(|l| !v.active(l.index)) {\n                return Err(SdkError::MsigSlotInactive);\n            }",
          "            let _ = (members, v);")],
     L + "account::msig::tests::msig_minimal_sets"),
    ("a stale structure signed (the first, not the current)",
     [(M, "    let current = |id: [u8; 32]| views.get(&id).map(|v| (v.current.clone(), v.enabled));\n    let inner = |id: [u8; 32]| views.get(&id).map(|v| v.first.clone());\n    let apart",
          "    let current = |_: [u8; 32]| None;\n    let inner = |id: [u8; 32]| views.get(&id).map(|v| v.first.clone());\n    let apart")],
     L + "account::msig::tests::update_msig_current"),
    ("the update's version from zero, not the stored one",
     [(M, "                    version: v.version,\n                    enabled: v.enabled,", "                    version: 0,\n                    enabled: v.enabled,")],
     L + "account::msig::tests::update_msig_current"),
    ("an operation signed without its check",
     [(M, "    if !asked.load(Ordering::SeqCst) {\n        return Err(dry.err().map_or(SdkError::Internal, SdkError::from));\n    }",
          "    let _ = (asked.load(Ordering::SeqCst), dry);")],
     L + "account::msig::tests::update_msig_current"),
    ("landed from the receipt",
     [(FO, "        _ => match native_state(pool, row, choice).await {\n            OpState::Landed { .. } => OpState::InFlight {\n                detail: InFlight::TxIncluded,\n            },",
           "        _ => match native_state(pool, row, choice).await {")],
     L + "account::msig::tests::msig_writes_landed_by_record"),
    ("acceptance landed by another slot's bit",
     [(R, "word(out, 2).is_some_and(|w| w.bit(usize::from(i)))", "word(out, 2).is_some_and(|w| w.bit(usize::from(i) + 1))")],
     L + "account::msig::tests::msig_writes_landed_by_record"),
]

if __name__ == "__main__":
    main("t13msig", MUTANTS)
