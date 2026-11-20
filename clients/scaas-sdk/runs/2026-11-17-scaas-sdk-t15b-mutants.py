# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T15, second commit (the rest of the Zether pairs, the confidential watch):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t15b-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

Z = "clients/scaas-sdk/src/confidential/zether.rs"
S = "clients/scaas-sdk/src/op/submit.rs"
W = "clients/scaas-sdk/src/watch.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test confidential "
MUTANTS = [
    ("decoys may be the holder or a real recipient",
     [(Z, '"exclude": exclude, "count": decoys', '"exclude": Vec::<String>::new(), "count": decoys')],
     T + "zether_transfer_multi_pairs"),
    ("expectedPendingSeq taken from accSeq",
     [(Z, '"expectedPendingSeq": pending.to_string(), "validUntilBlock": valid_until_block.to_string()})),',
       '"expectedPendingSeq": acc_seq.to_string(), "validUntilBlock": valid_until_block.to_string()})),')],
     T + "zether_owner_statements"),
    ("a roll-over with nothing pending", [(Z, "if pending <= rolled {", "if false {")], T + "zether_owner_statements"),
    ("the Zether signer refuses zether-owner",
     [(Z, 'const PURPOSES: [&str; 4] = ["metatx", "payee-fee", "trade", "zether-owner"];',
       'const PURPOSES: [&str; 4] = ["metatx", "payee-fee", "trade", "metatx"];')],
     T + "zether_owner_statements"),
    ("the relayed form's ownerSig left unsigned",
     [(S, "    if let Some((td, ex, slot)) = &p.t.owner {", "    if let Some((td, ex, slot)) = &None::<(scaas_ua::wallet::TypedData, scaas_ua::wallet::Expect, &str)> {")],
     T + "zether_owner_statements"),
    ("the owner statement's modeNonce not read", [(Z, '"modeNonce": mode_nonce.to_string(),', '"modeNonce": "0",')],
     T + "zether_owner_statements"),
    ("the watch loop skips the Zether words",
     [(W, "        let moved = moved | self.poll_zether(account, chain, token, &key).await?;", "        let moved = moved;")],
     T + "watch_reads_a_zether_account"),
    ("the unwrap's leg not reviewed as touched", [(Z, "            touched: vec![underlying],", "            touched: vec![],")],
     T + "zether_unshield_unwrap_pair"),
]

if __name__ == "__main__":
    main("t15b", MUTANTS)
