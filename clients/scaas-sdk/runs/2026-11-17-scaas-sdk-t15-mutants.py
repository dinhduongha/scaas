# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T15 mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t15-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

R = "clients/scaas-sdk/src/confidential/read.rs"
M = "clients/scaas-sdk/src/confidential/mod.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test confidential "
MUTANTS = [
    # the plan's four
    ("mark a read Plain", [(R, "const PURPOSE: Purpose = Purpose::FeedsDecryption;", "const PURPOSE: Purpose = Purpose::Plain;")],
     T + "decryption_reads_skip_discovered"),
    ("retry the next endpoint on a decryption failure",
     [(M, "                let out = call(&sdk, key, cmd, words).await?;",
       "                let out = match call(&sdk, key, cmd, words).await {\n"
       "                    Ok(o) => o,\n"
       "                    Err(e) => {\n"
       "                        let key = handle(&sdk, &req.seed, req.account)?;\n"
       "                        read::zether(&sdk, &req.chain, &req.token, Some(&key.1.y()), key.1.ua(), &[]).await?;\n"
       "                        return Err(e);\n"
       "                    }\n"
       "                };")],
     T + "decryption_failure_never_fails_over"),
    ("read a word by call_at",
     [(R, "    Ok(pool\n        .storage_at(at, who, U256::from_be_bytes(*slot))\n        .await?\n        .to_be_bytes::<32>())",
       "    let b = pool.call_at(at, who, alloy::primitives::Bytes::from(slot.to_vec())).await?;\n"
       "    Ok(U256::from_be_slice(&b).to_be_bytes::<32>())")],
     T + "view_never_serves_a_word"),
    ("read at Depth(1)", [(R, ".read_at_block(final_block(&profile), PURPOSE, |at| fetch(", ".read_at_block(scaas_rpc::pool::BlockChoice::Depth(1), PURPOSE, |at| fetch(")],
     T + "words_at_one_final_block"),
    # each check of the task
    ("no factory record check", [(R, "if class != CLASS_TOKEN || !ZETHER_KINDS.contains(&kind) {", "if false {")],
     T + "uncatalogued_token_refused"),
    # not listed: dropping the clone check is equivalent (a token that is not a clone names no registry, so no record is read
    # and R6 refuses it with the same code)
    ("the clone's chain not checked", [(R, "if env.chain_uid != *chain_uid {", "if false {")], T + "code_hash_checked"),
    ("the key pointer's Y not checked against the UA",
     [(R, "                && scaas_ua::derive_ua(ZETHER_UA_KIND, y, false).ok().as_ref() == Some(ua) =>", "                && !ua.is_empty() =>")],
     T + "zether_transfer_single_pair"),
    ("the record's kind not checked", [(R, "            if kind == ZETHER_UA_KIND\n", "            if kind == kind\n")],
     T + "leg_of_another_key_refused"),
    ("every data word passed, the empty points' too",
     [(R, "        if *lw != [0; 32] {\n            let mine", "        if *lw == *lw {\n            let mine")],
     T + "nothing_back_to_the_source"),
]

if __name__ == "__main__":
    main("t15", MUTANTS)
