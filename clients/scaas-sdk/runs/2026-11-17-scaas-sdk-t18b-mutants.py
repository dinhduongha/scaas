# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T18b (the governance-delay sentence) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t18b-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

D = "clients/scaas-sdk/src/admin/delay.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
SDK = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test governance_delay "
MUTANTS = [
    # the two noticePeriod rows re-anchored 2026-11-23 (T26 A2-2 / A2-3: the six views are one read at the final block): the
    # same mutations on the current text
    ("grantDelay read where noticePeriod applies", [(D, "(factory, selector(\"noticePeriod()\").to_vec()),", "(token, selector(\"grantDelay()\").to_vec()),")], SDK + "every_bit_has_its_named_sentence"),
    ("a singleKey bit read as atOnce", [(D, "out.push(DelaySentence::SingleKey);", "out.push(DelaySentence::AtOnce);")], SDK + "every_bit_has_its_named_sentence"),
    ("an unread delay defaults to zero", [(D, "                                        .await?\n                                        .to_vec(),", "                                        .await\n                                        .map(|b| b.to_vec())\n                                        .unwrap_or_default(),"),
                                          (D, "let (notice, grant) = (small(notice)?, small(grant)?);", "let (notice, grant) = (small(notice).unwrap_or(0), small(grant)?);")], SDK + "a_failed_read_is_an_error"),
]

if __name__ == "__main__":
    main("t18b", MUTANTS)
