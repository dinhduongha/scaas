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
    ("grantDelay read where noticePeriod applies", [(D, "read(&pool, factory, \"noticePeriod()\")", "read(&pool, token, \"grantDelay()\")")], SDK + "every_bit_has_its_named_sentence"),
    ("a singleKey bit read as atOnce", [(D, "out.push(DelaySentence::SingleKey);", "out.push(DelaySentence::AtOnce);")], SDK + "every_bit_has_its_named_sentence"),
    ("an unread delay defaults to zero", [(D, "let notice = small(&read(&pool, factory, \"noticePeriod()\").await?)?;", "let notice = match read(&pool, factory, \"noticePeriod()\").await {\n                    Ok(w) => small(&w)?,\n                    Err(_) => 0,\n                };")], SDK + "a_failed_read_is_an_error"),
]

if __name__ == "__main__":
    main("t18b", MUTANTS)
