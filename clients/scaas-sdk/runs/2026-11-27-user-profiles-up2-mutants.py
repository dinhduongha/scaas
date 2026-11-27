# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""user-profiles UP2 mutants (ua-rs src/wallet/profile.rs): python3 clients/scaas-sdk/runs/2026-11-27-user-profiles-up2-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import mutants_lib  # noqa: E402

mutants_lib.PREFIX = "2026-11-27-user-profiles-"
mutants_lib.NOT_CODE = [
    ":!clients/scaas-sdk/runs/*-mutants.txt",
    ":!clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt",
]

P = "clients/ua-rs/src/wallet/profile.rs"
UA = ("cd clients/ua-rs && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
      "--features user-profile,test-hooks,vectors --test profile ")
MUTANTS = [
    ("a fixed nonce in seal_item (the nonce from K_name, not drawn)",
     [(P, "                .seal(&k.item, Nonce::Random, &item_ad(part, name, rev)?, pt)\n",
       "                .seal(&k.item, Nonce::FromHandle(&k.name), &item_ad(part, name, rev)?, pt)\n")],
     UA + "two_seals_differ"),
    ("the part left out of the item AD",
     [(P, "        lp(part.as_bytes())?,\n        lp(name.as_bytes())?,\n        rev.to_be_bytes().to_vec(),\n",
       "        lp(name.as_bytes())?,\n        rev.to_be_bytes().to_vec(),\n")],
     UA + "item_refusal_rows"),
    ("KdfOutOfMemory mapped to Argument",
     [(P, "        argon2::Error::OutOfMemory => Error::KdfOutOfMemory,\n",
       "        argon2::Error::OutOfMemory => Error::Argument,\n")],
     UA + "kdf_out_of_memory"),
    ("the m lower bound not checked",
     [(P, "        let ok = (65_536..=1_048_576).contains(&kdf.m_kib) && (3..=10).contains(&kdf.t);\n",
       "        let ok = (..=1_048_576).contains(&kdf.m_kib) && (3..=10).contains(&kdf.t);\n")],
     UA + "kdf_bound_rows"),
    ("lock() not wiping the arena",
     [(P, "        *s = State::Locked;\n        self.store.lock();\n", "        *s = State::Locked;\n")],
     UA + "lock_wipes_the_arena"),
]

if __name__ == "__main__":
    mutants_lib.main("up2", MUTANTS)
