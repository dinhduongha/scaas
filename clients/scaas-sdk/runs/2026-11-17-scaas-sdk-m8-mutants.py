# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The per-transaction cap under EIP-8037 (50e5d0699, controller call, owner auto-run 2026-11-19) and the merged-tree review's
M8 / M17 (2026-11-20): the regular bound held to the cap at quote and after signing, the gas limit to the block limit, the
signature's growth counted, a row without `regular` whole, the generator's `regular` fields, the caller's quote never
lowering the bound, the fake chain's own cap: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-m8-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

Q = "clients/scaas-sdk/src/op/quote.rs"
G = "clients/scaas-sdk/src/op/gas.rs"
GEN = "clients/scaas-sdk/gas/generate.py"
FAKE = "clients/scaas-sdk/tests/common/fake_chain.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib "
PY = "cd clients/scaas-sdk/gas && python3 -I test_generate.py"
MUTANTS = [
    ("the quote's regular bound not held to the cap",
     [(Q, "    above_caps(&profile, regular, gas, block.limit)?;", "    above_caps(&profile, 0, gas, block.limit)?;")],
     T + "op::tests::tx_cap_holds_the_regular_part"),
    ("the regular compare off by one (at the cap refused)",
     [(Q, "profile.tx_gas_cap.is_some_and(|c| regular > c)", "profile.tx_gas_cap.is_some_and(|c| regular >= c)")],
     T + "op::tests::tx_cap_holds_the_regular_part"),
    ("after signing the regular bound not held to the cap",
     [(Q, "    above_caps(&c.profile, regular, gas, block.limit)?;", "    above_caps(&c.profile, 0, gas, block.limit)?;")],
     T + "op::tests::signed_gas_regular_is_held_to_the_cap"),
    ("the signature's growth not counted as regular",
     [(Q, "let regular = base_regular.saturating_add(gas.saturating_sub(base));", "let regular = base_regular;")],
     T + "op::tests::signed_gas_regular_is_held_to_the_cap"),
    ("a row without `regular` read as 0",
     [(G, "let mut g = b.regular.filter(|_| reg).unwrap_or(b.gas);", "let mut g = b.regular.filter(|_| reg).unwrap_or(0);")],
     T + "op::gas::tests::quoted_regular_bound"),
    ("M17: the caller's quote lowers the regular bound",
     [(Q, "Some(f) if f.gas > q.gas_limit => (f.gas, f.regular.max(q_regular), Some(f.from)),",
       "Some(f) if f.gas > q.gas_limit => (f.gas, q_regular, Some(f.from)),"),
      (Q, "_ => (q.gas_limit, q_regular.max(own_regular), q.gas_from.clone()),",
       "_ => (q.gas_limit, q_regular, q.gas_from.clone()),")],
     T + "op::tests::signed_quote_never_lowers_the_regular_bound"),
    ("M17: a quote's regular part 0 read as 0",
     [(Q, "        0 => q.gas_limit,\n", "        0 => 0,\n")], T + "op::tests::signed_quote_never_lowers_the_regular_bound"),
    ("M17: the caps not held when nothing grew",
     [(Q, "    above_caps(&c.profile, regular, gas, block.limit)?;\n",
       "    if gas == q.gas_limit && regular == q.regular_gas {\n        return Ok(q.clone());\n    }\n"
       "    above_caps(&c.profile, regular, gas, block.limit)?;\n")],
     T + "op::tests::signed_quote_never_lowers_the_regular_bound"),
    ("generator: an uncounted row's regular the best variant, not the worst",
     [(GEN, '        x = max(m[f"{k}_regular"] for k in keys)', '        x = min(m[f"{k}_regular"] for k in keys)')], PY),
    ("M8: the fake chain's regular cap removed",
     [(FAKE, "                if regular > c.tx_cap {", "                if regular > u64::MAX - 1 {")],
     T + "op::tests::the_fake_chain_holds_the_regular_gas_to_the_cap"),
    ("M18: a count above the measured range quoted (lookup)",
     [(G, "*n <= COUNT_MAX && p.measured_max.is_none_or(|m| *n <= m));", "*n <= COUNT_MAX);")],
     T + "op::gas::tests::gas_per_item_adds_gas_times_its_count"),
    ("M18: a group above the measured range quoted (registration)",
     [(G, "                        && p.measured_max.is_none_or(|m| n <= m) =>", "                        =>")],
     T + "op::gas::tests::gas_bls_multi_rows_quote_by_members"),
    ("M18 generator: the measured range not written",
     [(GEN, '                        row["per_item"]["measured_max"] = top', '                        pass')], PY),
]

if __name__ == "__main__":
    main("m8", MUTANTS)
