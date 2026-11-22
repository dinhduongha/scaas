# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T38: the OP Stack L1 data fee in the quote: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t38-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

Q = "clients/scaas-sdk/src/op/quote.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features wallet --test l1_fee -- --exact "
MUTANTS = [
    # the plan's two
    ("the L1 fee left out of max_cost", [(Q, "    q.max_cost = check_cost(sdk, q.gas_limit, fee, l1)?.to_string();", "    q.max_cost = check_cost(sdk, q.gas_limit, fee, U256::ZERO)?.to_string();")],
     T + "op_stack_quote_adds_the_l1_fee_read_at_its_block"),
    ("the read made without the profile field", [(Q, "    if profile.l1_fee != Some(crate::L1Fee::OpStack) {\n        return Ok(U256::ZERO);", "    if false {\n        return Ok(U256::ZERO);")],
     T + "without_the_field_no_l1_read"),
    # each further check
    ("an answer of any length read", [(Q, "                let w: [u8; 32] = r.as_ref().try_into().map_err(|_| {", "                let w: [u8; 32] = r.get(..32).unwrap_or(&[0u8; 32]).try_into().map_err(|_| {")],
     T + "an_l1_fee_that_is_no_uint256_is_answer_malformed"),
    ("the cap without the L1 fee", [(Q, "        .and_then(|c| c.checked_add(l1))", "        .and_then(|c| Some(c))")],
     T + "fee_above_cap_counts_the_l1_fee"),
    ("the L1 fee over the calldata only", [(Q, "    let l1 = l1_fee(&profile, &pool, &unsigned).await?;", "    let l1 = l1_fee(&profile, &pool, data).await?;")],
     T + "op_stack_quote_adds_the_l1_fee_read_at_its_block"),
]

if __name__ == "__main__":
    main("t38", MUTANTS)
