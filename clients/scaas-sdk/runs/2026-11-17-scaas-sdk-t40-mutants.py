# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T40: the EVM probe runner (NET-EVM-19 H1-H8 and the profile probes), the profiles' chain pair check and `finalized` pinned
by hash in scaas-rpc, the native send's type in the SDK:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t40-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "clients/scaas-rpc/runs/2026-11-22-evm-probes.py"
T = "python3 -I clients/scaas-rpc/runs/test_evm_probes.py "
E = "clients/scaas-rpc/src/evm.rs"
RT = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test evm_profiles -- --exact "
Q = "clients/scaas-sdk/src/op/quote.rs"
N = "clients/scaas-sdk/src/wallet/native_evm.rs"
ST = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features wallet --test evm_profiles -- --exact "
MUTANTS = [
    # the probe runner
    ("H1 without the chain id", [(P, 'ok &= e["chain_id"] == ctx["row"]["chainId"] and ', "ok &= ")], T + "h1_block0_and_chain_id"),
    ("H1 without block 0", [(P, ' and e["block0"] == ctx["row"]["chainUid"].lower()', "")], T + "h1_block0_and_chain_id"),
    ("H1 on one endpoint", [(P, "    if len(ctx[\"eps\"]) < 2:\n", "    if False:\n")], T + "h1_block0_and_chain_id"),
    ("H2 without the made-up refusal", [(P, " and refused == len(READS)", "")], T + "h2_eip1898"),
    ("H3 replaced heads not counted", [(P, "        replaced += c.lower() != h.lower()", "        replaced += 0")],
     T + "h3_replaced_heads_counted"),
    ("H4 another block taken", [(P, 'made in ("null", "refused")', 'made in ("null", "refused", "another block")')],
     T + "h4_block_by_hash"),
    ("H5 endpoints' finalized disagreement passed", [(P, "    if max(gaps) > 32 and min(gaps) * 10 < max(gaps):", "    if False:")],
     T + "h5_gap"),
    ("H7 moving back allowed", [(P, "        if prev and n < max(prev):", "        if False:")], T + "h7_finalized_never_back"),
    ("H8 a mismatch not counted", [(P, "        elif num(now) != num(then):\n            mismatch += 1", "        elif False:\n            mismatch += 1")],
     T + "h8_pinned_head_read"),
    ("fork without CLZ", [(P, '                if has["osaka"]:', '                if True:')], T + "fork_level"),
    ("caps without the published limit", [(P, "    limit = min(x for x in (EIP7825, cap, pub) if x)", "    limit = min(x for x in (EIP7825, cap) if x)"),
                                          (P, "    whole = min(block, pub) if pub else block", "    whole = block")], T + "caps_and_pq_fit"),
    ("caps without the chain's own cap", [(P, "    limit = min(x for x in (EIP7825, cap, pub) if x)", "    limit = min(x for x in (EIP7825, pub) if x)")],
     T + "caps_and_pq_fit"),
    ("a gas refusal read as a size limit", [(P, '            if ok is None:\n                return f">={last} (gas-bound)" if last else None',
                                             '            if ok is None:\n                ok = False')], T + "code_size_limits"),
    ("no bisection between candidates", [(P, "                while hi - lo > 1:", "                while False:")], T + "code_size_limits"),
    ("a 4xx JSON-RPC error read as no answer", [(P, "        if b'\"error\"' not in raw:", "        if True:")], T + "h6_log_span"),
    ("a quota read as the chain's answer", [(P, '        return ("down", f"rate limited: {m[:60]}") if RATE.search(m) else ("err", m)', '        return ("err", m)')],
     T + "rate_limited_is_unread"),
    ("getL1Fee's answer not held to a uint256", [(P, 'if st != "ok" or not isinstance(r, str) or len(r) != 66:', 'if st != "ok" or not isinstance(r, str):')],
     T + "l1_fee_model"),
    ("Arbitrum not read from ArbGasInfo", [(P, 'else "in-estimate" if e["arb_gas_info"] or (e["estimate"] or 0) > 21_000', 'else "in-estimate" if (e["estimate"] or 0) > 21_000')],
     T + "l1_fee_model"),
    ("basefee always type 2", [(P, '        types.append(2 if h.get("baseFeePerGas") is not None else 0)', "        types.append(2)")], T + "base_fee_type"),
    # scaas-rpc: the chain pair (plan: the identity check on chain id only)
    ("the identity check on chain id only", [(E, "            Ok(Some(b)) => Ok(b.header.hash == want),", "            Ok(Some(_)) => Ok(true),")],
     RT + "each_profile_drops_an_endpoint_of_the_other_chain"),
    ("the identity check on block 0 only", [(E, "        if id != self.number {\n            return Ok(false);", "        if false {\n            return Ok(false);")],
     RT + "each_profile_drops_an_endpoint_of_the_other_chain"),
    ("a finalized read pinned by number", [(E, "    alloy::eips::BlockId::Hash(alloy::eips::RpcBlockHash {\n        block_hash: at.hash,\n        require_canonical: Some(true),\n    })",
                                            "    alloy::eips::BlockId::Number(alloy::eips::BlockNumberOrTag::Number(at.number))")],
     RT + "a_finalized_read_is_pinned_by_hash"),
    # the SDK: the owner's disabled kinds (2026-11-22, decisions CLI-SDK-32 (2))
    ("a disabled kind signed", [("clients/scaas-sdk/src/op/mod.rs", "    if profile.disabled_kinds.iter().any(|k| k == name) {", "    if false {")],
     ST + "a_disabled_kind_is_refused_before_signing"),
    ("a registration's kind not checked", [("clients/scaas-sdk/src/account/register.rs", "        crate::op::ua_kind_enabled(&profile, k)?;", "        let _ = k;")],
     ST + "a_disabled_kind_is_refused_before_signing"),
    ("an unknown disabled kind taken", [("clients/scaas-sdk/src/lib.rs", '.any(|k| k != "pqz" && !scaas_ua::KINDS.iter().any(|x| x.name == k))', '.any(|_| false)')],
     ST + "a_disabled_kind_is_refused_before_signing"),
    # the SDK (plan: type 2 asked without a base fee)
    ("type 2 asked without a base fee", [(Q, "        tx_type: if block.base_fee.is_some() { 2 } else { 0 },", "        tx_type: 2,")],
     ST + "a_native_send_type_follows_the_base_fee"),
    ("type 2 taken without a base fee", [(N, "                    Some(2) if quote.tx_type != 2 => return Err(SdkError::TxTypeRefused),\n", "")],
     ST + "a_native_send_type_follows_the_base_fee"),
]

if __name__ == "__main__":
    main("t40", MUTANTS)
