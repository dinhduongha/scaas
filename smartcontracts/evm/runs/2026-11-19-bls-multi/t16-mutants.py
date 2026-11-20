#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 16 mutants (scaas-sdk per_item rows for 0x0121, the forge line fit). From the worktree root, PATH holding
forge: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

SDK = "clients/scaas-sdk"
G = SDK + "/src/op/gas.rs"
TS = ["../../scripts/capped", "cargo", "test", "--locked", "--lib", "gas_bls_multi"]
EVM = "smartcontracts/evm"
V = EVM + "/test/gas/SdkGasVerify.t.sol"
TV = ["../../scripts/capped", "forge", "test", "--match-path", "test/gas/SdkGasVerify.t.sol", "--match-test",
      "test_sdkGas_verifyBlsMulti"]
M = [
    ("registration without per_item", G, "&& n <= COUNT_MAX => p.gas.saturating_mul(n),", "&& n <= COUNT_MAX => 0,",
     TS, SDK, "gas_bls_multi_rows_quote_by_members"),
    ("registration counts any item", G, 'Some(p) if p.item == "members" && n <= COUNT_MAX', "Some(p) if n <= COUNT_MAX",
     TS, SDK, "gas_bls_multi_rows_quote_by_members"),
    ("registration without COUNT_MAX", G, 'Some(p) if p.item == "members" && n <= COUNT_MAX', 'Some(p) if p.item == "members"',
     TS, SDK, "gas_bls_multi_rows_quote_by_members"),
    ("fit without the lifted intercept", V,
     "                if (g[r][i] - s * SG_BLS_N[i] > b[r]) b[r] = g[r][i] - s * SG_BLS_N[i];\n", "", TV, EVM,
     "test_sdkGas_verifyBlsMulti"),
    ("fit slope rounded down", V, "uint256 c = (g[r][3] - g[r][0] + 61) / 62;", "uint256 c = (g[r][3] - g[r][0]) / 62;", TV,
     EVM, "test_sdkGas_verifyBlsMulti"),
]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
