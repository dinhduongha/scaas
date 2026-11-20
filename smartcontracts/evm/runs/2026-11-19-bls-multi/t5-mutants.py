#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 5 mutants (UAKinds 0x0121 key data). From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

EVM = "smartcontracts/evm"
UK = EVM + "/src/ua/UAKinds.sol"
T = [os.path.abspath("scripts/capped"), "forge", "test", "--match-path", "test/ua/UAKinds.t.sol"]
G2ADD_FIRST = [  # the (n - 1) G2ADD calls and the apk comparison moved before the n G2MSM checks, one buffer
    ("        bytes memory buf = new bytes(512); // a key ‖ scalar 1 (G2MSM), then acc ‖ key (G2ADD)\n",
     "        bytes memory buf = new bytes(512);\n"
     "        assembly (\"memory-safe\") {\n            mcopy(add(buf, 32), add(d, 292), 256)\n        }\n"
     "        for (uint256 i = 1; i < n; ++i) {\n            uint256 o = 260 + 258 * i;\n"
     "            assembly (\"memory-safe\") {\n                mcopy(add(buf, 288), add(add(d, 32), o), 256)\n            }\n"
     "            if (!_add(buf)) return false;\n        }\n"
     "        bool sumOk = !_zeroAt(buf, 0, 256) && _hashAt(buf, 0, 256) == _hashAt(d, 0, 256);\n"),
    ("        assembly (\"memory-safe\") {\n            mstore(buf, 512)\n            mcopy(add(buf, 32), add(d, 292), 256) // acc = pk_1\n        }\n"
     "        for (uint256 i = 1; i < n; ++i) {\n            uint256 o = 260 + 258 * i;\n            assembly (\"memory-safe\") {\n"
     "                mcopy(add(buf, 288), add(add(d, 32), o), 256)\n            }\n            if (!_add(buf)) return false;\n        }\n"
     "        assembly (\"memory-safe\") {\n            mstore(buf, 256)\n        }\n"
     "        return !_zeroAt(buf, 0, 256) && keccak256(buf) == _hashAt(d, 0, 256);\n",
     "        return sumOk;\n"),
]
M = [(n, f, a, b, T, EVM, e) for n, f, a, b, e in [
    ("G2ADD before the G2MSM checks", UK, G2ADD_FIRST, None, "test_blsMulti_invalidKeyFailsBeforeG2Add"),
    ("uncapped G2ADD", UK, "ok := staticcall(G2ADD_GAS, 0x0d,", "ok := staticcall(gas(), 0x0d,", "EQUIVALENT"),
    ("uint16 weight sum", UK, "            total += w;\n        }\n        uint256 t = _u16(d, 256);",
     "            total = (total + w) & 0xffff;\n        }\n        uint256 t = _u16(d, 256);", "test_blsMulti_weightSumWide"),
    ("order check <= instead of <", UK, "            if (i > 0 && !_lt(d, o - 258, o, 256)) return false;",
     "            if (i > 0 && _lt(d, o, o - 258, 256)) return false;", "test_blsMulti_kinds_json_rows"),
    ("no identity check on a key", UK, "            if (_zeroAt(buf, 0, 256) || !_precompile(", "            if (!_precompile(",
     "test_blsMulti_kinds_json_rows"),
    ("no identity check on apk", UK, "        return !_zeroAt(buf, 0, 256) && keccak256(buf)", "        return keccak256(buf)",
     "test_blsMulti_kinds_json_rows"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
