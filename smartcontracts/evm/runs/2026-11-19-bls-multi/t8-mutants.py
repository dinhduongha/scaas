#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 8 mutants (0x0121 stored-path dispatch, a direct verifyMinimal for msig members, N1). From the worktree root:
python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

EVM = "smartcontracts/evm"
CORE = EVM + "/src/ua/UARegistryCoreLib.sol"
REG = EVM + "/src/ua/UARegistry.sol"
T = [os.path.abspath("scripts/capped"), "forge", "test", "--match-path", "test/ua/UARegistryBlsMulti.t.sol"]
MIN = "abi.encodeWithSelector(IUAMinimalVerifier.verifyMinimal.selector, SSTORE2.read(r.keyPtr), message, sig);"
M = [(n, f, a, b, T, EVM, e) for n, f, a, b, e in [
    ("verify instead of verifyMinimal on the stored paths (single signer)", CORE,
     "        if (UAKinds.hasSurplusForm(kind)) return _multi(cfg, kind, ua, purpose, digest, d, sig);\n",
     "        if (UAKinds.hasSurplusForm(kind) && purpose == UAKinds.PURPOSE_POP_V2) return _multi(cfg, kind, ua, purpose, digest, d, sig);\n"
     "        if (UAKinds.hasSurplusForm(kind)) { IUARegistry.Record memory q = UAStore.layout().records[ua]; return UAStore.capped(address(uint160(cfg)), cfg >> 160, abi.encodeWithSelector(bytes4(keccak256(\"verify(bytes,bytes32,bytes)\")), SSTORE2.read(q.keyPtr), UAKinds.uaMessage(kind, purpose, digest), sig), 1, true); }\n",
     "test_portable_minimalOnly"),
    ("verify instead of verifyMinimal for every stored path (the shared helper)", CORE, MIN,
     "abi.encodeWithSelector(bytes4(keccak256(\"verify(bytes,bytes32,bytes)\")), SSTORE2.read(r.keyPtr), message, sig);",
     "test_acceptMembership_minimalOnly"),
    ("pop v2 sent to verifyMinimal", CORE,
     "        if (purpose == UAKinds.PURPOSE_POP_V2) {\n            bytes memory pop",
     "        if (false) {\n            bytes memory pop",
     "test_register_typedEqualsPacked"),
    ("verifyPop kept for app purposes", CORE,
     "        if (purpose == UAKinds.PURPOSE_POP_V2) {\n            bytes memory pop",
     "        if (true) {\n            bytes memory pop",
     "test_portableApp_popAggregateUnderMultiPop_UAUnauthorized"),
    ("_memberOk keeps the requireAuthorized hop for 0x0121", CORE,
     "        if (UAKinds.hasSurplusForm(kind)) return _multi(_cfgMulti(), kind, id, UAKinds.PURPOSE_MEMBER, md, \"\", s.sig);\n",
     "", "test_acceptMembership_minimalOnly"),
    ("a hand-off to the predecessor when _cfg(0x0121) is 0", CORE,
     "        if (uint160(cfg) == 0) return false;\n        bytes32 message",
     "        if (uint160(cfg) == 0) return UAStore.via(_pred(), ua, purpose, digest, IUARegistry.UASig(\"\", sig, new IUARegistry.MemberSig[](0)));\n        bytes32 message",
     "test_storedPath_noMultiVerifier_false"),
    ("the fourth word not appended", REG,
     "            mstore(add(e, 96), m)\n", "",
     "test_libWords_fourth_isMultiCfg"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
