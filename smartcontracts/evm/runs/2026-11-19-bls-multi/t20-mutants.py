#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 20 mutants (the Fable build review's fixes B1-B3). From the worktree root, PATH holding forge:
python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

EVM = "smartcontracts/evm"
R = EVM + "/src/ua/UARegistryRegLib.sol"
C = EVM + "/src/ua/UARegistryCoreLib.sol"
TF = ["../../scripts/capped", "forge", "test", "--match-path", "test/ua/UARegistryBlsMulti.t.sol"]
NODE = "scaas-node"
T = NODE + "/src/typed.rs"
TN = ["../scripts/capped", "cargo", "test", "--locked", "--lib", "bls_multi"]
M = [
    ("B1 gen-2 lists a gen-1 group", R, "        if (cap == 0 && UAKinds.hasSurplusForm(kind)) revert IUARegistry.UAMemberUnknown(id);\n", "",
     TF, EVM, "test_storedPath_noMultiVerifier_false"),
    ("B3 a member slot by verify, not verifyMinimal", C,
     "abi.encodeWithSelector(IUAMinimalVerifier.verifyMinimal.selector, SSTORE2.read(r.keyPtr), message, sig);",
     "abi.encodeWithSelector(bytes4(keccak256(\"verify(bytes,bytes32,bytes)\")), SSTORE2.read(r.keyPtr), message, sig);", TF, EVM,
     "test_updateMsig_blsMultiMember_minimalOnly"),
    ("B2 member slot signers ignored", T, '    if (ty == "MemberSig" || ty == "InnerSig") && j.get("signers").is_some() {',
     '    if false && j.get("signers").is_some() {', TN, NODE, "bls_multi_member_slot_named"),
    ("B2 member slot keeps the packed 160", T, "    if sig.len() == 160 {\n        bail!(\"HEX_ARGS_REFUSED",
     "    if sig.len() == 0 {\n        bail!(\"HEX_ARGS_REFUSED", TN, NODE, "bls_multi_member_slot_named"),
]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
