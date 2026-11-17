// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {kindModuleNames, kindImplArgs} from "../../../script/KindModules.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {closureLibs, regArgs} from "../../../test/helpers/Catalogue.sol";
import {LinkClosureTest} from "../../../test/v2/LinkClosure.t.sol";

contract Create2Probe3p {
    function deploy(bytes calldata code, bytes32 salt) external returns (address a) {
        bytes memory c = code;
        assembly ("memory-safe") { a := create2(0, add(c, 32), mload(c), salt) }
    }
}

/// @notice ua-mtx-3p (owner 2026-11-10, the body modules by function): every body module of every kind, each its own CREATE2
///         transaction through a probe (the T66b Step 1 method, runs/2026-11-09-ua-mtx-merge-t66b-build/DeployGas.t.sol):
///         regular = `lastCallGas.gasTotalUsed` x 64/63, state = EIP-8037's, asked = (regular + state) x 1.05, and the module's
///         opcode figures of `test/v2/module-opcodes.json` ([DELEGATECALL count, DELEGATECALLs without a closure PUSH20]),
///         by `LinkClosureTest`'s own walk. Line: `3P | name | runtime | init | regular | state | asked | regular x 1.05 < 2^24
///         | delegates | stack targets`. Forge gas is deterministic: a measurement of gas used, not a timing calibration.
///         FOUNDRY_TEST=runs/2026-11-10-ua-mtx-3p/probe forge test --match-test test_3pModules -vv
contract Probe3pTest is LinkClosureTest {
    Create2Probe3p internal probe;
    uint256 internal salt;

    string[14] internal faces = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "NormalPqzToken",
        "WrappedPqzToken", "", "", "NormalRegulatedToken", "WrappedRegulatedToken", "NormalZetherRegulatedToken",
        "WrappedZetherRegulatedToken", "NormalPqzRegulatedToken", "WrappedPqzRegulatedToken"];

    /// Each kind's modules, then its face (the release's init code naming them; the factory frame of `deployTokenImplementation`,
    /// about 0.31 M at T66b Step 1, is not in the face's row).
    function test_3pModules() public {
        probe = new Create2Probe3p();
        for (uint8 k; k < 14; ++k) {
            if (k == 6 || k == 7) continue;
            bytes memory core = k >= 8 ? regArgs() : bytes("");
            string[] memory n = kindModuleNames(k);
            address[] memory ms = new address[](n.length);
            for (uint256 i; i <= n.length; ++i) {
                bytes memory code = i < n.length ? bytes.concat(vm.getCode(n[i]), abi.encode(address(0xFAC), core))
                    : bytes.concat(vm.getCode(string.concat(faces[k], ".sol:", faces[k])), abi.encode(address(0xFAC), kindImplArgs(k, ms, core)));
                address a = probe.deploy(code, bytes32(++salt));
                if (i < n.length) ms[i] = a;
                Vm.Gas memory g = vm.lastCallGas();
                assertTrue(a != address(0), faces[k]);
                uint256 regular = g.gasTotalUsed * 64 / 63;
                uint256 state = uint256(int256(g.gasStateUsed));
                (uint256 delegates,,) = _walk(a.code);
                uint256 targets = _stackTargets(a.code, closureLibs(IOpenFactory.TokenKind(k)));
                string memory s = string.concat("3P | ", i < n.length ? vm.split(n[i], ":")[1] : faces[k], " | ", vm.toString(a.code.length), " | ",
                    vm.toString(code.length), " | ", vm.toString(regular), " | ", vm.toString(state), " | ");
                s = string.concat(s, vm.toString((regular + state) * 105 / 100), " | ", regular * 105 / 100 < 1 << 24 ? "yes" : "NO");
                emit log(string.concat(s, " | ", vm.toString(delegates), " | ", vm.toString(targets)));
            }
        }
    }
}
