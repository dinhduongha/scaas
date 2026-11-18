// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindModuleNames, deployKindModules} from "../../../script/KindModules.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {closureLibs, regArgs} from "../../../test/helpers/Catalogue.sol";
import {LinkClosureTest} from "../../../test/v2/LinkClosure.t.sol";

/// @notice Set-auditor closing review C3.2: the opcode figures of `test/v2/module-opcodes.json` ([DELEGATECALL count,
///         DELEGATECALLs without a closure PUSH20]) of every body module of the confidential kinds 2, 3, 4, 5, 10, 11, 12, 13,
///         measured on the built modules (LinkClosure's own scan), each line `OPC | kind | module | pinned | now`. Lists only;
///         the re-pin is the bundle step's.
contract OpcodeProbe is LinkClosureTest {
    function test_c3OpcodeList() public {
        string memory pins = vm.readFile("test/v2/module-opcodes.json");
        uint8[8] memory ks = [2, 3, 4, 5, 10, 11, 12, 13];
        for (uint256 j; j < 8; ++j) {
            uint8 k = ks[j];
            (address[] memory ms,) = deployKindModules(k, address(0xFAC), k >= 8 ? regArgs() : bytes(""));
            string[] memory n = kindModuleNames(k);
            for (uint256 i; i < ms.length; ++i) {
                string memory name = vm.split(n[i], ":")[1];
                (uint256 d,,) = _walk(ms[i].code);
                uint256 t = _stackTargets(ms[i].code, closureLibs(IOpenFactory.TokenKind(k)));
                uint256[] memory want = vm.parseJsonUintArray(pins, string.concat(".", name));
                emit log(string.concat("OPC | ", vm.toString(k), " | ", name, " | [", vm.toString(want[0]), ", ", vm.toString(want[1]),
                    "] | [", vm.toString(d), ", ", vm.toString(t), "]", d != want[0] || t != want[1] ? " | MOVED" : ""));
            }
        }
    }
}
