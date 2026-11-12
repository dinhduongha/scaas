// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindModuleNames, deployKindModules, deployDexModules} from "../../../script/KindModules.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {GovernanceLib} from "../../../src/governance/GovernanceLib.sol";
import {TradeLib} from "../../../src/trade/TradeLib.sol";
import {closureLibs, regArgs} from "../../../test/helpers/Catalogue.sol";
import {LinkClosureTest} from "../../../test/v2/LinkClosure.t.sol";

/// @notice Fable recheck-2 P3-1 (CTR-GOV-27): the opcode figures of `test/v2/module-opcodes.json` ([DELEGATECALL count,
///         DELEGATECALLs without a closure PUSH20]) of every body module and of the DEX's two, measured on the built modules
///         as `test_moduleOpcodes` scans them. Lines `P31 | <module> | <count> | <targets>`. Run from smartcontracts/evm with
///         the file copied into test/ (forge compiles test/ only).
contract ProbeP31 is LinkClosureTest {
    function test_probeP31() public {
        for (uint8 k; k < 14; ++k) {
            if (k == 6 || k == 7) continue;
            (address[] memory ms,) = deployKindModules(k, address(0xFAC), k >= 8 ? regArgs() : bytes(""));
            string[] memory n = kindModuleNames(k);
            for (uint256 i; i < ms.length; ++i) _line(vm.split(n[i], ":")[1], ms[i].code, closureLibs(IOpenFactory.TokenKind(k)));
        }
        (address[] memory d,) = deployDexModules(address(0xFAC));
        address[] memory dl = new address[](2);
        (dl[0], dl[1]) = (address(GovernanceLib), address(TradeLib));
        _line("SCaaSDexGovernanceModule", d[0].code, dl);
        _line("SCaaSDexLiquidityModule", d[1].code, dl);
    }

    function _line(string memory name, bytes memory c, address[] memory closure) internal {
        (uint256 delegates,,) = _walk(c);
        emit log(string.concat("P31 | ", name, " | ", vm.toString(delegates), " | ", vm.toString(_stackTargets(c, closure))));
    }
}
