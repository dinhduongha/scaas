// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVaultBase} from "./PqVaultBase.sol";

/// CTR-PQV-18 (controller call 2026-11-23, PqChat's CTR-CHAT-25): `PqVaultCreate.groupMode`, 0 only in this release.
contract PqVaultGroupModeTest is PqVaultBase {
    function test_onlyFlatWrapsAccepted() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(1, 4, 0, address(vault));
        v.groupMode = 1;
        bytes memory err = abi.encodeWithSelector(IPqVault.PqVaultModeUnsupported.selector, uint8(1));
        IUARegistry.UASig memory sig = _createSig(v, address(vault));
        vm.expectRevert(err);
        vault.createVault(v, w, sig);
        v.groupMode = 0;
        // the control: mode 0 lands; `vaultOf` returns the create record, groupMode included (read raw: the test's memory
        // decoder of a `UASig` runs out of stack)
        bytes32 vid = _create(vault, v, w);
        assertTrue(vault.epochComplete(vid));
        bytes memory ret = _raw(address(vault), abi.encodeCall(IPqVault.vaultOf, (vid)));
        uint256 off = uint256(bytes32(_slice32(ret, 0)));
        assertEq(uint256(bytes32(_slice32(ret, off + 11 * 32))), 0, "groupMode, the record's last head word");
    }

    function _slice32(bytes memory b, uint256 at) internal pure returns (bytes32 x) {
        assembly ("memory-safe") {
            x := mload(add(add(b, 32), at))
        }
    }
}
