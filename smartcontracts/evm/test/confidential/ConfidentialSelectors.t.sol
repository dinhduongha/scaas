// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IConfidentialToken, IConfidentialUnderlyingToken} from "../../src/confidential/IConfidentialToken.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {UnderlyingPqzToken} from "../../src/pqz/UnderlyingPqzToken.sol";

/// Plan 5h D20 (spec §5.11, owner Q3): one interface, one selector per shared function across the Zether and the PQZ
/// layer; the ABI the clients encode is pinned by signature.
contract ConfidentialSelectorsTest is Test {
    function test_sharedSelectorsEqualOnBothLayers() public pure {
        bytes4[6] memory i = [
            IConfidentialToken.mtxShield.selector, IConfidentialToken.mtxConfidentialTransfer.selector,
            IConfidentialToken.mtxConfidentialTransferCompact.selector, IConfidentialToken.mtxConfidentialTransferSingle.selector,
            IConfidentialToken.mtxUnshield.selector, IConfidentialToken.mtxRollOver.selector
        ];
        bytes4[6] memory z = [
            ZetherLayer.mtxShield.selector, ZetherLayer.mtxConfidentialTransfer.selector,
            ZetherLayer.mtxConfidentialTransferCompact.selector, ZetherLayer.mtxConfidentialTransferSingle.selector,
            ZetherLayer.mtxUnshield.selector, ZetherLayer.mtxRollOver.selector
        ];
        bytes4[6] memory p = [
            PqzLayer.mtxShield.selector, PqzLayer.mtxConfidentialTransfer.selector,
            PqzLayer.mtxConfidentialTransferCompact.selector, PqzLayer.mtxConfidentialTransferSingle.selector,
            PqzLayer.mtxUnshield.selector, PqzLayer.mtxRollOver.selector
        ];
        bytes4 id;
        bytes4 zid;
        bytes4 pid;
        for (uint256 k; k < 6; ++k) {
            assertEq(z[k], i[k], "Zether");
            assertEq(p[k], i[k], "PQZ");
            (id, zid, pid) = (id ^ i[k], zid ^ z[k], pid ^ p[k]);
        }
        assertEq(id, type(IConfidentialToken).interfaceId);
        assertEq(zid, type(IConfidentialToken).interfaceId);
        assertEq(pid, type(IConfidentialToken).interfaceId);

        assertEq(UnderlyingZetherToken.mtxWrapShield.selector, IConfidentialUnderlyingToken.mtxWrapShield.selector);
        assertEq(UnderlyingPqzToken.mtxWrapShield.selector, IConfidentialUnderlyingToken.mtxWrapShield.selector);
        assertEq(UnderlyingZetherToken.mtxUnshieldUnwrap.selector, IConfidentialUnderlyingToken.mtxUnshieldUnwrap.selector);
        assertEq(UnderlyingPqzToken.mtxUnshieldUnwrap.selector, IConfidentialUnderlyingToken.mtxUnshieldUnwrap.selector);
        assertEq(UnderlyingZetherToken.mtxWrapShield.selector ^ UnderlyingPqzToken.mtxUnshieldUnwrap.selector,
            type(IConfidentialUnderlyingToken).interfaceId);
    }

    /// The shared ABI: `(payload, proof, auth, beneficiary, accHint[, …])`, ids `bytes32`.
    function test_signaturesPinned() public pure {
        assertEq(IConfidentialToken.mtxShield.selector, bytes4(keccak256("mtxShield(bytes32,uint256)")));
        assertEq(IConfidentialToken.mtxConfidentialTransfer.selector,
            bytes4(keccak256("mtxConfidentialTransfer(bytes,bytes,bytes,bytes32,bytes)")));
        assertEq(IConfidentialToken.mtxConfidentialTransferCompact.selector,
            bytes4(keccak256("mtxConfidentialTransferCompact(bytes,bytes,bytes,bytes32,bytes)")));
        assertEq(IConfidentialToken.mtxConfidentialTransferSingle.selector,
            bytes4(keccak256("mtxConfidentialTransferSingle(bytes,bytes,bytes,bytes32,bytes)")));
        assertEq(IConfidentialToken.mtxUnshield.selector,
            bytes4(keccak256("mtxUnshield(bytes,bytes,bytes,bytes32,bytes,uint256,bytes32)")));
        assertEq(IConfidentialToken.mtxRollOver.selector, bytes4(keccak256("mtxRollOver(bytes32,uint256)")));
        assertEq(IConfidentialUnderlyingToken.mtxWrapShield.selector,
            bytes4(keccak256("mtxWrapShield(address,uint256,bytes32)")));
        assertEq(IConfidentialUnderlyingToken.mtxUnshieldUnwrap.selector,
            bytes4(keccak256("mtxUnshieldUnwrap(bytes,bytes,bytes,bytes32,bytes,(address,bytes32,uint256,uint256))")));
        assertEq(IConfidentialToken.Shielded.selector, keccak256("Shielded(bytes32,address,uint256,uint64)"));
        assertEq(IConfidentialToken.RolledOver.selector, keccak256("RolledOver(bytes32,uint64,uint32,bytes32)"));
        assertEq(IConfidentialToken.Unshielded.selector, keccak256("Unshielded(bytes32,uint256,bytes32,address)"));
    }
}
