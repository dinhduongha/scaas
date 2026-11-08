// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {IZetherToken, IZetherWrappedToken} from "../../src/zether/IZetherToken.sol";
import {IPqzToken, IPqzWrappedToken} from "../../src/pqz/IPqzToken.sol";

/// Plan 5h D20 (spec §5.11, owner Q3): one interface, one selector per shared function across the Zether and the PQZ
/// layer; the proof-taking entries are kind-specific (typed-signing Appendix X.3). The ABI the clients encode is pinned by
/// signature.
contract ConfidentialSelectorsTest is Test {
    string constant G1 = "(bytes32,bytes32,bytes32,bytes32)";

    function test_sharedSelectorsEqualOnBothLayers() public pure {
        assertEq(IConfidentialToken.mtxShield.selector ^ IConfidentialToken.mtxRollOver.selector, type(IConfidentialToken).interfaceId);
        assertEq(type(IConfidentialToken).interfaceId, bytes4(0x69d6bb06));
        assertEq(IConfidentialWrappedToken.mtxWrapShield.selector, type(IConfidentialWrappedToken).interfaceId);
        assertEq(type(IPqzWrappedToken).interfaceId, IPqzWrappedToken.mtxUnshieldUnwrap.selector);
        assertEq(type(IZetherWrappedToken).interfaceId, IZetherWrappedToken.mtxUnshieldUnwrap.selector);
    }

    /// The shared ABI, ids `bytes32`.
    function test_signaturesPinned() public pure {
        assertEq(IConfidentialToken.mtxShield.selector, bytes4(keccak256("mtxShield(bytes32,uint256)")));
        assertEq(IConfidentialToken.mtxRollOver.selector, bytes4(keccak256("mtxRollOver(bytes32,uint256)")));
        assertEq(IConfidentialWrappedToken.mtxWrapShield.selector,
            bytes4(keccak256("mtxWrapShield(address,uint256,bytes32)")));
        assertEq(IConfidentialToken.Shielded.selector, keccak256("Shielded(bytes32,address,uint256,uint64)"));
        assertEq(IConfidentialToken.RolledOver.selector, keccak256("RolledOver(bytes32,uint64,uint32,bytes32)"));
        assertEq(IConfidentialToken.Unshielded.selector, keccak256("Unshielded(bytes32,uint256,bytes32,address)"));
    }

    /// The PQZ layer's explicit entries (Appendix X.3); `IPqzToken` has the direct forms only, the signed ones are `PqzLayer`'s,
    /// read from `typed_ops.json` in `PqzTyped.t.sol`.
    function test_pqzExplicitSignaturesPinned() public pure {
        string memory tail = ",bytes,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]),bytes)";
        string memory single = "(uint64,uint256,uint256,bytes32,bytes32,bytes32,bytes16,bytes,bytes,bytes,bytes,bytes)";
        string memory multi = "(uint64,uint256,uint256,bytes32,bytes32,uint256,bytes16,bytes[],(bytes32,bytes,bytes)[],bytes,bytes)";
        string memory burn = "(uint64,uint256,uint256,bytes32,bytes32,bytes,bytes)";
        assertEq(IPqzToken.mtxConfidentialTransfer.selector, bytes4(keccak256(bytes(string.concat("mtxConfidentialTransfer(", multi, tail)))));
        assertEq(IPqzToken.mtxConfidentialTransferCompact.selector,
            bytes4(keccak256(bytes(string.concat("mtxConfidentialTransferCompact(", multi, tail)))));
        assertEq(IPqzToken.mtxConfidentialTransferSingle.selector,
            bytes4(keccak256(bytes(string.concat("mtxConfidentialTransferSingle(", single, tail)))));
        assertEq(IPqzToken.mtxConfidentialTransferSingleCompact.selector,
            bytes4(keccak256(bytes(string.concat("mtxConfidentialTransferSingleCompact(", single, tail)))));
        assertEq(IPqzToken.mtxUnshield.selector, bytes4(keccak256(bytes(string.concat("mtxUnshield(", burn, ",uint256,bytes32", tail)))));
        assertEq(IPqzWrappedToken.mtxUnshieldUnwrap.selector,
            bytes4(keccak256(bytes(string.concat("mtxUnshieldUnwrap(", burn, ",(address,bytes32,uint256,uint256)", tail)))));
    }

    /// The Zether layer's explicit entries (Appendix X.3); `IZetherToken` has the direct forms only, the signed ones are
    /// `ZetherLayer`'s, read from `typed_ops.json` in `ZetherTyped.t.sol`.
    function test_zetherExplicitSignaturesPinned() public pure {
        string memory head = "(uint64,uint64,uint256,bytes16,bytes32,";
        string memory single = string.concat(head, G1, ",", G1, ",", G1, ",", G1, ",", G1, ",", G1, ")");
        string memory legs = string.concat("(", G1, ",", G1, ",", G1, ",", G1, ")[]");
        string memory multi = string.concat(head, "uint256,", G1, ",", G1, ",", G1, ",", legs, ",bytes)");
        string memory burn = string.concat("(uint64,uint64,uint256,bytes32,", G1, ")");
        string memory sig = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";
        assertEq(IZetherToken.mtxConfidentialTransferSingle.selector,
            bytes4(keccak256(bytes(string.concat("mtxConfidentialTransferSingle(", single, ",bytes)")))));
        assertEq(IZetherToken.mtxConfidentialTransfer.selector,
            bytes4(keccak256(bytes(string.concat("mtxConfidentialTransfer(", multi, ",bytes)")))));
        assertEq(IZetherToken.mtxConfidentialTransferCompact.selector,
            bytes4(keccak256(bytes(string.concat("mtxConfidentialTransferCompact(", multi, ",bytes)")))));
        assertEq(IZetherToken.mtxUnshield.selector,
            bytes4(keccak256(bytes(string.concat("mtxUnshield(", burn, ",uint256,bytes32,bytes)")))));
        assertEq(IZetherWrappedToken.mtxUnshieldUnwrap.selector,
            bytes4(keccak256(bytes(string.concat("mtxUnshieldUnwrap(", burn, ",(address,bytes32,uint256,uint256),bytes)")))));
        assertEq(IZetherToken.mtxRollOverSigned.selector, bytes4(keccak256(bytes(string.concat("mtxRollOverSigned(bytes32,uint64,uint64,", sig, ")")))));
        assertEq(IZetherToken.mtxSetRollOverMode.selector, bytes4(keccak256(bytes(string.concat("mtxSetRollOverMode(bytes32,uint8,uint64,", sig, ")")))));
    }

    function test_badPointInTheAbi() public pure {
        assertEq(IZetherToken.BadPoint.selector, bytes4(keccak256("BadPoint()")));
    }
}
