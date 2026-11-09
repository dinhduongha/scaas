// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {noVerdict} from "../../pqz/helpers/PqzVerdicts.sol";
import {PqzRegFixture} from "./PqzRegFixture.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {WrappedPqzToken} from "../../../src/pqz/WrappedPqzToken.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {IPqzToken, IPqzWrappedToken} from "../../../src/pqz/IPqzToken.sol";
import {IConfidentialWrappedToken} from "../../../src/confidential/IConfidentialToken.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {IMetaTx} from "../../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {nid} from "../../helpers/Ids.sol";

/// Group 3f, T45 on the regulated PQZ kinds 12 and 13 (PQZ verifier mode spec §5.3, §4.2): `mtxSelectors()` lists the
/// proof-carrying entries with the verdict last and none of the pre-3f forms; an `OFFCHAIN` regulated token takes the
/// verifier's verdict on a debit (12: op 1; 13: the unshield-unwrap) and its owner's verifier ops run. UNAUDITED.
abstract contract PqzVerdictKinds is PqzRegFixture {
    uint256 internal constant VKEY = 0xA77E57;
    string internal constant SIG_T = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";
    string internal constant VERDICT_T =
        "((address,uint256,bytes32,bytes32,bytes32,uint32,uint64),(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))";
    string internal constant TARGS_T =
        "(uint64,uint256,uint256,bytes32,uint64,bytes32,bytes32,bytes16,bytes32,bytes,bytes,bytes,bytes,bytes)";
    string internal constant BARGS_T = "(uint64,uint256,uint256,bytes32,uint64,bytes32,bytes32,bytes,bytes)";

    function _has(bytes4 sel) internal view returns (bool found) {
        (bytes4[] memory s,,) = IMetaTx(address(tok)).mtxSelectors();
        for (uint256 i; i < s.length; ++i) if (s[i] == sel) found = true;
    }

    function _selectors() internal view {
        string memory v = string.concat(",bytes,", SIG_T, ",bytes,", VERDICT_T, ")");
        assertTrue(_has(bytes4(keccak256(bytes(string.concat("mtxConfidentialTransferSingle(", TARGS_T, v))))), "op 1");
        assertTrue(_has(bytes4(keccak256(bytes(string.concat("mtxUnshield(", BARGS_T, ",uint256,bytes32", v))))), "unshield");
        assertTrue(_has(IPqzToken.mtxConfidentialTransfer.selector) && _has(IPqzToken.mtxConfidentialTransferCompact.selector)
            && _has(IPqzToken.mtxConfidentialTransferSingleCompact.selector), "the rest");
        assertFalse(_has(bytes4(keccak256(bytes(string.concat("mtxConfidentialTransferSingle(", TARGS_T, ",bytes,", SIG_T,
            ",bytes)"))))), "no pre-3f op 1");
        if (_isWrapped()) {
            assertTrue(_has(IPqzWrappedToken.mtxUnshieldUnwrap.selector), "unwrap");
            assertTrue(_has(bytes4(keccak256(bytes(string.concat("mtxUnshieldUnwrap(", BARGS_T,
                ",(address,bytes32,uint256,uint256)", v))))));
        }
    }

    function _sepOf(address t) internal view returns (bytes32) {
        (, string memory n, string memory ver, uint256 cid, address vc, bytes32 salt_,) = PqzLayer(t).eip712Domain();
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(n)), keccak256(bytes(ver)), cid, vc, salt_));
    }

    function _sv(bytes memory st) internal view returns (IPqzToken.PqzSignedVerdict memory sv) {
        sv.pqzVerdict = IPqzToken.PqzVerdict(address(tok), block.chainid, tok.proofSystemId(), keccak256(st), keccak256(PROOF),
            tok.pqzVerifyConfig().pqzVerifierEpoch, uint64(block.timestamp + 600));
        bytes32 d = MessageHashUtils.toTypedDataHash(_sepOf(address(tok)),
            keccak256(abi.encode(PqzCore.VERDICT_TYPEHASH, sv.pqzVerdict)));
        (uint8 w, bytes32 r, bytes32 s_) = vm.sign(VKEY, reg.uaAuthDigest(nid(vm.addr(VKEY)), UAKinds.PURPOSE_PQZ_VERDICT, d));
        sv.sig.signature = abi.encodePacked(r, s_, w);
    }

    /// The fixture's token again, OFFCHAIN with the EOA verifier of `VKEY`, transferable.
    function _offchain() internal {
        (vMode, vUA, vFixed) = (PqzCore.OFFCHAIN, nid(vm.addr(VKEY)), false);
        IFactoryToken.TokenConfig memory c = _regCfg();
        (vMode, vUA, vFixed) = (0, bytes32(0), false);
        tok = PqzLayer(factory.createToken(_kind(), 1, abi.encode(c), "pr-off"));
        w = WrappedPqzToken(payable(address(tok)));
    }

    function test_offchain_debit() public {
        _offchain();
        assertEq(tok.pqzVerifyConfig().pqzVerifyMode, PqzCore.OFFCHAIN);
        _shieldTo(alice, BAL);
        if (!_isWrapped()) {
            IPqzToken.PqzTransferArgs memory t = _single(false, bob, bytes32(0), 0, 80);
            bytes memory st = tok.transferSingleStatement(t, 0);
            vm.expectRevert(abi.encodeWithSelector(IPqzToken.PqzVerdictMismatch.selector, uint8(0)));
            tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "", noVerdict());
            tok.mtxConfidentialTransferSingle(t, PROOF, _pqAuth(), "", _sv(st));
            return;
        }
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(address(0xD00D)), 5, 5 * SCALE);
        IPqzToken.PqzBurnArgs memory b = _burnArgs(bytes32(0), 0, 81);
        bytes memory bst = WrappedPqzTokenLike(address(tok)).unshieldUnwrapStatement(b, x, 0);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PqzVerdictMismatch.selector, uint8(0)));
        IPqzWrappedToken(address(tok)).mtxUnshieldUnwrap(b, x, PROOF, _pqAuth(), "", noVerdict());
        IPqzWrappedToken(address(tok)).mtxUnshieldUnwrap(b, x, PROOF, _pqAuth(), "", _sv(bst));
        assertEq(usd.balanceOf(address(0xD00D)), 5 * SCALE, "paid out of the leg");
    }

    /// The owner (`ownerA`) revokes: the next debit refuses `PqzVerifierRevoked`.
    function test_offchain_ownerRevokes() public {
        _offchain();
        _shieldTo(alice, BAL);
        vm.prank(address(0xBEEF));
        vm.expectRevert();
        tok.pqzRevokeVerifier();
        vm.prank(ownerA);
        tok.pqzRevokeVerifier();
        IPqzToken.PqzBurnArgs memory b = _burnArgs(bytes32(0), 0, 82);
        bytes memory st = tok.burnStatement(b, 0, 0, 0);
        IPqzToken.PqzSignedVerdict memory sv = _sv(st);
        vm.expectRevert(IPqzToken.PqzVerifierRevoked.selector);
        tok.mtxUnshield(b, 0, 0, PROOF, _pqAuth(), "", sv);
    }
}

/// The views of kind 13 a test needs (`WrappedPqzToken`'s).
interface WrappedPqzTokenLike {
    function unshieldUnwrapStatement(IPqzToken.PqzBurnArgs calldata b, IConfidentialWrappedToken.Unwrap calldata x,
        bytes32 binding) external view returns (bytes memory);
}

contract PqzVerdictKind12Test is PqzVerdictKinds {
    function _isWrapped() internal pure override returns (bool) { return false; }

    function test_mtxSelectors_pqzVerdict_12() public view { _selectors(); }
}

contract PqzVerdictKind13Test is PqzVerdictKinds {
    function _isWrapped() internal pure override returns (bool) { return true; }

    function test_mtxSelectors_pqzVerdict_13() public view { _selectors(); }
}
