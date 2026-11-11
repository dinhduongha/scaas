// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UACall} from "../ua/UACall.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {WrapLimitsBase} from "../wrap/WrapLimitsBase.sol";

/// Group 3l, plan T98 (wrap limits spec 2026-11-10 §9): `mtxSetWrapLimits` and `mtxSetWrapMember` through the chain's
/// `GovernanceRouter` on a hybrid whose owner is `alice` (a native id, her own key); the subject is the signer; a signature
/// over a type string without the referenced struct types fails; bit 27 through the router's existing grant ops. The digests
/// are built here from the type strings, as a wallet builds them. UNAUDITED.
contract GovWrapLimitsTest is WrapLimitsBase {
    string constant LIMIT = "WrapLimit(uint24 perUser,uint64 tokenWide,uint32 period)";
    string constant LEG = "WrapLegLimits(address underlying,uint8 unitExp,uint16 decayDays,WrapLimit wrapShort,WrapLimit wrapLong,WrapLimit unwrapShort,WrapLimit unwrapLong)";
    string constant SET = "UASetWrapLimits(bytes32 from,address target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string constant MEMBER = "UASetWrapMember(bytes32 from,address target,bytes32 account,bool canWrap,bool canUnwrap,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string constant GRANT = "UAGrantRole(bytes32 from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

    GovernanceRouter internal router;
    WrappedToken internal w;

    function setUp() public override {
        super.setUp();
        router = new GovernanceRouter(chainUidA, REG_L, address(0), false);
        (address[] memory l, uint256[] memory n) = _one(u);
        IFactoryToken.TokenConfig memory c = _cfg(l, n, 1 | (uint256(1) << GovernanceBits.MINTABLE) | CONTROLS);
        c.admin = _pad(alice);
        address impl_ = address(new WrappedToken(address(this), kindArgs(1, address(this), "")));
        w = WrappedToken(payable(EnvKit.clone(impl_, EnvKit.env(chainUidA, REG_L, address(0), false, address(router)))));
        w.initialize(nid(address(this)), 1, abi.encode(c));
    }

    function _domain() internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) = router.eip712Domain();
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt));
    }

    function _env(bytes32 from) internal view returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(from, 1, router.mtxNonce(from, 1), block.timestamp + 1 hours, 0, address(0), 0, address(0));
    }

    function _limit(IWrappedToken.WrapLimit memory x) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256(bytes(LIMIT)), x.perUser, x.tokenWide, x.period));
    }

    function _legs(IWrappedToken.WrapLegLimits[] memory legs) internal pure returns (bytes32) {
        bytes memory cat;
        for (uint256 i; i < legs.length; ++i) {
            IWrappedToken.WrapLegLimits memory l = legs[i];
            cat = bytes.concat(cat, keccak256(abi.encode(keccak256(bytes(string.concat(LEG, LIMIT))), l.underlying, l.unitExp,
                l.decayDays, _limit(l.wrapShort), _limit(l.wrapLong), _limit(l.unwrapShort), _limit(l.unwrapLong))));
        }
        return keccak256(cat);
    }

    function _digest(string memory typeString, MetaTxLib.UAEnvelope memory e, bytes memory words)
        internal view returns (bytes32)
    {
        bytes32 h = keccak256(bytes.concat(abi.encode(keccak256(bytes(typeString)), e.from, address(w)), words,
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        return keccak256(abi.encodePacked("\x19\x01", _domain(), h));
    }

    function _setLimits(uint256 pk, bytes32 from, string memory typeString, IWrappedToken.WrapLegLimits[] memory legs,
        bytes memory err) internal
    {
        MetaTxLib.UAEnvelope memory e = _env(from);
        bytes memory sig = _ecdsa(pk, _digest(typeString, e, abi.encode(_legs(legs), true, false, false)));
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(RELAYER);
        router.mtxSetWrapLimits(e, address(w), legs, true, false, false, UACall.auth(from, sig));
    }

    function test_setWrapLimitsThroughTheRouter() public {
        IWrappedToken.WrapLegLimits[] memory legs = _cfg1(2, 730, L(10, 0, 1 days), OFF(), OFF(), OFF());
        _setLimits(ALICE_PK, _pad(alice), string.concat(SET, LEG, LIMIT), legs, "");
        (IWrappedToken.WrapLegLimits[] memory got, bool net,,,,,,) = w.wrapLimits();
        assertEq(got[0].wrapShort.perUser, 10);
        assertEq(got[0].decayDays, 730);
        assertTrue(net);
    }

    function test_theSubjectIsTheSigner() public {
        IWrappedToken.WrapLegLimits[] memory legs = _cfg1(0, 0, L(10, 0, 1 days), OFF(), OFF(), OFF());
        _setLimits(BOB_PK, _pad(bob), string.concat(SET, LEG, LIMIT), legs,
            abi.encodeWithSelector(IAdmin.NotAdmin.selector, _pad(bob)));
    }

    /// A wallet that leaves a referenced struct type out of the type string signs another digest: refused.
    function test_aMissingStructTypeFails() public {
        IWrappedToken.WrapLegLimits[] memory legs = _cfg1(0, 0, L(10, 0, 1 days), OFF(), OFF(), OFF());
        _setLimits(ALICE_PK, _pad(alice), string.concat(SET, LEG), legs, abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector));
        _setLimits(ALICE_PK, _pad(alice), string.concat(SET, LIMIT, LEG), legs,
            abi.encodeWithSelector(IMetaTx.MetaTxBadSignature.selector)); // the referenced types out of order
        _setLimits(ALICE_PK, _pad(alice), string.concat(SET, LEG, LIMIT), legs, ""); // positive control
    }

    function _member(uint256 pk, bytes32 from, bytes32 account, bytes memory err) internal {
        MetaTxLib.UAEnvelope memory e = _env(from);
        bytes memory sig = _ecdsa(pk, _digest(MEMBER, e, abi.encode(account, true, true)));
        if (err.length != 0) vm.expectRevert(err);
        vm.prank(RELAYER);
        router.mtxSetWrapMember(e, address(w), account, true, true, UACall.auth(from, sig));
    }

    function test_setWrapMemberThroughTheRouter() public {
        _member(BOB_PK, _pad(bob), uaP, abi.encodeWithSelector(IGovernance.MissingRole.selector, WLIST, _pad(bob)));
        vm.prank(alice);
        w.grantRole(WLIST, _pad(bob));
        _member(BOB_PK, _pad(bob), uaP, "");
        IWrappedToken.WrapQuota memory q = w.wrapQuotaOf(uaP, u);
        assertTrue(q.canWrap && q.canUnwrap);
    }

    /// Bit 27 needs no op of its own: the router's `mtxGrantRole` grants it.
    function test_redeemerThroughTheRouterGrantOp() public {
        MetaTxLib.UAEnvelope memory e = _env(_pad(alice));
        bytes memory sig = _ecdsa(ALICE_PK, _digest(GRANT, e, abi.encode(uint8(RED), _pad(MERCHANT))));
        vm.prank(RELAYER);
        router.mtxGrantRole(e, address(w), RED, _pad(MERCHANT), UACall.auth(_pad(alice), sig));
        assertTrue(w.hasRole(RED, _pad(MERCHANT)));
        assertTrue(w.wrapQuotaOf(_pad(MERCHANT), u).redeemer);
    }
}
