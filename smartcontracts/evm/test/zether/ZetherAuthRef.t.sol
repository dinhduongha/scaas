// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ZetherFixture, ZUID} from "./helpers/ZetherFixture.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";

/// @notice T-ZET-1 (accounts.md §1.16), token side: Zether accounts with `authRef` 0, native and derived on a real
///         token. With an authority, knowing `x` (the proof) is not enough to spend or to roll over: the authority signs
///         the `authDigest` (purpose `zether-auth`) or the owner digest (purpose `zether-owner`); a self account spends
///         with the proof alone and refuses any `authSig` beside it (`zkCovered`).
contract ZetherAuthRefTest is ZetherFixture {
    uint256 internal constant OWNER_PK = 0x0DD;
    uint256 internal constant X_AUTH = 0xA07;
    bytes internal constant UA_SCHNORR_TAG = "scaas.ua.schnorr.v1";

    function setUp() public {
        _deploy(false, false);
    }

    function _authDigest(Tx memory t) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "SCAAS-ZETHER-AUTH-V1", keccak256(stm.transferStatementSingle(address(tok), t.payload, _none(), 0))
        ));
    }

    function _ecdsa(uint256 pk, bytes32 h) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r, s, v);
    }

    /// A native authority (an EOA) signs `UAAuth(authRef, purpose, digest)` under the registry's domain.
    function _nativeAuth(bytes32 purpose, bytes32 digest) internal view returns (bytes memory) {
        bytes32 authRef = bytes32(uint256(uint160(vm.addr(OWNER_PK))));
        return _ecdsa(OWNER_PK, reg.uaAuthDigest(authRef, purpose, digest));
    }

    function _nativeUser(uint256 x, address evm) internal returns (User memory) {
        bytes32 authRef = bytes32(uint256(uint160(vm.addr(OWNER_PK))));
        bytes32 ua = ZetherTypes.UA.unwrap(ZetherTypes.toUA(ZetherKeys.pub(x, bls)));
        return _user(x, evm, authRef, _nativeAuth(UAKinds.PURPOSE_AUTHREF, reg.popDigest(ua, authRef)));
    }

    /// A derived authority: a `schnorr-bn254` UA, `auth = abi.encode(Y_auth, sig over its ua_msg)`.
    function _derivedAuth(bytes32 purpose, bytes32 digest) internal view returns (bytes memory) {
        bytes32 m = reg.uaMessage(UAKinds.SCHNORR_BN254, purpose, digest);
        return abi.encode(ZetherKeys.pub(X_AUTH, false), ZetherKeys.sign(UA_SCHNORR_TAG, X_AUTH, m, false));
    }

    function _derivedAuthority() internal returns (bytes32 ua) {
        bytes memory y = ZetherKeys.pub(X_AUTH, false);
        ua = UAKinds.uaOf(UAKinds.SCHNORR_BN254, y);
        bytes32 m = reg.uaMessage(UAKinds.SCHNORR_BN254, UAKinds.PURPOSE_POP, reg.popDigest(ua, 0));
        reg.register(UAKinds.SCHNORR_BN254, y, ZetherKeys.sign(UA_SCHNORR_TAG, X_AUTH, m, false), 0, "");
    }

    /// Self: the proof is the authorization; an `authSig` beside it is refused.
    function test_selfSpendsWithTheProofOnly() public {
        _fund(tok, alice, 100);
        tok.zetherRollOver(alice.ua);
        Tx memory t = _proveTransfer(tok, alice, bob, 10, 100, _none(), 0);
        bytes memory extra = _ownerAuth(alice, _authDigest(t));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ZetherTypes.UA.unwrap(alice.ua)));
        tok.zetherTransferSingle(t.payload, t.proof, extra, _none());
        tok.zetherTransferSingle(t.payload, t.proof, "", _none());
        assertEq(tok.sendCounter(alice.ua), 1);
    }

    /// Native `authRef`: `x` alone cannot spend; the EOA's `UAAuth` over `authDigest` (purpose `zether-auth`) can.
    function test_nativeAuthRefSpends() public {
        User memory dave = _nativeUser(0xDA7E, address(0xD4));
        _fund(tok, dave, 100);
        tok.zetherRollOver(dave.ua);
        Tx memory t = _proveTransfer(tok, dave, bob, 10, 100, _none(), 0);
        bytes32 d = _authDigest(t);
        bytes32 id = ZetherTypes.UA.unwrap(dave.ua);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, id));
        tok.zetherTransferSingle(t.payload, t.proof, "", _none()); // a valid proof, no authority
        bytes memory wrongPurpose = _nativeAuth(UAKinds.PURPOSE_ZETHER_OWNER, d);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, id));
        tok.zetherTransferSingle(t.payload, t.proof, wrongPurpose, _none());
        bytes memory ownSig = _ownerAuth(dave, d);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, id));
        tok.zetherTransferSingle(t.payload, t.proof, ownSig, _none()); // the Zether key is not the authority
        tok.zetherTransferSingle(t.payload, t.proof, _nativeAuth(UAKinds.PURPOSE_ZETHER_AUTH, d), _none());
        assertEq(tok.sendCounter(dave.ua), 1);
    }

    /// Derived `authRef` (`schnorr-bn254`): spends with its signature; its owner ops use purpose `zether-owner`.
    function test_derivedAuthRefSpendsAndRollsOver() public {
        bytes32 authRef = _derivedAuthority();
        bytes32 ua = ZetherTypes.UA.unwrap(ZetherTypes.toUA(ZetherKeys.pub(0xE7E, bls)));
        User memory erin = _user(0xE7E, address(0xE4), authRef, _derivedAuth(UAKinds.PURPOSE_AUTHREF, reg.popDigest(ua, authRef)));
        _fund(tok, erin, 100);
        uint64 until = uint64(block.number + 50);
        bytes32 rd = keccak256(bytes.concat(
            abi.encode(keccak256("ZETHER_ROLLOVER_V1"), block.chainid, ZUID, address(tok)),
            abi.encode(erin.ua, uint64(0), uint64(1), until)
        ));
        bytes memory selfSig = _ownerAuth(erin, rd);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        tok.zetherRollOverSigned(erin.ua, 1, until, selfSig);
        tok.zetherRollOverSigned(erin.ua, 1, until, _derivedAuth(UAKinds.PURPOSE_ZETHER_OWNER, rd));
        Tx memory t = _proveTransfer(tok, erin, bob, 10, 100, _none(), 0);
        tok.zetherTransferSingle(t.payload, t.proof, _derivedAuth(UAKinds.PURPOSE_ZETHER_AUTH, _authDigest(t)), _none());
        assertEq(tok.sendCounter(erin.ua), 1);
        (, bytes32 recorded) = reg.recordOf(ua);
        assertEq(recorded, authRef);
    }

    /// The registry keeps `Y` (`keyOf`, CTR-ZTH-50) and the token sees only its own Zether kind as registered.
    function test_registeredByKind() public {
        assertTrue(tok.registered(alice.ua));
        assertEq(reg.keyOf(ZetherTypes.UA.unwrap(alice.ua)), alice.y);
        bytes32 authRef = _derivedAuthority();
        assertFalse(tok.registered(ZetherTypes.UA.wrap(authRef)), "a schnorr-bn254 UA over a bn254 point");
        assertFalse(tok.registered(ZetherTypes.UA.wrap(keccak256(alice.y))), "the old untagged id");
    }
}
