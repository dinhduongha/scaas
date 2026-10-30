// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SchnorrBls12381Verifier, ZetherSchnorrBls12381Verifier} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {ZetherSafety} from "../../src/zether/ZetherSafety.sol";
import {ZetherKeys} from "../zether/helpers/ZetherKeys.sol";
import {UARegistryBase} from "./UARegistryBase.sol";

/// accounts.md CTR-UA-07, CTR-UA-16, §1.8 for the Zether kind 0x0141 (UA-3; UA-6: the Zether key is the UA, no
/// `authRef`, a SIGNING UA through `requireAuthorized`, U8/U9; `zether-bn254` and `requireZetherAuthorized` are in
/// `legacy/ua6/`, U10): the real Zether Schnorr verifier, the stand-in verifier for the classical kinds. T-AUTH-1b,
/// T-ZET-1 (registry side).
contract UARegistryZetherTest is UARegistryBase {
    uint256 internal constant X1 = 0xA11CE5;
    uint256 internal constant X2 = 0xB0B5;
    uint16 internal constant ZK = UAKinds.ZETHER_BLS12381;
    address internal constant REG_Z = 0x5cA0000000000000000000000000000000000002;

    UARegistry internal zreg;
    ZetherSchnorrBls12381Verifier internal zbls;

    function setUp() public override {
        super.setUp();
        zbls = new ZetherSchnorrBls12381Verifier();
        zreg = _deploy(REG_Z, chainUidA, address(0), false, BUDGET, address(0), true, _zcfgs(address(mock)));
    }

    /// The eight classical kinds on `v`, the Zether kind on its real verifier (cap as `schnorr-bls12381`).
    function _zcfgs(address v) internal view returns (UARegistry.KindConfig[] memory c) {
        UARegistry.KindConfig[] memory base = _cfgs(v);
        c = new UARegistry.KindConfig[](base.length + 1);
        for (uint256 i; i < base.length; ++i) {
            c[i] = base[i];
        }
        c[base.length] = UARegistry.KindConfig(ZK, address(zbls), 70_000);
    }

    /// The Zether PoP: Schnorr by `x` under the Zether tag over the portable `uaMessage(0x0141, POP_V2, registrationDigest(portablePopDigest(ua, 0, 0), 0))` (UA-8).
    function _zpop(UARegistry r, uint256 x) internal view returns (bytes memory) {
        bytes32 ua = r.uaOf(ZK, ZetherKeys.pub(x, true));
        return ZetherKeys.schnorr(x, r.uaMessage(ZK, UAKinds.PURPOSE_POP_V2, UAKinds.registrationDigest(UAKinds.portablePopDigest(ua, 0, 0), 0)), true);
    }

    function _zregister(UARegistry r, uint256 x) internal returns (bytes32) {
        return r.register(ZK, ZetherKeys.pub(x, true), _none(), _zpop(r, x), "");
    }

    /// A Zether UA's signature: `abi.encode(bytes(""), Schnorr by x over uaMessage(0x0141, purpose, digest))`.
    function _zauth(uint256 x, bytes32 purpose, bytes32 digest) internal view returns (bytes memory) {
        return abi.encode(bytes(""), ZetherKeys.schnorr(x, zreg.uaMessage(ZK, purpose, digest), true));
    }

    function _expectUnauthorized(bytes32 ua, bytes32 purpose, bytes memory auth) internal {
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        zreg.requireAuthorized(ua, purpose, DIGEST, auth);
    }

    // ----- register -----

    /// Record, stored `Y` (`keyOf`, CTR-ZTH-50), keyOwner, the event (no PQZ key).
    function test_registerSelf() public {
        bytes memory y = ZetherKeys.pub(X1, true);
        bytes32 ua = UAKinds.uaOf(ZK, y);
        bytes memory pop = _zpop(zreg, X1);
        vm.expectEmit(true, true, false, true, address(zreg));
        emit IUARegistry.UARegistered(ua, ZK, y, _none(), keccak256(pop), "", 1, 0, 0);
        uint256 g = gasleft();
        assertEq(zreg.register(ZK, y, _none(), pop, ""), ua);
        console.log("register zether-bls12381", g - gasleft());
        (IUARegistry.Record memory rec, address pqzKey) = zreg.recordOf(ua);
        assertEq(rec.kind, ZK);
        assertEq(pqzKey, address(0));
        assertTrue(rec.keyPtr != address(0), "Y stored");
        assertEq(zreg.keyOf(ua), y);
        assertEq(zreg.kindOf(ua), ZK);
        assertEq(zreg.keyOwner(UAKinds.keyHashOf(ZK, y)), ua);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, ua));
        zreg.register(ZK, y, _none(), pop, "");
        assertEq(zreg.keyOf(bytes32(uint256(1) << 200)).length, 0, "unregistered: empty");
    }

    /// The same point as `schnorr-bls12381` and as `zether-bls12381`: one keyHash group, so the second is `UAKeyInUse`.
    function test_keyHashGroupShared() public {
        bytes memory y = ZetherKeys.pub(X1, true);
        bytes32 ua = _zregister(zreg, X1);
        bytes32 kh = UAKinds.keyHashOf(UAKinds.SCHNORR_BLS12381, y);
        bytes memory pop = _pop(zreg, UAKinds.SCHNORR_BLS12381, y);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, kh, ua));
        zreg.register(UAKinds.SCHNORR_BLS12381, y, _none(), pop, "");
    }

    // ----- requireAuthorized (UA-6 U8/U9: no requireZetherAuthorized) -----

    /// The token's owner ops (`zether-owner`) and every other write: a Schnorr by `x` on `Y` from `keyPtr`; another
    /// purpose, another key, `Y` in `auth` or an undecodable `auth` fail.
    function test_zetherOwnerOpThroughRequireAuthorized() public {
        bytes32 ua = _zregister(zreg, X1);
        bytes memory owner = _zauth(X1, UAKinds.PURPOSE_ZETHER_OWNER, DIGEST);
        uint256 g = gasleft();
        zreg.requireAuthorized(ua, UAKinds.PURPOSE_ZETHER_OWNER, DIGEST, owner);
        console.log("owner op zether-bls12381 (requireAuthorized)", g - gasleft());
        _expectUnauthorized(ua, UAKinds.PURPOSE_ZETHER_OWNER, _zauth(X1, UAKinds.PURPOSE_ZETHER_AUTH, DIGEST));
        _expectUnauthorized(ua, UAKinds.PURPOSE_ZETHER_OWNER, _zauth(X2, UAKinds.PURPOSE_ZETHER_OWNER, DIGEST));
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, owner);
        (, bytes memory sig) = abi.decode(owner, (bytes, bytes));
        bytes memory withY = abi.encode(ZetherKeys.pub(X1, true), sig); // stored kind: Y in auth is refused
        _expectUnauthorized(ua, UAKinds.PURPOSE_ZETHER_OWNER, withY);
        vm.expectRevert(bytes("")); // an auth that does not ABI-decode fails closed without data (as UA-2a)
        zreg.requireAuthorized(ua, UAKinds.PURPOSE_ZETHER_OWNER, DIGEST, "");
        bytes32 ghost = UAKinds.uaOf(ZK, ZetherKeys.pub(X2, true));
        _expectUnauthorized(ghost, UAKinds.PURPOSE_ZETHER_OWNER, _zauth(X2, UAKinds.PURPOSE_ZETHER_OWNER, DIGEST));
    }

    // ----- generations -----

    /// Gen 2 (no Zether kind of its own) sees gen-1 Zether records and their `Y`, and hands their checks to gen 1; it
    /// may not enable a Zether kind whose group gen 1 enables.
    function test_gen2HandsZetherToGen1() public {
        bytes32 z = _zregister(zreg, X2);
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry gen2 = new UARegistry(chainUidA, address(zreg), false, BUDGET, address(0), true, none);
        assertEq(gen2.kindOf(z), ZK);
        (, address pqzKey) = gen2.recordOf(z);
        assertEq(pqzKey, address(0));
        assertEq(gen2.keyOf(z), ZetherKeys.pub(X2, true));
        gen2.requireAuthorized(z, UAKinds.PURPOSE_METATX, DIGEST, _zauth(X2, UAKinds.PURPOSE_METATX, DIGEST));
        bytes memory other = _zauth(X1, UAKinds.PURPOSE_METATX, DIGEST);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, z));
        gen2.requireAuthorized(z, UAKinds.PURPOSE_METATX, DIGEST, other);
        bytes memory y = ZetherKeys.pub(X1, true);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, ZK));
        gen2.register(ZK, y, _none(), "", "");
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(ZK, address(zbls), 70_000);
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, ZK));
        new UARegistry(chainUidA, address(zreg), false, BUDGET, address(0), true, c);
    }

    // ----- constructor, verifiers -----

    /// 0x0141 has a slot (and `pqz-mlwe` since P6c, `UARegistryPq.t.sol`); `zether-bn254` (0x0140, legacy) and the
    /// neighbours do not.
    function test_constructorZetherSlots() public {
        assertTrue(zreg.kindEnabled(ZK));
        assertFalse(zreg.kindEnabled(0x0140));
        assertEq(zreg.verifyCap(ZK), 70_000);
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        uint16[4] memory refused = [0x013f, 0x0140, 0x0143, 0x0144];
        for (uint256 i; i < refused.length; ++i) {
            c[0] = UARegistry.KindConfig(refused[i], address(mock), 50_000);
            vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, refused[i]));
            new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, c);
        }
    }

    /// S13: the Zether tag and the UA Schnorr tag never accept each other's signature; the verifier deploys on dev
    /// chains only (CTR-ZTH-02).
    function test_zetherVerifiers() public {
        SchnorrBls12381Verifier ua = new SchnorrBls12381Verifier();
        bytes memory y = ZetherKeys.pub(X1, true);
        bytes32 m = keccak256("m");
        bytes memory zsig = ZetherKeys.schnorr(X1, m, true);
        assertTrue(zbls.verify(y, m, zsig));
        assertTrue(zbls.verifyPop(y, m, zsig));
        assertFalse(ua.verify(y, m, zsig), "a Zether signature is no schnorr-bls12381 signature");
        assertFalse(zbls.verify(y, m, ZetherKeys.sign("scaas.ua.schnorr.v1", X1, m, true)), "and back");
        assertFalse(zbls.verify(y, keccak256("n"), zsig));
        assertFalse(zbls.verify(ZetherKeys.pub(X1, false), m, ZetherKeys.schnorr(X1, m, false)), "a bn254 key");
        assertFalse(zbls.verify(y, m, new bytes(160)), "malformed: false, no revert");
        vm.chainId(7622);
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, uint256(7622)));
        new ZetherSchnorrBls12381Verifier();
    }
}
