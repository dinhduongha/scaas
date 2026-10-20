// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {
    SchnorrBn254Verifier,
    ZetherSchnorrBn254Verifier,
    ZetherSchnorrBls12381Verifier
} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {ZetherSafety} from "../../src/zether/ZetherSafety.sol";
import {ZetherKeys} from "../zether/helpers/ZetherKeys.sol";
import {UARegistryBase, MockVerifier} from "./UARegistryBase.sol";

/// accounts.md CTR-UA-07, CTR-UA-16, §1.8 and §1.7 Z-auth for the Zether kinds 0x0140/0x0141 (UA-3; UA-6: the Zether
/// key is the UA, no `authRef` — the `authRef` cases are in legacy/ua6/test/ua/UARegistryZether.t.sol): the real Zether
/// Schnorr verifiers for the Zether kinds, the stand-in verifier for the classical kinds. T-AUTH-1b, T-ZET-1 (registry
/// side).
contract UARegistryZetherTest is UARegistryBase {
    uint256 internal constant PK_A = 0xA11CE;
    uint256 internal constant X1 = 0xA11CE5;
    uint256 internal constant X2 = 0xB0B5;
    address internal constant REG_Z = 0x5cA0000000000000000000000000000000000002;

    UARegistry internal zreg;
    ZetherSchnorrBn254Verifier internal zbn;
    ZetherSchnorrBls12381Verifier internal zbls;

    function setUp() public override {
        super.setUp();
        zbn = new ZetherSchnorrBn254Verifier();
        zbls = new ZetherSchnorrBls12381Verifier();
        zreg = _deploy(REG_Z, chainUidA, address(0), false, BUDGET, address(0), true, _zcfgs(address(mock)));
    }

    /// The eight classical kinds on `v`, the Zether kinds on their real verifiers (caps as `schnorr-*`).
    function _zcfgs(address v) internal view returns (UARegistry.KindConfig[] memory c) {
        UARegistry.KindConfig[] memory base = _cfgs(v);
        c = new UARegistry.KindConfig[](base.length + 2);
        for (uint256 i; i < base.length; ++i) {
            c[i] = base[i];
        }
        c[base.length] = UARegistry.KindConfig(UAKinds.ZETHER_BN254, address(zbn), 50_000);
        c[base.length + 1] = UARegistry.KindConfig(UAKinds.ZETHER_BLS12381, address(zbls), 70_000);
    }

    function _zkind(bool bls) internal pure returns (uint16) {
        return bls ? UAKinds.ZETHER_BLS12381 : UAKinds.ZETHER_BN254;
    }

    /// The Zether PoP: Schnorr by `x` under the Zether tag over `uaMessage(kind, POP, popDigest(ua, 0))`.
    function _zpop(UARegistry r, uint256 x, bool bls) internal view returns (bytes memory) {
        uint16 kind = _zkind(bls);
        bytes32 ua = r.uaOf(kind, ZetherKeys.pub(x, bls));
        return ZetherKeys.schnorr(x, r.uaMessage(kind, UAKinds.PURPOSE_POP, r.popDigest(ua, 0)), bls);
    }

    function _zregister(UARegistry r, uint256 x, bool bls) internal returns (bytes32) {
        return r.register(_zkind(bls), ZetherKeys.pub(x, bls), _zpop(r, x, bls), "", "");
    }

    /// The owner op of a self Zether UA: `abi.encode(bytes(""), Schnorr by x over uaMessage(kind, purpose, digest))`.
    function _ownerAuth(uint256 x, bool bls, bytes32 purpose, bytes32 digest) internal view returns (bytes memory) {
        return abi.encode(bytes(""), ZetherKeys.schnorr(x, zreg.uaMessage(_zkind(bls), purpose, digest), bls));
    }

    function _expectZetherUnauthorized(bytes32 ua, bytes32 digest, bytes memory auth, bool zk) internal {
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        zreg.requireZetherAuthorized(ua, digest, auth, zk);
    }

    // ----- register -----

    /// Both curves: record, stored `Y` (`keyOf`, CTR-ZTH-50), keyOwner, the event (no PQZ key).
    function test_registerSelf() public {
        for (uint256 b; b < 2; ++b) {
            bool bls = b == 1;
            bytes memory y = ZetherKeys.pub(X1, bls);
            uint16 kind = _zkind(bls);
            bytes32 ua = UAKinds.uaOf(kind, y);
            bytes memory pop = _zpop(zreg, X1, bls);
            vm.expectEmit(true, true, false, true, address(zreg));
            emit IUARegistry.UARegistered(ua, kind, y, address(0));
            uint256 g = gasleft();
            assertEq(zreg.register(kind, y, pop, "", ""), ua);
            console.log(bls ? "register zether-bls12381 self" : "register zether-bn254 self", g - gasleft());
            (IUARegistry.Record memory rec, address pqzKey) = zreg.recordOf(ua);
            assertEq(rec.kind, kind);
            assertEq(pqzKey, address(0));
            assertTrue(rec.keyPtr != address(0), "Y stored");
            assertEq(zreg.keyOf(ua), y);
            assertEq(zreg.kindOf(ua), kind);
            assertEq(zreg.keyOwner(UAKinds.keyHashOf(kind, y)), ua);
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, ua));
            zreg.register(kind, y, pop, "", "");
        }
        assertEq(zreg.keyOf(bytes32(uint256(1) << 200)).length, 0, "unregistered: empty");
    }

    /// The same point as `schnorr-bn254` and as `zether-bn254`: one keyHash group, so the second is `UAKeyInUse`.
    function test_keyHashGroupShared() public {
        bytes memory y = ZetherKeys.pub(X1, false);
        bytes32 ua = _zregister(zreg, X1, false);
        bytes32 kh = UAKinds.keyHashOf(UAKinds.SCHNORR_BN254, y);
        bytes memory pop = _pop(zreg, UAKinds.SCHNORR_BN254, y);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, kh, ua));
        zreg.register(UAKinds.SCHNORR_BN254, y, pop, "", "");
    }

    // ----- requireAuthorized / requireZetherAuthorized -----

    /// T-AUTH-1b: a registered `zether-bn254` UA never signs through `requireAuthorized`, whatever the auth (not in
    /// SIGNING; to legacy/ in UA-6 Task 4). `zether-bls12381` signs there since UA-6 (U8): `UARegistryUA6.t.sol`.
    function test_T_AUTH_1b_registeredZether() public {
        bytes32 ua = _zregister(zreg, X1, false);
        bytes memory y = ZetherKeys.pub(X1, false);
        bytes memory sig = ZetherKeys.schnorr(X1, zreg.uaMessage(UAKinds.ZETHER_BN254, UAKinds.PURPOSE_METATX, DIGEST), false);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        zreg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(y, sig));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        zreg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(bytes(""), sig));
    }

    /// Self: the proof (`zkCovered`, empty auth) or a Zether Schnorr by `x` for owner ops, purpose `zether-owner`.
    function test_zetherAuthorizedSelf() public {
        for (uint256 b; b < 2; ++b) {
            bool bls = b == 1;
            bytes32 ua = _zregister(zreg, X1, bls);
            zreg.requireZetherAuthorized(ua, DIGEST, "", true);
            bytes memory owner = _ownerAuth(X1, bls, UAKinds.PURPOSE_ZETHER_OWNER, DIGEST);
            _expectZetherUnauthorized(ua, DIGEST, owner, true); // zkCovered: auth must be empty
            uint256 g = gasleft();
            zreg.requireZetherAuthorized(ua, DIGEST, owner, false);
            console.log(bls ? "owner op zether-bls12381 self" : "owner op zether-bn254 self", g - gasleft());
            vm.expectRevert(bytes("")); // an auth that does not ABI-decode fails closed without data (as UA-2a)
            zreg.requireZetherAuthorized(ua, DIGEST, "", false);
            _expectZetherUnauthorized(ua, keccak256("other"), owner, false);
            _expectZetherUnauthorized(ua, DIGEST, _ownerAuth(X1, bls, UAKinds.PURPOSE_ZETHER_AUTH, DIGEST), false);
            _expectZetherUnauthorized(ua, DIGEST, _ownerAuth(X2, bls, UAKinds.PURPOSE_ZETHER_OWNER, DIGEST), false);
            // stored kind: Y in auth is refused
            (, bytes memory sig) = abi.decode(owner, (bytes, bytes));
            _expectZetherUnauthorized(ua, DIGEST, abi.encode(ZetherKeys.pub(X1, bls), sig), false);
        }
        // not a Zether UA, unregistered, native
        bytes32 p256 = _register(zreg, 0x0101, _key(0x0101));
        _expectZetherUnauthorized(p256, DIGEST, "", true);
        bytes32 ghost = UAKinds.uaOf(UAKinds.ZETHER_BN254, ZetherKeys.pub(X2, false));
        _expectZetherUnauthorized(ghost, DIGEST, "", true);
        bytes32 native = _pad(vm.addr(PK_A));
        _expectZetherUnauthorized(native, DIGEST, _nativeSig(zreg, PK_A, UAKinds.PURPOSE_ZETHER_AUTH, DIGEST), true);
    }

    // ----- generations -----

    /// Gen 2 (no Zether kinds of its own) sees gen-1 Zether records and their `Y`, and hands their checks to gen 1
    /// (`requireAuthorized` too for `zether-bls12381`, UA-6); it may not enable a Zether kind whose group gen 1 enables.
    function test_gen2HandsZetherToGen1() public {
        bytes32 zua = _zregister(zreg, X1, false);
        bytes32 self = _zregister(zreg, X2, true);
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry gen2 = new UARegistry(chainUidA, address(zreg), false, BUDGET, address(0), true, none);
        assertEq(gen2.kindOf(zua), UAKinds.ZETHER_BN254);
        (, address pqzKey) = gen2.recordOf(zua);
        assertEq(pqzKey, address(0));
        assertEq(gen2.keyOf(self), ZetherKeys.pub(X2, true));
        gen2.requireZetherAuthorized(zua, DIGEST, "", true);
        gen2.requireZetherAuthorized(self, DIGEST, "", true);
        gen2.requireAuthorized(self, UAKinds.PURPOSE_METATX, DIGEST, _ownerAuth(X2, true, UAKinds.PURPOSE_METATX, DIGEST));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, self));
        gen2.requireZetherAuthorized(self, DIGEST, hex"01", true);
        bytes memory y = ZetherKeys.pub(X2, false);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, UAKinds.ZETHER_BN254));
        gen2.register(UAKinds.ZETHER_BN254, y, "", "", "");
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(UAKinds.ZETHER_BLS12381, address(zbls), 70_000);
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, UAKinds.ZETHER_BLS12381));
        new UARegistry(chainUidA, address(zreg), false, BUDGET, address(0), true, c);
    }

    // ----- constructor, verifiers -----

    /// 0x0140/0x0141 have slots (and `pqz-mlwe` since P6c, `UARegistryPq.t.sol`); the neighbours do not.
    function test_constructorZetherSlots() public {
        assertTrue(zreg.kindEnabled(UAKinds.ZETHER_BN254));
        assertEq(zreg.verifyCap(UAKinds.ZETHER_BLS12381), 70_000);
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        uint16[3] memory refused = [0x013f, 0x0143, 0x0144];
        for (uint256 i; i < refused.length; ++i) {
            c[0] = UARegistry.KindConfig(refused[i], address(mock), 50_000);
            vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, refused[i]));
            new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, c);
        }
    }

    /// S13: the Zether tag and the UA Schnorr tag never accept each other's signature; the verifiers deploy on dev
    /// chains only (CTR-ZTH-02).
    function test_zetherVerifiers() public {
        SchnorrBn254Verifier ua = new SchnorrBn254Verifier();
        bytes memory y = ZetherKeys.pub(X1, false);
        bytes32 m = keccak256("m");
        bytes memory zsig = ZetherKeys.schnorr(X1, m, false);
        assertTrue(zbn.verify(y, m, zsig));
        assertTrue(zbn.verifyPop(y, m, zsig));
        assertFalse(ua.verify(y, m, zsig), "a Zether signature is no schnorr-bn254 signature");
        assertFalse(zbn.verify(y, keccak256("n"), zsig));
        assertFalse(zbls.verify(ZetherKeys.pub(X1, true), m, zsig), "wrong length");
        assertTrue(zbls.verify(ZetherKeys.pub(X1, true), m, ZetherKeys.schnorr(X1, m, true)));
        assertFalse(zbls.verify(ZetherKeys.pub(X1, true), m, new bytes(160)), "malformed: false, no revert");
        vm.chainId(7622);
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, uint256(7622)));
        new ZetherSchnorrBn254Verifier();
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, uint256(7622)));
        new ZetherSchnorrBls12381Verifier();
    }
}
