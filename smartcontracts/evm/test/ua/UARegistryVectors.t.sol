// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {P256Verifier} from "../../src/ua/verifiers/P256Verifier.sol";
import {WebAuthnP256Verifier} from "../../src/ua/verifiers/WebAuthnP256Verifier.sol";
import {Bip340Verifier} from "../../src/ua/verifiers/Bip340Verifier.sol";
import {Ed25519Verifier} from "../../src/ua/verifiers/Ed25519Verifier.sol";
import {
    SchnorrBn254Verifier,
    SchnorrBls12381Verifier,
    BlsMinSigBls12381Verifier,
    BlsMinSigBn254Verifier
} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {UARegistryBase} from "./UARegistryBase.sol";

/// The registry with the real UA-2a/UA-2b verifiers on smartcontracts/vectors/ua/signatures.json (context A, generation 1):
/// T-REG-1/T-REG-2/T-AUTH-1/T-AUTH-2/T-AUTH-3/T-CHAIN on the published rows. Gas of every call is logged (`-vv`).
contract UARegistryVectorsTest is UARegistryBase {
    string internal sj;
    bytes32 internal digest;
    uint256 internal nSigs; // counted by the loops: a path mismatch must not pass vacuously
    uint256 internal nNegs;

    function setUp() public override {
        super.setUp();
        sj = vm.readFile("../vectors/ua/signatures.json");
        digest = vm.parseJsonBytes32(sj, ".digest");
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _realCfgs());
    }

    /// The gen-1 default caps (controller ruling 2026-10-12) on the real verifiers.
    function _realCfgs() internal returns (UARegistry.KindConfig[] memory c) {
        address[8] memory v = [
            address(new WebAuthnP256Verifier()),
            address(new P256Verifier()),
            address(new Ed25519Verifier()),
            address(new Bip340Verifier()),
            address(new SchnorrBn254Verifier()),
            address(new SchnorrBls12381Verifier()),
            address(new BlsMinSigBls12381Verifier()),
            address(new BlsMinSigBn254Verifier())
        ];
        c = new UARegistry.KindConfig[](8);
        for (uint256 i; i < 8; ++i) {
            c[i] = UARegistry.KindConfig(KINDS[i], v[i], _cap(KINDS[i]));
        }
    }

    function _d(uint256 i, string memory f) internal view returns (string memory) {
        return string.concat(".derived[", vm.toString(i), "].", f);
    }

    function _purposeTag(string memory p) internal pure returns (bytes32) {
        return keccak256(bytes(string.concat("scaas.ua.purpose.", p, ".v1")));
    }

    function test_vectors_derived() public {
        uint256 rows;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            _derivedRow(i);
            ++rows;
        }
        assertEq(rows, 8, "derived kinds");
        assertEq(nSigs, 18, "derived sigs");
        assertEq(nNegs, 73, "derived negatives");
    }

    function _derivedRow(uint256 i) internal {
        uint16 kind = uint16(vm.parseJsonUint(sj, _d(i, "kind")));
        bytes memory k = vm.parseJsonBytes(sj, _d(i, "keyData"));
        bytes32 ua = vm.parseJsonBytes32(sj, _d(i, "ua"));
        assertEq(reg.popDigest(ua, 0), vm.parseJsonBytes32(sj, _d(i, "pop.popDigest")));
        // PoPs for another chain / registry and SIG-DST signatures offered as PoP: refused before the record exists
        _popRefused(kind, k, vm.parseJsonBytes(sj, _d(i, "popOther.sig")));
        for (uint256 n; _hasNeg(i, n); ++n) {
            if (vm.parseJsonBool(sj, _neg(i, n, "verifyPop"))) {
                _popRefused(kind, k, vm.parseJsonBytes(sj, _neg(i, n, "sig")));
            }
        }
        bytes memory pop = vm.parseJsonBytes(sj, _d(i, "pop.sig"));
        uint256 g = gasleft();
        reg.register(kind, k, pop, 0, "");
        g -= gasleft();
        emit log_named_uint(string.concat("register ", vm.parseJsonString(sj, _d(i, "name"))), g);
        assertEq(reg.kindOf(ua), kind);
        for (uint256 s; vm.keyExistsJson(sj, _d(i, string.concat("sigs[", vm.toString(s), "]"))); ++s) {
            _derivedSig(i, s, k, ua);
            ++nSigs;
        }
        for (uint256 n; _hasNeg(i, n); ++n) {
            ++nNegs;
            if (!vm.parseJsonBool(sj, _neg(i, n, "verifyPop"))) _derivedNegative(i, n, kind, k, ua);
        }
    }

    function _hasNeg(uint256 i, uint256 n) internal view returns (bool) {
        return vm.keyExistsJson(sj, _d(i, string.concat("negatives[", vm.toString(n), "]")));
    }

    function _neg(uint256 i, uint256 n, string memory f) internal view returns (string memory) {
        return _d(i, string.concat("negatives[", vm.toString(n), "].", f));
    }

    function _derivedSig(uint256 i, uint256 s, bytes memory k, bytes32 ua) internal {
        string memory row = string.concat("sigs[", vm.toString(s), "].");
        bytes32 p = _purposeTag(vm.parseJsonString(sj, _d(i, string.concat(row, "purpose"))));
        bytes memory auth = abi.encode(k, vm.parseJsonBytes(sj, _d(i, string.concat(row, "sig"))));
        bytes32 dg = vm.parseJsonBytes32(sj, _d(i, string.concat(row, "digest")));
        uint256 g = gasleft();
        reg.requireAuthorized(ua, p, dg, auth);
        g -= gasleft();
        if (s == 0) emit log_named_uint(string.concat("requireAuthorized ", vm.parseJsonString(sj, _d(i, "name"))), g);
    }

    /// Verify-side negatives: the registry is asked exactly the row's message under metatx or member.
    function _derivedNegative(uint256 i, uint256 n, uint16 kind, bytes memory k, bytes32 ua) internal {
        bytes32 m = vm.parseJsonBytes32(sj, _neg(i, n, "message"));
        bytes memory auth = abi.encode(k, vm.parseJsonBytes(sj, _neg(i, n, "sig")));
        bytes32 p;
        if (m == UAKinds.uaMessage(kind, UAKinds.PURPOSE_METATX, digest)) p = UAKinds.PURPOSE_METATX;
        else if (m == UAKinds.uaMessage(kind, UAKinds.PURPOSE_MEMBER, digest)) p = UAKinds.PURPOSE_MEMBER;
        else revert(string.concat(vm.parseJsonString(sj, _neg(i, n, "name")), ": a message the registry never asks"));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        reg.requireAuthorized(ua, p, digest, auth);
    }

    function _popRefused(uint16 kind, bytes memory k, bytes memory sig) internal {
        vm.expectRevert(IUARegistry.UAPoP.selector);
        reg.register(kind, k, sig, 0, "");
    }

    function test_vectors_native() public {
        bytes32 ua = vm.parseJsonBytes32(sj, ".native.ua");
        assertEq(ua, _pad(vm.addr(vm.parseJsonUint(sj, ".native.secret"))));
        string memory s = _structures();
        // gen 1 on A, gen 2 on A (gen 1 elsewhere), gen 1 on B
        uint256 sigRows;
        UARegistry gen1 = _deploy(
            address(0x5ca9), chainUidA, address(0), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0)
        );
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".native.sigs[", vm.toString(i), "]")); ++i) {
            string memory row = string.concat(".native.sigs[", vm.toString(i), "].");
            string memory ctx = vm.parseJsonString(sj, string.concat(row, "context"));
            uint256 gen = vm.parseJsonUint(sj, string.concat(row, "generation"));
            UARegistry r = reg;
            uint256 snap = vm.snapshotState();
            if (gen == 2) {
                r = _deploy(
                    REG_A, chainUidA, address(gen1), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0)
                );
            } else if (keccak256(bytes(ctx)) == keccak256("B")) {
                vm.chainId(7622);
                r = _deploy(
                    REG_A,
                    vm.parseJsonBytes32(s, ".contexts.B.chainUid"),
                    address(0),
                    false,
                    BUDGET,
                    address(0),
                    true,
                    new UARegistry.KindConfig[](0)
                );
            }
            bytes32 p = _purposeTag(vm.parseJsonString(sj, string.concat(row, "purpose")));
            bytes32 dg = vm.parseJsonBytes32(sj, string.concat(row, "digest"));
            assertEq(r.uaAuthDigest(ua, p, dg), vm.parseJsonBytes32(sj, string.concat(row, "uaAuthDigest")));
            bytes memory sig = vm.parseJsonBytes(sj, string.concat(row, "sig"));
            uint256 g = gasleft();
            r.requireAuthorized(ua, p, dg, sig);
            if (i == 0) emit log_named_uint("requireAuthorized native ECDSA", g - gasleft());
            vm.revertToState(snap);
            vm.chainId(31337); // not relied on to be restored by the snapshot
            ++sigRows;
        }
        assertEq(sigRows, 4, "native sigs");
        assertEq(block.chainid, 31337);
        uint256 negRows;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".native.negatives[", vm.toString(i), "]")); ++i) {
            string memory row = string.concat(".native.negatives[", vm.toString(i), "].");
            bytes32 p = _purposeTag(vm.parseJsonString(sj, string.concat(row, "purpose")));
            bytes memory sig = vm.parseJsonBytes(sj, string.concat(row, "sig"));
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
            reg.requireAuthorized(ua, p, vm.parseJsonBytes32(sj, string.concat(row, "digest")), sig);
            ++negRows;
        }
        assertEq(negRows, 5, "native negatives");
    }

    function test_vectors_msig() public {
        // members: the derived rows' keys, registered with their PoPs
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            reg.register(
                uint16(vm.parseJsonUint(sj, _d(i, "kind"))),
                vm.parseJsonBytes(sj, _d(i, "keyData")),
                vm.parseJsonBytes(sj, _d(i, "pop.sig")),
                0,
                ""
            );
        }
        bytes memory d = vm.parseJsonBytes(sj, ".msig.keyData");
        uint256 g = gasleft();
        bytes32 ua = reg.register(UAKinds.MSIG, d, "", 0, "");
        emit log_named_uint("register msig (4 members)", g - gasleft());
        assertEq(ua, vm.parseJsonBytes32(sj, ".msig.ua"));
        uint256 valid;
        uint256 sets;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".msig.sets[", vm.toString(i), "]")); ++i) {
            string memory row = string.concat(".msig.sets[", vm.toString(i), "].");
            ++sets;
            bytes memory auth = vm.parseJsonBytes(sj, string.concat(row, "auth"));
            assertEq(auth, abi.encode(d, vm.parseJsonBytes(sj, string.concat(row, "sig"))));
            bytes32 p = _purposeTag(vm.parseJsonString(sj, string.concat(row, "purpose")));
            bytes32 dg = vm.parseJsonBytes32(sj, string.concat(row, "digest"));
            assertEq(_memberDigest(ua, p, dg), vm.parseJsonBytes32(sj, string.concat(row, "memberDigest")));
            if (vm.parseJsonBool(sj, string.concat(row, "valid"))) {
                g = gasleft();
                reg.requireAuthorized(ua, p, dg, auth);
                g -= gasleft();
                emit log_named_uint(
                    string.concat("requireAuthorized msig ", vm.parseJsonString(sj, string.concat(row, "name"))), g
                );
                ++valid;
            } else {
                vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
                reg.requireAuthorized(ua, p, dg, auth);
            }
        }
        assertEq(sets, 9, "msig sets");
        assertEq(valid, 2);
    }
}
