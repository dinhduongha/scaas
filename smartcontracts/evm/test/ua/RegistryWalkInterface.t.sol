// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IUAVerifyOnlyVerifier} from "../../src/ua/IUAVerifier.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {MldsaVerifier} from "../../src/ua/MlDsa.sol";

/// The frozen walk interface (spec 2026-11-19-registry-verify-only-kinds §11.3, CTR-UA-72; owner W4, P13, M8; plan Task 11): what a
/// later generation, the node and the SDK call on a predecessor. Pinned as the typehash pins are: each full signature with its
/// return types (and the list's hash), each selector, the error selectors, the `UASig` / `MemberSig` encoding (in the check
/// entries' selectors), the verifier getters, the hold constants, and each view's Solidity type (a typed function pointer per
/// entry: a changed argument or return type does not compile). A change moves the pin with old -> new and needs the owner.
contract RegistryWalkInterfaceIsPinned is Test {
    string[55] internal SIGS = [
        "predecessor()(address)",
        "generation()(uint8)",
        "chainUid()(bytes32)",
        "hederaNative()(bool)",
        "verifyBudget()(uint64)",
        "txGasCap()(uint64)",
        "smartKeyCloneHash()(bytes32)",
        "kindEnabled(uint16)(bool)",
        "verifyOnly(uint16)(bool)",
        "verifyCap(uint16)(uint64)",
        "verifierOf(uint16)(address)",
        "kindHome(uint16)(address)",
        "holderOf(bytes32)(address,uint16,address)",
        "kindOf(bytes32)(uint16)",
        "isRegistered(bytes32)(bool)",
        "recordOf(bytes32)((uint16,uint40,address,uint40),address)",
        "keyOf(bytes32)(bytes)",
        "webAuthnKeyOf(bytes32)((bytes32,bytes32,bytes32))",
        "muSig2KeyOf(bytes32)((bytes,bytes[]))",
        "frostKeyOf(bytes32)((bytes,uint16,(bytes[],bytes,bytes32)[]))",
        "registrationOf(bytes32)(uint16,bytes,(bytes,bytes32,(uint8,bytes,bytes32),bytes32),bytes,bytes)",
        "popOf(bytes32)(bytes)",
        "popSlotsOf(bytes32)(uint16[],bytes32[])",
        "expandedKeyOf(bytes32)(address[3])",
        "keyOwner(bytes32)(bytes32)",
        "checkedOf(bytes32)(uint8,uint8,uint8)",
        "msigOf(bytes32)((uint16,(uint16,bytes32,uint16)[]))",
        "msigStateOf(bytes32)(uint64,uint256,uint256)",
        "msigAt(bytes32,uint64)((uint16,(uint16,bytes32,uint16)[]),uint256)",
        "memberAccepted(bytes32,uint256)(bool)",
        "memberSigHashOf(bytes32,uint256)(bytes32)",
        "kemKeyOf(bytes32)(uint64,(uint8,bytes,bytes32),bytes)",
        "kemKeyAt(bytes32,uint64)((uint8,bytes,bytes32),bytes)",
        "pqzHomeOf(bytes32)(address)",
        "pqzKeyOf(bytes32)(uint64,address,bytes32,bool)",
        "pqzKeyAt(bytes32,uint64)(address,bytes32,bool)",
        "pqzKeyLatest(bytes32)(uint64)",
        "pqzKeyUsed(bytes32,bytes32)(bool)",
        "pqzKeySigOf(bytes32,uint64)(bytes)",
        "pqzPopOf(bytes32,uint64)(bytes)",
        "pqzScopedKeyOf(bytes32,address)(uint64,address,bytes32,bool)",
        "pqzScopedKeyAt(bytes32,address,uint64)(address,bytes32,bool)",
        "pqzScopedKeyLatest(bytes32,address)(uint64)",
        "pqzScopedPopOf(bytes32,address,uint64)(bytes)",
        "pqzOpenKemAt(bytes32,address,uint64)((uint8,bytes,bytes32))",
        "pqzScopedCount(address)(uint256)",
        "pqzScopedAt(address,uint256)(bytes32)",
        "uaCount(uint16)(uint256)",
        "uaAt(uint16,uint256)(bytes32)",
        "uaPage(uint16,uint256,uint256)(bytes32[])",
        "uaIndex(bytes32)(uint256)",
        "requireAuthorized(bytes32,bytes32,bytes32,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))()",
        "requirePortable(bytes32,bytes32,bytes32,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))()",
        "requirePortableApp(bytes32,bytes32,bytes32,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))()",
        "lineReaches(address)(bool)"
    ];

    bytes32 internal constant LIST_HASH = 0xaee91dbf4ed9aca8fba7135130c99b8d80674711be3ee21ed0baacf6f8d0ec7c; // Task 21 P3-5 (lineReaches): 0x9b671c72… -> 0x3b34c54d…; CTR-UA-74 (msigAt, owner 2026-11-25): 0x3b34c54d… -> 0xaee91dbf…

    function test_walkInterface_signaturesSelectorsAndHash() public view {
        bytes4[55] memory sel = [
            IUARegistry.predecessor.selector,
            IUARegistry.generation.selector,
            IUARegistry.chainUid.selector,
            IUARegistry.hederaNative.selector,
            IUARegistry.verifyBudget.selector,
            IUARegistry.txGasCap.selector,
            IUARegistry.smartKeyCloneHash.selector,
            IUARegistry.kindEnabled.selector,
            IUARegistry.verifyOnly.selector,
            IUARegistry.verifyCap.selector,
            IUARegistry.verifierOf.selector,
            IUARegistry.kindHome.selector,
            IUARegistry.holderOf.selector,
            IUARegistry.kindOf.selector,
            IUARegistry.isRegistered.selector,
            IUARegistry.recordOf.selector,
            IUARegistry.keyOf.selector,
            IUARegistry.webAuthnKeyOf.selector,
            IUARegistry.muSig2KeyOf.selector,
            IUARegistry.frostKeyOf.selector,
            IUARegistry.registrationOf.selector,
            IUARegistry.popOf.selector,
            IUARegistry.popSlotsOf.selector,
            IUARegistry.expandedKeyOf.selector,
            IUARegistry.keyOwner.selector,
            IUARegistry.checkedOf.selector,
            IUARegistry.msigOf.selector,
            IUARegistry.msigStateOf.selector,
            IUARegistry.msigAt.selector, // CTR-UA-74 (owner 2026-11-25)
            IUARegistry.memberAccepted.selector,
            IUARegistry.memberSigHashOf.selector,
            IUARegistry.kemKeyOf.selector,
            IUARegistry.kemKeyAt.selector,
            IUARegistry.pqzHomeOf.selector,
            IUARegistry.pqzKeyOf.selector,
            IUARegistry.pqzKeyAt.selector,
            IUARegistry.pqzKeyLatest.selector,
            IUARegistry.pqzKeyUsed.selector,
            IUARegistry.pqzKeySigOf.selector,
            IUARegistry.pqzPopOf.selector,
            IUARegistry.pqzScopedKeyOf.selector,
            IUARegistry.pqzScopedKeyAt.selector,
            IUARegistry.pqzScopedKeyLatest.selector,
            IUARegistry.pqzScopedPopOf.selector,
            IUARegistry.pqzOpenKemAt.selector,
            IUARegistry.pqzScopedCount.selector,
            IUARegistry.pqzScopedAt.selector,
            IUARegistry.uaCount.selector,
            IUARegistry.uaAt.selector,
            IUARegistry.uaPage.selector,
            IUARegistry.uaIndex.selector,
            IUARegistry.requireAuthorized.selector,
            IUARegistry.requirePortable.selector,
            IUARegistry.requirePortableApp.selector,
            IUARegistry.lineReaches.selector // Task 21 review P3-5: OpenFactory's env check asks it of a later generation (§10)
        ];
        bytes memory all;
        for (uint256 i; i < SIGS.length; ++i) {
            bytes memory s = bytes(SIGS[i]);
            uint256 e = _argsEnd(s);
            bytes memory head = new bytes(e + 1);
            for (uint256 j; j <= e; ++j) {
                head[j] = s[j];
            }
            assertEq(bytes4(keccak256(head)), sel[i], SIGS[i]);
            all = i == 0 ? s : bytes.concat(all, "\n", s);
        }
        assertEq(keccak256(all), LIST_HASH, "the list's hash");
    }

    /// The index of the `)` that closes a signature's argument list.
    function _argsEnd(bytes memory s) internal pure returns (uint256 i) {
        uint256 d;
        for (;; ++i) {
            if (s[i] == "(") ++d;
            if (s[i] == ")" && --d == 0) return i;
        }
    }

    function test_walkInterface_errorsGettersHold() public view {
        assertEq(UAKinds.UAVerifyGas.selector, bytes4(keccak256("UAVerifyGas()")));
        assertEq(IUARegistry.UAKeyNotCached.selector, bytes4(keccak256("UAKeyNotCached(bytes32)")));
        assertEq(IUARegistry.UAKeyCache.selector, bytes4(keccak256("UAKeyCache(uint16)")));
        assertEq(IUARegistry.UAKeyData.selector, bytes4(keccak256("UAKeyData(uint16)")));
        assertEq(IUARegistry.UAPoP.selector, bytes4(keccak256("UAPoP()")));
        assertEq(IUARegistry.UAUnauthorized.selector, bytes4(keccak256("UAUnauthorized(bytes32)")));
        assertEq(IUARegistry.UAVerifyOnly.selector, bytes4(keccak256("UAVerifyOnly(uint16)")));
        assertEq(IUAVerifyOnlyVerifier.PRECOMPILE.selector, bytes4(keccak256("PRECOMPILE()")));
        assertEq(IUAVerifyOnlyVerifier.KEY_FORM.selector, bytes4(keccak256("KEY_FORM()")));
        assertEq(
            MldsaVerifier(address(0)).PRECOMPILE.selector,
            bytes4(keccak256("PRECOMPILE()")),
            "every PQ verifier's getter"
        );
        assertEq(MldsaVerifier.verifyCached.selector, bytes4(keccak256("verifyCached(bytes,bytes32,bytes)")));
        assertEq(SigCheck.GAS_MARGIN, 5_000, "the hold: cap / 63 + GAS_MARGIN");
    }

    /// Each entry's Solidity type: a changed argument or return type in `IUARegistry` does not compile.
    function test_walkInterface_types() public view {
        IUARegistry r = IUARegistry(address(0));
        {
            function() external view returns (address) f0 = r.predecessor;
            f0;
        }
        {
            function() external view returns (uint8) f1 = r.generation;
            f1;
        }
        {
            function() external view returns (bytes32) f2 = r.chainUid;
            f2;
        }
        {
            function() external view returns (bool) f3 = r.hederaNative;
            f3;
        }
        {
            function() external view returns (uint64) f4 = r.verifyBudget;
            f4;
        }
        {
            function() external view returns (uint64) f5 = r.txGasCap;
            f5;
        }
        {
            function() external view returns (bytes32) f6 = r.smartKeyCloneHash;
            f6;
        }
        {
            function(uint16) external view returns (bool) f7 = r.kindEnabled;
            f7;
        }
        {
            function(uint16) external view returns (bool) f8 = r.verifyOnly;
            f8;
        }
        {
            function(uint16) external view returns (uint64) f9 = r.verifyCap;
            f9;
        }
        {
            function(uint16) external view returns (address) f10 = r.verifierOf;
            f10;
        }
        {
            function(uint16) external view returns (address) f11 = r.kindHome;
            f11;
        }
        {
            function(bytes32) external view returns (address, uint16, address) f12 = r.holderOf;
            f12;
        }
        {
            function(bytes32) external view returns (uint16) f13 = r.kindOf;
            f13;
        }
        {
            function(bytes32) external view returns (bool) f14 = r.isRegistered;
            f14;
        }
        {
            function(bytes32) external view returns (IUARegistry.Record memory, address) f15 = r.recordOf;
            f15;
        }
        {
            function(bytes32) external view returns (bytes memory) f16 = r.keyOf;
            f16;
        }
        {
            function(bytes32) external view returns (IUARegistry.WebAuthnKey memory) f17 = r.webAuthnKeyOf;
            f17;
        }
        {
            function(bytes32) external view returns (IUARegistry.MuSig2Key memory) f18 = r.muSig2KeyOf;
            f18;
        }
        {
            function(bytes32) external view returns (IUARegistry.FrostKey memory) f19 = r.frostKeyOf;
            f19;
        }
        {
            function(bytes32)
                external
                view returns (uint16, bytes memory, IUARegistry.UAAttrs memory, bytes memory, bytes memory)
                f20 = r.registrationOf;
            f20;
        }
        {
            function(bytes32) external view returns (bytes memory) f21 = r.popOf;
            f21;
        }
        {
            function(bytes32) external view returns (uint16[] memory, bytes32[] memory) f22 = r.popSlotsOf;
            f22;
        }
        {
            function(bytes32) external view returns (address[3] memory) f23 = r.expandedKeyOf;
            f23;
        }
        {
            function(bytes32) external view returns (bytes32) f24 = r.keyOwner;
            f24;
        }
        {
            function(bytes32) external view returns (uint8, uint8, uint8) f25 = r.checkedOf;
            f25;
        }
        {
            function(bytes32) external view returns (IUARegistry.MsigStructure memory) f26 = r.msigOf;
            f26;
        }
        {
            function(bytes32) external view returns (uint64, uint256, uint256) f27 = r.msigStateOf;
            f27;
        }
        {
            function(bytes32, uint64) external view returns (IUARegistry.MsigStructure memory, uint256) f27b = r.msigAt;
            f27b;
        }
        {
            function(bytes32, uint256) external view returns (bool) f28 = r.memberAccepted;
            f28;
        }
        {
            function(bytes32, uint256) external view returns (bytes32) f29 = r.memberSigHashOf;
            f29;
        }
        {
            function(bytes32) external view returns (uint64, IUARegistry.KemKey memory, bytes memory) f30 = r.kemKeyOf;
            f30;
        }
        {
            function(bytes32, uint64) external view returns (IUARegistry.KemKey memory, bytes memory) f31 = r.kemKeyAt;
            f31;
        }
        {
            function(bytes32) external view returns (address) f32 = r.pqzHomeOf;
            f32;
        }
        {
            function(bytes32) external view returns (uint64, address, bytes32, bool) f33 = r.pqzKeyOf;
            f33;
        }
        {
            function(bytes32, uint64) external view returns (address, bytes32, bool) f34 = r.pqzKeyAt;
            f34;
        }
        {
            function(bytes32) external view returns (uint64) f35 = r.pqzKeyLatest;
            f35;
        }
        {
            function(bytes32, bytes32) external view returns (bool) f36 = r.pqzKeyUsed;
            f36;
        }
        {
            function(bytes32, uint64) external view returns (bytes memory) f37 = r.pqzKeySigOf;
            f37;
        }
        {
            function(bytes32, uint64) external view returns (bytes memory) f38 = r.pqzPopOf;
            f38;
        }
        {
            function(bytes32, address) external view returns (uint64, address, bytes32, bool) f39 = r.pqzScopedKeyOf;
            f39;
        }
        {
            function(bytes32, address, uint64) external view returns (address, bytes32, bool) f40 = r.pqzScopedKeyAt;
            f40;
        }
        {
            function(bytes32, address) external view returns (uint64) f41 = r.pqzScopedKeyLatest;
            f41;
        }
        {
            function(bytes32, address, uint64) external view returns (bytes memory) f42 = r.pqzScopedPopOf;
            f42;
        }
        {
            function(bytes32, address, uint64) external view returns (IUARegistry.KemKey memory) f43 = r.pqzOpenKemAt;
            f43;
        }
        {
            function(address) external view returns (uint256) f44 = r.pqzScopedCount;
            f44;
        }
        {
            function(address, uint256) external view returns (bytes32) f45 = r.pqzScopedAt;
            f45;
        }
        {
            function(uint16) external view returns (uint256) f46 = r.uaCount;
            f46;
        }
        {
            function(uint16, uint256) external view returns (bytes32) f47 = r.uaAt;
            f47;
        }
        {
            function(uint16, uint256, uint256) external view returns (bytes32[] memory) f48 = r.uaPage;
            f48;
        }
        {
            function(bytes32) external view returns (uint256) f49 = r.uaIndex;
            f49;
        }
        {
            function(bytes32, bytes32, bytes32, IUARegistry.UASig memory) external view f50 = r.requireAuthorized;
            f50;
        }
        {
            function(bytes32, bytes32, bytes32, IUARegistry.UASig memory) external view f51 = r.requirePortable;
            f51;
        }
        {
            function(bytes32, bytes32, bytes32, IUARegistry.UASig memory) external view f52 = r.requirePortableApp;
            f52;
        }
        {
            function(address) external view returns (bool) f53 = r.lineReaches;
            f53;
        }
    }
}
