// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {deployKindModules, deployDexModules} from "../../script/KindModules.sol";
import {GovernanceRouterTypes as T} from "../../src/governance/GovernanceRouterBase.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {ComplianceRegistry} from "../../src/regulated/ComplianceRegistry.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {ZetherStatements} from "../../src/zether/ZetherStatements.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {plainEnv, withModules} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {NoteKind, INoteKind} from "../v2/mocks/GenericKinds.sol";
import {RouterOpsRelease} from "../governance/GovRouterAdmin.t.sol";
import {SdkGasRouterBase} from "./SdkGasRouter.t.sol";

/// The router's fifteen admin entries of `OpenFactory` and `ComplianceRegistry` (round 3r), in the order of
/// `GovRouterAdminTest._everyOp`, on a factory whose admin is `eoa` (configured for this router, env 1 and release 1 of the
/// Normal kind, the DEX and class 4 kind 0 published) and a `ComplianceRegistry(eoa, router)`: env 9 of each published
/// (every `Env` array of two), release 2 of each approved, the token approval revoked, release 1 of each deprecated, the
/// Wrapped kind and class 4 kind 0 enabled, a KYC provider enabled, one account's compliance set (a first write; each
/// further account adds its own), the chain's directory entries set. Variant `factory` (the registry's two: `registry`).
contract SdkGasRouterAdminTest is SdkGasRouterBase {
    uint16 internal constant CLS = 4;
    bytes32 internal constant PROV = bytes32(uint256(0x9A0F));
    OpenFactory internal f;
    ComplianceRegistry internal cr;
    SmartKeyAccountFactory internal skaf;
    RelayFeeRouter internal relay;
    ZetherStatements internal zs;
    /// the op being built: its kind's index (0 token, 1 DEX, 2 class) and, for `SetCompliance`, its account
    uint8 internal adWhich;

    function setUp() public override {
        super.setUp();
        // the registry at `PREG` and the router name the deploy's `SmartKeyAccount` implementation (G4, `SdkGasRouterFix`):
        // its factory is the directory's entry (`SmartKeyCloneHashMismatch` otherwise)
        skaf = sgSkaf;
        relay = new RelayFeeRouter();
        zs = new ZetherStatements();
        address a = address(uint160(uint256(eoa)));
        _routerNaming(EnvKit.nextCreate(2)); // G-3: the router names the factory built next
        f = EnvKit.factory(a, chainUidA, 0, address(router));
        IFactoryToken.Env memory e;
        bytes32 fu = EnvKit.uidOf(address(f));
        vm.startPrank(a);
        f.publishTokenEnv(IOpenFactory.TokenKind.NORMAL, 1, fu, e);
        f.publishDexEnv(1, fu, e);
        f.publishClassEnv(CLS, 0, 1, fu, e);
        f.deployTokenImplementation(
            IOpenFactory.TokenKind.NORMAL, 1, 1, type(RouterOpsRelease).creationCode, hex"01", fu
        );
        f.deployDexImplementation(1, 1, type(RouterOpsRelease).creationCode, hex"02", fu);
        f.deployImplementation(
            IOpenFactory.ReleaseId(CLS, 0, 1),
            1,
            INoteKind.initialize.selector,
            type(INoteKind).interfaceId,
            type(NoteKind).creationCode,
            hex"03",
            fu
        );
        vm.stopPrank();
        cr = new ComplianceRegistry(eoa, address(router), chainUidA);
    }

    /// An env every array of two: the router's registry, no `SmartKeyAccount` implementation (the fixture's registry has
    /// none).
    function _adEnv() internal pure returns (IFactoryToken.Env memory e) {
        e.registry = PREG;
        e.deps = new address[](2);
        (e.deps[0], e.deps[1]) = (address(0xD1), address(0xD2));
        e.params = new bytes32[](2);
        (e.params[0], e.params[1]) = (keccak256("param 0"), keccak256("param 1"));
        e.libs = new address[](2);
        (e.libs[0], e.libs[1]) = (address(0x11B1), address(0x11B2));
        e.libCodeHashes = new bytes32[](2);
        (e.libCodeHashes[0], e.libCodeHashes[1]) = (keccak256("lib 1"), keccak256("lib 2"));
    }

    /// I1 part 2, K2 (owner 2026-11-19): the env of a counted point, `adShape[sgPoint]` = (deps, params, libs with their
    /// code hashes); the item counts every element of the four arrays. Each array grows from the empty env on its own
    /// sequence (deps 0, 4; params 0, 2; libs 0, 2, 4), so the slope is the worst array's.
    uint256[3][] internal adShape;

    function _adEnvN() internal view returns (IFactoryToken.Env memory e) {
        if (bytes(sgCountTag).length == 0) return _adEnv();
        uint256[3] memory sh = adShape[sgPoint];
        e.registry = PREG;
        e.deps = new address[](sh[0]);
        for (uint256 i; i < sh[0]; ++i) {
            e.deps[i] = address(uint160(0xD1 + i));
        }
        e.params = new bytes32[](sh[1]);
        for (uint256 i; i < sh[1]; ++i) {
            e.params[i] = keccak256(abi.encode("param", i));
        }
        (e.libs, e.libCodeHashes) = (new address[](sh[2]), new bytes32[](sh[2]));
        for (uint256 i; i < sh[2]; ++i) {
            (e.libs[i], e.libCodeHashes[i]) = (address(uint160(0x11B1 + i)), keccak256(abi.encode("lib", i)));
        }
    }

    /// The env rows of `entry` at the points of `adShape` (tags `d<deps>p<params>l<libs>_`).
    function _adEnvRows(string memory entry, string memory v) internal {
        uint256[3][7] memory sh = [
            [uint256(0), 0, 0],
            [uint256(4), 0, 0],
            [uint256(0), 0, 0],
            [uint256(0), 2, 0],
            [uint256(0), 0, 0],
            [uint256(0), 0, 2],
            [uint256(0), 0, 4]
        ];
        delete adShape;
        uint256[] memory counts = new uint256[](7);
        string[] memory tags = new string[](7);
        for (uint256 i; i < 7; ++i) {
            adShape.push(sh[i]);
            counts[i] = sh[i][0] + sh[i][1] + 2 * sh[i][2];
            tags[i] =
                string.concat("d", vm.toString(sh[i][0]), "p", vm.toString(sh[i][1]), "l", vm.toString(sh[i][2]), "_");
        }
        (grWho, sgLineLoose) = (eoa, true); // P1 (owner 2026-11-19, "approved"): the worst array's slope, a line above
        _bothTagged("gov_router", entry, v, address(router), eoa, _adPublish, counts, tags);
        sgLineLoose = false;
        _grApply(_adPublish);
    }

    function _adEnvHash(IFactoryToken.Env memory v) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                T.ENV,
                v.registry,
                v.smartKeyAccountImpl,
                v.hedera,
                keccak256(abi.encodePacked(v.deps)),
                keccak256(abi.encodePacked(v.params)),
                keccak256(abi.encodePacked(v.libs)),
                keccak256(abi.encodePacked(v.libCodeHashes))
            )
        );
    }

    /// `PublishTokenEnv` / `PublishDexEnv` / `PublishClassEnv` (by `adWhich`) of env 9.
    function _adPublish(address, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _grE(nonce);
        IFactoryToken.Env memory v = _adEnvN();
        bytes32 h = _adEnvHash(v);
        address t = address(f);
        if (adWhich == 0) {
            bytes32 d = _grD(T.UA_PUBLISH_TOKEN_ENV, t, abi.encode(uint8(0), uint16(9), chainUidA, h), e);
            return abi.encodeCall(
                router.mtxPublishTokenEnv, (e, t, IOpenFactory.TokenKind.NORMAL, 9, chainUidA, v, _auth(grWho, d))
            );
        }
        if (adWhich == 1) {
            bytes32 d = _grD(T.UA_PUBLISH_DEX_ENV, t, abi.encode(uint16(9), chainUidA, h), e);
            return abi.encodeCall(router.mtxPublishDexEnv, (e, t, 9, chainUidA, v, _auth(grWho, d)));
        }
        bytes32 dc = _grD(T.UA_PUBLISH_CLASS_ENV, t, abi.encode(CLS, uint16(0), uint16(9), chainUidA, h), e);
        return abi.encodeCall(router.mtxPublishClassEnv, (e, t, CLS, 0, 9, chainUidA, v, _auth(grWho, dc)));
    }

    /// `DeprecateToken` / `DeprecateDex` / `DeprecateRelease` (by `adWhich`) of release 1.
    function _adDeprecate(address, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _grE(nonce);
        (address t, string memory why) = (address(f), "a release found bad");
        bytes32 r = keccak256(bytes(why));
        if (adWhich == 0) {
            bytes32 d = _grD(T.UA_DEPRECATE_TOKEN, t, abi.encode(uint8(0), uint64(1), chainUidA, r), e);
            return abi.encodeCall(
                router.mtxDeprecateToken, (e, t, IOpenFactory.TokenKind.NORMAL, 1, chainUidA, why, _auth(grWho, d))
            );
        }
        if (adWhich == 1) {
            bytes32 d = _grD(T.UA_DEPRECATE_DEX, t, abi.encode(uint64(1), chainUidA, r), e);
            return abi.encodeCall(router.mtxDeprecateDex, (e, t, 1, chainUidA, why, _auth(grWho, d)));
        }
        bytes32 dc = _grD(T.UA_DEPRECATE_RELEASE, t, abi.encode(CLS, uint16(0), uint64(1), chainUidA, r), e);
        return abi.encodeCall(router.mtxDeprecateRelease, (e, t, CLS, 0, 1, chainUidA, why, _auth(grWho, dc)));
    }

    /// `SetCompliance` of one account holding nothing yet (KYC, no expiry).
    function _adCompliance(address, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _grE(nonce);
        uint256 n = _sgN(1); // I1 part 2: the accounts counted, each holding nothing yet
        (bytes32[] memory a, uint64[] memory fl, uint64[] memory un) =
            (new bytes32[](n), new uint64[](n), new uint64[](n));
        for (uint256 i; i < n; ++i) {
            (a[i], fl[i], un[i]) = (bytes32(uint256(0xACC1 + i)), 1, type(uint64).max);
        }
        bytes memory w = abi.encode(
            keccak256(abi.encodePacked(a)), keccak256(abi.encodePacked(fl)), keccak256(abi.encodePacked(un)), chainUidA
        );
        bytes32 d = _grD(T.UA_SET_COMPLIANCE, address(cr), w, e);
        return abi.encodeCall(router.mtxSetCompliance, (e, address(cr), a, fl, un, chainUidA, _auth(grWho, d)));
    }

    /// The approval of release 2 of `op` (0 token, 1 DEX, 2 class 4 kind 0) on env 1: its static words.
    function _adApproval(uint8 op) internal view returns (bytes memory head, bytes memory tail) {
        bytes memory code = op == 2 ? type(NoteKind).creationCode : type(RouterOpsRelease).creationCode;
        bytes memory args = abi.encodePacked(bytes1(0xA0) | bytes1(op + 3));
        if (op == 0) {
            head = abi.encode(uint8(0), uint64(2), uint16(1));
        } else if (op == 1) {
            head = abi.encode(uint64(2), uint16(1));
        } else {
            head = abi.encode(
                CLS, uint16(0), uint64(2), uint16(1), INoteKind.initialize.selector, type(INoteKind).interfaceId
            );
        }
        tail = abi.encode(
            keccak256(code),
            keccak256(args),
            chainUidA,
            address(f),
            f.adminGeneration(),
            uint64(block.timestamp + 1 days)
        );
    }

    function _adStatic(string memory entry, bytes32 th, bytes4 sel, address t, bytes memory args) internal {
        _grSt(entry, t == address(cr) ? "registry" : "factory", th, sel, eoa, t, args);
    }

    /// G2: the same sequence by derived identities (`_grUaRun`): the factory and the compliance registry, made by `eoa`'s
    /// key in `setUp`, handed to the derived `eoa` first (transferred by the key, accepted through the router, no row).
    function test_sdkGas_routerAdmin_ua() public {
        bytes32 ua = UAKinds.uaOf(UAKinds.SECP256K1, sgUaKey);
        vm.startPrank(address(uint160(uint256(eoa))));
        IAdmin(address(f)).transferAdmin(ua, chainUidA);
        IAdmin(address(cr)).transferAdmin(ua, chainUidA);
        vm.stopPrank();
        _grUaRun();
        _grDo(T.UA_ACCEPT_ADMIN, router.mtxAcceptAdmin.selector, eoa, address(f), "");
        _grDo(T.UA_ACCEPT_ADMIN, router.mtxAcceptAdmin.selector, eoa, address(cr), "");
        test_sdkGas_routerAdmin();
    }

    function test_sdkGas_routerAdmin() public {
        address t = address(f);
        string memory v = "factory";
        for (uint8 k; k < 3; ++k) {
            adWhich = k;
            _adEnvRows(["mtxPublishTokenEnv", "mtxPublishDexEnv", "mtxPublishClassEnv"][k], v);
        }
        bytes32[3] memory th = [T.UA_APPROVE_TOKEN_RELEASE, T.UA_APPROVE_DEX_RELEASE, T.UA_APPROVE_RELEASE];
        bytes4[3] memory sel = [
            router.mtxApproveTokenRelease.selector,
            router.mtxApproveDexRelease.selector,
            router.mtxApproveRelease.selector
        ];
        string[3] memory name = ["mtxApproveTokenRelease", "mtxApproveDexRelease", "mtxApproveRelease"];
        bytes32 key;
        for (uint8 k; k < 3; ++k) {
            (bytes memory head, bytes memory tail) = _adApproval(k);
            _adStatic(name[k], th[k], sel[k], t, bytes.concat(head, tail));
            if (k == 0) {
                (bytes memory h0, bytes memory t0) = _adApproval(0);
                key = keccak256(
                    bytes.concat(
                        abi.encode(keccak256("scaas.factory.release.token"), f.chainUid(), t), h0, _adFirstTwo(t0)
                    )
                );
            }
        }
        _adStatic(
            "mtxRevokeApproval", T.UA_REVOKE_APPROVAL, router.mtxRevokeApproval.selector, t, abi.encode(key, chainUidA)
        );
        for (uint8 k; k < 3; ++k) {
            adWhich = k;
            _grRow(["mtxDeprecateToken", "mtxDeprecateDex", "mtxDeprecateRelease"][k], v, eoa, _adDeprecate);
        }
        _adStatic(
            "mtxSetTokenKindEnabled",
            T.UA_SET_TOKEN_KIND_ENABLED,
            router.mtxSetTokenKindEnabled.selector,
            t,
            abi.encode(uint8(1), true, chainUidA)
        );
        _adStatic(
            "mtxSetClassKindEnabled",
            T.UA_SET_CLASS_KIND_ENABLED,
            router.mtxSetClassKindEnabled.selector,
            t,
            abi.encode(CLS, uint16(0), true, chainUidA)
        );
        _adStatic(
            "mtxSetKycProvider",
            T.UA_SET_KYC_PROVIDER,
            router.mtxSetKycProvider.selector,
            address(cr),
            abi.encode(PROV, true, chainUidA)
        );
        _grRowN("mtxSetCompliance", "registry", eoa, _adCompliance, _grCounts(true));
        bytes memory nine = abi.encode(
            address(relay),
            address(relay).codehash,
            relay.EXECUTOR().codehash,
            address(cr),
            address(cr).codehash,
            address(skaf),
            address(skaf).codehash,
            address(zs),
            address(zs).codehash
        );
        _grSet(
            T.UA_SET_CHAIN_ENTRIES,
            router.mtxSetChainEntries.selector,
            t,
            bytes.concat(nine, abi.encode(chainUidA)),
            abi.encode(keccak256(bytes.concat(T.CHAIN_ENTRIES, nine)), chainUidA)
        );
        _grRow("mtxSetChainEntries", v, eoa, _grStatic);
    }

    /// The first two words of an approval's tail (the code hashes): the token approval's key ends with them.
    function _adFirstTwo(bytes memory tail) internal pure returns (bytes memory r) {
        r = new bytes(64);
        for (uint256 i; i < 64; ++i) {
            r[i] = tail[i];
        }
    }
}

/// The router's three creates (`mtxCreateToken`, `mtxCreateDex`, `mtxCreateInstance`) on a factory configured for the router
/// (`GovRouterCreateTest`'s: release 1 of the Normal kind and the DEX with their modules, class 4 kind 0 `NoteKind`
/// enabled), each a new contract at a fresh salt by `eoa`: a Normal token of 1,000 units to one holder (variant `normal`),
/// a DEX (`dex`), a note instance (`note`).
contract SdkGasRouterCreateTest is SdkGasRouterBase {
    address internal constant REGISTRAR = address(0x5E6);
    uint16 internal constant CLS = 4;
    OpenFactory internal f;
    uint8 internal crWhich;
    address[] internal crUnd;

    function setUp() public override {
        super.setUp();
        _routerNaming(EnvKit.nextCreate(2)); // G-3: the router names the factory built next
        f = EnvKit.factory(REGISTRAR, chainUidA, 0, address(router));
        (address[] memory ms, bytes memory args) = deployKindModules(0, address(f), "");
        (address[] memory dm, bytes memory dargs) = deployDexModules(address(f));
        bytes32 fu = EnvKit.uidOf(address(f));
        vm.startPrank(REGISTRAR);
        f.publishTokenEnv(
            IOpenFactory.TokenKind.NORMAL, 1, fu, withModules(plainEnv(address(f), sgSka, chainUidA, PREG, false), ms)
        );
        f.deployTokenImplementation(IOpenFactory.TokenKind.NORMAL, 1, 1, type(NormalToken).creationCode, args, fu);
        // K2: the Wrapped kind's release, whose `TokenConfig.legs` the creation counts
        (address[] memory wm, bytes memory wargs) = deployKindModules(1, address(f), "");
        f.publishTokenEnv(
            IOpenFactory.TokenKind.WRAPPED, 1, fu, withModules(plainEnv(address(f), sgSka, chainUidA, PREG, false), wm)
        );
        f.deployTokenImplementation(IOpenFactory.TokenKind.WRAPPED, 1, 1, type(WrappedToken).creationCode, wargs, fu);
        for (uint256 i; i < 8; ++i) {
            crUnd.push(address(new MockERC20("L", "L", 6)));
        }
        f.publishDexEnv(1, fu, withModules(plainEnv(address(f), sgSka, chainUidA, address(0), false), dm));
        f.deployDexImplementation(1, 1, type(SCaaSDex).creationCode, dargs, fu);
        f.publishClassEnv(CLS, 0, 1, fu, plainEnv(address(f), sgSka, chainUidA, address(0), false));
        f.deployImplementation(
            IOpenFactory.ReleaseId(CLS, 0, 1),
            1,
            INoteKind.initialize.selector,
            type(INoteKind).interfaceId,
            type(NoteKind).creationCode,
            "",
            fu
        );
        f.setClassKindEnabled(CLS, 0, true, fu);
        vm.stopPrank();
    }

    function _crBuild(address, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _grE(nonce);
        address t = address(f);
        bytes32 salt = keccak256("sdk-gas");
        if (crWhich == 0) {
            bytes memory a = abi.encode(normalInit("C", "C", 6, 1000, address(0xCAFE), address(0)));
            bytes32 d = _grD(T.UA_CREATE_TOKEN, t, abi.encode(uint8(0), uint64(1), keccak256(a), salt), e);
            return
                abi.encodeCall(
                    router.mtxCreateToken, (e, t, IOpenFactory.TokenKind.NORMAL, 1, a, salt, _auth(grWho, d))
                );
        }
        if (crWhich == 3) {
            // K2: a Wrapped token of `_sgN(1)` legs 1:1, each an ERC-20 of its own
            IFactoryToken.TokenConfig memory c;
            (c.name, c.symbol, c.decimals, c.features) = ("W", "W", 6, uint256(1) << GovernanceBits.PAYABLE);
            c.legs = new IFactoryToken.Leg[](_sgN(1));
            for (uint256 i; i < c.legs.length; ++i) {
                c.legs[i] = IFactoryToken.Leg(crUnd[i], 1, 1);
            }
            bytes memory a = abi.encode(c);
            bytes32 d = _grD(T.UA_CREATE_TOKEN, t, abi.encode(uint8(1), uint64(1), keccak256(a), salt), e);
            return
                abi.encodeCall(
                    router.mtxCreateToken, (e, t, IOpenFactory.TokenKind.WRAPPED, 1, a, salt, _auth(grWho, d))
                );
        }
        if (crWhich == 1) {
            bytes memory a = abi.encode(ISCaaSDex.DexConfig(eoa, 0, TREASURY, false, 0, address(0), 0, 0));
            bytes32 d = _grD(T.UA_CREATE_DEX, t, abi.encode(uint64(1), keccak256(a), salt), e);
            return abi.encodeCall(router.mtxCreateDex, (e, t, 1, a, salt, _auth(grWho, d)));
        }
        bytes memory ic = abi.encodeCall(INoteKind.initialize, (eoa, "by router"));
        bytes32 di = _grD(T.UA_CREATE_INSTANCE, t, abi.encode(CLS, uint16(0), uint64(1), keccak256(ic), salt), e);
        return abi.encodeCall(router.mtxCreateInstance, (e, t, CLS, 0, 1, ic, salt, _auth(grWho, di)));
    }

    /// G2: the same sequence by derived identities (`_grUaRun`).
    function test_sdkGas_routerCreate_ua() public {
        _grUaRun();
        test_sdkGas_routerCreate();
    }

    function test_sdkGas_routerCreate() public {
        string[3] memory entry = ["mtxCreateToken", "mtxCreateDex", "mtxCreateInstance"];
        string[3] memory variant = ["normal", "dex", "note"];
        for (uint8 k; k < 3; ++k) {
            crWhich = k;
            grWho = eoa;
            _both("gov_router", entry[k], variant[k], address(router), eoa, _crBuild);
        }
        // K2: `TokenConfig.legs`, 1 to 8 (the kind's bound)
        (crWhich, grWho) = (3, eoa);
        _bothN("gov_router", "mtxCreateToken", "wrapped", address(router), eoa, _crBuild, _grCounts(true));
    }
}
