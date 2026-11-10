// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {dexArgs, kindArgs, deployKindModules} from "../../script/KindModules.sol";
import {envClosure} from "../helpers/ProbeModules.sol";

import {Test, Vm} from "forge-std/Test.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";
import {Create2Probe} from "../zether/ZetherDeploy.t.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceBase} from "../../src/governance/GovernanceBase.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {WrappedRegulatedToken} from "../../src/regulated/WrappedRegulatedToken.sol";
import {WrappedPqzRegulatedToken} from "../../src/regulated/WrappedPqzRegulatedToken.sol";
import {NormalPqzRegulatedToken} from "../../src/regulated/NormalPqzRegulatedToken.sol";
import {NormalZetherRegulatedToken} from "../../src/regulated/NormalZetherRegulatedToken.sol";
import {WrappedZetherRegulatedToken} from "../../src/regulated/WrappedZetherRegulatedToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {plainEnv, pinned, withModules, closureLibs, regArgs} from "../helpers/Catalogue.sol";
import {ComplianceRegistry} from "../../src/regulated/ComplianceRegistry.sol";
import {IComplianceRegistry} from "../../src/regulated/IComplianceRegistry.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {RegulatedLib} from "../../src/regulated/RegulatedLib.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {nid} from "../helpers/Ids.sol";
import {ZUID} from "../zether/helpers/ZetherFixture.sol";
import {ZetherDisclosure} from "../../src/zether/ZetherDisclosure.sol";
import {
    ZetherInnerProductVerifierBls12381,
    ZetherTransferVerifierBls12381,
    ZetherBurnVerifierBls12381
} from "../../src/zether/ZetherVerifier.sol";

/// @notice Plan T16 (CTR-GOV-19, GD-12; spec S0, S8, §12.10): every kind has a deploy path, the chain's `GovernanceRouter` is
///         deployed before the releases and gated, and every kind's release fits a 200 M block (the SCaaS testnet's,
///         NET-EVM-06), by the deploy gate's formula and by forge's EIP-8037 figures. Forge gas is deterministic: no calibration.
contract GovDeployTest is Test {
    uint256 constant BLOCK = 200_000_000;
    uint256 constant TX_GAS_CAP = 1 << 24;
    address ska = new SmartKeyAccountFactory(ZUID).IMPLEMENTATION();
    address[] zdeps; // the Zether kinds' env deps: transfer, burn, inner-product verifier, disclosure (CTR-ZTH-20)

    /// GD-12: `DEPLOY_WRAPPED` deploys the `WRAPPED` release (version 1, env 1, the kind's link closure pinned, on the UA
    /// registry and the router), gated by `chainUid()`, JSON `implementation_wrapped`; without it none.
    function test_deployWrappedPath() public {
        DeployHarness h = new DeployHarness();
        h.setWrapped(true);
        (OpenFactory f, string memory json) = h.deploy(ZUID, false, ska);
        address w = f.implementationOf(IOpenFactory.TokenKind.WRAPPED, 1);
        assertTrue(w.code.length != 0, "the release");
        assertEq(vm.parseJsonAddress(json, ".implementation_wrapped"), w);
        assertEq(WrappedToken(w).chainUid(), bytes32(0), "chain-neutral: a release carries no env");
        assertEq(f.chainUid(), ZUID, "the factory's, gated");
        assertTrue(f.kindEnabled(IOpenFactory.TokenKind.WRAPPED), "the kind is on from the factory's start");
        IFactoryToken.Env memory e = envClosure(f.envOf(IOpenFactory.TokenKind.WRAPPED, 1), w); // T66b: modules after it
        assertEq(keccak256(abi.encode(e.libs)), keccak256(abi.encode(closureLibs(IOpenFactory.TokenKind.WRAPPED))), "link closure");
        for (uint256 i; i < e.libs.length; ++i) assertEq(e.libCodeHashes[i], e.libs[i].codehash, "pinned");
        assertEq(e.registry, vm.parseJsonAddress(json, ".ua_registry"));
        assertEq(f.govRouter(), vm.parseJsonAddress(json, ".governance_router"), "the factory's router");
        assertEq(GovernanceBase(w).GOV_ROUTER(), address(0), "the release's: none (every clone's env names the factory's)");

        DeployHarness plain = new DeployHarness();
        (OpenFactory g,) = plain.deploy(ZUID, false, ska); // (the JSON object "deploy" is one per process: not read here)
        assertEq(g.latestEnvVersion(IOpenFactory.TokenKind.WRAPPED), 0, "the default deploys no WRAPPED");
        assertEq(g.implementationOf(IOpenFactory.TokenKind.WRAPPED, 1), address(0), "no WRAPPED release");
    }

    /// Plan T27 (regulated-kinds spec §6.1): `DEPLOY_REGULATED` deploys the regulated releases (version 1, env 1, the base
    /// kind's closure and `RegulatedLib` pinned, on the UA registry and the router), gated by `chainUid()`; plan T28: kind 8
    /// beside 9 (JSON `implementation_normal_regulated`, `implementation_wrapped_regulated`), both kinds enabled; without it
    /// none.
    function test_deployRegulatedPath() public {
        DeployHarness h = new DeployHarness();
        h.setRegulated(true);
        h.setComplianceAdmin(address(this)); // T33: the registry needs its admin
        (OpenFactory f, string memory json) = h.deploy(ZUID, false, ska);
        IOpenFactory.TokenKind[2] memory ks = [IOpenFactory.TokenKind.NORMAL_REGULATED, IOpenFactory.TokenKind.WRAPPED_REGULATED];
        string[2] memory keys = [".implementation_normal_regulated", ".implementation_wrapped_regulated"];
        for (uint256 i; i < 2; ++i) {
            IOpenFactory.TokenKind k = ks[i];
            address w = f.implementationOf(k, 1);
            assertEq(WrappedRegulatedToken(payable(w)).kind(), 8 + i, "the release");
            assertEq(vm.parseJsonAddress(json, keys[i]), w);
            assertEq(WrappedRegulatedToken(payable(w)).chainUid(), bytes32(0), "a release carries no env");
            assertTrue(f.kindEnabled(k), "enabled (T28)");
            assertEq(WrappedRegulatedToken(payable(w)).REGISTRY_CODEHASH(), keccak256(type(ComplianceRegistry).runtimeCode),
                "the registry code pin in implArgs (T29)");
            IFactoryToken.Env memory e = envClosure(f.envOf(k, 1), w); // T66b: the body modules after the closure
            assertEq(keccak256(abi.encode(e.libs)), keccak256(abi.encode(closureLibs(k))), "link closure");
            for (uint256 j; j < e.libs.length; ++j) assertEq(e.libCodeHashes[j], e.libs[j].codehash, "pinned");
            assertEq(e.registry, vm.parseJsonAddress(json, ".ua_registry"));
            assertEq(f.govRouter(), vm.parseJsonAddress(json, ".governance_router"));
        }

        DeployHarness plain = new DeployHarness();
        (OpenFactory g,) = plain.deploy(ZUID, false, ska);
        assertEq(g.implementationOf(ks[0], 1), address(0), "the default deploys no regulated release");
        assertEq(g.implementationOf(ks[1], 1), address(0), "the default deploys no regulated release");
        assertFalse(g.kindEnabled(ks[0]));
    }

    /// Plan 3c T92 (UA-7 D22, topics spec §11): `DEPLOY_PQCHAT` registers `PqChat` on the factory's generic path: the class
    /// env 1 of `(3, 0)` (the UA registry, `params[0]` the declared code limit), release 1 from the chain-neutral init code,
    /// the `(3, 0)` switch on, and with a notice period of 0 one instance owned by no UA (JSON `pqchat_implementation`,
    /// `pqchat_instance`), listed by `contractsPage(3, …)`; with a notice period the release waits and no instance is made;
    /// without the flag nothing of class 3.
    function test_deployPqChatPath() public {
        DeployHarness h = new DeployHarness();
        h.setPqChat(true);
        h.setNotice(0);
        (OpenFactory f, string memory json) = h.deploy(ZUID, false, ska);
        IOpenFactory.ReleaseId memory id = IOpenFactory.ReleaseId(3, 0, 1);
        IOpenFactory.ClassRelease memory r = f.classReleaseOf(id);
        assertEq(vm.parseJsonAddress(json, ".pqchat_implementation"), r.implementation);
        assertTrue(r.implementation.code.length != 0, "the release");
        assertEq(PqChat(r.implementation).owner(), bytes32(0), "an implementation: no owner");
        assertEq(r.initSelector, IPqChat.initialize.selector);
        assertEq(r.interfaceId, type(IPqChat).interfaceId);
        assertTrue(f.classKindEnabled(3, 0), "(3, 0) on");
        IFactoryToken.Env memory e = f.classEnvOf(3, 0, r.envVersion);
        assertEq(e.registry, vm.parseJsonAddress(json, ".ua_registry"));
        assertEq(uint256(e.params[0]), h.chainCodeLimit(), "params[0]: the declared code limit");
        address topics = vm.parseJsonAddress(json, ".pqchat_topics");
        assertEq(e.libs.length, 1);
        assertEq(e.libs[0], topics, "the body module pinned in libs (CTR-TOK-30, 3C-D2)");
        assertEq(e.libCodeHashes[0], topics.codehash);
        assertEq(PqChat(r.implementation).modules()[0], topics, "named in implArgs");
        address inst = vm.parseJsonAddress(json, ".pqchat_instance");
        assertEq(IPqChat(inst).owner(), bytes32(0), "owned by no UA");
        (IOpenFactory.Created[] memory page, uint256 total) = f.contractsPage(3, 0, 8);
        assertEq(total, 1);
        assertEq(page[0].addr, inst);

        DeployHarness late = new DeployHarness();
        late.setPqChat(true);
        late.setNotice(1 days);
        (OpenFactory g,) = late.deploy(ZUID, false, ska); // (the JSON object "deploy" is one per process: not read here)
        assertTrue(g.classReleaseOf(id).implementation != address(0), "the release, waiting for its notice period");
        (, total) = g.contractsPage(3, 0, 8);
        assertEq(total, 0, "no instance before the notice period");

        DeployHarness plain = new DeployHarness();
        (OpenFactory p,) = plain.deploy(ZUID, false, ska);
        assertEq(p.classReleaseOf(id).implementation, address(0), "the default registers no PqChat");
        assertFalse(p.classKindEnabled(3, 0));
    }

    /// Plan T30 (regulated-kinds spec §6.1): `DEPLOY_ZETHER` also deploys the regulated Zether releases 10 and 11 (version 1,
    /// env 1: the base kind's deps, its closure and `RegulatedLib` pinned, the UA registry and the router; `implArgs` the
    /// registry code pin), gated by `chainUid()`, both kinds enabled; JSON `implementation_{normal,wrapped}_zether_regulated_bls12381`.
    function test_deployZetherRegulatedPath() public {
        DeployHarness h = new DeployHarness();
        (OpenFactory f, string memory json) = h.deploy(ZUID, true, ska);
        IOpenFactory.TokenKind[2] memory ks =
            [IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED];
        string[2] memory keys =
            [".implementation_normal_zether_regulated_bls12381", ".implementation_wrapped_zether_regulated_bls12381"];
        for (uint256 i; i < 2; ++i) {
            IOpenFactory.TokenKind k = ks[i];
            address w = f.implementationOf(k, 1);
            assertTrue(w.code.length != 0, "the release");
            assertEq(NormalZetherRegulatedToken(w).kind(), 10 + i, "the release's kind");
            assertEq(vm.parseJsonAddress(json, keys[i]), w);
            assertEq(NormalZetherRegulatedToken(w).chainUid(), bytes32(0), "a release carries no env");
            assertTrue(f.kindEnabled(k), "enabled");
            assertEq(NormalZetherRegulatedToken(w).REGISTRY_CODEHASH(), keccak256(type(ComplianceRegistry).runtimeCode),
                "the registry code pin in implArgs");
            IFactoryToken.Env memory e = envClosure(f.envOf(k, 1), w); // T66b: each env's body modules after its closure
            IFactoryToken.Env memory b = envClosure(f.envOf(IOpenFactory.TokenKind(2 + i), 1),
                f.implementationOf(IOpenFactory.TokenKind(2 + i), 1));
            // the base kind's env libraries (DeployBase's order) and `RegulatedLib`: the closure as a set
            assertEq(e.libs.length, b.libs.length + 1, "link closure");
            for (uint256 j; j < b.libs.length; ++j) assertEq(e.libs[j], b.libs[j], "the base kind's closure");
            assertEq(e.libs[b.libs.length], address(RegulatedLib), "RegulatedLib");
            address[] memory want = closureLibs(k);
            for (uint256 j; j < want.length; ++j) {
                bool found;
                for (uint256 m; m < e.libs.length; ++m) found = found || e.libs[m] == want[j];
                assertTrue(found, "every library of the closure");
            }
            for (uint256 j; j < e.libs.length; ++j) assertEq(e.libCodeHashes[j], e.libs[j].codehash, "pinned");
            assertEq(keccak256(abi.encode(e.deps)), keccak256(abi.encode(b.deps)), "the base kind's verifiers and disclosure");
            assertEq(e.registry, vm.parseJsonAddress(json, ".ua_registry"));
            assertEq(f.govRouter(), vm.parseJsonAddress(json, ".governance_router"));
        }
        DeployHarness plain = new DeployHarness();
        (OpenFactory g,) = plain.deploy(ZUID, false, ska);
        assertEq(g.implementationOf(ks[0], 1), address(0), "no Zether stack, no regulated Zether release");
        assertFalse(g.kindEnabled(ks[1]));
    }

    /// Plan T33 (regulated-kinds spec §6.1): each regulated release published as its stack deploys it: 8, 9 by
    /// `DEPLOY_REGULATED`, 10, 11 by `DEPLOY_ZETHER` (`DeployBase`), 12, 13 as `script/pqz/e2e.py` does (its base PQZ kind's
    /// env with `RegulatedLib`, `implArgs` the registry pin; a forge EVM has no PQZ precompile, so a contract stands in for
    /// the verifier as in `_release`). Each: version 1 on env 1, its kind, gated, enabled, `RegulatedLib` in `Env.libs`
    /// with its code hash in `libCodeHashes`, the UA registry and the router of this deploy (T32's move), and a
    /// `REGISTRY_CODEHASH` equal to the code of the registry this deploy put up (`compliance_registry`).
    function test_regulatedReleasesPublished_8() public { _published(IOpenFactory.TokenKind.NORMAL_REGULATED); }

    function test_regulatedReleasesPublished_9() public { _published(IOpenFactory.TokenKind.WRAPPED_REGULATED); }

    function test_regulatedReleasesPublished_10() public { _published(IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED); }

    function test_regulatedReleasesPublished_11() public { _published(IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED); }

    function test_regulatedReleasesPublished_12() public { _published(IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED); }

    function test_regulatedReleasesPublished_13() public { _published(IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED); }

    function _published(IOpenFactory.TokenKind k) internal {
        DeployHarness h = new DeployHarness();
        h.setRegulated(true);
        h.setComplianceAdmin(address(this));
        uint8 b = uint8(k) - 8;
        (OpenFactory f, string memory json) = h.deploy(ZUID, b == 2 || b == 3, ska);
        address router = vm.parseJsonAddress(json, ".governance_router");
        address w;
        if (b < 4) {
            string[4] memory keys = [".implementation_normal_regulated", ".implementation_wrapped_regulated",
                ".implementation_normal_zether_regulated_bls12381", ".implementation_wrapped_zether_regulated_bls12381"];
            w = f.implementationOf(k, 1);
            assertEq(vm.parseJsonAddress(json, keys[b]), w, "the JSON key");
        } else { // e2e.py's steps: publishEnv(k, 1, base env + RegulatedLib), deployTokenImplementation(k, 1, 1, code, pin), enable
            IFactoryToken.Env memory e = pinned(plainEnv(address(f), address(0), ZUID, vm.parseJsonAddress(json, ".ua_registry"),
                false), k);
            e.deps = new address[](1);
            e.deps[0] = router; // the PQZ constructor checks code only
            bytes memory code = b == 4 ? type(NormalPqzRegulatedToken).creationCode : type(WrappedPqzRegulatedToken).creationCode;
            (address[] memory ms, bytes memory args) = deployKindModules(uint8(k), address(f), regArgs()); // T66b
            vm.startPrank(address(h));
            f.publishEnv(k, 1, withModules(e, ms));
            w = f.deployTokenImplementation(k, 1, 1, code, args);
            f.setKindEnabled(k, true);
            vm.stopPrank();
        }
        assertEq(NormalRegulatedToken(w).kind(), uint8(k), "the release's kind");
        assertEq(NormalRegulatedToken(w).chainUid(), bytes32(0), "a release carries no env");
        assertTrue(f.kindEnabled(k), "enabled");
        address creg = vm.parseJsonAddress(json, ".compliance_registry");
        assertEq(NormalRegulatedToken(w).REGISTRY_CODEHASH(), creg.codehash, "the pin = the deployed registry's code");
        IFactoryToken.Env memory env = envClosure(f.envOf(k, 1), w); // T66b: the body modules after the closure
        address[] memory want = closureLibs(k);
        assertEq(env.libs.length, want.length, "link closure");
        bool lib;
        for (uint256 j; j < env.libs.length; ++j) {
            assertEq(env.libCodeHashes[j], env.libs[j].codehash, "pinned");
            lib = lib || (env.libs[j] == address(RegulatedLib) && env.libCodeHashes[j] == address(RegulatedLib).codehash);
            bool found;
            for (uint256 m; m < want.length; ++m) found = found || want[m] == env.libs[j];
            assertTrue(found, "a library of the closure");
        }
        assertTrue(lib, "RegulatedLib in libs and libCodeHashes");
        assertEq(env.registry, vm.parseJsonAddress(json, ".ua_registry"));
        assertEq(f.govRouter(), router, "the factory's router = this deploy's");
        assertEq(GovernanceBase(w).GOV_ROUTER(), address(0), "a release carries no env");
    }

    /// Plan T33 (regulated-kinds spec §6.1, F-21; CTR-AS-07, CTR-AS-16): `DEPLOY_REGULATED` puts up one canonical
    /// `ComplianceRegistry` by CREATE2, its admin `COMPLIANCE_ADMIN` (a contract; none or an EOA refused by the registry's
    /// constructor), its code the regulated releases' pin; JSON `compliance_registry`, `compliance_registry_codehash`. The
    /// admin's `ELIGIBLE_CONTRACT` rows for a DEX venue (`createDex`) and its `DexPuller` let an `ALLOWLIST` token reach the
    /// venue, which it refuses before them.
    function test_registryDeployedAndDexAttested() public {
        DeployHarness h = new DeployHarness();
        h.setRegulated(true);
        h.setComplianceAdmin(address(this));
        (OpenFactory f, string memory json) = h.deploy(ZUID, false, ska);
        ComplianceRegistry r = ComplianceRegistry(vm.parseJsonAddress(json, ".compliance_registry"));
        bytes32 pin = keccak256(type(ComplianceRegistry).runtimeCode);
        assertEq(address(r).codehash, pin, "the canonical code");
        assertEq(vm.parseJsonBytes32(json, ".compliance_registry_codehash"), pin, "JSON codehash");
        assertEq(r.admin(), address(this), "COMPLIANCE_ADMIN");
        assertEq(address(r), vm.computeCreate2Address(keccak256("scaas.deploy.v1"),
            keccak256(abi.encodePacked(type(ComplianceRegistry).creationCode, abi.encode(address(this)))), address(h)), "CREATE2");

        address dex = f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(address(this)), 0, address(0x7EA5), false, 0, address(0))), "venue");
        address puller = SCaaSDex(dex).puller();
        address alice = address(0xA11CE);
        _attest(r, nid(alice), 1, type(uint64).max);
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.admin) = ("Reg", "REG", nid(address(0x0A11)));
        c.features = (1 << GovernanceBits.PAYABLE) | (1 << GovernanceBits.ALLOWLIST);
        (c.initialSupply, c.initialHolder) = (1000, alice);
        (c.reg.complianceRegistry, c.reg.requiredFlags, c.reg.termsHash) = (address(r), 1, keccak256("terms"));
        address t = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), "t");
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(dex), 0));
        IERC20(t).transfer(dex, 1);

        bytes32[] memory a = new bytes32[](2);
        uint64[] memory fl = new uint64[](2);
        uint64[] memory vu = new uint64[](2);
        (a[0], a[1], fl[0], fl[1], vu[0], vu[1]) = (nid(dex), nid(puller), 8, 8, type(uint64).max, type(uint64).max);
        r.attest(a, fl, vu); // the admin's call (this test is COMPLIANCE_ADMIN)
        for (uint256 i; i < 2; ++i) {
            (uint64 flags, uint64 until, uint32 id) = r.attestationOf(a[i]);
            assertEq(flags, 8, "ELIGIBLE_CONTRACT");
            assertEq(until, type(uint64).max);
            assertEq(id, 0, "an admin row");
            assertTrue(r.hasFlags(a[i], 1, 0), "eligible for any requiredFlags");
        }
        vm.prank(alice);
        IERC20(t).transfer(dex, 1);
        assertEq(IERC20(t).balanceOf(dex), 1, "the venue receives");

        DeployHarness none = new DeployHarness();
        none.setRegulated(true);
        vm.expectRevert(abi.encodeWithSelector(IComplianceRegistry.AdminNotContract.selector, address(0)));
        none.deploy(ZUID, false, ska);
        none.setComplianceAdmin(address(0xE0A));
        vm.expectRevert(abi.encodeWithSelector(IComplianceRegistry.AdminNotContract.selector, address(0xE0A)));
        none.deploy(ZUID, false, ska);
    }

    function _attest(ComplianceRegistry r, bytes32 account, uint64 flags, uint64 until) internal {
        bytes32[] memory a = new bytes32[](1);
        uint64[] memory fl = new uint64[](1);
        uint64[] memory vu = new uint64[](1);
        (a[0], fl[0], vu[0]) = (account, flags, until);
        r.attest(a, fl, vu);
    }

    /// The `WRAPPED` release is gated as every release (NET-EVM-06, GD-4): one gas below its own need, by name, and nothing of
    /// the release sent; the releases before it (NORMAL, the DEX) pass that limit.
    function test_wrappedReleaseIsGated() public {
        DeployHarness h = new DeployHarness();
        h.setWrapped(true);
        uint256 need = h.gasNeed("WrappedToken");
        // T66b: the release (17,808 B) now needs less than the UA registry before it, so a deploy at `need - 1` stops at the
        // registry's gate first; the WRAPPED release's own gate is checked by name
        vm.expectRevert(bytes(string.concat("block gas limit ", vm.toString(need - 1), " < ", vm.toString(need),
            " needed to deploy the WrappedToken release (NET-EVM-06)")));
        h.checkGas("WrappedToken", need - 1);
        h.checkGas("WrappedToken", need);
        h.limitBlockGas(need - 1);
        vm.expectRevert(); // nothing of the release is sent: the deploy refuses before it
        h.deploy(ZUID, false, ska);
        h.limitBlockGas(0);
        // ua-mtx-merge T1: `size-baseline.json`'s WrappedToken row 52,297 -> 51,436 B, so the control moves with it;
        // T2: 51,436 -> 46,804 B; T3: 46,804 -> 45,140 B; T6: 45,140 -> 42,669 B; T24: 42,669 -> 42,985 B;
        // T25: 42,985 -> 43,333 B; T26: 43,333 -> 43,552 B; pay-meta-tax T37: 43,552 -> 43,667 B; T38: 43,667 -> 43,714 B;
        // T39: 43,714 -> 43,711 B; T40: 43,711 -> 43,503 B (lever 5: `_payMeta` in `MtxPipelineLib`); chain-neutral T72:
        // 43,503 -> 44,456 B (the env read from the clone's code, `chainEnv`, `validateEnv`); 3f T44: 44,456 -> 44,610 B (the
        // three PQZ verifier fields refused by `_requireUnused`); 3h T60: 44,610 -> 44,635 B (`proofStore` refused there too);
        // T83: 44,635 -> 45,522 B (the pay records' views and `_payRecord`, the v3 `PayMeta` tuple); T66b (the body
        // modules): 45,522 -> 17,808 B, under the registry's 28,165, so the code limit is checked on the release by name;
        // group 3l: 17,808 -> 19,366 B (the five wrap-limit stubs); merge3k (+ ua-mtx-liquidity's `mtxLiquidityPull` stub):
        // 19,366 -> 19,532 B
        h.limitCode(19_531);
        vm.expectRevert(bytes("WrappedToken runtime 19532 B > chain code limit 19531 B (CHAIN_CODE_LIMIT, CTR-GOV-19)"));
        h.requireGas("WrappedToken");
    }

    /// Spec S8, §3.1: one `GovernanceRouter` per chain, CREATE2 before every release, gated by `chainUid()`, named by every
    /// release env and every release's `GOV_ROUTER`.
    function test_routerDeployedAndGated() public {
        DeployHarness h = new DeployHarness();
        h.setWrapped(true);
        (OpenFactory f, string memory json) = h.deploy(ZUID, true, ska);
        address r = vm.parseJsonAddress(json, ".governance_router");
        assertTrue(r.code.length != 0);
        assertEq(GovernanceRouter(r).chainUid(), ZUID, "gated");
        assertEq(address(GovernanceRouter(r).registry()), vm.parseJsonAddress(json, ".ua_registry"));
        for (uint8 k; k <= 3; ++k) {
            IOpenFactory.TokenKind kind = IOpenFactory.TokenKind(k);
            assertEq(GovernanceBase(f.implementationOf(kind, 1)).GOV_ROUTER(), address(0), "a release carries no env");
        }
        assertEq(f.govRouter(), r, "the factory's router: every clone's env");
        assertEq(GovernanceBase(vm.parseJsonAddress(json, ".dex_implementation")).GOV_ROUTER(), address(0), "DEX release");
    }

    /// NET-EVM-06, C5-1: the deploy gate's need, `runtime x 1,530 + 2^24` from `size-baseline.json`, fits 200 M for every
    /// release (the six kinds, the DEX); one gas below the need is refused by name (the control).
    function test_everyKindsReleaseFitsTwoHundredMillion() public {
        DeployHarness h = new DeployHarness();
        string[13] memory kinds = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "NormalPqzToken",
            "WrappedPqzToken", "SCaaSDex", "NormalRegulatedToken", "WrappedRegulatedToken", "WrappedPqzRegulatedToken",
            "NormalZetherRegulatedToken", "WrappedZetherRegulatedToken", "NormalPqzRegulatedToken"];
        for (uint256 i; i < kinds.length; ++i) {
            uint256 need = h.gasNeed(kinds[i]);
            assertEq(need, vm.parseJsonUint(vm.readFile("./size-baseline.json"), string.concat(".", kinds[i])) * 1530 + TX_GAS_CAP,
                kinds[i]);
            h.checkGas(kinds[i], BLOCK);
            emit log_named_uint(string.concat(kinds[i], " deploy gate need"), need);
            vm.expectRevert(bytes(string.concat("block gas limit ", vm.toString(need - 1), " < ", vm.toString(need),
                " needed to deploy the ", kinds[i], " release (NET-EVM-06)")));
            h.checkGas(kinds[i], need - 1);
        }
    }

    /// The release figures (plan T16): each kind's creation as one transaction (`Create2Probe`, `isolate`): regular gas
    /// (x 64/63 for the probe's call), EIP-8037 state gas, the total and x 1.05 (`--gas-estimate-multiplier 105`) against a
    /// 200 M block; regular under 2^24 (EIP-7825). Printed for runs/2026-11-03-governance-deploy-gas.txt.
    function test_releaseGasPerKind() public {
        address router = address(new GovernanceRouter(ZUID, address(this), ska, false));
        ZetherInnerProductVerifierBls12381 ip = new ZetherInnerProductVerifierBls12381();
        zdeps = [address(new ZetherTransferVerifierBls12381(ip)), address(new ZetherBurnVerifierBls12381(ip)), address(ip),
            address(new ZetherDisclosure())];
        Create2Probe probe = new Create2Probe();
        string[15] memory names = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "NormalPqzToken",
            "WrappedPqzToken", "SCaaSDex", "GovernanceRouter", "WrappedRegulatedToken", "WrappedPqzRegulatedToken",
            "NormalRegulatedToken", "ComplianceRegistry", "NormalZetherRegulatedToken", "WrappedZetherRegulatedToken",
            "NormalPqzRegulatedToken"];
        bytes[15] memory codes = [
            _release(type(NormalToken).creationCode, IOpenFactory.TokenKind.NORMAL, router),
            _release(type(WrappedToken).creationCode, IOpenFactory.TokenKind.WRAPPED, router),
            _release(type(NormalZetherToken).creationCode, IOpenFactory.TokenKind.NORMAL_ZETHER, router),
            _release(type(WrappedZetherToken).creationCode, IOpenFactory.TokenKind.WRAPPED_ZETHER, router),
            _release(type(NormalPqzToken).creationCode, IOpenFactory.TokenKind.NORMAL_PQZ, router),
            _release(type(WrappedPqzToken).creationCode, IOpenFactory.TokenKind.WRAPPED_PQZ, router),
            _dex(router),
            abi.encodePacked(type(GovernanceRouter).creationCode, abi.encode(ZUID, address(this), ska, false)),
            _release(type(WrappedRegulatedToken).creationCode, IOpenFactory.TokenKind.WRAPPED_REGULATED, router),
            _release(type(WrappedPqzRegulatedToken).creationCode, IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, router),
            _release(type(NormalRegulatedToken).creationCode, IOpenFactory.TokenKind.NORMAL_REGULATED, router),
            abi.encodePacked(type(ComplianceRegistry).creationCode, abi.encode(router)), // T29: a plain deploy, admin a contract
            _release(type(NormalZetherRegulatedToken).creationCode, IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, router), // T30
            _release(type(WrappedZetherRegulatedToken).creationCode, IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED, router),
            _release(type(NormalPqzRegulatedToken).creationCode, IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, router) // T31
        ];
        for (uint256 i; i < codes.length; ++i) {
            address a = probe.deploy(codes[i], bytes32(i));
            Vm.Gas memory g = vm.lastCallGas();
            assertTrue(a != address(0), names[i]);
            uint256 regular = g.gasTotalUsed * 64 / 63;
            uint256 state = uint256(int256(g.gasStateUsed));
            uint256 total = regular + state;
            emit log(string.concat("RELEASE | ", names[i], " | runtime ", vm.toString(a.code.length), " B | init ",
                vm.toString(codes[i].length), " B | regular ", vm.toString(regular), " | state ", vm.toString(state), " | total ",
                vm.toString(total), " | x1.05 ", vm.toString(total * 105 / 100), total * 105 / 100 <= BLOCK ? " | fits 200 M" : " | does not fit 200 M"));
            assertLt(regular * 105 / 100, TX_GAS_CAP, string.concat(names[i], ": regular gas over 2^24"));
            assertLe(total * 105 / 100, BLOCK, string.concat(names[i], ": over a 200 M block"));
        }
    }

    /// Q4 (CTR-MTX-30, R40), ua-mtx-merge T10: a chain that declares the public gate (`RELEASE_GAS_GATE=public`) gates each
    /// release on its own transaction, measured: (regular x 64/63 + EIP-8037 state) x 1.05 within the block gas limit, not
    /// `runtime x 1,530 + 2^24`. One gas below the first release's ask is refused by name before it is sent; at the largest
    /// ask the deploy goes through, below every token release's testnet formula. (Here the releases are calls inside the
    /// harness, so the figures leave out the intrinsic gas a real transaction adds; under `forge script` each is its own
    /// transaction.)
    function test_publicGateUsesMeasuredReleaseGas() public {
        // the rule itself: (regular + state) x 1.05, never max(regular, state) (a block's gas_used, EIP-8037)
        DeployHarness h = new DeployHarness();
        h.checkMeasured("X", 1_000_000, 50_000_000, 53_550_000);
        vm.expectRevert(bytes("block gas limit 53549999 < 53550000 asked by the X release (measured regular + state x 1.05, NET-EVM-06)"));
        h.checkMeasured("X", 1_000_000, 50_000_000, 53_549_999);

        h.setGate(2);
        h.setWrapped(true);
        h.limitBlockGas(type(uint64).max);
        (OpenFactory f,) = h.deploy(ZUID, false, ska);
        string[6] memory names = ["UARegistry", "UARegistryCoreLib", "UARegistryAuxLib", "NormalToken", "SCaaSDex", "WrappedToken"];
        uint256 most;
        for (uint256 i; i < names.length; ++i) {
            (uint256 regular, uint256 state) = h.measured(names[i]);
            uint256 asked = (regular + state) * 105 / 100;
            emit log(string.concat("PUBLIC GATE | ", names[i], " | regular ", vm.toString(regular), " | state ",
                vm.toString(state), " | asked ", vm.toString(asked), " | testnet formula ", vm.toString(h.gasNeed(names[i]))));
            assertGt(regular, 0, names[i]);
            assertLt(asked, h.gasNeed(names[i]), string.concat(names[i], ": below the testnet formula"));
            if (asked > most) most = asked;
        }
        (, uint256 st) = h.measured("NormalToken");
        assertGe(st, f.implementationOf(IOpenFactory.TokenKind.NORMAL, 1).code.length * 1530, "the code deposit is in it");

        (uint256 r0, uint256 s0) = h.measured("UARegistry");
        uint256 first = (r0 + s0) * 105 / 100;
        DeployHarness g = new DeployHarness();
        g.setGate(2);
        g.setWrapped(true);
        g.limitBlockGas(first - 1);
        vm.expectRevert(bytes(string.concat("block gas limit ", vm.toString(first - 1), " < ", vm.toString(first),
            " asked by the UARegistry release (measured regular + state x 1.05, NET-EVM-06)")));
        g.deploy(ZUID, false, ska);
        g.limitBlockGas(most);
        (OpenFactory gf,) = g.deploy(ZUID, false, ska);
        assertTrue(gf.implementationOf(IOpenFactory.TokenKind.WRAPPED, 1).code.length != 0, "at the largest ask: deployed");
        // T66b: the token releases fell under the public asks (WrappedToken's formula 86.4 M -> 44.0 M); the UA registry keeps
        // the illustration
        assertLt(most, h.gasNeed("UARegistry"), "a limit at which the testnet gate refuses the UARegistry release");
    }

    /// Q4: the public gate also refuses a release whose regular gas x 1.05 reaches 2^24 (EIP-7825), whatever the block
    /// gas limit; one gas under passes.
    function test_publicGateRefusesRegularOver2pow24() public {
        DeployHarness h = new DeployHarness();
        vm.expectRevert(bytes("X release: regular gas x 1.05 = 16777216 >= 2^24 (EIP-7825, NET-EVM-06)"));
        h.checkMeasured("X", 15_978_301, 0, type(uint256).max);
        h.checkMeasured("X", 15_978_300, 0, type(uint256).max);
    }

    /// Q4: the SCaaS testnet keeps the owner's formula, `runtime x 1,530 + 2^24`, and it is the default when nothing is
    /// declared; it measures nothing and refuses by the formula, by name, before anything is sent.
    function test_testnetGateFormulaUnchanged() public {
        DeployHarness h = new DeployHarness();
        assertFalse(h.publicGate(), "the default is the testnet gate");
        h.setGate(1);
        string memory base = vm.readFile("./size-baseline.json");
        string[10] memory names = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "NormalPqzToken",
            "WrappedPqzToken", "SCaaSDex", "UARegistry", "UARegistryCoreLib", "UARegistryAuxLib"];
        for (uint256 i; i < names.length; ++i) {
            assertEq(h.gasNeed(names[i]), vm.parseJsonUint(base, string.concat(".", names[i])) * 1530 + TX_GAS_CAP, names[i]);
        }
        uint256 need = h.gasNeed("UARegistry");
        h.limitBlockGas(need - 1);
        vm.expectRevert(bytes(string.concat("block gas limit ", vm.toString(need - 1), " < ", vm.toString(need),
            " needed to deploy the UARegistry release (NET-EVM-06)")));
        h.deploy(ZUID, false, ska);
        h.limitBlockGas(type(uint64).max);
        h.deploy(ZUID, false, ska);
        (uint256 regular, uint256 state) = h.measured("NormalToken");
        assertEq(regular + state, 0, "nothing measured");
    }

    /// Plan T10 (T2 and T7 moved the bytecode): `RelayFeeRouter` (no constructor argument: one address on every chain) and the
    /// `GovernanceRouter` (here on the SCaaS testnet's reset-1 inputs: chain_uid, registry, `SmartKeyAccount`
    /// implementation, not Hedera) at their deploy CREATE2 addresses (the deterministic deployer, the default
    /// `DEPLOY_SALT`), not the reset-1 ones (that reset's book `7622.json`, which `node.example.toml`'s `governance_routers`
    /// names): a deploy of this tree lists the new ones.
    function test_routerAndRelayFeeRouterNewAddresses() public pure {
        bytes32 deploySalt = keccak256("scaas.deploy.v1");
        address deployer = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
        address rf = vm.computeCreate2Address(deploySalt, keccak256(type(RelayFeeRouter).creationCode), deployer);
        address router = vm.computeCreate2Address(deploySalt, keccak256(abi.encodePacked(type(GovernanceRouter).creationCode,
            abi.encode(bytes32(0xf1f491abec46eb7c1784b7fc75a0174171b41831530e510c46b7178c02d63164),
                address(0x838b5D28fbc07844a070818012A8a68980688C26), address(0x428C6e1Cad562Dc16b2bf19515B9b08dD0361e8f), false))),
            deployer);
        assertTrue(rf != 0xD5D8d5e1cD81f1E83C5B6c1a4Fd9AcfF02d89BB2, "not reset 1's RelayFeeRouter");
        assertTrue(router != 0xB64D2D5f27D2d5eA951409773343D856e41Fb8E0, "not reset 1's GovernanceRouter");
        // pay-meta-tax T37: 0xaf843Ac33a5A73A2baf3E979F922Bd3c1feD6B43 -> 0x616AEe61C11e53a1a5104d448eba7574e5AE2a8b (the
        // metadata hash: `MetaTxLib` gains `PayMeta`); T38: -> 0xa615f3672E60a2e91F92463bB4Df8b4374245C8A (`relay` with
        // `batch`, `nonce`); 3g T51: 0xF1D87045dAef620300637Ed6DE7123B42f23f9aB (the metadata hash: `IUARegistry`'s versioned PQZ
        // key records); T66a item 1: -> this (the metadata hash: `IUARegistry.requirePortable`)
        // T66a item 2 (the metadata hash: IUARegistry's KEM holder docs): 0xC9C1aC557303551b16d78DBce193f02e414CAA39 -> this
        // T66a item 5 (the metadata hash: IUARegistry.popSlotsOf): 0x3d0DB1d457Ac07B199e8Bd65676AFF7fF127330E ->
        // 0x8B56809BBf5f6595351F648a499E194292B6100C; T82 (the metadata hash: the contract's new name and file, owner
        // 2026-11-09): -> 0x6e5ADaD0b26E45d76250564dC569D2C05a082762; T83 (the metadata hash: `MetaTxLib.PayMeta` v3 and
        // `PayRecord`, owner 2026-11-09): -> 0x70ba50D63EC511e4a39bf34d8EE01F3e85D3cEaC; T66b (the metadata hash: the
        // T66b sources it imports, the `IERC20MetaTx` comment of f0c03715 among them; its code unchanged): -> this
        assertEq(rf, 0xd981282EC3f2F979B953BDE7c7c3c4100caDfe89, "RelayFeeRouter");
        // ua-mtx-merge T24: 0x2AEfB2af419765600eC00a7D0CfC4dE30f2d3750 -> 0xAb151Df7DC7CbbD9755028a27Ad0bc55a34b5b53 (the
        // router's metadata hash: `IGovernance`); T26: -> this (the two empty hooks `UAMetaTxBase` adds, its
        // `mtxCancelNonce` seats); T32: 0xBc8Df1a828dA586e5ccB8Db8942bbCC9c130cC34 -> this (the eight regulated control ops)
        // pay-meta-tax T37: 0xb7a8E5b24F6822cba41f77A6c4CdeEDAfA9399F1 -> 0xd2EaEC2593D30e536d3E0900008f66dc67A2B032 (the
        // metadata hash: `MetaTxLib.PayMeta`); T38: -> 0x2BEc911FA998177Eb0a56B94Fd4Dc5e5dae7e819 (the metadata hash:
        // `IERC20MetaTx.mtxRelayFee`); T39: -> 0xe6D87D56A2aB446F60Ec89CF75D9ab33f443C8B2 (`mtxSetTaxRate`,
        // `mtxSetTaxRecipient`); T40: -> this (the metadata hash: `IRegulatedToken`'s two tax entries; `MtxPipelineLib`'s
        // levers 5 and 6); 3g T51: 0x9F9448a2e031D1d7055c7D7b6593EA8f752c7D91 -> 0x8C7beC80b3bD61A2920083C0617555a87A5fa7E5
        // (the metadata hash: `IUARegistry`); chain-neutral T72: -> this (the metadata hash: `SaltedEIP712`'s virtual
        // domain, `UAMetaTxBase`'s immutables behind `_registry()` / `_hedera()`) 0x77826623be224e298A4Ad0edd07b520e342523A2;
        // T76: 0x773A627eD1C1CCF588DCB81799c1BFB52E5d9d57 (the router's three creation ops, S3); 3f T45: -> this (the
        // three PQZ verifier ops `mtxPqz{Set,Cancel,Revoke}Verifier`): 0x5A6E6681A1Ec31741438D863ffCC138C186FB933; T66a item 1: -> this
        // (the metadata hash: `IUARegistry.requirePortable`)
        // T66a item 2 (the metadata hash: IUARegistry's KEM holder docs): 0x0240966987610aC882D8501247EF3Ce2AC2c477B -> this
        // T66a item 5 (the metadata hash: IUARegistry.popSlotsOf): 0xbf24455f26b2cB0a343fc47a546Fd68F4b5CAEAD -> 0x3A893f1938bA3E34339D3d4b85CC13a5983A7149
        // 3h T58 (the metadata hash: IPqzToken's debit record view and `lastDebit`): -> 0x942f489e2f453AaEd2Be4B3DFb8b5dA441Fa6BdA
        // 3h T59 (the metadata hash: IPqzToken's args with `ownTag`; found by T60's suite): -> 0xA4Ab7e0673548a32B96d7164b6e81B9D6Ce29C4b
        // 3h T60 (the metadata hash: `proofStore`'s error, event and view; `ConfidentialConfig.proofStore`): ->
        // 0xB95B3fA6EDD80605484A95ffBa63B6e2e873C0C6; T61 (`mtxSetProofStore`, bit 24): -> 0x8D4632FcCd353fb46400D356B79A7171eE44d2d0;
        // T83 (the metadata hash: `IMetaTokenV2`'s pay-record views, `PaymentMeta` v3): -> 0x7d3C8bE73d8840bA378F83D8Ac1297080ceaCc03
        // T66b 3.1b (the metadata hash: `UAKinds` / `UAStore` comments naming `UARegistryCoreLib`): ->
        // 0x13CBB3D5DCb0736f87F136ad13276568A80d1aa9; T66b 4.1 (the `<X>Core` + flat-face split of `GovernanceRouterBase`,
        // 15,305 -> 15,572 B runtime): -> 0x639e34f93Ac69d6Ba31D773AC915894542180723; the factory's release entries renamed
        // (owner 2026-11-10; the metadata hash: `IOpenFactory`'s `deployTokenImplementation` / `deployImplementation`, its
        // code unchanged): -> 0x9084894b49299A2b1DFdB271e2C5Fd8D4f9bA904; group 3l (`mtxSetWrapLimits`, `mtxSetWrapMember`,
        // their typehashes; 0x7F3b13D20e51EA69BBEeF32394a76db36013FEE3 on its branch), merged (merge3k): ->
        // 0x1b8ae68e34f2710b8ba48b33fD53942F3b1a47A0; group 3p (owner 2026-11-10, CTR-UA-41; the metadata hash: the comment of
        // `IFactoryToken` naming `PqzKeyVerifier`, was `UAPqzVerifier`): -> 0xe3E535A28d5aBCa856dE18bdc46AaD334ab71f42; the
        // directories renamed (owner 2026-11-10; the metadata hash: `UAMetaTxBase`'s comment names script/modules/gen_faces.py,
        // was script/t66b/): -> this
        assertEq(router, 0xb0E39bCa5EA2C70840e28Ba356606f607F54a1D3, "GovernanceRouter");
    }

    /// A kind's init code with the factory's append: chain-neutral releases (plan T72), `abi.encode(factory, implArgs)`;
    /// the env is the clones', not in the release's code.
    function _release(bytes memory code, IOpenFactory.TokenKind kind, address) internal returns (bytes memory) {
        // T29; T66b: the kind's body modules, deployed for this factory (their own transactions, not in these figures)
        return abi.encodePacked(code, abi.encode(address(this),
            kindArgs(uint8(kind), address(this), uint8(kind) >= 8 ? regArgs() : bytes(""))));
    }

    function _dex(address) internal returns (bytes memory) {
        return abi.encodePacked(type(SCaaSDex).creationCode, abi.encode(address(this), dexArgs(address(this))));
    }
}
