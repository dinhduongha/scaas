// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

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
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {MtxRelayFee} from "../../src/metatx/MtxRelayFee.sol";
import {plainEnv, pinned, closureLibs} from "../helpers/Catalogue.sol";
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
        assertEq(WrappedToken(w).chainUid(), ZUID, "gated");
        assertTrue(f.kindEnabled(IOpenFactory.TokenKind.WRAPPED), "the kind is on from the factory's start");
        IFactoryToken.Env memory e = f.envOf(IOpenFactory.TokenKind.WRAPPED, 1);
        assertEq(keccak256(abi.encode(e.libs)), keccak256(abi.encode(closureLibs(IOpenFactory.TokenKind.WRAPPED))), "link closure");
        for (uint256 i; i < e.libs.length; ++i) assertEq(e.libCodeHashes[i], e.libs[i].codehash, "pinned");
        assertEq(e.registry, vm.parseJsonAddress(json, ".ua_registry"));
        assertEq(e.govRouter, vm.parseJsonAddress(json, ".governance_router"));
        assertEq(GovernanceBase(w).GOV_ROUTER(), e.govRouter);

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
        (OpenFactory f, string memory json) = h.deploy(ZUID, false, ska);
        IOpenFactory.TokenKind[2] memory ks = [IOpenFactory.TokenKind.NORMAL_REGULATED, IOpenFactory.TokenKind.WRAPPED_REGULATED];
        string[2] memory keys = [".implementation_normal_regulated", ".implementation_wrapped_regulated"];
        for (uint256 i; i < 2; ++i) {
            IOpenFactory.TokenKind k = ks[i];
            address w = f.implementationOf(k, 1);
            assertEq(WrappedRegulatedToken(payable(w)).kind(), 8 + i, "the release");
            assertEq(vm.parseJsonAddress(json, keys[i]), w);
            assertEq(WrappedRegulatedToken(payable(w)).chainUid(), ZUID, "gated");
            assertTrue(f.kindEnabled(k), "enabled (T28)");
            IFactoryToken.Env memory e = f.envOf(k, 1);
            assertEq(keccak256(abi.encode(e.libs)), keccak256(abi.encode(closureLibs(k))), "link closure");
            for (uint256 j; j < e.libs.length; ++j) assertEq(e.libCodeHashes[j], e.libs[j].codehash, "pinned");
            assertEq(e.registry, vm.parseJsonAddress(json, ".ua_registry"));
            assertEq(e.govRouter, vm.parseJsonAddress(json, ".governance_router"));
        }

        DeployHarness plain = new DeployHarness();
        (OpenFactory g,) = plain.deploy(ZUID, false, ska);
        assertEq(g.implementationOf(ks[0], 1), address(0), "the default deploys no regulated release");
        assertEq(g.implementationOf(ks[1], 1), address(0), "the default deploys no regulated release");
        assertFalse(g.kindEnabled(ks[0]));
    }

    /// The `WRAPPED` release is gated as every release (NET-EVM-06, GD-4): one gas below its own need, by name, and nothing of
    /// the release sent; the releases before it (NORMAL, the DEX) pass that limit.
    function test_wrappedReleaseIsGated() public {
        DeployHarness h = new DeployHarness();
        h.setWrapped(true);
        uint256 need = h.gasNeed("WrappedToken");
        h.limitBlockGas(need - 1);
        vm.expectRevert(bytes(string.concat("block gas limit ", vm.toString(need - 1), " < ", vm.toString(need),
            " needed to deploy the WrappedToken release (NET-EVM-06)")));
        h.deploy(ZUID, false, ska);
        h.limitBlockGas(0);
        // ua-mtx-merge T1: `size-baseline.json`'s WrappedToken row 52,297 -> 51,436 B, so the control moves with it;
        // T2: 51,436 -> 46,804 B; T3: 46,804 -> 45,140 B; T6: 45,140 -> 42,669 B; T24: 42,669 -> 42,985 B;
        // T25: 42,985 -> 43,333 B; T26: 43,333 -> 43,552 B
        h.limitCode(43_551);
        vm.expectRevert(bytes("WrappedToken runtime 43552 B > chain code limit 43551 B (CHAIN_CODE_LIMIT, CTR-GOV-19)"));
        h.deploy(ZUID, false, ska);
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
            assertEq(f.envOf(kind, 1).govRouter, r, "env");
            assertEq(GovernanceBase(f.implementationOf(kind, 1)).GOV_ROUTER(), r, "release");
        }
        assertEq(f.dexEnvOf(1).govRouter, r, "DEX env");
        assertEq(GovernanceBase(vm.parseJsonAddress(json, ".dex_implementation")).GOV_ROUTER(), r, "DEX release");
    }

    /// NET-EVM-06, C5-1: the deploy gate's need, `runtime x 1,530 + 2^24` from `size-baseline.json`, fits 200 M for every
    /// release (the six kinds, the DEX); one gas below the need is refused by name (the control).
    function test_everyKindsReleaseFitsTwoHundredMillion() public {
        DeployHarness h = new DeployHarness();
        string[10] memory kinds = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "NormalPqzToken",
            "WrappedPqzToken", "SCaaSDex", "NormalRegulatedToken", "WrappedRegulatedToken", "WrappedPqzRegulatedToken"];
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
        string[11] memory names = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "NormalPqzToken",
            "WrappedPqzToken", "SCaaSDex", "GovernanceRouter", "WrappedRegulatedToken", "WrappedPqzRegulatedToken",
            "NormalRegulatedToken"];
        bytes[11] memory codes = [
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
            _release(type(NormalRegulatedToken).creationCode, IOpenFactory.TokenKind.NORMAL_REGULATED, router)
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
        string[5] memory names = ["UARegistry", "UARegistryLib", "NormalToken", "SCaaSDex", "WrappedToken"];
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
        assertLt(most, h.gasNeed("WrappedToken"), "a limit at which the testnet gate refuses the WrappedToken release");
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
        string[9] memory names = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "NormalPqzToken",
            "WrappedPqzToken", "SCaaSDex", "UARegistry", "UARegistryLib"];
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

    /// Plan T10 (T2 and T7 moved the bytecode): `MtxRelayFee` (no constructor argument: one address on every chain) and the
    /// `GovernanceRouter` (here on the SCaaS testnet's reset-1 inputs: chain_uid, registry, `SmartKeyAccount`
    /// implementation, not Hedera) at their deploy CREATE2 addresses (the deterministic deployer, the default
    /// `DEPLOY_SALT`), not the reset-1 ones (`deployments/7622.json`, which `node.example.toml`'s `governance_routers`
    /// names): a deploy of this tree lists the new ones.
    function test_routerAndRelayFeeNewAddresses() public pure {
        bytes32 deploySalt = keccak256("scaas.deploy.v1");
        address deployer = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
        address rf = vm.computeCreate2Address(deploySalt, keccak256(type(MtxRelayFee).creationCode), deployer);
        address router = vm.computeCreate2Address(deploySalt, keccak256(abi.encodePacked(type(GovernanceRouter).creationCode,
            abi.encode(bytes32(0xf1f491abec46eb7c1784b7fc75a0174171b41831530e510c46b7178c02d63164),
                address(0x838b5D28fbc07844a070818012A8a68980688C26), address(0x428C6e1Cad562Dc16b2bf19515B9b08dD0361e8f), false))),
            deployer);
        assertTrue(rf != 0xD5D8d5e1cD81f1E83C5B6c1a4Fd9AcfF02d89BB2, "not reset 1's MtxRelayFee");
        assertTrue(router != 0xB64D2D5f27D2d5eA951409773343D856e41Fb8E0, "not reset 1's GovernanceRouter");
        assertEq(rf, 0xaf843Ac33a5A73A2baf3E979F922Bd3c1feD6B43, "MtxRelayFee");
        // ua-mtx-merge T24: 0x2AEfB2af419765600eC00a7D0CfC4dE30f2d3750 -> 0xAb151Df7DC7CbbD9755028a27Ad0bc55a34b5b53 (the
        // router's metadata hash: `IGovernance`); T26: -> this (the two empty hooks `UAMetaTxBase` adds, its
        // `mtxCancelNonce` seats)
        assertEq(router, 0xBc8Df1a828dA586e5ccB8Db8942bbCC9c130cC34, "GovernanceRouter");
    }

    /// A kind's init code with the factory's append, `abi.encode(envVersion, env, implArgs)`: the env names the real Zether
    /// verifiers, a contract for the PQZ verifier, the kind's link closure and the router.
    function _release(bytes memory code, IOpenFactory.TokenKind kind, address router) internal view returns (bytes memory) {
        IFactoryToken.Env memory e = pinned(plainEnv(address(this), ska, ZUID, address(this), false), kind);
        e.govRouter = router;
        uint8 b = uint8(kind) >= 8 ? uint8(kind) - 8 : uint8(kind); // a regulated kind's env is its base kind's (T27)
        if (b >= 2) e.smartKeyAccountImpl = address(0);
        if (b == 2 || b == 3) e.deps = zdeps;
        if (b >= 4) {
            e.deps = new address[](1);
            e.deps[0] = router; // any contract: the PQZ constructor checks code only (the verifier needs the chain's precompile)
        }
        return abi.encodePacked(code, abi.encode(uint16(1), e, bytes("")));
    }

    function _dex(address router) internal view returns (bytes memory) {
        IFactoryToken.Env memory e = plainEnv(address(this), ska, ZUID, address(0), false);
        e.libs = new address[](2);
        (e.libs[0], e.libs[1]) = (address(GovernanceLib), address(TradeLib));
        e.libCodeHashes = new bytes32[](2);
        (e.libCodeHashes[0], e.libCodeHashes[1]) = (address(GovernanceLib).codehash, address(TradeLib).codehash);
        e.govRouter = router;
        return abi.encodePacked(type(SCaaSDex).creationCode, abi.encode(uint16(1), e, bytes("")));
    }
}
