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
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
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
        h.limitCode(52_296);
        vm.expectRevert(bytes("WrappedToken runtime 52297 B > chain code limit 52296 B (CHAIN_CODE_LIMIT, CTR-GOV-19)"));
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
        string[7] memory kinds = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "NormalPqzToken",
            "WrappedPqzToken", "SCaaSDex"];
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
        string[8] memory names = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "NormalPqzToken",
            "WrappedPqzToken", "SCaaSDex", "GovernanceRouter"];
        bytes[8] memory codes = [
            _release(type(NormalToken).creationCode, IOpenFactory.TokenKind.NORMAL, router),
            _release(type(WrappedToken).creationCode, IOpenFactory.TokenKind.WRAPPED, router),
            _release(type(NormalZetherToken).creationCode, IOpenFactory.TokenKind.NORMAL_ZETHER, router),
            _release(type(WrappedZetherToken).creationCode, IOpenFactory.TokenKind.WRAPPED_ZETHER, router),
            _release(type(NormalPqzToken).creationCode, IOpenFactory.TokenKind.NORMAL_PQZ, router),
            _release(type(WrappedPqzToken).creationCode, IOpenFactory.TokenKind.WRAPPED_PQZ, router),
            _dex(router),
            abi.encodePacked(type(GovernanceRouter).creationCode, abi.encode(ZUID, address(this), ska, false))
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

    /// A kind's init code with the factory's append, `abi.encode(envVersion, env, implArgs)`: the env names the real Zether
    /// verifiers, a contract for the PQZ verifier, the kind's link closure and the router.
    function _release(bytes memory code, IOpenFactory.TokenKind kind, address router) internal view returns (bytes memory) {
        IFactoryToken.Env memory e = pinned(plainEnv(address(this), ska, ZUID, address(this), false), kind);
        e.govRouter = router;
        if (uint8(kind) >= 2) e.smartKeyAccountImpl = address(0);
        if (uint8(kind) == 2 || uint8(kind) == 3) e.deps = zdeps;
        if (uint8(kind) >= 4) {
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
