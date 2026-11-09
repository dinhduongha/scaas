// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";
import {UAPrecompileProbe} from "../../script/UAPrecompileProbe.sol";
import {Bls12381} from "../../src/common/Bls12381.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceBase} from "../../src/governance/GovernanceBase.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";

/// @notice `DeployBase` deploys UA registry generation 1 on every chain (CTR-UA-22) with the per-chain kind set of
///         accounts.md §1.9: the precompile probe (`UAPrecompileProbe`: the kinds.json points outside the subgroup,
///         the registry's caps) gates the EIP-2537 kinds (`zether-bls12381` among them, on every chain: owner ruling 2026-10-31)
///         and `bls-bn254-minsig`.
contract UADeployTest is Test {
    bytes32 constant UID = keccak256("scaas.ua3.deploy");
    uint16[12] internal EVERYWHERE = [0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0110, 0x0111, 0x0112, 0x0113, 0x0120, 0, 0];
    address ska = new SmartKeyAccountFactory(UID).IMPLEMENTATION();

    function _registry(uint256 chainId, bool hedera) internal returns (IUARegistry reg) {
        vm.chainId(chainId);
        DeployHarness h = new DeployHarness();
        (, string memory json) = h.deploy(UID, false, ska, hedera);
        reg = IUARegistry(vm.parseJsonAddress(json, ".ua_registry"));
    }

    function _kinds(IUARegistry reg, uint16[5] memory optional) internal view returns (bool[5] memory on) {
        for (uint256 i; i < 10; ++i) {
            assertTrue(reg.kindEnabled(EVERYWHERE[i]), "a kind every chain enables");
        }
        for (uint256 i; i < 5; ++i) {
            on[i] = reg.kindEnabled(optional[i]);
        }
    }

    /// Osaka has EIP-2537 and EIP-197: the probe passes both; under an EVM without EIP-2537 (`FOUNDRY_EVM_VERSION=cancun`)
    /// it reports `bls12381 = false`, as the registry's `Bls12381.isSupported` does. Its points are kinds.json's.
    function test_probe() public {
        (bool bls, bool bn) = abi.decode(address(new UAPrecompileProbe()).code, (bool, bool));
        assertEq(bls, Bls12381.isSupported());
        assertTrue(bn);
        string memory code = vm.toString(type(UAPrecompileProbe).creationCode);
        string memory j = vm.readFile("../vectors/ua/kinds.json");
        uint256[3] memory rows = [uint256(79), 85, 90];
        for (uint256 i; i < 3; ++i) {
            string memory row = string.concat(".invalid[", vm.toString(rows[i]), "]");
            assertEq(vm.parseJsonString(j, string.concat(row, ".reason")), "outside the subgroup");
            string memory kd = vm.toString(vm.parseJsonBytes(j, string.concat(row, ".keyData")));
            assertTrue(vm.indexOf(code, vm.replace(kd, "0x", "")) != type(uint256).max, "probe carries the row");
        }
    }

    /// Dev chain 31337: every kind this registry code has, `zether-bls12381` included (`zether-bn254` is in
    /// `legacy/ua6/`, UA-6 U10); budget 12 M; msig on.
    function test_devChain() public {
        IUARegistry reg = _registry(31337, false);
        bool[5] memory on = _kinds(reg, [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
        assertTrue(on[0] && on[1] && on[2] && !on[3] && on[4]);
        assertEq(reg.verifyBudget(), 12_000_000);
        assertEq(reg.chainUid(), UID);
        assertEq(reg.generation(), 1);
        assertEq(reg.verifyCap(UAKinds.ED25519), 210_000);
        assertEq(reg.verifyCap(UAKinds.ZETHER_BLS12381), 70_000);
        assertFalse(reg.kindEnabled(UAKinds.PQZ_MLWE));
        _pq(reg, true);
        assertFalse(reg.kindEnabled(0x0134), "mldsa87: no precompile here (CTR-UA-39 Q1)");
    }

    /// CTR-UA-39: `mldsa87` is enabled exactly where a candidate answers its EIP-8355 probe (`0x14`, then the SCaaS testnet's
    /// `0x…5caa0014`), with the precompile path's cap; a candidate that answers 1 to everything does not count.
    function test_mldsa87OnlyWithAPrecompile() public {
        string memory kat = vm.readFile("../vectors/ua/pq_kat.json");
        bytes memory valid = vm.parseJsonBytes(kat, ".kinds.mldsa87.eip8355_probe_valid");
        bytes memory invalid = vm.parseJsonBytes(kat, ".kinds.mldsa87.eip8355_probe_invalid");
        address[2] memory at = [address(0x14), 0x000000000000000000000000000000005caA0014];
        for (uint256 i; i < 2; ++i) {
            vm.mockCall(at[i], valid, abi.encode(uint256(1)));
            vm.mockCall(at[i], invalid, abi.encode(uint256(0)));
            IUARegistry reg = _registry(31337, i == 1);
            assertTrue(reg.kindEnabled(0x0134));
            assertEq(reg.verifyCap(0x0134), 250_000, "the precompile path's cap (provisional)");
            vm.clearMockedCalls();
        }
        vm.mockCall(at[1], bytes(""), abi.encode(uint256(1))); // the word 1 to every input
        assertFalse(_registry(31337, false).kindEnabled(0x0134));
        vm.clearMockedCalls();
        assertFalse(_registry(7622, false).kindEnabled(0x0134), "no precompile in this EVM");
    }

    /// P6c: the PQ signing kinds with the gen-1 caps on every chain whose budget holds them at ≤ 66 % (owner rulings
    /// 2026-10-31: no chain-id lock, 66 % instead of 50 %); the ML-DSA verifiers in Solidity (the expanded-key cache).
    function _pq(IUARegistry reg, bool on) internal view {
        uint64[4] memory caps = [uint64(4_250_000), 5_950_000, 2_500_000, 1_400_000];
        for (uint16 k = UAKinds.MLDSA44; k <= UAKinds.SLHDSA128S; ++k) {
            assertEq(reg.kindEnabled(k), on);
            assertEq(reg.verifyCap(k), on ? caps[k - UAKinds.MLDSA44] : 0);
            assertLe(uint256(reg.verifyCap(k)) * 100, uint256(reg.verifyBudget()) * 66);
        }
        // fndsa1024 (CTR-UA-40): pure Solidity wherever its cap fits, the provisional 5,250,000
        assertEq(reg.kindEnabled(UAKinds.FNDSA1024), on, "fndsa1024");
        assertEq(reg.verifyCap(UAKinds.FNDSA1024), on ? 5_250_000 : 0);
        assertLe(uint256(reg.verifyCap(UAKinds.FNDSA1024)) * 100, uint256(reg.verifyBudget()) * 66);
    }

    /// Owner ruling 2026-10-31: no chain-id lock for any kind. Chain 7622, the mainnet 22776, the e2e's 31901 and an
    /// arbitrary id get every kind whose requirement the chain meets (here: the probe passes, the budget is 12 M).
    /// Hedera 298: `hederaNative`, budget 10.5 M, all four PQ kinds (66 % = 6.93 M ≥ `mldsa65`'s 5.95 M); no
    /// `zether-bls12381` (no Zether token on Hedera).
    function test_otherChains() public {
        IUARegistry r7622 = _registry(7622, false);
        bool[5] memory on = _kinds(r7622, [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
        assertTrue(on[0] && on[1] && on[2] && !on[3] && on[4]);
        _pq(r7622, true);
        assertFalse(r7622.kindEnabled(UAKinds.PQZ_MLWE));
        uint256[3] memory ids = [uint256(31901), 22776, 987654321];
        for (uint256 i; i < ids.length; ++i) {
            IUARegistry r = _registry(ids[i], false);
            on = _kinds(r, [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
            assertTrue(on[0] && on[1] && on[2] && !on[3] && on[4]);
            _pq(r, true);
        }
        IUARegistry h = _registry(298, true);
        assertTrue(h.hederaNative());
        assertFalse(h.kindEnabled(UAKinds.ZETHER_BLS12381), "never on Hedera (CTR-ZTH-52)");
        assertEq(h.verifyBudget(), 10_500_000);
        _pq(h, true);
    }

    /// The 66 % rule at its boundary (owner ruling 2026-10-31), integer-exact: 12 M allows 7,920,000, not one more;
    /// Hedera's 10.5 M allows 6,930,000.
    function test_pqKindThreshold66() public {
        DeployHarness h = new DeployHarness();
        assertTrue(h.pqKindFits(7_920_000, 12_000_000));
        assertFalse(h.pqKindFits(7_920_001, 12_000_000));
        assertTrue(h.pqKindFits(6_930_000, 10_500_000));
        assertFalse(h.pqKindFits(6_930_001, 10_500_000));
        assertTrue(h.pqKindFits(5_950_000, 10_500_000), "mldsa65 on Hedera");
        assertTrue(h.pqKindFits(5_250_000, 7_954_546), "fndsa1024: the least budget that holds it");
        assertFalse(h.pqKindFits(5_250_000, 7_954_545));
    }

    /// A chain whose precompiles fail the probe gets none of the kinds that need them (never registrable but unusable).
    function test_probeFailureDisables() public {
        vm.chainId(31337);
        DeployHarness h = new DeployHarness();
        h.force(false, false);
        (, string memory json) = h.deploy(UID, false, ska, false);
        IUARegistry reg = IUARegistry(vm.parseJsonAddress(json, ".ua_registry"));
        bool[5] memory on = _kinds(reg, [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
        assertTrue(!on[0] && !on[1] && !on[2] && !on[3] && !on[4], "none of these");
        _pq(reg, true); // the PQ kinds need no precompile
        // `DEPLOY_ZETHER` on a chain without EIP-2537 stops before deploying anything (CTR-ZTH-52)
        h = new DeployHarness();
        h.force(false, true);
        vm.expectRevert("DEPLOY_ZETHER: the chain has no EIP-2537 (BLS12-381 precompiles)");
        h.deploy(UID, true, ska, false);
    }

    /// C5-1 (NET-EVM-06): a release deploys only where the chain's block gas limit covers its state gas (1,530 per byte
    /// of runtime, size-baseline.json) plus the 2^24 regular-gas cap; the deploy refuses before sending otherwise.
    function test_C5_1_releaseNeedsABlockGasLimit() public {
        DeployHarness h = new DeployHarness();
        string memory base = vm.readFile("./size-baseline.json");
        uint256 plain = vm.parseJsonUint(base, ".NormalToken") * 1530 + 16_777_216;
        uint256 conf = vm.parseJsonUint(base, ".WrappedPqzToken") * 1530 + 16_777_216;
        assertEq(h.gasNeed("NormalToken"), plain);
        assertEq(h.gasNeed("WrappedPqzToken"), conf);
        assertLt(plain, 80_000_000, "plain kinds: about 75 M");
        assertGt(conf, 100_000_000, "confidential kinds: about 124 M");
        assertLt(conf, 130_000_000);
        // a contract over the EIP-170 limit is priced at its baseline size (SCaaSDex since the DEX round)
        assertEq(h.gasNeed("SCaaSDex"), vm.parseJsonUint(base, ".SCaaSDex") * 1530 + 16_777_216);
        // a contract under the EIP-170 limit is not in the baseline: priced at 24,576 B
        assertFalse(vm.keyExistsJson(base, ".UniswapExecutor"));
        assertEq(h.gasNeed("UniswapExecutor"), uint256(24_576) * 1530 + 16_777_216);
        // an Ethereum-like 60 M block cannot hold any confidential release
        vm.expectRevert(bytes(string.concat("block gas limit 60000000 < ", vm.toString(conf),
            " needed to deploy the WrappedPqzToken release (NET-EVM-06)")));
        h.checkGas("WrappedPqzToken", 60_000_000);
        h.checkGas("WrappedPqzToken", conf);
        // the gate reads the chain's block gas limit (at the SCaaS testnet's declared code limit, GD-4: WrappedPqzToken
        // is above EIP-7954's 65,536 B, the default)
        h.limitCode(131_072);
        if (block.gaslimit < conf) vm.expectRevert();
        h.requireGas("WrappedPqzToken");
    }

    /// U8S-D9 (owner 2026-10-31, option (a)): a gen-1 registry built in-test with the EIP-2537 kinds given (verifier: any
    /// code), budget 12 M.
    function _gen1(bool schnorrBls, bool blsMinSig, bool zether, bool hedera) internal returns (IUARegistry) {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](3);
        uint256 n;
        if (schnorrBls) k[n++] = UARegistry.KindConfig(UAKinds.SCHNORR_BLS12381, address(this), 70_000);
        if (blsMinSig) k[n++] = UARegistry.KindConfig(UAKinds.BLS12381_MINSIG, address(this), 200_000);
        if (zether) k[n++] = UARegistry.KindConfig(UAKinds.ZETHER_BLS12381, address(this), 70_000);
        assembly ("memory-safe") {
            mstore(k, n)
        }
        return IUARegistry(address(new UARegistry(UID, address(0), hedera, 12_000_000, address(0), true, k)));
    }

    function _missing(string memory kind) internal pure returns (bytes memory) {
        return bytes(string.concat("gen-1 registry: EIP-2537 kind ", kind, " the probe passes is missing"));
    }

    /// The probe passes EIP-2537 and the registry lacks `zether-bls12381` 0x0141 (not Hedera): refused; all three: passes.
    function test_gen1KindGate_refusesMissingZether() public {
        DeployHarness h = new DeployHarness();
        IUARegistry reg = _gen1(true, true, false, false);
        vm.expectRevert(_missing("0x0141"));
        h.checkGen1Kinds(reg, true, false);
        h.checkGen1Kinds(_gen1(true, true, true, false), true, false);
    }

    /// Without `schnorr-bls12381` 0x0105 or without `bls12381-minsig` 0x0106: refused, naming the kind.
    function test_gen1KindGate_refusesMissingSchnorrBls() public {
        DeployHarness h = new DeployHarness();
        IUARegistry reg = _gen1(false, true, true, false);
        vm.expectRevert(_missing("0x0105"));
        h.checkGen1Kinds(reg, true, false);
        reg = _gen1(true, false, true, false);
        vm.expectRevert(_missing("0x0106"));
        h.checkGen1Kinds(reg, true, false);
    }

    /// The probe does not pass EIP-2537: nothing is required (Hedera or not).
    function test_gen1KindGate_noBlsPasses() public {
        DeployHarness h = new DeployHarness();
        h.checkGen1Kinds(_gen1(false, false, false, false), false, false);
        h.checkGen1Kinds(_gen1(false, false, false, true), false, true);
    }

    /// Hedera: no Zether token can exist there (`ZetherLayer`), so 0x0141 is not required; 0x0105 / 0x0106 still are.
    function test_gen1KindGate_hederaExempts0141() public {
        DeployHarness h = new DeployHarness();
        h.checkGen1Kinds(_gen1(true, true, false, true), true, true);
        IUARegistry reg = _gen1(false, true, false, true);
        vm.expectRevert(_missing("0x0105"));
        h.checkGen1Kinds(reg, true, true);
    }

    /// `_deployUARegistry` runs the gate on the registry it deployed (dev chain 31337: passes, `test_devChain` unchanged).
    /// The registry's CREATE2 address is learnt from a first deploy, then the state is reverted and the deploy repeated.
    function test_gen1KindGate_deployPathRunsIt() public {
        uint256 s = vm.snapshotState();
        address reg = address(_registry(31337, false));
        vm.revertToState(s);
        vm.expectCall(reg, abi.encodeCall(IUARegistry.generation, ()));
        vm.expectCall(reg, abi.encodeCall(IUARegistry.kindEnabled, (UAKinds.SCHNORR_BLS12381)));
        vm.expectCall(reg, abi.encodeCall(IUARegistry.kindEnabled, (UAKinds.BLS12381_MINSIG)));
        vm.expectCall(reg, abi.encodeCall(IUARegistry.kindEnabled, (UAKinds.ZETHER_BLS12381)));
        assertEq(address(_registry(31337, false)), reg);
    }

    /// NET-EVM-06: the registry and each of its libraries have the gate of a release (typed-signing R2; T66b 3.1b: two
    /// libraries): the deploy refuses one below each figure, in the deploy's order (the registry, `UARegistryCoreLib`,
    /// `UARegistryAuxLib`), and goes through at the largest gate of a plain deploy (the libraries', `NormalToken`'s and the
    /// DEX's, whichever is largest).
    function test_registryDeployGate() public {
        DeployHarness h = new DeployHarness();
        string memory base = vm.readFile("./size-baseline.json");
        uint256 need = h.gasNeed("UARegistry");
        uint256 lib = h.gasNeed("UARegistryCoreLib");
        uint256 key = h.gasNeed("UARegistryAuxLib");
        assertEq(need, vm.parseJsonUint(base, ".UARegistry") * 1530 + 16_777_216);
        assertEq(lib, vm.parseJsonUint(base, ".UARegistryCoreLib") * 1530 + 16_777_216);
        assertEq(key, vm.parseJsonUint(base, ".UARegistryAuxLib") * 1530 + 16_777_216);
        assertLt(need, lib);
        assertLt(need, key);
        _refused(h, need - 1, need, "UARegistry");
        _refused(h, need, lib, "UARegistryCoreLib");
        if (key > lib) _refused(h, lib, key, "UARegistryAuxLib");
        uint256 top = lib > key ? lib : key;
        uint256 token = h.gasNeed("NormalToken");
        uint256 dex = h.gasNeed("SCaaSDex");
        if (token > top) top = token;
        if (dex > top) top = dex;
        h.limitBlockGas(top);
        h.deploy(UID, false, ska);
    }

    /// Plan T11 (CTR-GOV-15 Change): the chain's `GovernanceRouter` is deployed before the releases, on the chain's registry
    /// and `chain_uid`; chain-neutral releases (plan T72): it is the factory's one-time `govRouter` (every clone's env), and
    /// a release carries none: `NORMAL`, the DEX, both Zether kinds.
    function test_govRouterBeforeTheReleases() public {
        vm.chainId(31337);
        DeployHarness h = new DeployHarness();
        (OpenFactory f, string memory json) = h.deploy(UID, true, ska);
        GovernanceRouter r = GovernanceRouter(vm.parseJsonAddress(json, ".governance_router"));
        assertGt(address(r).code.length, 0);
        assertEq(r.chainUid(), UID);
        assertEq(r.registry(), vm.parseJsonAddress(json, ".ua_registry"));
        string[4] memory impls = ["implementation_normal", "dex_implementation", "implementation_normal_zether_bls12381",
            "implementation_wrapped_zether_bls12381"];
        for (uint256 i; i < 4; ++i) {
            address impl = vm.parseJsonAddress(json, string.concat(".", impls[i]));
            assertEq(GovernanceBase(impl).GOV_ROUTER(), address(0), impls[i]);
        }
        assertEq(f.govRouter(), address(r), "the factory's router");
    }

    function _refused(DeployHarness h, uint256 limit, uint256 need, string memory name) internal {
        h.limitBlockGas(limit);
        vm.expectRevert(bytes(string.concat("block gas limit ", vm.toString(limit), " < ", vm.toString(need),
            " needed to deploy the ", name, " release (NET-EVM-06)")));
        h.deploy(UID, false, ska);
    }
}
