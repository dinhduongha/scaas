// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";
import {MldsaKit} from "../helpers/MldsaKit.sol";
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
        assertTrue(reg.kindEnabled(0x0134), "mldsa87: on the cache without a precompile (CTR-UA-39 Q1, owner 2026-11-15)");
        assertEq(reg.verifyCap(0x0134), 8_850_000, "the cached cap");
    }

    /// CTR-UA-39 as changed by the owner 2026-11-15 (MD-2, MD-6): `mldsa87` on the precompile path (cap 250,000, provisional)
    /// where a candidate (`0x14`, then the SCaaS testnet's `0x…5caa0014`) answers its EIP-8355 probe in this EVM, else on the
    /// cache (8,850,000); a candidate that answers 1 to everything does not count; on Hedera's 10.5 M budget the cached cap fails
    /// the 75 % rule (7,875,000), so there only the precompile path enables it.
    function test_mldsa87_precompileOrCache() public {
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
        assertEq(_registry(31337, false).verifyCap(0x0134), 8_850_000, "no precompile counts: the cache");
        vm.clearMockedCalls();
        assertEq(_registry(7622, false).verifyCap(0x0134), 8_850_000, "no precompile in this EVM: the cache");
        assertFalse(_registry(298, true).kindEnabled(0x0134), "Hedera: 8,850,000 > 75 % of 10.5 M");
    }

    /// MD-6 (owner 2026-11-15): `MLDSA_PRECOMPILE=off` builds every ML-DSA kind on the cache even where the chain answers the
    /// probe, and refuses any `MLDSA<x>_VERIFIER`; `on` where the chain answers and no verifier is handed in refuses by name;
    /// `on` with the CREATE2 verifier takes it (the deploy JSON records each kind's path, MD-15).
    function test_mldsaPrecompileFlag() public {
        vm.chainId(7622);
        DeployHarness h = new DeployHarness();
        h.setMldsa(false, address(0), address(0));
        h.forceMl(true, true);
        h.forcePq(false, true);
        (, string memory json) = h.deploy(UID, false, ska);
        IUARegistry reg = IUARegistry(vm.parseJsonAddress(json, ".ua_registry"));
        assertEq(reg.verifyCap(0x0130), 4_250_000);
        assertEq(reg.verifyCap(0x0131), 5_950_000);
        assertEq(reg.verifyCap(0x0134), 8_850_000);
        assertEq(vm.parseJsonString(json, ".mldsa_precompile"), "off");
        assertEq(vm.parseJsonString(json, ".mldsa65_path"), "cache");
        address v65 = MldsaKit.onChain(1, 0x000000000000000000000000000000005CAa0013, keccak256("scaas.deploy.v1"));
        h = new DeployHarness();
        h.setMldsa(false, address(0), v65);
        vm.expectRevert(bytes("MLDSA65_VERIFIER: set with MLDSA_PRECOMPILE=off (pure Solidity with the cache)"));
        h.deploy(UID, false, ska);
        h = new DeployHarness(); // on: the chain answers 0x0131's probe, no verifier handed in
        h.forceMl(false, true);
        vm.expectRevert(bytes("gen-1 registry: PQ precompile kind 0x0131 the probe passes is missing (MLDSA65_VERIFIER: deploy.sh evm's pq-verifiers step)"));
        h.deploy(UID, false, ska);
        h = new DeployHarness();
        h.setMldsa(true, address(0), v65);
        h.forceMl(false, true);
        (, json) = h.deploy(UID, false, ska);
        reg = IUARegistry(vm.parseJsonAddress(json, ".ua_registry"));
        assertEq(reg.verifyCap(0x0131), 200_000, "the precompile path's cap");
        assertEq(vm.parseJsonAddress(json, ".mldsa65_verifier"), v65);
        assertEq(vm.parseJsonString(json, ".mldsa65_path"), "precompile 0x000000000000000000000000000000005CAa0013");
        assertEq(vm.parseJsonString(json, ".mldsa44_path"), "cache");
        assertEq(vm.parseJsonString(json, ".mldsa_precompile"), "on");
    }

    /// MD-15 (owner 2026-11-15, F-7): with `on`, a probe call that fails (no RPC here) refuses the deploy by name; with `off` it
    /// requires no kind.
    function test_mldsaProbeFailureRefuses() public {
        DeployHarness h = new DeployHarness();
        vm.expectRevert(bytes("MLDSA_PRECOMPILE=on: the chain's PQ precompile probe (PqPrecompileProbe by eth_call) failed or answered no 128 bytes: refused (MD-15)"));
        h.realPq();
        h.setMldsa(false, address(0), address(0));
        (bool pqz, bool[3] memory ml) = h.realPq();
        assertFalse(pqz || ml[0] || ml[1] || ml[2]);
    }

    /// MD-5 (owner 2026-11-15, F-5): an ML-DSA kind on the cache is enabled only where each part transaction fits the block
    /// (`DeployGas`, measured): `mldsa87`'s part 2 asks (10,730,000 + 34,848,810) x 1.05 = 47,857,750, so a block of one less
    /// disables it and one of exactly that enables it; `mldsa65` (45,687,694) and `mldsa44` (43,528,138) fit both; 200 M holds all.
    function test_mldsaCacheBlockGate() public {
        DeployHarness h = new DeployHarness();
        h.limitBlockGas(47_857_749);
        assertFalse(h.cacheFits(2), "mldsa87 under its largest part");
        assertTrue(h.cacheFits(1) && h.cacheFits(0));
        h.limitBlockGas(47_857_750);
        assertTrue(h.cacheFits(2), "mldsa87 at its largest part");
        h.limitBlockGas(45_687_693);
        assertFalse(h.cacheFits(1), "mldsa65 under its largest part");
        h.limitBlockGas(200_000_000);
        assertTrue(h.cacheFits(0) && h.cacheFits(1) && h.cacheFits(2));
    }

    /// P6c: the PQ signing kinds with the gen-1 caps on every chain whose budget holds them at ≤ 75 % (owner rulings
    /// 2026-10-31: no chain-id lock; 2026-11-15: 75 % instead of 66 %); the ML-DSA verifiers in Solidity (the expanded-key cache).
    function _pq(IUARegistry reg, bool on) internal view {
        uint64[4] memory caps = [uint64(4_250_000), 5_950_000, 2_500_000, 1_400_000];
        for (uint16 k = UAKinds.MLDSA44; k <= UAKinds.SLHDSA128S; ++k) {
            assertEq(reg.kindEnabled(k), on);
            assertEq(reg.verifyCap(k), on ? caps[k - UAKinds.MLDSA44] : 0);
            assertLe(uint256(reg.verifyCap(k)) * 100, uint256(reg.verifyBudget()) * 75);
        }
        // fndsa1024 (CTR-UA-40): pure Solidity wherever its cap fits, the provisional 5,250,000
        assertEq(reg.kindEnabled(UAKinds.FNDSA1024), on, "fndsa1024");
        assertEq(reg.verifyCap(UAKinds.FNDSA1024), on ? 5_250_000 : 0);
        assertLe(uint256(reg.verifyCap(UAKinds.FNDSA1024)) * 100, uint256(reg.verifyBudget()) * 75);
    }

    /// Owner ruling 2026-10-31: no chain-id lock for any kind. Chain 7622, the mainnet 22776, the e2e's 31901 and an
    /// arbitrary id get every kind whose requirement the chain meets (here: the probe passes, the budget is 12 M).
    /// Hedera 298: `hederaNative`, budget 10.5 M, all four PQ kinds (75 % = 7.875 M ≥ `mldsa65`'s 5.95 M; not the cached `mldsa87`); no
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

    /// The 75 % rule at its boundary (CTR-UA-23; owner 2026-11-15, was 66 % by the ruling of 2026-10-31: 7,920,000 at 12 M),
    /// integer-exact: 12 M allows 9,000,000, not one more; Hedera's 10.5 M allows 7,875,000 (so not the cached `mldsa87`'s
    /// 8,850,000). A threshold of 74 refuses 9,000,000, one of 76 admits 9,000,001: both caught here.
    function test_pqKindThreshold75() public {
        DeployHarness h = new DeployHarness();
        assertTrue(h.pqKindFits(9_000_000, 12_000_000));
        assertFalse(h.pqKindFits(9_000_001, 12_000_000));
        assertTrue(h.pqKindFits(7_875_000, 10_500_000));
        assertFalse(h.pqKindFits(7_875_001, 10_500_000));
        assertTrue(h.pqKindFits(8_850_000, 12_000_000), "mldsa87 cached at 12 M");
        assertFalse(h.pqKindFits(8_850_000, 10_500_000), "mldsa87 cached on Hedera");
        assertTrue(h.pqKindFits(5_950_000, 10_500_000), "mldsa65 on Hedera");
        assertTrue(h.pqKindFits(5_250_000, 7_000_000), "fndsa1024: the least budget that holds it");
        assertFalse(h.pqKindFits(5_250_000, 6_999_999));
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
        // T66b (the window closed): WrappedPqzToken's row 62,022 -> 24,314 B, its gate 111.7 M -> 54.0 M: under 60 M
        assertLt(conf, 60_000_000, "confidential kinds: about 54 M");
        // a contract over the EIP-170 limit is priced at its baseline size (SCaaSDex since the DEX round)
        assertEq(h.gasNeed("SCaaSDex"), vm.parseJsonUint(base, ".SCaaSDex") * 1530 + 16_777_216);
        // a contract under the EIP-170 limit is not in the baseline: priced at 24,576 B
        assertFalse(vm.keyExistsJson(base, ".UniswapExecutor"));
        assertEq(h.gasNeed("UniswapExecutor"), uint256(24_576) * 1530 + 16_777_216);
        // T66b: an Ethereum-like 60 M block holds the largest confidential release (it could not before the split); one
        // gas below its need is refused by name
        h.checkGas("WrappedPqzToken", 60_000_000);
        vm.expectRevert(bytes(string.concat("block gas limit ", vm.toString(conf - 1), " < ", vm.toString(conf),
            " needed to deploy the WrappedPqzToken release (NET-EVM-06)")));
        h.checkGas("WrappedPqzToken", conf - 1);
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

    /// Owner 2026-11-15: a gen-1 registry with `pqz-mlwe` 0x0142 / `mldsa87` 0x0134 as given (verifier: any code).
    function _gen1Pq(bool pqz, bool ml87) internal returns (IUARegistry) {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](2);
        uint256 n;
        if (pqz) k[n++] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(this), 4_500_000);
        if (ml87) k[n++] = UARegistry.KindConfig(UAKinds.MLDSA87, address(this), 250_000);
        assembly ("memory-safe") {
            mstore(k, n)
        }
        return IUARegistry(address(new UARegistry(UID, address(0), false, 12_000_000, address(0), true, k)));
    }

    function _missingPq(string memory kind, string memory env) internal pure returns (bytes memory) {
        return bytes(string.concat("gen-1 registry: PQ precompile kind ", kind, " the probe passes is missing (", env,
            ": deploy.sh evm's pq-verifiers step)"));
    }

    /// Owner 2026-11-15: the chain answers the `PQZ` self-test / the `mldsa87` probe and the registry lacks `pqz-mlwe` 0x0142
    /// / `mldsa87` 0x0134: refused, naming the kind; with it: passes; a chain whose probe fails (anvil) requires neither.
    function test_gen1KindGate_pqKinds() public {
        DeployHarness h = new DeployHarness();
        IUARegistry none = _gen1Pq(false, false);
        vm.expectRevert(_missingPq("0x0142", "PQZ_KEY_VERIFIER"));
        h.checkGen1Kinds(none, false, false, true, false);
        vm.expectRevert(_missingPq("0x0134", "MLDSA87_VERIFIER"));
        h.checkGen1Kinds(none, false, false, false, true);
        IUARegistry onlyPqz = _gen1Pq(true, false);
        h.checkGen1Kinds(onlyPqz, false, false, true, false);
        vm.expectRevert(_missingPq("0x0134", "MLDSA87_VERIFIER"));
        h.checkGen1Kinds(onlyPqz, false, false, true, true);
        IUARegistry only87 = _gen1Pq(false, true);
        vm.expectRevert(_missingPq("0x0142", "PQZ_KEY_VERIFIER"));
        h.checkGen1Kinds(only87, false, false, true, true);
        h.checkGen1Kinds(_gen1Pq(true, true), false, false, true, true); // control: both there
        h.checkGen1Kinds(none, false, false, false, false); // the probe fails: nothing required
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
        // T66b 3.1c / 3.1d (owner): the Aux library's gate is implied by an earlier one. 3ze (CTR-UA-44): the Aux library
        // (32,372 B) passed the registry (32,055 B) but stays below the Core library (35,165 B), whose gate is checked first
        // (was `key < need` while the Aux library was below the registry)
        assertLt(key, lib);
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
