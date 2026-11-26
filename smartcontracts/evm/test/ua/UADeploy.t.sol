// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";
import {MldsaKit} from "../helpers/MldsaKit.sol";
import {PcStandIn} from "./MlDsaVerifyOnly.t.sol";
import {MldsaVerifyOnly65} from "../../src/ua/MlDsaVerifyOnly.sol";
import {PqzSafety} from "../../src/pqz/PqzSafety.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UAPrecompileProbe} from "../../script/UAPrecompileProbe.sol";
import {Bls12381} from "../../src/common/Bls12381.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UARegistryRegLib} from "../../src/ua/UARegistryRegLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceBase} from "../../src/governance/GovernanceBase.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";

/// @notice `DeployBase` deploys UA registry generation 1 on every chain (CTR-UA-22) with the per-chain kind set of
///         accounts.md §1.9: the precompile probe (`UAPrecompileProbe`: the kinds.json points outside the subgroup,
///         the registry's caps) gates the EIP-2537 kinds (`zether-bls12381` among them, on every chain: owner ruling 2026-10-31)
///         and `bls-bn254-minsig`.
/// The getters `DeployBase` checks on a `pqz-mlwe` verifier (a real one needs the PQZ precompile in its constructor).
contract PqzKeyVerifierGetters {
    address public constant PRECOMPILE = PqzSafety.PQZ;
    bytes32 public constant PROOF_SYSTEM_ID = PqzSafety.PQZL_ID;
}

contract UADeployTest is Test {
    bytes32 constant UID = keccak256("scaas.ua3.deploy");
    uint16[12] internal EVERYWHERE =
        [0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0110, 0x0111, 0x0112, 0x0113, 0x0120, 0, 0];
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
        assertTrue(reg.kindEnabled(UAKinds.BLS12381_MULTI), "bls12381-multi where the probe passes EIP-2537");
        assertEq(reg.verifyCap(UAKinds.BLS12381_MULTI), 330_000);
        assertFalse(reg.kindEnabled(UAKinds.PQZ_MLWE));
        _pq(reg, true);
        assertTrue(
            reg.kindEnabled(0x0134), "mldsa87: on the cache without a precompile (CTR-UA-39 Q1, owner 2026-11-15)"
        );
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
        // CTR-UA-69 (owner R9, plan Task 14): the Draft 0x14 is not probed without the chain's flag: the cache; the chain's own
        // 0x…5caa0014: the precompile path (was: both on the precompile, the Draft first)
        for (uint256 i; i < 2; ++i) {
            vm.mockCall(at[i], valid, abi.encode(uint256(1)));
            vm.mockCall(at[i], invalid, abi.encode(uint256(0)));
            IUARegistry reg = _registry(31337, i == 1);
            assertTrue(reg.kindEnabled(0x0134));
            assertEq(
                reg.verifyCap(0x0134),
                i == 0 ? 8_850_000 : 250_000,
                i == 0 ? "a Draft address unprobed: the cache" : "the precompile path's cap (provisional)"
            );
            vm.clearMockedCalls();
        }
        vm.mockCall(at[1], bytes(""), abi.encode(uint256(1))); // the word 1 to every input
        assertEq(_registry(31337, false).verifyCap(0x0134), 8_850_000, "no precompile counts: the cache");
        vm.clearMockedCalls();
        assertEq(_registry(22779, false).verifyCap(0x0134), 8_850_000, "no precompile in this EVM: the cache");
    }

    /// `test_mldsa87_precompileOrCache`'s Hedera row, its own test since bls-multi Task 7: five full deploys (each ~1 G of EIP-8037
    /// state gas for its harness) no longer fit one test's `gas_limit`.
    function test_mldsa87_hederaCacheFails() public {
        assertFalse(_registry(298, true).kindEnabled(0x0134), "Hedera: 8,850,000 > 75 % of 10.5 M");
    }

    /// MD-6 (owner 2026-11-15): `MLDSA_PRECOMPILE=off` builds every ML-DSA kind on the cache even where the chain answers the
    /// probe, and refuses any `MLDSA<x>_VERIFIER`; `on` where the chain answers and no verifier is handed in refuses by name;
    /// `on` with the CREATE2 verifier takes it (the deploy JSON records each kind's path, MD-15).
    function test_mldsaPrecompileFlag() public {
        vm.chainId(22779);
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
        vm.expectRevert(
            bytes(
                "gen-1 registry: PQ precompile kind 0x0131 the probe passes is missing (MLDSA65_VERIFIER: deploy.sh evm's pq-verifiers step)"
            )
        );
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
        vm.expectRevert(
            bytes(
                "MLDSA_PRECOMPILE=on: the chain's PQ precompile probe (PqPrecompileProbe by eth_call) failed or answered no 128 bytes: refused (MD-15)"
            )
        );
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

    /// Owner ruling 2026-10-31: no chain-id lock for any kind. Chain 22779, the mainnet 22777, the e2e's 31901 and an
    /// arbitrary id get every kind whose requirement the chain meets (here: the probe passes, the budget is 12 M).
    /// Hedera 298: `hederaNative`, budget 10.5 M, all four PQ kinds (75 % = 7.875 M ≥ `mldsa65`'s 5.95 M; not the cached `mldsa87`); no
    /// `zether-bls12381` (no Zether token on Hedera).
    function test_otherChains() public {
        IUARegistry rTestnet = _registry(22779, false);
        bool[5] memory on = _kinds(rTestnet, [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
        assertTrue(on[0] && on[1] && on[2] && !on[3] && on[4]);
        _pq(rTestnet, true);
        assertFalse(rTestnet.kindEnabled(UAKinds.PQZ_MLWE));
        uint256[3] memory ids = [uint256(31901), 22777, 987654321];
        for (uint256 i; i < ids.length; ++i) {
            IUARegistry r = _registry(ids[i], false);
            on = _kinds(r, [uint16(0x0105), 0x0106, 0x0107, 0x0140, 0x0141]);
            assertTrue(on[0] && on[1] && on[2] && !on[3] && on[4]);
            _pq(r, true);
        }
    }

    /// `test_otherChains`'s Hedera row, its own test since bls-multi Task 7 (five deploys no longer fit one test's `gas_limit`).
    function test_otherChains_hedera() public {
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

    /// `bls12381-multi` without EIP-2537 (spec 2026-11-19-bls12381-multi §7, ARCH-POS-18; Q-SW1): on a chain other than Hedera the
    /// deploy refuses the kind (no verifier: no software BLS12-381 path is built) and names it in the deploy book, a case for the
    /// owner; where the probe passes, the book names the precompile path.
    function test_deploy_noEip2537_refuses0x0121_named() public {
        vm.chainId(31337);
        DeployHarness h = new DeployHarness();
        (, string memory json) = h.deploy(UID, false, ska, false);
        assertEq(vm.parseJsonString(json, ".ua_kind_0x0121"), "precompile: EIP-2537");
        h = new DeployHarness();
        h.force(false, false);
        (, json) = h.deploy(UID, false, ska, false);
        IUARegistry reg = IUARegistry(vm.parseJsonAddress(json, ".ua_registry"));
        assertFalse(reg.kindEnabled(UAKinds.BLS12381_MULTI));
        assertEq(
            vm.parseJsonString(json, ".ua_kind_0x0121"),
            "refused: no EIP-2537 and no software BLS12-381 path built (ARCH-POS-18): a case for the owner"
        );
    }

    /// Q-SW1 (owner 2026-11-19, ARCH-POS-18's confirmation for this kind and chain): Hedera's profile disables `bls12381-multi`,
    /// whatever the probe answers, and the book says so.
    function test_deploy_hedera_0x0121Disabled() public {
        bool[2] memory probe = [true, false];
        for (uint256 i; i < 2; ++i) {
            vm.chainId(298);
            DeployHarness h = new DeployHarness();
            if (!probe[i]) h.force(false, false);
            (, string memory json) = h.deploy(UID, false, ska, true);
            IUARegistry reg = IUARegistry(vm.parseJsonAddress(json, ".ua_registry"));
            assertFalse(reg.kindEnabled(UAKinds.BLS12381_MULTI));
            assertEq(
                vm.parseJsonString(json, ".ua_kind_0x0121"),
                "disabled: Hedera, owner-confirmed 2026-11-19 (Q-SW1, ARCH-POS-18)"
            );
        }
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
        vm.expectRevert(
            bytes(
                string.concat(
                    "block gas limit ",
                    vm.toString(conf - 1),
                    " < ",
                    vm.toString(conf),
                    " needed to deploy the WrappedPqzToken release (NET-EVM-06)"
                )
            )
        );
        h.checkGas("WrappedPqzToken", conf - 1);
        h.checkGas("WrappedPqzToken", conf);
        // the gate reads the chain's block gas limit (at the SCaaS testnet's declared code limit, GD-4: WrappedPqzToken
        // is above EIP-7954's 65,536 B, the default)
        h.limitCode(131_072);
        if (block.gaslimit < conf) vm.expectRevert();
        h.requireGas("WrappedPqzToken");
    }

    /// U8S-D9 (owner 2026-10-31, option (a)): a gen-1 registry built in-test with the EIP-2537 kinds given (verifier: any
    /// code), budget 12 M. `bls12381-multi` goes with `zether-bls12381` (both: EIP-2537, not on Hedera); `_gen1m` sets it apart.
    function _gen1(bool schnorrBls, bool blsMinSig, bool zether, bool hedera) internal returns (IUARegistry) {
        return _gen1m(schnorrBls, blsMinSig, zether, hedera, zether);
    }

    function _gen1m(bool schnorrBls, bool blsMinSig, bool zether, bool hedera, bool multi)
        internal
        returns (IUARegistry)
    {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](4);
        uint256 n;
        if (schnorrBls) k[n++] = UARegistry.KindConfig(UAKinds.SCHNORR_BLS12381, address(this), 70_000, false, 0);
        if (blsMinSig) k[n++] = UARegistry.KindConfig(UAKinds.BLS12381_MINSIG, address(this), 200_000, false, 0);
        if (zether) k[n++] = UARegistry.KindConfig(UAKinds.ZETHER_BLS12381, address(this), 70_000, false, 0);
        if (multi) k[n++] = UARegistry.KindConfig(UAKinds.BLS12381_MULTI, address(this), 330_000, false, 0);
        assembly ("memory-safe") {
            mstore(k, n)
        }
        return IUARegistry(address(new UARegistry(UID, address(0), hedera, 12_000_000, 1 << 24, address(0), true, k)));
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

    /// The probe passes EIP-2537 and the registry lacks `bls12381-multi` 0x0121 (not Hedera): refused, naming it; on Hedera not
    /// required (disabled there, owner-confirmed 2026-11-19, Q-SW1).
    function test_gen1KindGate_refusesMissing0121() public {
        DeployHarness h = new DeployHarness();
        IUARegistry reg = _gen1m(true, true, true, false, false);
        vm.expectRevert(_missing("0x0121"));
        h.checkGen1Kinds(reg, true, false);
        h.checkGen1Kinds(_gen1m(true, true, true, false, true), true, false);
        h.checkGen1Kinds(_gen1m(true, true, false, true, false), true, true);
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
        if (pqz) k[n++] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(this), 4_500_000, false, 0);
        if (ml87) k[n++] = UARegistry.KindConfig(UAKinds.MLDSA87, address(this), 250_000, false, 0);
        assembly ("memory-safe") {
            mstore(k, n)
        }
        return IUARegistry(address(new UARegistry(UID, address(0), false, 12_000_000, 1 << 24, address(0), true, k)));
    }

    function _missingPq(string memory kind, string memory env) internal pure returns (bytes memory) {
        return bytes(
            string.concat(
                "gen-1 registry: PQ precompile kind ",
                kind,
                " the probe passes is missing (",
                env,
                ": deploy.sh evm's pq-verifiers step)"
            )
        );
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
    /// libraries; owner 2026-11-19: three, `UARegistryRegLib` split from the core): the deploy refuses one below each figure,
    /// in the deploy's order (the registry, `UARegistryCoreLib`, `UARegistryAuxLib`, `UARegistryRegLib`), and goes through at
    /// the largest gate of a plain deploy (the libraries', `NormalToken`'s and the DEX's, whichever is largest).
    function test_registryDeployGate() public {
        DeployHarness h = new DeployHarness();
        string memory base = vm.readFile("./size-baseline.json");
        uint256 need = h.gasNeed("UARegistry");
        uint256 lib = h.gasNeed("UARegistryCoreLib");
        uint256 key = h.gasNeed("UARegistryAuxLib");
        uint256 rl = h.gasNeed("UARegistryRegLib");
        assertEq(need, vm.parseJsonUint(base, ".UARegistry") * 1530 + 16_777_216);
        assertEq(lib, vm.parseJsonUint(base, ".UARegistryCoreLib") * 1530 + 16_777_216);
        assertEq(key, vm.parseJsonUint(base, ".UARegistryAuxLib") * 1530 + 16_777_216);
        assertEq(rl, vm.parseJsonUint(base, ".UARegistryRegLib") * 1530 + 16_777_216);
        // multi-gen-verify Task 8 moved the PQZ readers out of the Aux library (35,670 -> 33,858 B): all three libraries (core
        // 23,465, registration 31,665, Aux 33,858 B) are now below the registry (35,166 B), whose gate is checked first, so
        // theirs are implied by it (was, after the split: the Aux library above the registry, the next gate refused)
        // CTR-UA-74 (owner 2026-11-25): `msigAt` and two `pure` views moved in, the Aux library (35,099 B) is above the registry
        // (35,069 B) again and is the next gate refused, as after the split
        assertLt(lib, need);
        assertLt(rl, need);
        assertGt(key, need);
        _refused(h, need - 1, need, "UARegistry");
        _refused(h, need, key, "UARegistryAuxLib");
        uint256 top = key;
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
        string[4] memory impls = [
            "implementation_normal",
            "dex_implementation",
            "implementation_normal_zether_bls12381",
            "implementation_wrapped_zether_bls12381"
        ];
        for (uint256 i; i < 4; ++i) {
            address impl = vm.parseJsonAddress(json, string.concat(".", impls[i]));
            assertEq(GovernanceBase(impl).GOV_ROUTER(), address(0), impls[i]);
        }
        assertEq(f.govRouter(), address(r), "the factory's router");
    }

    function _refused(DeployHarness h, uint256 limit, uint256 need, string memory name) internal {
        h.limitBlockGas(limit);
        vm.expectRevert(
            bytes(
                string.concat(
                    "block gas limit ",
                    vm.toString(limit),
                    " < ",
                    vm.toString(need),
                    " needed to deploy the ",
                    name,
                    " release (NET-EVM-06)"
                )
            )
        );
        h.deploy(UID, false, ska);
    }

    // ----- later-generation mode (spec 2026-11-19-registry-verify-only-kinds §9, X1, M9, M10 d, W5; plan Task 13 Step 1) -----
    // Red until `DeployHarness.deployGen(bytes32 uid, address ska, string book)` exists: it deploys generation n + 1 over the
    // book's latest registry and returns (registry, json); a refusal reverts with its name. Called by name so the suite
    // compiles before it is built.

    function _gen(DeployHarness h, string memory book) internal returns (bool ok, bytes memory ret) {
        (ok, ret) = address(h).call(abi.encodeWithSignature("deployGen(bytes32,address,string)", UID, ska, book));
    }

    /// A book of `generations` generations (gen 1 from the harness), `extra` JSON fields appended.
    function _book(DeployHarness h, string memory extra) internal returns (string memory) {
        (, string memory json) = h.deploy(UID, false, ska, false);
        address r = vm.parseJsonAddress(json, ".ua_registry");
        return string.concat(
            '{"ua_registry":"',
            vm.toString(r),
            '","ua_registry_codehash":"',
            vm.toString(r.codehash),
            '",',
            '"tx_gas_cap":16777216',
            extra,
            "}"
        );
    }

    /// `extra` fields appended to a flat book.
    function _add(string memory b, string memory extra) internal pure returns (string memory) {
        return vm.replace(b, "}", string.concat(extra, "}"));
    }

    function _named(DeployHarness h, string memory book, string memory name) internal {
        (bool ok, bytes memory ret) = _gen(h, book);
        assertFalse(ok, name);
        assertTrue(vm.contains(string(ret), name), name);
    }

    address internal constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    uint256 internal constant VO_CALL_GAS = 50_000;

    /// A verify-only ML-DSA verifier of `kind` (key form `form`) as `pq_verifiers.py verify-only` builds it (Task 21 review P2-3):
    /// CREATE2 with the deploy salt of `_voInit` (this chain's candidates, pq_kat.json's valid row, the flipped row and every
    /// mutation row); its probe finds a stand-in at the chain's own address (`working`: valid row 1, every other input 0), or none.
    function _vo(DeployHarness h, uint16 kind, uint8 form, bool working) internal returns (address v) {
        if (working) _ownStandIn(kind);
        v = _create2(h.voInit(kind, form, VO_CALL_GAS));
    }

    function _ownStandIn(uint16 kind) internal {
        uint256 i = kind == UAKinds.MLDSA44 ? 0 : kind == UAKinds.MLDSA65 ? 1 : 2;
        address pc = address(uint160(0x5caa0012 + i));
        string memory k = string.concat(".kinds.mldsa", ["44", "65", "87"][i], ".eip8355_probe_valid");
        vm.etch(pc, address(new PcStandIn()).code);
        PcStandIn(pc)
            .set(keccak256(vm.parseJsonBytes(vm.readFile("../vectors/ua/pq_kat.json"), k)), new bytes[](0), 0, 0);
    }

    function _create2(bytes memory init) internal returns (address v) {
        bytes32 s = keccak256("scaas.deploy.v1");
        v = vm.computeCreate2Address(s, keccak256(init), CREATE2_DEPLOYER);
        if (v.code.length == 0) {
            (bool ok,) = CREATE2_DEPLOYER.call(bytes.concat(s, init));
            require(ok && v.code.length != 0, "CREATE2");
        }
    }

    /// The book's `gen_verify_only` list of one entry, with the differential probe's `ok` for its verifier.
    function _voEntry(uint16 kind, address v, uint64 cap, uint8 form) internal pure returns (string memory) {
        return _voEntry(kind, v, cap, form, string.concat("ok ", vm.toString(v)));
    }

    function _voEntry(uint16 kind, address v, uint64 cap, uint8 form, string memory diff)
        internal
        pure
        returns (string memory)
    {
        return string.concat(
            ',"gen_verify_only":[{"kind":',
            vm.toString(kind),
            ',"verifier":"',
            vm.toString(v),
            '","cap":',
            vm.toString(cap),
            ',"keyForm":',
            vm.toString(form),
            ',"differential":"',
            diff,
            '"}]'
        );
    }

    /// Gen 1 with `pqz-mlwe` 0x0142 (a stand-in with the getters `DeployBase` checks).
    function _pqzHarness() internal returns (DeployHarness h) {
        h = new DeployHarness();
        h.setPqz(false, address(new PqzKeyVerifierGetters()), address(0));
    }

    function test_deploy_gen2_overGen1_fromBook() public {
        vm.chainId(31337);
        DeployHarness h = new DeployHarness();
        address v = _vo(h, UAKinds.MLDSA65, 0, true);
        (bool ok, bytes memory ret) = _gen(h, _book(h, _voEntry(UAKinds.MLDSA65, v, 250_000, 0)));
        assertTrue(ok, "deployGen");
        (address r, string memory json) = abi.decode(ret, (address, string));
        assertEq(UARegistry(r).generation(), 2);
        assertEq(UARegistry(r).txGasCap(), 1 << 24, "from the book's probed cap");
        assertTrue(UARegistry(r).verifyOnly(UAKinds.MLDSA65) && UARegistry(r).verifierOf(UAKinds.MLDSA65) == v);
        assertTrue(UARegistry(r).kindEnabled(UAKinds.MSIG), "msig re-enabled in full");
        assertFalse(UARegistry(r).kindEnabled(UAKinds.PQZ_MLWE), "no predecessor enables 0x0142");
        assertEq(vm.parseJsonUint(json, ".ua_registry_generation"), 2);
        assertEq(vm.parseJsonBytes32(json, ".ua_registry_codehash"), r.codehash);
        assertEq(vm.parseJsonAddress(json, ".verify_only.0x0131.verifier"), v);
    }

    function test_deploy_notLatest_GEN_NOT_LATEST() public {
        DeployHarness h = new DeployHarness();
        _named(h, _book(h, ',"ua_registry_latest":"0x00000000000000000000000000000000000000aa"'), "GEN_NOT_LATEST");
    }

    function test_deploy_notLatest_ownerOverride() public {
        DeployHarness h = new DeployHarness();
        (bool ok,) = _gen(
            h,
            _book(
                h,
                ',"ua_registry_latest":"0x00000000000000000000000000000000000000aa","owner_override_GEN_NOT_LATEST":"owner: reason"'
            )
        );
        assertTrue(ok, "the owner's override recorded in the book");
    }

    function test_deploy_gen17_GEN_DEPTH() public {
        DeployHarness h = new DeployHarness();
        _named(h, _book(h, ',"ua_registry_generation":16'), "GEN_DEPTH");
    }

    function test_deploy_walkMismatch_codeHash() public {
        DeployHarness h = new DeployHarness();
        string memory b = _book(h, "");
        b = vm.replace(b, vm.parseJsonString(b, ".ua_registry_codehash"), vm.toString(bytes32(uint256(1))));
        _named(h, b, "GEN_WALK_MISMATCH");
    }

    function test_deploy_omits0142_GEN_PQZ_OMITTED() public {
        DeployHarness h = _pqzHarness();
        string memory b = _book(h, "");
        (bool ok, bytes memory ret) = _gen(h, b);
        assertTrue(ok, "positive control: 0x0142 carried");
        (address r,) = abi.decode(ret, (address, string));
        assertTrue(UARegistry(r).kindEnabled(UAKinds.PQZ_MLWE) && !UARegistry(r).verifyOnly(UAKinds.PQZ_MLWE));
        h = _pqzHarness();
        _named(h, _book(h, ',"gen_pqz":false'), "GEN_PQZ_OMITTED");
    }

    function test_deploy_omits0142_ownerOverride() public {
        DeployHarness h = _pqzHarness();
        (bool ok, bytes memory ret) =
            _gen(h, _book(h, ',"gen_pqz":false,"owner_override_GEN_PQZ_OMITTED":"owner: reason"'));
        assertTrue(ok);
        (address r,) = abi.decode(ret, (address, string));
        assertFalse(UARegistry(r).kindEnabled(UAKinds.PQZ_MLWE));
    }

    /// Key form 1 where the home's `mldsa65` verifier is on a precompile (no cache can exist there); key form 0 passes.
    function test_deploy_keyForm1_precompileHome_named() public {
        DeployHarness h = new DeployHarness();
        h.setMldsa(
            true,
            address(0),
            MldsaKit.onChain(1, 0x000000000000000000000000000000005CAa0013, keccak256("scaas.deploy.v1"))
        );
        h.forceMl(false, true);
        string memory b = _book(h, "");
        (bool ok,) = _gen(h, _add(b, _voEntry(UAKinds.MLDSA65, _vo(h, UAKinds.MLDSA65, 0, true), 250_000, 0)));
        assertTrue(ok, "positive control: key form 0");
        _named(
            h,
            _add(b, _voEntry(UAKinds.MLDSA65, _vo(h, UAKinds.MLDSA65, 1, true), 250_000, 1)),
            "GEN_KEY_FORM_IMPOSSIBLE"
        );
    }

    function test_deploy_verifyOnlyNoPrecompile_named() public {
        DeployHarness h = new DeployHarness();
        _named(
            h,
            _book(h, _voEntry(UAKinds.MLDSA65, _vo(h, UAKinds.MLDSA65, 0, false), 250_000, 0)),
            "GEN_VERIFY_ONLY_NO_PRECOMPILE"
        );
    }

    /// M10 d: with 0x0142 on the line, `mldsa87`'s single-key fallback (this cap, the home's cap, the set's debit) over the cap
    /// is refused by name. Over the home's cached path (8.85 M) a 4 M cap is refused at every set, and a precompile-sized cap
    /// fits only where the set's `PQZ_DEBIT_MIN_GAS` leaves room: the test's own figure (the bound spelled out below,
    /// not read from the code under test), n2304-kmax4096 only, and `voDebitFits` must answer the same; over a home on
    /// its precompile (250,000) a precompile-sized cap fits at every set.
    function test_deploy_debitBound_named() public {
        DeployHarness h = _pqzHarness();
        string memory b = _book(h, "");
        address v = _vo(h, UAKinds.MLDSA87, 0, true);
        assertEq(
            UARegistry(vm.parseJsonAddress(b, ".ua_registry")).verifyCap(UAKinds.MLDSA87), 8_850_000, "home cached"
        );
        _named(h, _add(b, _voEntry(UAKinds.MLDSA87, v, 4_000_000, 0)), "GEN_PQZ_DEBIT_BOUND");
        string memory small = _add(b, _voEntry(UAKinds.MLDSA87, v, 150_000, 0));
        // the bound by hand (spec M10 d): w = this cap + one hop (LINE_HOP_GAS 13,100) + VO_READ_GAS 60,000 + the
        // home's cap and its hold (cap / 63) + GAS_MARGIN 5,000; then the walk's hold w / 63, GAS_MARGIN, the set's
        // debit and mldsa87's largest signature as calldata (192 + 4,627 rounded up to a word = 4,832 B, 16 gas a byte;
        // the debit alone at 64 a byte)
        uint256 hc = 8_850_000;
        uint256 w = 150_000 + 13_100 + 60_000 + hc + hc / 63 + 5_000;
        uint256 d = PqzSet.PQZ_DEBIT_MIN_GAS;
        bool fits = w + w / 63 + 5_000 + d + 16 * 4_832 <= 1 << 24 && d + 64 * 4_832 <= 1 << 24;
        assertEq(fits, keccak256(bytes(PqzSet.NAME)) == keccak256("n2304-kmax4096"), "fits at n2304-kmax4096 only");
        bool lib = UARegistryRegLib.voDebitFits(UAKinds.MLDSA87, 150_000, hc, 1, 1 << 24);
        assertEq(lib, fits, "voDebitFits as the bound");
        if (fits) {
            (bool ok0,) = _gen(h, small);
            assertTrue(ok0, "a precompile-sized cap over the cached home, where the set leaves room");
        } else {
            _named(h, small, "GEN_PQZ_DEBIT_BOUND");
        }
        // positive control at every set: the home's mldsa87 on its precompile (the stand-in `_vo` put at the chain's own
        // address is there before this gen 1 is deployed)
        DeployHarness hp = _pqzHarness();
        string memory bp = _book(hp, "");
        assertEq(
            UARegistry(vm.parseJsonAddress(bp, ".ua_registry")).verifyCap(UAKinds.MLDSA87),
            250_000,
            "home on its precompile"
        );
        (bool ok,) = _gen(hp, _add(bp, _voEntry(UAKinds.MLDSA87, _vo(hp, UAKinds.MLDSA87, 0, true), 150_000, 0)));
        assertTrue(ok, "positive control: a precompile-sized cap over a home on its precompile");
    }

    function test_deploy_txGasCap_fromProbe() public {
        DeployHarness h = new DeployHarness();
        string memory b = vm.replace(_book(h, ""), '"tx_gas_cap":16777216', '"tx_gas_cap":30000000');
        (bool ok, bytes memory ret) = _gen(h, b);
        assertTrue(ok);
        (address r,) = abi.decode(ret, (address, string));
        assertEq(UARegistry(r).txGasCap(), 30_000_000);
        _named(h, vm.replace(b, ',"tx_gas_cap":30000000', ""), "GEN_TX_CAP_UNKNOWN");
    }

    // ----- the Draft precompile probe flag (spec §9 CTR-UA-69, owner R9, C5; plan Task 14) -----

    /// A precompile stand-in at the Draft address `0x13` answering the mldsa65 KAT probe (valid 1, every other input 0), lax
    /// (answer 1) on the `lax`-th mutation row (1-based; 0 none).
    function _draft65(uint256 lax) internal {
        string memory kat = vm.readFile("../vectors/ua/pq_kat.json");
        bytes memory valid = vm.parseJsonBytes(kat, ".kinds.mldsa65.eip8355_probe_valid");
        bytes[] memory rows = new bytes[](lax == 0 ? 0 : 1);
        if (lax != 0) {
            string memory m = string.concat(".kinds.mldsa65.mutations[", vm.toString(lax - 1), "]");
            rows[0] = abi.encodePacked(
                vm.parseJsonBytes(kat, string.concat(m, ".pk")),
                vm.parseJsonBytes(kat, string.concat(m, ".sig")),
                keccak256(
                    abi.encodePacked(
                        keccak256("scaas.ua.mldsa65.v1"), vm.parseJsonBytes32(kat, string.concat(m, ".ua_msg"))
                    )
                )
            );
        }
        address at = address(0x13);
        vm.etch(at, address(new PcStandIn()).code);
        PcStandIn(at).set(keccak256(valid), rows, 0, lax == 0 ? 0 : 1);
    }

    function test_candidates_default_noDraft() public {
        DeployHarness h = new DeployHarness();
        address[] memory c = h.mldsaCandidates(1);
        assertEq(c.length, 1);
        assertEq(c[0], address(0x5CAa0013), "the chain's own only");
        _draft65(0);
        assertEq(h.mldsaPrecompileOf(1), address(0), "a Draft address that answers is not probed without the flag");
    }

    function test_candidates_flag_withoutBook_refused() public {
        DeployHarness h = new DeployHarness();
        h.setDraft(true, false);
        vm.expectRevert(
            bytes(
                "DRAFT_PROBE_UNCONFIRMED: chain-uids.json sets probe_draft_precompiles, the book has no probe_draft_precompiles_owner (CTR-UA-69)"
            )
        );
        h.mldsaCandidates(1);
    }

    /// Under the flag and the owner's confirmation the Draft address comes after the chain's own and is taken only when it answers
    /// every row of the fuller probe; one lax mutation row (each in turn) and it is not taken.
    function test_candidates_flag_fullerProbe() public {
        DeployHarness h = new DeployHarness();
        h.setDraft(true, true);
        address[] memory c = h.mldsaCandidates(1);
        assertEq(c.length, 2);
        assertEq(c[0], address(0x5CAa0013));
        assertEq(c[1], address(0x13));
        _draft65(0);
        assertEq(h.mldsaPrecompileOf(1), address(0x13), "every row answered exactly");
        for (uint256 r = 1; r <= 8; ++r) {
            // pq_kat.json's 8 mldsa65 mutation rows
            _draft65(r);
            assertEq(h.mldsaPrecompileOf(1), address(0), string.concat("lax on mutation row ", vm.toString(r)));
        }
    }

    // ----- Task 21 review P2-3, P2-4: the verify-only verifier bound to its rows and the differential probe, its cap to CALL_GAS -----

    /// A verifier built over the flipped row only (no edge rows) is not this build's CREATE2: GEN_VERIFY_ONLY_UNBOUND; the bound
    /// one passes (positive control).
    function test_deploy_voUnbound_named() public {
        DeployHarness h = new DeployHarness();
        string memory b = _book(h, "");
        address good = _vo(h, UAKinds.MLDSA65, 0, true);
        (bool ok,) = _gen(h, _add(b, _voEntry(UAKinds.MLDSA65, good, 250_000, 0)));
        assertTrue(ok, "positive control: the bound verifier");
        string memory kat = vm.readFile("../vectors/ua/pq_kat.json");
        bytes[] memory rows = new bytes[](1);
        rows[0] = vm.parseJsonBytes(kat, ".kinds.mldsa65.eip8355_probe_invalid");
        address[] memory c = new address[](1);
        c[0] = address(0x5CAa0013);
        address bad = _create2(
            abi.encodePacked(
                type(MldsaVerifyOnly65).creationCode,
                abi.encode(c, vm.parseJsonBytes(kat, ".kinds.mldsa65.eip8355_probe_valid"), rows, uint8(0), VO_CALL_GAS)
            )
        );
        _named(h, _add(b, _voEntry(UAKinds.MLDSA65, bad, 250_000, 0)), "GEN_VERIFY_ONLY_UNBOUND");
    }

    /// No differential probe ok for the verifier (absent, or another verifier's): GEN_DIFFERENTIAL_MISSING.
    function test_deploy_voDifferentialMissing_named() public {
        DeployHarness h = new DeployHarness();
        string memory b = _book(h, "");
        address v = _vo(h, UAKinds.MLDSA65, 0, true);
        _named(h, _add(b, _voEntry(UAKinds.MLDSA65, v, 250_000, 0, "")), "GEN_DIFFERENTIAL_MISSING");
        _named(
            h,
            _add(b, _voEntry(UAKinds.MLDSA65, v, 250_000, 0, "ok 0x0000000000000000000000000000000000000001")),
            "GEN_DIFFERENTIAL_MISSING"
        );
    }

    /// A cap below 2 x CALL_GAS + the verifier's own work (140,000 at CALL_GAS 50,000): GEN_VERIFY_ONLY_CAP; at it, deployed.
    function test_deploy_voCapBelowCallGas_named() public {
        DeployHarness h = new DeployHarness();
        string memory b = _book(h, "");
        address v = _vo(h, UAKinds.MLDSA65, 0, true);
        _named(h, _add(b, _voEntry(UAKinds.MLDSA65, v, 139_999, 0)), "GEN_VERIFY_ONLY_CAP");
        (bool ok,) = _gen(h, _add(b, _voEntry(UAKinds.MLDSA65, v, 140_000, 0)));
        assertTrue(ok, "at 2 x CALL_GAS + 40,000");
    }

    /// Task 21 review P2-2: the book of the next generation exists (the line moved past this predecessor): GEN_NOT_LATEST without
    /// any hand-written field; with the owner's override recorded, deployed.
    function test_deploy_newerGenBook_GEN_NOT_LATEST() public {
        DeployHarness h = new DeployHarness();
        string memory b = _book(h, "");
        h.setNewerBook(true);
        _named(h, b, "GEN_NOT_LATEST");
        (bool ok,) = _gen(h, _add(b, ',"owner_override_GEN_NOT_LATEST":"owner: reason"'));
        assertTrue(ok, "the owner's override");
    }
}
