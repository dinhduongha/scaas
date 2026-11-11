// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalToken} from "../../src/metatx/NormalToken.sol";

import {Test, Vm} from "forge-std/Test.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {TokenStore} from "../../src/metatx/TokenStore.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {ZetherDisclosure} from "../../src/zether/ZetherDisclosure.sol";
import {ZetherStatements} from "../../src/zether/ZetherStatements.sol";
import {
    ZetherInnerProductVerifierBls12381,
    ZetherTransferVerifierBls12381,
    ZetherBurnVerifierBls12381
} from "../../src/zether/ZetherVerifier.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {ZUID} from "./helpers/ZetherFixture.sol";
import {zetherEnv, closureLibs} from "../helpers/Catalogue.sol";
import {kindArgs} from "../../script/KindModules.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {envClosure} from "../helpers/ProbeModules.sol";

/// @notice `DeployBase` with `DEPLOY_ZETHER` deploys and registers the Zether stack (kinds 2 and 3, the gate on) on any
///         chain but Hedera (owner ruling 2026-10-31: no dev-chain allowlist); without it (the default) none of it.
/// F185: a CREATE2 deployer the stack test calls, so each deploy is its own transaction (`isolate`) and
/// `vm.lastCallGas()` splits its regular gas from the EIP-8037 state gas.
contract Create2Probe {
    function deploy(bytes calldata code, bytes32 salt) external returns (address a) {
        bytes memory c = code;
        assembly ("memory-safe") { a := create2(0, add(c, 32), mload(c), salt) }
    }
}

contract ZetherDeployTest is Test {
    /// EIP-7825: the per-transaction gas cap (regular gas only under Amsterdam, EIP-8037).
    uint256 constant TX_GAS_CAP = 1 << 24;
    address ska = new SmartKeyAccountFactory(ZUID).IMPLEMENTATION();

    function _at(DeployHarness h, bytes memory initCode) internal pure returns (address) {
        return vm.computeCreate2Address(keccak256("scaas.deploy.v1"), keccak256(initCode), address(h));
    }

    /// The BLS12-381 canonical set in the factory and the JSON, and its two releases (version 1; the bn254 line is in
    /// `legacy/ua6/`, CTR-ZTH-32); returns its transfer verifier.
    function _checkCurve(OpenFactory f, DeployHarness h, string memory json) internal view returns (address tv) {
        string memory key = "bls12381";
        uint16 c = 0; // version c + 1
        address ip = _at(h, type(ZetherInnerProductVerifierBls12381).creationCode);
        tv = _at(h, abi.encodePacked(type(ZetherTransferVerifierBls12381).creationCode, abi.encode(ip)));
        address bv = _at(h, abi.encodePacked(type(ZetherBurnVerifierBls12381).creationCode, abi.encode(ip)));
        // the env each release was deployed with (plan 5g-Z2): deps = transfer, burn, inner-product verifier, disclosure
        for (uint8 k = 2; k <= 3; ++k) {
            IOpenFactory.Release memory rel = f.releaseOf(IOpenFactory.TokenKind(k), c + 1);
            assertEq(rel.envVersion, c + 1);
            IFactoryToken.Env memory e = f.tokenEnvOf(IOpenFactory.TokenKind(k), c + 1);
            assertEq(rel.envHash, keccak256(abi.encode(e)));
            assertEq(e.deps[0], tv);
            assertEq(e.deps[1], bv);
            assertEq(e.deps[2], ip);
            assertEq(e.deps[3], _at(h, type(ZetherDisclosure).creationCode));
            e = envClosure(e, rel.implementation); // T66b: the release's body modules pinned after its closure
            assertEq(e.libs.length, closureLibs(IOpenFactory.TokenKind(k)).length); // NORMAL_ZETHER: no WrappedLib, no ZetherWrappedLib
            for (uint256 i; i < e.libs.length; ++i) assertEq(e.libCodeHashes[i], e.libs[i].codehash);
        }
        assertEq(vm.parseJsonAddress(json, string.concat(".zether_verifier_", key)), tv);
        assertEq(vm.parseJsonAddress(json, string.concat(".zether_burn_verifier_", key)), bv);
        assertEq(vm.parseJsonAddress(json, string.concat(".zether_inner_product_verifier_", key)), ip);
        for (uint8 k = 2; k <= 3; ++k) {
            // chain-neutral releases (plan T72): a release carries no env (its `curve()` has no verifier to ask); the
            // published env names the verifiers, every clone reads them from its code
            NormalZetherToken rel = NormalZetherToken(f.implementationOf(IOpenFactory.TokenKind(k), c + 1));
            assertEq(address(rel.verifier()), address(0));
            assertEq(address(rel.burnVerifier()), address(0));
        }
        assertEq(vm.parseJsonAddress(json, string.concat(".implementation_normal_zether_", key)),
            f.implementationOf(IOpenFactory.TokenKind.NORMAL_ZETHER, c + 1));
        assertEq(vm.parseJsonAddress(json, string.concat(".implementation_wrapped_zether_", key)),
            f.implementationOf(IOpenFactory.TokenKind.WRAPPED_ZETHER, c + 1));
    }

    function test_devChain_registersBothConfidentialKinds() public {
        DeployHarness h = new DeployHarness();
        (OpenFactory f, string memory json) = h.deploy(ZUID, true, ska);
        assertTrue(f.tokenKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER));
        assertTrue(f.tokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_ZETHER));
        NormalZetherToken none = NormalZetherToken(f.implementationOf(IOpenFactory.TokenKind.NORMAL_ZETHER, 1));
        WrappedZetherToken und =
            WrappedZetherToken(payable(f.implementationOf(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1)));
        // CTR-ZTH-20: one release per kind on the canonical verifiers, the curve an attribute of the release (`curve()`)
        address tv = _checkCurve(f, h, json);
        assertEq(none.kind(), TokenStore.KIND_NORMAL_ZETHER);
        assertEq(und.kind(), TokenStore.KIND_WRAPPED_ZETHER);
        address reg = vm.parseJsonAddress(json, ".ua_registry");
        assertEq(vm.parseJsonAddress(json, ".zether_registry"), reg, "the same registry");
        assertFalse(IUARegistry(reg).kindEnabled(0x0140), "zether-bn254 is in legacy/ua6/");
        assertTrue(IUARegistry(reg).kindEnabled(UAKinds.ZETHER_BLS12381));
        assertEq(IUARegistry(reg).chainUid(), ZUID);
        assertEq(IUARegistry(reg).verifyBudget(), 12_000_000);
        address dis = _at(h, type(ZetherDisclosure).creationCode);
        // chain-neutral releases (plan T72): the releases carry no env; the published envs name them, every clone reads them
        assertEq(none.registry(), address(0), "a release carries no env");
        assertEq(f.tokenEnvOf(IOpenFactory.TokenKind.NORMAL_ZETHER, 1).registry, reg);
        assertEq(f.tokenEnvOf(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1).deps[3], dis);
        assertEq(f.tokenEnvOf(IOpenFactory.TokenKind.NORMAL_ZETHER, 1).smartKeyAccountImpl, ska);
        assertEq(f.tokenEnvOf(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1).smartKeyAccountImpl, ska);
        assertEq(address(und.disclosure()), address(0));
        // the JSON keys the node and Odoo read
        assertEq(vm.parseJsonAddress(json, ".zether_disclosure"), dis);
        assertEq(vm.parseJsonAddress(json, ".zether_statements"), _at(h, type(ZetherStatements).creationCode));

        // a token from the deployed catalogue, on the deployed verifier
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features) = ("Z", "Z", 6, 1 << GovernanceBits.PAYABLE);
        c.conf = IFactoryToken.ConfidentialConfig("", 1, 1 << 40, 0, 0, 0, 0, 0, bytes32(0), false, 0);
        NormalZetherToken t = NormalZetherToken(f.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "z"));
        assertEq(address(t.verifier()), tv);
        assertEq(t.curve(), "bls12-381");
        assertEq(t.chainUid(), ZUID);
        assertEq(t.registry(), reg, "the clone's env");
        assertEq(address(t.disclosure()), dis);
        assertEq(NormalToken(address(t)).SMART_KEY_ACCOUNT_IMPL(), ska);
        // minDecoyFee on both layers (owner 2026-10-20): a Zether token takes a non-zero one (bounds: ZetherMulti)
        c.conf.minDecoyFee = 1;
        assertEq(NormalZetherToken(f.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "z2")).minDecoyFee(), 1);
    }

    /// Q4 (CTR-MTX-30, R40), ua-mtx-merge T10: on a chain that declares the public gate the two Zether releases are each
    /// measured as their own transaction through `deployTokenImplementation` and asked below their testnet formula.
    function test_publicGateMeasuresBothZetherReleases() public {
        DeployHarness h = new DeployHarness();
        h.setGate(2);
        h.limitBlockGas(type(uint64).max);
        (OpenFactory f,) = h.deploy(ZUID, true, ska);
        string[2] memory names = ["NormalZetherToken", "WrappedZetherToken"];
        for (uint8 k = 2; k <= 3; ++k) {
            (uint256 regular, uint256 state) = h.measured(names[k - 2]);
            assertGt(regular, 0, names[k - 2]);
            assertGe(state, f.implementationOf(IOpenFactory.TokenKind(k), 1).code.length * 1530, "the code deposit is in it");
            assertLt((regular + state) * 105 / 100, h.gasNeed(names[k - 2]), "below the testnet formula");
        }
    }

    /// Without `DEPLOY_ZETHER` no chain gets the stack (a plain anvil deploys as before P3); with it the SCaaS testnet
    /// 7622 and the mainnet 22776 get it (owner ruling 2026-10-31, CTR-ZTH-02 superseded, `test_testnetAndMainnet_…`)
    /// and Hedera refuses `DEPLOY_ZETHER`.
    function test_defaultNoZether_hederaRefusesZether() public {
        uint256[4] memory ids = [uint256(31337), 31901, 298, 7622];
        for (uint256 i; i < ids.length; ++i) {
            vm.chainId(ids[i]);
            DeployHarness h = new DeployHarness();
            (OpenFactory f,) = h.deploy(ZUID, false, ska);
            assertFalse(f.tokenKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER));
            assertEq(f.implementationOf(IOpenFactory.TokenKind.NORMAL_ZETHER, 1), address(0));
            assertEq(f.implementationOf(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1), address(0));
            assertEq(f.implementationOf(IOpenFactory.TokenKind.NORMAL, 1) == address(0), false, "the public kinds still");
        }
        vm.chainId(298);
        DeployHarness hh = new DeployHarness();
        vm.expectRevert("DEPLOY_ZETHER: not on Hedera (ZetherLayer refuses a Hedera env)");
        hh.deploy(ZUID, true, ska, true);
    }

    function test_testnetAndMainnet_registerZether() public {
        uint256[2] memory ids = [uint256(7622), 22776];
        for (uint256 i; i < ids.length; ++i) {
            vm.chainId(ids[i]);
            DeployHarness h = new DeployHarness();
            (OpenFactory f, string memory json) = h.deploy(ZUID, true, ska);
            assertTrue(f.tokenKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER));
            assertTrue(f.tokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_ZETHER));
            _checkCurve(f, h, json);
            assertTrue(IUARegistry(vm.parseJsonAddress(json, ".ua_registry")).kindEnabled(UAKinds.ZETHER_BLS12381));
            IFactoryToken.TokenConfig memory c;
            (c.name, c.symbol, c.decimals, c.features) = ("Z", "Z", 6, 1 << GovernanceBits.PAYABLE);
            c.conf = IFactoryToken.ConfidentialConfig("", 1, 1 << 40, 0, 0, 0, 0, 0, bytes32(0), false, 0);
            assertTrue(f.isRegisteredToken(f.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "z")));
        }
    }

    /// `NOTICE_PERIOD` (owner ruling 2026-10-20, review 5g-Z2 P2-4): safe by default — every chain outside the fixed
    /// test / dev list is a mainnet, default and floor 3 days; 7622 defaults to 10 minutes, the other test chains to 0;
    /// a value over `uint64` is refused, never truncated.
    function test_noticePeriod_mainnetFloorAndDefaults() public {
        DeployHarness h = new DeployHarness();
        uint256[8] memory test = [uint256(31337), 1337, 31950, 7622, 296, 298, 11155111, 97];
        for (uint256 i; i < test.length; ++i) {
            assertEq(h.defaultNotice(test[i]), test[i] == 7622 ? 10 minutes : 0);
            assertEq(h.noticeFor(test[i], 0), 0);
        }
        uint256[6] memory main = [uint256(22776), 295, 1, 56, 100, 987654321]; // the last: an unknown chain
        for (uint256 i; i < main.length; ++i) {
            assertEq(h.defaultNotice(main[i]), 3 days);
            assertEq(h.noticeFor(main[i], 3 days), 3 days);
            vm.expectRevert("NOTICE_PERIOD below 3 days on a mainnet (not a listed test chain)");
            h.noticeFor(main[i], 3 days - 1);
        }
        vm.expectRevert("NOTICE_PERIOD exceeds uint64");
        h.noticeFor(7622, uint256(type(uint64).max) + 1);
    }

    /// Each Zether-stack deploy fits one Osaka transaction as `deploy.sh` sends it (the verifiers through the CREATE2
    /// deployer, the releases through `OpenFactory.deployTokenImplementation`, a few k more; gas limit = forge's estimate ×
    /// `--gas-estimate-multiplier 105`) and the anvil's 64 KiB code limit. Tx gas ≈ 21,000 +
    /// calldata + the CREATE2 measured here + the 1/64 the deployer's call holds back; forge's estimate was 1.047× this
    /// figure on anvil (BLS verifier: 14,963,261 vs 14,296,783; 14,083,070 used), hence the first ×1.05.
    function test_zetherStack_fitsOneOsakaTx() public {
        address ip = address(new ZetherInnerProductVerifierBls12381());
        bytes memory ipArg = abi.encode(ip);
        // the factory's append (chain-neutral releases, plan T72): abi.encode(factory, implArgs); the env is the clones'
        // T66b: each kind's `implArgs` names its body modules (deployed here for this factory, their own transactions)
        bytes memory zArgs = abi.encode(address(this), kindArgs(2, address(this), ""));
        bytes memory wArgs = abi.encode(address(this), kindArgs(3, address(this), ""));
        bytes[7] memory codes = [
            type(ZetherDisclosure).creationCode,
            type(ZetherStatements).creationCode,
            type(ZetherInnerProductVerifierBls12381).creationCode,
            abi.encodePacked(type(ZetherTransferVerifierBls12381).creationCode, ipArg),
            abi.encodePacked(type(ZetherBurnVerifierBls12381).creationCode, ipArg),
            abi.encodePacked(type(NormalZetherToken).creationCode, zArgs),
            abi.encodePacked(type(WrappedZetherToken).creationCode, wArgs)
        ];
        Create2Probe probe = new Create2Probe();
        for (uint256 i; i < codes.length; ++i) {
            bytes memory code = codes[i];
            address a = probe.deploy(code, bytes32(uint256(7)));
            assertTrue(a != address(0), "deploys");
            assertLe(a.code.length, 131_072, "anvil --code-size-limit 131072 (CTR-GOV-19)");
            // F185: regular gas with the intrinsic and the calldata (the probe's call is a transaction), x 64/63 for the
            // deployer's call holding back 1/64; the EIP-8037 state gas (code deposit, the new account) comes apart
            Vm.Gas memory vg = vm.lastCallGas();
            uint256 txGas = vg.gasTotalUsed * 64 / 63;
            emit log_named_uint("deploy tx regular gas", txGas);
            emit log_named_uint("deploy tx state gas (EIP-8037)", uint256(int256(vg.gasStateUsed)));
            assertLt(txGas * 105 * 105 / 10_000, TX_GAS_CAP, "regular gas fits EIP-7825 with --gas-estimate-multiplier 105");
            // C5-1: regular + state gas against the budget of the deploy gate (NET-EVM-06): runtime x 1,530 + 2^24
            assertLe(txGas + uint256(int256(vg.gasStateUsed)),
                vm.parseJsonUint(vm.readFile("./size-baseline.json"), ".WrappedZetherToken") * 1530 + TX_GAS_CAP,
                "regular + state gas fits the deploy gate's budget");
        }
    }
}
