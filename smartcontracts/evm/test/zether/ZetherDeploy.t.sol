// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
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
import {NoUnderlyingZetherToken} from "../../src/zether/NoUnderlyingZetherToken.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {ZUID} from "./helpers/ZetherFixture.sol";
import {zetherEnv} from "../helpers/Catalogue.sol";

/// @notice `DeployBase` with `DEPLOY_ZETHER` on a dev chain deploys and registers the Zether stack (kinds 2 and 3, the
///         gate on); without it (the default) or on any other chain (the e2e's 319xx, Hedera's 298) none of it.
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
            IFactoryToken.Env memory e = f.envOf(IOpenFactory.TokenKind(k), c + 1);
            assertEq(rel.envHash, keccak256(abi.encode(e)));
            assertEq(e.deps[0], tv);
            assertEq(e.deps[1], bv);
            assertEq(e.deps[2], ip);
            assertEq(e.deps[3], _at(h, type(ZetherDisclosure).creationCode));
            assertEq(e.libs.length, k == 2 ? 5 : 6); // NONE_ZETHER: no UnderlyingLib
            for (uint256 i; i < e.libs.length; ++i) assertEq(e.libCodeHashes[i], e.libs[i].codehash);
        }
        assertEq(vm.parseJsonAddress(json, string.concat(".zether_verifier_", key)), tv);
        assertEq(vm.parseJsonAddress(json, string.concat(".zether_burn_verifier_", key)), bv);
        assertEq(vm.parseJsonAddress(json, string.concat(".zether_inner_product_verifier_", key)), ip);
        for (uint8 k = 2; k <= 3; ++k) {
            ZetherLayer rel = ZetherLayer(f.implementationOf(IOpenFactory.TokenKind(k), c + 1));
            assertEq(rel.curve(), "bls12-381");
            assertEq(address(rel.verifier()), tv);
            assertEq(address(rel.burnVerifier()), bv);
        }
        assertEq(vm.parseJsonAddress(json, string.concat(".implementation_none_zether_", key)),
            f.implementationOf(IOpenFactory.TokenKind.NONE_ZETHER, c + 1));
        assertEq(vm.parseJsonAddress(json, string.concat(".implementation_underlying_zether_", key)),
            f.implementationOf(IOpenFactory.TokenKind.UNDERLYING_ZETHER, c + 1));
    }

    function test_devChain_registersBothConfidentialKinds() public {
        DeployHarness h = new DeployHarness();
        (OpenFactory f, string memory json) = h.deploy(ZUID, true, ska);
        assertTrue(f.kindEnabled(IOpenFactory.TokenKind.NONE_ZETHER));
        assertTrue(f.kindEnabled(IOpenFactory.TokenKind.UNDERLYING_ZETHER));
        NoUnderlyingZetherToken none = NoUnderlyingZetherToken(f.implementationOf(IOpenFactory.TokenKind.NONE_ZETHER, 1));
        UnderlyingZetherToken und =
            UnderlyingZetherToken(payable(f.implementationOf(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1)));
        // CTR-ZTH-20: one release per kind on the canonical verifiers, the curve an attribute of the release (`curve()`)
        address tv = _checkCurve(f, h, json);
        assertEq(none.kind(), AdminLib.KIND_NONE_ZETHER);
        assertEq(und.kind(), AdminLib.KIND_UNDERLYING_ZETHER);
        address reg = vm.parseJsonAddress(json, ".ua_registry");
        assertEq(vm.parseJsonAddress(json, ".zether_registry"), reg, "the same registry");
        assertFalse(IUARegistry(reg).kindEnabled(0x0140), "zether-bn254 is in legacy/ua6/");
        assertTrue(IUARegistry(reg).kindEnabled(UAKinds.ZETHER_BLS12381));
        assertEq(IUARegistry(reg).chainUid(), ZUID);
        assertEq(IUARegistry(reg).verifyBudget(), 12_000_000);
        address dis = _at(h, type(ZetherDisclosure).creationCode);
        assertEq(none.registry(), reg);
        assertEq(address(und.disclosure()), dis);
        assertEq(none.SMART_KEY_ACCOUNT_IMPL(), ska);
        assertEq(und.SMART_KEY_ACCOUNT_IMPL(), ska);
        // the JSON keys the node and Odoo read
        assertEq(vm.parseJsonAddress(json, ".zether_disclosure"), dis);
        assertEq(vm.parseJsonAddress(json, ".zether_statements"), _at(h, type(ZetherStatements).creationCode));

        // a token from the deployed catalogue, on the deployed verifier
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features) = ("Z", "Z", 6, 1 << AdminLib.PAYABLE);
        c.conf = IFactoryToken.ConfidentialConfig("", 1, 1 << 40, 0, 0, 0, 0);
        ZetherLayer t = ZetherLayer(f.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(c), "z"));
        assertEq(address(t.verifier()), tv);
        assertEq(t.chainUid(), ZUID);
        // minDecoyFee on both layers (owner 2026-10-20): a Zether token takes a non-zero one (bounds: ZetherMulti)
        c.conf.minDecoyFee = 1;
        assertEq(ZetherLayer(f.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(c), "z2")).minDecoyFee(), 1);
    }

    /// Without `DEPLOY_ZETHER` no chain gets the stack (a plain anvil deploys as before P3); with it, a non-dev
    /// chain refuses.
    function test_defaultOrOtherChains_noZether() public {
        uint256[4] memory ids = [uint256(31337), 31901, 298, 7622];
        for (uint256 i; i < ids.length; ++i) {
            vm.chainId(ids[i]);
            DeployHarness h = new DeployHarness();
            (OpenFactory f,) = h.deploy(ZUID, false, ska);
            assertFalse(f.kindEnabled(IOpenFactory.TokenKind.NONE_ZETHER));
            assertEq(f.implementationOf(IOpenFactory.TokenKind.NONE_ZETHER, 1), address(0));
            assertEq(f.implementationOf(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1), address(0));
            assertEq(f.implementationOf(IOpenFactory.TokenKind.NONE, 1) == address(0), false, "the public kinds still");
            if (i == 0) continue;
            h = new DeployHarness();
            vm.expectRevert("DEPLOY_ZETHER: dev chains only (CTR-ZTH-02)");
            h.deploy(ZUID, true, ska);
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
    /// deployer, the releases through `OpenFactory.deployImplementation`, a few k more; gas limit = forge's estimate ×
    /// `--gas-estimate-multiplier 105`) and the anvil's 64 KiB code limit. Tx gas ≈ 21,000 +
    /// calldata + the CREATE2 measured here + the 1/64 the deployer's call holds back; forge's estimate was 1.047× this
    /// figure on anvil (BLS verifier: 14,963,261 vs 14,296,783; 14,083,070 used), hence the first ×1.05.
    function test_zetherStack_fitsOneOsakaTx() public {
        address ip = address(new ZetherInnerProductVerifierBls12381());
        bytes memory ipArg = abi.encode(ip);
        // the factory's append (plan 5g-Z2): abi.encode(envVersion, env, implArgs)
        bytes memory zArgs = abi.encode(uint16(1), zetherEnv(address(this), ZUID, address(this),
            address(new ZetherTransferVerifierBls12381(ZetherInnerProductVerifierBls12381(ip))),
            address(new ZetherBurnVerifierBls12381(ZetherInnerProductVerifierBls12381(ip))), ip,
            address(new ZetherDisclosure())), bytes(""));
        bytes[7] memory codes = [
            type(ZetherDisclosure).creationCode,
            type(ZetherStatements).creationCode,
            type(ZetherInnerProductVerifierBls12381).creationCode,
            abi.encodePacked(type(ZetherTransferVerifierBls12381).creationCode, ipArg),
            abi.encodePacked(type(ZetherBurnVerifierBls12381).creationCode, ipArg),
            abi.encodePacked(type(NoUnderlyingZetherToken).creationCode, zArgs),
            abi.encodePacked(type(UnderlyingZetherToken).creationCode, zArgs)
        ];
        Create2Probe probe = new Create2Probe();
        for (uint256 i; i < codes.length; ++i) {
            bytes memory code = codes[i];
            address a = probe.deploy(code, bytes32(uint256(7)));
            assertTrue(a != address(0), "deploys");
            assertLe(a.code.length, 65536, "anvil --code-size-limit 65536");
            // F185: regular gas with the intrinsic and the calldata (the probe's call is a transaction), x 64/63 for the
            // deployer's call holding back 1/64; the EIP-8037 state gas (code deposit, the new account) comes apart
            Vm.Gas memory vg = vm.lastCallGas();
            uint256 txGas = vg.gasTotalUsed * 64 / 63;
            emit log_named_uint("deploy tx regular gas", txGas);
            emit log_named_uint("deploy tx state gas (EIP-8037)", uint256(int256(vg.gasStateUsed)));
            assertLt(txGas * 105 * 105 / 10_000, TX_GAS_CAP, "regular gas fits EIP-7825 with --gas-estimate-multiplier 105");
            // C5-1: regular + state gas against the budget of the deploy gate (NET-EVM-06): runtime x 1,530 + 2^24
            assertLe(txGas + uint256(int256(vg.gasStateUsed)),
                vm.parseJsonUint(vm.readFile("./size-baseline.json"), ".UnderlyingZetherToken") * 1530 + TX_GAS_CAP,
                "regular + state gas fits the deploy gate's budget");
        }
    }
}
