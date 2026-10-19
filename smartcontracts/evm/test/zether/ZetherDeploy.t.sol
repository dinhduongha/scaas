// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
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
    ZetherInnerProductVerifierBn254,
    ZetherTransferVerifierBn254,
    ZetherBurnVerifierBn254,
    ZetherInnerProductVerifierBls12381,
    ZetherTransferVerifierBls12381,
    ZetherBurnVerifierBls12381
} from "../../src/zether/ZetherVerifier.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {NoUnderlyingZetherToken} from "../../src/zether/NoUnderlyingZetherToken.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {ZUID} from "./helpers/ZetherFixture.sol";

/// @notice `DeployBase` with `DEPLOY_ZETHER` on a dev chain deploys and registers the Zether stack (kinds 2 and 3, the
///         gate on); without it (the default) or on any other chain (the e2e's 319xx, Hedera's 298) none of it.
contract ZetherDeployTest is Test {
    /// EIP-7825 (Osaka): the per-transaction gas cap.
    uint256 constant TX_GAS_CAP = 1 << 24;
    address ska = new SmartKeyAccountFactory(ZUID).IMPLEMENTATION();

    function _at(DeployHarness h, bytes memory initCode) internal pure returns (address) {
        return vm.computeCreate2Address(keccak256("scaas.deploy.v1"), keccak256(initCode), address(h));
    }

    /// Curve `c`'s canonical set in the factory and the JSON, and its two releases; returns its transfer verifier.
    function _checkCurve(OpenFactory f, DeployHarness h, string memory json, uint8 c) internal view returns (address tv) {
        string memory key = c == 0 ? "bn254" : "bls12381";
        address ip = _at(h, c == 0 ? type(ZetherInnerProductVerifierBn254).creationCode
            : type(ZetherInnerProductVerifierBls12381).creationCode);
        tv = _at(h, abi.encodePacked(c == 0 ? type(ZetherTransferVerifierBn254).creationCode
            : type(ZetherTransferVerifierBls12381).creationCode, abi.encode(ip)));
        address bv = _at(h, abi.encodePacked(c == 0 ? type(ZetherBurnVerifierBn254).creationCode
            : type(ZetherBurnVerifierBls12381).creationCode, abi.encode(ip)));
        (address t_, address b_, address d_) = f.zetherVerifiers(c);
        assertEq(t_, tv);
        assertEq(b_, bv);
        assertEq(d_, _at(h, type(ZetherDisclosure).creationCode));
        assertEq(vm.parseJsonAddress(json, string.concat(".zether_verifier_", key)), tv);
        assertEq(vm.parseJsonAddress(json, string.concat(".zether_burn_verifier_", key)), bv);
        assertEq(vm.parseJsonAddress(json, string.concat(".zether_inner_product_verifier_", key)), ip);
        for (uint8 k = 2; k <= 3; ++k) {
            ZetherLayer rel = ZetherLayer(f.implementationOf(IOpenFactory.TokenKind(k), c + 1));
            assertEq(rel.curve(), c == 0 ? "bn254" : "bls12-381");
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
        assertTrue(f.zetherEnabled());
        NoUnderlyingZetherToken none = NoUnderlyingZetherToken(f.implementationOf(IOpenFactory.TokenKind.NONE_ZETHER, 1));
        UnderlyingZetherToken und =
            UnderlyingZetherToken(payable(f.implementationOf(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1)));
        // CTR-ZTH-20: the factory fixed the canonical verifiers in its constructor; one release per curve and kind, the
        // curve an attribute of the release (`curve()`), not of the version number
        address[2] memory tv = [_checkCurve(f, h, json, 0), _checkCurve(f, h, json, 1)];
        assertEq(none.kind(), AdminLib.KIND_NONE_ZETHER);
        assertEq(und.kind(), AdminLib.KIND_UNDERLYING_ZETHER);
        address reg = vm.parseJsonAddress(json, ".ua_registry");
        assertEq(vm.parseJsonAddress(json, ".zether_registry"), reg, "the same registry");
        assertTrue(IUARegistry(reg).kindEnabled(UAKinds.ZETHER_BN254));
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
        c.conf = IFactoryToken.ConfidentialConfig(address(0), "", 1, 1 << 40, 0, 0, 0, 0);
        ZetherLayer t = ZetherLayer(f.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, c, "z"));
        assertEq(address(t.verifier()), tv[0]);
        assertEq(t.chainUid(), ZUID);
        // multiLegFee is PQZ's (op 7, CTR-PQZ-25): a Zether token refuses a non-zero one
        c.conf.multiLegFee = 1;
        vm.expectRevert();
        f.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, c, "z2");
    }

    /// Without `DEPLOY_ZETHER` no chain gets the stack (a plain anvil deploys as before P3); with it, a non-dev
    /// chain refuses.
    function test_defaultOrOtherChains_noZether() public {
        uint256[4] memory ids = [uint256(31337), 31901, 298, 7622];
        for (uint256 i; i < ids.length; ++i) {
            vm.chainId(ids[i]);
            DeployHarness h = new DeployHarness();
            (OpenFactory f,) = h.deploy(ZUID, false, ska);
            assertFalse(f.zetherEnabled());
            assertEq(f.implementationOf(IOpenFactory.TokenKind.NONE_ZETHER, 1), address(0));
            assertEq(f.implementationOf(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1), address(0));
            assertEq(f.implementationOf(IOpenFactory.TokenKind.NONE, 1) == address(0), false, "the public kinds still");
            if (i == 0) continue;
            h = new DeployHarness();
            vm.expectRevert("DEPLOY_ZETHER: dev chains only (CTR-ZTH-02)");
            h.deploy(ZUID, true, ska);
        }
    }

    /// Each Zether-stack deploy fits one Osaka transaction as `deploy.sh` sends it (through the CREATE2 deployer, gas
    /// limit = forge's estimate × `--gas-estimate-multiplier 105`) and the anvil's 64 KiB code limit. Tx gas ≈ 21,000 +
    /// calldata + the CREATE2 measured here + the 1/64 the deployer's call holds back; forge's estimate was 1.047× this
    /// figure on anvil (BLS verifier: 14,963,261 vs 14,296,783; 14,083,070 used), hence the first ×1.05.
    function test_zetherStack_fitsOneOsakaTx() public {
        address ip = address(new ZetherInnerProductVerifierBls12381());
        address ipBn = address(new ZetherInnerProductVerifierBn254());
        bytes memory ipArg = abi.encode(ip);
        bytes memory zArgs = abi.encode(address(this), ska, ZUID, address(this), address(new ZetherDisclosure()),
            address(new ZetherTransferVerifierBn254(ZetherInnerProductVerifierBn254(ipBn))),
            address(new ZetherBurnVerifierBn254(ZetherInnerProductVerifierBn254(ipBn))));
        bytes[10] memory codes = [
            type(ZetherDisclosure).creationCode,
            type(ZetherStatements).creationCode,
            type(ZetherInnerProductVerifierBn254).creationCode,
            type(ZetherInnerProductVerifierBls12381).creationCode,
            abi.encodePacked(type(ZetherTransferVerifierBn254).creationCode, abi.encode(ipBn)),
            abi.encodePacked(type(ZetherBurnVerifierBn254).creationCode, abi.encode(ipBn)),
            abi.encodePacked(type(ZetherTransferVerifierBls12381).creationCode, ipArg),
            abi.encodePacked(type(ZetherBurnVerifierBls12381).creationCode, ipArg),
            abi.encodePacked(type(NoUnderlyingZetherToken).creationCode, zArgs),
            abi.encodePacked(type(UnderlyingZetherToken).creationCode, zArgs)
        ];
        for (uint256 i; i < codes.length; ++i) {
            bytes memory code = codes[i];
            uint256 g = gasleft();
            address a;
            assembly ("memory-safe") { a := create2(0, add(code, 32), mload(code), 7) }
            g -= gasleft();
            assertTrue(a != address(0), "deploys");
            assertLe(a.code.length, 65536, "anvil --code-size-limit 65536");
            uint256 data = 32 * 16; // the salt word
            for (uint256 j; j < code.length; ++j) data += code[j] == 0 ? 4 : 16;
            uint256 txGas = 21_000 + data + g * 64 / 63;
            emit log_named_uint("deploy tx gas", txGas);
            assertLt(txGas * 105 * 105 / 10_000, TX_GAS_CAP, "fits EIP-7825 with --gas-estimate-multiplier 105");
        }
    }
}
