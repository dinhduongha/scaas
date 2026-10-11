// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployBase} from "../../script/DeployBase.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {UniversalAccountRegistry} from "../../src/registry/UniversalAccountRegistry.sol";
import {ZetherDisclosure} from "../../src/zether/ZetherDisclosure.sol";
import {ZetherStatements} from "../../src/zether/ZetherStatements.sol";
import {ZetherVerifierBn254, ZetherVerifierBls12381} from "../../src/zether/ZetherVerifier.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {NoUnderlyingZetherToken} from "../../src/zether/NoUnderlyingZetherToken.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {ZUID} from "./helpers/ZetherFixture.sol";

/// The deploy steps without the RPC parts (`_setup`): the salt, `chain_uid` and `DEPLOY_ZETHER` set directly.
contract DeployHarness is DeployBase {
    function deploy(bytes32 uid_, bool zether, address ska) external returns (OpenFactory f, string memory json) {
        salt = keccak256("scaas.deploy.v1");
        uid = uid_;
        deployZether = zether;
        f = _deployTokenFactory(address(this), true, ska, false);
        json = vm.serializeBytes32("deploy", "chain_uid", uid);
    }
}

/// @notice `DeployBase` with `DEPLOY_ZETHER` on a dev chain deploys and registers the Zether stack (kinds 2 and 3, the
///         gate on); without it (the default) or on any other chain (the e2e's 319xx, Hedera's 298) none of it.
contract ZetherDeployTest is Test {
    /// EIP-7825 (Osaka): the per-transaction gas cap.
    uint256 constant TX_GAS_CAP = 1 << 24;
    address ska = new SmartKeyAccountFactory(ZUID).IMPLEMENTATION();

    function _at(DeployHarness h, bytes memory initCode) internal pure returns (address) {
        return vm.computeCreate2Address(keccak256("scaas.deploy.v1"), keccak256(initCode), address(h));
    }

    function test_devChain_registersBothConfidentialKinds() public {
        DeployHarness h = new DeployHarness();
        (OpenFactory f, string memory json) = h.deploy(ZUID, true, ska);
        assertTrue(f.zetherEnabled());
        NoUnderlyingZetherToken none = NoUnderlyingZetherToken(f.implementationOf(IOpenFactory.TokenKind.NONE_ZETHER, 1));
        UnderlyingZetherToken und =
            UnderlyingZetherToken(payable(f.implementationOf(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1)));
        assertEq(none.kind(), AdminLib.KIND_NONE_ZETHER);
        assertEq(und.kind(), AdminLib.KIND_UNDERLYING_ZETHER);
        address reg = _at(h, type(UniversalAccountRegistry).creationCode);
        address dis = _at(h, type(ZetherDisclosure).creationCode);
        address bn = _at(h, type(ZetherVerifierBn254).creationCode);
        assertEq(none.registry(), reg);
        assertEq(address(und.disclosure()), dis);
        assertEq(none.SMART_KEY_ACCOUNT_IMPL(), ska);
        assertEq(und.SMART_KEY_ACCOUNT_IMPL(), ska);
        // the JSON keys the node and Odoo read
        assertEq(vm.parseJsonAddress(json, ".zether_registry"), reg);
        assertEq(vm.parseJsonAddress(json, ".zether_disclosure"), dis);
        assertEq(vm.parseJsonAddress(json, ".zether_statements"), _at(h, type(ZetherStatements).creationCode));
        assertEq(vm.parseJsonAddress(json, ".zether_verifier_bn254"), bn);
        assertEq(vm.parseJsonAddress(json, ".zether_verifier_bls12381"), _at(h, type(ZetherVerifierBls12381).creationCode));
        assertEq(vm.parseJsonAddress(json, ".implementation_none_zether"), address(none));
        assertEq(vm.parseJsonAddress(json, ".implementation_underlying_zether"), address(und));
        // a token from the deployed catalogue, on the deployed verifier
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features) = ("Z", "Z", 6, 1 << AdminLib.PAYABLE);
        c.conf = IFactoryToken.ConfidentialConfig(bn, "", 1, 1 << 40, 0);
        ZetherLayer t = ZetherLayer(f.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, c, "z"));
        assertEq(address(t.verifier()), bn);
        assertEq(t.chainUid(), ZUID);
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
        bytes memory zArgs = abi.encode(address(this), ska, ZUID, address(new UniversalAccountRegistry()),
            address(new ZetherDisclosure()));
        bytes[7] memory codes = [
            type(UniversalAccountRegistry).creationCode,
            type(ZetherDisclosure).creationCode,
            type(ZetherStatements).creationCode,
            type(ZetherVerifierBn254).creationCode,
            type(ZetherVerifierBls12381).creationCode,
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
