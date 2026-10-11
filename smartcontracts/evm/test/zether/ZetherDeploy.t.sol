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
import {ZetherVerifierBn254} from "../../src/zether/ZetherVerifier.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {NoUnderlyingZetherToken} from "../../src/zether/NoUnderlyingZetherToken.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {ZUID} from "./helpers/ZetherFixture.sol";

/// The deploy steps without the RPC parts (`_setup`): the salt and `chain_uid` set directly.
contract DeployHarness is DeployBase {
    function deploy(bytes32 uid_) external returns (OpenFactory) {
        salt = keccak256("scaas.deploy.v1");
        uid = uid_;
        return _deployTokenFactory(address(this), true, address(0), false);
    }
}

/// @notice `DeployBase` on a dev chain deploys and registers the Zether stack (kinds 2 and 3, the gate on); on any
///         other chain (the e2e's 319xx and Hedera's 298 included) it deploys none of it.
contract ZetherDeployTest is Test {
    function _at(DeployHarness h, bytes memory initCode) internal pure returns (address) {
        return vm.computeCreate2Address(keccak256("scaas.deploy.v1"), keccak256(initCode), address(h));
    }

    function test_devChain_registersBothConfidentialKinds() public {
        DeployHarness h = new DeployHarness();
        OpenFactory f = h.deploy(ZUID);
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
        // a token from the deployed catalogue, on the deployed verifier
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features) = ("Z", "Z", 6, 1 << AdminLib.PAYABLE);
        c.conf = IFactoryToken.ConfidentialConfig(bn, "", 1, 1 << 40, 0);
        ZetherLayer t = ZetherLayer(f.createToken(IOpenFactory.TokenKind.NONE_ZETHER, 1, c, "z"));
        assertEq(address(t.verifier()), bn);
        assertEq(t.chainUid(), ZUID);
    }

    function test_otherChains_noZether() public {
        uint256[3] memory ids = [uint256(31901), 298, 7622];
        for (uint256 i; i < ids.length; ++i) {
            vm.chainId(ids[i]);
            DeployHarness h = new DeployHarness();
            OpenFactory f = h.deploy(ZUID);
            assertFalse(f.zetherEnabled());
            assertEq(f.implementationOf(IOpenFactory.TokenKind.NONE_ZETHER, 1), address(0));
            assertEq(f.implementationOf(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1), address(0));
            assertEq(f.implementationOf(IOpenFactory.TokenKind.NONE, 1) == address(0), false, "the public kinds still");
        }
    }
}
