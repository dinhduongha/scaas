// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../src/factory/IFactoryToken.sol";
import {AdminLib} from "../src/metatx/AdminLib.sol";
import {IUARegistry} from "../src/ua/IUARegistry.sol";
import {UAKinds} from "../src/ua/UAKinds.sol";
import {ZetherLayer} from "../src/zether/ZetherLayer.sol";
import {ZetherTypes} from "../src/zether/ZetherTypes.sol";

/// @title The token leg of the UA-3 dev-chain e2e (`scripts/e2e-zether.sh`): after `deploy.sh evm` with
///        `DEPLOY_ZETHER=1` and a `zether-bn254` UA registered with a clientkeys PoP, a `NONE_ZETHER` token from the
///        deployed factory shields to it: the token finds the UA by `registry.kindOf` (accounts.md §1.13).
/// @notice env: PRIVATE_KEY (deployer, holds the token's initial supply), ZETHER_Y (the UA's `Y`, 64 bytes).
contract ZetherE2E is Script {
    using stdJson for string;

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        bytes memory y = vm.envBytes("ZETHER_Y");
        string memory j = vm.readFile(string.concat("./deployments/", vm.toString(block.chainid), ".json"));
        IUARegistry reg = IUARegistry(j.readAddress(".ua_registry"));
        ZetherTypes.UA ua = ZetherTypes.toUA(y);
        require(reg.kindOf(ZetherTypes.UA.unwrap(ua)) == UAKinds.ZETHER_BN254, "the Zether UA is not registered");
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features) = ("Zether E2E", "zE2E", 6, 1 << AdminLib.PAYABLE);
        (c.initialSupply, c.initialHolder) = (1_000_000, vm.addr(pk));
        // version 1 of NONE_ZETHER is the bn254 release (CTR-ZTH-20); the creator names no verifier
        c.conf = IFactoryToken.ConfidentialConfig("", 1, 1 << 40, 0, 0, 0, 0);
        vm.startBroadcast(pk);
        ZetherLayer t = ZetherLayer(
            OpenFactory(j.readAddress(".token_factory")).createToken(
                IOpenFactory.TokenKind.NONE_ZETHER, 1, abi.encode(c), keccak256("scaas.e2e.zether")
            )
        );
        t.zetherShield(y, 1234);
        vm.stopBroadcast();
        require(t.registry() == address(reg) && t.registered(ua), "registered by kindOf");
        require(t.accountState(ua).pendingSeq == 1 && t.totalShielded() == 1234, "shielded");
        console.log("zether token", address(t));
    }
}
