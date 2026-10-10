// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {console} from "forge-std/Script.sol";
import {OpenFactoryV1} from "../../src/factory/OpenFactoryV1.sol";
import {IOpenFactoryV1} from "../../src/common/IOpenFactoryV1.sol";
import {MetaToken} from "../../src/metatx/MetaToken.sol";
import {MetaTxDex} from "../../src/dex/MetaTxDex.sol";
import {HederaMetaToken} from "../../src/hedera/HederaMetaToken.sol";
import {DeployBase} from "../DeployBase.sol";

/// Như `script/Deploy.s.sol` nhưng implementation META là `HederaMetaToken` (R63).
/// Hedera JSON-RPC Relay: `forge script script/hedera/DeployHedera.s.sol --rpc-url $RELAY --broadcast --slow`
/// (relay không có mempool: `--slow` gửi tuần tự, mỗi tx chờ receipt). Deployer = tài khoản ECDSA có alias EVM.
/// env: PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?, DEMO_HOLDER?, CHAIN_UID? (mặc định blockhash(0)).
/// Ghi `deployments/hedera-<chainid>.json`.
contract DeployHedera is DeployBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address registrar = vm.envOr("REGISTRAR", deployer);
        uint256 demoSupply = vm.envOr("DEMO_SUPPLY", uint256(0));
        address demoHolder = vm.envOr("DEMO_HOLDER", deployer);

        _setup();
        vm.startBroadcast(pk);
        OpenFactoryV1 factory = new OpenFactoryV1{salt: salt}(registrar);
        HederaMetaToken impl = new HederaMetaToken{salt: salt}(address(factory));
        if (registrar == deployer) factory.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl));
        _deployTokenFactory(registrar, registrar == deployer, address(0), true);
        MetaTxDex dex = new MetaTxDex{salt: salt}();
        address demo;
        address demo2;
        if (demoSupply != 0 && registrar == deployer) {
            demo = factory.createMetaToken(1, address(0),
                abi.encode("SCaaS Demo USD", "bUSD", uint8(6), demoSupply, deployer), bytes32("demo"));
            demo2 = factory.createMetaToken(1, address(0),
                abi.encode("SCaaS Demo Points", "bPTS", uint8(6), demoSupply, deployer), bytes32("demo2"));
            if (demoHolder != deployer) {
                MetaToken(demo).transfer(demoHolder, demoSupply / 2);
                MetaToken(demo2).transfer(demoHolder, demoSupply / 2);
            }
        }
        vm.stopBroadcast();

        string memory k = "deploy";
        vm.serializeAddress(k, "factory", address(factory));
        vm.serializeAddress(k, "implementation", address(impl));
        vm.serializeAddress(k, "dex", address(dex));
        vm.serializeAddress(k, "demo_token_2", demo2);
        string memory out = vm.serializeAddress(k, "demo_token", demo);
        vm.writeJson(out, string.concat("./deployments/hedera-", vm.toString(block.chainid), ".json"));
        console.log(out);
    }
}
