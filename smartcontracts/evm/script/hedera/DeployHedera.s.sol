// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/common/IOpenFactory.sol";
import {MetaToken} from "../../src/metatx/MetaToken.sol";
import {MetaTxDex} from "../../src/dex/MetaTxDex.sol";
import {HederaMetaToken} from "../../src/hedera/HederaMetaToken.sol";
import {OpenFactoryV2} from "../../src/factory/OpenFactoryV2.sol";
import {IOpenFactoryV2} from "../../src/common/IOpenFactoryV2.sol";
import {HederaNoUnderlyingToken, HederaSingleUnderlyingToken, HederaMultiUnderlyingToken}
    from "../../src/hedera/HederaTokensV2.sol";

/// Như `script/Deploy.s.sol` nhưng implementation META là `HederaMetaToken` (R63).
/// Hedera JSON-RPC Relay: `forge script script/hedera/DeployHedera.s.sol --rpc-url $RELAY --broadcast --slow`
/// (relay không có mempool: `--slow` gửi tuần tự, mỗi tx chờ receipt). Deployer = tài khoản ECDSA có alias EVM.
/// env: PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?, DEMO_HOLDER?. Ghi `deployments/hedera-<chainid>.json`.
contract DeployHedera is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address registrar = vm.envOr("REGISTRAR", deployer);
        uint256 demoSupply = vm.envOr("DEMO_SUPPLY", uint256(0));
        address demoHolder = vm.envOr("DEMO_HOLDER", deployer);

        vm.startBroadcast(pk);
        OpenFactory factory = new OpenFactory(registrar);
        HederaMetaToken impl = new HederaMetaToken(address(factory));
        if (registrar == deployer) factory.registerImplementation(IOpenFactory.TokenKind.META, 1, address(impl));
        _deployV2(registrar, registrar == deployer);
        MetaTxDex dex = new MetaTxDex();
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

    /// TW2 §9/§11: factory v2 + ba tầng Hedera, version 1 của từng kind; ghi thẳng vào object JSON "deploy".
    function _deployV2(address registrar, bool register) internal {
        OpenFactoryV2 f = new OpenFactoryV2(registrar);
        address none = address(new HederaNoUnderlyingToken(address(f)));
        address single = address(new HederaSingleUnderlyingToken(address(f)));
        address multi = address(new HederaMultiUnderlyingToken(address(f)));
        if (register) {
            f.registerImplementation(IOpenFactoryV2.TokenKind.META_NONE, 1, none);
            f.registerImplementation(IOpenFactoryV2.TokenKind.META_SINGLE, 1, single);
            f.registerImplementation(IOpenFactoryV2.TokenKind.META_MULTI, 1, multi);
        }
        vm.serializeAddress("deploy", "factory_v2", address(f));
        vm.serializeAddress("deploy", "implementation_meta_none", none);
        vm.serializeAddress("deploy", "implementation_meta_single", single);
        vm.serializeAddress("deploy", "implementation_meta_multi", multi);
    }
}
