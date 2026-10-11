// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {console} from "forge-std/Script.sol";
import {OpenFactoryV1} from "../../src/factory/OpenFactoryV1.sol";
import {IOpenFactoryV1} from "../../src/common/IOpenFactoryV1.sol";
import {MetaTxDex} from "../../src/dex/MetaTxDex.sol";
import {HederaMetaToken} from "../../src/hedera/HederaMetaToken.sol";
import {DeployBase} from "../DeployBase.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";

/// Như `script/Deploy.s.sol` nhưng implementation META là `HederaMetaToken` (R63).
/// Hedera JSON-RPC Relay: `forge script script/hedera/DeployHedera.s.sol --rpc-url $RELAY --broadcast --slow --sender <địa chỉ deployer>`
/// (relay không có mempool: `--slow` gửi tuần tự, mỗi tx chờ receipt). Deployer = tài khoản ECDSA có alias EVM.
/// env: PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?, DEMO_HOLDER?, CHAIN_UID? (mặc định hash block 0 của RPC),
///      DEPLOY_SALT? (mặc định keccak256("scaas.deploy.v1"); chạy lại trên cùng chain cần salt mới).
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
        OpenFactory tokens = _deployTokenFactory(registrar, registrar == deployer, address(0), true);
        MetaTxDex dex = new MetaTxDex{salt: salt}();
        if (demoSupply != 0 && registrar == deployer) _demoTokens(tokens, demoSupply, deployer, demoHolder);
        vm.stopBroadcast();

        string memory k = "deploy";
        vm.serializeAddress(k, "factory", address(factory));
        vm.serializeAddress(k, "implementation", address(impl));
        string memory out = vm.serializeAddress(k, "dex", address(dex));
        vm.createDir("./deployments", true);
        vm.writeJson(out, string.concat("./deployments/hedera-", vm.toString(block.chainid), ".json"));
        console.log(out);
    }
}
