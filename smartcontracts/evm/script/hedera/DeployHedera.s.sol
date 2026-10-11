// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {console} from "forge-std/Script.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {DeployBase} from "../DeployBase.sol";

/// Như `script/Deploy.s.sol` trên Hedera (R63): every implementation with `IS_HEDERA` (HIP-632 signatures, CTR-TOK-23),
/// no `SmartKeyAccount` implementation (Hedera accounts are native), two demo tokens.
/// Hedera JSON-RPC Relay: `forge script script/hedera/DeployHedera.s.sol --rpc-url $RELAY --broadcast --slow --sender <địa chỉ deployer>`
/// (relay không có mempool: `--slow` gửi tuần tự, mỗi tx chờ receipt). Deployer = tài khoản ECDSA có alias EVM.
/// env: PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?, DEMO_HOLDER?, CHAIN_UID? (mặc định hash block 0 của RPC),
///      DEPLOY_SALT? (mặc định keccak256("scaas.deploy.v1"); chạy lại trên cùng chain cần salt mới).
/// Ghi `deployments/hedera-<chainid>.json`. The v1 `HederaMetaToken` line is in `legacy/p5/` (P5).
contract DeployHedera is DeployBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address registrar = vm.envOr("REGISTRAR", deployer);
        uint256 demoSupply = vm.envOr("DEMO_SUPPLY", uint256(0));
        address demoHolder = vm.envOr("DEMO_HOLDER", deployer);

        _setup();
        vm.startBroadcast(pk);
        OpenFactory tokens = _deployTokenFactory(registrar, registrar == deployer, address(0), true);
        if (demoSupply != 0 && registrar == deployer) _demoTokens(tokens, demoSupply, deployer, demoHolder);
        vm.stopBroadcast();

        string memory out = vm.serializeString("deploy", "network", "hedera");
        vm.createDir("./deployments", true);
        vm.writeJson(out, string.concat("./deployments/hedera-", vm.toString(block.chainid), ".json"));
        console.log(out);
    }
}
