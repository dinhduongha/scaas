// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {console} from "forge-std/Script.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {DeployBase} from "../DeployBase.sol";

/// Như `script/Deploy.s.sol` trên Hedera (R63): every implementation with `IS_HEDERA` (HIP-632 signatures, CTR-TOK-23),
/// no `SmartKeyAccount` implementation (Hedera accounts are native), two demo tokens.
/// Hedera JSON-RPC Relay: `forge script script/hedera/DeployHedera.s.sol --rpc-url $RELAY --broadcast --slow --code-size-limit 65536 --sender <địa chỉ deployer>`
/// (relay không có mempool: `--slow` gửi tuần tự, mỗi tx chờ receipt). Deployer = tài khoản ECDSA có alias EVM.
/// env: PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?, DEMO_HOLDER?, CHAIN_UID? (mặc định hash block 0 của RPC),
///      DEPLOY_SALT? (mặc định keccak256("scaas.deploy.v1"); chạy lại trên cùng chain cần salt mới).
/// DEPLOY_NAME (a chain not in chain-uids.json, e.g. a local node: `<name>-testnet`, NET-EVM-13).
/// Ghi `deployments/hedera-<key>.json` (NET-EVM-13: the chain's key, its header first; `family` "hedera"). The v1
/// `HederaMetaToken` line is in `legacy/p5/` (P5).
contract DeployHedera is DeployBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address registrar = vm.envOr("REGISTRAR", deployer);
        uint256 demoSupply = vm.envOr("DEMO_SUPPLY", uint256(0));
        address demoHolder = vm.envOr("DEMO_HOLDER", deployer);

        _setup();
        string memory book = _bookPath(uid, "hedera-", ".json"); // DEPLOY_NAME_REQUIRED before anything is sent
        vm.startBroadcast(pk);
        OpenFactory tokens = _deployTokenFactory(registrar, registrar == deployer, address(0), true);
        if (demoSupply != 0 && registrar == deployer) _demoTokens(tokens, demoSupply, deployer, demoHolder);
        vm.stopBroadcast();

        string memory out = vm.serializeString("deploy", "family", "hedera"); // `network` is the header's (NET-EVM-13)
        vm.createDir("./deployments", true);
        vm.writeFile(book, _bookHeader(uid, out));
        _writeReleases();
        console.log(out);
    }
}
