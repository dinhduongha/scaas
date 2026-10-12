// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {console} from "forge-std/Script.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {SmartKeyAccountFactory} from "../src/account/SmartKeyAccountFactory.sol";
import {DeployBase} from "./DeployBase.sol";

/// forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --sender <địa chỉ deployer = vm.addr(PRIVATE_KEY)>
/// env: PRIVATE_KEY (deployer; registrar mặc định), REGISTRAR (tuỳ chọn),
///      DEMO_SUPPLY (tuỳ chọn; 0 = không tạo token demo), DEMO_HOLDER (tuỳ chọn, nhận một nửa),
///      DEPLOY_SALT (tuỳ chọn; mặc định keccak256("scaas.deploy.v1"); chạy lại trên cùng chain cần salt mới),
///      CHAIN_UID (genesis hash, chain-uids.json; tuỳ chọn; phải bằng hash block 0 của RPC, mặc định chính hash đó).
///      DEPLOY_ZETHER (tuỳ chọn, true/false; chỉ dev chain; cần cờ forge trong deploy.sh, docs/networks/evm.md).
/// Ghi `deployments/<chainid>.json` (token factory, implementations, the DEX implementation, the SmartKeyAccount
/// factory, `chain_uid`, the demo tokens) để seed client (`blockchain.token`) và config node; a DEX is a clone from
/// `OpenFactory.createDex` (CTR-DEX-24). The v1 line (`OpenFactoryV1`, `MetaToken`, `MetaTxDex`, `SCaaSDexV1`) is in
/// `legacy/p5/` (P5).
contract Deploy is DeployBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address registrar = vm.envOr("REGISTRAR", deployer);
        uint256 demoSupply = vm.envOr("DEMO_SUPPLY", uint256(0));
        address demoHolder = vm.envOr("DEMO_HOLDER", deployer);

        _setup();
        vm.startBroadcast(pk);
        SmartKeyAccountFactory accounts = new SmartKeyAccountFactory{salt: salt}(uid);
        _gate(address(accounts));
        OpenFactory tokens = _deployTokenFactory(registrar, registrar == deployer, accounts.IMPLEMENTATION(), false);
        if (demoSupply != 0 && registrar == deployer) _demoTokens(tokens, demoSupply, deployer, demoHolder);
        vm.stopBroadcast();

        string memory k = "deploy";
        vm.serializeAddress(k, "smart_key_account_factory", address(accounts));
        string memory out = vm.serializeAddress(k, "smart_key_account_implementation", accounts.IMPLEMENTATION());
        vm.createDir("./deployments", true);
        vm.writeJson(out, string.concat("./deployments/", vm.toString(block.chainid), ".json"));
        console.log(out);
    }
}
