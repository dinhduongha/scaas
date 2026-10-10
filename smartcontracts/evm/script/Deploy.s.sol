// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {console} from "forge-std/Script.sol";
import {OpenFactoryV1} from "../src/factory/OpenFactoryV1.sol";
import {IOpenFactoryV1} from "../src/common/IOpenFactoryV1.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxDex} from "../src/dex/MetaTxDex.sol";
import {SubjectAccountFactory} from "../src/account/SubjectAccountFactory.sol";
import {SCaaSDex} from "../src/dex/SCaaSDex.sol";
import {DeployBase} from "./DeployBase.sol";

/// forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --sender <địa chỉ deployer = vm.addr(PRIVATE_KEY)>
/// env: PRIVATE_KEY (deployer; registrar mặc định), REGISTRAR (tuỳ chọn),
///      DEMO_SUPPLY (tuỳ chọn; 0 = không tạo token demo), DEMO_HOLDER (tuỳ chọn, nhận một nửa),
///      DEPLOY_SALT (tuỳ chọn; mặc định keccak256("scaas.deploy.v1"); chạy lại trên cùng chain cần salt mới),
///      CHAIN_UID (genesis hash, chain-uids.json; tuỳ chọn; phải bằng hash block 0 của RPC, mặc định chính hash đó).
/// Ghi `deployments/<chainid>.json` để seed Odoo (`blockchain.token`) và config node (`dex`).
contract Deploy is DeployBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address registrar = vm.envOr("REGISTRAR", deployer);
        uint256 demoSupply = vm.envOr("DEMO_SUPPLY", uint256(0));
        address demoHolder = vm.envOr("DEMO_HOLDER", deployer);

        _setup();
        vm.startBroadcast(pk);
        OpenFactoryV1 factory = new OpenFactoryV1{salt: salt}(registrar);
        SubjectAccountFactory accounts = new SubjectAccountFactory{salt: salt}();
        MetaToken impl = new MetaToken{salt: salt}(address(factory), accounts.IMPLEMENTATION());
        if (registrar == deployer) factory.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl));
        _deployTokenFactory(registrar, registrar == deployer, accounts.IMPLEMENTATION(), false);
        MetaTxDex dex = new MetaTxDex{salt: salt}();
        // R35: admin chỉ `setMarket`; production đặt REGISTRAR là một Safe (RS5-1).
        SCaaSDex scaasDex = new SCaaSDex{salt: salt}(registrar);
        address demo;
        if (demoSupply != 0 && registrar == deployer) {
            demo = factory.createMetaToken(1, address(0),
                abi.encode("SCaaS Demo USD", "bUSD", uint8(6), demoSupply, deployer), bytes32("demo"));
            if (demoHolder != deployer) MetaToken(demo).transfer(demoHolder, demoSupply / 2);
        }
        vm.stopBroadcast();

        string memory k = "deploy";
        vm.serializeAddress(k, "factory", address(factory));
        vm.serializeAddress(k, "implementation", address(impl));
        vm.serializeAddress(k, "dex", address(dex));
        vm.serializeAddress(k, "subject_account_factory", address(accounts));
        vm.serializeAddress(k, "subject_account_implementation", accounts.IMPLEMENTATION());
        vm.serializeAddress(k, "scaas_dex", address(scaasDex));
        string memory out = vm.serializeAddress(k, "demo_token", demo);
        vm.createDir("./deployments", true);
        vm.writeJson(out, string.concat("./deployments/", vm.toString(block.chainid), ".json"));
        console.log(out);
    }
}
