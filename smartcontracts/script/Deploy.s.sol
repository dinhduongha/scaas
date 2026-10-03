// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/common/IOpenFactory.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxDex} from "../src/dex/MetaTxDex.sol";
import {OrderBookDex} from "../src/dex/OrderBookDex.sol";

/// forge script script/Deploy.s.sol --rpc-url $RPC --broadcast
/// env: PRIVATE_KEY (deployer; registrar mặc định), REGISTRAR (tuỳ chọn),
///      DEMO_SUPPLY (tuỳ chọn; 0 = không tạo token demo), DEMO_HOLDER (tuỳ chọn, nhận một nửa).
/// Ghi `deployments/<chainid>.json` để seed Odoo (`blockchain.token`) và config node (`dex`).
contract Deploy is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address registrar = vm.envOr("REGISTRAR", deployer);
        uint256 demoSupply = vm.envOr("DEMO_SUPPLY", uint256(0));
        address demoHolder = vm.envOr("DEMO_HOLDER", deployer);

        vm.startBroadcast(pk);
        OpenFactory factory = new OpenFactory(registrar);
        MetaToken impl = new MetaToken(address(factory));
        if (registrar == deployer) factory.registerImplementation(IOpenFactory.TokenKind.META, 1, address(impl));
        MetaTxDex dex = new MetaTxDex();
        // R35: admin chỉ `setMarket`; production đặt REGISTRAR là một Safe (RS5-1).
        OrderBookDex obDex = new OrderBookDex(registrar);
        address demo;
        if (demoSupply != 0 && registrar == deployer) {
            demo = factory.createMetaToken(1, address(0),
                abi.encode("Bamboo Demo USD", "bUSD", uint8(6), demoSupply, deployer), bytes32("demo"));
            if (demoHolder != deployer) MetaToken(demo).transfer(demoHolder, demoSupply / 2);
        }
        vm.stopBroadcast();

        string memory k = "deploy";
        vm.serializeAddress(k, "factory", address(factory));
        vm.serializeAddress(k, "implementation", address(impl));
        vm.serializeAddress(k, "dex", address(dex));
        vm.serializeAddress(k, "order_book_dex", address(obDex));
        string memory out = vm.serializeAddress(k, "demo_token", demo);
        vm.writeJson(out, string.concat("./deployments/", vm.toString(block.chainid), ".json"));
        console.log(out);
    }
}
