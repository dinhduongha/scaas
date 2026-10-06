// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/common/IOpenFactory.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxDex} from "../src/dex/MetaTxDex.sol";
import {SubjectAccountFactory} from "../src/account/SubjectAccountFactory.sol";
import {OrderBookDex} from "../src/dex/OrderBookDex.sol";
import {OpenFactoryV2} from "../src/factory/OpenFactoryV2.sol";
import {IOpenFactoryV2} from "../src/common/IOpenFactoryV2.sol";
import {NoUnderlyingToken} from "../src/metatx/NoUnderlyingToken.sol";
import {SingleUnderlyingToken} from "../src/metatx/SingleUnderlyingToken.sol";
import {MultiUnderlyingToken} from "../src/metatx/MultiUnderlyingToken.sol";

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
        SubjectAccountFactory accounts = new SubjectAccountFactory();
        MetaToken impl = new MetaToken(address(factory), accounts.IMPLEMENTATION());
        if (registrar == deployer) factory.registerImplementation(IOpenFactory.TokenKind.META, 1, address(impl));
        _deployV2(registrar, registrar == deployer, accounts.IMPLEMENTATION());
        MetaTxDex dex = new MetaTxDex();
        // R35: admin chỉ `setMarket`; production đặt REGISTRAR là một Safe (RS5-1).
        OrderBookDex obDex = new OrderBookDex(registrar);
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
        vm.serializeAddress(k, "order_book_dex", address(obDex));
        string memory out = vm.serializeAddress(k, "demo_token", demo);
        vm.writeJson(out, string.concat("./deployments/", vm.toString(block.chainid), ".json"));
        console.log(out);
    }

    /// TW2 §9: factory v2 + ba tầng, mỗi tầng là version 1 của kind riêng (số version theo kind; chuỗi domain "2"
    /// là thế hệ hợp đồng). Factory v2 không đăng ký MetaToken v1. Ghi thẳng vào object JSON "deploy" (run() đã
    /// hết chỗ trên stack).
    function _deployV2(address registrar, bool register, address subjectImpl) internal {
        OpenFactoryV2 f = new OpenFactoryV2(registrar);
        address none = address(new NoUnderlyingToken(address(f), subjectImpl));
        address single = address(new SingleUnderlyingToken(address(f), subjectImpl));
        address multi = address(new MultiUnderlyingToken(address(f), subjectImpl));
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
