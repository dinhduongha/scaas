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
import {HederaNoUnderlyingToken} from "../../src/hedera/HederaTokensV2.sol";

/// Như `script/Deploy.s.sol` nhưng implementation META là `HederaMetaToken` (R63).
/// Hedera JSON-RPC Relay: `forge script script/hedera/DeployHedera.s.sol --rpc-url $RELAY --broadcast --slow`
/// (relay không có mempool: `--slow` gửi tuần tự, mỗi tx chờ receipt). Deployer = tài khoản ECDSA có alias EVM.
/// env: PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?, DEMO_HOLDER?, CHAIN_UID? (mặc định blockhash(0)).
/// Ghi `deployments/hedera-<chainid>.json`.
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

    /// TW2 §9/§11: factory v2 + tầng None Hedera (Single/Multi chờ P1d, R3), version 1; ghi thẳng vào object JSON "deploy".
    function _deployV2(address registrar, bool register) internal {
        OpenFactoryV2 f = new OpenFactoryV2(registrar);
        // chain_uid = genesis hash (CTR-GEN-05, chain-uids.json). Default: block 0's hash as the RPC reports it. The
        // script runs at the head block and BLOCKHASH of the current block is 0, so roll one ahead to read it on a
        // fresh chain (head 0); past block 256 BLOCKHASH(0) is 0 and CHAIN_UID is required.
        bytes32 uid = vm.envOr("CHAIN_UID", bytes32(0));
        if (uid == bytes32(0)) {
            uint256 head = block.number;
            vm.roll(head + 1);
            uid = blockhash(0);
            vm.roll(head);
        }
        require(uid != bytes32(0), "set CHAIN_UID (chain-uids.json)");
        // Transitional (R3): Single/Multi are over EIP-170 until P1d (UnderlyingToken + UnderlyingLib); only META_NONE
        // is deployed and registered, and the JSON has no implementation_meta_single/_multi keys.
        address none = address(new HederaNoUnderlyingToken(address(f), uid));
        if (register) f.registerImplementation(IOpenFactoryV2.TokenKind.META_NONE, 1, none);
        vm.serializeAddress("deploy", "factory_v2", address(f));
        vm.serializeAddress("deploy", "implementation_meta_none", none);
    }
}
