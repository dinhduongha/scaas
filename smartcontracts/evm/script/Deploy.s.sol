// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {console} from "forge-std/Script.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {SmartKeyAccountFactory} from "../src/account/SmartKeyAccountFactory.sol";
import {DeployBase} from "./DeployBase.sol";

/// forge script script/Deploy.s.sol --rpc-url $RPC --broadcast --slow --code-size-limit 65536 --sender <địa chỉ deployer = vm.addr(PRIVATE_KEY)>
/// env: PRIVATE_KEY (deployer; registrar mặc định), REGISTRAR (tuỳ chọn),
///      DEMO_SUPPLY (tuỳ chọn; 0 = không tạo token demo), DEMO_HOLDER (tuỳ chọn, nhận một nửa),
///      DEPLOY_SALT (tuỳ chọn; mặc định keccak256("scaas.deploy.v1"); chạy lại trên cùng chain cần salt mới),
///      CHAIN_UID (genesis hash, chain-uids.json; tuỳ chọn; phải bằng hash block 0 của RPC, mặc định chính hash đó).
///      DEPLOY_ZETHER (tuỳ chọn, true/false; mọi chain trừ Hedera; cần cờ forge trong deploy.sh, docs/networks/evm.md).
///      DEPLOY_WRAPPED (optional, true/false): the `WRAPPED` release too (GD-12). DEPLOY_REGULATED (optional, true/false):
///      the regulated releases (`_deployRegulated`: kinds 8 and 9, enabled; plan T28) and the canonical ComplianceRegistry
///      (`_deployComplianceRegistry`, plan T33) with COMPLIANCE_ADMIN (an address with code, CTR-AS-07). CHAIN_CODE_LIMIT (optional, default
///      65,536, EIP-7954): the chain's declared code limit; a release above it is refused by name before anything is sent
///      (CTR-GOV-19, GD-4); the SCaaS testnet after the next reset: 131,072 (`maxCodeSize` `0x20000`). RELEASE_GAS_GATE
///      (optional, testnet / public; Q4 of CTR-MTX-30): the release gas gate, `DeployBase._publicGate`. DEPLOY_PQCHAT
///      (optional, true/false; plan 3c T92): `PqChat` on the generic path (class 3, kind 0), its body module
///      `PqChatTopics`, and one instance when NOTICE_PERIOD is 0 (`_deployPqChat`; JSON `pqchat_topics`,
///      `pqchat_implementation`, `pqchat_instance`). DEPLOY_NAME (a chain not in chain-uids.json: `<name>-testnet` |
///      `<name>-mainnet`, NET-EVM-13; refused before anything is sent when missing).
/// Ghi `deployments/<key>.json` (NET-EVM-13: the chain's key, its header first; token factory, implementations, the DEX
/// implementation, the SmartKeyAccount factory, `chain_uid`, the demo tokens) để seed client (`blockchain.token`) và config
/// node; a DEX is a clone from `OpenFactory.createDex` (CTR-DEX-24). The v1 line (`OpenFactoryV1`, `MetaToken`, `MetaTxDex`, `SCaaSDexV1`) is in
/// `legacy/p5/` (P5).
contract Deploy is DeployBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        address registrar = vm.envOr("REGISTRAR", deployer);
        uint256 demoSupply = vm.envOr("DEMO_SUPPLY", uint256(0));
        address demoHolder = vm.envOr("DEMO_HOLDER", deployer);

        _setup();
        string memory book = _bookPath(uid, "", ".json"); // the key now: DEPLOY_NAME_REQUIRED before anything is sent
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
        vm.writeFile(book, _bookHeader(uid, out));
        _writeReleases();
        console.log(out);
    }
}
