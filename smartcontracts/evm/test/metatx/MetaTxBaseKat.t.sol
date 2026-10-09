// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MtxFixture} from "../helpers/MtxFixture.sol";
import {MtxRegistryMock} from "../helpers/MtxRegistryMock.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// KAT of the generic `MetaTransaction` digest (metatx.md "One rule, four places"): writes
/// `test/vectors/metatx_kat.json`, which the node, clientkeys and the Odoo connector read (P5). The vector is
/// `cancelNonce(uint256)` (allowlisted on every contract on `MetaTxBase`) in the token domain "SCaaS MetaToken"
/// on chain 7622 with its real `chain_uid`; `feeRecipient` is set with its flag off, so it is hashed as 0.
contract MetaTxBaseKatTest is MtxFixture {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    string internal constant OUT = "./test/vectors/metatx_kat.json";

    function test_metaTxKat() public {
        MtxRegistryMock tok = new MtxRegistryMock("SCaaS MetaToken", UID);
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: vm.addr(ALICE_PK), data: abi.encodeCall(IMetaTx.cancelNonce, (42)),
            batch: 7, nonce: 0, validUntil: 1_800_000_300, mode: MetaTxLib.MODE_RESTRICT_RELAYER,
            relayer: relayer, fee: 0, feeRecipient: address(0xFEE)
        });
        bytes32 structHash = m.hashStruct();
        bytes32 domainSep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), uint256(7622), address(tok), UID));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
        assertEq(digest, tok.mtxDigest(m));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(relayer);                                   // the vector really executes
        tok.mtxExecute(m, sig);
        assertEq(tok.mtxNonce(m.from, 7), 1);

        string memory k = "kat";
        vm.serializeString(k, "domain_name", "SCaaS MetaToken");
        vm.serializeString(k, "domain_version", "1");
        vm.serializeString(k, "chain_id", "7622");
        vm.serializeString(k, "verifying_contract", vm.toString(address(tok)));
        vm.serializeString(k, "salt", vm.toString(UID));
        vm.serializeString(k, "from", vm.toString(m.from));
        vm.serializeString(k, "data", vm.toString(m.data));
        vm.serializeString(k, "batch", vm.toString(m.batch));
        vm.serializeString(k, "nonce", vm.toString(m.nonce));
        vm.serializeString(k, "valid_until", vm.toString(m.validUntil));
        vm.serializeString(k, "mode", vm.toString(uint256(m.mode)));
        vm.serializeString(k, "relayer", vm.toString(m.relayer));
        vm.serializeString(k, "fee", vm.toString(m.fee));
        vm.serializeString(k, "fee_recipient", vm.toString(m.feeRecipient));
        vm.serializeString(k, "type_hash", vm.toString(MetaTxLib.METATX_TYPEHASH));
        vm.serializeString(k, "domain_separator", vm.toString(domainSep));
        vm.serializeString(k, "struct_hash", vm.toString(structHash));
        vm.serializeString(k, "digest", vm.toString(digest));
        vm.serializeString(k, "signer", vm.toString(m.from));
        string memory out = vm.serializeString(k, "signature", vm.toString(sig));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT);

        string memory onDisk = vm.readFile(OUT);
        assertEq(vm.parseJsonBytes32(onDisk, ".type_hash"), MetaTxLib.METATX_TYPEHASH);
        assertEq(vm.parseJsonBytes32(onDisk, ".salt"), UID);
        assertEq(vm.parseJsonAddress(onDisk, ".verifying_contract"), address(tok));
        assertEq(vm.parseJsonBytes32(onDisk, ".struct_hash"), structHash);
        assertEq(vm.parseJsonBytes32(onDisk, ".digest"), digest);
        assertEq(vm.parseJsonBytes(onDisk, ".signature"), sig);
    }
}
