// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";

/// @title Vector KAT cho ba bản sao của digest (Python ở Odoo, Rust ở node, ví).
/// @notice Sinh `test/vectors/metatx_kat.json`. File được commit; đổi typehash, đổi quy
///         tắc canonical-zeroing hay đổi domain là test Python và Rust đỏ ngay.
contract MetaTxKatTest is Fixtures {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    function test_writeKat() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        _deployFactory();
        MetaToken tok = _standalone(address(this), "BUSD", 6, 0, address(0));
        uint256 pk = 0xA11CE;
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: vm.addr(pk), to: address(0x5409), value: 250e6,
            data: _payData(bytes32(uint256(0x42))), batch: uint256(keccak256("scaas.pay.lane")),
            nonce: 0, validUntil: 1_800_000_300, mode: MetaTxLib.MODE_RESTRICT_RELAYER,
            relayer: relayer, fee: 0,
            feeRecipient: address(0xFEE)        // flag off -> canonical-zeroed in the hash
        });
        bytes32 structHash = m.hashStruct();
        bytes32 domainSep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), uint256(7622), address(tok)));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
        assertEq(digest, tok.metaTxDigest(m));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);

        string memory k = "kat";
        vm.serializeString(k, "domain_name", "SCaaS MetaToken");
        vm.serializeString(k, "domain_version", "1");
        vm.serializeString(k, "chain_id", "7622");
        vm.serializeString(k, "verifying_contract", vm.toString(address(tok)));
        vm.serializeString(k, "from", vm.toString(m.from));
        vm.serializeString(k, "to", vm.toString(m.to));
        vm.serializeString(k, "value", vm.toString(m.value));
        vm.serializeString(k, "data", vm.toString(m.data));
        vm.serializeString(k, "batch", vm.toString(m.batch));
        vm.serializeString(k, "nonce", vm.toString(m.nonce));
        vm.serializeString(k, "valid_until", vm.toString(m.validUntil));
        vm.serializeString(k, "mode", vm.toString(uint256(m.mode)));
        vm.serializeString(k, "relayer", vm.toString(m.relayer));
        vm.serializeString(k, "fee", vm.toString(m.fee));
        vm.serializeString(k, "fee_recipient", vm.toString(m.feeRecipient));
        vm.serializeString(k, "struct_hash", vm.toString(structHash));
        vm.serializeString(k, "digest", vm.toString(digest));
        vm.serializeString(k, "signer", vm.toString(m.from));
        string memory out = vm.serializeString(k, "signature", vm.toString(abi.encodePacked(r, s, v)));
        vm.writeJson(out, "./test/vectors/metatx_kat.json");
    }
}
