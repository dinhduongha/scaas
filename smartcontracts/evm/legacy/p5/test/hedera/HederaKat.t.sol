// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {console} from "forge-std/console.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {HederaMetaToken} from "../../src/hedera/HederaMetaToken.sol";
import {HederaFixture} from "./HederaMetaToken.t.sol";

/// @title Vector chung Hedera (Python ở Odoo, Rust ở node, Solidity ở đây).
/// @notice `test/vectors/hedera_kat.json` sinh bởi `test/hedera/gen_hedera_kat.py` (digest EIP-712 theo
///         `dms_blockchain/lib/eip712.py` + chữ ký ed25519 THẬT RFC 8032 trên digest, khoá từ seed cố định).
///         Ở đây: cùng kịch bản phải ra cùng địa chỉ token và cùng digest. Toán ed25519 của chữ ký được Python
///         (`cryptography`) và Rust (`ed25519-dalek`) kiểm; precompile HIP-632 trên Hedera kiểm đúng phép đó.
contract HederaKatTest is HederaFixture {
    using stdJson for string;

    function test_katDigestMatchesPythonAndRust() public {
        _setUpHedera();
        HederaMetaToken tok = _token("HBUSD", 0);
        console.log("verifying_contract", address(tok));
        string memory j = vm.readFile("./test/vectors/hedera_kat.json");
        assertEq(address(tok), j.readAddress(".verifying_contract"));
        assertEq(block.chainid, j.readUint(".chain_id"));
        bytes32 ref = j.readBytes32(".entry_ref");
        MetaTxLib.LegacyMetaTransaction memory m = MetaTxLib.LegacyMetaTransaction({
            from: j.readAddress(".from"), to: j.readAddress(".to"), value: j.readUint(".value"),
            data: j.readBytes(".data"), batch: j.readUint(".batch"), nonce: 0,
            validUntil: j.readUint(".valid_until"), mode: uint32(j.readUint(".mode")),
            relayer: j.readAddress(".relayer"), fee: 0, feeRecipient: address(0)
        });
        assertEq(m.data, abi.encodeWithSelector(bytes4(keccak256("pay(bytes32)")), ref));
        assertEq(m.batch, uint256(keccak256(abi.encodePacked("scaas.pay.lane", ref))));
        assertEq(tok.metaTxDigest(m), j.readBytes32(".digest"));
        assertEq(j.readBytes(".ed25519_signature").length, 64);
    }
}
