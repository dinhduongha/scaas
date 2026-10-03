// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MandateWallet} from "../src/wallet/MandateWallet.sol";

/// Vector cố định cho bản Python (`dms_blockchain/lib/eip712.py`, `lib/abi.py`): digest của
/// delegate và calldata mà Odoo xếp vào outbox. Đổi contract mà không đổi Python ⇒ test này
/// và `test_eip712.TestMandateKat` cùng đỏ.
contract MandateWalletKatTest is Test {
    address constant WALLET = address(uint160(0xBA3B0));
    address constant OWNER = address(uint160(0xA1));
    address constant TOKEN = address(uint160(0xCD));
    address constant PAYEE = address(uint160(0xEE));
    bytes32 constant REF = 0x1111111111111111111111111111111111111111111111111111111111111111;

    function test_kat() public {
        // Same constants in dms_blockchain/tests/test_eip712.py (TestMandateKat).
        vm.chainId(9001);
        deployCodeTo("MandateWallet.sol:MandateWallet", abi.encode(OWNER), WALLET);
        MandateWallet w = MandateWallet(WALLET);
        bytes32 pay = w.payDigest(TOKEN, PAYEE, 123456789, REF, 1800000300);
        bytes32 rev = w.revokeDigest(TOKEN, 1800000300);
        bytes memory sig = new bytes(65);
        sig[0] = 0xAB;
        bytes memory payCall = abi.encodeCall(
            MandateWallet.payUnderMandate, (TOKEN, PAYEE, 123456789, REF, 1800000300, sig));
        bytes memory revCall = abi.encodeCall(MandateWallet.revokeWithSig, (TOKEN, 1800000300, sig));
        assertEq(pay, 0xe89e9bc4ea5f6fee32509317f2e846cd1fb578c95e79a03e2309cc92b11ef6a4);
        assertEq(rev, 0x82ec5bdfb5fe113c73a007f228c53b49a913a10f69e1cbb8f60e40c9712e1c77);
        assertEq(keccak256(payCall), 0x9e6b33e38a11bbd8cf6c3ce48e59dd02e13e132ecfb50fcb78398e1b3da83f26);
        assertEq(keccak256(revCall), 0x68dca3e85f0fb2edb37ed5b012b3bef205b259f4eee8d2c967e498613290e0fe);
    }
}
