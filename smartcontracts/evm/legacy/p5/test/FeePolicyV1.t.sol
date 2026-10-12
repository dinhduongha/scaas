// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// legacy/p5 — reference only, not built: cut from `test/FeePolicy.t.sol` when the v1 line left the build (P5).
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";

contract FeePolicyV1Test is Test {
    /// Typehash là hợp đồng giữa contract và SDK client. Lệch một ký tự ⇒ hai digest
    /// khác nhau ⇒ 100% chữ ký fail, và triệu chứng là "chữ ký sai" chứ không phải
    /// "typehash lệch". Pin nó bằng test.
    function test_legacyMetaTxTypehashIsPinned() public pure {
        assertEq(
            MetaTxLib.LEGACY_METATX_TYPEHASH,
            keccak256(
                "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
            )
        );
    }
}
