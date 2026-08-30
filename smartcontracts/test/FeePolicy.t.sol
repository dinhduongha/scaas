// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {FeePolicy, FeeMode} from "../src/common/FeePolicy.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";

contract FeePolicyTest is Test {
    function test_percentFeeIsForbiddenOnConfidential() public {
        // Đây là ràng buộc BẢO MẬT, không phải tuỳ chọn: fee = v*p với fee và p công
        // khai ⇒ v = fee/p ⇒ toàn bộ Zether vô nghĩa.
        vm.expectRevert(FeePolicy.PercentFeeForbiddenOnConfidential.selector);
        this.callRequireConfidentialSafe(FeeMode.PERCENT);

        this.callRequireConfidentialSafe(FeeMode.NONE);
        this.callRequireConfidentialSafe(FeeMode.FIXED);
    }

    function test_fixedFeeObeysTheOnePercentCap() public {
        assertEq(FeePolicy.compute(FeeMode.FIXED, 1_000_000, 10_000), 10_000);

        vm.expectRevert(
            abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 10_001, 10_000)
        );
        this.callCompute(FeeMode.FIXED, 1_000_000, 10_001);
    }

    function test_percentFeeObeysTheSameCap() public {
        // Nếu PERCENT không chịu trần thì feePpm tuỳ ý sẽ vượt mặt nó, và FIXED
        // thành nhánh duy nhất được bảo vệ.
        assertEq(FeePolicy.compute(FeeMode.PERCENT, 1_000_000, 10_000), 10_000);

        vm.expectRevert(
            abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 10_001, 10_000)
        );
        this.callCompute(FeeMode.PERCENT, 1_000_000, 10_001);
    }

    function test_noneModeIsAlwaysZero() public pure {
        assertEq(FeePolicy.compute(FeeMode.NONE, 1_000_000, 999_999), 0);
    }

    /// Typehash là hợp đồng giữa contract và SDK client. Lệch một ký tự ⇒ hai digest
    /// khác nhau ⇒ 100% chữ ký fail, và triệu chứng là "chữ ký sai" chứ không phải
    /// "typehash lệch". Pin nó bằng test.
    function test_metaTxTypehashIsPinned() public pure {
        assertEq(
            MetaTxLib.METATX_TYPEHASH,
            keccak256(
                "MetaTransaction(address from,uint8 op,bytes args,uint256 batch,uint256 nonce,uint256 validUntil,address relayer,uint8 feeMode,uint256 fee,address feeRecipient)"
            )
        );
    }

    // Wrapper external để `vm.expectRevert` bắt được revert của library internal.
    function callRequireConfidentialSafe(FeeMode m) external pure {
        FeePolicy.requireConfidentialSafe(m);
    }

    function callCompute(FeeMode m, uint256 amount, uint256 fee) external pure returns (uint256) {
        return FeePolicy.compute(m, amount, fee);
    }
}
