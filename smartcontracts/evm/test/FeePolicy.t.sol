// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
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

    /// CHAIN-03 (review T2, 2026-10-19): amount · ppm past 2^256 is `mulDiv`, the same floor, not a panic.
    function test_hugeAmounts_noOverflow() public {
        uint256 amount = 1 << 250;
        uint256 cap = amount / 100; // floor(2^250 · 1 %)
        assertEq(FeePolicy.compute(FeeMode.FIXED, amount, 0), 0);
        assertEq(FeePolicy.compute(FeeMode.FIXED, amount, cap), cap);
        assertEq(FeePolicy.compute(FeeMode.PERCENT, amount, 10_000), cap);
        vm.expectRevert(abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, cap + 1, cap));
        this.callCompute(FeeMode.FIXED, amount, cap + 1);
    }

    function test_noneModeIsAlwaysZero() public pure {
        assertEq(FeePolicy.compute(FeeMode.NONE, 1_000_000, 999_999), 0);
    }

    /// Nửa byte sau của `mode` là cách tính phí. Ba giá trị hợp lệ, phần còn lại phải
    /// revert — nếu không thì `0x30` hôm nay bị bỏ qua và ngữ nghĩa của nó ngày mai
    /// bị khoá chết bởi những chữ ký đã phát hành.
    function test_feeModeLivesInTheSecondNibble() public pure {
        assertEq(uint8(MetaTxLib.feeModeOf(MetaTxLib.MODE_FEE_NONE)),    uint8(FeeMode.NONE));
        assertEq(uint8(MetaTxLib.feeModeOf(MetaTxLib.MODE_FEE_PERCENT)), uint8(FeeMode.PERCENT));
        assertEq(uint8(MetaTxLib.feeModeOf(MetaTxLib.MODE_FEE_FIXED)),   uint8(FeeMode.FIXED));
        // Nửa byte đầu không ảnh hưởng nửa byte sau, và ngược lại.
        assertEq(
            uint8(MetaTxLib.feeModeOf(MetaTxLib.MODE_FEE_FIXED | MetaTxLib.MODE_RESTRICT_RELAYER)),
            uint8(FeeMode.FIXED)
        );
    }

    function test_unknownFeeNibbleReverts() public {
        vm.expectRevert(abi.encodeWithSelector(MetaTxLib.ModeFeeInvalid.selector, uint32(0x30)));
        this.callValidateMode(0x30);
    }

    function test_unknownModeBitsRevert() public {
        vm.expectRevert(abi.encodeWithSelector(MetaTxLib.ModeUnknownBits.selector, uint32(0x100)));
        this.callValidateMode(0x100);
    }

    function callValidateMode(uint32 m) external pure { MetaTxLib.validateMode(m); }

    // Wrapper external để `vm.expectRevert` bắt được revert của library internal.
    function callRequireConfidentialSafe(FeeMode m) external pure {
        FeePolicy.requireConfidentialSafe(m);
    }

    function callCompute(FeeMode m, uint256 amount, uint256 fee) external pure returns (uint256) {
        return FeePolicy.compute(m, amount, fee);
    }
}
