// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ERC20MetaTx} from "../src/metatx/ERC20MetaTx.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";

contract DemoToken is ERC20MetaTx {
    constructor() ERC20("Demo", "DEMO") EIP712("Demo", "1") {}
    function mint(address to, uint256 v) external { _mint(to, v); }
}

/// Smart account tối thiểu: chấp mọi chữ ký. Đo CHI PHÍ ĐƯỜNG ĐI (staticcall +
/// returndata), không đo chi phí verify của một ví thật — ví thật cộng thêm phần
/// của nó, và phần đó không thuộc phong bì.
contract AlwaysValid1271 is IERC1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return IERC1271.isValidSignature.selector;
    }
}

/// @title Đo phong bì meta-transaction. Số cho `00-CANON.md` §C7.2.
///
/// **Mỗi kịch bản một hàm test, và đó không phải chuyện tổ chức code.** Forge chạy
/// trọn một hàm test trong MỘT frame, nên access list của EIP-2929 KHÔNG reset giữa
/// các lời gọi trong cùng hàm. Đo năm kịch bản nối tiếp nhau trong một hàm cho kết
/// quả sai: lời gọi thứ hai trở đi thấy slot đã "dirty" và trả 100 gas thay vì 5.000
/// cho cùng một SSTORE. Lần đo đầu của file này mắc đúng lỗi đó và cho phí FIXED rẻ
/// hơn PERCENT 4.744 gas — một khác biệt không tồn tại, nó chỉ là thứ tự.
contract MetaTxGasTest is Test {
    DemoToken tok;
    uint256 constant PK = 0xA11CE;
    address signer;
    address relayer = address(0xBEEF);
    address recipient = address(0xCAFE);

    AlwaysValid1271 acct;

    uint256 constant WARM_BATCH = 1;   // nonce slot đã nonzero
    uint256 constant COLD_BATCH = 2;   // nonce slot còn 0

    function setUp() public {
        tok = new DemoToken();
        signer = vm.addr(PK);
        tok.mint(signer, 1_000_000 ether);
        // Số dư nonzero sẵn: một transfer tới ví chưa từng có token là zero->nonzero
        // (20.000 gas) và đó là chi phí của LẦN ĐẦU, không phải của phong bì.
        tok.mint(recipient, 1 ether);
        tok.mint(relayer, 1 ether);
        // Smart account phải được tạo và cấp vốn Ở ĐÂY, không trong hàm test: tạo nó
        // trong hàm test làm địa chỉ của nó warm và slot số dư của nó dirty, và lần
        // đo đầu vì thế cho ERC-1271 RẺ HƠN ECDSA 9.611 gas — vô lý, và sai.
        acct = new AlwaysValid1271();
        tok.mint(address(acct), 1_000 ether);
        vm.warp(1_800_000_000);
        // Đốt nonce 0 của WARM_BATCH để slot của nó nonzero.
        _exec(_mt(MetaTxLib.MODE_OPEN, WARM_BATCH, 0, 0, address(0)));
    }

    function _mt(uint32 mode, uint256 batch, uint256 nonce, uint256 fee, address feeRcpt)
        internal view returns (MetaTxLib.LegacyMetaTransaction memory m)
    {
        m = MetaTxLib.LegacyMetaTransaction({
            from: signer, to: recipient, value: 1 ether, data: "",
            batch: batch, nonce: nonce, validUntil: block.timestamp + 600,
            mode: mode, relayer: relayer, fee: fee, feeRecipient: feeRcpt
        });
    }

    function _sign(MetaTxLib.LegacyMetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, tok.metaTxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function _exec(MetaTxLib.LegacyMetaTransaction memory m) internal {
        vm.prank(relayer);
        tok.executeMetaTransaction(m, _sign(m));
    }

    function _measure(MetaTxLib.LegacyMetaTransaction memory m, string memory label)
        internal returns (uint256 used)
    {
        bytes memory sig = _sign(m);
        vm.prank(relayer);
        uint256 g0 = gasleft();
        tok.executeMetaTransaction(m, sig);
        used = g0 - gasleft();
        console.log(label, used);
        assertGt(used, 0);
    }

    function test_gasWarmBatchNoFee() public {
        _measure(_mt(MetaTxLib.MODE_OPEN, WARM_BATCH, 1, 0, address(0)),
                 "A warm batch, NONE       ");
    }

    function test_gasColdBatchNoFee() public {
        _measure(_mt(MetaTxLib.MODE_OPEN, COLD_BATCH, 0, 0, address(0)),
                 "B cold batch, NONE       ");
    }

    function test_gasWarmBatchFixedFee() public {
        _measure(_mt(MetaTxLib.MODE_FEE_FIXED, WARM_BATCH, 1, 0.001 ether, relayer),
                 "C warm batch, FIXED fee  ");
    }

    function test_gasWarmBatchPercentFee() public {
        _measure(_mt(MetaTxLib.MODE_FEE_PERCENT, WARM_BATCH, 1, 5_000, relayer),
                 "D warm batch, PERCENT fee");
    }

    function test_gasWarmBatchRestricted() public {
        _measure(
            _mt(MetaTxLib.MODE_FEE_FIXED | MetaTxLib.MODE_RESTRICT_RELAYER
                | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT, WARM_BATCH, 1, 0.001 ether, relayer),
            "E warm batch, FIXED+restrict");
    }

    function test_gasFirstTimeRecipient() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(MetaTxLib.MODE_OPEN, WARM_BATCH, 1, 0, address(0));
        m.to = address(0xD00D);   // ví chưa từng giữ token: SSTORE zero->nonzero
        _measure(m, "F warm batch, new recipient");
    }

    function test_gasErc1271() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(MetaTxLib.MODE_OPEN, COLD_BATCH, 0, 0, address(0));
        m.from = address(acct);
        bytes memory sig = hex"deadbeef";
        vm.prank(relayer);
        uint256 g0 = gasleft();
        tok.executeMetaTransaction(m, sig);
        console.log("G cold batch, ERC-1271   ", g0 - gasleft());
    }

    function test_gasCancel() public {
        vm.prank(signer);
        uint256 g0 = gasleft();
        tok.cancelMetaNonce(99);
        console.log("H cancelMetaNonce (cold) ", g0 - gasleft());
    }

    /// Đường CƠ SỞ: cùng thao tác, không phong bì. Hiệu số A − J là **giá thật của
    /// meta-transaction**, và đó mới là con số §C7.2 gọi là "envelope". Đo A một mình
    /// rồi gọi nó là envelope là cộng cả chi phí của thao tác vào phong bì.
    function test_gasPlainTransfer() public {
        vm.prank(signer);
        uint256 g0 = gasleft();
        tok.transfer(recipient, 1 ether);
        console.log("J plain transfer (base)  ", g0 - gasleft());
    }

    /// Calldata của giao dịch NGOÀI: phí CẤP GIAO DỊCH, không phải chi phí thực thi.
    /// §C7.2 bản cũ cộng hai thứ này vào một tổng rồi dùng tổng đó cho cả hai việc.
    function test_gasCalldata() public view {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(MetaTxLib.MODE_OPEN, WARM_BATCH, 1, 0, address(0));
        bytes memory cd = abi.encodeCall(tok.executeMetaTransaction, (m, _sign(m)));
        uint256 g;
        for (uint256 i; i < cd.length; ++i) g += cd[i] == 0 ? 4 : 16;
        console.log("I calldata bytes         ", cd.length);
        console.log("I calldata gas (EIP-2028)", g);
        console.log("I  + intrinsic 21000     ", g + 21_000);
    }
}
