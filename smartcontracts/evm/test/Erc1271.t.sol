// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {Mock1271Wallet} from "./helpers/WalletMocks.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {IERC20MetaTx} from "../src/metatx/IERC20MetaTx.sol";
import {IERC20Payment} from "../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";

/// Ví hợp đồng (EIP-1271) trả qua đúng pipeline meta-tx: `ERC20MetaTx._requireValidSignature`
/// đi đường `isValidSignature` khi `from` có code. Không có verifier thứ hai.
contract Erc1271Test is Fixtures {
    MetaToken internal t;
    uint256 internal ownerPk = 0xA11CE;
    Mock1271Wallet internal wallet;
    address internal shop = address(0x5409);

    function setUp() public {
        _deployFactory();
        t = _standalone(address(this), "ZVND", 0, 0, address(this));
        wallet = new Mock1271Wallet(vm.addr(ownerPk));
        t.mint(address(wallet), 1000);
    }

    function _payment(bytes32 ref) internal view returns (MetaTxLib.LegacyMetaTransaction memory m, bytes memory sig) {
        m = _mt(address(wallet), shop, 400, _payData(ref), uint256(ref), MetaTxLib.MODE_RESTRICT_RELAYER);
        sig = _sign(ownerPk, t, m);
    }

    function test_valid_wallet_pays() public {
        (MetaTxLib.LegacyMetaTransaction memory m, bytes memory sig) = _payment(keccak256("r1"));
        vm.expectEmit(true, true, true, true, address(t));
        emit IERC20Payment.PaymentSettled(address(wallet), shop, 400, 0, relayer, keccak256("r1"));
        vm.prank(relayer);
        t.executeMetaTransaction(m, sig);
        assertEq(t.balanceOf(shop), 400);
    }

    function _refused(Mock1271Wallet.Mode mode) internal {
        wallet.setMode(mode);
        (MetaTxLib.LegacyMetaTransaction memory m, bytes memory sig) = _payment(keccak256("r2"));
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTx.MetaTxBadSignature.selector);
        t.executeMetaTransaction(m, sig);
        assertEq(t.metaNonce(address(wallet), m.batch), 0);
        assertEq(t.balanceOf(shop), 0);
    }

    function test_wrong_magic_is_refused() public { _refused(Mock1271Wallet.Mode.WrongMagic); }

    function test_reverting_wallet_is_refused() public { _refused(Mock1271Wallet.Mode.Reverts); }

    function test_short_return_is_refused() public { _refused(Mock1271Wallet.Mode.Short); }

    function test_signature_from_someone_else_is_refused() public {
        (MetaTxLib.LegacyMetaTransaction memory m,) = _payment(keccak256("r3"));
        bytes memory sig = _sign(0xB0B, t, m);
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTx.MetaTxBadSignature.selector);
        t.executeMetaTransaction(m, sig);
    }
}
