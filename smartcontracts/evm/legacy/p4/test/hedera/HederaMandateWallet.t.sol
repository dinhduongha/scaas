// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

// Backup (P4): the `HederaMandateWalletTest` of `test/hedera/HederaMetaToken.t.sol` as it stood before P4 moved
// `MandateWallet` onto `MetaTxBase`; it tested `legacy/p4/src/hedera/HederaMandateWallet.sol`. Not built.

contract HederaMandateWalletTest is HederaFixture {
    uint256 constant OWNER_KEY = 0x0E1;
    uint256 constant DELEGATE_PK = 0xDE1;
    address owner;
    HederaMandateWallet wallet;
    HederaMetaToken tok;

    function setUp() public {
        _setUpHedera();
        owner = _nativeAccount(2_000_001, OWNER_KEY);
        wallet = new HederaMandateWallet(owner);
        tok = _token("HBUSD", 1_000_000e6);
        tok.transfer(address(wallet), 1_000e6);
    }

    function _setMandateCall() internal view returns (bytes memory) {
        return abi.encodeCall(MandateWallet.setMandate,
            (address(tok), vm.addr(DELEGATE_PK), 100e6, 300e6, 1 days, uint64(block.timestamp + 30 days)));
    }

    function test_ed25519OwnerSetsMandateGasless() public {
        bytes memory data = _setMandateCall();
        uint256 vu = block.timestamp + 300;
        bytes memory sig = _edSign(OWNER_KEY, wallet.ownerCallDigest(data, 0, vu));
        vm.prank(relayer);
        wallet.executeAsOwnerRaw(data, 0, vu, sig);
        (address d,,,,,,) = wallet.mandates(address(tok));
        assertEq(d, vm.addr(DELEGATE_PK));
        assertEq(wallet.ownerNonce(), 1);
        // replay
        vm.expectRevert(MandateWallet.BadNonce.selector);
        wallet.executeAsOwnerRaw(data, 0, vu, sig);
    }

    function test_ownerRawRejectsOtherKeyAndExpiry() public {
        bytes memory data = _setMandateCall();
        uint256 vu = block.timestamp + 300;
        bytes memory bad = _edSign(DELEGATE_PK, wallet.ownerCallDigest(data, 0, vu));
        vm.expectRevert(MandateWallet.BadSignature.selector);
        wallet.executeAsOwnerRaw(data, 0, vu, bad);
        bytes memory sig = _edSign(OWNER_KEY, wallet.ownerCallDigest(data, 0, vu));
        vm.warp(vu + 1);
        vm.expectRevert(MandateWallet.SignatureExpired.selector);
        wallet.executeAsOwnerRaw(data, 0, vu, sig);
    }

    /// Delegate (custody secp256k1 của platform) trả trong hạn mức; payRef một lần — như MandateWallet.
    function test_delegatePaysUnderMandateSetByEd25519Owner() public {
        bytes memory data = _setMandateCall();
        uint256 vu = block.timestamp + 300;
        wallet.executeAsOwnerRaw(data, 0, vu, _edSign(OWNER_KEY, wallet.ownerCallDigest(data, 0, vu)));
        bytes memory payee = abi.encodeCall(MandateWallet.setPayee, (address(tok), address(0x5409), true));
        wallet.executeAsOwnerRaw(payee, 1, vu, _edSign(OWNER_KEY, wallet.ownerCallDigest(payee, 1, vu)));
        bytes32 ref = bytes32(uint256(7));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(DELEGATE_PK, wallet.payDigest(address(tok), address(0x5409), 50e6, ref, vu));
        wallet.payUnderMandate(address(tok), address(0x5409), 50e6, ref, vu, abi.encodePacked(r, s, v));
        assertEq(tok.balanceOf(address(0x5409)), 50e6);
        vm.expectRevert(abi.encodeWithSelector(MandateWallet.RefAlreadyPaid.selector, ref));
        wallet.payUnderMandate(address(tok), address(0x5409), 50e6, ref, vu, abi.encodePacked(r, s, v));
    }
}
