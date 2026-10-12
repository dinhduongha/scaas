// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Test} from "forge-std/Test.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";

contract SigCheckHarness {
    function isValid(address signer, bytes32 digest, bytes calldata sig, uint256 cap) external view returns (bool) {
        return SigCheck.isValid(signer, digest, sig, cap);
    }

    function isContract(address a) external view returns (bool) {
        return SigCheck.isContract(a);
    }
}

/// CTR-MTX-25: EOA low-s, ERC-1271 with the gas-cap rule, EIP-7702 designator = EOA.
contract SigCheckTest is Test {
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant PK = 0xA11CE;
    SigCheckHarness internal h;
    Mock1271Wallet internal wallet;
    address internal signer;
    bytes32 internal constant D = keccak256("digest");

    function setUp() public {
        h = new SigCheckHarness();
        signer = vm.addr(PK);
        wallet = new Mock1271Wallet(signer);
    }

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function test_eoa_valid() public view {
        assertTrue(h.isValid(signer, D, _sig(PK, D), SigCheck.ERC1271_GAS));
    }

    function test_eoa_wrongSigner() public view {
        assertFalse(h.isValid(signer, D, _sig(0xB0B, D), SigCheck.ERC1271_GAS));
    }

    function test_eoa_highS_refused() public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, D);
        bytes memory high = abi.encodePacked(r, bytes32(N - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        assertEq(ecrecover(D, v == 27 ? 28 : 27, r, bytes32(N - uint256(s))), signer); // raw ecrecover accepts it
        assertFalse(h.isValid(signer, D, high, SigCheck.ERC1271_GAS));
    }

    function test_eoa_64byteCompact_refused() public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, D);
        bytes32 vs = bytes32(uint256(s) | (uint256(v - 27) << 255));
        assertEq(ECDSA.recover(D, r, vs), signer); // the compact form is otherwise valid
        assertFalse(h.isValid(signer, D, abi.encodePacked(r, vs), SigCheck.ERC1271_GAS));
    }

    function test_7702Designator_isEoa() public {
        address delegated = vm.addr(0xD7702);
        vm.etch(delegated, abi.encodePacked(hex"ef0100", address(wallet)));
        assertFalse(h.isContract(delegated));
        assertTrue(h.isValid(delegated, D, _sig(0xD7702, D), SigCheck.ERC1271_GAS));
        assertTrue(h.isContract(address(wallet)));
    }

    function test_1271_valid() public view {
        assertTrue(h.isValid(address(wallet), D, _sig(PK, D), SigCheck.ERC1271_GAS));
    }

    function test_1271_refusals() public {
        assertFalse(h.isValid(address(wallet), D, _sig(0xB0B, D), SigCheck.ERC1271_GAS));
        wallet.setMode(Mock1271Wallet.Mode.WrongMagic);
        assertFalse(h.isValid(address(wallet), D, _sig(PK, D), SigCheck.ERC1271_GAS));
        wallet.setMode(Mock1271Wallet.Mode.Reverts);
        assertFalse(h.isValid(address(wallet), D, _sig(PK, D), SigCheck.ERC1271_GAS));
        wallet.setMode(Mock1271Wallet.Mode.Short);
        assertFalse(h.isValid(address(wallet), D, _sig(PK, D), SigCheck.ERC1271_GAS));
    }

    /// The cap is what the wallet gets: a wallet that needs more than the cap fails, not the whole call.
    function test_1271_capIsEnforced() public view {
        assertFalse(h.isValid(address(wallet), D, _sig(PK, D), 2_000));
    }

    /// EIP-150: a caller holding less than cap·64/63 + margin reverts instead of answering "invalid".
    function test_1271_starvedCallReverts() public {
        bytes memory sig = _sig(PK, D);
        vm.expectPartialRevert(SigCheck.SigCheckGasStarved.selector);
        h.isValid{gas: 52_000}(address(wallet), D, sig, SigCheck.ERC1271_GAS);
        assertTrue(h.isValid{gas: 80_000}(address(wallet), D, sig, SigCheck.ERC1271_GAS));
    }

    /// Returndata shape: exactly 32 bytes, clean tail.
    function test_1271_longReturndata_refused() public {
        wallet.setMode(Mock1271Wallet.Mode.Long);
        assertFalse(h.isValid(address(wallet), D, _sig(PK, D), SigCheck.ERC1271_GAS));
    }

    function test_1271_dirtyTail_refused() public {
        wallet.setMode(Mock1271Wallet.Mode.DirtyTail);
        assertFalse(h.isValid(address(wallet), D, _sig(PK, D), SigCheck.ERC1271_GAS));
    }

    /// When the guard passes, the wallet gets the full cap: a wallet burning ~48k still answers valid.
    function test_1271_guardPassed_walletGetsFullCap() public {
        wallet.setMode(Mock1271Wallet.Mode.Burn);
        bytes memory sig = _sig(PK, D);
        assertTrue(h.isValid{gas: 58_000}(address(wallet), D, sig, SigCheck.ERC1271_GAS));
    }
}
