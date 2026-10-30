// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Test, console2} from "forge-std/Test.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";

contract SigCheckHarness {
    function isValid(address signer, bytes32 digest, bytes calldata sig, uint256 cap) external view returns (bool) {
        return SigCheck.isValid(signer, digest, sig, cap);
    }

    function isContract(address a) external view returns (bool) {
        return SigCheck.isContract(a);
    }

    function isDesignator(address a) external view returns (bool) {
        return SigCheck.isDesignator(a);
    }

    function requireNotDelegated(address a) external view {
        SigCheck.requireNotDelegated(a);
    }

    /// The gas of the caller guard as `_msgSender()` runs it, on a warm caller (a real direct caller is warm: the
    /// transaction's sender, or a contract already executing).
    function guardGas() external view returns (uint256 g) {
        address s = msg.sender;
        SigCheck.requireNotDelegated(s); // warms the caller's account
        g = gasleft();
        SigCheck.requireNotDelegated(s);
        g -= gasleft();
    }
}

/// CTR-MTX-25: EOA low-s, ERC-1271 with the gas-cap rule, EIP-7702 by CTR-UA-24 (owner ruling 2026-10-30: own key only).
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

    /// accounts.md CTR-UA-24, one rule on every path (owner ruling 2026-10-30, D1, superseding 2026-10-28): a
    /// 7702-delegated EOA signs with its own key only; its delegate's ERC-1271 is never asked, even when it would say
    /// yes (a sweeper delegate); empty code is ECDSA only; other code is ERC-1271 only.
    function test_isValid_7702_ctrUa24() public {
        address delegated = vm.addr(0xD7702);
        Mock1271Wallet delegate = new Mock1271Wallet(signer); // answers for ECDSA by `signer` over the hash
        vm.signAndAttachDelegation(address(delegate), 0xD7702);
        assertEq(delegated.code.length, 23);
        assertTrue(h.isValid(delegated, D, _sig(0xD7702, D), SigCheck.ERC1271_GAS), "the base key");
        assertFalse(h.isValid(delegated, D, _sig(PK, D), SigCheck.ERC1271_GAS), "the delegate's ERC-1271 refused");
        bytes memory viaDelegate = _sig(PK, D);
        vm.expectCall(delegated, abi.encodeCall(Mock1271Wallet.isValidSignature, (D, viaDelegate)), 0);
        assertFalse(h.isValid(delegated, D, viaDelegate, SigCheck.ERC1271_GAS), "the delegate is never called");
        assertFalse(h.isValid(delegated, D, _sig(0xB0B, D), SigCheck.ERC1271_GAS));
        assertTrue(h.isValid(signer, D, _sig(PK, D), SigCheck.ERC1271_GAS));
        assertFalse(h.isValid(signer, D, _sig(0xB0B, D), SigCheck.ERC1271_GAS));
        assertTrue(h.isValid(address(wallet), D, _sig(PK, D), SigCheck.ERC1271_GAS));
        assertFalse(h.isValid(address(wallet), D, _sig(0xB0B, D), SigCheck.ERC1271_GAS));
    }

    /// T-AUTH-3 on the address path: a delegate without ERC-1271, with a wrong magic value, reverting, short, or burning
    /// past the cap fails the delegate's signature while the base key stays root; 23 bytes of code that are not a
    /// designator are a contract (ERC-1271 only).
    function test_isValid_7702_badDelegates() public {
        address delegated = vm.addr(0xD7702);
        bytes memory viaDelegate = _sig(PK, D);
        vm.signAndAttachDelegation(address(new SigCheckHarness()), 0xD7702); // no isValidSignature
        assertFalse(h.isValid(delegated, D, viaDelegate, SigCheck.ERC1271_GAS), "no 1271");
        assertTrue(h.isValid(delegated, D, _sig(0xD7702, D), SigCheck.ERC1271_GAS));
        Mock1271Wallet.Mode[3] memory modes = [Mock1271Wallet.Mode.WrongMagic, Mock1271Wallet.Mode.Reverts, Mock1271Wallet.Mode.Short];
        for (uint256 i; i < modes.length; ++i) {
            // the delegate's code runs on the account's storage: its mode is set through the account
            vm.signAndAttachDelegation(address(new Mock1271Wallet(signer)), 0xD7702);
            Mock1271Wallet(delegated).setMode(modes[i]);
            assertFalse(h.isValid(delegated, D, viaDelegate, SigCheck.ERC1271_GAS), "bad delegate");
            assertTrue(h.isValid(delegated, D, _sig(0xD7702, D), SigCheck.ERC1271_GAS), "the base key stays root");
        }
        vm.signAndAttachDelegation(address(new Mock1271Wallet(signer)), 0xD7702);
        Mock1271Wallet(delegated).setMode(Mock1271Wallet.Mode.Burn); // ~46 k: over a 20 k cap
        assertFalse(h.isValid(delegated, D, viaDelegate, 20_000), "gas-exhausting delegate");
        address fake = vm.addr(0xFA4E);
        vm.etch(fake, abi.encodePacked(hex"63ffffffff60e01b60005260206000f3", bytes7(0)));
        assertEq(fake.code.length, 23);
        assertTrue(h.isContract(fake));
        assertFalse(h.isValid(fake, D, _sig(0xFA4E, D), SigCheck.ERC1271_GAS), "not a designator: 1271 only");
    }

    /// D2 helper: a designator (to code or to a code-less address) is refused as a direct caller; a contract, a
    /// code-less EOA and 23 bytes of real code pass. (revm refuses to etch other `0xef01…` code.)
    function test_requireNotDelegated() public {
        address delegated = vm.addr(0xD7702);
        h.requireNotDelegated(delegated);
        h.requireNotDelegated(address(wallet));
        vm.etch(delegated, abi.encodePacked(hex"ef0100", address(wallet)));
        assertTrue(h.isDesignator(delegated));
        vm.expectRevert(abi.encodeWithSelector(SigCheck.CallerDelegated.selector, delegated));
        h.requireNotDelegated(delegated);
        vm.etch(delegated, abi.encodePacked(hex"ef0100", address(0xdead)));
        vm.expectRevert(abi.encodeWithSelector(SigCheck.CallerDelegated.selector, delegated));
        h.requireNotDelegated(delegated);
        address fake = vm.addr(0xFA4E);
        vm.etch(fake, abi.encodePacked(hex"63ffffffff60e01b60005260206000f3", bytes7(0))); // 23 bytes, real code
        assertFalse(h.isDesignator(fake));
        assertTrue(h.isContract(fake));
        h.requireNotDelegated(fake);
    }

    /// The per-call cost of the D2 caller guard for a code-less EOA and a contract caller, warm. Logged for the gas
    /// record; bounded here (one warm EXTCODESIZE and a compare: 313 at Amsterdam prices, 2026-10-30).
    function test_requireNotDelegated_gas() public {
        address[2] memory callers = [vm.addr(0xE0A), address(wallet)];
        string[2] memory label = ["code-less EOA", "contract"];
        for (uint256 i; i < 2; ++i) {
            vm.prank(callers[i]);
            uint256 g = h.guardGas();
            console2.log("requireNotDelegated gas,", label[i], g);
            assertLt(g, 400);
        }
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

    /// When the guard passes, the wallet gets the full cap: a wallet burning ~46k still answers valid.
    function test_1271_guardPassed_walletGetsFullCap() public {
        wallet.setMode(Mock1271Wallet.Mode.Burn);
        bytes memory sig = _sig(PK, D);
        // F185: was 58,000. The guard needs 55,793 (50,000 * 64 / 63 + 5,000) and 4,276 are spent before it (the wallet's
        // cold code read; Osaka: at most 2,207, EIP-8038 raises the cold account access under Amsterdam)
        assertTrue(h.isValid{gas: 62_000}(address(wallet), D, sig, SigCheck.ERC1271_GAS));
    }
}
