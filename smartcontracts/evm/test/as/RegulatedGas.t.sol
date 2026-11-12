// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";
import {ListFixture} from "./helpers/ListFixture.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {nid} from "../helpers/Ids.sol";

/// Round 3s, spec 2026-11-10-token-lists.md §14, §13 (7): the regulated transfer rows of kind 8, each measured on a cold
/// token, sender, receiver and registry (`vm.cool`) after one priming transfer, so every row reads the same state shape:
/// no control on, the two lists, `KYC` (one bounded registry call), `KYC` with a list; `mtxTransfer` at fee 0 and with a
/// fee under the lists. Each figure is pinned (`PIN_*`): a pin moves only with old → new in the commit.
contract RegulatedGasTest is ListFixture {
    uint256 constant PIN_PLAIN = 52_844;
    uint256 constant PIN_LISTS = 57_480;
    uint256 constant PIN_KYC = 61_857;
    uint256 constant PIN_KYC_LIST = 66_465;
    uint256 constant PIN_MTX_LISTS = 97_166;
    uint256 constant PIN_MTX_FEE_LISTS = 120_651;
    /// T9 (no regulated transfer pin existed before; spec §14's estimates: lists +4.6 k over no control, measured; KYC +9.0 k,
    /// KYC with a list +13.6 k): measured at 298ddc5b, Foundry 1.8.5, the token's frame gas. Stacked gate (3r + 3s + 3t): the
    /// two `mtxExecuteTransfer` rows 97,074 -> 97,075 and 120,471 -> 120,472, from round 3t's two `ConfidentialConfig` fields
    /// (`verifierFee`, `verifierFeeMax`) alone (the 3s tip with only that struct change measures the same +1).
    /// Fable review fixes (2026-11-11, B P3-1: `_poolMove` refuses a native `UA_POOL` side, one check per move): 97,075 ->
    /// 97,189 and 120,472 -> 120,674 (two moves); the plain transfer rows unchanged. Fable recheck-2 P3-1 (CTR-GOV-27: the
    /// face's `renounceAdmin(bytes32)` selector moves its dispatch tree, nothing in the transfer path): 97,189 -> 97,144 and
    /// 120,674 -> 120,629. Fix3 CTR-GOV-28 (the faces' admin entries take `chainUid_`: their selectors move the dispatch
    /// tree, nothing in the transfer path): the transfer rows 52,867 -> 52,844, 57,503 -> 57,480, 61,880 -> 61,857, 66,488 ->
    /// 66,465; the `mtxExecuteTransfer` rows 97,144 -> 97,166 and 120,629 -> 120,651.
    bool constant PINNED = true;

    uint256 nonce;

    function _measure(string memory label, address t, address sender, bytes memory cd, uint256 pin) internal {
        vm.cool(t);
        vm.cool(sender);
        vm.cool(bob);
        vm.cool(relayer);
        vm.cool(address(creg));
        vm.prank(sender);
        uint256 g0 = gasleft();
        (bool ok,) = t.call(cd);
        uint256 used = g0 - gasleft();
        assertTrue(ok, label);
        console.log("REGGAS", label, used);
        if (PINNED) assertEq(used, pin, label);
    }

    function _prime(address t, bytes memory cd) internal {
        vm.prank(relayer);
        (bool ok,) = t.call(cd);
        assertTrue(ok, "prime");
    }

    function _tokenWith(uint256 on, bytes32 salt) internal returns (address t) {
        t = _lt(0, on, 0, salt);
        _setList(t, ALLOW, nid(bob), true);
        _setList(t, ALLOW, nid(relayer), true);
        vm.prank(alice);
        NormalToken(t).transfer(bob, 10); // prime: bob's balance slot exists
    }

    function _plainRow(string memory label, uint256 on, bytes32 salt, uint256 pin) internal {
        address t = _tokenWith(on, salt);
        _measure(label, t, bob, abi.encodeWithSignature("transfer(address,uint256)", alice, 1), pin);
    }

    function test_gas_transfer_noControl() public {
        _plainRow("transfer, no control on", 0, "p", PIN_PLAIN);
    }

    function test_gas_transfer_lists() public {
        _plainRow("transfer, ALLOWLIST and DENYLIST", (1 << ALLOW) | (1 << DENY), "l", PIN_LISTS);
    }

    function test_gas_transfer_kyc() public {
        _plainRow("transfer, KYC", 1 << KYC_BIT, "k", PIN_KYC);
    }

    function test_gas_transfer_kycAndList() public {
        _plainRow("transfer, KYC and DENYLIST", (1 << KYC_BIT) | (1 << DENY), "kl", PIN_KYC_LIST);
    }

    function _mtxCd(address t, uint32 mode, uint256 fee) internal returns (bytes memory) {
        MetaTxLib.UAMetaTransfer memory x;
        (x.from, x.to, x.value, x.batch, x.nonce, x.validUntil, x.mode, x.fee) =
            (nid(alice), nid(bob), 100, 1, nonce++, block.timestamp + 60, mode, fee); // FIXED: at most 1 %
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, NormalToken(t).mtxTransferDigest(x));
        IUARegistry.UASig memory a;
        a.signature = abi.encodePacked(r, s, v);
        return abi.encodeCall(NormalToken.mtxExecuteTransfer, (x, a));
    }

    function test_gas_mtxTransfer_lists() public {
        address t = _tokenWith((1 << ALLOW) | (1 << DENY), "m");
        _prime(t, _mtxCd(t, 0, 0));
        _measure("mtxExecuteTransfer fee 0, ALLOWLIST and DENYLIST", t, relayer, _mtxCd(t, 0, 0), PIN_MTX_LISTS);
    }

    function test_gas_mtxTransfer_feeLists() public {
        address t = _tokenWith((1 << ALLOW) | (1 << DENY), "mf");
        _prime(t, _mtxCd(t, MetaTxLib.MODE_FEE_FIXED, 1));
        _measure("mtxExecuteTransfer with a fee, ALLOWLIST and DENYLIST", t, relayer, _mtxCd(t, MetaTxLib.MODE_FEE_FIXED, 1),
            PIN_MTX_FEE_LISTS);
    }
}
