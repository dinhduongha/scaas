// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {IMetaTokenV2} from "../../../src/metatx/IMetaTokenV2.sol";
import {IUALedger} from "../../../src/metatx/IUALedger.sol";
import {MetaTokenBase} from "../../../src/metatx/MetaTokenBase.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../../src/common/FeePolicy.sol";
import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {MtxDigest} from "../../helpers/MtxDigest.sol";
import {PayMetaKit} from "../../helpers/PayMetaKit.sol";
import {nid} from "../../helpers/Ids.sol";

/// The handler of the pay-meta-tax invariants (spec §13, plan T43) on one kind 8 token with `TAX` and a notice period: every
/// pay entry (`mtxPay`, `payWithFee`, `mtxPayWithTax`, `payWithTax`), the two tax powers, time. Each call checks what it
/// can see and counts a violation by number (`vio[j]`, the first reason in `why`); `hits[j]` counts the checks that had
/// something to check, so a vacuous pass is visible. **UNAUDITED.**
contract PayTaxHandler is Test {
    bytes32 internal constant UA_PAY_WITH_TAX = keccak256(
        "UAPayWithTax(UAMetaTransfer payment,uint8 taxMode,uint256 tax)UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    address internal constant RELAYER = address(0xBEEF);

    address public immutable t;
    address internal immutable issuer;
    address[2] internal recipients;
    uint256[3] internal pks = [uint256(0xE01), 0xE02, 0xE03]; // apart from the fixture's keys
    address[3] public eoas;
    uint256 internal seeds;

    mapping(uint256 => uint256) public vio;
    mapping(uint256 => uint256) public hits;
    string public why;

    constructor(address t_, address issuer_, address r0, address r1) {
        (t, issuer, recipients) = (t_, issuer_, [r0, r1]);
        for (uint256 i; i < 3; ++i) eoas[i] = vm.addr(pks[i]);
    }

    function recipient(uint256 i) external view returns (address) {
        return recipients[i];
    }

    function _bad(uint256 j, string memory w) internal {
        if (vio[j]++ == 0 && bytes(why).length == 0) why = string.concat("J", vm.toString(j), ": ", w);
    }

    function _meta() internal returns (MetaTxLib.PayMeta memory m, bytes32 ref) {
        bytes32 s = bytes32(++seeds);
        (m, ref) = (PayMetaKit.meta(s), PayMetaKit.ref(s));
    }

    function _x(uint256 i, uint256 j, uint256 v, bytes32 ref, uint256 lane)
        internal view returns (MetaTxLib.UAMetaTransfer memory x)
    {
        x = MetaTxLib.UAMetaTransfer(nid(eoas[i]), nid(eoas[j]), v, ref, lane, MetaTokenBase(t).mtxNonce(nid(eoas[i]), lane),
            block.timestamp + 300, RR, RELAYER, 0, address(0));
    }

    function _sign(uint256 i, bytes32 d) internal view returns (IUARegistry.UASig memory s) {
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pks[i], d);
        s.signature = abi.encodePacked(r, ss, v);
    }

    function _bal(bytes32 a) internal view returns (uint256) {
        return IERC20(t).balanceOf(address(uint160(uint256(a))));
    }

    /// J1: the call's logs hold exactly one `PaymentMeta` for `ref`, before its `UAPaymentSettled`.
    function _j1(bytes32 ref) internal {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        (uint256 n, uint256 pm, uint256 ps) = (0, type(uint256).max, type(uint256).max);
        for (uint256 k; k < logs.length; ++k) {
            if (logs[k].emitter != t || logs[k].topics.length == 0) continue;
            if (logs[k].topics[0] == IMetaTokenV2.PaymentMeta.selector && logs[k].topics[1] == ref) {
                ++n;
                if (pm == type(uint256).max) pm = k;
            }
            if (logs[k].topics[0] == IUALedger.UAPaymentSettled.selector && ps == type(uint256).max) ps = k;
        }
        ++hits[1];
        if (n != 1) _bad(1, "not one PaymentMeta");
        else if (ps != type(uint256).max && pm > ps) _bad(1, "PaymentMeta after the settled event");
    }

    /// J4 (the rule of the rate): the effective rate never rises before `eta`; at `eta` it is the pending one.
    function _j4(uint32 effBefore, IRegulatedToken.TaxConfig memory c0) internal {
        IRegulatedToken.TaxConfig memory c = IRegulatedToken(t).taxConfig();
        if (c.effectivePpm <= effBefore) return;
        ++hits[4];
        if (c0.eta == 0 || block.timestamp < c0.eta || c.effectivePpm != c0.pendingPpm) _bad(4, "rate rose before eta");
    }

    // ------------------------------------------------------------------ the pay entries

    function pay(uint256 i, uint256 j, uint256 v, uint256 lane) external {
        (i, j, lane) = (i % 3, j % 3, lane % 4);
        if (i == j) return;
        v = bound(v, 0, IERC20(t).balanceOf(eoas[i]));
        (MetaTxLib.PayMeta memory m, bytes32 ref) = _meta();
        MetaTxLib.UAMetaTransfer memory x = _x(i, j, v, ref, lane);
        IUARegistry.UASig memory s = _sign(i, MetaTokenBase(t).mtxTransferDigest(x));
        vm.recordLogs();
        vm.prank(RELAYER);
        MetaTokenBase(t).mtxPay(x, s, m);
        _j1(ref);
        // J2: the same signature never lands twice, on this entry or the plain transfer
        ++hits[2];
        vm.prank(RELAYER);
        try MetaTokenBase(t).mtxPay(x, s, m) returns (bool) { _bad(2, "mtxPay replayed"); } catch {}
        vm.prank(RELAYER);
        try MetaTokenBase(t).mtxExecuteTransfer(x, s) returns (bool) { _bad(2, "replayed as a plain transfer"); } catch {}
    }

    function payDirect(uint256 i, uint256 j, uint256 v) external {
        (i, j) = (i % 3, j % 3);
        if (i == j) return;
        v = bound(v, 0, IERC20(t).balanceOf(eoas[i]));
        (MetaTxLib.PayMeta memory m, bytes32 ref) = _meta();
        vm.recordLogs();
        vm.prank(eoas[i]);
        MetaTokenBase(t).payWithFee(eoas[j], v, FeeMode.NONE, 0, address(0), ref, m);
        _j1(ref);
    }

    /// J1-J5 on `mtxPayWithTax`: PERCENT at the effective rate or AMOUNT up to `value`; the books, the leg, the replay.
    function payTax(uint256 i, uint256 j, uint256 v, bool percent, uint256 amt) external {
        (i, j) = (i % 3, j % 3);
        if (i == j) return;
        v = bound(v, 0, IERC20(t).balanceOf(eoas[i]));
        uint256 tax = percent ? Math.mulDiv(v, IRegulatedToken(t).taxConfig().effectivePpm, 1_000_000) : bound(amt, 0, v);
        uint8 mode = percent ? 1 : 2;
        (MetaTxLib.PayMeta memory m, bytes32 ref) = _meta();
        MetaTxLib.UAMetaTransfer memory x = _x(i, j, v, ref, 9);
        IUARegistry.UASig memory s =
            _sign(i, MtxDigest.typed(t, keccak256(abi.encode(UA_PAY_WITH_TAX, MetaTxLib.hashStruct(x), mode, tax))));
        bytes32 r = IRegulatedToken(t).taxConfig().taxRecipient;
        uint256[3] memory b0 = [_bal(x.from), _bal(x.to), _bal(r)];
        vm.recordLogs();
        vm.prank(RELAYER);
        IRegulatedToken(t).mtxPayWithTax(x, mode, tax, s, m);
        _j1(ref);
        _books(x.from, x.to, r, v, tax, b0);
        ++hits[2];
        vm.prank(RELAYER);
        try IRegulatedToken(t).mtxPayWithTax(x, mode, tax, s, m) returns (bool) { _bad(2, "mtxPayWithTax replayed"); } catch {}
    }

    function payTaxDirect(uint256 i, uint256 j, uint256 v, bool percent, uint256 amt) external {
        (i, j) = (i % 3, j % 3);
        if (i == j) return;
        v = bound(v, 0, IERC20(t).balanceOf(eoas[i]));
        uint256 tax = percent ? Math.mulDiv(v, IRegulatedToken(t).taxConfig().effectivePpm, 1_000_000) : bound(amt, 0, v);
        (MetaTxLib.PayMeta memory m, bytes32 ref) = _meta();
        bytes32 r = IRegulatedToken(t).taxConfig().taxRecipient;
        (bytes32 from, bytes32 to) = (nid(eoas[i]), nid(eoas[j]));
        uint256[3] memory b0 = [_bal(from), _bal(to), _bal(r)];
        vm.recordLogs();
        vm.prank(eoas[i]);
        IRegulatedToken(t).payWithTax(to, v, percent ? 1 : 2, tax, ref, m);
        _j1(ref);
        _books(from, to, r, v, tax, b0);
    }

    /// J3 (books, fee 0 here) and J5 (the leg: the configured recipient, never 0, a pool, the token or the payee; at most
    /// the value).
    function _books(bytes32 from, bytes32 to, bytes32 r, uint256 v, uint256 tax, uint256[3] memory b0) internal {
        ++hits[3];
        if (_bal(from) != b0[0] - v || _bal(to) != b0[1] + v - tax || _bal(r) != b0[2] + tax) _bad(3, "books");
        ++hits[5];
        if (r == 0 || r == to || r == MetaTxLib.pad(MetaTxLib.UA_POOL) || r == MetaTxLib.pad(MetaTxLib.SHIELD_POOL)
            || r == nid(t) || tax > v) _bad(5, "the tax leg");
        if (tax != 0) ++hits[6];
    }

    // ------------------------------------------------------------------ the tax powers, time

    function setRate(uint32 ppm) external {
        IRegulatedToken.TaxConfig memory c0 = IRegulatedToken(t).taxConfig();
        uint32 eff = c0.effectivePpm;
        if (c0.eta != 0 && block.timestamp >= c0.eta) (c0.eta, eff) = (0, c0.pendingPpm); // folded first
        vm.prank(issuer);
        IRegulatedToken(t).setTaxRate(uint32(bound(ppm, 0, 1_000_000)));
        _j4(eff, c0);
    }

    function setRecipient(uint256 k) external {
        vm.prank(issuer);
        IRegulatedToken(t).setTaxRecipient(nid(recipients[k % 2]));
    }

    function warp(uint32 dt) external {
        IRegulatedToken.TaxConfig memory c0 = IRegulatedToken(t).taxConfig();
        vm.warp(block.timestamp + bound(dt, 0, 5 days));
        _j4(c0.effectivePpm, c0);
    }
}
