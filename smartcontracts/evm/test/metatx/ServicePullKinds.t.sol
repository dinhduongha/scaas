// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IRig, PlainRig, PqzRig, ZetherRig} from "./helpers/KindRigs.sol";
import {RegRig, ZetherRegRig, PqzRegRig} from "./helpers/RegKindRigs.sol";
import {RefServiceEscrow} from "./helpers/RefServiceEscrow.sol";
import {spDepositRef, spNoteRef, spPull} from "./helpers/ServicePullKit.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";

/// @notice Service pull on every EVM kind (spec 2026-11-09-service-pull §6, §11; plan T77): `NORMAL`, `WRAPPED`, `NORMAL`
///         with the UA ledger off, the public side of `NORMAL_PQZ`, `WRAPPED_PQZ`, `NORMAL_ZETHER`, `WRAPPED_ZETHER`, and
///         the regulated kinds 8-13 (lists off, so S is eligible). One `RefServiceEscrow` per token; the signer `0xA11CE`,
///         funded on every rig, deposits, notes and is released to. The PQZ kinds are the committed set here; the gate runs
///         this file at the four sets (`script/pqz/at-set.sh`). UNAUDITED.
contract ServicePullKindsTest is Test {
    uint256 internal constant PK = 0xA11CE;
    address internal constant REL = address(0x7E1A);
    uint256 internal constant AMT = 1_000;
    uint256 internal constant LANE = 7;

    address internal signer = vm.addr(PK);
    string[] internal kinds;
    address[] internal toks;

    function setUp() public {
        IRig[6] memory rigs;
        RegRig rr = new RegRig();
        rr.init();
        rigs[0] = IRig(address(rr));
        PlainRig plain = new PlainRig();
        plain.init();
        rigs[1] = IRig(address(plain));
        PqzRig pqz = new PqzRig();
        pqz.init();
        rigs[2] = IRig(address(pqz));
        ZetherRig zeth = new ZetherRig();
        zeth.init();
        rigs[3] = IRig(address(zeth));
        ZetherRegRig zr = new ZetherRegRig();
        zr.init();
        rigs[4] = IRig(address(zr));
        PqzRegRig pr = new PqzRegRig();
        pr.init();
        rigs[5] = IRig(address(pr));
        for (uint256 r; r < 6; ++r) {
            (string[] memory k, address[] memory t,) = rigs[r].setup();
            for (uint256 i; i < t.length; ++i) {
                kinds.push(k[i]);
                toks.push(t[i]);
            }
        }
        assertEq(toks.length, 13, "the twelve kinds 0-5, 8-13 and NORMAL with the ledger off");
    }

    function _sig(address t, MetaTxLib.UAMetaTransfer memory x) internal view returns (IUARegistry.UASig memory a) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, MetaTokenBase(t).mtxTransferDigest(x));
        a.signature = abi.encodePacked(r, s, v);
    }

    function _regulated(string memory k) internal pure returns (bool) {
        bytes memory b = bytes(k);
        bytes memory suffix = bytes("_REGULATED");
        if (b.length < suffix.length) return false;
        for (uint256 i; i < suffix.length; ++i) if (b[b.length - suffix.length + i] != suffix[i]) return false;
        return true;
    }

    /// Every kind: `deposit` and `note` pulled (payer -> S, `UAPaymentSettled` with the operation digest), the custody
    /// recorded, both released back; `REGULATED` as the kind.
    function test_positive_everyKind() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            RefServiceEscrow s = new RefServiceEscrow(t);
            assertEq(s.REGULATED(), _regulated(kinds[i]), kinds[i]);
            uint256 b0 = IERC20(t).balanceOf(signer);
            RefServiceEscrow.Deposit memory op =
                RefServiceEscrow.Deposit(MetaTxLib.pad(signer), AMT, uint64(block.timestamp + 1 hours), "kinds");
            bytes32 ref = spDepositRef(address(s), block.chainid, op);
            MetaTxLib.UAMetaTransfer memory x = spPull(op.payer, address(s), AMT, ref, LANE, 0, block.timestamp + 300);
            IUARegistry.UASig memory a = _sig(t, x);
            vm.expectEmit(t);
            emit IUALedger.UAPaymentSettled(op.payer, MetaTxLib.pad(address(s)), AMT, 0, address(s), ref);
            vm.prank(REL);
            s.deposit(op, x, a);
            RefServiceEscrow.Note memory nt = RefServiceEscrow.Note(op.payer, AMT, kinds[i], bytes(kinds[i]), "kinds");
            bytes32 nref = spNoteRef(address(s), block.chainid, nt);
            x = spPull(op.payer, address(s), AMT, nref, LANE, 1, block.timestamp + 300);
            a = _sig(t, x);
            vm.prank(REL);
            s.note(nt, x, a);
            assertEq(IERC20(t).balanceOf(address(s)), 2 * AMT, kinds[i]);
            assertEq(IERC20(t).balanceOf(signer), b0 - 2 * AMT, kinds[i]);
            assertEq(s.owed(), 2 * AMT, kinds[i]);
            s.release(nref);
            vm.warp(block.timestamp + 1 hours);
            s.release(ref);
            assertEq(IERC20(t).balanceOf(signer), b0, kinds[i]);
            assertEq(IERC20(t).balanceOf(address(s)), 0, kinds[i]);
        }
    }
}
