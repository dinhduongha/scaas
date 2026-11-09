// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";

import {NormalZetherToken} from "../../../src/zether/NormalZetherToken.sol";

import {Vm} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {PqzRegFixture} from "./PqzRegFixture.sol";
import {ZetherRegFixture} from "./ZetherRegFixture.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {IMetaTokenV2} from "../../../src/metatx/IMetaTokenV2.sol";
import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {MtxDigest} from "../../helpers/MtxDigest.sol";
import {PayMetaKit} from "../../helpers/PayMetaKit.sol";
import {nid} from "../../helpers/Ids.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {WrappedPqzToken} from "../../../src/pqz/WrappedPqzToken.sol";
import {ZetherLayer} from "../../../src/zether/ZetherLayer.sol";

/// The tax rows every confidential regulated kind shares (pay-meta-tax spec §5.1, O8, B-2, B-3, J7): a public pay with tax
/// works on 10-13 (PERCENT too: `requireConfidentialSafe` does not apply to a public pay), and no confidential op has a tax
/// leg: a shielded transfer and an unshield with `TAX` set emit no `PaymentTaxed` and read neither `scaas.regulated` +5
/// nor +6. **UNAUDITED.**
library TaxRows {
    bytes32 internal constant UA_PAY_WITH_TAX = keccak256(
        "UAPayWithTax(UAMetaTransfer payment,uint8 taxMode,uint256 tax)UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `scaas.regulated` (RegulatedLib._STORAGE) +5, +6.
    bytes32 internal constant SLOT5 = bytes32(uint256(0xb2c09f76d73c73fd19cb676c5bc2ea2b05d0674d12ed1b6dc6508457a3913d00) + 5);
    bytes32 internal constant SLOT6 = bytes32(uint256(0xb2c09f76d73c73fd19cb676c5bc2ea2b05d0674d12ed1b6dc6508457a3913d00) + 6);
    address internal constant TAX_TO = address(0x7A0);
    /// Plan T83: the `payNo` of the public pay saved before the confidential ops, and `scaas.pay.records`' root.
    bytes32 internal constant NO = bytes32(uint256(0x019a6e3c5f007a3b8c4d5e6f708192a3));
    bytes32 internal constant RECORDS = 0x51f719d8931af2fa9a126c65fc0e6dd2bb24ee24e9808e19427ae58097f31a00;

    /// Plan T83: a confidential op writes no pay record: `NO`'s count stays 1, none of its slots (the length, the record's
    /// two words, the next record's) is written, no `PaymentMeta`.
    function noRecord(Vm vm, address t, bytes32[] memory writes, Vm.Log[] memory logs) internal view {
        bytes32 len = keccak256(abi.encode(NO, RECORDS));
        uint256 d = uint256(keccak256(abi.encode(len)));
        for (uint256 j; j < writes.length; ++j) {
            uint256 w = uint256(writes[j]);
            require(writes[j] != len && (w < d || w > d + 3), "a pay record slot written by a confidential op");
        }
        for (uint256 j; j < logs.length; ++j) {
            require(logs[j].topics.length == 0 || logs[j].topics[0] != IMetaTokenV2.PaymentMeta.selector,
                "PaymentMeta on a confidential op");
        }
        require(uint256(vm.load(t, len)) == 1, "the saved record count moved");
        require(IMetaTokenV2(t).paymentCount(NO) == 1, "paymentCount moved");
    }
}

/// B-5: kind 11 with bit 23 and `taxRecipient = 0` is refused at creation (`RegulatedLib.init` through `_initRaw`).
contract TaxConfidential11Test is ZetherRegFixture {
    function _isWrapped() internal pure override returns (bool) {
        return true;
    }

    function test_taxRecipientZeroInitRefused_11() public {
        IFactoryToken.TokenConfig memory c = _regCfg(true, 1 << 40);
        c.features |= 1 << GovernanceBits.TAX;
        vm.expectRevert(IRegulatedToken.RegulatedConfigInvalid.selector);
        factory.createToken(_kind(), 1, abi.encode(c), "tax0");
        c.reg.taxRecipient = nid(TaxRows.TAX_TO); // control
        factory.createToken(_kind(), 1, abi.encode(c), "tax1");
    }
}

/// B-5: kind 13 likewise.
contract TaxConfidential13Test is PqzRegFixture {
    function _isWrapped() internal pure override returns (bool) {
        return true;
    }

    function test_taxRecipientZeroInitRefused_13() public {
        IFactoryToken.TokenConfig memory c = _regCfg();
        c.features |= 1 << GovernanceBits.TAX;
        vm.expectRevert(IRegulatedToken.RegulatedConfigInvalid.selector);
        factory.createToken(_kind(), 1, abi.encode(c), "tax0");
        c.reg.taxRecipient = nid(TaxRows.TAX_TO);
        factory.createToken(_kind(), 1, abi.encode(c), "tax1");
    }
}


/// The tax rows of the PQZ kinds 12 (`_isWrapped` false) and 13: the fixture's token with bit 23 and a recipient; the test
/// contract holds public units.
abstract contract TaxPqzRows is PqzRegFixture {
    uint256 internal constant PUB = 1_000_000;

    function setUp() public override {
        super.setUp();
        IFactoryToken.TokenConfig memory c = _regCfg();
        c.features |= uint256(1) << GovernanceBits.TAX;
        c.reg.taxRecipient = nid(TaxRows.TAX_TO);
        tok = NormalPqzToken(factory.createToken(_kind(), 1, abi.encode(c), "ptax"));
        w = WrappedPqzToken(payable(address(tok)));
        _shieldTo(alice, 300);
        _pub(address(this), PUB);
    }

    /// A public pay with tax works (O8), PERCENT included (B-3: `requireConfidentialSafe` does not apply).
    function _payWithTaxOn() internal {
        vm.prank(issuer);
        IRegulatedToken(address(tok)).setTaxRate(100_000);
        IRegulatedToken(address(tok)).payWithTax(alice, 1_000, 1, 100, PayMetaKit.ref("c1"), PayMetaKit.meta("c1"));
        assertEq(tok.balanceOfUA(alice), 900);
        assertEq(tok.balanceOf(TaxRows.TAX_TO), 100);
    }

    /// J7: a shield, a shielded single transfer and an unshield with `TAX` set: no `PaymentTaxed`, no read or write of
    /// `scaas.regulated` +5 / +6.
    function _noTaxLeg() internal {
        MetaTxLib.PayMeta memory m = PayMetaKit.saved("t83.c", TaxRows.NO); // plan T83: one saved public pay first
        IRegulatedToken(address(tok)).payWithTax(alice, 1_000, 2, 1, PayMetaKit.id(m), m);
        for (uint256 i; i < 3; ++i) {
            uint256 snap = vm.snapshotState();
            vm.recordLogs();
            vm.record();
            if (i == 0) {
                _shieldTo(alice, 1);
            } else {
                (bool ok,,) = _try(_opCall(i == 1 ? 2 : 4, bytes32(0), 0));
                assertTrue(ok, "the confidential op ran");
            }
            (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tok));
            for (uint256 j; j < reads.length; ++j) {
                assertTrue(reads[j] != TaxRows.SLOT5 && reads[j] != TaxRows.SLOT6, "a tax slot read");
            }
            for (uint256 j; j < writes.length; ++j) assertTrue(writes[j] != TaxRows.SLOT5 && writes[j] != TaxRows.SLOT6);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            for (uint256 j; j < logs.length; ++j) assertTrue(logs[j].topics.length == 0
                || logs[j].topics[0] != IRegulatedToken.PaymentTaxed.selector, "PaymentTaxed on a confidential op");
            TaxRows.noRecord(vm, address(tok), writes, logs);
            vm.revertToState(snap);
        }
    }
}

contract TaxPqz12Test is TaxPqzRows {
    function _isWrapped() internal pure override returns (bool) {
        return false;
    }

    function test_payWithTax_on_12() public { _payWithTaxOn(); }
    function test_confidentialOps_noTaxLeg_12() public { _noTaxLeg(); }
}

contract TaxPqz13Test is TaxPqzRows {
    function _isWrapped() internal pure override returns (bool) {
        return true;
    }

    function test_payWithTax_on_13() public { _payWithTaxOn(); }
    function test_confidentialOps_noTaxLeg_13() public { _noTaxLeg(); }
}

/// The tax rows of the Zether kinds 10 (`_isWrapped` false) and 11: the fixture's token re-created with bit 23 and a
/// recipient; `alice` holds `BAL` shielded, this test holds public units.
abstract contract TaxZetherRows is ZetherRegFixture {
    uint256 internal constant BAL = 50;
    uint256 internal constant PUB = 1_000_000;
    address internal constant PAYEE = address(0xB0B5);

    function setUp() public override {
        super.setUp();
        IFactoryToken.TokenConfig memory c = _regCfg(true, 1 << 40);
        c.features |= uint256(1) << GovernanceBits.TAX;
        c.reg.taxRecipient = nid(TaxRows.TAX_TO);
        tok = NormalZetherToken(factory.createToken(_kind(), 1, abi.encode(c), "ztax"));
        _funded(BAL);
        _public(tok, address(this), PUB);
    }

    /// A public pay with tax works (O8), PERCENT included (B-3: `requireConfidentialSafe` does not apply).
    function _payWithTaxOn() internal {
        vm.prank(issuer);
        IRegulatedToken(address(tok)).setTaxRate(100_000);
        IRegulatedToken(address(tok)).payWithTax(nid(PAYEE), 1_000, 1, 100, PayMetaKit.ref("z1"), PayMetaKit.meta("z1"));
        assertEq(IERC20(address(tok)).balanceOf(PAYEE), 900);
        assertEq(IERC20(address(tok)).balanceOf(TaxRows.TAX_TO), 100);
    }

    /// J7: a shield, a shielded single transfer and an unshield with `TAX` set: no `PaymentTaxed`, no read or write of
    /// `scaas.regulated` +5 / +6.
    function _noTaxLeg() internal {
        MetaTxLib.PayMeta memory m = PayMetaKit.saved("t83.z", TaxRows.NO); // plan T83: one saved public pay first
        IRegulatedToken(address(tok)).payWithTax(nid(PAYEE), 1_000, 2, 1, PayMetaKit.id(m), m);
        for (uint256 i; i < 3; ++i) {
            uint256 snap = vm.snapshotState();
            vm.recordLogs();
            vm.record();
            if (i == 0) {
                tok.mtxShield(aId, 1);
            } else {
                (bool ok,,) = _try(_opCall(i == 1 ? 2 : 3, BAL, 0));
                assertTrue(ok, "the confidential op ran");
            }
            (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tok));
            for (uint256 j; j < reads.length; ++j) {
                assertTrue(reads[j] != TaxRows.SLOT5 && reads[j] != TaxRows.SLOT6, "a tax slot read");
            }
            for (uint256 j; j < writes.length; ++j) assertTrue(writes[j] != TaxRows.SLOT5 && writes[j] != TaxRows.SLOT6);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            for (uint256 j; j < logs.length; ++j) assertTrue(logs[j].topics.length == 0
                || logs[j].topics[0] != IRegulatedToken.PaymentTaxed.selector, "PaymentTaxed on a confidential op");
            TaxRows.noRecord(vm, address(tok), writes, logs);
            vm.revertToState(snap);
        }
    }
}

contract TaxZether10Test is TaxZetherRows {
    function _isWrapped() internal pure override returns (bool) {
        return false;
    }

    function test_payWithTax_on_10() public { _payWithTaxOn(); }
    function test_confidentialOps_noTaxLeg_10() public { _noTaxLeg(); }
}

contract TaxZether11Test is TaxZetherRows {
    function _isWrapped() internal pure override returns (bool) {
        return true;
    }

    function test_payWithTax_on_11() public { _payWithTaxOn(); }
    function test_confidentialOps_noTaxLeg_11() public { _noTaxLeg(); }
}
