// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {PqzRegFixture} from "./PqzRegFixture.sol";
import {ZetherRegFixture} from "./ZetherRegFixture.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {MtxDigest} from "../../helpers/MtxDigest.sol";
import {PayMetaKit} from "../../helpers/PayMetaKit.sol";
import {nid} from "../../helpers/Ids.sol";

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
