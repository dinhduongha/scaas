// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";
import {IPqzToken} from "./IPqzToken.sol";
import {IConfidentialWrappedToken} from "../confidential/IConfidentialToken.sol";
import {PqzCt} from "./PqzCt.sol";
import {PqzSafety} from "./PqzSafety.sol";
import {PqzKeyVerifier} from "./PqzKeyVerifier.sol";
import {PqzCore} from "./PqzCore.sol";

/// @title statement views and disclosure (D14): one of the four `DELEGATECALL` libraries of the PQZ release (plan 5h D14), in the ERC-7201
///        namespace `scaas.pqz`; the shared steps are `internal` in `PqzCore`, compiled into each.
/// @notice **UNAUDITED.** `address(this)` is the token.
library PqzViewLib {
    bytes32 private constant TH_TRANSFER_ARGS = keccak256(
        "PqzTransferArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,bytes32 ownTag,bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes sealedMemo)"
    );
    bytes32 private constant TH_LEG = keccak256("PqzLeg(bytes32 ua,bytes v,bytes vAuditor)");
    bytes32 private constant TH_MULTI_ARGS = keccak256(
        "PqzMultiArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,bytes32 ownTag,bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo)PqzLeg(bytes32 ua,bytes v,bytes vAuditor)"
    );
    bytes32 private constant TH_BURN_ARGS = keccak256(
        "PqzBurnArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,bytes32 ownTag,bytes u,bytes vFrom)"
    );
    bytes32 private constant TH_UNWRAP = keccak256("Unwrap(address underlying,bytes32 recipient,uint256 amount,uint256 minOut)");

    /// @notice The op 7 statement an entry point would build for `t`, after every cheap check; a `sealedMemo` reads as
    ///         commit-reveal. `T` is read from the current state (plan 5h D5). Public, so the builders stay in the library
    ///         and out of the tokens' code.
    function multiStatement(PqzCore.Env memory e, IPqzToken.PqzMultiArgs calldata t) public view returns (bytes memory) {
        e.mode = t.sealedMemo.length != 0 ? ZetherTypes.TransferMode.HASH : PqzCore._defaultMode();
        (, bytes memory buf) = PqzCore.prepareMulti(e, t, msg.data[0:0], 0);
        return PqzCore._stmtOf(buf);
    }

    /// @notice The op 1 statement, as `multiStatement`.
    function singleStatement(PqzCore.Env memory e, IPqzToken.PqzTransferArgs calldata t) public view returns (bytes memory) {
        e.mode = t.sealedMemo.length != 0 ? ZetherTypes.TransferMode.HASH : PqzCore._defaultMode();
        (, bytes memory buf) = PqzCore.prepareTransfer(e, t, msg.data[0:0], 0);
        return PqzCore._stmtOf(buf);
    }

    /// @notice The burn / refresh statement of `e.amount`, `e.recipient`.
    function burnStatement(PqzCore.Env memory e, IPqzToken.PqzBurnArgs calldata b) public view returns (bytes memory) {
        (, bytes memory buf) = PqzCore.prepareBurn(e, b, msg.data[0:0], 0);
        return PqzCore._stmtOf(buf);
    }

    // ------------------------------------------------------------------ EIP-712 hashes of the explicit parameters (TS-D17)

    function hashTransfer(IPqzToken.PqzTransferArgs calldata t) public pure returns (bytes32) {
        return keccak256(bytes.concat(
            abi.encode(TH_TRANSFER_ARGS, t.p, t.validUntilBlock, t.shieldIn, t.fromUA, t.keyVersion, t.toUA, t.beneficiaryUA, t.salt,
                t.ownTag),
            abi.encode(keccak256(t.u), keccak256(t.vTo), keccak256(t.vFrom), keccak256(t.vAuditor), keccak256(t.sealedMemo))
        ));
    }

    function hashMulti(IPqzToken.PqzMultiArgs calldata t) public pure returns (bytes32) {
        return keccak256(bytes.concat(
            abi.encode(TH_MULTI_ARGS, t.p, t.validUntilBlock, t.shieldIn, t.fromUA, t.keyVersion, t.beneficiaryUA, t.decoyFee, t.salt,
                t.ownTag),
            abi.encode(_hashParts(t.u), _hashLegs(t.legs), keccak256(t.vFrom), keccak256(t.sealedMemo))
        ));
    }

    function hashBurn(IPqzToken.PqzBurnArgs calldata b) public pure returns (bytes32) {
        return keccak256(abi.encode(TH_BURN_ARGS, b.p, b.validUntilBlock, b.shieldIn, b.fromUA, b.keyVersion, b.beneficiaryUA,
            b.ownTag, keccak256(b.u), keccak256(b.vFrom)));
    }

    function hashUnwrap(IConfidentialWrappedToken.Unwrap calldata x) public pure returns (bytes32) {
        return keccak256(abi.encode(TH_UNWRAP, x));
    }

    function _hashParts(bytes[] calldata u) private pure returns (bytes32) {
        bytes32[] memory h = new bytes32[](u.length);
        for (uint256 g; g < u.length; ++g) h[g] = keccak256(u[g]);
        return keccak256(abi.encodePacked(h));
    }

    function _hashLegs(IPqzToken.PqzLeg[] calldata legs) private pure returns (bytes32) {
        bytes32[] memory h = new bytes32[](legs.length);
        for (uint256 j; j < legs.length; ++j) {
            h[j] = keccak256(abi.encode(TH_LEG, legs[j].ua, keccak256(legs[j].v), keccak256(legs[j].vAuditor)));
        }
        return keccak256(abi.encodePacked(h));
    }

    /// @notice The disclosure statement of leg `leg` of `ref`, `R` from the op blob (reverts as
    ///         `PqzCore.disclosureBuffer`).
    function disclosureStatementOf(bytes32 ref, uint256 leg, uint256 amount, uint8 kind, uint64 keyVersion,
        PqzCore.Env memory e) public view returns (bytes memory)
    {
        return PqzCore._stmtOf(PqzCore.disclosureBuffer(ref, leg, amount, kind, keyVersion, e, 0));
    }

    /// @notice Group 3f (spec §5.4): the `OFFCHAIN` disclosure's answer, spec §5.3 against the statement's and the proof's
    ///         hashes (`UAVerifyGas` reverts).
    function verdictOk(bytes32 sh, bytes32 ph, IPqzToken.PqzSignedVerdict calldata pqzVerdict, PqzCore.Env memory e) public view returns (bool)
    {
        return PqzCore.verdictStatus(sh, ph, pqzVerdict, e.registry, e.domainSeparator) == 0;
    }

    /// @notice Group 3h (PP-2, `pqzDebitRecord`): the record's two words as named fields; no record (`w0 == 0`):
    ///         `DebitRecordUnknown`. A narrow record with a predecessor has `prevCounter = counter − 1`.
    function debitRecord(bytes32 ua, uint64 counter) public view returns (IPqzToken.DebitRecordView memory r) {
        PqzCore.DebitRecord storage d = PqzCore.$().debitRec[ua][counter];
        uint256 w0 = d.w0;
        if (w0 == 0) revert IPqzToken.DebitRecordUnknown(ua, counter);
        (r.prevBlob, r.p, r.deltaP, r.proofStore) = (address(uint160(w0 >> 96)), uint64(w0 >> 32), uint16(w0 >> 16), uint8(w0 >> 8));
        r.hasPrev = r.prevBlob != address(0);
        if (uint8(w0) & PqzCore.WIDE != 0) {
            uint256 w1 = d.w1;
            (r.shieldIn, r.keyVersion, r.prevCounter) = (uint64(w1 >> 192), uint64(w1 >> 128), uint64(w1 >> 64));
        } else if (r.hasPrev) {
            r.prevCounter = counter - 1;
        }
    }

    /// @notice The precompile's verdict on the disclosure of leg `leg` with `proof` (the token checked the shape).
    function verifyAmountOf(bytes32 ref, uint256 leg, uint256 amount, uint8 kind, uint64 keyVersion, bytes calldata proof,
        PqzCore.Env memory e) public view returns (bool)
    {
        bytes memory buf = PqzCore.disclosureBuffer(ref, leg, amount, kind, keyVersion, e, proof.length);
        uint256 off = PqzCore.DISCLOSE;
        assembly ("memory-safe") { calldatacopy(add(add(buf, 37), off), proof.offset, proof.length) }
        return PqzCore.verdict(PqzCore.$().pqz, buf);
    }
}
