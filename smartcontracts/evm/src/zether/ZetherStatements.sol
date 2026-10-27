// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IMetaTx} from "../metatx/IMetaTx.sol";
import {IZetherToken} from "./IZetherToken.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {ZetherLib} from "./ZetherLib.sol";

/// @title The prover views of every Zether token (CTR-ZTH-46): the statement a token will build at this block.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Stateless, no admin, no upgrade, one instance for every token on
///         every curve (as `ZetherDisclosure`). It reads the token's views (`verifier`, `registry`, `chainUid`,
///         `confidentialFee`, `minDecoyFee`, `maxDecryptableShielded`, `auditorKey`, `auditorMode`, `disclosureMode`, `accountState`)
///         and runs the token's own builders (`ZetherLib`, internal), so the bytes are the token's, with the same cheap
///         checks. The caller picks the token it trusts. `envelopeBinding` 0 = a direct call (`ZTX_V1_DIRECT`), else the envelope's binding
///         (`ZTX_V1_RELAYED`, `IZetherToken.envelopeBinding`).
contract ZetherStatements {
    /// @notice The multi-recipient statement by its stored form `mode`: BUNDLE (`mtxConfidentialTransfer` on a `BUNDLE` token), HASH
    ///         (`mtxConfidentialTransferCompact`, and `mtxConfidentialTransfer` on a `COMPACT` token; the payload ends with the memo).
    ///         `TransferEntryDisabled` for a form other than HASH on a `COMPACT` token, the
    ///         auditor errors by `auditorMode`.
    function transferStatement(
        address token,
        bytes calldata payload,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode,
        bytes32 envelopeBinding
    ) external view returns (bytes memory) {
        ZetherLib.Ctx memory c = _ctx(token, ZetherLib.tagOf(envelopeBinding), envelopeBinding);
        ZetherLib.Acct memory a = _acct(token, ZetherLib.multiFrom(payload, c.p));
        return ZetherLib.prepareMulti(c, a, payload, beneficiary, mode).statement;
    }

    /// @notice The single-recipient statement (`mtxConfidentialTransferSingle`).
    function transferStatementSingle(
        address token,
        bytes calldata payload,
        ZetherTypes.UA beneficiary,
        bytes32 envelopeBinding
    ) external view returns (bytes memory) {
        ZetherLib.Ctx memory c = _ctx(token, ZetherLib.tagOf(envelopeBinding), envelopeBinding);
        ZetherLib.Acct memory a = _acct(token, ZetherLib.singleFrom(payload, c.p));
        return ZetherLib.prepareSingle(c, a, payload, beneficiary).statement;
    }

    /// @notice The unshield statement (`mtxUnshield`; built: `burnStatement`).
    function unshieldStatement(
        address token,
        bytes calldata payload,
        uint256 amount,
        bytes32 recipient,
        ZetherTypes.UA beneficiary,
        bytes32 envelopeBinding
    ) external view returns (bytes memory) {
        return _unshield(token, payload, amount, recipient, beneficiary, ZetherLib.tagOf(envelopeBinding), envelopeBinding);
    }

    /// @notice The statement of `mtxUnshieldUnwrap` on an `UNDERLYING_ZETHER` token: relayed, the envelope binding;
    ///         direct, `ZTX_V1_DIRECT` with the leg and `minOut` bound (`unwrapBinding`).
    function unshieldUnwrapStatement(
        address token,
        bytes calldata payload,
        uint256 amount,
        bytes32 recipient,
        ZetherTypes.UA beneficiary,
        address u,
        uint256 minOut,
        bytes32 envelopeBinding
    ) external view returns (bytes memory) {
        if (envelopeBinding != bytes32(0)) {
            return _unshield(token, payload, amount, recipient, beneficiary, ZetherLib.TAG_RELAYED, envelopeBinding);
        }
        return _unshield(token, payload, amount, recipient, beneficiary, ZetherLib.TAG_DIRECT, unwrapBinding(u, minOut));
    }

    /// @notice The binding word of a direct `mtxUnshieldUnwrap` (controller ruling, pending the owner).
    function unwrapBinding(address u, uint256 minOut) public pure returns (bytes32) {
        return ZetherLib.unwrapBinding(u, minOut);
    }

    function _unshield(
        address token,
        bytes calldata payload,
        uint256 amount,
        bytes32 recipient,
        ZetherTypes.UA beneficiary,
        bytes32 tag,
        bytes32 binding
    ) internal view returns (bytes memory) {
        ZetherLib.Ctx memory c = _ctx(token, tag, binding);
        ZetherLib.Acct memory a = _acct(token, ZetherLib.unshieldFrom(payload, c.p));
        return ZetherLib.prepareUnshield(c, a, payload, amount, recipient, beneficiary).statement;
    }

    function _ctx(address token, bytes32 tag, bytes32 binding) internal view returns (ZetherLib.Ctx memory c) {
        IZetherToken t = IZetherToken(token);
        c.ver = t.verifier();
        c.registry = t.registry();
        c.token = token;
        c.chainUid = IMetaTx(token).chainUid();
        c.psid = c.ver.proofSystemId();
        c.p = c.ver.g1EncodedBytes();
        c.fee = t.confidentialFee();
        c.minDecoyFee = t.minDecoyFee();
        c.maxShielded = t.maxDecryptableShielded();
        c.auditorKey = t.auditorKey();
        c.auditorMode = t.auditorMode();
        c.disclosureMode = t.disclosureMode();
        c.tag = tag;
        c.binding = binding;
    }

    function _acct(address token, ZetherTypes.UA from) internal view returns (ZetherLib.Acct memory) {
        IZetherToken.AccountState memory s = IZetherToken(token).accountState(from);
        return ZetherLib.Acct(s.accC, s.accD, s.accSeq, s.sendCounter);
    }
}
