// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {MtxDigest} from "../../helpers/MtxDigest.sol";
import {RefServiceEscrow} from "./RefServiceEscrow.sol";

// The service-pull digests a test signs (spec 2026-11-09-service-pull §3.2, §2.4), computed here from the type strings, not
// by the reference service, so a service on another formula fails. `ServicePull.t`, `ServicePullKinds.t` and the vector
// cross-check (`ServicePullVectors.t`) share them.

bytes32 constant SP_DOMAIN_TYPEHASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
bytes32 constant SP_DEPOSIT_TYPEHASH = keccak256("Deposit(bytes32 payer,uint256 amount,uint64 releaseAfter,bytes32 salt)");
bytes32 constant SP_NOTE_TYPEHASH =
    keccak256("Note(bytes32 payer,uint256 amount,string memo,bytes commitment,bytes32 salt)");
bytes32 constant SP_RELAY_FEE_TYPEHASH = keccak256(
    "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)");

/// The reference service's domain separator at `s` on `chainId` (OpenZeppelin `EIP712`, ERC-5267 fields `0x0f`).
function spDomain(address s, uint256 chainId) pure returns (bytes32) {
    return keccak256(abi.encode(SP_DOMAIN_TYPEHASH, keccak256("SCaaS RefServiceEscrow"), keccak256("1"), chainId, s));
}

/// `entryRef` of a `Deposit` (§3.2): `keccak256(0x1901 ‖ domain(s) ‖ hashStruct(op))`.
function spDepositRef(address s, uint256 chainId, RefServiceEscrow.Deposit memory op) pure returns (bytes32) {
    return keccak256(abi.encodePacked(hex"1901", spDomain(s, chainId),
        keccak256(abi.encode(SP_DEPOSIT_TYPEHASH, op.payer, op.amount, op.releaseAfter, op.salt))));
}

/// `entryRef` of a `Note`: `string` and `bytes` hashed as `keccak256(value)` (EIP-712), passed raw in the ABI.
function spNoteRef(address s, uint256 chainId, RefServiceEscrow.Note memory op) pure returns (bytes32) {
    return keccak256(abi.encodePacked(hex"1901", spDomain(s, chainId), keccak256(abi.encode(SP_NOTE_TYPEHASH, op.payer,
        op.amount, keccak256(bytes(op.memo)), keccak256(op.commitment), op.salt))));
}

/// The pull of §3.3: `to` = `relayer` = `s`, `MODE_RESTRICT_RELAYER`, fee `NONE`, fee 0, no fee recipient.
function spPull(bytes32 from, address s, uint256 value, bytes32 entryRef, uint256 batch, uint256 nonce, uint256 validUntil)
    pure returns (MetaTxLib.UAMetaTransfer memory)
{
    return MetaTxLib.UAMetaTransfer(from, MetaTxLib.pad(s), value, entryRef, batch, nonce, validUntil,
        MetaTxLib.MODE_RESTRICT_RELAYER, s, 0, address(0));
}

/// The digest of a `UARelayFee` the payer signs for `router` in `feeToken`'s domain (CTR-MTX-27, §2.4 (b)).
function spRelayFeeDigest(address feeToken, bytes32 from, address target, bytes memory callData, bytes32 payee,
    uint256 value, uint256 batch, uint256 nonce, uint256 validUntil, address router) view returns (bytes32)
{
    return MtxDigest.typed(feeToken, keccak256(abi.encode(SP_RELAY_FEE_TYPEHASH, from, target, keccak256(callData), payee,
        value, batch, nonce, validUntil, router)));
}
