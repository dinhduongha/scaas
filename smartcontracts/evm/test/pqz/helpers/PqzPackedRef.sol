// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";

/// @notice The reference of the explicit parameters (Appendix X.2): the statement and op blob code of `PqzCore` as it stood
///         before typed-signing C4, on the packed payload, and the digest of a statement. A test etches this contract onto a
///         token for one call, so it reads that token's state with `address(this)` the token, and the token's statement
///         from the explicit struct must equal it byte for byte (`legacy/typed-signing/PqzPacked.sol` is the same code).
///         Group 3h (T59, pqz-proof-path spec §3): a packed payload carries no `ownTag`, the explicit struct's is 0 there, so
///         the reference's `memoHash` is 3h's `keccak256(memo ‖ ownTag)` with the tag 0 and its blobs end with the tail
///         `ownTag(0) ‖ kv ‖ u8(n)` at version 0 of every credited key (no test that uses it rotates one).
contract PqzPackedRef {
    uint256 internal constant T_OUT = 208;
    uint256 internal constant M_OUT = 240;
    uint256 internal constant B_OUT = 160;
    uint256 internal constant MEMO = 16 + PqzCore.SEALED; // op 1's memo, op 7's encoding with M = 1 (CTR-PQZ-23)

    function single(PqzCore.Env memory e, bytes calldata payload) external view returns (bytes memory) {
        PqzCore._bindMode(e);
        PqzCore.Op memory o = _parseTransfer(payload, e.mode);
        PqzCore._common(o, e);
        PqzCore._receiver(o, e);
        return PqzCore._stmtOf(_transferBuffer(o, e, payload[T_OUT:T_OUT + o.outLen]));
    }

    function multi(PqzCore.Env memory e, bytes calldata payload) external view returns (bytes memory) {
        PqzCore._bindMode(e);
        PqzCore.Op memory o = _parseMulti(payload, e.mode);
        PqzCore._common(o, e);
        uint256 d = uint256(bytes32(payload[192:224]));
        o.decoyFee = d;
        o.fee += o.legs * d;
        _legs(o, e, payload);
        uint256 off = M_OUT + 32 * o.legs;
        return PqzCore._stmtOf(_multiBuffer(o, e, payload[off:off + o.outLen]));
    }

    function burn(PqzCore.Env memory e, bytes calldata payload) external view returns (bytes memory) {
        PqzCore.Op memory o;
        o.opTag = e.amount == 0 ? PqzCore.OP_REFRESH : PqzCore.OP_BURN;
        o.op = 2;
        o.amount = e.amount;
        o.recipient = e.recipient;
        _head(o, payload);
        o.ben = bytes32(payload[128:160]);
        o.memoHash = keccak256(abi.encodePacked(bytes32(0)));
        PqzCore._common(o, e);
        bytes memory t = PqzCore._total(o, msg.data[0:0]);
        o.stLen = PqzCore.HEADER + PqzCt.PK + 2 * PqzCt.CT;
        bytes memory buf = PqzCore._buffer(2, o.stLen, 0);
        PqzCore._header(buf, o, e);
        PqzCore._key(buf, PqzCore.HEADER, o.keyF);
        PqzCore._mem(buf, PqzCore.HEADER + PqzCt.PK, t);
        PqzCore._cd(buf, PqzCore.HEADER + PqzCt.PK + PqzCt.CT, payload[B_OUT:B_OUT + PqzCt.CT]);
        return PqzCore._stmtOf(buf);
    }

    function _head(PqzCore.Op memory o, bytes calldata payload) private pure {
        o.p = uint64(uint256(bytes32(payload[0:32])));
        o.validUntil = uint256(bytes32(payload[32:64]));
        o.shieldIn = uint256(bytes32(payload[64:96]));
        o.from = bytes32(payload[96:128]);
    }

    function _parseTransfer(bytes calldata payload, ZetherTypes.TransferMode mode) private pure returns (PqzCore.Op memory o) {
        uint256 memo = mode == ZetherTypes.TransferMode.HASH ? MEMO : 0;
        uint256 len = payload.length;
        uint256 outLen = len - T_OUT - memo;
        o.outLen = outLen;
        o.auditorOn = outLen == PqzCore.OUT_ON ? 1 : 0;
        o.opTag = PqzCore.OP_TRANSFER;
        o.mode = mode;
        o.op = 1;
        _head(o, payload);
        o.to = bytes32(payload[128:160]);
        o.ben = bytes32(payload[160:192]);
        o.salt = bytes16(payload[192:208]);
        o.memoHash = keccak256(abi.encodePacked(memo != 0 ? payload[len - MEMO:] : payload[0:0], bytes32(0)));
    }

    function _transferBuffer(PqzCore.Op memory o, PqzCore.Env memory e, bytes calldata out) private view returns (bytes memory buf) {
        bytes memory t = PqzCore._total(o, msg.data[0:0]);
        uint256 nk = 2 + o.auditorOn;
        o.stLen = PqzCore.HEADER + nk * PqzCt.PK + PqzCt.CT + o.outLen;
        buf = PqzCore._buffer(1, o.stLen, 0);
        PqzCore._header(buf, o, e);
        PqzCore._key(buf, PqzCore.HEADER, o.keyF);
        PqzCore._key(buf, PqzCore.HEADER + PqzCt.PK, o.keyT);
        if (o.auditorOn == 1) PqzCore._key(buf, PqzCore.HEADER + 2 * PqzCt.PK, o.keyA);
        PqzCore._mem(buf, PqzCore.HEADER + nk * PqzCt.PK, t);
        PqzCore._cd(buf, PqzCore.HEADER + nk * PqzCt.PK + PqzCt.CT, out);
    }

    function _parseMulti(bytes calldata payload, ZetherTypes.TransferMode mode) private pure returns (PqzCore.Op memory o) {
        uint256 m = uint256(bytes32(payload[160:192]));
        o.legs = m;
        o.opTag = PqzCore.OP_TRANSFER_MULTI;
        o.mode = mode;
        o.op = 7;
        uint256 memo = mode == ZetherTypes.TransferMode.HASH ? 18 + 40 * m : 0;
        uint256 rest = payload.length - M_OUT - 32 * m - memo;
        if (rest == PqzCt.PK * PqzCore._groups(m, 1) + PqzCt.V * (2 * m + 1)) o.auditorOn = 1;
        o.groups = PqzCore._groups(m, o.auditorOn);
        o.outLen = rest;
        _head(o, payload);
        o.ben = bytes32(payload[128:160]);
        o.salt = bytes16(payload[224:240]);
        o.to = keccak256(payload[M_OUT:M_OUT + 32 * m]);
        o.memoHash = keccak256(abi.encodePacked(memo != 0 ? payload[payload.length - memo:] : payload[0:0], bytes32(0)));
    }

    function _legs(PqzCore.Op memory o, PqzCore.Env memory e, bytes calldata payload) private view {
        o.keys = new address[](o.legs);
        for (uint256 j; j < o.legs; ++j) {
            (o.keys[j],) = PqzCore._creditKey(e.registry, bytes32(payload[M_OUT + 32 * j:M_OUT + 32 * j + 32]));
        }
        if (o.auditorOn == 1) o.keyA = PqzCore._keyPtr(e.registry, PqzCore.$().auditorUA);
    }

    function _multiBuffer(PqzCore.Op memory o, PqzCore.Env memory e, bytes calldata out) private view returns (bytes memory buf) {
        bytes memory t = PqzCore._total(o, msg.data[0:0]);
        uint256 nk = 1 + o.legs + o.auditorOn;
        o.stLen = PqzCore.HEADER + nk * PqzCt.PK + PqzCt.CT + o.outLen;
        buf = PqzCore._buffer(7, o.stLen, 0);
        PqzCore._header(buf, o, e);
        PqzCore._mem(buf, 320, abi.encode(o.legs));
        PqzCore._key(buf, PqzCore.HEADER, o.keyF);
        for (uint256 j; j < o.legs; ++j) PqzCore._key(buf, PqzCore.HEADER + (1 + j) * PqzCt.PK, o.keys[j]);
        if (o.auditorOn == 1) PqzCore._key(buf, PqzCore.HEADER + (1 + o.legs) * PqzCt.PK, o.keyA);
        PqzCore._mem(buf, PqzCore.HEADER + nk * PqzCt.PK, t);
        PqzCore._cd(buf, PqzCore.HEADER + nk * PqzCt.PK + PqzCt.CT, out);
    }

    /// The op blob `R ‖ v_f` of an op 1 payload (`_settleTransfer`): `out` packed whole, `u ‖ v_t` in one pass.
    function blobSingle(bytes calldata payload, bool hash) external pure returns (bytes memory blob) {
        PqzCore.Op memory o = _parseTransfer(payload, hash ? ZetherTypes.TransferMode.HASH : ZetherTypes.TransferMode.BUNDLE);
        bytes calldata out = payload[T_OUT:T_OUT + o.outLen];
        uint256 len = 16 + PqzCt.PKP + PqzCt.VP * (2 + o.auditorOn) + 32 + PqzCore._tailLen(1 + o.auditorOn);
        blob = new bytes(len + 32);
        PqzCore._put(blob, 0, abi.encodePacked(o.salt));
        PqzCt.packCd(blob, 16, out[0:PqzCt.CT]);
        uint256 q = 16 + PqzCt.PKP + PqzCt.VP;
        if (o.auditorOn == 1) {
            PqzCt.packCd(blob, q, out[PqzCore.OUT_OFF:o.outLen]);
            q += PqzCt.VP;
        }
        PqzCore._put(blob, q, abi.encode(o.to));
        PqzCt.packCd(blob, q + 32, out[PqzCt.CT:PqzCt.CT + PqzCt.V]);
        PqzCore._putTail(blob, q + 32 + PqzCt.VP, 0, new uint64[](1 + o.auditorOn));
        assembly ("memory-safe") { mstore(blob, len) }
    }

    /// The op blob of an op 7 payload (`_bundleMulti`).
    function blobMulti(bytes calldata payload, bool hash) external pure returns (bytes memory r) {
        PqzCore.Op memory o = _parseMulti(payload, hash ? ZetherTypes.TransferMode.HASH : ZetherTypes.TransferMode.BUNDLE);
        bytes calldata out = payload[M_OUT + 32 * o.legs:M_OUT + 32 * o.legs + o.outLen];
        uint256 ls = 32 + PqzCt.VP * (1 + o.auditorOn);
        uint256 start = 16 + PqzCt.PKP * o.groups;
        uint256 len = start + ls * o.legs + PqzCt.VP + PqzCore._tailLen(o.legs + o.auditorOn);
        r = new bytes(len + 32);
        PqzCore._put(r, 0, abi.encodePacked(o.salt));
        PqzCt.packCd(r, 16, out[0:PqzCt.PK * o.groups]);
        for (uint256 j; j < o.legs; ++j) _leg(r, o, payload, out, j);
        uint256 us = PqzCt.PK * o.groups;
        PqzCt.packCd(r, start + ls * o.legs, out[us + PqzCt.V * o.legs:us + PqzCt.V * (o.legs + 1)]);
        PqzCore._putTail(r, start + ls * o.legs + PqzCt.VP, 0, new uint64[](o.legs + o.auditorOn));
        assembly ("memory-safe") { mstore(r, len) }
    }

    function _leg(bytes memory r, PqzCore.Op memory o, bytes calldata payload, bytes calldata out, uint256 j) private pure {
        uint256 us = PqzCt.PK * o.groups;
        uint256 ls = 32 + PqzCt.VP * (1 + o.auditorOn);
        uint256 d = 16 + PqzCt.PKP * o.groups + ls * j;
        PqzCt.packCd(r, d, out[us + PqzCt.V * j:us + PqzCt.V * (j + 1)]);
        if (o.auditorOn == 1) {
            PqzCt.packCd(r, d + PqzCt.VP, out[us + PqzCt.V * (o.legs + 1 + j):us + PqzCt.V * (o.legs + 2 + j)]);
        }
        PqzCore._put(r, d + ls - 32, abi.encode(bytes32(payload[M_OUT + 32 * j:M_OUT + 32 * j + 32])));
    }

    /// The typed `PqzAuth` digest of a bare statement, in its precompile buffer.
    function digest(uint8 op, bytes calldata stmt, bytes32 domainSeparator) external pure returns (bytes32) {
        return PqzCore.authDigest(bytes.concat(bytes1(op), bytes4(uint32(stmt.length)), stmt), stmt.length, domainSeparator);
    }
}
