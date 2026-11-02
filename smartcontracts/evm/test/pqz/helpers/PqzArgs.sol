// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";
import {PqzSet} from "../../../src/pqz/PqzSet.sol";

/// @notice The client's side of the explicit PQZ parameters (Appendix X.2), for the fixture and the invariant handlers.
abstract contract PqzArgs {
    bytes32 internal constant TH_TRANSFER_ARGS = keccak256(
        "PqzTransferArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes sealedMemo)"
    );
    bytes32 internal constant TH_LEG = keccak256("PqzLeg(bytes32 ua,bytes v,bytes vAuditor)");
    bytes32 internal constant TH_MULTI_ARGS = keccak256(
        "PqzMultiArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo)PqzLeg(bytes32 ua,bytes v,bytes vAuditor)"
    );
    bytes32 internal constant TH_BURN_ARGS = keccak256(
        "PqzBurnArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 beneficiaryUA,bytes u,bytes vFrom)"
    );

    /// The offset of `out` in the packed payloads the tests keep as "today's bytes": op 1, op 7, a burn; op 1's whole memo.
    uint256 internal constant T_OUT = 208;
    uint256 internal constant M_OUT = 240;
    uint256 internal constant B_OUT = 160;
    uint256 internal constant MEMO_LEN = 57;

    /// A holder's `pqzAuth` with a filler ML-DSA signature (the key is the one on record).
    function _pqAuth() internal pure returns (IUARegistry.UASig memory s) {
        s.signature = new bytes(3309);
    }

    function _outLen(uint256 m, bool withAud) internal pure returns (uint256) {
        return PqzCt.PK * _groups(m, withAud) + PqzCt.V * (m + 1) + (withAud ? PqzCt.V * m : 0);
    }

    /// op 7's randomness groups (R0-1): `⌈M / S_AUD⌉` with the auditor copies, `⌈M / 4⌉` without; leg `j` in `_groupOf`.
    function _groups(uint256 m, bool withAud) internal pure returns (uint256) {
        return withAud ? (m + PqzSet.S_AUD - 1) / PqzSet.S_AUD : (m + 3) / 4;
    }

    function _groupOf(uint256 j, bool withAud) internal pure returns (uint256) {
        return withAud ? j / PqzSet.S_AUD : j / 4;
    }

    function _word(bytes memory pl, uint256 off) internal pure returns (bytes32 w) {
        assembly ("memory-safe") { w := mload(add(add(pl, 32), off)) }
    }

    function _part(bytes memory b, uint256 off, uint256 len) private pure returns (bytes memory r) {
        r = new bytes(len);
        for (uint256 i; i < len; i += 32) {
            bytes32 w = _word(b, off + i);
            assembly ("memory-safe") { mstore(add(add(r, 32), i), w) }
        }
        assembly ("memory-safe") { mstore(add(add(r, 32), len), 0) } // a tail past `len` is no part of `r`
    }

    /// The test's reference for "today's bytes": the packed payloads of `_payload`, `_mpayload`, read back into the explicit
    /// struct, so every statement comparison below is packed reference against the token's assembly from the fields
    /// (Appendix X.2). Op 1: `p ‖ vub ‖ shieldIn ‖ from ‖ to ‖ ben ‖ salt ‖ u ‖ v_t ‖ v_f ‖ [v_a] ‖ [salt ‖ sealed41]`.
    function _ts(bytes memory pl) internal pure returns (IPqzToken.PqzTransferArgs memory t) {
        uint256 rest = pl.length - 208;
        bool memo = rest == PqzCore.OUT_ON + 57 || rest == PqzCore.OUT_OFF + 57;
        if (memo) rest -= 57;
        t.p = uint64(uint256(_word(pl, 0)));
        t.validUntilBlock = uint256(_word(pl, 32));
        t.shieldIn = uint256(_word(pl, 64));
        t.fromUA = _word(pl, 96);
        t.toUA = _word(pl, 128);
        t.beneficiaryUA = _word(pl, 160);
        t.salt = bytes16(_word(pl, 192));
        t.u = _part(pl, 208, PqzCt.PK);
        t.vTo = _part(pl, 208 + PqzCt.PK, PqzCt.V);
        t.vFrom = _part(pl, 208 + PqzCt.CT, PqzCt.V);
        if (rest == PqzCore.OUT_ON) t.vAuditor = _part(pl, 208 + PqzCore.OUT_OFF, PqzCt.V);
        if (memo) t.sealedMemo = _part(pl, pl.length - 41, 41);
    }

    /// Op 7: `p ‖ vub ‖ shieldIn ‖ from ‖ ben ‖ M ‖ decoyFee ‖ salt ‖ UA_0 … ‖ u_0 … ‖ v_0 … ‖ v_f ‖ [v_{a,0} …] ‖ [salt ‖ sealed]`.
    function _ms(bytes memory pl) internal pure returns (IPqzToken.PqzMultiArgs memory t) {
        uint256 m = uint256(_word(pl, 160));
        uint256 rest = pl.length - 240 - 32 * m;
        uint256 memo = 18 + 40 * m;
        bool aud = rest == _outLen(m, true) || rest == _outLen(m, true) + memo;
        if (rest != _outLen(m, aud)) rest -= memo;
        else memo = 0;
        t.p = uint64(uint256(_word(pl, 0)));
        t.validUntilBlock = uint256(_word(pl, 32));
        t.shieldIn = uint256(_word(pl, 64));
        t.fromUA = _word(pl, 96);
        t.beneficiaryUA = _word(pl, 128);
        t.decoyFee = uint256(_word(pl, 192));
        t.salt = bytes16(_word(pl, 224));
        uint256 g = _groups(m, aud);
        uint256 o = 240 + 32 * m;
        t.u = new bytes[](g);
        for (uint256 i; i < g; ++i) t.u[i] = _part(pl, o + PqzCt.PK * i, PqzCt.PK);
        o += PqzCt.PK * g;
        t.legs = new IPqzToken.PqzLeg[](m);
        for (uint256 j; j < m; ++j) {
            t.legs[j].ua = _word(pl, 240 + 32 * j);
            t.legs[j].v = _part(pl, o + PqzCt.V * j, PqzCt.V);
            if (aud) t.legs[j].vAuditor = _part(pl, o + PqzCt.V * (m + 1 + j), PqzCt.V);
        }
        t.vFrom = _part(pl, o + PqzCt.V * m, PqzCt.V);
        if (memo != 0) t.sealedMemo = _part(pl, pl.length - memo + 16, memo - 16);
    }

    /// A burn: `p ‖ vub ‖ shieldIn ‖ from ‖ ben ‖ u' ‖ v_f`.
    function _bs(bytes memory pl) internal pure returns (IPqzToken.PqzBurnArgs memory b) {
        b.p = uint64(uint256(_word(pl, 0)));
        b.validUntilBlock = uint256(_word(pl, 32));
        b.shieldIn = uint256(_word(pl, 64));
        b.fromUA = _word(pl, 96);
        b.beneficiaryUA = _word(pl, 128);
        b.u = _part(pl, 160, PqzCt.PK);
        b.vFrom = _part(pl, 160 + PqzCt.PK, PqzCt.V);
    }

    // The client's EIP-712 hashes of the three argument structs (the wallet JSON tests in `PqzTyped.t.sol` pin them).

    function _hashT(IPqzToken.PqzTransferArgs memory t) internal pure returns (bytes32) {
        return keccak256(bytes.concat(
            abi.encode(TH_TRANSFER_ARGS, t.p, t.validUntilBlock, t.shieldIn, t.fromUA, t.toUA, t.beneficiaryUA, t.salt),
            abi.encode(keccak256(t.u), keccak256(t.vTo), keccak256(t.vFrom), keccak256(t.vAuditor), keccak256(t.sealedMemo))
        ));
    }

    function _hashM(IPqzToken.PqzMultiArgs memory t) internal pure returns (bytes32) {
        bytes memory us;
        for (uint256 g; g < t.u.length; ++g) us = bytes.concat(us, keccak256(t.u[g]));
        bytes memory ls;
        for (uint256 j; j < t.legs.length; ++j) {
            IPqzToken.PqzLeg memory l = t.legs[j];
            ls = bytes.concat(ls, keccak256(abi.encode(TH_LEG, l.ua, keccak256(l.v), keccak256(l.vAuditor))));
        }
        return keccak256(bytes.concat(
            abi.encode(TH_MULTI_ARGS, t.p, t.validUntilBlock, t.shieldIn, t.fromUA, t.beneficiaryUA, t.decoyFee, t.salt),
            abi.encode(keccak256(us), keccak256(ls), keccak256(t.vFrom), keccak256(t.sealedMemo))
        ));
    }

    function _hashB(IPqzToken.PqzBurnArgs memory b) internal pure returns (bytes32) {
        return keccak256(abi.encode(TH_BURN_ARGS, b.p, b.validUntilBlock, b.shieldIn, b.fromUA, b.beneficiaryUA,
            keccak256(b.u), keccak256(b.vFrom)));
    }
}
