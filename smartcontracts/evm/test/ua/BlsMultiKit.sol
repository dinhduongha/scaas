// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UAKinds} from "../../src/ua/UAKinds.sol";
import {Bls12381} from "../../src/common/Bls12381.sol";
import {CurveSigs} from "../../src/common/CurveSigs.sol";
import {HashToCurve} from "../../src/common/HashToCurve.sol";
import {G1Bls12381} from "../../src/zether/ZetherCurves.sol";

/// Test-only `bls12381-multi` (0x0121) signer on the EIP-2537 precompiles (spec 2026-11-19-bls12381-multi §2–§5): keys `sk·g2` from
/// fixed scalars, the key data sorted by key with weights moved with their keys, the registration PoP (§4), aggregates over any
/// signer set (σ = (Σ sk_i)·H(m)). The vectors (groups.json, made by ua-rs) are the authority; this kit only makes signatures over
/// messages a test chooses (purposes, digests, nested `msig`). Not a reference implementation.
library BlsMultiKit {
    uint16 internal constant KIND = 0x0121;

    struct Group {
        bytes d; // the key data
        uint256[] sk; // in key-data order
        bytes32 ua;
    }

    function g2() internal view returns (bytes memory) {
        return _g2msm(Bls12381.NEG_G2_GENERATOR, G1Bls12381.R - 1); // (r − 1)·(−g2) = g2
    }

    function pk(uint256 sk) internal view returns (bytes memory) {
        return _g2msm(g2(), sk);
    }

    /// The key data of `sks` with weights `w` and threshold `t`: sorted by key (weights travel with their keys), apk = Σ pk_i.
    function group(uint256[] memory sks, uint16[] memory w, uint16 t) internal view returns (Group memory g) {
        uint256 n = sks.length;
        bytes[] memory pks = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            pks[i] = pk(sks[i]);
        }
        for (uint256 i = 1; i < n; ++i) {
            for (uint256 j = i; j > 0 && _lt(pks[j], pks[j - 1]); --j) {
                (pks[j], pks[j - 1]) = (pks[j - 1], pks[j]);
                (sks[j], sks[j - 1]) = (sks[j - 1], sks[j]);
                (w[j], w[j - 1]) = (w[j - 1], w[j]);
            }
        }
        bytes memory apk = pks[0];
        for (uint256 i = 1; i < n; ++i) {
            (bool ok, bytes memory out) = Bls12381.G2ADD.staticcall(bytes.concat(apk, pks[i]));
            require(ok && out.length == 256, "G2ADD");
            apk = out;
        }
        g.d = abi.encodePacked(apk, t, uint16(n));
        for (uint256 i; i < n; ++i) {
            g.d = bytes.concat(g.d, pks[i], abi.encodePacked(w[i]));
        }
        g.sk = sks;
        g.ua = UAKinds.uaOf(KIND, g.d);
    }

    /// The registration PoP message without attributes: `uaMessage(0x0121, POP_V2, registrationDigest(record))`.
    function popMsg(bytes32 ua) internal pure returns (bytes32) {
        bytes32 rec = UAKinds.portableRecordHash(ua, KIND, 0, UAKinds.kemRecordHash(ua, 0, bytes("")));
        return UAKinds.uaMessage(KIND, UAKinds.PURPOSE_POP_V2, UAKinds.portableDigest(UAKinds.registrationHash(rec, 0)));
    }

    /// `pop = Σ sk_i·H(keccak256(popMsg ‖ pk_i), DST_MULTI_POP)` over every member (spec §4).
    function pop(Group memory g, bytes32 message) internal view returns (bytes memory acc) {
        for (uint256 i; i < g.sk.length; ++i) {
            bytes memory key = _cut(g.d, 260 + 258 * i, 256);
            bytes memory h = HashToCurve.hashToG1(
                abi.encodePacked(keccak256(abi.encodePacked(message, key))), CurveSigs.DST_MULTI_POP
            );
            bytes memory part = _g1msm(h, g.sk[i]);
            acc = i == 0 ? part : Bls12381.g1Add(acc, part);
        }
    }

    /// `σ ‖ signers` by the members in `signers` (bit i = member i) over `uaMsg` (spec §3, §5.1).
    function sign(Group memory g, uint256 signers, bytes32 uaMsg) internal view returns (bytes memory) {
        uint256 s;
        for (uint256 i; i < g.sk.length; ++i) {
            if ((signers >> i) & 1 == 1) s = addmod(s, g.sk[i], G1Bls12381.R);
        }
        bytes memory h =
            HashToCurve.hashToG1(abi.encodePacked(keccak256(abi.encodePacked(g.ua, uaMsg))), CurveSigs.DST_MULTI_SIG);
        return bytes.concat(_g1msm(h, s), bytes32(signers));
    }

    /// The typed key of `g` (registerBlsMulti).
    function members(Group memory g) internal pure returns (bytes[] memory keys, uint16[] memory weights) {
        uint256 n = g.sk.length;
        keys = new bytes[](n);
        weights = new uint16[](n);
        for (uint256 i; i < n; ++i) {
            keys[i] = _cut(g.d, 260 + 258 * i, 256);
            weights[i] = uint16(bytes2(_cut(g.d, 260 + 258 * i + 256, 2)));
        }
    }

    function _g2msm(bytes memory p, uint256 s) private view returns (bytes memory) {
        (bool ok, bytes memory out) = Bls12381.G2MSM.staticcall(bytes.concat(p, bytes32(s)));
        require(ok && out.length == 256, "G2MSM");
        return out;
    }

    function _g1msm(bytes memory p, uint256 s) private view returns (bytes memory) {
        (bool ok, bytes memory out) = Bls12381.G1MSM.staticcall(bytes.concat(p, bytes32(s)));
        require(ok && out.length == 128, "G1MSM");
        return out;
    }

    function _lt(bytes memory a, bytes memory b) private pure returns (bool) {
        for (uint256 i; i < a.length; ++i) {
            if (a[i] != b[i]) return a[i] < b[i];
        }
        return false;
    }

    function _cut(bytes memory b, uint256 o, uint256 n) internal pure returns (bytes memory r) {
        r = new bytes(n);
        for (uint256 i; i < n; ++i) {
            r[i] = b[o + i];
        }
    }
}
