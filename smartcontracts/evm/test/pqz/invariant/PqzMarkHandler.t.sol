// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzOffchainBase} from "../helpers/PqzOffchainBase.sol";
import {PqzCtHarness} from "../helpers/PqzCtHarness.sol";
import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";
import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../../src/ua/UARegistry.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// Three-key spec §14 items 5, 20 (K3-8, CTR-PQZ-41): the handler of the skip-mark invariants on an `offchain-shared` token with
/// the sealed opening. One holder (`holder`) receives op 1 credits only (no TRIVIAL entry: every pending entry is a credit that
/// may be marked) from two senders; it marks and rolls by signed rollovers (marks anywhere in `[rolled, pendingCount)`, rolled
/// or not in the same call), and refreshes at any `p` (an un-roll below `rolled` included); blocks pass. The `zether-auth`
/// signature and the verifier's verdicts are the fixture's (mocked ML-DSA; a real ECDSA verdict); proofs are not under test.
/// Ghosts: every entry's slot (without the mark) and ciphertext at creation, the marks placed, the base of `acc` (zero after
/// prepare, a refresh's `u' ‖ v_f` after it) and its index, accepted signed rollovers, and calls the rules refuse that
/// landed (`bad`). No action reverts (a refused call is caught). UNAUDITED.
contract PqzMarkHandler is PqzOffchainBase {
    NormalPqzToken public t;
    bytes32 public holder;
    bytes32[2] internal senders;

    uint256 public entries; // pendingCount as the handler made it (credits that landed)
    mapping(uint256 => uint256) public slot0; // the slot at creation, mark bit clear
    mapping(uint256 => bytes) internal ct0; // the ciphertext at creation
    mapping(uint256 => bool) public marked; // ghost marks
    uint256 public marks;
    uint256 public rolls; // accepted signed rollovers (rollSeq)
    uint256 public rolledEntries; // entries rolled, summed over accepted calls (non-vacuity)
    uint256 public refreshes;
    uint256 public unrolls; // refreshes below `rolled`
    bytes public base; // `acc` after the last refresh (zero ciphertext after prepare)
    uint256 public baseIdx; // `rolled` right after it
    uint256 public bad;
    uint256 internal nonce = 0x3a11;

    bytes32 internal constant ROLL_TH = keccak256(
        "PqzRollOver(bytes32 ua,uint64 keyVersion,uint64 rollSeq,uint64 rolled,uint64 n,uint64[] skip,bytes32 entriesHash,uint64 validUntilBlock,bytes32 chainUid)"
    );

    constructor(NormalPqzToken t_, UARegistry r, PqzCtHarness c, bytes32 h, bytes32 s0, bytes32 s1) {
        (t, tok, reg, ct, holder) = (t_, t_, r, c, h);
        senders = [s0, s1];
        base = new bytes(PqzCt.CT);
    }

    // ----- actions -----

    /// Op 1 of a sender to the holder (a credit with its own blob), at the sender's `pendingCount`.
    function credit(uint256 who) external {
        bytes32 from = senders[who % 2];
        IPqzToken.PqzTransferArgs memory a =
            _ts(_payload(t.pqzAccount(from, 0).pendingCount, 0, from, holder, bytes32(0), _out(nonce, false), ""));
        a.uFrom = _blob(nonce + 7, PqzCt.PK);
        a.openingTo = _openingOf(nonce);
        ++nonce;
        uint256 i = t.pqzAccount(holder, 0).pendingCount;
        bytes memory st;
        try t.transferSingleStatement(a, 0) returns (bytes memory x) { // the view refuses too
            st = x;
        } catch {
            return;
        }
        try t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(t, st)) {
            if (t.pqzAccount(holder, 0).pendingCount != i + 1) ++bad;
            slot0[i] = t.pqzPending(holder, 0, uint64(i)) & ~uint256(PqzCore.SKIP);
            ct0[i] = t.pqzPendingCt(holder, 0, uint64(i));
            entries = i + 1;
        } catch {}
    }

    /// The holder's signed rollover of `n` entries with marks on the unmarked entries of `[rolled, pendingCount)` the bits of
    /// `pick` name (ascending, at most `ROLL_MAX`).
    function roll(uint256 n, uint256 pick) external {
        IPqzToken.AccountState memory s = t.pqzAccount(holder, 0);
        (uint256 r, uint256 pc) = (s.rolled, s.pendingCount);
        n = bound(n, 0, pc - r < PqzCore.ROLL_MAX ? pc - r : PqzCore.ROLL_MAX);
        uint64[] memory skip = new uint64[](pc - r);
        uint256 k;
        for (uint256 i = r; i < pc && k < PqzCore.ROLL_MAX; ++i) {
            if (!marked[i] && (pick >> ((i - r) % 256)) & 1 == 1) skip[k++] = uint64(i);
        }
        assembly ("memory-safe") { mstore(skip, k) }
        if (n == 0 && k == 0) return;
        uint64 vub = uint64(block.number + 10);
        _only(_rollDigest(uint64(n), skip, vub));
        try t.mtxRollOverSigned(holder, 0, uint64(n), skip, vub, _pqAuth()) {
            for (uint256 j; j < k; ++j) {
                marked[skip[j]] = true;
            }
            marks += k;
            ++rolls;
            rolledEntries += n;
            if (t.pqzAccount(holder, 0).rolled != r + n) ++bad;
        } catch {}
        _any();
    }

    /// The holder's refresh (a burn of 0) at `p` anywhere in `[0, pendingCount]`: below `rolled` it un-rolls.
    function refresh(uint256 p) external {
        IPqzToken.AccountState memory s = t.pqzAccount(holder, 0);
        p = bound(p, 0, s.pendingCount);
        IPqzToken.PqzBurnArgs memory b = _bs(
            bytes.concat(abi.encode(p, block.number + 50, uint256(0), holder, bytes32(0)), _blob(nonce++, PqzCt.CT))
        );
        bytes memory st;
        try t.burnStatement(b, 0, bytes32(0), 0) returns (bytes memory x) { // p < floor: PendingRange
            st = x;
        } catch {
            return;
        }
        try t.mtxUnshield(b, 0, bytes32(0), VPROOF, _pqAuth(), "", _sv(t, st)) {
            if (p < s.rolled) ++unrolls;
            ++refreshes;
            (base, baseIdx) = (bytes.concat(b.u, b.vFrom), t.pqzAccount(holder, 0).rolled);
        } catch {}
    }

    /// Blocks pass: credits age past `ROLL_AGE`.
    function age(uint256 k) external {
        vm.roll(block.number + bound(k, 1, 2 * ROLL_AGE));
    }

    // ----- the wallet's model -----

    /// `acc` as the wallet computes it: the base plus every unmarked entry in `[baseIdx, rolled)`.
    function modelAcc() external view returns (bytes memory) {
        uint256 r = t.pqzAccount(holder, 0).rolled;
        uint256 c;
        for (uint256 i = baseIdx; i < r; ++i) {
            if (!marked[i]) ++c;
        }
        bytes[] memory plus = new bytes[](c);
        c = 0;
        for (uint256 i = baseIdx; i < r; ++i) {
            if (!marked[i]) plus[c++] = ct0[i];
        }
        return ct.sumMixed(base, plus, new uint256[](0));
    }

    function ctAt(uint256 i) external view returns (bytes memory) {
        return ct0[i];
    }

    // ----- helpers (as PqzThreeKeysTest's) -----

    function _openingOf(uint256 seed) internal pure returns (IPqzToken.PqzOpening memory o) {
        (o.mlkemCt, o.x25519Eph, o.sealedSeed) =
        (_blob(seed, PqzCore.MLKEM_CT), keccak256(abi.encode("eph", seed)), _blob(seed + 1, PqzCore.SEALED_SEED));
    }

    function _eh(uint256 i) internal view returns (bytes32) {
        uint256 e = t.pqzPending(holder, 0, uint64(i)) & ~uint256(PqzCore.SKIP);
        bytes32 c = uint16(e >> 64) == 0 ? bytes32(0) : address(uint160(e >> 96)).codehash;
        return keccak256(abi.encode(i, e, c));
    }

    function _rollDigest(uint64 n, uint64[] memory skip, uint64 vub) internal view returns (bytes32) {
        IPqzToken.AccountState memory s = t.pqzAccount(holder, 0);
        bytes32[] memory h = new bytes32[](n + skip.length);
        for (uint256 k; k < n; ++k) {
            h[k] = _eh(s.rolled + k);
        }
        for (uint256 j; j < skip.length; ++j) {
            h[n + j] = _eh(skip[j]);
        }
        bytes memory head = abi.encode(ROLL_TH, holder, uint64(0), s.rollSeq, s.rolled, n);
        return MessageHashUtils.toTypedDataHash(
            _sepOf(address(t)),
            keccak256(
                bytes.concat(
                    head,
                    abi.encode(keccak256(abi.encodePacked(skip)), keccak256(abi.encodePacked(h)), vub, t.chainUid())
                )
            )
        );
    }

    /// The registry accepts the holder's signature over `d` only (as `PqzThreeKeysTest._onlyDigest`).
    function _only(bytes32 d) internal {
        vm.mockCallRevert(
            address(reg),
            abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, holder, UAKinds.PURPOSE_ZETHER_AUTH),
            "another digest"
        );
        vm.mockCall(
            address(reg),
            abi.encodeCall(IUARegistry.requireAuthorized, (holder, UAKinds.PURPOSE_ZETHER_AUTH, d, _pqAuth())),
            ""
        );
    }

    function _any() internal {
        vm.mockCall(
            address(reg),
            abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, holder, UAKinds.PURPOSE_ZETHER_AUTH),
            ""
        );
    }
}
