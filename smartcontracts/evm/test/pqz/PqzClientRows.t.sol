// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {PqzOffchainBase} from "./helpers/PqzOffchainBase.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";

/// Fable review of the three-key round, P2-2: the client rows of `smartcontracts/vectors/ua/pqz3k_kat.json` (clientkeys
/// `scripts/pqz3k-vectors.mjs`, read by clientkeys and ua-rs) against the contracts, the authority for bytes: the scoped key
/// record digests and messages (`UAKinds`), `h(i)` and `entriesHash` (CTR-PQZ-41, the code hash taken from the EVM), and the
/// opening blob's field offsets (CTR-PQZ-40) against a blob the token writes itself. UNAUDITED.
contract PqzClientRowsTest is PqzOffchainBase {
    using stdJson for string;

    string internal j;

    function setUp() public {
        j = vm.readFile(string.concat(vm.projectRoot(), "/../vectors/ua/pqz3k_kat.json"));
    }

    struct Rec {
        bytes32 ua;
        uint8 cls;
        bytes32 cu;
        address t;
        uint64 v;
        bytes32 kh;
    }

    function test_scopedKeyRecords() public view {
        for (uint256 i; i < 3; ++i) {
            _record(string.concat(".scopedKeyRecords[", vm.toString(i), "]"));
        }
    }

    function _record(string memory k) internal view {
        Rec memory r = Rec(
            j.readBytes32(string.concat(k, ".ua")),
            uint8(j.readUint(string.concat(k, ".keyClass"))),
            j.readBytes32(string.concat(k, ".chainUid")),
            j.readAddress(string.concat(k, ".token")),
            uint64(j.readUint(string.concat(k, ".version"))),
            j.readBytes32(string.concat(k, ".pqzKeyHash"))
        );
        bytes32 kd = UAKinds.pqzScopedKeyDigest(r.ua, r.cls, r.cu, r.t, r.v, r.kh);
        assertEq(kd, j.readBytes32(string.concat(k, ".keyDigest")), "UAPqzScopedKey");
        bytes32 rd = _recordDigest(k, r);
        assertEq(rd, j.readBytes32(string.concat(k, ".recordDigest")), "UAPqzScopedKeyRecord");
        uint16 kind = uint16(j.readUint(string.concat(k, ".kind")));
        assertEq(
            UAKinds.uaMessage(kind, UAKinds.PURPOSE_PQZ_SCOPED_KEY, rd), j.readBytes32(string.concat(k, ".message"))
        );
        assertEq(
            UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_SCOPED_KEY, kd),
            j.readBytes32(string.concat(k, ".regMessage"))
        );
    }

    function _recordDigest(string memory k, Rec memory r) internal view returns (bytes32) {
        bytes32 ph = j.readBytes32(string.concat(k, ".pqzPopHash"));
        bytes32 okh = j.readBytes32(string.concat(k, ".openKemHash"));
        uint64 vub = uint64(j.readUint(string.concat(k, ".validUntilBlock")));
        return UAKinds.pqzScopedKeyRecordDigest(r.ua, r.cls, r.cu, r.t, r.v, r.kh, ph, okh, vub);
    }

    /// `h(i)` as the token's `entriesHash` builds it: the slot with the mark cleared, the blob's EVM code hash (etched here at the
    /// slot's address), 0 for a TRIVIAL entry.
    function test_entryHashes() public {
        bytes memory code = j.readBytes(".entries.code");
        bytes32[] memory hs = new bytes32[](3);
        for (uint256 i; i < 3; ++i) {
            string memory k = string.concat(".entries.rows[", vm.toString(i), "]");
            uint256 e = uint256(j.readBytes32(string.concat(k, ".slot")));
            if (j.readBool(string.concat(k, ".code"))) vm.etch(address(uint160(e >> 96)), code);
            uint256 m = e & ~uint256(PqzCore.SKIP);
            bytes32 c = uint16(m >> 64) == 0 ? bytes32(0) : address(uint160(m >> 96)).codehash;
            hs[i] = keccak256(abi.encode(j.readUint(string.concat(k, ".index")), m, c));
            assertEq(hs[i], j.readBytes32(string.concat(k, ".h")), "h(i)");
        }
        assertEq(keccak256(abi.encodePacked(hs)), j.readBytes32(".entries.entriesHash"), "entriesHash");
    }

    /// The row's offsets are the formula at the row's set; a class-2 token's own op 1 blob with the auditor puts `toUA`,
    /// `P(u_f)`, `O_t`, `O_a`, the tail and its length where that formula says, at the build's set.
    function test_openingBlobOffsets() public {
        (uint256 pkp, uint256 vp) = (j.readUint(".layout.pkp"), j.readUint(".layout.vp"));
        if (keccak256(bytes(PqzSet.NAME)) == keccak256(bytes(j.readString(".set.name")))) {
            assertEq(abi.encode(pkp, vp), abi.encode(PqzCt.PKP, PqzCt.VP), "the row's layout is the set's");
            assertEq(j.readUint(".openingBlob.dataLen"), _len(2), "the row's length");
            assertEq(j.readUint(".openingBlob.at.oT"), 16 + 2 * PqzCt.PKP + 3 * PqzCt.VP + 32, "the row's O_t offset");
        }
        _offStack();
        (vMode, vUA, vOwnKey, vOpening) = (PqzCore.OFFCHAIN, vA, false, true);
        NormalPqzToken t = _newToken("client-rows");
        (vMode, vUA, vOwnKey, vOpening) = (0, bytes32(0), false, false);
        _shieldOn(t, bob, 50);
        IPqzToken.PqzTransferArgs memory a = _ts(_payload(1, 0, bob, alice, bytes32(0), _out(41, true), ""));
        a.uFrom = _blob(48, PqzCt.PK);
        (IPqzToken.PqzOpening memory ot, IPqzToken.PqzOpening memory oa) = (_op(1), _op(2));
        (a.openingTo, a.openingAuditor) = (ot, oa);
        t.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(t, t.transferSingleStatement(a, 0)));
        uint256 e = t.pqzPending(alice, 0, 0);
        bytes memory d = _slice(address(uint160(e >> 96)).code, 1, _len(2));
        assertEq(address(uint160(e >> 96)).code.length, 1 + _len(2), "the blob's length");
        uint256 puf = 16 + PqzCt.PKP + 2 * PqzCt.VP + 32; // salt, P(u), P(v_t), P(v_a), toUA
        assertEq(bytes32(_slice(d, puf - 32, 32)), alice, "toUA before P(u_f)");
        assertEq(_slice(d, puf, PqzCt.PKP), _packed(a.uFrom), "P(u_f)");
        uint256 oT = puf + PqzCt.PKP + PqzCt.VP;
        assertEq(_slice(d, oT, PqzCore.OPEN), abi.encodePacked(ot.mlkemCt, ot.x25519Eph, ot.sealedSeed), "O_t");
        assertEq(
            _slice(d, oT + PqzCore.OPEN, PqzCore.OPEN), abi.encodePacked(oa.mlkemCt, oa.x25519Eph, oa.sealedSeed), "O_a"
        );
        assertEq(uint8(d[d.length - 1]), 2, "n");
    }

    function _len(uint256 n) internal pure returns (uint256) {
        return 16 + 2 * PqzCt.PKP + (n + 1) * PqzCt.VP + 32 + n * PqzCore.OPEN + 33 + 8 * n;
    }

    function _op(uint256 seed) internal pure returns (IPqzToken.PqzOpening memory o) {
        (o.mlkemCt, o.x25519Eph, o.sealedSeed) =
        (_blob(seed, PqzCore.MLKEM_CT), keccak256(abi.encode("eph", seed)), _blob(seed + 1, PqzCore.SEALED_SEED));
    }
}
