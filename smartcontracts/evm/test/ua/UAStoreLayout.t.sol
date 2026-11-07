// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {UAStore} from "../../src/ua/UAStore.sol";

/// Writes one field of every `UAStore.Layout` slot through the source's own struct, so the test reads where the compiler
/// put each one.
contract UAStoreProbe {
    function poke(bytes32 u) external {
        UAStore.Layout storage s = UAStore.layout();
        s.records[u].kind = 0x71; // 0
        s.keyOwner[u] = bytes32(uint256(0x72)); // 1
        s.pqzKey[u][5] = UAStore.PqzKey(address(0x73), true, true); // 2
        s.ekPtr[u][1] = address(0x74); // 3
        s.uaCount[0x75] = 0x76; // 4
        s.uaAt[0x75][7] = u; // 5
        s.reg[u].push(address(0x77)); // 6
        s.pqzPopHash[u][5] = bytes32(uint256(0x78)); // 7
        s.pqzPop[u][5].push(address(0x79)); // 8
        s.pqzKeySig[u][5].push(address(0x7a)); // 9
        s.kem[u][5].push(address(0x7b)); // 10
        s.kemMax[u] = 0x7c; // 11
        s.kemCommit[u].kemPkHash = bytes32(uint256(0x7d)); // 12
        s.retiredRegPqzKey[u] = address(0x7e); // 13 (retired by R2, a placeholder)
        s.retiredRegPqzPopHash[u] = bytes32(uint256(0x7f)); // 14 (retired by R2, a placeholder)
        s.accepted[u] = 0x80; // 15
        s.memberSigHash[u][3] = bytes32(uint256(0x81)); // 16
        s.pqzVersions[u] = UAStore.PqzVersions(0x82, 0x83, true); // 17
        s.pqzKeyUsed[u][bytes32(uint256(0x84))] = true; // 18
    }
}

/// The active pin of the registry's storage (spec 2026-11-06-pqz-key-versions §2.3, Codex: `UARegistrySplit.t.sol`, which
/// `UAStore`'s comment named, lives under `legacy/` and is no gate). Every slot number of `UAStore.Layout`, the nested
/// PQZ mappings keyed `(ua, version)` (2, 7, 8, 9), the retired placeholders 13 and 14 (R2), `PqzVersions` (17: `latest`
/// in bytes 0–7, `current` 8–15, `listed` byte 16) and `pqzKeyUsed` (18). Moves only old → new in a commit.
contract UAStoreLayoutTest is Test {
    using stdJson for string;

    bytes32 internal constant U = 0xcafe00000000000000000000000000000000000000000000000000000000a11a;

    function _m(bytes32 k, uint256 slot) internal pure returns (bytes32) {
        return keccak256(abi.encode(k, slot));
    }

    function _mm(bytes32 k1, uint256 k2, uint256 slot) internal pure returns (bytes32) {
        return keccak256(abi.encode(k2, _m(k1, slot)));
    }

    function _at(address a, bytes32 s) internal view returns (uint256) {
        return uint256(vm.load(a, s));
    }

    function test_UAStoreLayout() public {
        UAStoreProbe p = new UAStoreProbe();
        p.poke(U);
        address a = address(p);
        assertEq(uint16(_at(a, _m(U, 0))), 0x71, "0 records");
        assertEq(_at(a, _m(U, 1)), 0x72, "1 keyOwner");
        assertEq(_at(a, _mm(U, 5, 2)), uint256(0x73) | 1 << 160 | 1 << 168, "2 pqzKey[ua][version]: ptr, proven, added");
        assertEq(_at(a, bytes32(uint256(_m(U, 3)) + 1)), 0x74, "3 ekPtr");
        assertEq(_at(a, keccak256(abi.encode(uint256(0x75), uint256(4)))), 0x76, "4 uaCount");
        assertEq(_at(a, keccak256(abi.encode(uint256(7), keccak256(abi.encode(uint256(0x75), uint256(5)))))), uint256(U), "5 uaAt");
        assertEq(_at(a, _m(U, 6)), 1, "6 reg (length)");
        assertEq(_at(a, _mm(U, 5, 7)), 0x78, "7 pqzPopHash[ua][version]");
        assertEq(_at(a, _mm(U, 5, 8)), 1, "8 pqzPop[ua][version] (length)");
        assertEq(_at(a, keccak256(abi.encode(_mm(U, 5, 8)))), 0x79, "8 pqzPop[ua][version][0]");
        assertEq(_at(a, _mm(U, 5, 9)), 1, "9 pqzKeySig[ua][version] (length)");
        assertEq(_at(a, _mm(U, 5, 10)), 1, "10 kem[ua][version] (length)");
        assertEq(_at(a, _m(U, 11)), 0x7c, "11 kemMax");
        assertEq(_at(a, _m(U, 12)), 0x7d, "12 kemCommit");
        assertEq(_at(a, _m(U, 13)), 0x7e, "13 retired");
        assertEq(_at(a, _m(U, 14)), 0x7f, "14 retired");
        assertEq(_at(a, _m(U, 15)), 0x80, "15 accepted");
        assertEq(_at(a, _mm(U, 3, 16)), 0x81, "16 memberSigHash");
        assertEq(_at(a, _m(U, 17)), uint256(0x82) | uint256(0x83) << 64 | 1 << 128, "17 pqzVersions: latest, current, listed");
        assertEq(_at(a, keccak256(abi.encode(uint256(0x84), _m(U, 18)))), 1, "18 pqzKeyUsed[ua][pqzKeyHash]");
    }

    /// The registry keeps `UAStore.Layout` at slot 0 (its only state variable): the probe's slots are the registry's.
    function test_UAStoreLayoutAtSlot0() public view {
        string memory art = vm.readFile(string.concat("./", vm.envOr("FOUNDRY_OUT", string("out")), "/UARegistry.sol/UARegistry.json"));
        assertEq(art.readString(".storageLayout.storage[0].label"), "_s");
        assertEq(art.readString(".storageLayout.storage[0].slot"), "0");
        assertFalse(vm.keyExistsJson(art, ".storageLayout.storage[1]"));
    }
}
