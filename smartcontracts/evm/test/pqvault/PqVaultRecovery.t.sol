// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVault} from "../../src/pqvault/PqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";
import {PqVaultBase} from "./PqVaultBase.sol";

/// PqVault plan V5 (spec §5.9, CTR-PQV-10): recovery from state alone. Every view, its entries, paging, the end and the clamps
/// (128 ids, 16 latest versions; an offset past the end is empty, never a revert); home against replica (a replica's divergent
/// version is detectable against the home); the shared vault of the V1 vectors written here and read back from views only, byte
/// for byte what clientkeys' keys open (vectors/pqvault/keys.json, items.json).
contract PqVaultRecoveryTest is PqVaultBase {
    function _ct(uint256 n, uint256 seed) internal pure returns (bytes memory c) {
        c = new bytes(n);
        for (uint256 i; i < n; ++i) {
            c[i] = bytes1(uint8(i + seed));
        }
    }

    /// `n` items of `ids[1]` in one batch under `epochId`, nonces `nonce + 1 ..`.
    function _items(bytes32 vid, bytes32 epochId, uint64 nonce, uint256 n) internal returns (bytes32[] memory iids) {
        IPqVault.PqVaultBatch memory b =
            IPqVault.PqVaultBatch(vid, epochId, ids[1], nonce, new IPqVault.PqVaultItem[](n));
        iids = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            uint64 k = nonce + 1 + uint64(i);
            b.items[i] = IPqVault.PqVaultItem(vid, epochId, ids[1], k, _ct(64, k));
            iids[i] = PqVaultTypes.itemId(vid, ids[1], k);
        }
        vault.createItems(b, _sig(ids[1], h.batch(b, PqVaultTypes.DS_V)));
    }

    function test_itemsOf_pagingAndClamp() public {
        (bytes32 vid,) = _newVault(2, 0);
        bytes32[] memory iids = _items(vid, vid, 1000, 130);
        assertEq(vault.itemCount(vid), 130);
        bytes32[] memory p = vault.itemsOf(vid, 0, 1000);
        assertEq(p.length, 128, "clamped to ITEMS_RANGE_MAX");
        assertEq(p[0], iids[0]);
        assertEq(p[127], iids[127]);
        p = vault.itemsOf(vid, 128, 128);
        assertEq(p.length, 2, "the end");
        assertEq(p[1], iids[129]);
        assertEq(vault.itemsOf(vid, 5, 3).length, 3);
        assertEq(vault.itemsOf(vid, 5, 0).length, 0);
        assertEq(vault.itemsOf(vid, 130, 10).length, 0, "past the end: empty");
        assertEq(vault.itemsOf(vid, type(uint256).max, type(uint256).max).length, 0);
        assertEq(vault.itemsOf(keccak256("x"), 0, 10).length, 0);
    }

    /// The latest version of each item, 16 per page, its count, epoch, author and ciphertext.
    function test_latestRange() public {
        (bytes32 vid,) = _newVault(3, 0);
        bytes32[] memory iids = _items(vid, vid, 1000, 20);
        for (uint32 v = 2; v <= 3; ++v) {
            IPqVault.PqVaultEdit memory d = IPqVault.PqVaultEdit(iids[17], vid, ids[2], v, v, _ct(288, v));
            vault.editItem(d, _sig(ids[2], h.edit(d, PqVaultTypes.DS_V)));
        }
        IPqVault.LatestView[] memory l = vault.latestRange(vid, 0, 100);
        assertEq(l.length, 16, "clamped to LATEST_RANGE_MAX");
        assertEq(l[0].itemId, iids[0]);
        assertEq(l[0].versionCount, 1);
        assertEq(l[0].author, ids[1]);
        assertEq(l[0].epochId, vid);
        assertEq(l[0].ciphertext, _ct(64, 1001));
        l = vault.latestRange(vid, 16, 16);
        assertEq(l.length, 4, "the end");
        assertEq(l[1].itemId, iids[17]);
        assertEq(l[1].versionCount, 3);
        assertEq(l[1].author, ids[2]);
        assertEq(l[1].ciphertext, _ct(288, 3));
        assertEq(vault.latestRange(vid, 20, 16).length, 0, "past the end: empty");
        assertEq(vault.latestRange(vid, 0, 0).length, 0);
    }

    /// `vaultsOf` clamps at 128; `epochsOf` at 128 with epoch 0 first; `latestEpoch` the last.
    function test_vaultsOfAndEpochsOf_clamps() public {
        bytes32 first;
        for (uint64 n = 1; n <= 129; ++n) {
            (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(1, n, 0, address(vault));
            bytes32 id = _create(vault, v, w);
            if (n == 1) first = id;
        }
        assertEq(vault.vaultCount(ids[0]), 129);
        assertEq(vault.vaultsOf(ids[0], 0, 500).length, 128);
        assertEq(vault.vaultsOf(ids[0], 0, 500)[0], first);
        assertEq(vault.vaultsOf(ids[0], 128, 500).length, 1);
        assertEq(vault.vaultsOf(ids[0], 129, 500).length, 0);
        bytes32 parent = first;
        bytes32 last;
        for (uint64 k = 1; k <= 129; ++k) {
            (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
                _epoch(first, ids[0], k, k, parent, _list(ids[0]), _members(1));
            parent = last = _rekey(vault, e, w, 0);
        }
        assertEq(vault.epochCount(first), 130);
        bytes32[] memory p = vault.epochsOf(first, 0, 500);
        assertEq(p.length, 128);
        assertEq(p[0], first, "epoch 0 first");
        p = vault.epochsOf(first, 128, 500);
        assertEq(p.length, 2);
        assertEq(p[1], last);
        assertEq(vault.latestEpoch(first), last);
        assertEq(vault.epochsOf(first, 130, 5).length, 0);
    }

    /// Items and versions are read at home: a replica takes a version 2 the home refused (another writer won there); the two
    /// differ by `sigHash`, so a client comparing with the home sees it.
    function test_homeAgainstReplica() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(3, 1, 0, address(vault));
        IUARegistry.UASig memory cs = _createSig(v, address(vault));
        bytes32 vid = vault.createVault(v, w, cs);
        vaultB.createVault(v, w, cs);
        IPqVault.PqVaultItem memory it = IPqVault.PqVaultItem(vid, vid, ids[1], 1, _ct(288, 1));
        IUARegistry.UASig memory isig = _sig(ids[1], h.item(it, PqVaultTypes.DS_V));
        bytes32 iid = vault.createItem(it, isig);
        vaultB.createItem(it, isig);
        IPqVault.PqVaultEdit memory a = IPqVault.PqVaultEdit(iid, vid, ids[0], 1, 2, _ct(288, 2));
        IPqVault.PqVaultEdit memory b = IPqVault.PqVaultEdit(iid, vid, ids[2], 1, 2, _ct(288, 3));
        vault.editItem(a, _sig(ids[0], h.edit(a, PqVaultTypes.DS_V)));
        vaultB.editItem(b, _sig(ids[2], h.edit(b, PqVaultTypes.DS_V)));
        IPqVault.VersionView memory home = vault.versionAt(iid, 2);
        IPqVault.VersionView memory rep = vaultB.versionAt(iid, 2);
        assertEq(home.author, ids[0]);
        assertEq(rep.author, ids[2]);
        assertTrue(home.sigHash != rep.sigHash, "detectable against the home");
        assertEq(vault.versionAt(iid, 1).sigHash, vaultB.versionAt(iid, 1).sigHash, "the shared version agrees");
    }

    // ----- the V1 vectors' shared vault, written and read back -----

    string internal rec;
    string internal kjs;

    /// A UA of the vectors (its ML-DSA-65 public key as the registered key) with KEM key versions 0..`keyId` (the stand-in
    /// verifier signs for it here; the vectors' own signatures are checked by the clients).
    function _vectorUa(string memory name, uint64 keyId) internal returns (bytes32 ua) {
        uint256 i;
        while (
            keccak256(bytes(vm.parseJsonString(rec, string.concat(".signers[", vm.toString(i), "].name"))))
                != keccak256(bytes(name))
        ) ++i;
        bytes memory key = vm.parseJsonBytes(rec, string.concat(".signers[", vm.toString(i), "].publicKey"));
        IUARegistry.UAAttrs memory a;
        a.kem = _kem(uint8(i + 40));
        ua = _register(p, ML, key, a, _pop(p, ML, key, a), "");
        assertEq(ua, vm.parseJsonBytes32(rec, string.concat(".signers[", vm.toString(i), "].ua")));
        keyOf_[ua] = key;
        for (uint64 k = 1; k <= keyId; ++k) {
            IUARegistry.KemKey memory kk = _kem(uint8(i * 8 + k + 50));
            IUARegistry.UASig memory s;
            s.signature = _sig(key, UAKinds.uaMessage(ML, UAKinds.PURPOSE_KEM, p.kemRecordDigest(ua, k, kk)));
            p.setKemKey(ua, k, kk, s);
        }
    }

    function _wrapRow(string memory name) internal view returns (IPqChat.Wrap memory w) {
        uint256 n = abi.decode(vm.parseJson(kjs, ".wraps[*].name"), (string[])).length;
        for (uint256 i; i < n; ++i) {
            string memory q = string.concat(".wraps[", vm.toString(i), "]");
            if (keccak256(bytes(vm.parseJsonString(kjs, string.concat(q, ".name")))) != keccak256(bytes(name))) {
                continue;
            }
            q = string.concat(q, ".wrap");
            w.member = vm.parseJsonBytes32(kjs, string.concat(q, ".member"));
            w.keyId = uint64(vm.parseJsonUint(kjs, string.concat(q, ".keyId")));
            w.mlkemCt = vm.parseJsonBytes(kjs, string.concat(q, ".mlkemCt"));
            w.x25519Eph = vm.parseJsonBytes32(kjs, string.concat(q, ".x25519Eph"));
            w.sealedKey = vm.parseJsonBytes(kjs, string.concat(q, ".sealedKey"));
            return w;
        }
        revert(name);
    }

    function _members(string memory p) internal view returns (IPqChat.MemberKey[] memory m) {
        uint256 n = vm.parseJsonBytes32Array(rec, string.concat(p, ".wrapHashes")).length;
        m = new IPqChat.MemberKey[](n);
        for (uint256 i; i < n; ++i) {
            string memory q = string.concat(p, ".members[", vm.toString(i), "]");
            m[i] = IPqChat.MemberKey(
                vm.parseJsonBytes32(rec, string.concat(q, ".ua")),
                uint64(vm.parseJsonUint(rec, string.concat(q, ".keyId"))),
                vm.parseJsonBytes32(rec, string.concat(q, ".via"))
            );
        }
    }

    function _vecCreate() internal view returns (IPqVault.PqVaultCreate memory v) {
        string memory p = ".vaults[0].records[0].record";
        v.creator = vm.parseJsonBytes32(rec, string.concat(p, ".creator"));
        v.nonce = uint64(vm.parseJsonUint(rec, string.concat(p, ".nonce")));
        v.mode = uint8(vm.parseJsonUint(rec, string.concat(p, ".mode")));
        v.homeChain = vm.parseJsonBytes32(rec, string.concat(p, ".homeChain"));
        v.homeVaultContract = vm.parseJsonAddress(rec, string.concat(p, ".homeVaultContract"));
        v.groupMode = uint8(vm.parseJsonUint(rec, string.concat(p, ".groupMode")));
        v.admins = vm.parseJsonBytes32Array(rec, string.concat(p, ".admins"));
        v.members = _members(p);
        v.wrapHashes = vm.parseJsonBytes32Array(rec, string.concat(p, ".wrapHashes"));
        v.passKdf = uint16(vm.parseJsonUint(rec, string.concat(p, ".passKdf")));
        v.passSalt = vm.parseJsonBytes32(rec, string.concat(p, ".passSalt"));
        v.sealedInfo = vm.parseJsonBytes(rec, string.concat(p, ".sealedInfo"));
    }

    function _vecItem(string memory p) internal view returns (IPqVault.PqVaultItem memory it) {
        it.vaultId = vm.parseJsonBytes32(rec, string.concat(p, ".vaultId"));
        it.epochId = vm.parseJsonBytes32(rec, string.concat(p, ".epochId"));
        it.author = vm.parseJsonBytes32(rec, string.concat(p, ".author"));
        it.nonce = uint64(vm.parseJsonUint(rec, string.concat(p, ".nonce")));
        it.ciphertext = vm.parseJsonBytes(rec, string.concat(p, ".ciphertext"));
    }

    /// The vectors' shared vault in mode 0 (records.json `vaults[0]`: create, item, its wraps and sealedInfo), here a replica of
    /// its home; read back from views only: the record, every wrap and every ciphertext are the vectors' bytes, which the V1
    /// keys open (clientkeys test/pqvault.test.js).
    function test_recoveryOfTheVectorsVault() public {
        rec = vm.readFile("../vectors/pqvault/records.json");
        kjs = vm.readFile("../vectors/pqvault/keys.json");
        bytes32 alice = _vectorUa("alice", 1);
        bytes32 bob = _vectorUa("bob", 3);
        _vectorUa("carol", 2);
        IPqVault.PqVaultCreate memory v = _vecCreate();
        IPqChat.Wrap[] memory w = new IPqChat.Wrap[](3);
        string[3] memory who = ["alice", "bob", "carol"];
        for (uint256 i; i < 3; ++i) {
            IPqChat.Wrap memory x = _wrapRow(string.concat("shared0/epoch-0/", who[i]));
            for (uint256 j; j < 3; ++j) {
                if (v.members[j].ua == x.member) w[j] = x;
            }
        }
        bytes32 vid = vault.createVault(v, w, _sig(alice, h.create(v, PqVaultTypes.DS_V)));
        assertEq(vid, vm.parseJsonBytes32(rec, ".vaults[0].vaultId"));
        IPqVault.PqVaultItem memory it = _vecItem(".vaults[0].records[1].record");
        assertEq(it.author, bob);
        bytes32 iid = vault.createItem(it, _sig(bob, h.item(it, PqVaultTypes.DS_V)));
        assertEq(iid, vm.parseJsonBytes32(rec, ".vaults[0].records[1].id"));
        // read back from views only
        bytes32 rv = vault.vaultsOf(bob, 0, 1)[0];
        assertEq(rv, vid);
        IPqVault.PqVaultCreate memory got =
            abi.decode(_raw(address(vault), abi.encodeCall(IPqVault.vaultOf, (rv))), (IPqVault.PqVaultCreate));
        assertEq(keccak256(abi.encode(got)), keccak256(abi.encode(v)));
        assertEq(got.sealedInfo, v.sealedInfo, "the vectors' sealedInfo (opens under K_v of keys.json)");
        assertEq(vault.latestEpoch(rv), vid);
        for (uint256 j; j < 3; ++j) {
            assertEq(keccak256(abi.encode(vault.wrapAt(vid, j))), keccak256(abi.encode(w[j])), "the vectors' wrap");
        }
        IPqVault.LatestView[] memory l = vault.latestRange(rv, 0, 16);
        assertEq(l.length, 1);
        assertEq(l[0].itemId, iid);
        assertEq(l[0].ciphertext, it.ciphertext, "items.json shared0/login");
        assertEq(l[0].author, bob);
        assertEq(l[0].epochId, vid);
    }
}
