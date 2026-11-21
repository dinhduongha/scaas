// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";
import {PqVaultHasher} from "./PqVaultBase.sol";

/// PqVault plan V2: the typed records of `PqVault` against `smartcontracts/vectors/pqvault/records.json` (written by
/// clientkeys, `scripts/pqvault-vectors.mjs`): typehashes, `DS_V`, `DS_B`, `P_V`, tags, and for every record of every vault in
/// both modes its struct hash, typed digest, `uaMessage`, id, scope and stored blob. A literal pin beside each vector value, so
/// a regenerated vector cannot move a typehash unnoticed. **UNAUDITED.**
contract PqVaultTypesTest is Test {
    PqVaultHasher internal h;
    string internal rec;

    function setUp() public {
        h = new PqVaultHasher();
        rec = vm.readFile("../vectors/pqvault/records.json");
    }

    function _th(string memory name) internal view returns (bytes32) {
        return vm.parseJsonBytes32(rec, string.concat(".typehashes.", name, ".hash"));
    }

    function _b32(string memory k) internal view returns (bytes32) {
        return vm.parseJsonBytes32(rec, k);
    }

    function _u(string memory k) internal view returns (uint256) {
        return vm.parseJsonUint(rec, k);
    }

    function test_pqvaultTypehashIsPinned() public view {
        assertEq(PqVaultTypes.MEMBER_KEY_TYPEHASH, 0x6d7e57dfbfdfbc352504f1e82bc1658aeeb466b69ba168e7a3d69b0c1d448113);
        assertEq(PqVaultTypes.CREATE_TYPEHASH, 0xb5e6f0323db4eb92065a67dedef66888c5936a3fda2508c66728db676184d587);
        assertEq(PqVaultTypes.EPOCH_TYPEHASH, 0x71c0c9183ebe0b2c720191922d877237665a2f0a48c930022307d2ee46ca2adb);
        assertEq(PqVaultTypes.LEAVE_TYPEHASH, 0xfda6d43fa3b8346bb820f8a1d246a2216bb02589076a611063d5781fd5e52e5e);
        assertEq(PqVaultTypes.REMOVE_TYPEHASH, 0x553e622a0d5f9fd21ae3a11cc12f2b60ad5d9ab70b7b7d1c03e8ba2f2e7f55ce);
        assertEq(PqVaultTypes.ITEM_TYPEHASH, 0xc27ac3ae28c17879772efcfc42c24fa5bd680999094212960cf9e76a38ab95f7);
        assertEq(PqVaultTypes.EDIT_TYPEHASH, 0xcc60596d415d81d1ed553cbf426be9d0116b12842bd86717a9a34485edb123c7);
        assertEq(PqVaultTypes.BATCH_TYPEHASH, 0x120be6bb12a7b0ca8c131bce4f2617f2133c47217b465a275fd0c0e85b0e5e19);
        assertEq(PqVaultTypes.MEMBER_KEY_TYPEHASH, _th("MemberKey"));
        assertEq(PqVaultTypes.CREATE_TYPEHASH, _th("PqVaultCreate"));
        assertEq(PqVaultTypes.EPOCH_TYPEHASH, _th("PqVaultEpoch"));
        assertEq(PqVaultTypes.LEAVE_TYPEHASH, _th("PqVaultLeave"));
        assertEq(PqVaultTypes.REMOVE_TYPEHASH, _th("PqVaultRemove"));
        assertEq(PqVaultTypes.ITEM_TYPEHASH, _th("PqVaultItem"));
        assertEq(PqVaultTypes.EDIT_TYPEHASH, _th("PqVaultEdit"));
        assertEq(PqVaultTypes.BATCH_TYPEHASH, _th("PqVaultBatch"));
        // the wrap is PqChat's: one type string, one hash
        assertEq(_th("Wrap"), 0xf7d817cc55f4324caed15db75da261c4bd468454b80ac0cc8d30cd5a0d331e87);
    }

    function test_domainsAndPurpose() public {
        assertEq(PqVaultTypes.DS_V, 0x473bbd23e59a52330188730e8f2e008b6f8c698ac8f709459e53793e4fe9bb6f);
        assertEq(PqVaultTypes.DS_V, _b32(".domains.V.separator"));
        assertEq(PqVaultTypes.APP_ID, 0xbebdf5ae85d22e2594d8d660bce47add63fe70651184e7fca7f4485103c429d0);
        assertEq(PqVaultTypes.APP_ID, _b32(".purpose.appId"));
        assertEq(PqVaultTypes.P_V, 0xccf692e22e573f1ea3462c3d49ef3df68ab4188a04fd4d1d852a829a4514098f);
        assertEq(PqVaultTypes.P_V, _b32(".purpose.purpose"));
        assertEq(PqVaultTypes.P_V, UAKinds.appPurpose(PqVaultTypes.APP_ID));
        assertTrue(PqVaultTypes.P_V != UAKinds.PURPOSE_PQCHAT);
        vm.chainId(_u(".domains.B.chainId"));
        address b = vm.parseJsonAddress(rec, ".domains.B.verifyingContract");
        assertEq(h.dsB(b), 0xe7046943d86fbaf5536a7f0d913b33d36048eab4c3d42f46d02b7da3edbeba13);
        assertEq(h.dsB(b), _b32(".domains.B.separator"));
        // DS_B binds the chain and the instance
        assertTrue(h.dsB(address(uint160(b) ^ 1)) != _b32(".domains.B.separator"));
        vm.chainId(_u(".domains.B.chainId") + 1);
        assertTrue(h.dsB(b) != _b32(".domains.B.separator"));
    }

    function test_tags() public view {
        assertEq(PqVaultTypes.TAG_VAULT, _b32(".tags['scaas/pqvault/v1/vault']"));
        assertEq(PqVaultTypes.TAG_EPOCH, _b32(".tags['scaas/pqvault/v1/epoch']"));
        assertEq(PqVaultTypes.TAG_ITEM, _b32(".tags['scaas/pqvault/v1/item']"));
        assertEq(PqVaultTypes.TAG_BATCH, _b32(".tags['scaas/pqvault/v1/batch']"));
        assertEq(PqVaultTypes.SCOPE_VAULT, _b32(".tags['scaas/pqvault/v1/scope/vault']"));
        assertEq(PqVaultTypes.SCOPE_EPOCH, _b32(".tags['scaas/pqvault/v1/scope/epoch']"));
        assertEq(PqVaultTypes.SCOPE_ITEM, _b32(".tags['scaas/pqvault/v1/scope/item']"));
    }

    // ------------------------------------------------------------------ records from the vectors

    function _members(string memory p) internal view returns (IPqChat.MemberKey[] memory m) {
        uint256 n = vm.parseJsonBytes32Array(rec, string.concat(p, ".wrapHashes")).length;
        m = new IPqChat.MemberKey[](n);
        for (uint256 i; i < n; ++i) {
            string memory q = string.concat(p, ".members[", vm.toString(i), "]");
            m[i] = IPqChat.MemberKey(
                _b32(string.concat(q, ".ua")), uint64(_u(string.concat(q, ".keyId"))), _b32(string.concat(q, ".via"))
            );
        }
    }

    function _create(string memory p) internal view returns (IPqVault.PqVaultCreate memory v) {
        v.creator = _b32(string.concat(p, ".creator"));
        v.nonce = uint64(_u(string.concat(p, ".nonce")));
        v.mode = uint8(_u(string.concat(p, ".mode")));
        v.homeChain = _b32(string.concat(p, ".homeChain"));
        v.homeVaultContract = vm.parseJsonAddress(rec, string.concat(p, ".homeVaultContract"));
        v.admins = vm.parseJsonBytes32Array(rec, string.concat(p, ".admins"));
        v.members = _members(p);
        v.wrapHashes = vm.parseJsonBytes32Array(rec, string.concat(p, ".wrapHashes"));
        v.passKdf = uint16(_u(string.concat(p, ".passKdf")));
        v.passSalt = _b32(string.concat(p, ".passSalt"));
        v.sealedInfo = vm.parseJsonBytes(rec, string.concat(p, ".sealedInfo"));
    }

    function _epoch(string memory p) internal view returns (IPqVault.PqVaultEpoch memory e) {
        e.vaultId = _b32(string.concat(p, ".vaultId"));
        e.author = _b32(string.concat(p, ".author"));
        e.nonce = uint64(_u(string.concat(p, ".nonce")));
        e.epoch = uint64(_u(string.concat(p, ".epoch")));
        e.parentEpochId = _b32(string.concat(p, ".parentEpochId"));
        e.admins = vm.parseJsonBytes32Array(rec, string.concat(p, ".admins"));
        e.members = _members(p);
        e.wrapHashes = vm.parseJsonBytes32Array(rec, string.concat(p, ".wrapHashes"));
        e.passKdf = uint16(_u(string.concat(p, ".passKdf")));
        e.passSalt = _b32(string.concat(p, ".passSalt"));
        e.sealedInfo = vm.parseJsonBytes(rec, string.concat(p, ".sealedInfo"));
    }

    function _item(string memory p) internal view returns (IPqVault.PqVaultItem memory it) {
        it.vaultId = _b32(string.concat(p, ".vaultId"));
        it.epochId = _b32(string.concat(p, ".epochId"));
        it.author = _b32(string.concat(p, ".author"));
        it.nonce = uint64(_u(string.concat(p, ".nonce")));
        it.ciphertext = vm.parseJsonBytes(rec, string.concat(p, ".ciphertext"));
    }

    function _sig(string memory p) internal view returns (IUARegistry.UASig memory s) {
        s.keyData = vm.parseJsonBytes(rec, string.concat(p, ".uaSig.keyData"));
        s.signature = vm.parseJsonBytes(rec, string.concat(p, ".uaSig.signature"));
        assertEq(vm.parseJsonStringArray(rec, string.concat(p, ".uaSig.members")).length, 0);
    }

    struct Row {
        bytes32 typed;
        bytes32 id;
        bytes32 scope;
        bytes blob;
    }

    /// Every record of vault `vi`: struct hash, typed digest in the vault's domain, uaMessage, id, scope, sigHash, blob.
    function _vault(uint256 vi) internal returns (uint256 n) {
        string memory vp = string.concat(".vaults[", vm.toString(vi), "]");
        uint8 mode = uint8(_u(string.concat(vp, ".mode")));
        bytes32 ds = mode == 0 ? PqVaultTypes.DS_V : h.dsB(vm.parseJsonAddress(rec, ".domains.B.verifyingContract"));
        bytes32 vid = _b32(string.concat(vp, ".vaultId"));
        string[] memory structs = abi.decode(vm.parseJson(rec, string.concat(vp, ".records[*].struct")), (string[]));
        for (uint256 i; i < structs.length; ++i) {
            string memory p = string.concat(vp, ".records[", vm.toString(i), "]");
            string memory q = string.concat(p, ".record");
            bytes32 s = keccak256(bytes(structs[i]));
            IUARegistry.UASig memory sig = _sig(p);
            bytes32 sh = keccak256(abi.encode(sig));
            assertEq(sh, _b32(string.concat(p, ".sigHash")), "sigHash");
            Row memory r;
            if (s == keccak256("PqVaultCreate")) {
                IPqVault.PqVaultCreate memory v = _create(q);
                assertEq(v.mode, mode);
                r = Row(
                    h.create(v, ds),
                    PqVaultTypes.vaultId(v.creator, v.nonce, v.mode, v.homeChain, v.homeVaultContract),
                    PqVaultTypes.scopeVault(v.creator),
                    abi.encode(v, sig)
                );
                assertEq(r.id, vid, "vaultId");
            } else if (s == keccak256("PqVaultEpoch")) {
                IPqVault.PqVaultEpoch memory e = _epoch(q);
                r = Row(
                    h.epoch(e, ds),
                    PqVaultTypes.epochId(e.vaultId, e.author, e.nonce),
                    PqVaultTypes.scopeEpoch(e.vaultId, e.author),
                    abi.encode(e, sig)
                );
            } else if (s == keccak256("PqVaultLeave")) {
                IPqVault.PqVaultLeave memory l = IPqVault.PqVaultLeave(
                    _b32(string.concat(q, ".vaultId")),
                    _b32(string.concat(q, ".epochId")),
                    _b32(string.concat(q, ".member")),
                    uint64(_u(string.concat(q, ".nonce")))
                );
                r = Row(h.leave(l, ds), 0, PqVaultTypes.scopeEpoch(l.vaultId, l.member), "");
            } else if (s == keccak256("PqVaultRemove")) {
                IPqVault.PqVaultRemove memory rm = IPqVault.PqVaultRemove(
                    _b32(string.concat(q, ".vaultId")),
                    _b32(string.concat(q, ".epochId")),
                    uint64(_u(string.concat(q, ".nextEpoch"))),
                    vm.parseJsonBytes32Array(rec, string.concat(q, ".members")),
                    _b32(string.concat(q, ".admin")),
                    uint64(_u(string.concat(q, ".nonce")))
                );
                r = Row(h.remove(rm, ds), 0, PqVaultTypes.scopeEpoch(rm.vaultId, rm.admin), abi.encode(rm, sig));
            } else if (s == keccak256("PqVaultItem")) {
                IPqVault.PqVaultItem memory it = _item(q);
                r = Row(
                    h.item(it, ds),
                    PqVaultTypes.itemId(it.vaultId, it.author, it.nonce),
                    PqVaultTypes.scopeItem(it.vaultId, it.author),
                    abi.encode(it, sh, bytes32(0))
                );
            } else if (s == keccak256("PqVaultEdit")) {
                IPqVault.PqVaultEdit memory d = IPqVault.PqVaultEdit(
                    _b32(string.concat(q, ".itemId")),
                    _b32(string.concat(q, ".epochId")),
                    _b32(string.concat(q, ".author")),
                    uint64(_u(string.concat(q, ".nonce"))),
                    uint32(_u(string.concat(q, ".version"))),
                    vm.parseJsonBytes(rec, string.concat(q, ".ciphertext"))
                );
                r = Row(h.edit(d, ds), 0, PqVaultTypes.scopeItem(vid, d.author), abi.encode(d, sh));
            } else {
                assertEq(s, keccak256("PqVaultBatch"));
                _batch(p, ds, sh);
                ++n;
                continue;
            }
            _check(p, r, mode == 0 ? 0 : 1);
            ++n;
        }
    }

    function _check(string memory p, Row memory r, uint256) internal view {
        assertEq(r.typed, _b32(string.concat(p, ".typed")), string.concat(p, " typed"));
        assertEq(r.scope, _b32(string.concat(p, ".scope")), string.concat(p, " scope"));
        if (r.id != 0) assertEq(r.id, _b32(string.concat(p, ".id")), string.concat(p, " id"));
        if (r.blob.length != 0) {
            assertEq(r.blob, vm.parseJsonBytes(rec, string.concat(p, ".blob")), string.concat(p, " blob"));
        }
        assertEq(
            UAKinds.uaMessage(uint16(_u(string.concat(p, ".uaMessage.kind"))), PqVaultTypes.P_V, r.typed),
            _b32(string.concat(p, ".uaMessage.digest")),
            string.concat(p, " uaMessage")
        );
    }

    function _batch(string memory p, bytes32 ds, bytes32 sh) internal view {
        string memory q = string.concat(p, ".record");
        IPqVault.PqVaultBatch memory b;
        b.vaultId = _b32(string.concat(q, ".vaultId"));
        b.epochId = _b32(string.concat(q, ".epochId"));
        b.author = _b32(string.concat(q, ".author"));
        b.nonce = uint64(_u(string.concat(q, ".nonce")));
        uint256 n = abi.decode(vm.parseJson(rec, string.concat(q, ".items[*].nonce")), (uint256[])).length;
        b.items = new IPqVault.PqVaultItem[](n);
        bytes32[] memory ids = new bytes32[](n);
        bytes32 bid = PqVaultTypes.batchId(b.vaultId, b.author, b.nonce);
        for (uint256 i; i < n; ++i) {
            b.items[i] = _item(string.concat(q, ".items[", vm.toString(i), "]"));
            ids[i] = PqVaultTypes.itemId(b.items[i].vaultId, b.items[i].author, b.items[i].nonce);
            assertEq(
                abi.encode(b.items[i], sh, bid),
                vm.parseJsonBytes(rec, string.concat(p, ".itemBlobs[", vm.toString(i), "]")),
                "batch item blob"
            );
        }
        assertEq(ids, vm.parseJsonBytes32Array(rec, string.concat(p, ".itemIds")));
        assertEq(
            abi.encode(b.vaultId, b.epochId, b.author, b.nonce, ids, sh),
            vm.parseJsonBytes(rec, string.concat(p, ".header"))
        );
        _check(p, Row(h.batch(b, ds), bid, PqVaultTypes.scopeItem(b.vaultId, b.author), ""), 0);
    }

    function test_recordVectors() public {
        vm.chainId(_u(".domains.B.chainId"));
        uint256 n;
        for (uint256 i; i < 4; ++i) {
            n += _vault(i);
        }
        assertEq(n, 23); // 19, then F9: a tombstone edit in each shared vault, two longer notes in the index vault
        // F9: a creation nonce above 2^63 (a decimal string in the vectors)
        uint64 big = uint64(vm.parseJsonUint(rec, ".extra.bigNonce.nonce"));
        assertGt(big, uint64(1) << 63);
        assertEq(
            PqVaultTypes.vaultId(
                _b32(".extra.bigNonce.creator"),
                big,
                0,
                _b32(".extra.bigNonce.homeChain"),
                vm.parseJsonAddress(rec, ".extra.bigNonce.homeVaultContract")
            ),
            _b32(".extra.bigNonce.vaultId")
        );
        // both modes present
        assertEq(_u(".vaults[0].mode"), 0);
        assertEq(_u(".vaults[1].mode"), 1);
    }

    // ------------------------------------------------------------------ the mode rows (§5.15, review r2 R5)

    function test_modeRows() public {
        vm.chainId(_u(".domains.B.chainId"));
        bytes32 creator = _b32(".modes.creator");
        uint64 nonce = uint64(_u(".modes.nonce"));
        bytes32 id0;
        for (uint256 i; i < 2; ++i) {
            string memory p = string.concat(".modes.sameCreatorNonce[", vm.toString(i), "]");
            bytes32 id = PqVaultTypes.vaultId(
                creator,
                nonce,
                uint8(_u(string.concat(p, ".mode"))),
                _b32(string.concat(p, ".homeChain")),
                vm.parseJsonAddress(rec, string.concat(p, ".homeVaultContract"))
            );
            assertEq(id, _b32(string.concat(p, ".vaultId")));
            if (i == 0) id0 = id;
            else assertTrue(id != id0, "the mode is in the id");
        }
        for (uint256 i; i < 2; ++i) {
            string memory p = string.concat(".modes.flipped[", vm.toString(i), "]");
            IPqVault.PqVaultCreate memory v = _create(string.concat(p, ".record"));
            bytes32 ds = v.mode == 0
                ? PqVaultTypes.DS_V
                : keccak256(
                    abi.encode(
                        PqVaultTypes.DOMAIN_B_TYPEHASH,
                        PqVaultTypes.NAME_HASH,
                        PqVaultTypes.VERSION_HASH,
                        _u(string.concat(p, ".chainId")),
                        vm.parseJsonAddress(rec, string.concat(p, ".verifyingContract"))
                    )
                );
            bytes32 t = h.create(v, ds);
            assertEq(t, _b32(string.concat(p, ".typed")));
            assertTrue(t != _b32(string.concat(p, ".signedTyped")));
        }
    }

    /// One change at a time moves the create digest: mode, home, passKdf, passSalt, a member's via.
    function test_oneFieldMovesTheDigest() public view {
        IPqVault.PqVaultCreate memory v = _create(".vaults[0].records[0].record");
        bytes32 t = h.create(v, PqVaultTypes.DS_V);
        assertEq(t, _b32(".vaults[0].records[0].typed"));
        v.mode = 1;
        assertTrue(h.create(v, PqVaultTypes.DS_V) != t);
        v.mode = 0;
        v.homeVaultContract = address(uint160(v.homeVaultContract) ^ 1);
        assertTrue(h.create(v, PqVaultTypes.DS_V) != t);
        v.homeVaultContract = address(uint160(v.homeVaultContract) ^ 1);
        v.passKdf = 2;
        assertTrue(h.create(v, PqVaultTypes.DS_V) != t);
        v.passKdf = 1;
        v.passSalt = bytes32(uint256(v.passSalt) ^ 1);
        assertTrue(h.create(v, PqVaultTypes.DS_V) != t);
        v.passSalt = bytes32(uint256(v.passSalt) ^ 1);
        v.members[0].via = bytes32(uint256(v.members[0].via) ^ 1);
        assertTrue(h.create(v, PqVaultTypes.DS_V) != t);
        v.members[0].via = bytes32(uint256(v.members[0].via) ^ 1);
        assertEq(h.create(v, PqVaultTypes.DS_V), t, "restored");
    }
}
