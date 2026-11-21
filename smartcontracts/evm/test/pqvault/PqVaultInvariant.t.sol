// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVault} from "../../src/pqvault/PqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";
import {PqVaultBase, PqVaultHasher} from "./PqVaultBase.sol";

/// The handler of `PqVaultInvariantTest`: the eight writes by honest and hostile actors (members, admins, removed and leaving
/// members, strangers; forged and other-domain signatures; random epochs, versions, nonces and lengths). Every call is caught;
/// what an accepted write must have checked is checked here at once and a breach recorded in `breach`.
contract PqVaultHandler is Test {
    PqVault internal v;
    PqVaultHasher internal h;
    bytes32[] internal ids;
    mapping(bytes32 => bytes) internal keyOf;

    bytes32[] public vaults;
    bytes32[] public epochs; // every epoch id known to exist (vault ids included)
    bytes32[] public itemIds;
    mapping(bytes32 => uint32) public seenVersions;
    mapping(bytes32 => uint256) public completeChildren; // at home, per parent
    mapping(bytes32 => mapping(bytes32 => bool)) public removed; // epoch => ua, by a remove
    mapping(bytes32 => mapping(bytes32 => bool)) public left; // epoch => ua, by a leave
    mapping(bytes32 => bool) internal counted;
    string public breach;
    uint64 internal nonce = 1;
    uint256 public accepted;

    constructor(PqVault v_, PqVaultHasher h_, bytes32[] memory ids_, bytes[] memory keys) {
        (v, h, ids) = (v_, h_, ids_);
        for (uint256 i; i < ids_.length; ++i) {
            keyOf[ids_[i]] = keys[i];
        }
    }

    function _sig(bytes32 ua, bytes32 digest, bool forge) internal view returns (IUARegistry.UASig memory s) {
        bytes32 m = UAKinds.uaMessage(UAKinds.MLDSA65, PqVaultTypes.P_V, digest);
        s.signature = abi.encodePacked(keccak256(abi.encode(keyOf[forge ? ids[0] : ua], m)));
        if (forge && ua == ids[0]) s.signature = hex"00";
    }

    function _ua(uint256 r) internal view returns (bytes32) {
        return r % 7 == 6 ? keccak256(abi.encode("stranger", r)) : ids[r % ids.length];
    }

    function _members(uint256 seed) internal view returns (IPqChat.MemberKey[] memory m) {
        uint256 n = 1 + seed % ids.length;
        m = new IPqChat.MemberKey[](n);
        for (uint256 i; i < n; ++i) {
            m[i] = IPqChat.MemberKey(ids[i], 0, bytes32(0));
        }
    }

    function _wraps(IPqChat.MemberKey[] memory m, bytes32 epochId)
        internal
        pure
        returns (IPqChat.Wrap[] memory w, bytes32[] memory hs)
    {
        w = new IPqChat.Wrap[](m.length);
        hs = new bytes32[](m.length);
        for (uint256 i; i < m.length; ++i) {
            w[i] = IPqChat.Wrap(m[i].ua, m[i].keyId, new bytes(1568), keccak256(abi.encode(epochId, i)), new bytes(48));
            hs[i] = keccak256(
                abi.encode(
                    PqChatTypes.WRAP_TYPEHASH,
                    w[i].member,
                    w[i].keyId,
                    keccak256(w[i].mlkemCt),
                    w[i].x25519Eph,
                    keccak256(w[i].sealedKey)
                )
            );
        }
    }

    function _pick(bytes32[] storage l, uint256 r) internal view returns (bytes32) {
        return l.length == 0 ? bytes32(r) : l[r % l.length];
    }

    function _fail(string memory why) internal {
        if (bytes(breach).length == 0) breach = why;
    }

    function createVault(uint256 seed) external tracked {
        IPqVault.PqVaultCreate memory c;
        c.members = _members(seed);
        c.creator = c.members[seed % c.members.length].ua;
        c.nonce = nonce++;
        c.homeChain = v.factoryInfo().chainUid;
        c.homeVaultContract = address(v);
        c.admins = new bytes32[](1);
        c.admins[0] = c.creator;
        bytes32 vid = PqVaultTypes.vaultId(c.creator, c.nonce, 0, c.homeChain, c.homeVaultContract);
        IPqChat.Wrap[] memory w;
        (w, c.wrapHashes) = _wraps(c.members, vid);
        c.passKdf = uint16(seed % 2);
        c.passSalt = c.passKdf == 0 ? bytes32(0) : keccak256(abi.encode(seed));
        try v.createVault(c, w, _sig(c.creator, h.create(c, PqVaultTypes.DS_V), seed % 11 == 0)) {
            if (seed % 11 == 0) _fail("a forged vault accepted");
            if (!v.nonceUsed(PqVaultTypes.scopeVault(c.creator), c.nonce)) _fail("vault nonce not marked");
            vaults.push(vid);
            epochs.push(vid);
            ++accepted;
        } catch {}
    }

    function _parentInfo(bytes32 parent) internal view returns (bytes32 vid, bytes32[] memory pa, uint64 number) {
        vid = parent;
        (bool ok, bytes memory ret) = address(v).staticcall(abi.encodeCall(IPqVault.epochOf, (parent)));
        if (ok) {
            IPqVault.PqVaultEpoch memory pe = abi.decode(ret, (IPqVault.PqVaultEpoch));
            (vid, pa, number) = (pe.vaultId, pe.admins, pe.epoch);
        } else {
            pa = abi.decode(_raw(abi.encodeCall(IPqVault.vaultOf, (parent))), (IPqVault.PqVaultCreate)).admins;
        }
    }

    function _newEpoch(bytes32 vid, bytes32 parent, uint64 number, uint256 seed, uint256 who)
        internal
        returns (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w)
    {
        (e.vaultId, e.author, e.nonce, e.epoch, e.parentEpochId) = (vid, _ua(who), nonce++, number + 1, parent);
        e.members = _members(seed >> 8);
        e.admins = new bytes32[](1);
        e.admins[0] = ids[who % ids.length];
        (w, e.wrapHashes) = _wraps(e.members, PqVaultTypes.epochId(vid, e.author, e.nonce));
    }

    function rekeyVault(uint256 seed, uint256 who) external tracked {
        bytes32 parent = _pick(epochs, seed);
        if (!v.epochComplete(parent)) return;
        (bytes32 vid, bytes32[] memory pa, uint64 number) = _parentInfo(parent);
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) = _newEpoch(vid, parent, number, seed, who);
        try v.rekeyVault(e, w, _sig(e.author, h.epoch(e, PqVaultTypes.DS_V), seed % 13 == 0)) returns (bytes32 eid) {
            _rekeyed(e, eid, pa);
        } catch {}
    }

    function _rekeyed(IPqVault.PqVaultEpoch memory e, bytes32 eid, bytes32[] memory pa) internal {
        bool admin;
        for (uint256 i; i < pa.length; ++i) {
            if (pa[i] == e.author) admin = true;
        }
        if (!admin || removed[e.parentEpochId][e.author]) {
            _fail("a complete epoch not authored by an admin of its parent");
        }
        if (!v.nonceUsed(PqVaultTypes.scopeEpoch(e.vaultId, e.author), e.nonce)) _fail("epoch nonce not marked");
        if (v.epochComplete(eid) && ++completeChildren[e.parentEpochId] > 1) _fail("two complete children at home");
        epochs.push(eid);
        ++accepted;
    }

    function _raw(bytes memory data) internal view returns (bytes memory ret) {
        bool ok;
        (ok, ret) = address(v).staticcall(data);
        require(ok);
    }

    function removeVaultMembers(uint256 seed, uint256 who) external tracked {
        bytes32 ep = _pick(epochs, seed);
        bytes32 vid = ep;
        (bool ok, bytes memory ret) = address(v).staticcall(abi.encodeCall(IPqVault.epochOf, (ep)));
        if (ok) vid = abi.decode(ret, (IPqVault.PqVaultEpoch)).vaultId;
        uint64 next = uint64(v.epochCount(vid)); // a guess; wrong numbers are refused
        bytes32 m = ids[(seed >> 8) % ids.length];
        IPqVault.PqVaultRemove memory r = IPqVault.PqVaultRemove(vid, ep, next, new bytes32[](1), _ua(who), nonce++);
        r.members[0] = m;
        try v.removeVaultMembers(r, _sig(r.admin, h.remove(r, PqVaultTypes.DS_V), false)) {
            removed[ep][m] = true;
            ++accepted;
        } catch {}
    }

    function leaveVault(uint256 seed, uint256 who) external tracked {
        bytes32 ep = _pick(epochs, seed);
        bytes32 vid = ep;
        (bool ok, bytes memory ret) = address(v).staticcall(abi.encodeCall(IPqVault.epochOf, (ep)));
        if (ok) vid = abi.decode(ret, (IPqVault.PqVaultEpoch)).vaultId;
        IPqVault.PqVaultLeave memory l = IPqVault.PqVaultLeave(vid, ep, _ua(who), nonce++);
        try v.leaveVault(l, _sig(l.member, h.leave(l, PqVaultTypes.DS_V), false)) {
            left[ep][l.member] = true; // a leaver writes no item under it either (O3 (b)); an admin that left may still rekey
            ++accepted;
        } catch {}
    }

    function _len(uint256 seed) internal pure returns (uint256) {
        uint256[6] memory l = [uint256(31), 32, 288, 4128, 16_416, 16_417];
        return l[seed % 6];
    }

    function _wrote(bytes32 ep, bytes32 author, bytes32 vid, uint64 n) internal {
        if (removed[ep][author] || left[ep][author]) _fail("a removed or leaving member wrote under the epoch");
        if (!v.nonceUsed(PqVaultTypes.scopeItem(vid, author), n)) _fail("item nonce not marked");
        ++accepted;
    }

    function createItem(uint256 seed, uint256 who) external tracked {
        bytes32 ep = _pick(epochs, seed);
        bytes32 vid = ep;
        (bool ok, bytes memory ret) = address(v).staticcall(abi.encodeCall(IPqVault.epochOf, (ep)));
        if (ok) vid = abi.decode(ret, (IPqVault.PqVaultEpoch)).vaultId;
        IPqVault.PqVaultItem memory it = IPqVault.PqVaultItem(vid, ep, _ua(who), nonce++, new bytes(_len(seed >> 4)));
        try v.createItem(it, _sig(it.author, h.item(it, PqVaultTypes.DS_V), seed % 17 == 0)) returns (bytes32 iid) {
            itemIds.push(iid);
            _wrote(ep, it.author, vid, it.nonce);
        } catch {}
    }

    function editItem(uint256 seed, uint256 who, uint32 version) external tracked {
        if (itemIds.length == 0) return;
        bytes32 iid = itemIds[seed % itemIds.length];
        bytes32 vid = v.itemOf(iid).vaultId;
        bytes32 ep = _pick(epochs, seed >> 8);
        IPqVault.PqVaultEdit memory d = IPqVault.PqVaultEdit(
            iid,
            ep,
            _ua(who),
            nonce++,
            version % 2 == 0 ? v.itemOf(iid).versionCount + 1 : version % 9,
            new bytes(_len(seed >> 4))
        );
        try v.editItem(d, _sig(d.author, h.edit(d, PqVaultTypes.DS_V), false)) {
            _wrote(ep, d.author, vid, d.nonce);
        } catch {}
    }

    function createItems(uint256 seed, uint256 who, uint8 n) external tracked {
        bytes32 ep = _pick(epochs, seed);
        bytes32 vid = ep;
        (bool ok, bytes memory ret) = address(v).staticcall(abi.encodeCall(IPqVault.epochOf, (ep)));
        if (ok) vid = abi.decode(ret, (IPqVault.PqVaultEpoch)).vaultId;
        IPqVault.PqVaultBatch memory b =
            IPqVault.PqVaultBatch(vid, ep, _ua(who), nonce++, new IPqVault.PqVaultItem[](n % 4));
        for (uint256 i; i < b.items.length; ++i) {
            b.items[i] = IPqVault.PqVaultItem(
                vid, ep, b.author, seed % 19 == 0 ? b.nonce : nonce++, new bytes(_len(seed >> (4 + i)))
            );
        }
        try v.createItems(b, _sig(b.author, h.batch(b, PqVaultTypes.DS_V), false)) {
            for (uint256 i; i < b.items.length; ++i) {
                itemIds.push(PqVaultTypes.itemId(vid, b.author, b.items[i].nonce));
                _wrote(ep, b.author, vid, b.items[i].nonce);
            }
            if (!v.nonceUsed(PqVaultTypes.scopeItem(vid, b.author), b.nonce)) _fail("batch nonce not marked");
        } catch {}
    }

    function addVaultWraps(uint256 seed) external tracked {
        bytes32 ep = _pick(epochs, seed);
        IPqChat.MemberKey[] memory m = _members(seed >> 8);
        (IPqChat.Wrap[] memory w,) = _wraps(m, ep);
        try v.addVaultWraps(ep, uint32(seed % 3), w) {} catch {}
    }

    function itemCount() external view returns (uint256) {
        return itemIds.length;
    }

    function vaultCount() external view returns (uint256) {
        return vaults.length;
    }

    // ----- the ghost baselines (Fable code review F6): kept and compared in the handler's own writes, which Foundry commits; an
    // `invariant_*` call's state changes are not, so a baseline written there would be 0 again at every check

    uint256 public lastItemTotal;
    mapping(bytes32 => uint256) public lastVaultCount;

    /// After every handler write: no item's `versionCount` decreased, the vaults' item lists and each UA's `vaultsOf` did not
    /// shrink; the baselines move up.
    modifier tracked() {
        _;
        for (uint256 i; i < itemIds.length; ++i) {
            uint32 c = v.itemOf(itemIds[i]).versionCount;
            if (c < seenVersions[itemIds[i]]) _fail("versionCount decreased");
            seenVersions[itemIds[i]] = c;
        }
        uint256 total;
        for (uint256 i; i < vaults.length; ++i) {
            total += v.itemCount(vaults[i]);
        }
        if (total < lastItemTotal) _fail("itemsOf shrank");
        lastItemTotal = total;
        for (uint256 i; i < ids.length; ++i) {
            uint256 n = v.vaultCount(ids[i]);
            if (n < lastVaultCount[ids[i]]) _fail("vaultsOf shrank");
            lastVaultCount[ids[i]] = n;
        }
    }

    /// The breach recorded by a handler write, if any; every stored version decodes and is 32..16,416 B (read now).
    function check() external view returns (string memory) {
        if (bytes(breach).length != 0) return breach;
        for (uint256 i; i < itemIds.length; ++i) {
            uint32 c = v.itemOf(itemIds[i]).versionCount;
            for (uint32 k = 1; k <= c; ++k) {
                uint256 n = v.versionAt(itemIds[i], k).ciphertext.length;
                if (n < 32 || n > 16_416) return "a stored ciphertext outside 32..16,416 B";
            }
        }
        return "";
    }
}

/// PqVault plan V6 (spec §11 "Invariants"): a handler over the eight writes with honest and hostile actors. `versionCount` never
/// decreases and every stored version decodes; at home every epoch has at most one complete child; no removed (or leaving) member
/// writes under that epoch; every complete epoch >= 1 was authored by an admin of its parent; every stored ciphertext is 32..16,416
/// B; `itemsOf` and `vaultsOf` only grow (the handler's ghost baselines, F6); every accepted write's nonce is marked. **UNAUDITED.**
contract PqVaultInvariantTest is PqVaultBase {
    PqVaultHandler internal hd;

    function setUp() public override {
        super.setUp();
        bytes[] memory keys = new bytes[](ids.length);
        for (uint256 i; i < ids.length; ++i) {
            keys[i] = keyOf_[ids[i]];
        }
        hd = new PqVaultHandler(vault, h, ids, keys);
        targetContract(address(hd));
    }

    function invariant_noBreach() public view {
        assertEq(hd.check(), "");
    }

    /// `vaultsOf` pages at most 128 entries of each UA's list (its growth: the handler's ghost baselines, `invariant_noBreach`).
    function invariant_vaultsOfPages() public view {
        for (uint256 i; i < ids.length; ++i) {
            uint256 n = vault.vaultCount(ids[i]);
            assertEq(vault.vaultsOf(ids[i], 0, 128).length, n > 128 ? 128 : n);
        }
    }

    /// The handler reaches accepted writes of every kind, so the invariants are not vacuous (a fixed sequence).
    function test_handlerReachesAcceptedWrites() public {
        hd.createVault(4); // 1 + 4 % 5 = 5 members, ids[4] creator and admin
        hd.createItem(0, 1); // 31 B: refused
        hd.createItem(32, 1); // epoch 0, ids[1], 288 B
        hd.createItems(0, 2, 2); // an item nonce equal to the batch nonce: refused
        hd.createItems(32, 2, 2); // 288 B and 32 B
        hd.editItem(32, 3, 2); // version 2 by ids[3]
        hd.leaveVault(0, 3);
        hd.removeVaultMembers(0, 4);
        assertEq(hd.accepted(), 7, "createVault, createItem, two batch items, editItem, leaveVault, removeVaultMembers");
        assertEq(hd.check(), "");
    }

    /// Fable code review F6: the baselines live in the handler (committed by its write calls), so a decrease between two handler
    /// writes is a breach. Positive controls: after a write, `itemOf` mocked to a lower `versionCount`, then `vaultCount` mocked
    /// to a lower count; the next handler write records each breach.
    function test_ghostBaselinesCatchADecrease() public {
        hd.createVault(4);
        hd.createItem(32, 1);
        bytes32 iid = hd.itemIds(0);
        IPqVault.ItemView memory iv = vault.itemOf(iid);
        assertEq(iv.versionCount, 1);
        hd.createItem(33, 2); // a later write: no breach yet
        assertEq(hd.breach(), "");
        vm.mockCall(
            address(vault), abi.encodeCall(IPqVault.itemOf, (iid)), abi.encode(IPqVault.ItemView(iv.vaultId, 0, 0))
        );
        hd.createItem(34, 3);
        assertEq(hd.breach(), "versionCount decreased");
    }

    function test_ghostBaselinesCatchAShrinkingList() public {
        hd.createVault(4);
        hd.createItem(32, 1);
        assertEq(hd.breach(), "");
        vm.mockCall(address(vault), abi.encodeCall(IPqVault.vaultCount, (ids[0])), abi.encode(uint256(0)));
        hd.createItem(33, 2);
        assertEq(hd.breach(), "vaultsOf shrank");
    }
}
