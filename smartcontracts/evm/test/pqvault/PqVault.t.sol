// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {EnvKit} from "../helpers/EnvKit.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVault} from "../../src/pqvault/PqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";
import {PqVaultBase} from "./PqVaultBase.sol";

/// PqVault plan V3 (spec §5.1, §5.5): the release on the generic path (class 4, kind 0), vaults of one and of N members, wraps
/// in chunks, `addVaultWraps` front-run, the passphrase field shape, the full `UASig` read back. Every refusal beside its
/// positive control, one change at a time.
contract PqVaultTest is PqVaultBase {
    // ----- the release and its instances (CTR-PQV-02) -----

    function test_instance_factoryInfoAndInterfaces() public view {
        IOpenFactory.FactoryInfo memory i = vault.factoryInfo();
        assertEq(i.factory, address(f));
        assertEq(i.chainUid, chainUidA);
        assertEq(i.contractClass, 4);
        assertEq(i.kind, 0);
        assertEq(i.version, 1);
        assertTrue(i.initialized);
        assertEq(vault.owner(), OWNER_UA);
        assertEq(vaultB.owner(), bytes32(0), "owner 0 allowed");
        assertTrue(vault.supportsInterface(0x01ffc9a7));
        assertTrue(vault.supportsInterface(type(IPqVault).interfaceId));
        assertFalse(vault.supportsInterface(type(IPqChat).interfaceId));
        assertFalse(vault.supportsInterface(0xffffffff));
        IOpenFactory.FactoryInfo memory r = PqVault(impl).factoryInfo();
        assertEq(r.chainUid, bytes32(0));
        assertTrue(r.initialized);
        IFactoryToken.ChainEnv memory e = vault.chainEnv();
        assertEq(e.registry, address(p));
        assertEq(uint256(e.params[0]), LIMIT);
        assertEq(f.infoOf(address(vault)).contractClass, 4);
        assertEq(vault.REMOVE_MAX(), 16);
        assertEq(vault.VAULTS_RANGE_MAX(), 128);
        assertEq(vault.EPOCHS_RANGE_MAX(), 128);
        assertEq(vault.ITEMS_RANGE_MAX(), 128);
        assertEq(vault.LATEST_RANGE_MAX(), 16);
    }

    function test_initialize_onceAndOnlyByTheFactory() public {
        vm.expectRevert(IPqVault.PqVaultNotFactory.selector);
        vault.initialize(bytes32(uint256(7)));
        vm.prank(address(f));
        vm.expectRevert(IPqVault.PqVaultInitialized.selector);
        vault.initialize(bytes32(uint256(7)));
        vm.prank(address(f));
        vm.expectRevert(IPqVault.PqVaultInitialized.selector);
        PqVault(impl).initialize(bytes32(uint256(7)));
        assertEq(vault.owner(), OWNER_UA);
    }

    /// The owner is 0 or the creator: a creator naming another UA is refused; its own id and 0 pass.
    function test_initialize_ownerIsTheCreator() public {
        vm.prank(address(0xB0B));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultOwnerNotCreator.selector, OWNER_UA));
        f.createInstance(IOpenFactory.ReleaseId(4, 0, 1), "forged", abi.encodeCall(IPqVault.initialize, (OWNER_UA)));
        vm.prank(address(0xB0B));
        PqVault own = PqVault(
            f.createInstance(
                IOpenFactory.ReleaseId(4, 0, 1), "own", abi.encodeCall(IPqVault.initialize, (bytes32(uint256(0xB0B))))
            )
        );
        assertEq(own.owner(), bytes32(uint256(0xB0B)));
    }

    function test_validateEnv_refusals() public view {
        IFactoryToken.ChainEnv memory e;
        e.chainUid = chainUidA;
        e.registry = address(p);
        e.params = new bytes32[](1);
        e.params[0] = bytes32(uint256(24_576));
        vault.validateEnv(e); // the control
        for (uint256 k; k < 4; ++k) {
            IFactoryToken.ChainEnv memory b = IFactoryToken.ChainEnv(
                e.chainUid, e.registry, e.govRouter, e.smartKeyAccountImpl, e.hedera, e.deps, e.params
            );
            if (k == 0) b.chainUid = 0;
            if (k == 1) b.registry = address(0);
            if (k == 2) b.params = new bytes32[](0);
            if (k == 3) {
                b.params = new bytes32[](1);
                b.params[0] = bytes32(uint256(24_575));
            }
            try vault.validateEnv(b) {
                revert("validateEnv accepted a bad env");
            } catch (bytes memory err) {
                assertEq(bytes4(err), IPqVault.PqVaultEnv.selector);
            }
        }
    }

    /// The constructor: class 4, kind 0, version >= 1, a factory, no `implArgs`; each changed alone is refused.
    function test_constructor_refusals() public {
        new PqVault(IOpenFactory.ReleaseId(4, 0, 1), address(f), ""); // the control
        vm.expectRevert(IPqVault.PqVaultEnv.selector);
        new PqVault(IOpenFactory.ReleaseId(3, 0, 1), address(f), "");
        vm.expectRevert(IPqVault.PqVaultEnv.selector);
        new PqVault(IOpenFactory.ReleaseId(4, 1, 1), address(f), "");
        vm.expectRevert(IPqVault.PqVaultEnv.selector);
        new PqVault(IOpenFactory.ReleaseId(4, 0, 0), address(f), "");
        vm.expectRevert(IPqVault.PqVaultEnv.selector);
        new PqVault(IOpenFactory.ReleaseId(4, 0, 1), address(0), "");
        vm.expectRevert(IPqVault.PqVaultEnv.selector);
        new PqVault(IOpenFactory.ReleaseId(4, 0, 1), address(f), hex"00");
    }

    /// The implementation holds no env: every write refuses `PqVaultEnv`.
    function test_implementation_refusesWrites() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(1, 1, 0, address(vault));
        IUARegistry.UASig memory sig = _createSig(v, address(vault));
        vm.expectRevert();
        PqVault(impl).createVault(v, w, sig);
    }

    // ----- createVault (CTR-PQV-06) -----

    /// Ruling (a): a personal vault is one member, its one wrap, landed in the same call; the record and its full `UASig` read
    /// back; the nonce marked; `vaultsOf` lists it.
    function test_createVault_oneMember() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(1, 9, 0, address(vault));
        bytes32 vid = PqVaultTypes.vaultId(v.creator, 9, 0, chainUidA, address(vault));
        IUARegistry.UASig memory sig = _createSig(v, address(vault));
        vm.expectEmit(address(vault));
        emit IPqVault.PqVaultCreated(vid, v.creator, chainUidA);
        vm.expectEmit(address(vault));
        emit IPqVault.PqVaultWraps(vid, 0, 1);
        vm.expectEmit(address(vault));
        emit IPqVault.PqVaultEpochComplete(vid);
        vm.prank(STRANGER);
        assertEq(vault.createVault(v, w, sig), vid);
        assertTrue(vault.epochComplete(vid));
        bytes memory got = _raw(address(vault), abi.encodeCall(IPqVault.vaultOf, (vid)));
        assertEq(got, abi.encode(v, sig), "the record and its full UASig");
        assertEq(keccak256(abi.encode(abi.decode(got, (IPqVault.PqVaultCreate)))), keccak256(abi.encode(v)));
        assertTrue(vault.nonceUsed(PqVaultTypes.scopeVault(v.creator), 9));
        assertEq(vault.vaultCount(v.creator), 1);
        assertEq(vault.vaultsOf(v.creator, 0, 10)[0], vid);
        assertEq(vault.epochCount(vid), 1);
        assertEq(vault.latestEpoch(vid), vid);
        IPqChat.Wrap memory gw = vault.wrapAt(vid, 0);
        assertEq(keccak256(abi.encode(gw)), keccak256(abi.encode(w[0])));
    }

    /// N members, wraps in chunks: incomplete until the last lands; anyone lands the rest; every member's `vaultsOf`.
    function test_createVault_nMembersInChunks() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(4, 2, 0, address(vault));
        bytes32 vid = vault.createVault(v, _slice(w, 0, 1), _createSig(v, address(vault)));
        assertFalse(vault.epochComplete(vid));
        assertEq(vault.epochCount(vid), 0);
        vm.prank(STRANGER);
        vault.addVaultWraps(vid, 1, _slice(w, 1, 3));
        assertFalse(vault.epochComplete(vid));
        vm.expectEmit(address(vault));
        emit IPqVault.PqVaultEpochComplete(vid);
        vault.addVaultWraps(vid, 3, _slice(w, 3, 4));
        assertTrue(vault.epochComplete(vid));
        for (uint256 i; i < 4; ++i) {
            assertEq(vault.vaultsOf(ids[i], 0, 1)[0], vid);
        }
        // the wraps are stored once; none injected
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultWrapStored.selector, vid, 1));
        vault.addVaultWraps(vid, 1, _slice(w, 1, 2));
    }

    /// A front-runner lands the author's own wraps: the author's chunk reverts `PqVaultWrapStored`; it re-reads `wrapAt` and
    /// sends the rest. A forged wrap is refused by its hash.
    function test_addVaultWraps_frontRunThenTheRest() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(3, 3, 0, address(vault));
        bytes32 vid = vault.createVault(v, _slice(w, 0, 1), _createSig(v, address(vault)));
        vm.prank(STRANGER);
        vault.addVaultWraps(vid, 1, _slice(w, 1, 2)); // the front-run
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultWrapStored.selector, vid, 1));
        vault.addVaultWraps(vid, 1, _slice(w, 1, 3));
        IPqChat.Wrap[] memory forged = _slice(w, 2, 3);
        forged[0].x25519Eph = bytes32(uint256(forged[0].x25519Eph) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultWrapHash.selector, vid, 2));
        vault.addVaultWraps(vid, 2, forged);
        forged[0].x25519Eph = bytes32(uint256(forged[0].x25519Eph) ^ 1); // the same memory as w[2]: restored
        assertEq(vault.wrapAt(vid, 2).member, bytes32(0), "not landed yet");
        vault.addVaultWraps(vid, 2, _slice(w, 2, 3));
        assertTrue(vault.epochComplete(vid));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, keccak256("x")));
        vault.addVaultWraps(keccak256("x"), 0, _slice(w, 0, 1));
    }

    /// The passphrase field shape (P2): `(passKdf == 0) == (passSalt == 0)`; both off and both on pass.
    function test_createVault_passphraseShape() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(1, 4, 0, address(vault));
        v.passSalt = 0;
        _createRefused(v, w, abi.encodeWithSelector(IPqVault.PqVaultShape.selector));
        v.passKdf = 0;
        v.passSalt = keccak256("salt");
        _createRefused(v, w, abi.encodeWithSelector(IPqVault.PqVaultShape.selector));
        v.passSalt = 0;
        _create(vault, v, w); // off: the control
        (v, w) = _vault(1, 5, 0, address(vault));
        v.passKdf = 7; // a set the contract does not know: clients refuse it, the contract only checks the shape
        _create(vault, v, w);
    }

    function _createRefused(IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w, bytes memory err) internal {
        IUARegistry.UASig memory sig = _createSig(v, address(vault));
        vm.expectRevert(err);
        vault.createVault(v, w, sig);
    }

    /// The other shapes of a vault record, each beside the control that lands last.
    function test_createVault_refusals() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(2, 6, 0, address(vault));
        bytes memory shape = abi.encodeWithSelector(IPqVault.PqVaultShape.selector);
        // no member (the bound is 1)
        IPqVault.PqVaultCreate memory z = _copy(v);
        z.members = new IPqChat.MemberKey[](0);
        z.wrapHashes = new bytes32[](0);
        _createRefused(z, new IPqChat.Wrap[](0), shape);
        // unsorted members
        z = _copy(v);
        (z.members[0], z.members[1]) = (z.members[1], z.members[0]);
        _createRefused(z, w, shape);
        // the creator not an admin, not a member
        z = _copy(v);
        z.admins = _list(ids[1]);
        _createRefused(z, w, shape);
        z = _copy(v);
        z.creator = ids[2];
        z.admins = _list(ids[2]);
        _createRefused(z, w, shape);
        // no home
        z = _copy(v);
        z.homeChain = 0;
        _createRefused(z, w, shape);
        z = _copy(v);
        z.homeVaultContract = address(0);
        _createRefused(z, w, shape);
        // a member without the KEM key version
        z = _copy(v);
        z.members[1].keyId = 5;
        _createRefused(z, w, abi.encodeWithSelector(IPqVault.PqVaultKemKey.selector, z.members[1].ua, uint64(5)));
        // a hash count other than the members'
        z = _copy(v);
        z.wrapHashes = new bytes32[](1);
        _createRefused(z, w, shape);
        // forged: another key signs for the creator
        IUARegistry.UASig memory bad = _sig(ids[1], h.create(v, PqVaultTypes.DS_V));
        vm.expectRevert(_unauthorized(v.creator));
        vault.createVault(v, w, bad);
        assertFalse(vault.nonceUsed(PqVaultTypes.scopeVault(v.creator), 6), "a forged record burns no nonce");
        // a PqChat signature (PURPOSE_PQCHAT) is no PqVault signature
        IUARegistry.UASig memory chatSig;
        chatSig.signature =
            _sig(keyOf_[v.creator], UAKinds.uaMessage(ML, UAKinds.PURPOSE_PQCHAT, h.create(v, PqVaultTypes.DS_V)));
        vm.expectRevert(_unauthorized(v.creator));
        vault.createVault(v, w, chatSig);
        // a wrong wrap
        IPqChat.Wrap[] memory ww = _slice(w, 0, 2);
        bytes memory sk = ww[1].sealedKey;
        ww[1].sealedKey = new bytes(47);
        _createRefused(
            v,
            ww,
            abi.encodeWithSelector(
                IPqVault.PqVaultWrapHash.selector, PqVaultTypes.vaultId(v.creator, 6, 0, chainUidA, address(vault)), 1
            )
        );
        ww[1].sealedKey = sk; // the same memory as w[1]: restored
        bytes32 vid = _create(vault, v, w); // the control
        _createRefused(
            v,
            w,
            abi.encodeWithSelector(IPqVault.PqVaultNonceUsed.selector, PqVaultTypes.scopeVault(v.creator), uint64(6))
        );
        assertTrue(vault.epochComplete(vid));
    }

    function _copy(IPqVault.PqVaultCreate memory v) internal pure returns (IPqVault.PqVaultCreate memory z) {
        z = abi.decode(abi.encode(v), (IPqVault.PqVaultCreate));
    }

    /// A replica of a mode-0 vault homed at A, in B: the same record, the same id; B is not its home.
    function test_createVault_replica() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(2, 8, 0, address(vault));
        IUARegistry.UASig memory sig = _createSig(v, address(vault));
        bytes32 a = vault.createVault(v, w, sig);
        assertEq(vaultB.createVault(v, w, sig), a);
        assertTrue(vaultB.epochComplete(a));
    }

    // ----- views of the group part -----

    function test_views_unknownIds() public {
        (bytes32 vid,) = _newVault(2, 0);
        bytes32 x = keccak256("x");
        _rawRefused(abi.encodeCall(IPqVault.vaultOf, (x)), abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, x));
        _rawRefused(abi.encodeCall(IPqVault.epochOf, (x)), abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, x));
        // epoch 0 is the vault: vaultOf
        _rawRefused(
            abi.encodeCall(IPqVault.epochOf, (vid)), abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, vid)
        );
        assertEq(vault.epochCount(x), 0);
        assertEq(vault.latestEpoch(x), bytes32(0));
        assertEq(vault.vaultsOf(ids[0], 5, 10).length, 0, "an offset past the end: empty");
        assertFalse(vault.epochComplete(x));
    }
}
