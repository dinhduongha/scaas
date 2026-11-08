// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {Catalogue, plainEnv} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {UID_, normalInit} from "./helpers/V2Fixture.sol";
import {NoteKind, RosterKind, BadKind, INoteKind, IRosterKind} from "./mocks/GenericKinds.sol";

/// Plan T70 (factory index spec §8; CTR-TOK-28, owner 2026-11-07 with Q7-Q12): generic classes and kinds added by the
/// registrar with no factory code (`publishClassEnv`, `deployRelease`, `setClassKindEnabled`), created by anyone
/// (`createInstance` with the release's typed initializer), indexed under their class. The kinds are test-only mocks
/// (`test/v2/mocks/GenericKinds.sol`): `NoteKind` (class 4, kind 0, a string), `RosterKind` (class 5, kind 1, a dynamic
/// array). **UNAUDITED.**
contract FactoryGenericKindTest is Test {
    address registrar = address(0xF00D);
    address alice = address(0xA11CE);
    address relayer = address(0xBEEF);
    OpenFactory f;
    uint64 constant NOTICE = 1 hours;

    function setUp() public {
        vm.warp(1_800_000_000);
        f = EnvKit.factory(registrar, UID_, NOTICE);
    }

    function _id(uint16 c, uint16 k, uint64 v) internal pure returns (IOpenFactory.ReleaseId memory) {
        return IOpenFactory.ReleaseId(c, k, v);
    }

    function _env() internal view returns (IFactoryToken.Env memory e) {
        e = plainEnv(address(f), address(0), UID_, address(0), false);
        e.params = new bytes32[](1);
        e.params[0] = bytes32(uint256(131_072)); // a chain value of the class (PqChat: the code-size limit)
    }

    function _publish(uint16 c, uint16 k, uint16 v) internal {
        vm.prank(registrar);
        f.publishClassEnv(c, k, v, _env());
    }

    function _release(uint16 c, uint16 k, uint64 v, bytes memory code, bytes4 sel, bytes4 iface, bytes memory implArgs)
        internal returns (address)
    {
        vm.prank(registrar);
        return f.deployRelease(_id(c, k, v), 1, sel, iface, code, implArgs);
    }

    function _note(uint64 v) internal returns (address) {
        return _release(4, 0, v, type(NoteKind).creationCode, INoteKind.initialize.selector, type(INoteKind).interfaceId, "");
    }

    function _enable(uint16 c, uint16 k, bool on) internal {
        vm.prank(registrar);
        f.setClassKindEnabled(c, k, on);
    }

    function _noteCall(bytes32 owner_, string memory note) internal pure returns (bytes memory) {
        return abi.encodeCall(INoteKind.initialize, (owner_, note));
    }

    // ------------------------------------------------------------------ the acceptance test (spec §8.9)

    /// Two classes and three kinds are added, created, listed, versioned and deprecated on a factory deployed before them,
    /// its runtime code unchanged throughout.
    function test_generic_addKindWithoutFactoryChange() public {
        bytes32 codeHash = address(f).codehash;
        // class 4, kind 0: env, release, before the notice period, off, enabled
        _publish(4, 0, 1);
        address n1 = _note(1);
        assertEq(f.classes().length, 1);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ReleaseNotYetUsable.selector, 4, 0, 1,
            uint64(block.timestamp + NOTICE)));
        f.createInstance(_id(4, 0, 1), "a", _noteCall(nid(alice), "hi"));
        vm.warp(block.timestamp + NOTICE);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassKindDisabled.selector, 4, 0));
        f.createInstance(_id(4, 0, 1), "a", _noteCall(nid(alice), "hi"));
        _enable(4, 0, true);
        // an EOA and a relayer naming another owner
        vm.prank(alice);
        address a = f.createInstance(_id(4, 0, 1), "a", _noteCall(nid(alice), "hi"));
        vm.prank(relayer);
        address b = f.createInstance(_id(4, 0, 1), "b", _noteCall(nid(alice), "for alice"));
        assertEq(NoteKind(a).note(), "hi");
        assertEq(NoteKind(b).owner(), nid(alice));
        assertEq(NoteKind(a).seenCreator(), nid(alice), "creating() inside initialize");
        assertEq(NoteKind(b).seenCreator(), nid(relayer));
        assertEq(f.creating(), bytes32(0), "0 after");
        IOpenFactory.Created memory c = f.infoOf(b);
        assertEq(c.addr, b);
        assertEq(c.creatorId, nid(relayer));
        assertEq(c.ownerUA, nid(alice));
        assertEq(c.contractClass, 4);
        assertEq(c.kind, 0);
        assertEq(c.version, 1);
        assertEq(c.createdBlock, block.number);
        assertEq(c.createdAt, block.timestamp);
        (IOpenFactory.Created[] memory p, uint256 n) = f.contractsPage(4, 0, 10);
        assertEq(n, 2);
        assertEq(p[0].addr, a);
        (p, n) = f.contractsOfOwner(nid(alice), 4, 0, 10);
        assertEq(n, 2);
        (p, n) = f.contractsOfCreator(nid(relayer), 4, 0, 10);
        assertEq(n, 1);
        assertEq(p[0].addr, b);
        assertEq(NoteKind(a).factoryInfo().chainUid, UID_, "the env in the clone's code");
        assertEq(NoteKind(a).chainEnv().params[0], bytes32(uint256(131_072)), "the class's chain value");
        assertEq(NoteKind(n1).factoryInfo().chainUid, bytes32(0), "the release carries no env");
        // class 5, kind 1: a dynamic argument
        _publish(5, 1, 1);
        _release(5, 1, 1, type(RosterKind).creationCode, IRosterKind.initialize.selector, type(IRosterKind).interfaceId, "");
        vm.warp(block.timestamp + NOTICE);
        _enable(5, 1, true);
        address[] memory ms = new address[](3);
        (ms[0], ms[1], ms[2]) = (alice, relayer, address(0xC0));
        address r = f.createInstance(_id(5, 1, 1), "r", abi.encodeCall(IRosterKind.initialize, (nid(alice), 7, ms)));
        assertEq(RosterKind(r).members().length, 3);
        assertEq(RosterKind(r).start(), 7);
        uint16[] memory cs = f.classes();
        assertEq(cs.length, 2);
        assertEq(cs[0], 4);
        assertEq(cs[1], 5);
        uint16[] memory ks = f.kindsOf(5);
        assertEq(ks.length, 1);
        assertEq(ks[0], 1);
        // version 2 of (4, 0), version 1 deprecated: the old instance still answers, v1 refused, v2 created
        _note(2);
        vm.warp(block.timestamp + NOTICE);
        vm.prank(registrar);
        vm.expectEmit(true, true, true, true, address(f));
        emit IOpenFactory.ReleaseDeprecated(4, 0, 1, "bug");
        f.deprecateRelease(_id(4, 0, 1), "bug");
        assertTrue(f.classReleaseOf(_id(4, 0, 1)).deprecated);
        assertEq(NoteKind(a).note(), "hi", "the old instance answers");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ReleaseIsDeprecated.selector, 4, 0, 1));
        f.createInstance(_id(4, 0, 1), "c", _noteCall(nid(alice), "x"));
        address v2 = f.createInstance(_id(4, 0, 2), "c", _noteCall(nid(alice), "v2"));
        assertEq(f.infoOf(v2).version, 2);
        assertEq(f.latestClassVersion(4, 0), 2);
        // a second kind added to class 4
        _publish(4, 7, 1);
        _release(4, 7, 1, type(NoteKind).creationCode, INoteKind.initialize.selector, type(INoteKind).interfaceId, "");
        ks = f.kindsOf(4);
        assertEq(ks.length, 2);
        assertEq(ks[1], 7);
        assertEq(f.classes().length, 2, "a class is listed once");
        assertEq(address(f).codehash, codeHash, "the factory's code never changed");
    }

    // ------------------------------------------------------------------ negatives, each with its positive control

    function test_generic_reservedClassesRefusedOnEveryEntry() public {
        for (uint16 c; c <= 2; ++c) {
            vm.startPrank(registrar);
            vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassReserved.selector, c));
            f.publishClassEnv(c, 0, 1, _env());
            vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassReserved.selector, c));
            f.deployRelease(_id(c, 0, 1), 1, INoteKind.initialize.selector, type(INoteKind).interfaceId,
                type(NoteKind).creationCode, "");
            vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassReserved.selector, c));
            f.deprecateRelease(_id(c, 0, 1), "x");
            vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassReserved.selector, c));
            f.setClassKindEnabled(c, 0, true);
            vm.stopPrank();
            vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassReserved.selector, c));
            f.createInstance(_id(c, 0, 1), "x", _noteCall(0, ""));
        }
        _publish(3, 0, 1); // positive control: the first generic class
    }

    function test_generic_versionZeroTakenAndSelectorZeroRefused() public {
        _publish(4, 0, 1);
        bytes memory code = type(NoteKind).creationCode;
        vm.startPrank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ReleaseUnknown.selector, 4, 0, 0));
        f.deployRelease(_id(4, 0, 0), 1, INoteKind.initialize.selector, type(INoteKind).interfaceId, code, "");
        vm.expectRevert(IOpenFactory.InitSelectorZero.selector);
        f.deployRelease(_id(4, 0, 1), 1, bytes4(0), type(INoteKind).interfaceId, code, "");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.EnvUnknown.selector, uint32(4) << 16, 2));
        f.deployRelease(_id(4, 0, 1), 2, INoteKind.initialize.selector, type(INoteKind).interfaceId, code, "");
        address n1 = f.deployRelease(_id(4, 0, 1), 1, INoteKind.initialize.selector, type(INoteKind).interfaceId, code, "");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ReleaseAlreadyRegistered.selector, 4, 0, 1, n1));
        f.deployRelease(_id(4, 0, 1), 1, INoteKind.initialize.selector, type(INoteKind).interfaceId, code, "");
        vm.stopPrank();
    }

    /// A release whose `factoryInfo()` or ERC-165 lies is refused at deployment, each mode alone.
    function test_generic_releaseChecks() public {
        _publish(4, 0, 1);
        bytes memory code = type(BadKind).creationCode;
        bytes4 sel = INoteKind.initialize.selector;
        bytes4 iface = type(INoteKind).interfaceId;
        for (uint8 m = 1; m <= 9; ++m) { // another factory, class, kind, version; uninitialized; an owner; 192 B; 256 B; none
            address at = vm.computeCreate2Address(keccak256(abi.encode("release", _id(4, 0, 1))),
                keccak256(bytes.concat(code, abi.encode(_id(4, 0, 1), address(f), abi.encode(m)))), address(f));
            vm.prank(registrar);
            vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ReleaseInfoMismatch.selector, at));
            f.deployRelease(_id(4, 0, 1), 1, sel, iface, code, abi.encode(m));
        }
        for (uint8 m = 10; m <= 11; ++m) { // ERC-165 false for the interface; true for 0xffffffff
            address at = vm.computeCreate2Address(keccak256(abi.encode("release", _id(4, 0, 1))),
                keccak256(bytes.concat(code, abi.encode(_id(4, 0, 1), address(f), abi.encode(m)))), address(f));
            vm.prank(registrar);
            vm.expectRevert(abi.encodeWithSelector(IOpenFactory.InterfaceNotSupported.selector, at, m == 10 ? iface : bytes4(0xffffffff)));
            f.deployRelease(_id(4, 0, 1), 1, sel, iface, code, abi.encode(m));
        }
        vm.prank(registrar);
        f.deployRelease(_id(4, 0, 1), 1, sel, iface, code, abi.encode(uint8(0))); // positive control
    }

    /// The creation's checks: the selector, the post-init `factoryInfo()` and `chain_uid`, a reverting initializer, salts.
    function test_generic_creationChecks() public {
        _publish(4, 0, 1);
        bytes memory code = type(BadKind).creationCode;
        for (uint8 m = 12; m <= 17; ++m) {
            if (m == 16) continue; // NESTED: test_generic_nestedCreation
            vm.prank(registrar);
            f.deployRelease(_id(4, 0, uint64(m)), 1, INoteKind.initialize.selector, type(INoteKind).interfaceId, code,
                abi.encode(m));
        }
        _note(1);
        vm.warp(block.timestamp + NOTICE);
        _enable(4, 0, true);
        // the initCall's selector: none (0-3 bytes) or another
        for (uint256 len; len < 4; ++len) {
            vm.expectRevert(abi.encodeWithSelector(IOpenFactory.InitSelectorMismatch.selector, INoteKind.initialize.selector,
                bytes4(new bytes(len))));
            f.createInstance(_id(4, 0, 1), "s", new bytes(len));
        }
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.InitSelectorMismatch.selector, INoteKind.initialize.selector,
            INoteKind.note.selector));
        f.createInstance(_id(4, 0, 1), "s", abi.encodeCall(INoteKind.note, ()));
        // an initializer that leaves `initialized` false, or reports another class after init
        address p12 = f.predictAddress(nid(address(this)), 4, 0, "12");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.InstanceInfoMismatch.selector, p12));
        f.createInstance(_id(4, 0, 12), "12", _noteCall(0, ""));
        address p13 = f.predictAddress(nid(address(this)), 4, 0, "13");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.InstanceInfoMismatch.selector, p13));
        f.createInstance(_id(4, 0, 13), "13", _noteCall(0, ""));
        // a reverting initializer: bubbled
        vm.expectRevert(bytes("init reverts"));
        f.createInstance(_id(4, 0, 14), "14", _noteCall(0, ""));
        // another chain_uid after init (chain-neutral spec §3.2)
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidMismatch.selector, UID_, keccak256("another chain")));
        f.createInstance(_id(4, 0, 15), "15", _noteCall(0, ""));
        // another version after init (T68: the post-init version comparison)
        address p17 = f.predictAddress(nid(address(this)), 4, 0, "17");
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.InstanceInfoMismatch.selector, p17));
        f.createInstance(_id(4, 0, 17), "17", _noteCall(0, ""));
        // the salt once
        address ok = f.createInstance(_id(4, 0, 1), "s", _noteCall(0, "ok")); // positive control
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, ok));
        f.createInstance(_id(4, 0, 1), "s", _noteCall(0, "again"));
        // unknown release
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ReleaseUnknown.selector, 4, 0, 9));
        f.createInstance(_id(4, 0, 9), "u", _noteCall(0, ""));
    }

    /// A creation nested inside an `initialize` is appended first; both records and both creators right (the nested one's
    /// is the outer clone).
    function test_generic_nestedCreation() public {
        _publish(4, 0, 1);
        _note(1);
        vm.prank(registrar);
        f.deployRelease(_id(4, 0, 16), 1, INoteKind.initialize.selector, type(INoteKind).interfaceId,
            type(BadKind).creationCode, abi.encode(uint8(16)));
        vm.warp(block.timestamp + NOTICE);
        _enable(4, 0, true);
        vm.prank(alice);
        address outer = f.createInstance(_id(4, 0, 16), "outer", _noteCall(nid(alice), "outer"));
        (IOpenFactory.Created[] memory p, uint256 n) = f.contractsPage(4, 0, 10);
        assertEq(n, 2);
        assertEq(p[1].addr, outer);
        assertEq(p[0].creatorId, nid(outer), "the nested creator: the outer clone");
        assertEq(p[1].creatorId, nid(alice));
        assertEq(NoteKind(p[0].addr).seenCreator(), nid(outer));
        assertEq(BadKind(outer).seenCreator(), nid(alice));
        assertEq(BadKind(outer).seenAfter(), nid(alice), "creating() restored after the nested creation");
        assertEq(f.creating(), bytes32(0));
    }

    function test_generic_registrarOnly() public {
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.publishClassEnv(4, 0, 1, _env());
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.deployRelease(_id(4, 0, 1), 1, INoteKind.initialize.selector, type(INoteKind).interfaceId, "", "");
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.deprecateRelease(_id(4, 0, 1), "x");
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.setClassKindEnabled(4, 0, true);
        vm.etch(registrar, abi.encodePacked(hex"ef0100", address(0x5EE9)));
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(SigCheck.CallerDelegated.selector, registrar));
        f.publishClassEnv(4, 0, 1, _env());
        vm.etch(registrar, "");
        _publish(4, 0, 1); // positive control
    }

    /// The enabled switch is the reversible stop of every version of a kind; on again, creation resumes.
    function test_generic_disabledKindStopsEveryVersion() public {
        _publish(4, 0, 1);
        _note(1);
        _note(2);
        vm.warp(block.timestamp + NOTICE);
        assertFalse(f.classKindEnabled(4, 0), "a new (class, kind) starts off (Q7)");
        _enable(4, 0, true);
        f.createInstance(_id(4, 0, 1), "1", _noteCall(0, ""));
        _enable(4, 0, false);
        for (uint64 v = 1; v <= 2; ++v) {
            vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassKindDisabled.selector, 4, 0));
            f.createInstance(_id(4, 0, v), bytes32(uint256(v + 10)), _noteCall(0, ""));
        }
        _enable(4, 0, true);
        f.createInstance(_id(4, 0, 2), "2", _noteCall(0, ""));
    }

    /// The index views know a generic class once it has a release (spec §2.2, §8.1).
    function test_generic_classUnknownUntilARelease() public {
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassUnknown.selector, 4));
        f.contractsPage(4, 0, 1);
        _publish(4, 0, 1);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ClassUnknown.selector, 4));
        f.contractsPage(4, 0, 1); // an env alone is no class
        _note(1);
        (, uint256 n) = f.contractsPage(4, 0, 1);
        assertEq(n, 0);
    }

    /// Slots (spec §3, §8.9): a generic creation writes the index's +5 steady / +7 first, as a token's.
    function test_generic_slotCount() public {
        _publish(4, 0, 1);
        _note(1);
        vm.warp(block.timestamp + NOTICE);
        _enable(4, 0, true);
        f.createInstance(_id(4, 0, 1), "seed", _noteCall(nid(alice), "")); // the creator, owner and class lists exist
        vm.startStateDiffRecording();
        f.createInstance(_id(4, 0, 1), "steady", _noteCall(nid(alice), ""));
        assertEq(_newSlots(address(f)), 6, "record 3, three elements");
        vm.startStateDiffRecording();
        vm.prank(relayer);
        f.createInstance(_id(4, 0, 1), "first", _noteCall(nid(address(0x0A)), ""));
        assertEq(_newSlots(address(f)), 8, "record 3, three elements, two first list lengths");
    }

    function _newSlots(address who) internal returns (uint256 m) {
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        bytes32[] memory seen = new bytes32[](64);
        for (uint256 i; i < acc.length; ++i) {
            for (uint256 j; j < acc[i].storageAccesses.length; ++j) {
                VmSafe.StorageAccess memory s = acc[i].storageAccesses[j];
                if (s.account != who || !s.isWrite || s.reverted || s.previousValue != 0 || s.newValue == 0) continue;
                bool dup;
                for (uint256 k; k < m; ++k) if (seen[k] == s.slot) dup = true;
                if (!dup) seen[m++] = s.slot;
            }
        }
    }

    /// The token and DEX paths are untouched by the generic block (their tests: FactoryIndex, Factory, Dex).
    function test_generic_tokenAndDexUntouched() public {
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        vm.warp(block.timestamp + NOTICE);
        address t = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(normalInit("N", "N", 0, 1, alice, address(0))),
            "t");
        assertEq(f.infoOf(t).contractClass, 1);
        assertEq(f.creating(), bytes32(0));
    }
}
