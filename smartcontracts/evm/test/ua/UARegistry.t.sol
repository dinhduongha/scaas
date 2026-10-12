// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {SaltedEIP712} from "../../src/common/SaltedEIP712.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryBase, MockVerifier, MockWallet, MockPredecessor} from "./UARegistryBase.sol";

/// accounts.md §1.16 T-REG / T-AUTH / T-CHAIN / T-MEMBER for the UA-2a registry, with stand-in verifiers (the real ones
/// are the verifier tasks' own tests; `UARegistryVectors.t.sol` runs the registry on signatures.json).
contract UARegistryTest is UARegistryBase {
    uint256 internal constant PK_A = 0xA11CE;
    uint256 internal constant PK_B = 0xB0B;

    // ----- surface, vectors of the identity layer -----

    function test_surface() public view {
        assertEq(reg.generation(), 1);
        assertEq(reg.predecessor(), address(0));
        assertEq(reg.chainUid(), chainUidA);
        assertEq(reg.verifyBudget(), BUDGET);
        assertFalse(reg.hederaNative());
        for (uint256 i; i < KINDS.length; ++i) {
            assertTrue(reg.kindEnabled(KINDS[i]));
            assertEq(reg.verifyCap(KINDS[i]), _cap(KINDS[i]));
        }
        assertTrue(reg.kindEnabled(UAKinds.MSIG));
        assertEq(reg.verifyCap(UAKinds.MSIG), BUDGET);
        uint16[12] memory off =
            [0x0001, 0x0002, 0x0003, 0x0102, 0x0110, 0x0111, 0x0112, 0x0113, 0x0130, 0x0133, 0x0140, 0x0142];
        for (uint256 i; i < off.length; ++i) {
            assertFalse(reg.kindEnabled(off[i]));
            assertEq(reg.verifyCap(off[i]), 0);
        }
        assertEq(reg.chainKeyHash(), UAKinds.chainKeyHash(31337));
    }

    function test_vectorsContextA() public view {
        string memory s = _structures();
        // popDigest, the UAAuth digest (gen 1) and the member digest of structures.json, context A
        bytes32 ua = vm.parseJsonBytes32(s, ".pop[0].ua");
        assertEq(reg.popDigest(ua, 0), vm.parseJsonBytes32(s, ".pop[0].popDigest"));
        bytes32 nua = vm.parseJsonBytes32(s, ".uaAuth[0].ua");
        assertEq(
            reg.uaAuthDigest(
                nua, vm.parseJsonBytes32(s, ".uaAuth[0].purposeTag"), vm.parseJsonBytes32(s, ".uaAuth[0].digest")
            ),
            vm.parseJsonBytes32(s, ".uaAuth[0].uaAuthDigest")
        );
        assertEq(
            UAKinds.memberDigest(
                vm.parseJsonBytes32(s, ".member[0].structureUa"), vm.parseJsonBytes32(s, ".member[0].uaMsg")
            ),
            vm.parseJsonBytes32(s, ".member[0].memberDigest")
        );
        string memory j = _kindsJson();
        for (uint256 i; i < KINDS.length; ++i) {
            bytes memory k = _key(KINDS[i]);
            string memory row = string.concat(".valid[", vm.toString(KINDS[i] - 0x0100), "]");
            assertEq(reg.uaOf(KINDS[i], k), vm.parseJsonBytes32(j, string.concat(row, ".ua")));
            assertEq(reg.keyHashOf(KINDS[i], k), vm.parseJsonBytes32(j, string.concat(row, ".keyHash")));
        }
    }

    // ----- T-REG -----

    function test_T_REG_1_registerEveryKind() public {
        for (uint256 i; i < KINDS.length; ++i) {
            uint16 kind = KINDS[i];
            bytes memory k = _key(kind);
            bytes32 ua = reg.uaOf(kind, k);
            vm.warp(1000 + i);
            vm.expectEmit(true, true, false, true, address(reg));
            emit IUARegistry.UARegistered(ua, kind, k, 0);
            assertEq(_register(reg, kind, k), ua);
            (IUARegistry.Record memory r, bytes32 authRef) = reg.recordOf(ua);
            assertEq(r.kind, kind);
            assertEq(r.registeredAt, 1000 + i);
            assertEq(r.keyPtr, address(0));
            assertEq(authRef, 0);
            assertEq(reg.kindOf(ua), kind);
            assertTrue(reg.isRegistered(ua));
            assertEq(reg.keyOwner(reg.keyHashOf(kind, k)), ua);
        }
        // the structure: no PoP, no keyOwner
        (bytes memory d, bytes32 ua2) = _registerMsig();
        assertEq(reg.kindOf(ua2), UAKinds.MSIG);
        assertEq(reg.keyHashOf(UAKinds.MSIG, d), 0);
    }

    /// kinds.json `invalid` rows of every kind this registry enables (msig members unregistered: the layout fails first).
    function test_T_REG_2_negativeKeyData() public {
        string memory j = _kindsJson();
        uint256 n;
        for (uint256 i; vm.keyExistsJson(j, string.concat(".invalid[", vm.toString(i), "]")); ++i) {
            string memory row = string.concat(".invalid[", vm.toString(i), "]");
            uint16 kind = uint16(vm.parseJsonUint(j, string.concat(row, ".kind")));
            if (!reg.kindEnabled(kind) || vm.parseJsonBool(j, string.concat(row, ".hederaNative"))) continue;
            bytes memory k = vm.parseJsonBytes(j, string.concat(row, ".keyData"));
            string memory reason = vm.parseJsonString(j, string.concat(row, ".reason"));
            // T-MEMBER: a hedera-native member outside a Hedera profile is UAMemberUnknown (§1.8), not UAKeyData.
            if (keccak256(bytes(reason)) == keccak256("hedera-native outside a Hedera profile")) {
                vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, _firstMemberId(k)));
            } else {
                vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, kind));
            }
            reg.register(kind, k, "", 0, "");
            ++n;
        }
        assertGt(n, 50);
    }

    function test_T_REG_2_negativeRegistry() public {
        // disabled kinds: natives, out-of-scope kinds, unknown
        uint16[9] memory off = [0x0001, 0x0003, 0x0102, 0x0110, 0x0113, 0x0131, 0x0140, 0x0142, 0x0121];
        for (uint256 i; i < off.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, off[i]));
            reg.register(off[i], hex"00", "", 0, "");
        }
        bytes memory p = _key(0x0101);
        bytes32 ua = reg.uaOf(0x0101, p);
        // wrong-tag PoP, PoP for another authRef, a PoP over the metatx purpose
        bytes memory wrongTag = _sig(p, reg.uaMessage(0x0100, UAKinds.PURPOSE_POP, reg.popDigest(ua, 0)));
        bytes memory otherAuthRef =
            _sig(p, reg.uaMessage(0x0101, UAKinds.PURPOSE_POP, reg.popDigest(ua, bytes32(uint256(1)))));
        bytes memory metatx = _sig(p, reg.uaMessage(0x0101, UAKinds.PURPOSE_METATX, reg.popDigest(ua, 0)));
        bytes[4] memory bad = [wrongTag, otherAuthRef, metatx, bytes("")];
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(IUARegistry.UAPoP.selector);
            reg.register(0x0101, p, bad[i], 0, "");
        }
        _register(reg, 0x0101, p);
        _registerReverts(reg, 0x0101, p, abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, ua));
        // the same point under the other p256-group kind (kinds.json valid[22]: p256 key ‖ rpIdHash)
        bytes memory w = vm.parseJsonBytes(_kindsJson(), ".valid[22].keyData");
        bytes32 kh = reg.keyHashOf(0x0100, w);
        assertEq(kh, reg.keyHashOf(0x0101, p));
        _registerReverts(reg, 0x0100, w, abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, kh, ua));
        // msig: a pop is refused (structures have none)
        (bytes memory d,) = _msigMembers();
        vm.expectRevert(IUARegistry.UAPoP.selector);
        reg.register(UAKinds.MSIG, d, hex"01", 0, "");
    }

    /// Anyone may relay: two senders, one calldata ⇒ the same writes with the same values.
    function test_T_REG_3_senderIndependent() public {
        bytes memory k = _key(0x0104);
        bytes memory pop = _pop(reg, 0x0104, k);
        uint256 snap = vm.snapshotState();
        bytes32[] memory w1 = _writes(address(0xA), k, pop);
        bytes32[] memory v1 = _values(w1);
        vm.revertToState(snap);
        bytes32[] memory w2 = _writes(address(0xB), k, pop);
        assertEq(w1, w2);
        assertEq(v1, _values(w2));
    }

    function test_T_REG_3b_authRef() public {
        bytes memory k = _key(0x0103);
        bytes memory pop = _pop(reg, 0x0103, k);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAuthRef.selector, bytes32(uint256(7))));
        reg.register(0x0103, k, pop, bytes32(uint256(7)), "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAuthRef.selector, bytes32(0)));
        reg.register(0x0103, k, pop, 0, hex"00");
        (bytes memory d,) = _msigMembers();
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAuthRef.selector, bytes32(uint256(7))));
        reg.register(UAKinds.MSIG, d, "", bytes32(uint256(7)), "");
    }

    /// Gen 2 may not enable a kind or keyHash group gen 1 enables, nor follow a registry of another chain or profile.
    function test_T_REG_4_gen2Constructor() public {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        for (uint256 i; i < KINDS.length; ++i) {
            c[0] = UARegistry.KindConfig(KINDS[i], address(mock), 50_000);
            vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, KINDS[i]));
            new UARegistry(chainUidA, address(reg), false, BUDGET, address(0), true, c);
        }
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0)));
        new UARegistry(
            bytes32(uint256(1)), address(reg), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0)
        );
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0)));
        new UARegistry(chainUidA, address(reg), true, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        UARegistry gen2 = _gen2();
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0))); // no gen 3
        new UARegistry(chainUidA, address(gen2), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        assertEq(gen2.generation(), 2);
        assertEq(gen2.predecessor(), address(reg));
        (,, string memory version,,,,) = gen2.eip712Domain();
        assertEq(version, "2");
    }

    /// Gen 2 sees gen-1 records, refuses gen-1 kinds and ids, and hands gen-1 records to gen 1 for verification.
    function test_T_REG_4_gen2SeesGen1() public {
        bytes memory p = _key(0x0101);
        bytes32 p256Ua = _register(reg, 0x0101, p);
        (bytes memory d1, bytes32 msig1) = _registerMsig();
        UARegistry gen2 = _gen2();
        assertEq(gen2.kindOf(p256Ua), 0x0101);
        assertTrue(gen2.isRegistered(msig1));
        assertEq(gen2.keyOwner(reg.keyHashOf(0x0101, p)), p256Ua);
        (IUARegistry.Record memory r,) = gen2.recordOf(p256Ua);
        assertEq(r.kind, 0x0101);
        _registerReverts(gen2, 0x0101, p, abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, uint16(0x0101)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, msig1));
        gen2.register(UAKinds.MSIG, d1, "", 0, "");
        gen2.requireAuthorized(
            p256Ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(reg, 0x0101, p, UAKinds.PURPOSE_METATX, DIGEST)
        );
        _expectUnauthorizedOn(
            gen2, p256Ua, UAKinds.PURPOSE_KEYOP, DIGEST, _auth(reg, 0x0101, p, UAKinds.PURPOSE_METATX, DIGEST)
        );
    }

    /// A gen-2 msig over a gen-1 p256 member and a gen-2 ed25519 member; gen 1 cannot register it.
    function test_T_REG_4_gen2Msig() public {
        bytes memory p = _key(0x0101);
        bytes32 p256Ua = _register(reg, 0x0101, p);
        UARegistry gen2 = _gen2();
        bytes memory ed = _key(0x0102);
        bytes32 edUa = _register(gen2, 0x0102, ed);
        Member[] memory m = new Member[](2);
        m[0] = Member(0x0101, p256Ua, 1);
        m[1] = Member(0x0102, edUa, 1);
        bytes memory d2 = _msigKey(2, m);
        bytes32 msig2 = gen2.register(UAKinds.MSIG, d2, "", 0, "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, edUa));
        reg.register(UAKinds.MSIG, d2, "", 0, ""); // gen 1 does not know the gen-2 member
        bytes32 md = _memberDigest(msig2, UAKinds.PURPOSE_METATX, DIGEST);
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](2);
        uint16 ip = _indexOf(d2, p256Ua);
        uint16 ie = _indexOf(d2, edUa);
        s[ip] = UARegistry.MemberSig(ip, p, _sig(p, UAKinds.uaMessage(0x0101, UAKinds.PURPOSE_MEMBER, md)));
        s[ie] = UARegistry.MemberSig(ie, ed, _sig(ed, UAKinds.uaMessage(0x0102, UAKinds.PURPOSE_MEMBER, md)));
        gen2.requireAuthorized(msig2, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d2, s));
        s[ip].sig = _sig(p, UAKinds.uaMessage(0x0101, UAKinds.PURPOSE_METATX, md));
        _expectUnauthorizedOn(gen2, msig2, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d2, s));
    }

    /// msig re-enabled in gen 2: the same id registered in both generations is the same record.
    function test_T_REG_4_msigBothGenerations() public {
        UARegistry gen2 = _gen2();
        Member[] memory m = new Member[](1);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(PK_B)), 1);
        bytes memory d = _msigKey(1, m);
        bytes32 id = gen2.register(UAKinds.MSIG, d, "", 0, "");
        assertEq(reg.register(UAKinds.MSIG, d, "", 0, ""), id);
        (IUARegistry.Record memory ra,) = reg.recordOf(id);
        (IUARegistry.Record memory rb,) = gen2.recordOf(id);
        assertEq(abi.encode(ra), abi.encode(rb));
    }

    /// gen 2 = ed25519 (a group gen 1 does not enable) + msig.
    function _gen2() internal returns (UARegistry) {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0102, address(mock), 50_000);
        return _deploy(address(0x5ca2), chainUidA, address(reg), false, BUDGET, address(0), true, c);
    }

    /// The code path of `UAKeyInUse` across generations (a real gen 1 cannot reach it once gen 2's group rule holds).
    function test_T_REG_4_keyInUseAcrossGenerations() public {
        bytes memory p = _key(0x0101);
        bytes32 kh = UAKinds.keyHashOf(0x0101, p);
        MockPredecessor pred = new MockPredecessor(chainUidA, kh, bytes32(uint256(0xdead) << 200));
        UARegistry gen2 =
            _deploy(address(0x5ca3), chainUidA, address(pred), false, BUDGET, address(0), false, _cfgs(address(mock)));
        _registerReverts(
            gen2,
            0x0101,
            p,
            abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, kh, bytes32(uint256(0xdead) << 200))
        );
    }

    /// Invariants: no value, records never change, `uaOf(keyData) == ua`.
    function test_T_REG_5_invariants() public {
        bytes32[] memory uas = new bytes32[](KINDS.length);
        for (uint256 i; i < KINDS.length; ++i) {
            uas[i] = _register(reg, KINDS[i], _key(KINDS[i]));
            assertEq(uas[i], UAKinds.uaOf(KINDS[i], _key(KINDS[i])));
        }
        vm.warp(block.timestamp + 1 days);
        for (uint256 i; i < KINDS.length; ++i) {
            (IUARegistry.Record memory before,) = reg.recordOf(uas[i]);
            _registerReverts(
                reg, KINDS[i], _key(KINDS[i]), abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, uas[i])
            );
            (IUARegistry.Record memory after_,) = reg.recordOf(uas[i]);
            assertEq(abi.encode(before), abi.encode(after_));
        }
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(reg).call{value: 1}("");
        assertFalse(ok);
        (ok,) = address(reg).call{value: 1}(abi.encodeCall(reg.register, (0x0101, hex"", hex"", 0, hex"")));
        assertFalse(ok);
        assertEq(address(reg).balance, 0);
    }

    // ----- T-AUTH -----

    function test_T_AUTH_1_kindsByPurpose() public {
        bytes32[4] memory purposes =
            [UAKinds.PURPOSE_METATX, UAKinds.PURPOSE_METATX_CANCEL, UAKinds.PURPOSE_KEYOP, UAKinds.PURPOSE_RECEIVER_FEE];
        for (uint256 i; i < KINDS.length; ++i) {
            bytes32 ua = _register(reg, KINDS[i], _key(KINDS[i]));
            for (uint256 p; p < purposes.length; ++p) {
                _kindPurpose(
                    ua, KINDS[i], KINDS[(i + 1) % KINDS.length], purposes[p], purposes[(p + 1) % purposes.length]
                );
            }
        }
        // unregistered derived id
        bytes memory e = _key(0x0102);
        _expectUnauthorized(
            UAKinds.uaOf(0x0102, e),
            UAKinds.PURPOSE_METATX,
            DIGEST,
            _auth(reg, 0x0102, e, UAKinds.PURPOSE_METATX, DIGEST)
        );
    }

    /// Passes for (kind, purpose); fails for a wrong purpose, a wrong kind's tag, another digest, other key data.
    function _kindPurpose(bytes32 ua, uint16 kind, uint16 otherKind, bytes32 purpose, bytes32 other) internal {
        bytes memory k = _key(kind);
        reg.requireAuthorized(ua, purpose, DIGEST, _auth(reg, kind, k, purpose, DIGEST));
        _expectUnauthorized(ua, purpose, DIGEST, _auth(reg, kind, k, other, DIGEST));
        _expectUnauthorized(ua, purpose, DIGEST, abi.encode(k, _sig(k, reg.uaMessage(otherKind, purpose, DIGEST))));
        _expectUnauthorized(ua, purpose, DIGEST, _auth(reg, kind, k, purpose, bytes32(0)));
        _expectUnauthorized(ua, purpose, DIGEST, _auth(reg, kind, _key(otherKind), purpose, DIGEST));
    }

    /// A Zether UA (it cannot even be registered by this generation) is never authorized.
    function test_T_AUTH_1b_zether() public {
        bytes memory y = vm.parseJsonBytes(_kindsJson(), ".valid[16].keyData");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, uint16(0x0140)));
        reg.register(0x0140, y, "", 0, "");
        bytes32 ua = UAKinds.uaOf(0x0140, y);
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(reg, 0x0140, y, UAKinds.PURPOSE_METATX, DIGEST));
    }

    function test_T_AUTH_2_msig() public {
        (bytes memory d, bytes32 ua, Fixture memory f) = _msigRegistered();
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        // threshold 3: native (1) + schnorr (2) at threshold; p256 (1) + bls (1) + native (1)
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, _sigs(d, f, md, 0x9))); // native, schnorr
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, _sigs(d, f, md, 0x7))); // native, p256, bls
        // below the threshold
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, _sigs(d, f, md, 0x3)));
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, _sigs(d, f, md, 0x8)));
        // a MemberSig after the threshold
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, _sigs(d, f, md, 0xf)));
        // unsorted, duplicate index, out-of-range index
        UARegistry.MemberSig[] memory s = _sigs(d, f, md, 0x9);
        (s[0], s[1]) = (s[1], s[0]);
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        s = _sigs(d, f, md, 0x9);
        s[1] = s[0];
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        s[1].index = 4;
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        // member signatures for another purpose / another structure's digest / a wrong member key
        _expectUnauthorized(ua, UAKinds.PURPOSE_KEYOP, DIGEST, _msigAuth(d, _sigs(d, f, md, 0x9)));
        s = _sigs(d, f, _memberDigest(bytes32(uint256(1) << 200), UAKinds.PURPOSE_METATX, DIGEST), 0x9);
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        s = _sigs(d, f, md, 0x7);
        s[1].keyData = _key(0x0100);
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        // a native member's MemberSig carries no key data
        s = _sigs(d, f, md, 0x9);
        for (uint256 i; i < s.length; ++i) {
            if (s[i].keyData.length == 0) s[i].keyData = hex"01";
        }
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        // the key data in auth must be the structure's
        bytes memory d2 = bytes.concat(d);
        d2[1] = 0x02;
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d2, _sigs(d, f, md, 0x9)));
    }

    /// Native contract members: an ERC-1271 wallet (`evm-contract`) and a 7702-delegated EOA signing through its
    /// delegate's 1271 (`evm-eoa`), both over `UAAuth(memberId, member, member_digest)`.
    function test_T_AUTH_2_msigContractMembers() public {
        address session = vm.addr(PK_B);
        MockWallet wallet = new MockWallet(session, 0, 0, address(0));
        MockWallet delegate = new MockWallet(session, 0, 0, address(0));
        address eoa = vm.addr(PK_A);
        vm.signAndAttachDelegation(address(delegate), PK_A);
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_CONTRACT, _pad(address(wallet)), 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(eoa), 1);
        bytes memory d = _msigKey(2, m);
        bytes32 ua = reg.register(UAKinds.MSIG, d, "", 0, ""); // the delegation lands with this call
        assertEq(eoa.code.length, 23);
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](2);
        for (uint256 i; i < 2; ++i) {
            bytes32 id = m[i].id;
            uint16 idx = _indexOf(d, id);
            s[idx] = UARegistry.MemberSig(idx, "", _ecdsa(PK_B, reg.uaAuthDigest(id, UAKinds.PURPOSE_MEMBER, md)));
        }
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        // a member signature under the structure's own purpose instead of `member` fails
        uint16 w = _indexOf(d, _pad(address(wallet)));
        s[w].sig = _ecdsa(PK_B, reg.uaAuthDigest(_pad(address(wallet)), UAKinds.PURPOSE_METATX, md));
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
    }

    function test_T_AUTH_2_msigRegistration() public {
        bytes32 p256Ua = _register(reg, 0x0101, _key(0x0101));
        bytes32 eoa = _pad(vm.addr(PK_A));
        Member[] memory m = new Member[](2);
        // unregistered member
        m[0] = Member(UAKinds.EVM_EOA, eoa, 1);
        m[1] = Member(0x0103, UAKinds.uaOf(0x0103, _key(0x0103)), 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, m[1].id));
        reg.register(UAKinds.MSIG, _msigKey(2, m), "", 0, "");
        // registered under another kind than stated
        m[1] = Member(0x0100, p256Ua, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, p256Ua));
        reg.register(UAKinds.MSIG, _msigKey(2, m), "", 0, "");
        // nested structure, Zether member: refused by the layout (UAKinds, kinds.json) — UAKeyData
        (, bytes32 inner) = _registerMsig();
        m[1] = Member(UAKinds.MSIG, inner, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(2, m), "", 0, "");
        m[1] = Member(0x0140, bytes32(uint256(1) << 200), 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(2, m), "", 0, "");
        // duplicate member, threshold 0, threshold > weight
        m[1] = Member(UAKinds.EVM_EOA, eoa, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(1, m), "", 0, "");
        m[1] = Member(0x0101, p256Ua, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(0, m), "", 0, "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(3, m), "", 0, "");
    }

    /// Addendum (UA-1 carry-over): `ecrecover` → address(0) never satisfies native id 0 (ua 0, or an msig member 0).
    function test_T_AUTH_3_zeroAddressNeverSigns() public {
        bytes memory garbage = abi.encodePacked(bytes32(0), bytes32(uint256(1)), uint8(27)); // ecrecover ⇒ 0
        bytes memory garbage2 = abi.encodePacked(bytes32(uint256(5)), bytes32(uint256(7)), uint8(29)); // bad v
        _expectUnauthorized(0, UAKinds.PURPOSE_METATX, DIGEST, garbage);
        _expectUnauthorized(0, UAKinds.PURPOSE_METATX, DIGEST, garbage2);
        _expectUnauthorized(0, UAKinds.PURPOSE_METATX, DIGEST, "");
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, bytes32(0), 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(vm.addr(PK_A)), 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = reg.register(UAKinds.MSIG, d, "", 0, "");
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](1);
        s[0] = UARegistry.MemberSig(0, "", garbage);
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        s[0].sig = garbage2;
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        s[0] = UARegistry.MemberSig(1, "", _nativeSig(reg, PK_A, UAKinds.PURPOSE_MEMBER, md));
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
    }

    function test_T_AUTH_3_nativeEoa() public {
        bytes32 ua = _pad(vm.addr(PK_A));
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _nativeSig(reg, PK_A, UAKinds.PURPOSE_METATX, DIGEST));
        // raw digest, other purpose, other signer, high s
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_A, DIGEST));
        _expectUnauthorized(ua, UAKinds.PURPOSE_KEYOP, DIGEST, _nativeSig(reg, PK_A, UAKinds.PURPOSE_METATX, DIGEST));
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _nativeSig(reg, PK_B, UAKinds.PURPOSE_METATX, DIGEST));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK_A, reg.uaAuthDigest(ua, UAKinds.PURPOSE_METATX, DIGEST));
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes memory high = abi.encodePacked(r, bytes32(n - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, high);
    }

    function test_T_AUTH_3_native1271() public {
        address owner = vm.addr(PK_B);
        MockWallet ok = new MockWallet(owner, 0, 0, address(reg));
        bytes32 ua = _pad(address(ok));
        bytes memory sig = _ecdsa(PK_B, reg.uaAuthDigest(ua, UAKinds.PURPOSE_METATX, DIGEST));
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, sig);
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, DIGEST));
        // wrong magic, revert, out of gas, over the 50 k cap
        for (uint8 mode = 1; mode <= 3; ++mode) {
            MockWallet w = new MockWallet(owner, mode, 0, address(reg));
            _expectUnauthorized(_pad(address(w)), UAKinds.PURPOSE_METATX, DIGEST, sig);
        }
        MockWallet heavy = new MockWallet(owner, 0, 60_000, address(reg));
        bytes32 hua = _pad(address(heavy));
        _expectUnauthorized(
            hua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, reg.uaAuthDigest(hua, UAKinds.PURPOSE_METATX, DIGEST))
        );
        // ERC-7739-style: the wallet rebuilds the hash from eip712Domain() (salt = chainUid)
        MockWallet w7739 = new MockWallet(owner, 4, 0, address(reg));
        bytes32 wua = _pad(address(w7739));
        bytes memory inner = _ecdsa(PK_B, reg.uaAuthDigest(wua, UAKinds.PURPOSE_METATX, DIGEST));
        reg.requireAuthorized(wua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(UAKinds.PURPOSE_METATX, DIGEST, inner));
        _expectUnauthorized(wua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(UAKinds.PURPOSE_KEYOP, DIGEST, inner));
    }

    /// 400 k for `SmartKeyAccount` clones (by the immutable clone codehash), 50 k for the same code elsewhere.
    function test_T_AUTH_3_smartKeyCloneCap() public {
        address owner = vm.addr(PK_B);
        MockWallet impl = new MockWallet(owner, 0, 200_000, address(0));
        UARegistry r =
            _deploy(address(0x5ca4), chainUidA, address(0), false, BUDGET, address(impl), true, _cfgs(address(mock)));
        address clone = Clones.clone(address(impl));
        bytes32 cua = _pad(clone);
        r.requireAuthorized(
            cua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, r.uaAuthDigest(cua, UAKinds.PURPOSE_METATX, DIGEST))
        );
        MockWallet same = new MockWallet(owner, 0, 200_000, address(0));
        bytes32 sua = _pad(address(same));
        bytes memory sig = _ecdsa(PK_B, r.uaAuthDigest(sua, UAKinds.PURPOSE_METATX, DIGEST));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, sua));
        r.requireAuthorized(sua, UAKinds.PURPOSE_METATX, DIGEST, sig);
        // a clone of the implementation on a registry without the codehash: 50 k
        _expectUnauthorized(
            cua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, reg.uaAuthDigest(cua, UAKinds.PURPOSE_METATX, DIGEST))
        );
    }

    /// CTR-UA-24: a 7702-delegated EOA signs with its base key, or through the delegate's 1271 within 50 k.
    function test_T_AUTH_3_eip7702() public {
        address eoa = vm.addr(PK_A);
        bytes32 ua = _pad(eoa);
        address session = vm.addr(PK_B);
        MockWallet delegate = new MockWallet(session, 0, 0, address(0));
        bytes32 h = reg.uaAuthDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        vm.signAndAttachDelegation(address(delegate), PK_A);
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_A, h)); // base key
        assertEq(eoa.code.length, 23);
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, h)); // delegate's 1271
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_A, DIGEST));
        // delegates: none (no 1271), wrong magic, reverting, out of gas, over 50 k
        address[5] memory bad = [
            address(new MockVerifier(0, 0)),
            address(new MockWallet(session, 1, 0, address(0))),
            address(new MockWallet(session, 2, 0, address(0))),
            address(new MockWallet(session, 3, 0, address(0))),
            address(new MockWallet(session, 0, 60_000, address(0)))
        ];
        for (uint256 i; i < bad.length; ++i) {
            vm.signAndAttachDelegation(bad[i], PK_A);
            _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, h));
            reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_A, h)); // the base key stays root
        }
        // 23 bytes of code that are not a designator: a contract (1271 only, here always "invalid")
        address fake = vm.addr(PK_B);
        vm.etch(fake, abi.encodePacked(hex"63ffffffff60e01b60005260206000f3", bytes7(0)));
        assertEq(fake.code.length, 23);
        _expectUnauthorized(
            _pad(fake), UAKinds.PURPOSE_METATX, DIGEST, _nativeSig(reg, PK_B, UAKinds.PURPOSE_METATX, DIGEST)
        );
    }

    /// Every capped call fails closed: revert, short/long/wrong returndata, out of gas ⇒ UAUnauthorized; a caller
    /// that cannot hand over the full cap ⇒ UAVerifyGas, never a pass.
    function test_T_AUTH_4_failClosed() public {
        bytes memory k = _key(0x0103);
        bytes32 ua = UAKinds.uaOf(0x0103, k);
        for (uint8 mode = 1; mode <= 5; ++mode) {
            MockVerifier v = new MockVerifier(mode, 0);
            UARegistry r = _deploy(
                address(uint160(0x5cb0 + mode)),
                chainUidA,
                address(0),
                false,
                BUDGET,
                address(0),
                false,
                _cfgs(address(v))
            );
            _registerReverts(r, 0x0103, k, abi.encodePacked(IUARegistry.UAPoP.selector));
            // a record made with a good verifier at the same address, then the bad verifier swapped in
            vm.etch(address(v), address(mock).code);
            _register(r, 0x0103, k);
            vm.etch(address(v), address(new MockVerifier(mode, 0)).code);
            _expectUnauthorizedOn(
                r, ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(r, 0x0103, k, UAKinds.PURPOSE_METATX, DIGEST)
            );
        }
    }

    function test_T_AUTH_4_starvation() public {
        MockVerifier slow = new MockVerifier(0, 40_000); // valid answers after 40 k gas; cap 50 k
        UARegistry r =
            _deploy(address(0x5cc0), chainUidA, address(0), false, BUDGET, address(0), false, _cfgs(address(slow)));
        bytes memory k = _key(0x0103);
        bytes32 ua = _register(r, 0x0103, k);
        bytes memory good = abi.encodeCall(
            r.requireAuthorized,
            (ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(r, 0x0103, k, UAKinds.PURPOSE_METATX, DIGEST))
        );
        bytes memory bad = abi.encodeCall(
            r.requireAuthorized,
            (ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(r, 0x0103, k, UAKinds.PURPOSE_KEYOP, DIGEST))
        );
        bool sawGasError;
        for (uint256 g = 10_000; g < 150_000; g += 1_000) {
            (bool okBad,) = address(r).staticcall{gas: g}(bad);
            assertFalse(okBad);
            (bool ok, bytes memory ret) = address(r).staticcall{gas: g}(good);
            if (!ok && ret.length == 4 && bytes4(ret) == UAKinds.UAVerifyGas.selector) sawGasError = true;
            if (!ok) assertTrue(ret.length == 0 || bytes4(ret) == UAKinds.UAVerifyGas.selector); // never UAUnauthorized
            if (ok) assertGe(g, 50_000);
        }
        assertTrue(sawGasError);
        // the same for an ERC-1271 wallet (cap 50 k)
        MockWallet w = new MockWallet(vm.addr(PK_B), 0, 40_000, address(0));
        bytes32 wua = _pad(address(w));
        bytes memory wsig = _ecdsa(PK_B, r.uaAuthDigest(wua, UAKinds.PURPOSE_METATX, DIGEST));
        (bool ok2, bytes memory ret2) = address(r).staticcall{gas: 45_000}(
            abi.encodeCall(r.requireAuthorized, (wua, UAKinds.PURPOSE_METATX, DIGEST, wsig))
        );
        assertFalse(ok2);
        assertEq(bytes4(ret2), UAKinds.UAVerifyGas.selector);
        r.requireAuthorized(wua, UAKinds.PURPOSE_METATX, DIGEST, wsig);
    }

    // ----- T-CHAIN, T-MEMBER -----

    /// Contexts B and C of structures.json: chain 7622 twice, same registry address, different chainUid.
    function test_T_CHAIN() public {
        string memory s = _structures();
        bytes32 uidB = vm.parseJsonBytes32(s, ".contexts.B.chainUid");
        bytes32 uidC = vm.parseJsonBytes32(s, ".contexts.C.chainUid");
        vm.chainId(7622);
        bytes memory k = _key(0x0104);
        UARegistry rC = _deploy(REG_A, uidC, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
        bytes memory popC = _pop(rC, 0x0104, k);
        bytes32 ua = UAKinds.uaOf(0x0104, k);
        bytes32 nua = _pad(vm.addr(PK_A));
        bytes memory uaAuthC = _nativeSig(rC, PK_A, UAKinds.PURPOSE_MEMBER, DIGEST);
        _assertVectors(rC, 2, 3);
        UARegistry rB = _deploy(REG_A, uidB, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
        _assertVectors(rB, 1, 2);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        rB.register(0x0104, k, popC, 0, "");
        _expectUnauthorizedOn(rB, nua, UAKinds.PURPOSE_MEMBER, DIGEST, uaAuthC);
        rB.register(0x0104, k, _pop(rB, 0x0104, k), 0, "");
        rB.requireAuthorized(nua, UAKinds.PURPOSE_MEMBER, DIGEST, _nativeSig(rB, PK_A, UAKinds.PURPOSE_MEMBER, DIGEST));
        assertEq(rB.kindOf(ua), 0x0104);
        _assertDomain(rB, uidB);
        // chainUid 0 refused
        vm.expectRevert(SaltedEIP712.ChainUidZero.selector);
        new UARegistry(0, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
    }

    function _assertVectors(UARegistry r, uint256 popRow, uint256 authRow) internal view {
        string memory s = _structures();
        string memory a = string.concat(".uaAuth[", vm.toString(authRow), "]");
        string memory p = string.concat(".pop[", vm.toString(popRow), "]");
        assertEq(
            r.popDigest(vm.parseJsonBytes32(s, string.concat(p, ".ua")), 0),
            vm.parseJsonBytes32(s, string.concat(p, ".popDigest"))
        );
        assertEq(
            r.uaAuthDigest(
                vm.parseJsonBytes32(s, string.concat(a, ".ua")),
                vm.parseJsonBytes32(s, string.concat(a, ".purposeTag")),
                vm.parseJsonBytes32(s, string.concat(a, ".digest"))
            ),
            vm.parseJsonBytes32(s, string.concat(a, ".uaAuthDigest"))
        );
    }

    function _assertDomain(UARegistry r, bytes32 uid) internal view {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address vc,
            bytes32 salt,
            uint256[] memory ext
        ) = r.eip712Domain();
        assertEq(fields, bytes1(0x1f));
        assertEq(name, "SCaaS UARegistry");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(vc, address(r));
        assertEq(salt, uid);
        assertEq(ext.length, 0);
    }

    function test_T_MEMBER_hederaNative() public {
        bytes32 hedera = bytes32(uint256(0x4d2)); // long-zero 0.0.1234
        bytes32 p256Ua = _register(reg, 0x0101, _key(0x0101));
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.HEDERA_NATIVE, hedera, 1);
        m[1] = Member(0x0101, p256Ua, 1);
        bytes memory d = _msigKey(2, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, hedera));
        reg.register(UAKinds.MSIG, d, "", 0, "");
        UARegistry h =
            _deploy(address(0x5ce0), chainUidA, address(0), true, BUDGET, address(0), true, _cfgs(address(mock)));
        assertTrue(h.hederaNative());
        _register(h, 0x0101, _key(0x0101));
        assertEq(h.kindOf(h.register(UAKinds.MSIG, d, "", 0, "")), UAKinds.MSIG);
    }

    // ----- constructor -----

    function test_constructorConfig() public {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        uint16[6] memory refused = [0x0001, 0x00ff, 0x0108, 0x0110, 0x0120, 0x0130];
        for (uint256 i; i < refused.length; ++i) {
            c[0] = UARegistry.KindConfig(refused[i], address(mock), 50_000);
            vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, refused[i]));
            new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, c);
        }
        c[0] = UARegistry.KindConfig(0x0101, address(0x1234), 50_000); // no code
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0x0101)));
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, c);
        c[0] = UARegistry.KindConfig(0x0101, address(mock), 0); // cap 0
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0x0101)));
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, c);
        c[0] = UARegistry.KindConfig(0x0101, address(mock), BUDGET + 1); // cap above the budget
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0x0101)));
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, c);
        UARegistry.KindConfig[] memory dup = new UARegistry.KindConfig[](2);
        dup[0] = UARegistry.KindConfig(0x0101, address(mock), 50_000);
        dup[1] = dup[0];
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0x0101)));
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, dup);
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0)));
        new UARegistry(chainUidA, address(0), false, 0, address(0), true, new UARegistry.KindConfig[](0));
        // msig off
        UARegistry r =
            _deploy(address(0x5cf1), chainUidA, address(0), false, BUDGET, address(0), false, _cfgs(address(mock)));
        (bytes memory d,) = _msigFixture();
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, UAKinds.MSIG));
        r.register(UAKinds.MSIG, d, "", 0, "");
    }

    // ----- helpers -----

    struct Fixture {
        bytes32[4] ids; // native, p256, bls-bn254, schnorr-bn254
        uint16[4] kinds;
        bytes[4] keys;
    }

    /// signatures.json's structure: native EOA, p256, bls-bn254-minsig, schnorr-bn254; weights 1,1,1,2; threshold 3.
    function _msigFixture() internal view returns (bytes memory d, Fixture memory f) {
        f.kinds = [UAKinds.EVM_EOA, uint16(0x0101), uint16(0x0107), uint16(0x0104)];
        f.ids[0] = _pad(vm.addr(PK_A));
        for (uint256 i = 1; i < 4; ++i) {
            f.keys[i] = _key(f.kinds[i]);
            f.ids[i] = UAKinds.uaOf(f.kinds[i], f.keys[i]);
        }
        Member[] memory m = new Member[](4);
        for (uint256 i; i < 4; ++i) {
            m[i] = Member(f.kinds[i], f.ids[i], i == 3 ? 2 : 1);
        }
        d = _msigKey(3, m);
    }

    /// The fixture with its derived members registered (the structure itself not).
    function _msigMembers() internal returns (bytes memory d, Fixture memory f) {
        (d, f) = _msigFixture();
        for (uint256 i = 1; i < 4; ++i) {
            if (!reg.isRegistered(f.ids[i])) _register(reg, f.kinds[i], f.keys[i]);
        }
    }

    function _msigRegistered() internal returns (bytes memory d, bytes32 ua, Fixture memory f) {
        (d, f) = _msigMembers();
        ua = reg.register(UAKinds.MSIG, d, "", 0, "");
    }

    function _registerMsig() internal returns (bytes memory d, bytes32 ua) {
        (d, ua,) = _msigRegistered();
    }

    /// Member signatures of the fixture members selected by `mask` (bit i = fixture member i), in index order.
    function _sigs(bytes memory d, Fixture memory f, bytes32 md, uint256 mask)
        internal
        view
        returns (UARegistry.MemberSig[] memory s)
    {
        uint256 n;
        for (uint256 i; i < 4; ++i) {
            if (mask >> i & 1 == 1) ++n;
        }
        s = new UARegistry.MemberSig[](n);
        uint256 j;
        for (uint16 idx; idx < 4; ++idx) {
            for (uint256 i; i < 4; ++i) {
                if (mask >> i & 1 == 0 || _indexOf(d, f.ids[i]) != idx) continue;
                s[j++] = i == 0
                    ? UARegistry.MemberSig(idx, "", _nativeSig(reg, PK_A, UAKinds.PURPOSE_MEMBER, md))
                    : UARegistry.MemberSig(
                        idx, f.keys[i], _sig(f.keys[i], UAKinds.uaMessage(f.kinds[i], UAKinds.PURPOSE_MEMBER, md))
                    );
            }
        }
    }

    function _firstMemberId(bytes memory d) internal pure returns (bytes32 id) {
        assembly ("memory-safe") {
            id := mload(add(d, 38))
        }
    }

    function _expectUnauthorized(bytes32 ua, bytes32 purpose, bytes32 digest, bytes memory auth) internal {
        _expectUnauthorizedOn(reg, ua, purpose, digest, auth);
    }

    function _expectUnauthorizedOn(UARegistry r, bytes32 ua, bytes32 purpose, bytes32 digest, bytes memory auth)
        internal
    {
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        r.requireAuthorized(ua, purpose, digest, auth);
    }

    function _writes(address sender, bytes memory k, bytes memory pop) internal returns (bytes32[] memory writes) {
        vm.record();
        vm.prank(sender);
        reg.register(0x0104, k, pop, 0, "");
        (, writes) = vm.accesses(address(reg));
    }

    function _values(bytes32[] memory slots) internal view returns (bytes32[] memory v) {
        v = new bytes32[](slots.length);
        for (uint256 i; i < slots.length; ++i) {
            v[i] = vm.load(address(reg), slots[i]);
        }
    }
}
