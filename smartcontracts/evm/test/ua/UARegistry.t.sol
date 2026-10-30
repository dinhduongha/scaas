// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Vm} from "forge-std/Vm.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {SaltedEIP712} from "../../src/common/SaltedEIP712.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryBase, MockVerifier, MockWallet, MockPredecessor} from "./UARegistryBase.sol";

/// accounts.md §1.16 T-REG / T-AUTH / T-CHAIN / T-MEMBER for the UA-2a registry, with stand-in verifiers (the real ones
/// are the verifier tasks' own tests; `UARegistryVectors.t.sol` runs the registry on signatures.json).
/// W-M: a gen 1 that runs out of gas before answering (every hand-off spends all it is given), or, when `cheap`,
/// reverts at once with no data.
contract StarvingPredecessor is MockPredecessor {
    bool public cheap;

    constructor(bytes32 chainUid_) MockPredecessor(chainUid_, bytes32(0), bytes32(0)) {}

    function setCheap(bool c) external {
        cheap = c;
    }

    function requireAuthorized(bytes32, bytes32, bytes32, bytes calldata) external view {
        _fail();
    }

    function _fail() private view {
        if (cheap) revert();
        while (true) {}
    }
}

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
        uint16[11] memory off = [0x0001, 0x0002, 0x0003, 0x0110, 0x0111, 0x0112, 0x0113, 0x0130, 0x0133, 0x0140, 0x0142];
        for (uint256 i; i < off.length; ++i) {
            assertFalse(reg.kindEnabled(off[i]));
            assertEq(reg.verifyCap(off[i]), 0);
        }
        assertEq(reg.chainKeyHash(), UAKinds.chainKeyHash(31337));
    }

    function test_vectorsContextA() public view {
        string memory s = _structures();
        // the portable PoP digests (UA-8, no context), the UAAuth digest (gen 1, context A) and the member digest of
        // structures.json
        _assertPortable(reg);
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
            emit IUARegistry.UARegistered(ua, kind, k, _none(), _pop(reg, kind, k), "", 1, 0, 0);
            assertEq(_register(reg, kind, k), ua);
            (IUARegistry.Record memory r, address pqzKey) = reg.recordOf(ua);
            assertEq(r.kind, kind);
            assertEq(r.registeredAt, 1000 + i);
            assertEq(r.keyPtr, address(0));
            assertEq(pqzKey, address(0));
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
            reg.register(kind, k, _none(), "", "");
            ++n;
        }
        assertGt(n, 50);
    }

    function test_T_REG_2_negativeRegistry() public {
        // disabled kinds: natives, out-of-scope kinds, unknown
        uint16[9] memory off = [0x0001, 0x0003, 0x0111, 0x0110, 0x0113, 0x0131, 0x0140, 0x0142, 0x0121];
        for (uint256 i; i < off.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, off[i]));
            reg.register(off[i], hex"00", _none(), "", "");
        }
        bytes memory p = _key(0x0101);
        bytes32 ua = reg.uaOf(0x0101, p);
        // wrong-tag PoP, PoP for another PQZ keyHash, a PoP over the metatx purpose, over the pre-UA-8 purpose (v1)
        bytes32 rd = _regDigest(ua, _none());
        bytes memory wrongTag = _sig(p, reg.uaMessage(0x0100, UAKinds.PURPOSE_POP_V2, rd));
        bytes memory otherKeyHash = _sig(
            p,
            reg.uaMessage(0x0101, UAKinds.PURPOSE_POP_V2, UAKinds.registrationDigest(UAKinds.portablePopDigest(ua, bytes32(uint256(1)), 0), 0))
        );
        bytes memory metatx = _sig(p, reg.uaMessage(0x0101, UAKinds.PURPOSE_METATX, rd));
        bytes memory v1 = _sig(p, reg.uaMessage(0x0101, UAKinds.PURPOSE_POP, rd));
        bytes[5] memory bad = [wrongTag, otherKeyHash, metatx, v1, bytes("")];
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(IUARegistry.UAPoP.selector);
            reg.register(0x0101, p, _none(), bad[i], "");
        }
        _register(reg, 0x0101, p);
        _registerReverts(reg, 0x0101, p, abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, ua));
        // the same point under the other p256-group kind (kinds.json valid[20]: p256 key ‖ rpIdHash)
        bytes memory w = vm.parseJsonBytes(_kindsJson(), ".valid[20].keyData");
        bytes32 kh = reg.keyHashOf(0x0100, w);
        assertEq(kh, reg.keyHashOf(0x0101, p));
        _registerReverts(reg, 0x0100, w, abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, kh, ua));
        // msig: a pop is refused (structures have none)
        (bytes memory d,) = _msigMembers();
        vm.expectRevert(IUARegistry.UAPoP.selector);
        reg.register(UAKinds.MSIG, d, _none(), hex"01", "");
    }

    /// `secp256k1` (ECDSA, 0x0108) shares the keyHash group of `bip340`: the bip340 key's point as an ECDSA key
    /// (kinds.json valid[26]) is UAKeyInUse; another ECDSA key registers, is listed and has its own id.
    function test_secp256k1_sharesTheSecp256k1Group() public {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](2);
        c[0] = UARegistry.KindConfig(0x0103, address(mock), 50_000);
        c[1] = UARegistry.KindConfig(0x0108, address(mock), 50_000);
        UARegistry r = _deploy(address(0x5ca0000000000000000000000000000000000108), chainUidA, address(0), false, BUDGET,
            address(0), true, c);
        string memory j = _kindsJson();
        assertEq(vm.parseJsonUint(j, ".valid[25].kind"), 0x0108);
        assertEq(vm.parseJsonUint(j, ".valid[26].kind"), 0x0108);
        bytes32 bip = _register(r, 0x0103, _key(0x0103));
        bytes memory lifted = vm.parseJsonBytes(j, ".valid[26].keyData");
        bytes32 kh = r.keyHashOf(0x0108, lifted);
        assertEq(kh, r.keyHashOf(0x0103, _key(0x0103)));
        _registerReverts(r, 0x0108, lifted, abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, kh, bip));
        bytes memory k = vm.parseJsonBytes(j, ".valid[25].keyData");
        bytes32 ua = _register(r, 0x0108, k);
        assertEq(ua, vm.parseJsonBytes32(j, ".valid[25].ua"));
        assertEq(r.kindOf(ua), 0x0108);
        assertEq(r.uaAt(0x0108, 0), ua);
        // off the curve: y + 1
        k[63] = bytes1(uint8(k[63]) ^ 1);
        _registerReverts(r, 0x0108, k, abi.encodeWithSelector(UAKinds.UAKeyData.selector, uint16(0x0108)));
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

    /// UA-6 (replaces T-REG-3b `authRef`, now in legacy/ua6) as revised by UA-8 UA8-D8: where slot 0x0142 has no
    /// verifier a holder's PQZ key is stored unproven (formerly `UAKindDisabled(0x0142)`) and claims nothing: no
    /// `keyOwner`, no `0x0142` list entry, so a second UA may list the same key. A non-holder's key (single key or
    /// classical `msig`) is `UAPqzHolder`; proof bytes without a key are `UAPqzPopHash`.
    function test_T_REG_3b_pqzKey() public {
        bytes memory k = _key(0x0103);
        bytes32 bipUa = reg.uaOf(0x0103, k);
        IUARegistry.UAAttrs memory a = IUARegistry.UAAttrs(new bytes(16_384), keccak256(hex"07"), 0, "");
        a.pqzKey[0] = 0x07;
        bytes memory pop = _pop(reg, 0x0103, k, a);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, bipUa));
        reg.register(0x0103, k, a, pop, hex"07");
        pop = _pop(reg, 0x0103, k);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzPopHash.selector, bipUa));
        reg.register(0x0103, k, _none(), pop, hex"00");
        (bytes memory d,) = _msigMembers();
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, reg.uaOf(UAKinds.MSIG, d)));
        reg.register(UAKinds.MSIG, d, a, "", hex"07");
        // two mldsa65 holders on a registry without the 0x0142 verifier list the same key, both unproven
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(UAKinds.MLDSA65, address(mock), 1_000_000);
        UARegistry r = _deploy(address(0x5ca6), chainUidA, address(0), false, BUDGET, address(0), true, c);
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, a.pqzKey);
        _unprovenHolder(r, a, 1);
        _unprovenHolder(r, a, 2);
        assertEq(r.keyOwner(h), bytes32(0));
        assertEq(r.uaCount(UAKinds.PQZ_MLWE), 0);
    }

    function _unprovenHolder(UARegistry r, IUARegistry.UAAttrs memory a, uint8 seed) internal {
        bytes memory pk = new bytes(1952);
        pk[0] = bytes1(seed);
        bytes32 ua = r.register(UAKinds.MLDSA65, pk, a, _pop(r, UAKinds.MLDSA65, pk, a), hex"07");
        (address ptr, bytes32 ph, bool proven) = r.pqzKeyOf(ua);
        assertEq(ptr.code, bytes.concat(hex"00", a.pqzKey));
        assertEq(ph, keccak256(hex"07"));
        assertFalse(proven);
        assertEq(r.pqzPopOf(ua), hex"07");
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
        _gen1WithoutEd25519();
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
        _gen1WithoutEd25519();
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
        gen2.register(UAKinds.MSIG, d1, _none(), "", "");
        gen2.requireAuthorized(
            p256Ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(reg, 0x0101, p, UAKinds.PURPOSE_METATX, DIGEST)
        );
        _expectUnauthorizedOn(
            gen2, p256Ua, UAKinds.PURPOSE_KEYOP, DIGEST, _auth(reg, 0x0101, p, UAKinds.PURPOSE_METATX, DIGEST)
        );
    }

    /// A gen-2 msig over a gen-1 p256 member and a gen-2 ed25519 member; gen 1 cannot register it.
    function test_T_REG_4_gen2Msig() public {
        _gen1WithoutEd25519();
        bytes memory p = _key(0x0101);
        bytes32 p256Ua = _register(reg, 0x0101, p);
        UARegistry gen2 = _gen2();
        bytes memory ed = _key(0x0102);
        bytes32 edUa = _register(gen2, 0x0102, ed);
        Member[] memory m = new Member[](2);
        m[0] = Member(0x0101, p256Ua, 1);
        m[1] = Member(0x0102, edUa, 1);
        bytes memory d2 = _msigKey(2, m);
        bytes32 msig2 = gen2.register(UAKinds.MSIG, d2, _none(), "", "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, edUa));
        reg.register(UAKinds.MSIG, d2, _none(), "", ""); // gen 1 does not know the gen-2 member
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

    /// msig re-enabled in gen 2: the same id registered in both generations has the same `kind` and `keyPtr`; each
    /// generation keeps its own `registeredAt`.
    function test_T_REG_4_msigBothGenerations() public {
        _gen1WithoutEd25519();
        UARegistry gen2 = _gen2();
        Member[] memory m = new Member[](1);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(PK_B)), 1);
        bytes memory d = _msigKey(1, m);
        bytes32 id = gen2.register(UAKinds.MSIG, d, _none(), "", "");
        vm.warp(block.timestamp + 1 days);
        assertEq(reg.register(UAKinds.MSIG, d, _none(), "", ""), id);
        (IUARegistry.Record memory ra,) = reg.recordOf(id);
        (IUARegistry.Record memory rb,) = gen2.recordOf(id);
        assertEq(ra.kind, rb.kind);
        assertEq(ra.keyPtr, rb.keyPtr);
        assertEq(rb.registeredAt + 1 days, ra.registeredAt);
    }

    /// Gen 1 enables every single-key kind since UA-2b; the gen-2 tests need a keyHash group gen 1 does not enable, so
    /// they first redeploy `reg` without ed25519.
    function _gen1WithoutEd25519() internal {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](KINDS.length - 1);
        uint256 n;
        for (uint256 i; i < KINDS.length; ++i) {
            if (KINDS[i] != 0x0102) c[n++] = UARegistry.KindConfig(KINDS[i], address(mock), _cap(KINDS[i]));
        }
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, c);
    }

    /// gen 2 = ed25519 (a group gen 1 does not enable after `_gen1WithoutEd25519`) + msig.
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
        (ok,) = address(reg).call{value: 1}(abi.encodeCall(reg.register, (0x0101, hex"", _none(), hex"", "")));
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
        // unregistered derived id (another 32-byte key under the ed25519 tag)
        bytes memory e = _key(0x0103);
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

    /// `zether-bn254` (0x0140) is in `legacy/ua6/` (UA-6 U10): no slot, no tag; its old id is never authorized.
    function test_T_AUTH_1b_zether() public {
        bytes memory y = new bytes(64); // any key data: 0x0140 has no slot and no tag
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, uint16(0x0140)));
        reg.register(0x0140, y, _none(), "", "");
        vm.expectRevert(abi.encodeWithSelector(UAKinds.UAKindUnknown.selector, uint16(0x0140)));
        reg.uaOf(0x0140, y);
        bytes32 ua = keccak256(abi.encodePacked(keccak256("scaas.ua.zether-bn254.v1"), y));
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(y, _sig(y, DIGEST)));
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

    /// R21: an msig `auth` that does not ABI-decode reverts without data (fail closed), never passes.
    function test_T_AUTH_2_msigUndecodableAuth() public {
        (bytes memory d, bytes32 ua, Fixture memory f) = _msigRegistered();
        bytes memory sigs = abi.encode(_sigs(d, f, _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST), 0x9));
        bytes memory auth = abi.encode(d, sigs);
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, auth); // the untouched blob passes
        // truncated outer `abi.encode(keyData, sig)`
        bytes memory cut = new bytes(auth.length - 64);
        for (uint256 i; i < cut.length; ++i) {
            cut[i] = auth[i];
        }
        _expectBareRevert(ua, cut);
        // MemberSig[0].index = 0x10000 (does not fit uint16): words 0x20 | length | offset[0] | index
        assembly ("memory-safe") {
            mstore(add(sigs, 0x80), 0x10000)
        }
        _expectBareRevert(ua, abi.encode(d, sigs));
    }

    function _expectBareRevert(bytes32 ua, bytes memory auth) internal view {
        (bool ok, bytes memory ret) =
            address(reg).staticcall(abi.encodeCall(reg.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, auth)));
        assertFalse(ok, "undecodable auth passed");
        assertEq(ret.length, 0, "undecodable auth: revert data");
    }

    /// Native contract members: an ERC-1271 wallet (`evm-contract`) and a 7702-delegated EOA (`evm-eoa`), both over
    /// `UAAuth(memberId, member, member_digest)`; ruling D1 (2026-10-30): the EOA signs with its own key only, its
    /// delegate's 1271 is refused.
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
        bytes32 ua = reg.register(UAKinds.MSIG, d, _none(), "", ""); // the delegation lands with this call
        assertEq(eoa.code.length, 23);
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](2);
        for (uint256 i; i < 2; ++i) {
            bytes32 id = m[i].id;
            uint16 idx = _indexOf(d, id);
            s[idx] = UARegistry.MemberSig(idx, "", _ecdsa(PK_B, reg.uaAuthDigest(id, UAKinds.PURPOSE_MEMBER, md)));
        }
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s)); // the EOA through its delegate
        uint16 e = _indexOf(d, _pad(eoa));
        s[e].sig = _ecdsa(PK_A, reg.uaAuthDigest(_pad(eoa), UAKinds.PURPOSE_MEMBER, md));
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
        reg.register(UAKinds.MSIG, _msigKey(2, m), _none(), "", "");
        // registered under another kind than stated
        m[1] = Member(0x0100, p256Ua, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, p256Ua));
        reg.register(UAKinds.MSIG, _msigKey(2, m), _none(), "", "");
        // nested structure, Zether member: refused by the layout (UAKinds, kinds.json) — UAKeyData
        (, bytes32 inner) = _registerMsig();
        m[1] = Member(UAKinds.MSIG, inner, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(2, m), _none(), "", "");
        m[1] = Member(0x0140, bytes32(uint256(1) << 200), 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(2, m), _none(), "", "");
        // duplicate member, threshold 0, threshold > weight
        m[1] = Member(UAKinds.EVM_EOA, eoa, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(1, m), _none(), "", "");
        m[1] = Member(0x0101, p256Ua, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(0, m), _none(), "", "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(3, m), _none(), "", "");
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
        bytes32 ua = reg.register(UAKinds.MSIG, d, _none(), "", "");
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

    /// 400 k for `SmartKeyAccount` clones (by the immutable clone codehash), 50 k for the same code elsewhere; a clone
    /// burning 380 k passes (the clone keeps 1/64 of the cap for its DELEGATECALL), one burning 410 k is refused.
    function test_T_AUTH_3_smartKeyCloneCap() public {
        address owner = vm.addr(PK_B);
        MockWallet impl = new MockWallet(owner, 0, 380_000, address(0));
        UARegistry r =
            _deploy(address(0x5ca4), chainUidA, address(0), false, BUDGET, address(impl), true, _cfgs(address(mock)));
        address clone = Clones.clone(address(impl));
        bytes32 cua = _pad(clone);
        r.requireAuthorized(
            cua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, r.uaAuthDigest(cua, UAKinds.PURPOSE_METATX, DIGEST))
        );
        MockWallet same = new MockWallet(owner, 0, 380_000, address(0));
        bytes32 sua = _pad(address(same));
        bytes memory sig = _ecdsa(PK_B, r.uaAuthDigest(sua, UAKinds.PURPOSE_METATX, DIGEST));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, sua));
        r.requireAuthorized(sua, UAKinds.PURPOSE_METATX, DIGEST, sig);
        // a clone of the implementation on a registry without the codehash: 50 k
        _expectUnauthorized(
            cua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, reg.uaAuthDigest(cua, UAKinds.PURPOSE_METATX, DIGEST))
        );
        // over the 400 k cap: a clone whose 1271 burns 410 k
        MockWallet heavy = new MockWallet(owner, 0, 410_000, address(0));
        UARegistry rh =
            _deploy(address(0x5ca5), chainUidA, address(0), false, BUDGET, address(heavy), true, _cfgs(address(mock)));
        bytes32 hua = _pad(Clones.clone(address(heavy)));
        sig = _ecdsa(PK_B, rh.uaAuthDigest(hua, UAKinds.PURPOSE_METATX, DIGEST));
        _expectUnauthorizedOn(rh, hua, UAKinds.PURPOSE_METATX, DIGEST, sig);
    }

    /// CTR-UA-24 as amended by owner ruling D1 (2026-10-30, "an EOA must really sign, no delegation"): a 7702-delegated
    /// EOA signs with its base key only; the delegate's 1271 is never asked, even for a signature it accepts.
    function test_T_AUTH_3_eip7702() public {
        address eoa = vm.addr(PK_A);
        bytes32 ua = _pad(eoa);
        address session = vm.addr(PK_B);
        MockWallet delegate = new MockWallet(session, 0, 0, address(0));
        bytes32 h = reg.uaAuthDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        vm.signAndAttachDelegation(address(delegate), PK_A);
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_A, h)); // base key
        assertEq(eoa.code.length, 23);
        assertEq(IERC1271(eoa).isValidSignature(h, _ecdsa(PK_B, h)), IERC1271.isValidSignature.selector, "the delegate accepts");
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, h)); // ruling D1: no delegate 1271
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

    // ----- fix round 1 -----

    /// Gen 1 starved through gen 2 ⇒ UAVerifyGas (record and msig member), enough gas ⇒ passes.
    function test_T_AUTH_4_gen2Starvation() public {
        _gen1WithoutEd25519();
        bytes memory p = _key(0x0101);
        bytes32 p256Ua = _register(reg, 0x0101, p);
        UARegistry gen2 = _gen2();
        bytes memory a = abi.encodeCall(
            gen2.requireAuthorized,
            (p256Ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(reg, 0x0101, p, UAKinds.PURPOSE_METATX, DIGEST))
        );
        (bool ok, bytes memory ret) = address(gen2).staticcall{gas: 100_000}(a);
        assertFalse(ok);
        assertEq(bytes4(ret), UAKinds.UAVerifyGas.selector);
        (ok,) = address(gen2).staticcall{gas: 2_000_000}(a);
        assertTrue(ok);

        // gen-1 p256 member + native EOA member of a gen-2 msig
        Member[] memory m = new Member[](2);
        m[0] = Member(0x0101, p256Ua, 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(vm.addr(PK_A)), 1);
        bytes memory d2 = _msigKey(2, m);
        bytes32 msig2 = gen2.register(UAKinds.MSIG, d2, _none(), "", "");
        bytes32 md = _memberDigest(msig2, UAKinds.PURPOSE_METATX, DIGEST);
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](2);
        uint16 ip = _indexOf(d2, p256Ua);
        uint16 ie = _indexOf(d2, _pad(vm.addr(PK_A)));
        s[ip] = UARegistry.MemberSig(ip, p, _sig(p, UAKinds.uaMessage(0x0101, UAKinds.PURPOSE_MEMBER, md)));
        s[ie] = UARegistry.MemberSig(
            ie, "", _ecdsa(PK_A, gen2.uaAuthDigest(_pad(vm.addr(PK_A)), UAKinds.PURPOSE_MEMBER, md))
        );
        bytes memory b = abi.encodeCall(
            gen2.requireAuthorized, (msig2, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d2, s))
        );
        (ok, ret) = address(gen2).staticcall{gas: 100_000}(b);
        assertFalse(ok);
        assertEq(bytes4(ret), UAKinds.UAVerifyGas.selector);
        (ok,) = address(gen2).staticcall{gas: 2_000_000}(b); // native member through gen 2 passes too
        assertTrue(ok);
    }

    /// W-M: gen 1 out of gas behind gen 2 is `UAVerifyGas` on both hand-offs (before: `UAUnauthorized`); gen 1 reverting
    /// at once with no data (it returns its unused gas) stays a failed check.
    function test_W_M_gen1OutOfGas_isUAVerifyGas_aCheapRevertIsAVerdict() public {
        StarvingPredecessor pred = new StarvingPredecessor(chainUidA);
        UARegistry gen2 =
            _deploy(address(0x5ca4), chainUidA, address(pred), false, BUDGET, address(0), false, _cfgs(address(mock)));
        bytes32 ua = bytes32(uint256(0xbeef) << 200); // derived, unknown to gen 2: handed to gen 1
        vm.expectRevert(UAKinds.UAVerifyGas.selector);
        gen2.requireAuthorized{gas: 1_000_000}(ua, UAKinds.PURPOSE_METATX, DIGEST, "");
        pred.setCheap(true);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        gen2.requireAuthorized{gas: 1_000_000}(ua, UAKinds.PURPOSE_METATX, DIGEST, "");
    }

    /// W-M: gen 1 running out of gas before its hold (behind gen 2) is `UAVerifyGas`, never a verdict. At every gas
    /// level a valid signature through gen 2 passes, reverts `UAVerifyGas`, or (gen 2 itself starved) reverts with no
    /// data; it never reverts `UAUnauthorized`.
    function test_W_M_gen1StarvedBeforeItsHold_isUAVerifyGas() public {
        _gen1WithoutEd25519();
        bytes memory p = _key(0x0101);
        bytes32 ua = _register(reg, 0x0101, p);
        UARegistry gen2 = _gen2();
        bytes memory a = abi.encodeCall(
            gen2.requireAuthorized,
            (ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(reg, 0x0101, p, UAKinds.PURPOSE_METATX, DIGEST))
        );
        bool sawGasError;
        for (uint256 g = 5_000; g < 300_000; g += 250) {
            (bool ok, bytes memory ret) = address(gen2).staticcall{gas: g}(a);
            if (ok) continue;
            assertTrue(ret.length == 0 || bytes4(ret) == UAKinds.UAVerifyGas.selector, "a starved call gave a verdict");
            if (ret.length != 0) sawGasError = true;
        }
        assertTrue(sawGasError, "no UAVerifyGas in the sweep");
        (bool passed,) = address(gen2).staticcall{gas: 2_000_000}(a);
        assertTrue(passed, "enough gas passes");
    }

    /// A 1271 answer with the magic in the high 4 bytes but dirty low bytes is refused.
    function test_T_AUTH_3_dirtyMagic() public {
        address a = address(0xD1127);
        // returns 0x1626ba7e ‖ 28 bytes of 0x01
        vm.etch(
            a,
            hex"7f1626ba7e01010101010101010101010101010101010101010101010101010101600052602060006000f3"
        );
        _expectUnauthorized(_pad(a), UAKinds.PURPOSE_METATX, DIGEST, hex"00");
    }

    function test_constructorSmartKeyNoCode() public {
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0)));
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0x1234), true, new UARegistry.KindConfig[](0));
    }

    // ----- T-CHAIN, T-MEMBER -----

    /// Contexts B and C of structures.json: chain 7622 twice, same registry address, different chainUid. UA-8 (P1):
    /// the PoP made for C registers on B (no chain context); the native UAAuth signature of C stays refused on B
    /// (writes stay chain-bound, P6).
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
        _assertVectors(rC, 3);
        UARegistry rB = _deploy(REG_A, uidB, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
        _assertVectors(rB, 2);
        assertEq(rB.register(0x0104, k, _none(), popC, ""), ua);
        _expectUnauthorizedOn(rB, nua, UAKinds.PURPOSE_MEMBER, DIGEST, uaAuthC);
        rB.requireAuthorized(nua, UAKinds.PURPOSE_MEMBER, DIGEST, _nativeSig(rB, PK_A, UAKinds.PURPOSE_MEMBER, DIGEST));
        assertEq(rB.kindOf(ua), 0x0104);
        _assertDomain(rB, uidB);
        // chainUid 0 refused
        vm.expectRevert(SaltedEIP712.ChainUidZero.selector);
        new UARegistry(0, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
    }

    /// structures.json `pop` rows (UA-8: no context, the same on every registry): both digests.
    function _assertPortable(UARegistry r) internal view {
        string memory s = _structures();
        uint256 n;
        for (; vm.keyExistsJson(s, string.concat(".pop[", vm.toString(n), "]")); ++n) {
            string memory p = string.concat(".pop[", vm.toString(n), "]");
            bytes32 d = r.portablePopDigest(
                vm.parseJsonBytes32(s, string.concat(p, ".ua")),
                vm.parseJsonBytes32(s, string.concat(p, ".pqzKeyHash")),
                vm.parseJsonBytes32(s, string.concat(p, ".kemRecordHash"))
            );
            assertEq(d, vm.parseJsonBytes32(s, string.concat(p, ".portablePopDigest")));
            assertEq(
                r.registrationDigest(d, vm.parseJsonBytes32(s, string.concat(p, ".pqzPopHash"))),
                vm.parseJsonBytes32(s, string.concat(p, ".registrationDigest"))
            );
        }
        assertEq(n, 7, "structures.json pop rows");
    }

    function _assertVectors(UARegistry r, uint256 authRow) internal view {
        string memory s = _structures();
        string memory a = string.concat(".uaAuth[", vm.toString(authRow), "]");
        _assertPortable(r);
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
        reg.register(UAKinds.MSIG, d, _none(), "", "");
        UARegistry h =
            _deploy(address(0x5ce0), chainUidA, address(0), true, BUDGET, address(0), true, _cfgs(address(mock)));
        assertTrue(h.hederaNative());
        _register(h, 0x0101, _key(0x0101));
        assertEq(h.kindOf(h.register(UAKinds.MSIG, d, _none(), "", "")), UAKinds.MSIG);
    }

    // ----- constructor -----

    function test_constructorConfig() public {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        uint16[6] memory refused = [0x0001, 0x00ff, 0x0109, 0x0114, 0x0120, 0x0134];
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
        r.register(UAKinds.MSIG, d, _none(), "", "");
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
        ua = reg.register(UAKinds.MSIG, d, _none(), "", "");
    }

    // ----- the per-kind list (owner 2026-10-17: decoy selection; uaCount / uaAt / uaPage / uaIndex) -----

    function _p256(uint256 pk) internal pure returns (bytes memory) {
        (uint256 x, uint256 y) = vm.publicKeyP256(pk);
        return abi.encodePacked(x, y);
    }

    function test_index_appendsPerKindInRegistrationOrder() public {
        assertEq(reg.uaCount(0x0101), 0);
        bytes32[3] memory p;
        for (uint256 i; i < 3; ++i) {
            p[i] = _register(reg, 0x0101, _p256(i + 1));
            if (i == 0) _register(reg, 0x0102, _key(0x0102)); // another kind in between: its own list
        }
        assertEq(reg.uaCount(0x0101), 3);
        assertEq(reg.uaCount(0x0102), 1);
        for (uint256 i; i < 3; ++i) {
            assertEq(reg.uaAt(0x0101, i), p[i]);
            assertEq(reg.uaIndex(p[i]), i);
            (IUARegistry.Record memory r,) = reg.recordOf(p[i]);
            assertEq(r.index, i);
        }
        assertEq(reg.uaAt(0x0102, 0), reg.uaOf(0x0102, _key(0x0102)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAIndex.selector, uint16(0x0101), uint256(3)));
        reg.uaAt(0x0101, 3);
        // pages: clipped at the end, empty past it, n = 0 empty
        bytes32[] memory pg = reg.uaPage(0x0101, 1, 10);
        assertEq(pg.length, 2);
        assertEq(pg[0], p[1]);
        assertEq(pg[1], p[2]);
        assertEq(reg.uaPage(0x0101, 0, 3).length, 3);
        assertEq(reg.uaPage(0x0101, 3, 1).length, 0);
        assertEq(reg.uaPage(0x0101, type(uint256).max, 1).length, 0);
        assertEq(reg.uaPage(0x0101, 0, 0).length, 0);
        assertEq(reg.uaPage(0x0103, 0, 5).length, 0); // an enabled kind with no registration
    }

    function test_index_msigListedUnknownIdsNot() public {
        (, bytes32 msig) = _registerMsig();
        assertEq(reg.uaCount(UAKinds.MSIG), 1);
        assertEq(reg.uaAt(UAKinds.MSIG, 0), msig);
        assertEq(reg.uaIndex(msig), 0);
        bytes32 nobody = bytes32(uint256(0xbeef) << 200);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UANotIndexed.selector, nobody));
        reg.uaIndex(nobody);
        // the members the fixture registered are listed under their own kinds
        uint256 listed;
        for (uint256 i; i < KINDS.length; ++i) {
            listed += reg.uaCount(KINDS[i]);
        }
        assertGt(listed, 0);
    }

    /// Gen 2 answers for a kind it enables from its own list and forwards every other kind to gen 1.
    function test_index_gen2ForwardsGen1Kinds() public {
        _gen1WithoutEd25519();
        bytes32 a = _register(reg, 0x0101, _p256(7));
        bytes32 b = _register(reg, 0x0101, _p256(8));
        UARegistry gen2 = _gen2();
        bytes32 e = _register(gen2, 0x0102, _key(0x0102));
        assertEq(gen2.uaCount(0x0101), 2);
        assertEq(gen2.uaAt(0x0101, 1), b);
        assertEq(gen2.uaPage(0x0101, 0, 5)[0], a);
        assertEq(gen2.uaIndex(b), 1);
        assertEq(gen2.uaCount(0x0102), 1);
        assertEq(gen2.uaAt(0x0102, 0), e);
        assertEq(gen2.uaIndex(e), 0);
        assertEq(reg.uaCount(0x0102), 0); // gen 1 does not enable ed25519: its own list stays empty
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
        reg.register(0x0104, k, _none(), pop, "");
        (, writes) = vm.accesses(address(reg));
    }

    function _values(bytes32[] memory slots) internal view returns (bytes32[] memory v) {
        v = new bytes32[](slots.length);
        for (uint256 i; i < slots.length; ++i) {
            v[i] = vm.load(address(reg), slots[i]);
        }
    }
}
