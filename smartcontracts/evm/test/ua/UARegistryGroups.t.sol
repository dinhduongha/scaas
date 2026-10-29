// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {Musig2Secp256k1Verifier} from "../../src/ua/verifiers/Musig2Secp256k1Verifier.sol";
import {Musig2Bn254Verifier} from "../../src/ua/verifiers/Musig2Bn254Verifier.sol";
import {UAFrostSecp256k1Verifier} from "../../src/ua/verifiers/UAFrostSecp256k1Verifier.sol";
import {FrostBn254Verifier} from "../../src/ua/verifiers/FrostBn254Verifier.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {GroupFixtures} from "./GroupFixtures.sol";

/// Accepts every PoP at once; `verify` burns all the gas it gets, then accepts (the worst case of a capped stored-kind
/// member inside the `msig` bound).
contract BurnVerify {
    function verify(bytes calldata, bytes32, bytes calldata) external view returns (bool) {
        while (gasleft() > 1_000) {}
        return true;
    }

    function verifyPop(bytes calldata, bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }
}

/// UA-2c: the registry's stored kinds 0x0110–0x0113 (accounts.md §1.6.1, CTR-UA-17, §1.8 steps 6/8,
/// generations, `msig` members) with the real MuSig2 and FROST verifiers on groups.json (context A = `REG_A`), and
/// T-GAS for every groups.json group (`-vv`; `--isolate` for the cold numbers).
contract UARegistryGroupsTest is UARegistryBase, GroupFixtures {
    uint64 internal constant GROUP_CAP = 50_000; // accounts.md §1.15: every group kind's verify cap
    uint256 internal constant PK_E = 0xE0A;
    /// 02 ‖ N: a valid secp256k1 point with x ≥ N (refused by the hint check, not by key validation).
    bytes internal constant KEY_X_N = hex"02fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

    address internal vMS;
    address internal vFS;
    address internal vMB;
    address internal vFB;

    function setUp() public override {
        super.setUp();
        (vMS, vMB) = (address(new Musig2Secp256k1Verifier()), address(new Musig2Bn254Verifier()));
        (vFS, vFB) = (address(new UAFrostSecp256k1Verifier()), address(new FrostBn254Verifier()));
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _allCfgs(KINDS.length));
    }

    /// The first `single` single-key kinds (mock verifier) plus the four group kinds with their real verifiers.
    function _allCfgs(uint256 single) internal view returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](single + 4);
        for (uint256 i; i < single; ++i) {
            c[i] = UARegistry.KindConfig(KINDS[i], address(mock), _cap(KINDS[i]));
        }
        c[single] = UARegistry.KindConfig(MS, vMS, GROUP_CAP);
        c[single + 1] = UARegistry.KindConfig(FS, vFS, GROUP_CAP);
        c[single + 2] = UARegistry.KindConfig(MB, vMB, GROUP_CAP);
        c[single + 3] = UARegistry.KindConfig(FB, vFB, GROUP_CAP);
    }

    function _gen2Empty() internal returns (UARegistry) {
        return _deploy(
            address(0x5ca2), chainUidA, address(reg), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0)
        );
    }

    // ----- helpers -----

    function _mains() internal view returns (Group[4] memory) {
        return [_main(MS), _main(FS), _main(MB), _main(FB)];
    }

    function _popMsg(UARegistry r, uint16 kind, bytes memory keyData) internal view returns (bytes32) {
        return r.uaMessage(kind, UAKinds.PURPOSE_POP_V2, UAKinds.registrationDigest(UAKinds.portablePopDigest(r.uaOf(kind, keyData), 0, 0), 0));
    }

    /// Registers `g` on `r` with the groups.json PoP (UA-8: portable, the same bytes on every registry).
    function _reg(UARegistry r, Group memory g) internal returns (bytes32) {
        return r.register(g.kind, g.keyData, _none(), g.pop, "");
    }

    /// `auth = abi.encode(bytes(""), sig)` (CTR-UA-17: stored kinds carry only the signature).
    function _gauth(Group memory g, bytes32 purpose, bytes32 digest) internal returns (bytes memory) {
        return abi.encode(bytes(""), _gsign(g.kind, g.secret, g.vk, UAKinds.uaMessage(g.kind, purpose, digest)));
    }

    function _expectUnauthorized(UARegistry r, bytes32 ua, bytes32 purpose, bytes32 digest, bytes memory auth)
        internal
    {
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        r.requireAuthorized(ua, purpose, digest, auth);
    }

    // ----- registry surface -----

    function test_groupKindsEnabled() public view {
        uint16[4] memory g = [MS, FS, MB, FB];
        for (uint256 i; i < 4; ++i) {
            assertTrue(reg.kindEnabled(g[i]));
            assertEq(reg.verifyCap(g[i]), GROUP_CAP);
        }
        assertFalse(reg.kindEnabled(0x0114));
    }

    // ----- register (§1.8 steps 2, 4, 6, 8) on every groups.json group -----

    /// Every group registers with its groups.json PoP (portable, UA-8): the event carries the full key data, `ua` and
    /// `keyHash` are the file's (UA-1: `secp256k1` x-only / `bn254-g1`), the record stores `vk` at `keyPtr` (SSTORE2)
    /// and the rest of the key data in the registration blob (`registrationOf` returns it whole, UA8-D7),
    /// `keyOwner[keyHash] = ua`; a second registration is `UAAlreadyRegistered`.
    function test_vectorsRegister() public {
        string memory j = _gj();
        uint256 count;
        for (uint256 i; vm.keyExistsJson(j, string.concat(".groups[", vm.toString(i), "]")); ++i) {
            Group memory g = _load(j, string.concat(".groups[", vm.toString(i), "]"));
            assertEq(_popMsg(reg, g.kind, g.keyData), g.popMessage, "portable");
            assertEq(reg.uaOf(g.kind, g.keyData), g.ua);
            assertEq(reg.keyHashOf(g.kind, g.keyData), g.keyHash);
            vm.warp(5_000 + i);
            vm.expectEmit(true, true, false, true, address(reg));
            emit IUARegistry.UARegistered(g.ua, g.kind, g.keyData, _none(), g.pop, "", 1, 0, 0);
            assertEq(reg.register(g.kind, g.keyData, _none(), g.pop, ""), g.ua);
            (IUARegistry.Record memory r, address pqzKey) = reg.recordOf(g.ua);
            assertEq(r.kind, g.kind);
            assertEq(r.registeredAt, 5_000 + i);
            assertEq(pqzKey, address(0));
            assertEq(r.keyPtr.code, bytes.concat(hex"00", g.vk), "keyPtr = SSTORE2(vk)");
            (, bytes memory kd,, bytes memory p,) = reg.registrationOf(g.ua);
            assertEq(kd, g.keyData, "registrationOf: the whole key data");
            assertEq(p, g.pop);
            assertEq(reg.keyOwner(g.keyHash), g.ua);
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, g.ua));
            reg.register(g.kind, g.keyData, _none(), g.pop, "");
            ++count;
        }
        assertEq(count, 20);
    }

    /// Every groups.json `register` negative (4 main groups) reverts with its error: `UAKeyData(kind)` (layout,
    /// validateKeyData) or `UAPoP` (KeyAgg / hints / DKG PoKs / `Y = Σ C_i0` / the group signature).
    function test_vectorsRegisterNegatives() public {
        string memory j = _gj();
        Group[4] memory gs = _mains();
        uint256 seen;
        for (uint256 k; k < 4; ++k) {
            for (uint256 i; vm.keyExistsJson(j, string.concat(gs[k].row, ".negatives[", vm.toString(i), "]")); ++i) {
                string memory r = string.concat(gs[k].row, ".negatives[", vm.toString(i), "]");
                if (keccak256(bytes(vm.parseJsonString(j, string.concat(r, ".entry")))) != keccak256("register")) {
                    continue;
                }
                bytes memory d = vm.parseJsonBytes(j, string.concat(r, ".keyData"));
                bytes memory pop = vm.parseJsonBytes(j, string.concat(r, ".pop"));
                bytes32 err = keccak256(bytes(vm.parseJsonString(j, string.concat(r, ".error"))));
                if (err == keccak256("UAKeyData")) {
                    vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, gs[k].kind));
                } else {
                    assertEq(err, keccak256("UAPoP"), vm.parseJsonString(j, string.concat(r, ".name")));
                    vm.expectRevert(IUARegistry.UAPoP.selector);
                }
                reg.register(gs[k].kind, d, _none(), pop, "");
                ++seen;
            }
        }
        assertEq(seen, 16 + 17 + 11 + 13);
    }

    /// `x(P_i) ≥ N` passes key validation (a valid point) and is refused by the hint check: `UAPoP`.
    function test_registerKeyXAtLeastN() public {
        Group memory g = _group(MS, 2, 2);
        bytes memory other = _slice(g.keyData, 35, 33);
        bytes memory d = other[0] == bytes1(0x03)
            ? bytes.concat(g.vk, hex"0002", KEY_X_N, other)
            : bytes.concat(g.vk, hex"0002", other, KEY_X_N);
        bytes memory pop = bytes.concat(_bip340Sign(g.secret, _popMsg(reg, MS, d)), g.hints);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        reg.register(MS, d, _none(), pop, "");
    }

    /// The group key occupies its keyHash group: the same key as a single key (`bip340` x(Q), `schnorr-bn254` Y) is
    /// `UAKeyInUse`, and the other way round.
    function test_keyHashGroup() public {
        Group memory g = _main(MS);
        bytes32 ua = _reg(reg, g);
        bytes memory x = _slice(g.vk, 1, 32);
        assertEq(g.keyHash, reg.keyHashOf(UAKinds.BIP340, x));
        assertEq(g.keyHash, keccak256(abi.encodePacked(UAKinds.groupTag("secp256k1"), x)));
        _registerReverts(reg, UAKinds.BIP340, x, abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, g.keyHash, ua));
        Group memory b = _main(FB);
        bytes32 qua = _register(reg, UAKinds.SCHNORR_BN254, b.vk);
        assertEq(b.keyHash, reg.keyHashOf(UAKinds.SCHNORR_BN254, b.vk));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, b.keyHash, qua));
        reg.register(FB, b.keyData, _none(), b.pop, "");
    }

    // ----- requireAuthorized (CTR-UA-17) -----

    /// The main groups' `sigs` rows (metatx, member) authorize with empty `keyData`; non-empty key data (the vk, the
    /// full key data), another purpose, a mutated signature ⇒ `UAUnauthorized`.
    function test_authStored() public {
        string memory j = _gj();
        Group[4] memory gs = _mains();
        for (uint256 k; k < 4; ++k) {
            bytes32 ua = _reg(reg, gs[k]);
            for (uint256 i; i < 2; ++i) {
                string memory r = string.concat(gs[k].row, ".sigs[", vm.toString(i), "]");
                bytes32 purpose = vm.parseJsonBytes32(j, string.concat(r, ".purposeTag"));
                bytes32 digest = vm.parseJsonBytes32(j, string.concat(r, ".digest"));
                bytes memory sig = vm.parseJsonBytes(j, string.concat(r, ".sig"));
                assertEq(
                    reg.uaMessage(gs[k].kind, purpose, digest), vm.parseJsonBytes32(j, string.concat(r, ".message"))
                );
                reg.requireAuthorized(ua, purpose, digest, abi.encode(bytes(""), sig));
                _expectUnauthorized(reg, ua, purpose, digest, abi.encode(gs[k].vk, sig));
                _expectUnauthorized(reg, ua, purpose, digest, abi.encode(gs[k].keyData, sig));
                _expectUnauthorized(reg, ua, UAKinds.PURPOSE_KEYOP, digest, abi.encode(bytes(""), sig));
                _expectUnauthorized(reg, ua, purpose, digest, abi.encode(bytes(""), _flip(sig, sig.length - 1)));
            }
            reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _gauth(gs[k], UAKinds.PURPOSE_METATX, DIGEST));
        }
    }

    /// T-AUTH-4 for every stored kind: a caller that leaves less than the cap gets `UAVerifyGas`, never a verdict.
    function test_authStoredStarved() public {
        Group[4] memory gs = _mains();
        for (uint256 k; k < 4; ++k) {
            bytes32 ua = _reg(reg, gs[k]);
            bytes memory good = abi.encodeCall(
                reg.requireAuthorized,
                (ua, UAKinds.PURPOSE_METATX, DIGEST, _gauth(gs[k], UAKinds.PURPOSE_METATX, DIGEST))
            );
            bool sawGasError;
            bool sawOk;
            for (uint256 gas = 20_000; gas < 120_000; gas += 1_000) {
                (bool ok, bytes memory ret) = address(reg).staticcall{gas: gas}(good);
                if (ok) sawOk = true;
                else if (ret.length == 4 && bytes4(ret) == UAKinds.UAVerifyGas.selector) sawGasError = true;
                else assertEq(ret.length, 0, "a starved call never answers UAUnauthorized");
            }
            assertTrue(sawGasError && sawOk);
        }
    }

    /// C13: a starved group registration reverts `UAPoP` (the PoP call's share runs out), `SSTORE2WriteFailed` (the
    /// key-write `CREATE` runs out) or with empty data (the outer call runs out), and never leaves a record. Per main
    /// group: find the least outer gas that registers, sweep finely below it (covers both bands) and coarsely under.
    function test_registerStoredStarved() public {
        Group[4] memory gs = _mains();
        for (uint256 k; k < 4; ++k) {
            Group memory g = gs[k];
            bytes memory call = abi.encodeCall(reg.register, (g.kind, g.keyData, _none(), g.pop, ""));
            (uint256 lo, uint256 hi) = (20_000, 8_000_000); // lo fails, hi succeeds
            while (hi - lo > 250) {
                uint256 mid = (lo + hi) / 2;
                uint256 snap = vm.snapshotState();
                (bool ok,) = address(reg).call{gas: mid}(call);
                vm.revertToState(snap);
                if (ok) hi = mid;
                else lo = mid;
            }
            uint256 found = hi;
            emit log_named_uint(string.concat("register threshold kind ", vm.toString(g.kind)), found);
            bool sawPoP;
            for (uint256 gas = 20_000; gas < found; gas += gas + 80_000 < found ? 20_000 : 250) {
                uint256 snap = vm.snapshotState();
                (bool ok, bytes memory ret) = address(reg).call{gas: gas}(call);
                if (!ok) {
                    assertEq(reg.kindOf(g.ua), 0, "no record after a starved register");
                    assertEq(reg.keyOwner(g.keyHash), 0, "no key owner after a starved register");
                    if (ret.length == 0) {} // outer out-of-gas
                    else if (bytes4(ret) == IUARegistry.UAPoP.selector && ret.length == 4) sawPoP = true;
                    else assertTrue(bytes4(ret) == bytes4(keccak256("SSTORE2WriteFailed()")) && ret.length == 4, "outcome");
                }
                vm.revertToState(snap);
            }
            assertTrue(sawPoP, "UAPoP seen");
        }
    }

    // ----- generations -----

    /// Gen 1 holds the stored records: gen 2 (no group kinds) reports them and hands `requireAuthorized` to gen 1,
    /// which reads its own `keyPtr`; gen 2 refuses to register them (`UAKindDisabled`).
    function test_gen2HandsStoredToGen1() public {
        Group[4] memory gs = _mains();
        for (uint256 k; k < 4; ++k) {
            _reg(reg, gs[k]);
        }
        UARegistry gen2 = _gen2Empty();
        for (uint256 k; k < 4; ++k) {
            Group memory g = gs[k];
            assertEq(gen2.kindOf(g.ua), g.kind);
            (IUARegistry.Record memory r1,) = reg.recordOf(g.ua);
            (IUARegistry.Record memory r2,) = gen2.recordOf(g.ua);
            assertEq(abi.encode(r1), abi.encode(r2));
            assertEq(gen2.keyOwner(g.keyHash), g.ua);
            bytes memory auth = _gauth(g, UAKinds.PURPOSE_METATX, DIGEST);
            gen2.requireAuthorized(g.ua, UAKinds.PURPOSE_METATX, DIGEST, auth);
            (, bytes memory sig) = abi.decode(auth, (bytes, bytes));
            _expectUnauthorized(gen2, g.ua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(g.keyData, sig));
            _expectUnauthorized(gen2, g.ua, UAKinds.PURPOSE_KEYOP, DIGEST, auth);
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, g.kind));
            gen2.register(g.kind, g.keyData, _none(), g.pop, "");
        }
    }

    /// The gen-2 rule (§1.8): the group kinds share the `secp256k1` / `bn254-g1` keyHash groups with `bip340` /
    /// `schnorr-bn254`, so gen 2 enables them only when gen 1 enables neither group; they then register in gen 2.
    function test_gen2EnablesGroupKinds() public {
        UARegistry.KindConfig[] memory one = new UARegistry.KindConfig[](1);
        uint16[4] memory g = [MS, FS, MB, FB];
        for (uint256 i; i < 4; ++i) {
            one[0] = UARegistry.KindConfig(g[i], vMS, GROUP_CAP);
            vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, g[i]));
            new UARegistry(chainUidA, address(reg), false, BUDGET, address(0), true, one);
        }
        // gen 1 without any secp256k1 / bn254-g1 kind (webauthn-p256, p256, ed25519, BLS)
        UARegistry.KindConfig[] memory c1 = new UARegistry.KindConfig[](6);
        uint16[6] memory k1 = [0x0100, 0x0101, 0x0102, 0x0105, 0x0106, 0x0107];
        for (uint256 i; i < 6; ++i) {
            c1[i] = UARegistry.KindConfig(k1[i], address(mock), _cap(k1[i]));
        }
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, c1);
        UARegistry gen2 =
            _deploy(address(0x5ca2), chainUidA, address(reg), false, BUDGET, address(0), true, _allCfgs(0));
        Group[4] memory gs = _mains();
        for (uint256 k; k < 4; ++k) {
            bytes32 ua = _reg(gen2, gs[k]);
            assertEq(reg.kindOf(ua), 0);
            (IUARegistry.Record memory r,) = gen2.recordOf(ua);
            assertEq(r.keyPtr.code, bytes.concat(hex"00", gs[k].vk));
            gen2.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _gauth(gs[k], UAKinds.PURPOSE_METATX, DIGEST));
        }
    }

    // ----- msig members of stored kinds (§1.9: vk from the member's keyPtr) -----

    /// An msig over a MuSig2 member, a FROST member and an EOA: members sign with empty `MemberSig.keyData`; key data
    /// in a stored member's MemberSig, or a wrong member signature ⇒ `UAUnauthorized`.
    function test_msigStoredMembers() public {
        (Group memory a, Group memory b) = (_main(MS), _main(FB));
        _reg(reg, a);
        _reg(reg, b);
        (bytes memory d, bytes32 ms) = _msigOf(reg, a.ua, b.ua);
        UARegistry.MemberSig[] memory s = _memberSigs(reg, d, ms, a, b);
        reg.requireAuthorized(ms, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        uint16 im = _indexOf(d, a.ua);
        s[im].keyData = a.vk;
        _expectUnauthorized(reg, ms, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        s[im].keyData = "";
        s[im].sig = _flip(s[im].sig, 63);
        _expectUnauthorized(reg, ms, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
    }

    /// A gen-2 msig over gen-1 stored members: gen 2 (no group kinds) hands each member to gen 1.
    function test_msigStoredMembersGen2() public {
        (Group memory a, Group memory b) = (_main(FS), _main(MB));
        _reg(reg, a);
        _reg(reg, b);
        UARegistry gen2 = _gen2Empty();
        (bytes memory d, bytes32 ms) = _msigOf(gen2, a.ua, b.ua);
        UARegistry.MemberSig[] memory s = _memberSigs(gen2, d, ms, a, b);
        gen2.requireAuthorized(ms, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        uint16 i = _indexOf(d, b.ua);
        s[i].keyData = b.vk;
        _expectUnauthorized(gen2, ms, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
    }

    /// msig {a, b, EOA}, threshold 3, registered on `r`.
    function _msigOf(UARegistry r, bytes32 a, bytes32 b) internal returns (bytes memory d, bytes32 ms) {
        Member[] memory m = new Member[](3);
        m[0] = Member(r.kindOf(a), a, 1);
        m[1] = Member(r.kindOf(b), b, 1);
        m[2] = Member(UAKinds.EVM_EOA, _pad(vm.addr(PK_E)), 1);
        d = _msigKey(3, m);
        ms = r.register(UAKinds.MSIG, d, _none(), "", "");
    }

    function _memberSigs(UARegistry r, bytes memory d, bytes32 ms, Group memory a, Group memory b)
        internal
        returns (UARegistry.MemberSig[] memory s)
    {
        bytes32 md = _memberDigest(ms, UAKinds.PURPOSE_METATX, DIGEST);
        s = new UARegistry.MemberSig[](3);
        uint16 ia = _indexOf(d, a.ua);
        uint16 ib = _indexOf(d, b.ua);
        uint16 ie = _indexOf(d, _pad(vm.addr(PK_E)));
        s[ia] = UARegistry.MemberSig(
            ia, "", _gsign(a.kind, a.secret, a.vk, UAKinds.uaMessage(a.kind, UAKinds.PURPOSE_MEMBER, md))
        );
        s[ib] = UARegistry.MemberSig(
            ib, "", _gsign(b.kind, b.secret, b.vk, UAKinds.uaMessage(b.kind, UAKinds.PURPOSE_MEMBER, md))
        );
        s[ie] = UARegistry.MemberSig(ie, "", _nativeSig(r, PK_E, UAKinds.PURPOSE_MEMBER, md));
    }

    // ----- T-GAS -----

    /// register and requireAuthorized (frame gas of the registry call, real verifiers) for every groups.json group:
    /// MuSig2 n = 2, 3, 8, 16; FROST (t, n) = (2, 2), (2, 3), (2, 8), (8, 8), (2, 16), (16, 16). `--isolate`: cold.
    function test_T_GAS_groups() public {
        string memory j = _gj();
        for (uint256 i; vm.keyExistsJson(j, string.concat(".groups[", vm.toString(i), "]")); ++i) {
            Group memory g = _load(j, string.concat(".groups[", vm.toString(i), "]"));
            string memory label = string.concat(
                vm.parseJsonString(j, string.concat(g.row, ".kindName")),
                " t=",
                vm.toString(g.t),
                " n=",
                vm.toString(g.n)
            );
            // UA-8 (UA8-D7): `register` also stores the key data past `vk` and the PoP, whose EIP-8037 state gas
            // (FROST(bn254) 16-of-16: 18 KB of key data) is logged apart; the regular gas stays well within the budget.
            // A8 re-pins the UA-8 gas figures.
            reg.register(g.kind, g.keyData, _none(), g.pop, "");
            Vm.Gas memory vg = vm.lastCallGas();
            assertLt(vg.gasTotalUsed, BUDGET / 4, "register (regular gas) well within the budget");
            emit log_named_uint(string.concat(label, " register"), vg.gasTotalUsed);
            emit log_named_int("  state gas (EIP-8037)", vg.gasStateUsed);
            bytes memory auth = _gauth(g, UAKinds.PURPOSE_METATX, DIGEST);
            (bool ok,, uint256 used) = meter.measure(
                address(reg), abi.encodeCall(reg.requireAuthorized, (g.ua, UAKinds.PURPOSE_METATX, DIGEST, auth))
            );
            assertTrue(ok, label);
            emit log_named_uint(string.concat(label, " requireAuthorized"), used);
        }
    }

    /// The msig bound (register step 4) with a stored-kind member: an msig of one group member whose verifier burns
    /// its whole cap authorizes with exactly `cap + MSIG_MEMBER_GAS` for the `requireAuthorized` frame, in gen 1 and
    /// handed from gen 2 (+ gen 1's hold). MuSig2-secp256k1 n = 16 with a 64-byte signature, and musig2-bn254 n = 16
    /// (the widest stored key data, 1,090 bytes) with a 96-byte one. Run with `--isolate` for the cold case.
    function test_T_GAS_msigStoredMemberBound() public {
        _memberBound(MS, 64, address(0x5cb1));
        _memberBound(MB, 96, address(0x5cb3));
    }

    function _memberBound(uint16 kind, uint256 sigLen, address at) internal {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(kind, address(new BurnVerify()), GROUP_CAP);
        UARegistry r1 = _deploy(at, chainUidA, address(0), false, BUDGET, address(0), true, c);
        UARegistry r2 = _deploy(
            address(uint160(at) + 1), chainUidA, address(r1), false, BUDGET, address(0), true,
            new UARegistry.KindConfig[](0)
        );
        Group memory g = _group(kind, 16, 16);
        bytes32 mu = r1.register(kind, g.keyData, _none(), "", "");
        Member[] memory m = new Member[](1);
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](1);
        s[0] = UARegistry.MemberSig(0, "", new bytes(sigLen));
        UARegistry[2] memory regs = [r1, r2];
        for (uint256 i; i < 2; ++i) {
            m[0] = Member(kind, mu, uint16(i + 1)); // another id per generation
            bytes memory d = _msigKey(uint16(i + 1), m);
            bytes32 ms = regs[i].register(UAKinds.MSIG, d, _none(), "", "");
            uint256 bound = GROUP_CAP + 35_000; // UARegistry.MSIG_MEMBER_GAS
            if (i == 1) bound += GROUP_CAP / 63 + 5_000; // gen 1's own hold (register step 4)
            (bool ok,) = address(regs[i]).call{gas: bound}(
                abi.encodeCall(regs[i].requireAuthorized, (ms, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s)))
            );
            assertTrue(ok, "authorizes within the registration bound");
        }
    }
}
