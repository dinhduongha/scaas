// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryBase, MockVerifier} from "./UARegistryBase.sol";
import {UACall} from "./UACall.sol";

/// A verify-only verifier stand-in (spec 2026-11-19-registry-verify-only-kinds §2, §5): settable `PRECOMPILE()` and `KEY_FORM()`,
/// and an answer per mode: 0 the `MockVerifier` rule (`sig == keccak256(abi.encode(keyData, message))`), 1 accept all, 2 refuse
/// all, 3 revert `PqNoAnswer()`, 4 revert empty, 5 run out of gas, 6 return empty with success, 7 return two words `1, 0`, 8 return
/// `abi.encode(2)`. `verify`, `verifyPop` and `verifyCached` answer alike.
contract VerifyOnlyStandIn {
    error PqNoAnswer();

    address public immutable PRECOMPILE;
    uint8 public immutable KEY_FORM;
    uint8 public immutable mode;
    uint256 public calls; // never written in a view; kept for the ABI shape only

    constructor(address precompile, uint8 keyForm, uint8 mode_) {
        (PRECOMPILE, KEY_FORM, mode) = (precompile, keyForm, mode_);
    }

    function _answer(bytes calldata key, bytes32 message, bytes calldata sig) internal view returns (bool) {
        uint8 m = mode;
        if (m == 1) return true;
        if (m == 2) return false;
        if (m == 3) revert PqNoAnswer();
        if (m == 4) {
            assembly {
                revert(0, 0)
            }
        }
        if (m == 5) {
            assembly {
                for {} 1 {} {}
            }
        }
        if (m == 6) {
            assembly {
                return(0, 0)
            }
        }
        if (m == 7) {
            assembly {
                mstore(0, 1)
                mstore(32, 0)
                return(0, 64)
            }
        }
        if (m == 8) {
            assembly {
                mstore(0, 2)
                return(0, 32)
            }
        }
        return sig.length == 32 && bytes32(sig) == keccak256(abi.encode(key, message));
    }

    function verify(bytes calldata key, bytes32 message, bytes calldata sig) external view returns (bool) {
        return _answer(key, message, sig);
    }

    function verifyPop(bytes calldata key, bytes32 message, bytes calldata sig) external view returns (bool) {
        return _answer(key, message, sig);
    }

    function verifyCached(bytes calldata ek, bytes32 message, bytes calldata sig) external view returns (bool) {
        return _answer(ek, message, sig);
    }
}

/// A home verifier stand-in with a `PRECOMPILE()` getter (the impossible key form `1`, N8): the `MockVerifier` rule.
contract HomeStandIn is MockVerifier {
    address public immutable PRECOMPILE;

    constructor(address precompile) MockVerifier(0, 0) {
        PRECOMPILE = precompile;
    }
}

/// A registry look-alike for the constructor's walk (Review Focus 4): every view the walk reads, each settable; `missing` makes one
/// probed view revert (§11.3, W3).
contract FakeRegistry {
    bytes32 public chainUid;
    uint8 public generation;
    address public predecessor;
    bytes4 public missing;

    constructor(bytes32 uid, uint8 g, address p) {
        (chainUid, generation, predecessor) = (uid, g, p);
    }

    function setPredecessor(address p) external {
        predecessor = p;
    }

    function setMissing(bytes4 sel) external {
        missing = sel;
    }

    modifier probed() {
        require(msg.sig != missing);
        _;
    }

    function hederaNative() external pure returns (bool) {}
    function kindEnabled(uint16) external pure returns (bool) {}
    function kindHome(uint16) external view probed returns (address) {}
    function verifierOf(uint16) external view probed returns (address) {}
    function verifyOnly(uint16) external view probed returns (bool) {}
    function holderOf(bytes32) external view probed returns (address, uint16, address) {}
    function pqzHomeOf(bytes32) external view probed returns (address) {}
    function expandedKeyOf(bytes32) external view probed returns (address[3] memory) {}

    function txGasCap() external view probed returns (uint64) {
        return 1 << 24;
    }

    function checkedOf(bytes32) external view probed returns (uint8, uint8, uint8) {}
    function memberSigHashOf(bytes32, uint256) external view probed returns (bytes32) {}
    function msigStateOf(bytes32) external view probed returns (uint64, uint256, uint256) {}
}

/// The line of generations (spec 2026-11-19-registry-verify-only-kinds §2, §11.1; plan Task 2): the kind word's flags, the
/// constructor's rules (the `⇔` rule for single-key kinds, `msig` / `0x0142` outside it, the key form, a verify-only verifier
/// without a precompile, the group across the line), `generation = predecessor + 1` up to `MAX_GENERATION`, the EIP-712 version.
contract UARegistryLineTest is UARegistryBase {
    uint16 internal constant ML65 = UAKinds.MLDSA65;
    uint64 internal constant CAP_VO = 250_000;
    address internal constant PC = address(0x5caa0013); // a precompile address a stand-in names

    function _k(uint16 kind, address v, uint64 cap) internal pure returns (UARegistry.KindConfig memory) {
        return UARegistry.KindConfig(kind, v, cap, false, 0);
    }

    function _vo(uint16 kind, address v, uint64 cap, uint8 form) internal pure returns (UARegistry.KindConfig memory) {
        return UARegistry.KindConfig(kind, v, cap, true, form);
    }

    function _one(UARegistry.KindConfig memory c) internal pure returns (UARegistry.KindConfig[] memory k) {
        k = new UARegistry.KindConfig[](1);
        k[0] = c;
    }

    function _noKinds() internal pure returns (UARegistry.KindConfig[] memory) {}

    function _new(address pred, UARegistry.KindConfig[] memory k) internal returns (UARegistry) {
        return new UARegistry(chainUidA, pred, false, BUDGET, 1 << 24, address(0), true, k);
    }

    function _refused(address pred, UARegistry.KindConfig[] memory k, uint16 kind) internal {
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, kind));
        _new(pred, k);
    }

    function _standIn(address precompile, uint8 form) internal returns (address) {
        return address(new VerifyOnlyStandIn(precompile, form, 0));
    }

    /// Gen 1 with `mldsa65` on `home` (a verifier with or without a precompile) and the base kinds.
    function _gen1Ml(address home) internal returns (UARegistry) {
        UARegistry.KindConfig[] memory b = _cfgs(address(mock));
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](b.length + 1);
        for (uint256 i; i < b.length; ++i) {
            k[i] = b[i];
        }
        k[b.length] = _k(ML65, home, 5_950_000);
        return _new(address(0), k);
    }

    // ----- the `⇔` rule (§2 N4, M6) -----

    function test_gen2_predecessorKind_withoutFlag_UAConfig() public {
        _refused(address(reg), _one(_k(0x0101, address(mock), 50_000)), 0x0101);
        _new(address(reg), _one(_vo(0x0101, _standIn(PC, 0), CAP_VO, 0))); // the control: flagged
    }

    function test_gen2_flagOnUnknownKind_UAConfig() public {
        _refused(address(reg), _one(_vo(ML65, _standIn(PC, 0), CAP_VO, 0)), ML65); // gen 1 has no mldsa65
        _new(address(reg), _one(_k(ML65, address(mock), CAP_VO))); // the control: unflagged, its group is new
    }

    function test_gen1_flag_UAConfig() public {
        _refused(address(0), _one(_vo(0x0101, _standIn(PC, 0), CAP_VO, 0)), 0x0101);
        _new(address(0), _one(_k(0x0101, address(mock), 50_000))); // the control
    }

    function test_flagOnMsig_UAConfig() public {
        _refused(address(reg), _one(_vo(UAKinds.MSIG, _standIn(PC, 0), CAP_VO, 0)), UAKinds.MSIG);
    }

    /// M6: `0x0142` is never verify-only (its proof check is a write).
    function test_flagOn0142_UAConfig() public {
        UARegistry g1 = _new(address(0), _one(_k(UAKinds.PQZ_MLWE, address(mock), 1_000_000)));
        _refused(address(g1), _one(_vo(UAKinds.PQZ_MLWE, _standIn(PC, 0), CAP_VO, 0)), UAKinds.PQZ_MLWE);
        _refused(address(0), _one(_vo(UAKinds.PQZ_MLWE, _standIn(PC, 0), CAP_VO, 0)), UAKinds.PQZ_MLWE);
    }

    /// M6 / §11.2 (1): `msig` and `0x0142` re-enabled in a later generation, unflagged, are not refused (today's A5-I1 group rule
    /// refused `0x0142` there).
    function test_msigAnd0142_reenabled_notRefused() public {
        UARegistry g1 = _new(address(0), _one(_k(UAKinds.PQZ_MLWE, address(mock), 1_000_000)));
        UARegistry g2 = _new(address(g1), _one(_k(UAKinds.PQZ_MLWE, address(mock), 1_000_000)));
        assertTrue(g2.kindEnabled(UAKinds.PQZ_MLWE));
        assertTrue(g2.kindEnabled(UAKinds.MSIG));
        assertEq(g2.kindHome(UAKinds.PQZ_MLWE), address(g2), "0x0142: the newest enabling generation");
        assertEq(g2.kindHome(UAKinds.MSIG), address(g2));
    }

    // ----- the key form (R3, P1, N8) and the precompile (P11) -----

    function test_keyForm1_homeHasPrecompile_UAConfig() public {
        UARegistry g1 = _gen1Ml(address(new HomeStandIn(PC))); // the home's verifier has a precompile: no cache can exist
        _refused(address(g1), _one(_vo(ML65, _standIn(PC, 1), CAP_VO, 1)), ML65);
        _new(address(g1), _one(_vo(ML65, _standIn(PC, 0), CAP_VO, 0))); // the control: form 0
        UARegistry c = _gen1Ml(address(new HomeStandIn(address(0)))); // the control: the home on the cache path
        _new(address(c), _one(_vo(ML65, _standIn(PC, 1), CAP_VO, 1)));
    }

    /// N8: the impossible-form check reads the **home's** verifier, never a middle generation's verify-only one (which always has a
    /// precompile).
    function test_keyForm1_throughMiddleVerifyOnly_readsHome() public {
        UARegistry g1 = _gen1Ml(address(new HomeStandIn(address(0))));
        UARegistry g2 = _new(address(g1), _one(_vo(ML65, _standIn(PC, 0), CAP_VO, 0)));
        UARegistry g3 = _new(address(g2), _one(_vo(ML65, _standIn(PC, 1), CAP_VO, 1)));
        assertEq(g3.kindHome(ML65), address(g1));
        assertTrue(g3.verifyOnly(ML65));
    }

    /// P11 / N16: a verify-only verifier whose probe failed (`PRECOMPILE() == 0`) is refused.
    function test_verifyOnly_noPrecompile_UAConfig() public {
        _refused(address(reg), _one(_vo(0x0101, _standIn(address(0), 0), CAP_VO, 0)), 0x0101);
        _refused(address(reg), _one(_vo(0x0101, address(mock), CAP_VO, 0)), 0x0101); // no getter at all
    }

    function test_keyForm_mismatch_UAConfig() public {
        UARegistry g1 = _gen1Ml(address(new HomeStandIn(address(0))));
        _refused(address(g1), _one(_vo(ML65, _standIn(PC, 1), CAP_VO, 0)), ML65); // the verifier wants form 1
        _refused(address(g1), _one(_vo(ML65, _standIn(PC, 0), CAP_VO, 1)), ML65); // the verifier wants form 0
        _refused(address(g1), _one(UARegistry.KindConfig(ML65, _standIn(PC, 2), CAP_VO, true, 2)), ML65); // no form 2
        _refused(address(0), _one(UARegistry.KindConfig(ML65, address(mock), CAP_VO, false, 1)), ML65); // form on a home kind
    }

    /// A non-verify-only kind whose keyHash group any predecessor enables is refused across the line: gen 1 enables `bip340`
    /// (group `secp256k1`), gen 2 nothing, gen 3 `secp256k1` 0x0108.
    function test_groupAcrossLine_UAConfig() public {
        UARegistry g2 = _new(address(reg), _noKinds());
        _refused(address(g2), _one(_k(UAKinds.SECP256K1, address(mock), 50_000)), UAKinds.SECP256K1);
        _new(address(g2), _one(_k(UAKinds.MLDSA44, address(mock), 50_000))); // the control: a new group
        // a verify-only kind is exempt: its group is the home's
        _new(address(g2), _one(_vo(0x0103, _standIn(PC, 0), CAP_VO, 0)));
    }

    // ----- the line (§11.1, R10, R11) -----

    function test_generation_isPredPlusOne() public {
        UARegistry g2 = _new(address(reg), _noKinds());
        UARegistry g3 = _new(address(g2), _noKinds());
        assertEq(reg.generation(), 1);
        assertEq(g2.generation(), 2);
        assertEq(g3.generation(), 3);
        assertEq(g3.predecessor(), address(g2));
    }

    function test_eip712Version_isGenerationDecimal() public {
        UARegistry g2 = _new(address(reg), _noKinds());
        UARegistry g3 = _new(address(g2), _noKinds());
        (, string memory n, string memory v,,,,) = g3.eip712Domain();
        assertEq(n, "SCaaS UARegistry");
        assertEq(v, "3");
        (,, v,,,,) = g2.eip712Domain();
        assertEq(v, "2");
        (,, v,,,,) = reg.eip712Domain();
        assertEq(v, "1");
    }

    /// R11: generation 16 deploys (version "16"), a 17th is `UAConfig(0)`.
    function test_depth17_UAConfig0() public {
        UARegistry g = reg;
        for (uint256 i = 2; i <= 16; ++i) {
            g = _new(address(g), _noKinds());
        }
        assertEq(g.generation(), 16);
        (,, string memory v,,,,) = g.eip712Domain();
        assertEq(v, "16");
        _refused(address(g), _noKinds(), 0);
    }

    // ----- N12: every reader masks the flags -----

    function test_n12_flaggedWord_capAndRegistrable() public {
        bytes memory p = _key(0x0101);
        bytes32 id = _register(reg, 0x0101, p);
        UARegistry g2 = _new(address(reg), _one(_vo(0x0101, _standIn(PC, 0), CAP_VO, 0)));
        assertEq(g2.verifyCap(0x0101), CAP_VO, "the cap, the flags masked");
        assertTrue(g2.kindEnabled(0x0101), "kindEnabled stays local: a verifier word is set");
        assertTrue(g2.verifyOnly(0x0101));
        assertFalse(g2.verifyOnly(0x0100));
        assertFalse(reg.verifyOnly(0x0101));
        assertEq(g2.kindHome(0x0101), address(reg), "not registrable here: the home is gen 1");
        assertEq(g2.verifierOf(0x0101), address(VerifyOnlyStandIn(g2.verifierOf(0x0101))));
        assertEq(reg.verifierOf(0x0101), address(mock));
        // nothing reads the flagged word as a cap above 2^64: the check of a gen-1 record through gen 2 is a verdict
        _req(g2, id, UAKinds.PURPOSE_METATX, DIGEST, _auth(reg, 0x0101, p, UAKinds.PURPOSE_METATX, DIGEST));
        // and its registration is not this generation's (step 1, before the id is looked up)
        bytes memory pop = _pop(g2, 0x0101, p);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAVerifyOnly.selector, uint16(0x0101)));
        UACall.register(g2, 0x0101, p, _none(), pop, "");
    }

    // ----- Review Focus 4: a fake predecessor -----

    function test_fakePredecessor_selfLoop_UAConfig0() public {
        FakeRegistry f = new FakeRegistry(chainUidA, 2, address(0));
        f.setPredecessor(address(f)); // claims generation 2 over itself
        _refused(address(f), _noKinds(), 0);
        FakeRegistry g = new FakeRegistry(chainUidA, 1, address(0)); // the control: a gen-1 look-alike
        _new(address(g), _noKinds());
    }

    function test_fakePredecessor_generationOutOfRange_UAConfig0() public {
        _refused(address(new FakeRegistry(chainUidA, 0, address(0))), _noKinds(), 0);
        _refused(address(new FakeRegistry(chainUidA, 16, address(0))), _noKinds(), 0);
        _refused(address(new FakeRegistry(chainUidA, 255, address(0))), _noKinds(), 0);
        // a gen-1 look-alike that names a predecessor, and a gen 2 over nothing
        FakeRegistry a = new FakeRegistry(chainUidA, 1, address(0));
        _refused(address(new FakeRegistry(chainUidA, 1, address(a))), _noKinds(), 0);
        _refused(address(new FakeRegistry(chainUidA, 2, address(0))), _noKinds(), 0);
        // a gap: a look-alike claiming generation 3 over the real generation 1
        _refused(address(new FakeRegistry(chainUidA, 3, address(reg))), _noKinds(), 0);
        _new(address(new FakeRegistry(chainUidA, 2, address(reg))), _noKinds()); // the control: generation 2 over it
        // a chain of 16 look-alikes claiming 16 … 1: the predecessor's generation is 16, refused before any walk
        FakeRegistry top = new FakeRegistry(chainUidA, 1, address(0));
        for (uint8 i = 2; i <= 16; ++i) {
            top = new FakeRegistry(chainUidA, i, address(top));
        }
        _refused(address(top), _noKinds(), 0);
    }
    // ===== Task 3: the one walk, the forwarding readers, the refusals, the probes (§3, §11.1, §11.3) =====

    uint16 internal constant FN512 = UAKinds.FNDSA512;

    /// A gen-1 `msig` of one EOA (`salt` picks the member): a record every generation can hold.
    function _msigOf(UARegistry r, uint256 salt) internal returns (bytes32 ua, bytes memory d) {
        Member[] memory m = new Member[](1);
        m[0] = Member(UAKinds.EVM_EOA, bytes32(uint256(uint160(0xE0A0 + salt))), 1);
        d = _msigKey(1, m);
        ua = UACall.register(r, UAKinds.MSIG, d, _none(), "", "");
    }

    /// A line of three generations, `pqz[i]`: generation i + 1 enables `0x0142` (a stand-in verifier). Gen 1 has the base kinds.
    function _line3(bool[3] memory pqz) internal returns (UARegistry[3] memory g) {
        address prev;
        for (uint256 i; i < 3; ++i) {
            UARegistry.KindConfig[] memory b = i == 0 ? _cfgs(address(mock)) : _noKinds();
            UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](b.length + (pqz[i] ? 1 : 0));
            for (uint256 j; j < b.length; ++j) {
                k[j] = b[j];
            }
            if (pqz[i]) k[b.length] = _k(UAKinds.PQZ_MLWE, address(mock), 1_000_000);
            g[i] = _new(prev, k);
            prev = address(g[i]);
        }
    }

    function _holder(UARegistry r, bytes32 ua) internal view returns (address h, uint16 k, address p) {
        return r.holderOf(ua);
    }

    function test_holderOf_ownRecord() public {
        bytes32 id = _register(reg, 0x0101, _key(0x0101));
        (address h, uint16 k, address p) = reg.holderOf(id);
        assertEq(h, address(reg));
        assertEq(k, 0x0101);
        assertEq(p, address(0), "no 0x0142 on the line");
    }

    function test_holderOf_threeGenerations() public {
        UARegistry[3] memory g = _line3([false, false, false]);
        bytes32 a = _register(g[0], 0x0101, _key(0x0101));
        (bytes32 b,) = _msigOf(g[1], 1);
        (bytes32 c,) = _msigOf(g[2], 2);
        (address h, uint16 k,) = g[2].holderOf(a);
        assertEq(h, address(g[0]));
        assertEq(k, 0x0101);
        (h, k,) = g[2].holderOf(b);
        assertEq(h, address(g[1]));
        assertEq(k, UAKinds.MSIG);
        (h, k,) = g[2].holderOf(c);
        assertEq(h, address(g[2]));
        (h,,) = g[1].holderOf(c);
        assertEq(h, address(0), "a generation below never sees a later record");
        assertEq(g[2].kindOf(b), UAKinds.MSIG);
        assertTrue(g[2].isRegistered(a));
    }

    function test_holderOf_miss_zero() public {
        UARegistry[3] memory g = _line3([true, true, true]);
        (address h, uint16 k, address p) = g[2].holderOf(keccak256("nobody"));
        assertEq(h, address(0));
        assertEq(k, 0);
        assertEq(p, address(0), "a miss has no PQZ home");
    }

    /// §11.2 (a) and (b): the third word is the oldest generation from the holder to the reader that enables `0x0142`;
    /// `pqzHomeOf` is that word.
    function test_holderOf_pqzHome_thirdWord() public {
        UARegistry[3] memory a = _line3([true, false, true]);
        bytes32 r1 = _register(a[0], 0x0101, _key(0x0101));
        (bytes32 r2,) = _msigOf(a[1], 3);
        (bytes32 r3,) = _msigOf(a[2], 4);
        _home(a[2], r1, address(a[0]));
        _home(a[2], r2, address(a[2]));
        _home(a[1], r2, address(0)); // below its home: none
        _home(a[2], r3, address(a[2]));
        UARegistry[3] memory b = _line3([false, true, true]);
        bytes32 s1 = _register(b[0], 0x0101, _key(0x0101));
        (bytes32 s3,) = _msigOf(b[2], 5);
        _home(b[0], s1, address(0));
        _home(b[1], s1, address(b[1]));
        _home(b[2], s1, address(b[1]), "the oldest, never the newest");
        _home(b[2], s3, address(b[2]));
    }

    function _home(UARegistry r, bytes32 ua, address want) internal view {
        _home(r, ua, want, "pqz home");
    }

    function _home(UARegistry r, bytes32 ua, address want, string memory what) internal view {
        (,, address p) = r.holderOf(ua);
        assertEq(p, want, what);
        assertEq(r.pqzHomeOf(ua), p, "pqzHomeOf: the walk's third word");
    }

    /// §11.2 (g), M4: a miss through four generations that all enable `0x0142` makes one `holderOf` call per generation (gas
    /// against the pinned per-hop figure, the library DELEGATECALL included); `pqzHomeOf` walks once too.
    function test_holderOf_oneCallPerGeneration() public {
        UARegistry[3] memory g = _line3([true, true, true]);
        UARegistry g4 = _new(address(g[2]), _one(_k(UAKinds.PQZ_MLWE, address(mock), 1_000_000)));
        bytes32 miss = keccak256("nobody");
        vm.expectCall(address(g[0]), abi.encodeCall(IUARegistry.holderOf, (miss)), 1);
        vm.expectCall(address(g[1]), abi.encodeCall(IUARegistry.holderOf, (miss)), 1);
        vm.expectCall(address(g[2]), abi.encodeCall(IUARegistry.holderOf, (miss)), 1);
        uint256 used = gasleft();
        g4.pqzHomeOf(miss);
        used -= gasleft();
        emit log_named_uint("pqzHomeOf, a miss at depth 4 (cold)", used);
        assertLe(used, 4 * HOP_GAS, "one call per generation");
    }

    /// Pinned per-hop figure of a miss (cold registry, cold library, the record slot, the thin view and its DELEGATECALL): measured
    /// 37,016 at depth 4 (2026-11-20, `pqzHomeOf`), 9,254 a hop, rounded up. A second recursive walk (O(n^2)) is ~ 2.5 times it.
    uint256 internal constant HOP_GAS = 10_000;

    /// The thin view's cost on a record held here (spec: "a few hundred gas" over the library entry), pinned.
    function test_holderOf_viewOverhead() public {
        bytes32 id = _register(reg, 0x0101, _key(0x0101));
        reg.kindOf(id); // warm the record and the account
        uint256 used = gasleft();
        reg.holderOf(id);
        used -= gasleft();
        uint256 base = gasleft();
        reg.kindOf(id);
        base -= gasleft();
        emit log_named_uint("holderOf, warm own record", used);
        emit log_named_uint("kindOf, warm own record", base);
        assertLe(used - base, VIEW_OVERHEAD_GAS, "the thin view's overhead over a plain view");
    }

    /// Measured 4,688 (holderOf 12,750 - kindOf 8,062, warm, 2026-11-20): the DELEGATECALL with its appended words, the library's
    /// `predecessor()` / `_cfgPqz` reads; the spec's "a few hundred gas" [estimate] is low by that much. Rounded up.
    uint256 internal constant VIEW_OVERHEAD_GAS = 5_000;

    /// P5: a native-space id is answered without a walk (no call to the predecessor).
    function test_nativeSpace_noWalk_noStore() public {
        UARegistry g2 = _new(address(reg), _noKinds());
        bytes32 nat = _pad(address(0xBEEF));
        vm.expectCall(address(reg), abi.encodeCall(IUARegistry.holderOf, (nat)), 0);
        vm.expectCall(address(reg), abi.encodeCall(IUARegistry.kindOf, (nat)), 0);
        (address h, uint16 k, address p) = g2.holderOf(nat);
        assertEq(h, address(0));
        assertEq(k, 0);
        assertEq(p, address(0));
        assertEq(g2.kindOf(nat), 0);
        assertFalse(g2.isRegistered(nat));
        assertEq(g2.pqzHomeOf(nat), address(0));
    }

    /// N11: each reader of a gen-1 record through gen 3 equals gen 1's answer, read at the holder directly (gen 2's reader is never
    /// called).
    function test_readers_forwardByHolder() public {
        UARegistry[3] memory g = _line3([false, false, false]);
        (bytes32 m,) = _msigOf(g[0], 6);
        bytes32 p = _register(g[0], 0x0101, _key(0x0101));
        vm.expectCall(address(g[1]), abi.encodeCall(IUARegistry.msigOf, (m)), 0);
        vm.expectCall(address(g[1]), abi.encodeCall(IUARegistry.keyOf, (p)), 0);
        vm.expectCall(address(g[1]), abi.encodeCall(IUARegistry.popOf, (p)), 0);
        assertEq(keccak256(abi.encode(g[2].msigOf(m))), keccak256(abi.encode(g[0].msigOf(m))));
        assertEq(g[2].memberAccepted(m, 0), g[0].memberAccepted(m, 0));
        assertEq(g[2].memberSigHashOf(m, 0), g[0].memberSigHashOf(m, 0));
        assertEq(g[2].keyOf(p), g[0].keyOf(p));
        assertEq(g[2].popOf(p), g[0].popOf(p));
        assertEq(g[2].uaIndex(p), g[0].uaIndex(p));
        assertEq(keccak256(abi.encode(g[2].webAuthnKeyOf(p))), keccak256(abi.encode(g[0].webAuthnKeyOf(p))));
        (uint16 k1, bytes memory d1,,,) = g[2].registrationOf(p);
        (uint16 k0, bytes memory d0,,,) = g[0].registrationOf(p);
        assertEq(k1, k0);
        assertEq(d1, d0);
        (uint64 v2, uint256 e2, uint256 a2) = g[2].msigStateOf(m);
        (uint64 v0, uint256 e0, uint256 a0) = g[0].msigStateOf(m);
        assertEq(abi.encode(v2, e2, a2), abi.encode(v0, e0, a0));
    }

    /// F12: `expandedKeyOf` forwards a record held elsewhere to its holder.
    function test_expandedKeyOf_forwards() public {
        CacheStandIn v = new CacheStandIn();
        UARegistry g1 = _new(address(0), _one(_k(UAKinds.MLDSA44, address(v), 4_250_000)));
        bytes memory pk = _pkOf(UAKinds.MLDSA44, 1);
        bytes32 id = g1.cacheExpandedKey(UAKinds.MLDSA44, pk, 0);
        address[3] memory e = g1.expandedKeyOf(id);
        bytes memory ek = abi.encodePacked(e[0]);
        bytes32 msg_ = UAKinds.uaMessage(UAKinds.MLDSA44, UAKinds.PURPOSE_POP_V2, _regDigest(id, UAKinds.MLDSA44));
        UACall.register(g1, UAKinds.MLDSA44, pk, _none(), _sig(ek, msg_), "");
        UARegistry g2 = _new(address(g1), _noKinds());
        UARegistry g3 = _new(address(g2), _noKinds());
        address[3] memory f = g3.expandedKeyOf(id);
        assertEq(f[0], e[0], "the holder's cache through gen 3");
        assertTrue(f[0] != address(0));
    }

    /// A key of `kind`'s length (the ML-DSA / FN-DSA layouts `validateKeyData` takes; the bytes are a stand-in's).
    function _pkOf(uint16 kind, uint256 salt) internal pure returns (bytes memory pk) {
        uint256 len = kind == UAKinds.MLDSA44 ? 1312 : kind == FN512 ? 897 : 1952;
        pk = new bytes(len);
        pk[0] = bytes1(uint8(salt));
        if (kind == FN512) (pk[0], pk[3]) = (bytes1(0x09), bytes1(uint8(salt % 16)));
    }

    /// §3: every `register` form of a verify-only kind reverts `UAVerifyOnly(kind)` at step 1, before its key is read.
    function test_register_verifyOnly_UAVerifyOnly() public {
        UARegistry.KindConfig[] memory b = _cfgs(address(mock));
        UARegistry.KindConfig[] memory k1 = new UARegistry.KindConfig[](b.length + 2);
        for (uint256 i; i < b.length; ++i) {
            k1[i] = b[i];
        }
        (k1[b.length], k1[b.length + 1]) =
        (_k(UAKinds.MUSIG2_BN254, address(mock), 50_000), _k(UAKinds.FROST_BN254, address(mock), 50_000));
        UARegistry g1 = _new(address(0), k1);
        UARegistry.KindConfig[] memory k2 = new UARegistry.KindConfig[](4);
        k2[0] = _vo(0x0100, _standIn(PC, 0), CAP_VO, 0);
        k2[1] = _vo(0x0101, _standIn(PC, 0), CAP_VO, 0);
        k2[2] = _vo(UAKinds.MUSIG2_BN254, _standIn(PC, 0), CAP_VO, 0);
        k2[3] = _vo(UAKinds.FROST_BN254, _standIn(PC, 0), CAP_VO, 0);
        UARegistry g2 = _new(address(g1), k2);
        IUARegistry.UAAttrs memory a;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAVerifyOnly.selector, uint16(0x0101)));
        g2.register(0x0101, hex"00", a, "", "");
        IUARegistry.WebAuthnKey memory w;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAVerifyOnly.selector, uint16(0x0100)));
        g2.registerWebAuthn(w, a, "", "");
        IUARegistry.MuSig2Key memory mk;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAVerifyOnly.selector, UAKinds.MUSIG2_BN254));
        g2.registerMuSig2(UAKinds.MUSIG2_BN254, mk, a, "", "");
        IUARegistry.FrostKey memory fk;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAVerifyOnly.selector, UAKinds.FROST_BN254));
        g2.registerFrost(UAKinds.FROST_BN254, fk, a, "", "");
        // a kind with no word here keeps `UAKindDisabled`
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, uint16(0x0102)));
        g2.register(0x0102, hex"00", a, "", "");
    }

    function test_cacheExpandedKey_verifyOnly_UAVerifyOnly() public {
        UARegistry g1 = _new(address(0), _one(_k(UAKinds.MLDSA44, address(new CacheStandIn()), 4_250_000)));
        UARegistry g2 = _new(address(g1), _one(_vo(UAKinds.MLDSA44, _standIn(PC, 0), CAP_VO, 0)));
        bytes memory pk = _pkOf(UAKinds.MLDSA44, 2);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAVerifyOnly.selector, UAKinds.MLDSA44));
        g2.cacheExpandedKey(UAKinds.MLDSA44, pk, 0);
        g1.cacheExpandedKey(UAKinds.MLDSA44, pk, 0); // the control: in the holding generation
    }

    /// CTR-UA-29: a verify-only kind's list is its home's.
    function test_lists_verifyOnly_forwardToHome() public {
        bytes32 id = _register(reg, 0x0101, _key(0x0101));
        UARegistry g2 = _new(address(reg), _one(_vo(0x0101, _standIn(PC, 0), CAP_VO, 0)));
        assertEq(g2.uaCount(0x0101), 1);
        assertEq(g2.uaAt(0x0101, 0), id);
        assertEq(g2.uaPage(0x0101, 0, 5).length, 1);
        assertEq(g2.uaIndex(id), 0);
    }

    /// P12: a single-key registration reads this generation only (no `kindOf` / `keyOwner` call below it).
    function test_identify_singleKey_noWalk() public {
        UARegistry g2 = _new(address(reg), _noKinds());
        UARegistry g3 = _new(address(g2), _one(_k(FN512, address(mock), 2_500_000)));
        bytes memory pk = _pkOf(FN512, 1);
        bytes memory pop = _pop(g3, FN512, pk);
        vm.expectCall(address(g2), abi.encodeWithSelector(IUARegistry.kindOf.selector), 0);
        vm.expectCall(address(g2), abi.encodeWithSelector(IUARegistry.keyOwner.selector), 0);
        vm.expectCall(address(g2), abi.encodeWithSelector(IUARegistry.holderOf.selector), 0);
        UACall.register(g3, FN512, pk, _none(), pop, "");
    }

    /// `msig` is re-enabled in every generation: its `UAAlreadyRegistered` covers the line.
    function test_msig_alreadyRegistered_acrossLine() public {
        UARegistry[3] memory g = _line3([false, false, false]);
        (bytes32 m, bytes memory d) = _msigOf(g[0], 7);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, m));
        UACall.register(g[2], UAKinds.MSIG, d, _none(), "", "");
    }

    /// §11.3 (W3): each view a successor reads, missing on a predecessor, is `UAConfig(0)`; the control passes.
    function test_probe_missingView_UAConfig0() public {
        bytes4[10] memory sel = [
            IUARegistry.holderOf.selector,
            IUARegistry.kindHome.selector,
            IUARegistry.verifierOf.selector,
            IUARegistry.verifyOnly.selector,
            IUARegistry.pqzHomeOf.selector,
            IUARegistry.txGasCap.selector,
            IUARegistry.expandedKeyOf.selector,
            IUARegistry.checkedOf.selector,
            IUARegistry.memberSigHashOf.selector,
            IUARegistry.msigStateOf.selector
        ];
        for (uint256 i; i < sel.length; ++i) {
            FakeRegistry f = new FakeRegistry(chainUidA, 1, address(0));
            f.setMissing(sel[i]);
            _refused(address(f), _noKinds(), 0);
        }
        _new(address(new FakeRegistry(chainUidA, 1, address(0))), _noKinds());
    }
}

/// An ML-DSA verifier stand-in on the cache path (`PRECOMPILE()` 0): `expandedKeyPart` returns 32 bytes of the key's hash, every
/// check the `MockVerifier` rule.
contract CacheStandIn is MockVerifier {
    address public constant PRECOMPILE = address(0);

    constructor() MockVerifier(0, 0) {}

    function expandedKeyPart(bytes calldata pk, uint256 part) external pure returns (bytes memory) {
        return abi.encode(keccak256(abi.encode(pk, part)));
    }

    function verifyCached(bytes calldata ek, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(ek, message, sig);
    }
}
