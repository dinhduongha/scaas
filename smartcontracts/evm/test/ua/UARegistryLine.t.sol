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

/// A registry look-alike for the constructor's walk (Review Focus 4): every view the walk reads, each settable.
contract FakeRegistry {
    bytes32 public chainUid;
    uint8 public generation;
    address public predecessor;

    constructor(bytes32 uid, uint8 g, address p) {
        (chainUid, generation, predecessor) = (uid, g, p);
    }

    function setPredecessor(address p) external {
        predecessor = p;
    }

    function hederaNative() external pure returns (bool) {}
    function kindEnabled(uint16) external pure returns (bool) {}
    function kindHome(uint16) external pure returns (address) {}
    function verifierOf(uint16) external pure returns (address) {}
    function verifyOnly(uint16) external pure returns (bool) {}
    function holderOf(bytes32) external pure returns (address, uint16, address) {}
    function pqzHomeOf(bytes32) external pure returns (address) {}
    function expandedKeyOf(bytes32) external pure returns (address[3] memory) {}

    function txGasCap() external pure returns (uint64) {
        return 1 << 24;
    }

    function checkedOf(bytes32) external pure returns (uint8, uint8, uint8) {}
    function memberSigHashOf(bytes32, uint256) external pure returns (bytes32) {}
    function msigStateOf(bytes32) external pure returns (uint64, uint256, uint256) {}
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
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, uint16(0x0101)));
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
}
