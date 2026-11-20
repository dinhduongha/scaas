// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MldsaVerifier} from "../../src/ua/MlDsa.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {PqzKeyVerifier} from "../../src/pqz/PqzKeyVerifier.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {GasBurner} from "../pqz/PqzStateGas.t.sol";
import {PqzMock} from "../pqz/helpers/PqzMock.sol";
import {UARegistryBase} from "../ua/UARegistryBase.sol";
import {UACall} from "../ua/UACall.sol";
import {SdkGasRows} from "./SdkGasOps.sol";
import {SdkGasMeter} from "./SdkGasMeter.sol";

/// The registry writes' base rows (scaas-sdk spec §13.3; controller call, owner auto-run 2026-11-19: every registry write form
/// the SDK builds has a row): real calls on the registry as a deploy configures it (G4, `SdkGasDeploy`), plus ML-DSA-87 on its
/// precompile stand-in (CTR-UA-39: enabled only where its precompile answers) and `pqz-mlwe` (0x0142) on a `PqzKeyVerifier`.
/// Stand-ins for what forge cannot execute (`stand_in` in the input list): the ML-DSA-87 precompile a `GasBurner` at the
/// calibrated 135,000 + 6 a message word, the `PQZ` precompile a `GasBurner` at the set's calibrated `REGISTER` row
/// (`test/vectors/pqz-gas/<set>.json`: row + 3 a word of its input), each less 2,900 (a cold stand-in against a warm
/// precompile). Every figure is execution gas (regular + EIP-8037 state gas), measured inside the transaction by the meter
/// (`SdkGasMetered`: a large calldata registration sits on EIP-7976's floor, which the SDK prices by the byte itself); only
/// the `fresh` lane, the registry's first write of its kind (what the SDK quotes, `fresh_only` in the input list).
///
/// Rows (kind, entry): `ua-<kind>` `register` (`registerWebAuthn` for `0x0100`), each signing kind's registration with no
/// attribute on its vector PoP (`signatures.json`, `pq_signatures.json`), plus the kind's forced worst case over its vector
/// where the verify rows measured one (`verify_<kind>_worst_extra` / `_varied_extra`; WebAuthn at ua-rs's assertion cap);
/// ML-DSA-44 / -65 on the registry's expanded-key cache (the deploy's path, `ua-<kind>` `cacheExpandedKey` each part first);
/// `kem` `register`, what a KEM key adds (the full key or its hash commit, the worse), and `kem` `setKemKey` (the fill of a
/// commit); `pqz-key` `register`, what a PQZ key adds without its proof (a split's first step), `pqz-pop` with its proof, and
/// `pqz` `storePqzPop` (a split's second step): each an addition measured on ML-DSA-87 (its PoP on the stand-in, so the
/// attributes vary under one key), the KEM key of the `mldsa87` registration blob, the set's self-test `R_REG` key and proof
/// (the PQZ key verifier's probe vector: a canonical key, the set's proof length); `msig`
/// `registerMsig`, `acceptMembership`, `updateMsig`, counted by `members` (EOA members, weight 1, threshold all of them: an
/// update signed by every member, so a member's slope holds one native signature check).
contract SdkGasRegistryTest is SdkGasRows, UARegistryBase, PqzMock {
    address internal constant ML87 = address(uint160(0x5caa0014));
    uint64 internal constant CAP_ML87 = 250_000; // `DeployBase`'s precompile path
    uint64 internal constant CAP_PQZ_MLWE = 4_500_000; // `DeployBase`'s `CAP_PQZ_MLWE`
    uint256 internal constant SG_METER_CALL = 3_038; // `SdkGasMetered`'s, held there by `_meterControl`
    uint256[4] internal SG_MSIG_N = [uint256(2), 4, 8, 16];

    SdkGasMeter internal meter;
    /// the set's self-test `R_REG` key and proof (`statement_register.json`, `proof_pqzl.json`): a canonical PQZ key and its proof
    bytes internal pqzPk;
    bytes internal pqzProof;

    /// The table is measured at the committed set (`gen_set.py`): at another set (`script/pqz/at-set.sh`) every row runs and
    /// nothing is pinned (the PQZ key and proof are the set's own), as `SdkGasConfPqzTest`.
    function _sgCommittedSet() internal view returns (string memory) {
        string memory f = vm.readFile("src/pqz/PqzSet.sol");
        return vm.split(vm.split(f, "The committed one is ")[1], ";")[0];
    }

    function _sgPinned() internal view override returns (bool) {
        return keccak256(bytes(PqzSet.NAME)) == keccak256(bytes(_sgCommittedSet()));
    }

    function test_sdkGas_registryPinnedAtTheCommittedSet() public view {
        assertEq(
            _sgPinned(),
            keccak256(bytes(PqzSet.NAME)) == keccak256("n2304-kmax4096"),
            "pinned at the committed set only"
        );
    }

    function setUp() public override {
        super.setUp();
        _sgSkaSetup(chainUidA);
        UARegistry.KindConfig[] memory keep = new UARegistry.KindConfig[](2);
        keep[0] = UARegistry.KindConfig(UAKinds.MLDSA87, address(_ml87()), CAP_ML87);
        keep[1] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(_pqzVerifier()), CAP_PQZ_MLWE);
        vm.clearMockedCalls();
        vm.etch(ML87, address(new GasBurner(135_000 + 6 - 2_900)).code);
        vm.etch(PQZ, address(new GasBurner(_regRow() - 2_900)).code);
        _sgDeployRegistry(REG_A, chainUidA, keep);
        reg = UARegistry(REG_A);
        meter = new SdkGasMeter();
    }

    // ------------------------------------------------------------------ fixture

    /// ML-DSA-87 on its precompile, its constructor's probe answered by mocks (as `SdkGasVerifyTest._withPq`).
    function _ml87() internal returns (MldsaVerifier) {
        uint256 len = 2592 + 4627;
        (bytes memory valid, bytes memory invalid) = (new bytes(len + 32), new bytes(len + 32));
        valid[0] = 0x01;
        vm.mockCall(ML87, bytes(""), abi.encode(uint256(1)));
        vm.mockCall(ML87, invalid, abi.encode(uint256(0)));
        return new MldsaVerifier(UAKinds.MLDSA87, ML87, valid, invalid);
    }

    /// The PQZ key verifier on the set's self-test `R_REG` vector, the precompile mocked for its probe (as
    /// `PqzRegistryBase._newPqzVerifier`, PQZL).
    function _pqzVerifier() internal returns (PqzKeyVerifier) {
        bytes memory st = _vecHex("statement_register.json", ".rows[0].stmt");
        bytes memory proof = _vecHex("proof_pqzl.json", ".rows[4].proof");
        _mockSelfTest();
        vm.mockCall(PQZ, abi.encodePacked(uint8(3)), abi.encode(uint256(0)));
        bytes memory input = bytes.concat(_slice(st, 0, 32), PqzSet.PQZL_ID, _slice(st, 64, PqzSet.STMT_REGISTER - 64));
        vm.mockCall(PQZ, abi.encodePacked(uint8(3), uint32(PqzSet.STMT_REGISTER), input, proof), abi.encode(uint256(1)));
        (pqzPk, pqzProof) = (_slice(st, 96, PqzSet.PK), proof);
        return new PqzKeyVerifier(PQZ, PqzSet.PQZL_ID, pqzPk, bytes32(_slice(st, 64, 32)), proof);
    }

    /// The set's calibrated `REGISTER` price: `row + 3 · ⌈input / 32⌉`.
    function _regRow() internal view returns (uint256) {
        string memory f = vm.readFile(string.concat("test/vectors/pqz-gas/", PqzSet.NAME, ".json"));
        return vm.parseJsonUint(f, ".pqzl.REGISTER.row") + 3 * ((vm.parseJsonUint(f, ".pqzl.REGISTER.input") + 31) / 32);
    }

    function _hex4(uint16 k) internal pure returns (string memory) {
        bytes memory h = "0123456789abcdef";
        return string(abi.encodePacked("0x", h[k >> 12], h[(k >> 8) & 15], h[(k >> 4) & 15], h[k & 15]));
    }

    function _ua(uint16 kind) internal pure returns (string memory) {
        return string.concat("ua-", _hex4(kind));
    }

    /// The call `cd` by the relayer through the meter (`SdkGasMetered`): its regular and state gas, nothing pinned.
    function _run(bytes memory cd) internal returns (uint256 regular, uint256 state) {
        vm.prank(SG_RELAYER);
        uint256 used = meter.measure(address(reg), cd);
        state = uint256(int256(vm.lastFrameGas().gasStateUsed));
        regular = used - SG_METER_CALL - state;
    }

    function _pinSplit(string memory key, uint256 regular, uint256 state) internal {
        _pin(string.concat(key, "_regular"), regular);
        _pin(string.concat(key, "_state"), state);
        _pin(key, regular + state);
    }

    /// `cd` measured and pinned under `key`, `extra` regular gas added (a kind's worst case over its vector).
    function _row(string memory key, bytes memory cd, uint256 extra) internal returns (uint256 regular, uint256 state) {
        (regular, state) = _run(cd);
        _pinSplit(key, regular + extra, state);
    }

    /// `key` as measured (this run's table, or the pin file).
    function _read(string memory key) internal view returns (uint256 v) {
        bool ok;
        (ok, v) = this.sgRead(key);
        assertTrue(ok, key);
    }

    /// What a kind's forced worst case adds over its vector signature's check, as the verify rows measured it: ed25519 and
    /// SLH-DSA-128s `verify_<kind>_worst_extra`, FN-DSA `verify_<kind>_varied_extra`, WebAuthn its check at ua-rs's assertion
    /// cap (`verify_0x0100_cap_row` + `verify_0x0100_origin_extra`) less its vector's (`verify_0x0100_vector`); else 0.
    function _worst(uint16 kind) internal view returns (uint256) {
        if (!_sgPinned()) return 0;
        if (kind == 0x0102 || kind == 0x0133) return _read(string.concat("verify_", _hex4(kind), "_worst_extra"));
        if (kind == 0x0132 || kind == 0x0135) return _read(string.concat("verify_", _hex4(kind), "_varied_extra"));
        if (kind == 0x0100) {
            uint256 cap = _read("verify_0x0100_cap_row") + _read("verify_0x0100_origin_extra");
            uint256 vec = _read("verify_0x0100_vector");
            assertGe(cap, vec, "the cap's check at least the vector's");
            return cap - vec;
        }
        return 0;
    }

    function _registerCd(
        uint16 kind,
        bytes memory k,
        IUARegistry.UAAttrs memory a,
        bytes memory pop,
        bytes memory pqzPop
    ) internal pure returns (bytes memory) {
        if (kind == UAKinds.WEBAUTHN_P256) {
            IUARegistry.WebAuthnKey memory w = IUARegistry.WebAuthnKey(
                bytes32(_slice(k, 0, 32)), bytes32(_slice(k, 32, 32)), bytes32(_slice(k, 64, 32))
            );
            return abi.encodeCall(IUARegistry.registerWebAuthn, (w, a, pop, pqzPop));
        }
        return abi.encodeCall(IUARegistry.register, (kind, k, a, pop, pqzPop));
    }

    /// One kind's registration with no attribute, from a snapshot: an ML-DSA kind on the cache first stores each part
    /// (`cacheExpandedKey`, measured: `ua-<kind>_cacheExpandedKey_fresh_p<part>`).
    function _kindRow(uint16 kind, bytes memory k, bytes memory pop) internal {
        uint256 s = vm.snapshotState();
        string memory entry = kind == UAKinds.WEBAUTHN_P256 ? "registerWebAuthn" : "register";
        if (kind == UAKinds.MLDSA44 || kind == UAKinds.MLDSA65) {
            for (uint256 p; p < PqUA.mldsaParts(kind); ++p) {
                _row(
                    _k(_ua(kind), "cacheExpandedKey", "fresh", string.concat("p", vm.toString(p))),
                    abi.encodeCall(IUARegistry.cacheExpandedKey, (kind, k, p)),
                    0
                );
            }
        }
        _row(_k(_ua(kind), entry, "fresh", "vector"), _registerCd(kind, k, _none(), pop, ""), _worst(kind));
        assertTrue(reg.isRegistered(UAKinds.uaOf(kind, k)), "registered");
        vm.revertToState(s);
    }

    // ------------------------------------------------------------------ the rows

    /// `ua-<kind>` `register` / `registerWebAuthn` of every signing kind the SDK registers (0x0100 - 0x0108, 0x0130 - 0x0135,
    /// 0x0141), and ML-DSA-44 / -65's `cacheExpandedKey` parts.
    function test_sdkGas_registerKinds() public {
        string memory sj = vm.readFile("../vectors/ua/signatures.json");
        uint256 rows;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".derived[", vm.toString(i), "].");
            uint16 kind = uint16(vm.parseJsonUint(sj, string.concat(r, "kind")));
            if (kind > 0x0108 && kind != 0x0141) continue;
            _kindRow(
                kind,
                vm.parseJsonBytes(sj, string.concat(r, "keyData")),
                vm.parseJsonBytes(sj, string.concat(r, "pop.sig"))
            );
            ++rows;
        }
        string memory pj = vm.readFile("../vectors/ua/pq_signatures.json");
        for (uint256 i; vm.keyExistsJson(pj, string.concat(".kinds[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".kinds[", vm.toString(i), "].");
            uint16 kind = uint16(vm.parseJsonUint(pj, string.concat(r, "kind")));
            _kindRow(
                kind,
                vm.parseJsonBytes(pj, string.concat(r, "keyData")),
                vm.parseJsonBytes(pj, string.concat(r, "pop.sig"))
            );
            ++rows;
        }
        assertEq(rows, 16, "0x0100 - 0x0108, 0x0141, 0x0130 - 0x0135");
    }

    /// The full KEM key of the registration blob `name` (`registration_blobs.json`), in a frame of its own (a 1 MB file).
    function sgKem(string calldata name) external view returns (IUARegistry.KemKey memory kem) {
        string memory j = vm.readFile("../vectors/ua/registration_blobs.json");
        for (uint256 i;; ++i) {
            string memory b = string.concat(".blobs[", vm.toString(i), "]");
            if (keccak256(bytes(vm.parseJsonString(j, string.concat(b, ".name")))) != keccak256(bytes(name))) continue;
            string memory a = string.concat(b, ".blob.args");
            kem.scheme = uint8(vm.parseJsonUint(j, string.concat(a, ".attrs.kem.scheme")));
            kem.mlkemEk = vm.parseJsonBytes(j, string.concat(a, ".attrs.kem.mlkemEk"));
            kem.x25519 = vm.parseJsonBytes32(j, string.concat(a, ".attrs.kem.x25519"));
            return kem;
        }
    }

    /// `key`: the registration with attributes `a` (and `pqzPop`) less the one without any, on the same ML-DSA-87 key, each
    /// from the snapshot `s` (left as the call left it).
    function _added(
        string memory key,
        bytes memory k,
        bytes memory pop,
        IUARegistry.UAAttrs memory a,
        bytes memory pqzPop,
        uint256 s
    ) internal {
        vm.revertToState(s);
        (uint256 r0, uint256 s0) = _run(_registerCd(UAKinds.MLDSA87, k, _none(), pop, ""));
        vm.revertToState(s);
        (uint256 r1, uint256 s1) = _run(_registerCd(UAKinds.MLDSA87, k, a, pop, pqzPop));
        assertGt(r1, r0, "the attribute adds regular gas");
        assertGt(s1, s0, "the attribute adds state");
        _pinSplit(key, r1 - r0, s1 - s0);
    }

    /// `kem` / `pqz-key` / `pqz-pop` `register` (what an attribute adds), `kem` `setKemKey` and `pqz` `storePqzPop`.
    function test_sdkGas_registerAttrs() public {
        string memory pj = vm.readFile("../vectors/ua/pq_signatures.json");
        string memory r = ".kinds[4].";
        assertEq(vm.parseJsonUint(pj, string.concat(r, "kind")), UAKinds.MLDSA87, "pq_signatures.json kinds[4]");
        bytes memory k = vm.parseJsonBytes(pj, string.concat(r, "keyData"));
        bytes memory pop = vm.parseJsonBytes(pj, string.concat(r, "pop.sig"));
        bytes32 ua = UAKinds.uaOf(UAKinds.MLDSA87, k);
        IUARegistry.KemKey memory kem = this.sgKem("mldsa87");
        (bytes memory pqzKey, bytes memory pqzPop) = (pqzPk, pqzProof);
        assertEq(pqzKey.length, PqzSet.PK, "the set's PQZ key");
        uint256 s = vm.snapshotState();

        IUARegistry.UAAttrs memory full;
        full.kem = kem;
        _added("kem_register_fresh_full", k, pop, full, "", s);
        IUARegistry.UAAttrs memory commit = UACall.commit(full);
        _added("kem_register_fresh_commit", k, pop, commit, "", s);
        IUARegistry.UASig memory none;
        _row("kem_setKemKey_fresh_commit", abi.encodeCall(IUARegistry.setKemKey, (ua, uint64(0), kem, none)), 0);
        (, IUARegistry.KemKey memory stored) = _kemAt(ua);
        assertEq(stored.scheme, kem.scheme, "the commit filled");

        IUARegistry.UAAttrs memory p;
        (p.pqzKey, p.pqzPopHash) = (pqzKey, keccak256(pqzPop));
        _added("pqz-key_register_fresh_mldsa87", k, pop, p, "", s);
        _row("pqz_storePqzPop_fresh_mldsa87", abi.encodeCall(IUARegistry.storePqzPop, (ua, uint64(0), pqzPop)), 0);
        assertGt(reg.pqzPopOf(ua, 0).length, 0, "the proof stored");
        _added("pqz-pop_register_fresh_mldsa87", k, pop, p, pqzPop, s);
        assertGt(reg.pqzPopOf(ua, 0).length, 0, "the proof stored at registration");
        vm.revertToState(s);
    }

    function _kemAt(bytes32 ua) internal view returns (bytes memory sig, IUARegistry.KemKey memory kem) {
        (kem, sig) = reg.kemKeyAt(ua, 0);
    }

    // ------------------------------------------------------------------ msig

    /// `n` EOA members (secrets `0x5100 + i`), weight 1, threshold `n`: the key data and each member's secret by slot.
    function _eoaMsig(uint256 n) internal pure returns (bytes memory d, uint256[] memory sk) {
        Member[] memory m = new Member[](n);
        for (uint256 i; i < n; ++i) {
            m[i] = Member(UAKinds.EVM_EOA, _pad(vm.addr(0x5100 + i)), 1);
        }
        d = _msigKey(uint16(n), m); // sorts `m` by id
        sk = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            for (uint256 j; j < n; ++j) {
                if (_pad(vm.addr(0x5100 + j)) == m[i].id) sk[i] = 0x5100 + j;
            }
        }
    }

    function _registerMsigCd(bytes memory d) internal pure returns (bytes memory) {
        return abi.encodeCall(
            IUARegistry.registerMsig, (UACall.structure(d), _none(), new IUARegistry.MemberSig[](0), bytes(""))
        );
    }

    /// The line of a counted row over its points `g` at `SG_MSIG_N`: the steepest slope between neighbours (rounded up),
    /// the intercept the largest `g(n) - slope · n`, so the line is at or above every point; pinned as
    /// `<kind>_<entry>_per_item_<variant>` and `<kind>_<entry>_fresh_<variant>`.
    function _line(string memory kind, string memory entry, string memory variant, uint256[4] memory g) internal {
        if (!_sgPinned()) return;
        uint256 s;
        for (uint256 i = 1; i < 4; ++i) {
            assertGe(g[i], g[i - 1], "the cost grows with the count");
            uint256 d = SG_MSIG_N[i] - SG_MSIG_N[i - 1];
            uint256 c = (g[i] - g[i - 1] + d - 1) / d;
            if (c > s) s = c;
        }
        assertGt(s, 0, "a counted row's slope");
        uint256 b;
        for (uint256 i; i < 4; ++i) {
            assertGe(g[i], s * SG_MSIG_N[i], "a positive intercept");
            if (g[i] - s * SG_MSIG_N[i] > b) b = g[i] - s * SG_MSIG_N[i];
        }
        for (uint256 i; i < 4; ++i) {
            assertGe(b + s * SG_MSIG_N[i], g[i], "the line at or above every point");
        }
        _pin(string.concat(kind, "_", entry, "_per_item_", variant), s);
        _pin(string.concat(kind, "_", entry, "_fresh_", variant), b);
    }

    /// The `msig` rows at n = 2, 4, 8, 16 members (keys `msig_<entry>_n<n>_fresh_native`): `registerMsig` (the registry's
    /// first `msig`, no `pop`: an EOA structure is not PQ-eligible), the last slot's `acceptMembership` (the first), then
    /// with every slot accepted the first `updateMsig` (the same structure, every slot enabled, signed by all `n`).
    function test_sdkGas_msig() public {
        uint256[4][3] memory g;
        for (uint256 i; i < 4; ++i) {
            uint256 n = SG_MSIG_N[i];
            sgCountTag = string.concat("n", vm.toString(n), "_");
            (bytes memory d, uint256[] memory sk) = _eoaMsig(n);
            bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
            uint256 snap = vm.snapshotState();
            (uint256 r, uint256 st) = _row(_k("msig", "registerMsig", "fresh", "native"), _registerMsigCd(d), 0);
            g[0][i] = r + st;
            (r, st) = _row(
                _k("msig", "acceptMembership", "fresh", "native"),
                abi.encodeCall(IUARegistry.acceptMembership, (ua, _acceptEoaSig(d, sk[n - 1]))),
                0
            );
            g[1][i] = r + st;
            for (uint256 j; j + 1 < n; ++j) {
                reg.acceptMembership(ua, _acceptEoaSig(d, sk[j]));
            }
            (r, st) = _row(_k("msig", "updateMsig", "fresh", "native"), _updateCd(ua, sk), 0);
            g[2][i] = r + st;
            (uint64 v,,) = reg.msigStateOf(ua);
            assertEq(v, 1, "updated");
            vm.revertToState(snap);
        }
        sgCountTag = "";
        _line("msig", "registerMsig", "native", g[0]);
        _line("msig", "acceptMembership", "native", g[1]);
        _line("msig", "updateMsig", "native", g[2]);
    }

    /// `updateMsig` of `ua` to its own structure, every slot enabled, version 1, signed by every slot (`sk` by slot) over the
    /// typed `UAMsigUpdate` (a native member signs the typed digest itself).
    function _updateCd(bytes32 ua, uint256[] memory sk) internal view returns (bytes memory) {
        IUARegistry.MsigStructure memory st = reg.msigOf(ua);
        uint256 enabled = (uint256(1) << st.members.length) - 1;
        uint64 until = uint64(block.number + 100);
        bytes32 typed = UAKinds.msigUpdateDigest(ua, chainUidA, address(reg), 1, st, enabled, until);
        IUARegistry.MemberSig[] memory sigs = new IUARegistry.MemberSig[](sk.length);
        for (uint256 i; i < sk.length; ++i) {
            sigs[i] = IUARegistry.MemberSig(uint16(i), new IUARegistry.InnerSig[](0), _ecdsa(sk[i], typed));
        }
        return abi.encodeCall(IUARegistry.updateMsig, (ua, uint64(1), st, enabled, until, sigs, chainUidA));
    }
}
