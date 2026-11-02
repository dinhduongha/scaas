// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm, VmSafe} from "forge-std/Vm.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IUAPopVerifier} from "../../src/ua/IUAVerifier.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UARegistryLib} from "../../src/ua/UARegistryLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UAMldsaVerifier} from "../../src/ua/MlDsa.sol";
import {UAFndsaVerifier} from "../../src/ua/FnDsa.sol";
import {UASlhdsaVerifier} from "../../src/ua/SlhDsa.sol";
import {P256Verifier} from "../../src/ua/verifiers/P256Verifier.sol";
import {WebAuthnP256Verifier} from "../../src/ua/verifiers/WebAuthnP256Verifier.sol";
import {Bip340Verifier} from "../../src/ua/verifiers/Bip340Verifier.sol";
import {Secp256k1Verifier} from "../../src/ua/verifiers/Secp256k1Verifier.sol";
import {Ed25519Verifier} from "../../src/ua/verifiers/Ed25519Verifier.sol";
import {
    SchnorrBn254Verifier,
    SchnorrBls12381Verifier,
    BlsMinSigBls12381Verifier,
    BlsMinSigBn254Verifier,
    ZetherSchnorrBls12381Verifier
} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {UARegistryBase, MockWallet} from "./UARegistryBase.sol";
import {AcceptAll, BurnAll} from "./UAGas.t.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {UACall} from "./UACall.sol";
import {SplitDiff} from "./SplitDiff.sol";

/// The PQZ tokens' key gate (`PqzCore._keyPtr`) against a given registry.
/// A gen 1 from before UA-8: the constructor's checks pass, but no UA-8 view (review n3).
contract PreUa8Gen1 {
    bytes32 public immutable chainUid;

    constructor(bytes32 chainUid_) {
        chainUid = chainUid_;
    }

    function generation() external pure returns (uint8) {
        return 1;
    }

    function hederaNative() external pure returns (bool) {
        return false;
    }

    function kindEnabled(uint16) external pure returns (bool) {
        return false;
    }
}

contract KeyPtrHarness {
    function keyPtr(address registry, bytes32 ua) external view returns (address) {
        return PqzCore._keyPtr(registry, ua);
    }
}

/// `UARegistryLib._sigOk` exposed (ruling A5-m3: the portable-purpose guard); `cfg` is the entry's `_cfg(kind)`.
contract SigOkHarness is UARegistry {
    constructor(bytes32 uid, uint64 budget, KindConfig[] memory k)
        UARegistry(uid, address(0), false, budget, address(0), true, k)
    {}

    function sigOk(uint256 cfg, uint16 kind, bytes memory d, bytes32 ua, bytes32 purpose, bytes32 digest, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return UARegistryLib._sigOk(cfg, kind, d, ua, purpose, digest, sig, new IUARegistry.MemberSig[](0));
    }
}

/// Spends `burn` gas and accepts: the 0x0142 slot at the cost of the real `R_REG` verify, which the precompile-free tests lack.
contract BurnAccept {
    uint256 public immutable burn;

    constructor(uint256 b) {
        burn = b;
    }

    function verifyPop(bytes calldata, bytes32, bytes calldata) external view returns (bool) {
        uint256 start = gasleft();
        while (start - gasleft() < burn) {}
        return true;
    }
}

/// `SSTORE2.writeChunks` / `readChunks` behind a storage array.
contract ChunkHarness {
    address[] internal ptrs;

    function put(bytes memory data) external returns (uint256) {
        ptrs = SSTORE2.writeChunks(data);
        return ptrs.length;
    }

    function get() external view returns (bytes memory) {
        return SSTORE2.readChunks(ptrs);
    }

    function sizes() external view returns (uint256[] memory s) {
        s = new uint256[](ptrs.length);
        for (uint256 i; i < s.length; ++i) s[i] = ptrs[i].code.length - 1;
    }
}

/// UA-8 Tasks A5 / A6 (spec 2026-10-25-ua8-portable-registrations P1–P3, P6, P8, P9; UA8-D2, D4, D7–D11; rulings C1,
/// C2, C7, C8, A1-I1, A4-c2, A4-c3, A5-c2): `register` on the portable digest with every field stored, the optional
/// PQZ proof (`storePqzPop`) and the later PQZ key (`setPqzKey`), on smartcontracts/vectors/ua/portable.json.
/// Real verifiers for every kind except `mldsa65`, which runs on its precompile path with the precompile mocked per
/// exact input (`pk ‖ sig ‖ pq_msg` of each vector signature: any other byte is refused), so a PQ-eligible `msig` of two
/// `mldsa65` members fits the PQZ holder bound; the `0x0142` slot is empty (PQZ keys unproven) unless a test sets the
/// stand-in, which accepts exactly the row's `R_REG` message.
contract UARegistryUA8Test is UARegistryBase {
    struct Row {
        string name;
        string set;
        uint16 kind;
        bytes keyData;
        bytes32 ua;
        IUARegistry.UAAttrs attrs; // the KEM key as `KemKey` (TS-D11)
        bytes kemPk; // portable.json `attrs.kemPk`: the assembled key bytes
        bytes pop;
        bytes pqzPop;
        bytes32 popMessage;
        bytes32 pqzRegMessage;
    }

    struct Neg {
        string name;
        string entry;
        string err;
        string row;
        string[] keys;
        bytes[] values;
    }

    string internal constant PJ = "../vectors/ua/portable.json";
    address internal constant ML65 = 0x000000000000000000000000000000005CAa0013;
    address internal constant REG_B = 0x5cB0000000000000000000000000000000000002;
    uint256 internal constant ML65_LEN = 1952 + 3309 + 32;
    uint64 internal constant CAP_MLDSA44 = 4_250_000;
    uint64 internal constant CAP_FNDSA = 2_500_000;
    uint64 internal constant CAP_SLHDSA = 1_400_000;
    // the row indexes of portable.json `registrations` (asserted by name where used)
    uint256 internal constant P256_ROW = 1;
    uint256 internal constant SECP_ROW = 4;
    uint256 internal constant ML65_1 = 11;
    uint256 internal constant FNDSA_ROW = 17;
    uint256 internal constant SLH_ROW = 18;
    uint256 internal constant MSIG_NATIVE_ROW = 24;

    bytes32 internal chainUidB;
    UARegistry.KindConfig[] internal vcfg; // the vector verifiers, deployed once per test
    address internal rreg; // the 0x0142 stand-in

    function setUp() public override {
        super.setUp();
        chainUidB = vm.parseJsonBytes32(_structures(), ".contexts.B.chainUid");
        _deployVerifiers();
    }

    // ----- portable.json, read in a frame of its own (a 2.5 MB string per cheatcode call) -----

    /// Moves a parsed `bytes` result down over the cheatcode's argument copy, so the frame's memory stays one file wide.
    function _jb(string memory j, string memory k) internal pure returns (bytes memory r) {
        uint256 fp;
        assembly {
            fp := mload(0x40)
        }
        bytes memory v = vm.parseJsonBytes(j, k);
        assembly {
            let n := add(mload(v), 32)
            mcopy(fp, v, n)
            r := fp
            mstore(0x40, add(fp, and(add(n, 31), not(31))))
        }
    }

    function _js(string memory j, string memory k) internal pure returns (string memory) {
        return string(_jbRaw(j, k));
    }

    function _jbRaw(string memory j, string memory k) internal pure returns (bytes memory r) {
        uint256 fp;
        assembly {
            fp := mload(0x40)
        }
        bytes memory v = bytes(vm.parseJsonString(j, k));
        assembly {
            let n := add(mload(v), 32)
            mcopy(fp, v, n)
            r := fp
            mstore(0x40, add(fp, and(add(n, 31), not(31))))
        }
    }

    function _jw(string memory j, string memory k) internal pure returns (bytes32 w) {
        uint256 fp;
        assembly {
            fp := mload(0x40)
        }
        w = vm.parseJsonBytes32(j, k);
        assembly {
            mstore(0x40, fp)
        }
    }

    function _ju(string memory j, string memory k) internal pure returns (uint256 u) {
        uint256 fp;
        assembly {
            fp := mload(0x40)
        }
        u = vm.parseJsonUint(j, k);
        assembly {
            mstore(0x40, fp)
        }
    }

    function _jx(string memory j, string memory k) internal view returns (bool e) {
        uint256 fp;
        assembly {
            fp := mload(0x40)
        }
        e = vm.keyExistsJson(j, k);
        assembly {
            mstore(0x40, fp)
        }
    }

    function _parseRow(string memory j, string memory p) internal pure returns (Row memory r) {
        r.name = _js(j, string.concat(p, ".name"));
        r.set = _js(j, string.concat(p, ".set"));
        r.kind = uint16(_ju(j, string.concat(p, ".kind")));
        r.keyData = _jb(j, string.concat(p, ".keyData"));
        r.ua = _jw(j, string.concat(p, ".ua"));
        r.attrs.pqzKey = _jb(j, string.concat(p, ".attrs.pqzKey"));
        r.attrs.pqzPopHash = _jw(j, string.concat(p, ".attrs.pqzPopHash"));
        r.kemPk = _jb(j, string.concat(p, ".attrs.kemPk"));
        r.attrs.kem = UACall.kem(r.kemPk);
        r.pop = _jb(j, string.concat(p, ".pop"));
        r.pqzPop = _jb(j, string.concat(p, ".pqzPop"));
        r.popMessage = _jw(j, string.concat(p, ".popMessage"));
        r.pqzRegMessage = _jw(j, string.concat(p, ".pqzRegMessage"));
    }

    function loadRows() external view returns (Row[] memory rows) {
        string memory j = vm.readFile(PJ);
        uint256 n;
        while (_jx(j, string.concat(".registrations[", vm.toString(n), "]"))) ++n;
        rows = new Row[](n);
        for (uint256 i; i < n; ++i) rows[i] = _parseRow(j, string.concat(".registrations[", vm.toString(i), "]"));
    }

    function loadNegs() external view returns (Neg[] memory negs) {
        string memory j = vm.readFile(PJ);
        uint256 n;
        while (_jx(j, string.concat(".negatives[", vm.toString(n), "]"))) ++n;
        negs = new Neg[](n);
        for (uint256 i; i < n; ++i) {
            string memory p = string.concat(".negatives[", vm.toString(i), "]");
            Neg memory g = negs[i];
            g.name = _js(j, string.concat(p, ".name"));
            if (_jx(j, string.concat(p, ".rule"))) continue; // a full registration, no mutation of a row: its own test
            g.entry = _js(j, string.concat(p, ".entry"));
            g.err = _js(j, string.concat(p, ".error"));
            if (
                !_eq(g.entry, "register") && !_eq(g.entry, "storePqzPop") && !_eq(g.entry, "setPqzKey")
                    && !_eq(g.entry, "setKemKey")
            ) continue;
            g.row = _js(j, string.concat(p, ".mutation.row"));
            g.keys = vm.parseJsonKeys(j, string.concat(p, ".mutation.set"));
            g.values = new bytes[](g.keys.length);
            for (uint256 k; k < g.keys.length; ++k) {
                string memory f = string.concat(p, ".mutation.set['", g.keys[k], "']");
                g.values[k] = _jb(j, f);
            }
        }
    }

    function _rows() internal view returns (Row[] memory rows) {
        rows = this.loadRows();
        assertEq(rows.length, 25, "registrations");
        assertEq(rows[P256_ROW].name, "p256");
        assertEq(rows[SECP_ROW].name, "secp256k1");
        assertEq(rows[ML65_1].name, "mldsa65#1");
        assertEq(rows[FNDSA_ROW].name, "fndsa512");
        assertEq(rows[SLH_ROW].name, "slhdsa128s");
        assertEq(rows[MSIG_NATIVE_ROW].name, "msig-pq-native");
    }

    function _find(Row[] memory rows, string memory name) internal pure returns (Row memory) {
        for (uint256 i; i < rows.length; ++i) {
            if (keccak256(bytes(rows[i].name)) == keccak256(bytes(name))) return rows[i];
        }
        revert(string.concat("no row ", name));
    }

    function _setName() internal pure returns (string memory) {
        return PqzSet.NAME;
    }

    // ----- registries -----

    /// The vector verifiers: real ones, `mldsa65` through the exact-input precompile mock (probe pinned as in
    /// `PqzRegistryBase`).
    function _deployVerifiers() internal {
        bytes memory valid = new bytes(ML65_LEN);
        valid[0] = 0x01;
        vm.mockCall(ML65, valid, abi.encode(uint256(1)));
        vm.mockCall(ML65, new bytes(ML65_LEN), abi.encode(uint256(0)));
        address[8] memory v = [
            address(new WebAuthnP256Verifier()),
            address(new P256Verifier()),
            address(new Ed25519Verifier()),
            address(new Bip340Verifier()),
            address(new SchnorrBn254Verifier()),
            address(new SchnorrBls12381Verifier()),
            address(new BlsMinSigBls12381Verifier()),
            address(new BlsMinSigBn254Verifier())
        ];
        for (uint256 i; i < 8; ++i) vcfg.push(UARegistry.KindConfig(KINDS[i], v[i], _cap(KINDS[i])));
        vcfg.push(UARegistry.KindConfig(0x0108, address(new Secp256k1Verifier()), 50_000));
        vcfg.push(UARegistry.KindConfig(0x0141, address(new ZetherSchnorrBls12381Verifier()), 70_000));
        vcfg.push(UARegistry.KindConfig(0x0130, address(new UAMldsaVerifier(0x0130, address(0), "", "")), CAP_MLDSA44));
        UAMldsaVerifier m65 = new UAMldsaVerifier(0x0131, ML65, valid, new bytes(ML65_LEN));
        assertEq(m65.PRECOMPILE(), ML65);
        vcfg.push(UARegistry.KindConfig(0x0131, address(m65), 100_000));
        vcfg.push(UARegistry.KindConfig(0x0132, address(new UAFndsaVerifier()), CAP_FNDSA));
        vcfg.push(UARegistry.KindConfig(0x0133, address(new UASlhdsaVerifier()), CAP_SLHDSA));
        rreg = makeAddr("rreg");
        vm.etch(rreg, hex"00"); // STOP: any input the test did not allow returns nothing (refused)
    }

    /// The vector verifiers, without `drop` (0 = none), with the 0x0142 stand-in if `pqz`.
    function _vcfg(uint16 drop, bool pqz) internal view returns (UARegistry.KindConfig[] memory c) {
        uint256 n;
        c = new UARegistry.KindConfig[](vcfg.length + 1);
        for (uint256 i; i < vcfg.length; ++i) {
            if (vcfg[i].kind != drop) c[n++] = vcfg[i];
        }
        if (pqz) c[n++] = UARegistry.KindConfig(0x0142, rreg, 1_000_000);
        assembly {
            mstore(c, n)
        }
    }

    /// Registry A (chain 31337, context A) or B (chain 7622, another chain uid and address).
    function _regA(bool pqz) internal returns (UARegistry) {
        vm.chainId(31337);
        return _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, pqz));
    }

    function _regB() internal returns (UARegistry r) {
        vm.chainId(7622);
        r = _deploy(REG_B, chainUidB, address(0), false, BUDGET, address(0), true, _vcfg(0, false));
        vm.chainId(31337);
    }

    // ----- the mocked mldsa65 precompile: exactly the vectors' signatures -----

    function _allowMl65(bytes memory pk, bytes32 uaMsg, bytes memory sig) internal {
        bytes32 pq = PqUA.pqMessage(PqUA.tag(UAKinds.MLDSA65), uaMsg);
        vm.mockCall(ML65, abi.encodePacked(pk, sig, pq), abi.encode(uint256(1)));
    }

    /// Every `mldsa65` signature of the rows: the signer's `pop`, and each `mldsa65` member's signature inside an
    /// `msig` pop (under `member`, over `memberDigest(ua, popMessage)`).
    function _allowAll(Row[] memory rows) internal {
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            if (r.kind == UAKinds.MLDSA65) _allowMl65(r.keyData, r.popMessage, r.pop);
            if (r.kind != UAKinds.MSIG || r.pop.length == 0) continue;
            _allowMembers(rows, r.keyData, UAKinds.memberDigest(r.ua, r.popMessage), r.pop);
        }
    }

    /// Each `mldsa65` member signature of the `MemberSig[]` blob `sigs` of the `msig` `d` over `md` (under `member`).
    function _allowMembers(Row[] memory rows, bytes memory d, bytes32 md, bytes memory sigs) internal {
        IUARegistry.MemberSig[] memory s = UACall.memberSigs(sigs);
        for (uint256 k; k < s.length; ++k) {
            (uint16 kind, bytes32 id) = _member(d, s[k].index);
            if (kind != UAKinds.MLDSA65) continue;
            _allowMl65(_byUa(rows, id).keyData, UAKinds.uaMessage(UAKinds.MLDSA65, UAKinds.PURPOSE_MEMBER, md), s[k].sig);
        }
    }

    function _byUa(Row[] memory rows, bytes32 ua) internal pure returns (Row memory) {
        for (uint256 i; i < rows.length; ++i) {
            if (rows[i].ua == ua) return rows[i];
        }
        revert("no member row");
    }

    function _member(bytes memory d, uint256 index) internal pure returns (uint16 kind, bytes32 id) {
        uint256 o = 4 + 36 * index;
        kind = uint16(bytes2(abi.encodePacked(d[o], d[o + 1])));
        assembly {
            id := mload(add(add(d, 34), o))
        }
    }

    /// The 0x0142 stand-in accepts exactly `R_REG(pqzKey, pqzRegMessage, pqzPop)` of `r`.
    function _allowPqz(Row memory r) internal {
        vm.mockCall(
            rreg,
            abi.encodeCall(IUAPopVerifier.verifyPop, (r.attrs.pqzKey, r.pqzRegMessage, r.pqzPop)),
            abi.encode(uint256(1))
        );
    }

    // ----- registering rows -----

    /// `register` with the row's arguments (the ML-DSA-44 cache first: it verifies without a precompile).
    function _reg(UARegistry r, Row memory row) internal returns (bytes32 ua) {
        if (row.kind == UAKinds.MLDSA44 && r.expandedKeyOf(row.ua)[0] == address(0)) {
            r.cacheExpandedKey(UAKinds.MLDSA44, row.keyData, 0);
        }
        ua = UACall.register(r, row.kind, row.keyData, row.attrs, row.pop, row.pqzPop);
        assertEq(ua, row.ua, row.name);
        _assertRecord(r, row);
    }

    function _args(Row memory row) internal pure returns (bytes memory) {
        return abi.encode(row.kind, row.keyData, row.attrs, row.pop, row.pqzPop);
    }

    function _stored(UARegistry r, bytes32 ua) internal view returns (bytes memory) {
        (uint16 k, bytes memory d, IUARegistry.UAAttrs memory a, bytes memory p, bytes memory z) = r.registrationOf(ua);
        return abi.encode(k, d, a, p, z);
    }

    /// `registrationOf` returns exactly the `register` arguments; the per-field views agree.
    function _assertRecord(UARegistry r, Row memory row) internal view {
        assertEq(keccak256(_stored(r, row.ua)), keccak256(_args(row)), string.concat(row.name, ": registrationOf"));
        assertEq(r.kindOf(row.ua), row.kind);
        assertEq(r.popOf(row.ua), row.pop);
        assertEq(r.pqzPopOf(row.ua), row.pqzPop);
        (address ptr, bytes32 ph, bool proven) = r.pqzKeyOf(row.ua);
        assertEq(ptr.code, row.attrs.pqzKey.length == 0 ? bytes("") : bytes.concat(hex"00", row.attrs.pqzKey));
        assertEq(ph, row.attrs.pqzPopHash);
        (uint64 v, IUARegistry.KemKey memory pk, bytes memory sig) = r.kemKeyOf(row.ua);
        assertEq(v, 0, "the register KEM key is version 0 (owner 2026-10-31)");
        assertEq(UACall.kemPk(pk), row.kemPk);
        assertEq(sig, "", "the initial KEM record has no signature (UA8-D4)");
        (uint8 cp, uint8 cq, uint8 ck) = r.checkedOf(row.ua);
        assertEq(cp, UAKinds.CHECKED_CHAIN);
        assertEq(cq, proven ? UAKinds.CHECKED_CHAIN : UAKinds.CHECKED_NONE);
        assertEq(ck, row.kemPk.length != 0 ? UAKinds.CHECKED_CHAIN : UAKinds.CHECKED_NONE);
    }

    /// The rows an `msig` names as members (registered first) and nothing else: p256, schnorr-bn254, bls-bn254-minsig
    /// (msig-classical), mldsa65#1, mldsa65#2 (msig-pq, msig-pq-native).
    function _members(UARegistry r, Row[] memory rows) internal {
        uint256[5] memory m = [uint256(1), 5, 8, 11, 12];
        for (uint256 i; i < 5; ++i) _reg(r, rows[m[i]]);
    }

    /// Every set-free row (single keys first, then the msigs) and the rows of this build's parameter set.
    function _registerAll(UARegistry r, Row[] memory rows) internal returns (uint256 n) {
        for (uint256 pass; pass < 2; ++pass) {
            for (uint256 i; i < rows.length; ++i) {
                bool here = bytes(rows[i].set).length == 0 || keccak256(bytes(rows[i].set)) == keccak256(bytes(_setName()));
                if (here && (rows[i].kind == UAKinds.MSIG) == (pass == 1)) {
                    _reg(r, rows[i]);
                    ++n;
                }
            }
        }
    }

    // ----- Step 1 tests -----

    /// A11 / UA8-D16: the four UA-8 registry writes keep these selectors; scaas-node's `ua8_registry_writes_are_call_jobs`
    /// pins the same literals, so an ABI change fails a test on both sides. typed-signing R1 (TS-D10 … TS-D12): the
    /// explicit ABI moved `register`, `setKemKey`, `setPqzKey` and added `registerMsig`; R1b (TS-D13) added
    /// `registerWebAuthn`, `registerMuSig2`, `registerFrost`.
    function test_ua8_writeSelectorsPinned() public pure {
        assert(IUARegistry.register.selector == bytes4(0x4e229efb));
        assert(IUARegistry.registerMsig.selector == bytes4(0x82b86a46));
        assert(IUARegistry.registerWebAuthn.selector == bytes4(0xee03a1fe));
        assert(IUARegistry.registerMuSig2.selector == bytes4(0xe1eddcdf));
        assert(IUARegistry.registerFrost.selector == bytes4(0x7bd63410));
        assert(IUARegistry.setKemKey.selector == bytes4(0xa00cce2a));
        assert(IUARegistry.storePqzPop.selector == bytes4(0x7fac161a));
        assert(IUARegistry.setPqzKey.selector == bytes4(0x3c6897f1));
        assert(IUARegistry.acceptMembership.selector == bytes4(0x73fd7d54));
        assert(IUARegistry.requireAuthorized.selector == bytes4(0x58d5ff4f));
    }

    /// TS-D5 (owner 2026-10-31): `kindName` answers every kind id of kinds.json (and the scheme 0x0142), enabled or not.
    function test_kindNameEveryKind() public {
        UARegistry a = _regA(false);
        string memory j = vm.readFile("../vectors/ua/kinds.json");
        uint256 n;
        for (; vm.keyExistsJson(j, string.concat(".kinds[", vm.toString(n), "]")); ++n) {
            string memory p = string.concat(".kinds[", vm.toString(n), "]");
            uint16 kind = uint16(vm.parseJsonUint(j, string.concat(p, ".kind")));
            assertEq(a.kindName(kind), vm.parseJsonString(j, string.concat(p, ".name")));
        }
        assertEq(n, 31);
        assertEq(a.kindName(uint16(vm.parseJsonUint(j, ".schemes[0].kind"))), vm.parseJsonString(j, ".schemes[0].name"));
        assertFalse(a.kindEnabled(0x0011));
        assertEq(a.kindName(0x0011), "stellar-account");
    }

    /// TS-D5: an unknown id reverts `UAKindUnknown(kind)`.
    function test_kindNameUnknownReverts() public {
        UARegistry a = _regA(false);
        uint16[4] memory unknown = [uint16(0x0000), 0x0109, 0x0140, 0xffff];
        for (uint256 i; i < 4; ++i) {
            vm.expectRevert(abi.encodeWithSelector(UAKinds.UAKindUnknown.selector, unknown[i]));
            a.kindName(unknown[i]);
        }
    }

    /// P1 / P10: the same arguments register on two registries with different chain ids, chain uids and addresses.
    function test_ua8_copyBetweenRegistries() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry a = _regA(false);
        UARegistry b = _regB();
        assertTrue(a.chainUid() != b.chainUid() && address(a) != address(b) && a.chainKeyHash() != b.chainKeyHash());
        uint256 na = _registerAll(a, rows);
        vm.chainId(7622);
        uint256 nb = _registerAll(b, rows);
        vm.chainId(31337);
        assertEq(na, 19, "17 set-free rows + 2 of this set");
        assertEq(nb, na);
        for (uint256 i; i < rows.length; ++i) {
            if (a.kindOf(rows[i].ua) == 0) continue;
            assertEq(keccak256(_stored(a, rows[i].ua)), keccak256(_stored(b, rows[i].ua)), rows[i].name);
        }
    }

    /// P2: a record rebuilt from A's state alone (`registrationOf`) is submitted to B by a third party; B's record and
    /// its `registrationOf` bytes equal A's.
    function test_ua8_copyFromState() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry a = _regA(false);
        UARegistry b = _regB();
        _registerAll(a, rows);
        _members(b, rows);
        string[4] memory names = [string("fndsa512"), "slhdsa128s", "msig-pq-native", "zether-bls12381"];
        Row[] memory copied = new Row[](6);
        for (uint256 i; i < 4; ++i) copied[i] = _find(rows, names[i]);
        copied[4] = _find(rows, string.concat("mldsa65/", _setName()));
        copied[5] = _find(rows, string.concat("msig-pq/", _setName()));
        vm.chainId(7622);
        for (uint256 i; i < copied.length; ++i) {
            bytes32 ua = copied[i].ua;
            (uint16 k, bytes memory d, IUARegistry.UAAttrs memory att, bytes memory p, bytes memory z) = a.registrationOf(ua);
            vm.prank(address(0xC0B1E5), address(0xC0B1E5));
            assertEq(UACall.register(b, k, d, att, p, z), ua);
            assertEq(keccak256(_stored(b, ua)), keccak256(_stored(a, ua)), copied[i].name);
            assertEq(b.keyOf(ua), a.keyOf(ua));
            (IUARegistry.Record memory ra,) = a.recordOf(ua);
            (IUARegistry.Record memory rb,) = b.recordOf(ua);
            assertEq(ra.kind, rb.kind);
            _assertRecord(b, copied[i]);
        }
        vm.chainId(31337);
    }

    /// Every portable.json registration row registers with its own arguments (msig members first; the four parameter
    /// sets' rows each in a state of their own: they share their UA ids).
    function test_ua8_everyKindFromVectors() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry a = _regA(false);
        uint256 n;
        for (uint256 pass; pass < 2; ++pass) {
            for (uint256 i; i < rows.length; ++i) {
                if (bytes(rows[i].set).length == 0 && (rows[i].kind == UAKinds.MSIG) == (pass == 1)) {
                    _reg(a, rows[i]);
                    ++n;
                }
            }
        }
        string[4] memory sets = [string("n2048-kmax1024"), "n2304-kmax4096", "n2560-kmax16384", "n2816-kmax65536"];
        for (uint256 s; s < 4; ++s) {
            uint256 snap = vm.snapshotState();
            for (uint256 i; i < rows.length; ++i) {
                if (keccak256(bytes(rows[i].set)) == keccak256(bytes(sets[s]))) {
                    _reg(a, rows[i]);
                    ++n;
                }
            }
            vm.revertToState(snap);
        }
        assertEq(n, 25, "every row");
    }

    /// P3: a kind whose slot is empty in the target registry is refused like any registration of a disabled kind.
    function test_ua8_disabledKindReverts() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        uint16[3] memory off = [uint16(0x0132), 0x0133, 0x0108];
        uint256[3] memory row = [FNDSA_ROW, SLH_ROW, SECP_ROW];
        for (uint256 i; i < 3; ++i) {
            UARegistry r =
                _deploy(address(uint160(0x5ce70 + i)), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(off[i], false));
            Row memory x = rows[row[i]];
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, off[i]));
            UACall.register(r, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
        }
        UARegistry noMsig = _deploy(address(0x5ce7f), chainUidA, address(0), false, BUDGET, address(0), false, _vcfg(0, false));
        Row memory m = rows[MSIG_NATIVE_ROW];
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, UAKinds.MSIG));
        UACall.register(noMsig, m.kind, m.keyData, m.attrs, m.pop, m.pqzPop);
    }

    /// UA8-D2: a PQ-eligible `msig`'s m-of-n PoP (derived members under `member`) is portable: the same bytes register
    /// on both registries.
    function test_ua8_msigPqEligibleCopy() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry a = _regA(false);
        UARegistry b = _regB();
        _members(a, rows);
        _members(b, rows);
        Row memory m = _find(rows, string.concat("msig-pq/", _setName()));
        _reg(a, m);
        vm.chainId(7622);
        _reg(b, m);
        vm.chainId(31337);
        assertEq(keccak256(_stored(a, m.ua)), keccak256(_stored(b, m.ua)));
    }

    /// Ruling C7 (D6 overridden) as amended by typed-signing TS-D4 (owner decision 4): a code-less native member signs
    /// the record's typed digest (`eth_signTypedData_v4` of the `UARegistration`), so the same native-member `msig`
    /// registration is accepted on two registries with different chain ids. A UAAuth-framed native signature inside a
    /// portable pop, a malformed signature (high s, 64 bytes, v 0 / 1) are `UAPoP`; the portable member signature never
    /// passes `requireAuthorized`, under any purpose.
    function test_msigNativeMemberTypedDigest() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory m = rows[MSIG_NATIVE_ROW];
        UARegistry a = _regA(false);
        UARegistry b = _regB();
        _members(a, rows);
        _members(b, rows);
        // the vector's native member signature recovers to the member over the typed registration digest
        bytes32 rd = _regDigest(m.ua, UAKinds.MSIG, m.attrs);
        assertEq(UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_POP_V2, rd), m.popMessage);
        IUARegistry.MemberSig[] memory s = UACall.memberSigs(m.pop);
        (uint16 k0, bytes32 id0) = _member(m.keyData, s[0].index);
        assertEq(k0, UAKinds.EVM_EOA, "member 0 is the native one");
        assertEq(ECDSA.recover(rd, s[0].sig), address(uint160(uint256(id0))));
        _malformedNativeSig(a, m);
        Neg memory g = _neg("native-uaauth-in-portable-pop");
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(a, m.kind, m.keyData, m.attrs, g.values[0], m.pqzPop);
        // the vector's typed pop: accepted on A and on B
        _reg(a, m);
        vm.chainId(7622);
        _reg(b, m);
        vm.chainId(31337);
        assertEq(keccak256(_stored(a, m.ua)), keccak256(_stored(b, m.ua)));
        _portableNotForRequireAuthorized(a, m, rd);
    }

    /// TS-D4: the pre-typed native member form is refused (`UAPoP`): portable.json's `native-member-personal-sign`
    /// (EIP-191 `personal_sign` of `memberDigest`), and the member's own key by `personal_sign` of the typed digest or
    /// over the raw `memberDigest`.
    function test_msigNativeMemberPersonalSignRefused() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory m = rows[MSIG_NATIVE_ROW];
        UARegistry a = _regA(false);
        _members(a, rows);
        Neg memory g = _neg("native-member-personal-sign");
        assertEq(g.err, "UAPoP");
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(a, m.kind, m.keyData, m.attrs, g.values[0], m.pqzPop);
        uint256 sk = _nativeSk();
        bytes32 rd = _regDigest(m.ua, UAKinds.MSIG, m.attrs);
        bytes32 md = UAKinds.memberDigest(m.ua, m.popMessage);
        bytes32[3] memory wrong =
            [MessageHashUtils.toEthSignedMessageHash(md), MessageHashUtils.toEthSignedMessageHash(rd), md];
        IUARegistry.MemberSig[] memory s = UACall.memberSigs(m.pop);
        for (uint256 i; i < 3; ++i) {
            s[0].sig = _ecdsa(sk, wrong[i]);
            bytes memory pop = abi.encode(s);
            vm.expectRevert(IUARegistry.UAPoP.selector);
            UACall.register(a, m.kind, m.keyData, m.attrs, pop, m.pqzPop);
        }
        _reg(a, m);
    }

    /// High s, 64 bytes, v 0 and v 1 for the native member's typed signature: `UAPoP`.
    function _malformedNativeSig(UARegistry a, Row memory m) internal {
        IUARegistry.MemberSig[] memory s = UACall.memberSigs(m.pop);
        (uint16 k0,) = _member(m.keyData, s[0].index);
        assertEq(k0, UAKinds.EVM_EOA, "member 0 is the native one");
        bytes memory good = s[0].sig;
        assertEq(good.length, 65);
        (bytes32 r_, bytes32 s_, uint8 v_) = (bytes32(_slice(good, 0, 32)), bytes32(_slice(good, 32, 32)), uint8(good[64]));
        bytes[4] memory bad = [
            abi.encodePacked(r_, bytes32(SECP_N - uint256(s_)), v_ == 27 ? uint8(28) : uint8(27)), // high s
            abi.encodePacked(r_, s_), // 64 bytes
            abi.encodePacked(r_, s_, v_ - 27), // v 0 / 1
            abi.encodePacked(r_, s_, v_ == 27 ? uint8(1) : uint8(0))
        ];
        for (uint256 i; i < 4; ++i) {
            s[0].sig = bad[i];
            bytes memory pop = abi.encode(s);
            vm.expectRevert(IUARegistry.UAPoP.selector);
            UACall.register(a, m.kind, m.keyData, m.attrs, pop, m.pqzPop);
        }
    }

    /// `requireAuthorized` keeps UAAuth for native members: the very pop as an auth under PURPOSE_POP_V2 is refused, the
    /// same set with the member's UAAuth signature passes; portable.json's personal_sign member under metatx is refused.
    function _portableNotForRequireAuthorized(UARegistry a, Row memory m, bytes32 rd) internal {
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, m.ua));
        a.requireAuthorized(m.ua, UAKinds.PURPOSE_POP_V2, rd, UACall.auth(m.ua, abi.encode(m.keyData, m.pop)));
        IUARegistry.MemberSig[] memory s = UACall.memberSigs(m.pop);
        s[0].sig = _nativeSig(a, _nativeSk(), UAKinds.PURPOSE_MEMBER, UAKinds.memberDigest(m.ua, m.popMessage));
        a.requireAuthorized(m.ua, UAKinds.PURPOSE_POP_V2, rd, UACall.auth(m.ua, abi.encode(m.keyData, abi.encode(s))));
        (bytes32 purpose, bytes32 dg, bytes memory auth) = this.loadAuthNeg();
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, m.ua));
        a.requireAuthorized(m.ua, purpose, dg, UACall.auth(m.ua, auth));
    }

    /// A native member with code (a contract wallet; not an EIP-7702 designator, which is an EOA: own key only, ruling
    /// D1, `test_ua8_msigNativeMember7702Portable`) answers ERC-1271 `isValidSignature(typedDigest, sig)` in a portable
    /// pop (TS-D4); its key's signature is not asked, and a wallet signature over `memberDigest` is refused.
    function test_msigContractMember1271OverTypedDigest() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory m = rows[MSIG_NATIVE_ROW];
        UARegistry a = _regA(false);
        _members(a, rows);
        (, bytes32 id) = _member(m.keyData, 0);
        uint256 ownerSk = 0xA11CE;
        MockWallet w = new MockWallet(vm.addr(ownerSk), 0, 0, address(a));
        vm.etch(address(uint160(uint256(id))), address(w).code);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(a, m.kind, m.keyData, m.attrs, m.pop, m.pqzPop); // the key's typed pop: code ⇒ ERC-1271 only
        IUARegistry.MemberSig[] memory s = UACall.memberSigs(m.pop);
        s[0].sig = _ecdsa(ownerSk, UAKinds.memberDigest(m.ua, m.popMessage));
        bytes memory overMd = abi.encode(s);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(a, m.kind, m.keyData, m.attrs, overMd, m.pqzPop);
        s[0].sig = _ecdsa(ownerSk, _regDigest(m.ua, UAKinds.MSIG, m.attrs));
        assertEq(UACall.register(a, m.kind, m.keyData, m.attrs, abi.encode(s), m.pqzPop), m.ua);
    }

    // ----- U8S-D1 (owner 2026-10-31): a stored msig signature is minimal, every slot necessary -----

    function _one(IUARegistry.MemberSig memory s) internal pure returns (IUARegistry.MemberSig[] memory one) {
        one = new IUARegistry.MemberSig[](1);
        one[0] = s;
    }

    /// 2-of-(mldsa65#1 w1, mldsa65#2 w2): both slots verify and the old rule passes (1, then 3 >= 2), but the weight-2
    /// slot alone reaches the threshold. `pop` signs both slots; `d` / `ua` are the structure and its UA.
    function _notMinimal(Row[] memory rows) internal returns (bytes memory d, bytes32 ua, bytes memory pop) {
        Member[] memory mm = new Member[](2);
        mm[0] = Member(UAKinds.MLDSA65, rows[ML65_1].ua, 1);
        mm[1] = Member(UAKinds.MLDSA65, rows[ML65_1 + 1].ua, 2);
        d = _msigKey(2, mm);
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
        pop = _msigSigs(rows, d, ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG), 0, 1, 0);
    }

    /// The not-minimal `msig` registered by its weight-2 slot alone (the minimal `pop`).
    function _notMinimalRegistered()
        internal
        returns (UARegistry a, Row[] memory rows, bytes memory d, bytes32 ua, IUARegistry.MemberSig[] memory slots)
    {
        rows = _rows();
        _allowAll(rows);
        bytes memory pop;
        (d, ua, pop) = _notMinimal(rows);
        a = _regA(false);
        _members(a, rows);
        slots = UACall.memberSigs(pop);
        assertEq(UACall.register(a, UAKinds.MSIG, d, _none(), abi.encode(_one(slots[1])), ""), ua);
        _acceptSlot(a, rows, d, ua, 0, 0); // the `pop` signer is accepted, the weight-1 slot accepts: the rule under test decides
    }

    /// Slot `index` of `d` accepts (CTR-UA-37), `sk` for a native member.
    function _acceptSlot(UARegistry a, Row[] memory rows, bytes memory d, bytes32 ua, uint256 index, uint256 sk) internal {
        (, bytes32 id) = _member(d, index);
        bytes32 typed = UAKinds.membershipDigest(ua, id);
        bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBERSHIP, typed));
        a.acceptMembership(ua, IUARegistry.MemberSig(uint16(index), new IUARegistry.InnerSig[](0), _memberSig(rows, d, index, md, typed, sk)));
    }

    /// Both slots verify and the old rule passes, but the weight-2 slot alone reaches the threshold: `UAPoP`. The weight-1
    /// slot alone is below it; the weight-2 slot alone registers.
    function test_msigPopNotMinimalRefused() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        (bytes memory d, bytes32 ua, bytes memory pop) = _notMinimal(rows);
        UARegistry a = _regA(false);
        _members(a, rows);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(a, UAKinds.MSIG, d, _none(), pop, "");
        IUARegistry.MemberSig[] memory s = UACall.memberSigs(pop);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(a, UAKinds.MSIG, d, _none(), abi.encode(_one(s[0])), "");
        assertEq(UACall.register(a, UAKinds.MSIG, d, _none(), abi.encode(_one(s[1])), ""), ua);
    }

    /// The KEM record of that `msig`: both slots are `UAUnauthorized`, the weight-2 slot lands.
    function test_msigKemSigNotMinimalRefused() public {
        (UARegistry a, Row[] memory rows, bytes memory d, bytes32 ua,) = _notMinimalRegistered();
        bytes memory pk = _kemPk(41);
        bytes memory sig = _msigSigs(rows, d, ua, UAKinds.PURPOSE_KEM, UAKinds.kemRecordDigest(ua, 1, pk), 0, 1, 0);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        a.setKemKey(ua, 1, UACall.kem(pk), UACall.sig(sig));
        bytes memory one = abi.encode(_one(UACall.memberSigs(sig)[1]));
        a.setKemKey(ua, 1, UACall.kem(pk), UACall.sig(one));
        _assertKemAt(a, ua, 1, pk, one);
    }

    /// The PQZ key record of the same `msig`: both slots are `UAUnauthorized`, the weight-2 slot lands.
    function test_msigPqzKeySigNotMinimalRefused() public {
        (UARegistry a, Row[] memory rows, bytes memory d, bytes32 ua,) = _notMinimalRegistered();
        Row memory x = _pqzRow(rows);
        bytes32 rd = UAKinds.pqzKeyRecordDigest(ua, _h(x.attrs.pqzKey), x.attrs.pqzPopHash);
        bytes memory sig = _msigSigs(rows, d, ua, UAKinds.PURPOSE_PQZ_KEY, rd, 0, 1, 0);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        a.setPqzKey(ua, x.attrs.pqzKey, x.attrs.pqzPopHash, UACall.sig(sig));
        bytes memory one = abi.encode(_one(UACall.memberSigs(sig)[1]));
        a.setPqzKey(ua, x.attrs.pqzKey, x.attrs.pqzPopHash, UACall.sig(one));
        assertEq(a.pqzKeySigOf(ua), one);
    }

    /// U8S-D1 scope: a transaction authorisation is not stored and keeps the old rule: the same redundant set passes
    /// `requireAuthorized`, as does the weight-2 slot alone.
    function test_msigRequireAuthorizedKeepsRule() public {
        (UARegistry a, Row[] memory rows, bytes memory d, bytes32 ua,) = _notMinimalRegistered();
        bytes32 dg = keccak256("a metatx digest");
        bytes memory sig = _msigSigs(rows, d, ua, UAKinds.PURPOSE_METATX, dg, 0, 1, 0);
        a.requireAuthorized(ua, UAKinds.PURPOSE_METATX, dg, UACall.sig(sig));
        a.requireAuthorized(ua, UAKinds.PURPOSE_METATX, dg, UACall.sig(abi.encode(_one(UACall.memberSigs(sig)[1]))));
    }

    /// The minimal `pop` of portable.json's `msig-pq-native` (2-of-2) minus either slot is refused, and so is a slot added
    /// to a minimal `pop` of 2-of-(1, 1, 1): nobody re-shapes a `pop` into another stored one (final review A-m1).
    function test_msigFrontRunSlotDropRefused() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory m = rows[MSIG_NATIVE_ROW];
        UARegistry a = _regA(false);
        _members(a, rows);
        IUARegistry.MemberSig[] memory s = UACall.memberSigs(m.pop);
        for (uint256 i; i < 2; ++i) {
            vm.expectRevert(IUARegistry.UAPoP.selector);
            UACall.register(a, m.kind, m.keyData, m.attrs, abi.encode(_one(s[i])), m.pqzPop);
        }
        Member[] memory mm = new Member[](3);
        mm[0] = Member(UAKinds.MLDSA65, rows[ML65_1].ua, 1);
        mm[1] = Member(UAKinds.MLDSA65, rows[ML65_1 + 1].ua, 1);
        mm[2] = Member(UAKinds.EVM_EOA, _pad(vm.addr(_nativeSk())), 1);
        bytes memory d = _msigKey(2, mm);
        bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 rd = _regDigest(ua, UAKinds.MSIG);
        bytes memory pop = _msigSigs(rows, d, ua, UAKinds.PURPOSE_POP_V2, rd, 0, 1, _nativeSk());
        bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_POP_V2, rd));
        IUARegistry.MemberSig[] memory p = UACall.memberSigs(pop);
        IUARegistry.MemberSig[] memory extra = new IUARegistry.MemberSig[](3);
        (extra[0], extra[1]) = (p[0], p[1]);
        extra[2] = IUARegistry.MemberSig(2, new IUARegistry.InnerSig[](0), _memberSig(rows, d, 2, md, rd, _nativeSk()));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(a, UAKinds.MSIG, d, _none(), abi.encode(extra), "");
        assertEq(UACall.register(a, UAKinds.MSIG, d, _none(), pop, ""), ua);
    }

    /// CTR-UA-37: every `memberships` row of portable.json by its real verifier: the digests against the contract's, then the
    /// signature accepted on a registry where the `msig` is registered without a `pop`-signed slot of that member. `msig-pq-native`
    /// is PQ-eligible and its `pop` accepts both slots, so its rows are checked at the member's own verify and read accepted.
    function test_membershipVectors() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        vm.pauseGasMetering();
        string memory j = vm.readFile("../vectors/ua/portable.json");
        vm.resumeGasMetering();
        UARegistry a = _regA(false);
        _members(a, rows);
        Row memory classical = _find(rows, "msig-classical");
        Row memory native = rows[MSIG_NATIVE_ROW];
        assertEq(UACall.register(a, UAKinds.MSIG, classical.keyData, _none(), "", ""), classical.ua);
        assertEq(UACall.register(a, UAKinds.MSIG, native.keyData, native.attrs, native.pop, native.pqzPop), native.ua);
        for (uint256 i; i < 6; ++i) _membershipRow(a, rows, j, string.concat(".memberships[", vm.toString(i), "]."), classical.ua);
    }

    function _membershipRow(UARegistry a, Row[] memory rows, string memory j, string memory p, bytes32 classical) internal {
        bytes32 ua = vm.parseJsonBytes32(j, string.concat(p, "ua"));
        bytes32 member = vm.parseJsonBytes32(j, string.concat(p, "member"));
        uint16 index = uint16(vm.parseJsonUint(j, string.concat(p, "index")));
        uint16 kind = uint16(vm.parseJsonUint(j, string.concat(p, "memberKind")));
        bytes memory sig = vm.parseJsonBytes(j, string.concat(p, "sig"));
        bytes32 typed = UAKinds.membershipDigest(ua, member);
        bytes32 message = UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBERSHIP, typed);
        bytes32 md = UAKinds.memberDigest(ua, message);
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "digest")), typed, "digest");
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "message")), message, "message");
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "memberDigest")), md, "memberDigest");
        if (ua == classical) {
            assertFalse(a.memberAccepted(ua, index));
            vm.expectEmit(address(a));
            emit IUARegistry.UAMembershipAccepted(ua, index, member);
            a.acceptMembership(ua, IUARegistry.MemberSig(index, new IUARegistry.InnerSig[](0), sig));
        } else if (kind == UAKinds.EVM_EOA) {
            assertEq(ECDSA.recover(typed, sig), address(uint160(uint256(member))));
        } else {
            _allowMl65(_byUa(rows, member).keyData, UAKinds.uaMessage(kind, UAKinds.PURPOSE_MEMBER, md), sig);
            a.requireAuthorized(member, UAKinds.PURPOSE_MEMBER, md, UACall.sig(sig));
        }
        assertTrue(a.memberAccepted(ua, index), "accepted");
    }

    /// Review focus 2: stripping or swapping `pqzKey`, `pqzPopHash`, `kemVersion` or `kemPk` (portable.json negatives
    /// with error `UAPoP`) is `UAPoP`.
    function test_ua8_popCoversAttrs() public {
        // + native-member-personal-sign, record-kind-mismatch, kem-record-as-registration (typed-signing P1)
        assertEq(_runNegatives(_errs("UAPoP", "", "", "")), 22, "UAPoP negatives");
    }

    /// The attribute shape: a PQZ key with its proof hash and only with it, proof bytes hashing to it, a PQZ key of a
    /// set's length, a 1,601-byte scheme-1 KEM key — before the PoP. Also: proof bytes without a key.
    function test_ua8_attrsShapeRefused() public {
        assertEq(_runNegatives(_errs("UAPqzPopHash", "UAKeyData", "UAKemKeyLength", "")), 16);
        Row[] memory rows = _rows();
        UARegistry a = _deploy(address(0x5ce60), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, false));
        Row memory p = rows[P256_ROW];
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzPopHash.selector, p.ua));
        UACall.register(a, p.kind, p.keyData, p.attrs, p.pop, hex"01");
    }

    /// CTR-UA-32: portable.json's scheme negatives (no scheme byte, reserved scheme 2, unknown id) are `UAKemScheme`.
    function test_ua8_kemSchemeRefused() public {
        assertEq(_runNegatives(_errs("UAKemScheme", "", "", "")), 3);
    }

    /// Only the PQ holders carry a PQZ key or a KEM record (UA-6 U3, UA8-D12): portable.json's holder negatives, and
    /// `slhdsa128s` with a KEM record.
    function test_ua8_nonHolderAttrsRefused() public {
        assertEq(_runNegatives(_errs("UAPqzHolder", "UAKemHolder", "", "")), 6);
        Row[] memory rows = _rows();
        UARegistry a = _deploy(address(0x5ce61), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, false));
        Row memory s = rows[SLH_ROW];
        s.attrs.kem = rows[FNDSA_ROW].attrs.kem;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemHolder.selector, s.ua));
        UACall.register(a, s.kind, s.keyData, s.attrs, s.pop, s.pqzPop);
    }

    /// The registration is the UA's: a front-runner submitting the same arguments first gets exactly the record the
    /// UA signed (nothing is taken from `msg.sender` / `tx.origin`), and the UA's own submission then reverts
    /// `UAAlreadyRegistered`.
    function test_ua8_frontRunnerGetsIdenticalRecord() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry a = _regA(false);
        Row[2] memory xs = [rows[FNDSA_ROW], _find(rows, string.concat("mldsa65/", _setName()))];
        for (uint256 i; i < 2; ++i) {
            Row memory x = xs[i];
            vm.prank(address(0xBAD), address(0xBAD));
            UACall.register(a, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
            _assertRecord(a, x);
            vm.prank(address(0x600D), address(0x600D));
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, x.ua));
            UACall.register(a, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
        }
    }

    /// P2 / UA8-D7: every field in state and in the event; `keyData` stored once: the code `register` creates is the
    /// stored kinds' `keyPtr`, the PQZ key, the proof chunks, the KEM record and the registration blob
    /// `abi.encode(keyRest, pop)` (typed-signing R1: no KEM version word), nothing else.
    function test_ua8_storesEveryField() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry a = _regA(false);
        Row[2] memory xs = [rows[P256_ROW], _find(rows, string.concat("mldsa65/", _setName()))];
        uint256[2] memory vk = [uint256(0), 1952]; // p256 is not stored (its keyData all in the blob); mldsa65 is
        for (uint256 i; i < 2; ++i) {
            Row memory x = xs[i];
            uint64 v; // the register KEM key is version 0 (owner 2026-10-31)
            vm.expectEmit(true, true, false, true, address(a));
            emit IUARegistry.UARegistered(x.ua, x.kind, x.keyData, x.attrs, keccak256(x.pop), x.pqzPop, UAKinds.CHECKED_CHAIN,
                UAKinds.CHECKED_NONE, x.kemPk.length == 0 ? UAKinds.CHECKED_NONE : UAKinds.CHECKED_CHAIN);
            vm.startStateDiffRecording();
            UACall.register(a, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
            (uint256 created, uint256 bytes_) = _created(vm.stopAndReturnStateDiff());
            _assertRecord(a, x);
            uint256 rest = x.keyData.length - vk[i];
            uint256 blob = abi.encode(_slice(x.keyData, vk[i], rest), x.pop).length;
            uint256 want = vk[i] + x.attrs.pqzKey.length + x.pqzPop.length + x.kemPk.length + blob;
            assertEq(bytes_, want, "created code = keyPtr + pqzKey + pqzPop + KEM record + blob");
            assertEq(created, (vk[i] == 0 ? 0 : 1) + (x.attrs.pqzKey.length == 0 ? 0 : 1) + _chunks(x.pqzPop.length)
                + _chunks(x.kemPk.length) + _chunks(blob));
            assertEq(a.keyOf(x.ua), vk[i] == 0 ? bytes("") : x.keyData);
            (IUARegistry.KemKey memory pk, bytes memory sig) = a.kemKeyAt(x.ua, v);
            assertEq(UACall.kemPk(pk), x.kemPk);
            assertEq(sig, "");
            (pk, sig) = a.kemKeyAt(x.ua, v + 1);
            assertEq(UACall.kemPk(pk).length + sig.length, 0, "a version not stored");
            (, address zp) = a.recordOf(x.ua);
            (address ptr,,) = a.pqzKeyOf(x.ua);
            assertEq(zp, ptr, "recordOf's pointer, proven or not (UA8-D9)");
        }
        assertEq(a.uaCount(UAKinds.PQZ_MLWE), 0, "an unproven key is not listed (UA8-D8)");
    }

    /// Ruling C8 / UA8-D10: `checkedOf` = (CHAIN, proven ? CHAIN : NONE, KEM ? CHAIN : NONE); NONE for an unregistered
    /// id. With the 0x0142 verifier the row's proof is checked over its portable `R_REG` message (only that message is
    /// accepted): proven, the key's owner and the `0x0142` list set; without the proof bytes, or without the verifier,
    /// the key is stored unproven and claims nothing (UA8-D8).
    function test_ua8_checkedIsChain() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _find(rows, string.concat("mldsa65/", _setName()));
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, x.attrs.pqzKey);
        UARegistry a = _regA(false);
        (uint8 cp, uint8 cq, uint8 ck) = a.checkedOf(x.ua);
        assertEq(uint256(cp) + cq + ck, 0, "unregistered");
        // no verifier: unproven, the proof bytes stored
        UACall.register(a, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
        (cp, cq, ck) = a.checkedOf(x.ua);
        assertEq(abi.encode(cp, cq, ck), abi.encode(1, 0, 1));
        assertEq(a.pqzPopOf(x.ua), x.pqzPop);
        assertEq(a.keyOwner(h), bytes32(0));
        (cp, cq, ck) = a.checkedOf(rows[P256_ROW].ua);
        assertEq(uint256(cp) + cq + ck, 0);
        // with the verifier: a proof it refuses (not yet allowed) is UAPoP
        UARegistry p = _deploy(address(0x5ce80), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, true));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(p, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
        // proven: R_REG accepted over the row's portable message
        _allowPqz(x);
        vm.expectEmit(true, false, false, true, address(p));
        emit IUARegistry.UAPqzPopStored(x.ua, UAKinds.CHECKED_CHAIN, ""); // the bytes: in UARegistered
        vm.expectEmit(true, true, false, true, address(p));
        emit IUARegistry.UARegistered(x.ua, x.kind, x.keyData, x.attrs, keccak256(x.pop), x.pqzPop, 1, 1, 1);
        UACall.register(p, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
        (cp, cq, ck) = p.checkedOf(x.ua);
        assertEq(abi.encode(cp, cq, ck), abi.encode(1, 1, 1));
        (,, bool proven) = p.pqzKeyOf(x.ua);
        assertTrue(proven);
        assertEq(p.keyOwner(h), x.ua);
        assertEq(p.uaCount(UAKinds.PQZ_MLWE), 1);
        assertEq(p.uaAt(UAKinds.PQZ_MLWE, 0), x.ua);
        // unproven: no proof bytes in register (the verifier is there)
        UARegistry q = _deploy(address(0x5ce81), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, true));
        vm.expectEmit(true, true, false, true, address(q));
        emit IUARegistry.UARegistered(x.ua, x.kind, x.keyData, x.attrs, keccak256(x.pop), "", 1, 0, 1);
        UACall.register(q, x.kind, x.keyData, x.attrs, x.pop, "");
        (cp, cq, ck) = q.checkedOf(x.ua);
        assertEq(abi.encode(cp, cq, ck), abi.encode(1, 0, 1));
        assertEq(q.keyOwner(h), bytes32(0));
        assertEq(q.uaCount(UAKinds.PQZ_MLWE), 0);
        assertEq(q.pqzPopOf(x.ua), "");
    }

    /// UA8-D11: gen 2 forwards every UA-8 read of a record gen 1 holds.
    function test_ua8_gen2ForwardsReads() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry g1 = _regA(false);
        UARegistry g2 = _deploy(address(0x5ce90), chainUidA, address(g1), false, BUDGET, address(0), true,
            new UARegistry.KindConfig[](0));
        Row[2] memory xs = [rows[FNDSA_ROW], _find(rows, string.concat("mldsa65/", _setName()))];
        for (uint256 i; i < 2; ++i) {
            Row memory x = xs[i];
            _reg(g1, x);
            _assertRecord(g2, x);
            assertEq(keccak256(_stored(g2, x.ua)), keccak256(_stored(g1, x.ua)));
            (IUARegistry.KemKey memory pk, bytes memory sig) = g2.kemKeyAt(x.ua, 0);
            assertEq(abi.encode(UACall.kemPk(pk), sig), abi.encode(x.kemPk, bytes("")));
            (address p1, bytes32 h1, bool v1) = g1.pqzKeyOf(x.ua);
            (address p2, bytes32 h2, bool v2) = g2.pqzKeyOf(x.ua);
            assertEq(abi.encode(p1, h1, v1), abi.encode(p2, h2, v2));
        }
        (uint8 cp, uint8 cq, uint8 ck) = g2.checkedOf(rows[P256_ROW].ua);
        assertEq(uint256(cp) + cq + ck, 0);
    }

    /// UA8-D7: `writeChunks` / `readChunks` round trip at the chunk edges.
    function test_ua8_blobChunksRoundTrip() public {
        ChunkHarness c = new ChunkHarness();
        uint256[5] memory lens = [uint256(0), 1, 32_768, 32_769, 100_000];
        uint256[5] memory n = [uint256(0), 1, 1, 2, 4];
        for (uint256 i; i < 5; ++i) {
            bytes memory d = new bytes(lens[i]);
            for (uint256 o; o < d.length; o += 32) {
                bytes32 w = keccak256(abi.encode(i, o));
                for (uint256 k; k < 32 && o + k < d.length; ++k) d[o + k] = w[k];
            }
            assertEq(c.put(d), n[i]);
            assertEq(c.get(), d);
            uint256[] memory s = c.sizes();
            for (uint256 k; k < s.length; ++k) assertEq(s[k], k + 1 < s.length ? 32_768 : lens[i] - 32_768 * k);
        }
        assertEq(SSTORE2.BLOB_CHUNK, 32_768);
    }

    /// UA8-D7: the largest `msig` PoP the gas bound admits is stored and read back: `UAGas.t.sol`'s 8 × `slhdsa128s`
    /// + 1 `SmartKeyAccount` clone at `verifyBudget` (the clone answers ERC-1271 over `memberDigest`), and 12 ×
    /// `slhdsa128s` on a registry with a larger budget (over 64 KiB: more than one code blob).
    function test_ua8_largestMsigPopStored() public {
        BurnAll impl = new BurnAll();
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0133, address(new BurnAll()), 1_400_000);
        address clone = address(0x5cf40);
        vm.etch(clone, abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"));
        uint256 bound = 8 * (1_400_000 + 45_000) + 400_000 + 45_000 + uint256(1_400_000 - 400_000) / 63 + 2_500;
        UARegistry r = _deploy(address(0x5cea0), chainUidA, address(0), false, uint64(bound), address(impl), true, c);
        Member[] memory m = new Member[](9);
        for (uint256 i; i < 8; ++i) {
            m[i] = Member(0x0133, UACall.register(r, 0x0133, abi.encodePacked(keccak256(abi.encode("slh", i))), _none(), hex"01", ""), 1);
        }
        m[8] = Member(UAKinds.EVM_EOA, _pad(clone), 1);
        _storedPop(r, _msigKey(9, m), 9);
        // 12 members, a budget that admits them
        c[0].verifier = address(new AcceptAll());
        UARegistry big = _deploy(address(0x5cea1), chainUidA, address(0), false, uint64(12 * 1_445_000 + uint256(1_000_000) / 63 + 2_500),
            address(0), true, c);
        Member[] memory m12 = new Member[](12);
        for (uint256 i; i < 12; ++i) {
            m12[i] = Member(0x0133, UACall.register(big, 0x0133, abi.encodePacked(keccak256(abi.encode("slh12", i))), _none(), hex"01", ""), 1);
        }
        _storedPop(big, _msigKey(12, m12), 12);
    }

    function _storedPop(UARegistry r, bytes memory d, uint16 n) internal {
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](n);
        for (uint16 j; j < n; ++j) s[j] = IUARegistry.MemberSig(j, new IUARegistry.InnerSig[](0), new bytes(7_856));
        bytes memory pop = abi.encode(s);
        bytes32 ua = UACall.register(r, UAKinds.MSIG, d, _none(), pop, "");
        assertEq(r.popOf(ua), pop);
        (, bytes memory kd,, bytes memory p,) = r.registrationOf(ua);
        assertEq(kd, d);
        assertEq(p, pop);
        emit log_named_uint(string.concat("msig pop stored, members ", vm.toString(n), ", bytes"), pop.length);
        assertGt(pop.length, n == 12 ? 65_536 : 32_768);
    }

    // ----- fix round 1 (review A5: m1, m2, m3) -----

    /// m1: a front-runner may drop the optional `pqzPop` (P8): on a registry with the verifier the record is the UA's
    /// signed one with the key unproven (no owner, not listed) until `storePqzPop` (A6) adds the proof that hashes to
    /// the signed `pqzPopHash`; the UA's full submission is then `UAAlreadyRegistered`.
    function test_ua8_frontRunnerDropsPqzPop() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _find(rows, string.concat("mldsa65/", _setName()));
        _allowPqz(x);
        UARegistry p = _regA(true);
        vm.prank(address(0xBAD), address(0xBAD));
        UACall.register(p, x.kind, x.keyData, x.attrs, x.pop, "");
        Row memory dropped = _apply(x, Neg("", "", "", "", new string[](0), new bytes[](0)));
        dropped.pqzPop = "";
        _assertRecord(p, dropped);
        (,, bool proven) = p.pqzKeyOf(x.ua);
        assertFalse(proven);
        assertEq(p.keyOwner(UAKinds.keyHashOf(UAKinds.PQZ_MLWE, x.attrs.pqzKey)), bytes32(0));
        assertEq(p.uaCount(UAKinds.PQZ_MLWE), 0);
        (, bytes32 ph,) = p.pqzKeyOf(x.ua);
        assertEq(ph, keccak256(x.pqzPop), "the signed proof hash: storePqzPop can only add these bytes");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, x.ua));
        UACall.register(p, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
    }

    /// Owner ruling 2026-10-30 ("an EOA must really sign, no delegation"; supersedes R-7702 and A5-m m2): a native member
    /// with an EIP-7702 designator (an EOA delegated to a wallet) in a portable pop is an EOA: only its own key's
    /// signature over the typed digest (the vector's pop, TS-D4) is accepted; ERC-1271 through the delegate is never
    /// asked, even for a signature the delegate itself accepts, and the own key over `memberDigest` is refused (`UAPoP`).
    function test_ua8_msigNativeMember7702Portable() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory m = rows[MSIG_NATIVE_ROW];
        UARegistry a = _regA(false);
        _members(a, rows);
        uint256 sk = _nativeSk();
        _delegate(m, sk, 0x5E55);
        IUARegistry.MemberSig[] memory s = UACall.memberSigs(m.pop);
        bytes32 md = UAKinds.memberDigest(m.ua, m.popMessage);
        bytes32 rd = _regDigest(m.ua, UAKinds.MSIG, m.attrs);
        s[0].sig = _ecdsa(0x5E55, rd);
        (, bytes32 id) = _member(m.keyData, 0);
        assertEq(IERC1271(address(uint160(uint256(id)))).isValidSignature(rd, s[0].sig), IERC1271.isValidSignature.selector,
            "the delegate would accept it");
        bytes memory viaDelegate = abi.encode(s);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(a, m.kind, m.keyData, m.attrs, viaDelegate, m.pqzPop);
        s[0].sig = _ecdsa(sk, md); // the EOA's own key over `memberDigest`, not the typed digest
        bytes memory raw = abi.encode(s);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(a, m.kind, m.keyData, m.attrs, raw, m.pqzPop);
        _reg(a, m); // the own key over the typed digest, with the designator in place
    }

    /// The native member of `m` (secret `sk`) delegates by EIP-7702 to a wallet owned by `sessionSk`.
    function _delegate(Row memory m, uint256 sk, uint256 sessionSk) internal {
        (, bytes32 id) = _member(m.keyData, 0);
        address eoa = address(uint160(uint256(id)));
        assertEq(vm.addr(sk), eoa);
        MockWallet w = new MockWallet(vm.addr(sessionSk), 0, 0, address(0));
        vm.signAndAttachDelegation(address(w), sk);
        assertEq(eoa.code.length, 23);
        assertEq(bytes3(eoa.code), bytes3(0xef0100));
    }

    /// m3: `_sigOk`, the chain-free signature path (native members over the typed digest), accepts only the portable purposes
    /// POP_V2, KEM and PQZ_KEY; any other purpose reverts `UAUnauthorized`, for every kind.
    function test_ua8_sigOkPortablePurposesOnly() public {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(0x0101, address(mock), 400_000);
        SigOkHarness h = new SigOkHarness(chainUidA, BUDGET, k);
        bytes memory p = _key(0x0101);
        bytes32 ua = UAKinds.uaOf(0x0101, p);
        uint256 cfg = uint256(uint160(address(mock))) | uint256(400_000) << 160;
        bytes32[3] memory ok = [UAKinds.PURPOSE_POP_V2, UAKinds.PURPOSE_KEM, UAKinds.PURPOSE_PQZ_KEY];
        for (uint256 i; i < 3; ++i) {
            assertTrue(h.sigOk(cfg, 0x0101, p, ua, ok[i], DIGEST, _sig(p, UAKinds.uaMessage(0x0101, ok[i], DIGEST))));
        }
        bytes32[4] memory no =
            [UAKinds.PURPOSE_METATX, UAKinds.PURPOSE_MEMBER, UAKinds.PURPOSE_POP, UAKinds.PURPOSE_TRADE];
        for (uint256 i; i < 4; ++i) {
            bytes memory sig = _sig(p, UAKinds.uaMessage(0x0101, no[i], DIGEST)); // a valid signature under that purpose
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
            h.sigOk(cfg, 0x0101, p, ua, no[i], DIGEST, sig);
        }
        // a classical msig (empty sig is its answer under a portable purpose) is refused under metatx too
        Member[] memory mm = new Member[](1);
        mm[0] = Member(UAKinds.EVM_EOA, _pad(address(0xA11CE)), 1);
        bytes memory d = _msigKey(1, mm);
        bytes32 mua = UAKinds.uaOf(UAKinds.MSIG, d);
        assertTrue(h.sigOk(0, UAKinds.MSIG, d, mua, UAKinds.PURPOSE_POP_V2, DIGEST, ""));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, mua));
        h.sigOk(0, UAKinds.MSIG, d, mua, UAKinds.PURPOSE_METATX, DIGEST, "");
    }

    // ----- A6: the optional pqzPop, proven, storePqzPop, setPqzKey (P8, P9; UA8-D8, D9, D11; rulings A1-I1, A4-c2,
    // A4-c3, A5-c2, C8) -----

    /// A `pqzKeyRecords` row of portable.json: `setPqzKey(ua, pqzKey, pqzPopHash, sig)` for a UA registered without a
    /// PQZ key; `message` is what `sig` signs, `pqzRegMessage` what the key's `R_REG` proves over.
    struct KeyRec {
        string name;
        string set;
        uint16 kind;
        bytes32 ua;
        bytes pqzKey;
        bytes32 pqzPopHash;
        bytes32 message;
        bytes sig;
        bytes32 pqzRegMessage;
    }

    function loadKeyRecs() external view returns (KeyRec[] memory recs) {
        string memory j = vm.readFile(PJ);
        uint256 n;
        while (_jx(j, string.concat(".pqzKeyRecords[", vm.toString(n), "]"))) ++n;
        recs = new KeyRec[](n);
        for (uint256 i; i < n; ++i) {
            string memory p = string.concat(".pqzKeyRecords[", vm.toString(i), "]");
            KeyRec memory r = recs[i];
            r.name = _js(j, string.concat(p, ".name"));
            r.set = _js(j, string.concat(p, ".set"));
            r.kind = uint16(_ju(j, string.concat(p, ".kind")));
            r.ua = _jw(j, string.concat(p, ".ua"));
            r.pqzKey = _jb(j, string.concat(p, ".pqzKey"));
            r.pqzPopHash = _jw(j, string.concat(p, ".pqzPopHash"));
            r.message = _jw(j, string.concat(p, ".message"));
            r.sig = _jb(j, string.concat(p, ".sig"));
            r.pqzRegMessage = _jw(j, string.concat(p, ".pqzRegMessage"));
        }
    }

    function _keyRecs() internal view returns (KeyRec[] memory recs) {
        recs = this.loadKeyRecs();
        assertEq(recs.length, 8, "pqzKeyRecords: fndsa512 and msig-pq-native at four sets");
    }

    function _keyRec(KeyRec[] memory ks, string memory name) internal pure returns (KeyRec memory) {
        for (uint256 i; i < ks.length; ++i) {
            if (_eq(ks[i].name, name)) return ks[i];
        }
        revert(string.concat("no key record ", name));
    }

    function _pqzRow(Row[] memory rows) internal pure returns (Row memory) {
        return _find(rows, string.concat("mldsa65/", _setName()));
    }

    function _h(bytes memory pqzKey) internal pure returns (bytes32) {
        return UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqzKey);
    }

    function _proven(UARegistry r, bytes32 ua) internal view returns (bool proven) {
        (,, proven) = r.pqzKeyOf(ua);
    }

    function _checkedEq(UARegistry r, bytes32 ua, uint8 pop, uint8 pqzPop, uint8 kem) internal view {
        (uint8 cp, uint8 cq, uint8 ck) = r.checkedOf(ua);
        assertEq(abi.encode(cp, cq, ck), abi.encode(pop, pqzPop, kem), "checkedOf");
    }

    /// `registrationOf(ua)` on `from` submitted to `to` by a third party (`withProof`: with the stored `pqzPop`).
    function _copy(UARegistry from, UARegistry to, bytes32 ua, bool withProof) internal {
        (uint16 k, bytes memory d, IUARegistry.UAAttrs memory att, bytes memory pop, bytes memory z) = from.registrationOf(ua);
        vm.prank(address(0xC0B1E5), address(0xC0B1E5));
        assertEq(UACall.register(to, k, d, att, pop, withProof ? z : bytes("")), ua);
    }

    /// `storePqzPop` again with the stored bytes: no event, nothing changes.
    function _noOp(UARegistry r, bytes32 ua, bytes memory proof) internal {
        bytes memory before = _stored(r, ua);
        bool p = _proven(r, ua);
        vm.recordLogs();
        r.storePqzPop(ua, proof);
        assertEq(vm.getRecordedLogs().length, 0, "storePqzPop: a no-op once stored");
        assertEq(keccak256(_stored(r, ua)), keccak256(before));
        assertEq(_proven(r, ua), p);
    }

    /// P8 / UA8-D8: slot 0x0142 empty: the key and the proof are stored, unproven: no owner, not listed, `checkedOf`
    /// pqzPop NONE (C8); `storePqzPop` with the same bytes is a no-op (this registry can never prove them).
    function test_ua8_pqzUnprovenWithoutVerifier() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _pqzRow(rows);
        UARegistry a = _regA(false);
        vm.expectEmit(true, false, false, true, address(a));
        emit IUARegistry.UAPqzPopStored(x.ua, UAKinds.CHECKED_NONE, "");
        _reg(a, x);
        assertFalse(_proven(a, x.ua));
        assertEq(a.pqzPopOf(x.ua), x.pqzPop);
        assertEq(a.keyOwner(_h(x.attrs.pqzKey)), bytes32(0));
        assertEq(a.uaCount(UAKinds.PQZ_MLWE), 0);
        _checkedEq(a, x.ua, 1, 0, 1);
        _noOp(a, x.ua, x.pqzPop);
    }

    /// P8: a registration copied without its `pqzPop` to a registry with the verifier is unproven (`checkedOf` pqzPop
    /// NONE, C8); a third party's `storePqzPop` with the proof from the source's state proves it (owner, list, CHAIN).
    /// Ruling A5-c2: `registrationOf` then returns the stored proof (exactly the row's `register` arguments), so a copy
    /// from that state alone registers proven on a third registry.
    function test_ua8_pqzProveLaterOnVerifierChain() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _pqzRow(rows);
        bytes32 h = _h(x.attrs.pqzKey);
        _allowPqz(x);
        UARegistry a = _regA(false);
        _reg(a, x);
        UARegistry p = _deploy(address(0x5ceb1), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, true));
        _copy(a, p, x.ua, false);
        _checkedEq(p, x.ua, 1, 0, 1);
        assertEq(p.keyOwner(h), bytes32(0));
        assertEq(p.uaCount(UAKinds.PQZ_MLWE), 0);
        vm.expectEmit(true, false, false, true, address(p));
        emit IUARegistry.UAPqzPopStored(x.ua, UAKinds.CHECKED_CHAIN, x.pqzPop);
        vm.prank(address(0x7111D), address(0x7111D));
        p.storePqzPop(x.ua, a.pqzPopOf(x.ua));
        _checkedEq(p, x.ua, 1, 1, 1);
        assertEq(p.keyOwner(h), x.ua);
        assertEq(p.uaCount(UAKinds.PQZ_MLWE), 1);
        assertEq(p.uaAt(UAKinds.PQZ_MLWE, 0), x.ua);
        _assertRecord(p, x); // registrationOf's pqzPop: the stored proof
        UARegistry q = _deploy(address(0x5ceb2), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, true));
        _copy(p, q, x.ua, true);
        assertTrue(_proven(q, x.ua));
        _assertRecord(q, x);
    }

    /// The proof given in `register` on a registry with the verifier: proven at once; `storePqzPop` is then a no-op.
    function test_ua8_pqzPopInRegisterProven() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _pqzRow(rows);
        _allowPqz(x);
        UARegistry p = _regA(true);
        _reg(p, x);
        assertTrue(_proven(p, x.ua));
        assertEq(p.keyOwner(_h(x.attrs.pqzKey)), x.ua);
        assertEq(p.uaAt(UAKinds.PQZ_MLWE, 0), x.ua);
        _checkedEq(p, x.ua, 1, 1, 1);
        _noOp(p, x.ua, x.pqzPop);
    }

    /// portable.json `store-pqz-pop-other-bytes` (four sets): bytes that do not hash to the stored `pqzPopHash` are
    /// `UAPqzPopHash`; so is any proof for a UA without a PQZ key; an id this registry does not hold is `UAUnauthorized`.
    function test_ua8_storePqzPopWrongBytesRefused() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Neg[] memory negs = this.loadNegs();
        UARegistry p = _regA(true);
        uint256 n;
        for (uint256 i; i < negs.length; ++i) {
            if (!_eq(negs[i].entry, "storePqzPop")) continue;
            Row memory r = _find(rows, negs[i].row);
            Row memory x = _apply(r, negs[i]);
            assertTrue(keccak256(x.pqzPop) != keccak256(r.pqzPop));
            uint256 snap = vm.snapshotState();
            UACall.register(p, r.kind, r.keyData, r.attrs, r.pop, ""); // registerWith: no proof
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzPopHash.selector, r.ua));
            p.storePqzPop(r.ua, x.pqzPop);
            vm.revertToState(snap);
            ++n;
        }
        assertEq(n, 4, "one per set");
        // A6-m: an empty proof is refused (its hash is refused wherever one is signed)
        Row memory x0 = _pqzRow(rows);
        UACall.register(p, x0.kind, x0.keyData, x0.attrs, x0.pop, "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzPopHash.selector, x0.ua));
        p.storePqzPop(x0.ua, "");
        Row memory s = rows[P256_ROW];
        _reg(p, s);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzPopHash.selector, s.ua));
        p.storePqzPop(s.ua, "");
        bytes32 none = keccak256("unregistered");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, none));
        p.storePqzPop(none, hex"01");
    }

    /// `storePqzPop` twice with the same bytes: the second call is a no-op (no event), with and without the verifier.
    function test_ua8_storePqzPopIdempotent() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _pqzRow(rows);
        _allowPqz(x);
        UARegistry[2] memory rs = [
            _regA(true),
            _deploy(address(0x5ceb3), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, false))
        ];
        for (uint256 i; i < 2; ++i) {
            UARegistry r = rs[i];
            UACall.register(r, x.kind, x.keyData, x.attrs, x.pop, "");
            vm.expectEmit(true, false, false, true, address(r));
            emit IUARegistry.UAPqzPopStored(x.ua, i == 0 ? UAKinds.CHECKED_CHAIN : UAKinds.CHECKED_NONE, x.pqzPop);
            r.storePqzPop(x.ua, x.pqzPop);
            _noOp(r, x.ua, x.pqzPop);
            _assertRecord(r, x);
            assertEq(_proven(r, x.ua), i == 0);
        }
    }

    /// The hash matches but the verifier refuses the proof (returns 0): `UAPoP`, nothing stored.
    function test_ua8_storePqzPopBadProofReverts() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _pqzRow(rows);
        UARegistry p = _regA(true);
        UACall.register(p, x.kind, x.keyData, x.attrs, x.pop, "");
        vm.mockCall(rreg, abi.encodeCall(IUAPopVerifier.verifyPop, (x.attrs.pqzKey, x.pqzRegMessage, x.pqzPop)),
            abi.encode(uint256(0)));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        p.storePqzPop(x.ua, x.pqzPop);
        assertEq(p.pqzPopOf(x.ua), "");
        assertFalse(_proven(p, x.ua));
        _checkedEq(p, x.ua, 1, 0, 1);
    }

    /// `mldsa65#1` registered with `x`'s PQZ key and proof hash by its own (mocked) PoP, its `R_REG` message its own:
    /// someone who copies another UA's PQZ key.
    function _squatter(Row[] memory rows, Row memory x) internal returns (Row memory s) {
        s = _apply(rows[ML65_1], Neg("", "", "", "", new string[](0), new bytes[](0)));
        s.attrs = UACall.attrs(x.attrs.pqzKey, x.attrs.pqzPopHash, "");
        bytes32 record = UAKinds.portableRecordHash(s.ua, UAKinds.MLDSA65, _h(x.attrs.pqzKey), UAKinds.kemRecordHash(s.ua, 0, ""));
        s.popMessage = UAKinds.uaMessage(UAKinds.MLDSA65, UAKinds.PURPOSE_POP_V2,
            UAKinds.portableDigest(UAKinds.registrationHash(record, s.attrs.pqzPopHash)));
        s.pqzRegMessage = UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, UAKinds.portableDigest(record));
        s.pop = new bytes(3309);
        s.pop[0] = 0x5a;
        s.pqzPop = x.pqzPop;
        _allowMl65(s.keyData, s.popMessage, s.pop);
    }

    /// UA8-D8: an attacker lists the victim's PQZ key unproven first; the victim still registers proven (owner,
    /// list); the attacker's `storePqzPop` with the victim's proof cannot prove (it proves over the victim's message).
    function test_ua8_unprovenListingDoesNotBlockOwner() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _pqzRow(rows);
        bytes32 h = _h(x.attrs.pqzKey);
        _allowPqz(x);
        UARegistry p = _regA(true);
        Row memory s = _squatter(rows, x);
        UACall.register(p, s.kind, s.keyData, s.attrs, s.pop, "");
        assertEq(p.keyOwner(h), bytes32(0));
        _reg(p, x);
        assertEq(p.keyOwner(h), x.ua);
        assertTrue(_proven(p, x.ua));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        p.storePqzPop(s.ua, x.pqzPop);
        assertFalse(_proven(p, s.ua));
        assertEq(p.uaCount(UAKinds.PQZ_MLWE), 1);
    }

    /// UA8-D8: a proven key is still one UA's: a second UA whose proof the verifier accepts is `UAKeyInUse`, in
    /// `register` and in `storePqzPop`.
    function test_ua8_provenKeyStillUnique() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _pqzRow(rows);
        bytes32 h = _h(x.attrs.pqzKey);
        _allowPqz(x);
        UARegistry p = _regA(true);
        Row memory s = _squatter(rows, x);
        _allowPqz(s);
        _reg(p, x);
        bytes memory inUse = abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, h, x.ua);
        vm.expectRevert(inUse);
        UACall.register(p, s.kind, s.keyData, s.attrs, s.pop, s.pqzPop);
        UACall.register(p, s.kind, s.keyData, s.attrs, s.pop, "");
        vm.expectRevert(inUse);
        p.storePqzPop(s.ua, s.pqzPop);
        assertEq(p.keyOwner(h), x.ua);
    }

    /// UA8-D11: gen 2 refuses `storePqzPop` and `setPqzKey` for a record gen 1 holds (`UAUnauthorized`: they go to gen
    /// 1); gen 1 takes them and gen 2 forwards the reads.
    function test_ua8_gen2RefusesWritesForGen1() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _pqzRow(rows);
        KeyRec memory k = _keyRec(_keyRecs(), string.concat("fndsa512/", _setName()));
        UARegistry g1 = _regA(false);
        UARegistry g2 = _deploy(address(0x5ceb4), chainUidA, address(g1), false, BUDGET, address(0), true,
            new UARegistry.KindConfig[](0));
        UACall.register(g1, x.kind, x.keyData, x.attrs, x.pop, "");
        _reg(g1, rows[FNDSA_ROW]);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, x.ua));
        g2.storePqzPop(x.ua, x.pqzPop);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, k.ua));
        g2.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig));
        g1.storePqzPop(x.ua, x.pqzPop);
        g1.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig));
        assertEq(g2.pqzPopOf(x.ua), x.pqzPop);
        assertEq(g2.pqzKeySigOf(k.ua), k.sig);
        (address p1,,) = g1.pqzKeyOf(k.ua);
        (address p2,,) = g2.pqzKeyOf(k.ua);
        assertEq(p1, p2);
    }

    /// A5 n1: a gen 2 in front of a gen 1 without 0x0142 takes a PQZ key (a PQ-eligible `msig` of gen-1 members):
    /// unproven where gen 2 has no verifier either, proven where gen 2 enables 0x0142 itself (owner on gen 2).
    function test_ua8_gen2PqzKeyWhenGen1HasNone() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry g1 = _regA(false);
        _members(g1, rows);
        Row memory m = _find(rows, string.concat("msig-pq/", _setName()));
        bytes32 h = _h(m.attrs.pqzKey);
        UARegistry g2 = _deploy(address(0x5ceb5), chainUidA, address(g1), false, BUDGET, address(0), true,
            new UARegistry.KindConfig[](0));
        uint256 snap = vm.snapshotState();
        _reg(g2, m);
        assertFalse(_proven(g2, m.ua));
        assertEq(g2.keyOwner(h), bytes32(0));
        vm.revertToState(snap);
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, rreg, 1_000_000);
        UARegistry g2p = _deploy(address(0x5ceb6), chainUidA, address(g1), false, BUDGET, address(0), true, c);
        _allowPqz(m);
        _reg(g2p, m);
        assertTrue(_proven(g2p, m.ua));
        assertEq(g2p.keyOwner(h), m.ua);
        assertEq(g1.keyOwner(h), bytes32(0));
        _checkedEq(g2p, m.ua, 1, 1, m.kemPk.length != 0 ? 1 : 0);
    }

    /// `msig` key records: each `mldsa65` member's signature over the record's `memberDigest`.
    function _allowRecord(Row[] memory rows, Row memory base, KeyRec memory k) internal {
        if (k.kind == UAKinds.MSIG) _allowMembers(rows, base.keyData, UAKinds.memberDigest(k.ua, k.message), k.sig);
    }

    /// Registers `base` (no PQZ key) on `r`, then `setPqzKey` of `k` by a third party; the record's messages are
    /// the ones `UAKinds` builds (`pqzKeyRecordMessage` / `pqzKeyDigest`).
    function _addKey(UARegistry r, Row memory base, KeyRec memory k) internal {
        _reg(r, base);
        bytes32 h = _h(k.pqzKey);
        bytes32 kd = UAKinds.pqzKeyDigest(k.ua, h);
        assertEq(UAKinds.uaMessage(k.kind, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyRecordDigest(k.ua, h, k.pqzPopHash)), k.message);
        assertEq(UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, kd), k.pqzRegMessage);
        vm.expectEmit(true, false, false, true, address(r));
        emit IUARegistry.UAPqzKeyAdded(k.ua, h, k.pqzPopHash, k.pqzKey, k.sig);
        vm.prank(address(0xBEEF), address(0xBEEF));
        r.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig));
        _assertAdded(r, base, k, "", false);
    }

    /// A key added by `setPqzKey`: `pqzKeyOf`, `recordOf`, `pqzKeySigOf`, `pqzPopOf`, `checkedOf`, owner and list;
    /// `registrationOf` stays exactly the `register` arguments (ruling A4-c3: no key, no proof).
    function _assertAdded(UARegistry r, Row memory base, KeyRec memory k, bytes memory proof, bool proven) internal view {
        assertEq(keccak256(_stored(r, k.ua)), keccak256(_args(base)), string.concat(k.name, ": registrationOf"));
        (address ptr, bytes32 ph, bool pv) = r.pqzKeyOf(k.ua);
        assertEq(SSTORE2.read(ptr), k.pqzKey);
        assertEq(ph, k.pqzPopHash);
        assertEq(pv, proven);
        (, address zp) = r.recordOf(k.ua);
        assertEq(zp, ptr);
        assertEq(r.pqzKeySigOf(k.ua), k.sig);
        assertEq(r.pqzPopOf(k.ua), proof);
        _checkedEq(r, k.ua, 1, proven ? 1 : 0, base.kemPk.length != 0 ? 1 : 0);
        assertEq(r.keyOwner(_h(k.pqzKey)), proven ? k.ua : bytes32(0));
        assertEq(r.uaCount(UAKinds.PQZ_MLWE), proven ? 1 : 0);
    }

    /// Ruling A1-I1: every portable.json `pqzKeyRecords` row (fndsa512, msig-pq-native with its native member's
    /// the typed digest; four sets) adds its key to a registration without one: unproven, `pqzKeySigOf` the record's
    /// signature, `registrationOf` unchanged (A4-c3). The set's proof (`storePqzPop`) is stored unproven without the
    /// verifier and proves over `uaMessage(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest)` with it.
    function test_ua8_setPqzKeyFromVectors() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        KeyRec[] memory ks = _keyRecs();
        UARegistry a = _regA(false);
        UARegistry p = _deploy(address(0x5ceb7), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, true));
        _members(a, rows);
        _members(p, rows);
        for (uint256 i; i < ks.length; ++i) {
            KeyRec memory k = ks[i];
            Row memory base = _byUa(rows, k.ua);
            bytes memory proof = _find(rows, string.concat("mldsa65/", k.set)).pqzPop;
            assertEq(keccak256(proof), k.pqzPopHash);
            _allowRecord(rows, base, k);
            uint256 snap = vm.snapshotState();
            _addKey(a, base, k);
            vm.expectEmit(true, false, false, true, address(a));
            emit IUARegistry.UAPqzPopStored(k.ua, UAKinds.CHECKED_NONE, proof);
            a.storePqzPop(k.ua, proof);
            _assertAdded(a, base, k, proof, false);
            _addKey(p, base, k);
            vm.mockCall(rreg, abi.encodeCall(IUAPopVerifier.verifyPop, (k.pqzKey, k.pqzRegMessage, proof)),
                abi.encode(uint256(1)));
            vm.expectEmit(true, false, false, true, address(p));
            emit IUARegistry.UAPqzPopStored(k.ua, UAKinds.CHECKED_CHAIN, proof);
            vm.prank(address(0x7111D), address(0x7111D));
            p.storePqzPop(k.ua, proof);
            _assertAdded(p, base, k, proof, true);
            _noOp(p, k.ua, proof);
            vm.revertToState(snap);
        }
    }

    /// Ruling A4-c2's order on portable.json's `setPqzKey` negatives (four sets): a non-holder (`UAPqzHolder`), a
    /// record that has a PQZ key (`UAPqzKeySet`, before the signature), another UA's signature (`UAUnauthorized`); then
    /// an unregistered id (`UAUnauthorized`), a key of no set's length (`UAKeyData(0x0142)`, before the signature), a
    /// zero proof hash (`UAPqzPopHash`), a second record (`UAPqzKeySet`), and on a gen 2 whose gen 1 enables 0x0142
    /// `UAKindDisabled(0x0142)` (ruling A5-I1, as in `register`).
    function test_ua8_setPqzKeyRefused() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        KeyRec[] memory ks = _keyRecs();
        Neg[] memory negs = this.loadNegs();
        UARegistry a = _regA(false);
        _reg(a, rows[FNDSA_ROW]);
        _reg(a, rows[SLH_ROW]);
        uint256 n;
        for (uint256 i; i < negs.length; ++i) {
            Neg memory g = negs[i];
            if (!_eq(g.entry, "setPqzKey")) continue;
            KeyRec memory k0 = _keyRec(ks, g.row);
            KeyRec memory k =
                KeyRec(k0.name, k0.set, k0.kind, k0.ua, k0.pqzKey, k0.pqzPopHash, k0.message, k0.sig, k0.pqzRegMessage);
            uint256 snap = vm.snapshotState();
            _reg(a, _find(rows, string.concat("mldsa65/", k.set))); // the UA of `already-set`, with this set's key
            for (uint256 f; f < g.keys.length; ++f) {
                if (_eq(g.keys[f], "ua")) k.ua = bytes32(g.values[f]);
                else if (_eq(g.keys[f], "sig")) k.sig = g.values[f];
                else if (_eq(g.keys[f], "pqzPopHash")) k.pqzPopHash = bytes32(g.values[f]);
                else revert(string.concat(g.name, ": unknown mutation ", g.keys[f]));
            }
            bytes4 sel = _eq(g.err, "UAPqzKeySet")
                ? IUARegistry.UAPqzKeySet.selector
                : _eq(g.err, "UAPqzHolder")
                    ? IUARegistry.UAPqzHolder.selector
                    : _eq(g.err, "UAPqzPopHash") ? IUARegistry.UAPqzPopHash.selector : IUARegistry.UAUnauthorized.selector;
            assertTrue(_eq(g.err, "UAPqzKeySet") || _eq(g.err, "UAPqzHolder") || _eq(g.err, "UAUnauthorized")
                || _eq(g.err, "UAPqzPopHash"), g.err);
            vm.expectRevert(abi.encodeWithSelector(sel, k.ua));
            a.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig));
            vm.revertToState(snap);
            ++n;
        }
        assertEq(n, 13, "three per set + the empty proof hash (A6-m)");
        KeyRec memory r = _keyRec(ks, string.concat("fndsa512/", _setName()));
        bytes32 none = keccak256("unregistered");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, none));
        a.setPqzKey(none, r.pqzKey, r.pqzPopHash, UACall.sig(r.sig));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.PQZ_MLWE));
        a.setPqzKey(r.ua, _slice(r.pqzKey, 0, r.pqzKey.length - 1), r.pqzPopHash, UACall.sig(r.sig));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzPopHash.selector, r.ua));
        a.setPqzKey(r.ua, r.pqzKey, 0, UACall.sig(r.sig));
        a.setPqzKey(r.ua, r.pqzKey, r.pqzPopHash, UACall.sig(r.sig));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, r.ua));
        a.setPqzKey(r.ua, r.pqzKey, r.pqzPopHash, UACall.sig(r.sig));
        // A5-I1: gen 2 (fndsa512) in front of a gen 1 that enables 0x0142
        UARegistry.KindConfig[] memory c1 = new UARegistry.KindConfig[](1);
        c1[0] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, rreg, 1_000_000);
        UARegistry g1 = _deploy(address(0x5ceb8), chainUidA, address(0), false, BUDGET, address(0), true, c1);
        UARegistry.KindConfig[] memory c2 = new UARegistry.KindConfig[](1);
        c2[0] = UARegistry.KindConfig(UAKinds.FNDSA512, address(new UAFndsaVerifier()), CAP_FNDSA);
        UARegistry g2 = _deploy(address(0x5ceb9), chainUidA, address(g1), false, BUDGET, address(0), true, c2);
        _reg(g2, rows[FNDSA_ROW]);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, UAKinds.PQZ_MLWE));
        g2.setPqzKey(r.ua, r.pqzKey, r.pqzPopHash, UACall.sig(r.sig));
    }

    /// Rulings A5-c2 / A4-c3: a key added by `setPqzKey` is copied from state alone — `registrationOf` (no key) into
    /// `register`, `pqzKeyOf` + `pqzKeySigOf` into `setPqzKey`, `pqzPopOf` into `storePqzPop` — and proves on the
    /// copy's registry.
    function test_ua8_setPqzKeyCopyFromState() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        KeyRec memory k = _keyRec(_keyRecs(), string.concat("fndsa512/", _setName()));
        Row memory base = rows[FNDSA_ROW];
        bytes memory proof = _pqzRow(rows).pqzPop;
        UARegistry a = _regA(false);
        _addKey(a, base, k);
        a.storePqzPop(k.ua, proof);
        UARegistry p = _deploy(address(0x5ceba), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, true));
        _copy(a, p, k.ua, true);
        (address ptr, bytes32 ph,) = a.pqzKeyOf(k.ua);
        vm.prank(address(0xC0B1E5), address(0xC0B1E5));
        p.setPqzKey(k.ua, SSTORE2.read(ptr), ph, UACall.sig(a.pqzKeySigOf(k.ua)));
        vm.mockCall(rreg, abi.encodeCall(IUAPopVerifier.verifyPop, (k.pqzKey, k.pqzRegMessage, proof)), abi.encode(uint256(1)));
        vm.prank(address(0xC0B1E5), address(0xC0B1E5));
        p.storePqzPop(k.ua, a.pqzPopOf(k.ua));
        _assertAdded(p, base, k, proof, true);
    }

    // ----- A6 fix 1 (review A6: I1 → ruling A6-I1; m2) -----

    /// m2: `storePqzPop` for a key from `register` without a KEM record proves over exactly
    /// `uaMessage(0x0142, PURPOSE_POP_V2, portableRecordDigest(ua, kind, keyHash, zero KEM record))` (the stand-in
    /// accepts only that input).
    function test_ua8_storePqzPopNoKemExactMessage() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory s = _squatter(rows, _pqzRow(rows));
        assertEq(s.kemPk.length, 0);
        assertEq(s.pqzRegMessage, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2,
            UAKinds.portableRecordDigest(s.ua, s.kind, _h(s.attrs.pqzKey), UAKinds.kemRecordHash(s.ua, 0, ""))));
        UARegistry p = _regA(true);
        UACall.register(p, s.kind, s.keyData, s.attrs, s.pop, "");
        _allowPqz(s);
        p.storePqzPop(s.ua, s.pqzPop);
        assertTrue(_proven(p, s.ua));
        _checkedEq(p, s.ua, 1, 1, 0);
    }

    /// Gen 2 enabling 0x0142 in front of `g1` (which does not).
    function _gen2Pqz(address where, UARegistry g1) internal returns (UARegistry) {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, rreg, 1_000_000);
        return _deploy(where, chainUidA, address(g1), false, BUDGET, address(0), true, c);
    }

    /// Ruling A6-I1, the griefer (review I1): a PQ-eligible `msig`'s registration is copied to a gen 1 without 0x0142
    /// first, its key unproven there and the record final there (gen 2's `register` is `UAAlreadyRegistered`). Gen 2,
    /// the oldest generation enabling 0x0142, proves the gen-1 key by `storePqzPop` (over the `register` message, the
    /// KEM record read from gen 1) and holds the attachment: owner, list, `proven`, the proof. A PQZ token bound to gen 2
    /// (`PqzCore._keyPtr`) takes the UA; gen 1 still reads it unproven.
    function test_ua8_gen2ProvesGen1RegisterKey() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry g1 = _regA(false);
        _members(g1, rows);
        UARegistry g2 = _gen2Pqz(address(0x5cebb), g1);
        Row memory m = _find(rows, string.concat("msig-pq/", _setName()));
        bytes32 h = _h(m.attrs.pqzKey);
        vm.prank(address(0xBAD), address(0xBAD));
        UACall.register(g1, m.kind, m.keyData, m.attrs, m.pop, "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, m.ua));
        UACall.register(g2, m.kind, m.keyData, m.attrs, m.pop, m.pqzPop);
        KeyPtrHarness t = new KeyPtrHarness();
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, m.ua));
        t.keyPtr(address(g2), m.ua);
        _allowPqz(m);
        vm.expectEmit(true, false, false, true, address(g2));
        emit IUARegistry.UAPqzPopStored(m.ua, UAKinds.CHECKED_CHAIN, m.pqzPop);
        vm.prank(address(0x7111D), address(0x7111D));
        g2.storePqzPop(m.ua, m.pqzPop);
        (address p1, bytes32 h1, bool v1) = g1.pqzKeyOf(m.ua);
        (address p2, bytes32 h2, bool v2) = g2.pqzKeyOf(m.ua);
        assertEq(abi.encode(p1, h1, v1), abi.encode(p2, h2, false), "gen 2 proves gen 1's key and hash");
        assertTrue(v2);
        assertEq(g2.keyOwner(h), m.ua);
        assertEq(g1.keyOwner(h), bytes32(0));
        assertEq(g2.uaAt(UAKinds.PQZ_MLWE, 0), m.ua);
        _checkedEq(g2, m.ua, 1, 1, m.kemPk.length != 0 ? 1 : 0);
        _checkedEq(g1, m.ua, 1, 0, m.kemPk.length != 0 ? 1 : 0);
        assertEq(g2.pqzPopOf(m.ua), m.pqzPop);
        assertEq(g1.pqzPopOf(m.ua), "");
        assertEq(keccak256(_stored(g2, m.ua)), keccak256(_args(m)), "gen 2's registrationOf: gen 1's record + its proof");
        (, address zp) = g2.recordOf(m.ua);
        assertEq(zp, p2);
        assertEq(t.keyPtr(address(g2), m.ua), p2);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, m.ua));
        t.keyPtr(address(g1), m.ua);
        _noOp(g2, m.ua, m.pqzPop);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, m.ua));
        g2.setPqzKey(m.ua, m.attrs.pqzKey, m.attrs.pqzPopHash, UACall.sig(hex"01")); // the gen-1 key counts
    }

    /// typed-signing TS-D3: the R_REG message of a `register` key names the registering kind (`UAPortableRecord.kind`);
    /// a gen 2 proving a gen-1 record's key (ruling A6-I1) takes the kind from gen 1 (`kindOf`): the stand-in accepts
    /// exactly the row's `pqzRegMessage` (kind `mldsa65`), not the same record under another kind.
    function test_storePqzPopGen2HostKindFromGen1() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry g1 = _regA(false);
        UARegistry g2 = _gen2Pqz(address(0x5cebc), g1);
        Row memory x = _pqzRow(rows);
        assertEq(x.kind, UAKinds.MLDSA65);
        UACall.register(g1, x.kind, x.keyData, x.attrs, x.pop, "");
        assertEq(g2.kindOf(x.ua), UAKinds.MLDSA65);
        bytes32 h = _h(x.attrs.pqzKey);
        bytes32 kh = UAKinds.kemRecordHash(x.ua, 0, x.kemPk);
        assertEq(x.pqzRegMessage, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2,
            g2.portableRecordDigest(x.ua, UAKinds.MLDSA65, h, kh)));
        // the same record under another kind is another message: refused by the stand-in
        bytes32 other = UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2,
            UAKinds.portableRecordDigest(x.ua, UAKinds.MLDSA44, h, kh));
        assertTrue(other != x.pqzRegMessage);
        vm.mockCall(rreg, abi.encodeCall(IUAPopVerifier.verifyPop, (x.attrs.pqzKey, other, x.pqzPop)), abi.encode(uint256(1)));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        g2.storePqzPop(x.ua, x.pqzPop);
        _allowPqz(x);
        g2.storePqzPop(x.ua, x.pqzPop);
        assertTrue(_proven(g2, x.ua));
        assertEq(g2.keyOwner(h), x.ua);
    }

    /// Ruling A6-I1, the other key origin: `setPqzKey` on gen 2 for a gen-1 record without a PQZ key (fndsa512: the
    /// signature checked by gen 1; msig-pq-native: members on gen 1, the native one over the typed digest), then its proof
    /// over the PURPOSE_PQZ_KEY message; the attachment is gen 2's, gen 1 has no key. A token bound to gen 2 takes it.
    function test_ua8_gen2SetPqzKeyForGen1Record() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        KeyRec[] memory ks = _keyRecs();
        UARegistry g1 = _regA(false);
        _members(g1, rows);
        UARegistry g2 = _gen2Pqz(address(0x5cebc), g1);
        KeyPtrHarness t = new KeyPtrHarness();
        bytes memory proof = _pqzRow(rows).pqzPop;
        string[2] memory names = [string("fndsa512/"), "msig-pq-native/"];
        for (uint256 i; i < 2; ++i) {
            KeyRec memory k = _keyRec(ks, string.concat(names[i], _setName()));
            Row memory base = _byUa(rows, k.ua);
            _allowRecord(rows, base, k);
            uint256 snap = vm.snapshotState();
            _reg(g1, base);
            vm.expectEmit(true, false, false, true, address(g2));
            emit IUARegistry.UAPqzKeyAdded(k.ua, _h(k.pqzKey), k.pqzPopHash, k.pqzKey, k.sig);
            vm.prank(address(0xBEEF), address(0xBEEF));
            g2.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig));
            _assertAdded(g2, base, k, "", false);
            (address p1,,) = g1.pqzKeyOf(k.ua);
            assertEq(p1, address(0), "gen 1 untouched");
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, k.ua));
            g2.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig));
            vm.mockCall(rreg, abi.encodeCall(IUAPopVerifier.verifyPop, (k.pqzKey, k.pqzRegMessage, proof)),
                abi.encode(uint256(1)));
            g2.storePqzPop(k.ua, proof);
            _assertAdded(g2, base, k, proof, true);
            (address p2,,) = g2.pqzKeyOf(k.ua);
            assertEq(t.keyPtr(address(g2), k.ua), p2);
            vm.revertToState(snap);
            // A6 n1: gen 1's `setPqzKey` wrote the key; gen 2 proves it over the PURPOSE_PQZ_KEY message (the key's
            // origin read from gen 1's `pqzKeySigOf`; the stand-in refuses the `register` message)
            _reg(g1, base);
            vm.prank(address(0xBEEF), address(0xBEEF));
            g1.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig));
            vm.mockCall(rreg, abi.encodeCall(IUAPopVerifier.verifyPop, (k.pqzKey, k.pqzRegMessage, proof)),
                abi.encode(uint256(1)));
            vm.prank(address(0x7111D), address(0x7111D));
            g2.storePqzPop(k.ua, proof);
            _assertAdded(g2, base, k, proof, true);
            (address q1,, bool v1) = g1.pqzKeyOf(k.ua);
            (address q2,,) = g2.pqzKeyOf(k.ua);
            assertEq(q2, q1, "gen 2 proves gen 1's key");
            assertFalse(v1);
            assertEq(t.keyPtr(address(g2), k.ua), q2);
            vm.revertToState(snap);
        }
    }

    /// Ruling A6-I1 from the other side (A5-I1): where gen 1 enables 0x0142, gen 2 holds no PQZ attachment —
    /// `storePqzPop` / `setPqzKey` for gen-1 records stay `UAUnauthorized` (D11), a PQZ key in gen 2's `register` is
    /// `UAKindDisabled(0x0142)`.
    function test_ua8_gen2RefusesWhenGen1HasPqz() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _pqzRow(rows);
        KeyRec memory k = _keyRec(_keyRecs(), string.concat("fndsa512/", _setName()));
        UARegistry g1 = _regA(true);
        _members(g1, rows);
        UARegistry g2 = _deploy(address(0x5cebd), chainUidA, address(g1), false, BUDGET, address(0), true,
            new UARegistry.KindConfig[](0));
        UACall.register(g1, x.kind, x.keyData, x.attrs, x.pop, "");
        _reg(g1, rows[FNDSA_ROW]);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, x.ua));
        g2.storePqzPop(x.ua, x.pqzPop);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, k.ua));
        g2.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig));
        Row memory m = _find(rows, string.concat("msig-pq/", _setName()));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, UAKinds.PQZ_MLWE));
        UACall.register(g2, m.kind, m.keyData, m.attrs, m.pop, m.pqzPop);
    }

    // ----- final fix wave: R-cross-set, review m3, n3 -----

    /// A parameter set other than this build's.
    function _otherSet() internal pure returns (string memory) {
        return _eq(_setName(), "n2048-kmax1024") ? "n2304-kmax4096" : "n2048-kmax1024";
    }

    /// `mldsa65/<set>`'s UA (the same id at every set) copied by a third party without its proof: its PQZ key is of
    /// that set's length.
    function _copyOtherSet(UARegistry r, Row[] memory rows) internal returns (Row memory o) {
        o = _find(rows, string.concat("mldsa65/", _otherSet()));
        vm.prank(address(0xBAD), address(0xBAD));
        assertEq(UACall.register(r, o.kind, o.keyData, o.attrs, o.pop, ""), o.ua);
    }

    /// `setPqzKey` of this build's `mldsa65/<set>` key for its UA, signed (mocked precompile) over the record's message.
    function _setThisSetKey(UARegistry r, Row memory x) internal returns (bytes memory sig) {
        bytes32 h = _h(x.attrs.pqzKey);
        bytes32 rd = UAKinds.pqzKeyRecordDigest(x.ua, h, x.attrs.pqzPopHash);
        sig = _ml65Sig(x.keyData, UAKinds.uaMessage(UAKinds.MLDSA65, UAKinds.PURPOSE_PQZ_KEY, rd));
        vm.expectEmit(true, false, false, true, address(r));
        emit IUARegistry.UAPqzKeyAdded(x.ua, h, x.attrs.pqzPopHash, x.attrs.pqzKey, sig);
        vm.prank(address(0xBEEF), address(0xBEEF));
        r.setPqzKey(x.ua, x.attrs.pqzKey, x.attrs.pqzPopHash, UACall.sig(sig));
    }

    /// Its proof over the PURPOSE_PQZ_KEY message (the stand-in accepts exactly that input), by a third party.
    function _proveAdded(UARegistry r, Row memory x) internal {
        bytes32 m = UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyDigest(x.ua, _h(x.attrs.pqzKey)));
        vm.mockCall(rreg, abi.encodeCall(IUAPopVerifier.verifyPop, (x.attrs.pqzKey, m, x.pqzPop)), abi.encode(uint256(1)));
        vm.prank(address(0x7111D), address(0x7111D));
        r.storePqzPop(x.ua, x.pqzPop);
    }

    /// The current PQZ key is `x`'s (`pqzKeyOf`, `recordOf`, `pqzKeySigOf`, `checkedOf`, owner, list), added by `sig`.
    function _assertThisSetKey(UARegistry r, Row memory x, bytes memory sig, bool proven) internal view {
        (address ptr, bytes32 ph, bool pv) = r.pqzKeyOf(x.ua);
        assertEq(SSTORE2.read(ptr), x.attrs.pqzKey);
        assertEq(abi.encode(ph, pv), abi.encode(x.attrs.pqzPopHash, proven));
        (, address zp) = r.recordOf(x.ua);
        assertEq(zp, ptr);
        assertEq(r.pqzKeySigOf(x.ua), sig);
        assertEq(r.pqzPopOf(x.ua), proven ? x.pqzPop : bytes(""));
        _checkedEq(r, x.ua, 1, proven ? 1 : 0, x.kemPk.length != 0 ? 1 : 0);
        assertEq(r.keyOwner(_h(x.attrs.pqzKey)), proven ? x.ua : bytes32(0));
        assertEq(r.uaCount(UAKinds.PQZ_MLWE), proven ? 1 : 0);
    }

    /// Ruling R-cross-set (review I2): a registration copied from a chain of another parameter set stores a PQZ key this
    /// chain's verifier can never prove; `setPqzKey` replaces it with a key of this chain's set (`UAPqzKeyAdded`), which
    /// then proves and is write-once (`UAPqzKeySet`). `registrationOf` stays exactly the `register` arguments (the
    /// replaced key, no proof), so the registration is still copyable from this state; `checkedOf` follows the new key.
    function test_ua8_crossSetKeyReplaced() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _pqzRow(rows);
        UARegistry p = _deploy(address(0x5cec0), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, true));
        Row memory o = _copyOtherSet(p, rows);
        assertEq(o.ua, x.ua, "one UA at every set");
        assertTrue(o.attrs.pqzKey.length != PqzSet.PK);
        bytes memory args = abi.encode(o.kind, o.keyData, o.attrs, o.pop, bytes(""));
        bytes memory sig = _setThisSetKey(p, x);
        _assertThisSetKey(p, x, sig, false);
        assertEq(keccak256(_stored(p, x.ua)), keccak256(args), "registrationOf: the register arguments");
        _proveAdded(p, x);
        _assertThisSetKey(p, x, sig, true);
        assertEq(keccak256(_stored(p, x.ua)), keccak256(args), "registrationOf: not the new key's proof");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, x.ua));
        p.setPqzKey(x.ua, x.attrs.pqzKey, x.attrs.pqzPopHash, UACall.sig(sig));
        // still copyable from this state: the register arguments verify on another registry
        UARegistry q = _regA(false);
        _copy(p, q, x.ua, true);
        (address qp,,) = q.pqzKeyOf(x.ua);
        assertEq(SSTORE2.read(qp), o.attrs.pqzKey);
        // a key added by `setPqzKey` (fndsa512, real signatures) of another set is replaced the same way
        KeyRec[] memory ks = _keyRecs();
        Row memory base = rows[FNDSA_ROW];
        _reg(p, base);
        KeyRec memory k1 = _keyRec(ks, string.concat("fndsa512/", _otherSet()));
        KeyRec memory k = _keyRec(ks, string.concat("fndsa512/", _setName()));
        p.setPqzKey(k1.ua, k1.pqzKey, k1.pqzPopHash, UACall.sig(k1.sig));
        p.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig));
        (address ptr,,) = p.pqzKeyOf(k.ua);
        assertEq(SSTORE2.read(ptr), k.pqzKey);
        assertEq(p.pqzKeySigOf(k.ua), k.sig);
        assertEq(keccak256(_stored(p, k.ua)), keccak256(_args(base)), "registrationOf: no key (A4-c3)");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, k.ua));
        p.setPqzKey(k1.ua, k1.pqzKey, k1.pqzPopHash, UACall.sig(k1.sig));
    }

    /// Ruling R-cross-set, the refusals: a key of this chain's set stays write-once, proven or not (`UAPqzKeySet`, also
    /// for a key of another set offered in its place); a registry without the 0x0142 verifier replaces nothing (nothing
    /// is provable there either way).
    function test_ua8_crossSetRightSetKeyStays() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _pqzRow(rows);
        KeyRec[] memory ks = _keyRecs();
        KeyRec memory k1 = _keyRec(ks, string.concat("fndsa512/", _otherSet()));
        KeyRec memory k = _keyRec(ks, string.concat("fndsa512/", _setName()));
        UARegistry p = _deploy(address(0x5cec1), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, true));
        UACall.register(p, x.kind, x.keyData, x.attrs, x.pop, ""); // unproven, this set
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, x.ua));
        p.setPqzKey(x.ua, x.attrs.pqzKey, x.attrs.pqzPopHash, UACall.sig(hex"01"));
        _reg(p, rows[FNDSA_ROW]);
        p.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig)); // added, this set
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, k.ua));
        p.setPqzKey(k1.ua, k1.pqzKey, k1.pqzPopHash, UACall.sig(k1.sig));
        // no verifier: the other set's key stays
        UARegistry a = _regA(false);
        Row memory o = _copyOtherSet(a, rows);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, o.ua));
        a.setPqzKey(o.ua, x.attrs.pqzKey, x.attrs.pqzPopHash, UACall.sig(hex"01"));
        _reg(a, rows[FNDSA_ROW]);
        a.setPqzKey(k1.ua, k1.pqzKey, k1.pqzPopHash, UACall.sig(k1.sig));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, k.ua));
        a.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig));
    }

    /// Ruling R-cross-set on generations (A6-I1): gen 1 (no 0x0142) holds a copied other-set key; gen 2 (the verifier)
    /// replaces it in its own attachment and proves it, gen 1 keeps its record; gen 2's `registrationOf` stays gen 1's
    /// `register` arguments (not the new key's proof). Gen 1 itself replaces nothing.
    function test_ua8_crossSetGen2ReplacesGen1Key() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = _pqzRow(rows);
        UARegistry g1 = _regA(false);
        UARegistry g2 = _gen2Pqz(address(0x5cec2), g1);
        Row memory o = _copyOtherSet(g1, rows);
        bytes memory args = abi.encode(o.kind, o.keyData, o.attrs, o.pop, bytes(""));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, x.ua));
        g1.setPqzKey(x.ua, x.attrs.pqzKey, x.attrs.pqzPopHash, UACall.sig(hex"01"));
        bytes memory sig = _setThisSetKey(g2, x);
        _assertThisSetKey(g2, x, sig, false);
        _proveAdded(g2, x);
        _assertThisSetKey(g2, x, sig, true);
        assertEq(keccak256(_stored(g2, x.ua)), keccak256(args), "gen 2's registrationOf: gen 1's register arguments");
        assertEq(keccak256(_stored(g1, x.ua)), keccak256(args));
        (address p1,, bool v1) = g1.pqzKeyOf(x.ua);
        assertEq(abi.encode(SSTORE2.read(p1), v1), abi.encode(o.attrs.pqzKey, false), "gen 1 untouched");
        assertEq(new KeyPtrHarness().keyPtr(address(g2), x.ua), _ptrOf(g2, x.ua));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, x.ua));
        g2.setPqzKey(x.ua, x.attrs.pqzKey, x.attrs.pqzPopHash, UACall.sig(sig));
    }

    function _ptrOf(UARegistry r, bytes32 ua) internal view returns (address ptr) {
        (ptr,,) = r.pqzKeyOf(ua);
    }

    /// Review m3 under the typed ABI (TS-D12): an `msig`'s portable signature comes as `MemberSig[]`, so no other
    /// encoding reaches the registry; what it stores and returns (`popOf`, `pqzKeySigOf`) is exactly the canonical
    /// `abi.encode(MemberSig[])` of the vectors. A portable `UASig` with `keyData` is `UAUnauthorized`.
    function test_ua8_msigPopCanonical() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory m = rows[MSIG_NATIVE_ROW];
        UARegistry a = _regA(false);
        _members(a, rows);
        _reg(a, m);
        assertEq(a.popOf(m.ua), abi.encode(UACall.members(m.pop)));
        assertEq(a.popOf(m.ua), m.pop);
        KeyRec memory k = _keyRec(_keyRecs(), string.concat("msig-pq-native/", _setName()));
        _allowRecord(rows, m, k);
        IUARegistry.UASig memory s = UACall.sig(k.sig);
        s.keyData = m.keyData;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, k.ua));
        a.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, s);
        a.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig));
        assertEq(a.pqzKeySigOf(k.ua), k.sig);
    }

    /// Review n3: a gen 2 over a gen 1 without the UA-8 views (its `pqzKeyOf` / `registrationOf` / `checkedOf` forwards
    /// would revert) is refused at deploy, `UAConfig(0)`.
    function test_ua8_gen2RefusesPreUa8Gen1() public {
        PreUa8Gen1 old = new PreUa8Gen1(chainUidA);
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0)));
        new UARegistry(chainUidA, address(old), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        UARegistry g1 = _regA(false);
        assertEq(_gen2Pqz(address(0x5cec3), g1).predecessor(), address(g1));
    }

    // ----- A7: KEM key records (P4, P5, P7, P9; UA8-D3–D5, D11, D12; rulings C2, C7, A6-m m3) -----

    /// A `kemRecords` row of portable.json: `setKemKey(ua, version, kemPk, sig)`; `message` is what `sig` signs.
    struct KemRec {
        string id;
        string name;
        uint16 kind;
        bytes32 ua;
        uint64 version;
        bytes kemPk;
        bytes32 digest;
        bytes32 message;
        bytes sig;
    }

    function loadKemRecs() external view returns (KemRec[] memory recs) {
        string memory j = vm.readFile(PJ);
        uint256 n;
        while (_jx(j, string.concat(".kemRecords[", vm.toString(n), "]"))) ++n;
        recs = new KemRec[](n);
        for (uint256 i; i < n; ++i) {
            string memory p = string.concat(".kemRecords[", vm.toString(i), "]");
            KemRec memory r = recs[i];
            r.id = _js(j, string.concat(p, ".id"));
            r.name = _js(j, string.concat(p, ".name"));
            r.kind = uint16(_ju(j, string.concat(p, ".kind")));
            r.ua = _jw(j, string.concat(p, ".ua"));
            r.version = uint64(_ju(j, string.concat(p, ".version")));
            r.kemPk = _jb(j, string.concat(p, ".kemPk"));
            r.digest = _jw(j, string.concat(p, ".digest"));
            r.message = _jw(j, string.concat(p, ".message"));
            r.sig = _jb(j, string.concat(p, ".sig"));
        }
    }

    function _kemRecs() internal view returns (KemRec[] memory recs) {
        recs = this.loadKemRecs();
        assertEq(recs.length, 9, "kemRecords: v1-v3 of mldsa65, fndsa512, msig-pq");
        for (uint256 i; i < recs.length; ++i) {
            KemRec memory k = recs[i];
            assertEq(k.digest, UAKinds.kemRecordDigest(k.ua, k.version, k.kemPk), k.id);
            assertEq(k.message, UAKinds.uaMessage(k.kind, UAKinds.PURPOSE_KEM, k.digest), k.id);
        }
    }

    function _kemRec(KemRec[] memory ks, string memory id) internal pure returns (KemRec memory) {
        for (uint256 i; i < ks.length; ++i) {
            if (_eq(ks[i].id, id)) return ks[i];
        }
        revert(string.concat("no KEM record ", id));
    }

    /// The registration row of a KEM record's UA (this build's set for `mldsa65` / `msig-pq`; v1 is its initial record).
    function _kemBase(Row[] memory rows, KemRec memory k) internal pure returns (Row memory) {
        return _eq(k.name, "fndsa512") ? _find(rows, "fndsa512") : _find(rows, string.concat(k.name, "/", _setName()));
    }

    /// The mocked `mldsa65` precompile accepts the record's signature (`msig`: each `mldsa65` member's, under `member`).
    function _allowKem(Row[] memory rows, Row memory base, KemRec memory k) internal {
        if (k.kind == UAKinds.MLDSA65) _allowMl65(base.keyData, k.message, k.sig);
        if (k.kind == UAKinds.MSIG) _allowMembers(rows, base.keyData, UAKinds.memberDigest(k.ua, k.message), k.sig);
    }

    /// The three KEM holders (msig members first) and every KEM record's signature allowed.
    function _kemSetup(UARegistry r, Row[] memory rows, KemRec[] memory ks) internal {
        _allowAll(rows);
        _members(r, rows);
        for (uint256 i; i < ks.length; ++i) {
            Row memory base = _kemBase(rows, ks[i]);
            _allowKem(rows, base, ks[i]);
            if (r.kindOf(base.ua) == 0) _reg(r, base);
        }
    }

    /// Scheme 1 key (`0x01 ‖` pseudo-random 1,600 bytes).
    function _kemPk(uint256 seed) internal pure returns (bytes memory pk) {
        pk = new bytes(1632); // whole words, then cut to the key length
        for (uint256 o; o < pk.length; o += 32) {
            bytes32 w = keccak256(abi.encode("kem", seed, o));
            assembly {
                mstore(add(add(pk, 32), o), w)
            }
        }
        assembly {
            mstore(pk, 1601)
        }
        pk[0] = bytes1(UAKinds.KEM_SCHEME_MLKEM1024_X25519);
    }

    /// An `mldsa65` signature of `pk`'s key over `uaMsg`, accepted by the mocked precompile (that exact input only).
    function _ml65Sig(bytes memory pk, bytes32 uaMsg) internal returns (bytes memory sig) {
        sig = new bytes(3309);
        bytes32 w = keccak256(abi.encode("sig", pk, uaMsg));
        assembly {
            mstore(add(sig, 32), w)
        }
        _allowMl65(pk, uaMsg, sig);
    }

    /// A KEM record of the single-key `mldsa65` row `r`, signed (mocked) over its `PURPOSE_KEM` message.
    function _ml65Kem(Row memory r, uint64 v, bytes memory pk) internal returns (bytes memory) {
        return _ml65Sig(r.keyData, UAKinds.uaMessage(UAKinds.MLDSA65, UAKinds.PURPOSE_KEM, UAKinds.kemRecordDigest(r.ua, v, pk)));
    }

    function _assertKemAt(UARegistry r, bytes32 ua, uint64 v, bytes memory pk, bytes memory sig) internal view {
        (IUARegistry.KemKey memory p, bytes memory s) = r.kemKeyAt(ua, v);
        assertEq(keccak256(abi.encode(UACall.kemPk(p), s)), keccak256(abi.encode(pk, sig)),
            string.concat("kemKeyAt v", vm.toString(v)));
    }

    function _assertKemOf(UARegistry r, bytes32 ua, uint64 v, bytes memory pk, bytes memory sig) internal view {
        (uint64 x, IUARegistry.KemKey memory p, bytes memory s) = r.kemKeyOf(ua);
        assertEq(keccak256(abi.encode(x, UACall.kemPk(p), s)), keccak256(abi.encode(v, pk, sig)), "kemKeyOf");
    }

    /// P4 / UA8-D5: anyone submits the UA's signed KEM record (fndsa512, its real verifier); `kemKeyAt` returns the
    /// written bytes, `kemKeyOf` the highest version; the initial record (v0, from `register`) keeps its empty `sig`.
    function test_ua8_setKemKeyByThirdParty() public {
        Row[] memory rows = _rows();
        KemRec[] memory ks = _kemRecs();
        KemRec memory k2 = _kemRec(ks, "fndsa512/v2");
        UARegistry a = _regA(false);
        _reg(a, rows[FNDSA_ROW]);
        vm.prank(address(0xBEEF), address(0xBEEF));
        a.setKemKey(k2.ua, 2, UACall.kem(k2.kemPk), UACall.sig(k2.sig));
        _assertKemAt(a, k2.ua, 2, k2.kemPk, k2.sig);
        _assertKemAt(a, k2.ua, 0, rows[FNDSA_ROW].kemPk, "");
        _assertKemAt(a, k2.ua, 1, "", "");
        _assertKemAt(a, k2.ua, 3, "", "");
        _assertKemOf(a, k2.ua, 2, k2.kemPk, k2.sig);
        _checkedEq(a, k2.ua, 1, 0, 1);
        assertEq(keccak256(_stored(a, k2.ua)), keccak256(_args(rows[FNDSA_ROW])), "registrationOf: the register args (C2)");
    }

    /// P1 / P10: every portable.json `kemRecords` row lands on two registries (other chain id, uid, address) with the
    /// same bytes; each UA's initial record from `register` is version 0, so every v1-v3 lands (owner 2026-10-31).
    function test_ua8_kemCopyBetweenRegistries() public {
        Row[] memory rows = _rows();
        KemRec[] memory ks = _kemRecs();
        UARegistry a = _regA(false);
        UARegistry b = _regB();
        _kemSetup(a, rows, ks);
        vm.chainId(7622);
        _kemSetup(b, rows, ks);
        uint256 written;
        for (uint256 i; i < ks.length; ++i) {
            KemRec memory k = ks[i];
            UARegistry[2] memory rs = [a, b];
            for (uint256 j; j < 2; ++j) {
                vm.chainId(j == 0 ? 31337 : 7622);
                vm.prank(address(0xC0B1E5), address(0xC0B1E5));
                rs[j].setKemKey(k.ua, k.version, UACall.kem(k.kemPk), UACall.sig(k.sig));
                _assertKemAt(rs[j], k.ua, k.version, k.kemPk, k.sig);
                ++written;
            }
        }
        vm.chainId(31337);
        assertEq(written, 18, "v1, v2 and v3 of three UAs on two registries");
        for (uint256 i; i < ks.length; ++i) {
            (IUARegistry.KemKey memory pa, bytes memory sa) = a.kemKeyAt(ks[i].ua, ks[i].version);
            (IUARegistry.KemKey memory pb, bytes memory sb) = b.kemKeyAt(ks[i].ua, ks[i].version);
            assertEq(keccak256(abi.encode(pa, sa)), keccak256(abi.encode(pb, sb)), ks[i].id);
            if (ks[i].version == 3) {
                _assertKemOf(a, ks[i].ua, 3, ks[i].kemPk, ks[i].sig);
                _assertKemOf(b, ks[i].ua, 3, ks[i].kemPk, ks[i].sig);
            }
        }
    }

    /// UA8-D5: any order — 3, then 1, then 2 on a UA registered without a KEM record: all stored, `kemKeyOf` stays 3.
    function test_ua8_kemLowerVersionAfterHigher() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = rows[ML65_1];
        assertEq(x.kemPk.length, 0);
        UARegistry a = _regA(false);
        _reg(a, x);
        _assertKemOf(a, x.ua, 0, "", "");
        _checkedEq(a, x.ua, 1, 0, 0);
        uint64[3] memory order = [uint64(3), 1, 2];
        bytes[4] memory pks;
        bytes[4] memory sigs;
        for (uint256 i; i < 3; ++i) {
            uint64 v = order[i];
            pks[v] = _kemPk(v);
            sigs[v] = _ml65Kem(x, v, pks[v]);
            a.setKemKey(x.ua, v, UACall.kem(pks[v]), UACall.sig(sigs[v]));
            _assertKemOf(a, x.ua, 3, pks[3], sigs[3]);
            _checkedEq(a, x.ua, 1, 0, 1);
        }
        for (uint64 v = 1; v <= 3; ++v) _assertKemAt(a, x.ua, v, pks[v], sigs[v]);
    }

    /// UA8-D5: write-once per `(ua, version)`: the same bytes again and other (validly signed) bytes are `UAKemVersion`.
    function test_ua8_kemRepeatedVersionRefused() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = rows[ML65_1];
        UARegistry a = _regA(false);
        _reg(a, x);
        bytes memory pk = _kemPk(1);
        bytes memory sig = _ml65Kem(x, 3, pk);
        a.setKemKey(x.ua, 3, UACall.kem(pk), UACall.sig(sig));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 3));
        a.setKemKey(x.ua, 3, UACall.kem(pk), UACall.sig(sig));
        bytes memory other = _kemPk(2);
        bytes memory otherSig = _ml65Kem(x, 3, other);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 3));
        a.setKemKey(x.ua, 3, UACall.kem(other), UACall.sig(otherSig));
        _assertKemAt(a, x.ua, 3, pk, sig);
    }

    /// `setKemKey` never writes version 0 (the `register` key's slot, owner 2026-10-31; R1's hash-commit fill aside): on a
    /// UA registered without a KEM key it is `UAKemVersion(ua, 0)`, even validly signed.
    function test_ua8_kemVersionZeroRefused() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = rows[ML65_1];
        UARegistry a = _regA(false);
        _reg(a, x);
        bytes memory pk = _kemPk(0);
        bytes memory sig = _ml65Kem(x, 0, pk);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 0));
        a.setKemKey(x.ua, 0, UACall.kem(pk), UACall.sig(sig));
        _assertKemOf(a, x.ua, 0, "", "");
    }

    /// P7 / CTR-UA-32: the KEM key is 1,601 bytes (`UAKemKeyLength`, before the signature): 1,600, 1,602 and 0 are
    /// refused; scheme 1 only: scheme 0, the reserved scheme 2 and an unknown id are `UAKemScheme`.
    function test_ua8_kemLengthRefused() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = rows[ML65_1];
        UARegistry a = _regA(false);
        _reg(a, x);
        uint256[3] memory lens = [uint256(1600), 1602, 0];
        for (uint256 i; i < 3; ++i) {
            bytes memory pk = _slice(bytes.concat(_kemPk(7), hex"07"), 0, lens[i]);
            bytes memory sig = _ml65Kem(x, 1, pk);
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemKeyLength.selector, lens[i]));
            a.setKemKey(x.ua, 1, UACall.kem(pk), UACall.sig(sig));
        }
        uint8[3] memory ids = [uint8(0), 2, 0xff];
        for (uint256 i; i < 3; ++i) {
            bytes memory pk = _kemPk(7);
            pk[0] = bytes1(ids[i]);
            bytes memory sig = _ml65Kem(x, 1, pk);
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemScheme.selector, ids[i]));
            a.setKemKey(x.ua, 1, UACall.kem(pk), UACall.sig(sig));
        }
        bytes memory ok = _kemPk(7); // scheme 1 accepted
        a.setKemKey(x.ua, 1, UACall.kem(ok), UACall.sig(_ml65Kem(x, 1, ok)));
    }

    /// P7 / UA8-D12: only the PQ holders (`mldsa44`, `mldsa65`, `fndsa512`, a PQ-eligible `msig`) hold KEM keys:
    /// `secp256k1`, `slhdsa128s` and a classical `msig` are `UAKemHolder`; an unregistered id is `UAUnauthorized`.
    function test_ua8_kemNonHolderRefused() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry a = _regA(false);
        _members(a, rows);
        Row[3] memory xs = [rows[SECP_ROW], rows[SLH_ROW], _find(rows, "msig-classical")];
        bytes memory pk = _kemPk(1);
        for (uint256 i; i < 3; ++i) {
            if (a.kindOf(xs[i].ua) == 0) _reg(a, xs[i]);
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemHolder.selector, xs[i].ua));
            a.setKemKey(xs[i].ua, 1, UACall.kem(pk), UACall.sig(""));
        }
        bytes32 none = keccak256("unregistered");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, none));
        a.setKemKey(none, 1, UACall.kem(pk), UACall.sig(""));
    }

    /// The m-of-n record signature (U5; rulings C7, A1-I2): portable.json's `msig-pq` v2 (2-of-2 `mldsa65` members)
    /// lands, one member alone does not. A 2-of-3 PQ-eligible `msig` (two `mldsa65` members, one code-less native
    /// member signing the typed `UAKemRecord` digest) takes every 2-member subset and refuses a single member,
    /// out-of-order members and the native member's UAAuth (EIP-712) signature.
    function test_ua8_kemMsigMofN() public {
        Row[] memory rows = _rows();
        KemRec[] memory ks = _kemRecs();
        UARegistry a = _regA(false);
        _kemSetup(a, rows, ks);
        KemRec memory k = _kemRec(ks, "msig-pq/v2");
        IUARegistry.MemberSig[] memory s = UACall.memberSigs(k.sig);
        assertEq(s.length, 2);
        IUARegistry.MemberSig[] memory one = new IUARegistry.MemberSig[](1);
        one[0] = s[0];
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, k.ua));
        a.setKemKey(k.ua, 2, UACall.kem(k.kemPk), UACall.sig(abi.encode(one)));
        a.setKemKey(k.ua, 2, UACall.kem(k.kemPk), UACall.sig(k.sig));
        _assertKemAt(a, k.ua, 2, k.kemPk, k.sig);
        // 2-of-3 with a native member
        uint256 sk = _nativeSk();
        (bytes memory d, bytes32 ua) = _msig2of3(a, rows, sk);
        bytes memory pk = _kemPk(23);
        _kemSubsets(a, rows, d, ua, pk, sk);
        _kemNativeUAAuth(a, rows, d, ua, pk, sk);
    }

    /// A 2-of-3 PQ-eligible `msig` of `mldsa65#1`, `mldsa65#2` and the native `sk`, registered on `a`.
    function _msig2of3(UARegistry a, Row[] memory rows, uint256 sk) internal returns (bytes memory d, bytes32 ua) {
        Member[] memory mm = new Member[](3);
        mm[0] = Member(UAKinds.MLDSA65, rows[ML65_1].ua, 1);
        mm[1] = Member(UAKinds.MLDSA65, rows[ML65_1 + 1].ua, 1);
        mm[2] = Member(UAKinds.EVM_EOA, _pad(vm.addr(sk)), 1);
        d = _msigKey(2, mm);
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes memory pop = _msigSigs(rows, d, ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG), 0, 1, sk);
        assertEq(UACall.register(a, UAKinds.MSIG, d, _none(), pop, ""), ua);
        _acceptSlot(a, rows, d, ua, 2, sk); // the third slot, outside the `pop`
    }

    /// Versions 1–3 signed by each 2-member subset land; one member, and two out of order, are refused.
    function _kemSubsets(UARegistry a, Row[] memory rows, bytes memory d, bytes32 ua, bytes memory pk, uint256 sk)
        internal
    {
        uint8[2][3] memory pairs = [[0, 1], [0, 2], [1, 2]];
        for (uint64 v = 1; v <= 3; ++v) {
            bytes32 kd = UAKinds.kemRecordDigest(ua, v, pk);
            bytes memory sig = _msigSigs(rows, d, ua, UAKinds.PURPOSE_KEM, kd, pairs[v - 1][0], pairs[v - 1][1], sk);
            IUARegistry.MemberSig[] memory p = UACall.memberSigs(sig);
            IUARegistry.MemberSig[] memory bad = new IUARegistry.MemberSig[](1);
            bad[0] = p[1];
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
            a.setKemKey(ua, v, UACall.kem(pk), UACall.sig(abi.encode(bad))); // one member: below the threshold
            bad = new IUARegistry.MemberSig[](2);
            bad[0] = p[1];
            bad[1] = p[0];
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
            a.setKemKey(ua, v, UACall.kem(pk), UACall.sig(abi.encode(bad))); // out of order
            a.setKemKey(ua, v, UACall.kem(pk), UACall.sig(sig));
            _assertKemAt(a, ua, v, pk, sig);
        }
    }

    /// The native member's UAAuth signature (chain-bound) and its `personal_sign` of `memberDigest` (the pre-typed form)
    /// instead of its signature over the typed `UAKemRecord` digest are refused; the typed signature lands (TS-D4).
    function _kemNativeUAAuth(UARegistry a, Row[] memory rows, bytes memory d, bytes32 ua, bytes memory pk, uint256 sk)
        internal
    {
        uint256 ni;
        for (uint256 i; i < 3; ++i) {
            (uint16 kind,) = _member(d, i);
            if (kind == UAKinds.EVM_EOA) ni = i;
        }
        bytes32 kd = UAKinds.kemRecordDigest(ua, 4, pk);
        bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_KEM, kd));
        uint256 other = ni == 0 ? 1 : 0;
        IUARegistry.MemberSig[] memory q = UACall.memberSigs(_msigSigs(rows, d, ua, UAKinds.PURPOSE_KEM, kd, other < ni ? other : ni, other < ni ? ni : other, sk));
        uint256 qn = q[0].index == ni ? 0 : 1;
        bytes memory typedSig = q[qn].sig;
        q[qn].sig = _nativeSig(a, sk, UAKinds.PURPOSE_MEMBER, md);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        a.setKemKey(ua, 4, UACall.kem(pk), UACall.sig(abi.encode(q)));
        q[qn].sig = _ecdsa(sk, MessageHashUtils.toEthSignedMessageHash(md));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        a.setKemKey(ua, 4, UACall.kem(pk), UACall.sig(abi.encode(q)));
        q[qn].sig = typedSig;
        a.setKemKey(ua, 4, UACall.kem(pk), UACall.sig(abi.encode(q)));
        _assertKemOf(a, ua, 4, pk, abi.encode(q));
    }

    /// The `MemberSig[]` of members `i < j` of the `msig` `d` over the portable record's typed digest `typed` under
    /// `purpose`: an `mldsa65` member under `member` over `memberDigest(ua, uaMessage(MSIG, purpose, typed))` (mocked), a
    /// native member over `typed` itself with `sk` (TS-D4).
    function _msigSigs(
        Row[] memory rows,
        bytes memory d,
        bytes32 ua,
        bytes32 purpose,
        bytes32 typed,
        uint256 i,
        uint256 j,
        uint256 sk
    ) internal returns (bytes memory) {
        bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purpose, typed));
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](2);
        s[0] = IUARegistry.MemberSig(uint16(i), new IUARegistry.InnerSig[](0), _memberSig(rows, d, i, md, typed, sk));
        s[1] = IUARegistry.MemberSig(uint16(j), new IUARegistry.InnerSig[](0), _memberSig(rows, d, j, md, typed, sk));
        return abi.encode(s);
    }

    function _memberSig(Row[] memory rows, bytes memory d, uint256 index, bytes32 md, bytes32 typed, uint256 sk)
        internal
        returns (bytes memory)
    {
        (uint16 kind, bytes32 id) = _member(d, index);
        if (kind == UAKinds.EVM_EOA) return _ecdsa(sk, typed);
        return _ml65Sig(_byUa(rows, id).keyData, UAKinds.uaMessage(UAKinds.MLDSA65, UAKinds.PURPOSE_MEMBER, md));
    }

    /// The record's signature (`UAUnauthorized`): portable.json's `setKemKey` negatives (another version's signature,
    /// another UA's record), and a flipped byte; each record with its own bytes then lands.
    function test_ua8_kemBadSigRefused() public {
        Row[] memory rows = _rows();
        KemRec[] memory ks = _kemRecs();
        Neg[] memory negs = this.loadNegs();
        UARegistry a = _regA(false);
        _kemSetup(a, rows, ks);
        uint256 n;
        for (uint256 i; i < negs.length; ++i) {
            Neg memory g = negs[i];
            if (!_eq(g.entry, "setKemKey")) continue;
            assertEq(g.err, "UAUnauthorized");
            KemRec memory k0 = _kemRec(ks, g.row);
            (bytes32 ua, bytes memory sig) = (k0.ua, k0.sig);
            for (uint256 f; f < g.keys.length; ++f) {
                if (_eq(g.keys[f], "ua")) ua = bytes32(g.values[f]);
                else if (_eq(g.keys[f], "sig")) sig = g.values[f];
                else revert(string.concat(g.name, ": unknown mutation ", g.keys[f]));
            }
            assertTrue(a.kindOf(ua) != 0, "the target UA is registered (the signature is what fails)");
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
            a.setKemKey(ua, k0.version, UACall.kem(k0.kemPk), UACall.sig(sig));
            _assertKemAt(a, ua, k0.version, "", "");
            ++n;
        }
        assertEq(n, 2, "kem-sig-of-other-version, kem-record-of-other-ua");
        KemRec memory k = _kemRec(ks, "fndsa512/v2");
        bytes memory flipped = bytes.concat(k.sig);
        flipped[flipped.length / 2] ^= 0x01;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, k.ua));
        a.setKemKey(k.ua, 2, UACall.kem(k.kemPk), UACall.sig(flipped));
        string[2] memory ok = [string("fndsa512/v2"), "mldsa65/v3"];
        for (uint256 i; i < 2; ++i) {
            KemRec memory r = _kemRec(ks, ok[i]);
            a.setKemKey(r.ua, r.version, UACall.kem(r.kemPk), UACall.sig(r.sig));
            _assertKemAt(a, r.ua, r.version, r.kemPk, r.sig);
        }
    }

    /// P7: no owner check — two UAs list the same KEM key, each under its own signature.
    function test_ua8_kemNoOwnerCheck() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry a = _regA(false);
        Row memory x = rows[ML65_1];
        Row memory y = rows[ML65_1 + 1];
        assertEq(y.name, "mldsa65#2");
        _reg(a, x);
        _reg(a, y);
        bytes memory pk = _kemPk(42);
        bytes memory sx = _ml65Kem(x, 1, pk);
        bytes memory sy = _ml65Kem(y, 5, pk);
        a.setKemKey(x.ua, 1, UACall.kem(pk), UACall.sig(sx));
        a.setKemKey(y.ua, 5, UACall.kem(pk), UACall.sig(sy));
        _assertKemOf(a, x.ua, 1, pk, sx);
        _assertKemOf(a, y.ua, 5, pk, sy);
    }

    /// Ruling A6-m m3 (spec P2): `UAKemKeySet` carries the written bytes (`kemPk`, `sig`) with `keccak256(kemPk)`; the
    /// only log of the call. The gas of each holder kind's record is logged (`mldsa65`: its precompile mocked).
    function test_ua8_kemEvent() public {
        Row[] memory rows = _rows();
        KemRec[] memory ks = _kemRecs();
        UARegistry a = _regA(false);
        _kemSetup(a, rows, ks);
        string[3] memory ids = [string("fndsa512/v2"), "mldsa65/v2", "msig-pq/v2"];
        for (uint256 i; i < 3; ++i) {
            KemRec memory k = _kemRec(ks, ids[i]);
            vm.recordLogs();
            vm.expectEmit(true, true, false, true, address(a));
            emit IUARegistry.UAKemKeySet(k.ua, k.version, keccak256(k.kemPk), UACall.kem(k.kemPk), k.sig);
            uint256 g = gasleft();
            a.setKemKey(k.ua, k.version, UACall.kem(k.kemPk), UACall.sig(k.sig));
            g -= gasleft();
            VmSafe.Log[] memory logs = vm.getRecordedLogs();
            uint256 mine;
            for (uint256 l; l < logs.length; ++l) {
                if (logs[l].emitter == address(a)) ++mine;
            }
            assertEq(mine, 1, "one log");
            uint256 data = abi.encode(keccak256(k.kemPk), k.kemPk, k.sig).length;
            emit log_named_uint(string.concat("setKemKey gas, ", k.id, " (sig ", vm.toString(k.sig.length),
                " B; event data B ", vm.toString(data), ")"), g);
        }
    }

    /// UA8-D11 (A6 re-review note): gen 2 refuses a KEM record for a record gen 1 holds (`UAUnauthorized`: it goes to
    /// gen 1), even where `_sigOk` could verify it — a holder kind gen 2 does not enable falls back to gen 1's
    /// `requireAuthorized` (accepted here), an `msig` hands its members to gen 1 (the same bytes land on gen 2 for a
    /// record gen 2 holds) — and even on a gen 2 that holds gen-1 records' PQZ attachments (ruling A6-I1). Gen 1 takes
    /// the record; gen 2 forwards `kemKeyOf` / `kemKeyAt`.
    function test_ua8_kemGen2RecordElsewhereRefused() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        KemRec[] memory ks = _kemRecs();
        UARegistry g1 = _regA(false);
        _members(g1, rows);
        UARegistry g2 = _gen2Pqz(address(0x5cebe), g1);
        string[2] memory ids = [string("fndsa512/v2"), "msig-pq/v2"];
        for (uint256 i; i < 2; ++i) {
            KemRec memory k = _kemRec(ks, ids[i]);
            Row memory base = _kemBase(rows, k);
            _allowKem(rows, base, k);
            uint256 snap = vm.snapshotState();
            _reg(g1, base);
            if (k.kind == UAKinds.FNDSA512) {
                assertFalse(g2.kindEnabled(UAKinds.FNDSA512));
                g1.requireAuthorized(k.ua, UAKinds.PURPOSE_KEM, k.digest, UACall.auth(k.ua, abi.encode(bytes(""), k.sig))); // _sigOk's fallback
            }
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, k.ua));
            g2.setKemKey(k.ua, k.version, UACall.kem(k.kemPk), UACall.sig(k.sig));
            _assertKemAt(g2, k.ua, k.version, "", "");
            g1.setKemKey(k.ua, k.version, UACall.kem(k.kemPk), UACall.sig(k.sig));
            _assertKemOf(g2, k.ua, k.version, k.kemPk, k.sig);
            _assertKemAt(g2, k.ua, k.version, k.kemPk, k.sig);
            _assertKemAt(g2, k.ua, 0, base.kemPk, "");
            if (k.kind == UAKinds.MSIG) {
                // a record gen 2 holds (members on gen 1): the same bytes land on gen 2
                vm.revertToState(snap);
                _allowPqz(base);
                _reg(g2, base);
                g2.setKemKey(k.ua, k.version, UACall.kem(k.kemPk), UACall.sig(k.sig));
                _assertKemOf(g2, k.ua, k.version, k.kemPk, k.sig);
                _assertKemOf(g1, k.ua, 0, "", "");
            }
            vm.revertToState(snap);
        }
    }

    /// Owner 2026-10-31 (KEM items 1, 4): `register`'s KEM key is version 0, write-once — `setKemKey` of version 0
    /// (its own bytes, other bytes) is `UAKemVersion(ua, 0)` and leaves it unchanged; `kemKeyAt(ua, 0)` returns it with an
    /// empty `sig` (its consent is the pop), `kemKeyOf` it until a later version lands; a stored v1 is write-once too;
    /// `registrationOf` keeps returning the `register` arguments after later records.
    function test_ua8_kemInitialVersionFromRegister() public {
        Row[] memory rows = _rows();
        KemRec[] memory ks = _kemRecs();
        Row memory x = rows[FNDSA_ROW];
        KemRec memory k1 = _kemRec(ks, "fndsa512/v1");
        KemRec memory k3 = _kemRec(ks, "fndsa512/v3");
        assertTrue(keccak256(x.kemPk) != keccak256(k1.kemPk), "v0 is a key of its own");
        UARegistry a = _regA(false);
        _reg(a, x);
        _assertKemAt(a, x.ua, 0, x.kemPk, "");
        _assertKemOf(a, x.ua, 0, x.kemPk, "");
        _checkedEq(a, x.ua, 1, 0, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 0));
        a.setKemKey(x.ua, 0, UACall.kem(x.kemPk), UACall.sig(""));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 0));
        a.setKemKey(x.ua, 0, UACall.kem(k1.kemPk), UACall.sig(k1.sig));
        _assertKemAt(a, x.ua, 0, x.kemPk, "");
        a.setKemKey(x.ua, 1, UACall.kem(k1.kemPk), UACall.sig(k1.sig));
        _assertKemOf(a, x.ua, 1, k1.kemPk, k1.sig);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 1));
        a.setKemKey(x.ua, 1, UACall.kem(k1.kemPk), UACall.sig(k1.sig));
        a.setKemKey(x.ua, 3, UACall.kem(k3.kemPk), UACall.sig(k3.sig));
        _assertKemOf(a, x.ua, 3, k3.kemPk, k3.sig);
        _assertKemAt(a, x.ua, 0, x.kemPk, "");
        _assertKemAt(a, x.ua, 1, k1.kemPk, k1.sig);
        assertEq(keccak256(_stored(a, x.ua)), keccak256(_args(x)), "registrationOf: the register args (C2)");
    }

    // ----- typed-signing R1: the explicit registry ABI (TS-D10 … TS-D12; owner KEM rulings 2026-10-31) -----

    function _here(Row memory x) internal pure returns (bool) {
        return bytes(x.set).length == 0 || _eq(x.set, _setName());
    }

    /// An empty `UASig`: the hash-commit fill's (its consent is the PoP).
    function _noSig() internal pure returns (IUARegistry.UASig memory) {}

    /// TS-D10: every `msig` row registers through `registerMsig` with its typed structure and `MemberSig[]` pop; the id
    /// is the packed CTR-UA-09 key data's (`uaOf(0x0120, keyData)`, the structure round-trips those bytes), and
    /// `register(0x0120, …)` is refused (`UAKeyData(0x0120)`: one accepted form).
    function test_registerMsigTypedMembersSameId() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry a = _regA(false);
        _members(a, rows);
        uint256 n;
        for (uint256 i; i < rows.length; ++i) {
            Row memory x = rows[i];
            if (x.kind != UAKinds.MSIG || !_here(x)) continue;
            IUARegistry.MsigStructure memory s = UACall.structure(x.keyData);
            assertEq(UACall.keyData(s), x.keyData, "the structure is the packed key data");
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
            a.register(UAKinds.MSIG, x.keyData, x.attrs, x.pop, x.pqzPop);
            assertEq(a.registerMsig(s, x.attrs, UACall.members(x.pop), x.pqzPop), x.ua, x.name);
            assertEq(x.ua, UAKinds.uaOf(UAKinds.MSIG, x.keyData), x.name);
            ++n;
        }
        assertEq(n, 3, "msig-classical, msig-pq/<set>, msig-pq-native");
    }

    /// TS-D10: `msigOf` is the typed structure of a registered `msig` (its packed key data's fields), empty for every
    /// other id (single keys, unregistered); a gen 2 forwards a gen-1 record.
    function test_msigOfRoundTrip() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry a = _regA(false);
        _registerAll(a, rows);
        IUARegistry.MsigStructure memory empty;
        uint256 n;
        for (uint256 i; i < rows.length; ++i) {
            Row memory x = rows[i];
            if (!_here(x)) continue;
            IUARegistry.MsigStructure memory s = a.msigOf(x.ua);
            if (x.kind != UAKinds.MSIG) {
                assertEq(abi.encode(s), abi.encode(empty), x.name);
                continue;
            }
            assertEq(abi.encode(s), abi.encode(UACall.structure(x.keyData)), x.name);
            assertEq(UACall.keyData(s), x.keyData, x.name);
            UARegistry g2 = _gen2Pqz(address(uint160(0x5ce0f0 + i)), a);
            assertEq(abi.encode(g2.msigOf(x.ua)), abi.encode(s), "gen 2 forwards");
            ++n;
        }
        assertEq(n, 3);
        assertEq(abi.encode(a.msigOf(keccak256("unregistered"))), abi.encode(empty));
    }

    /// TS-D10 / TS-D11: `registrationOf` returns the key data and pop bytes exactly as the packed ABI took them (an
    /// `msig`: the CTR-UA-09 bytes and `abi.encode(MemberSig[])`, "" without a pop) and the attributes typed, the KEM key
    /// assembling back to the row's `kemPk`; `popOf` the same pop bytes.
    function test_registrationOfUnchangedBytes() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry a = _regA(false);
        uint256 n = _registerAll(a, rows);
        uint256 m;
        for (uint256 i; i < rows.length; ++i) {
            Row memory x = rows[i];
            if (!_here(x)) continue;
            (uint16 k, bytes memory d, IUARegistry.UAAttrs memory at, bytes memory p, bytes memory z) = a.registrationOf(x.ua);
            assertEq(k, x.kind, x.name);
            assertEq(d, x.keyData, x.name);
            assertEq(p, x.pop, x.name);
            assertEq(z, x.pqzPop, x.name);
            assertEq(a.popOf(x.ua), x.pop, x.name);
            assertEq(UACall.kemPk(at.kem), x.kemPk, x.name);
            assertEq(at.kemPkHash, bytes32(0), x.name);
            assertEq(at.pqzKey, x.attrs.pqzKey, x.name);
            assertEq(at.pqzPopHash, x.attrs.pqzPopHash, x.name);
            ++m;
        }
        assertEq(m, n);
    }

    /// TS-D11: the KEM key travels as `KemKey{scheme, mlkemEk, x25519}`; the registry assembles `scheme ‖ ek ‖ x25519`
    /// (1,601 B: the row's `kemPk`), hashes the record over those bytes (the views agree with `UAKinds` and the vectors;
    /// the empty key is the zero record), and gives the typed key back (`kemKeyAt`, `kemKeyOf`, `UAKemKeySet`).
    function test_kemKeyAssembledBytes() public {
        Row[] memory rows = _rows();
        KemRec[] memory ks = _kemRecs();
        Row memory x = rows[FNDSA_ROW];
        KemRec memory k2 = _kemRec(ks, "fndsa512/v2");
        UARegistry a = _regA(false);
        IUARegistry.KemKey memory key = x.attrs.kem;
        assertEq(key.scheme, UAKinds.KEM_SCHEME_MLKEM1024_X25519);
        assertEq(key.mlkemEk.length, 1568);
        assertEq(abi.encodePacked(key.scheme, key.mlkemEk, key.x25519), x.kemPk);
        assertEq(a.kemRecordHash(x.ua, 0, key), UAKinds.kemRecordHash(x.ua, 0, x.kemPk));
        IUARegistry.KemKey memory none_;
        assertEq(a.kemRecordHash(x.ua, 0, none_), UAKinds.kemRecordHash(x.ua, 0, ""), "the zero record");
        IUARegistry.KemKey memory key2 = UACall.kem(k2.kemPk);
        assertEq(a.kemRecordDigest(x.ua, 2, key2), k2.digest);
        _reg(a, x);
        (IUARegistry.KemKey memory got, bytes memory sig) = a.kemKeyAt(x.ua, 0);
        assertEq(abi.encode(got), abi.encode(key));
        assertEq(sig, "");
        vm.expectEmit(true, true, false, true, address(a));
        emit IUARegistry.UAKemKeySet(x.ua, 2, keccak256(k2.kemPk), key2, k2.sig);
        a.setKemKey(x.ua, 2, key2, UACall.sig(k2.sig));
        (uint64 v, IUARegistry.KemKey memory top, bytes memory s2) = a.kemKeyOf(x.ua);
        assertEq(v, 2);
        assertEq(abi.encode(top), abi.encode(key2));
        assertEq(s2, k2.sig);
    }

    /// portable.json `registrations[i].args` / `.kemCommit` (typed-signing R1), the fields the EVM ABI takes.
    struct ArgRow {
        string entry;
        IUARegistry.MsigStructure structure;
        IUARegistry.WebAuthnKey key;
        IUARegistry.KemKey kem;
        bool commit;
        IUARegistry.KemKey commitKem;
        bytes32 commitHash;
        IUARegistry.KemKey fillKem;
        uint256 fillVersion;
    }

    function loadArgs() external view returns (ArgRow[] memory a) {
        string memory j = vm.readFile(PJ);
        uint256 n;
        while (_jx(j, string.concat(".registrations[", vm.toString(n), "]"))) ++n;
        a = new ArgRow[](n);
        for (uint256 i; i < n; ++i) {
            string memory p = string.concat(".registrations[", vm.toString(i), "].");
            a[i].entry = _js(j, string.concat(p, "args.entry"));
            a[i].kem = _kemAt(j, string.concat(p, "args.attrs.kem."));
            if (_eq(a[i].entry, "registerWebAuthn")) {
                a[i].key = IUARegistry.WebAuthnKey(_jw(j, string.concat(p, "args.key.x")),
                    _jw(j, string.concat(p, "args.key.y")), _jw(j, string.concat(p, "args.key.rpIdHash")));
            }
            if (_eq(a[i].entry, "registerMsig")) {
                a[i].structure.threshold = uint16(_ju(j, string.concat(p, "args.structure.threshold")));
                uint256 m;
                while (_jx(j, string.concat(p, "args.structure.members[", vm.toString(m), "]"))) ++m;
                a[i].structure.members = new IUARegistry.MsigMember[](m);
                for (uint256 k; k < m; ++k) {
                    string memory e = string.concat(p, "args.structure.members[", vm.toString(k), "].");
                    a[i].structure.members[k] = IUARegistry.MsigMember(uint16(_ju(j, string.concat(e, "kind"))),
                        _jw(j, string.concat(e, "id")), uint16(_ju(j, string.concat(e, "weight"))));
                }
            }
            a[i].commit = _jx(j, string.concat(p, "kemCommit"));
            if (!a[i].commit) continue;
            a[i].commitKem = _kemAt(j, string.concat(p, "kemCommit.register.attrs.kem."));
            a[i].commitHash = _jw(j, string.concat(p, "kemCommit.register.attrs.kemPkHash"));
            a[i].fillKem = _kemAt(j, string.concat(p, "kemCommit.fill.kem."));
            a[i].fillVersion = _ju(j, string.concat(p, "kemCommit.fill.version"));
        }
    }

    function _kemAt(string memory j, string memory p) internal pure returns (IUARegistry.KemKey memory k) {
        k.scheme = uint8(_ju(j, string.concat(p, "scheme")));
        k.mlkemEk = _jb(j, string.concat(p, "mlkemEk"));
        k.x25519 = _jw(j, string.concat(p, "x25519"));
    }

    /// portable.json's typed arguments (R1, R1b) are the EVM ABI's: `registerMsig` with the structure of the packed key
    /// data for every msig row, `registerWebAuthn` with the typed key of the webauthn-p256 row, `register` otherwise; the `KemKey` of the row's `kemPk`; a KEM row's `kemCommit` = the scheme
    /// alone + `keccak256(kemPk)`, filled by `setKemKey(ua, 0, the key)`.
    function test_registrationArgsFromVectors() public view {
        Row[] memory rows = _rows();
        ArgRow[] memory a = this.loadArgs();
        uint256 commits;
        for (uint256 i; i < rows.length; ++i) {
            Row memory x = rows[i];
            assertEq(a[i].entry, x.kind == UAKinds.MSIG ? "registerMsig"
                : x.kind == UAKinds.WEBAUTHN_P256 ? "registerWebAuthn" : "register", x.name);
            if (x.kind == UAKinds.WEBAUTHN_P256) assertEq(abi.encode(a[i].key), abi.encode(UACall.webAuthnKey(x.keyData)));
            assertEq(abi.encode(a[i].kem), abi.encode(x.attrs.kem), x.name);
            if (x.kind == UAKinds.MSIG) assertEq(abi.encode(a[i].structure), abi.encode(UACall.structure(x.keyData)), x.name);
            assertEq(a[i].commit, x.kemPk.length != 0, x.name);
            if (!a[i].commit) continue;
            IUARegistry.UAAttrs memory c = UACall.commit(x.attrs);
            assertEq(abi.encode(a[i].commitKem), abi.encode(c.kem), x.name);
            assertEq(a[i].commitHash, c.kemPkHash, x.name);
            assertEq(abi.encode(a[i].fillKem), abi.encode(x.attrs.kem), x.name);
            assertEq(a[i].fillVersion, 0, x.name);
            ++commits;
        }
        assertEq(commits, 9, "fndsa512, mldsa65 and msig-pq at four sets");
    }

    /// The KEM holder rows of this build: fndsa512, mldsa65/<set>, msig-pq/<set> (members registered).
    function _kemHolders(UARegistry a, Row[] memory rows) internal returns (Row[3] memory h) {
        _allowAll(rows);
        _members(a, rows);
        h = [_find(rows, "fndsa512"), _find(rows, string.concat("mldsa65/", _setName())),
            _find(rows, string.concat("msig-pq/", _setName()))];
        for (uint256 i; i < 3; ++i) assertEq(h[i].kemPk.length, 1601, h[i].name);
    }

    /// Owner 2026-10-31 (KEM items 2, 3): `register` with the KEM record's hash only (`kem` = the scheme, `kemPkHash`)
    /// verifies the row's own pop — both forms sign `UAKemRecord{ua, 0, scheme, kemPkHash}` — and stores no key:
    /// `kemKeyOf` / `kemKeyAt(ua, 0)` return nothing, `checkedOf` kem is NONE. Anyone then fills version 0 with
    /// `setKemKey(ua, 0, key, UASig())` (no signature): the key reads back, kem is CHAIN, `UAKemKeySet(ua, 0, …, "")`,
    /// and `registrationOf` still returns the committed `register` arguments. A single key, `mldsa65` with a PQZ key and
    /// a PQ-eligible `msig`.
    function test_kemHashCommitThenFill() public {
        Row[] memory rows = _rows();
        UARegistry a = _regA(false);
        Row[3] memory h = _kemHolders(a, rows);
        for (uint256 i; i < 3; ++i) {
            Row memory x = h[i];
            IUARegistry.UAAttrs memory c = UACall.commit(x.attrs);
            assertEq(c.kem.mlkemEk.length, 0);
            assertEq(c.kemPkHash, keccak256(x.kemPk));
            assertEq(UACall.register(a, x.kind, x.keyData, c, x.pop, x.pqzPop), x.ua, x.name);
            _assertKemOf(a, x.ua, 0, "", "");
            _assertKemAt(a, x.ua, 0, "", "");
            _checkedEq(a, x.ua, 1, 0, 0);
            (,, IUARegistry.UAAttrs memory at,,) = a.registrationOf(x.ua);
            assertEq(abi.encode(at), abi.encode(c), "registrationOf: the committed form");
            vm.expectEmit(true, true, false, true, address(a));
            emit IUARegistry.UAKemKeySet(x.ua, 0, keccak256(x.kemPk), x.attrs.kem, "");
            vm.prank(address(0xF111), address(0xF111));
            a.setKemKey(x.ua, 0, x.attrs.kem, _noSig());
            _assertKemOf(a, x.ua, 0, x.kemPk, "");
            _assertKemAt(a, x.ua, 0, x.kemPk, "");
            _checkedEq(a, x.ua, 1, 0, 1);
            (,, at,,) = a.registrationOf(x.ua);
            assertEq(abi.encode(at), abi.encode(c), "registrationOf: still the committed form");
        }
    }

    /// PRV L7, `_kemHash`'s commit branch for a record here: `storePqzPop` after a hash-committed `register` proves over the
    /// row's own `pqzRegMessage` (the committed record is the same record), the key not filled yet (`mldsa65`) or filled
    /// (a PQ-eligible `msig`). The stand-in verifier accepts exactly that message.
    function test_storePqzPopAfterKemHashCommit() public {
        Row[] memory rows = _rows();
        UARegistry a = _regA(true);
        Row[3] memory h = _kemHolders(a, rows);
        for (uint256 i = 1; i < 3; ++i) {
            Row memory x = h[i];
            assertEq(UACall.register(a, x.kind, x.keyData, UACall.commit(x.attrs), x.pop, ""), x.ua, x.name);
            if (i == 2) a.setKemKey(x.ua, 0, x.attrs.kem, _noSig());
            _allowPqz(x);
            a.storePqzPop(x.ua, x.pqzPop);
            assertTrue(_proven(a, x.ua), x.name);
        }
    }

    /// PRV L7, `_kemHash`'s commit branch on a gen-2 host: gen 2 proves a gen-1 record's hash-committed `register` key, the
    /// commit read from gen 1's `registrationOf`, unfilled (`mldsa65`) or filled there (a PQ-eligible `msig`).
    function test_storePqzPopAfterKemHashCommitGen2Host() public {
        Row[] memory rows = _rows();
        UARegistry g1 = _regA(false);
        Row[3] memory h = _kemHolders(g1, rows);
        UARegistry g2 = _gen2Pqz(address(0x5cebd), g1);
        for (uint256 i = 1; i < 3; ++i) {
            Row memory x = h[i];
            assertEq(UACall.register(g1, x.kind, x.keyData, UACall.commit(x.attrs), x.pop, ""), x.ua, x.name);
            if (i == 2) g1.setKemKey(x.ua, 0, x.attrs.kem, _noSig());
            _allowPqz(x);
            g2.storePqzPop(x.ua, x.pqzPop);
            assertTrue(_proven(g2, x.ua), x.name);
        }
    }

    /// Owner 2026-10-31 (KEM item 4): every version is write-once. `setKemKey` on version 0 stored by `register`, on
    /// version 0 after the hash-commit fill, and on a stored version ≥ 1 each revert `UAKemVersion` and leave the stored
    /// key unchanged — the same key again and another key, signed or not.
    function test_setKemKeyNeverOverwrites() public {
        Row[] memory rows = _rows();
        KemRec[] memory ks = _kemRecs();
        Row memory x = rows[FNDSA_ROW];
        KemRec memory k1 = _kemRec(ks, "fndsa512/v1");
        KemRec memory k2 = _kemRec(ks, "fndsa512/v2");
        IUARegistry.KemKey memory other = UACall.kem(k1.kemPk);
        // version 0 stored by register (the full key)
        UARegistry a = _regA(false);
        _reg(a, x);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 0));
        a.setKemKey(x.ua, 0, x.attrs.kem, _noSig());
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 0));
        a.setKemKey(x.ua, 0, other, UACall.sig(k1.sig));
        _assertKemAt(a, x.ua, 0, x.kemPk, "");
        // version 0 after the hash-commit fill
        UARegistry b = _deploy(address(0x5ce0b), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, false));
        UACall.register(b, x.kind, x.keyData, UACall.commit(x.attrs), x.pop, x.pqzPop);
        b.setKemKey(x.ua, 0, x.attrs.kem, _noSig());
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 0));
        b.setKemKey(x.ua, 0, x.attrs.kem, _noSig());
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 0));
        b.setKemKey(x.ua, 0, other, _noSig());
        _assertKemAt(b, x.ua, 0, x.kemPk, "");
        // a stored version >= 1
        a.setKemKey(x.ua, 1, other, UACall.sig(k1.sig));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 1));
        a.setKemKey(x.ua, 1, other, UACall.sig(k1.sig));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 1));
        a.setKemKey(x.ua, 1, UACall.kem(k2.kemPk), UACall.sig(k2.sig));
        _assertKemAt(a, x.ua, 1, k1.kemPk, k1.sig);
        _assertKemAt(a, x.ua, 0, x.kemPk, "");
    }

    /// `setKemKey(ua, 0, …)` on a UA that never committed a KEM hash — a holder registered without a KEM key — is
    /// `UAKemVersion(ua, 0)`, without a signature and validly signed alike; nothing is stored.
    function test_setKemKeyV0WithoutCommitReverts() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = rows[ML65_1];
        assertEq(x.kemPk.length, 0);
        UARegistry a = _regA(false);
        _reg(a, x);
        bytes memory pk = _kemPk(0);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 0));
        a.setKemKey(x.ua, 0, UACall.kem(pk), _noSig());
        bytes memory sig = _ml65Kem(x, 0, pk);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 0));
        a.setKemKey(x.ua, 0, UACall.kem(pk), UACall.sig(sig));
        _assertKemOf(a, x.ua, 0, "", "");
        _checkedEq(a, x.ua, 1, 0, 0);
    }

    /// The hash-commit fill takes exactly the committed key: another (valid) key is `UAKemKeyHash(ua)`, a key of the wrong
    /// shape `UAKemKeyLength` / `UAKemScheme` (checked first), a non-empty `sig` (any field) `UAUnauthorized(ua)` (the PoP
    /// is the consent); nothing is stored, and the right key still lands afterwards.
    function test_setKemKeyV0WrongKeyReverts() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = rows[FNDSA_ROW];
        UARegistry a = _regA(false);
        UACall.register(a, x.kind, x.keyData, UACall.commit(x.attrs), x.pop, x.pqzPop);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemKeyHash.selector, x.ua));
        a.setKemKey(x.ua, 0, UACall.kem(_kemPk(7)), _noSig());
        IUARegistry.KemKey memory k = UACall.kem(x.kemPk);
        k.x25519 = ~k.x25519;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemKeyHash.selector, x.ua));
        a.setKemKey(x.ua, 0, k, _noSig());
        k = UACall.kem(x.kemPk);
        k.mlkemEk = _slice(k.mlkemEk, 0, 1567);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemKeyLength.selector, 1600));
        a.setKemKey(x.ua, 0, k, _noSig());
        k = UACall.kem(x.kemPk);
        k.scheme = 2;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemScheme.selector, 2));
        a.setKemKey(x.ua, 0, k, _noSig());
        IUARegistry.UASig memory s;
        s.signature = hex"01";
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, x.ua));
        a.setKemKey(x.ua, 0, x.attrs.kem, s);
        s.signature = "";
        s.keyData = hex"01";
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, x.ua));
        a.setKemKey(x.ua, 0, x.attrs.kem, s);
        s.keyData = "";
        s.members = new IUARegistry.MemberSig[](1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, x.ua));
        a.setKemKey(x.ua, 0, x.attrs.kem, s);
        _assertKemAt(a, x.ua, 0, "", "");
        a.setKemKey(x.ua, 0, x.attrs.kem, _noSig());
        _assertKemAt(a, x.ua, 0, x.kemPk, "");
    }

    /// The commit form at `register`, checked with the attributes before the PoP: key bytes next to a `kemPkHash`
    /// (`mlkemEk` or `x25519`) are `UAKemKeyLength` (the assembled length), a scheme other than 1 `UAKemScheme`, a
    /// non-holder `UAKemHolder`; a commit over another key's hash fails the PoP (`UAPoP`).
    function test_kemCommitFormRefused() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory x = rows[FNDSA_ROW];
        UARegistry a = _regA(false);
        IUARegistry.UAAttrs memory c = UACall.commit(x.attrs);
        c.kem.x25519 = bytes32(uint256(1));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemKeyLength.selector, 33));
        UACall.register(a, x.kind, x.keyData, c, x.pop, x.pqzPop);
        c = UACall.commit(x.attrs);
        c.kem.mlkemEk = hex"00";
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemKeyLength.selector, 34));
        UACall.register(a, x.kind, x.keyData, c, x.pop, x.pqzPop);
        c = UACall.commit(x.attrs);
        c.kem.scheme = 2;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemScheme.selector, 2));
        UACall.register(a, x.kind, x.keyData, c, x.pop, x.pqzPop);
        c.kem.scheme = 0;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemScheme.selector, 0));
        UACall.register(a, x.kind, x.keyData, c, x.pop, x.pqzPop);
        c = UACall.commit(x.attrs);
        c.kemPkHash = keccak256(_kemPk(9));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(a, x.kind, x.keyData, c, x.pop, x.pqzPop);
        Row memory y = rows[SECP_ROW];
        IUARegistry.UAAttrs memory cy = UACall.commit(x.attrs);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemHolder.selector, y.ua));
        UACall.register(a, y.kind, y.keyData, cy, y.pop, y.pqzPop);
        assertEq(UACall.register(a, x.kind, x.keyData, UACall.commit(x.attrs), x.pop, x.pqzPop), x.ua);
    }

    // ----- helpers -----

    uint256 internal constant SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function _nativeSk() internal view returns (uint256) {
        return vm.parseJsonUint(vm.readFile("../vectors/ua/signatures.json"), ".native.secret");
    }

    function loadAuthNeg() external view returns (bytes32 purpose, bytes32 digest, bytes memory auth) {
        string memory j = vm.readFile(PJ);
        for (uint256 i; _jx(j, string.concat(".negatives[", vm.toString(i), "]")); ++i) {
            string memory p = string.concat(".negatives[", vm.toString(i), "]");
            if (keccak256(_jbRaw(j, string.concat(p, ".name"))) != keccak256("native-personal-sign-under-metatx")) continue;
            purpose = _jw(j, string.concat(p, ".mutation.set.purposeTag"));
            digest = _jw(j, string.concat(p, ".mutation.set.digest"));
            auth = _jb(j, string.concat(p, ".mutation.set.auth"));
            return (purpose, digest, auth);
        }
        revert("no requireAuthorized negative");
    }

    function _neg(string memory name) internal view returns (Neg memory) {
        Neg[] memory negs = this.loadNegs();
        for (uint256 i; i < negs.length; ++i) {
            if (keccak256(bytes(negs[i].name)) == keccak256(bytes(name))) return negs[i];
        }
        revert(string.concat("no negative ", name));
    }

    function _eq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function _errs(string memory a, string memory b, string memory c, string memory d)
        internal
        pure
        returns (string[4] memory)
    {
        return [a, b, c, d];
    }

    /// Runs every `register` negative whose error is in `errs` on a registry with the msig members registered; each
    /// reverts with exactly the registry's error. Returns the count.
    function _runNegatives(string[4] memory errs) internal returns (uint256 n) {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Neg[] memory negs = this.loadNegs();
        UARegistry a = _regA(false);
        _members(a, rows);
        // a negative on a member row (record-kind-mismatch: p256) runs where that row is not registered yet
        UARegistry fresh = _deploy(address(0x5ce6f), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, false));
        for (uint256 i; i < negs.length; ++i) {
            Neg memory g = negs[i];
            if (keccak256(bytes(g.entry)) != keccak256("register") || !_in(g.err, errs)) continue;
            Row memory x = _apply(_find(rows, g.row), g);
            UARegistry t = a.kindOf(x.ua) != 0 ? fresh : a;
            vm.expectRevert(_expected(g.err, x));
            UACall.register(t, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
            ++n;
        }
    }

    function _in(string memory e, string[4] memory errs) internal pure returns (bool) {
        for (uint256 i; i < 4; ++i) {
            if (bytes(errs[i]).length != 0 && keccak256(bytes(e)) == keccak256(bytes(errs[i]))) return true;
        }
        return false;
    }

    /// A copy of `r` with the negative's fields replaced (the rows array is not touched).
    function _apply(Row memory src, Neg memory g) internal pure returns (Row memory r) {
        r = Row(src.name, src.set, src.kind, src.keyData, src.ua,
            UACall.attrs(src.attrs.pqzKey, src.attrs.pqzPopHash, src.kemPk), src.kemPk, src.pop, src.pqzPop,
            src.popMessage, src.pqzRegMessage);
        for (uint256 k; k < g.keys.length; ++k) {
            bytes32 key = keccak256(bytes(g.keys[k]));
            bytes memory v = g.values[k];
            if (key == keccak256("attrs.pqzKey")) r.attrs.pqzKey = v;
            else if (key == keccak256("attrs.pqzPopHash")) r.attrs.pqzPopHash = bytes32(v);
            else if (key == keccak256("attrs.kemPk")) (r.kemPk, r.attrs.kem) = (v, UACall.kem(v));
            else if (key == keccak256("pqzPop")) r.pqzPop = v;
            else if (key == keccak256("pop")) r.pop = v;
            else revert(string.concat(g.name, ": unknown mutation ", g.keys[k]));
        }
    }

    function _expected(string memory e, Row memory x) internal pure returns (bytes memory) {
        bytes32 k = keccak256(bytes(e));
        if (k == keccak256("UAPoP")) return abi.encodeWithSelector(IUARegistry.UAPoP.selector);
        if (k == keccak256("UAPqzPopHash")) return abi.encodeWithSelector(IUARegistry.UAPqzPopHash.selector, x.ua);
        if (k == keccak256("UAPqzHolder")) return abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, x.ua);
        if (k == keccak256("UAKemHolder")) return abi.encodeWithSelector(IUARegistry.UAKemHolder.selector, x.ua);
        if (k == keccak256("UAKeyData")) return abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.PQZ_MLWE);
        if (k == keccak256("UAKemKeyLength")) {
            return abi.encodeWithSelector(IUARegistry.UAKemKeyLength.selector, x.kemPk.length);
        }
        if (k == keccak256("UAKemScheme")) {
            return abi.encodeWithSelector(IUARegistry.UAKemScheme.selector, uint8(x.kemPk[0]));
        }
        revert(string.concat("unmapped error ", e));
    }

    /// Contracts created (and their code bytes after the STOP byte) by the recorded call.
    function _created(VmSafe.AccountAccess[] memory acc) internal pure returns (uint256 n, uint256 bytes_) {
        for (uint256 i; i < acc.length; ++i) {
            // not the linked library: forge books its creation in a test's first recording
            if (acc[i].kind == VmSafe.AccountAccessKind.Create && !acc[i].reverted && acc[i].account != address(UARegistryLib)) {
                ++n;
                bytes_ += acc[i].deployedCode.length - 1;
            }
        }
    }

    function _chunks(uint256 len) internal pure returns (uint256) {
        return (len + 32_767) / 32_768;
    }

    function _slice(bytes memory b, uint256 o, uint256 n) internal pure returns (bytes memory r) {
        r = new bytes(n);
        for (uint256 i; i < n; ++i) r[i] = b[o + i];
    }

    // ----- typed-signing R2: the real signatures, on both sides of the split -----

    using SplitDiff for SplitDiff.Run;

    function _splitRegister(SplitDiff.Run memory r, address at, Row memory x, string memory label) internal {
        if (x.kind == UAKinds.MLDSA44) r.write("cache", at, abi.encodeCall(IUARegistry.cacheExpandedKey, (UAKinds.MLDSA44, x.keyData, 0)));
        if (x.attrs.pqzKey.length != 0) _allowPqz(x);
        r.write(label, at, UACall.registerCall(x.kind, x.keyData, x.attrs, x.pop, x.pqzPop));
    }

    /// `register` negatives of portable.json, each with its exact error.
    function _splitNegatives(SplitDiff.Run memory r, Row[] memory rows, Neg[] memory negs) internal {
        UARegistry a = _deploy(address(0x5ce6e), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, false));
        UARegistry fresh = _deploy(address(0x5ce6f), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, false));
        _members(a, rows);
        for (uint256 i; i < negs.length; ++i) {
            if (!_eq(negs[i].entry, "register")) continue;
            Row memory x = _apply(_find(rows, negs[i].row), negs[i]);
            r.refused(negs[i].name, address(a.kindOf(x.ua) != 0 ? fresh : a),
                UACall.registerCall(x.kind, x.keyData, x.attrs, x.pop, x.pqzPop), _expected(negs[i].err, x));
        }
    }

    function _splitRecords(SplitDiff.Run memory r, address at, Row[] memory rows, KemRec[] memory ks, KeyRec[] memory kr)
        internal
    {
        for (uint256 i; i < ks.length; ++i) {
            KemRec memory k = ks[i];
            _allowKem(rows, _kemBase(rows, k), k);
            r.write(string.concat("setKemKey ", k.id), at, abi.encodeCall(IUARegistry.setKemKey, (k.ua, k.version, UACall.kem(k.kemPk), UACall.sig(k.sig))));
        }
        for (uint256 i; i < kr.length; ++i) {
            KeyRec memory k = kr[i];
            if (!_eq(k.set, _setName())) continue;
            _allowRecord(rows, _byUa(rows, k.ua), k);
            r.write(string.concat("setPqzKey ", k.name), at, abi.encodeCall(IUARegistry.setPqzKey, (k.ua, k.pqzKey, k.pqzPopHash, UACall.sig(k.sig))));
        }
    }

    function _splitRun(string memory art, Row[] memory rows, Neg[] memory negs) internal returns (SplitDiff.Run memory r) {
        registryArtifact = art;
        r = SplitDiff.start(3_000, address(UARegistryLib));
        r.accepts = keccak256(bytes(art)) == keccak256("UARegistry.sol:UARegistry");
        _allowAll(rows);
        _splitNegatives(r, rows, negs);
        address at = address(_regA(true));
        for (uint256 pass; pass < 2; ++pass) {
            for (uint256 i; i < rows.length; ++i) {
                Row memory x = rows[i];
                bool here = bytes(x.set).length == 0 || _eq(x.set, _setName());
                if (here && (x.kind == UAKinds.MSIG) == (pass == 1)) _splitRegister(r, at, x, string.concat("register ", x.name));
            }
        }
        _splitRecords(r, at, rows, _kemRecs(), _keyRecs());
        for (uint256 i; i < rows.length; ++i) {
            r.read(string.concat("registrationOf ", rows[i].name), at, abi.encodeCall(IUARegistry.registrationOf, (rows[i].ua)));
            r.read(string.concat("kemKeyOf ", rows[i].name), at, abi.encodeCall(IUARegistry.kemKeyOf, (rows[i].ua)));
            r.read(string.concat("recordOf ", rows[i].name), at, abi.encodeCall(IUARegistry.recordOf, (rows[i].ua)));
        }
    }

    /// Every portable.json registration row of this set, with its real signatures and its real verifiers, its KEM and PQZ key
    /// records and its `register` negatives, on the pre-split source and on the split one: same result, logs, storage, created
    /// contracts and calls out (`SplitDiff`).
    function test_split_portableRowsSame() public {
        Row[] memory rows = _rows();
        Neg[] memory negs = this.loadNegs();
        uint256 snap = vm.snapshotState();
        SplitDiff.Run memory a = _splitRun("UARegistryPreSplit.sol:UARegistryPreSplit", rows, negs);
        vm.revertToState(snap);
        SplitDiff.Run memory b = _splitRun("UARegistry.sol:UARegistry", rows, negs);
        assertEq(SplitDiff.firstDiff(a, b), "", "first row that differs");
        emit log_named_uint("rows", a.n);
        emit log_named_uint("writes", a.writes);
        emit log_named_uint("reverts", a.reverts);
        assertGe(a.writes, 25, "registrations, KEM records, PQZ key records");
        assertGe(a.reverts, 20, "register negatives");
    }

    function _lastGas() internal view returns (uint256) {
        Vm.Gas memory lg = vm.lastCallGas();
        return lg.gasTotalUsed + uint256(int256(lg.gasStateUsed));
    }

    function _popHolder(address v, Row[] memory rows) internal returns (uint256) {
        Row memory x = _pqzRow(rows);
        UARegistry.KindConfig[] memory c = _vcfg(0, true);
        c[c.length - 1] = _one0142(v)[0];
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, c);
        UACall.register(r, x.kind, x.keyData, x.attrs, x.pop, "");
        r.storePqzPop(x.ua, x.pqzPop);
        return _lastGas();
    }

    function _popGen2(address v, Row[] memory rows) internal returns (uint256) {
        Row memory m = _find(rows, string.concat("msig-pq/", _setName()));
        UARegistry g1 = _deploy(address(0x5cebc), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, false));
        _members(g1, rows);
        UACall.register(g1, m.kind, m.keyData, m.attrs, m.pop, "");
        UARegistry g2 = _deploy(address(0x5cebb), chainUidA, address(g1), false, BUDGET, address(0), true, _one0142(v));
        g2.storePqzPop(m.ua, m.pqzPop);
        return _lastGas();
    }

    function _one0142(address v) internal pure returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, v, 4_500_000);
    }

    /// The TODO watch item: `storePqzPop` of this set's proof with a verify of the real cost (3.65 M), so the execution, not
    /// the calldata floor, sets the regular gas, on the pre-split source and the split one; rows `GAS|label|before|after|delta`,
    /// regular + state gas.
    function test_split_storePqzPopWithAVerify() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        address v = address(new BurnAccept(3_650_000));
        string memory n = _setName();
        uint256 snap = vm.snapshotState();
        registryArtifact = "UARegistryPreSplit.sol:UARegistryPreSplit";
        (uint256 a, uint256 a2) = (_popHolder(v, rows), _popGen2(v, rows));
        vm.revertToState(snap);
        registryArtifact = "UARegistry.sol:UARegistry";
        (uint256 b, uint256 b2) = (_popHolder(v, rows), _popGen2(v, rows));
        emit log_string(string.concat("GAS|storePqzPop ", n, "|", vm.toString(a), "|", vm.toString(b), "|", vm.toString(int256(b) - int256(a))));
        emit log_string(string.concat("GAS|storePqzPop on gen 2 ", n, "|", vm.toString(a2), "|", vm.toString(b2), "|", vm.toString(int256(b2) - int256(a2))));
    }

    // ----- A8: gas figures (UA-8 `register`, `storePqzPop`, `setKemKey`) -----
    // The pins below are regression guards only: each is the first measured run (forge 1.8.5, `--isolate`, evm
    // amsterdam) "/ 1.0", not a derived bound; re-pinned (GAS_REPIN=1, the four sets) by typed-signing P3 where the
    // typed portable digests moved them, and by P1b (the register KEM key at version 0: `_kemMax` written by the first
    // `setKemKey`, not by `register`), by R1 (the explicit ABI: typed arguments copied to memory, the blob without its
    // KEM version word, the KEM hash-commit slot) and by R2 (the registry split: `runs/…-r2-pins.txt`, old and new) (old -> new
    // in their commit messages). Regular gas = `gasTotalUsed`, EIP-8037 state gas = `gasStateUsed`
    // (the log `runs/2026-10-30-ua8-gas.txt` has the table). The `mldsa65` precompile is the exact-input mock, so its
    // verify gas is the mock's, and the 0x0142 verifier is the `rreg` stand-in: both verifies are not real figures.

    /// One figure: logs it as a `GAS` row and checks both gases against the pin (0 = unset, fails).
    function _gas(string memory name) internal {
        Vm.Gas memory g = vm.lastCallGas();
        uint256 st = uint256(int256(g.gasStateUsed));
        emit log_string(string.concat("GAS|", name, "|", vm.toString(g.gasTotalUsed), "|", vm.toString(st)));
        if (vm.envOr("GAS_REPIN", false)) return; // GAS_REPIN=1: only print the GAS| rows to pin from
        (uint256 reg, uint256 state) = _pin(name);
        assertLe(g.gasTotalUsed, reg, string.concat(name, ": regular gas over the pin"));
        assertLe(st, state, string.concat(name, ": state gas over the pin"));
    }

    /// GAS_REPIN=1 prints rows without checking pins: end the test FAILED (vm.skip would drop the printed rows), so a
    /// re-pin run can never read as a checked pass.
    function _repinSkip() internal {
        if (vm.envOr("GAS_REPIN", false)) fail("GAS_REPIN: pins NOT checked");
    }

    function _pin(string memory name) internal pure returns (uint256, uint256) {
        bytes32 h = keccak256(bytes(name));
        // PINS: name -> (regular gas, state gas); the rows of all four sets (a set's rows carry its name)
        if (h == keccak256("register webauthn-p256")) return (181861, 1702890);
        if (h == keccak256("register p256")) return (164402, 1164330);
        if (h == keccak256("register ed25519")) return (323901, 1115370);
        if (h == keccak256("register bip340")) return (161195, 1115370);
        if (h == keccak256("register secp256k1")) return (160128, 1213290);
        if (h == keccak256("register schnorr-bn254")) return (175599, 1213290);
        if (h == keccak256("register schnorr-bls12381")) return (202734, 1409130);
        if (h == keccak256("register bls12381-minsig")) return (338614, 1556010);
        if (h == keccak256("register bls-bn254-minsig")) return (353388, 1262250);
        if (h == keccak256("register zether-bls12381")) return (215365, 1594260);
        if (h == keccak256("register mldsa44")) return (4347671, 6881940);
        if (h == keccak256("register mldsa65#1")) return (387992, 9232020);
        if (h == keccak256("register mldsa65#2")) return (387992, 9134100);
        if (h == keccak256("register mldsa65/n2048-kmax1024")) return (3341208, 81220050);
        if (h == keccak256("register fndsa512")) return (2740640, 6384690);
        if (h == keccak256("register slhdsa128s")) return (1123151, 13246740);
        if (h == keccak256("register msig-classical")) return (165778, 1115370);
        if (h == keccak256("register msig-pq/n2048-kmax1024")) return (3468184, 83874600);
        if (h == keccak256("register msig-pq-native")) return (308120, 6941610);
        if (h == keccak256("setKemKey mldsa65/v2 n2048-kmax1024")) return (357272, 7991190);
        if (h == keccak256("popOf (the blob setKemKey decodes) mldsa65/v2 n2048-kmax1024")) return (15299, 0);
        if (h == keccak256("setKemKey fndsa512/v2 n2048-kmax1024")) return (2509996, 3947400);
        if (h == keccak256("popOf (the blob setKemKey decodes) fndsa512/v2 n2048-kmax1024")) return (13360, 0);
        if (h == keccak256("setKemKey msig-pq/v2 n2048-kmax1024")) return (594840, 13797540);
        if (h == keccak256("popOf (the blob setKemKey decodes) msig-pq/v2 n2048-kmax1024")) return (18534, 0);
        if (h == keccak256("setKemKey msig-12-slhdsa128s (96,832 B pop)")) return (6337432, 151930530);
        if (h == keccak256("popOf (the blob setKemKey decodes) msig-12-slhdsa128s (96,832 B pop)")) return (252226, 0);
        if (h == keccak256("popOf unregistered (view baseline)")) return (2861, 0);
        if (h == keccak256("register mldsa65 with pqzPop n2048-kmax1024")) return (3341208, 81317970);
        if (h == keccak256("register mldsa65 without pqzPop n2048-kmax1024")) return (1536920, 37511010);
        if (h == keccak256("storePqzPop mldsa65 n2048-kmax1024")) return (1825688, 43806960);
        if (h == keccak256("storePqzPop again (no-op) n2048-kmax1024")) return (1825688, 0);
        if (h == keccak256("storePqzPop msig-pq on gen 2 (gen 1 record) n2048-kmax1024")) return (1825688, 44002800);
        if (h == keccak256("register msig-pq without pqzPop n2048-kmax1024")) return (1663896, 40263480);
        if (h == keccak256("storePqzPop msig-pq on gen 1 n2048-kmax1024")) return (1825688, 43806960);
        if (h == keccak256("registrationOf msig-pq on gen 2 (gen 1 record) n2048-kmax1024")) return (143722, 0);
        if (h == keccak256("registrationOf msig-pq on gen 1 n2048-kmax1024")) return (99494, 0);
        if (h == keccak256("register mldsa65/n2304-kmax4096")) return (3613592, 87704190);
        if (h == keccak256("register msig-pq/n2304-kmax4096")) return (3740568, 90358740);
        if (h == keccak256("setKemKey mldsa65/v2 n2304-kmax4096")) return (357272, 7991190);
        if (h == keccak256("popOf (the blob setKemKey decodes) mldsa65/v2 n2304-kmax4096")) return (15299, 0);
        if (h == keccak256("setKemKey fndsa512/v2 n2304-kmax4096")) return (2509996, 3947400);
        if (h == keccak256("popOf (the blob setKemKey decodes) fndsa512/v2 n2304-kmax4096")) return (13360, 0);
        if (h == keccak256("setKemKey msig-pq/v2 n2304-kmax4096")) return (594840, 13797540);
        if (h == keccak256("popOf (the blob setKemKey decodes) msig-pq/v2 n2304-kmax4096")) return (18534, 0);
        if (h == keccak256("register mldsa65 with pqzPop n2304-kmax4096")) return (3613592, 87802110);
        if (h == keccak256("register mldsa65 without pqzPop n2304-kmax4096")) return (1667992, 40644450);
        if (h == keccak256("storePqzPop mldsa65 n2304-kmax4096")) return (1967000, 47157660);
        if (h == keccak256("storePqzPop again (no-op) n2304-kmax4096")) return (1967000, 0);
        if (h == keccak256("storePqzPop msig-pq on gen 2 (gen 1 record) n2304-kmax4096")) return (1967000, 47353500);
        if (h == keccak256("register msig-pq without pqzPop n2304-kmax4096")) return (1794968, 43396920);
        if (h == keccak256("storePqzPop msig-pq on gen 1 n2304-kmax4096")) return (1967000, 47157660);
        if (h == keccak256("registrationOf msig-pq on gen 2 (gen 1 record) n2304-kmax4096")) return (153454, 0);
        if (h == keccak256("registrationOf msig-pq on gen 1 n2304-kmax4096")) return (105419, 0);
        if (h == keccak256("register mldsa65/n2560-kmax16384")) return (3881880, 94139370);
        if (h == keccak256("register msig-pq/n2560-kmax16384")) return (4008856, 96793920);
        if (h == keccak256("setKemKey mldsa65/v2 n2560-kmax16384")) return (357272, 7991190);
        if (h == keccak256("popOf (the blob setKemKey decodes) mldsa65/v2 n2560-kmax16384")) return (15299, 0);
        if (h == keccak256("setKemKey fndsa512/v2 n2560-kmax16384")) return (2509996, 3947400);
        if (h == keccak256("popOf (the blob setKemKey decodes) fndsa512/v2 n2560-kmax16384")) return (13360, 0);
        if (h == keccak256("setKemKey msig-pq/v2 n2560-kmax16384")) return (594840, 13797540);
        if (h == keccak256("popOf (the blob setKemKey decodes) msig-pq/v2 n2560-kmax16384")) return (18534, 0);
        if (h == keccak256("register mldsa65 with pqzPop n2560-kmax16384")) return (3881880, 94237290);
        if (h == keccak256("register mldsa65 without pqzPop n2560-kmax16384")) return (1799064, 43777890);
        if (h == keccak256("storePqzPop mldsa65 n2560-kmax16384")) return (2104216, 50459400);
        if (h == keccak256("storePqzPop again (no-op) n2560-kmax16384")) return (2104216, 0);
        if (h == keccak256("storePqzPop msig-pq on gen 2 (gen 1 record) n2560-kmax16384")) return (2104216, 50655240);
        if (h == keccak256("register msig-pq without pqzPop n2560-kmax16384")) return (1926040, 46530360);
        if (h == keccak256("storePqzPop msig-pq on gen 1 n2560-kmax16384")) return (2104216, 50459400);
        if (h == keccak256("registrationOf msig-pq on gen 2 (gen 1 record) n2560-kmax16384")) return (163568, 0);
        if (h == keccak256("registrationOf msig-pq on gen 1 n2560-kmax16384")) return (111562, 0);
        if (h == keccak256("register mldsa65/n2816-kmax65536")) return (4201368, 102054060);
        if (h == keccak256("register msig-pq/n2816-kmax65536")) return (4328344, 104708610);
        if (h == keccak256("setKemKey mldsa65/v2 n2816-kmax65536")) return (357272, 7991190);
        if (h == keccak256("popOf (the blob setKemKey decodes) mldsa65/v2 n2816-kmax65536")) return (15299, 0);
        if (h == keccak256("setKemKey fndsa512/v2 n2816-kmax65536")) return (2509996, 3947400);
        if (h == keccak256("popOf (the blob setKemKey decodes) fndsa512/v2 n2816-kmax65536")) return (13360, 0);
        if (h == keccak256("setKemKey msig-pq/v2 n2816-kmax65536")) return (594840, 13797540);
        if (h == keccak256("popOf (the blob setKemKey decodes) msig-pq/v2 n2816-kmax65536")) return (18534, 0);
        if (h == keccak256("register mldsa65 with pqzPop n2816-kmax65536")) return (4201368, 102151980);
        if (h == keccak256("register mldsa65 without pqzPop n2816-kmax65536")) return (1930136, 46911330);
        if (h == keccak256("storePqzPop mldsa65 n2816-kmax65536")) return (2292632, 55240650);
        if (h == keccak256("storePqzPop again (no-op) n2816-kmax65536")) return (2292632, 0);
        if (h == keccak256("storePqzPop msig-pq on gen 2 (gen 1 record) n2816-kmax65536")) return (2292632, 55436490);
        if (h == keccak256("register msig-pq without pqzPop n2816-kmax65536")) return (2057112, 49663800);
        if (h == keccak256("storePqzPop msig-pq on gen 1 n2816-kmax65536")) return (2292632, 55240650);
        if (h == keccak256("registrationOf msig-pq on gen 2 (gen 1 record) n2816-kmax65536")) return (182107, 0);
        if (h == keccak256("registrationOf msig-pq on gen 1 n2816-kmax65536")) return (125760, 0);
        return (0, 0); // an unpinned name fails its check
    }

    /// `register` of every portable.json row of this build's set (singles first, then the msigs), the PQZ rows with
    /// their `pqzPop` in the call, on a registry with the 0x0142 stand-in; `--isolate`: cold.
    function test_T_GAS_register_ua8PerKind() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry r = _regA(true);
        for (uint256 pass; pass < 2; ++pass) {
            for (uint256 i; i < rows.length; ++i) {
                Row memory x = rows[i];
                bool here = bytes(x.set).length == 0 || _eq(x.set, _setName());
                if (!here || (x.kind == UAKinds.MSIG) != (pass == 1)) continue;
                if (x.kind == UAKinds.MLDSA44 && r.expandedKeyOf(x.ua)[0] == address(0)) {
                    r.cacheExpandedKey(UAKinds.MLDSA44, x.keyData, 0);
                }
                if (x.attrs.pqzKey.length != 0) _allowPqz(x);
                UACall.register(r, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
                _gas(string.concat("register ", x.name));
            }
        }
        _repinSkip();
    }

    /// The PQZ attachment of the `mldsa65` row: `register` with the proof in the call, `register` without it, and
    /// `storePqzPop` of the proof (R_REG length by the set); the same for the PQ-eligible `msig`'s attachment on gen 2
    /// proving a gen-1 record (gen 2 reads gen 1's whole `registrationOf`, A6 note).
    function test_T_GAS_storePqzPop() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        string memory sn = _setName();
        Row memory x = _pqzRow(rows);
        _allowPqz(x);
        emit log_named_uint(string.concat("R_REG proof bytes ", sn), x.pqzPop.length);
        UARegistry r = _regA(true);
        uint256 snap = vm.snapshotState();
        UACall.register(r, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
        _gas(string.concat("register mldsa65 with pqzPop ", sn));
        vm.revertToState(snap);
        UACall.register(r, x.kind, x.keyData, x.attrs, x.pop, "");
        _gas(string.concat("register mldsa65 without pqzPop ", sn));
        vm.prank(address(0x7111D), address(0x7111D));
        r.storePqzPop(x.ua, x.pqzPop);
        _gas(string.concat("storePqzPop mldsa65 ", sn));
        r.storePqzPop(x.ua, x.pqzPop);
        _gas(string.concat("storePqzPop again (no-op) ", sn));
        // the msig-pq attachment: gen 1 alone, then gen 2 over a gen-1 record
        Row memory m = _find(rows, string.concat("msig-pq/", sn));
        _allowPqz(m);
        UARegistry g1 = _deploy(address(0x5cebc), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, false));
        _members(g1, rows);
        UACall.register(g1, m.kind, m.keyData, m.attrs, m.pop, "");
        UARegistry g2 = _gen2Pqz(address(0x5cebb), g1);
        g2.storePqzPop(m.ua, m.pqzPop);
        _gas(string.concat("storePqzPop msig-pq on gen 2 (gen 1 record) ", sn));
        UARegistry solo = _deploy(address(0x5cebd), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, true));
        _members(solo, rows);
        UACall.register(solo, m.kind, m.keyData, m.attrs, m.pop, "");
        _gas(string.concat("register msig-pq without pqzPop ", sn));
        solo.storePqzPop(m.ua, m.pqzPop);
        _gas(string.concat("storePqzPop msig-pq on gen 1 ", sn));
        // gen 2 reading gen 1's whole registration (A6 note): the views alone
        g2.registrationOf(m.ua);
        _gas(string.concat("registrationOf msig-pq on gen 2 (gen 1 record) ", sn));
        solo.registrationOf(m.ua);
        _gas(string.concat("registrationOf msig-pq on gen 1 ", sn));
        _repinSkip();
    }

    /// `setKemKey` (version 2) for `mldsa65`, `fndsa512`, the PQ-eligible `msig` (2 `mldsa65` members), and a PQ-eligible
    /// 12-of-12 `msig` of `slhdsa128s` members whose registration pop is 94 KB (over 64 KiB: three code blobs; the
    /// verifier accepts everything): `setKemKey` decodes the whole registration blob (A7 m2), so the second row against the first
    /// shows the blob-read share; `popOf` of the same UA decodes the same `_reg` blob (what `setKemKey` reads), `popOf` of an unregistered id is the view's baseline.
    function test_T_GAS_setKemKey() public {
        Row[] memory rows = _rows();
        KemRec[] memory ks = _kemRecs();
        UARegistry a = _regA(false);
        _kemSetup(a, rows, ks);
        string[3] memory ids = ["mldsa65/v2", "fndsa512/v2", "msig-pq/v2"];
        for (uint256 i; i < 3; ++i) {
            KemRec memory k = _kemRec(ks, ids[i]);
            a.setKemKey(k.ua, 2, UACall.kem(k.kemPk), UACall.sig(k.sig));
            _gas(string.concat("setKemKey ", ids[i], " ", _setName()));
            a.popOf(k.ua);
            _gas(string.concat("popOf (the blob setKemKey decodes) ", ids[i], " ", _setName()));
        }
        // 12 x slhdsa128s members
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0133, address(new AcceptAll()), 1_400_000);
        UARegistry big = _deploy(address(0x5cea2), chainUidA, address(0), false, uint64(12 * 1_445_000 + uint256(1_000_000) / 63 + 2_500),
            address(0), true, c);
        Member[] memory m12 = new Member[](12);
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](12);
        for (uint16 i; i < 12; ++i) {
            m12[i] = Member(0x0133, UACall.register(big, 0x0133, abi.encodePacked(keccak256(abi.encode("slhk", i))), _none(), hex"01", ""), 1);
            s[i] = IUARegistry.MemberSig(i, new IUARegistry.InnerSig[](0), new bytes(7_856));
        }
        bytes memory d = _msigKey(12, m12); // threshold 12: the KEM signature is as large as the pop (calldata-floor bound)
        bytes32 ua = UACall.register(big, UAKinds.MSIG, d, _none(), abi.encode(s), "");
        emit log_named_uint("msig 12 x slhdsa128s pop bytes", abi.encode(s).length);
        big.setKemKey(ua, 1, UACall.kem(_kemPk(12)), UACall.sig(abi.encode(s)));
        _gas("setKemKey msig-12-slhdsa128s (96,832 B pop)");
        big.popOf(ua);
        _gas("popOf (the blob setKemKey decodes) msig-12-slhdsa128s (96,832 B pop)");
        big.popOf(bytes32(uint256(1))); // unregistered: no blob read, the view's own cost (intrinsic gas) alone
        _gas("popOf unregistered (view baseline)");
        _repinSkip();
    }
}
