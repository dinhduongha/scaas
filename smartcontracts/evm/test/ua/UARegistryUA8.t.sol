// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {VmSafe} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IUAPopVerifier} from "../../src/ua/IUAVerifier.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
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

/// `UARegistry._sigOk` exposed (ruling A5-m3: the portable-purpose guard).
contract SigOkHarness is UARegistry {
    constructor(bytes32 uid, uint64 budget, KindConfig[] memory k)
        UARegistry(uid, address(0), false, budget, address(0), true, k)
    {}

    function sigOk(uint16 kind, bytes memory d, bytes32 ua, bytes32 purpose, bytes32 digest, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return _sigOk(kind, d, ua, purpose, digest, sig);
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
        IUARegistry.UAAttrs attrs;
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

    function _parseRow(string memory j, uint256 i) internal pure returns (Row memory r) {
        string memory p = string.concat(".registrations[", vm.toString(i), "]");
        r.name = _js(j, string.concat(p, ".name"));
        r.set = _js(j, string.concat(p, ".set"));
        r.kind = uint16(_ju(j, string.concat(p, ".kind")));
        r.keyData = _jb(j, string.concat(p, ".keyData"));
        r.ua = _jw(j, string.concat(p, ".ua"));
        r.attrs.pqzKey = _jb(j, string.concat(p, ".attrs.pqzKey"));
        r.attrs.pqzPopHash = _jw(j, string.concat(p, ".attrs.pqzPopHash"));
        r.attrs.kemVersion = uint64(_ju(j, string.concat(p, ".attrs.kemVersion")));
        r.attrs.kemPk = _jb(j, string.concat(p, ".attrs.kemPk"));
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
        for (uint256 i; i < n; ++i) rows[i] = _parseRow(j, i);
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
            g.entry = _js(j, string.concat(p, ".entry"));
            g.err = _js(j, string.concat(p, ".error"));
            if (!_eq(g.entry, "register") && !_eq(g.entry, "storePqzPop") && !_eq(g.entry, "setPqzKey")) continue;
            g.row = _js(j, string.concat(p, ".mutation.row"));
            g.keys = vm.parseJsonKeys(j, string.concat(p, ".mutation.set"));
            g.values = new bytes[](g.keys.length);
            for (uint256 k; k < g.keys.length; ++k) {
                string memory f = string.concat(p, ".mutation.set['", g.keys[k], "']");
                g.values[k] = keccak256(bytes(g.keys[k])) == keccak256("attrs.kemVersion")
                    ? abi.encode(_ju(j, f))
                    : _jb(j, f);
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
        UARegistry.MemberSig[] memory s = abi.decode(sigs, (UARegistry.MemberSig[]));
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
        ua = r.register(row.kind, row.keyData, row.attrs, row.pop, row.pqzPop);
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
        (uint64 v, bytes memory pk, bytes memory sig) = r.kemKeyOf(row.ua);
        assertEq(v, row.attrs.kemVersion);
        assertEq(pk, row.attrs.kemPk);
        assertEq(sig, "", "the initial KEM record has no signature (UA8-D4)");
        (uint8 cp, uint8 cq, uint8 ck) = r.checkedOf(row.ua);
        assertEq(cp, UAKinds.CHECKED_CHAIN);
        assertEq(cq, proven ? UAKinds.CHECKED_CHAIN : UAKinds.CHECKED_NONE);
        assertEq(ck, row.attrs.kemVersion != 0 ? UAKinds.CHECKED_CHAIN : UAKinds.CHECKED_NONE);
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
            assertEq(b.register(k, d, att, p, z), ua);
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
            r.register(x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
        }
        UARegistry noMsig = _deploy(address(0x5ce7f), chainUidA, address(0), false, BUDGET, address(0), false, _vcfg(0, false));
        Row memory m = rows[MSIG_NATIVE_ROW];
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, UAKinds.MSIG));
        noMsig.register(m.kind, m.keyData, m.attrs, m.pop, m.pqzPop);
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

    /// Ruling C7 (D6 overridden): a code-less native member signs the portable message by `personal_sign`, so the
    /// same native-member `msig` registration is accepted on two registries with different chain ids. A UAAuth-framed
    /// native signature inside a portable pop, a malformed `personal_sign` (high s, 64 bytes, v 0 / 1) are `UAPoP`; a
    /// `personal_sign` member signature never passes `requireAuthorized`, under any purpose.
    function test_ua8_msigNativeMemberPersonalSignPortable() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory m = rows[MSIG_NATIVE_ROW];
        UARegistry a = _regA(false);
        UARegistry b = _regB();
        _members(a, rows);
        _members(b, rows);
        _malformedPersonalSign(a, m);
        Neg memory g = _neg("native-uaauth-in-portable-pop");
        vm.expectRevert(IUARegistry.UAPoP.selector);
        a.register(m.kind, m.keyData, m.attrs, g.values[0], m.pqzPop);
        // the vector's personal_sign pop: accepted on A and on B
        _reg(a, m);
        vm.chainId(7622);
        _reg(b, m);
        vm.chainId(31337);
        assertEq(keccak256(_stored(a, m.ua)), keccak256(_stored(b, m.ua)));
        _personalSignNotForRequireAuthorized(a, m);
    }

    /// High s, 64 bytes, v 0 and v 1 for the native member's `personal_sign`: `UAPoP`.
    function _malformedPersonalSign(UARegistry a, Row memory m) internal {
        UARegistry.MemberSig[] memory s = abi.decode(m.pop, (UARegistry.MemberSig[]));
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
            a.register(m.kind, m.keyData, m.attrs, pop, m.pqzPop);
        }
    }

    /// `requireAuthorized` keeps UAAuth for native members: the very pop as an auth under PURPOSE_POP_V2 is refused, the
    /// same set with the member's UAAuth signature passes; portable.json's personal_sign member under metatx is refused.
    function _personalSignNotForRequireAuthorized(UARegistry a, Row memory m) internal {
        bytes32 rd = UAKinds.registrationDigest(UAKinds.portablePopDigest(m.ua, 0, 0), 0);
        assertEq(UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_POP_V2, rd), m.popMessage);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, m.ua));
        a.requireAuthorized(m.ua, UAKinds.PURPOSE_POP_V2, rd, abi.encode(m.keyData, m.pop));
        UARegistry.MemberSig[] memory s = abi.decode(m.pop, (UARegistry.MemberSig[]));
        s[0].sig = _nativeSig(a, _nativeSk(), UAKinds.PURPOSE_MEMBER, UAKinds.memberDigest(m.ua, m.popMessage));
        a.requireAuthorized(m.ua, UAKinds.PURPOSE_POP_V2, rd, abi.encode(m.keyData, abi.encode(s)));
        (bytes32 purpose, bytes32 dg, bytes memory auth) = this.loadAuthNeg();
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, m.ua));
        a.requireAuthorized(m.ua, purpose, dg, auth);
    }

    /// A native member with code (a contract wallet; an EIP-7702 delegate takes the same path) answers ERC-1271
    /// `isValidSignature(memberDigest, sig)` in a portable pop; its key's `personal_sign` is not asked.
    function test_ua8_msigNativeMemberWithCode1271() public {
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
        a.register(m.kind, m.keyData, m.attrs, m.pop, m.pqzPop); // the personal_sign pop: code ⇒ ERC-1271 only
        UARegistry.MemberSig[] memory s = abi.decode(m.pop, (UARegistry.MemberSig[]));
        s[0].sig = _ecdsa(ownerSk, UAKinds.memberDigest(m.ua, m.popMessage));
        assertEq(a.register(m.kind, m.keyData, m.attrs, abi.encode(s), m.pqzPop), m.ua);
    }

    /// Review focus 2: stripping or swapping `pqzKey`, `pqzPopHash`, `kemVersion` or `kemPk` (portable.json negatives
    /// with error `UAPoP`) is `UAPoP`.
    function test_ua8_popCoversAttrs() public {
        assertEq(_runNegatives(_errs("UAPoP", "", "", "")), 20, "UAPoP negatives");
    }

    /// The attribute shape: a PQZ key with its proof hash and only with it, proof bytes hashing to it, a PQZ key of a
    /// set's length, a KEM version ≥ 1 with a 1,600-byte key — before the PoP. Also: proof bytes without a key.
    function test_ua8_attrsShapeRefused() public {
        assertEq(_runNegatives(_errs("UAPqzPopHash", "UAKeyData", "UAKemKeyLength", "UAKemVersion")), 16);
        Row[] memory rows = _rows();
        UARegistry a = _deploy(address(0x5ce60), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, false));
        Row memory p = rows[P256_ROW];
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzPopHash.selector, p.ua));
        a.register(p.kind, p.keyData, p.attrs, p.pop, hex"01");
    }

    /// Only the PQ holders carry a PQZ key or a KEM record (UA-6 U3, UA8-D12): portable.json's holder negatives, and
    /// `slhdsa128s` with a KEM record.
    function test_ua8_nonHolderAttrsRefused() public {
        assertEq(_runNegatives(_errs("UAPqzHolder", "UAKemHolder", "", "")), 6);
        Row[] memory rows = _rows();
        UARegistry a = _deploy(address(0x5ce61), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, false));
        Row memory s = rows[SLH_ROW];
        s.attrs.kemVersion = 1;
        s.attrs.kemPk = rows[FNDSA_ROW].attrs.kemPk;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemHolder.selector, s.ua));
        a.register(s.kind, s.keyData, s.attrs, s.pop, s.pqzPop);
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
            a.register(x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
            _assertRecord(a, x);
            vm.prank(address(0x600D), address(0x600D));
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, x.ua));
            a.register(x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
        }
    }

    /// P2 / UA8-D7: every field in state and in the event; `keyData` stored once: the code `register` creates is the
    /// stored kinds' `keyPtr`, the PQZ key, the proof chunks, the KEM record and the registration blob
    /// `abi.encode(keyRest, pop, kemVersion)`, nothing else.
    function test_ua8_storesEveryField() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        UARegistry a = _regA(false);
        Row[2] memory xs = [rows[P256_ROW], _find(rows, string.concat("mldsa65/", _setName()))];
        uint256[2] memory vk = [uint256(0), 1952]; // p256 is not stored (its keyData all in the blob); mldsa65 is
        for (uint256 i; i < 2; ++i) {
            Row memory x = xs[i];
            uint64 v = x.attrs.kemVersion;
            vm.expectEmit(true, true, false, true, address(a));
            emit IUARegistry.UARegistered(x.ua, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop, UAKinds.CHECKED_CHAIN,
                UAKinds.CHECKED_NONE, v == 0 ? UAKinds.CHECKED_NONE : UAKinds.CHECKED_CHAIN);
            vm.startStateDiffRecording();
            a.register(x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
            (uint256 created, uint256 bytes_) = _created(vm.stopAndReturnStateDiff());
            _assertRecord(a, x);
            uint256 rest = x.keyData.length - vk[i];
            uint256 blob = abi.encode(_slice(x.keyData, vk[i], rest), x.pop, v).length;
            uint256 want = vk[i] + x.attrs.pqzKey.length + x.pqzPop.length + x.attrs.kemPk.length + blob;
            assertEq(bytes_, want, "created code = keyPtr + pqzKey + pqzPop + KEM record + blob");
            assertEq(created, (vk[i] == 0 ? 0 : 1) + (x.attrs.pqzKey.length == 0 ? 0 : 1) + _chunks(x.pqzPop.length)
                + _chunks(x.attrs.kemPk.length) + _chunks(blob));
            assertEq(a.keyOf(x.ua), vk[i] == 0 ? bytes("") : x.keyData);
            (bytes memory pk, bytes memory sig) = a.kemKeyAt(x.ua, v);
            assertEq(pk, x.attrs.kemPk);
            assertEq(sig, "");
            (pk, sig) = a.kemKeyAt(x.ua, v + 1);
            assertEq(pk.length + sig.length, 0, "a version not stored");
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
        a.register(x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
        (cp, cq, ck) = a.checkedOf(x.ua);
        assertEq(abi.encode(cp, cq, ck), abi.encode(1, 0, 1));
        assertEq(a.pqzPopOf(x.ua), x.pqzPop);
        assertEq(a.keyOwner(h), bytes32(0));
        (cp, cq, ck) = a.checkedOf(rows[P256_ROW].ua);
        assertEq(uint256(cp) + cq + ck, 0);
        // with the verifier: a proof it refuses (not yet allowed) is UAPoP
        UARegistry p = _deploy(address(0x5ce80), chainUidA, address(0), false, BUDGET, address(0), true, _vcfg(0, true));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        p.register(x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
        // proven: R_REG accepted over the row's portable message
        _allowPqz(x);
        vm.expectEmit(true, false, false, true, address(p));
        emit IUARegistry.UAPqzPopStored(x.ua, UAKinds.CHECKED_CHAIN);
        vm.expectEmit(true, true, false, true, address(p));
        emit IUARegistry.UARegistered(x.ua, x.kind, x.keyData, x.attrs, x.pop, x.pqzPop, 1, 1, 1);
        p.register(x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
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
        emit IUARegistry.UARegistered(x.ua, x.kind, x.keyData, x.attrs, x.pop, "", 1, 0, 1);
        q.register(x.kind, x.keyData, x.attrs, x.pop, "");
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
            (bytes memory pk, bytes memory sig) = g2.kemKeyAt(x.ua, 1);
            assertEq(abi.encode(pk, sig), abi.encode(x.attrs.kemPk, bytes("")));
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
        uint256 bound = 8 * (1_400_000 + 35_000) + 400_000 + 35_000 + uint256(1_400_000 - 400_000) / 63;
        UARegistry r = _deploy(address(0x5cea0), chainUidA, address(0), false, uint64(bound), address(impl), true, c);
        Member[] memory m = new Member[](9);
        for (uint256 i; i < 8; ++i) {
            m[i] = Member(0x0133, r.register(0x0133, abi.encodePacked(keccak256(abi.encode("slh", i))), _none(), hex"01", ""), 1);
        }
        m[8] = Member(UAKinds.EVM_EOA, _pad(clone), 1);
        _storedPop(r, _msigKey(9, m), 9);
        // 12 members, a budget that admits them
        c[0].verifier = address(new AcceptAll());
        UARegistry big = _deploy(address(0x5cea1), chainUidA, address(0), false, uint64(12 * 1_435_000 + uint256(1_000_000) / 63),
            address(0), true, c);
        Member[] memory m12 = new Member[](12);
        for (uint256 i; i < 12; ++i) {
            m12[i] = Member(0x0133, big.register(0x0133, abi.encodePacked(keccak256(abi.encode("slh12", i))), _none(), hex"01", ""), 1);
        }
        _storedPop(big, _msigKey(12, m12), 12);
    }

    function _storedPop(UARegistry r, bytes memory d, uint16 n) internal {
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](n);
        for (uint16 j; j < n; ++j) s[j] = UARegistry.MemberSig(j, "", new bytes(7_856));
        bytes memory pop = abi.encode(s);
        bytes32 ua = r.register(UAKinds.MSIG, d, _none(), pop, "");
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
        p.register(x.kind, x.keyData, x.attrs, x.pop, "");
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
        p.register(x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
    }

    /// m2: a native member with an EIP-7702 designator (an EOA delegated to a wallet) answers ERC-1271 over
    /// `memberDigest` in a portable pop: its own key's `personal_sign` is refused, the delegate's 1271 accepted.
    function test_ua8_msigNativeMember7702Portable() public {
        Row[] memory rows = _rows();
        _allowAll(rows);
        Row memory m = rows[MSIG_NATIVE_ROW];
        UARegistry a = _regA(false);
        _members(a, rows);
        uint256 sk = _nativeSk();
        _delegate(m, sk, 0x5E55);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        a.register(m.kind, m.keyData, m.attrs, m.pop, m.pqzPop); // the EOA's personal_sign: not asked with code
        UARegistry.MemberSig[] memory s = abi.decode(m.pop, (UARegistry.MemberSig[]));
        bytes32 md = UAKinds.memberDigest(m.ua, m.popMessage);
        s[0].sig = _ecdsa(sk, md); // the EOA's own key over the raw digest: the delegate's owner is the session key
        bytes memory own = abi.encode(s);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        a.register(m.kind, m.keyData, m.attrs, own, m.pqzPop);
        s[0].sig = _ecdsa(0x5E55, md);
        bytes memory viaDelegate = abi.encode(s);
        assertEq(a.register(m.kind, m.keyData, m.attrs, viaDelegate, m.pqzPop), m.ua);
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

    /// m3: `_sigOk`, the chain-free signature path (personal_sign native members), accepts only the portable purposes
    /// POP_V2, KEM and PQZ_KEY; any other purpose reverts `UAUnauthorized`, for every kind.
    function test_ua8_sigOkPortablePurposesOnly() public {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(0x0101, address(mock), 400_000);
        SigOkHarness h = new SigOkHarness(chainUidA, BUDGET, k);
        bytes memory p = _key(0x0101);
        bytes32 ua = UAKinds.uaOf(0x0101, p);
        bytes32[3] memory ok = [UAKinds.PURPOSE_POP_V2, UAKinds.PURPOSE_KEM, UAKinds.PURPOSE_PQZ_KEY];
        for (uint256 i; i < 3; ++i) {
            assertTrue(h.sigOk(0x0101, p, ua, ok[i], DIGEST, _sig(p, UAKinds.uaMessage(0x0101, ok[i], DIGEST))));
        }
        bytes32[4] memory no =
            [UAKinds.PURPOSE_METATX, UAKinds.PURPOSE_MEMBER, UAKinds.PURPOSE_POP, UAKinds.PURPOSE_TRADE];
        for (uint256 i; i < 4; ++i) {
            bytes memory sig = _sig(p, UAKinds.uaMessage(0x0101, no[i], DIGEST)); // a valid signature under that purpose
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
            h.sigOk(0x0101, p, ua, no[i], DIGEST, sig);
        }
        // a classical msig (empty sig is its answer under a portable purpose) is refused under metatx too
        Member[] memory mm = new Member[](1);
        mm[0] = Member(UAKinds.EVM_EOA, _pad(address(0xA11CE)), 1);
        bytes memory d = _msigKey(1, mm);
        bytes32 mua = UAKinds.uaOf(UAKinds.MSIG, d);
        assertTrue(h.sigOk(UAKinds.MSIG, d, mua, UAKinds.PURPOSE_POP_V2, DIGEST, ""));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, mua));
        h.sigOk(UAKinds.MSIG, d, mua, UAKinds.PURPOSE_METATX, DIGEST, "");
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
        assertEq(to.register(k, d, att, pop, withProof ? z : bytes("")), ua);
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
        emit IUARegistry.UAPqzPopStored(x.ua, UAKinds.CHECKED_NONE);
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
        emit IUARegistry.UAPqzPopStored(x.ua, UAKinds.CHECKED_CHAIN);
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
            p.register(r.kind, r.keyData, r.attrs, r.pop, ""); // registerWith: no proof
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzPopHash.selector, r.ua));
            p.storePqzPop(r.ua, x.pqzPop);
            vm.revertToState(snap);
            ++n;
        }
        assertEq(n, 4, "one per set");
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
            r.register(x.kind, x.keyData, x.attrs, x.pop, "");
            vm.expectEmit(true, false, false, true, address(r));
            emit IUARegistry.UAPqzPopStored(x.ua, i == 0 ? UAKinds.CHECKED_CHAIN : UAKinds.CHECKED_NONE);
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
        p.register(x.kind, x.keyData, x.attrs, x.pop, "");
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
        s.attrs = IUARegistry.UAAttrs(x.attrs.pqzKey, x.attrs.pqzPopHash, 0, "");
        bytes32 portable = UAKinds.portablePopDigest(s.ua, _h(x.attrs.pqzKey), 0);
        s.popMessage = UAKinds.uaMessage(UAKinds.MLDSA65, UAKinds.PURPOSE_POP_V2,
            UAKinds.registrationDigest(portable, s.attrs.pqzPopHash));
        s.pqzRegMessage = UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, portable);
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
        p.register(s.kind, s.keyData, s.attrs, s.pop, "");
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
        p.register(s.kind, s.keyData, s.attrs, s.pop, s.pqzPop);
        p.register(s.kind, s.keyData, s.attrs, s.pop, "");
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
        g1.register(x.kind, x.keyData, x.attrs, x.pop, "");
        _reg(g1, rows[FNDSA_ROW]);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, x.ua));
        g2.storePqzPop(x.ua, x.pqzPop);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, k.ua));
        g2.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, k.sig);
        g1.storePqzPop(x.ua, x.pqzPop);
        g1.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, k.sig);
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
        _checkedEq(g2p, m.ua, 1, 1, m.attrs.kemVersion != 0 ? 1 : 0);
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
        assertEq(UAKinds.uaMessage(k.kind, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyRecordDigest(kd, k.pqzPopHash)), k.message);
        assertEq(UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, kd), k.pqzRegMessage);
        vm.expectEmit(true, false, false, true, address(r));
        emit IUARegistry.UAPqzKeyAdded(k.ua, h, k.pqzPopHash);
        vm.prank(address(0xBEEF), address(0xBEEF));
        r.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, k.sig);
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
        _checkedEq(r, k.ua, 1, proven ? 1 : 0, base.attrs.kemVersion != 0 ? 1 : 0);
        assertEq(r.keyOwner(_h(k.pqzKey)), proven ? k.ua : bytes32(0));
        assertEq(r.uaCount(UAKinds.PQZ_MLWE), proven ? 1 : 0);
    }

    /// Ruling A1-I1: every portable.json `pqzKeyRecords` row (fndsa512, msig-pq-native with its native member's
    /// personal_sign; four sets) adds its key to a registration without one: unproven, `pqzKeySigOf` the record's
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
            emit IUARegistry.UAPqzPopStored(k.ua, UAKinds.CHECKED_NONE);
            a.storePqzPop(k.ua, proof);
            _assertAdded(a, base, k, proof, false);
            _addKey(p, base, k);
            vm.mockCall(rreg, abi.encodeCall(IUAPopVerifier.verifyPop, (k.pqzKey, k.pqzRegMessage, proof)),
                abi.encode(uint256(1)));
            vm.expectEmit(true, false, false, true, address(p));
            emit IUARegistry.UAPqzPopStored(k.ua, UAKinds.CHECKED_CHAIN);
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
                else revert(string.concat(g.name, ": unknown mutation ", g.keys[f]));
            }
            bytes4 sel = _eq(g.err, "UAPqzKeySet")
                ? IUARegistry.UAPqzKeySet.selector
                : _eq(g.err, "UAPqzHolder") ? IUARegistry.UAPqzHolder.selector : IUARegistry.UAUnauthorized.selector;
            assertTrue(_eq(g.err, "UAPqzKeySet") || _eq(g.err, "UAPqzHolder") || _eq(g.err, "UAUnauthorized"), g.err);
            vm.expectRevert(abi.encodeWithSelector(sel, k.ua));
            a.setPqzKey(k.ua, k.pqzKey, k.pqzPopHash, k.sig);
            vm.revertToState(snap);
            ++n;
        }
        assertEq(n, 12, "three per set");
        KeyRec memory r = _keyRec(ks, string.concat("fndsa512/", _setName()));
        bytes32 none = keccak256("unregistered");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, none));
        a.setPqzKey(none, r.pqzKey, r.pqzPopHash, r.sig);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.PQZ_MLWE));
        a.setPqzKey(r.ua, _slice(r.pqzKey, 0, r.pqzKey.length - 1), r.pqzPopHash, r.sig);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzPopHash.selector, r.ua));
        a.setPqzKey(r.ua, r.pqzKey, 0, r.sig);
        a.setPqzKey(r.ua, r.pqzKey, r.pqzPopHash, r.sig);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, r.ua));
        a.setPqzKey(r.ua, r.pqzKey, r.pqzPopHash, r.sig);
        // A5-I1: gen 2 (fndsa512) in front of a gen 1 that enables 0x0142
        UARegistry.KindConfig[] memory c1 = new UARegistry.KindConfig[](1);
        c1[0] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, rreg, 1_000_000);
        UARegistry g1 = _deploy(address(0x5ceb8), chainUidA, address(0), false, BUDGET, address(0), true, c1);
        UARegistry.KindConfig[] memory c2 = new UARegistry.KindConfig[](1);
        c2[0] = UARegistry.KindConfig(UAKinds.FNDSA512, address(new UAFndsaVerifier()), CAP_FNDSA);
        UARegistry g2 = _deploy(address(0x5ceb9), chainUidA, address(g1), false, BUDGET, address(0), true, c2);
        _reg(g2, rows[FNDSA_ROW]);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, UAKinds.PQZ_MLWE));
        g2.setPqzKey(r.ua, r.pqzKey, r.pqzPopHash, r.sig);
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
        p.setPqzKey(k.ua, SSTORE2.read(ptr), ph, a.pqzKeySigOf(k.ua));
        vm.mockCall(rreg, abi.encodeCall(IUAPopVerifier.verifyPop, (k.pqzKey, k.pqzRegMessage, proof)), abi.encode(uint256(1)));
        vm.prank(address(0xC0B1E5), address(0xC0B1E5));
        p.storePqzPop(k.ua, a.pqzPopOf(k.ua));
        _assertAdded(p, base, k, proof, true);
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
        for (uint256 i; i < negs.length; ++i) {
            Neg memory g = negs[i];
            if (keccak256(bytes(g.entry)) != keccak256("register") || !_in(g.err, errs)) continue;
            Row memory x = _apply(_find(rows, g.row), g);
            vm.expectRevert(_expected(g.err, x));
            a.register(x.kind, x.keyData, x.attrs, x.pop, x.pqzPop);
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
            IUARegistry.UAAttrs(src.attrs.pqzKey, src.attrs.pqzPopHash, src.attrs.kemVersion, src.attrs.kemPk), src.pop,
            src.pqzPop, src.popMessage, src.pqzRegMessage);
        for (uint256 k; k < g.keys.length; ++k) {
            bytes32 key = keccak256(bytes(g.keys[k]));
            bytes memory v = g.values[k];
            if (key == keccak256("attrs.pqzKey")) r.attrs.pqzKey = v;
            else if (key == keccak256("attrs.pqzPopHash")) r.attrs.pqzPopHash = bytes32(v);
            else if (key == keccak256("attrs.kemVersion")) r.attrs.kemVersion = uint64(abi.decode(v, (uint256)));
            else if (key == keccak256("attrs.kemPk")) r.attrs.kemPk = v;
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
            return abi.encodeWithSelector(IUARegistry.UAKemKeyLength.selector, x.attrs.kemPk.length);
        }
        if (k == keccak256("UAKemVersion")) return abi.encodeWithSelector(IUARegistry.UAKemVersion.selector, x.ua, 0);
        revert(string.concat("unmapped error ", e));
    }

    /// Contracts created (and their code bytes after the STOP byte) by the recorded call.
    function _created(VmSafe.AccountAccess[] memory acc) internal pure returns (uint256 n, uint256 bytes_) {
        for (uint256 i; i < acc.length; ++i) {
            if (acc[i].kind == VmSafe.AccountAccessKind.Create && !acc[i].reverted) {
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
}
