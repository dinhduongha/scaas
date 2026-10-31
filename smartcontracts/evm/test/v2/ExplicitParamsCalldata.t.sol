// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";

/// typed-signing X0 (measurement only, no contract change): the calldata of every confidential op and of the PQZ
/// registration in today's packed form next to the explicit-parameter form proposed in the plan's Appendix X, per
/// relay path (`mtx*`: ECDSA envelope; `ua*`: an `mldsa65` fee UA, 3,309-byte signature). Today's calls are built
/// exactly as `PqzStatePinGasTest`'s gas table (`_envelopeVia`, `_op1p`, `_op7a`, `_burnP`, `_msigHolder`,
/// `_registerRows`) with the set's proof lengths (`test/vectors/pqz-gas/<set>.json`: PQZL the vector proof, PQZH its
/// bound), so the "today" byte counts reproduce the pinned rows (pq-zero-knowledge.md "Findings for the owner" (3)).
/// Every PQZH debit is floor-bound (EIP-7976: regular gas = 15,000 + 64 per calldata byte, zero bytes too), so its
/// headroom against 2^24 (EIP-7825) follows from the byte count alone; PQZL rows are execution-bound (their headroom is
/// read from the gas-table logs, the typed form only adds `std` delta). Proof bytes are pseudo-random, signatures
/// zero-filled as the gas table's (the floor counts zero bytes the same).
/// Run per set: `scripts/capped smartcontracts/evm/script/pqz/at-set.sh <set> test --match-path test/v2/ExplicitParamsCalldata.t.sol -vv`
/// (logs `runs/2026-10-31-typed-signing-x0-calldata-<set>.txt`).
contract ExplicitParamsCalldataTest is Test {
    // ------------------------------------------------------------------ proposed explicit forms (Appendix X)

    struct Envelope {
        address from;
        uint256 batch;
        uint256 nonce;
        uint256 validUntil;
        uint32 mode;
        address relayer;
        uint256 fee;
        address feeRecipient;
    }

    struct UAEnvelope {
        bytes32 from;
        uint256 batch;
        uint256 nonce;
        uint256 validUntil;
        uint32 mode;
        address relayer;
        uint256 fee;
        address feeRecipient;
    }

    struct MemberSig {
        uint16 index;
        bytes keyData;
        bytes sig;
    }

    struct UASig {
        bytes keyData;
        bytes signature;
        MemberSig[] members;
    }

    struct PqzTransferArgs {
        uint64 p;
        uint256 validUntilBlock;
        uint256 shieldIn;
        bytes32 fromUA;
        bytes32 toUA;
        bytes32 beneficiaryUA;
        bytes16 salt;
        bytes u;
        bytes vTo;
        bytes vFrom;
        bytes vAuditor; // empty: auditor off
        bytes sealedMemo; // commit-reveal only: memo[16:] (41 B); the token prepends `salt`
    }

    struct PqzLeg {
        bytes32 ua;
        bytes v;
        bytes vAuditor; // empty: auditor off
    }

    struct PqzMultiArgs {
        uint64 p;
        uint256 validUntilBlock;
        uint256 shieldIn;
        bytes32 fromUA;
        bytes32 beneficiaryUA;
        uint256 decoyFee;
        bytes16 salt;
        bytes[] u; // G randomness parts
        PqzLeg[] legs; // M = legs.length
        bytes vFrom;
        bytes sealedMemo; // commit-reveal only: memo[16:] (2 + 40·M B)
    }

    struct PqzBurnArgs {
        uint64 p;
        uint256 validUntilBlock;
        uint256 shieldIn;
        bytes32 fromUA;
        bytes32 beneficiaryUA;
        bytes u;
        bytes vFrom;
    }

    /// An EIP-2537 BLS12-381 G1 point (128 B: `x` and `y`, each 16 zero bytes ‖ 48 bytes), a static type.
    struct G1 {
        bytes32 x0;
        bytes32 x1;
        bytes32 y0;
        bytes32 y1;
    }

    struct ZetherSingle {
        uint64 accSeq;
        uint64 sendCounter;
        uint256 validUntilBlock;
        bytes16 salt;
        bytes32 beneficiaryUA;
        G1 yFrom;
        G1 yTo;
        G1 cOut;
        G1 dOut;
        G1 cDeb;
        G1 cAud;
    }

    struct ZetherLeg {
        G1 yTo;
        G1 cOut;
        G1 cAud;
        G1 dAud;
    }

    struct ZetherMulti {
        uint64 accSeq;
        uint64 sendCounter;
        uint256 validUntilBlock;
        bytes16 salt;
        bytes32 beneficiaryUA;
        uint256 decoyFee;
        G1 yFrom;
        G1 dOut;
        G1 cDeb;
        ZetherLeg[] legs;
        bytes sealedMemo; // commit-reveal only: memo[16:] (1 + 40·M B)
    }

    struct ZetherBurn {
        uint64 accSeq;
        uint64 sendCounter;
        uint256 validUntilBlock;
        bytes32 beneficiaryUA;
        G1 yFrom;
    }

    struct KemKey {
        uint8 scheme;
        bytes mlkemEk;
        bytes32 x25519;
    }

    struct UAAttrsT {
        bytes pqzKey;
        bytes32 pqzPopHash;
        uint64 kemVersion;
        KemKey kem;
    }

    struct WrappedUnwrapArgs {
        address underlying;
        uint256 wrapped;
        address recipient;
        uint256 minOut;
    }

    // ------------------------------------------------------------------ constants and helpers

    uint256 internal constant CAP = 1 << 24; // EIP-7825
    uint256 internal constant ML65_SIG = 3309;
    uint256 internal constant ML65_PK = 1952;
    uint256 internal constant ECDSA_SIG = 65;
    uint256 internal constant P = 128; // a BLS12-381 G1 point
    uint256 internal constant PK = PqzSet.PK;
    uint256 internal constant V = PqzSet.V;
    bytes16 internal constant SALT = bytes16(uint128(0x5A17));
    bytes32 internal constant FROM = keccak256("from");
    bytes32 internal constant TO = keccak256("to");
    bytes32 internal constant BEN = keccak256("ben");

    string internal gj;
    string internal sys;

    function _rnd(uint256 seed, uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            bytes32 w = keccak256(abi.encode(seed, i));
            assembly ("memory-safe") { mstore(add(add(b, 32), i), w) }
        }
    }

    function _g1(uint256 seed) internal pure returns (G1 memory g) {
        g = G1(bytes32(uint256(uint128(uint256(keccak256(abi.encode(seed, 0)))))), keccak256(abi.encode(seed, 1)),
            bytes32(uint256(uint128(uint256(keccak256(abi.encode(seed, 2)))))), keccak256(abi.encode(seed, 3)));
    }

    function _g1b(uint256 seed) internal pure returns (bytes memory) {
        return abi.encode(_g1(seed));
    }

    function _proofLen(string memory key) internal view returns (uint256) {
        return vm.parseJsonUint(gj, string.concat(".", sys, "['", key, "'].proof"));
    }

    function _env() internal view returns (Envelope memory e) {
        e = Envelope(vm.addr(0xA11CE), 0, 0, block.timestamp + 1 hours, MetaTxLib.MODE_FEE_FIXED, address(0), 7,
            address(0));
    }

    function _uaEnv() internal view returns (UAEnvelope memory e) {
        e = UAEnvelope(keccak256("fee UA"), 0, 0, block.timestamp + 1 hours, MetaTxLib.MODE_FEE_FIXED, address(0), 7,
            address(0));
    }

    /// Today: `data` in a `mtxExecute` (ua = false) or `uaExecute` envelope, as `PqzStatePinGasTest._envelopeVia`.
    function _today(bool ua, bytes memory data) internal view returns (bytes memory) {
        if (ua) {
            UAEnvelope memory x = _uaEnv();
            MetaTxLib.UAMetaTransaction memory u = MetaTxLib.UAMetaTransaction(x.from, data, 0, 0, x.validUntil, x.mode,
                address(0), 7, address(0));
            return abi.encodeCall(IUALedger.uaExecute, (u, abi.encode(bytes(""), _rnd(9, ML65_SIG))));
        }
        Envelope memory y = _env();
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction(y.from, data, 0, 0, y.validUntil, y.mode,
            address(0), 7, address(0));
        return abi.encodeCall(IMetaTx.mtxExecute, (m, _rnd(8, ECDSA_SIG)));
    }

    function _feeAuth() internal pure returns (UASig memory s) {
        s.signature = _rnd(9, ML65_SIG);
    }

    /// The holder's statement authorization (`_mlAuth`: an `mldsa65` holder, zero-filled 3,309-byte signature).
    function _mlAuthToday() internal pure returns (bytes memory) {
        return abi.encode(bytes(""), new bytes(ML65_SIG));
    }

    function _mlAuthTyped() internal pure returns (UASig memory s) {
        s.signature = new bytes(ML65_SIG);
    }

    // ------------------------------------------------------------------ reporting

    function _row(string memory form, bool ua, bytes memory today, bytes memory typed) internal view {
        (uint256 n0, uint256 z0) = _count(today);
        (uint256 n1, uint256 z1) = _count(typed);
        uint256 f0 = 15_000 + 64 * n0;
        uint256 f1 = 15_000 + 64 * n1;
        int256 d = int256(n1) - int256(n0);
        int256 dStd = int256(4 * z1 + 16 * (n1 - z1)) - int256(4 * z0 + 16 * (n0 - z0));
        console2.log(string.concat("X0 ", PqzSet.NAME, " ", sys, ua ? " ua " : " mtx", " | ", form, " | today ",
            vm.toString(n0), " B floor ", vm.toString(f0), " | typed ", vm.toString(n1), " B floor ", vm.toString(f1)));
        console2.log(string.concat("    | delta ", vm.toString(d), " B, floor ", vm.toString(d * 64), " gas, std ",
            vm.toString(dStd), " gas | floor headroom to 2^24 today ", vm.toString(int256(CAP) - int256(f0)), " / typed ",
            vm.toString(int256(CAP) - int256(f1)), " (", vm.toString((int256(CAP) - int256(f1)) / 64), " B)",
            f1 > CAP ? " | OVER" : ""));
    }

    function _count(bytes memory b) internal pure returns (uint256 n, uint256 z) {
        n = b.length;
        for (uint256 i; i < n; ++i) if (b[i] == 0) ++z;
    }

    /// A typed entry's selector (4 bytes; the exact signatures are Appendix X's, overloads included).
    function _sel(string memory name) internal pure returns (bytes4) {
        return bytes4(keccak256(bytes(name)));
    }

    // ------------------------------------------------------------------ PQZ

    function _outOp1(bool aud) internal pure returns (bytes memory) {
        return _rnd(77, PK + V * (aud ? 3 : 2));
    }

    function _op1Today(bool aud, bytes memory proof, bytes memory memo) internal view returns (bytes memory) {
        bytes memory pl = bytes.concat(abi.encode(uint256(0), block.number + 100, uint256(0), FROM, TO, BEN), SALT,
            _outOp1(aud), memo);
        return abi.encodeCall(IConfidentialToken.mtxConfidentialTransferSingle, (pl, proof, _mlAuthToday(), BEN, ""));
    }

    function _op1Args(bool aud, bytes memory memo) internal view returns (PqzTransferArgs memory a) {
        bytes memory o = _outOp1(aud);
        a = PqzTransferArgs(0, block.number + 100, 0, FROM, TO, BEN, SALT, _cut(o, 0, PK), _cut(o, PK, V),
            _cut(o, PK + V, V), aud ? _cut(o, PK + 2 * V, V) : bytes(""), memo.length == 0 ? memo : _cut(memo, 16, memo.length - 16));
    }

    function _op1Typed(bool ua, bool aud, bytes memory proof, bytes memory memo) internal view returns (bytes memory) {
        PqzTransferArgs memory a = _op1Args(aud, memo);
        if (ua) return abi.encodeWithSelector(_sel("uaConfidentialTransferSingle"), _uaEnv(), a, proof,
            _mlAuthTyped(), bytes(""), _feeAuth());
        return abi.encodeWithSelector(_sel("mtxConfidentialTransferSingle"), _env(), a, proof, _mlAuthTyped(), bytes(""), _rnd(8, ECDSA_SIG));
    }

    function _groups(uint256 m, bool aud) internal pure returns (uint256) {
        return aud ? (m + PqzSet.S_AUD - 1) / PqzSet.S_AUD : (m + 3) / 4;
    }

    function _legUA(uint256 j) internal pure returns (bytes32) {
        return keccak256(abi.encode("leg", j));
    }

    function _op7Today(uint256 m, bool aud, bytes memory proof, bytes memory memo) internal view returns (bytes memory) {
        bytes memory r;
        for (uint256 j; j < m; ++j) r = bytes.concat(r, _legUA(j));
        uint256 g = _groups(m, aud);
        bytes memory out = _rnd(81 + m, PK * g + V * (m + 1) + (aud ? V * m : 0));
        bytes memory pl = bytes.concat(abi.encode(uint256(0), block.number + 100, uint256(0), FROM, BEN, m, uint256(0)),
            SALT, r, out, memo);
        return abi.encodeCall(IConfidentialToken.mtxConfidentialTransfer, (pl, proof, _mlAuthToday(), BEN, ""));
    }

    function _op7Args(uint256 m, bool aud, bytes memory memo) internal view returns (PqzMultiArgs memory a) {
        uint256 g = _groups(m, aud);
        bytes memory out = _rnd(81 + m, PK * g + V * (m + 1) + (aud ? V * m : 0));
        a.p = 0;
        a.validUntilBlock = block.number + 100;
        a.fromUA = FROM;
        a.beneficiaryUA = BEN;
        a.salt = SALT;
        a.u = new bytes[](g);
        for (uint256 i; i < g; ++i) a.u[i] = _cut(out, PK * i, PK);
        a.legs = new PqzLeg[](m);
        uint256 vs = PK * g;
        for (uint256 j; j < m; ++j) {
            a.legs[j] = PqzLeg(_legUA(j), _cut(out, vs + V * j, V), aud ? _cut(out, vs + V * (m + 1 + j), V) : bytes(""));
        }
        a.vFrom = _cut(out, vs + V * m, V);
        a.sealedMemo = memo.length == 0 ? memo : _cut(memo, 16, memo.length - 16);
    }

    function _op7Typed(bool ua, uint256 m, bool aud, bytes memory proof, bytes memory memo)
        internal view returns (bytes memory)
    {
        PqzMultiArgs memory a = _op7Args(m, aud, memo);
        if (ua) return abi.encodeWithSelector(_sel("uaConfidentialTransfer"), _uaEnv(), a, proof, _mlAuthTyped(),
            bytes(""), _feeAuth());
        return abi.encodeWithSelector(_sel("mtxConfidentialTransfer"), _env(), a, proof, _mlAuthTyped(), bytes(""), _rnd(8, ECDSA_SIG));
    }

    function _burnPayload() internal view returns (bytes memory) {
        return bytes.concat(abi.encode(uint256(0), block.number + 5, uint256(0), FROM, BEN), _rnd(5, PK + V));
    }

    function _burnArgs() internal view returns (PqzBurnArgs memory a) {
        bytes memory o = _rnd(5, PK + V);
        a = PqzBurnArgs(0, block.number + 5, 0, FROM, BEN, _cut(o, 0, PK), _cut(o, PK, V));
    }

    function _burnToday(bytes memory proof, bytes memory auth, uint256 amount) internal view returns (bytes memory) {
        return abi.encodeCall(IConfidentialToken.mtxUnshield, (_burnPayload(), proof, auth, BEN, "", amount,
            amount == 0 ? bytes32(0) : bytes32(uint256(0xD00D))));
    }

    function _burnTyped(bool ua, bytes memory proof, UASig memory auth, uint256 amount) internal view returns (bytes memory) {
        bytes32 rcp = amount == 0 ? bytes32(0) : bytes32(uint256(0xD00D));
        if (ua) return abi.encodeWithSelector(_sel("uaUnshield"), _uaEnv(), _burnArgs(), amount, rcp, proof, auth,
            bytes(""), _feeAuth());
        return abi.encodeWithSelector(_sel("mtxUnshield"), _env(), _burnArgs(), amount, rcp, proof, auth, bytes(""),
            _rnd(8, ECDSA_SIG));
    }

    function _unwrapX() internal pure returns (IConfidentialWrappedToken.Unwrap memory) {
        return IConfidentialWrappedToken.Unwrap(address(0xBEEF), bytes32(uint256(0xD00D)), 1, 1);
    }

    function _burnUnwrapToday(bytes memory proof) internal view returns (bytes memory) {
        return abi.encodeCall(IConfidentialWrappedToken.mtxUnshieldUnwrap, (_burnPayload(), proof, _mlAuthToday(), BEN,
            "", _unwrapX()));
    }

    function _burnUnwrapTyped(bool ua, bytes memory proof) internal view returns (bytes memory) {
        if (ua) return abi.encodeWithSelector(_sel("uaUnshieldUnwrap"), _uaEnv(), _burnArgs(), _unwrapX(), proof,
            _mlAuthTyped(), bytes(""), _feeAuth());
        return abi.encodeWithSelector(_sel("mtxUnshieldUnwrap"), _env(), _burnArgs(), _unwrapX(), proof,
            _mlAuthTyped(), bytes(""), _rnd(8, ECDSA_SIG));
    }

    /// An n-of-n `mldsa65` `msig` holder's auth (`PqzStatePinGasTest._msigHolder`): today `abi.encode(structure,
    /// abi.encode(MemberSig[]))`; typed `UASig{members}` (TS-D12: `msig` carries only `members`).
    function _msigToday(uint256 n) internal pure returns (bytes memory) {
        bytes memory d = abi.encodePacked(uint16(n), uint16(n));
        MemberSig[] memory s = new MemberSig[](n);
        for (uint256 i; i < n; ++i) {
            d = abi.encodePacked(d, uint16(0x0131), keccak256(abi.encode(i)), uint16(1));
            s[i] = MemberSig(uint16(i), "", new bytes(ML65_SIG));
        }
        return abi.encode(d, abi.encode(s));
    }

    function _msigTyped(uint256 n) internal pure returns (UASig memory a) {
        a.members = new MemberSig[](n);
        for (uint256 i; i < n; ++i) a.members[i] = MemberSig(uint16(i), "", new bytes(ML65_SIG));
    }

    function _pqzRows() internal {
        gj = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/pqz-gas/", PqzSet.NAME, ".json"));
        bool h = keccak256(bytes(sys)) == keccak256("pqzh");
        for (uint256 k; k < 2; ++k) {
            bool ua = k == 1;
            for (uint256 a; a < 2; ++a) {
                bool aud = a == 0;
                string memory key = aud ? "TRANSFER" : "TRANSFER0";
                bytes memory pf = _rnd(1, _proofLen(key));
                { uint256 m0 = _fmp();
                    _row(string.concat("op 1 BUNDLE", aud ? ", auditor" : ", no auditor"), ua, _today(ua, _op1Today(aud, pf, "")),
                        _op1Typed(ua, aud, pf, ""));
                    _reset(m0); }
                bytes memory memo = bytes.concat(SALT, _rnd(0x3e30, 41));
                { uint256 m0 = _fmp();
                    _row(string.concat("op 1 commit-reveal (memo 57 B)", aud ? ", auditor" : ", no auditor"), ua,
                        _today(ua, _op1Today(aud, pf, memo)), _op1Typed(ua, aud, pf, memo));
                    _reset(m0); }
            }
            for (uint256 m = 1; m <= (h ? 4 : 8); m *= 2) {
                for (uint256 a; a < 2; ++a) {
                    bool aud = a == 0;
                    string memory key = string.concat("M", vm.toString(m), aud ? "-on" : "-off");
                    bytes memory pf = _rnd(2, _proofLen(key));
                    string memory f = string.concat("op 7 M = ", vm.toString(m), aud ? ", auditor" : ", no auditor");
                    { uint256 m0 = _fmp();
                        _row(f, ua, _today(ua, _op7Today(m, aud, pf, "")), _op7Typed(ua, m, aud, pf, ""));
                        _reset(m0); }
                    bytes memory memo = bytes.concat(SALT, _rnd(0x3e31, 2 + 40 * m));
                    { uint256 m0 = _fmp();
                        _row(string.concat(f, ", commit-reveal (memo 18 + 40M B)"), ua, _today(ua, _op7Today(m, aud, pf, memo)),
                            _op7Typed(ua, m, aud, pf, memo));
                        _reset(m0); }
                }
            }
            bytes memory bp = _rnd(3, _proofLen("BURN"));
            { uint256 m0 = _fmp();
                _row("burn 1 to an address", ua, _today(ua, _burnToday(bp, _mlAuthToday(), 1)),
                    _burnTyped(ua, bp, _mlAuthTyped(), 1));
                _reset(m0); }
            { uint256 m0 = _fmp();
                _row("refresh", ua, _today(ua, _burnToday(bp, _mlAuthToday(), 0)), _burnTyped(ua, bp, _mlAuthTyped(), 0));
                _reset(m0); }
            { uint256 m0 = _fmp();
                _row("unshield-unwrap (wrapped PQZ)", ua, _today(ua, _burnUnwrapToday(bp)), _burnUnwrapTyped(ua, bp));
                _reset(m0); }
            for (uint256 n = 2; n <= 3; ++n) {
                { uint256 m0 = _fmp();
                    _row(string.concat("burn 1, ", vm.toString(n), "-of-", vm.toString(n), " mldsa65 msig holder"), ua,
                        _today(ua, _burnToday(bp, _msigToday(n), 1)), _burnTyped(ua, bp, _msigTyped(n), 1));
                    _reset(m0); }
            }
        }
        // registration (a direct call, no envelope): `mldsa65` UA with a PQZ key, without and with a scheme-1 KEM key
        bytes memory rp = _rnd(4, _proofLen("REGISTER"));
        for (uint256 kem; kem < 2; ++kem) {
            bytes memory kemPk = kem == 1 ? bytes.concat(bytes1(0x01), _rnd(6, 1600)) : bytes("");
            IUARegistry.UAAttrs memory at = IUARegistry.UAAttrs(_rnd(7, PK), keccak256(rp), uint64(kem), kemPk);
            UAAttrsT memory tt = UAAttrsT(_rnd(7, PK), keccak256(rp), uint64(kem),
                kem == 1 ? KemKey(1, _cut(kemPk, 1, 1568), bytes32(_cut(kemPk, 1569, 32))) : KemKey(0, "", 0));
            { uint256 m0 = _fmp();
                _row(kem == 1 ? "register, PQZ key + KEM key (direct)" : "register, PQZ key, no KEM key (direct)", false,
                    abi.encodeCall(IUARegistry.register, (0x0131, _rnd(10, ML65_PK), at, new bytes(ML65_SIG), rp)),
                    abi.encodeWithSelector(_sel("register"), uint16(0x0131), _rnd(10, ML65_PK), tt, new bytes(ML65_SIG), rp));
                _reset(m0); }
        }
    }

    // ------------------------------------------------------------------ Zether (BLS12-381; set-independent)

    function _zSinglePayload() internal view returns (bytes memory) {
        bytes memory pts;
        for (uint256 i; i < 6; ++i) pts = bytes.concat(pts, _g1b(100 + i));
        return bytes.concat(abi.encode(uint256(5), uint256(3), block.number + 100), SALT, pts);
    }

    function _zSingle() internal view returns (ZetherSingle memory) {
        return ZetherSingle(5, 3, block.number + 100, SALT, BEN, _g1(100), _g1(101), _g1(102), _g1(103), _g1(104), _g1(105));
    }

    function _zMultiPayload(uint256 m, bytes memory memo) internal view returns (bytes memory pl) {
        pl = bytes.concat(abi.encode(uint256(5), uint256(3), block.number + 100), SALT, abi.encode(m, uint256(7)),
            _g1b(200), _g1b(201), _g1b(202));
        for (uint256 j; j < m; ++j) pl = bytes.concat(pl, _g1b(300 + 4 * j), _g1b(301 + 4 * j), _g1b(302 + 4 * j), _g1b(303 + 4 * j));
        pl = bytes.concat(pl, memo);
    }

    function _zMulti(uint256 m, bytes memory memo) internal view returns (ZetherMulti memory z) {
        z = ZetherMulti(5, 3, block.number + 100, SALT, BEN, 7, _g1(200), _g1(201), _g1(202), new ZetherLeg[](m),
            memo.length == 0 ? memo : _cut(memo, 16, memo.length - 16));
        for (uint256 j; j < m; ++j) z.legs[j] = ZetherLeg(_g1(300 + 4 * j), _g1(301 + 4 * j), _g1(302 + 4 * j), _g1(303 + 4 * j));
    }

    function _zetherRows() internal {
        sys = "zether";
        bytes memory ps = _rnd(11, 5_888); // zether s3 vectors: single 5,888 B, multi (M = 3) 11,936 B, burn 2,816 B
        bytes memory pm = _rnd(12, 11_936);
        bytes memory pb = _rnd(13, 2_816);
        for (uint256 k; k < 2; ++k) {
            bool ua = k == 1;
            bytes memory today = _today(ua, abi.encodeCall(IConfidentialToken.mtxConfidentialTransferSingle,
                (_zSinglePayload(), ps, "", BEN, "")));
            bytes memory typed = ua
                ? abi.encodeWithSelector(_sel("uaConfidentialTransferSingle"), _uaEnv(), _zSingle(), ps, _feeAuth())
                : abi.encodeWithSelector(_sel("mtxConfidentialTransferSingle"), _env(), _zSingle(), ps, _rnd(8, ECDSA_SIG));
            { uint256 m0 = _fmp();
                _row("single (6 points)", ua, today, typed);
                _reset(m0); }
            for (uint256 m = 1; m <= 8; m = m == 1 ? 3 : m + 5) {
                for (uint256 c; c < 2; ++c) {
                    bytes memory memo = c == 1 ? bytes.concat(SALT, _rnd(14, 1 + 40 * m)) : bytes("");
                    today = _today(ua, abi.encodeCall(IConfidentialToken.mtxConfidentialTransfer,
                        (_zMultiPayload(m, memo), pm, "", BEN, "")));
                    typed = ua
                        ? abi.encodeWithSelector(_sel("uaConfidentialTransfer"), _uaEnv(), _zMulti(m, memo), pm, _feeAuth())
                        : abi.encodeWithSelector(_sel("mtxConfidentialTransfer"), _env(), _zMulti(m, memo), pm, _rnd(8, ECDSA_SIG));
                    { uint256 m0 = _fmp();
                        _row(string.concat("multi M = ", vm.toString(m), c == 1 ? ", commit-reveal (memo 17 + 40M B)" : ", BUNDLE",
                            " (proof fixed at 11,936 B)"), ua, today, typed);
                        _reset(m0); }
                }
            }
            bytes memory bpl = bytes.concat(abi.encode(uint256(5), uint256(3), block.number + 100), _g1b(400));
            ZetherBurn memory zb = ZetherBurn(5, 3, block.number + 100, BEN, _g1(400));
            today = _today(ua, abi.encodeCall(IConfidentialToken.mtxUnshield, (bpl, pb, "", BEN, "", 1, bytes32(uint256(0xD00D)))));
            typed = ua
                ? abi.encodeWithSelector(_sel("uaUnshield"), _uaEnv(), zb, uint256(1), bytes32(uint256(0xD00D)), pb, _feeAuth())
                : abi.encodeWithSelector(_sel("mtxUnshield"), _env(), zb, uint256(1), bytes32(uint256(0xD00D)), pb,
                    _rnd(8, ECDSA_SIG));
            { uint256 m0 = _fmp();
                _row("unshield", ua, today, typed);
                _reset(m0); }
        }
        // a static op for scale: `mtxUnwrap` / `uaUnwrap` named entry vs the generic envelope
        sys = "static";
        WrappedUnwrapArgs memory w = WrappedUnwrapArgs(address(0xBEEF), 1, address(0xD00D), 1);
        bytes memory inner = abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", w.underlying, w.wrapped,
            w.recipient, w.minOut);
        { uint256 m0 = _fmp();
            _row("mtxUnwrap (WrappedToken)", false, _today(false, inner),
                abi.encodeWithSelector(_sel("mtxUnwrap"), _env(), w, _rnd(8, ECDSA_SIG)));
            _reset(m0); }
        { uint256 m0 = _fmp();
            _row("uaUnwrap (WrappedToken)", true, _today(true, inner), abi.encodeWithSelector(_sel("uaUnwrap"), _uaEnv(), w, _feeAuth()));
            _reset(m0); }
    }

    // ------------------------------------------------------------------ tests

    function test_x0_calldata() public {
        vm.roll(1_000);
        vm.warp(1_800_000_000);
        console2.log(string.concat("# X0 calldata at ", PqzSet.NAME, " (PK ", vm.toString(PK), ", V ", vm.toString(V),
            ", S_AUD ", vm.toString(PqzSet.S_AUD), ")"));
        sys = "pqzl";
        _pqzRows();
        if (PqzSet.HAS_PQZH) {
            sys = "pqzh";
            _pqzRows();
        }
        _zetherRows();
    }

    /// The explicit forms reassemble today's bytes exactly (Review Focus 5 at the ABI level; the contracts' own
    /// statement KATs come in C3 / C4): op 1, op 7 (M = 4, auditor) and burn payloads, Zether single / multi / burn.
    function test_x0_reassemblesPayload() public view {
        bytes memory memo = bytes.concat(SALT, _rnd(0x3e30, 41));
        PqzTransferArgs memory a = _op1Args(true, memo);
        bytes memory pl = bytes.concat(abi.encode(uint256(a.p), a.validUntilBlock, a.shieldIn, a.fromUA, a.toUA,
            a.beneficiaryUA), a.salt, a.u, a.vTo, a.vFrom, a.vAuditor, a.salt, a.sealedMemo);
        bytes memory want = bytes.concat(abi.encode(uint256(0), block.number + 100, uint256(0), FROM, TO, BEN), SALT,
            _outOp1(true), memo);
        assertEq(pl, want, "op 1");
        PqzMultiArgs memory b = _op7Args(4, true, "");
        bytes memory r;
        bytes memory vs;
        bytes memory va;
        for (uint256 j; j < 4; ++j) {
            r = bytes.concat(r, b.legs[j].ua);
            vs = bytes.concat(vs, b.legs[j].v);
            va = bytes.concat(va, b.legs[j].vAuditor);
        }
        bytes memory us;
        for (uint256 i; i < b.u.length; ++i) us = bytes.concat(us, b.u[i]);
        pl = bytes.concat(abi.encode(uint256(b.p), b.validUntilBlock, b.shieldIn, b.fromUA, b.beneficiaryUA,
            b.legs.length, b.decoyFee), b.salt, r, us, vs, b.vFrom, va);
        assertEq(keccak256(pl), keccak256(_cut(_op7Today(4, true, "", ""), 4 + 32 * 5 + 32, pl.length)), "op 7");
        PqzBurnArgs memory c = _burnArgs();
        assertEq(bytes.concat(abi.encode(uint256(c.p), c.validUntilBlock, c.shieldIn, c.fromUA, c.beneficiaryUA), c.u,
            c.vFrom), _burnPayload(), "burn");
        ZetherSingle memory z = _zSingle();
        assertEq(bytes.concat(abi.encode(uint256(z.accSeq), uint256(z.sendCounter), z.validUntilBlock), z.salt,
            abi.encode(z.yFrom, z.yTo, z.cOut, z.dOut, z.cDeb, z.cAud)), _zSinglePayload(), "zether single");
        bytes memory zm = bytes.concat(SALT, _rnd(14, 1 + 40 * 3));
        ZetherMulti memory y = _zMulti(3, zm);
        bytes memory zl = bytes.concat(abi.encode(uint256(y.accSeq), uint256(y.sendCounter), y.validUntilBlock), y.salt,
            abi.encode(y.legs.length, y.decoyFee, y.yFrom, y.dOut, y.cDeb), abi.encode(y.legs[0], y.legs[1], y.legs[2]),
            y.salt, y.sealedMemo);
        assertEq(zl, _zMultiPayload(3, zm), "zether multi");
    }

    function _cut(bytes memory b, uint256 off, uint256 n) internal pure returns (bytes memory c) {
        require(off + n <= b.length, "cut");
        c = new bytes(n);
        assembly ("memory-safe") { mcopy(add(c, 32), add(add(b, 32), off), n) }
    }

    /// Every row's buffers are garbage once logged: the free memory pointer goes back (the test's memory stays at one
    /// row's size; without it the quadratic memory cost of ~60 rows of ~300 KB runs out of gas).
    function _fmp() internal pure returns (uint256 p) {
        assembly ("memory-safe") { p := mload(0x40) }
    }

    function _reset(uint256 p) internal pure {
        assembly ("memory-safe") { mstore(0x40, p) }
    }
}
