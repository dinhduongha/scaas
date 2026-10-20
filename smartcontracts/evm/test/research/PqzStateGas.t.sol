// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";

/// @title Plan Task 5h (design) measurement prototype, **not production code**: the proposed PQZ state layout of
///        docs/superpowers/specs/2026-10-20-pqz-state-redesign.md, reduced to its storage and arithmetic hot paths.
/// @notice One SSTORE2 "op blob" per debit operation holds `u_0 … u_{G−1} ‖ v_0 … v_{M−1} ‖ v_f ‖ [v_a …]` (the shared
///         `u` of CTR-PQZ-04 stored once); a pending credit is ONE slot `blob(160) | g(8) | G(8) | j(8) | block(64)`;
///         `acc` is either a reference to the last debit's blob (`u_0`, `v_f`) or materialised in `CTW` slots, written
///         by rollovers. No proof, no statement, no registry: those costs are unchanged by the layout.
contract PqzStateProto {
    uint256 public immutable U; // bytes of u = 8 n
    uint256 public immutable CTW; // words of a ciphertext (U + 128) / 32
    uint256 public immutable Q; // modulus (lanes < 2^64; sums of up to 2^(64 − log2 q) terms)
    uint256 internal constant V = 128;
    uint64 internal constant INLINE_MAX = 16;
    uint64 internal constant ROLL_AGE = 24;
    uint8 internal constant MAT = 1; // acc is the materialised slots (else the blob reference)
    uint8 internal constant WRITTEN = 2; // the acc slots were written once (non-zero), so a rewrite is 2,900 + 2,100

    struct Account {
        uint64 pendingCount;
        uint64 rolled;
        uint64 floor;
        uint64 cleared;
        address accBlob; // fresh acc: (u_accG, v at accV) of the last debit's blob
        uint8 accG;
        uint8 accGs;
        uint8 accV;
        uint32 accUnits;
        uint8 flags;
        bytes32 accHash; // keccak of the materialised acc (calldata hint)
        mapping(uint64 => uint256) pending;
    }

    mapping(bytes32 => Account) internal acct;
    mapping(bytes32 => bytes32) internal todayPendingHash; // today's layout, for the comparison
    bytes32 internal todayAccHash;

    constructor(uint256 n, uint256 q) {
        U = 8 * n;
        CTW = (8 * n + V) / 32;
        Q = q;
    }

    // ---------------------------------------------------------------- writes of one debit operation

    /// The op blob, one pending slot per leg (`to[j]` in group `j / 4`), the sender's fresh acc reference.
    function writeOp(bytes calldata blob, uint8 groups, bytes32[] calldata to, bytes32 from) external returns (address p) {
        p = SSTORE2.write(blob);
        uint256 m = to.length;
        for (uint256 j; j < m; ++j) {
            Account storage b = acct[to[j]];
            uint64 i = b.pendingCount;
            b.pending[i] = _pack(p, uint8(j / 4), groups, uint8(j), uint64(block.number));
            b.pendingCount = i + 1;
        }
        if (from != 0) _fresh(acct[from], p, groups, uint8(m));
    }

    /// Only the pending slots (the blob exists): the per-credit write.
    function credit(bytes32 to, address p, uint8 g, uint8 groups, uint8 j) external {
        Account storage b = acct[to];
        uint64 i = b.pendingCount;
        b.pending[i] = _pack(p, g, groups, j, uint64(block.number));
        b.pendingCount = i + 1;
    }

    /// Debit effects: fresh acc reference, accUnits 1, rolled = floor = p, the consumed slots deleted (≤ 2 INLINE_MAX).
    function debitEffects(bytes32 from, address p, uint8 groups, uint8 vf, uint64 pp) external {
        Account storage a = acct[from];
        _fresh(a, p, groups, vf);
        a.rolled = pp;
        a.floor = pp;
        uint64 c0 = a.cleared;
        for (uint64 i = c0; i < pp; ++i) delete a.pending[i];
        a.cleared = pp;
    }

    function _fresh(Account storage a, address p, uint8 groups, uint8 vf) private {
        a.accBlob = p;
        a.accG = 0;
        a.accGs = groups;
        a.accV = vf;
        a.accUnits = 1;
        a.flags &= ~MAT;
    }

    // ---------------------------------------------------------------- rollover (anyone, strict order)

    function rollOver(bytes32 ua, uint256 n) external {
        Account storage a = acct[ua];
        uint64 r = a.rolled;
        require(n != 0 && r + n <= a.pendingCount, "range");
        bytes memory c = _loadAcc(ua, a);
        bytes memory t = new bytes(32 * CTW);
        uint256 w = CTW;
        for (uint256 k; k < n; ++k) {
            uint256 e = a.pending[uint64(r + k)];
            require(uint64(e) + ROLL_AGE <= block.number, "young");
            _entry(e, t);
            _addInto(c, t, w);
        }
        _reduce(c);
        _storeAcc(ua, a, c);
        a.accUnits += uint32(n);
        uint64 nr = uint64(r + n);
        a.rolled = nr;
        uint64 end = nr > INLINE_MAX ? nr - INLINE_MAX : 0;
        for (uint64 i = a.cleared; i < end; ++i) delete a.pending[i];
        if (end > a.cleared) a.cleared = end;
    }

    // ---------------------------------------------------------------- the debit's read: T = acc ± Σ inline

    /// `hint` empty: acc from state; else used when its keccak equals `accHash` (falls back to state otherwise).
    function total(bytes32 ua, uint64 p, bytes calldata hint) external view returns (bytes32) {
        Account storage a = acct[ua];
        bytes memory c;
        if (hint.length == 32 * CTW && a.flags & MAT != 0 && keccak256(hint) == a.accHash) c = hint;
        else c = _loadAcc(ua, a);
        uint64 r = a.rolled;
        require(p >= r && p - r <= INLINE_MAX, "inline");
        bytes memory t = new bytes(32 * CTW);
        uint256 w = CTW;
        for (uint64 i = r; i < p; ++i) {
            _entry(a.pending[i], t);
            _addInto(c, t, w);
        }
        _reduce(c);
        return keccak256(c);
    }

    /// Read view (wallet / restore from state): the acc bytes.
    function accOf(bytes32 ua) external view returns (bytes memory) {
        return _loadAcc(ua, acct[ua]);
    }

    function state(bytes32 ua) external view returns (uint64, uint64, uint64, uint64, uint32, uint8) {
        Account storage a = acct[ua];
        return (a.pendingCount, a.rolled, a.floor, a.cleared, a.accUnits, a.flags);
    }

    // ---------------------------------------------------------------- today's layout (calldata + hashes), for comparison

    function todayCredit(bytes32 ua, uint64 i, bytes calldata ct) external {
        todayPendingHash[keccak256(abi.encode(ua, i))] = keccak256(ct);
    }

    /// PqzCore.rollOver's work: the acc and every ct from calldata, hash-checked, summed, the new hash stored.
    function todaySetAcc(bytes32 h) external {
        todayAccHash = h;
    }

    function todayRollOver(bytes32 ua, bytes calldata acc, bytes[] calldata cts) external {
        require(todayAccHash == 0 || keccak256(acc) == todayAccHash, "acc");
        bytes memory c = acc;
        uint256 w = CTW;
        for (uint256 j; j < cts.length; ++j) {
            require(keccak256(cts[j]) == todayPendingHash[keccak256(abi.encode(ua, uint64(j)))], "ct");
            bytes calldata x = cts[j];
            assembly ("memory-safe") {
                let cd := add(c, 32)
                for { let i := 0 } lt(i, w) { i := add(i, 1) } {
                    let o := shl(5, i)
                    mstore(add(cd, o), add(mload(add(cd, o)), calldataload(add(x.offset, o))))
                }
            }
        }
        _reduce(c);
        todayAccHash = keccak256(c);
    }

    // ---------------------------------------------------------------- internals

    /// `c += t` lane-wise over `w` words (w a multiple of 4: 516, 708): two pointers, unrolled by four.
    function _addInto(bytes memory c, bytes memory t, uint256 w) private pure {
        assembly ("memory-safe") {
            let p := add(c, 32)
            let q := add(t, 32)
            let e := add(p, shl(5, w))
            for {} lt(p, e) {} {
                mstore(p, add(mload(p), mload(q)))
                mstore(add(p, 32), add(mload(add(p, 32)), mload(add(q, 32))))
                mstore(add(p, 64), add(mload(add(p, 64)), mload(add(q, 64))))
                mstore(add(p, 96), add(mload(add(p, 96)), mload(add(q, 96))))
                p := add(p, 128)
                q := add(q, 128)
            }
        }
    }

    /// Test setup only: `k` op blobs `tmpl` (word 0 xor-ed with `seed + i`, so each is a distinct contract) credited
    /// to `ua` as single-leg ops; the init code is built once and reused (no memory growth per blob).
    function seedOps(bytes32 ua, uint256 k, uint256 seed, bytes calldata tmpl) external {
        bytes memory init = abi.encodePacked(hex"61", uint16(tmpl.length + 1), hex"80600c6000396000f3", hex"00", tmpl);
        Account storage b = acct[ua];
        uint256 w0;
        assembly ("memory-safe") { w0 := mload(add(init, 45)) }
        for (uint256 i; i < k; ++i) {
            address p;
            assembly ("memory-safe") {
                mstore(add(init, 45), xor(w0, shl(192, add(seed, i))))
                p := create(0, add(init, 32), mload(init))
            }
            require(p != address(0), "create");
            uint64 n = b.pendingCount;
            b.pending[n] = _pack(p, 0, 1, 0, uint64(block.number));
            b.pendingCount = n + 1;
        }
    }

    function _pack(address p, uint8 g, uint8 groups, uint8 j, uint64 blk) private pure returns (uint256) {
        return uint256(uint160(p)) << 96 | uint256(g) << 88 | uint256(groups) << 80 | uint256(j) << 72 | blk;
    }

    /// u_g and v_j of a pending slot into `t` (blob = STOP ‖ u_0 … u_{G−1} ‖ v_0 …).
    function _entry(uint256 e, bytes memory t) private view {
        address p = address(uint160(e >> 96));
        uint256 g = (e >> 88) & 0xff;
        uint256 gs = (e >> 80) & 0xff;
        uint256 j = (e >> 72) & 0xff;
        uint256 u = U;
        assembly ("memory-safe") {
            extcodecopy(p, add(t, 32), add(1, mul(g, u)), u)
            extcodecopy(p, add(add(t, 32), u), add(add(1, mul(gs, u)), mul(j, 128)), 128)
        }
    }

    function _loadAcc(bytes32 ua, Account storage a) private view returns (bytes memory c) {
        c = new bytes(32 * CTW);
        if (a.flags & MAT == 0) {
            if (a.accBlob == address(0)) return c; // Trivial(0)
            _entry(_pack(a.accBlob, a.accG, a.accGs, a.accV, 0), c);
            return c;
        }
        uint256 base = _accBase(ua);
        uint256 w = CTW;
        assembly ("memory-safe") {
            let cd := add(c, 32)
            for { let i := 0 } lt(i, w) { i := add(i, 1) } { mstore(add(cd, shl(5, i)), sload(add(base, i))) }
        }
    }

    function _storeAcc(bytes32 ua, Account storage a, bytes memory c) private {
        uint256 base = _accBase(ua);
        uint256 w = CTW;
        assembly ("memory-safe") {
            let cd := add(c, 32)
            for { let i := 0 } lt(i, w) { i := add(i, 1) } { sstore(add(base, i), mload(add(cd, shl(5, i)))) }
        }
        a.accHash = keccak256(c);
        a.flags |= MAT | WRITTEN;
    }

    function _accBase(bytes32 ua) private pure returns (uint256) {
        return uint256(keccak256(abi.encode(ua, "scaas.pqz.acc")));
    }

    function _reduce(bytes memory a) private view {
        uint256 q = Q;
        assembly ("memory-safe") {
            let m := 0xffffffffffffffff
            let d := add(a, 32)
            let n := mload(a)
            for { let i := 0 } lt(i, n) { i := add(i, 32) } {
                let p := add(d, i)
                let x := mload(p)
                mstore(p, or(or(shl(192, mod(shr(192, x), q)), shl(128, mod(and(shr(128, x), m), q))),
                    or(shl(64, mod(and(shr(64, x), m), q)), mod(and(x, m), q))))
            }
        }
    }
}

/// Gas of the proposed layout (execution gas as it counts against the 2^24 transaction cap: cold accesses as in a fresh
/// transaction via `vm.cool`, refunds not subtracted). Run:
///   cd smartcontracts/evm && ../../scripts/capped forge test --match-path test/research/PqzStateGas.t.sol -vv \
///     --gas-limit 60000000000
/// Logs: smartcontracts/evm/runs/2026-10-20-5h-state-gas.txt.
abstract contract PqzGasBase is Test {
    /// @dev The large-`n` series run only with the documented `--gas-limit 60000000000`
    ///      (runs/2026-10-20-5h-state-gas.txt); the default `forge test` skips them instead of failing on `create`.
    function _needsHighGasLimit() internal {
        vm.skip(gasleft() < 10_000_000_000);
    }

    uint256 internal constant Q42 = 4_398_046_510_889; // 2^42 − 215
    uint256 internal constant Q54 = 18_014_398_509_481_657; // 2^54 − 327 (A' candidate)
    uint256 internal constant CAP = 1 << 24;

    PqzStateProto internal pr;
    uint256 internal q;
    uint256 internal nCoef;
    bytes internal tmpl; // one random canonical ciphertext-sized template

    function _setup(uint256 n, uint256 qq) internal {
        nCoef = n;
        q = qq;
        pr = new PqzStateProto(n, qq);
        tmpl = _rand(8 * n + 128, 1);
    }

    function _rand(uint256 len, uint256 seed) internal view returns (bytes memory b) {
        b = new bytes(len);
        uint256 qq = q;
        for (uint256 o; o < len; o += 32) {
            uint256 h = uint256(keccak256(abi.encode(seed, o)));
            uint256 w;
            for (uint256 k; k < 4; ++k) w |= (((h >> (64 * k)) & 0xffffffffffffffff) % qq) << (64 * (3 - k));
            assembly ("memory-safe") { mstore(add(add(b, 32), o), w) }
        }
    }

    /// An op blob: G u's, M + 1 v's (legs, v_f), A·M auditor copies, salt and the M recipient words (bundle data).
    function _blob(uint256 g, uint256 m, uint256 aud, uint256 seed) internal view returns (bytes memory b) {
        uint256 u = 8 * nCoef;
        b = new bytes(g * u + 128 * (m + 1 + aud * m) + 16 + 32 * m);
        bytes memory t = tmpl;
        for (uint256 i; i < g; ++i) {
            assembly ("memory-safe") { mcopy(add(add(b, 32), mul(i, u)), add(t, 32), u) }
        }
        for (uint256 i; i < m + 1 + aud * m; ++i) {
            assembly ("memory-safe") { mcopy(add(add(b, 32), add(mul(g, u), mul(i, 128))), add(add(t, 32), u), 128) }
        }
        assembly ("memory-safe") { mstore(add(b, 32), xor(mload(add(b, 32)), shl(192, seed))) } // distinct, < q
    }

    function _measure(address target, bytes memory data) internal returns (uint256 used) {
        vm.cool(target);
        uint256 g0 = gasleft();
        (bool ok,) = target.call(data);
        used = g0 - gasleft();
        require(ok, "call failed");
    }

    function _coolPending(bytes32 ua, uint64 from, uint64 to) internal {
        for (uint64 i = from; i < to; ++i) {
            bytes32 slot = keccak256(abi.encode(uint256(i), uint256(keccak256(abi.encode(ua, uint256(0)))) + 3));
            uint256 e = uint256(vm.load(address(pr), slot));
            if (e != 0) vm.cool(address(uint160(e >> 96)));
        }
    }

    /// Calldata cost of `b`: standard (4 / 16 per byte) and the EIP-7623 floor (10 per token, token = zero byte 1,
    /// non-zero 4).
    function _calldata(bytes memory b) internal pure returns (uint256 std, uint256 floor) {
        for (uint256 i; i < b.length; ++i) {
            if (b[i] == 0) { std += 4; floor += 10; }
            else { std += 16; floor += 40; }
        }
    }

    // ---------------------------------------------------------------- per-op writes

    function _opWrites(string memory tag, uint256 g, uint256 m, uint256 aud, bool sender) internal {
        bytes memory b = _blob(g, m, aud, 7);
        bytes32[] memory to = new bytes32[](m);
        for (uint256 j; j < m; ++j) to[j] = keccak256(abi.encode("to", j));
        uint256 gas = _measure(address(pr), abi.encodeCall(pr.writeOp, (b, uint8(g), to, sender ? bytes32("from") : bytes32(0))));
        console2.log(string.concat(tag, " blob bytes / gas (blob + M credits + sender acc ref)"), b.length, gas);
    }

    function _writes(uint256 n, uint256 qq) internal {
        _setup(n, qq);
        console2.log("== op writes, n =", n);
        _opWrites("op1 auditor on  (G1 M1 A)", 1, 1, 1, true);
        _opWrites("op1 auditor off (G1 M1)  ", 1, 1, 0, true);
        _opWrites("op7 M2 A                  ", 1, 2, 1, true);
        _opWrites("op7 M4 A                  ", 1, 4, 1, true);
        _opWrites("op7 M8 A                  ", 2, 8, 1, true);
        _opWrites("op7 M8                    ", 2, 8, 0, true);
        _opWrites("burn/refresh (u', v_f)    ", 1, 0, 0, true);
        // per-credit slot alone (fresh slot, zero -> non-zero)
        address p = SSTORE2.write(_blob(1, 1, 0, 9));
        uint256 c1 = _measure(address(pr), abi.encodeCall(pr.credit, (bytes32("solo"), p, 0, 1, 0)));
        console2.log("one pending slot (credit), first entry of an account", c1);
        uint256 c2 = _measure(address(pr), abi.encodeCall(pr.credit, (bytes32("solo"), p, 0, 1, 0)));
        console2.log("one pending slot (credit), next entry", c2);
        // SSTORE2 alone, per size
        for (uint256 s = 4096; s <= 49_152; s += 4096) {
            bytes memory d = new bytes(s);
            d[0] = 0x01;
            uint256 g0 = gasleft();
            SSTORE2.write(d);
            console2.log("SSTORE2.write bytes / gas", s, g0 - gasleft());
        }
    }

    // ---------------------------------------------------------------- rollover

    /// `k` pending credits for `ua`, each from its own op blob (distinct, cold accounts), all old enough to roll.
    function _fill(bytes32 ua, uint256 k, uint256 seed) internal {
        bytes memory b = _blob(1, 1, 0, 0);
        for (uint256 i; i < k; i += 32) pr.seedOps(ua, k - i < 32 ? k - i : 32, seed + i, b);
        vm.roll(block.number + 100);
    }

    function _roll(bytes32 ua, uint256 n) internal returns (uint256 gas) {
        (, uint64 r,,,,) = pr.state(ua);
        _coolPending(ua, r, r + uint64(n));
        gas = _measure(address(pr), abi.encodeCall(pr.rollOver, (ua, n)));
    }

    function _rollSeries(uint256 n, uint256 qq, uint256[] memory sizes) internal {
        _setup(n, qq);
        console2.log("== rollover, n =", n);
        uint256 total;
        for (uint256 i; i < sizes.length; ++i) total += sizes[i];
        // first: the acc slots never written (zero -> non-zero)
        bytes32 ua = "first";
        _fill(ua, total, 1000);
        for (uint256 i; i < sizes.length; ++i) {
            uint256 gas = _roll(ua, sizes[i]);
            console2.log(i == 0 ? "first rollover (acc slots zero) n / gas" : "steady rollover (acc materialised) n / gas",
                sizes[i], gas);
        }
        // after a debit: acc = fresh blob reference, the acc slots still non-zero
        (uint64 pc,,,,,) = pr.state(ua);
        address p = SSTORE2.write(_blob(1, 0, 0, 77));
        pr.debitEffects(ua, p, 1, 0, pc);
        _fill(ua, sizes[sizes.length - 1], 50_000);
        uint256 gas2 = _roll(ua, sizes[sizes.length - 1]);
        console2.log("rollover after a debit (fresh acc, slots non-zero) n / gas", sizes[sizes.length - 1], gas2);
    }

    /// big-endian uint16 list -> uint256[]
    function _arr(bytes memory b) internal pure returns (uint256[] memory a) {
        a = new uint256[](b.length / 2);
        for (uint256 i; i < a.length; ++i) a[i] = uint256(uint8(b[2 * i])) << 8 | uint8(b[2 * i + 1]);
    }

    // ---------------------------------------------------------------- the debit's read and write

    function _debitSeries(uint256 n, uint256 qq) internal {
        _setup(n, qq);
        console2.log("== debit read (T) and effects, n =", n);
        bytes32 ua = "deb";
        _fill(ua, 40, 3000);
        // fresh acc (after a debit), 0 and 16 inline
        address p = SSTORE2.write(_blob(1, 0, 0, 5));
        pr.debitEffects(ua, p, 1, 0, 0);
        vm.cool(p);
        console2.log("T, acc fresh (blob), inline 0", _measure(address(pr), abi.encodeCall(pr.total, (ua, 0, ""))));
        _coolPending(ua, 0, 16);
        vm.cool(p);
        console2.log("T, acc fresh (blob), inline 16", _measure(address(pr), abi.encodeCall(pr.total, (ua, 16, ""))));
        // materialised acc: roll 24, then T from slots vs from the calldata hint
        pr.rollOver(ua, 24);
        bytes memory accB = pr.accOf(ua);
        console2.log("T, acc materialised, from slots, inline 0",
            _measure(address(pr), abi.encodeCall(pr.total, (ua, 24, ""))));
        console2.log("T, acc materialised, calldata hint, inline 0",
            _measure(address(pr), abi.encodeCall(pr.total, (ua, 24, accB))));
        (uint256 std, uint256 fl) = _calldata(accB);
        console2.log("  hint calldata: standard / EIP-7623 floor", std, fl);
        _coolPending(ua, 24, 40);
        console2.log("T, acc materialised, calldata hint, inline 16",
            _measure(address(pr), abi.encodeCall(pr.total, (ua, 40, accB))));
        // effects: fresh reference, rolled = floor = p, consumed slots deleted (16 + 16)
        address p2 = SSTORE2.write(_blob(1, 0, 0, 6));
        console2.log("debit effects (acc ref, counters, 32 slots deleted)",
            _measure(address(pr), abi.encodeCall(pr.debitEffects, (ua, p2, 1, 0, 40))));
    }
}

/// The measurements (one transaction per test; see the note on PqzStateSteadyGasTest for slots rewritten twice).
contract PqzStateGasTest is PqzGasBase {
    function test_opWrites_n2048() public { _writes(2048, Q42); }
    function test_opWrites_n2816() public { _writes(2816, Q54); }

    function test_rollover_n2048() public {
        _needsHighGasLimit();
        _rollSeries(2048, Q42, _arr(hex"0020_0001_0010_0040_0080_0100_0180_01c0_0200"));
    }

    function test_rollover_n2816() public {
        _needsHighGasLimit();
        _rollSeries(2816, Q54, _arr(hex"0010_0001_0010_0040_0080_0100_0140_0180"));
    }

    function test_debit_n2048() public { _debitSeries(2048, Q42); }
    function test_debit_n2816() public { _debitSeries(2816, Q54); }

    // ---------------------------------------------------------------- today's layout (calldata), n = 2048

    function test_today_n2048() public {
        _setup(2048, Q42);
        console2.log("== today's layout (ciphertexts in calldata, hashes in storage), n = 2048");
        bytes32 ua = "today";
        bytes memory ct = tmpl;
        for (uint256 k = 1; k <= 16; k *= 4) {
            bytes[] memory cts = new bytes[](k);
            for (uint64 j; j < k; ++j) {
                cts[j] = ct;
                pr.todayCredit(ua, j, ct);
            }
            pr.todaySetAcc(keccak256(ct));
            bytes memory data = abi.encodeCall(pr.todayRollOver, (ua, ct, cts));
            uint256 gas = _measure(address(pr), data);
            (uint256 std, uint256 fl) = _calldata(data);
            console2.log("today rollover k / execution gas", k, gas);
            console2.log("  calldata standard / EIP-7623 floor (+21,000 intrinsic)", std, fl);
        }
        console2.log("today credit (keccak 16,512 B + one slot)",
            _measure(address(pr), abi.encodeCall(pr.todayCredit, (bytes32("t2"), 0, ct))));
        (uint256 s1, uint256 f1) = _calldata(ct);
        console2.log("one ciphertext in calldata: standard / floor", s1, f1);
    }

    // ---------------------------------------------------------------- arithmetic check (the one runnable check)

    /// acc' = acc + Σ entries mod q, lane by lane, against a direct computation on the first and last word.
    function test_rollSumIsExact() public {
        _setup(2048, Q42);
        bytes32 ua = "exact";
        _fill(ua, 5, 9000);
        pr.rollOver(ua, 5);
        bytes memory got = pr.accOf(ua);
        uint256 u = 8 * nCoef;
        for (uint256 o = 0; o <= u; o += u) {
            uint256 want;
            for (uint256 lane; lane < 4; ++lane) {
                uint256 s;
                for (uint256 i; i < 5; ++i) {
                    bytes memory bi = _blob(1, 1, 0, 9000 + i);
                    uint256 x;
                    assembly ("memory-safe") { x := mload(add(add(bi, 32), o)) }
                    s += (x >> (64 * (3 - lane))) & 0xffffffffffffffff;
                }
                want |= (s % q) << (64 * (3 - lane));
            }
            uint256 have;
            assembly ("memory-safe") { have := mload(add(add(got, 32), o)) }
            assertEq(have, want, o == 0 ? "u word 0" : "v word 0");
        }
        (, uint64 r,,, uint32 units,) = pr.state(ua);
        assertEq(r, 5);
        assertEq(units, 5);
    }
}

/// Steady-state rollovers measured in their own transaction: forge runs a test as one transaction, so a slot written
/// earlier in the same test is "dirty" and a rewrite costs 100 instead of 2,900. Here `setUp` (a transaction of its
/// own) fills the queue and materialises `acc`; each test then rolls once, so every `acc` word is a true non-zero
/// rewrite (2,100 cold + 2,900) and every deleted pending slot a true non-zero -> 0 (refund not subtracted).
abstract contract SteadyBase is PqzGasBase {
    bytes32 internal constant UA = "steady";

    function _n() internal pure virtual returns (uint256);
    function _q() internal pure virtual returns (uint256);

    function setUp() public {
        _needsHighGasLimit();
        _setup(_n(), _q());
        _fill(UA, 16 + 512, 1000);
        pr.rollOver(UA, 16);
    }

    function _one(uint256 k) internal {
        console2.log("steady rollover (own transaction) n / gas", k, _roll(UA, k));
    }

    function test_steady_1() public { _one(1); }
    function test_steady_64() public { _one(64); }
    function test_steady_128() public { _one(128); }
    function test_steady_256() public { _one(256); }
    function test_steady_320() public { _one(320); }
    function test_steady_384() public { _one(384); }
    function test_steady_448() public { _one(448); }
    function test_steady_512() public { _one(512); }

    /// after a debit: `acc` is the fresh blob reference, the acc slots keep their old (non-zero) words
    function test_steady_afterDebit_384() public {
        address p = SSTORE2.write(_blob(1, 0, 0, 77));
        pr.debitEffects(UA, p, 1, 0, 16);
        console2.log("rollover after a debit (fresh acc, own transaction) n / gas", 384, _roll(UA, 384));
    }
}

contract PqzStateSteadyGasTest2048 is SteadyBase {
    function _n() internal pure override returns (uint256) { return 2048; }
    function _q() internal pure override returns (uint256) { return Q42; }
}

contract PqzStateSteadyGasTest2816 is SteadyBase {
    function _n() internal pure override returns (uint256) { return 2816; }
    function _q() internal pure override returns (uint256) { return Q54; }
}
