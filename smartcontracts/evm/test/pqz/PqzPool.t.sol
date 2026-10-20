// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {PqzFixture} from "./helpers/PqzFixture.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzSafety} from "../../src/pqz/PqzSafety.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {UnderlyingPqzToken} from "../../src/pqz/UnderlyingPqzToken.sol";
import {NoUnderlyingPqzToken} from "../../src/pqz/NoUnderlyingPqzToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";

/// Plan 5h Task 3 (D10–D13, D15, D19; owner fee ruling 2026-10-20): `SHIELD_POOL` on the PQZ kinds, txFee to the
/// beneficiary's public balance, free shields, the events (pointers, D12), the views (D13), the relayed mode binding
/// (D15, review L1). The precompile is mocked; the rest is real.
contract PqzPoolTest is PqzFixture {
    uint256 internal constant KEY = 0xA11CE;

    function setUp() public {
        _stack();
        _mockOp(7, 1);
        tok = _newToken("pqz");
    }

    function _pool() internal view returns (uint256) {
        return tok.balanceOf(MetaTxLib.SHIELD_POOL);
    }

    /// The next SSTORE2 blob the token writes.
    function _nextBlob(address t) internal view returns (address) {
        return vm.computeCreateAddress(t, vm.getNonce(t));
    }

    // ------------------------------------------------------------------ D19: the pool, free shields, txFee

    /// A shield (third party too) moves exactly `amount · scale` from the signer to the pool: no fee, nothing burnt.
    function test_shield_toPoolAndFree() public {
        _public(tok, address(this), 30 * SCALE);
        tok.pqzShield(alice, 10);
        tok.pqzShield(bob, 20); // into another account: free (owner ruling 2)
        assertEq(tok.balanceOf(address(this)), 0, "exactly the amounts, no fee");
        assertEq(_pool(), 30 * SCALE);
        assertEq(tok.balanceOfUA(bob), 0, "no fee to the recipient");
        assertEq(tok.totalSupply(), 30 * SCALE, "nothing burnt");
        _assertConservation(tok);
    }

    /// op 1: txFee (`confidentialFee`) out of the pool to the beneficiary's public UA-ledger balance; the burn's too;
    /// the unshield moves `amount · scale` from the pool to the recipient.
    function test_txFee_toBeneficiaryPublicBalance() public {
        _fund(tok, alice, 1000);
        _transfer(tok, alice, bob, carol, 1, true);
        assertEq(tok.balanceOfUA(carol), FEE * SCALE, "op 1 txFee");
        assertEq(tok.pqzAccount(carol).pendingCount, 0, "no TRIVIAL entry");
        assertEq(tok.totalShielded(), 1000 - FEE);
        _assertConservation(tok);
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, carol), _blob(3, PqzCt.CT));
        tok.pqzUnshield(pl, "", 100, address(0xD00D), hex"c0de", _mlAuth());
        assertEq(tok.balanceOf(address(0xD00D)), 100 * SCALE, "from the pool");
        assertEq(tok.balanceOfUA(carol), 2 * FEE * SCALE, "burn txFee");
        assertEq(tok.totalShielded(), 900 - 2 * FEE);
        _assertConservation(tok);
        // no beneficiary: no txFee
        pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, bytes32(0)), _blob(4, PqzCt.CT));
        tok.pqzUnshield(pl, "", 0, address(0), hex"c0de", _mlAuth());
        assertEq(tok.totalShielded(), 900 - 2 * FEE);
        _assertConservation(tok);
    }

    /// The pool is neither a payee nor a spender: an unshield to it (or to `UA_POOL`) is refused, a public transfer
    /// to or from it too.
    function test_pool_neitherPayeeNorSpender() public {
        _fund(tok, alice, 100);
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, bytes32(0)), _blob(3, PqzCt.CT));
        vm.expectRevert(IUALedger.ShieldPoolNotPayable.selector);
        tok.pqzUnshield(pl, "", 10, MetaTxLib.SHIELD_POOL, hex"c0de", _mlAuth());
        vm.expectRevert(IUALedger.UAPoolNotPayable.selector);
        tok.pqzUnshield(pl, "", 10, MetaTxLib.UA_POOL, hex"c0de", _mlAuth());
        vm.expectRevert(IUALedger.ShieldPoolNotPayable.selector);
        tok.burnStatement(pl, 10, MetaTxLib.SHIELD_POOL, 0);
        _public(tok, address(this), 1);
        vm.expectRevert(IUALedger.ShieldPoolNotPayable.selector);
        tok.transfer(MetaTxLib.SHIELD_POOL, 1);
        vm.prank(MetaTxLib.SHIELD_POOL);
        vm.expectRevert(IUALedger.ShieldPoolNotPayable.selector);
        tok.transfer(address(this), 1);
        _assertConservation(tok);
    }

    // ------------------------------------------------------------------ D12: events carry pointers

    function test_events() public {
        _public(tok, address(this), 1000 * SCALE);
        vm.expectEmit(true, true, false, true, address(tok));
        emit IPqzToken.PqzShielded(alice, address(this), 600, 0);
        tok.pqzShield(alice, 600);
        _mirrorTrivial(tok, alice, 600);
        vm.expectEmit(true, true, false, true, address(tok));
        emit IPqzToken.PqzShielded(alice, address(this), 400, 0); // merged into entry 0 (same block)
        tok.pqzShield(alice, 400);
        _mirrorTrivial(tok, alice, 400);

        // op 1: Debited, Credited, Transfer (the op blob, not the bytes)
        bytes memory out = _out(1, true);
        bytes memory pl = _payloadFor(tok, alice, bob, carol, out);
        address blob = _nextBlob(address(tok));
        bytes32 ref = keccak256(abi.encode(keccak256("SCAAS-PQZ-ENTRY-V1"), block.chainid, tok.chainUid(), address(tok),
            alice, uint256(0)));
        vm.expectEmit(true, false, false, true, address(tok));
        emit IPqzToken.PqzDebited(alice, 1, 1, blob);
        vm.expectEmit(true, true, false, true, address(tok));
        emit IPqzToken.PqzCredit(bob, 0, ref);
        vm.expectEmit(true, true, true, true, address(tok));
        emit IPqzToken.PqzTransfer(ref, alice, bob, blob);
        tok.pqzTransferSingle(pl, "", hex"01", _mlAuth());
        _afterDebit(alice, _cut(out, 0, PqzCt.PK), _cut(out, PqzCt.CT, PqzCt.V));
        pend[bob].push(_cut(out, 0, PqzCt.CT));

        // op 7
        bytes32[] memory rec = new bytes32[](2);
        (rec[0], rec[1]) = (bob, carol);
        pl = _mpayload(1, 0, alice, bytes32(0), rec, _blob(2, _outLen(2, true)), "");
        blob = _nextBlob(address(tok));
        ref = keccak256(abi.encode(keccak256("SCAAS-PQZ-ENTRY-V1"), block.chainid, tok.chainUid(), address(tok), alice,
            uint256(1)));
        vm.expectEmit(true, true, false, true, address(tok));
        emit IPqzToken.PqzTransferMulti(ref, alice, keccak256(abi.encodePacked(rec)), 2, blob);
        tok.pqzTransfer(pl, "", hex"01", _mlAuth());

        // burn (refresh: amount 0)
        pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, bytes32(0)), _blob(3, PqzCt.CT));
        blob = _nextBlob(address(tok));
        vm.expectEmit(true, false, false, true, address(tok));
        emit IPqzToken.PqzBurned(alice, 0, address(0), blob);
        tok.pqzUnshield(pl, "", 0, address(0), hex"c0de", _mlAuth());

        // rollover: rolled, accUnits, accHash
        _prepare(tok, bob);
        vm.roll(block.number + ROLL_AGE);
        vm.recordLogs();
        tok.pqzRollOver(bob, 2);
        IPqzToken.AccountState memory a = tok.pqzAccount(bob);
        assertEq(a.accUnits, 2); // bob never debited: 0 + 2
        assertEq(a.accHash, keccak256(tok.pqzAcc(bob)));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs[0].topics[0], IPqzToken.PqzRolled.selector);
        assertEq(logs[0].topics[1], bob);
        assertEq(logs[0].data, abi.encode(uint64(2), uint32(2), a.accHash));
    }

    // ------------------------------------------------------------------ D13: views

    function test_views() public {
        _fund(tok, alice, 100);
        (bytes32 ref, bytes memory out) = _transfer(tok, alice, bob, bytes32(0), 7, true);
        IPqzToken.AccountState memory a = tok.pqzAccount(alice);
        assertEq(a.pendingCount, 1);
        assertEq(a.rolled, 1);
        assertEq(a.floor, 1);
        assertEq(a.cleared, 1);
        assertEq(a.accUnits, 1);
        assertEq(a.flags, 0);
        assertEq(a.sendCounter, 1);
        bytes memory r = bytes.concat(salt, _cut(out, 0, PqzCt.CT), _cut(out, 16_640, 128), bob);
        bytes memory blob = tok.pqzEntryBlob(ref);
        assertEq(blob, bytes.concat(r, _cut(out, PqzCt.CT, PqzCt.V)), "R || v_f");
        assertEq(a.accBlob.code, bytes.concat(hex"00", blob), "the acc reference is the op blob");
        assertEq(tok.transferCiphertextHash(ref), keccak256(r), "ciphertextHash unchanged in value");
        assertEq(tok.pqzEntryBlob(bytes32(0)), "");
        assertEq(tok.minDecoyFee(), 0);
        assertEq(tok.pqzPendingCt(bob, 0), _cut(out, 0, PqzCt.CT));
        assertEq(tok.pqzAcc(alice), accOf[alice]);
    }

    // ------------------------------------------------------------------ D15: the relayed mode binding (review L1)

    function _m(address signer, bytes memory data, uint256 nonce) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m.from = signer;
        m.data = data;
        m.nonce = nonce;
        m.validUntil = block.timestamp + 1 hours;
    }

    /// A relayed transfer's statement binds `keccak256(abi.encode(envelopeBinding, uint8(mode)))`: a proof made for the
    /// envelope's binding in another mode (a `…NoBundle`-style replay of a BUNDLE envelope) is rejected; the folded
    /// one passes.
    function test_relayedModeBound() public {
        bytes memory pl = _payload(0, 0, alice, bob, bytes32(0), _out(5, true), "");
        MetaTxLib.MetaTransaction memory m =
            _m(vm.addr(KEY), abi.encodeCall(PqzLayer.pqzTransferSingle, (pl, bytes(""), hex"c0de", _mlAuth())), 0);
        bytes32 env = tok.envelopeBinding(m);
        bytes memory st = tok.transferSingleStatement(pl, env);
        assertEq(bytes32(_cut(st, 544, 32)), _relayed(env, ZetherTypes.TransferMode.BUNDLE), "mode folded in");
        _mockOp(1, 0);
        _accept(_withBinding(st, _relayed(env, ZetherTypes.TransferMode.NONE))); // a NoBundle-style proof
        _accept(_withBinding(st, env)); // a proof of the pre-D15 binding
        bytes memory sg = _sign(m);
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.mtxExecute(m, sg);
        _accept(st);
        tok.mtxExecute(m, sg);
        assertEq(tok.pqzAccount(alice).sendCounter, 1);
    }

    function _withBinding(bytes memory st, bytes32 b) internal pure returns (bytes memory x) {
        x = bytes.concat(st);
        assembly ("memory-safe") { mstore(add(x, 576), b) }
    }

    /// The mocked precompile accepts this op 1 statement with the proof `c0de`.
    function _accept(bytes memory st) internal {
        vm.mockCall(PQZ, abi.encodePacked(uint8(1), uint32(st.length), st, hex"c0de"), abi.encode(uint256(1)));
    }

    function _sign(MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(KEY, tok.mtxDigest(m));
        return abi.encodePacked(r, s_, v);
    }
}

/// The relayed unwrap binding (D15) and the D19 pool moves of the underlying kind.
contract PqzPoolUnderlyingTest is PqzFixture {
    uint256 internal constant KEY = 0xA11CE;
    MockERC20 internal usd;
    UnderlyingPqzToken internal w;

    function setUp() public {
        _stack();
        _releaseUnderlying();
        w = _newUnderlying("w");
        tok = PqzLayer(address(w));
        usd = MockERC20(w.underlyings()[0]);
    }

    /// wrap-shield mints to the pool, unshield-unwrap burns from it (then the leg pays), its txFee goes to the
    /// beneficiary's public balance; `reserve ≥ totalSupply()`.
    function test_wrapShieldMintsToPool_unwrapBurnsFromPool() public {
        usd.mint(address(this), 1_000 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.pqzWrapShield(address(usd), 1_000 * SCALE, alice);
        assertEq(w.totalSupply(), 1_000 * SCALE, "minted to the pool");
        assertEq(w.balanceOf(MetaTxLib.SHIELD_POOL), 1_000 * SCALE);
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, carol), _blob(3, PqzCt.CT));
        UnderlyingPqzToken.Unwrap memory x = UnderlyingPqzToken.Unwrap(address(usd), address(0xD00D), 400, 0);
        w.pqzUnshieldUnwrap(pl, "", x, hex"c0de", _mlAuth());
        assertEq(usd.balanceOf(address(0xD00D)), 400 * SCALE);
        assertEq(w.totalSupply(), 600 * SCALE, "burnt from the pool");
        assertEq(w.balanceOfUA(carol), FEE * SCALE, "txFee to the beneficiary");
        assertEq(w.balanceOf(MetaTxLib.SHIELD_POOL), w.totalShielded() * SCALE);
        assertGe(usd.balanceOf(address(w)), w.totalSupply(), "reserve >= totalSupply");
        x.recipient = MetaTxLib.SHIELD_POOL;
        vm.expectRevert(IUALedger.ShieldPoolNotPayable.selector);
        w.pqzUnshieldUnwrap(pl, "", x, hex"c0de", _mlAuth());
    }

    /// Relayed: `binding = keccak256(abi.encode(envelopeBinding, unwrapBinding(u, minOut)))` (D15).
    function test_relayedUnwrapBound() public {
        usd.mint(address(this), 100 * SCALE);
        usd.approve(address(w), type(uint256).max);
        w.pqzWrapShield(address(usd), 100 * SCALE, alice);
        bytes memory pl = bytes.concat(abi.encode(uint256(1), block.number + 5, uint256(0), alice, bytes32(0)), _blob(3, PqzCt.CT));
        UnderlyingPqzToken.Unwrap memory x = UnderlyingPqzToken.Unwrap(address(usd), address(0xD00D), 40, 7);
        MetaTxLib.MetaTransaction memory m;
        m.from = vm.addr(KEY);
        m.data = abi.encodeCall(UnderlyingPqzToken.pqzUnshieldUnwrap, (pl, bytes(""), x, hex"c0de", _mlAuth()));
        m.validUntil = block.timestamp + 1 hours;
        bytes32 env = w.envelopeBinding(m);
        bytes32 want = keccak256(abi.encode(env, w.unwrapBinding(address(usd), 7)));
        bytes memory st = w.unshieldUnwrapStatement(pl, x, env);
        assertEq(bytes32(_cut(st, 544, 32)), want, "envelope and leg / minOut folded");
        _mockOp(2, 0);
        vm.mockCall(PQZ, abi.encodePacked(uint8(2), uint32(st.length), st, hex"c0de"), abi.encode(uint256(1)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(KEY, w.mtxDigest(m));
        w.mtxExecute(m, abi.encodePacked(r, s, v));
        assertEq(usd.balanceOf(address(0xD00D)), 40 * SCALE);
    }
}

/// The D19 invariant on PQZ (Review Focus 10): `totalSupply()` moves only with wraps / unwraps (never with a shield,
/// unshield or fee), `balanceOf(SHIELD_POOL) == totalShielded · shieldScale`, `Σ balanceOf == totalSupply`, the leg's
/// reserve `≥ totalSupply()`, every fee in a public UA balance. Handler: shield, wrap-shield, op 1 with txFee and
/// `shieldIn`, op 7 with `decoyFee`, unshield, unshield-unwrap (the mocked precompile accepts every proof; amounts are
/// bounded by `totalShielded` so the pool never goes short).
contract PqzPoolHandler is Test {
    UnderlyingPqzToken internal w;
    MockERC20 internal usd;
    bytes32[] internal uas; // alice (the sender), bob, carol, xs
    bytes internal auth;
    uint256 internal constant SCALE = 10_000;
    uint256 internal seed;
    uint256 public supply; // ghost totalSupply: + wraps, − unwraps
    uint256 public fees; // ghost Σ fees paid to UAs
    address public constant PAYEE = address(0xD00D);

    constructor(UnderlyingPqzToken w_, bytes32[] memory uas_, bytes memory auth_) {
        (w, uas, auth) = (w_, uas_, auth_);
        usd = MockERC20(w.underlyings()[0]);
        usd.approve(address(w), type(uint256).max);
    }

    function uaCount() external view returns (uint256) {
        return uas.length;
    }

    function uaAt(uint256 i) external view returns (bytes32) {
        return uas[i];
    }

    function _blob(uint256 n) internal returns (bytes memory b) {
        uint256 s = ++seed;
        b = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            uint256 x = uint256(keccak256(abi.encode(s, i))) & 0x000000ffffffffff000000ffffffffff000000ffffffffff000000ffffffffff;
            assembly ("memory-safe") { mstore(add(add(b, 32), i), x) }
        }
    }

    function _p() internal view returns (uint256) {
        return w.pqzAccount(uas[0]).rolled; // always a legal cut with an empty window
    }

    function _ben(uint256 sel) internal view returns (bytes32) {
        return sel % 3 == 0 ? bytes32(0) : uas[2];
    }

    function _fee(bytes32 ben) internal view returns (uint256) {
        return ben == 0 ? 0 : w.confidentialFee();
    }

    function wrapPublic(uint256 a) external {
        a = bound(a, 1, 1000) * SCALE;
        usd.mint(address(this), a);
        w.wrap(address(usd), a);
        supply += a;
    }

    function shield(uint256 a, uint256 to) external {
        uint256 have = w.balanceOf(address(this)) / SCALE;
        if (have == 0) return;
        w.pqzShield(uas[to % uas.length], bound(a, 1, have));
    }

    function wrapShield(uint256 a, uint256 to) external {
        a = bound(a, 1, 1000) * SCALE;
        usd.mint(address(this), a);
        w.pqzWrapShield(address(usd), a, uas[to % uas.length]);
        supply += a;
    }

    /// op 1 with a txFee and a `shieldIn` top-up from the handler's public balance.
    function transfer(uint256 sel, uint256 top) external {
        bytes32 ben = _ben(sel);
        top = bound(top, 0, w.balanceOf(address(this)) / SCALE);
        if (w.totalShielded() + top < _fee(ben)) return;
        bytes memory pl = bytes.concat(abi.encode(_p(), block.number + 100, top, uas[0], uas[1], ben),
            bytes16(uint128(seed)), _blob(16_640));
        w.pqzTransferSingle(pl, "", hex"c0de", auth);
        fees += _fee(ben);
    }

    /// op 7, M = 4, `decoyFee` d ≥ minDecoyFee to every leg.
    function multi(uint256 sel, uint256 d) external {
        bytes32 ben = _ben(sel);
        d = bound(d, w.minDecoyFee(), 50);
        uint256 total = _fee(ben) + 4 * d;
        if (w.totalShielded() < total) return;
        bytes memory legs = abi.encodePacked(uas[1], uas[2], uas[3], uas[4]);
        bytes memory pl = bytes.concat(abi.encode(_p(), block.number + 100, uint256(0), uas[0], ben, uint256(4), d),
            bytes16(uint128(seed)), legs, _blob(16_384 + 128 * 5));
        w.pqzTransfer(pl, "", hex"c0de", auth);
        fees += total;
    }

    function unshield(uint256 sel, uint256 a) external {
        bytes32 ben = _ben(sel);
        uint256 f = _fee(ben);
        if (w.totalShielded() <= f) return;
        a = bound(a, 1, w.totalShielded() - f);
        bytes memory pl = bytes.concat(abi.encode(_p(), block.number + 100, uint256(0), uas[0], ben), _blob(16_512));
        w.pqzUnshield(pl, "", a, PAYEE, hex"c0de", auth);
        fees += f;
    }

    function unshieldUnwrap(uint256 sel, uint256 a) external {
        bytes32 ben = _ben(sel);
        uint256 f = _fee(ben);
        if (w.totalShielded() <= f) return;
        a = bound(a, 1, w.totalShielded() - f);
        bytes memory pl = bytes.concat(abi.encode(_p(), block.number + 100, uint256(0), uas[0], ben), _blob(16_512));
        w.pqzUnshieldUnwrap(pl, "", UnderlyingPqzToken.Unwrap(address(usd), PAYEE, a, 0), hex"c0de", auth);
        fees += f;
        supply -= a * SCALE;
    }
}

contract PqzPoolInvariantTest is PqzFixture {
    PqzPoolHandler internal h;
    UnderlyingPqzToken internal w;

    function setUp() public {
        _stack();
        _mockOp(7, 1);
        _releaseUnderlying();
        minDecoy = 1;
        w = _newUnderlying("inv");
        tok = PqzLayer(address(w));
        bytes32[] memory u = new bytes32[](5);
        (u[0], u[1], u[2]) = (alice, bob, carol);
        u[3] = _pqzUA(_pk(40), 40);
        u[4] = _pqzUA(_pk(41), 41);
        h = new PqzPoolHandler(w, u, _mlAuth());
        targetContract(address(h));
    }

    /// forge-config: default.invariant.runs = 16
    /// forge-config: default.invariant.depth = 24
    function invariant_shieldPool() public view {
        assertEq(w.totalSupply(), h.supply(), "totalSupply moves only with wraps / unwraps");
        assertEq(w.balanceOf(MetaTxLib.SHIELD_POOL), w.totalShielded() * SCALE, "pool = totalShielded * scale");
        uint256 ua;
        for (uint256 i; i < h.uaCount(); ++i) ua += w.balanceOfUA(h.uaAt(i));
        assertEq(ua, h.fees() * SCALE, "every fee in a public UA balance");
        assertEq(w.balanceOf(MetaTxLib.UA_POOL), ua, "UA_POOL = sum of the UA balances");
        assertEq(w.balanceOf(address(h)) + w.balanceOf(h.PAYEE()) + w.balanceOf(MetaTxLib.SHIELD_POOL)
            + w.balanceOf(MetaTxLib.UA_POOL), w.totalSupply(), "sum of balances = totalSupply");
        assertGe(MockERC20(w.underlyings()[0]).balanceOf(address(w)), w.totalSupply(), "reserve >= totalSupply");
    }
}
