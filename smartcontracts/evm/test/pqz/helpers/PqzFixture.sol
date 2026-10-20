// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzRegistryBase, PQZ_UID, PQZL_ID} from "./PqzRegistryBase.sol";
import {PqzCtHarness} from "./PqzCtHarness.sol";
import {OpenFactory} from "../../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../../src/metatx/AdminLib.sol";
import {NoUnderlyingPqzToken} from "../../../src/pqz/NoUnderlyingPqzToken.sol";
import {UnderlyingPqzToken} from "../../../src/pqz/UnderlyingPqzToken.sol";
import {MockERC20} from "../../helpers/Mocks.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {Catalogue, pqzEnv} from "../../helpers/Catalogue.sol";

/// @notice The PQZ token stack of chain 7622 in forge (P6g plan D6): the gen-1 registry (`PqzRegistryBase`), `OpenFactory`
///         with the PQZ gate on, `NoUnderlyingPqzToken` clones. The `PQZ` precompile answers 1 for ops 1, 2, 4, 5 unless
///         a test changes it; everything else is real. The test is the client: it mirrors each account's `acc` and
///         entries (arbitrary canonical bytes; the proofs are mocked; the token reads both from its own state, plan 5h) and the alice / bob / auditor keys of
///         `statement_transfer.json`, so a transfer can rebuild the vector's statement body.
abstract contract PqzFixture is PqzRegistryBase {
    OpenFactory internal factory;
    NoUnderlyingPqzToken internal noneImpl;
    PqzLayer internal tok;
    PqzCtHarness internal ct;
    address internal registrar = address(0xF00D);
    uint256 internal constant SCALE = 10_000;
    uint256 internal constant FEE = 3;
    bytes internal txStmt; // statement_transfer.json row 0 (R_TX)

    bytes32 internal alice;
    bytes32 internal bob;
    bytes32 internal carol;
    bytes32 internal aud;

    uint8 internal dMode; // BUNDLE
    uint8 internal aMode = uint8(ZetherTypes.AuditorMode.OPTIONAL);
    bytes16 internal salt = bytes16(uint128(0x5A17));
    uint256 internal minted;
    uint256 internal minDecoy; // the token's `minDecoyFee` (op 7)
    uint256 internal decoy; // the sender's per-leg `decoyFee` in an op 7 payload

    /// the client's view of each account: `acc` and every entry ever appended (TRIVIAL amounts in `triv`)
    mapping(bytes32 => bytes) internal accOf;
    mapping(bytes32 => bytes[]) internal pend;
    mapping(bytes32 => mapping(uint256 => uint256)) internal triv;
    mapping(bytes32 => mapping(uint256 => uint256)) internal trivBlk; // the block a TRIVIAL entry was appended in
    mapping(bytes32 => uint256) internal feeIn; // fees paid to a UA's public balance, in shielded units

    function _stack() internal virtual {
        _registryStack();
        ct = new PqzCtHarness();
        factory = new OpenFactory(registrar, PQZ_UID, 0);
        // plan 5g-Z2: the PQZL release, its verifier the env's (CTR-ZTH-20)
        noneImpl = NoUnderlyingPqzToken(Catalogue.release(factory, IOpenFactory.TokenKind.NONE_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(NoUnderlyingPqzToken).creationCode));
        vm.startPrank(registrar);
        factory.setKindEnabled(IOpenFactory.TokenKind.NONE_PQZ, true);
        factory.setKindEnabled(IOpenFactory.TokenKind.UNDERLYING_PQZ, true);
        vm.stopPrank();
        for (uint8 op = 1; op <= 5; ++op) if (op != 3) _mockOp(op, 1);
        txStmt = _vecHex("statement_transfer.json", ".rows[0].stmt");
        vm.mockCall(PQZ, abi.encodePacked(uint8(3)), abi.encode(uint256(1))); // PoPs of the fixture's keys
        alice = _pqzUA(_slice(txStmt, 640, PqzCt.PK), 1);
        bob = _pqzUA(_slice(txStmt, 17_024, PqzCt.PK), 2);
        aud = _pqzUA(_slice(txStmt, 33_408, PqzCt.PK), 3);
        carol = _pqzUA(_pk(7), 4);
    }

    function _cfg(uint256 maxShielded) internal view virtual returns (IFactoryToken.TokenConfig memory c) {
        c.name = "PQZ USD";
        c.symbol = "pqUSD";
        c.decimals = 6;
        c.features = (1 << AdminLib.PAYABLE) | (1 << AdminLib.MINTABLE) | (1 << AdminLib.BURNABLE);
        c.roles.minter = address(this);
        bool withAud = aMode != uint8(ZetherTypes.AuditorMode.NONE);
        c.conf = IFactoryToken.ConfidentialConfig(
            withAud ? abi.encode(aud) : bytes(""), SCALE, maxShielded, FEE, dMode, aMode, minDecoy
        );
    }

    function _newToken(bytes32 s) internal returns (PqzLayer) {
        return PqzLayer(factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(_cfg(uint256(1) << 40)), s));
    }

    function _releaseUnderlying() internal {
        Catalogue.release(factory, IOpenFactory.TokenKind.UNDERLYING_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(UnderlyingPqzToken).creationCode);
    }

    /// An `UNDERLYING_PQZ` token with one 1:1 `MockERC20` leg (after `_releaseUnderlying`).
    function _newUnderlying(bytes32 s) internal returns (UnderlyingPqzToken) {
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = (1 << AdminLib.PAYABLE);
        c.roles.minter = address(0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
        return UnderlyingPqzToken(payable(factory.createToken(IOpenFactory.TokenKind.UNDERLYING_PQZ, 1, abi.encode(c), s)));
    }

    // ------------------------------------------------------------------ ciphertexts

    /// A canonical 16,384-byte key: zero but coefficient 0 = `seed`.
    function _pk(uint8 seed) internal pure returns (bytes memory k) {
        k = new bytes(PqzCt.PK);
        k[7] = bytes1(seed);
    }

    /// `n` canonical bytes from `seed` (every 64-bit lane < 2^40 < q).
    function _blob(uint256 seed, uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            uint256 w = uint256(keccak256(abi.encode(seed, i))) & 0x000000ffffffffff000000ffffffffff000000ffffffffff000000ffffffffff;
            assembly ("memory-safe") { mstore(add(add(b, 32), i), w) }
        }
    }

    /// `out = u ‖ v_t ‖ v_f ‖ [v_a]`.
    function _out(uint256 seed, bool withAud) internal pure returns (bytes memory) {
        return _blob(seed, withAud ? 16_768 : 16_640);
    }

    function _payload(uint256 p, uint256 shieldIn, bytes32 from, bytes32 to, bytes32 ben, bytes memory out,
        bytes memory memo) internal view returns (bytes memory)
    {
        return bytes.concat(abi.encode(p, block.number + 100, shieldIn, from, to, ben), salt, out, memo);
    }

    /// Op 7: `p ‖ validUntilBlock ‖ shieldIn ‖ fromUA ‖ beneficiaryUA ‖ M ‖ decoyFee ‖ salt(16) ‖ UA_0 … UA_{M−1} ‖ out ‖
    /// [memo]` (`decoyFee` the sender's per-leg fee, owner 2026-10-20).
    function _mpayload(uint256 p, uint256 shieldIn, bytes32 from, bytes32 ben, bytes32[] memory rec, bytes memory out,
        bytes memory memo) internal view returns (bytes memory)
    {
        bytes memory r;
        for (uint256 j; j < rec.length; ++j) r = bytes.concat(r, rec[j]);
        return bytes.concat(abi.encode(p, block.number + 100, shieldIn, from, ben, rec.length, decoy), salt, r, out, memo);
    }

    function _outLen(uint256 m, bool withAud) internal pure returns (uint256) {
        return PqzCt.PK * ((m + 3) / 4) + PqzCt.V * (m + 1) + (withAud ? PqzCt.V * m : 0);
    }

    function _memo() internal view returns (bytes memory) {
        return bytes.concat(salt, _slice(_blob(0x3e30, 64), 0, 41));
    }

    // ------------------------------------------------------------------ the client

    uint256 internal constant ROLL_AGE = 5; // PqzCore.ROLL_AGE (owner 2026-10-20)

    /// The client's `acc`: the last debit's `(u, v_f)` plus every entry rolled since (D4).
    function _acc(bytes32 ua) internal view returns (bytes memory a) {
        a = accOf[ua];
        if (a.length == 0) a = new bytes(PqzCt.CT);
    }

    /// `Trivial(digits(amount))` as a ciphertext (u = 0).
    function _trivCt(uint256 amount) internal view returns (bytes memory) {
        return ct.sum(new bytes(PqzCt.CT), new bytes[](0), new bytes[](0), amount);
    }

    /// The client's mirror of a TRIVIAL entry (D18), the merge rule computed here, not read from the token: merge into
    /// the tail when it is TRIVIAL, of this block and at an index `≥ max(floor, rolled)`, else append; the token must
    /// agree. `pend` holds "" and `triv` the amount (16.5 KB of test storage per entry would cost ≈ 11 M gas).
    function _mirrorTrivial(PqzLayer t, bytes32 ua, uint256 amount) internal {
        IPqzToken.AccountState memory a = t.pqzAccount(ua);
        uint256 n = pend[ua].length;
        uint256 lo = a.floor > a.rolled ? a.floor : a.rolled;
        if (n != 0 && pend[ua][n - 1].length == 0 && trivBlk[ua][n - 1] == block.number && n - 1 >= lo) {
            triv[ua][n - 1] += amount;
        } else {
            pend[ua].push("");
            (triv[ua][n], trivBlk[ua][n]) = (amount, block.number);
        }
        assertEq(a.pendingCount, pend[ua].length, "mirror: merge / append");
    }

    /// Entry `i` as a ciphertext (a TRIVIAL one rebuilt from its amount).
    function _entCt(bytes32 ua, uint256 i) internal view returns (bytes memory) {
        bytes memory c = pend[ua][i];
        return c.length != 0 ? c : _trivCt(triv[ua][i]);
    }

    /// Entries `[lo, hi)` as ciphertexts.
    function _range(bytes32 ua, uint256 lo, uint256 hi) internal view returns (bytes[] memory xs) {
        xs = new bytes[](hi - lo);
        for (uint256 i; i < xs.length; ++i) xs[i] = _entCt(ua, lo + i);
    }

    /// `base + Σ entries [lo, hi) + Trivial(digits(plain))`, each TRIVIAL entry its own `Trivial(digits(amount))`.
    function _sumRange(bytes memory base, bytes32 ua, uint256 lo, uint256 hi, uint256 plain)
        internal view returns (bytes memory)
    {
        uint256 nc;
        for (uint256 i = lo; i < hi; ++i) if (pend[ua][i].length != 0) ++nc;
        bytes[] memory cs = new bytes[](nc);
        uint256[] memory am = new uint256[](hi - lo - nc + 1);
        (uint256 k, uint256 m) = (0, 0);
        for (uint256 i = lo; i < hi; ++i) {
            if (pend[ua][i].length != 0) cs[k++] = pend[ua][i];
            else am[m++] = triv[ua][i];
        }
        am[m] = plain;
        return ct.sumMixed(base, cs, am);
    }

    function _public(PqzLayer t, address to, uint256 units) internal {
        NoUnderlyingPqzToken(address(t)).mint(to, units);
        minted += units;
    }

    /// Shield `amount` from the test's public balance (a TRIVIAL entry, D18).
    function _fund(PqzLayer t, bytes32 ua, uint256 amount) internal {
        _public(t, address(this), amount * SCALE);
        t.mtxShield(ua, amount);
        _mirrorTrivial(t, ua, amount);
    }

    /// A direct transfer at `p = pendingCount` (the client's rule), `shieldIn = 0`, no hint; the client's mirror.
    function _transfer(PqzLayer t, bytes32 from, bytes32 to, bytes32 ben, uint256 seed, bool withAud)
        internal returns (bytes32 ref, bytes memory out)
    {
        out = _out(seed, withAud);
        bytes memory pl = _payloadFor(t, from, to, ben, out);
        ref = t.mtxConfidentialTransferSingle(pl, hex"c0de", _mlAuth(), _benT(pl), "");
        _afterDebit(from, _cut(out, 0, PqzCt.PK), _cut(out, PqzCt.CT, PqzCt.V));
        pend[to].push(_cut(out, 0, PqzCt.CT));
        if (ben != 0) feeIn[ben] += t.confidentialFee(); // txFee: the beneficiary's public balance (D19)
    }

    function _payloadFor(PqzLayer t, bytes32 from, bytes32 to, bytes32 ben, bytes memory out)
        internal view returns (bytes memory)
    {
        bytes memory memo = t.disclosureMode() == ZetherTypes.DisclosureMode.COMPACT ? _memo() : bytes("");
        return _payload(t.pqzAccount(from).pendingCount, 0, from, to, ben, out, memo);
    }

    /// The client's `acc` after any debit: `u ‖ v_f` (D4: a debit below `rolled` un-rolls, it keeps nothing).
    function _afterDebit(bytes32 from, bytes memory u, bytes memory vF) internal {
        accOf[from] = bytes.concat(u, vF);
    }

    /// Both halves of the account's `acc` words (D8), once.
    function _prepare(PqzLayer t, bytes32 ua) internal {
        uint8 f = t.pqzAccount(ua).flags;
        if (f & 2 == 0) t.mtxPrepareAcc(ua, 0);
        if (f & 4 == 0) t.mtxPrepareAcc(ua, 1);
    }

    /// Anyone's rollover of up to `n` entries after `ROLL_AGE` blocks; the client's mirror adds what was rolled.
    function _roll(PqzLayer t, bytes32 ua, uint256 n) internal {
        _prepare(t, ua);
        vm.roll(block.number + ROLL_AGE);
        uint256 r = t.pqzAccount(ua).rolled;
        t.mtxRollOver(ua, n);
        accOf[ua] = _sumRange(_acc(ua), ua, r, t.pqzAccount(ua).rolled, 0);
    }

    /// D19: shields, unshields and fees move public units to / from `SHIELD_POOL`; nothing is minted or burnt.
    function _assertConservation(PqzLayer t) internal view {
        assertEq(t.totalSupply(), minted, "totalSupply = created");
        assertEq(t.balanceOf(MetaTxLib.SHIELD_POOL), t.totalShielded() * SCALE, "pool = totalShielded * scale");
    }

    /// A direct transfer's `envelopeBinding` word (review W-A).
    function _direct(ZetherTypes.TransferMode m) internal pure returns (bytes32) {
        return keccak256(abi.encode(PqzCore.TAG_DIRECT_MODE, uint8(m)));
    }

    /// A relayed transfer's binding word: the envelope's with the mode folded in (plan 5h D15, review L1).
    function _relayed(bytes32 envelope, ZetherTypes.TransferMode m) internal pure returns (bytes32) {
        return keccak256(abi.encode(envelope, uint8(m)));
    }

    function _cut(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes memory) {
        return _slice(b, off, len);
    }

    /// @dev The shared `beneficiary` argument (plan 5h D20): the payload's beneficiary word, op 7 / burn at 128, op 1 at
    ///      160; 0 for a payload too short to hold it (the library's `BadPayload` then).
    function _benM(bytes memory pl) internal pure returns (bytes32) {
        return _word(pl, 128);
    }

    function _benT(bytes memory pl) internal pure returns (bytes32) {
        return _word(pl, 160);
    }

    function _word(bytes memory pl, uint256 off) internal pure returns (bytes32 w) {
        if (pl.length < off + 32) return 0;
        assembly ("memory-safe") { w := mload(add(add(pl, 32), off)) }
    }
}
