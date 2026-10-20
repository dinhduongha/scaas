// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzRegistryBase, PQZ_UID, PQZL_ID} from "./PqzRegistryBase.sol";
import {PqzCtHarness} from "./PqzCtHarness.sol";
import {OpenFactory} from "../../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../../src/metatx/AdminLib.sol";
import {NoUnderlyingPqzToken} from "../../../src/pqz/NoUnderlyingPqzToken.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";
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
    uint256 internal mlf; // multiLegFee (op 7)

    /// the client's view of each account: `acc` and every entry ever appended (TRIVIAL amounts in `triv`)
    mapping(bytes32 => bytes) internal accOf;
    mapping(bytes32 => bytes[]) internal pend;
    mapping(bytes32 => mapping(uint256 => uint256)) internal triv;

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
            withAud ? abi.encode(aud) : bytes(""), SCALE, maxShielded, FEE, dMode, aMode, mlf
        );
    }

    function _newToken(bytes32 s) internal returns (PqzLayer) {
        return PqzLayer(factory.createToken(IOpenFactory.TokenKind.NONE_PQZ, 1, abi.encode(_cfg(uint256(1) << 40)), s));
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

    /// The client's mirror of a TRIVIAL entry the token appended or merged into its tail (D18): `pend` holds "" and
    /// `triv` the amount (16.5 KB of test storage per entry would cost ≈ 11 M gas).
    function _mirrorTrivial(PqzLayer t, bytes32 ua, uint256 amount) internal {
        uint256 n = t.accountState(ua).pendingCount;
        if (n > pend[ua].length) pend[ua].push("");
        triv[ua][n - 1] += amount;
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
        t.pqzShield(ua, amount);
        _mirrorTrivial(t, ua, amount);
    }

    /// A direct transfer at `p = pendingCount` (the client's rule), `shieldIn = 0`, no hint; the client's mirror.
    function _transfer(PqzLayer t, bytes32 from, bytes32 to, bytes32 ben, uint256 seed, bool withAud)
        internal returns (bytes32 ref, bytes memory out)
    {
        out = _out(seed, withAud);
        bytes memory pl = _payloadFor(t, from, to, ben, out);
        ref = t.pqzTransferSingle(pl, "", hex"c0de", _mlAuth());
        _afterDebit(from, _cut(out, 0, PqzCt.PK), _cut(out, PqzCt.CT, PqzCt.V));
        pend[to].push(_cut(out, 0, PqzCt.CT));
        if (ben != 0 && t.confidentialFee() != 0) _mirrorTrivial(t, ben, t.confidentialFee());
    }

    function _payloadFor(PqzLayer t, bytes32 from, bytes32 to, bytes32 ben, bytes memory out)
        internal view returns (bytes memory)
    {
        bytes memory memo = t.disclosureMode() == ZetherTypes.DisclosureMode.COMPACT ? _memo() : bytes("");
        return _payload(t.accountState(from).pendingCount, 0, from, to, ben, out, memo);
    }

    /// The client's `acc` after any debit: `u ‖ v_f` (D4: a debit below `rolled` un-rolls, it keeps nothing).
    function _afterDebit(bytes32 from, bytes memory u, bytes memory vF) internal {
        accOf[from] = bytes.concat(u, vF);
    }

    /// Both halves of the account's `acc` words (D8), once.
    function _prepare(PqzLayer t, bytes32 ua) internal {
        uint8 f = t.accountState(ua).flags;
        if (f & 2 == 0) t.pqzPrepareAcc(ua, 0);
        if (f & 4 == 0) t.pqzPrepareAcc(ua, 1);
    }

    /// Anyone's rollover of up to `n` entries after `ROLL_AGE` blocks; the client's mirror adds what was rolled.
    function _roll(PqzLayer t, bytes32 ua, uint256 n) internal {
        _prepare(t, ua);
        vm.roll(block.number + ROLL_AGE);
        uint256 r = t.accountState(ua).rolled;
        t.pqzRollOver(ua, n);
        accOf[ua] = _sumRange(_acc(ua), ua, r, t.accountState(ua).rolled, 0);
    }

    function _assertConservation(PqzLayer t) internal view {
        assertEq(t.totalSupply() + t.totalShielded() * SCALE, minted, "public + shielded = created");
    }

    /// A direct transfer's `envelopeBinding` word (review W-A).
    function _direct(ZetherTypes.TransferMode m) internal pure returns (bytes32) {
        return keccak256(abi.encode(PqzCore.TAG_DIRECT_MODE, uint8(m)));
    }

    function _cut(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes memory) {
        return _slice(b, off, len);
    }
}
