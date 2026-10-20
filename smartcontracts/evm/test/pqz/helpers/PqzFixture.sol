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
///         a test changes it; everything else is real. The test is the client: it keeps each account's `acc` and pending
///         ciphertexts (arbitrary canonical bytes; the proofs are mocked) and the alice / bob / auditor keys of
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

    /// the client's view of each account (on the token: hashes only)
    mapping(bytes32 => bytes) internal accOf;
    mapping(bytes32 => bytes[]) internal pend;

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

    function _payload(uint256 p, uint256 plainUsed, bytes32 from, bytes32 to, bytes32 ben, bytes memory out,
        bytes memory memo) internal view returns (bytes memory)
    {
        return bytes.concat(abi.encode(p, block.number + 100, plainUsed, from, to, ben), salt, out, memo);
    }

    function _memo() internal view returns (bytes memory) {
        return bytes.concat(salt, _slice(_blob(0x3e30, 64), 0, 41));
    }

    // ------------------------------------------------------------------ the client

    function _acc(bytes32 ua) internal view returns (bytes memory a) {
        a = accOf[ua];
        if (a.length == 0) a = new bytes(PqzCt.CT);
    }

    /// The inline credits a debit at `p` needs (`pending[rolled..p)` or `pending[p..rolled)`).
    function _inline(PqzLayer t, bytes32 ua, uint256 p) internal view returns (bytes[] memory xs) {
        uint256 r = t.accountState(ua).rolled;
        (uint256 lo, uint256 n) = p >= r ? (r, p - r) : (p, r - p);
        xs = new bytes[](n);
        for (uint256 i; i < n; ++i) xs[i] = pend[ua][lo + i];
    }

    function _public(PqzLayer t, address to, uint256 units) internal {
        NoUnderlyingPqzToken(address(t)).mint(to, units);
        minted += units;
    }

    /// Shield `amount` from the test's public balance.
    function _fund(PqzLayer t, bytes32 ua, uint256 amount) internal {
        _public(t, address(this), amount * SCALE);
        t.pqzShield(ua, amount);
    }

    /// A direct transfer at `p = pendingCount` (the client's rule), `plainUsed = plainPending`; the client's mirror.
    function _transfer(PqzLayer t, bytes32 from, bytes32 to, bytes32 ben, uint256 seed, bool withAud)
        internal returns (bytes32 ref, bytes memory out)
    {
        out = _out(seed, withAud);
        bytes memory pl = _payloadFor(t, from, to, ben, out);
        bytes[] memory inl = _inline(t, from, t.accountState(from).pendingCount);
        bytes memory accF = _acc(from);
        ref = t.pqzTransferSingle(pl, accF, inl, hex"c0de", _mlAuth());
        _afterDebit(from, _cut(out, 0, PqzCt.PK), _cut(out, PqzCt.CT, PqzCt.V));
        pend[to].push(_cut(out, 0, PqzCt.CT));
    }

    function _payloadFor(PqzLayer t, bytes32 from, bytes32 to, bytes32 ben, bytes memory out)
        internal view returns (bytes memory)
    {
        PqzLayer.AccountState memory a = t.accountState(from);
        bytes memory memo = t.disclosureMode() == ZetherTypes.DisclosureMode.COMPACT ? _memo() : bytes("");
        return _payload(a.pendingCount, a.plainPending, from, to, ben, out, memo);
    }

    /// The client's `acc` after a debit at `p ≥ rolled`: `u ‖ v_f`.
    function _afterDebit(bytes32 from, bytes memory u, bytes memory vF) internal {
        accOf[from] = bytes.concat(u, vF);
    }

    function _roll(PqzLayer t, bytes32 ua, uint256 n) internal {
        uint256 r = t.accountState(ua).rolled;
        bytes[] memory cts = new bytes[](n);
        for (uint256 i; i < n; ++i) cts[i] = pend[ua][r + i];
        t.pqzRollOver(ua, _acc(ua), cts);
        accOf[ua] = ct.sum(_acc(ua), cts, new bytes[](0), 0);
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
