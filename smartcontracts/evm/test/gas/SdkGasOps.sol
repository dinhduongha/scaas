// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {MtxHash} from "../helpers/MtxHash.sol";
import {SdkGasDeploy} from "./SdkGasDeploy.sol";

interface ISdkGasNonce {
    function mtxNonce(bytes32 from, uint256 batch) external view returns (uint256);
}

interface ISdkGasBurn {
    function mtxBurn(MetaTxLib.UAEnvelope calldata e, uint256 amount, IUARegistry.UASig calldata auth)
        external
        returns (bytes memory);
}

interface ISdkGasCancel {
    function mtxCancelNonce(MetaTxLib.UAEnvelope calldata e, uint256 lane, IUARegistry.UASig calldata auth)
        external
        returns (bytes memory);
}

/// @notice The SDK gas table's measurement (scaas-sdk spec §13.3, owner 2026-11-19, part 3b): each base row's execution gas
///         of one isolated call (`foundry.toml`: `isolate = true`) signed by the reference signer, a native EVM key (no
///         registry call): regular gas, `gasTotalUsed - 15,000 (the Amsterdam intrinsic cost) - the call's standard calldata
///         gas (4 a zero byte, 16 a non-zero byte)`, plus the call's state gas (EIP-8037, `lastFrameGas().gasStateUsed`)
///         (owner 2026-11-19). A fresh lane has nonce 0; a used one has its nonce slot set to 1 before the call,
///         everything else the same. Every call starts from the same snapshot, so the payee holds nothing before it: the
///         worst case of a first write. Each value is a pin of `test/vectors/sdk_gas.json`: a run fails when a key is missing
///         or moved; `SDK_GAS_WRITE=true` merges `<key>` (the sum), `<key>_regular` and `<key>_state` into `SDK_GAS_OUT`
///         (default the pin file) instead; run it with `--threads 1`. Keys: `<kind>_<entry>_<fresh|used>_<variant>`, and for
///         the `PayMeta` body's per-byte coefficient (owner 2026-11-19, ruling B) `<kind>_<entry>_body<bytes>_<variant>` (a
///         saved record, `payNo` set, on a fresh lane) and `<kind>_<entry>_saved_<variant>` (the same, empty body).
abstract contract SdkGasRows is SdkGasDeploy {
    string internal constant SDK_GAS = "test/vectors/sdk_gas.json";
    address internal constant SG_RELAYER = address(0x5EAD);
    address internal constant SG_PAYEE = address(0xFA11);
    address internal constant SG_FEE_TO = address(0xFEE5);
    uint256 internal constant SG_LANE = 9;
    /// The two body lengths of ruling B's coefficient: below the length where EIP-7976's calldata floor binds the
    /// transaction's total (about 1.2 KiB of body on `mtxPay`), so the difference is execution gas.
    uint256 internal constant SG_BODY_LO = 256;
    uint256 internal constant SG_BODY_HI = 1_024;
    /// ruling 3 (owner 2026-11-19): the envelope's fee (`FIXED`, the recipient unbound: the relayer, who holds nothing)
    uint256 internal sgFee;
    /// the reference signer's key (a native key); a leg of the wrapper under measurement (an ERC-20 the signer holds and
    /// approved)
    uint256 internal sgPk;
    address internal sgLeg;
    /// the signer of a row: a UA of kind `sgKind` (0: the native key `sgPk`), its key data and secret (`SdkGasOps`)
    uint16 internal sgKind;
    bytes internal sgKeyData;
    uint256 internal sgSk;

    /// The standard calldata gas of `cd`: 4 a zero byte, 16 a non-zero one.
    function _cdGas(bytes memory cd) internal pure returns (uint256 g) {
        for (uint256 i; i < cd.length; ++i) {
            g += cd[i] == 0 ? 4 : 16;
        }
    }

    /// `from`'s nonce on `lane` of `c` set to `n` (the slot `mtxNonce` reads, found by `vm.record`).
    function _setNonce(address c, bytes32 from, uint256 lane, uint256 n) internal {
        vm.record();
        ISdkGasNonce(c).mtxNonce(from, lane);
        (bytes32[] memory r,) = vm.accesses(c);
        vm.store(c, r[r.length - 1], bytes32(n));
        assertEq(ISdkGasNonce(c).mtxNonce(from, lane), n, "the lane's nonce slot");
    }

    /// Whether this build's figures are the pin table's (`SDK_GAS`): true here; a suite whose figures depend on a build
    /// parameter the table is measured at one value of (the PQZ set) answers false at the others.
    function _sgPinned() internal view virtual returns (bool) {
        return true;
    }

    function _pin(string memory key, uint256 v) internal {
        this.sgPin(key, v);
    }

    /// `_pin`'s body in a call frame of its own, so the pin file it reads is freed on return (a test pins hundreds of keys,
    /// and a file read in the test's own frame grows its memory past the gas limit).
    function sgPin(string calldata key, uint256 v) external {
        // a figure of another build than the table's (`_sgPinned`): the operation ran, nothing compared or written
        if (!_sgPinned()) {
            require(!vm.envOr("SDK_GAS_WRITE", false), "SDK_GAS_WRITE at another build than the table's");
            return;
        }
        if (vm.envOr("SDK_GAS_WRITE", false)) {
            string memory out = vm.envOr("SDK_GAS_OUT", SDK_GAS);
            if (vm.exists(out)) vm.serializeJson("sdkgas", vm.readFile(out));
            vm.writeJson(vm.serializeUint("sdkgas", key, v), out);
        } else {
            assertEq(v, vm.parseJsonUint(vm.readFile(SDK_GAS), string.concat(".", key)), key);
        }
    }

    /// Ruling B's coefficient: the gas a byte between two lengths `n` bytes apart, rounded up to the whole gas.
    function _perByte(string memory key, uint256 lo, uint256 hi, uint256 n) internal {
        assertGt(hi, lo, "the cost grows with the input");
        _pin(key, (hi - lo + n - 1) / n);
    }

    /// The call by the relayer, its execution gas pinned under `key`.
    function _measure(string memory key, address c, bytes memory cd) internal returns (uint256 g) {
        vm.prank(SG_RELAYER);
        (bool ok, bytes memory ret) = c.call(cd);
        if (!ok) {
            assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        }
        Vm.Gas memory used = vm.lastFrameGas();
        assertGe(used.gasStateUsed, 0, "net state gas of a top-level call");
        // EIP-7976's floor (the 15,000 base + 64 a calldata byte) binding the total hides the execution gas: refused (a
        // total at the floor; probe: `mtxExecute` with 1,024 bytes of data sat on it, 48 = 64 - 16 gas a byte above)
        assertGt(used.gasTotalUsed, 15_000 + 64 * cd.length, "the calldata floor bound the total");
        uint256 regular = used.gasTotalUsed - 15_000 - _cdGas(cd);
        uint256 state = uint256(int256(used.gasStateUsed));
        g = regular + state;
        _pin(string.concat(key, "_regular"), regular);
        _pin(string.concat(key, "_state"), state);
        _pin(key, g);
    }

    /// One row on both lane states, each from the same snapshot: `build(c, nonce)` gives the calldata at that nonce. Owner
    /// 2026-11-19, A1: when the fixture set a derived signer (`_sgUaHook`), the fresh lane once more signed by it
    /// (`<kind>_<entry>_ua_<variant>`, on `sgUaAt[c]` when the fixture names another contract for it); A6: a wrap-in entry's
    /// fee row with a signer who already holds units (`..._held_<variant>` at fee 0, `..._fee_<variant>` at fee 1).
    function _both(
        string memory kind,
        string memory entry,
        string memory variant,
        address c,
        bytes32 from,
        function(address, uint256) internal view returns (bytes memory) build
    ) internal {
        if (sgUaRun) return _bothUaRun(kind, entry, variant, c, build);
        uint256 s = vm.snapshotState();
        _measure(_k(kind, entry, "fresh", variant), c, build(c, 0));
        vm.revertToState(s);
        _setNonce(c, from, SG_LANE, 1);
        _measure(_k(kind, entry, "used", variant), c, build(c, 1));
        vm.revertToState(s);
        if (_feeable(kind, entry)) {
            sgFee = 1; // a revert restores this contract's storage too: back to 0 after it
            _measure(_k(kind, entry, "fee", variant), c, build(c, 0));
            vm.revertToState(s);
        } else if (_wrapIn(entry)) {
            _sgHold(c);
            _measure(_k(kind, entry, "held", variant), c, build(c, 0));
            vm.revertToState(s);
            _sgHold(c);
            sgFee = 1;
            _measure(_k(kind, entry, "fee", variant), c, build(c, 0));
            vm.revertToState(s);
        }
        if (sgUaKind != 0 && !_uaNative(entry)) {
            address cu = sgUaAt[c] == address(0) ? c : sgUaAt[c];
            _sgUaPrep(cu);
            (sgKind, sgKeyData, sgSk) = (sgUaKind, sgUaKey, sgUaSk); // the revert below restores the native signer
            _measure(_k(kind, entry, "ua", variant), cu, build(cu, 0));
            vm.revertToState(s);
            if (sgPayeeKey.length != 0 && keccak256(bytes(entry)) == keccak256("mtxPayWithPayeeFee")) {
                // Q1 (owner 2026-11-19): the payer and the payee both derived, both debited
                _sgUaPrep(cu);
                (sgKind, sgKeyData, sgSk, sgPayeeUa) = (sgUaKind, sgUaKey, sgUaSk, true);
                _measure(_k(kind, entry, "ua2", variant), cu, build(cu, 0));
                vm.revertToState(s);
            }
        }
    }

    /// I1 part 2 (owner 2026-11-19): the point of a counted row being measured: its count (`sgCount`, what the builders
    /// read through `_sgN`), its index (`sgPoint`) and its key infix (`sgCountTag`, `n<count>_` or a fixture's own; empty
    /// outside a counted row, so every other key is as before).
    uint256 internal sgCount;
    /// The line's upper check waived, by the owner's rulings of 2026-11-19 that accept a line above the points:
    /// P1, the env publishes' `env_items` at the worst array's per-element slope (the other arrays, and an array's elements
    /// past its first, below it); P2, PQZ `mtxConfidentialTransfer` / `…Compact` (the precompile's price steps with the
    /// auditor groups). P4 ("approved"): a row whose chord is not at or above every point keeps the worst slope's line (Zether `mtxConfidentialTransferCompact`, PQZ `mtxRollOver`). The excess is refunded.
    bool internal sgLineLoose;
    uint256 internal sgPoint;
    string internal sgCountTag;

    /// The key `<kind>_<entry>_[<tag>]<what>_<variant>`.
    function _k(string memory kind, string memory entry, string memory what, string memory variant)
        internal
        view
        returns (string memory)
    {
        return string.concat(kind, "_", entry, "_", sgCountTag, what, "_", variant);
    }

    /// The count a builder uses: the counted row's point, else the fixture's own `dflt`.
    function _sgN(uint256 dflt) internal view returns (uint256) {
        return bytes(sgCountTag).length == 0 ? dflt : sgCount;
    }

    /// I1 part 2: a row whose cost grows with a count, measured by `_both` at each point (`counts[i]`, key infix
    /// `n<counts[i]>_`), then fitted (`_sgLine`).
    function _bothN(
        string memory kind,
        string memory entry,
        string memory variant,
        address c,
        bytes32 from,
        function(address, uint256) internal view returns (bytes memory) build,
        uint256[] memory counts
    ) internal {
        string[] memory tags = new string[](counts.length);
        for (uint256 i; i < counts.length; ++i) {
            tags[i] = string.concat("n", vm.toString(counts[i]), "_");
        }
        _bothTagged(kind, entry, variant, c, from, build, counts, tags);
    }

    /// `_bothN` with the fixture's own key infixes (`tags[i]`, a point's shape where one count has several: the env's
    /// arrays).
    function _bothTagged(
        string memory kind,
        string memory entry,
        string memory variant,
        address c,
        bytes32 from,
        function(address, uint256) internal view returns (bytes memory) build,
        uint256[] memory counts,
        string[] memory tags
    ) internal {
        for (uint256 i; i < counts.length; ++i) {
            (sgCount, sgPoint, sgCountTag) = (counts[i], i, tags[i]);
            _both(kind, entry, variant, c, from, build);
        }
        (sgCount, sgPoint, sgCountTag) = (0, 0, "");
        // the line is fitted to the table's figures (`sgRead`): none at another build than the table's
        if (_sgPinned()) _sgLine(kind, entry, variant, counts, tags);
    }

    /// `key` as measured: the pin file's value (written by this run under `SDK_GAS_WRITE`, else asserted equal to it), in a
    /// frame of its own as `sgPin`; `false` when the key is absent.
    function sgRead(string calldata key) external view returns (bool, uint256) {
        string memory f = vm.envOr("SDK_GAS_WRITE", false) ? vm.envOr("SDK_GAS_OUT", SDK_GAS) : SDK_GAS;
        string memory j = vm.readFile(f);
        string memory k = string.concat(".", key);
        if (!vm.keyExistsJson(j, k)) return (false, 0);
        return (true, vm.parseJsonUint(j, k));
    }

    /// The measured gas `<head><tags[i]><tail>` at each point.
    function _sgPoints(string memory head, string memory tail, string[] memory tags)
        internal
        view
        returns (uint256[] memory g)
    {
        g = new uint256[](tags.length);
        for (uint256 i; i < tags.length; ++i) {
            bool ok;
            (ok, g[i]) = this.sgRead(string.concat(head, tags[i], tail));
            assertTrue(ok, "a counted key measured at every point");
        }
    }

    /// Whether this run measures the key `what` (`_sgLine`'s `ws[w]`) of `entry` on `kind`: `_both`'s choice, so a key
    /// another run wrote (the derived run's `ua`) never enters this run's line.
    function _sgMeasured(string memory kind, string memory entry, uint256 w) internal view returns (bool) {
        if (sgUaRun) return w == 4;
        if (w < 2) return true;
        if (w == 2) return _feeable(kind, entry) || _wrapIn(entry);
        if (w == 3) return _wrapIn(entry);
        bool ua = sgUaKind != 0 && !_uaNative(entry);
        if (w == 4) return ua;
        return ua && sgPayeeKey.length != 0 && keccak256(bytes(entry)) == keccak256("mtxPayWithPayeeFee");
    }

    /// I1 part 2: the line of a counted row over its points (`counts`, `tags`; a point whose count does not exceed the one
    /// before it starts a new sequence). For every key the run measured (`fresh`, `used`, `fee`, `held`, `ua`, `ua2`; a
    /// derived run `ua` only) the run's slope `s` is, on one rising sequence whose chord is at or above every point (P4,
    /// owner 2026-11-19: tight where the cost rises faster at higher counts), the chord's: the worst over those
    /// keys of the whole-gas rise a count from the first point to the last (rounded up), each key's intercept its line
    /// through its first point; else the worst over the keys and sequences of the whole-gas rise a count between two
    /// points, each key's intercept the largest `g(c) - s * c` over its points. `s` is pinned as
    /// `<kind>_<entry>_per_item_<variant>` (a derived run `..._per_item_ua_<variant>`), the intercept, the gas at a count
    /// of 0, under the key without a tag. The check (owner 2026-11-19): the line `intercept + s * c` is at least the
    /// measured gas at every point, and less than it + 1,000 at the largest count (asserted), unless `sgLineLoose` (P1, P2,
    /// P4 where the chord does not hold): then the
    /// worst excess there over the keys is pinned as `<kind>_<entry>_overshoot_<variant>` (a derived run
    /// `..._overshoot_ua_<variant>`), stated with the row.
    function _sgLine(
        string memory kind,
        string memory entry,
        string memory variant,
        uint256[] memory counts,
        string[] memory tags
    ) internal {
        string[6] memory ws = ["fresh", "used", "fee", "held", "ua", "ua2"];
        uint256[][6] memory g;
        uint256 s;
        uint256 last;
        for (uint256 i; i < counts.length; ++i) {
            if (counts[i] >= counts[last]) last = i;
        }
        for (uint256 w; w < 6; ++w) {
            if (!_sgMeasured(kind, entry, w)) continue;
            g[w] = _sgPoints(string.concat(kind, "_", entry, "_"), string.concat(ws[w], "_", variant), tags);
            for (uint256 i = 1; i < g[w].length; ++i) {
                if (counts[i] > counts[i - 1]) {
                    assertGe(g[w][i], g[w][i - 1], "the cost grows with the count");
                    uint256 d = counts[i] - counts[i - 1];
                    uint256 r = (g[w][i] - g[w][i - 1] + d - 1) / d;
                    if (r > s) s = r;
                }
            }
        }
        assertGt(s, 0, "a counted row's slope");
        (uint256 c, bool chord) = _sgChord(counts, g);
        if (chord) s = c;
        uint256[6] memory bs;
        uint256 over;
        for (uint256 w; w < 6; ++w) {
            if (g[w].length == 0) continue;
            assertGe(g[w][0], s * counts[0], "a positive intercept");
            uint256 b = g[w][0] - s * counts[0]; // P4: the chord's line through the first point
            for (uint256 i; i < counts.length && !chord; ++i) {
                assertGe(g[w][i], s * counts[i], "a positive intercept");
                if (g[w][i] - s * counts[i] > b) b = g[w][i] - s * counts[i];
            }
            for (uint256 i; i < counts.length; ++i) {
                assertGe(b + s * counts[i], g[w][i], "the line at or above every point");
            }
            uint256 o = b + s * counts[last] - g[w][last];
            if (!sgLineLoose) assertLt(o, 1_000, "the line within 1,000 of the largest count");
            if (o > over) over = o;
            bs[w] = b;
        }
        _pin(string.concat(kind, "_", entry, sgUaRun ? "_per_item_ua_" : "_per_item_", variant), s);
        for (uint256 w; w < 6; ++w) {
            if (g[w].length != 0) _pin(string.concat(kind, "_", entry, "_", ws[w], "_", variant), bs[w]);
        }
        if (sgLineLoose) {
            _pin(string.concat(kind, "_", entry, sgUaRun ? "_overshoot_ua_" : "_overshoot_", variant), over);
        }
    }

    /// P4 (owner 2026-11-19): on one rising sequence (`counts` strictly increasing), the chord's slope `c`, the
    /// worst over the measured keys `g[w]` of the whole-gas rise a count from the first point to the last (rounded up), and
    /// whether each key's line through its first point at `c` is at or above every one of its points.
    function _sgChord(uint256[] memory counts, uint256[][6] memory g) internal pure returns (uint256 c, bool ok) {
        uint256 n = counts.length;
        for (uint256 i = 1; i < n; ++i) {
            if (counts[i] <= counts[i - 1]) return (0, false);
        }
        uint256 span = counts[n - 1] - counts[0];
        for (uint256 w; w < 6; ++w) {
            if (g[w].length == 0) continue;
            uint256 r = (g[w][n - 1] - g[w][0] + span - 1) / span;
            if (r > c) c = r;
        }
        ok = c != 0;
        for (uint256 w; w < 6 && ok; ++w) {
            for (uint256 i; i < g[w].length && ok; ++i) {
                ok = g[w][0] + c * (counts[i] - counts[0]) >= g[w][i];
            }
        }
    }

    /// G2 (owner 2026-11-19): a run of the fixture's whole sequence with derived identities (`sgUaRun`, the router's): each
    /// row measured once, on the fresh lane, as `<kind>_<entry>_ua_<variant>`; the native rows come from the native run.
    function _bothUaRun(
        string memory kind,
        string memory entry,
        string memory variant,
        address c,
        function(address, uint256) internal view returns (bytes memory) build
    ) internal {
        uint256 s = vm.snapshotState();
        _measure(_k(kind, entry, "ua", variant), c, build(c, 0));
        vm.revertToState(s);
    }

    /// The entries a derived signer cannot sign (A1, G2): the wrap-in entries and `mtxWrapShield`, signed by a native address.
    function _uaNative(string memory entry) internal pure returns (bool) {
        return _wrapIn(entry) || keccak256(bytes(entry)) == keccak256("mtxWrapShield");
    }

    /// A1: `amount` (at most what `holder` has) of the token `t`, from `holder` to the derived reference signer.
    function _sgUaFund(address t, address holder, uint256 amount) internal {
        uint256 b = IERC20MetaTx(t).balanceOf(holder);
        vm.prank(holder);
        IUALedger(t).transferToUA(UAKinds.uaOf(sgUaKind, sgUaKey), b < amount ? b : amount);
    }

    /// A1: what the derived signer needs on `c` before its run, given inside the run's snapshot only (the native rows keep the
    /// fixture's state: e.g. a ledger whose pool holds nothing yet, the worst case). None by default.
    function _sgUaPrep(address c) internal virtual {}

    /// A6 (owner 2026-11-19): the signer holds units of the wrapper `c` before a wrap-in entry's fee row: a direct wrap of
    /// 100 units of the leg `sgLeg` it holds and approved.
    function _sgHold(address c) internal {
        vm.prank(vm.addr(sgPk));
        IWrappedToken(c).wrap(sgLeg, 100);
    }

    /// The wrap-in entries: signed by a native address (`Envelope`), so no derived signer (A1: no `ua_extra`).
    function _wrapIn(string memory entry) internal pure returns (bool) {
        bytes32 e = keccak256(bytes(entry));
        return e == keccak256("mtxWrap") || e == keccak256("mtxWrapLeg") || e == keccak256("mtxAddReserve")
            || e == keccak256("mtxWrapToUA");
    }

    /// A1's derived reference signer (owner 2026-11-19): a UA of kind `sgUaKind` (0: none in this fixture), its key data
    /// and secret, holding what the native signer holds; `sgUaAt[c]`: the contract it signs on instead of `c` (a wallet
    /// it owns), 0 = `c`.
    uint16 internal sgUaKind;
    bytes internal sgUaKey;
    uint256 internal sgUaSk;
    mapping(address => address) internal sgUaAt;
    /// G2: the run's identities are derived (the router's sequences, `_bothUaRun`)
    bool internal sgUaRun;
    /// Q1: a second derived UA (secp256k1 `SG_UA_SK2`), the payee of `mtxPayWithPayeeFee` when `sgPayeeUa`
    bytes internal sgPayeeKey;
    bool internal sgPayeeUa;

    /// Ruling 3 (owner 2026-11-19): the entries whose envelope carries a fee, measured once more on a fresh lane with a fee
    /// of 1 (`<kind>_<entry>_fee_<variant>`; the generator's `fee_extra` is the worst difference to the fresh row): the
    /// token kinds' entries but `mtxRelayFee` and `mtxPayWithPayeeFee` (their fee is their own payment, already in the row
    /// to a recipient holding nothing; the payee-fee entry refuses an envelope fee, `PayeeFeeShape`) and the wrap-in entries
    /// (`mtxWrap`, `mtxWrapLeg`, `mtxAddReserve`, `mtxWrapToUA`: their fee is charged in units the signer holds before the
    /// call, so A6 measures it apart, against a signer who holds units, `_both`); the wallet and the router take fee `NONE`
    /// only.
    function _feeable(string memory kind, string memory entry) internal pure returns (bool) {
        (bytes32 k, bytes32 e) = (keccak256(bytes(kind)), keccak256(bytes(entry)));
        return (k == keccak256("token") || k == keccak256("zether") || k == keccak256("pqz"))
            && e != keccak256("mtxRelayFee") && e != keccak256("mtxPayWithPayeeFee") && !_wrapIn(entry);
    }
}

/// @notice The entries' calldata, signed by the reference signer `sgPk` (a native key, its padded address the `from`), the
///         digests from the type strings (`MtxDigest`, `MtxHash`) as the vector tests build them, relayer and fee recipient
///         unbound, fee 0 (a pay entry's own fee aside). A fixture sets the key, the legs and the UA a `…ToUA` entry pays.
abstract contract SdkGasOps is SdkGasRows {
    string internal constant E_TAIL =
        "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    bytes32 internal constant UA_PAYEE_FEE = keccak256(
        "UAPayeeFee(UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil)UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 internal constant UA_PAY_WITH_TAX = keccak256(
        "UAPayWithTax(UAMetaTransfer payment,uint8 taxMode,uint256 tax)UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 internal constant UA_RELAY_FEE = keccak256(
        "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)"
    );
    /// The payee of `mtxPayWithPayeeFee`, who signs its fee.
    uint256 internal constant SG_PAYEE_PK = 0xFA11EE;
    /// `mtxPayWithTax`'s value and tax (a 10 % rate).
    uint256 internal constant SG_TAX_VALUE = 1_000;
    uint256 internal constant SG_TAX = 100;

    /// a SCaaS ledger leg (`mtxUnwrapToUA`) and the UA a `…ToUA` entry credits
    address internal sgLedgerLeg;
    bytes32 internal sgUaTo;
    /// ruling B: the `PayMeta` body's length, and a saved record (`payNo` set)
    uint256 internal sgBody;
    bool internal sgSave;

    /// An entry's amount: `a`, raised to 100 under a fee so that the 1 % cap of an amount-class entry admits a fee of 1.
    function _amt(uint256 a) internal view returns (uint256) {
        return sgFee != 0 && a < 100 ? 100 : a;
    }

    function _sgFeeTerms() internal view returns (uint32 mode, uint256 fee) {
        if (sgFee != 0) (mode, fee) = (MetaTxLib.MODE_FEE_FIXED, sgFee);
    }

    /// `sgNoSig`: an empty `UASig` (the operation the SDK quotes, ruling 2).
    bool internal sgNoSig;
    uint256 internal constant SG_N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    function _sgFrom() internal view returns (bytes32) {
        return sgKind == 0 ? MetaTxLib.pad(vm.addr(sgPk)) : UAKinds.uaOf(sgKind, sgKeyData);
    }

    /// A1's derived reference signer: secp256k1 (0x0108), forge-signable by `vm.sign`; Q1's derived payee.
    uint256 internal constant SG_UA_SK = 0x5A3B10;
    uint256 internal constant SG_UA_SK2 = 0x5A3B11;

    /// The UA of `kind` (P-256, ed25519, secp256k1) from secret `sk`, registered on the registry `r` with its PoP, no
    /// attributes: its id and key data.
    function _sgRegisterOn(address r, uint16 kind, uint256 sk) internal returns (bytes32 ua, bytes memory k) {
        if (kind == UAKinds.P256) {
            (uint256 x, uint256 y) = vm.publicKeyP256(sk);
            k = abi.encodePacked(x, y);
        } else if (kind == UAKinds.ED25519) {
            k = abi.encodePacked(vm.publicKeyEd25519(bytes32(sk)));
        } else {
            Vm.Wallet memory w = vm.createWallet(sk);
            k = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        }
        ua = UAKinds.uaOf(kind, k);
        IUARegistry.UAAttrs memory none;
        bytes32 d = UAKinds.registrationDigest(ua, kind, 0, UAKinds.kemRecordHash(ua, 0, UAKinds.kemPk(none.kem)), 0);
        bytes memory pop = _sgUaSign(kind, sk, UAKinds.uaMessage(kind, UAKinds.PURPOSE_POP_V2, d));
        assertEq(IUARegistry(r).register(kind, k, none, pop, ""), ua, "the UA registered");
    }

    /// A1: the derived reference signer (secp256k1 `SG_UA_SK`) registered on `r`; the fixture gives it what the native
    /// signer holds.
    function _sgUaSignerOn(address r) internal returns (bytes32 ua) {
        bytes memory k;
        (ua, k) = _sgRegisterOn(r, UAKinds.SECP256K1, SG_UA_SK);
        (sgUaKind, sgUaKey, sgUaSk) = (UAKinds.SECP256K1, k, SG_UA_SK);
        (, sgPayeeKey) = _sgRegisterOn(r, UAKinds.SECP256K1, SG_UA_SK2);
    }

    /// Q1's derived payee.
    function _sgPayeeUa() internal view returns (bytes32) {
        return UAKinds.uaOf(UAKinds.SECP256K1, sgPayeeKey);
    }

    /// The signature of UA kind `kind` (P-256 low-s over sha256, ed25519, secp256k1 `r ‖ s ‖ v`) by `sk` over `m`.
    function _sgUaSign(uint16 kind, uint256 sk, bytes32 m) internal pure returns (bytes memory) {
        if (kind == UAKinds.P256) {
            (bytes32 r, bytes32 s) = vm.signP256(sk, sha256(abi.encodePacked(m)));
            if (uint256(s) > SG_N_P256 / 2) s = bytes32(SG_N_P256 - uint256(s));
            return abi.encodePacked(r, s);
        }
        if (kind == UAKinds.ED25519) return vm.signEd25519("", abi.encodePacked(m), bytes32(sk));
        require(kind == UAKinds.SECP256K1, "a sampled kind");
        (uint8 v, bytes32 r2, bytes32 s2) = vm.sign(sk, m);
        return abi.encodePacked(r2, s2, v);
    }

    function _sgSign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sgUaSig(bytes32 digest) internal view returns (IUARegistry.UASig memory a) {
        if (sgNoSig) return a;
        if (sgKind == 0) {
            a.signature = _sgSign(sgPk, digest);
        } else {
            (a.keyData, a.signature) =
            (sgKeyData, _sgUaSign(sgKind, sgSk, UAKinds.uaMessage(sgKind, UAKinds.PURPOSE_METATX, digest)));
        }
    }

    function _sgT(uint256 nonce, bytes32 to, uint256 value, bytes32 entryRef)
        internal
        view
        returns (MetaTxLib.UAMetaTransfer memory x)
    {
        (x.from, x.to, x.value, x.entryRef) = (_sgFrom(), to, _amt(value), entryRef);
        (x.batch, x.nonce, x.validUntil) = (SG_LANE, nonce, block.timestamp + 600);
        (x.mode, x.fee) = _sgFeeTerms();
    }

    function _sgE(uint256 nonce) internal view returns (MetaTxLib.UAEnvelope memory e) {
        (e.from, e.batch, e.nonce, e.validUntil) = (_sgFrom(), SG_LANE, nonce, block.timestamp + 600);
        (e.mode, e.fee) = _sgFeeTerms();
    }

    function _sgAddrE(uint256 nonce) internal view returns (MetaTxLib.Envelope memory e) {
        (e.from, e.batch, e.nonce, e.validUntil) = (vm.addr(sgPk), SG_LANE, nonce, block.timestamp + 600);
        (e.mode, e.fee) = _sgFeeTerms();
    }

    /// The digest of `<head><E>` over `(from, args…, E)` in `c`'s domain, relayer and fee recipient unbound.
    function _sgNamed(address c, string memory head, bytes memory args, uint256 nonce) internal view returns (bytes32) {
        MetaTxLib.UAEnvelope memory e = _sgE(nonce);
        return MtxDigest.typed(
            c,
            keccak256(
                bytes.concat(
                    abi.encode(keccak256(bytes(string.concat(head, E_TAIL))), e.from),
                    args,
                    abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))
                )
            )
        );
    }

    /// The `PayMeta` of a pay entry: salt-only (the base rows), or ruling B's saved record with a body of `sgBody` bytes.
    function _sgMeta() internal view returns (MetaTxLib.PayMeta memory m) {
        m = PayMetaKit.meta(keccak256("sdk-gas"));
        if (sgSave) (m.payNo, m.save) = (keccak256("sdk-gas-payNo"), true);
        if (sgBody != 0) {
            m.schema = 1;
            m.body = new bytes(sgBody);
            for (uint256 i; i < sgBody; ++i) {
                m.body[i] = 0xab;
            }
        }
    }

    // ------------------------------------------------------------------ the token kinds' entries

    function _transfer(address c, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAMetaTransfer memory x = _sgT(nonce, MetaTxLib.pad(SG_PAYEE), 1, 0);
        return abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (x, _sgUaSig(MtxDigest.typed(c, MtxHash.hashStruct(x)))));
    }

    function _pay(address c, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.PayMeta memory m = _sgMeta();
        MetaTxLib.UAMetaTransfer memory x = _sgT(nonce, MetaTxLib.pad(SG_PAYEE), 1, PayMetaKit.id(m));
        return abi.encodeCall(IMetaTokenV2.mtxPay, (x, _sgUaSig(MtxDigest.typed(c, MtxHash.hashStruct(x))), m));
    }

    /// The payer pays the payee (`SG_PAYEE_PK`), who gives 1 to `SG_FEE_TO`; the relayer bound (the entry's shape).
    function _payeeFee(address c, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.PayMeta memory m = _sgMeta();
        bytes32 payee = sgPayeeUa ? UAKinds.uaOf(UAKinds.SECP256K1, sgPayeeKey) : MetaTxLib.pad(vm.addr(SG_PAYEE_PK));
        MetaTxLib.UAMetaTransfer memory x = _sgT(nonce, payee, 10, PayMetaKit.id(m));
        (x.mode, x.relayer) = (x.mode | MetaTxLib.MODE_RESTRICT_RELAYER, SG_RELAYER); // the entry binds the relayer
        uint256 until = block.timestamp + 600;
        bytes32 rf = MtxDigest.typed(
            c, keccak256(abi.encode(UA_PAYEE_FEE, MtxHash.hashStruct(x), uint256(1), SG_FEE_TO, until))
        );
        return abi.encodeCall(
            IMetaTokenV2.mtxPayWithPayeeFee,
            (x, _sgUaSig(MtxDigest.typed(c, MtxHash.hashStruct(x))), 1, SG_FEE_TO, until, _sgPayeeSig(rf), m)
        );
    }

    /// The payee's signature of its fee `rf`: the native `SG_PAYEE_PK`, or (Q1, `sgPayeeUa`) the derived `SG_UA_SK2`.
    function _sgPayeeSig(bytes32 rf) internal view returns (IUARegistry.UASig memory a) {
        if (!sgPayeeUa) {
            a.signature = _sgSign(SG_PAYEE_PK, rf);
        } else {
            (a.keyData, a.signature) =
            (
                sgPayeeKey,
                _sgUaSign(
                    UAKinds.SECP256K1, SG_UA_SK2, UAKinds.uaMessage(UAKinds.SECP256K1, UAKinds.PURPOSE_PAYEE_FEE, rf)
                )
            );
        }
    }

    function _payWithTax(address c, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.PayMeta memory m = _sgMeta();
        MetaTxLib.UAMetaTransfer memory x = _sgT(nonce, MetaTxLib.pad(SG_PAYEE), SG_TAX_VALUE, PayMetaKit.id(m));
        bytes32 d = MtxDigest.typed(c, keccak256(abi.encode(UA_PAY_WITH_TAX, MtxHash.hashStruct(x), uint8(1), SG_TAX)));
        return abi.encodeCall(IRegulatedToken.mtxPayWithTax, (x, 1, SG_TAX, _sgUaSig(d), m));
    }

    /// 1 to `SG_PAYEE` for a call of `SG_RELAYER` (the relayer the payment binds: the caller).
    function _relayFee(address c, uint256 nonce) internal view returns (bytes memory) {
        (address target, bytes32 cdh, uint256 until) =
            (address(0xCA11), keccak256("sdk-gas-call"), block.timestamp + 600);
        bytes32 d = MtxDigest.typed(
            c,
            keccak256(
                abi.encode(
                    UA_RELAY_FEE,
                    _sgFrom(),
                    target,
                    cdh,
                    MetaTxLib.pad(SG_PAYEE),
                    uint256(1),
                    SG_LANE,
                    nonce,
                    until,
                    SG_RELAYER
                )
            )
        );
        return abi.encodeCall(
            IERC20MetaTx.mtxRelayFee,
            (_sgFrom(), target, cdh, MetaTxLib.pad(SG_PAYEE), 1, SG_LANE, nonce, until, _sgUaSig(d))
        );
    }

    function _cancel(address c, uint256 nonce) internal view returns (bytes memory) {
        uint256 lane = SG_LANE + 1;
        bytes32 d = _sgNamed(c, "UACancelNonce(bytes32 from,uint256 lane,", abi.encode(lane), nonce);
        return abi.encodeCall(ISdkGasCancel.mtxCancelNonce, (_sgE(nonce), lane, _sgUaSig(d)));
    }

    function _burn(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes32 d = _sgNamed(c, "UABurn(bytes32 from,uint256 amount,", abi.encode(_amt(1)), nonce);
        return abi.encodeCall(ISdkGasBurn.mtxBurn, (_sgE(nonce), _amt(1), _sgUaSig(d)));
    }

    function _wrap(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes32 d = _sgNamed(c, "Wrap(address from,uint256 amount,", abi.encode(_amt(1)), nonce);
        return abi.encodeCall(IWrappedToken.mtxWrap, (_sgAddrE(nonce), _amt(1), _sgSign(sgPk, d)));
    }

    function _wrapLeg(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes32 d =
            _sgNamed(c, "WrapLeg(address from,address underlying,uint256 amount,", abi.encode(sgLeg, _amt(1)), nonce);
        return abi.encodeCall(IWrappedToken.mtxWrapLeg, (_sgAddrE(nonce), sgLeg, _amt(1), _sgSign(sgPk, d)));
    }

    function _addReserve(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes32 d = _sgNamed(
            c, "AddReserve(address from,address underlying,uint256 amount,", abi.encode(sgLeg, _amt(1)), nonce
        );
        return abi.encodeCall(IWrappedToken.mtxAddReserve, (_sgAddrE(nonce), sgLeg, _amt(1), _sgSign(sgPk, d)));
    }

    function _wrapToUA(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes32 d = _sgNamed(
            c,
            "WrapToUA(address from,address underlying,uint256 amount,bytes32 to,",
            abi.encode(sgLeg, _amt(1), sgUaTo),
            nonce
        );
        return abi.encodeCall(IWrappedToken.mtxWrapToUA, (_sgAddrE(nonce), sgLeg, _amt(1), sgUaTo, _sgSign(sgPk, d)));
    }

    function _unwrap(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes32 d = _sgNamed(
            c,
            "UAUnwrap(bytes32 from,uint256 wrapped,address recipient,uint256 minOut,",
            abi.encode(_amt(1), SG_PAYEE, uint256(0)),
            nonce
        );
        return abi.encodeCall(IWrappedToken.mtxUnwrap, (_sgE(nonce), _amt(1), SG_PAYEE, 0, _sgUaSig(d)));
    }

    function _unwrapLeg(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes32 d = _sgNamed(
            c,
            "UAUnwrapLeg(bytes32 from,address underlying,uint256 wrapped,address recipient,uint256 minOut,",
            abi.encode(sgLeg, _amt(1), SG_PAYEE, uint256(0)),
            nonce
        );
        return abi.encodeCall(IWrappedToken.mtxUnwrapLeg, (_sgE(nonce), sgLeg, _amt(1), SG_PAYEE, 0, _sgUaSig(d)));
    }

    function _unwrapToUA(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes32 d = _sgNamed(
            c,
            "UAUnwrapToUA(bytes32 from,address underlying,uint256 wrapped,bytes32 to,uint256 minOut,",
            abi.encode(sgLedgerLeg, _amt(1), sgUaTo, uint256(0)),
            nonce
        );
        return abi.encodeCall(IWrappedToken.mtxUnwrapToUA, (_sgE(nonce), sgLedgerLeg, _amt(1), sgUaTo, 0, _sgUaSig(d)));
    }

    // ------------------------------------------------------------------ rows

    /// The entries every token kind's variant has, on both lane states.
    function _commonRows(string memory kind, string memory variant, address c) internal {
        bytes32 from = _sgFrom();
        _both(kind, "mtxExecuteTransfer", variant, c, from, _transfer);
        _both(kind, "mtxPay", variant, c, from, _pay);
        _both(kind, "mtxPayWithPayeeFee", variant, c, from, _payeeFee);
        _both(kind, "mtxRelayFee", variant, c, from, _relayFee);
        _both(kind, "mtxCancelNonce", variant, c, from, _cancel);
    }

    /// The wrap-in entries on a wrapper `c` of `sgLeg` the signer holds nothing of.
    function _wrapInRows(string memory kind, string memory variant, address c) internal {
        bytes32 from = _sgFrom();
        _both(kind, "mtxWrap", variant, c, from, _wrap);
        _both(kind, "mtxWrapLeg", variant, c, from, _wrapLeg);
        _both(kind, "mtxAddReserve", variant, c, from, _addReserve);
        _both(kind, "mtxWrapToUA", variant, c, from, _wrapToUA);
    }

    /// The unwraps on a wrapper `c` of `sgLeg` the signer holds units of; `mtxUnwrapToUA` on `cl`, a wrapper of the ledger
    /// leg `sgLedgerLeg`.
    function _unwrapRows(string memory kind, string memory variant, address c, address cl) internal {
        bytes32 from = _sgFrom();
        _both(kind, "mtxUnwrap", variant, c, from, _unwrap);
        _both(kind, "mtxUnwrapLeg", variant, c, from, _unwrapLeg);
        _both(kind, "mtxUnwrapToUA", variant, cl, from, _unwrapToUA);
    }

    /// Ruling B: a pay entry's `PayMeta` body at two lengths and a saved record without a body, each a fresh lane.
    function _bodyRows(
        string memory kind,
        string memory entry,
        string memory variant,
        address c,
        function(address, uint256) internal view returns (bytes memory) build
    ) internal {
        string memory k = string.concat(kind, "_", entry, "_");
        uint256 s = vm.snapshotState(); // a revert restores this contract's storage too: set the meta after each
        (sgBody, sgSave) = (0, true);
        _measure(string.concat(k, "saved_", variant), c, build(c, 0));
        vm.revertToState(s);
        (sgBody, sgSave) = (SG_BODY_LO, true);
        uint256 lo = _measure(string.concat(k, "body", vm.toString(SG_BODY_LO), "_", variant), c, build(c, 0));
        vm.revertToState(s);
        (sgBody, sgSave) = (SG_BODY_HI, true);
        uint256 hi = _measure(string.concat(k, "body", vm.toString(SG_BODY_HI), "_", variant), c, build(c, 0));
        vm.revertToState(s);
        _perByte(string.concat(k, "per_byte_", variant), lo, hi, SG_BODY_HI - SG_BODY_LO);
    }
}
