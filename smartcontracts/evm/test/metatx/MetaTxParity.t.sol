// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm, console2} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeePolicy} from "../../src/common/FeePolicy.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {NoUnderlyingPqzToken} from "../../src/pqz/NoUnderlyingPqzToken.sol";
import {UnderlyingPqzToken} from "../../src/pqz/UnderlyingPqzToken.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {ZetherKeys} from "../zether/helpers/ZetherKeys.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {NoUnderlyingZetherToken} from "../../src/zether/NoUnderlyingZetherToken.sol";
import {UnderlyingZetherToken} from "../../src/zether/UnderlyingZetherToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue, pqzEnv, plainEnv} from "../helpers/Catalogue.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// =====================================================================================================================
// The parity fixture of the metatx split (spec 2026-10-27-metatx-split-design.md R1, plan Task 1).
//
// WHAT IT IS. A fixed case set run on the PRE-split code on a clone of each of the six token kinds. For every case it
// records: outcome (ok, return data, revert data), the emitted events (emitter, topics, data), the digest views of the
// case's struct, the nonces of the lanes it touched, the balances (incl. UA_POOL, SHIELD_POOL) and the gas of the one
// top-level call. `test_parity` replays the same set and compares EVERY field with the file; `test_ruleTableParity`
// does the same for the allowlists (`mtxSelectors()` and the UA verdict per selector).
//
// WRITE:  PARITY_WRITE=1 forge test --match-path test/metatx/MetaTxParity.t.sol   (writes test/vectors/metatx-parity.json)
// REPLAY: forge test --match-path test/metatx/MetaTxParity.t.sol                   (compares every field except gas)
// GAS:    PARITY_GAS=1 forge test --match-path test/metatx/MetaTxParity.t.sol       (also compares gas: pre-split code only)
//
// DETERMINISM. Time, block number and chain id are fixed; the keys are fixed; every token is a CREATE clone made by a
// rig (the test plays the factory), so its address (and so every digest and every event emitter) does not depend on the
// bytecode of the implementation: it stays the same after the split. The cases run in one fixed order and each uses its
// own nonce lane. The file is one JSON object per line (a valid JSON array of cases), read back line by line.
//
// §3.8 (the one allowed difference after the split, owner 2026-10-27): the fee amount of a self-call is checked before
// the call. A case whose envelope breaks its fee rule carries `"expect":"fee-error-first"`. Its row holds the post-split
// outcome (Task 3): when the call fails too ("bothFail_*"), the revert is now the fee error instead of the call's; when the
// call alone would pass, the revert is the same fee error, but the self-call no longer runs, so the logs it emitted inside
// the reverted transaction (which `vm.recordLogs` keeps, a receipt never shows) are gone from `events`. Every other field
// of those rows is the pre-split one (`gas` included: the pre-split baseline). The replay checks that every marked row
// reverts with a fee error.
// =====================================================================================================================

/// One recorded case.
struct Rec {
    string kind;
    string entry;
    string path; // "addr" | "ua"
    string name;
    string expect; // "" or "fee-error-first"
    bool ok;
    bytes ret;
    bytes rev;
    string[] events;
    string[] dK;
    bytes32[] dV;
    string[] nK;
    uint256[] nV;
    string[] bK;
    uint256[] bV;
    uint256 gas;
}

/// One allowlist fact: kind × selector.
struct RuleRow {
    string kind;
    bytes4 sel;
    bool inList; // listed by `mtxSelectors()`
    uint8 feeClass;
    uint8 amountArg;
    bytes4 mtxRev; // the probe's revert selector through `mtxExecute` (0 = it did not revert)
    bytes4 uaRev; // the same through `uaExecute`
    bool mtxAllowed; // the probe through `mtxExecute` was not refused as `MtxSelectorNotAllowed`
    bool uaAllowed; // the probe through `uaExecute` was not refused as `MetaTxUnknownOp` (`_uaAllowed(sel)`)
}

/// A token under test, with the actors of its rig.
struct Tk {
    string kind;
    address t;
    uint256 pk; // signer
    address signer;
    uint256 payeePk;
    address payee;
    address feeTo;
    address relayer;
    bytes32 uaD; // a derived SIGNING UA with a ledger balance (0 = none)
    uint8 style; // 0: `burn` is the AMOUNT-class call, 1: `unwrap(uint256,address,uint256)`
    address und; // style 1: the sole leg
    address dex; // the contract that is `o.dex` of trade orders
    uint256 lane; // next free lane
    bytes32 oh; // trade cases: the order hash whose `pulled` / floor is recorded
}

struct H {
    string entry;
    string path;
    string name;
    string expect;
}

struct D {
    string[] n;
    bytes32[] v;
}

/// `o.dex` of the trade cases: only needs code.
contract ParityDex {
    receive() external payable {}
}

/// An ERC-1271 wallet (or the delegate of an EIP-7702 account): mode 0 accepts the ECDSA signature of `owner`, 1 reverts,
/// 2 answers a wrong magic value.
contract Mock1271 {
    address internal immutable OWNER;
    uint8 internal immutable MODE;

    constructor(address owner_, uint8 mode_) {
        (OWNER, MODE) = (owner_, mode_);
    }

    function isValidSignature(bytes32 h, bytes calldata sig) external view returns (bytes4) {
        if (MODE == 1) revert("wallet");
        if (MODE == 2) return 0xffffffff;
        (address r, ECDSA.RecoverError e,) = ECDSA.tryRecover(h, sig);
        return e == ECDSA.RecoverError.NoError && r == OWNER ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}

/// The file: the JSON of a case / a rule row, and the field-by-field comparison with the line read back.
abstract contract ParityIO is Test {
    string internal constant FILE = "./test/vectors/metatx-parity.json";

    /// Mismatches counted by this contract's comparisons.
    uint256 internal fails;
    /// The case list itself changed (a case added, removed or renamed): the lines are out of step, so the field
    /// comparison stops at the first such case.
    bool internal drifted;

    // ------------------------------------------------------------------ the JSON

    function _json(Rec memory r) internal pure returns (string memory) {
        string memory head = string.concat('{"kind":"', r.kind, '","entry":"', r.entry, '","path":"', r.path, '","case":"', r.name,
            '","expect":"', r.expect, '","ok":', r.ok ? "true" : "false", ',"ret":"', vm.toString(r.ret), '","revert":"',
            vm.toString(r.rev), '"');
        string memory ev = "[";
        for (uint256 i; i < r.events.length; ++i) ev = string.concat(ev, i == 0 ? '"' : ',"', r.events[i], '"');
        return string.concat(head, ',"events":', ev, '],"digests":', _hexMap(r.dK, r.dV), ',"nonces":', _decMap(r.nK, r.nV),
            ',"balances":', _decMap(r.bK, r.bV), ',"gas":"', vm.toString(r.gas), '"}');
    }

    function _jsonRule(RuleRow memory r) internal pure returns (string memory) {
        return string.concat('{"rule":1,"kind":"', r.kind, '","sel":"', vm.toString(abi.encodePacked(r.sel)), '","inList":', r.inList ? "true" : "false",
            ',"feeClass":', vm.toString(uint256(r.feeClass)), ',"amountArg":', vm.toString(uint256(r.amountArg)),
            ',"mtxRev":"', vm.toString(abi.encodePacked(r.mtxRev)), '","uaRev":"', vm.toString(abi.encodePacked(r.uaRev)),
            '","mtxAllowed":', r.mtxAllowed ? "true" : "false", ',"uaAllowed":', r.uaAllowed ? "true" : "false", "}");
    }

    function _hexMap(string[] memory n, bytes32[] memory v) internal pure returns (string memory o) {
        o = "{";
        for (uint256 i; i < n.length; ++i) o = string.concat(o, i == 0 ? '"' : ',"', n[i], '":"', vm.toString(v[i]), '"');
        return string.concat(o, "}");
    }

    function _decMap(string[] memory n, uint256[] memory v) internal pure returns (string memory o) {
        o = "{";
        for (uint256 i; i < n.length; ++i) o = string.concat(o, i == 0 ? '"' : ',"', n[i], '":"', vm.toString(v[i]), '"');
        return string.concat(o, "}");
    }

    // ------------------------------------------------------------------ the replay: every field, with a clear message


    /// The next line without its trailing comma.
    function _next(bool) internal returns (string memory) {
        return _strip(bytes(vm.readLine(FILE)));
    }

    function _strip(bytes memory b) internal pure returns (string memory) {
        if (b.length != 0 && b[b.length - 1] == ",") assembly ("memory-safe") { mstore(b, sub(mload(b), 1)) }
        return string(b);
    }

    function _bad(string memory id, string memory field, string memory was, string memory now_) internal {
        ++fails;
        console2.log(string.concat("PARITY MISMATCH [", id, "] field ", field, ": fixture=", was, " now=", now_));
    }

    function _eq(string memory id, string memory field, string memory was, string memory now_) internal {
        if (keccak256(bytes(was)) != keccak256(bytes(now_))) _bad(id, field, was, now_);
    }

    function _cmpCase(string memory line, Rec memory r, uint256 i) internal {
        if (drifted) return;
        string memory id = string.concat(r.kind, "/", r.entry, "/", r.path, "/", r.name);
        string memory fid = string.concat(vm.parseJsonString(line, ".kind"), "/", vm.parseJsonString(line, ".entry"), "/",
            vm.parseJsonString(line, ".path"), "/", vm.parseJsonString(line, ".case"));
        if (keccak256(bytes(id)) != keccak256(bytes(fid))) {
            drifted = true;
            _bad(string.concat("#", vm.toString(i)), "CASE LIST DRIFT (the fixture has another case here: a case was added, removed or renamed, not a behaviour change; regenerate with PARITY_WRITE=1 once reviewed)", fid, id);
            return;
        }
        _eq(id, "expect", vm.parseJsonString(line, ".expect"), r.expect);
        if (keccak256(bytes(r.expect)) == keccak256("fee-error-first")) {
            bytes4 s = r.rev.length >= 4 ? bytes4(r.rev) : bytes4(0);
            if (r.ok || (s != FeePolicy.FeeExceedsCap.selector && s != FeePolicy.FeeRecipientRequired.selector
                    && s != IUALedger.UAPoolNotPayable.selector)) {
                _bad(id, "expect", "fee-error-first: a fee error", vm.toString(r.rev));
            }
        }
        if (vm.parseJsonBool(line, ".ok") != r.ok) _bad(id, "ok", vm.toString(vm.parseJsonBool(line, ".ok")), vm.toString(r.ok));
        _eq(id, "ret", vm.parseJsonString(line, ".ret"), vm.toString(r.ret));
        _eq(id, "revert", vm.parseJsonString(line, ".revert"), vm.toString(r.rev));
        _cmpEvents(line, r, id);
        _cmpMap(line, ".digests", id, "digests", r.dK, _hexOf(r.dV));
        _cmpMap(line, ".nonces", id, "nonces", r.nK, _decOf(r.nV));
        _cmpMap(line, ".balances", id, "balances", r.bK, _decOf(r.bV));
        // gas is compared only with PARITY_GAS=1: after the split it moves by design (spec §5), the run that checks it
        // is the one on the pre-split code and the Task 5 budget tests
        if (vm.envOr("PARITY_GAS", false)) _eq(id, "gas", vm.parseJsonString(line, ".gas"), vm.toString(r.gas));
    }

    function _cmpEvents(string memory line, Rec memory r, string memory id) internal {
        string[] memory was = vm.parseJsonStringArray(line, ".events");
        if (was.length != r.events.length) {
            _bad(id, "events.length", vm.toString(was.length), vm.toString(r.events.length));
            return;
        }
        for (uint256 j; j < was.length; ++j) _eq(id, string.concat("events[", vm.toString(j), "]"), was[j], r.events[j]);
    }

    function _hexOf(bytes32[] memory v) internal pure returns (string[] memory o) {
        o = new string[](v.length);
        for (uint256 i; i < v.length; ++i) o[i] = vm.toString(v[i]);
    }

    function _decOf(uint256[] memory v) internal pure returns (string[] memory o) {
        o = new string[](v.length);
        for (uint256 i; i < v.length; ++i) o[i] = vm.toString(v[i]);
    }

    /// An object of name → string: same key set, same values.
    function _cmpMap(string memory line, string memory path, string memory id, string memory field, string[] memory ks,
        string[] memory vs) internal
    {
        string[] memory was = vm.parseJsonKeys(line, path);
        if (was.length != ks.length) {
            _bad(id, string.concat(field, ".keys"), vm.toString(was.length), vm.toString(ks.length));
            return;
        }
        for (uint256 i; i < ks.length; ++i) {
            bool found;
            for (uint256 j; j < was.length; ++j) if (keccak256(bytes(was[j])) == keccak256(bytes(ks[i]))) found = true;
            if (!found) {
                _bad(id, string.concat(field, ".", ks[i]), "(absent)", vs[i]);
                continue;
            }
            _eq(id, string.concat(field, ".", ks[i]), vm.parseJsonString(line, string.concat(path, ".", ks[i])), vs[i]);
        }
    }

    function _cmpRule(string memory line, RuleRow memory r, uint256 i) internal {
        if (drifted) return;
        string memory id = string.concat(r.kind, "/", vm.toString(abi.encodePacked(r.sel)));
        string memory fid = string.concat(vm.parseJsonString(line, ".kind"), "/", vm.parseJsonString(line, ".sel"));
        if (keccak256(bytes(id)) != keccak256(bytes(fid))) {
            _bad(string.concat("rule#", vm.toString(i)), "identity", fid, id);
            return;
        }
        if (vm.parseJsonBool(line, ".inList") != r.inList) _bad(id, "inList", vm.toString(vm.parseJsonBool(line, ".inList")), vm.toString(r.inList));
        _eq(id, "feeClass", vm.toString(vm.parseJsonUint(line, ".feeClass")), vm.toString(uint256(r.feeClass)));
        _eq(id, "amountArg", vm.toString(vm.parseJsonUint(line, ".amountArg")), vm.toString(uint256(r.amountArg)));
        _eq(id, "mtxRev", vm.parseJsonString(line, ".mtxRev"), vm.toString(abi.encodePacked(r.mtxRev)));
        _eq(id, "uaRev", vm.parseJsonString(line, ".uaRev"), vm.toString(abi.encodePacked(r.uaRev)));
        if (vm.parseJsonBool(line, ".mtxAllowed") != r.mtxAllowed) _bad(id, "mtxAllowed", vm.toString(vm.parseJsonBool(line, ".mtxAllowed")), vm.toString(r.mtxAllowed));
        if (vm.parseJsonBool(line, ".uaAllowed") != r.uaAllowed) _bad(id, "uaAllowed", vm.toString(vm.parseJsonBool(line, ".uaAllowed")), vm.toString(r.uaAllowed));
    }
}

interface IRig {
    function run(uint256 i, uint256 step) external;
    function steps() external view returns (uint256);
    function ruleTable(bytes4[] calldata probe) external returns (RuleRow[] memory);
    function count() external view returns (uint256);
    function selectors() external view returns (bytes4[] memory);
    function emitted() external view returns (uint256);
    function failures() external view returns (uint256);
    function isDrifted() external view returns (bool);
    function setup() external view returns (string[] memory, address[] memory, bytes32[] memory);
}

abstract contract ParityCases is ParityIO {
    uint32 internal constant P_RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint32 internal constant P_RF = MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
    uint32 internal constant P_PCT = MetaTxLib.MODE_FEE_PERCENT;
    uint32 internal constant P_FIX = MetaTxLib.MODE_FEE_FIXED;
    uint256 internal constant P_T0 = 1_800_000_000;
    uint256 internal constant P_VU = P_T0 + 300;
    uint256 internal constant P_BLOCK = 1_000;
    address internal constant P_UAP = MetaTxLib.UA_POOL;
    address internal constant P_SHP = MetaTxLib.SHIELD_POOL;
    uint256 internal constant P_BIG = 1 << 200;

    Tk[] internal tks;
    /// Cases emitted so far (written to / compared with the file as they are produced: no storage per case).
    uint256 internal nEmit;

    function count() external view returns (uint256) {
        return tks.length;
    }

    /// The number of steps of a token's run: each step is one top-level call, so each stays under the per-transaction
    /// gas cap (EIP-7825) however heavy the rig's kind-specific cases are.
    uint256 internal constant P_STEPS = 10;

    function steps() external pure returns (uint256) {
        return P_STEPS;
    }

    /// Step `step` of token `i`: the generic matrix in eight parts, the rig kind-specific cases, the contract signers. Every step has
    /// its own range of lanes.
    function run(uint256 i, uint256 step) external {
        Tk memory k = tks[i];
        k.lane = 1000 + step * 1000;
        if (k.style == 2) {
            if (step == 0) _pLedgerOff(k);
            return;
        }
        if (step == 0) _pMtxExecute(k);
        else if (step == 1) {
            _pMtxExecuteMisc(k);
            _pMtxBatch(k);
        } else if (step == 2) _pUaExecute(k);
        else if (step == 3) _pUaBatch(k);
        else if (step == 4) _pTypedAddr(k);
        else if (step == 5) _pTypedUa(k);
        else if (step == 6) _pReceiverPays(k);
        else if (step == 7) _pTrade(k);
        else if (step == 8) _pExtras(k);
        else if (step == 9) _pSigners(k);
    }

    function ruleTable(bytes4[] calldata probe) external returns (RuleRow[] memory) {
        return _pRules(probe);
    }

    /// Kind-specific cases (the confidential ops); none by default.
    function _pExtras(Tk memory) internal virtual {}

    function emitted() external view returns (uint256) {
        return nEmit;
    }

    function failures() external view returns (uint256) {
        return fails;
    }

    function isDrifted() external view returns (bool) {
        return drifted;
    }

    /// Each token's kind, address and domain hash (the setup the cases are written against).
    function setup() external view returns (string[] memory kinds, address[] memory toks, bytes32[] memory doms) {
        kinds = new string[](tks.length);
        toks = new address[](tks.length);
        doms = new bytes32[](tks.length);
        for (uint256 i; i < tks.length; ++i) {
            (kinds[i], toks[i]) = (tks[i].kind, tks[i].t);
            (, string memory n, string memory v, uint256 cid, address vc, bytes32 salt,) = MetaTokenBase(tks[i].t).eip712Domain();
            doms[i] = keccak256(abi.encode(keccak256(bytes(n)), keccak256(bytes(v)), cid, vc, salt));
        }
    }

    /// One case: written to the file in write mode, else compared with the next line of it.
    function _pEmit(Rec memory r) internal {
        ++nEmit;
        if (vm.envOr("PARITY_WRITE", false)) vm.writeLine(FILE, string.concat(_json(r), ","));
        else _cmpCase(_next(false), r, nEmit - 1);
    }

    /// The union of the allowlists of this rig's tokens.
    function selectors() external view returns (bytes4[] memory out) {
        bytes4[] memory acc = new bytes4[](256);
        uint256 n;
        for (uint256 i; i < tks.length; ++i) {
            (bytes4[] memory s,,) = MetaTokenBase(tks[i].t).mtxSelectors();
            for (uint256 j; j < s.length; ++j) {
                bool seen;
                for (uint256 q; q < n; ++q) if (acc[q] == s[j]) seen = true;
                if (!seen) acc[n++] = s[j];
            }
        }
        out = new bytes4[](n);
        for (uint256 i; i < n; ++i) out[i] = acc[i];
    }

    // ------------------------------------------------------------------ the rig supplies the signatures of derived ids

    /// `auth` of a derived SIGNING UA `from` (never a native id) under `purpose` over `digest`.
    function _pDerivedAuth(Tk memory k, bytes32 purpose, bytes32 digest) internal view virtual returns (bytes memory);

    /// A WELL-FORMED `auth` of the derived UA that its verifier rejects (so a real auth-failure selector is pinned).
    function _pBadDerived(Tk memory k, bytes32 purpose, bytes32 digest) internal view virtual returns (bytes memory);

    /// A wrong `auth` for the signer id `from` (a native id: the payee's key; the derived UA: `_pBadDerived`).
    function _pBadAuth(Tk memory k, bytes32 from, bytes32 purpose, bytes32 digest) internal view returns (bytes memory) {
        if (from == k.uaD && from != 0) return _pBadDerived(k, purpose, digest);
        return _pEcdsa(k.payeePk, digest);
    }

    function _pEcdsa(uint256 pk, bytes32 h) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r, s, v);
    }

    /// `auth` for the id `from` under `purpose`: a native id signs the digest itself, a derived one through the rig.
    function _pAuth(Tk memory k, bytes32 from, bytes32 purpose, bytes32 digest) internal view returns (bytes memory) {
        if (from == MetaTxLib.pad(k.signer)) return _pEcdsa(k.pk, digest);
        if (from == MetaTxLib.pad(k.payee)) return _pEcdsa(k.payeePk, digest);
        if (from == k.uaD) return _pDerivedAuth(k, purpose, digest);
        return hex"deadbeef";
    }

    // ------------------------------------------------------------------ recording

    /// Lane 0 in a builder means "the next free lane".
    function _pLn(Tk memory k) internal pure returns (uint256) {
        return k.lane++;
    }

    function _pH(string memory entry, string memory path, string memory name) internal pure returns (H memory) {
        return H(entry, path, name, "");
    }

    function _pD(string memory n, bytes32 v) internal pure returns (D memory d) {
        d.n = new string[](1);
        d.v = new bytes32[](1);
        (d.n[0], d.v[0]) = (n, v);
    }

    function _pD2(string memory n, bytes32 v, string memory n2, bytes32 v2) internal pure returns (D memory d) {
        d.n = new string[](2);
        d.v = new bytes32[](2);
        (d.n[0], d.v[0]) = (n, v);
        (d.n[1], d.v[1]) = (n2, v2);
    }

    function _pL(uint256 a) internal pure returns (uint256[] memory l) {
        l = new uint256[](1);
        l[0] = a;
    }

    function _pL2(uint256 a, uint256 b) internal pure returns (uint256[] memory l) {
        l = new uint256[](2);
        (l[0], l[1]) = (a, b);
    }

    function _pCool(Tk memory k) internal {
        vm.cool(k.t);
        vm.cool(k.signer);
        vm.cool(k.payee);
        vm.cool(k.feeTo);
        vm.cool(k.relayer);
        vm.cool(k.dex);
        vm.cool(MetaTokenBase(k.t).registry());
        if (k.und != address(0)) vm.cool(k.und);
    }

    /// The one top-level call of a case, recorded.
    function _pRec(Tk memory k, H memory h, address caller, bytes memory cd, D memory d, uint256[] memory lanes) internal {
        _pCool(k);
        vm.getRecordedLogs();
        vm.prank(caller);
        // the gas of the call alone: read around the CALL opcode, so the copy of the return data (whose memory
        // expansion depends on how much memory the rig has used so far) is not in it
        address t = k.t;
        uint256 g0;
        uint256 used;
        bool ok;
        assembly ("memory-safe") {
            g0 := gas()
            ok := call(gas(), t, 0, add(cd, 32), mload(cd), 0, 0)
            used := sub(g0, gas())
        }
        bytes memory out;
        assembly ("memory-safe") {
            out := mload(0x40)
            mstore(out, returndatasize())
            returndatacopy(add(out, 32), 0, returndatasize())
            mstore(0x40, and(add(add(out, add(32, returndatasize())), 31), not(31)))
        }
        _pEmit(_pMk(k, h, ok, out, used, vm.getRecordedLogs(), d, lanes));
    }

    function _pMk(
        Tk memory k, H memory h, bool ok, bytes memory out, uint256 used, Vm.Log[] memory ls, D memory d,
        uint256[] memory lanes
    ) internal view returns (Rec memory r) {
        (r.kind, r.entry, r.path, r.name, r.expect) = (k.kind, h.entry, h.path, h.name, h.expect);
        r.ok = ok;
        if (ok) r.ret = out;
        else r.rev = out;
        r.gas = used;
        (r.dK, r.dV) = (d.n, d.v);
        r.events = new string[](ls.length);
        for (uint256 i; i < ls.length; ++i) {
            string memory t = "";
            for (uint256 j; j < ls[i].topics.length; ++j) {
                t = string.concat(t, j == 0 ? "" : ",", vm.toString(ls[i].topics[j]));
            }
            string memory e = ls[i].emitter == k.t ? "T" : vm.toString(ls[i].emitter);
            r.events[i] = string.concat(e, "|", t, "|", vm.toString(ls[i].data));
        }
        (r.nK, r.nV) = _pNonces(k, lanes);
        (r.bK, r.bV) = _pBalances(k);
    }

    /// The nonce of every lane the case names (signer, and the derived UA when the rig has one); trade cases add the
    /// order's `pulled` and the floor `minNonce` of each lane.
    function _pNonces(Tk memory k, uint256[] memory lanes) internal view returns (string[] memory n, uint256[] memory v) {
        uint256 per = k.uaD == 0 ? 1 : 2;
        uint256 base = lanes.length * per;
        uint256 extra = k.oh == 0 ? 0 : 1 + base;
        n = new string[](base + extra);
        v = new uint256[](base + extra);
        MetaTokenBase t = MetaTokenBase(k.t);
        for (uint256 i; i < lanes.length; ++i) {
            n[i * per] = string.concat("nS_", vm.toString(lanes[i]));
            v[i * per] = t.mtxNonce(k.signer, lanes[i]);
            if (per == 2) {
                n[i * per + 1] = string.concat("nD_", vm.toString(lanes[i]));
                v[i * per + 1] = t.uaNonce(k.uaD, lanes[i]);
            }
        }
        if (extra == 0) return (n, v);
        (n[base], v[base]) = ("pulled", t.pulled(k.oh));
        for (uint256 i; i < lanes.length; ++i) {
            n[base + 1 + i * per] = string.concat("mnS_", vm.toString(lanes[i]));
            v[base + 1 + i * per] = t.minNonce(k.signer, lanes[i]);
            if (per == 2) {
                n[base + 2 + i * per] = string.concat("mnD_", vm.toString(lanes[i]));
                v[base + 2 + i * per] = t.uaMinNonce(k.uaD, lanes[i]);
            }
        }
    }

    function _pBalances(Tk memory k) internal view returns (string[] memory n, uint256[] memory v) {
        n = new string[](11);
        v = new uint256[](11);
        MetaTokenBase t = MetaTokenBase(k.t);
        (n[0], v[0]) = ("signer", t.balanceOf(k.signer));
        (n[1], v[1]) = ("payee", t.balanceOf(k.payee));
        (n[2], v[2]) = ("feeTo", t.balanceOf(k.feeTo));
        (n[3], v[3]) = ("relayer", t.balanceOf(k.relayer));
        (n[4], v[4]) = ("dex", t.balanceOf(k.dex));
        (n[5], v[5]) = ("token", t.balanceOf(k.t));
        (n[6], v[6]) = ("UA_POOL", t.balanceOf(P_UAP));
        (n[7], v[7]) = ("SHIELD_POOL", t.balanceOf(P_SHP));
        (n[8], v[8]) = ("uaD", k.uaD == 0 ? 0 : t.balanceOfUA(k.uaD));
        (n[9], v[9]) = ("supply", t.totalSupply());
        (n[10], v[10]) = ("reserve", k.und == address(0) ? 0 : MetaTokenBase(k.und).balanceOf(k.t));
    }

    // ------------------------------------------------------------------ builders

    function _pAmt(Tk memory k, uint256 amount) internal view returns (bytes memory) {
        if (k.style != 1) return abi.encodeCall(NoUnderlyingToken.burn, (amount));
        return abi.encodeWithSignature("unwrap(uint256,address,uint256)", amount, k.payee, uint256(0));
    }

    function _pCancel(uint256 batch) internal pure returns (bytes memory) {
        return abi.encodeCall(IMetaTx.cancelNonce, (batch));
    }

    function _pMt(Tk memory k, bytes memory data, uint256 lane, uint32 mode, uint256 fee, address fr)
        internal view returns (MetaTxLib.MetaTransaction memory)
    {
        if (lane == 0) lane = k.lane++;
        return MetaTxLib.MetaTransaction(k.signer, data, lane, 0, P_VU, mode, k.relayer, fee, fr);
    }

    function _pUm(Tk memory k, bytes32 from, bytes memory data, uint256 lane, uint32 mode, uint256 fee, address fr)
        internal view returns (MetaTxLib.UAMetaTransaction memory)
    {
        if (lane == 0) lane = k.lane++;
        return MetaTxLib.UAMetaTransaction(from, data, lane, 0, P_VU, mode, k.relayer, fee, fr);
    }

    function _pTr(Tk memory k, address to, uint256 value, bytes32 ref, uint256 lane, uint32 mode, uint256 fee, address fr)
        internal view returns (MetaTxLib.MetaTransfer memory)
    {
        if (lane == 0) lane = k.lane++;
        return MetaTxLib.MetaTransfer(k.signer, to, value, ref, lane, 0, P_VU, mode, k.relayer, fee, fr);
    }

    function _pUt(
        Tk memory k, bytes32 from, bytes32 to, uint256 value, bytes32 ref, uint256 lane, uint32 mode, uint256 fee,
        address fr
    ) internal view returns (MetaTxLib.UAMetaTransfer memory) {
        if (lane == 0) lane = k.lane++;
        return MetaTxLib.UAMetaTransfer(from, to, value, ref, lane, 0, P_VU, mode, k.relayer, fee, fr);
    }

    function _pSgM(Tk memory k, MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        return _pEcdsa(k.pk, MetaTokenBase(k.t).mtxDigest(m));
    }

    function _pSgT(Tk memory k, MetaTxLib.MetaTransfer memory t) internal view returns (bytes memory) {
        return _pEcdsa(k.pk, MetaTokenBase(k.t).mtxTransferDigest(t));
    }

    function _pAuM(Tk memory k, MetaTxLib.UAMetaTransaction memory m) internal view returns (bytes memory) {
        return _pAuth(k, m.from, UAKinds.PURPOSE_METATX, MetaTokenBase(k.t).uaDigest(m));
    }

    function _pAuT(Tk memory k, MetaTxLib.UAMetaTransfer memory t) internal view returns (bytes memory) {
        return _pAuth(k, t.from, UAKinds.PURPOSE_METATX, MetaTokenBase(k.t).uaTransferDigest(t));
    }

    // ------------------------------------------------------------------ one case per entry shape

    /// `mtxExecute` / `executeMetaTransaction` / `mtxExecuteWithFee` on `m`.
    function _pMx(Tk memory k, string memory entry, string memory name, string memory expect, bytes4 sel,
        MetaTxLib.MetaTransaction memory m, bytes memory sig, address caller) internal
    {
        H memory h = H(entry, "addr", name, expect);
        _pRec(k, h, caller, abi.encodeWithSelector(sel, m, sig), _pD("mtxDigest", MetaTokenBase(k.t).mtxDigest(m)), _pL(m.batch));
    }

    function _pX(Tk memory k, string memory name, MetaTxLib.MetaTransaction memory m) internal {
        _pMx(k, "mtxExecute", name, "", IMetaTx.mtxExecute.selector, m, _pSgM(k, m), k.relayer);
    }

    function _pUx(Tk memory k, string memory name, string memory expect, MetaTxLib.UAMetaTransaction memory m,
        bytes memory auth, address caller) internal
    {
        H memory h = H("uaExecute", "ua", name, expect);
        _pRec(k, h, caller, abi.encodeCall(IUALedger.uaExecute, (m, auth)),
            _pD("uaDigest", MetaTokenBase(k.t).uaDigest(m)), _pL(m.batch));
    }

    function _pU(Tk memory k, string memory name, MetaTxLib.UAMetaTransaction memory m) internal {
        _pUx(k, name, "", m, _pAuM(k, m), k.relayer);
    }

    /// `_pX` / `_pU` of a case whose fee rule breaks (§3.8, `"fee-error-first"`).
    function _pXf(Tk memory k, string memory name, MetaTxLib.MetaTransaction memory m) internal {
        _pMx(k, "mtxExecute", name, "fee-error-first", IMetaTx.mtxExecute.selector, m, _pSgM(k, m), k.relayer);
    }

    function _pUf(Tk memory k, string memory name, MetaTxLib.UAMetaTransaction memory m) internal {
        _pUx(k, name, "fee-error-first", m, _pAuM(k, m), k.relayer);
    }

    function _pXt(Tk memory k, string memory name, MetaTxLib.MetaTransfer memory t) internal {
        _pXtS(k, name, t, _pSgT(k, t), k.relayer);
    }

    function _pXtS(Tk memory k, string memory name, MetaTxLib.MetaTransfer memory t, bytes memory sig, address caller)
        internal
    {
        _pRec(k, _pH("mtxExecuteTransfer", "addr", name), caller, abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (t, sig)),
            _pD("mtxTransferDigest", MetaTokenBase(k.t).mtxTransferDigest(t)), _pL(t.batch));
    }

    function _pUt2(Tk memory k, string memory name, MetaTxLib.UAMetaTransfer memory t) internal {
        _pUtS(k, name, t, _pAuT(k, t), k.relayer);
    }

    function _pUtS(Tk memory k, string memory name, MetaTxLib.UAMetaTransfer memory t, bytes memory auth, address caller)
        internal
    {
        _pRec(k, _pH("uaExecuteTransfer", "ua", name), caller, abi.encodeCall(IUALedger.uaExecuteTransfer, (t, auth)),
            _pD("uaTransferDigest", MetaTokenBase(k.t).uaTransferDigest(t)), _pL(t.batch));
    }

    // =================================================================================================================
    // the generic matrix: every kind, both relay paths
    // =================================================================================================================

    function _pMtxExecute(Tk memory k) internal {
        MetaTxLib.MetaTransaction memory m;
        // success
        _pX(k, "ok_cancelNonce", _pMt(k, _pCancel(7), 0, P_RR, 0, address(0)));
        _pX(k, "ok_cancelNonce_openMode", _pMt(k, _pCancel(8), 0, 0, 0, address(0)));
        _pX(k, "ok_fixedFee_boundRecipient", _pMt(k, _pCancel(7), 0, P_RR | P_RF | P_FIX, 5, k.feeTo));
        _pX(k, "ok_fixedFee_defaultRecipient", _pMt(k, _pCancel(7), 0, P_RR | P_FIX, 3, address(0)));
        _pX(k, "ok_amountCall_noFee", _pMt(k, _pAmt(k, 100_000), 0, P_RR, 0, address(0)));
        _pX(k, "ok_amountCall_percentFee", _pMt(k, _pAmt(k, 100_000), 0, P_RR | P_PCT, 1_000, address(0)));
        _pX(k, "ok_amountCall_fixedFee", _pMt(k, _pAmt(k, 100_000), 0, P_RR | P_RF | P_FIX, 10, k.feeTo));
        // step 1: envelope
        m = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        _pMx(k, "mtxExecute", "err_unauthorizedRelayer", "", IMetaTx.mtxExecute.selector, m, _pSgM(k, m), k.payee);
        m = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        m.validUntil = P_T0 - 1;
        _pX(k, "err_expired", m);
        _pX(k, "err_unknownMode_flagBit", _pMt(k, _pCancel(7), 0, 0x04, 0, address(0)));
        _pX(k, "err_unknownMode_feeNibble", _pMt(k, _pCancel(7), 0, 0x30, 0, address(0)));
        m = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        m.nonce = 3;
        _pX(k, "err_badNonce", m);
        m = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        m.from = k.t;
        _pX(k, "err_selfSender", m);
        // step 2: signature
        m = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        _pMx(k, "mtxExecute", "err_badSignature", "", IMetaTx.mtxExecute.selector, m, _pEcdsa(k.payeePk, MetaTokenBase(k.t).mtxDigest(m)), k.relayer);
        // step 3: shape, allowlist, fee class
        _pX(k, "err_shortData", _pMt(k, hex"0102", 0, P_RR, 0, address(0)));
        _pX(k, "err_emptyData", _pMt(k, "", 0, P_RR, 0, address(0)));
        _pX(k, "err_selectorNotAllowed_transfer", _pMt(k, abi.encodeCall(IERC20.transfer, (k.payee, 1)), 0, P_RR, 0, address(0)));
        _pX(k, "err_selectorNotAllowed_unknown", _pMt(k, hex"deadbeef", 0, P_RR, 0, address(0)));
        _pX(k, "err_dataShape_longCancel", _pMt(k, abi.encodePacked(_pCancel(7), uint8(0)), 0, P_RR, 0, address(0)));
        _pX(k, "err_dataShape_shortAmount", _pMt(k, abi.encodePacked(bytes4(_pAmt(k, 1)), bytes1(0x01)), 0, P_RR | P_PCT, 1, address(0)));
        _pX(k, "err_feeClass_absolutePercent", _pMt(k, _pCancel(7), 0, P_RR | P_PCT, 100, address(0)));
        // step 4: nonce used once
        m = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        bytes memory sg = _pSgM(k, m);
        vm.prank(k.relayer);
        MetaTokenBase(k.t).mtxExecute(m, sg);
        _pMx(k, "mtxExecute", "err_replay", "", IMetaTx.mtxExecute.selector, m, sg, k.relayer);
        // the fee rule (amount checked in step 3, before the call, §3.8; moved in step 6)
        _pXf(k, "err_feeExceedsCap_percent", _pMt(k, _pAmt(k, 100_000), 0, P_RR | P_PCT, 20_000, address(0)));
        _pXf(k, "err_feeExceedsCap_fixed", _pMt(k, _pAmt(k, 100_000), 0, P_RR | P_FIX, 1_001, address(0)));
        _pXf(k, "err_feeRecipientUaPool", _pMt(k, _pCancel(7), 0, P_RR | P_RF | P_FIX, 5, P_UAP));
        _pX(k, "err_feeUnpayable_absoluteClass", _pMt(k, _pCancel(7), 0, P_RR | P_FIX, type(uint128).max, address(0)));
        _pX(k, "err_feeUnpayable_amountCall", _pMt(k, _pAmt(k, MetaTokenBase(k.t).balanceOf(k.signer)), 0, P_RR | P_PCT, 1_000, address(0)));
        // the call itself reverts
        _pX(k, "err_callReverts", _pMt(k, _pAmt(k, P_BIG), 0, P_RR, 0, address(0)));
        _pX(k, "err_callReverts_feeOk", _pMt(k, _pAmt(k, P_BIG), 0, P_RR | P_FIX, 0, address(0)));
        // both fail: the fee rule is broken AND the call reverts (§3.8: the fee error wins after the split)
        m = _pMt(k, _pAmt(k, P_BIG), 0, P_RR | P_PCT, 20_000, address(0));
        _pMx(k, "mtxExecute", "bothFail_feeExceedsCap_callReverts", "fee-error-first", IMetaTx.mtxExecute.selector, m, _pSgM(k, m), k.relayer);
        m = _pMt(k, _pAmt(k, P_BIG), 0, P_RR | P_RF | P_PCT, 1_000, P_UAP);
        _pMx(k, "mtxExecute", "bothFail_feeRecipientUaPool_callReverts", "fee-error-first", IMetaTx.mtxExecute.selector, m, _pSgM(k, m), k.relayer);
        // not a fee fault (1,001 is under 1 % of P_BIG): only the call fails, unmarked (T3; the name is the fixture's)
        m = _pMt(k, _pAmt(k, P_BIG), 0, P_RR | P_FIX, 1_001, address(0));
        _pMx(k, "mtxExecute", "bothFail_feeExceedsCapFixed_callReverts", "", IMetaTx.mtxExecute.selector, m, _pSgM(k, m), k.relayer);
    }

    function _pMtxExecuteMisc(Tk memory k) internal {
        _pTwoFault(k);
        _pBothFailMore(k);
        MetaTxLib.MetaTransaction memory m = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        _pMx(k, "executeMetaTransaction", "ok_cancelNonce", "", IMetaTx.executeMetaTransaction.selector, m, _pSgM(k, m), k.relayer);
        m = _pMt(k, _pCancel(7), 0, P_RR | P_FIX, 4, address(0));
        _pMx(k, "executeMetaTransaction", "ok_fixedFee", "", IMetaTx.executeMetaTransaction.selector, m, _pSgM(k, m), k.relayer);
        m = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        m.nonce = 2;
        _pMx(k, "executeMetaTransaction", "err_badNonce", "", IMetaTx.executeMetaTransaction.selector, m, _pSgM(k, m), k.relayer);
        m = _pMt(k, _pAmt(k, P_BIG), 0, P_RR | P_PCT, 20_000, address(0));
        _pMx(k, "executeMetaTransaction", "bothFail_feeExceedsCap_callReverts", "fee-error-first", IMetaTx.executeMetaTransaction.selector, m, _pSgM(k, m), k.relayer);
        // mtxExecuteWithFee
        m = _pMt(k, _pCancel(7), 0, P_RR | P_RF | P_FIX, 5, k.feeTo);
        _pMx(k, "mtxExecuteWithFee", "ok_fixedFee", "", MetaTokenBase.mtxExecuteWithFee.selector, m, _pSgM(k, m), k.relayer);
        m = _pMt(k, _pAmt(k, 100_000), 0, P_RR | P_PCT, 1_000, address(0));
        _pMx(k, "mtxExecuteWithFee", "ok_percentFee", "", MetaTokenBase.mtxExecuteWithFee.selector, m, _pSgM(k, m), k.relayer);
        m = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        _pMx(k, "mtxExecuteWithFee", "err_modeShape_noFeeNibble", "", MetaTokenBase.mtxExecuteWithFee.selector, m, _pSgM(k, m), k.relayer);
    }

    function _pMtxBatch(Tk memory k) internal {
        bytes[] memory sg = new bytes[](2);
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](2);
        uint256 l0 = _pLn(k);
        uint256 l1 = _pLn(k);
        ms[0] = _pMt(k, _pCancel(7), l0, P_RR, 0, address(0));
        ms[1] = _pMt(k, _pAmt(k, 1_000), l1, P_RR | P_FIX, 2, k.feeTo);
        sg[0] = _pSgM(k, ms[0]);
        sg[1] = _pSgM(k, ms[1]);
        H memory h = _pH("mtxBatch", "addr", "ok_two");
        _pRec(k, h, k.relayer, abi.encodeCall(IMetaTx.mtxBatch, (ms, sg)),
            _pD2("mtxDigest0", MetaTokenBase(k.t).mtxDigest(ms[0]), "mtxDigest1", MetaTokenBase(k.t).mtxDigest(ms[1])), _pL2(l0, l1));
        // atomic: the second item's signature is the first's
        l0 = _pLn(k);
        l1 = _pLn(k);
        ms[0] = _pMt(k, _pCancel(7), l0, P_RR, 0, address(0));
        ms[1] = _pMt(k, _pCancel(7), l1, P_RR, 0, address(0));
        sg[0] = _pSgM(k, ms[0]);
        sg[1] = sg[0];
        h = _pH("mtxBatch", "addr", "err_atomic_secondBadSignature");
        _pRec(k, h, k.relayer, abi.encodeCall(IMetaTx.mtxBatch, (ms, sg)),
            _pD2("mtxDigest0", MetaTokenBase(k.t).mtxDigest(ms[0]), "mtxDigest1", MetaTokenBase(k.t).mtxDigest(ms[1])), _pL2(l0, l1));
        // an item whose selector is not allowlisted
        l0 = _pLn(k);
        l1 = _pLn(k);
        ms[0] = _pMt(k, _pCancel(7), l0, P_RR, 0, address(0));
        ms[1] = _pMt(k, hex"deadbeef", l1, P_RR, 0, address(0));
        sg[0] = _pSgM(k, ms[0]);
        sg[1] = _pSgM(k, ms[1]);
        h = _pH("mtxBatch", "addr", "err_itemSelectorNotAllowed");
        _pRec(k, h, k.relayer, abi.encodeCall(IMetaTx.mtxBatch, (ms, sg)),
            _pD2("mtxDigest0", MetaTokenBase(k.t).mtxDigest(ms[0]), "mtxDigest1", MetaTokenBase(k.t).mtxDigest(ms[1])), _pL2(l0, l1));
        // the second item breaks its fee rule (refused before its call, §3.8; the whole batch reverts either way)
        l0 = _pLn(k);
        l1 = _pLn(k);
        ms[0] = _pMt(k, _pCancel(7), l0, P_RR, 0, address(0));
        ms[1] = _pMt(k, _pAmt(k, 1_000), l1, P_RR | P_PCT, 20_000, address(0));
        sg[0] = _pSgM(k, ms[0]);
        sg[1] = _pSgM(k, ms[1]);
        h = H("mtxBatch", "addr", "err_itemFeeExceedsCap", "fee-error-first");
        _pRec(k, h, k.relayer, abi.encodeCall(IMetaTx.mtxBatch, (ms, sg)),
            _pD2("mtxDigest0", MetaTokenBase(k.t).mtxDigest(ms[0]), "mtxDigest1", MetaTokenBase(k.t).mtxDigest(ms[1])), _pL2(l0, l1));
        // shape
        h = _pH("mtxBatch", "addr", "err_empty");
        _pRec(k, h, k.relayer, abi.encodeCall(IMetaTx.mtxBatch, (new MetaTxLib.MetaTransaction[](0), new bytes[](0))), _pD("none", 0), _pL(0));
        h = _pH("mtxBatch", "addr", "err_lengthMismatch");
        _pRec(k, h, k.relayer, abi.encodeCall(IMetaTx.mtxBatch, (ms, new bytes[](1))), _pD("none", 0), _pL(0));
    }

    // ------------------------------------------------------------------ ABI by hand (the named builders have 9-11 arguments)

    /// selector ++ static words ++ offset ++ the one trailing `bytes` (every named builder ends in the signature / auth).
    function _pEncB(bytes4 sel, uint256[] memory w, bytes memory dyn) internal pure returns (bytes memory) {
        return bytes.concat(
            sel, abi.encodePacked(w), abi.encode((w.length + 1) * 32, dyn.length), dyn, new bytes((32 - dyn.length % 32) % 32)
        );
    }

    function _pW(address a) internal pure returns (uint256) {
        return uint256(uint160(a));
    }

    // =================================================================================================================
    // uaExecute, uaBatch, uaUnwrap
    // =================================================================================================================

    function _pUaExecute(Tk memory k) internal {
        bytes32 s = MetaTxLib.pad(k.signer);
        MetaTxLib.UAMetaTransaction memory m;
        _pU(k, "ok_native_amountCall", _pUm(k, s, _pAmt(k, 100_000), 0, P_RR, 0, address(0)));
        _pU(k, "ok_native_percentFee", _pUm(k, s, _pAmt(k, 100_000), 0, P_RR | P_PCT, 1_000, address(0)));
        _pU(k, "ok_native_fixedFee_boundRecipient", _pUm(k, s, _pAmt(k, 100_000), 0, P_RR | P_RF | P_FIX, 10, k.feeTo));
        _pU(k, "ok_native_openMode", _pUm(k, s, _pAmt(k, 1_000), 0, 0, 0, address(0)));
        if (k.uaD != 0) {
            _pU(k, "ok_derived_amountCall", _pUm(k, k.uaD, _pAmt(k, 10_000), 0, P_RR, 0, address(0)));
            _pU(k, "ok_derived_percentFee", _pUm(k, k.uaD, _pAmt(k, 10_000), 0, P_RR | P_PCT, 1_000, address(0)));
            _pU(k, "ok_derived_fixedFee", _pUm(k, k.uaD, _pAmt(k, 10_000), 0, P_RR | P_RF | P_FIX, 10, k.feeTo));
            m = _pUm(k, k.uaD, _pAmt(k, 10_000), 0, P_RR, 0, address(0));
            _pUx(k, "err_derived_badAuth", "", m, _pBadAuth(k, k.uaD, UAKinds.PURPOSE_METATX, MetaTokenBase(k.t).uaDigest(m)), k.relayer);
            _pU(k, "err_derived_feeUnpayable", _pUm(k, k.uaD, _pAmt(k, MetaTokenBase(k.t).balanceOfUA(k.uaD)), 0, P_RR | P_PCT, 1_000, address(0)));
            _pU(k, "err_derived_callReverts", _pUm(k, k.uaD, _pAmt(k, P_BIG), 0, P_RR, 0, address(0)));
            m = _pUm(k, k.uaD, _pAmt(k, P_BIG), 0, P_RR | P_PCT, 20_000, address(0));
            _pUx(k, "bothFail_derived_feeExceedsCap_callReverts", "fee-error-first", m, _pAuM(k, m), k.relayer);
        }
        // step 1
        m = _pUm(k, s, _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        _pUx(k, "err_unauthorizedRelayer", "", m, _pAuM(k, m), k.payee);
        m = _pUm(k, s, _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        m.validUntil = P_T0 - 1;
        _pU(k, "err_expired", m);
        _pU(k, "err_unknownMode_flagBit", _pUm(k, s, _pAmt(k, 1_000), 0, 0x04, 0, address(0)));
        _pU(k, "err_unknownMode_feeNibble", _pUm(k, s, _pAmt(k, 1_000), 0, 0x30, 0, address(0)));
        m = _pUm(k, s, _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        m.nonce = 3;
        _pU(k, "err_badNonce", m);
        m = _pUm(k, MetaTxLib.pad(k.t), _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        _pUx(k, "err_selfSender", "", m, hex"00", k.relayer);
        // step 2: the id
        m = _pUm(k, s, _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        _pUx(k, "err_badAuth_native", "", m, _pEcdsa(k.payeePk, MetaTokenBase(k.t).uaDigest(m)), k.relayer);
        m = _pUm(k, bytes32(0), _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        _pUx(k, "err_idZero", "", m, hex"00", k.relayer);
        m = _pUm(k, MetaTxLib.pad(P_UAP), _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        _pUx(k, "err_idUaPool", "", m, hex"00", k.relayer);
        m = _pUm(k, MetaTxLib.pad(P_SHP), _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        _pUx(k, "err_idShieldPool", "", m, hex"00", k.relayer);
        m = _pUm(k, bytes32(uint256(1) << 200), _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        _pUx(k, "err_idUnregisteredDerived", "", m, hex"00", k.relayer);
        // step 3
        _pU(k, "err_unknownOp_cancelNonce", _pUm(k, s, _pCancel(7), 0, P_RR, 0, address(0)));
        _pU(k, "err_unknownOp_transfer", _pUm(k, s, abi.encodeCall(IERC20.transfer, (k.payee, 1)), 0, P_RR, 0, address(0)));
        _pU(k, "err_unknownOp_shortData", _pUm(k, s, hex"0102", 0, P_RR, 0, address(0)));
        _pU(k, "err_unknownOp_emptyData", _pUm(k, s, "", 0, P_RR, 0, address(0)));
        _pU(k, "err_dataShape_extraByte", _pUm(k, s, abi.encodePacked(_pAmt(k, 1), bytes1(0x01)), 0, P_RR, 0, address(0)));
        // step 4
        m = _pUm(k, s, _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        bytes memory au = _pAuM(k, m);
        vm.prank(k.relayer);
        MetaTokenBase(k.t).uaExecute(m, au);
        _pUx(k, "err_replay", "", m, au, k.relayer);
        // the fee rule (amount checked before the call, §3.8; moved after it)
        _pUf(k, "err_feeExceedsCap_percent", _pUm(k, s, _pAmt(k, 100_000), 0, P_RR | P_PCT, 20_000, address(0)));
        _pUf(k, "err_feeExceedsCap_fixed", _pUm(k, s, _pAmt(k, 100_000), 0, P_RR | P_FIX, 1_001, address(0)));
        _pUf(k, "err_feeRecipientUaPool", _pUm(k, s, _pAmt(k, 100_000), 0, P_RR | P_RF | P_PCT, 1_000, P_UAP));
        _pU(k, "err_feeUnpayable", _pUm(k, s, _pAmt(k, MetaTokenBase(k.t).balanceOf(k.signer)), 0, P_RR | P_PCT, 1_000, address(0)));
        _pUf(k, "err_feeHugeFixed", _pUm(k, s, _pAmt(k, 1), 0, P_RR | P_FIX, type(uint128).max, address(0)));
        _pU(k, "err_callReverts", _pUm(k, s, _pAmt(k, P_BIG), 0, P_RR, 0, address(0)));
        // both fail
        m = _pUm(k, s, _pAmt(k, P_BIG), 0, P_RR | P_PCT, 20_000, address(0));
        _pUx(k, "bothFail_feeExceedsCap_callReverts", "fee-error-first", m, _pAuM(k, m), k.relayer);
        m = _pUm(k, s, _pAmt(k, P_BIG), 0, P_RR | P_RF | P_PCT, 1_000, P_UAP);
        _pUx(k, "bothFail_feeRecipientUaPool_callReverts", "fee-error-first", m, _pAuM(k, m), k.relayer);
        // not a fee fault (1,001 is under 1 % of P_BIG): only the call fails, unmarked (T3; the name is the fixture's)
        m = _pUm(k, s, _pAmt(k, P_BIG), 0, P_RR | P_FIX, 1_001, address(0));
        _pUx(k, "bothFail_feeExceedsCapFixed_callReverts", "", m, _pAuM(k, m), k.relayer);
        _pUaUnwrap(k);
    }

    function _pUaBatch(Tk memory k) internal {
        bytes32 s = MetaTxLib.pad(k.signer);
        MetaTxLib.UAMetaTransaction[] memory ms = new MetaTxLib.UAMetaTransaction[](2);
        bytes[] memory au = new bytes[](2);
        uint256 l0 = _pLn(k);
        uint256 l1 = _pLn(k);
        ms[0] = _pUm(k, s, _pAmt(k, 1_000), l0, P_RR, 0, address(0));
        ms[1] = _pUm(k, k.uaD == 0 ? s : k.uaD, _pAmt(k, 1_000), l1, P_RR | P_FIX, 2, k.feeTo);
        au[0] = _pAuM(k, ms[0]);
        au[1] = _pAuM(k, ms[1]);
        _pUbRec(k, "ok_two_nativeAndDerived", ms, au, l0, l1);
        // atomic: the second item carries the first's auth
        l0 = _pLn(k);
        l1 = _pLn(k);
        ms[0] = _pUm(k, s, _pAmt(k, 1_000), l0, P_RR, 0, address(0));
        ms[1] = _pUm(k, s, _pAmt(k, 1_000), l1, P_RR, 0, address(0));
        au[0] = _pAuM(k, ms[0]);
        au[1] = au[0];
        _pUbRec(k, "err_atomic_secondBadAuth", ms, au, l0, l1);
        // an item outside the UA allowlist
        l0 = _pLn(k);
        l1 = _pLn(k);
        ms[0] = _pUm(k, s, _pAmt(k, 1_000), l0, P_RR, 0, address(0));
        ms[1] = _pUm(k, s, _pCancel(7), l1, P_RR, 0, address(0));
        au[0] = _pAuM(k, ms[0]);
        au[1] = _pAuM(k, ms[1]);
        _pUbRec(k, "err_itemUnknownOp", ms, au, l0, l1);
        // an item whose fee rule breaks (refused before its call, §3.8)
        l0 = _pLn(k);
        l1 = _pLn(k);
        ms[0] = _pUm(k, s, _pAmt(k, 1_000), l0, P_RR, 0, address(0));
        ms[1] = _pUm(k, s, _pAmt(k, 1_000), l1, P_RR | P_PCT, 20_000, address(0));
        au[0] = _pAuM(k, ms[0]);
        au[1] = _pAuM(k, ms[1]);
        _pRec(k, H("uaBatch", "ua", "err_itemFeeExceedsCap", "fee-error-first"), k.relayer, abi.encodeCall(IUALedger.uaBatch, (ms, au)),
            _pD2("uaDigest0", MetaTokenBase(k.t).uaDigest(ms[0]), "uaDigest1", MetaTokenBase(k.t).uaDigest(ms[1])), _pL2(l0, l1));
        _pUaCancel(k);
        H memory h = _pH("uaBatch", "ua", "err_empty");
        _pRec(k, h, k.relayer, abi.encodeCall(IUALedger.uaBatch, (new MetaTxLib.UAMetaTransaction[](0), new bytes[](0))), _pD("none", 0), _pL(0));
        h = _pH("uaBatch", "ua", "err_lengthMismatch");
        _pRec(k, h, k.relayer, abi.encodeCall(IUALedger.uaBatch, (ms, new bytes[](1))), _pD("none", 0), _pL(0));
    }

    /// `uaCancelNonce`: a derived UA cancels a lane under `metatx-cancel`, each signature works once; a native id uses
    /// `cancelNonce`.
    function _pUaCancel(Tk memory k) internal {
        uint256 lane = _pLn(k);
        _pUcOne(k, "err_nativeId", MetaTxLib.pad(k.signer), lane, P_VU, false);
        if (k.uaD == 0) return;
        _pUcOne(k, "ok_derived", k.uaD, lane, P_VU, false);
        _pUcOne(k, "err_replay_signatureUsed", k.uaD, lane, P_VU, false);
        _pUcOne(k, "ok_derived_nextLane", k.uaD, lane + 1, P_VU, false);
        _pUcOne(k, "err_expired", k.uaD, lane + 2, P_T0 - 1, false);
        _pUcOne(k, "err_badAuth", k.uaD, lane + 3, P_VU, true);
    }

    function _pUcOne(Tk memory k, string memory name, bytes32 ua, uint256 lane, uint256 vu, bool bad) internal {
        bytes32 dg = MetaTokenBase(k.t).uaCancelDigest(ua, lane, vu);
        bytes memory au = bad ? _pBadAuth(k, ua, UAKinds.PURPOSE_METATX_CANCEL, dg) : _pAuth(k, ua, UAKinds.PURPOSE_METATX_CANCEL, dg);
        _pRec(k, _pH("uaCancelNonce", "ua", name), k.relayer, abi.encodeCall(IUALedger.uaCancelNonce, (ua, lane, vu, au)),
            _pD("uaCancelDigest", dg), _pL(lane));
    }

    function _pUbRec(Tk memory k, string memory name, MetaTxLib.UAMetaTransaction[] memory ms, bytes[] memory au,
        uint256 l0, uint256 l1) internal
    {
        _pRec(k, _pH("uaBatch", "ua", name), k.relayer, abi.encodeCall(IUALedger.uaBatch, (ms, au)),
            _pD2("uaDigest0", MetaTokenBase(k.t).uaDigest(ms[0]), "uaDigest1", MetaTokenBase(k.t).uaDigest(ms[1])), _pL2(l0, l1));
    }

    /// `uaUnwrap` builds `unwrap(address,uint256,address,uint256)` (kinds without it: `MetaTxUnknownOp`).
    function _pUaUnwrap(Tk memory k) internal {
        // only the wrapper kinds list `unwrap` for the UA path; the others refuse it as `MetaTxUnknownOp`
        string memory ok = k.style == 1 ? "ok_" : "err_unknownOp_";
        _pUwOne(k, string.concat(ok, "native"), MetaTxLib.pad(k.signer), P_RR, false);
        if (k.uaD != 0) _pUwOne(k, string.concat(ok, "derived"), k.uaD, P_RR, false);
        _pUwOne(k, "err_modeShape_restrictFee", MetaTxLib.pad(k.signer), P_RR | P_RF, false);
        _pUwOne(k, "err_modeShape_feeNibble", MetaTxLib.pad(k.signer), P_RR | P_FIX, false);
        _pUwOne(k, "err_badAuth", MetaTxLib.pad(k.signer), P_RR, true);
    }

    function _pUwLeg(Tk memory k) internal pure returns (address) {
        return k.und == address(0) ? address(0x1234) : k.und;
    }

    /// The `UAMetaTransaction` `uaUnwrap` builds from its arguments.
    function _pUwM(Tk memory k, bytes32 from, uint256 lane, uint32 mode) internal view returns (MetaTxLib.UAMetaTransaction memory) {
        bytes memory data = abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", _pUwLeg(k), uint256(1_000), k.payee, uint256(0));
        return MetaTxLib.UAMetaTransaction(from, data, lane, 0, P_VU, mode & P_RR, k.relayer, 0, address(0));
    }

    function _pUwW(Tk memory k, bytes32 from, uint256 lane, uint32 mode) internal pure returns (uint256[] memory w) {
        w = new uint256[](10);
        (w[0], w[1], w[2], w[3], w[4]) = (uint256(from), _pW(_pUwLeg(k)), 1_000, _pW(k.payee), 0);
        (w[5], w[6], w[7], w[8], w[9]) = (lane, 0, P_VU, mode, _pW(k.relayer));
    }

    function _pUwOne(Tk memory k, string memory name, bytes32 from, uint32 mode, bool bad) internal {
        uint256 lane = _pLn(k);
        MetaTxLib.UAMetaTransaction memory m = _pUwM(k, from, lane, mode);
        bytes memory au = bad ? _pEcdsa(k.payeePk, MetaTokenBase(k.t).uaDigest(m)) : _pAuM(k, m);
        _pRec(k, _pH("uaUnwrap", "ua", name), k.relayer, _pEncB(MetaTokenBase.uaUnwrap.selector, _pUwW(k, from, lane, mode), au),
            _pD("uaDigest", MetaTokenBase(k.t).uaDigest(m)), _pL(lane));
    }

    // =================================================================================================================
    // the typed paths (spec §3.4): MetaTransfer / UAMetaTransfer, the named builders, batches
    // =================================================================================================================

    function _pTypedAddr(Tk memory k) internal {
        MetaTxLib.MetaTransfer memory t;
        _pXt(k, "ok_plain", _pTr(k, k.payee, 1_000, 0, 0, P_RR, 0, address(0)));
        _pXt(k, "ok_percentFee_boundRecipient", _pTr(k, k.payee, 100_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, k.feeTo));
        _pXt(k, "ok_percentFee_defaultRecipient", _pTr(k, k.payee, 100_000, 0, 0, P_RR | P_PCT, 1_000, address(0)));
        _pXt(k, "ok_fixedFee", _pTr(k, k.payee, 100_000, 0, 0, P_RR | P_FIX, 10, address(0)));
        _pXt(k, "ok_payment_entryRef", _pTr(k, k.payee, 1_000, keccak256("metatx-parity.pay-0"), 0, P_RR, 0, address(0)));
        _pXt(k, "ok_zeroValue", _pTr(k, k.payee, 0, 0, 0, P_RR, 0, address(0)));
        t = _pTr(k, k.payee, 1_000, 0, 0, 0, 0, address(0));
        _pXtS(k, "ok_openRelayer_otherCaller", t, _pSgT(k, t), k.payee);
        // step 1
        t = _pTr(k, k.payee, 1_000, 0, 0, P_RR, 0, address(0));
        _pXtS(k, "err_unauthorizedRelayer", t, _pSgT(k, t), k.payee);
        t = _pTr(k, k.payee, 1_000, 0, 0, P_RR, 0, address(0));
        t.validUntil = P_T0 - 1;
        _pXt(k, "err_expired", t);
        _pXt(k, "err_unknownMode_flagBit", _pTr(k, k.payee, 1_000, 0, 0, 0x04, 0, address(0)));
        _pXt(k, "err_unknownMode_feeNibble", _pTr(k, k.payee, 1_000, 0, 0, 0x30, 0, address(0)));
        t = _pTr(k, k.payee, 1_000, 0, 0, P_RR, 0, address(0));
        t.nonce = 3;
        _pXt(k, "err_badNonce", t);
        t = _pTr(k, k.payee, 1_000, 0, 0, P_RR, 0, address(0));
        t.from = k.t;
        _pXt(k, "err_selfSender", t);
        // step 2
        t = _pTr(k, k.payee, 1_000, 0, 0, P_RR, 0, address(0));
        _pXtS(k, "err_badSignature", t, _pEcdsa(k.payeePk, MetaTokenBase(k.t).mtxTransferDigest(t)), k.relayer);
        // step 3
        _pXt(k, "err_payToZero", _pTr(k, address(0), 1_000, 0, 0, P_RR, 0, address(0)));
        _pXt(k, "err_transferToSelf", _pTr(k, k.t, 1_000, 0, 0, P_RR, 0, address(0)));
        _pXt(k, "err_uaPoolPayee", _pTr(k, P_UAP, 1_000, 0, 0, P_RR, 0, address(0)));
        _pXt(k, "err_shieldPoolPayee", _pTr(k, P_SHP, 1_000, 0, 0, P_RR, 0, address(0)));
        _pXt(k, "err_feeExceedsCap_percent", _pTr(k, k.payee, 100_000, 0, 0, P_RR | P_PCT, 20_000, address(0)));
        _pXt(k, "err_feeExceedsCap_fixed", _pTr(k, k.payee, 100_000, 0, 0, P_RR | P_FIX, 1_001, address(0)));
        _pXt(k, "err_feeRecipientIsPayee_bound", _pTr(k, k.payee, 100_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, k.payee));
        _pXt(k, "err_feeRecipientIsPayee_unboundRaw", _pTr(k, k.payee, 100_000, 0, 0, P_RR | P_PCT, 1_000, k.payee));
        _pXt(k, "err_feeRecipientToken", _pTr(k, k.payee, 100_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, k.t));
        _pXt(k, "err_feeRecipientUaPool", _pTr(k, k.payee, 100_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, P_UAP));
        _pXt(k, "err_feeRecipientShieldPool", _pTr(k, k.payee, 100_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, P_SHP));
        _pXt(k, "err_insufficientForFee", _pTr(k, k.payee, P_BIG, 0, 0, P_RR, 0, address(0)));
        // step 4
        t = _pTr(k, k.payee, 1_000, 0, 0, P_RR, 0, address(0));
        bytes memory sg = _pSgT(k, t);
        vm.prank(k.relayer);
        MetaTokenBase(k.t).mtxExecuteTransfer(t, sg);
        _pXtS(k, "err_replay", t, sg, k.relayer);
        _pTypedNamedAddr(k);
        _pBatchTransfer(k);
    }

    function _pTypedNamedAddr(Tk memory k) internal {
        MetaTxLib.MetaTransfer memory t = _pTr(k, k.payee, 2_000, 0, 0, P_RR, 0, address(0));
        uint256[] memory w = new uint256[](8);
        (w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]) = (_pW(k.signer), _pW(k.payee), 2_000, t.batch, 0, P_VU, P_RR, _pW(k.relayer));
        _pNamed(k, "mtxTransfer", "ok", MetaTokenBase.mtxTransfer.selector, w, _pSgT(k, t), t);
        t = _pTr(k, k.payee, 2_000, 0, 0, P_RR, 0, address(0));
        w[3] = t.batch;
        _pNamed(k, "mtxTransfer", "err_badSignature", MetaTokenBase.mtxTransfer.selector, w, _pEcdsa(k.payeePk, MetaTokenBase(k.t).mtxTransferDigest(t)), t);
        w[3] = _pLn(k);
        w[6] = P_RR | P_RF;
        _pNamed(k, "mtxTransfer", "err_modeShape_restrictFee", MetaTokenBase.mtxTransfer.selector, w, hex"00", t);
        w[6] = P_PCT;
        _pNamed(k, "mtxTransfer", "err_modeShape_feeNibble", MetaTokenBase.mtxTransfer.selector, w, hex"00", t);
        // mtxTransferWithFee: from,to,amount,batch,nonce,validUntil,mode,relayer,fee,feeRecipient
        t = _pTr(k, k.payee, 100_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, k.feeTo);
        w = new uint256[](10);
        (w[0], w[1], w[2], w[3], w[4]) = (_pW(k.signer), _pW(k.payee), 100_000, t.batch, 0);
        (w[5], w[6], w[7], w[8], w[9]) = (P_VU, P_RR | P_RF | P_PCT, _pW(k.relayer), 1_000, _pW(k.feeTo));
        _pNamed(k, "mtxTransferWithFee", "ok_percent", MetaTokenBase.mtxTransferWithFee.selector, w, _pSgT(k, t), t);
        t = _pTr(k, k.payee, 100_000, 0, 0, P_RR | P_RF | P_FIX, 10, k.feeTo);
        (w[3], w[6]) = (t.batch, P_RR | P_RF | P_FIX);
        w[8] = 10;
        _pNamed(k, "mtxTransferWithFee", "ok_fixed", MetaTokenBase.mtxTransferWithFee.selector, w, _pSgT(k, t), t);
        w[3] = _pLn(k);
        w[6] = P_RR | P_PCT; // the recipient is not bound
        _pNamed(k, "mtxTransferWithFee", "err_modeShape_recipientNotBound", MetaTokenBase.mtxTransferWithFee.selector, w, hex"00", t);
        w[6] = P_RR | P_RF;
        _pNamed(k, "mtxTransferWithFee", "err_modeShape_noFeeNibble", MetaTokenBase.mtxTransferWithFee.selector, w, hex"00", t);
        (w[6], w[9]) = (P_RR | P_RF | P_PCT, 0);
        _pNamed(k, "mtxTransferWithFee", "err_modeShape_recipientZero", MetaTokenBase.mtxTransferWithFee.selector, w, hex"00", t);
        // mtxPay: from,to,amount,payId,validUntil,mode,relayer,fee,feeRecipient
        bytes32 id = keccak256("metatx-parity.pay-2");
        t = _pTr(k, k.payee, 3_000, id, MetaTokenBase(k.t).payLane(id), P_RR, 0, address(0));
        w = new uint256[](9);
        (w[0], w[1], w[2], w[3], w[4]) = (_pW(k.signer), _pW(k.payee), 3_000, uint256(id), P_VU);
        (w[5], w[6], w[7], w[8]) = (P_RR, _pW(k.relayer), 0, 0);
        bytes memory sg = _pSgT(k, t);
        _pNamed(k, "mtxPay", "ok", MetaTokenBase.mtxPay.selector, w, sg, t);
        _pNamed(k, "mtxPay", "err_replay", MetaTokenBase.mtxPay.selector, w, sg, t);
        id = keccak256("metatx-parity.pay-3");
        t = _pTr(k, k.payee, 100_000, id, MetaTokenBase(k.t).payLane(id), P_RR | P_RF | P_PCT, 1_000, k.feeTo);
        (w[3], w[5], w[7], w[8]) = (uint256(id), P_RR | P_RF | P_PCT, 1_000, _pW(k.feeTo));
        w[2] = 100_000;
        _pNamed(k, "mtxPay", "ok_percentFee", MetaTokenBase.mtxPay.selector, w, _pSgT(k, t), t);
        id = keccak256("metatx-parity.pay-4");
        t = _pTr(k, k.payee, 3_000, id, MetaTokenBase(k.t).payLane(id), P_RR, 0, address(0));
        (w[2], w[3], w[5], w[7], w[8]) = (3_000, uint256(id), P_RR, 0, 0);
        _pNamed(k, "mtxPay", "err_badSignature", MetaTokenBase.mtxPay.selector, w, _pEcdsa(k.payeePk, MetaTokenBase(k.t).mtxTransferDigest(t)), t);
    }

    /// One named-builder call; the digest is the struct's (the one the signature must be over).
    function _pNamed(Tk memory k, string memory entry, string memory name, bytes4 sel, uint256[] memory w, bytes memory sig,
        MetaTxLib.MetaTransfer memory t) internal
    {
        _pRec(k, _pH(entry, "addr", name), k.relayer, _pEncB(sel, w, sig),
            _pD("mtxTransferDigest", MetaTokenBase(k.t).mtxTransferDigest(t)), _pL(t.batch));
    }

    function _pBatchTransfer(Tk memory k) internal {
        MetaTxLib.MetaTransfer[] memory ts = new MetaTxLib.MetaTransfer[](2);
        bytes[] memory sg = new bytes[](2);
        uint256 l0 = _pLn(k);
        uint256 l1 = _pLn(k);
        ts[0] = _pTr(k, k.payee, 1_000, 0, l0, P_RR, 0, address(0));
        ts[1] = _pTr(k, k.payee, 100_000, 0, l1, P_RR | P_FIX, 10, address(0));
        sg[0] = _pSgT(k, ts[0]);
        sg[1] = _pSgT(k, ts[1]);
        _pBtRec(k, "ok_two", ts, sg, l0, l1);
        l0 = _pLn(k);
        l1 = _pLn(k);
        ts[0] = _pTr(k, k.payee, 1_000, 0, l0, P_RR, 0, address(0));
        ts[1] = _pTr(k, k.payee, 1_000, 0, l1, P_RR, 0, address(0));
        sg[0] = _pSgT(k, ts[0]);
        sg[1] = sg[0];
        _pBtRec(k, "err_atomic_secondBadSignature", ts, sg, l0, l1);
        l0 = _pLn(k);
        l1 = _pLn(k);
        ts[0] = _pTr(k, k.payee, 1_000, 0, l0, P_RR, 0, address(0));
        ts[1] = _pTr(k, address(0), 1_000, 0, l1, P_RR, 0, address(0));
        sg[0] = _pSgT(k, ts[0]);
        sg[1] = _pSgT(k, ts[1]);
        _pBtRec(k, "err_itemPayToZero", ts, sg, l0, l1);
        _pRec(k, _pH("mtxBatchTransfer", "addr", "err_empty"), k.relayer,
            abi.encodeCall(IERC20MetaTx.mtxBatchTransfer, (new MetaTxLib.MetaTransfer[](0), new bytes[](0))), _pD("none", 0), _pL(0));
        _pRec(k, _pH("mtxBatchTransfer", "addr", "err_lengthMismatch"), k.relayer,
            abi.encodeCall(IERC20MetaTx.mtxBatchTransfer, (ts, new bytes[](1))), _pD("none", 0), _pL(0));
    }

    function _pBtRec(Tk memory k, string memory name, MetaTxLib.MetaTransfer[] memory ts, bytes[] memory sg, uint256 l0,
        uint256 l1) internal
    {
        _pRec(k, _pH("mtxBatchTransfer", "addr", name), k.relayer, abi.encodeCall(IERC20MetaTx.mtxBatchTransfer, (ts, sg)),
            _pD2("mtxTransferDigest0", MetaTokenBase(k.t).mtxTransferDigest(ts[0]), "mtxTransferDigest1",
                MetaTokenBase(k.t).mtxTransferDigest(ts[1])), _pL2(l0, l1));
    }

    // ------------------------------------------------------------------ the UA ledger twin

    bytes32 internal constant P_UAPAY0 = keccak256("metatx-parity.ua-pay-0");

    function _pTypedUa(Tk memory k) internal {
        _pTypedUaOk(k);
        _pTypedUaErr(k);
        _pTypedNamedUa(k);
        _pBatchTransferUa(k);
    }

    function _pTypedUaOk(Tk memory k) internal {
        bytes32 s = MetaTxLib.pad(k.signer);
        bytes32 p = MetaTxLib.pad(k.payee);
        _pUt2(k, "ok_nativeToNative", _pUt(k, s, p, 1_000, 0, 0, P_RR, 0, address(0)));
        _pUt2(k, "ok_nativePercentFee", _pUt(k, s, p, 100_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, k.feeTo));
        _pUt2(k, "ok_nativeFixedFee_default", _pUt(k, s, p, 100_000, 0, 0, P_RR | P_FIX, 10, address(0)));
        _pUt2(k, "ok_nativePayment_entryRef", _pUt(k, s, p, 1_000, P_UAPAY0, 0, P_RR, 0, address(0)));
        if (k.uaD == 0) return;
        _pUt2(k, "ok_nativeToDerived", _pUt(k, s, k.uaD, 1_000, 0, 0, P_RR, 0, address(0)));
        _pUt2(k, "ok_derivedToNative", _pUt(k, k.uaD, p, 1_000, 0, 0, P_RR, 0, address(0)));
        _pUt2(k, "ok_derivedToNative_percentFee", _pUt(k, k.uaD, p, 10_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, k.feeTo));
        _pUt2(k, "ok_derivedToDerived_self", _pUt(k, k.uaD, k.uaD, 1_000, 0, 0, P_RR, 0, address(0)));
        MetaTxLib.UAMetaTransfer memory t = _pUt(k, k.uaD, p, 1_000, 0, 0, P_RR, 0, address(0));
        _pUtS(k, "err_derived_badAuth", t, _pBadAuth(k, k.uaD, UAKinds.PURPOSE_METATX, MetaTokenBase(k.t).uaTransferDigest(t)), k.relayer);
        _pUt2(k, "err_derived_insufficient", _pUt(k, k.uaD, p, P_BIG, 0, 0, P_RR, 0, address(0)));
    }

    function _pTypedUaErr(Tk memory k) internal {
        bytes32 s = MetaTxLib.pad(k.signer);
        bytes32 p = MetaTxLib.pad(k.payee);
        MetaTxLib.UAMetaTransfer memory t = _pUt(k, s, p, 1_000, 0, 0, P_RR, 0, address(0));
        _pUtS(k, "err_unauthorizedRelayer", t, _pAuT(k, t), k.payee);
        t = _pUt(k, s, p, 1_000, 0, 0, P_RR, 0, address(0));
        t.validUntil = P_T0 - 1;
        _pUt2(k, "err_expired", t);
        _pUt2(k, "err_unknownMode_flagBit", _pUt(k, s, p, 1_000, 0, 0, 0x04, 0, address(0)));
        _pUt2(k, "err_unknownMode_feeNibble", _pUt(k, s, p, 1_000, 0, 0, 0x30, 0, address(0)));
        t = _pUt(k, s, p, 1_000, 0, 0, P_RR, 0, address(0));
        t.nonce = 3;
        _pUt2(k, "err_badNonce", t);
        t = _pUt(k, MetaTxLib.pad(k.t), p, 1_000, 0, 0, P_RR, 0, address(0));
        _pUtS(k, "err_selfSender", t, hex"00", k.relayer);
        t = _pUt(k, s, p, 1_000, 0, 0, P_RR, 0, address(0));
        _pUtS(k, "err_badAuth_native", t, _pEcdsa(k.payeePk, MetaTokenBase(k.t).uaTransferDigest(t)), k.relayer);
        _pUt2(k, "err_payToZero", _pUt(k, s, bytes32(0), 1_000, 0, 0, P_RR, 0, address(0)));
        _pUt2(k, "err_transferToSelf", _pUt(k, s, MetaTxLib.pad(k.t), 1_000, 0, 0, P_RR, 0, address(0)));
        _pUt2(k, "err_uaPoolPayee", _pUt(k, s, MetaTxLib.pad(P_UAP), 1_000, 0, 0, P_RR, 0, address(0)));
        _pUt2(k, "err_shieldPoolPayee", _pUt(k, s, MetaTxLib.pad(P_SHP), 1_000, 0, 0, P_RR, 0, address(0)));
        _pUt2(k, "err_payeeUnregisteredDerived", _pUt(k, s, bytes32(uint256(1) << 200), 1_000, 0, 0, P_RR, 0, address(0)));
        _pUt2(k, "err_feeExceedsCap_percent", _pUt(k, s, p, 100_000, 0, 0, P_RR | P_PCT, 20_000, address(0)));
        _pUt2(k, "err_feeExceedsCap_fixed", _pUt(k, s, p, 100_000, 0, 0, P_RR | P_FIX, 1_001, address(0)));
        _pUt2(k, "err_feeRecipientIsPayee", _pUt(k, s, p, 100_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, k.payee));
        _pUt2(k, "err_feeRecipientToken", _pUt(k, s, p, 100_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, k.t));
        _pUt2(k, "err_feeRecipientUaPool", _pUt(k, s, p, 100_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, P_UAP));
        _pUt2(k, "err_feeRecipientShieldPool", _pUt(k, s, p, 100_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, P_SHP));
        _pUt2(k, "err_insufficientForFee", _pUt(k, s, p, P_BIG, 0, 0, P_RR, 0, address(0)));
        t = _pUt(k, s, p, 1_000, 0, 0, P_RR, 0, address(0));
        bytes memory au = _pAuT(k, t);
        vm.prank(k.relayer);
        IUALedger(k.t).uaExecuteTransfer(t, au);
        _pUtS(k, "err_replay", t, au, k.relayer);
    }

    function _pTypedNamedUa(Tk memory k) internal {
        bytes32 s = MetaTxLib.pad(k.signer);
        bytes32 p = MetaTxLib.pad(k.payee);
        MetaTxLib.UAMetaTransfer memory t = _pUt(k, s, p, 2_000, 0, 0, P_RR, 0, address(0));
        uint256[] memory w = new uint256[](8);
        (w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]) = (uint256(s), uint256(p), 2_000, t.batch, 0, P_VU, P_RR, _pW(k.relayer));
        _pNamedUa(k, "uaTransfer", "ok", MetaTokenBase.uaTransfer.selector, w, _pAuT(k, t), t);
        t = _pUt(k, s, p, 2_000, 0, 0, P_RR, 0, address(0));
        w[3] = t.batch;
        _pNamedUa(k, "uaTransfer", "err_badAuth", MetaTokenBase.uaTransfer.selector, w, _pEcdsa(k.payeePk, MetaTokenBase(k.t).uaTransferDigest(t)), t);
        w[3] = _pLn(k);
        w[6] = P_RR | P_RF;
        _pNamedUa(k, "uaTransfer", "err_modeShape_restrictFee", MetaTokenBase.uaTransfer.selector, w, hex"00", t);
        t = _pUt(k, s, p, 100_000, 0, 0, P_RR | P_RF | P_PCT, 1_000, k.feeTo);
        w = new uint256[](10);
        (w[0], w[1], w[2], w[3], w[4]) = (uint256(s), uint256(p), 100_000, t.batch, 0);
        (w[5], w[6], w[7], w[8], w[9]) = (P_VU, P_RR | P_RF | P_PCT, _pW(k.relayer), 1_000, _pW(k.feeTo));
        _pNamedUa(k, "uaTransferWithFee", "ok_percent", MetaTokenBase.uaTransferWithFee.selector, w, _pAuT(k, t), t);
        w[3] = _pLn(k);
        w[6] = P_RR | P_PCT;
        _pNamedUa(k, "uaTransferWithFee", "err_modeShape_recipientNotBound", MetaTokenBase.uaTransferWithFee.selector, w, hex"00", t);
        bytes32 id = keccak256("metatx-parity.ua-pay-1");
        t = _pUt(k, s, p, 3_000, id, MetaTokenBase(k.t).payLane(id), P_RR, 0, address(0));
        w = new uint256[](9);
        (w[0], w[1], w[2], w[3], w[4]) = (uint256(s), uint256(p), 3_000, uint256(id), P_VU);
        (w[5], w[6], w[7], w[8]) = (P_RR, _pW(k.relayer), 0, 0);
        bytes memory au = _pAuT(k, t);
        _pNamedUa(k, "uaPay", "ok", MetaTokenBase.uaPay.selector, w, au, t);
        _pNamedUa(k, "uaPay", "err_replay", MetaTokenBase.uaPay.selector, w, au, t);
        id = keccak256("metatx-parity.ua-pay-2");
        t = _pUt(k, s, p, 3_000, id, MetaTokenBase(k.t).payLane(id), P_RR, 0, address(0));
        w[3] = uint256(id);
        _pNamedUa(k, "uaPay", "err_badAuth", MetaTokenBase.uaPay.selector, w, _pEcdsa(k.payeePk, MetaTokenBase(k.t).uaTransferDigest(t)), t);
    }

    function _pNamedUa(Tk memory k, string memory entry, string memory name, bytes4 sel, uint256[] memory w, bytes memory au,
        MetaTxLib.UAMetaTransfer memory t) internal
    {
        _pRec(k, _pH(entry, "ua", name), k.relayer, _pEncB(sel, w, au),
            _pD("uaTransferDigest", MetaTokenBase(k.t).uaTransferDigest(t)), _pL(t.batch));
    }

    function _pBatchTransferUa(Tk memory k) internal {
        bytes32 s = MetaTxLib.pad(k.signer);
        bytes32 p = MetaTxLib.pad(k.payee);
        MetaTxLib.UAMetaTransfer[] memory ts = new MetaTxLib.UAMetaTransfer[](2);
        bytes[] memory au = new bytes[](2);
        uint256 l0 = _pLn(k);
        uint256 l1 = _pLn(k);
        ts[0] = _pUt(k, s, p, 1_000, 0, l0, P_RR, 0, address(0));
        ts[1] = _pUt(k, k.uaD == 0 ? s : k.uaD, p, 1_000, 0, l1, P_RR | P_FIX, 0, address(0));
        au[0] = _pAuT(k, ts[0]);
        au[1] = _pAuT(k, ts[1]);
        _pBtuRec(k, "ok_two_nativeAndDerived", ts, au, l0, l1);
        l0 = _pLn(k);
        l1 = _pLn(k);
        ts[0] = _pUt(k, s, p, 1_000, 0, l0, P_RR, 0, address(0));
        ts[1] = _pUt(k, s, p, 1_000, 0, l1, P_RR, 0, address(0));
        au[0] = _pAuT(k, ts[0]);
        au[1] = au[0];
        _pBtuRec(k, "err_atomic_secondBadAuth", ts, au, l0, l1);
        _pRec(k, _pH("uaBatchTransfer", "ua", "err_empty"), k.relayer,
            abi.encodeCall(IUALedger.uaBatchTransfer, (new MetaTxLib.UAMetaTransfer[](0), new bytes[](0))), _pD("none", 0), _pL(0));
        _pRec(k, _pH("uaBatchTransfer", "ua", "err_lengthMismatch"), k.relayer,
            abi.encodeCall(IUALedger.uaBatchTransfer, (ts, new bytes[](1))), _pD("none", 0), _pL(0));
    }

    function _pBtuRec(Tk memory k, string memory name, MetaTxLib.UAMetaTransfer[] memory ts, bytes[] memory au, uint256 l0,
        uint256 l1) internal
    {
        _pRec(k, _pH("uaBatchTransfer", "ua", name), k.relayer, abi.encodeCall(IUALedger.uaBatchTransfer, (ts, au)),
            _pD2("uaTransferDigest0", MetaTokenBase(k.t).uaTransferDigest(ts[0]), "uaTransferDigest1",
                MetaTokenBase(k.t).uaTransferDigest(ts[1])), _pL2(l0, l1));
    }

    // =================================================================================================================
    // receiver-pays
    // =================================================================================================================

    uint256 internal constant P_RFVU = P_T0 + 600;

    /// The `ReceiverFee` the payee co-signs; `badPayee` / `badPayer` swap in a wrong signature.
    struct Rfa {
        uint256 fee;
        address fr;
        uint256 vu;
        bool badPayee;
        bool badPayer;
    }

    function _pRfa(uint256 fee, address fr) internal pure returns (Rfa memory) {
        return Rfa(fee, fr, P_RFVU, false, false);
    }

    function _pReceiverPays(Tk memory k) internal {
        MetaTokenBase t = MetaTokenBase(k.t);
        MetaTxLib.MetaTransfer memory x;
        bytes32 id = keccak256("metatx-parity.rf-0");
        x = _pTr(k, k.payee, 10_000, id, t.payLane(id), P_RR, 0, address(0));
        _pRf(k, "ok", x, _pRfa(100, k.feeTo));
        id = keccak256("metatx-parity.rf-1");
        x = _pTr(k, k.payee, 10_000, id, t.payLane(id), P_RR, 0, address(0));
        Rfa memory a = _pRfa(100, k.feeTo);
        a.badPayee = true;
        _pRf(k, "err_payeeBadSignature", x, a);
        a.badPayee = false;
        a.badPayer = true;
        _pRf(k, "err_payerBadSignature", x, a);
        _pRf(k, "err_feeZero", x, _pRfa(0, k.feeTo));
        _pRf(k, "err_feeAboveValue", x, _pRfa(10_001, k.feeTo));
        a = _pRfa(100, k.feeTo);
        a.vu = P_T0 - 1;
        _pRf(k, "err_rfExpired", x, a);
        _pRf(k, "err_feeRecipientZero", x, _pRfa(100, address(0)));
        _pRf(k, "err_feeRecipientIsPayee", x, _pRfa(100, k.payee));
        _pRf(k, "err_feeRecipientToken", x, _pRfa(100, k.t));
        _pRf(k, "err_feeRecipientUaPool", x, _pRfa(100, P_UAP));
        _pRf(k, "err_feeRecipientShieldPool", x, _pRfa(100, P_SHP));
        _pReceiverPaysShape(k, id);
        _pRfUaNative(k);
        if (k.uaD != 0) _pRfUa(k);
    }

    /// The shape of the payer's struct.
    function _pReceiverPaysShape(Tk memory k, bytes32 id) internal {
        MetaTokenBase t = MetaTokenBase(k.t);
        MetaTxLib.MetaTransfer memory x = _pTr(k, k.payee, 10_000, 0, t.payLane(id), P_RR, 0, address(0));
        _pRf(k, "err_shape_noEntryRef", x, _pRfa(100, k.feeTo));
        x = _pTr(k, k.payee, 10_000, id, t.payLane(id), P_RR | P_FIX, 10, address(0));
        _pRf(k, "err_shape_payerFee", x, _pRfa(100, k.feeTo));
        x = _pTr(k, k.payee, 10_000, id, t.payLane(id), 0, 0, address(0));
        _pRf(k, "err_shape_noRestrictRelayer", x, _pRfa(100, k.feeTo));
        x = _pTr(k, k.payee, 10_000, id, 5, P_RR, 0, address(0));
        _pRf(k, "err_shape_wrongLane", x, _pRfa(100, k.feeTo));
        x = _pTr(k, k.payee, 10_000, id, t.payLane(id), P_RR, 0, address(0));
        x.nonce = 1;
        _pRf(k, "err_shape_nonce", x, _pRfa(100, k.feeTo));
    }

    /// `mtxPayReceiverFee`: the payer's `x` signed by the signer, the payee's `ReceiverFee` by the payee.
    function _pRf(Tk memory k, string memory name, MetaTxLib.MetaTransfer memory x, Rfa memory a) internal {
        MetaTokenBase t = MetaTokenBase(k.t);
        bytes32 d = t.mtxTransferDigest(x);
        bytes32 rfd = t.receiverFeeDigest(d, a.fee, a.fr, a.vu);
        bytes memory ps = _pEcdsa(a.badPayer ? k.payeePk : k.pk, d);
        bytes memory ys = _pEcdsa(a.badPayee ? k.pk : k.payeePk, rfd);
        _pRec(k, _pH("mtxPayReceiverFee", "addr", name), k.relayer,
            abi.encodeCall(MetaTokenBase.mtxPayReceiverFee, (x, ps, a.fee, a.fr, a.vu, ys)),
            _pD2("mtxTransferDigest", d, "receiverFeeDigest", rfd), _pL(x.batch));
    }

    function _pRfUaNative(Tk memory k) internal {
        MetaTokenBase t = MetaTokenBase(k.t);
        bytes32 s = MetaTxLib.pad(k.signer);
        bytes32 p = MetaTxLib.pad(k.payee);
        bytes32 id = keccak256("metatx-parity.ua-rf-0");
        MetaTxLib.UAMetaTransfer memory x = _pUt(k, s, p, 10_000, id, t.payLane(id), P_RR, 0, address(0));
        _pRfU(k, "ok_native", x, _pRfa(100, k.feeTo));
        id = keccak256("metatx-parity.ua-rf-1");
        x = _pUt(k, s, p, 10_000, id, t.payLane(id), P_RR, 0, address(0));
        Rfa memory a = _pRfa(100, k.feeTo);
        a.badPayee = true;
        _pRfU(k, "err_payeeBadAuth", x, a);
        _pRfU(k, "err_feeZero", x, _pRfa(0, k.feeTo));
        a = _pRfa(100, k.feeTo);
        a.vu = P_T0 - 1;
        _pRfU(k, "err_rfExpired", x, a);
        _pRfU(k, "err_feeRecipientIsPayee", x, _pRfa(100, k.payee));
        _pRfU(k, "err_feeRecipientToken", x, _pRfa(100, k.t));
        _pRfU(k, "err_feeRecipientUaPool", x, _pRfa(100, P_UAP));
        x = _pUt(k, s, p, 10_000, 0, t.payLane(id), P_RR, 0, address(0));
        _pRfU(k, "err_shape_noEntryRef", x, _pRfa(100, k.feeTo));
    }

    function _pRfUa(Tk memory k) internal {
        MetaTokenBase t = MetaTokenBase(k.t);
        // a derived payee co-signs under `receiver-fee`
        bytes32 id = keccak256("metatx-parity.ua-rf-2");
        MetaTxLib.UAMetaTransfer memory x = _pUt(k, MetaTxLib.pad(k.signer), k.uaD, 10_000, id, t.payLane(id), P_RR, 0, address(0));
        _pRfU(k, "ok_derivedPayee", x, _pRfa(100, k.feeTo));
        id = keccak256("metatx-parity.ua-rf-3");
        x = _pUt(k, k.uaD, MetaTxLib.pad(k.payee), 10_000, id, t.payLane(id), P_RR, 0, address(0));
        _pRfU(k, "ok_derivedPayer_nativePayee", x, _pRfa(100, k.feeTo));
        id = keccak256("metatx-parity.ua-rf-4");
        x = _pUt(k, MetaTxLib.pad(k.signer), k.uaD, 10_000, id, t.payLane(id), P_RR, 0, address(0));
        Rfa memory a = _pRfa(100, k.feeTo);
        a.badPayee = true;
        _pRfU(k, "err_derivedPayeeBadAuth", x, a);
    }

    function _pRfU(Tk memory k, string memory name, MetaTxLib.UAMetaTransfer memory x, Rfa memory a) internal {
        MetaTokenBase t = MetaTokenBase(k.t);
        bytes32 d = t.uaTransferDigest(x);
        bytes32 rfd = t.receiverFeeDigest(d, a.fee, a.fr, a.vu);
        bytes memory ys = !a.badPayee ? _pAuth(k, x.to, UAKinds.PURPOSE_RECEIVER_FEE, rfd)
            : (x.to == k.uaD && k.uaD != 0 ? _pBadDerived(k, UAKinds.PURPOSE_RECEIVER_FEE, rfd) : _pEcdsa(k.pk, rfd));
        _pRec(k, _pH("uaPayReceiverFee", "ua", name), k.relayer,
            abi.encodeCall(MetaTokenBase.uaPayReceiverFee, (x, _pAuth(k, x.from, UAKinds.PURPOSE_METATX, d), a.fee, a.fr, a.vu, ys)),
            _pD2("uaTransferDigest", d, "receiverFeeDigest", rfd), _pL(x.batch));
    }

    // =================================================================================================================
    // the trade side (mtxTrade, uaTrade, cancel, invalidate): the caller is `o.dex`, the order hash is recorded
    // =================================================================================================================

    function _pOrder(Tk memory k, uint256 lane) internal view returns (ITradeToken.TradeOrder memory) {
        if (lane == 0) lane = k.lane++;
        return ITradeToken.TradeOrder(k.signer, address(0x7777), 5_000, 4_000, 5_000, 0, address(0), k.dex, address(0), 0, lane, 0, P_VU);
    }

    function _pUOrder(Tk memory k, bytes32 from, uint256 lane) internal view returns (ITradeToken.UATradeOrder memory) {
        if (lane == 0) lane = k.lane++;
        return ITradeToken.UATradeOrder(from, address(0x7777), 5_000, 4_000, 5_000, 0, address(0), k.dex, bytes32(0), 0, lane, 0, P_VU);
    }

    function _pFill(Tk memory k, uint256 sell, uint256 recv) internal view returns (ITradeToken.TradeFill memory) {
        return ITradeToken.TradeFill(sell, recv, 0, k.relayer);
    }

    function _pTSign(Tk memory k, ITradeToken.TradeOrder memory o) internal view returns (bytes memory) {
        return _pEcdsa(k.pk, MetaTokenBase(k.t).tradeOrderDigest(o));
    }

    /// `mtxTrade` of `o` under signature `sg`, the fill `(sell, recv)`, by `caller`.
    function _pMtr(Tk memory k, string memory name, ITradeToken.TradeOrder memory o, bytes memory sg, uint256 sell,
        uint256 recv, address caller) internal
    {
        _pTradeRec(k, "mtxTrade", name, o, abi.encodeCall(ITradeToken.mtxTrade, (o, sg, _pFill(k, sell, recv))), caller);
    }

    function _pTrade(Tk memory k) internal {
        _pTradeFill(k);
        _pTradeErr(k);
        _pTradeCancel(k);
        _pTradeInvalidate(k);
        _pTradeUa(k);
    }

    function _pTradeFill(Tk memory k) internal {
        ITradeToken.TradeOrder memory o = _pOrder(k, 0);
        bytes memory sg = _pTSign(k, o);
        _pMtr(k, "ok_fillOrKill", o, sg, 5_000, 4_000, k.dex);
        _pMtr(k, "err_orderClosed", o, sg, 5_000, 4_000, k.dex);
        // a partial fill, then the rest under a signature that is no longer checked (pulled != 0)
        o = _pOrder(k, 0);
        o.minFill = 2_500;
        sg = _pTSign(k, o);
        _pMtr(k, "ok_partialFill", o, sg, 3_000, 2_400, k.dex);
        _pMtr(k, "ok_secondFillSkipsSignature", o, hex"00", 2_000, 1_600, k.dex);
    }

    function _pTradeErr(Tk memory k) internal {
        ITradeToken.TradeOrder memory o = _pOrder(k, 0);
        bytes memory sg = _pTSign(k, o);
        _pMtr(k, "err_notDex", o, sg, 5_000, 4_000, k.relayer);
        _pMtr(k, "err_badSignature", o, _pEcdsa(k.payeePk, MetaTokenBase(k.t).tradeOrderDigest(o)), 5_000, 4_000, k.dex);
        _pMtr(k, "err_zeroFill", o, sg, 0, 0, k.dex);
        _pMtr(k, "err_overfill", o, sg, 5_001, 4_001, k.dex);
        _pMtr(k, "err_belowMinFill", o, sg, 1_000, 800, k.dex);
        _pMtr(k, "err_priceLimit", o, sg, 5_000, 3_999, k.dex);
        o = _pOrder(k, 0);
        o.relayer = k.relayer;
        ITradeToken.TradeFill memory other = _pFill(k, 5_000, 4_000);
        other.submitter = k.payee;
        _pTradeRec(k, "mtxTrade", "err_wrongRelayer", o, abi.encodeCall(ITradeToken.mtxTrade, (o, _pTSign(k, o), other)), k.dex);
        o = _pOrder(k, 0);
        o.validUntil = P_T0 - 1;
        _pMtr(k, "err_expired", o, _pTSign(k, o), 5_000, 4_000, k.dex);
        o = _pOrder(k, 0);
        o.amount = 0;
        _pMtr(k, "err_zeroAmount", o, hex"00", 5_000, 4_000, k.dex);
        o = _pOrder(k, 0);
        o.flags = 8;
        _pMtr(k, "err_badFlags", o, hex"00", 5_000, 4_000, k.dex);
        o = _pOrder(k, 0);
        o.dex = k.t;
        _pMtr(k, "err_selfOrder", o, hex"00", 5_000, 4_000, k.t);
    }

    function _pTradeCancel(Tk memory k) internal {
        MetaTokenBase t = MetaTokenBase(k.t);
        ITradeToken.TradeOrder memory o = _pOrder(k, 0);
        bytes memory sg = _pEcdsa(k.pk, t.cancelOrderDigest(t.tradeOrderDigest(o)));
        _pTradeRec(k, "mtxCancelOrder", "ok", o, abi.encodeCall(ITradeToken.mtxCancelOrder, (o, sg)), k.relayer);
        _pTradeRec(k, "mtxCancelOrder", "ok_alreadyClosedNoop", o, abi.encodeCall(ITradeToken.mtxCancelOrder, (o, sg)), k.relayer);
        _pMtr(k, "err_afterCancel_orderClosed", o, _pTSign(k, o), 5_000, 4_000, k.dex);
        o = _pOrder(k, 0);
        sg = _pEcdsa(k.payeePk, t.cancelOrderDigest(t.tradeOrderDigest(o)));
        _pTradeRec(k, "mtxCancelOrder", "err_badSignature", o, abi.encodeCall(ITradeToken.mtxCancelOrder, (o, sg)), k.relayer);
    }

    /// One trade-side call by `caller`; `o` identifies the order (hash, lane, floor) whose state is recorded.
    function _pTradeRec(Tk memory k, string memory entry, string memory name, ITradeToken.TradeOrder memory o,
        bytes memory cd, address caller) internal
    {
        MetaTokenBase t = MetaTokenBase(k.t);
        bytes32 h = t.tradeOrderDigest(o);
        k.oh = h;
        _pRec(k, _pH(entry, "addr", name), caller, cd,
            _pD2("tradeOrderDigest", h, "cancelOrderDigest", t.cancelOrderDigest(h)), _pL(o.batch));
        k.oh = 0;
    }

    function _pTradeInvalidate(Tk memory k) internal {
        MetaTokenBase t = MetaTokenBase(k.t);
        uint256 lane = _pLn(k);
        bytes32 dg = t.invalidateNoncesDigest(k.signer, lane, 5);
        bytes memory sg = _pEcdsa(k.pk, dg);
        _pRec(k, _pH("mtxInvalidateNonces", "addr", "ok"), k.relayer,
            abi.encodeCall(ITradeToken.mtxInvalidateNonces, (k.signer, lane, 5, sg)), _pD("invalidateNoncesDigest", dg), _pL(lane));
        _pRec(k, _pH("mtxInvalidateNonces", "addr", "err_notIncreasing"), k.relayer,
            abi.encodeCall(ITradeToken.mtxInvalidateNonces, (k.signer, lane, 5, sg)), _pD("invalidateNoncesDigest", dg), _pL(lane));
        // an order below the floor is dead
        ITradeToken.TradeOrder memory o = _pOrder(k, lane);
        _pMtr(k, "err_nonceInvalidated", o, _pTSign(k, o), 5_000, 4_000, k.dex);
        dg = t.invalidateNoncesDigest(k.signer, lane, 9);
        _pRec(k, _pH("mtxInvalidateNonces", "addr", "err_badSignature"), k.relayer,
            abi.encodeCall(ITradeToken.mtxInvalidateNonces, (k.signer, lane, 9, _pEcdsa(k.payeePk, dg))), _pD("invalidateNoncesDigest", dg), _pL(lane));
        dg = t.invalidateNoncesDigest(k.signer, lane, type(uint256).max);
        _pRec(k, _pH("mtxInvalidateNonces", "addr", "err_aboveCap"), k.relayer,
            abi.encodeCall(ITradeToken.mtxInvalidateNonces, (k.signer, lane, type(uint256).max, _pEcdsa(k.pk, dg))),
            _pD("invalidateNoncesDigest", dg), _pL(lane));
    }

    // ------------------------------------------------------------------ the UA twins, native and derived

    function _pTradeUa(Tk memory k) internal {
        _pTradeUaOne(k, MetaTxLib.pad(k.signer), "native");
        if (k.uaD != 0) _pTradeUaOne(k, k.uaD, "derived");
    }

    function _pUTradeRec(Tk memory k, string memory entry, string memory name, ITradeToken.UATradeOrder memory o,
        bytes memory cd, address caller) internal
    {
        MetaTokenBase t = MetaTokenBase(k.t);
        bytes32 h = t.uaTradeOrderDigest(o);
        k.oh = h;
        _pRec(k, _pH(entry, "ua", name), caller, cd,
            _pD2("uaTradeOrderDigest", h, "cancelOrderDigest", t.cancelOrderDigest(h)), _pL(o.batch));
        k.oh = 0;
    }

    function _pUAuth(Tk memory k, bytes32 who, ITradeToken.UATradeOrder memory o) internal view returns (bytes memory) {
        return _pAuth(k, who, UAKinds.PURPOSE_TRADE, MetaTokenBase(k.t).uaTradeOrderDigest(o));
    }

    /// `uaTrade` of `o` under `au`, the fill-or-kill fill, by `caller`.
    function _pUtr(Tk memory k, string memory name, ITradeToken.UATradeOrder memory o, bytes memory au, address caller)
        internal
    {
        _pUTradeRec(k, "uaTrade", name, o, abi.encodeCall(ITradeToken.uaTrade, (o, au, _pFill(k, 5_000, 4_000))), caller);
    }

    function _pTradeUaOne(Tk memory k, bytes32 who, string memory tag) internal {
        ITradeToken.UATradeOrder memory o = _pUOrder(k, who, 0);
        bytes memory au = _pUAuth(k, who, o);
        _pUtr(k, string.concat("ok_", tag), o, au, k.dex);
        _pUtr(k, string.concat("err_orderClosed_", tag), o, au, k.dex);
        o = _pUOrder(k, who, 0);
        au = _pUAuth(k, who, o);
        _pUtr(k, string.concat("err_notDex_", tag), o, au, k.relayer);
        _pUtr(k, string.concat("err_badAuth_", tag), o,
            _pBadAuth(k, who, UAKinds.PURPOSE_TRADE, MetaTokenBase(k.t).uaTradeOrderDigest(o)), k.dex);
        _pTradeUaCancel(k, who, tag, o);
        uint256 lane = _pLn(k);
        bytes32 dg = MetaTokenBase(k.t).uaInvalidateNoncesDigest(who, lane, 5);
        bytes memory ia = _pAuth(k, who, UAKinds.PURPOSE_TRADE, dg);
        _pRec(k, _pH("uaInvalidateNonces", "ua", string.concat("ok_", tag)), k.relayer,
            abi.encodeCall(ITradeToken.uaInvalidateNonces, (who, lane, 5, ia)), _pD("uaInvalidateNoncesDigest", dg), _pL(lane));
        _pRec(k, _pH("uaInvalidateNonces", "ua", string.concat("err_notIncreasing_", tag)), k.relayer,
            abi.encodeCall(ITradeToken.uaInvalidateNonces, (who, lane, 5, ia)), _pD("uaInvalidateNoncesDigest", dg), _pL(lane));
        o = _pUOrder(k, who, lane);
        _pUtr(k, string.concat("err_nonceInvalidated_", tag), o, _pUAuth(k, who, o), k.dex);
        _pTradeUaInvBad(k, who, tag, lane);
    }

    function _pTradeUaInvBad(Tk memory k, bytes32 who, string memory tag, uint256 lane) internal {
        bytes32 dg = MetaTokenBase(k.t).uaInvalidateNoncesDigest(who, lane, 9);
        _pRec(k, _pH("uaInvalidateNonces", "ua", string.concat("err_badAuth_", tag)), k.relayer,
            abi.encodeCall(ITradeToken.uaInvalidateNonces, (who, lane, 9, _pBadAuth(k, who, UAKinds.PURPOSE_TRADE, dg))),
            _pD("uaInvalidateNoncesDigest", dg), _pL(lane));
    }

    function _pTradeUaCancel(Tk memory k, bytes32 who, string memory tag, ITradeToken.UATradeOrder memory o) internal {
        MetaTokenBase t = MetaTokenBase(k.t);
        bytes32 cd = t.cancelOrderDigest(t.uaTradeOrderDigest(o));
        bytes memory ca = _pAuth(k, who, UAKinds.PURPOSE_TRADE, cd);
        _pUTradeRec(k, "uaCancelOrder", string.concat("ok_", tag), o, abi.encodeCall(ITradeToken.uaCancelOrder, (o, ca)), k.relayer);
        _pUTradeRec(k, "uaCancelOrder", string.concat("ok_alreadyClosedNoop_", tag), o,
            abi.encodeCall(ITradeToken.uaCancelOrder, (o, ca)), k.relayer);
        _pUTradeRec(k, "uaCancelOrder", string.concat("err_badAuth_", tag), o,
            abi.encodeCall(ITradeToken.uaCancelOrder, (o, _pBadAuth(k, who, UAKinds.PURPOSE_TRADE, cd))), k.relayer);
    }

    // =================================================================================================================
    // two faults at once: the order of the checks (CTR-MTX-17: 1 envelope, 2 signature, 3 shape, 4 nonce use)
    // =================================================================================================================

    function _pTwoFault(Tk memory k) internal {
        MetaTxLib.MetaTransaction memory m = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        m.validUntil = P_T0 - 1;
        _pMx(k, "mtxExecute", "twoFault_expired_badSignature", "", IMetaTx.mtxExecute.selector, m, _pBadSg(k, m), k.relayer);
        m = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        m.validUntil = P_T0 - 1;
        _pMx(k, "mtxExecute", "twoFault_unauthorizedRelayer_expired", "", IMetaTx.mtxExecute.selector, m, _pSgM(k, m), k.payee);
        m = _pMt(k, _pCancel(7), 0, 0x04, 0, address(0));
        m.validUntil = P_T0 - 1;
        _pX(k, "twoFault_expired_unknownMode", m);
        m = _pMt(k, _pCancel(7), 0, 0x04, 0, address(0));
        m.nonce = 3;
        _pX(k, "twoFault_unknownMode_badNonce", m);
        m = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        m.nonce = 3;
        _pMx(k, "mtxExecute", "twoFault_badNonce_badSignature", "", IMetaTx.mtxExecute.selector, m, _pBadSg(k, m), k.relayer);
        m = _pMt(k, hex"deadbeef", 0, P_RR, 0, address(0));
        _pMx(k, "mtxExecute", "twoFault_selectorNotAllowed_badSignature", "", IMetaTx.mtxExecute.selector, m, _pBadSg(k, m), k.relayer);
        m = _pMt(k, _pCancel(7), 0, P_RR | P_PCT, 100, address(0));
        m.nonce = 1;
        _pX(k, "twoFault_feeClass_replay", m);
        _pTwoFaultUa(k);
    }

    function _pBadSg(Tk memory k, MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        return _pEcdsa(k.payeePk, MetaTokenBase(k.t).mtxDigest(m));
    }

    function _pTwoFaultUa(Tk memory k) internal {
        bytes32 s = MetaTxLib.pad(k.signer);
        MetaTxLib.UAMetaTransaction memory m = _pUm(k, s, _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        m.validUntil = P_T0 - 1;
        _pUx(k, "twoFault_expired_badAuth", "", m, _pBadAuth(k, s, UAKinds.PURPOSE_METATX, MetaTokenBase(k.t).uaDigest(m)), k.relayer);
        m = _pUm(k, s, _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        m.nonce = 3;
        _pUx(k, "twoFault_badNonce_badAuth", "", m, _pBadAuth(k, s, UAKinds.PURPOSE_METATX, MetaTokenBase(k.t).uaDigest(m)), k.relayer);
        m = _pUm(k, s, _pCancel(7), 0, P_RR, 0, address(0));
        _pUx(k, "twoFault_unknownOp_badAuth", "", m, _pBadAuth(k, s, UAKinds.PURPOSE_METATX, MetaTokenBase(k.t).uaDigest(m)), k.relayer);
        m = _pUm(k, s, abi.encodePacked(_pAmt(k, 1), bytes1(0x01)), 0, P_RR, 0, address(0));
        m.nonce = 1;
        _pU(k, "twoFault_dataShape_replay", m);
        m = _pUm(k, s, _pCancel(7), 0, P_RR, 0, address(0));
        m.nonce = 1;
        _pU(k, "twoFault_unknownOp_replay", m);
        if (k.uaD != 0) {
            m = _pUm(k, k.uaD, _pAmt(k, 1_000), 0, P_RR, 0, address(0));
            m.validUntil = P_T0 - 1;
            _pUx(k, "twoFault_derived_expired_badAuth", "", m, _pBadAuth(k, k.uaD, UAKinds.PURPOSE_METATX, MetaTokenBase(k.t).uaDigest(m)), k.relayer);
        }
    }

    /// §3.8 on the remaining entries: `mtxExecuteWithFee`, an `mtxBatch` item and a `uaBatch` item break the fee rule AND revert.
    function _pBothFailMore(Tk memory k) internal {
        MetaTxLib.MetaTransaction memory m = _pMt(k, _pAmt(k, P_BIG), 0, P_RR | P_PCT, 20_000, address(0));
        _pMx(k, "mtxExecuteWithFee", "bothFail_feeExceedsCap_callReverts", "fee-error-first", MetaTokenBase.mtxExecuteWithFee.selector, m, _pSgM(k, m), k.relayer);
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](2);
        bytes[] memory sg = new bytes[](2);
        ms[0] = _pMt(k, _pCancel(7), 0, P_RR, 0, address(0));
        ms[1] = m;
        ms[1].batch = k.lane++;
        sg[0] = _pSgM(k, ms[0]);
        sg[1] = _pSgM(k, ms[1]);
        H memory h = H("mtxBatch", "addr", "bothFail_item_feeExceedsCap_callReverts", "fee-error-first");
        _pRec(k, h, k.relayer, abi.encodeCall(IMetaTx.mtxBatch, (ms, sg)),
            _pD2("mtxDigest0", MetaTokenBase(k.t).mtxDigest(ms[0]), "mtxDigest1", MetaTokenBase(k.t).mtxDigest(ms[1])), _pL2(ms[0].batch, ms[1].batch));
        _pBothFailUaBatch(k);
    }

    function _pBothFailUaBatch(Tk memory k) internal {
        bytes32 s = MetaTxLib.pad(k.signer);
        MetaTxLib.UAMetaTransaction[] memory us = new MetaTxLib.UAMetaTransaction[](2);
        bytes[] memory au = new bytes[](2);
        us[0] = _pUm(k, s, _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        us[1] = _pUm(k, s, _pAmt(k, P_BIG), 0, P_RR | P_PCT, 20_000, address(0));
        au[0] = _pAuM(k, us[0]);
        au[1] = _pAuM(k, us[1]);
        _pRec(k, H("uaBatch", "ua", "bothFail_item_feeExceedsCap_callReverts", "fee-error-first"), k.relayer,
            abi.encodeCall(IUALedger.uaBatch, (us, au)),
            _pD2("uaDigest0", MetaTokenBase(k.t).uaDigest(us[0]), "uaDigest1", MetaTokenBase(k.t).uaDigest(us[1])), _pL2(us[0].batch, us[1].batch));
    }

    // =================================================================================================================
    // a token with no UA registry: every ua* entry refuses with UALedgerOff, the address path is unaffected
    // =================================================================================================================

    function _pLedgerOff(Tk memory k) internal {
        bytes32 s = MetaTxLib.pad(k.signer);
        bytes32 p = MetaTxLib.pad(k.payee);
        _pX(k, "ok_cancelNonce", _pMt(k, _pCancel(7), 0, P_RR, 0, address(0)));
        _pU(k, "err_ledgerOff_uaExecute", _pUm(k, s, _pAmt(k, 1_000), 0, P_RR, 0, address(0)));
        _pUt2(k, "err_ledgerOff_uaExecuteTransfer", _pUt(k, s, p, 1_000, 0, 0, P_RR, 0, address(0)));
        MetaTxLib.UAMetaTransaction[] memory us = new MetaTxLib.UAMetaTransaction[](1);
        bytes[] memory au = new bytes[](1);
        us[0] = _pUm(k, s, _pAmt(k, 1_000), 0, P_RR, 0, address(0));
        au[0] = _pAuM(k, us[0]);
        _pRec(k, _pH("uaBatch", "ua", "err_ledgerOff"), k.relayer, abi.encodeCall(IUALedger.uaBatch, (us, au)),
            _pD("uaDigest0", MetaTokenBase(k.t).uaDigest(us[0])), _pL(us[0].batch));
        MetaTxLib.UAMetaTransfer[] memory ts = new MetaTxLib.UAMetaTransfer[](1);
        ts[0] = _pUt(k, s, p, 1_000, 0, 0, P_RR, 0, address(0));
        au[0] = _pAuT(k, ts[0]);
        _pRec(k, _pH("uaBatchTransfer", "ua", "err_ledgerOff"), k.relayer, abi.encodeCall(IUALedger.uaBatchTransfer, (ts, au)),
            _pD("uaTransferDigest0", MetaTokenBase(k.t).uaTransferDigest(ts[0])), _pL(ts[0].batch));
        _pRec(k, _pH("transferToUA", "ua", "err_ledgerOff"), k.signer, abi.encodeCall(IUALedger.transferToUA, (bytes32(uint256(1) << 200), 100)),
            _pD("none", 0), _pL(0));
        ITradeToken.UATradeOrder memory o = _pUOrder(k, s, 0);
        _pUtr(k, "err_ledgerOff_uaTrade", o, _pUAuth(k, s, o), k.dex);
        _pUcOne(k, "err_ledgerOff_uaCancelNonce", s, k.lane++, P_VU, false);
    }

    // =================================================================================================================
    // contract signers (the signature code the split moves): an ERC-1271 wallet on the address path and the UA native
    // path, an EIP-7702 account (code = 0xef0100 || delegate) on both
    // =================================================================================================================

    uint256 internal constant P_OWNER = 0xD3D3; // the key a Mock1271 wallet / delegate accepts
    uint256 internal constant P_E7702 = 0x7702; // the EOA that carries the delegation designator

    function _pAs(Tk memory k, address who, uint256 pk) internal pure returns (Tk memory w) {
        w = Tk(k.kind, k.t, pk, who, k.payeePk, k.payee, k.feeTo, k.relayer, bytes32(0), k.style, k.und, k.dex, k.lane, 0);
    }

    function _pFundSigner(Tk memory k, address to) internal {
        vm.prank(k.signer);
        IERC20(k.t).transfer(to, 100_000);
    }

    function _pSigners(Tk memory k) internal {
        // ERC-1271 wallet (owner key P_OWNER), funded
        Tk memory w = _pAs(k, address(new Mock1271(vm.addr(P_OWNER), 0)), P_OWNER);
        _pFundSigner(k, w.signer);
        _pSignerCases(w, "w1271", true);
        // wallets that revert / answer a wrong magic value (the signature is the owner's)
        Tk memory r = _pAs(k, address(new Mock1271(vm.addr(P_OWNER), 1)), P_OWNER);
        MetaTxLib.MetaTransaction memory m = _pMt(r, _pCancel(7), 0, P_RR, 0, address(0));
        _pX(r, "err_w1271reverts", m);
        Tk memory g = _pAs(k, address(new Mock1271(vm.addr(P_OWNER), 2)), P_OWNER);
        m = _pMt(g, _pCancel(7), 0, P_RR, 0, address(0));
        _pX(g, "err_w1271wrongMagic", m);
        MetaTxLib.UAMetaTransaction memory u = _pUm(r, MetaTxLib.pad(r.signer), _pAmt(r, 1_000), 0, P_RR, 0, address(0));
        _pU(r, "err_w1271reverts", u);
        // EIP-7702: the EOA's code is the designator of a delegate that accepts P_OWNER
        address e = vm.addr(P_E7702);
        vm.etch(e, abi.encodePacked(hex"ef0100", address(new Mock1271(vm.addr(P_OWNER), 0))));
        Tk memory d = _pAs(k, e, P_E7702);
        _pFundSigner(k, e);
        _pSignerCases(d, "e7702", false);
        // signed by the delegate's owner instead of the account's key: refused, the delegate's ERC-1271 is never asked
        // (one rule on both paths, CTR-UA-24, owner ruling 2026-10-30 D1: a designator signs with its own key only)
        m = _pMt(d, _pCancel(7), 0, P_RR, 0, address(0));
        _pMx(d, "mtxExecute", "err_e7702_viaDelegate_addr", "", IMetaTx.mtxExecute.selector, m, _pEcdsa(P_OWNER, MetaTokenBase(d.t).mtxDigest(m)), d.relayer);
        u = _pUm(d, MetaTxLib.pad(e), _pAmt(d, 1_000), 0, P_RR, 0, address(0));
        _pUx(d, "err_e7702_viaDelegate", "", u, _pEcdsa(P_OWNER, MetaTokenBase(d.t).uaDigest(u)), d.relayer);
    }

    /// `mtxExecute`, `uaExecute`, a typed transfer and a trade for the contract signer `w`: valid and wrong signature.
    function _pSignerCases(Tk memory w, string memory tag, bool trade) internal {
        MetaTxLib.MetaTransaction memory m = _pMt(w, _pCancel(7), 0, P_RR, 0, address(0));
        _pX(w, string.concat("ok_", tag), m);
        m = _pMt(w, _pCancel(7), 0, P_RR, 0, address(0));
        _pMx(w, "mtxExecute", string.concat("err_", tag, "_badSignature"), "", IMetaTx.mtxExecute.selector, m, _pBadSg(w, m), w.relayer);
        MetaTxLib.MetaTransfer memory t = _pTr(w, w.payee, 1_000, 0, 0, P_RR, 0, address(0));
        _pXt(w, string.concat("ok_", tag), t);
        t = _pTr(w, w.payee, 1_000, 0, 0, P_RR, 0, address(0));
        _pXtS(w, string.concat("err_", tag, "_badSignature"), t, _pEcdsa(w.payeePk, MetaTokenBase(w.t).mtxTransferDigest(t)), w.relayer);
        bytes32 id = MetaTxLib.pad(w.signer);
        MetaTxLib.UAMetaTransaction memory u = _pUm(w, id, _pAmt(w, 1_000), 0, P_RR, 0, address(0));
        _pU(w, string.concat("ok_", tag), u);
        u = _pUm(w, id, _pAmt(w, 1_000), 0, P_RR, 0, address(0));
        _pUx(w, string.concat("err_", tag, "_badAuth"), "", u, _pEcdsa(w.payeePk, MetaTokenBase(w.t).uaDigest(u)), w.relayer);
        if (!trade) return;
        ITradeToken.TradeOrder memory o = _pOrder(w, 0);
        _pMtr(w, string.concat("ok_", tag), o, _pTSign(w, o), 5_000, 4_000, w.dex);
        o = _pOrder(w, 0);
        _pMtr(w, string.concat("err_", tag, "_badSignature"), o, _pEcdsa(w.payeePk, MetaTokenBase(w.t).tradeOrderDigest(o)), 5_000, 4_000, w.dex);
    }

    // =================================================================================================================
    // the allowlist tables (test_ruleTableParity)
    // =================================================================================================================

    /// Per token of the rig × `probe` selector: listed or not, the probe through `mtxExecute` and through `uaExecute`.
    function _pRules(bytes4[] memory probe) internal returns (RuleRow[] memory rows) {
        uint256 nt;
        for (uint256 q; q < tks.length; ++q) if (tks[q].style != 2) ++nt;
        rows = new RuleRow[](nt * probe.length);
        uint256 w;
        for (uint256 q; q < tks.length; ++q) {
            Tk memory k = tks[q];
            if (k.style == 2) continue; // the ledger-off token has its own cases
            k.lane = 900_000; // above every run step: a fresh lane, so the probe never meets a used nonce
            (bytes4[] memory ls, uint8[] memory fc, uint8[] memory aa) = MetaTokenBase(k.t).mtxSelectors();
            for (uint256 i; i < probe.length; ++i) {
                RuleRow memory r;
                (r.kind, r.sel) = (k.kind, probe[i]);
                for (uint256 j; j < ls.length; ++j) {
                    if (ls[j] == probe[i]) (r.inList, r.feeClass, r.amountArg) = (true, fc[j], aa[j]);
                }
                uint256 snap = vm.snapshotState();
                (r.mtxRev, r.uaRev) = _pProbe(k, probe[i]);
                r.mtxAllowed = r.mtxRev != IMetaTx.MtxSelectorNotAllowed.selector;
                r.uaAllowed = r.uaRev != IUALedger.MetaTxUnknownOp.selector;
                vm.revertToState(snap);
                rows[w++] = r;
            }
        }
    }

    /// The probes carry only the 4-byte selector, so they fail on shape: the revert selector says whether the allowlist
    /// refused them. The signature / auth is built BEFORE the prank (building it calls a view of the token, which would
    /// consume the prank and turn every probe into `MetaTxUnauthorizedRelayer`).
    function _pProbe(Tk memory k, bytes4 sel) internal returns (bytes4 mtxRev, bytes4 uaRev) {
        MetaTxLib.MetaTransaction memory m = _pMt(k, abi.encodePacked(sel), 0, P_RR, 0, address(0));
        bytes memory cd = abi.encodeCall(IMetaTx.mtxExecute, (m, _pSgM(k, m)));
        vm.prank(k.relayer);
        (bool ok, bytes memory out) = k.t.call(cd);
        mtxRev = ok ? bytes4(0) : bytes4(out);
        MetaTxLib.UAMetaTransaction memory u = _pUm(k, MetaTxLib.pad(k.signer), abi.encodePacked(sel), 0, P_RR, 0, address(0));
        cd = abi.encodeCall(IUALedger.uaExecute, (u, _pAuM(k, u)));
        vm.prank(k.relayer);
        (ok, out) = k.t.call(cd);
        uaRev = ok ? bytes4(0) : bytes4(out);
    }
}

// =====================================================================================================================
// the rigs: one per token family; each builds clones (CREATE, so stable addresses) of its two kinds
// =====================================================================================================================

/// `NONE` and `UNDERLYING` on the UA ledger fixture (a registry with the stand-in verifiers, `p256` / `bip340` UAs).
contract PlainRig is UALedgerBase, ParityCases {
    function init() external {
        setUp();
        vm.warp(P_T0);
        vm.roll(P_BLOCK);
        address dex = address(new ParityDex());
        // NONE: alice holds 1_000_000; the rig (the minter) tops her up and funds the derived UA
        tok.mint(alice, 9_000_000);
        vm.prank(alice);
        tok.transferToUA(uaP, 2_000_000);
        tks.push(Tk("NONE", address(tok), ALICE_PK, alice, BOB_PK, bob, FEE_TO, RELAYER, uaP, 0, address(0), dex, 0, 0));
        // UNDERLYING: 10_000_000 wrapped units
        _wrapFor(alice, 10_000_000);
        vm.prank(alice);
        wrp.transferToUA(uaP, 2_000_000);
        tks.push(Tk("UNDERLYING", address(wrp), ALICE_PK, alice, BOB_PK, bob, FEE_TO, RELAYER, uaP, 1, address(und), dex, 0, 0));
        // NONE with no UA registry (the ledger off)
        address off = Clones.clone(address(new NoUnderlyingToken(1, plainEnv(address(this), address(0), chainUidA, address(0), false), "")));
        NoUnderlyingToken(off).initialize(address(this), 1, abi.encode(noneInit("Points", "PTS", 6, 10_000_000, alice, address(this))));
        tks.push(Tk("NONE_LEDGEROFF", off, ALICE_PK, alice, BOB_PK, bob, FEE_TO, RELAYER, 0, 2, address(0), dex, 0, 0));
    }

    function _pDerivedAuth(Tk memory k, bytes32 purpose, bytes32 digest) internal view override returns (bytes memory) {
        uint16 kind = lreg.kindOf(k.uaD);
        return _auth(lreg, kind, _key(kind), purpose, digest);
    }

    /// The stand-in verifier accepts `keccak256(abi.encode(key, message))`: sign another message.
    function _pBadDerived(Tk memory k, bytes32 purpose, bytes32 digest) internal view override returns (bytes memory) {
        uint16 kind = lreg.kindOf(k.uaD);
        bytes memory key = _key(kind);
        return abi.encode(key, _sig(key, bytes32(uint256(lreg.uaMessage(kind, purpose, digest)) ^ 1)));
    }
}

/// `NONE_PQZ` and `UNDERLYING_PQZ` at the committed parameter set, the `PQZ` precompile mocked as in the PQZ suites:
/// the ops are relayed with a proof the mock accepts, everything else is real code.
contract PqzRig is PqzFixture, ParityCases {
    uint256 internal constant SK = 0xA11CE;
    uint256 internal constant PK2 = 0xB0B;

    function init() external {
        vm.warp(P_T0);
        vm.roll(P_BLOCK);
        _stack();
        address dex = address(new ParityDex());
        bytes32 uaD = _mldsaUA(9);
        address signer = vm.addr(SK);
        // NONE_PQZ
        address t = _pClone(address(noneImpl), _cfg(uint256(1) << 40));
        NoUnderlyingPqzToken(t).mint(signer, 20_000_000);
        NoUnderlyingPqzToken(t).mintToUA(uaD, 2_000_000);
        tks.push(Tk("NONE_PQZ", t, SK, signer, PK2, vm.addr(PK2), address(0xFEE), address(0xBEEF), uaD, 0, address(0), dex, 0, 0));
        // UNDERLYING_PQZ: one 1:1 leg
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        address impl = Catalogue.release(factory, IOpenFactory.TokenKind.UNDERLYING_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(UnderlyingPqzToken).creationCode);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = 1 << AdminLib.PAYABLE;
        c.roles.minter = address(0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        address w = _pClone(impl, c);
        usd.mint(signer, 20_000_000);
        vm.startPrank(signer);
        usd.approve(w, 20_000_000);
        UnderlyingToken(payable(w)).wrap(20_000_000);
        UnderlyingToken(payable(w)).transferToUA(uaD, 2_000_000);
        vm.stopPrank();
        tks.push(Tk("UNDERLYING_PQZ", w, SK, signer, PK2, vm.addr(PK2), address(0xFEE), address(0xBEEF), uaD, 1, address(usd), dex, 0, 0));
    }

    /// The test plays the factory: a CREATE clone (its address does not depend on the implementation's code).
    function _pClone(address impl, IFactoryToken.TokenConfig memory c) internal returns (address t) {
        t = Clones.clone(impl);
        vm.prank(address(factory));
        MetaTokenBase(t).initialize(address(this), 1, abi.encode(c));
    }

    function _pDerivedAuth(Tk memory, bytes32, bytes32) internal view override returns (bytes memory) {
        return _mlAuth();
    }

    /// A signature of the wrong length: the `mldsa65` verifier rejects it.
    function _pBadDerived(Tk memory, bytes32, bytes32) internal view override returns (bytes memory) {
        return abi.encode(bytes(""), new bytes(ML65_SIG - 1));
    }

    function _pExtras(Tk memory k) internal override {
        PqzLayer t = PqzLayer(k.t);
        bytes memory shield = abi.encodeCall(PqzLayer.mtxShield, (alice, 10));
        _pX(k, "ok_shield_noFee", _pMt(k, shield, 0, P_RR, 0, address(0)));
        _pX(k, "ok_shield_fixedFee", _pMt(k, shield, 0, P_RR | P_RF | P_FIX, 7, k.feeTo));
        _pX(k, "err_percentFeeRefused", _pMt(k, shield, 0, P_RR | P_PCT, 100, address(0)));
        _pX(k, "err_proofOpBadNonce", _pBadNonce(k, shield));
        _pU(k, "ok_native_shield_fixedFee", _pUm(k, MetaTxLib.pad(k.signer), shield, 0, P_RR | P_FIX, 7, address(0)));
        _pU(k, "ok_derived_shield", _pUm(k, k.uaD, shield, 0, P_RR, 0, address(0)));
        _pU(k, "ok_derived_shield_fixedFee", _pUm(k, k.uaD, shield, 0, P_RR | P_FIX, 5, address(0)));
        // PQZ ops never batch (CTR-PQZ-21)
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](1);
        bytes[] memory sg = new bytes[](1);
        ms[0] = _pMt(k, shield, 0, P_RR, 0, address(0));
        sg[0] = _pSgM(k, ms[0]);
        _pRec(k, _pH("mtxBatch", "addr", "err_pqzOpNotBatchable"), k.relayer, abi.encodeCall(IMetaTx.mtxBatch, (ms, sg)),
            _pD("mtxDigest0", t.mtxDigest(ms[0])), _pL(ms[0].batch));
        MetaTxLib.UAMetaTransaction[] memory us = new MetaTxLib.UAMetaTransaction[](1);
        bytes[] memory au = new bytes[](1);
        us[0] = _pUm(k, MetaTxLib.pad(k.signer), shield, 0, P_RR, 0, address(0));
        au[0] = _pAuM(k, us[0]);
        _pRec(k, _pH("uaBatch", "ua", "err_pqzOpNotBatchable"), k.relayer, abi.encodeCall(IUALedger.uaBatch, (us, au)),
            _pD("uaDigest0", t.uaDigest(us[0])), _pL(us[0].batch));
        _pTransfers(k);
        _pRelayedPrepare(k);
    }

    function _pBadNonce(Tk memory k, bytes memory data) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m = _pMt(k, data, 0, P_RR, 0, address(0));
        m.nonce = 4;
    }

    /// Prepare `acc` words (anyone, idempotent), relayed.
    function _pRelayedPrepare(Tk memory k) internal {
        _pX(k, "ok_prepareAcc", _pMt(k, abi.encodeCall(PqzLayer.mtxPrepareAcc, (bob, 0)), 0, P_RR, 0, address(0)));
        _pX(k, "ok_prepareAcc_again", _pMt(k, abi.encodeCall(PqzLayer.mtxPrepareAcc, (bob, 0)), 0, P_RR, 0, address(0)));
    }

    /// A relayed op 1 (single transfer, proof mocked): the statement carries the envelope binding of its own path.
    function _pTransfers(Tk memory k) internal {
        PqzLayer t = PqzLayer(k.t);
        bytes memory out = _out(1, true);
        bytes memory pl = _payloadFor(t, alice, bob, bytes32(0), out);
        bytes memory data = abi.encodeCall(PqzLayer.mtxConfidentialTransferSingle, (pl, hex"c0de", _mlAuth(), _benT(pl), bytes("")));
        MetaTxLib.MetaTransaction memory m = _pMt(k, data, 0, P_RR | P_FIX, 3, address(0));
        _pX(k, "ok_transferSingle_addr", m);
        _pMx(k, "mtxExecute", "err_transferSingle_replay", "", IMetaTx.mtxExecute.selector, m, _pSgM(k, m), k.relayer);
        out = _out(2, true);
        pl = _payloadFor(t, alice, bob, bytes32(0), out);
        data = abi.encodeCall(PqzLayer.mtxConfidentialTransferSingle, (pl, hex"c0de", _mlAuth(), _benT(pl), bytes("")));
        MetaTxLib.UAMetaTransaction memory u = _pUm(k, MetaTxLib.pad(k.signer), data, 0, P_RR, 0, address(0));
        _pU(k, "ok_transferSingle_ua", u);
        // op 7, two recipients (alice's debit; bob and carol credited)
        _mockOp(7, 1);
        bytes32[] memory rec = new bytes32[](2);
        (rec[0], rec[1]) = (bob, carol);
        out = _blob(11, _outLen(2, true));
        pl = _mpayload(t.pqzAccount(alice).pendingCount, 0, alice, bytes32(0), rec, out, bytes(""));
        data = abi.encodeCall(PqzLayer.mtxConfidentialTransfer, (pl, hex"c0de", _mlAuth(), _benM(pl), bytes("")));
        _pX(k, "ok_transferMulti_addr", _pMt(k, data, 0, P_RR | P_FIX, 3, address(0)));
        // the precompile rejects the proof: the whole envelope reverts, its nonce unused
        out = _out(3, true);
        pl = _payloadFor(t, alice, bob, bytes32(0), out);
        data = abi.encodeCall(PqzLayer.mtxConfidentialTransferSingle, (pl, hex"c0de", _mlAuth(), _benT(pl), bytes("")));
        _mockOp(1, 0);
        _pX(k, "err_transferSingle_proofRejected", _pMt(k, data, 0, P_RR, 0, address(0)));
        _mockOp(1, 1);
    }
}

/// `NONE_ZETHER` and `UNDERLYING_ZETHER` (BLS12-381 classical Zether, real prover, real verifiers).
contract ZetherRig is ZetherFixture, ParityCases {
    uint256 internal constant SK = 0xA11CE;
    uint256 internal constant PK2 = 0xB0B;

    function init() external {
        vm.warp(P_T0);
        vm.roll(P_BLOCK);
        _stack();
        _users();
        address dex = address(new ParityDex());
        address signer = vm.addr(SK);
        // NONE_ZETHER
        address t = _pClone(address(noneImpl), _cfg(true, uint256(1) << 40));
        NoUnderlyingZetherToken(t).mint(signer, 20_000_000);
        vm.prank(signer);
        MetaTokenBase(t).transferToUA(ZetherTypes.UA.unwrap(bob.ua), 2_000_000);
        tks.push(Tk("NONE_ZETHER", t, SK, signer, PK2, vm.addr(PK2), address(0xFEE), address(0xBEEF), ZetherTypes.UA.unwrap(bob.ua), 0, address(0), dex, 0, 0));
        // UNDERLYING_ZETHER: one 1:1 leg
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        address impl = Catalogue.release(factory, IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1, _zenv(),
            type(UnderlyingZetherToken).creationCode);
        IFactoryToken.TokenConfig memory c = _cfg(true, uint256(1) << 40);
        c.features = 1 << AdminLib.PAYABLE;
        c.roles.minter = address(0);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        address w = _pClone(impl, c);
        usd.mint(signer, 20_000_000);
        vm.startPrank(signer);
        usd.approve(w, 20_000_000);
        UnderlyingToken(payable(w)).wrap(20_000_000);
        UnderlyingToken(payable(w)).transferToUA(ZetherTypes.UA.unwrap(bob.ua), 2_000_000);
        vm.stopPrank();
        tks.push(Tk("UNDERLYING_ZETHER", w, SK, signer, PK2, vm.addr(PK2), address(0xFEE), address(0xBEEF), ZetherTypes.UA.unwrap(bob.ua), 1, address(usd), dex, 0, 0));
    }

    function _pClone(address impl, IFactoryToken.TokenConfig memory c) internal returns (address t) {
        t = Clones.clone(impl);
        vm.prank(address(factory));
        MetaTokenBase(t).initialize(address(this), 1, abi.encode(c));
    }

    /// A Zether UA signs like a stored kind: `abi.encode(bytes(""), Schnorr by x over the ua_msg)`.
    function _pDerivedAuth(Tk memory, bytes32 purpose, bytes32 digest) internal view override returns (bytes memory) {
        return abi.encode(bytes(""), ZetherKeys.schnorr(bob.x, reg.uaMessage(_zkind(), purpose, digest), bls));
    }

    /// A Schnorr signature by another Zether key.
    function _pBadDerived(Tk memory, bytes32 purpose, bytes32 digest) internal view override returns (bytes memory) {
        return abi.encode(bytes(""), ZetherKeys.schnorr(alice.x, reg.uaMessage(_zkind(), purpose, digest), bls));
    }

    function _pExtras(Tk memory k) internal override {
        ZetherLayer t = ZetherLayer(k.t);
        bytes32 bUa = ZetherTypes.UA.unwrap(bob.ua);
        bytes memory shield = abi.encodeCall(ZetherLayer.mtxShield, (bUa, 10));
        _pX(k, "ok_shield_noFee", _pMt(k, shield, 0, P_RR, 0, address(0)));
        _pX(k, "ok_shield_fixedFee", _pMt(k, shield, 0, P_RR | P_RF | P_FIX, 7, k.feeTo));
        _pX(k, "err_percentFeeRefused", _pMt(k, shield, 0, P_RR | P_PCT, 100, address(0)));
        _pU(k, "ok_native_shield_fixedFee", _pUm(k, MetaTxLib.pad(k.signer), shield, 0, P_RR | P_FIX, 7, address(0)));
        _pU(k, "ok_derived_shield", _pUm(k, k.uaD, shield, 0, P_RR, 0, address(0)));
        // a relayed confidential transfer: the proof binds the envelope of its own path
        _pFundAlice(k);
        _pTransfers(k, t);
    }

    /// alice holds 500 shielded units, rolled over, to prove from.
    function _pFundAlice(Tk memory k) internal {
        vm.prank(k.signer);
        ZetherLayer(k.t).mtxShield(ZetherTypes.UA.unwrap(alice.ua), 500);
        ZetherLayer(k.t).mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
    }

    function _pTransfers(Tk memory k, ZetherLayer t) internal {
        MetaTxLib.MetaTransaction memory m = _pMt(k, "", 0, P_RR | P_FIX, 3, address(0));
        Tx memory x = _proveTransfer(t, alice, bob, 100, 500, carol.ua, t.envelopeBinding(m));
        m.data = abi.encodeCall(ZetherLayer.mtxConfidentialTransferSingle, (x.payload, x.proof, bytes(""), ZetherTypes.UA.unwrap(carol.ua), bytes("")));
        _pX(k, "ok_transferSingle_addr", m);
        _pMx(k, "mtxExecute", "err_transferSingle_replay", "", IMetaTx.mtxExecute.selector, m, _pSgM(k, m), k.relayer);
        // the UA path: its own binding tag
        MetaTxLib.UAMetaTransaction memory u = _pUm(k, MetaTxLib.pad(k.signer), "", 0, P_RR, 0, address(0));
        x = _proveTransfer(t, alice, bob, 10, 500 - 100 - FEE, carol.ua, t.uaEnvelopeBinding(u));
        u.data = abi.encodeCall(ZetherLayer.mtxConfidentialTransferSingle, (x.payload, x.proof, bytes(""), ZetherTypes.UA.unwrap(carol.ua), bytes("")));
        _pU(k, "ok_transferSingle_ua", u);
        // a proof bound to the address path, replayed under the UA path's envelope, is refused
        m = _pMt(k, "", 0, P_RR, 0, address(0));
        x = _proveTransfer(t, alice, bob, 5, 500 - 100 - FEE - 10 - FEE, carol.ua, t.envelopeBinding(m));
        u = _pUm(k, MetaTxLib.pad(k.signer), "", 0, P_RR, 0, address(0));
        u.data = abi.encodeCall(ZetherLayer.mtxConfidentialTransferSingle, (x.payload, x.proof, bytes(""), ZetherTypes.UA.unwrap(carol.ua), bytes("")));
        _pU(k, "err_transferSingle_wrongPathBinding", u);
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// the file
// ---------------------------------------------------------------------------------------------------------------------

contract MetaTxParityTest is ParityIO {
    IRig[] internal rigs;

    function setUp() public {
        PlainRig plain = new PlainRig();
        plain.init();
        rigs.push(IRig(address(plain)));
        PqzRig pqz = new PqzRig();
        pqz.init();
        rigs.push(IRig(address(pqz)));
        ZetherRig zeth = new ZetherRig();
        zeth.init();
        rigs.push(IRig(address(zeth)));
    }

    // ------------------------------------------------------------------ test entry points

    /// Write (`PARITY_WRITE=1`) or replay the whole case set and the allowlist rows.
    function test_parity() public {
        bool write = vm.envOr("PARITY_WRITE", false);
        // the fixture belongs to one set (its closing `set` field); the other sets' cases differ, so the replay is skipped there
        if (!write) vm.skip(!_fixtureIsForThisSet());
        if (write) {
            vm.writeFile(FILE, "");
            vm.writeLine(FILE, "[");
        } else {
            _open();
        }
        _setup(write);
        // the cases: each rig writes / compares its own lines as it produces them
        for (uint256 r; r < rigs.length; ++r) {
            for (uint256 i; i < rigs[r].count(); ++i) {
                for (uint256 st; st < rigs[r].steps(); ++st) rigs[r].run(i, st);
            }
        }
        uint256 nc;
        for (uint256 r; r < rigs.length; ++r) {
            nc += rigs[r].emitted();
            fails += rigs[r].failures();
            if (rigs[r].isDrifted()) drifted = true;
        }
        RuleRow[] memory ru = _rules();
        _finish(write, nc, ru);
        if (write) console2.log("parity fixture written: cases / rule rows", nc, ru.length);
        assertEq(fails, 0, "parity: the code under test differs from the fixture (see the PARITY MISMATCH lines above)");
    }

    /// The allowlists alone: `mtxSelectors()` and the UA verdict, per kind and selector, against the fixture.
    function test_ruleTableParity() public {
        if (vm.envOr("PARITY_WRITE", false)) return; // `test_parity` writes the file in this run
        _open();
        RuleRow[] memory ru = _rules();
        // skip the case lines: the rule lines start with {"rule"
        while (true) {
            bytes memory peek = bytes(vm.readLine(FILE));
            require(peek.length > 3, "parity: the fixture has no rule rows");
            if (peek[2] == "r") {
                _cmpRule(_strip(peek), ru[0], 0);
                break;
            }
        }
        for (uint256 i = 1; i < ru.length; ++i) _cmpRule(_next(false), ru[i], i);
        vm.closeFile(FILE);
        assertEq(fails, 0, "parity: an allowlist differs from the fixture (see the PARITY MISMATCH lines above)");
    }

    // ------------------------------------------------------------------ the rule rows and the closing lines

    /// The first line: each token's address and domain hash. A difference here is a changed SETUP (the fixture or the
    /// token construction), not a behaviour difference, and every digest would follow it: stop at once.
    function _setup(bool write) internal {
        string memory line = '{"setup":1,"tokens":[';
        string memory first;
        for (uint256 r; r < rigs.length; ++r) {
            (string[] memory ks, address[] memory ts, bytes32[] memory ds) = rigs[r].setup();
            for (uint256 i; i < ks.length; ++i) {
                string memory e = string.concat('{"kind":"', ks[i], '","token":"', vm.toString(ts[i]), '","domain":"', vm.toString(ds[i]), '"}');
                line = string.concat(line, bytes(first).length == 0 ? "" : ",", e);
                first = "x";
            }
        }
        line = string.concat(line, "]},");
        if (write) {
            vm.writeLine(FILE, line);
            return;
        }
        string memory was = vm.readLine(FILE);
        if (keccak256(bytes(_strip(bytes(was)))) != keccak256(bytes(_strip(bytes(line))))) {
            console2.log("PARITY SETUP CHANGED (token addresses or domain separators), not a behaviour difference:");
            console2.log(string.concat("  fixture: ", was));
            console2.log(string.concat("  now:     ", line));
            revert("parity: SETUP CHANGED (token addresses / domain separators), not a behaviour difference; see the log");
        }
    }

    /// The fixture's closing object names its set: `"set":"<NAME>"` occurs in the file.
    function _fixtureIsForThisSet() internal view returns (bool) {
        bytes memory h = bytes(vm.readFile(FILE));
        bytes memory n = bytes(string.concat('"set":"', PqzSet.NAME, '"'));
        for (uint256 i = h.length; i >= n.length; --i) {
            uint256 j;
            while (j < n.length && h[i - n.length + j] == n[j]) ++j;
            if (j == n.length) return true;
        }
        return false;
    }

    function _open() internal {
        vm.closeFile(FILE);
        vm.readLine(FILE); // "["
    }

    function _rules() internal returns (RuleRow[] memory out) {
        bytes4[] memory probe = _probe();
        RuleRow[][] memory parts = new RuleRow[][](rigs.length);
        uint256 n;
        for (uint256 r; r < rigs.length; ++r) {
            parts[r] = rigs[r].ruleTable(probe);
            n += parts[r].length;
        }
        out = new RuleRow[](n);
        n = 0;
        for (uint256 r; r < rigs.length; ++r) {
            for (uint256 i; i < parts[r].length; ++i) out[n++] = parts[r][i];
        }
        // self-check of the probe: it must SEE refusals (some unlisted selector refused by `mtxExecute`, some selector refused by
        // `uaExecute`), else the table pins nothing. A selector that `_mtxRule` allows but `mtxSelectors()` does not list is
        // data, recorded as such (`inList=false, mtxAllowed=true`)
        uint256 refusedUa;
        uint256 refusedMtx;
        for (uint256 i; i < n; ++i) {
            if (!out[i].inList && !out[i].mtxAllowed) ++refusedMtx;
            if (!out[i].uaAllowed) ++refusedUa;
        }
        require(refusedUa != 0, "parity probe: uaExecute refused no selector");
        require(refusedMtx != 0, "parity probe: mtxExecute refused no unlisted selector");
    }

    /// Write: the rule lines and the closing object. Replay: compare them (the case lines are already compared).
    function _finish(bool write, uint256 nc, RuleRow[] memory ru) internal {
        if (write) {
            for (uint256 i; i < ru.length; ++i) vm.writeLine(FILE, string.concat(_jsonRule(ru[i]), ","));
            vm.writeLine(FILE, string.concat('{"fixture":"metatx-parity","set":"', PqzSet.NAME, '","nCases":', vm.toString(nc),
                ',"nRules":', vm.toString(ru.length), "}"));
            vm.writeLine(FILE, "]");
            return;
        }
        for (uint256 i; i < ru.length; ++i) _cmpRule(_next(false), ru[i], i);
        string memory meta = _next(true);
        assertEq(vm.parseJsonString(meta, ".set"), PqzSet.NAME, "parity: the fixture was written for another parameter set");
        assertEq(nc, vm.parseJsonUint(meta, ".nCases"), "parity: number of cases differs from the fixture");
        assertEq(ru.length, vm.parseJsonUint(meta, ".nRules"), "parity: number of allowlist rows differs from the fixture");
        vm.closeFile(FILE);
    }

    /// Every selector any kind lists, plus some a token never allowlists (so the "refused" side is pinned too).
    function _probe() internal view returns (bytes4[] memory out) {
        bytes4[] memory acc = new bytes4[](512);
        uint256 n;
        for (uint256 r; r < rigs.length; ++r) {
            bytes4[] memory s = rigs[r].selectors();
            for (uint256 j; j < s.length; ++j) n = _add(acc, n, s[j]);
        }
        string[14] memory extra = [
            "transfer(address,uint256)", "approve(address,uint256)", "transferFrom(address,address,uint256)",
            "mint(address,uint256)", "mintToUA(bytes32,uint256)", "transferToUA(bytes32,uint256)",
            "initialize(address,uint64,bytes)", "wrap(uint256)", "burn(uint256)", "cancelNonce(uint256)",
            "mtxExecute((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)",
            "grantRole(uint8,address)", "payWithFee(address,uint256,uint8,uint256,address,bytes32)",
            "unwrap(address,uint256,address,uint256)"
        ];
        for (uint256 i; i < extra.length; ++i) n = _add(acc, n, bytes4(keccak256(bytes(extra[i]))));
        n = _add(acc, n, 0xdeadbeef);
        out = new bytes4[](n);
        for (uint256 i; i < n; ++i) out[i] = acc[i];
    }

    function _add(bytes4[] memory acc, uint256 n, bytes4 s) internal pure returns (uint256) {
        for (uint256 i; i < n; ++i) if (acc[i] == s) return n;
        acc[n] = s;
        return n + 1;
    }
}
