// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {RegFixture, Holder} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {RegulatedLib} from "../../src/regulated/RegulatedLib.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// @notice ua-mtx-merge T34 (regulated-kinds spec §3.1, §3.3, §3.6, §5, §7): `smartcontracts/vectors/governance/regulated_kat.json`,
///         every row read off a real kind-8 token (`RegFixture`'s `t8`, lists on through `_listed`) and the canonical
///         `ComplianceRegistry`: `recordId` (the token keys the order by it), the `R` truth table (`canReceive`, equal to
///         `hasFlags` on the token's masks), the freeze transitions T1-T9 (the state before and after, or the revert), the
///         relaxation `commit` of each action (`pendingGrant` after the proposal). `WRITE_REGULATED_KAT=true forge test
///         --match-path test/as/RegulatedKat.t.sol` rewrites it; otherwise the file must equal what this test builds. Read by
///         `clientkeys` (test/regulated.test.js) and `ua-rs` (tests/regulated.rs).
contract RegulatedKatTest is RegFixture {
    string constant OUT = "../vectors/governance/regulated_kat.json";
    uint64 internal N;
    bytes32 internal acct = nid(address(0xF1));
    bytes32 internal ben = nid(address(0xBE));
    bytes32 internal other = nid(address(0xF2));
    bytes32 internal constant ORDER = keccak256("scaas.regulated-kat.order");

    // ------------------------------------------------------------------ JSON

    function _q(string memory s) internal pure returns (string memory) {
        return string.concat('"', s, '"');
    }

    function _u(uint256 x) internal view returns (string memory) {
        return _q(vm.toString(x));
    }

    function _h(bytes32 x) internal view returns (string memory) {
        return _q(vm.toString(x));
    }

    function _b(bool x) internal pure returns (string memory) {
        return x ? "true" : "false";
    }

    function _kv(string memory k, string memory v) internal pure returns (string memory) {
        return string.concat('"', k, '": ', v);
    }

    /// `, "k": v`
    function _c(string memory k, string memory v) internal pure returns (string memory) {
        return string.concat(', "', k, '": ', v);
    }

    function _end(bool last) internal pure returns (string memory) {
        return last ? "}\n" : "},\n";
    }

    function _state(IRegulatedToken.FreezeState memory s) internal view returns (string memory) {
        return string.concat("{", _kv("until", _u(s.until)), _c("episodeStart", _u(s.episodeStart)),
            _c("issuerCooldownUntil", _u(s.issuerCooldownUntil)), _c("recordBacked", _b(s.recordBacked)),
            _c("recordId", _h(s.recordId)), "}");
    }

    function _controls() internal view returns (uint8) {
        return _r(t8).regulatedConfig().controls;
    }

    function _record(bytes32 rid) internal view returns (string memory) {
        IRegulatedToken.OrderRecord memory o = _r(t8).order(rid);
        if (o.subject == 0) return "null";
        return string.concat("{", _kv("subject", _h(o.subject)), _c("freezeUntil", _u(o.freezeUntil)), _c("revoked", _b(o.revoked)),
            "}");
    }

    // ------------------------------------------------------------------ constants

    function _constants() internal view returns (string memory j) {
        j = string.concat('  "constants": {', _kv("uaPool", _h(MetaTxLib.pad(MetaTxLib.UA_POOL))),
            _c("shieldPool", _h(MetaTxLib.pad(MetaTxLib.SHIELD_POOL))), _c("freezeSpan", _u(RegulatedLib.FREEZE_SPAN)),
            _c("episodeSpan", _u(RegulatedLib.EPISODE_SPAN)), _c("freezeCooldown", _u(RegulatedLib.FREEZE_COOLDOWN)),
            _c("eligibleContract", _u(ELIGIBLE)));
        string memory a = string.concat("{", _kv("GRANT", vm.toString(GovernanceLib.GRANT)), _c("SET", vm.toString(GovernanceLib.SET)),
            _c("REVOKE", vm.toString(GovernanceLib.REVOKE)), _c("RENOUNCE", vm.toString(GovernanceLib.RENOUNCE)),
            _c("DISABLE", vm.toString(GovernanceLib.DISABLE)), "}");
        string memory c = string.concat("{", _kv("freeze", vm.toString(RegulatedLib.C_FREEZE)),
            _c("allowlist", vm.toString(RegulatedLib.C_ALLOW)), _c("denylist", vm.toString(RegulatedLib.C_DENY)),
            _c("record", vm.toString(RegulatedLib.C_RECORD)), _c("kyc", vm.toString(RegulatedLib.C_KYC)), "}");
        string memory l = string.concat("{", _kv("allowed", vm.toString(RegulatedLib.ALLOWED)),
            _c("denied", vm.toString(RegulatedLib.DENIED)), _c("maxBatch", vm.toString(RegulatedLib.MAX_LIST_BATCH)), "}");
        j = string.concat(j, ",\n    ", _kv("actions", a), _c("controls", c), _c("listFlags", l), "},\n");
    }

    // ------------------------------------------------------------------ recordId (spec §3.1)

    function _recordRow(string memory name, bytes32 orderId, bytes32 subject, bytes32 beneficiary, bool last)
        internal returns (string memory)
    {
        bytes32 rid = _order(t8, orderId, subject, beneficiary, 1, 0);
        IRegulatedToken.OrderRecord memory o = _r(t8).order(rid);
        assertEq(o.subject, subject, name);
        assertEq(o.beneficiary, beneficiary, name);
        return string.concat("    {", _kv("name", _q(name)), _c("orderId", _h(orderId)), _c("subject", _h(subject)),
            _c("beneficiary", _h(beneficiary)), _c("recordId", _h(rid)), _end(last));
    }

    function _recordIds() internal returns (string memory j) {
        uint256 s = vm.snapshotState();
        j = string.concat('  "recordId": [\n', _recordRow("two native ids", ORDER, acct, ben, false),
            _recordRow("a derived subject", keccak256("scaas.regulated-kat.order.2"), UA_X, ben, false),
            _recordRow("the same order, subject and beneficiary swapped", ORDER, ben, acct, true), "  ],\n");
        _back(s);
    }

    // ------------------------------------------------------------------ the R truth table (spec §3.2, §5)

    struct Acct {
        string name;
        bytes32 id;
    }

    struct Rx {
        uint64 flags;
        uint64 until;
        bool enabled;
        bool ok;
        uint8 reason;
    }

    /// The account's compliance row and the token's answer; with `KYC` on (round 3s, both masks), `ok` is the registry's
    /// `hasFlags` on its masks (a zero mask constrains nothing).
    function _rx(address t, uint64 req, uint64 den, Acct memory a) internal view returns (Rx memory x) {
        uint32 id;
        (x.flags, x.until, id) = creg.complianceOf(a.id);
        x.enabled = creg.kycProviderEnabled(id);
        (x.ok, x.reason) = _r(t).canReceive(a.id);
        if (req | den != 0) {
            assertEq(x.ok, creg.hasFlags(a.id, req, den), a.name);
        } else {
            assertTrue(x.ok && x.reason == 0, a.name);
        }
    }

    /// Config `c`: 0 `KYC` off, 1 `KYC` with `requiredFlags` only, 2 with `deniedFlags` only, 3 both masks.
    function _receiverRow(uint256 c, address t, Acct memory a, bool last) internal view returns (string memory) {
        (uint64 req, uint64 den) = (c == 1 || c == 3 ? KYC : 0, c >= 2 ? SANCTIONED : 0);
        return string.concat(_rxHead(c, a.name, req, den), _rxTail(_rx(t, req, den, a)), _end(last));
    }

    function _rxHead(uint256 c, string memory name, uint64 req, uint64 den) internal view returns (string memory j) {
        string[4] memory names = ["KYC off", "KYC, requiredFlags", "KYC, deniedFlags", "KYC, both masks"];
        j = string.concat("    {", _kv("name", _q(string.concat(names[c], ": ", name))), _c("kyc", _b(c != 0)));
        j = string.concat(j, _c("requiredFlags", _u(req)), _c("deniedFlags", _u(den)));
    }

    function _rxTail(Rx memory x) internal view returns (string memory j) {
        j = string.concat(_c("flags", _u(x.flags)), _c("validUntil", _u(x.until)), _c("kycProviderEnabled", _b(x.enabled)));
        j = string.concat(j, _c("now", _u(block.timestamp)), _c("ok", _b(x.ok)), _c("reason", vm.toString(x.reason)));
    }

    function _receivers() internal returns (string memory j) {
        uint256 s = vm.snapshotState();
        address att2 = address(0xA772);
        vm.prank(cadmin);
        creg.setKycProvider(nid(att2), true, EnvKit.regUidOf(address(creg)));
        string[11] memory nm = ["unattested", "KYC", "KYC and SANCTIONED", "SANCTIONED", "ELIGIBLE_CONTRACT, by the admin",
            "ELIGIBLE_CONTRACT and SANCTIONED, by the admin", "KYC lapsed", "KYC, validUntil == now",
            "KYC and SANCTIONED, KYC provider disabled", "SANCTIONED lapsed", "KYC, by the admin"];
        Acct[] memory as_ = new Acct[](11);
        for (uint256 i; i < 11; ++i) as_[i] = Acct(nm[i], nid(address(uint160(0xA0 + i))));
        uint64 max = type(uint64).max;
        _attest(as_[1].id, KYC, max);
        _attest(as_[2].id, KYC | SANCTIONED, max);
        _attest(as_[3].id, SANCTIONED, max);
        _attestAs(cadmin, as_[4].id, ELIGIBLE, max);
        _attestAs(cadmin, as_[5].id, ELIGIBLE | SANCTIONED, max);
        _attest(as_[6].id, KYC, N - 1);
        _attest(as_[7].id, KYC, N);
        _attestAs(att2, as_[8].id, KYC | SANCTIONED, max);
        _attest(as_[9].id, SANCTIONED, N - 1);
        _attestAs(cadmin, as_[10].id, KYC, max);
        vm.prank(cadmin);
        creg.setKycProvider(nid(att2), false, EnvKit.regUidOf(address(creg)));
        address[4] memory ts;
        ts[0] = t8;
        ts[1] = _listed(0, KYC, 0, "A");
        ts[2] = _listed(0, 0, SANCTIONED, "D");
        ts[3] = _listed(0, KYC, SANCTIONED, "AD");
        j = '  "receiver": [\n';
        for (uint256 c; c < 4; ++c) {
            for (uint256 i; i < as_.length; ++i) j = string.concat(j, _receiverRow(c, ts[c], as_[i], c == 3 && i == as_.length - 1));
        }
        j = string.concat(j, "  ],\n");
        _back(s);
    }

    // ------------------------------------------------------------------ the lists (round 3s, spec §4.2, §4.3)

    /// `canReceive` of a token with `ALLOWLIST` / `DENYLIST` on or off (no `KYC`: no call) for each `listFlagsOf` byte:
    /// reason 5 not on the allow list, 6 on the deny list, the allow list first.
    function _lists() internal returns (string memory j) {
        uint256 s = vm.snapshotState();
        address[4] memory ts;
        string[4] memory names = ["no list", "ALLOWLIST", "DENYLIST", "both lists"];
        j = '  "lists": [\n';
        for (uint256 c; c < 4; ++c) {
            IFactoryToken.TokenConfig memory cfg = _cfg8();
            cfg.features |= (c & 1) << GovernanceBits.ALLOWLIST | (c >> 1) << GovernanceBits.DENYLIST;
            ts[c] = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(cfg), bytes32(c + 1));
            for (uint8 fl; fl < 4; ++fl) {
                bytes32 a = nid(address(uint160(0xC0 + fl)));
                bytes32[] memory one = new bytes32[](1);
                one[0] = a;
                vm.startPrank(issuer);
                if (fl & 1 != 0) IRegulatedToken(ts[c]).setAllowed(one, true);
                if (fl & 2 != 0) IRegulatedToken(ts[c]).setDenied(one, true);
                vm.stopPrank();
                assertEq(IRegulatedToken(ts[c]).listFlagsOf(a), fl);
                j = string.concat(j, _listRow(string.concat(names[c], ": listFlags ", vm.toString(fl)), ts[c], a, fl,
                    c == 3 && fl == 3));
            }
        }
        j = string.concat(j, "  ],\n");
        _back(s);
    }

    /// Spec §5.5 (Fable P2-2): `GovernanceBits.enableable` on kind 8's and kind 12's masks, one row per term failing alone
    /// (the base row: nothing set, nothing locked, an admin, a registry).
    function _enableable() internal pure returns (string memory j) {
        uint256 v8 = GovernanceBits.NORMAL_BITS | (GovernanceBits.REGULATED | (1 << GovernanceBits.RECORD)
            | (1 << GovernanceBits.MODERATE) | (1 << GovernanceBits.OPERATOR_TRANSFER) | (1 << GovernanceBits.TAX));
        uint256 v12 = v8 & ~uint256(1 << GovernanceBits.ALLOWLIST) | GovernanceBits.PQZ_KIND_BITS;
        uint256 v0 = GovernanceBits.NORMAL_BITS;
        j = '  "enableable": [\n';
        j = string.concat(j, _enRow("kind 8, the base", 0, 0, v8, true, true, false),
            _enRow("kind 8, 8 set", 1 << 8, 0, v8, true, true, false),
            _enRow("kind 8, 9 locked off", 0, 1 << 9, v8, true, true, false),
            _enRow("kind 8, 28 locked off", 0, 1 << 28, v8, true, true, false),
            _enRow("kind 8, no registry", 0, 0, v8, true, false, false));
        j = string.concat(j, _enRow("kind 8, admin 0", 0, 0, v8, false, true, false),
            _enRow("kind 12 (no bit 8)", 0, 0, v12, true, true, false),
            _enRow("kind 0 (no regulated bit)", 0, 0, v0, true, true, false),
            _enRow("kind 8, all set", (1 << 8) | (1 << 9) | (1 << 28), 0, v8, true, true, true));
        j = string.concat(j, "  ],\n");
    }

    function _listRow(string memory name, address t, bytes32 a, uint8 fl, bool last) internal view returns (string memory) {
        (bool ok, uint8 why) = _r(t).canReceive(a);
        string memory h = string.concat("    {", _kv("name", _q(name)), _c("controls", vm.toString(_r(t).regulatedConfig().controls)));
        return string.concat(h, _c("listFlags", vm.toString(fl)), _c("ok", _b(ok)), _c("reason", vm.toString(why)), _end(last));
    }

    function _enRow(string memory name, uint256 f, uint256 l, uint256 v, bool admin, bool reg, bool last)
        internal pure returns (string memory)
    {
        uint256 e = GovernanceBits.enableable(f, l, v, admin ? bytes32(uint256(1)) : bytes32(0), reg);
        string memory h = string.concat("    {", _kv("name", _q(name)), _c("features", vm.toString(f)),
            _c("lockedFeatures", vm.toString(l)));
        return string.concat(h, _c("valid", vm.toString(v)), _c("admin", _b(admin)), _c("registry", _b(reg)),
            _c("enableable", vm.toString(e)), _end(last));
    }

    // ------------------------------------------------------------------ the freeze transitions T1-T9 (spec §3.3)

    struct Pre {
        uint64 now_;
        uint8 controls;
        IRegulatedToken.FreezeState before;
        bool frozen;
        string record;
    }

    function _pre(bytes32 a, bytes32 rid) internal view returns (Pre memory p) {
        p = Pre(_now(), _controls(), _r(t8).freezeOf(a), _r(t8).isFrozen(a), _record(rid));
    }

    /// A row's name, rule, account, the order it names, and the caller of its call.
    struct Row {
        string name;
        string rule;
        bytes32 a;
        bytes32 rid;
        address who;
    }

    /// The revert a call must give: `want` empty for success.
    struct Err {
        string sig;
        string args;
        bytes want;
    }

    function _head(Row memory r, Pre memory p) internal view returns (string memory j) {
        j = string.concat("    {", _kv("name", _q(r.name)), _c("rule", _q(r.rule)), _c("token", _q(vm.toLowercase(vm.toString(t8)))),
            _c("account", _h(r.a)), _c("now", _u(p.now_)), _c("controls", vm.toString(p.controls)));
        j = string.concat(j, ",\n      ", _kv("record", p.record), ",\n      ", _kv("before", _state(p.before)));
    }

    /// One call by `r.who` on `t8`: the state after and `F`, or the revert, which must be `e.want`.
    function _call(Row memory r, bytes memory data, string memory callJson, Err memory e) internal returns (string memory j) {
        Pre memory p = _pre(r.a, r.rid);
        vm.prank(r.who);
        (bool ok, bytes memory ret) = t8.call(data);
        j = string.concat(_head(r, p), ",\n      ", _kv("call", callJson), ",\n      ");
        if (e.want.length != 0) {
            assertFalse(ok, r.name);
            assertEq(ret, e.want, r.name);
            string memory err = string.concat("{", _kv("sig", _q(e.sig)), _c("args", e.args), _c("data", _q(vm.toString(ret))), "}");
            return string.concat(j, _kv("error", err), "},\n");
        }
        assertTrue(ok, r.name);
        j = string.concat(j, _kv("after", _state(_r(t8).freezeOf(r.a))), _c("frozen", _b(_r(t8).isFrozen(r.a))), "},\n");
    }

    /// No call: time passes or a feature goes (`ev`); the state before and after (equal), `F` before and after.
    function _noCall(string memory name, string memory rule, Pre memory p, string memory ev) internal view returns (string memory) {
        IRegulatedToken.FreezeState memory s = _r(t8).freezeOf(acct);
        assertEq(abi.encode(s), abi.encode(p.before), name);
        return string.concat(_ncHead(name, rule, ev), _ncMid(p, _pre(acct, 0)), _ncTail(p, s));
    }

    function _ncHead(string memory name, string memory rule, string memory ev) internal view returns (string memory j) {
        j = string.concat("    {", _kv("name", _q(name)), _c("rule", _q(rule)));
        j = string.concat(j, _c("token", _q(vm.toLowercase(vm.toString(t8)))), _c("account", _h(acct)), _c("event", _q(ev)));
    }

    function _ncMid(Pre memory p, Pre memory q) internal view returns (string memory j) {
        j = string.concat(",\n      ", _kv("nowBefore", _u(p.now_)), _c("controlsBefore", vm.toString(p.controls)));
        j = string.concat(j, _c("frozenBefore", _b(p.frozen)), _c("now", _u(q.now_)), _c("controls", vm.toString(q.controls)));
        j = string.concat(j, _c("record", "null"), _c("frozen", _b(q.frozen)));
    }

    function _ncTail(Pre memory p, IRegulatedToken.FreezeState memory s) internal view returns (string memory j) {
        j = string.concat(",\n      ", _kv("before", _state(p.before)), ",\n      ", _kv("call", "null"));
        j = string.concat(j, _c("after", _state(s)), "},\n");
    }

    function _fz(bytes32 a, bytes32 ref, bytes32 rid) internal view returns (bytes memory, string memory) {
        return (abi.encodeCall(IRegulatedToken.freeze, (a, ref, rid)), string.concat("{", _kv("fn", _q("freeze")),
            _c("account", _h(a)), _c("ref", _h(ref)), _c("recordId", _h(rid)), "}"));
    }

    function _ufz(bytes32 a, bytes32 ref) internal view returns (bytes memory, string memory) {
        return (abi.encodeCall(IRegulatedToken.unfreeze, (a, ref)), string.concat("{", _kv("fn", _q("unfreeze")),
            _c("account", _h(a)), _c("ref", _h(ref)), "}"));
    }

    function _rv(bytes32 rid, bytes32 reason) internal view returns (bytes memory, string memory) {
        return (abi.encodeCall(IRegulatedToken.revokeOrder, (rid, reason)), string.concat("{", _kv("fn", _q("revokeOrder")),
            _c("recordId", _h(rid)), _c("reasonRef", _h(reason)), "}"));
    }

    /// A freeze call by the issuer, `e.want` empty or the revert with its signature and arguments.
    function _freezeRow(string memory name, string memory rule, bytes32 a, bytes32 ref, bytes32 rid, Err memory e)
        internal returns (string memory)
    {
        (bytes memory d, string memory c) = _fz(a, ref, rid);
        return _call(Row(name, rule, a, rid, issuer), d, c, e);
    }

    function _ok(string memory name, string memory rule, bytes32 a, bytes32 ref, bytes32 rid) internal returns (string memory) {
        return _freezeRow(name, rule, a, ref, rid, _none());
    }

    function _none() internal pure returns (Err memory) {
        return Err("", "", "");
    }

    function _rec(bytes32 subject, uint64 freezeUntil) internal returns (bytes32) {
        return _order(t8, ORDER, subject, ben, 1000, freezeUntil);
    }

    /// Back to the fixture's state at `N`.
    function _back(uint256 s) internal {
        vm.revertToState(s);
        vm.warp(N);
    }

    function _e1(string memory sig, bytes4 sel, bytes32 x) internal view returns (Err memory) {
        return Err(sig, string.concat("[", _h(x), "]"), abi.encodeWithSelector(sel, x));
    }

    function _eU(string memory sig, bytes4 sel, uint64 x) internal view returns (Err memory) {
        return Err(sig, string.concat("[", _u(x), "]"), abi.encodeWithSelector(sel, x));
    }

    function _t1() internal returns (string memory j) {
        uint256 s = vm.snapshotState();
        j = _ok("an issuer-only freeze of an account never frozen", "T1", acct, REF, 0);
        _back(s);
        j = string.concat(j, _freezeRow("ref 0 refused", "T1", acct, 0, 0,
            Err("RefRequired()", "[]", abi.encodeWithSelector(IRegulatedToken.RefRequired.selector))));
        bytes32[4] memory targets =
            [bytes32(0), MetaTxLib.pad(MetaTxLib.UA_POOL), MetaTxLib.pad(MetaTxLib.SHIELD_POOL), MetaTxLib.pad(t8)];
        string[4] memory tn = ["target 0 refused", "the UA pool refused", "the shield pool refused", "the token itself refused"];
        for (uint256 i; i < 4; ++i) {
            j = string.concat(j, _freezeRow(tn[i], "T1", targets[i], REF, 0,
                _e1("FreezeTargetRefused(bytes32)", IRegulatedToken.FreezeTargetRefused.selector, targets[i])));
        }
        _freeze(t8, acct);
        vm.warp(N + 1 days);
        _unfreeze(t8, acct);
        vm.warp(N + 11 days);
        uint64 cool = _r(t8).freezeOf(acct).issuerCooldownUntil;
        j = string.concat(j, _freezeRow("in the issuer cooldown after an unfreeze", "T1", acct, REF, 0,
            _eU("FreezeCooldown(uint64)", IRegulatedToken.FreezeCooldown.selector, cool)));
        _back(s);
        _freeze(t8, acct);
        vm.warp(N + 60 days);
        j = string.concat(j, _ok("after the episode's cooldown, a new episode", "T1", acct, REF, 0));
        _back(s);
    }

    function _t2() internal returns (string memory j) {
        uint256 s = vm.snapshotState();
        Err memory long = _eU("FreezeTooLong(uint64)", IRegulatedToken.FreezeTooLong.selector, N + 60 days);
        _freeze(t8, acct);
        j = _freezeRow("re-frozen in the same block: no extension", "T2", acct, REF, 0, long);
        vm.warp(N + 20 days);
        j = string.concat(j, _ok("extended within the episode", "T2", acct, REF, 0));
        vm.warp(N + 45 days);
        j = string.concat(j, _ok("extended up to episodeStart + 60 d", "T2", acct, REF, 0));
        vm.warp(N + 55 days);
        j = string.concat(j, _freezeRow("no extension past episodeStart + 60 d", "T2", acct, REF, 0, long));
        _back(s);
    }

    function _t3t4() internal returns (string memory j) {
        uint256 s = vm.snapshotState();
        bytes32 rid = _rec(acct, N + 90 days);
        j = _ok("a record-backed freeze of an account not frozen", "T4", acct, REF, rid);
        j = string.concat(j, _freezeRow("an issuer-only freeze of a record-frozen account", "T3", acct, REF, 0,
            _e1("AlreadyRecordFrozen(bytes32)", IRegulatedToken.AlreadyRecordFrozen.selector, acct)));
        _back(s);
        _freeze(t8, acct);
        rid = _rec(acct, N + 90 days);
        j = string.concat(j, _ok("a record-backed freeze extends an issuer-only one", "T4", acct, REF, rid));
        _back(s);
        rid = _rec(acct, type(uint64).max);
        j = string.concat(j, _ok("an open-ended record", "T4", acct, REF, rid));
        _back(s);
        _freeze(t8, acct);
        rid = _rec(acct, N + 10 days);
        j = string.concat(j, _freezeRow("a record shorter than the freeze", "T4", acct, REF, rid,
            _eU("RecordFreezeShorter(uint64)", IRegulatedToken.RecordFreezeShorter.selector, N + 30 days)));
        _back(s);
        rid = _rec(acct, N + 1 days);
        vm.warp(N + 2 days);
        j = string.concat(j, _freezeRow("the record's freezeUntil has passed", "T4", acct, REF, rid,
            _e1("OrderInactive(bytes32)", IRegulatedToken.OrderInactive.selector, rid)));
        _back(s);
        rid = _rec(other, N + 90 days);
        j = string.concat(j, _freezeRow("the record names another subject", "T4", acct, REF, rid,
            _e1("OrderInactive(bytes32)", IRegulatedToken.OrderInactive.selector, rid)));
        bytes32 none = keccak256("scaas.regulated-kat.none");
        j = string.concat(j, _freezeRow("an unknown record", "T4", acct, REF, none,
            _e1("OrderUnknown(bytes32)", IRegulatedToken.OrderUnknown.selector, none)));
        _back(s);
        rid = _rec(acct, N + 90 days);
        vm.prank(compliance);
        _r(t8).revokeOrder(rid, REF);
        j = string.concat(j, _freezeRow("a revoked record", "T4", acct, REF, rid,
            _e1("OrderInactive(bytes32)", IRegulatedToken.OrderInactive.selector, rid)));
        _back(s);
    }

    function _t5() internal returns (string memory j) {
        uint256 s = vm.snapshotState();
        (bytes memory d, string memory c) = _ufz(acct, REF);
        _freeze(t8, acct);
        vm.warp(N + 1 days);
        j = _call(Row("unfreeze an issuer-only freeze", "T5", acct, 0, issuer), d, c, _none());
        _back(s);
        bytes32 rid = _rec(acct, N + 90 days);
        _freezeRecord(t8, acct, rid);
        vm.warp(N + 1 days);
        j = string.concat(j, _call(Row("unfreeze a record-backed freeze: recordId cleared", "T5", acct, rid, issuer), d, c, _none()));
        _back(s);
        j = string.concat(j, _call(Row("unfreeze an account not frozen", "T5", acct, 0, issuer), d, c,
            _e1("NotFrozen(bytes32)", IRegulatedToken.NotFrozen.selector, acct)));
        (d, c) = _ufz(acct, 0);
        _freeze(t8, acct);
        j = string.concat(j, _call(Row("unfreeze with ref 0", "T5", acct, 0, issuer), d, c,
            Err("RefRequired()", "[]", abi.encodeWithSelector(IRegulatedToken.RefRequired.selector))));
        _back(s);
    }

    function _t6() internal returns (string memory j) {
        uint256 s = vm.snapshotState();
        bytes32 rid = _rec(acct, N + 90 days);
        (bytes memory d, string memory c) = _rv(rid, keccak256("scaas.regulated-kat.reason"));
        _freezeRecord(t8, acct, rid);
        vm.warp(N + 1 days);
        j = _call(Row("revokeOrder ends the freeze it backs", "T6", acct, rid, compliance), d, c, _none());
        _back(s);
        _rec(acct, N + 90 days);
        _freezeRecord(t8, acct, rid);
        _unfreeze(t8, acct);
        vm.warp(N + 1 days);
        j = string.concat(j, _call(Row("revokeOrder after an unfreeze changes no freeze", "T6", acct, rid, compliance), d, c, _none()));
        _back(s);
        _freeze(t8, acct);
        _rec(acct, N + 90 days);
        j = string.concat(j, _call(Row("revokeOrder of a record that backs no freeze leaves the issuer-only one", "T6", acct, rid,
            compliance), d, c, _none()));
        j = string.concat(j, _call(Row("revokeOrder twice", "T6", acct, rid, compliance), d, c,
            _e1("OrderInactive(bytes32)", IRegulatedToken.OrderInactive.selector, rid)));
        _back(s);
    }

    function _t7t8t9() internal returns (string memory j) {
        uint256 s = vm.snapshotState();
        _freeze(t8, acct);
        Pre memory p = _pre(acct, 0);
        vm.warp(N + 30 days);
        j = _noCall("expiry at until: nothing written, F ends", "T7", p, "time");
        _back(s);
        bytes32 rid = _rec(acct, N + 90 days);
        _freezeRecord(t8, acct, rid);
        p = _pre(acct, 0);
        _disable(t8, GovernanceBits.RECORD);
        j = string.concat(j, _noCall("disableFeature(RECORD), one call: a record-backed freeze stops counting", "T8", p,
            "disableFeature(10)"));
        j = string.concat(j, _ok("then an issuer-only freeze replaces the one that no longer counts", "T8", acct, REF, 0));
        _back(s);
        _freeze(t8, acct);
        p = _pre(acct, 0);
        _disable(t8, GovernanceBits.FREEZE);
        j = string.concat(j, _noCall("disableFeature(FREEZE) proposed: the freeze stays", "T9", p, "disableFeature(5) proposed"));
        vm.warp(N + GD);
        _disable(t8, GovernanceBits.FREEZE);
        j = string.concat(j, _noCall("disableFeature(FREEZE) confirmed: no freeze counts", "T9", p, "disableFeature(5) confirmed"));
        _back(s);
    }

    function _freezes() internal returns (string memory j) {
        j = string.concat('  "freeze": [\n', _t1());
        j = string.concat(j, _t2());
        j = string.concat(j, _t3t4());
        j = string.concat(j, _t5());
        j = string.concat(j, _t6());
        j = string.concat(j, _t7t8t9());
        // the last row ends without its comma
        j = string.concat(_trim(j), "\n  ],\n");
    }

    function _trim(string memory j) internal pure returns (string memory) {
        bytes memory b = bytes(j);
        assembly ("memory-safe") { mstore(b, sub(mload(b), 2)) }
        return string(b);
    }

    // ------------------------------------------------------------------ the relaxation commit (spec §3.6)

    function _commitRow(string memory name, uint8 action, uint8 bit, bytes32 account, string memory terms, bool last)
        internal view returns (string memory j)
    {
        j = string.concat("    {", _kv("name", _q(name)), _c("action", vm.toString(action)), _c("bit", vm.toString(bit)));
        j = string.concat(j, _c("account", _h(account)), bytes(terms).length == 0 ? "" : _c("terms", terms));
        j = string.concat(j, _c("commit", _h(_pending(name, bit, account))), _end(last));
    }

    /// The live pending's commitment, proposed at `N`.
    function _pending(string memory name, uint8 bit, bytes32 account) internal view returns (bytes32 c) {
        uint64 eta;
        bool live;
        (eta,, c, live) = IGovernance(t8).pendingGrant(bit, account);
        assertTrue(live && eta == N + GD, name);
    }

    function _termsJson(IGovernance.GrantTerms memory t) internal view returns (string memory j) {
        j = string.concat("{", _kv("min", _u(t.min)), _c("max", _u(t.max)), _c("total", _u(t.total)), _c("perWindow", _u(t.perWindow)));
        j = string.concat(j, _c("window", _u(t.window)), _c("validUntil", _u(t.validUntil)), _c("maxUses", _u(t.maxUses)),
            _c("delegable", _b(t.delegable)), _c("scope", _h(t.scope)), "}");
    }

    function _commits() internal returns (string memory j) {
        uint256 s = vm.snapshotState();
        bytes32 h = nid(address(new Holder()));
        IGovernance g = IGovernance(t8);
        vm.prank(ownerA);
        g.grantRole(GovernanceBits.FREEZE, h, EnvKit.codeUidOf(address(g)));
        j = string.concat('  "commit": [\n', _commitRow("grantRole(FREEZE): GRANT", GovernanceLib.GRANT, GovernanceBits.FREEZE, h, "",
            false));
        _back(s);
        IGovernance.GrantTerms memory t;
        (t.max, t.validUntil) = (type(uint128).max, N + GD - 1);
        vm.prank(ownerA);
        g.setGrant(GovernanceBits.PAUSE, nid(issuer), t, EnvKit.codeUidOf(address(g)));
        j = string.concat(j, _commitRow("setGrant(PAUSE) ending before now + grantDelay: SET", GovernanceLib.SET, GovernanceBits.PAUSE,
            nid(issuer), _termsJson(t), false));
        _back(s);
        IGovernance.GrantTerms memory w;
        (w.max, w.maxUses, w.delegable) = (type(uint128).max, 10, true);
        vm.prank(ownerA);
        g.setGrant(GovernanceBits.FREEZE, nid(issuer), w, EnvKit.codeUidOf(address(g)));
        j = string.concat(j, _commitRow("setGrant(FREEZE) delegable, a widening: SET", GovernanceLib.SET, GovernanceBits.FREEZE,
            nid(issuer), _termsJson(w), false));
        _back(s);
        vm.prank(ownerA);
        g.revokeRole(GovernanceBits.FORCE, nid(issuer), EnvKit.codeUidOf(address(g)));
        j = string.concat(j, _commitRow("revokeRole(FORCE) by the owner: REVOKE", GovernanceLib.REVOKE, GovernanceBits.FORCE,
            nid(issuer), "", false));
        _back(s);
        vm.prank(issuer);
        g.renounceRole(GovernanceBits.PAUSE, EnvKit.codeUidOf(address(g)));
        j = string.concat(j, _commitRow("renounceRole(PAUSE) by its holder: RENOUNCE", GovernanceLib.RENOUNCE, GovernanceBits.PAUSE,
            nid(issuer), "", false));
        _back(s);
        vm.prank(ownerA);
        g.disableFeature(GovernanceBits.PAUSE, EnvKit.codeUidOf(address(g)));
        j = string.concat(j, _commitRow("disableFeature(PAUSE): DISABLE, account 0", GovernanceLib.DISABLE, GovernanceBits.PAUSE, 0, "",
            true), "  ]\n");
        _back(s);
    }

    // ------------------------------------------------------------------ the file

    function _build() internal returns (string memory) {
        N = _now();
        return string.concat("{\n",
            '  "note": "Generated by smartcontracts/evm/test/as/RegulatedKat.t.sol (WRITE_REGULATED_KAT=true) from a real kind-8 token',
            " and the canonical ComplianceRegistry; never edit by hand. Regulated-kinds spec 3.1, 3.3, 3.6, 5, 7. recordId:",
            " keccak256(abi.encode(orderId, subject, beneficiary)), the key the token stores the order under. receiver: canReceive(account)",
            " (ok, reason) of a token with KYC (bit 28, round 3s) on or off and its masks (0 = none); ok equals hasFlags(account,",
            " requiredFlags, deniedFlags), KYC off true with no call; reason 1 not attested or flags missing, 2 expired, 3 KYC provider",
            " disabled, 4 denied. lists: canReceive of a token with ALLOWLIST / DENYLIST on or off (no KYC) for each listFlagsOf byte",
            " (ALLOWED 1, DENIED 2): reason 5 not on the allow list, 6 on the deny list. enableable: GovernanceBits.enableable(features,",
            " lockedFeatures, valid, admin != 0, registry), the bits of 8, 9, 28 that can still be switched on (spec 5.5). freeze: one row per transition of spec 3.3 on freezeOf(account), the",
            " state before (record: the order the call names, read before it) and after, F after (isFrozen), or the revert (sig, args,",
            " data); a row with call null is time or a feature going, the state unchanged. commit: pendingGrant(bit, account).commit",
            " after the proposal, keccak256(abi.encode(uint8 action, uint8 bit, bytes32 account, argsHash)), argsHash",
            ' keccak256(abi.encode(GrantTerms)) for SET, else 0. uint64 and larger values are decimal strings.",\n',
            '  "version": 1,\n', _sections());
    }

    /// The sections in file order, each from the fixture's state at `N` (snapshot, revert, warp back).
    function _sections() internal returns (string memory j) {
        j = _constants();
        j = string.concat(j, _recordIds());
        vm.warp(N);
        j = string.concat(j, _receivers());
        vm.warp(N);
        j = string.concat(j, _lists(), _enableable());
        vm.warp(N);
        j = string.concat(j, _freezes());
        vm.warp(N);
        j = string.concat(j, _commits(), "}\n");
    }

    /// The file equals what the token builds; `WRITE_REGULATED_KAT=true` writes it first.
    function test_regulatedKatEqualsTheToken() public {
        string memory j = _build();
        if (vm.envOr("WRITE_REGULATED_KAT", false)) vm.writeFile(OUT, j);
        assertEq(vm.readFile(OUT), j,
            "regulated_kat.json is stale: WRITE_REGULATED_KAT=true forge test --match-path test/as/RegulatedKat.t.sol");
    }
}
