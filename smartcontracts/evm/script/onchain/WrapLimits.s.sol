// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";
import {OnchainBase} from "./OnchainBase.sol";
import {kindModuleNames, kindImplArgs} from "../KindModules.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedgerViews} from "../../src/metatx/IUALedgerViews.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceRouterBase} from "../../src/governance/GovernanceRouterBase.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {HederaLib} from "../../src/hedera/HederaLib.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {WrappedLib} from "../../src/metatx/WrappedLib.sol";
import {RegulatedLib} from "../../src/regulated/RegulatedLib.sol";
import {PqzStateLib} from "../../src/pqz/PqzStateLib.sol";
import {PqzTransferLib} from "../../src/pqz/PqzTransferLib.sol";
import {PqzBurnLib} from "../../src/pqz/PqzBurnLib.sol";
import {PqzViewLib} from "../../src/pqz/PqzViewLib.sol";
import {PqzWrappedLib} from "../../src/pqz/PqzWrappedLib.sol";
import {MockERC20} from "../../test/helpers/Mocks.sol";

/// @notice Group `wraplimits` (group 3l T104; spec 2026-11-10-wrap-limits.md §11): the wrap and unwrap limits on hybrids of
///         kinds 1, 5 and 13 (the PQZ kinds in the `OFFCHAIN` verify mode: no PQZ precompile on the local chain), released by
///         this group's own factory with `noticePeriod()` = 1 hour, so the two-call rows run. Seven forge runs on one node
///         (`wraplimits.sh`: `setup()` here, then `p1()`..`p6()` of `WrapLimits`), the chain's clock moved between them to the
///         time each run writes (a forge script's `vm.warp` moves only its simulation). Every transaction asks an explicit
///         gas limit, measured first on the run's fork (`_tx`), at most 60 M. Each run's negatives are checked by
///         `coverage.py neg` (eth_call) against the chain at its end; each run reads the previous one's state back through
///         the views. Signers: test key 1 (owner, minter, lister, relayed signer), 2 (depositor, relayer), 3 (merchant and
///         redeemer), a fourth key derived from key 1 (the decay row's depositor), `A5` a keyless holder. Public addresses
///         only are printed. UNAUDITED.
abstract contract WrapLimitsKit is OnchainBase {
    uint256 internal constant Q = 1e4; // one quantum of the 6-decimal leg (unitExp 4), in raw units
    uint64 internal constant NOTICE = 3600; // this group's factory's noticePeriod()
    uint256 internal constant MAX_ASK = 60_000_000;
    uint256 internal constant N_K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    address internal constant A5 = address(0xA5A5); // a holder with units by transfer only, no key
    string internal constant TAIL =
        "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant LIMIT_T = "WrapLimit(uint24 perUser,uint64 tokenWide,uint32 period)";
    string internal constant LEG_T =
        "WrapLegLimits(address underlying,uint8 unitExp,uint16 decayDays,WrapLimit wrapShort,WrapLimit wrapLong,WrapLimit unwrapShort,WrapLimit unwrapLong)";
    string internal constant TERMS_T =
        "GrantTerms(uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope)";
    string internal constant WRAP_LEG =
        "WrapLeg(address from,address underlying,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant UA_UNWRAP_LEG =
        "UAUnwrapLeg(bytes32 from,address underlying,uint256 wrapped,address recipient,uint256 minOut,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    bytes4 internal constant WRAP = bytes4(keccak256("wrap(address,uint256)"));
    bytes4 internal constant UNWRAP = bytes4(keccak256("unwrap(address,uint256,address,uint256)"));
    bytes4 internal constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 internal constant APPROVE = bytes4(keccak256("approve(address,uint256)"));
    uint8 internal constant WL = GovernanceBits.WRAP_LIMIT;
    uint8 internal constant WLIST = GovernanceBits.WRAP_LIST;
    uint8 internal constant RED = GovernanceBits.REDEEMER;

    OpenFactory internal fw;
    GovernanceRouter internal gr;
    MockERC20 internal usd;
    address[3] internal tk;
    uint256 internal k4;
    address internal a4;
    string internal ph;

    function _start(string memory p, bool load) internal {
        _init("wraplimits");
        ph = p;
        gr = GovernanceRouter(_dep("governance_router"));
        k4 = uint256(keccak256(abi.encode("scaas.onchain.wraplimits.k4", k1))) % (N_K1 - 1) + 1;
        a4 = vm.addr(k4);
        if (vm.exists(_file("rows.txt"))) vm.removeFile(_file("rows.txt"));
        if (!load) return;
        string memory j = vm.readFile(_file("state.json"));
        (fw, usd) = (OpenFactory(vm.parseJsonAddress(j, ".fw")), MockERC20(vm.parseJsonAddress(j, ".usd")));
        if (vm.keyExistsJson(j, ".t0")) {
            for (uint256 i; i < 3; ++i) tk[i] = vm.parseJsonAddress(j, string.concat(".t", vm.toString(i)));
        }
    }

    /// @dev `deployments/wraplimits-<net>-<name>` (git-ignored): the state, this run's rows, the time of the next run.
    function _file(string memory name) internal view returns (string memory) {
        bool perRun = keccak256(bytes(name)) == keccak256("rows.txt");
        return string.concat("deployments/wraplimits-", net, "-", perRun ? string.concat(ph, "-") : "", name);
    }

    /// @dev The state for the next run, the book, and `next` (0: none) the timestamp the next run starts at.
    function _save(uint256 next) internal {
        vm.serializeAddress("wls", "fw", address(fw));
        string memory j = vm.serializeAddress("wls", "usd", address(usd));
        _book(address(fw), "OpenFactory");
        _book(address(gr), "GovernanceRouter");
        _book(address(usd), "MockERC20");
        for (uint256 i; i < 3; ++i) {
            if (tk[i] == address(0)) continue;
            j = vm.serializeAddress("wls", string.concat("t", vm.toString(i)), tk[i]);
            _book(tk[i], _label(i));
        }
        vm.writeJson(j, _file("state.json"));
        if (next != 0) vm.writeFile(_file("next.txt"), vm.toString(next));
        _writeBook();
    }

    function _kind(uint256 i) internal pure returns (uint8) {
        return [uint8(1), 5, 13][i];
    }

    function _label(uint256 i) internal pure returns (string memory) {
        string[3] memory n = ["WrappedToken", "WrappedPqzToken", "WrappedPqzRegulatedToken"];
        return n[i];
    }

    function _h(uint256 i) internal pure returns (string memory) {
        string[3] memory n = ["H1", "H5", "H13"];
        return n[i];
    }

    function _log(uint256 i, string memory what) internal view {
        console2.log(string.concat("wl ", ph, " ", _h(i), " ", what));
    }

    // ------------------------------------------------------------------ one transaction, its gas explicit

    /// @dev `pk` sends `data` (and `value`) to `to` with an explicit gas limit: the call is first run in a snapshot of this
    ///      run's fork and measured as `DeployBase._measuredGas` does (regular = `lastCallGas` x 64/63 plus its refund,
    ///      state = EIP-8037's), then asked as (regular + state) x 1.05 for a deploy (`DeploySend`'s rule) and x 1.30 +
    ///      100,000 for a call (a refund or a cold path the fork's run did not take); above 60 M it is refused by name.
    ///      The row (`type | detail`) and the ask go to this run's rows file, in send order, for `wraplimits.sh`.
    function _tx(uint256 pk, address to, uint256 value, bytes memory data, bool deploy, string memory row)
        internal returns (bytes memory ret)
    {
        uint256 ask = _ask(vm.addr(pk), to, value, data, deploy, row);
        vm.broadcast(pk);
        bool ok;
        (ok, ret) = to.call{gas: ask, value: value}(data);
        require(ok, string.concat(row, ": reverts at its limit"));
        vm.writeLine(_file("rows.txt"), string.concat(row, " | ", vm.toString(ask)));
    }

    /// @dev A call of `pk` without value or deploy.
    function _call(uint256 pk, address to, bytes memory data, string memory row) internal returns (bytes memory) {
        return _tx(pk, to, 0, data, false, row);
    }

    function _ask(address from, address to, uint256 value, bytes memory data, bool deploy, string memory row)
        internal returns (uint256 ask)
    {
        uint256 snap = vm.snapshotState();
        vm.prank(from, from);
        (bool ok, bytes memory r) = to.call{value: value}(data);
        Vm.Gas memory g = vm.lastCallGas();
        vm.revertToStateAndDelete(snap);
        if (!ok) {
            console2.log(string.concat("wl ", ph, " refused on the fork: ", row));
            assembly ("memory-safe") { revert(add(r, 32), mload(r)) }
        }
        uint256 need = uint256(g.gasTotalUsed) * 64 / 63 + (g.gasRefunded > 0 ? uint256(int256(g.gasRefunded)) : 0)
            + (g.gasStateUsed > 0 ? uint256(int256(g.gasStateUsed)) : 0);
        ask = deploy ? need * 105 / 100 : need * 130 / 100 + 100_000;
        require(ask <= MAX_ASK, string.concat(row, ": asks ", vm.toString(ask), " > 60 M"));
    }

    function _row(string memory kind, uint256 i, string memory detail) internal pure returns (string memory) {
        return string.concat(kind, " | ", _h(i), " ", detail);
    }

    function _q(uint256 n) internal pure returns (string memory) {
        return string.concat(vm.toString(n), " Q");
    }

    // ------------------------------------------------------------------ the token's entries

    function _wrap(uint256 pk, uint256 i, uint256 n, string memory kind) internal {
        string memory row = _row(kind, i, string.concat(vm.toString(vm.addr(pk)), " wraps ", _q(n)));
        _call(pk, tk[i], _wrapData(n), row);
    }

    function _unwrap(uint256 pk, uint256 i, uint256 n, string memory kind) internal {
        string memory row = _row(kind, i, string.concat(vm.toString(vm.addr(pk)), " unwraps ", _q(n)));
        _call(pk, tk[i], _unwrapData(vm.addr(pk), n), row);
    }

    function _wrapData(uint256 n) internal view returns (bytes memory) {
        return abi.encodeWithSelector(WRAP, address(usd), n * Q);
    }

    function _unwrapData(address who, uint256 n) internal view returns (bytes memory) {
        return abi.encodeWithSelector(UNWRAP, address(usd), n * Q, who, uint256(0));
    }

    function _qt(uint256 i, address who) internal view returns (IWrappedToken.WrapQuota memory) {
        return IWrappedToken(tk[i]).wrapQuotaOf(_pad(who), address(usd));
    }

    function _over(uint8 limit, address who, uint256 n, uint256 left) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IWrappedToken.WrapLimitExceeded.selector, address(usd), limit, _pad(who), n * Q, left * Q);
    }

    function _capOver(uint8 limit, uint256 n, uint256 left) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IWrappedToken.WrapCapExceeded.selector, address(usd), limit, n * Q, left * Q);
    }

    function _aboveNet(address who, uint256 n) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IWrappedToken.UnwrapAboveNetWrapped.selector, address(usd), _pad(who), n * Q, 0);
    }

    // ------------------------------------------------------------------ the owner's configurations (spec §6)

    function _L(uint24 perUser, uint64 tokenWide, uint32 period) internal pure returns (IWrappedToken.WrapLimit memory) {
        return IWrappedToken.WrapLimit(perUser, tokenWide, period);
    }

    /// @dev The configurations in the order they are set: 0 the first (the wrap side: short 100 Q per user, 200 Q
    ///      token-wide, 1 hour; long 150 Q, 1 day), 1 + the unwrap side (30 Q / 50 Q per hour, 40 Q per day), the net rule
    ///      and the decay over 2 days (an unwrap tightening: waits the notice), 2 + the wrapper list (a wrap tightening: at
    ///      once), 3 the unwrap side relaxed (100 Q / 200 Q per hour, 200 Q per day: at once), 4 the wrap side relaxed (200 Q /
    ///      400 Q per hour, 400 Q per day) + the unwrapper list (waits the notice, once for both).
    function _cfg(uint256 which)
        internal view returns (IWrappedToken.WrapLegLimits[] memory r, bool net_, bool wlist, bool ulist)
    {
        r = new IWrappedToken.WrapLegLimits[](1);
        IWrappedToken.WrapLegLimits memory l = r[0];
        (l.underlying, l.unitExp, l.wrapShort, l.wrapLong) = (address(usd), 4, _L(100, 200, 3600), _L(150, 0, 86_400));
        if (which >= 1) (l.decayDays, l.unwrapShort, l.unwrapLong, net_) = (2, _L(30, 50, 3600), _L(40, 0, 86_400), true);
        if (which >= 2) wlist = true;
        if (which >= 3) (l.unwrapShort, l.unwrapLong) = (_L(100, 200, 3600), _L(200, 0, 86_400));
        if (which >= 4) (l.wrapShort, l.wrapLong, ulist) = (_L(200, 400, 3600), _L(400, 0, 86_400), true);
    }

    function _limHash(IWrappedToken.WrapLimit memory x) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256(bytes(LIMIT_T)), x.perUser, x.tokenWide, x.period));
    }

    /// @dev EIP-712 `WrapLegLimits[]`, as `GovernanceRouter._legsHash`.
    function _legsHash(IWrappedToken.WrapLegLimits[] memory legs) internal pure returns (bytes32) {
        bytes32[] memory h = new bytes32[](legs.length);
        for (uint256 i; i < legs.length; ++i) {
            IWrappedToken.WrapLegLimits memory l = legs[i];
            h[i] = keccak256(abi.encode(keccak256(bytes(string.concat(LEG_T, LIMIT_T))), l.underlying, l.unitExp, l.decayDays,
                _limHash(l.wrapShort), _limHash(l.wrapLong), _limHash(l.unwrapShort), _limHash(l.unwrapLong)));
        }
        return keccak256(abi.encodePacked(h));
    }

    // ------------------------------------------------------------------ GovernanceRouter, signed by key 1, sent by key 2

    function _auth(string memory typ, address target, bytes memory words)
        internal view returns (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory s)
    {
        (e.from, e.nonce, e.validUntil) = (_pad(a1), gr.mtxNonce(_pad(a1), 0), vu);
        s = _sig(k1, _named(address(gr), typ, bytes.concat(abi.encode(target), words), e));
    }

    function _setLimitsData(uint256 i, uint256 which) internal view returns (bytes memory) {
        (IWrappedToken.WrapLegLimits[] memory legs, bool n_, bool wl_, bool ul_) = _cfg(which);
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory s) = _auth(string.concat(
            "UASetWrapLimits(bytes32 from,address target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList,",
            TAIL, LEG_T, LIMIT_T), tk[i], abi.encode(_legsHash(legs), n_, wl_, ul_));
        return abi.encodeCall(GovernanceRouter.mtxSetWrapLimits, (e, tk[i], legs, n_, wl_, ul_, s));
    }

    function _setLimits(uint256 i, uint256 which, string memory kind) internal {
        _send(_setLimitsData(i, which), _row(kind, i, string.concat("configuration ", vm.toString(which))));
    }

    /// @dev A router op: key 2 relays it.
    function _send(bytes memory data, string memory row) internal {
        _tx(k2, address(gr), 0, data, false, row);
    }

    function _member(uint256 i, address who, bool canWrap, bool canUnwrap) internal {
        _send(_memberData(i, _pad(who), canWrap, canUnwrap), _row("router mtxSetWrapMember", i, vm.toString(who)));
    }

    function _memberData(uint256 i, bytes32 who, bool canWrap, bool canUnwrap) internal view returns (bytes memory) {
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory s) = _auth(string.concat(
            "UASetWrapMember(bytes32 from,address target,bytes32 account,bool canWrap,bool canUnwrap,", TAIL), tk[i],
            abi.encode(who, canWrap, canUnwrap));
        return abi.encodeCall(GovernanceRouter.mtxSetWrapMember, (e, tk[i], who, canWrap, canUnwrap, s));
    }

    function _role(uint256 i, uint8 bit, address who, bool grant) internal {
        _send(_roleData(i, bit, _pad(who), grant), _row(grant ? "router mtxGrantRole" : "router mtxRevokeRole", i,
            string.concat("bit ", vm.toString(bit), " ", vm.toString(who))));
    }

    function _roleData(uint256 i, uint8 bit, bytes32 who, bool grant) internal view returns (bytes memory) {
        bytes32 u = IMetaTx(tk[i]).chainUid(); // the token's chain word, signed and forwarded (CTR-GOV-28)
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory s) = _auth(string.concat(grant ? "UAGrantRole" : "UARevokeRole",
            "(bytes32 from,address target,uint8 bit,bytes32 account,bytes32 chainUid,", TAIL), tk[i], abi.encode(bit, who, u));
        if (grant) return abi.encodeCall(GovernanceRouterBase.mtxGrantRole, (e, tk[i], bit, who, u, s));
        return abi.encodeCall(GovernanceRouterBase.mtxRevokeRole, (e, tk[i], bit, who, u, s));
    }

    /// @dev Bit 27 to `who` as a limited grant: a budget of `budget` quanta (raw units of the leg above the entitlement).
    function _redeemer(uint256 i, address who, uint256 budget) internal {
        _send(_redeemerData(i, _pad(who), budget), _row("router mtxSetGrant", i,
            string.concat("bit 27 ", vm.toString(who), " budget ", _q(budget))));
    }

    function _redeemerData(uint256 i, bytes32 who, uint256 budget) internal view returns (bytes memory) {
        IGovernance.GrantTerms memory t;
        (t.max, t.total) = (type(uint128).max, uint128(budget * Q));
        bytes32 u = IMetaTx(tk[i]).chainUid(); // the token's chain word (CTR-GOV-28)
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory s) = _auth(string.concat(
            "UASetGrant(bytes32 from,address target,uint8 bit,bytes32 holder,GrantTerms terms,bytes32 chainUid,", TAIL, TERMS_T), tk[i],
            abi.encode(RED, who, keccak256(abi.encode(keccak256(bytes(TERMS_T)), t)), u));
        return abi.encodeCall(GovernanceRouterBase.mtxSetGrant, (e, tk[i], RED, who, t, u, s));
    }

    function _ready(uint256 i, string memory what) internal {
        _neg(a2, address(gr), _setLimitsData(i, _pendingOf()), IGovernance.GrantNotReady.selector,
            string.concat("wraplimits ", ph, " ", _h(i), ": ", what));
    }

    /// @dev The configuration waiting in this run: 1 in p1, 4 in p3.
    function _pendingOf() internal view returns (uint256) {
        return keccak256(bytes(ph)) == keccak256("p1") ? 1 : 4;
    }

    function _nx(address from, uint256 i, bytes memory data, bytes memory expected, string memory what) internal {
        _negData(from, tk[i], data, expected, string.concat("wraplimits ", ph, " ", _h(i), ": ", what));
    }

    function _nxSel(address from, uint256 i, bytes memory data, bytes4 expected, string memory what) internal {
        _neg(from, tk[i], data, expected, string.concat("wraplimits ", ph, " ", _h(i), ": ", what));
    }

    // ------------------------------------------------------------------ the token configs

    function _tokenCfg(uint256 i, uint256 features, bool hybrid) internal view returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals, c.admin) = (string.concat("Onchain WL ", _h(i)), string.concat("oWL", _h(i)), 6, _pad(a1));
        c.features = 1 << GovernanceBits.PAYABLE | features;
        if (hybrid) (c.features, c.roles.minter, c.maxSupply) = (c.features | 1 << GovernanceBits.MINTABLE, _pad(a1), 1e30);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        // the PQZ kinds in the OFFCHAIN verify mode (no PQZ precompile here): a fixed verifier, test key 3's native id
        if (i != 0) c.conf = IFactoryToken.ConfidentialConfig("", 10_000, uint256(1) << 40, 2, 0, 0, 0, 1, _pad(a3), true, 0, 0, 0);
        // round 3s (token-lists spec §5.5): kind 13 with an admin keeps its deny list enableable, so it carries terms
        if (_kind(i) >= 8) c.reg.termsHash = keccak256("onchain wl terms");
    }
}

/// @notice Run 0 (`setup()`): this group's factory (registrar test key 1, `noticePeriod()` 1 hour, the Step 5 router), the
///         body modules, envs and releases of kinds 1, 5 and 13 on the Step 5 registry, the libraries forge links for this
///         contract (the kinds' link closures), and the leg, a 6-decimal MockERC20. The releases are usable after the notice.
contract WrapLimitsSetup is WrapLimitsKit {
    function setup() external {
        _start("setup", false);
        OpenFactory f5 = OpenFactory(_dep("token_factory"));
        bytes memory init = abi.encodePacked(vm.getCode("OpenFactory.sol:OpenFactory"), abi.encode(_pad(a1)));
        fw = OpenFactory(_create2(init, "fw", "factory: this group's OpenFactory"));
        _tx(k1, address(fw), 0, abi.encodeCall(OpenFactory.configureChain, (vm.parseJsonBytes32(dj, ".chain_uid"), NOTICE,
            address(gr), address(gr).codehash, 0, bytes32(0))), false, "factory | configureChain, noticePeriod 3600 s");
        init = abi.encodePacked(type(MockERC20).creationCode, abi.encode("Onchain WL USD", "oWLUSD", uint8(6)));
        usd = MockERC20(_create2(init, "usd", "leg | MockERC20, 6 decimals"));
        IFactoryToken.Env memory e5 = f5.tokenEnvOf(IOpenFactory.TokenKind.WRAPPED, 1);
        for (uint256 i; i < 3; ++i) _release(i, e5);
        console2.log(string.concat("wl setup factory ", vm.toString(address(fw)), " leg ", vm.toString(address(usd)),
            " notice ", vm.toString(fw.noticePeriod())));
        _save(block.timestamp + NOTICE + 300);
    }

    function _create2(bytes memory init, string memory what, string memory row) internal returns (address a) {
        bytes32 s = _salt(what);
        a = vm.computeCreate2Address(s, keccak256(init), CREATE2_FACTORY);
        _tx(k1, CREATE2_FACTORY, 0, bytes.concat(s, init), true, row);
        require(a.code.length != 0, what);
    }

    /// @dev The link closure of kind `_kind(i)` (Catalogue.closureLibs): referenced here, so forge links and deploys them.
    function _libs(uint256 i) internal pure returns (address[] memory l) {
        l = new address[](i == 0 ? 4 : i == 1 ? 9 : 10);
        (l[0], l[1], l[2], l[3]) = (address(GovernanceLib), address(HederaLib), address(MtxPipelineLib), address(WrappedLib));
        if (i == 0) return l;
        (l[4], l[5], l[6], l[7], l[8]) =
            (address(PqzStateLib), address(PqzTransferLib), address(PqzBurnLib), address(PqzViewLib), address(PqzWrappedLib));
        if (i == 2) l[9] = address(RegulatedLib);
    }

    /// @dev Kind `k`'s body modules for this group's factory (`abi.encode(factory, core)`), each by CREATE2.
    function _modules(uint8 k, bytes memory core) internal returns (address[] memory ms) {
        string[] memory n = kindModuleNames(k);
        ms = new address[](n.length);
        for (uint256 j; j < n.length; ++j) {
            ms[j] = _create2(bytes.concat(vm.getCode(n[j]), abi.encode(address(fw), core)), n[j],
                string.concat("module | ", vm.split(n[j], ":")[1]));
        }
    }

    /// @dev Env 1 of kind `_kind(i)`: the Step 5 registry and SmartKeyAccount implementation, the link closure, the modules;
    ///      a PQZ kind's deps the release verifier 0 (the OFFCHAIN mode reads none).
    function _env(uint256 i, IFactoryToken.Env memory e5, address[] memory ms) internal view returns (IFactoryToken.Env memory) {
        address[] memory libs = _libs(i);
        address[] memory l = new address[](libs.length + ms.length);
        bytes32[] memory h = new bytes32[](l.length);
        for (uint256 j; j < l.length; ++j) {
            l[j] = j < libs.length ? libs[j] : ms[j - libs.length];
            h[j] = l[j].codehash;
        }
        return IFactoryToken.Env(e5.registry, e5.smartKeyAccountImpl, false, new address[](i == 0 ? 0 : 1), new bytes32[](0), l, h);
    }

    function _release(uint256 i, IFactoryToken.Env memory e5) internal {
        uint8 k = _kind(i);
        bytes memory core = k >= 8 ? abi.encode(vm.parseJsonBytes32(dj, ".compliance_registry_codehash")) : bytes("");
        address[] memory ms = _modules(k, core);
        IOpenFactory.TokenKind kind = IOpenFactory.TokenKind(k);
        _tx(k1, address(fw), 0, abi.encodeCall(OpenFactory.publishTokenEnv, (kind, 1, fw.chainUid(), _env(i, e5, ms))), false,
            string.concat("factory | publishTokenEnv kind ", vm.toString(k)));
        string memory face = string.concat(_label(i), ".sol:", _label(i));
        _tx(k1, address(fw), 0, abi.encodeCall(OpenFactory.deployTokenImplementation, (kind, 1, 1, vm.getCode(face),
            kindImplArgs(k, ms, core), fw.chainUid())), true, string.concat("release | ", _label(i)));
        if (k != 1) {
            _tx(k1, address(fw), 0, abi.encodeCall(OpenFactory.setTokenKindEnabled, (kind, true, fw.chainUid())), false,
                string.concat("factory | setTokenKindEnabled kind ", vm.toString(k)));
        }
    }
}

/// @notice Runs 1-6 of group `wraplimits` (`p1()`..`p6()`), each at the time the previous one wrote.
contract WrapLimits is WrapLimitsKit {
    /// p1 (the releases usable): the three hybrids, the pure-wrap refusals of bits 25-27, the first configuration
    /// (direct), the short window per user and token-wide, a relayed wrap counted on its signer, units paid away, an
    /// unwrap tracked with no rule on, the redeemer's budgeted grant, the unwrap tightening proposed.
    function p1() external {
        _start("p1", true);
        for (uint256 i; i < 3; ++i) {
            IFactoryToken.TokenConfig memory c = _tokenCfg(i, GovernanceBits.WRAP_CONTROLS, true);
            tk[i] = abi.decode(_tx(k1, address(fw), 0, abi.encodeCall(OpenFactory.createToken, (IOpenFactory.TokenKind(
                _kind(i)), 1, abi.encode(c), _salt(_h(i)))), false, _row("factory createToken", i, "hybrid, bits 25-27")),
                (address));
            _log(i, string.concat(_label(i), " ", vm.toString(tk[i])));
            for (uint8 bit = WL; bit <= RED; ++bit) {
                c = _tokenCfg(i, uint256(1) << bit, false);
                _negData(a1, address(fw), abi.encodeCall(OpenFactory.createToken, (IOpenFactory.TokenKind(_kind(i)), 1,
                    abi.encode(c), _salt(string.concat("pure", vm.toString(bit))))),
                    abi.encodeWithSelector(IWrappedToken.WrapControlNeedsHybrid.selector, bit),
                    string.concat("wraplimits p1 kind ", vm.toString(_kind(i)), ": a pure-wrap token with bit ", vm.toString(bit), ": WrapControlNeedsHybrid"));
            }
        }
        _tx(k1, a4, 1 ether, "", false, "fund | 1 ether to the fourth key");
        uint256[4] memory pks = [k1, k2, k3, k4];
        for (uint256 p; p < 4; ++p) {
            _tx(k1, address(usd), 0, abi.encodeCall(MockERC20.mint, (vm.addr(pks[p]), 1e12)), false, "fund | the leg minted");
            for (uint256 i; i < 3; ++i) {
                _tx(pks[p], address(usd), 0, abi.encodeWithSelector(APPROVE, tk[i], type(uint256).max), false,
                    _row("fund approve", i, vm.toString(vm.addr(pks[p]))));
            }
        }
        for (uint256 i; i < 3; ++i) _p1(i);
        // the router's negatives last: each signs the router's next nonce of key 1 at this run's end
        for (uint256 i; i < 3; ++i) _ready(i, "the unwrap tightening confirmed before the notice: GrantNotReady");
        _save(block.timestamp + NOTICE + 300);
    }

    function _p1(uint256 i) internal {
        address t = tk[i];
        (IWrappedToken.WrapLegLimits[] memory legs, bool n_, bool wl_, bool ul_) = _cfg(0);
        _tx(k1, t, 0, abi.encodeCall(IWrappedToken.setWrapLimits, (legs, n_, wl_, ul_)), false,
            _row("setWrapLimits direct (first, at once)", i, "configuration 0"));
        _wrap(k2, i, 100, "wrap (tracked, first use)");
        // relayed: key 1 signs, key 2 (at its own cap) submits; the signer's quota counts
        MetaTxLib.Envelope memory e = _aenv(a1, 11, IUALedgerViews(t).mtxNonce(_pad(a1), 11));
        bytes memory sg = _ecdsa(k1, _namedA(t, WRAP_LEG, abi.encode(address(usd), 100 * Q), e));
        _tx(k2, t, 0, abi.encodeCall(IWrappedToken.mtxWrapLeg, (e, address(usd), 100 * Q, sg)), false,
            _row("mtxWrapLeg relayed (tracked, first use)", i, string.concat("signed by ", vm.toString(a1), ", 100 Q")));
        require(_qt(i, a1).netWrapped == 100 * Q && _qt(i, a2).wrapShort.left == 0, "p1: the signer counted");
        _tx(k2, t, 0, abi.encodeWithSelector(TRANSFER, a3, 40 * Q), false, _row("transfer", i, "40 Q to the merchant"));
        _tx(k2, t, 0, abi.encodeWithSelector(TRANSFER, A5, 10 * Q), false, _row("transfer", i, "10 Q to A5"));
        _unwrap(k2, i, 10, "unwrap (tracked, no rule)");
        _redeemer(i, a3, 18);
        _setLimits(i, 1, "router mtxSetWrapLimits (unwrap tighter: proposed)");
        (, bool net_,,,, uint64 eta, bool live, uint64 delay) = IWrappedToken(t).wrapLimits();
        require(!net_ && live && delay == NOTICE && eta >= block.timestamp + NOTICE, "p1: proposed, nothing applied");
        require(_qt(i, a2).netWrapped == 90 * Q && _qt(i, a3).redeemer && _qt(i, a3).netWrapped == 0, "p1: net and role");
        _log(i, string.concat("proposed, eta ", vm.toString(eta)));
        _nx(a2, i, _wrapData(1), _over(0, a2, 1, 0), "a wrap over the short per-user cap: WrapLimitExceeded");
        _nx(a3, i, _wrapData(1), _capOver(0, 1, 0), "a wrap over the short token-wide cap: WrapCapExceeded");
    }

    /// p2 (after the notice; the short windows ended): the tightening confirmed, the long window, the unwrap windows per
    /// user and token-wide, the net rule, the redeemer within and over its budget, the decay row's wrap, the lister.
    function p2() external {
        _start("p2", true);
        for (uint256 i; i < 3; ++i) _p2(i);
        _save(block.timestamp + 3600 + 300);
    }

    function _p2(uint256 i) internal {
        address t = tk[i];
        (, bool net_,,,,, bool live,) = IWrappedToken(t).wrapLimits();
        require(!net_ && live, "p2: still pending");
        require(_qt(i, a2).netWrapped == 90 * Q && _qt(i, a1).netWrapped == 100 * Q && _qt(i, A5).netWrapped == 0
            && _qt(i, a2).wrapLong.left == 50 * Q && IWrappedToken(t).wrapQuotaTotal(address(usd)).wrapShort.left == 200 * Q,
            "p2: p1's state read back");
        _log(i, "read back: b(a2) 90 Q, b(a1) 100 Q, b(A5) 0, a2's long window 50 Q left, the token-wide short window over, pending live");
        _setLimits(i, 1, "router mtxSetWrapLimits (unwrap tighter: confirmed)");
        (IWrappedToken.WrapLegLimits[] memory legs, bool n2,,,,, bool live2,) = IWrappedToken(t).wrapLimits();
        require(n2 && !live2 && legs[0].decayDays == 2 && legs[0].unwrapShort.perUser == 30, "p2: applied");
        _wrap(k2, i, 50, "wrap (tracked)");
        _unwrap(k2, i, 30, "unwrap (tracked, net rule and decay)");
        _unwrap(k3, i, 15, "unwrap by the redeemer (past E, its budget)");
        _wrap(k4, i, 100, "wrap (tracked, first use)");
        IWrappedToken.WrapQuota memory q = _qt(i, a4);
        require(q.netWrapped == 100 * Q && q.entitlement == 100 * Q && q.entitlementZeroAt != 0, "p2: the decay row");
        _log(i, string.concat("a4 E ", vm.toString(q.entitlement), " zero at ", vm.toString(q.entitlementZeroAt)));
        _role(i, WLIST, a1, true);
        _nx(a2, i, _wrapData(1), _over(1, a2, 1, 0), "a wrap over the long per-user cap (the short has room): WrapLimitExceeded");
        _nx(a2, i, _unwrapData(a2, 1), _over(2, a2, 1, 0), "an unwrap over the short per-user cap: WrapLimitExceeded");
        _nx(a1, i, _unwrapData(a1, 10), _capOver(2, 10, 5), "an unwrap over the short token-wide cap: WrapCapExceeded");
        _nx(A5, i, _unwrapData(A5, 5), _aboveNet(A5, 5), "an unwrap of units received by transfer (the net rule): UnwrapAboveNetWrapped");
        _nx(a3, i, _unwrapData(a3, 4), abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(2)),
            "the redeemer past its budget (15 of 18 Q spent): GrantExhausted");
        _nx(a1, i, abi.encodeCall(IGovernance.disableFeature, (WL, IMetaTx(tk[i]).chainUid())),
            abi.encodeWithSelector(IWrappedToken.WrapControlActive.selector, WL), "disableFeature(25) with the limits on: WrapControlActive");
        _nx(a1, i, abi.encodeCall(IGovernance.disableFeature, (RED, IMetaTx(tk[i]).chainUid())),
            abi.encodeWithSelector(IWrappedToken.WrapControlActive.selector, RED), "disableFeature(27) with a holder: WrapControlActive");
    }

    /// p3 (the windows ended): the wrapper list at once, members direct and by the router, a listed wrap, the unwrap side
    /// relaxed at once, a relayed unwrap counted on its signer, the wrap side relaxed with the unwrapper list proposed.
    function p3() external {
        _start("p3", true);
        for (uint256 i; i < 3; ++i) _p3(i);
        for (uint256 i; i < 3; ++i) _ready(i, "the wrap relaxation confirmed before the notice: GrantNotReady");
        _save(block.timestamp + NOTICE + 300);
    }

    function _p3(uint256 i) internal {
        address t = tk[i];
        IWrappedToken.WrapQuota memory q = _qt(i, a4);
        require(q.netWrapped == 100 * Q && q.entitlement < 100 * Q && q.entitlement >= 95 * Q, "p3: a4's line decays");
        require(_qt(i, a2).wrapLong.left == 0 && _qt(i, a3).redeemer, "p3: p2's state read back");
        _log(i, "read back: b(a4) 100 Q, a2's long window full, the merchant a redeemer");
        _log(i, string.concat("a4 E after ~1 h ", vm.toString(q.entitlement)));
        _setLimits(i, 2, "router mtxSetWrapLimits (wrap tighter: at once)");
        (, , bool wl2,,,,,) = IWrappedToken(t).wrapLimits();
        require(wl2, "p3: the wrapper list on");
        _member(i, a2, true, true);
        _tx(k1, t, 0, abi.encodeCall(IWrappedToken.setWrapMember, (_pad(a1), true, true)), false,
            _row("setWrapMember direct", i, vm.toString(a1)));
        _tx(k1, t, 0, abi.encodeCall(IWrappedToken.setWrapMember, (_pad(a4), false, true)), false,
            _row("setWrapMember direct", i, vm.toString(a4)));
        _tx(k1, t, 0, abi.encodeCall(IWrappedToken.setWrapMember, (_pad(a3), false, true)), false,
            _row("setWrapMember direct", i, vm.toString(a3)));
        _wrap(k1, i, 10, "wrap (tracked, listed)");
        _setLimits(i, 3, "router mtxSetWrapLimits (unwrap looser: at once)");
        (IWrappedToken.WrapLegLimits[] memory legs,,,,,,,) = IWrappedToken(t).wrapLimits();
        require(legs[0].unwrapShort.perUser == 100, "p3: the unwrap side relaxed");
        _unwrap(k2, i, 50, "unwrap (tracked, net rule and decay)");
        MetaTxLib.UAEnvelope memory e = _env(a1, 12, IUALedgerViews(t).mtxNonce(_pad(a1), 12));
        IUARegistry.UASig memory s = _sig(k1, _named(t, UA_UNWRAP_LEG, abi.encode(address(usd), 10 * Q, a1, uint256(0)), e));
        _tx(k2, t, 0, abi.encodeCall(IWrappedToken.mtxUnwrapLeg, (e, address(usd), 10 * Q, a1, 0, s)), false,
            _row("mtxUnwrapLeg relayed (tracked)", i, string.concat("signed by ", vm.toString(a1), ", 10 Q")));
        require(_qt(i, a1).unwrapShort.left == 90 * Q, "p3: the signer counted");
        _setLimits(i, 4, "router mtxSetWrapLimits (wrap looser + unwrapper list: proposed)");
        _nx(a3, i, _wrapData(1), abi.encodeWithSelector(IWrappedToken.WrapperNotListed.selector, _pad(a3)),
            "a wrap by an id not on the wrapper list: WrapperNotListed");
        _nx(a1, i, abi.encodeCall(IGovernance.disableFeature, (WLIST, IMetaTx(tk[i]).chainUid())),
            abi.encodeWithSelector(IWrappedToken.WrapControlActive.selector, WLIST), "disableFeature(26) with a list on: WrapControlActive");
    }

    /// p4 (after the notice): the wrap relaxation and the unwrapper list confirmed; a wrap over the old caps; a listed
    /// unwrap. Next: the decay row's half horizon.
    function p4() external {
        _start("p4", true);
        uint256 zero;
        for (uint256 i; i < 3; ++i) {
            _p4(i);
            uint256 z = _qt(i, a4).entitlementZeroAt;
            if (z > zero) zero = z;
        }
        _save(zero - 1 days + 30); // H = 2 days: E at H/2
    }

    function _p4(uint256 i) internal {
        address t = tk[i];
        (,, bool wl1,,,, bool live,) = IWrappedToken(t).wrapLimits();
        require(wl1 && live && !_qt(i, a3).canWrap && _qt(i, a2).canWrap, "p4: p3's state read back");
        _log(i, "read back: the wrapper list on, the merchant not a wrapper, a2 a wrapper, pending live");
        _setLimits(i, 4, "router mtxSetWrapLimits (wrap looser + unwrapper list: confirmed)");
        (IWrappedToken.WrapLegLimits[] memory legs,,, bool ul,,, bool live2,) = IWrappedToken(t).wrapLimits();
        require(ul && !live2 && legs[0].wrapShort.perUser == 200, "p4: applied");
        _wrap(k2, i, 120, "wrap (tracked, listed)");
        _unwrap(k2, i, 10, "unwrap (tracked, listed)");
        _nx(A5, i, _unwrapData(A5, 1), abi.encodeWithSelector(IWrappedToken.UnwrapperNotListed.selector, _pad(A5)),
            "an unwrap by an id not on the unwrapper list: UnwrapperNotListed");
    }

    /// p5 (the decay row's H/2): E is half of what it wrapped; an unwrap within it, one above it refused.
    function p5() external {
        _start("p5", true);
        uint256 zero;
        for (uint256 i; i < 3; ++i) {
            IWrappedToken.WrapQuota memory q = _qt(i, a4);
            require(q.netWrapped == 100 * Q && q.entitlement >= 49 * Q && q.entitlement <= 50 * Q, "p5: E at H/2");
            _log(i, string.concat("a4 E at H/2 ", vm.toString(q.entitlement)));
            _unwrap(k4, i, 10, "unwrap (tracked, decay at H/2)");
            _nxSel(a4, i, _unwrapData(a4, 45), IWrappedToken.UnwrapAboveNetWrapped.selector, "an unwrap above E at H/2: UnwrapAboveNetWrapped");
            if (q.entitlementZeroAt > zero) zero = q.entitlementZeroAt;
        }
        _save(zero + 30);
    }

    /// p6 (the decay row's H): E is 0; the redeemer revoked through the router, at once.
    function p6() external {
        _start("p6", true);
        for (uint256 i; i < 3; ++i) {
            IWrappedToken.WrapQuota memory q = _qt(i, a4);
            // b after the H/2 unwrap: 80 Q at E = 50 Q, 79 Q at E = 49 Q (a minute later on that token)
            require(q.entitlement == 0 && q.netWrapped >= 79 * Q && q.netWrapped <= 80 * Q, "p6: E at H");
            _log(i, string.concat("a4 E at H ", vm.toString(q.entitlement), ", b ", vm.toString(q.netWrapped)));
            _role(i, RED, a3, false);
            require(!_qt(i, a3).redeemer, "p6: revoked");
            _nx(a4, i, _unwrapData(a4, 1), _aboveNet(a4, 1), "an unwrap at H (E = 0): UnwrapAboveNetWrapped");
            _nx(a3, i, _unwrapData(a3, 1), _aboveNet(a3, 1), "the revoked redeemer: UnwrapAboveNetWrapped");
        }
        _save(0);
    }
}
