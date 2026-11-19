// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";
import {GovernanceRouterTypes as T} from "../../src/governance/GovernanceRouterBase.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {regArgs} from "../helpers/Catalogue.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {SdkGasRouterFix} from "./SdkGasFixtures.sol";
import {MockWallet} from "../ua/UARegistryBase.sol";

/// The `gov_router` domain kind's base rows (owner 2026-11-19, part 3b): each router entry signed for its target, on the
/// router of `GovRouterFixture` (its targets clones of the real kinds, this test their factory), the variant the target's
/// kind. The signer is the fixture's native id `eoa` (an ECDSA key: the reference signer), its successor `next` where the
/// op is the successor's (`mtxAcceptAdmin`, `mtxRenounceAdmin` after it), the order's seat (`next`) for `mtxRecordOrder`
/// and `mtxRevokeOrder`; the wrapped token's rate admin is the fixture's `wallet` (`RATE_ADJUSTABLE` is a contract-only
/// bit: no native key can hold it, so the rate rows carry that wallet's ERC-1271 check). Each entry is measured in the
/// state the fixture's own sequence of ops reaches just before it (`_grSt` measures, then applies the op on lane 0 so the
/// next entry finds its effect); every write a first write (a mint, a force or operator transfer to an account holding
/// nothing, a list entry, a grant, a freeze). G2: each sequence runs once more with derived identities
/// (`_grUaRun`), its rows `gov_router_<entry>_ua_<variant>`.
abstract contract SdkGasRouterBase is SdkGasRouterFix {
    /// the signer of the row (a native id of the fixture, or `wallet`), the lane of the call built (`SG_LANE` measured, 0
    /// the sequence's own lane)
    bytes32 internal grWho;
    uint256 internal grLane;
    /// a static op: its typehash, selector, target, call words (every one static, the chain word last) and struct words
    bytes32 internal grTh;
    bytes4 internal grSel;
    address internal grT;
    bytes internal grArgs;
    bytes internal grWords;

    address internal regImpl;
    /// `_grRegulated` gives the issuer seat to `eoa` whatever the features (the list bits 8 and 9 need a holder root)
    bool internal grIssuerSeat;

    function setUp() public virtual override {
        super.setUp();
        grLane = SG_LANE;
        sgUaKind = 0; // the derived identities sign in a run of their own (`_grUaRun`), not beside each native row
    }

    /// G2 (owner 2026-11-19): the fixture's sequence once more with `eoa` and `next` the derived UAs registered on `PREG`
    /// (secp256k1 `SG_UA_SK`, `SG_UA_SK2`), every row measured once as `gov_router_<entry>_ua_<variant>` (`_bothUaRun`);
    /// the roles a native key cannot hold keep their ERC-1271 wallet, whose rows so add nothing.
    function _grUaRun() internal {
        (eoa, next, sgUaRun) = (UAKinds.uaOf(UAKinds.SECP256K1, sgUaKey), _sgPayeeUa(), true);
    }

    function _grE(uint256 nonce) internal view returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(grWho, grLane, nonce, block.timestamp + 1 hours, 0, address(0), 0, address(0));
    }

    /// The digest of `th` over `(from, target, words…, envelope)` in the router's domain, relayer and fee recipient unbound.
    function _grD(bytes32 th, address target, bytes memory words, MetaTxLib.UAEnvelope memory e)
        internal
        view
        returns (bytes32)
    {
        return MtxDigest.typed(
            address(router),
            keccak256(
                bytes.concat(
                    abi.encode(th, e.from, target),
                    words,
                    abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))
                )
            )
        );
    }

    /// The static op `grSel` of `grWho` on `grT` at `nonce`.
    function _grStatic(address, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _grE(nonce);
        bytes memory head = bytes.concat(abi.encode(e), abi.encode(grT), grArgs);
        bytes memory sig = _tail(abi.encode(_auth(grWho, _grD(grTh, grT, grWords, e))));
        return bytes.concat(grSel, head, abi.encode(head.length + 32), sig);
    }

    /// `build`'s call on the sequence's lane 0 at the signer's next nonce, run (the effect the next entry finds).
    function _grApply(function(address, uint256) internal view returns (bytes memory) build) internal {
        grLane = 0;
        bytes memory cd = build(address(router), router.mtxNonce(grWho, 0));
        grLane = SG_LANE;
        _run(cd);
    }

    /// One entry's rows (fresh and used lane), then the op applied.
    function _grRow(
        string memory entry,
        string memory variant,
        bytes32 who,
        function(address, uint256) internal view returns (bytes memory) build
    ) internal {
        grWho = who;
        _both("gov_router", entry, variant, address(router), who, build);
        _grApply(build);
    }

    function _grSet(bytes32 th, bytes4 sel, address t, bytes memory args, bytes memory words) internal {
        (grTh, grSel, grT, grArgs, grWords) = (th, sel, t, args, words);
    }

    /// A static entry's rows, then the op applied.
    function _grSt(
        string memory entry,
        string memory variant,
        bytes32 th,
        bytes4 sel,
        bytes32 who,
        address t,
        bytes memory args
    ) internal {
        _grSet(th, sel, t, args, args);
        _grRow(entry, variant, who, _grStatic);
    }

    /// A static op applied only (a step of the sequence that is no row here).
    function _grDo(bytes32 th, bytes4 sel, bytes32 who, address t, bytes memory args) internal {
        _grSet(th, sel, t, args, args);
        grWho = who;
        _grApply(_grStatic);
    }

    /// The admin `eoa` grants `bit` of `t` to `account`, a step of the sequence: directly by its key, or (G2, a derived `eoa`
    /// in `_grUaRun`, which has no key to call with) through the router on lane 0, no row.
    function _grGrant(address t, uint8 bit, bytes32 account) internal {
        bytes32 u = EnvKit.codeUidOf(t);
        if (sgUaRun) return _grDo(T.UA_GRANT_ROLE, router.mtxGrantRole.selector, eoa, t, abi.encode(bit, account, u));
        vm.prank(address(uint160(uint256(eoa))));
        IGovernance(t).grantRole(bit, account, u);
    }

    /// The admin hand-over of `t` (admin `eoa`): to `next`, accepted by `next`, renounced by `next`.
    function _grAdminRows(string memory v, address t) internal {
        bytes32 u = EnvKit.codeUidOf(t);
        _grHandOver(v, t);
        _grSt("mtxRenounceAdmin", v, T.UA_RENOUNCE_ADMIN, router.mtxRenounceAdmin.selector, next, t, abi.encode(u));
    }

    /// The hand-over without the renounce (a target whose roles still have holders refuses it, `AdminHasHolders`).
    function _grHandOver(string memory v, address t) internal {
        bytes32 u = EnvKit.codeUidOf(t);
        _grSt("mtxTransferAdmin", v, T.UA_TRANSFER_ADMIN, router.mtxTransferAdmin.selector, eoa, t, abi.encode(next, u));
        _grSt("mtxAcceptAdmin", v, T.UA_ACCEPT_ADMIN, router.mtxAcceptAdmin.selector, next, t, "");
    }

    /// A regulated token of kind 8 (`NormalRegulatedToken`), admin `eoa`, grant delay `delay`, features `features`
    /// (`PAYABLE` always), the issuer seat `eoa` and the compliance seat `next` where a bit has them, the minter `eoa` where
    /// `MINTABLE` is on; `BOB` holds 1,000.
    function _grRegulated(uint256 features, uint64 delay) internal returns (NormalRegulatedToken t) {
        if (regImpl == address(0)) {
            regImpl = address(new NormalRegulatedToken(address(this), kindArgs(8, address(this), regArgs())));
        }
        t = NormalRegulatedToken(EnvKit.clone(regImpl, _cenv()));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin, c.grantDelay) = ("R", "R", 6, eoa, delay);
        c.features = 1 | features;
        if (features & (uint256(1) << GovernanceBits.TAX) != 0) c.reg.taxRecipient = _pad(address(0x7A0));
        if (features & (uint256(1) << MINT) != 0) c.roles.minter = eoa;
        if (grIssuerSeat || features & ((1 << 5) | (1 << 6) | (1 << 7) | (uint256(1) << GovernanceBits.TAX)) != 0) {
            c.roles.issuer = eoa;
        }
        if (features & (1 << GovernanceBits.RECORD) != 0) c.roles.compliance = next;
        (c.initialSupply, c.initialHolder) = (1000, BOB);
        c.reg.termsHash = keccak256("terms");
        t.initialize(nid(address(this)), 1, abi.encode(c));
    }
}

/// The governance entries on a Normal token (variant `normal`, `MINTABLE`, grant delay 1 hour) and a regulated Normal
/// (`regulated`, kind 8, `MINTABLE` too, the same delay), in the fixture's order (`GovRouterTest._tokenOps`): the mints (to
/// an account and a UA holding nothing), `MINTABLE`'s grant narrowed, granted to `next` (pending under the delay),
/// cancelled, the role revoked (barring `next`), renounced, the feature disabled, the admin handed to `next`, accepted,
/// renounced.
contract SdkGasRouterTokenTest is SdkGasRouterBase {
    function _grGov(string memory v, address t) internal {
        bytes32 u = EnvKit.codeUidOf(t);
        (bytes32 s, bytes32 y) = (eoa, next);
        _grSt("mtxMint", v, T.UA_MINT, router.mtxMint.selector, s, t, abi.encode(SG_PAYEE, uint256(5), u));
        _grSt("mtxMintToUA", v, T.UA_MINT_TO_UA, router.mtxMintToUA.selector, s, t, abi.encode(pq, uint256(3), u));
        (bytes memory a, bytes memory w) = _setGrantArgs(MINT, s, _limited(100), u);
        _grSet(T.UA_SET_GRANT, router.mtxSetGrant.selector, t, a, w);
        _grRow("mtxSetGrant", v, s, _grStatic);
        _grSt("mtxGrantRole", v, T.UA_GRANT_ROLE, router.mtxGrantRole.selector, s, t, abi.encode(MINT, y, u));
        _grSt("mtxCancelGrant", v, T.UA_CANCEL_GRANT, router.mtxCancelGrant.selector, s, t, abi.encode(MINT, y, u));
        _grSt("mtxRevokeRole", v, T.UA_REVOKE_ROLE, router.mtxRevokeRole.selector, s, t, abi.encode(MINT, y, u));
        _grSt("mtxRenounceRole", v, T.UA_RENOUNCE_ROLE, router.mtxRenounceRole.selector, s, t, abi.encode(MINT, u));
        _grSt(
            "mtxDisableFeature", v, T.UA_DISABLE_FEATURE, router.mtxDisableFeature.selector, s, t, abi.encode(MINT, u)
        );
        _grAdminRows(v, t);
    }

    /// G2: the same sequence by derived identities (`_grUaRun`).
    function test_sdkGas_routerToken_ua() public {
        _grUaRun();
        test_sdkGas_routerToken();
    }

    function test_sdkGas_routerToken() public {
        _grGov("normal", address(_normal(eoa, eoa, 1 hours)));
        _grGov("regulated", address(_grRegulated(uint256(1) << MINT, 1 hours)));
    }
}

/// The rate, wrap and admin entries on a Wrapped token (variant `wrapped`: the fixture's `_wrapped`, leg `usd` 1:1, the rate
/// delay 2 days, `wallet` its rate admin): a rate proposed, cancelled, proposed again and executed 2 days on, the leg's wrap
/// disabled, the admin handed over; and the DEX entries on a DEX (`dex`, the fixture's `_dex`): a market listed, an exchange
/// target listed, listed-only on, the fee split set, the admin handed over.
contract SdkGasRouterWrappedTest is SdkGasRouterBase {
    /// G2: the same sequence by derived identities (`_grUaRun`).
    function test_sdkGas_routerWrapped_ua() public {
        _grUaRun();
        test_sdkGas_routerWrapped();
    }

    function test_sdkGas_routerWrapped() public {
        WrappedToken wt = _wrapped(eoa, eoa, wallet);
        address t = address(wt);
        bytes32 u = EnvKit.codeUidOf(t);
        bytes memory rate = abi.encode(address(usd), uint96(101), uint96(100), u);
        _grSt("mtxProposeRate", "wrapped", T.UA_PROPOSE_RATE, router.mtxProposeRate.selector, wallet, t, rate);
        _grSt("mtxCancelRate", "wrapped", T.UA_CANCEL_RATE, router.mtxCancelRate.selector, wallet, t, abi.encode(u));
        _grDo(T.UA_PROPOSE_RATE, router.mtxProposeRate.selector, wallet, t, rate);
        vm.warp(block.timestamp + 2 days);
        _grSt("mtxExecuteRate", "wrapped", T.UA_EXECUTE_RATE, router.mtxExecuteRate.selector, wallet, t, abi.encode(u));
        _grSt(
            "mtxDisableWrap",
            "wrapped",
            T.UA_DISABLE_WRAP,
            router.mtxDisableWrap.selector,
            eoa,
            t,
            abi.encode(address(usd), bytes32("r"), u)
        );
        _grHandOver("wrapped", t);
    }

    /// G2: the same sequence by derived identities (`_grUaRun`).
    function test_sdkGas_routerDex_ua() public {
        _grUaRun();
        test_sdkGas_routerDex();
    }

    function test_sdkGas_routerDex() public {
        SCaaSDex d = _dex(eoa);
        address t = address(d);
        bytes32 u = EnvKit.codeUidOf(t);
        address quote = address(_normal(eoa, eoa, 0));
        _grSt(
            "mtxSetMarket",
            "dex",
            T.UA_SET_MARKET,
            router.mtxSetMarket.selector,
            eoa,
            t,
            abi.encode(address(usd), quote, true, u)
        );
        _grSt(
            "mtxSetExchangeTarget",
            "dex",
            T.UA_SET_EXCHANGE_TARGET,
            router.mtxSetExchangeTarget.selector,
            eoa,
            t,
            abi.encode(address(0xE7), true, u)
        );
        _grSt(
            "mtxSetListedOnly",
            "dex",
            T.UA_SET_LISTED_ONLY,
            router.mtxSetListedOnly.selector,
            eoa,
            t,
            abi.encode(true, u)
        );
        _grSt(
            "mtxSetFeeSplit",
            "dex",
            T.UA_SET_FEE_SPLIT,
            router.mtxSetFeeSplit.selector,
            eoa,
            t,
            abi.encode(uint32(500_000), TREASURY, u)
        );
        _grHandOver("dex", t);
    }
}

/// The regulated controls on the fixture's regulated Normal (variant `regulated`, kind 8: `FREEZE`, `FORCE`, `PAUSE` with the
/// issuer seat `wallet` and `RECORD` with the compliance seat, another such wallet, contract-only bits, so these rows carry its ERC-1271
/// check; `OPERATOR_TRANSFER` and `TAX` granted to `eoa`; no grant delay; `BOB` holds 1,000), in the fixture's order
/// (`GovRouterRegulatedTest._eight`): paused, unpaused, an order recorded on `BOB`, `BOB` frozen under it, 30 forced to
/// `TREASURY` (holding nothing), the order revoked, another account frozen (applied only) and unfrozen, 5 moved by the
/// operator to an account holding nothing, the tax rate and recipient set; then on a second regulated Normal without the
/// list bits, `eoa` its issuer seat (the lists' holder root): bit 8 enabled, one account allowed; bit 9 enabled (applied
/// only), one account denied (each further account adds its own write).
contract SdkGasRouterRegulatedTest is SdkGasRouterBase {
    bytes32 internal constant REF = bytes32(uint256(0x5EF));
    bytes32[] internal grAccts;
    bool internal grDeny;

    function _grList(address, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _grE(nonce);
        bytes32 u = EnvKit.codeUidOf(grT);
        bytes memory w = abi.encode(keccak256(abi.encodePacked(grAccts)), true, u);
        bytes32 d = _grD(grDeny ? T.UA_SET_DENIED : T.UA_SET_ALLOWED, grT, w, e);
        if (grDeny) return abi.encodeCall(router.mtxSetDenied, (e, grT, grAccts, true, u, _auth(grWho, d)));
        return abi.encodeCall(router.mtxSetAllowed, (e, grT, grAccts, true, u, _auth(grWho, d)));
    }

    /// `GovRouterRegulatedTest._regulated`: kind 8 with bits 5-7, 10, 22 and 23, the seats given, bits 22 and 23 granted to
    /// `operator`; `BOB` holds 1,000.
    function _grEight(bytes32 issuer, bytes32 compliance, bytes32 operator) internal returns (NormalRegulatedToken t) {
        if (regImpl == address(0)) {
            regImpl = address(new NormalRegulatedToken(address(this), kindArgs(8, address(this), regArgs())));
        }
        t = NormalRegulatedToken(EnvKit.clone(regImpl, _cenv()));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin) = ("R", "R", 6, eoa);
        c.features = 1 | (uint256(1) << 5) | (uint256(1) << 6) | (uint256(1) << 7) | (uint256(1) << 10)
            | (uint256(1) << GovernanceBits.OPERATOR_TRANSFER) | (uint256(1) << GovernanceBits.TAX);
        c.reg.taxRecipient = _pad(address(0x7A0));
        (c.roles.issuer, c.roles.compliance) = (issuer, compliance);
        (c.initialSupply, c.initialHolder) = (1000, BOB);
        c.reg.termsHash = keccak256("terms");
        t.initialize(nid(address(this)), 1, abi.encode(c));
        _grGrant(address(t), GovernanceBits.OPERATOR_TRANSFER, operator);
        _grGrant(address(t), GovernanceBits.TAX, operator);
    }

    function _grOrderArgs(bytes32 bob, bytes32 ben, uint64 day, bytes32 u) internal pure returns (bytes memory) {
        return abi.encode(bytes32("order"), keccak256("doc"), bob, ben, uint256(100), day, u);
    }

    /// G2: the same sequence by derived identities (`_grUaRun`).
    function test_sdkGas_routerRegulated_ua() public {
        _grUaRun();
        test_sdkGas_routerRegulated();
    }

    function test_sdkGas_routerRegulated() public {
        string memory v = "regulated";
        // the fixture's regulated Normal: the issuer seat `wallet`, the compliance seat `cw`, a wallet like it (bits 5-7 and
        // 10 are contract-only: an ERC-1271 check in these rows), bits 22 and 23 granted to `eoa`
        (address wo, uint256 wpk) = makeAddrAndKey("compliance wallet owner");
        bytes32 cw = _pad(address(new MockWallet(wo, 0, 0, PREG)));
        pkOf[cw] = wpk;
        address t = address(_grEight(wallet, cw, eoa));
        bytes32 u = EnvKit.codeUidOf(t);
        (bytes32 bob, bytes32 ben) = (_pad(BOB), _pad(TREASURY));
        uint64 day = uint64(block.timestamp + 1 days);
        _grSt("mtxPause", v, T.UA_PAUSE, router.mtxPause.selector, wallet, t, abi.encode(REF, day, u));
        _grSt("mtxUnpause", v, T.UA_UNPAUSE, router.mtxUnpause.selector, wallet, t, abi.encode(REF, u));
        bytes32 rid = keccak256(abi.encode(bytes32("order"), bob, ben));
        _grSt(
            "mtxRecordOrder",
            v,
            T.UA_RECORD_ORDER,
            router.mtxRecordOrder.selector,
            cw,
            t,
            _grOrderArgs(bob, ben, day, u)
        );
        _grSt("mtxFreeze", v, T.UA_FREEZE, router.mtxFreeze.selector, wallet, t, abi.encode(bob, REF, rid, u));
        _grSt(
            "mtxForceTransfer",
            v,
            T.UA_FORCE_TRANSFER,
            router.mtxForceTransfer.selector,
            wallet,
            t,
            abi.encode(rid, uint256(30), u)
        );
        _grSt(
            "mtxRevokeOrder",
            v,
            T.UA_REVOKE_ORDER,
            router.mtxRevokeOrder.selector,
            cw,
            t,
            abi.encode(rid, bytes32("why"), u)
        );
        _grTail(v, t, u, bob);
        _grLists(v);
    }

    /// The second freeze, the operator transfer and the tax entries on the regulated Normal `t`.
    function _grTail(string memory v, address t, bytes32 u, bytes32 bob) internal {
        bytes32 other = _pad(address(0xF00));
        _grDo(T.UA_FREEZE, router.mtxFreeze.selector, wallet, t, abi.encode(other, REF, bytes32(0), u));
        _grSt("mtxUnfreeze", v, T.UA_UNFREEZE, router.mtxUnfreeze.selector, wallet, t, abi.encode(other, REF, u));
        _grSt(
            "mtxOperatorTransfer",
            v,
            T.UA_OPERATOR_TRANSFER,
            router.mtxOperatorTransfer.selector,
            eoa,
            t,
            abi.encode(bob, _pad(address(0xBE11)), uint256(5), REF, u)
        );
        _grSt(
            "mtxSetTaxRate", v, T.UA_SET_TAX_RATE, router.mtxSetTaxRate.selector, eoa, t, abi.encode(uint32(1_000), u)
        );
        _grSt(
            "mtxSetTaxRecipient",
            v,
            T.UA_SET_TAX_RECIPIENT,
            router.mtxSetTaxRecipient.selector,
            eoa,
            t,
            abi.encode(_pad(address(0x7A1)), u)
        );
    }

    /// The list entries on a regulated Normal without the list bits.
    function _grLists(string memory v) internal {
        grIssuerSeat = true;
        NormalRegulatedToken l = _grRegulated(0, 0);
        address t = address(l);
        bytes32 u = EnvKit.codeUidOf(t);
        bytes memory on8 = abi.encode(uint8(GovernanceBits.ALLOWLIST), u);
        _grSt("mtxEnableFeature", v, T.UA_ENABLE_FEATURE, router.mtxEnableFeature.selector, eoa, t, on8);
        grAccts.push(_pad(address(0xA11)));
        grT = t;
        _grRow("mtxSetAllowed", v, eoa, _grList);
        _grDo(
            T.UA_ENABLE_FEATURE, router.mtxEnableFeature.selector, eoa, t, abi.encode(uint8(GovernanceBits.DENYLIST), u)
        );
        (grDeny, grT) = (true, t);
        _grRow("mtxSetDenied", v, eoa, _grList);
    }
}

/// The wrap-limit and supply-cap entries on a hybrid (variant `hybrid`: a Wrapped token, `MINTABLE`, the wrap controls
/// (bits 25-27) and `SUPPLY_CAP_ADJUSTABLE`, leg `usd` 1:1, cap 1e30, no grant delay and the factory's notice period 0, so
/// each change applies at once): the first limits (one leg, its four limits on), `eoa` granted bit 26, one account's
/// membership set, the supply cap and the wrap-supply cap set.
contract SdkGasRouterHybridTest is SdkGasRouterBase {
    IWrappedToken.WrapLegLimits[] internal grLegs;

    function _grLimitHash(IWrappedToken.WrapLimit memory x) internal pure returns (bytes32) {
        return keccak256(abi.encode(T.WRAP_LIMIT, x.perUser, x.tokenWide, x.period));
    }

    function _grLimits(address, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _grE(nonce);
        bytes32 u = EnvKit.codeUidOf(grT);
        IWrappedToken.WrapLegLimits memory l = grLegs[0];
        bytes32 lh = keccak256(
            abi.encode(
                T.WRAP_LEG_LIMITS,
                l.underlying,
                l.unitExp,
                l.decayDays,
                _grLimitHash(l.wrapShort),
                _grLimitHash(l.wrapLong),
                _grLimitHash(l.unwrapShort),
                _grLimitHash(l.unwrapLong)
            )
        );
        bytes32 d = _grD(T.UA_SET_WRAP_LIMITS, grT, abi.encode(keccak256(abi.encode(lh)), true, true, true, u), e);
        return abi.encodeCall(router.mtxSetWrapLimits, (e, grT, grLegs, true, true, true, u, _auth(grWho, d)));
    }

    /// G2: the same sequence by derived identities (`_grUaRun`).
    function test_sdkGas_routerHybrid_ua() public {
        _grUaRun();
        test_sdkGas_routerHybrid();
    }

    function test_sdkGas_routerHybrid() public {
        if (wrappedImpl == address(0)) {
            wrappedImpl = address(new WrappedToken(address(this), kindArgs(1, address(this), "")));
        }
        WrappedToken w = WrappedToken(payable(EnvKit.clone(wrappedImpl, _cenv())));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin, c.maxSupply) = ("H", "H", 6, eoa, 1e30);
        c.features = 1 | (uint256(1) << MINT) | GovernanceBits.WRAP_CONTROLS
            | (uint256(1) << GovernanceBits.SUPPLY_CAP_ADJUSTABLE);
        c.roles.minter = eoa;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        w.initialize(nid(address(this)), 1, abi.encode(c));
        address t = address(w);
        bytes32 u = EnvKit.codeUidOf(t);
        string memory v = "hybrid";
        grLegs.push(
            IWrappedToken.WrapLegLimits(
                address(usd),
                2,
                730,
                IWrappedToken.WrapLimit(10, 1_000, 1 days),
                IWrappedToken.WrapLimit(100, 10_000, 30 days),
                IWrappedToken.WrapLimit(10, 1_000, 1 days),
                IWrappedToken.WrapLimit(100, 10_000, 30 days)
            )
        );
        grT = t;
        _grRow("mtxSetWrapLimits", v, eoa, _grLimits);
        _grGrant(address(w), GovernanceBits.WRAP_LIST, eoa);
        _grSt(
            "mtxSetWrapMember",
            v,
            T.UA_SET_WRAP_MEMBER,
            router.mtxSetWrapMember.selector,
            eoa,
            t,
            abi.encode(_pad(address(0xA11)), true, true, u)
        );
        _grSt(
            "mtxSetMaxSupply",
            v,
            T.UA_SET_MAX_SUPPLY,
            router.mtxSetMaxSupply.selector,
            eoa,
            t,
            abi.encode(uint256(5e29), u)
        );
        _grSt(
            "mtxSetMaxWrapSupply",
            v,
            T.UA_SET_MAX_WRAP_SUPPLY,
            router.mtxSetMaxWrapSupply.selector,
            eoa,
            t,
            abi.encode(uint256(500), u)
        );
    }
}
