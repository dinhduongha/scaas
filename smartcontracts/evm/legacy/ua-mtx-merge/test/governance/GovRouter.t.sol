// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceRouterBase} from "../../src/governance/GovernanceRouterBase.sol";
import {IGovernanceRouter} from "../../src/governance/IGovernanceRouter.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {UARegistryBase, MockWallet} from "../ua/UARegistryBase.sol";
import {UACall} from "../ua/UACall.sol";

/// Reads the router's subject on behalf of a contract that is not the router's live target.
contract SubjectPeek {
    function peek(IGovernanceRouter r) external view returns (bytes32) {
        return r.subject();
    }
}

/// A target that answers the DEX's `setListedOnly`: it records what the router names to it and to a bystander during the
/// call, can re-enter the router with prepared calldata, and can call the router itself and read `subject()` after, in
/// the same transaction.
contract ProbeTarget {
    IGovernanceRouter public immutable router;
    SubjectPeek public immutable other = new SubjectPeek();
    bytes32 public seen;
    bytes32 public seenByOther;
    bytes32 public seenAfter;
    bytes public reenter;
    bytes public failure;

    constructor(IGovernanceRouter r) {
        router = r;
    }

    function arm(bytes calldata cd) external {
        reenter = cd;
    }

    function setListedOnly(bool) external {
        seen = router.subject();
        seenByOther = other.peek(router);
        if (reenter.length != 0) {
            (bool ok, bytes memory e) = address(router).call(reenter);
            if (!ok) failure = e;
        }
    }

    /// One transaction: a signed op that targets this contract, then `subject()` asked by this contract again.
    function relayThenRead(bytes calldata cd) external {
        (bool ok, bytes memory e) = address(router).call(cd);
        if (!ok) assembly ("memory-safe") { revert(add(e, 32), mload(e)) }
        seenAfter = router.subject();
    }
}

/// `GovernanceRouter` (CTR-GOV-15 Change, owner 2026-11-04; spec `2026-11-04-governance-ua-identity.md` §3; governance spec
/// §3.2, §3.5 as adapted; plan T11). The real registry with PQ kinds (`mldsa44` single keys and an `msig` of three, 2-of-3) on
/// the stand-in verifier of `UARegistryBase`: the registry's paths (kind caps, `msig` threshold and acceptance) are real, the
/// signature check is the stand-in's. Every op of the closed table by both signed forms on a real `NormalToken`,
/// `WrappedToken` and `SCaaSDex` whose `GOV_ROUTER` is the router; every row of the failure table; the lock, the pair, the
/// generic path.
contract GovRouterTest is UARegistryBase {
    uint8 constant MINT = GovernanceBits.MINTABLE;
    uint8 constant RATE = GovernanceBits.RATE_ADJUSTABLE;
    uint8 constant WRAPOFF = GovernanceBits.WRAP_DISABLEABLE;
    uint8 constant LISTING = GovernanceBits.LISTING;
    uint16 constant ML44 = 0x0130;
    uint64 constant CAP = 4_250_000;
    address constant PREG = address(0x5CA0000000000000000000000000000000000007);
    address constant BOB = address(0xB0B);
    address constant TREASURY = address(0x7EA5);
    string constant TAIL =
        ",uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string constant TERMS =
        "GrantTerms(uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope)";

    // the closed table: index = op
    uint256 constant GRANT_ROLE = 0;
    uint256 constant REVOKE_ROLE = 1;
    uint256 constant SET_GRANT = 2;
    uint256 constant CANCEL_GRANT = 3;
    uint256 constant DISABLE_FEATURE = 4;
    uint256 constant TRANSFER_OWNERSHIP = 5;
    uint256 constant ACCEPT_OWNERSHIP = 6;
    uint256 constant RENOUNCE_OWNERSHIP = 7;
    uint256 constant RENOUNCE_ROLE = 8;
    uint256 constant OP_MINT = 9;
    uint256 constant MINT_TO_UA = 10;
    uint256 constant DISABLE_WRAP = 11;
    uint256 constant PROPOSE_RATE = 12;
    uint256 constant CANCEL_RATE = 13;
    uint256 constant EXECUTE_RATE = 14;
    uint256 constant SET_MARKET = 15;
    uint256 constant SET_EXCHANGE_TARGET = 16;
    uint256 constant SET_LISTED_ONLY = 17;
    uint256 constant SET_FEE_SPLIT = 18;

    struct Row {
        string name;
        string params;
        bytes4 mtx;
        bytes4 ua;
    }

    Row[19] internal rows;
    UARegistry internal preg;
    GovernanceRouter internal router;
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);
    address internal normalImpl;
    address internal wrappedImpl;
    address internal dexImpl;

    // signers
    bytes internal pqKey;
    bytes32 internal pq;            // a registered mldsa44 single key
    bytes[3] internal mkeys;
    bytes internal msigData;
    bytes32 internal msig;          // {mldsa44 x3} t=2, every slot accepted
    mapping(bytes32 => uint256) internal pkOf; // native ids: the ECDSA key (a wallet's: its owner's)
    bytes32 internal eoa;
    bytes32 internal next;
    bytes32 internal stranger;
    bytes32 internal wallet;        // a native id with code (ERC-1271): holds the contract-only RATE_ADJUSTABLE

    /// The test is the factory of every clone: it registered no token, so a leg is outside and a market is `KIND_OUTSIDE`.
    function isRegisteredToken(address) external pure returns (bool) { return false; }
    function isToken(address) external pure returns (bool) { return false; }

    function setUp() public override {
        super.setUp();
        preg = _deploy(PREG, chainUidA, address(0), false, BUDGET, address(0), true, _mockPqCfg());
        router = new GovernanceRouter(chainUidA, PREG, address(0), false);
        pqKey = _ml(1);
        pq = _register(preg, ML44, pqKey);
        Member[] memory m = new Member[](3);
        for (uint256 i; i < 3; ++i) {
            mkeys[i] = _ml(10 + i);
            m[i] = Member(ML44, _register(preg, ML44, mkeys[i]), 1);
        }
        msigData = _msigKey(2, m);
        bytes32 id = UAKinds.uaOf(UAKinds.MSIG, msigData);
        msig = UACall.register(preg, UAKinds.MSIG, msigData, _none(),
            abi.encode(_memberSigs(id, UAKinds.PURPOSE_POP_V2, _regDigest(id, UAKinds.MSIG), 2)), "");
        for (uint256 i; i < 3; ++i) preg.acceptMembership(msig, _acceptKeySig(msigData, ML44, mkeys[i]));
        eoa = _native("issuer");
        next = _native("next");
        stranger = _native("stranger");
        (address wo, uint256 wpk) = makeAddrAndKey("wallet owner");
        wallet = _pad(address(new MockWallet(wo, 0, 0, PREG)));
        pkOf[wallet] = wpk;
        _rows();
        vm.warp(1_800_000_000);
    }

    function _mockPqCfg() internal view returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(ML44, address(mock), CAP);
    }

    function _native(string memory name) internal returns (bytes32 id) {
        (address a, uint256 k) = makeAddrAndKey(name);
        id = _pad(a);
        pkOf[id] = k;
    }

    /// An mldsa44 public key of the right length (the stand-in verifier reads no structure).
    function _ml(uint256 salt) internal pure returns (bytes memory pk) {
        pk = new bytes(1312);
        for (uint256 i; i < 1312; i += 32) {
            bytes32 w = keccak256(abi.encode(ML44, salt, i));
            for (uint256 j; j < 32 && i + j < 1312; ++j) pk[i + j] = w[j];
        }
    }

    function _rows() internal {
        rows[GRANT_ROLE] = Row("GrantRole", ",uint8 bit,bytes32 account", router.mtxGrantRole.selector, router.uaGrantRole.selector);
        rows[REVOKE_ROLE] = Row("RevokeRole", ",uint8 bit,bytes32 account", router.mtxRevokeRole.selector, router.uaRevokeRole.selector);
        rows[SET_GRANT] = Row("SetGrant", ",uint8 bit,bytes32 holder,GrantTerms terms", router.mtxSetGrant.selector, router.uaSetGrant.selector);
        rows[CANCEL_GRANT] = Row("CancelGrant", ",uint8 bit,bytes32 account", router.mtxCancelGrant.selector, router.uaCancelGrant.selector);
        rows[DISABLE_FEATURE] = Row("DisableFeature", ",uint8 bit", router.mtxDisableFeature.selector, router.uaDisableFeature.selector);
        rows[TRANSFER_OWNERSHIP] =
            Row("TransferOwnership", ",bytes32 newOwner", router.mtxTransferOwnership.selector, router.uaTransferOwnership.selector);
        rows[ACCEPT_OWNERSHIP] = Row("AcceptOwnership", "", router.mtxAcceptOwnership.selector, router.uaAcceptOwnership.selector);
        rows[RENOUNCE_OWNERSHIP] = Row("RenounceOwnership", "", router.mtxRenounceOwnership.selector, router.uaRenounceOwnership.selector);
        rows[RENOUNCE_ROLE] = Row("RenounceRole", ",uint8 bit", router.mtxRenounceRole.selector, router.uaRenounceRole.selector);
        rows[OP_MINT] = Row("Mint", ",address to,uint256 amount", router.mtxMint.selector, router.uaMint.selector);
        rows[MINT_TO_UA] = Row("MintToUA", ",bytes32 to,uint256 amount", router.mtxMintToUA.selector, router.uaMintToUA.selector);
        rows[DISABLE_WRAP] = Row("DisableWrap", ",address leg,bytes32 reason", router.mtxDisableWrap.selector, router.uaDisableWrap.selector);
        rows[PROPOSE_RATE] =
            Row("ProposeRate", ",address leg,uint96 num,uint96 den", router.mtxProposeRate.selector, router.uaProposeRate.selector);
        rows[CANCEL_RATE] = Row("CancelRate", "", router.mtxCancelRate.selector, router.uaCancelRate.selector);
        rows[EXECUTE_RATE] = Row("ExecuteRate", "", router.mtxExecuteRate.selector, router.uaExecuteRate.selector);
        rows[SET_MARKET] =
            Row("SetMarket", ",address base,address quote,bool listed", router.mtxSetMarket.selector, router.uaSetMarket.selector);
        rows[SET_EXCHANGE_TARGET] = Row("SetExchangeTarget", ",address exchangeTarget,bool listed",
            router.mtxSetExchangeTarget.selector, router.uaSetExchangeTarget.selector);
        rows[SET_LISTED_ONLY] = Row("SetListedOnly", ",bool on", router.mtxSetListedOnly.selector, router.uaSetListedOnly.selector);
        rows[SET_FEE_SPLIT] =
            Row("SetFeeSplit", ",uint32 relayerSharePpm,address treasury", router.mtxSetFeeSplit.selector, router.uaSetFeeSplit.selector);
    }

    // ------------------------------------------------------------------ governed contracts

    function _env() internal view returns (IFactoryToken.Env memory e) {
        e = plainEnv(address(this), address(0), chainUidA, PREG, false);
        e.govRouter = address(router);
    }

    function _normal(bytes32 owner_, bytes32 minter, uint64 delay) internal returns (NormalToken t) {
        if (normalImpl == address(0)) normalImpl = address(new NormalToken(1, _env(), ""));
        t = NormalToken(Clones.clone(normalImpl));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features, c.owner, c.grantDelay) =
            ("G", "G", 6, 1 | (uint256(1) << MINT), owner_, delay);
        c.roles.minter = minter;
        t.initialize(address(this), 1, abi.encode(c));
    }

    function _wrapped(bytes32 owner_, bytes32 guardian, bytes32 rateAdmin) internal returns (WrappedToken w) {
        if (wrappedImpl == address(0)) wrappedImpl = address(new WrappedToken(1, _env(), ""));
        w = WrappedToken(payable(Clones.clone(wrappedImpl)));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features, c.owner) =
            ("W", "W", 6, 1 | (uint256(1) << RATE) | (uint256(1) << WRAPOFF), owner_);
        (c.roles.guardian, c.roles.rateAdmin) = (guardian, rateAdmin);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
        w.initialize(address(this), 1, abi.encode(c));
    }

    function _dex(bytes32 owner_) internal returns (SCaaSDex d) {
        if (dexImpl == address(0)) dexImpl = address(new SCaaSDex(1, _env(), ""));
        d = SCaaSDex(Clones.clone(dexImpl));
        d.initialize(address(this), 1, abi.encode(ISCaaSDex.DexConfig(owner_, 0, TREASURY, false, 0, address(0))));
    }

    function _limited(uint128 total) internal pure returns (IGovernance.GrantTerms memory g) {
        g.max = type(uint128).max;
        g.total = total;
    }

    // ------------------------------------------------------------------ signing

    function _domain(GovernanceRouter r) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) = r.eip712Domain();
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying, salt));
    }

    function _typehash(uint256 op, bool ua) internal view returns (bytes32) {
        string memory s = string.concat(ua ? "UA" : "", rows[op].name, ua ? "(bytes32 from" : "(address from",
            ",address target", rows[op].params, TAIL);
        if (op == SET_GRANT) s = string.concat(s, TERMS);
        return keccak256(bytes(s));
    }

    function _envelope(GovernanceRouter r, bytes32 from, uint256 batch) internal view returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(from, batch, r.uaNonce(from, batch), block.timestamp + 1 hours, 0, address(0), 0, address(0));
    }

    /// The digest `from` signs: the struct `<Op>` / `UA<Op>` over `target` and `words` (the op's own words) in `r`'s domain.
    function _digest(GovernanceRouter r, uint256 op, bool ua, MetaTxLib.UAEnvelope memory e, address target,
        bytes memory words) internal view returns (bytes32)
    {
        bytes32 h = keccak256(bytes.concat(abi.encode(_typehash(op, ua), e.from, target), words,
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        return keccak256(abi.encodePacked("\x19\x01", _domain(r), h));
    }

    function _ecdsa(bytes32 id, bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 a, bytes32 b) = vm.sign(pkOf[id], digest);
        return abi.encodePacked(a, b, v);
    }

    /// Members 0..n-1 of the `msig` (index order), each over `(purpose, digest)` under `member`.
    function _memberSigs(bytes32 ua, bytes32 purpose, bytes32 digest, uint256 n)
        internal view returns (IUARegistry.MemberSig[] memory s)
    {
        s = new IUARegistry.MemberSig[](n);
        for (uint16 i; i < n; ++i) s[i] = _slot(ua, purpose, digest, i);
    }

    function _auth(bytes32 id, bytes32 digest) internal view returns (IUARegistry.UASig memory a) {
        if (id == pq) a.signature = _sig(pqKey, UAKinds.uaMessage(ML44, UAKinds.PURPOSE_METATX, digest));
        else if (id == msig) a.members = _memberSigs(msig, UAKinds.PURPOSE_METATX, digest, 2);
        else a.signature = _ecdsa(id, digest);
    }

    /// The calldata of `mtx<Op>` / `ua<Op>`: the envelope, `target`, the op's ABI words `args`, then the signature.
    function _calldata(uint256 op, bool ua, MetaTxLib.UAEnvelope memory e, address target, bytes memory args,
        bytes memory sigTail) internal view returns (bytes memory)
    {
        bytes memory head = bytes.concat(abi.encode(e), abi.encode(target), args);
        return bytes.concat(ua ? rows[op].ua : rows[op].mtx, head, abi.encode(head.length + 32), sigTail);
    }

    /// `abi.encode(x)` of one dynamic value without its leading offset word.
    function _tail(bytes memory enc) internal pure returns (bytes memory t) {
        t = new bytes(enc.length - 32);
        for (uint256 i; i < t.length; ++i) t[i] = enc[i + 32];
    }

    /// The signed call of `op` by `from` on `r`: `args` the call's ABI words, `words` the struct's (equal but for `SetGrant`).
    function _signed(GovernanceRouter r, uint256 op, bool ua, bytes32 from, uint256 batch, address target, bytes memory args,
        bytes memory words) internal view returns (bytes memory)
    {
        return _signedAt(r, op, ua, _envelope(r, from, batch), target, args, words);
    }

    /// `_signed` over a given envelope.
    function _signedAt(GovernanceRouter r, uint256 op, bool ua, MetaTxLib.UAEnvelope memory e, address target,
        bytes memory args, bytes memory words) internal view returns (bytes memory)
    {
        bytes32 d = _digest(r, op, ua, e, target, words);
        return _calldata(op, ua, e, target, args, ua ? _tail(abi.encode(_auth(e.from, d))) : _tail(abi.encode(_ecdsa(e.from, d))));
    }

    function _op(uint256 op, bool ua, bytes32 from, address target, bytes memory args) internal view returns (bytes memory) {
        return _signed(router, op, ua, from, 0, target, args, args);
    }

    function _setGrantArgs(uint8 bit, bytes32 holder, IGovernance.GrantTerms memory t)
        internal pure returns (bytes memory args, bytes memory words)
    {
        args = abi.encode(bit, holder, t);
        bytes32 th = keccak256(bytes(TERMS));
        words = abi.encode(bit, holder, keccak256(abi.encode(th, t)));
    }

    function _run(bytes memory cd) internal {
        _runOn(router, cd);
    }

    function _runOn(GovernanceRouter r, bytes memory cd) internal {
        (bool ok, bytes memory ret) = address(r).call(cd);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    function _do(uint256 op, bool ua, bytes32 from, address target, bytes memory args) internal {
        _run(_op(op, ua, from, target, args));
    }

    // ------------------------------------------------------------------ every op, both forms

    /// The 19 ops of the closed table, in an order where each one's effect is read on a real token, wrapped token and DEX.
    /// `s` owns all three and is the guardian; `w` (a native id with code) is the rate admin; `y` takes the token over.
    function _everyOp(bool ua, bytes32 s, bytes32 y, bytes32 w) internal {
        NormalToken t = _normal(s, s, 1 hours);
        _tokenOps(ua, s, y, t);
        _wrappedOps(ua, s, w, _wrapped(s, s, w));
        _dexOps(ua, s, address(t), _dex(s));
    }

    function _tokenOps(bool ua, bytes32 s, bytes32 y, NormalToken t) internal {
        _do(OP_MINT, ua, s, address(t), abi.encode(BOB, uint256(5)));
        assertEq(t.balanceOf(BOB), 5, "Mint");
        _do(MINT_TO_UA, ua, s, address(t), abi.encode(pq, uint256(3)));
        assertEq(t.balanceOfUA(pq), 3, "MintToUA");
        (bytes memory a, bytes memory wd) = _setGrantArgs(MINT, s, _limited(100));
        _run(_signed(router, SET_GRANT, ua, s, 0, address(t), a, wd));
        assertEq(t.grantOf(MINT, s).total, 100, "SetGrant: a narrowing applies at once");
        _do(GRANT_ROLE, ua, s, address(t), abi.encode(MINT, y));
        (uint64 eta,,, bool live) = t.pendingGrant(MINT, y);
        assertTrue(eta != 0 && live, "GrantRole: proposed under the delay");
        _do(CANCEL_GRANT, ua, s, address(t), abi.encode(MINT, y));
        (eta,,,) = t.pendingGrant(MINT, y);
        assertEq(eta, 0, "CancelGrant");
        _do(REVOKE_ROLE, ua, s, address(t), abi.encode(MINT, y));
        assertTrue(t.grantOf(MINT, y).barred, "RevokeRole: the owner's revoke bars");
        _do(RENOUNCE_ROLE, ua, s, address(t), abi.encode(MINT));
        assertFalse(t.hasRole(MINT, s), "RenounceRole");
        _do(DISABLE_FEATURE, ua, s, address(t), abi.encode(MINT));
        assertEq(t.features() & (uint256(1) << MINT), 0, "DisableFeature");
        _do(TRANSFER_OWNERSHIP, ua, s, address(t), abi.encode(y));
        assertEq(t.pendingOwner(), y, "TransferOwnership");
        _do(ACCEPT_OWNERSHIP, ua, y, address(t), "");
        assertEq(t.owner(), y, "AcceptOwnership");
        _do(RENOUNCE_OWNERSHIP, ua, y, address(t), "");
        assertEq(t.owner(), bytes32(0), "RenounceOwnership");
    }

    function _wrappedOps(bool ua, bytes32 s, bytes32 w, WrappedToken wt) internal {
        _do(PROPOSE_RATE, ua, w, address(wt), abi.encode(address(usd), uint96(101), uint96(100)));
        (, uint96 num,, uint64 reta) = wt.pendingRate();
        assertTrue(num == 101 && reta != 0, "ProposeRate");
        _do(CANCEL_RATE, ua, w, address(wt), "");
        (,,, reta) = wt.pendingRate();
        assertEq(reta, 0, "CancelRate");
        _do(PROPOSE_RATE, ua, w, address(wt), abi.encode(address(usd), uint96(101), uint96(100)));
        vm.warp(block.timestamp + 2 days);
        _do(EXECUTE_RATE, ua, w, address(wt), "");
        (num,,,,) = wt.legOf(address(usd));
        assertEq(num, 101, "ExecuteRate");
        _do(DISABLE_WRAP, ua, s, address(wt), abi.encode(address(usd), bytes32("r")));
        (,,,, bool on) = wt.legOf(address(usd));
        assertFalse(on, "DisableWrap");
    }

    function _dexOps(bool ua, bytes32 s, address quote, SCaaSDex d) internal {
        _do(SET_MARKET, ua, s, address(d), abi.encode(address(usd), quote, true));
        assertTrue(d.marketListed(address(usd), quote), "SetMarket");
        _do(SET_EXCHANGE_TARGET, ua, s, address(d), abi.encode(address(0xE7), true));
        assertTrue(d.exchangeTarget(address(0xE7)), "SetExchangeTarget");
        _do(SET_LISTED_ONLY, ua, s, address(d), abi.encode(true));
        assertTrue(d.listedOnly(), "SetListedOnly");
        _do(SET_FEE_SPLIT, ua, s, address(d), abi.encode(uint32(500_000), TREASURY));
        assertEq(d.relayerSharePpm(), 500_000, "SetFeeSplit");
    }

    /// `mtx<Op>`: native addresses sign (an EOA owner, an EOA taking over, a contract wallet by ERC-1271).
    function test_eachOpByMtx() public {
        _everyOp(false, eoa, next, wallet);
    }

    /// `ua<Op>`: a PQ single key owns, a PQ `msig` takes over, the contract wallet signs as its native kind.
    function test_eachOpByUa() public {
        _everyOp(true, pq, msig, wallet);
    }

    /// A PQ `msig` becomes owner of a token and of the DEX, grants a PQ single key, which mints; the `msig` hands both over
    /// to it, and the new owner takes `LISTING` and removes the old owner's (B-13: powers do not move with ownership).
    function test_pqMsigOwnsGrantsMintsAndHandsOver() public {
        (address creator, uint256 ck) = makeAddrAndKey("creator");
        pkOf[_pad(creator)] = ck;
        NormalToken t = _normal(_pad(creator), 0, 0);
        SCaaSDex d = _dex(msig);
        vm.prank(creator);
        t.transferOwnership(msig);
        _do(ACCEPT_OWNERSHIP, true, msig, address(t), "");
        assertEq(t.owner(), msig, "the msig became owner through the router");
        _do(GRANT_ROLE, true, msig, address(t), abi.encode(MINT, pq));
        _do(OP_MINT, true, pq, address(t), abi.encode(BOB, uint256(9)));
        assertEq(t.balanceOf(BOB), 9);
        _do(TRANSFER_OWNERSHIP, true, msig, address(t), abi.encode(pq));
        _do(ACCEPT_OWNERSHIP, true, pq, address(t), "");
        assertEq(t.owner(), pq);

        _do(SET_MARKET, true, msig, address(d), abi.encode(address(usd), address(t), true));
        _do(TRANSFER_OWNERSHIP, true, msig, address(d), abi.encode(pq));
        _do(ACCEPT_OWNERSHIP, true, pq, address(d), "");
        assertEq(d.owner(), pq);
        _do(GRANT_ROLE, true, pq, address(d), abi.encode(LISTING, pq));
        _do(REVOKE_ROLE, true, pq, address(d), abi.encode(LISTING, msig));
        bytes memory cd = _op(SET_LISTED_ONLY, true, msig, address(d), abi.encode(true));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, LISTING, msig));
        _run(cd);
        _do(SET_LISTED_ONLY, true, pq, address(d), abi.encode(true));
        assertTrue(d.listedOnly());
    }

    /// `terms` round-trips: the nested struct's hash is the signed word, the whole struct reaches `setGrant`.
    function test_nestedTermsRoundTrip() public {
        NormalToken t = _normal(pq, 0, 0);
        IGovernance.GrantTerms memory g = IGovernance.GrantTerms(2, 50, 1000, 100, 1 days, uint64(block.timestamp + 30 days),
            7, true, bytes32(0));
        (bytes memory a, bytes memory w) = _setGrantArgs(MINT, msig, g);
        _run(_signed(router, SET_GRANT, true, pq, 0, address(t), a, w));
        IGovernance.Grant memory r = t.grantOf(MINT, msig);
        assertEq(abi.encode(r.min, r.max, r.total, r.perWindow, r.window, r.validUntil, r.maxUses, r.delegable, r.scope),
            abi.encode(g.min, g.max, g.total, g.perWindow, g.window, g.validUntil, g.maxUses, g.delegable, g.scope));
        // the terms are signed: other terms under a signature over these are refused
        g.total = 1001;
        (bytes memory a2,) = _setGrantArgs(MINT, msig, g);
        bytes memory forged = _signed(router, SET_GRANT, true, pq, 0, address(t), a2, w);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _run(forged);
    }

    // ------------------------------------------------------------------ the failure table (spec §3.5 as adapted)

    /// A subject without the power: the target refuses with its own error, the whole call reverts, the nonce is unspent.
    function test_wrongSubjectRefusedNonceUnspent() public {
        NormalToken t = _normal(pq, pq, 0);
        bytes memory cd = _op(OP_MINT, true, msig, address(t), abi.encode(BOB, uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, msig));
        _run(cd);
        cd = _op(GRANT_ROLE, false, stranger, address(t), abi.encode(MINT, stranger));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, stranger));
        _run(cd);
        assertEq(router.uaNonce(msig, 0), 0);
        assertEq(router.uaNonce(stranger, 0), 0);
        _do(OP_MINT, true, pq, address(t), abi.encode(BOB, uint256(1))); // positive control
        assertEq(router.uaNonce(pq, 0), 1);
    }

    /// Another signer's signature: refused before anything runs, on both forms.
    function test_wrongSignerRefused() public {
        NormalToken t = _normal(eoa, eoa, 0);
        MetaTxLib.UAEnvelope memory e = _envelope(router, eoa, 0);
        bytes memory args = abi.encode(BOB, uint256(1));
        bytes32 d = _digest(router, OP_MINT, false, e, address(t), args);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(_calldata(OP_MINT, false, e, address(t), args, _tail(abi.encode(_ecdsa(stranger, d)))));
        e = _envelope(router, pq, 0);
        d = _digest(router, OP_MINT, true, e, address(t), args);
        IUARegistry.UASig memory a;
        a.signature = _sig(mkeys[0], UAKinds.uaMessage(ML44, UAKinds.PURPOSE_METATX, d)); // another key's
        bytes memory cd = _calldata(OP_MINT, true, e, address(t), args, _tail(abi.encode(a)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _run(cd);
    }

    /// A relayer that starves the PQ verify gets `UAVerifyGas`, no verdict, and the nonce stays unspent.
    function test_starvedRelayerUAVerifyGasNonceUnspent() public {
        NormalToken t = _normal(pq, pq, 0);
        bytes memory cd = _op(OP_MINT, true, pq, address(t), abi.encode(BOB, uint256(1)));
        (bool ok, bytes memory ret) = address(router).call{gas: 3_000_000}(cd);
        assertFalse(ok);
        assertEq(bytes4(ret), UAKinds.UAVerifyGas.selector);
        assertEq(router.uaNonce(pq, 0), 0);
        _run(cd); // the same envelope with gas
        assertEq(t.balanceOf(BOB), 1);
    }

    /// An `msig` below its threshold authorizes nothing; nor does one whose members have not accepted (CTR-UA-37).
    function test_msigBelowThresholdRefused() public {
        NormalToken t = _normal(msig, 0, 0);
        MetaTxLib.UAEnvelope memory e = _envelope(router, msig, 0);
        bytes memory args = abi.encode(MINT, pq);
        bytes32 d = _digest(router, GRANT_ROLE, true, e, address(t), args);
        IUARegistry.UASig memory a;
        a.members = _memberSigs(msig, UAKinds.PURPOSE_METATX, d, 1);
        bytes memory cd = _calldata(GRANT_ROLE, true, e, address(t), args, _tail(abi.encode(a)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, msig));
        _run(cd);
        assertEq(router.uaNonce(msig, 0), 0);
        _do(GRANT_ROLE, true, msig, address(t), args); // positive control: 2 of 3
        assertTrue(t.hasRole(MINT, pq));
    }

    function test_msigSlotNotAcceptedIsInert() public {
        Member[] memory m = new Member[](3);
        for (uint256 i; i < 3; ++i) m[i] = Member(ML44, UAKinds.uaOf(ML44, mkeys[i]), 2);
        bytes memory saved = msigData;
        msigData = _msigKey(2, m); // the same keys at weight 2: another msig, one slot reaches the threshold
        bytes32 id = UAKinds.uaOf(UAKinds.MSIG, msigData);
        IUARegistry.MemberSig[] memory pop = new IUARegistry.MemberSig[](1);
        pop[0] = _slot(id, UAKinds.PURPOSE_POP_V2, _regDigest(id, UAKinds.MSIG), 0); // slot 0 signs the pop: accepted
        bytes32 m2 = UACall.register(preg, UAKinds.MSIG, msigData, _none(), abi.encode(pop), "");
        NormalToken t = _normal(m2, 0, 0);
        MetaTxLib.UAEnvelope memory e = _envelope(router, m2, 0);
        bytes memory args = abi.encode(MINT, pq);
        bytes32 dg = _digest(router, GRANT_ROLE, true, e, address(t), args);
        IUARegistry.UASig memory a;
        a.members = new IUARegistry.MemberSig[](1);
        a.members[0] = _slot(m2, UAKinds.PURPOSE_METATX, dg, 1); // slot 1 never accepted
        bytes memory cd = _calldata(GRANT_ROLE, true, e, address(t), args, _tail(abi.encode(a)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, m2));
        _run(cd);
        a.members[0] = _slot(m2, UAKinds.PURPOSE_METATX, dg, 0); // positive control: the accepted slot
        msigData = saved;
        _run(_calldata(GRANT_ROLE, true, e, address(t), args, _tail(abi.encode(a))));
        assertTrue(t.hasRole(MINT, pq));
    }

    /// Slot `idx` of `msigData` signs `(purpose, digest)` for the `msig` `ua`.
    function _slot(bytes32 ua, bytes32 purpose, bytes32 digest, uint16 idx)
        internal view returns (IUARegistry.MemberSig memory)
    {
        bytes32 md = _memberDigest(ua, purpose, digest);
        for (uint256 j; j < 3; ++j) {
            if (_indexOf(msigData, UAKinds.uaOf(ML44, mkeys[j])) != idx) continue;
            return IUARegistry.MemberSig(idx, new IUARegistry.InnerSig[](0),
                _sig(mkeys[j], UAKinds.uaMessage(ML44, UAKinds.PURPOSE_MEMBER, md)));
        }
        revert("slot");
    }

    /// R-04 on the real router: the target re-enters the router while the router calls it: `Reentrancy`, through a signed entry and `cancelNonce`.
    function test_refuted_targetReentersTheRouter() public {
        ProbeTarget p = new ProbeTarget(router);
        NormalToken t = _normal(pq, pq, 0);
        p.arm(_signed(router, OP_MINT, true, pq, 1, address(t), abi.encode(BOB, uint256(1)), abi.encode(BOB, uint256(1))));
        _do(SET_LISTED_ONLY, true, pq, address(p), abi.encode(true));
        assertEq(bytes4(p.failure()), IMetaTx.Reentrancy.selector);
        assertEq(t.balanceOf(BOB), 0);
        p.arm(abi.encodeCall(IMetaTx.cancelNonce, (0)));
        _do(SET_LISTED_ONLY, true, pq, address(p), abi.encode(true));
        assertEq(bytes4(p.failure()), IMetaTx.Reentrancy.selector);
    }

    /// R-03 on the router: no operator and no rotation exist; who controls a power is the target's rule, read at run time.
    /// An envelope the owner signed before it handed the token over is refused by the token once the hand-over completes.
    function test_refuted_formerOwnersEnvelope() public {
        NormalToken t = _normal(eoa, 0, 0);
        bytes memory late = _signed(router, GRANT_ROLE, false, eoa, 1, address(t), abi.encode(MINT, stranger),
            abi.encode(MINT, stranger));
        _do(TRANSFER_OWNERSHIP, false, eoa, address(t), abi.encode(next));
        _do(ACCEPT_OWNERSHIP, false, next, address(t), "");
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, eoa));
        _run(late);
        assertEq(router.uaNonce(eoa, 1), 0, "the nonce stays unspent: the target's refusal reverts the call");
    }

    /// A target without code: refused by name, nonce unspent (a call to it would succeed and do nothing).
    function test_targetWithoutCodeRefused() public {
        bytes memory cd = _op(SET_LISTED_ONLY, true, pq, address(0xC0DE), abi.encode(true));
        vm.expectRevert(abi.encodeWithSelector(GovernanceRouterBase.TargetHasNoCode.selector, address(0xC0DE)));
        _run(cd);
        assertEq(router.uaNonce(pq, 0), 0);
    }

    /// R-02 on the real router: `target` is a signed word, a relayer cannot move a signed op to another token.
    function test_refuted_relayerAltersTheTarget() public {
        NormalToken a = _normal(pq, pq, 0);
        NormalToken b = _normal(pq, pq, 0);
        bytes memory args = abi.encode(BOB, uint256(1));
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq, 0);
        bytes32 d = _digest(router, OP_MINT, true, e, address(a), args);
        bytes memory tail = _tail(abi.encode(_auth(pq, d)));
        bytes memory cd = _calldata(OP_MINT, true, e, address(b), args, tail);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _run(cd);
        e = _envelope(router, eoa, 0);
        d = _digest(router, OP_MINT, false, e, address(a), args);
        cd = _calldata(OP_MINT, false, e, address(b), args, _tail(abi.encode(_ecdsa(eoa, d))));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(cd);
        _run(_calldata(OP_MINT, true, _envelope(router, pq, 0), address(a), args, tail)); // positive control
        assertEq(a.balanceOf(BOB), 1);
    }

    /// R-02 on the real router: the same signature on a second router (another chain's `chain_uid`, or the same chain's second deployment) and on
    /// another chain id: `verifyingContract`, `chain_uid` and `chainId` are in the domain.
    function test_refuted_replayAcrossRoutersAndChains() public {
        GovernanceRouter other = new GovernanceRouter(chainUidA, PREG, address(0), false);
        GovernanceRouter otherUid = new GovernanceRouter(keccak256("another chain"), PREG, address(0), false);
        NormalToken t = _normal(pq, pq, 0);
        bytes memory cd = _op(OP_MINT, true, pq, address(t), abi.encode(BOB, uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _runOn(other, cd);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _runOn(otherUid, cd);
        uint256 id = block.chainid;
        vm.chainId(id + 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _run(cd);
        vm.chainId(id);
        _run(cd); // positive control, once
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _run(cd);
    }

    /// A fee mode other than `NONE` is refused: the router holds nothing to pay with (B-30: an `msig` at the bound relays
    /// at fee 0, or another account pays its relayer).
    function test_feeModeIsNone() public {
        NormalToken t = _normal(pq, pq, 0);
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq, 0);
        e.mode = MetaTxLib.MODE_FEE_FIXED;
        e.fee = 1;
        bytes memory args = abi.encode(BOB, uint256(1));
        bytes memory cd = _signedAt(router, OP_MINT, true, e, address(t), args, args);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, e.mode));
        _run(cd);
        assertEq(router.supportedModes(), MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT);
    }

    /// B-14, fixed (the attack round's `test_attack_theHoldersOpIsReachableAsABytesBlob` on the sketch): the generic path is
    /// refused on every entry, whatever the blob calls: `mtxExecute`, `executeMetaTransaction`,
    /// `mtxBatch`, `uaExecute`, `uaBatch`. The base's `cancelNonce` as the blob is refused too.
    function test_fixed_theRoutersOpIsNotReachableAsABytesBlob() public {
        bytes memory data = abi.encodeCall(IMetaTx.cancelNonce, (7));
        (address a, uint256 k) = makeAddrAndKey("blob signer");
        MetaTxLib.MetaTransaction memory m =
            MetaTxLib.MetaTransaction(a, data, 0, 0, block.timestamp + 1 hours, 0, address(0), 0, address(0));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(k, router.mtxDigest(m));
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes4 refused = IMetaTx.cancelNonce.selector;
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, refused));
        router.mtxExecute(m, sig);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, refused));
        router.executeMetaTransaction(m, sig);
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](1);
        bytes[] memory sigs = new bytes[](1);
        (ms[0], sigs[0]) = (m, sig);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, refused));
        router.mtxBatch(ms, sigs);
        assertEq(router.mtxNonce(a, 0), 0);
        _genericUaRefused(data, refused);
    }

    function _genericUaRefused(bytes memory data, bytes4 refused) internal {
        MetaTxLib.UAMetaTransaction memory u =
            MetaTxLib.UAMetaTransaction(pq, data, 0, 0, block.timestamp + 1 hours, 0, address(0), 0, address(0));
        bytes memory auth = abi.encode(bytes(""), _sig(pqKey, UAKinds.uaMessage(ML44, UAKinds.PURPOSE_METATX, router.uaDigest(u))));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, refused));
        router.uaExecute(u, auth);
        MetaTxLib.UAMetaTransaction[] memory us = new MetaTxLib.UAMetaTransaction[](1);
        bytes[] memory auths = new bytes[](1);
        (us[0], auths[0]) = (u, auth);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(0)));
        router.uaBatch(us, auths);
        assertEq(router.uaNonce(pq, 0), 0);
    }

    /// `cancelNonce`, `mtxCancelNonce` and `uaCancelNonce` stay: a cancelled lane kills a pre-signed op.
    function test_cancelNonceStays() public {
        NormalToken t = _normal(pq, pq, 0);
        bytes memory cd = _op(OP_MINT, true, pq, address(t), abi.encode(BOB, uint256(1)));
        uint256 until = block.timestamp + 1 hours;
        bytes32 d = router.uaCancelDigest(pq, 0, until);
        IUARegistry.UASig memory a;
        a.signature = _sig(pqKey, UAKinds.uaMessage(ML44, UAKinds.PURPOSE_METATX_CANCEL, d));
        router.uaCancelNonce(pq, 0, until, a);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _run(cd);
        address n = address(uint160(uint256(eoa)));
        vm.prank(n);
        router.cancelNonce(0);
        assertEq(router.mtxNonce(n, 0), 1);
    }

    // ------------------------------------------------------------------ subject() and the lock

    /// During the call the target reads the signer; a bystander reads 0 at the same moment; outside a call, 0.
    function test_subjectOnlyToTheLiveTarget() public {
        ProbeTarget p = new ProbeTarget(router);
        _do(SET_LISTED_ONLY, true, msig, address(p), abi.encode(true));
        assertEq(p.seen(), msig);
        assertEq(p.seenByOther(), bytes32(0), "a non-target reads 0 during a live call");
        vm.prank(address(p));
        assertEq(router.subject(), bytes32(0), "the target reads 0 outside a call");
        _do(SET_LISTED_ONLY, false, eoa, address(p), abi.encode(true));
        assertEq(p.seen(), eoa, "the mtx form's subject is the native id");
    }

    /// The pair is cleared when the call returns: the target asks again in the same transaction and reads 0.
    function test_subjectClearedInTheSameTransaction() public {
        ProbeTarget p = new ProbeTarget(router);
        bytes memory cd = _op(SET_LISTED_ONLY, true, pq, address(p), abi.encode(true));
        p.relayThenRead(cd);
        assertEq(p.seen(), pq);
        assertEq(p.seenAfter(), bytes32(0));
    }

    /// The router holds nothing: no `receive`, no payable entry.
    function test_noReceive() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(router).call{value: 1}("");
        assertFalse(ok);
        assertEq(address(router).balance, 0);
    }

    /// The domain of spec §3: ("SCaaS GovernanceRouter", "1", chainId, router, chain_uid).
    function test_domain() public view {
        (, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) =
            router.eip712Domain();
        assertEq(name, "SCaaS GovernanceRouter");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(verifying, address(router));
        assertEq(salt, chainUidA);
        assertEq(router.chainUid(), chainUidA);
    }
}
