// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs, dexArgs} from "../../script/KindModules.sol";

import {MtxDigest} from "../helpers/MtxDigest.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceRouterBase} from "../../src/governance/GovernanceRouterBase.sol";
import {IGovernanceRouter} from "../../src/governance/IGovernanceRouter.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
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
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {regArgs} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {Erc7739Kit} from "../helpers/Erc7739Kit.sol";

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
/// signature check is the stand-in's. Every op of the closed table on its one signed entry (ua-mtx-merge T7), native and
/// derived, on a real `NormalToken`, `WrappedToken` and `SCaaSDex` whose `GOV_ROUTER` is the router; every row of the
/// failure table; the lock, the pair, the generic path. The fixture (state, setUp, signing) is shared with `test/merge/RouterPairs.t.sol`.
abstract contract GovRouterFixture is UARegistryBase {
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
    uint256 constant TRANSFER_ADMIN = 5;
    uint256 constant ACCEPT_ADMIN = 6;
    uint256 constant RENOUNCE_ADMIN = 7;
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
        bytes4 sel;
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
    /// fix2-dex: the DEX reads the kind at use (`versionOf`, version 0: not a factory token)
    function versionOf(address) external pure returns (uint8, uint64) {}

    function setUp() public virtual override {
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
        rows[GRANT_ROLE] = Row("GrantRole", ",uint8 bit,bytes32 account,bytes32 chainUid", router.mtxGrantRole.selector);
        rows[REVOKE_ROLE] = Row("RevokeRole", ",uint8 bit,bytes32 account,bytes32 chainUid", router.mtxRevokeRole.selector);
        rows[SET_GRANT] =
            Row("SetGrant", ",uint8 bit,bytes32 holder,GrantTerms terms,bytes32 chainUid", router.mtxSetGrant.selector);
        rows[CANCEL_GRANT] =
            Row("CancelGrant", ",uint8 bit,bytes32 account,bytes32 chainUid", router.mtxCancelGrant.selector);
        rows[DISABLE_FEATURE] = Row("DisableFeature", ",uint8 bit,bytes32 chainUid", router.mtxDisableFeature.selector);
        rows[TRANSFER_ADMIN] =
            Row("TransferAdmin", ",bytes32 newAdmin,bytes32 chainUid", router.mtxTransferAdmin.selector);
        rows[ACCEPT_ADMIN] = Row("AcceptAdmin", "", router.mtxAcceptAdmin.selector);
        rows[RENOUNCE_ADMIN] = Row("RenounceAdmin", ",bytes32 chainUid", router.mtxRenounceAdmin.selector);
        rows[RENOUNCE_ROLE] = Row("RenounceRole", ",uint8 bit,bytes32 chainUid", router.mtxRenounceRole.selector);
        rows[OP_MINT] = Row("Mint", ",address to,uint256 amount", router.mtxMint.selector);
        rows[MINT_TO_UA] = Row("MintToUA", ",bytes32 to,uint256 amount", router.mtxMintToUA.selector);
        rows[DISABLE_WRAP] = Row("DisableWrap", ",address leg,bytes32 reason", router.mtxDisableWrap.selector);
        rows[PROPOSE_RATE] =
            Row("ProposeRate", ",address leg,uint96 num,uint96 den", router.mtxProposeRate.selector);
        rows[CANCEL_RATE] = Row("CancelRate", "", router.mtxCancelRate.selector);
        rows[EXECUTE_RATE] = Row("ExecuteRate", "", router.mtxExecuteRate.selector);
        rows[SET_MARKET] =
            Row("SetMarket", ",address base,address quote,bool listed", router.mtxSetMarket.selector);
        rows[SET_EXCHANGE_TARGET] = Row("SetExchangeTarget", ",address exchangeTarget,bool listed",
            router.mtxSetExchangeTarget.selector);
        rows[SET_LISTED_ONLY] = Row("SetListedOnly", ",bool on", router.mtxSetListedOnly.selector);
        rows[SET_FEE_SPLIT] =
            Row("SetFeeSplit", ",uint32 relayerSharePpm,address treasury", router.mtxSetFeeSplit.selector);
    }

    // ------------------------------------------------------------------ governed contracts

    /// The tokens' `FACTORY` is this fixture: the factory's notice period a regulated kind reads (pay-meta-tax T39, bit 23).
    function noticePeriod() external pure returns (uint64) {
        return 0;
    }

    /// The clones' env (chain-neutral spec §2.1): this chain, the registry, the router.
    function _cenv() internal view returns (IFactoryToken.ChainEnv memory) {
        return EnvKit.env(chainUidA, PREG, address(0), false, address(router));
    }

    function _normal(bytes32 owner_, bytes32 minter, uint64 delay) internal returns (NormalToken t) {
        if (normalImpl == address(0)) normalImpl = address(new NormalToken(address(this), kindArgs(0, address(this), "")));
        t = NormalToken(EnvKit.clone(normalImpl, _cenv()));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features, c.admin, c.grantDelay) =
            ("G", "G", 6, 1 | (uint256(1) << MINT), owner_, delay);
        c.roles.minter = minter;
        t.initialize(nid(address(this)), 1, abi.encode(c));
    }

    function _wrapped(bytes32 owner_, bytes32 guardian, bytes32 rateAdmin) internal returns (WrappedToken w) {
        if (wrappedImpl == address(0)) wrappedImpl = address(new WrappedToken(address(this), kindArgs(1, address(this), "")));
        w = WrappedToken(payable(EnvKit.clone(wrappedImpl, _cenv())));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features, c.admin) =
            ("W", "W", 6, 1 | (uint256(1) << RATE) | (uint256(1) << WRAPOFF), owner_);
        (c.roles.guardian, c.roles.rateAdmin) = (guardian, rateAdmin);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
        w.initialize(nid(address(this)), 1, abi.encode(c));
    }

    function _dex(bytes32 owner_) internal returns (SCaaSDex d) {
        if (dexImpl == address(0)) dexImpl = address(new SCaaSDex(address(this), dexArgs(address(this))));
        d = SCaaSDex(EnvKit.clone(dexImpl, _cenv()));
        d.initialize(nid(address(this)), 1, abi.encode(ISCaaSDex.DexConfig(owner_, 0, TREASURY, false, 0, address(0), 0, 0)));
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

    function _typehash(uint256 op) internal view returns (bytes32) {
        string memory s = string.concat("UA", rows[op].name, "(bytes32 from", ",address target", rows[op].params, TAIL);
        if (op == SET_GRANT) s = string.concat(s, TERMS);
        return keccak256(bytes(s));
    }

    function _envelope(GovernanceRouter r, bytes32 from, uint256 batch) internal view returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(from, batch, r.mtxNonce(from, batch), block.timestamp + 1 hours, 0, address(0), 0, address(0));
    }

    /// The digest `from` signs: the struct `UA<Op>` over `target` and `words` (the op's own words) in `r`'s domain.
    function _digest(GovernanceRouter r, uint256 op, MetaTxLib.UAEnvelope memory e, address target,
        bytes memory words) internal view returns (bytes32)
    {
        bytes32 h = keccak256(bytes.concat(abi.encode(_typehash(op), e.from, target), words,
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

    /// The calldata of `mtx<Op>`: the envelope, `target`, the op's ABI words `args`, then the signature.
    function _calldata(uint256 op, MetaTxLib.UAEnvelope memory e, address target, bytes memory args,
        bytes memory sigTail) internal view returns (bytes memory)
    {
        bytes memory head = bytes.concat(abi.encode(e), abi.encode(target), args);
        return bytes.concat(rows[op].sel, head, abi.encode(head.length + 32), sigTail);
    }

    /// `abi.encode(x)` of one dynamic value without its leading offset word.
    function _tail(bytes memory enc) internal pure returns (bytes memory t) {
        t = new bytes(enc.length - 32);
        for (uint256 i; i < t.length; ++i) t[i] = enc[i + 32];
    }

    /// The signed call of `op` by `from` on `r`: `args` the call's ABI words, `words` the struct's (equal but for `SetGrant`).
    function _signed(GovernanceRouter r, uint256 op, bytes32 from, uint256 batch, address target, bytes memory args,
        bytes memory words) internal view returns (bytes memory)
    {
        return _signedAt(r, op, _envelope(r, from, batch), target, args, words);
    }

    /// `_signed` over a given envelope.
    function _signedAt(GovernanceRouter r, uint256 op, MetaTxLib.UAEnvelope memory e, address target,
        bytes memory args, bytes memory words) internal view returns (bytes memory)
    {
        bytes32 d = _digest(r, op, e, target, words);
        return _calldata(op, e, target, args, _tail(abi.encode(_auth(e.from, d))));
    }

    function _op(uint256 op, bytes32 from, address target, bytes memory args) internal view returns (bytes memory) {
        return _signed(router, op, from, 0, target, args, args);
    }

    /// @dev `u` the target's chain word, the op's last field (CTR-GOV-28).
    function _setGrantArgs(uint8 bit, bytes32 holder, IGovernance.GrantTerms memory t, bytes32 u)
        internal pure returns (bytes memory args, bytes memory words)
    {
        args = abi.encode(bit, holder, t, u);
        bytes32 th = keccak256(bytes(TERMS));
        words = abi.encode(bit, holder, keccak256(abi.encode(th, t)), u);
    }

    function _run(bytes memory cd) internal {
        _runOn(router, cd);
    }

    function _runOn(GovernanceRouter r, bytes memory cd) internal {
        (bool ok, bytes memory ret) = address(r).call(cd);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    function _do(uint256 op, bytes32 from, address target, bytes memory args) internal {
        _run(_op(op, from, target, args));
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
}

contract GovRouterTest is GovRouterFixture {
    // ------------------------------------------------------------------ every op, native and derived

    /// The 19 ops of the closed table, in an order where each one's effect is read on a real token, wrapped token and DEX.
    /// `s` owns all three and is the guardian; `w` (a native id with code) is the rate admin; `y` takes the token over.
    function _everyOp(bytes32 s, bytes32 y, bytes32 w) internal {
        NormalToken t = _normal(s, s, 1 hours);
        _tokenOps(s, y, t);
        _wrappedOps(s, w, _wrapped(s, s, w));
        _dexOps(s, address(t), _dex(s));
    }

    function _tokenOps(bytes32 s, bytes32 y, NormalToken t) internal {
        _do(OP_MINT, s, address(t), abi.encode(BOB, uint256(5)));
        assertEq(t.balanceOf(BOB), 5, "Mint");
        _do(MINT_TO_UA, s, address(t), abi.encode(pq, uint256(3)));
        assertEq(t.balanceOfUA(pq), 3, "MintToUA");
        (bytes memory a, bytes memory wd) = _setGrantArgs(MINT, s, _limited(100), EnvKit.codeUidOf(address(t)));
        _run(_signed(router, SET_GRANT, s, 0, address(t), a, wd));
        assertEq(t.grantOf(MINT, s).total, 100, "SetGrant: a narrowing applies at once");
        _do(GRANT_ROLE, s, address(t), abi.encode(MINT, y, EnvKit.codeUidOf(address(t))));
        (uint64 eta,,, bool live) = t.pendingGrant(MINT, y);
        assertTrue(eta != 0 && live, "GrantRole: proposed under the delay");
        _do(CANCEL_GRANT, s, address(t), abi.encode(MINT, y, EnvKit.codeUidOf(address(t))));
        (eta,,,) = t.pendingGrant(MINT, y);
        assertEq(eta, 0, "CancelGrant");
        _do(REVOKE_ROLE, s, address(t), abi.encode(MINT, y, EnvKit.codeUidOf(address(t))));
        assertTrue(t.grantOf(MINT, y).barred, "RevokeRole: the owner's revoke bars");
        _do(RENOUNCE_ROLE, s, address(t), abi.encode(MINT, EnvKit.codeUidOf(address(t))));
        assertFalse(t.hasRole(MINT, s), "RenounceRole");
        _do(DISABLE_FEATURE, s, address(t), abi.encode(MINT, EnvKit.codeUidOf(address(t))));
        assertEq(t.features() & (uint256(1) << MINT), 0, "DisableFeature");
        _do(TRANSFER_ADMIN, s, address(t), abi.encode(y, EnvKit.codeUidOf(address(t))));
        assertEq(t.pendingAdmin(), y, "TransferAdmin");
        _do(ACCEPT_ADMIN, y, address(t), "");
        assertEq(t.admin(), y, "AcceptAdmin");
        _do(RENOUNCE_ADMIN, y, address(t), abi.encode(EnvKit.codeUidOf(address(t))));
        assertEq(t.admin(), bytes32(0), "RenounceAdmin");
    }

    function _wrappedOps(bytes32 s, bytes32 w, WrappedToken wt) internal {
        _do(PROPOSE_RATE, w, address(wt), abi.encode(address(usd), uint96(101), uint96(100)));
        (, uint96 num,, uint64 reta) = wt.pendingRate();
        assertTrue(num == 101 && reta != 0, "ProposeRate");
        _do(CANCEL_RATE, w, address(wt), "");
        (,,, reta) = wt.pendingRate();
        assertEq(reta, 0, "CancelRate");
        _do(PROPOSE_RATE, w, address(wt), abi.encode(address(usd), uint96(101), uint96(100)));
        vm.warp(block.timestamp + 2 days);
        _do(EXECUTE_RATE, w, address(wt), "");
        (num,,,,) = wt.legOf(address(usd));
        assertEq(num, 101, "ExecuteRate");
        _do(DISABLE_WRAP, s, address(wt), abi.encode(address(usd), bytes32("r")));
        (,,,, bool on) = wt.legOf(address(usd));
        assertFalse(on, "DisableWrap");
    }

    function _dexOps(bytes32 s, address quote, SCaaSDex d) internal {
        _do(SET_MARKET, s, address(d), abi.encode(address(usd), quote, true));
        assertTrue(d.marketListed(address(usd), quote), "SetMarket");
        _do(SET_EXCHANGE_TARGET, s, address(d), abi.encode(address(0xE7), true));
        assertTrue(d.exchangeTarget(address(0xE7)), "SetExchangeTarget");
        _do(SET_LISTED_ONLY, s, address(d), abi.encode(true));
        assertTrue(d.listedOnly(), "SetListedOnly");
        _do(SET_FEE_SPLIT, s, address(d), abi.encode(uint32(500_000), TREASURY));
        assertEq(d.relayerSharePpm(), 500_000, "SetFeeSplit");
    }

    /// recheck2 P2-2 (CTR-ACC-02): real wallets, a `SmartKeyAccount` clone and a `MandateWallet`, sign a router op
    /// (`mtxCancelNonce`, `UACancelNonce`) in ERC-7739 `TypedDataSign`, at the router's 50 k cap; the raw digest is refused.
    function test_erc7739RealWallets_routerOp() public {
        uint256 pk = 0x7739;
        (address ska, address mw) = Erc7739Kit.wallets(pk, chainUidA);
        address[2] memory ws = [ska, mw];
        for (uint256 i; i < 2; ++i) {
            address w = ws[i];
            MetaTxLib.UAEnvelope memory e = _envelope(router, _pad(w), 0);
            bytes32 c = keccak256(abi.encode(MetaTxLib.UA_CANCEL_NONCE_TYPEHASH, e.from, uint256(9), e.batch, e.nonce,
                e.validUntil, e.mode, address(0), e.fee, address(0)));
            bytes32 h = keccak256(abi.encodePacked(hex"1901", Erc7739Kit.separator(address(router)), c));
            IUARegistry.UASig memory a;
            a.signature = Erc7739Kit.raw(pk, w, h);
            vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
            router.mtxCancelNonce(e, 9, a);
            a.signature = Erc7739Kit.sign(pk, w, address(router), "UACancelNonce", Erc7739Kit.UA_CANCEL_NONCE_TYPE,
                Erc7739Kit.UA_CANCEL_NONCE_TYPE, c);
            router.mtxCancelNonce(e, 9, a);
            assertEq(router.mtxNonce(_pad(w), 9), 1, "positive control: the ERC-7739 op ran");
        }
    }

    /// recheck2 P2-2 (CTR-ACC-02): the registry's native contract path (`requireAuthorized`, ERC-1271 over `uaAuthDigest`)
    /// with real wallets: ERC-7739 `TypedDataSign` over `UAAuth` passes, the raw `uaAuthDigest` is refused.
    function test_erc7739RealWallets_registryUAAuth() public {
        uint256 pk = 0x7739;
        (address ska, address mw) = Erc7739Kit.wallets(pk, chainUidA);
        address[2] memory ws = [ska, mw];
        bytes32 dg = keccak256("operation");
        for (uint256 i; i < 2; ++i) {
            bytes32 id = _pad(ws[i]);
            bytes32 h = preg.uaAuthDigest(id, UAKinds.PURPOSE_METATX, dg);
            bytes32 c = keccak256(abi.encode(keccak256(bytes(Erc7739Kit.UA_AUTH_TYPE)), id, UAKinds.PURPOSE_METATX, dg));
            assertEq(keccak256(abi.encodePacked(hex"1901", Erc7739Kit.separator(address(preg)), c)), h, "the kit rebuilds it");
            IUARegistry.UASig memory a;
            a.signature = Erc7739Kit.raw(pk, ws[i], h);
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, id));
            preg.requireAuthorized(id, UAKinds.PURPOSE_METATX, dg, a);
            a.signature = Erc7739Kit.sign(pk, ws[i], address(preg), "UAAuth", Erc7739Kit.UA_AUTH_TYPE, Erc7739Kit.UA_AUTH_TYPE, c);
            preg.requireAuthorized(id, UAKinds.PURPOSE_METATX, dg, a); // positive control: no revert
        }
    }

    /// Native ids on the merged `mtx<Op>` (ua-mtx-merge T7, meaning: was the address `mtx<Op>` form): an EOA owner, an EOA
    /// taking over, a contract wallet by ERC-1271, each over `UA<Op>` with its own key.
    function test_eachOpByNative() public {
        _everyOp(eoa, next, wallet);
    }

    /// Derived ids on the merged `mtx<Op>` (was `ua<Op>`): a PQ single key owns, a PQ `msig` takes over, the contract wallet
    /// signs as its native kind.
    function test_eachOpByDerived() public {
        _everyOp(pq, msig, wallet);
    }

    /// A PQ `msig` becomes owner of a token and of the DEX, grants a PQ single key, which mints; the `msig` hands both over
    /// to it, and the new owner takes `LISTING` and removes the old owner's (B-13: powers do not move with ownership).
    function test_pqMsigOwnsGrantsMintsAndHandsOver() public {
        (address creator, uint256 ck) = makeAddrAndKey("creator");
        pkOf[_pad(creator)] = ck;
        NormalToken t = _normal(_pad(creator), 0, 0);
        SCaaSDex d = _dex(msig);
        vm.prank(creator);
        t.transferAdmin(msig, EnvKit.codeUidOf(address(t)));
        _do(ACCEPT_ADMIN, msig, address(t), "");
        assertEq(t.admin(), msig, "the msig became owner through the router");
        _do(GRANT_ROLE, msig, address(t), abi.encode(MINT, pq, EnvKit.codeUidOf(address(t))));
        _do(OP_MINT, pq, address(t), abi.encode(BOB, uint256(9)));
        assertEq(t.balanceOf(BOB), 9);
        _do(TRANSFER_ADMIN, msig, address(t), abi.encode(pq, EnvKit.codeUidOf(address(t))));
        _do(ACCEPT_ADMIN, pq, address(t), "");
        assertEq(t.admin(), pq);

        _do(SET_MARKET, msig, address(d), abi.encode(address(usd), address(t), true));
        _do(TRANSFER_ADMIN, msig, address(d), abi.encode(pq, EnvKit.codeUidOf(address(d))));
        _do(ACCEPT_ADMIN, pq, address(d), "");
        assertEq(d.admin(), pq);
        _do(GRANT_ROLE, pq, address(d), abi.encode(LISTING, pq, EnvKit.codeUidOf(address(d))));
        _do(REVOKE_ROLE, pq, address(d), abi.encode(LISTING, msig, EnvKit.codeUidOf(address(d))));
        bytes memory cd = _op(SET_LISTED_ONLY, msig, address(d), abi.encode(true));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, LISTING, msig));
        _run(cd);
        _do(SET_LISTED_ONLY, pq, address(d), abi.encode(true));
        assertTrue(d.listedOnly());
    }

    /// `terms` round-trips: the nested struct's hash is the signed word, the whole struct reaches `setGrant`.
    function test_nestedTermsRoundTrip() public {
        NormalToken t = _normal(pq, 0, 0);
        IGovernance.GrantTerms memory g = IGovernance.GrantTerms(2, 50, 1000, 100, 1 days, uint64(block.timestamp + 30 days),
            7, true, bytes32(0));
        (bytes memory a, bytes memory w) = _setGrantArgs(MINT, msig, g, EnvKit.codeUidOf(address(t)));
        _run(_signed(router, SET_GRANT, pq, 0, address(t), a, w));
        IGovernance.Grant memory r = t.grantOf(MINT, msig);
        assertEq(abi.encode(r.min, r.max, r.total, r.perWindow, r.window, r.validUntil, r.maxUses, r.delegable, r.scope),
            abi.encode(g.min, g.max, g.total, g.perWindow, g.window, g.validUntil, g.maxUses, g.delegable, g.scope));
        // the terms are signed: other terms under a signature over these are refused
        g.total = 1001;
        (bytes memory a2,) = _setGrantArgs(MINT, msig, g, EnvKit.codeUidOf(address(t)));
        bytes memory forged = _signed(router, SET_GRANT, pq, 0, address(t), a2, w);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _run(forged);
    }

    // ------------------------------------------------------------------ the failure table (spec §3.5 as adapted)

    /// A subject without the power: the target refuses with its own error, the whole call reverts, the nonce is unspent.
    function test_wrongSubjectRefusedNonceUnspent() public {
        NormalToken t = _normal(pq, pq, 0);
        bytes memory cd = _op(OP_MINT, msig, address(t), abi.encode(BOB, uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, msig));
        _run(cd);
        cd = _op(GRANT_ROLE, stranger, address(t), abi.encode(MINT, stranger, EnvKit.codeUidOf(address(t))));
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, stranger));
        _run(cd);
        assertEq(router.mtxNonce(msig, 0), 0);
        assertEq(router.mtxNonce(stranger, 0), 0);
        _do(OP_MINT, pq, address(t), abi.encode(BOB, uint256(1))); // positive control
        assertEq(router.mtxNonce(pq, 0), 1);
    }

    /// Another signer's signature: refused before anything runs, for a native and a derived signer.
    function test_wrongSignerRefused() public {
        NormalToken t = _normal(eoa, eoa, 0);
        MetaTxLib.UAEnvelope memory e = _envelope(router, eoa, 0);
        bytes memory args = abi.encode(BOB, uint256(1));
        bytes32 d = _digest(router, OP_MINT, e, address(t), args);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(_calldata(OP_MINT, e, address(t), args, _tail(abi.encode(_auth(stranger, d)))));
        e = _envelope(router, pq, 0);
        d = _digest(router, OP_MINT, e, address(t), args);
        IUARegistry.UASig memory a;
        a.signature = _sig(mkeys[0], UAKinds.uaMessage(ML44, UAKinds.PURPOSE_METATX, d)); // another key's
        bytes memory cd = _calldata(OP_MINT, e, address(t), args, _tail(abi.encode(a)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _run(cd);
    }

    /// A relayer that starves the PQ verify gets `UAVerifyGas`, no verdict, and the nonce stays unspent.
    function test_starvedRelayerUAVerifyGasNonceUnspent() public {
        NormalToken t = _normal(pq, pq, 0);
        bytes memory cd = _op(OP_MINT, pq, address(t), abi.encode(BOB, uint256(1)));
        (bool ok, bytes memory ret) = address(router).call{gas: 3_000_000}(cd);
        assertFalse(ok);
        assertEq(bytes4(ret), UAKinds.UAVerifyGas.selector);
        assertEq(router.mtxNonce(pq, 0), 0);
        _run(cd); // the same envelope with gas
        assertEq(t.balanceOf(BOB), 1);
    }

    /// An `msig` below its threshold authorizes nothing; nor does one whose members have not accepted (CTR-UA-37).
    function test_msigBelowThresholdRefused() public {
        NormalToken t = _normal(msig, 0, 0);
        MetaTxLib.UAEnvelope memory e = _envelope(router, msig, 0);
        bytes memory args = abi.encode(MINT, pq, EnvKit.codeUidOf(address(t)));
        bytes32 d = _digest(router, GRANT_ROLE, e, address(t), args);
        IUARegistry.UASig memory a;
        a.members = _memberSigs(msig, UAKinds.PURPOSE_METATX, d, 1);
        bytes memory cd = _calldata(GRANT_ROLE, e, address(t), args, _tail(abi.encode(a)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, msig));
        _run(cd);
        assertEq(router.mtxNonce(msig, 0), 0);
        _do(GRANT_ROLE, msig, address(t), args); // positive control: 2 of 3
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
        bytes memory args = abi.encode(MINT, pq, EnvKit.codeUidOf(address(t)));
        bytes32 dg = _digest(router, GRANT_ROLE, e, address(t), args);
        IUARegistry.UASig memory a;
        a.members = new IUARegistry.MemberSig[](1);
        a.members[0] = _slot(m2, UAKinds.PURPOSE_METATX, dg, 1); // slot 1 never accepted
        bytes memory cd = _calldata(GRANT_ROLE, e, address(t), args, _tail(abi.encode(a)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, m2));
        _run(cd);
        a.members[0] = _slot(m2, UAKinds.PURPOSE_METATX, dg, 0); // positive control: the accepted slot
        msigData = saved;
        _run(_calldata(GRANT_ROLE, e, address(t), args, _tail(abi.encode(a))));
        assertTrue(t.hasRole(MINT, pq));
    }

    /// R-04 on the real router: the target re-enters the router while the router calls it: `Reentrancy`, through a signed entry and `cancelNonce`.
    function test_refuted_targetReentersTheRouter() public {
        ProbeTarget p = new ProbeTarget(router);
        NormalToken t = _normal(pq, pq, 0);
        p.arm(_signed(router, OP_MINT, pq, 1, address(t), abi.encode(BOB, uint256(1)), abi.encode(BOB, uint256(1))));
        _do(SET_LISTED_ONLY, pq, address(p), abi.encode(true));
        assertEq(bytes4(p.failure()), IMetaTx.Reentrancy.selector);
        assertEq(t.balanceOf(BOB), 0);
        p.arm(abi.encodeCall(IMetaTx.cancelNonce, (0)));
        _do(SET_LISTED_ONLY, pq, address(p), abi.encode(true));
        assertEq(bytes4(p.failure()), IMetaTx.Reentrancy.selector);
    }

    /// R-03 on the router: no operator and no rotation exist; who controls a power is the target's rule, read at run time.
    /// An envelope the owner signed before it handed the token over is refused by the token once the hand-over completes.
    function test_refuted_formerOwnersEnvelope() public {
        NormalToken t = _normal(eoa, 0, 0);
        bytes32 tu = EnvKit.codeUidOf(address(t));
        bytes memory late = _signed(router, GRANT_ROLE, eoa, 1, address(t), abi.encode(MINT, stranger, tu),
            abi.encode(MINT, stranger, tu));
        _do(TRANSFER_ADMIN, eoa, address(t), abi.encode(next, EnvKit.codeUidOf(address(t))));
        _do(ACCEPT_ADMIN, next, address(t), "");
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, eoa));
        _run(late);
        assertEq(router.mtxNonce(eoa, 1), 0, "the nonce stays unspent: the target's refusal reverts the call");
    }

    /// Fable recheck-2 P3-1: `mtxRenounceAdmin` signs the target's chain word and forwards it. Signed for a sibling (another
    /// word) the token refuses it by name, nothing written, nonce unspent; the old entry without the word has no entry (empty
    /// revert); the control: the same signer with the token's word renounces.
    function test_renounceAdmin_siblingWordRefused() public {
        NormalToken t = _normal(eoa, 0, 0);
        bytes32 u = EnvKit.codeUidOf(address(t));
        bytes32 sib = keccak256("a sibling with the same chain id");
        bytes memory cd = _op(RENOUNCE_ADMIN, eoa, address(t), abi.encode(sib));
        vm.expectRevert(abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, u, sib));
        _run(cd);
        assertEq(t.admin(), eoa, "the admin kept");
        assertEq(router.mtxNonce(eoa, 0), 0, "the nonce stays unspent");
        bytes4 oldSel = bytes4(keccak256("mtxRenounceAdmin((bytes32,uint256,uint256,uint256,uint32,address,uint256,address),"
            "address,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))"));
        (bool ok, bytes memory ret) = address(router).call(abi.encodePacked(oldSel, new bytes(32 * 12)));
        assertTrue(!ok && ret.length == 0, "the old entry answers");
        _do(RENOUNCE_ADMIN, eoa, address(t), abi.encode(u));
        assertEq(t.admin(), bytes32(0), "the control");
    }

    /// CTR-GOV-27: `mtxTransferAdmin` signs the target's chain word and forwards it, on a token and on the DEX. Signed for a
    /// sibling (another word) the target refuses it by name, nothing written, nonce unspent; the old entry without the word
    /// has no entry (empty revert); the control: the same signer with the target's word names the successor.
    function test_transferAdmin_siblingWordRefused() public {
        NormalToken t = _normal(eoa, 0, 0);
        SCaaSDex d = _dex(eoa);
        bytes32 sib = keccak256("a sibling with the same chain id");
        address[2] memory ts = [address(t), address(d)];
        for (uint256 i; i < 2; ++i) {
            bytes32 u = EnvKit.codeUidOf(ts[i]);
            assertTrue(u != bytes32(0), "a clone's word");
            bytes memory cd = _op(TRANSFER_ADMIN, eoa, ts[i], abi.encode(next, sib));
            vm.expectRevert(abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, u, sib));
            _run(cd);
            assertEq(IAdmin(ts[i]).pendingAdmin(), bytes32(0), "nothing written");
            assertEq(router.mtxNonce(eoa, 0), 0, "the nonce stays unspent");
        }
        bytes4 oldSel = bytes4(keccak256("mtxTransferAdmin((bytes32,uint256,uint256,uint256,uint32,address,uint256,address),"
            "address,bytes32,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))"));
        (bool ok, bytes memory ret) = address(router).call(abi.encodePacked(oldSel, new bytes(32 * 13)));
        assertTrue(!ok && ret.length == 0, "the old entry answers");
        for (uint256 i; i < 2; ++i) {
            _do(TRANSFER_ADMIN, eoa, ts[i], abi.encode(next, EnvKit.codeUidOf(ts[i])));
            assertEq(IAdmin(ts[i]).pendingAdmin(), next, "the control");
        }
    }

    /// CTR-GOV-28 (owner 2026-11-13): the router's five governance admin ops sign the target's chain word and forward it; one
    /// signed for a sibling (another word) reaches the target, which refuses it by name, nothing written, the nonce unspent;
    /// a relayer cannot swap the word under a signature (another word, another digest); the own word is the control.
    /// Owner 2026-11-13 (renounceRole carries the chain word too): `mtxRenounceRole`, the holder's own, likewise.
    function test_governanceOps_siblingWordRefused() public {
        NormalToken t = _normal(eoa, eoa, 0);
        bytes32 u = EnvKit.codeUidOf(address(t));
        bytes32 sib = keccak256("a sibling with the same chain id");
        bytes memory mm = abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, u, sib);
        uint256[5] memory ops = [GRANT_ROLE, REVOKE_ROLE, CANCEL_GRANT, DISABLE_FEATURE, RENOUNCE_ROLE];
        for (uint256 i; i < 5; ++i) {
            bytes memory args = ops[i] == DISABLE_FEATURE || ops[i] == RENOUNCE_ROLE ? abi.encode(MINT, sib)
                : abi.encode(MINT, pq, sib);
            bytes memory cd = _op(ops[i], eoa, address(t), args);
            vm.expectRevert(mm);
            _run(cd);
        }
        (bytes memory a, bytes memory w) = _setGrantArgs(MINT, pq, _limited(5), sib);
        bytes memory cdg = _signed(router, SET_GRANT, eoa, 0, address(t), a, w);
        vm.expectRevert(mm);
        _run(cdg);
        assertEq(router.mtxNonce(eoa, 0), 0, "nonces unspent");
        assertTrue(t.hasRole(MINT, eoa) && !t.hasRole(MINT, pq), "nothing written");
        {
            bytes4 oldSel = bytes4(keccak256("mtxRenounceRole((bytes32,uint256,uint256,uint256,uint32,address,uint256,address),"
                "address,uint8,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))"));
            (bool ok, bytes memory ret) = address(router).call(abi.encodePacked(oldSel, new bytes(32 * 12)));
            assertTrue(!ok && ret.length == 0, "the old mtxRenounceRole answers");
        }
        // a word swapped under the signature: another digest, the signer's key does not verify it
        (a,) = _setGrantArgs(MINT, pq, _limited(5), u);
        cdg = _signed(router, SET_GRANT, eoa, 0, address(t), a, w);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(cdg);
        // the controls, the own word
        (a, w) = _setGrantArgs(MINT, pq, _limited(5), u);
        _run(_signed(router, SET_GRANT, eoa, 0, address(t), a, w));
        assertEq(t.grantOf(MINT, pq).total, 5, "SetGrant");
        _do(REVOKE_ROLE, eoa, address(t), abi.encode(MINT, pq, u));
        assertFalse(t.hasRole(MINT, pq), "RevokeRole");
        _do(GRANT_ROLE, eoa, address(t), abi.encode(MINT, pq, u));
        assertTrue(t.hasRole(MINT, pq), "GrantRole");
        _do(CANCEL_GRANT, eoa, address(t), abi.encode(MINT, pq, u));
        _do(REVOKE_ROLE, eoa, address(t), abi.encode(MINT, pq, u));
        _do(RENOUNCE_ROLE, eoa, address(t), abi.encode(MINT, u));
        assertFalse(t.hasRole(MINT, eoa), "RenounceRole");
        _do(DISABLE_FEATURE, eoa, address(t), abi.encode(MINT, u));
        assertEq(t.features() & (uint256(1) << MINT), 0, "DisableFeature");
    }

    /// A target without code: refused by name, nonce unspent (a call to it would succeed and do nothing).
    function test_targetWithoutCodeRefused() public {
        bytes memory cd = _op(SET_LISTED_ONLY, pq, address(0xC0DE), abi.encode(true));
        vm.expectRevert(abi.encodeWithSelector(GovernanceRouterBase.TargetHasNoCode.selector, address(0xC0DE)));
        _run(cd);
        assertEq(router.mtxNonce(pq, 0), 0);
    }

    /// R-02 on the real router: `target` is a signed word, a relayer cannot move a signed op to another token.
    function test_refuted_relayerAltersTheTarget() public {
        NormalToken a = _normal(pq, pq, 0);
        NormalToken b = _normal(pq, pq, 0);
        bytes memory args = abi.encode(BOB, uint256(1));
        MetaTxLib.UAEnvelope memory e = _envelope(router, pq, 0);
        bytes32 d = _digest(router, OP_MINT, e, address(a), args);
        bytes memory tail = _tail(abi.encode(_auth(pq, d)));
        bytes memory cd = _calldata(OP_MINT, e, address(b), args, tail);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, pq));
        _run(cd);
        e = _envelope(router, eoa, 0);
        d = _digest(router, OP_MINT, e, address(a), args);
        cd = _calldata(OP_MINT, e, address(b), args, _tail(abi.encode(_auth(eoa, d))));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        _run(cd);
        _run(_calldata(OP_MINT, _envelope(router, pq, 0), address(a), args, tail)); // positive control
        assertEq(a.balanceOf(BOB), 1);
    }

    /// R-02 on the real router: the same signature on a second router (another chain's `chain_uid`, or the same chain's second deployment) and on
    /// another chain id: `verifyingContract`, `chain_uid` and `chainId` are in the domain.
    function test_refuted_replayAcrossRoutersAndChains() public {
        GovernanceRouter other = new GovernanceRouter(chainUidA, PREG, address(0), false);
        GovernanceRouter otherUid = new GovernanceRouter(keccak256("another chain"), PREG, address(0), false);
        NormalToken t = _normal(pq, pq, 0);
        bytes memory cd = _op(OP_MINT, pq, address(t), abi.encode(BOB, uint256(1)));
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
        bytes memory cd = _signedAt(router, OP_MINT, e, address(t), args, args);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, e.mode));
        _run(cd);
        assertEq(router.supportedModes(), MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT);
    }

    /// B-14, fixed (the attack round's `test_attack_theHoldersOpIsReachableAsABytesBlob` on the sketch): the generic path is
    /// refused on every entry, whatever the blob calls: `executeMetaTransaction`, and `mtxExecute` / `mtxBatch` on ids for a
    /// native and a derived signer. The base's `cancelNonce` as the blob is refused too. (ua-mtx-merge T1: the address
    /// `mtxExecute` / `mtxBatch` left the router, MD-1; the `uaExecute` / `uaBatch` refusals are the `mtx*` ones.)
    function test_fixed_theRoutersOpIsNotReachableAsABytesBlob() public {
        bytes memory data = abi.encodeCall(IMetaTx.cancelNonce, (7));
        (address a, uint256 k) = makeAddrAndKey("blob signer");
        MetaTxLib.MetaTransaction memory m =
            MetaTxLib.MetaTransaction(a, data, 0, 0, block.timestamp + 1 hours, 0, address(0), 0, address(0));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(k, MtxDigest.metaTx(address(router), m));
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes4 refused = IMetaTx.cancelNonce.selector;
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, refused));
        router.executeMetaTransaction(m, sig);
        // the same native signer on the merged generic entries
        MetaTxLib.UAMetaTransaction memory n =
            MetaTxLib.UAMetaTransaction(MetaTxLib.pad(a), data, 0, 0, block.timestamp + 1 hours, 0, address(0), 0, address(0));
        (v, r, s) = vm.sign(k, router.mtxDigest(n));
        MetaTxLib.UAMetaTransaction[] memory ns = new MetaTxLib.UAMetaTransaction[](1);
        IUARegistry.UASig[] memory nas = new IUARegistry.UASig[](1);
        ns[0] = n;
        nas[0].signature = abi.encodePacked(r, s, v);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, refused));
        router.mtxExecute(n, nas[0]);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(0)));
        router.mtxBatch(ns, nas);
        assertEq(router.mtxNonce(MetaTxLib.pad(a), 0), 0);
        _genericUaRefused(data, refused);
    }

    function _genericUaRefused(bytes memory data, bytes4 refused) internal {
        MetaTxLib.UAMetaTransaction memory u =
            MetaTxLib.UAMetaTransaction(pq, data, 0, 0, block.timestamp + 1 hours, 0, address(0), 0, address(0));
        bytes memory auth = abi.encode(bytes(""), _sig(pqKey, UAKinds.uaMessage(ML44, UAKinds.PURPOSE_METATX, router.mtxDigest(u))));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, refused));
        router.mtxExecute(u, UACall.auth(u.from, auth));
        MetaTxLib.UAMetaTransaction[] memory us = new MetaTxLib.UAMetaTransaction[](1);
        bytes[] memory auths = new bytes[](1);
        (us[0], auths[0]) = (u, auth);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(0)));
        router.mtxBatch(us, UACall.auths(us, auths));
        assertEq(router.mtxNonce(pq, 0), 0);
    }

    /// `cancelNonce` and the ordered `mtxCancelNonce` stay: a cancelled lane kills a pre-signed op. (ua-mtx-merge T1,
    /// meaning: the unordered `uaCancelNonce` under `metatx-cancel` -> the ordered `mtxCancelNonce` on its own lane 5, under
    /// the named op's purpose `metatx`, MD-5.)
    function test_cancelNonceStays() public {
        NormalToken t = _normal(pq, pq, 0);
        bytes memory cd = _op(OP_MINT, pq, address(t), abi.encode(BOB, uint256(1)));
        MetaTxLib.UAEnvelope memory e = MetaTxLib.UAEnvelope(pq, 5, 0, block.timestamp + 1 hours, 0, address(0), 0, address(0));
        bytes32 d = MtxDigest.typed(address(router), keccak256(abi.encode(MetaTxLib.UA_CANCEL_NONCE_TYPEHASH, e.from, uint256(0),
            e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        IUARegistry.UASig memory a;
        a.signature = _sig(pqKey, UAKinds.uaMessage(ML44, UAKinds.PURPOSE_METATX, d));
        router.mtxCancelNonce(e, 0, a);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        _run(cd);
        address n = address(uint160(uint256(eoa)));
        vm.prank(n);
        router.cancelNonce(0);
        assertEq(router.mtxNonce(MetaTxLib.pad(n), 0), 1);
    }

    // ------------------------------------------------------------------ subject() and the lock

    /// During the call the target reads the signer; a bystander reads 0 at the same moment; outside a call, 0.
    function test_subjectOnlyToTheLiveTarget() public {
        ProbeTarget p = new ProbeTarget(router);
        _do(SET_LISTED_ONLY, msig, address(p), abi.encode(true));
        assertEq(p.seen(), msig);
        assertEq(p.seenByOther(), bytes32(0), "a non-target reads 0 during a live call");
        vm.prank(address(p));
        assertEq(router.subject(), bytes32(0), "the target reads 0 outside a call");
        _do(SET_LISTED_ONLY, eoa, address(p), abi.encode(true));
        assertEq(p.seen(), eoa, "a native signer's subject is its native id");
    }

    /// The pair is cleared when the call returns: the target asks again in the same transaction and reads 0.
    function test_subjectClearedInTheSameTransaction() public {
        ProbeTarget p = new ProbeTarget(router);
        bytes memory cd = _op(SET_LISTED_ONLY, pq, address(p), abi.encode(true));
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

/// Plan T32 (regulated-kinds spec §3.1, Q8; owner 2026-11-05, CTR-GOV-20): the eight control ops of the regulated kinds on the
/// router, `mtx<Op>(UAEnvelope, target, <the direct entry's params>, UASig)` over `UA<Op>`, fee mode `NONE`. Each runs on a
/// real `NormalRegulatedToken` (kind 8) whose `GOV_ROUTER` is the router, signed by a contract holder (ERC-1271, `wallet`)
/// and by an `msig` holder: two tokens, the issuer of one the compliance holder of the other (`FORCE` and `RECORD` never on
/// one id). Bit 22 `OPERATOR_TRANSFER` is held by the same two ids. The token keeps no `mtx` twin (G19).
contract GovRouterRegulatedTest is GovRouterFixture {
    uint256 constant R_FREEZE = 0;
    uint256 constant R_UNFREEZE = 1;
    uint256 constant R_FORCE = 2;
    uint256 constant R_PAUSE = 3;
    uint256 constant R_UNPAUSE = 4;
    uint256 constant R_RECORD = 5;
    uint256 constant R_REVOKE = 6;
    uint256 constant R_OPERATOR = 7;
    uint256 constant R_TAX_RATE = 8; // pay-meta-tax T39 (spec §6.2): bit 23 `TAX`
    uint256 constant R_TAX_RECIPIENT = 9;
    bytes32 constant REF = bytes32(uint256(0x5EF));
    address constant OTHER = address(0xF00);

    Row[10] internal reg8;
    address internal regImpl;

    function setUp() public override {
        super.setUp();
        reg8[R_FREEZE] = Row("Freeze", ",bytes32 account,bytes32 ref,bytes32 recordId", router.mtxFreeze.selector);
        reg8[R_UNFREEZE] = Row("Unfreeze", ",bytes32 account,bytes32 ref", router.mtxUnfreeze.selector);
        reg8[R_FORCE] = Row("ForceTransfer", ",bytes32 recordId,uint256 amount", router.mtxForceTransfer.selector);
        reg8[R_PAUSE] = Row("Pause", ",bytes32 ref,uint64 until", router.mtxPause.selector);
        reg8[R_UNPAUSE] = Row("Unpause", ",bytes32 ref", router.mtxUnpause.selector);
        reg8[R_RECORD] = Row("RecordOrder",
            ",bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,uint256 maxAmount,uint64 freezeUntil",
            router.mtxRecordOrder.selector);
        reg8[R_REVOKE] = Row("RevokeOrder", ",bytes32 recordId,bytes32 reasonRef", router.mtxRevokeOrder.selector);
        reg8[R_OPERATOR] = Row("OperatorTransfer", ",bytes32 account,bytes32 to,uint256 amount,bytes32 ref",
            router.mtxOperatorTransfer.selector);
        reg8[R_TAX_RATE] = Row("SetTaxRate", ",uint32 ratePpm", router.mtxSetTaxRate.selector);
        reg8[R_TAX_RECIPIENT] = Row("SetTaxRecipient", ",bytes32 taxRecipient", router.mtxSetTaxRecipient.selector);
    }

    /// Kind 8 with `FREEZE`, `FORCE`, `PAUSE`, `RECORD`, `OPERATOR_TRANSFER`; owner `eoa`, no grant delay; `BOB` holds 1,000.
    function _regulated(bytes32 issuer, bytes32 compliance, bytes32 operator) internal returns (NormalRegulatedToken t) {
        if (regImpl == address(0)) regImpl = address(new NormalRegulatedToken(address(this), kindArgs(8, address(this), regArgs())));
        t = NormalRegulatedToken(EnvKit.clone(regImpl, _cenv()));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin) = ("R", "R", 6, eoa);
        c.features = 1 | (uint256(1) << 5) | (uint256(1) << 6) | (uint256(1) << 7) | (uint256(1) << 10)
            | (uint256(1) << GovernanceBits.OPERATOR_TRANSFER) | (uint256(1) << GovernanceBits.TAX);
        c.reg.taxRecipient = _pad(address(0x7A0)); // pay-meta-tax T39: bit 23 with the issuer seat
        (c.roles.issuer, c.roles.compliance) = (issuer, compliance);
        (c.initialSupply, c.initialHolder) = (1000, BOB);
        c.reg.termsHash = keccak256("terms");
        t.initialize(nid(address(this)), 1, abi.encode(c));
        vm.prank(address(uint160(uint256(eoa))));
        t.grantRole(GovernanceBits.OPERATOR_TRANSFER, operator, EnvKit.codeUidOf(address(t)));
        if (operator != issuer) {
            vm.prank(address(uint160(uint256(eoa))));
            t.grantRole(GovernanceBits.TAX, operator, EnvKit.codeUidOf(address(t)));
        }
    }

    function _typehashR(uint256 op) internal view returns (bytes32) {
        return keccak256(bytes(string.concat("UA", reg8[op].name, "(bytes32 from,address target", reg8[op].params, TAIL)));
    }

    /// The signed `mtx<Op>` of `from` for `target`, every op word static (the struct words are the call's).
    function _rcall(uint256 op, bytes32 from, address target, bytes memory args) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _envelope(router, from, 0);
        bytes32 h = keccak256(bytes.concat(abi.encode(_typehashR(op), e.from, target), args,
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        bytes32 d = keccak256(abi.encodePacked("\x19\x01", _domain(router), h));
        bytes memory head = bytes.concat(abi.encode(e), abi.encode(target), args);
        return bytes.concat(reg8[op].sel, head, abi.encode(head.length + 32), _tail(abi.encode(_auth(e.from, d))));
    }

    function _rdo(uint256 op, bytes32 from, address target, bytes memory args) internal {
        _run(_rcall(op, from, target, args));
    }

    /// The eight in an order where each one's effect is read, up to `last`, on one token signed by `i` (issuer), `c`
    /// (compliance), `o` (bit 22).
    function _eight(uint256 last, bytes32 i, bytes32 c, bytes32 o) internal {
        NormalRegulatedToken t = _regulated(i, c, o);
        bytes32 bob = _pad(BOB);
        bytes32 ben = _pad(TREASURY);
        uint64 day = uint64(block.timestamp + 1 days);
        _rdo(R_PAUSE, i, address(t), abi.encode(REF, day));
        assertEq(t.regulatedConfig().pausedUntil, day, "Pause");
        if (last == R_PAUSE) return;
        _rdo(R_UNPAUSE, i, address(t), abi.encode(REF));
        assertEq(t.regulatedConfig().pausedUntil, block.timestamp, "Unpause");
        if (last == R_UNPAUSE) return;
        bytes32 rid = keccak256(abi.encode(bytes32("order"), bob, ben));
        _rdo(R_RECORD, c, address(t), abi.encode(bytes32("order"), keccak256("doc"), bob, ben, uint256(100), day));
        assertEq(t.order(rid).subject, bob, "RecordOrder");
        if (last == R_RECORD) return;
        _rdo(R_FREEZE, i, address(t), abi.encode(bob, REF, rid));
        assertTrue(t.isFrozen(bob), "Freeze");
        if (last == R_FREEZE) return;
        _rdo(R_FORCE, i, address(t), abi.encode(rid, uint256(30)));
        assertEq(t.balanceOf(TREASURY), 30, "ForceTransfer");
        if (last == R_FORCE) return;
        _rdo(R_REVOKE, c, address(t), abi.encode(rid, bytes32("why")));
        assertTrue(t.order(rid).revoked && !t.isFrozen(bob), "RevokeOrder");
        if (last == R_REVOKE) return;
        _rdo(R_FREEZE, i, address(t), abi.encode(_pad(OTHER), REF, bytes32(0)));
        _rdo(R_UNFREEZE, i, address(t), abi.encode(_pad(OTHER), REF));
        assertFalse(t.isFrozen(_pad(OTHER)), "Unfreeze");
        if (last == R_UNFREEZE) return;
        _rdo(R_OPERATOR, o, address(t), abi.encode(bob, ben, uint256(5), REF));
        assertEq(t.balanceOf(TREASURY), 35, "OperatorTransfer");
        assertEq(t.balanceOf(BOB), 965);
    }

    /// Each row signed by a contract holder (ERC-1271) and by an `msig` holder.
    function _row(uint256 op) internal {
        _eight(op, wallet, msig, wallet);
        _eight(op, msig, wallet, msig);
    }

    function test_routerRow_Pause() public { _row(R_PAUSE); }
    function test_routerRow_Unpause() public { _row(R_UNPAUSE); }
    function test_routerRow_RecordOrder() public { _row(R_RECORD); }
    function test_routerRow_Freeze() public { _row(R_FREEZE); }
    function test_routerRow_ForceTransfer() public { _row(R_FORCE); }
    function test_routerRow_RevokeOrder() public { _row(R_REVOKE); }
    function test_routerRow_Unfreeze() public { _row(R_UNFREEZE); }
    function test_routerRow_OperatorTransfer() public { _row(R_OPERATOR); }

    /// pay-meta-tax T39 (spec §6.1, §6.2, O9): bit 23 relayed by every holder class (an EOA, a single-key UA, a contract,
    /// an `msig`) at fee 0, through `mtxSetTaxRate` and `mtxSetTaxRecipient`.
    function test_routerRow_SetTaxRate() public {
        bytes32[4] memory hs = [eoa, pq, wallet, msig];
        for (uint256 k; k < 4; ++k) {
            NormalRegulatedToken t = _regulated(wallet, msig, hs[k]);
            _rdo(R_TAX_RATE, hs[k], address(t), abi.encode(uint32(1_000 + k)));
            assertEq(t.taxConfig().effectivePpm, 1_000 + k);
        }
    }

    function test_routerRow_SetTaxRecipient() public {
        bytes32[4] memory hs = [eoa, pq, wallet, msig];
        for (uint256 k; k < 4; ++k) {
            NormalRegulatedToken t = _regulated(wallet, msig, hs[k]);
            _rdo(R_TAX_RECIPIENT, hs[k], address(t), abi.encode(_pad(TREASURY)));
            assertEq(t.taxConfig().taxRecipient, _pad(TREASURY));
        }
    }

    /// Bit 22 takes any holder: an EOA and a single-key derived UA (`pq`) relay `mtxOperatorTransfer` too.
    function test_routerRow_OperatorTransferAnyHolder() public {
        bytes32[2] memory ops = [eoa, pq];
        for (uint256 k; k < 2; ++k) {
            NormalRegulatedToken t = _regulated(wallet, msig, ops[k]);
            _rdo(R_OPERATOR, ops[k], address(t), abi.encode(_pad(BOB), _pad(TREASURY), uint256(5), REF));
            assertEq(t.balanceOf(TREASURY), 5);
        }
    }

    /// A holder's refusal and the token's are the router's: a stranger's signed op reverts `MissingRole` with its own id,
    /// and the nonce is not spent.
    function test_routerRow_strangerRefused() public {
        NormalRegulatedToken t = _regulated(wallet, msig, wallet);
        _rfail(_rcall(R_OPERATOR, stranger, address(t), abi.encode(_pad(BOB), _pad(TREASURY), uint256(5), REF)),
            abi.encodeWithSelector(IGovernance.MissingRole.selector, uint8(GovernanceBits.OPERATOR_TRANSFER), stranger));
        _rfail(_rcall(R_FREEZE, stranger, address(t), abi.encode(_pad(BOB), REF, bytes32(0))),
            abi.encodeWithSelector(IGovernance.MissingRole.selector, uint8(GovernanceBits.FREEZE), stranger));
        assertEq(router.mtxNonce(stranger, 0), 0);
        _rdo(R_FREEZE, wallet, address(t), abi.encode(_pad(BOB), REF, bytes32(0))); // the control: the issuer
    }

    function _rfail(bytes memory cd, bytes memory err) internal {
        (bool ok, bytes memory ret) = address(router).call(cd);
        assertFalse(ok);
        assertEq(ret, err);
    }

    /// `target` is a signed word: a signature for one token does not run on another.
    function test_routerRow_targetIsSigned() public {
        NormalRegulatedToken t1 = _regulated(wallet, msig, wallet);
        NormalRegulatedToken t2 = _regulated(wallet, msig, wallet);
        bytes memory cd = _rcall(R_OPERATOR, wallet, address(t1), abi.encode(_pad(BOB), _pad(TREASURY), uint256(5), REF));
        bytes memory moved = bytes.concat(cd); // the same call with `target` at word 9 (after the 8-word envelope) moved
        assembly ("memory-safe") { mstore(add(moved, add(36, 256)), t2) }
        (bool ok,) = address(router).call(moved);
        assertFalse(ok, "another target");
        _run(cd);
        assertEq(t1.balanceOf(TREASURY), 5);
    }

    /// No control has a twin on the token (G19): the router's selectors are no token entry, and the token's allow-list
    /// carries none of the eight direct entries.
    function test_tokenHasNoTwin() public {
        NormalRegulatedToken t = _regulated(wallet, msig, wallet);
        (bytes4[] memory s,,) = t.mtxSelectors();
        bytes4[8] memory direct = [IRegulatedToken.freeze.selector, IRegulatedToken.unfreeze.selector,
            IRegulatedToken.forceTransfer.selector, IRegulatedToken.pause.selector, IRegulatedToken.unpause.selector,
            IRegulatedToken.recordOrder.selector, IRegulatedToken.revokeOrder.selector,
            IRegulatedToken.operatorTransfer.selector];
        for (uint256 k; k < 8; ++k) {
            for (uint256 j; j < s.length; ++j) assertTrue(s[j] != direct[k]);
            (bool ok, bytes memory ret) = address(t).call(bytes.concat(reg8[k].sel, new bytes(32 * 30)));
            assertFalse(ok);
            assertEq(ret.length, 0, reg8[k].name);
        }
    }
}
