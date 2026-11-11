// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OnchainBase} from "./OnchainBase.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedgerViews} from "../../src/metatx/IUALedgerViews.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {IRescuable} from "../../src/governance/IRescuable.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {ComplianceRegistry} from "../../src/regulated/ComplianceRegistry.sol";
import {SmartKeyAccount, SubjectKey, KeyKind, AccountSig} from "../../src/account/SmartKeyAccount.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {MockERC20} from "../../test/helpers/Mocks.sol";

/// @notice T66b Step 5b, group `gov`: every GovernanceRouter entry by UA signature (a native id's ECDSA, a SmartKeyAccount's
///         ERC-1271), relayed by k2, on tokens of kinds 0, 1, 8, 9 and a DEX made here with the Step 5 factory; the regulated
///         powers on kinds 8 (direct, the issuer and compliance roles held by SmartKeyAccounts) and 9 (through the router);
///         SmartKeyAccountFactory and every SmartKeyAccount entry (secp256k1 and WebAuthn P-256 keys); an own
///         ComplianceRegistry (admin a SmartKeyAccount) with an allow-listed kind-8 token. Not here: the router's PQZ setters
///         (no PQZ kind on the Step 5 factory; the e2e.py factory's PQZ tokens), `mtxCreateInstance` with a class release
///         (none on the Step 5 factory: a negative here). UNAUDITED.
contract Gov is OnchainBase {
    string constant TAIL = "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string constant TERMS_T =
        "GrantTerms(uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope)";
    string constant EXECUTE_T =
        "Execute(address from,address target,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    bytes32 constant UA_RELAY_FEE = keccak256(
        "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)");
    /// @dev The router calls signed by a SmartKeyAccount (ERC-1271): SigCheck refuses one with less than
    ///      SMART_KEY_1271_GAS (400,000) x 64/63 + 5,000 left at the check (`SigCheckGasStarved`, fail closed), a bound the
    ///      simulation does not see (it runs with ample gas and measures the cheap ECDSA path), so forge's estimate x 1.30
    ///      ran out at that check on the local copy. A relayer's eth_estimateGas finds it; a forge script states it.
    uint256 constant SKA_SIG_GAS = 1_500_000;
    uint256 constant N_K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 constant N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    string constant RP_ID = "scaas.test";
    string constant ORIGIN = "https://scaas.test";

    struct Sg {
        bytes32 from;
        uint256 pk;
        uint8 how; // 0 a native id (its own ECDSA), 1 a SmartKeyAccount (key 0, its ERC-1271), 2 a registered secp256k1 UA
    }

    GovernanceRouter gr;
    OpenFactory f;
    SmartKeyAccountFactory skf;
    MockERC20 u;
    MockERC20 u2;
    address iss; // issuer (FREEZE, FORCE, PAUSE, TAX) and rate admin: a SmartKeyAccount
    address cmp; // compliance (RECORD): another one (FORCE and RECORD never on one account)
    address acct; // the account whose own entries run
    uint256 pkI;
    uint256 pkC;
    uint256 pkA;
    address t0;
    address t0d;
    address t0r;
    address t1;
    address t8;
    address t9;
    address tc;
    address dex;
    ComplianceRegistry cr;
    uint256 nref;
    bytes32 uaD; // a secp256k1 UA registered on the Step 5 registry
    uint256 kD;
    bytes sgx; // a signature computed before its broadcast (no view call between broadcast and the call)
    bytes keyD; // its key data (x ‖ y): a stateless kind's UASig carries it

    function run() external {
        _init("gov");
        gr = GovernanceRouter(_dep("governance_router"));
        f = OpenFactory(_dep("token_factory"));
        skf = SmartKeyAccountFactory(_dep("smart_key_account_factory"));
        _book(address(gr), "GovernanceRouter");
        _book(address(f), "OpenFactory");
        _book(address(skf), "SmartKeyAccountFactory");
        _setup();
        _registerDerived();
        _compliance();
        _complianceRouter();
        _plain();
        _wrapped();
        _regulatedDirect();
        _regulatedRouter();
        _dexAndCreations();
        _relayFee();
        _account();
        _negatives();
        _writeBook();
    }

    // ------------------------------------------------------------------ fixtures

    function _key(string memory what, uint256 n) internal view returns (uint256 k) {
        k = uint256(keccak256(abi.encode(runSalt, what))) % n;
        if (k == 0) k = 1;
    }

    function _secp(uint256 pk) internal pure returns (SubjectKey memory k) {
        (k.kind, k.x) = (KeyKind.SECP256K1, bytes32(uint256(uint160(vm.addr(pk)))));
    }

    function _setup() internal {
        (pkI, pkC, pkA) = (_key("iss", N_K1), _key("cmp", N_K1), _key("acct", N_K1));
        vm.startBroadcast(k2);
        iss = skf.deploy(_secp(pkI), address(0));
        cmp = skf.deploy(_secp(pkC), address(0));
        acct = skf.deploy(_secp(pkA), a2);
        vm.stopBroadcast();
        _book(iss, "SmartKeyAccount");
        _book(cmp, "SmartKeyAccount");
        _book(acct, "SmartKeyAccount");
        vm.startBroadcast(k1);
        u = new MockERC20("Onchain USD", "oUSD", 6);
        u2 = new MockERC20("Onchain Stray", "oSTR", 6);
        u.mint(a1, 1_000_000_000);
        vm.stopBroadcast();
    }

    function _cfg(string memory sym, uint256 features) internal view returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals, c.features, c.admin) = ("Onchain Gov", sym, 6, features, _pad(a1));
    }

    function _create(IOpenFactory.TokenKind k, IFactoryToken.TokenConfig memory c, string memory label)
        internal returns (address t)
    {
        vm.broadcast(k1);
        t = f.createToken(k, 1, abi.encode(c), _salt(c.symbol));
        _book(t, label);
    }

    function _ref() internal returns (bytes32) {
        return keccak256(abi.encode(runSalt, "ref", ++nref));
    }

    // ------------------------------------------------------------------ signing

    function _ty(string memory name, string memory fields) internal pure returns (string memory) {
        return bytes(fields).length == 0 ? string.concat(name, "(bytes32 from,address target,", TAIL)
            : string.concat(name, "(bytes32 from,address target,", fields, ",", TAIL);
    }

    function _eoa(uint256 pk) internal pure returns (Sg memory) {
        return Sg(_pad(vm.addr(pk)), pk, 0);
    }

    function _skaSg(address a, uint256 pk) internal pure returns (Sg memory) {
        return Sg(_pad(a), pk, 1);
    }

    /// @dev The router envelope (lane 0, its next nonce, open mode, no fee) and the signer's UASig over the named digest.
    function _auth(Sg memory g, string memory typ, address target, bytes memory words)
        internal view returns (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory s)
    {
        (e.from, e.nonce, e.validUntil) = (g.from, gr.mtxNonce(g.from, 0), vu);
        s = _signR(g, _named(address(gr), typ, bytes.concat(abi.encode(target), words), e));
    }

    function _signR(Sg memory g, bytes32 d) internal view returns (IUARegistry.UASig memory s) {
        if (g.how == 1) s.signature = abi.encode(uint256(0), new bytes32[](0), _ecdsa(g.pk, d));
        else if (g.how == 2) {
            (s.keyData, s.signature) = (keyD, _ecdsa(g.pk, UAKinds.uaMessage(UAKinds.SECP256K1, UAKinds.PURPOSE_METATX, d)));
        }
        else s.signature = _ecdsa(g.pk, d);
    }

    /// @dev A secp256k1 UA registered on the Step 5 registry (its portable PoP), the router's derived signer and a
    ///      `mintToUA` receiver.
    function _registerDerived() internal {
        address reg = _dep("ua_registry");
        _book(reg, "UARegistry");
        kD = uint256(keccak256(abi.encode(runSalt, "derived"))) % type(uint128).max + 1;
        Vm.Wallet memory w = vm.createWallet(kD);
        bytes memory keyData = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        keyD = keyData;
        bytes32 ua = UAKinds.uaOf(UAKinds.SECP256K1, keyData);
        bytes32 rd = UAKinds.registrationDigest(ua, UAKinds.SECP256K1, 0, UAKinds.kemRecordHash(ua, 0, bytes("")), 0);
        bytes memory pop = _ecdsa(kD, UAKinds.uaMessage(UAKinds.SECP256K1, UAKinds.PURPOSE_POP_V2, rd));
        IUARegistry.UAAttrs memory none;
        vm.broadcast(k1);
        uaD = IUARegistry(reg).register(UAKinds.SECP256K1, keyData, none, pop, "");
        require(uaD == ua && IUARegistry(reg).isRegistered(ua), "derived UA");
    }

    /// @dev A SmartKeyAccount runs `target.call(data)` (its named `mtxExecute`, key 0, relayed by k2).
    function _skaExec(address ska, uint256 pk, address target, bytes memory data) internal {
        MetaTxLib.Envelope memory e = _aenv(ska, 0, SmartKeyAccount(payable(ska)).mtxNonce(ska, 0));
        bytes32 d = _namedA(ska, EXECUTE_T, abi.encode(target, uint256(0), keccak256(data)), e);
        vm.broadcast(k2);
        SmartKeyAccount(payable(ska)).mtxExecute(e, target, 0, data, AccountSig(0, new bytes32[](0), _ecdsa(pk, d)));
    }

    // ------------------------------------------------------------------ the own ComplianceRegistry (admin `iss`)

    /// The own registry: its admin the native id of the SmartKeyAccount `iss`, its router the chain's (round 3r, spec §5.3;
    /// T11 adds the router steps), one KYC provider `a2` (its native id).
    function _compliance() internal {
        vm.broadcast(k1);
        cr = new ComplianceRegistry(_pad(iss), address(gr));
        _book(address(cr), "ComplianceRegistry");
        require(address(cr).codehash == _dep("compliance_registry").codehash, "compliance code");
        _skaExec(iss, pkI, address(cr), abi.encodeCall(ComplianceRegistry.setKycProvider, (_pad(a2), true)));
        bytes32[] memory who = new bytes32[](2);
        uint64[] memory fl = new uint64[](2);
        uint64[] memory until = new uint64[](2);
        (who[0], who[1], fl[0], fl[1], until[0], until[1]) = (_pad(a1), _pad(a3), 1, 1, type(uint64).max, type(uint64).max);
        _skaExec(iss, pkI, address(cr), abi.encodeCall(ComplianceRegistry.setCompliance, (who, fl, until)));
        bytes32[] memory w2 = new bytes32[](1);
        uint64[] memory f2 = new uint64[](1);
        uint64[] memory u2_ = new uint64[](1);
        (w2[0], f2[0], u2_[0]) = (_pad(a2), 1, uint64(vu + 30 days));
        vm.broadcast(k2);
        cr.setCompliance(w2, f2, u2_); // a KYC provider's row
        IFactoryToken.TokenConfig memory c = _cfg("oGC8", 1 << GovernanceBits.PAYABLE | 1 << GovernanceBits.KYC); // round 3s
        (c.initialSupply, c.initialHolder) = (1_000_000, a1);
        (c.reg.complianceRegistry, c.reg.requiredFlags, c.reg.termsHash) = (address(cr), 1, keccak256("onchain terms"));
        tc = _create(IOpenFactory.TokenKind.NORMAL_REGULATED, c, "NormalRegulatedToken");
        vm.broadcast(k1);
        IERC20(tc).transfer(a3, 10); // to an attested holder
        vm.broadcast(k1);
        IERC20(tc).transfer(a2, 10); // to the KYC provider's own row
        // group 3s (CTR-GOV-24, spec §5.2, §15 T8): KYC off (grantDelay 0: at once; a1 the admin) and on again, at once; the
        // attested receiver still receives
        vm.startBroadcast(k1);
        IGovernance(tc).disableFeature(GovernanceBits.KYC);
        IRegulatedToken(tc).enableFeature(GovernanceBits.KYC);
        IERC20(tc).transfer(a3, 1);
        vm.stopBroadcast();
    }

    /// Round 3r (CTR-GOV-23, spec §7 "Matrix"): the registry's admin moves from `iss` to the derived secp256k1 UA (the
    /// two-step transfer, its signed `mtxAcceptAdmin`); then its admin ops are that UA's router ops, sent by key 2 at fee 0: a
    /// KYC provider (key 3's native id) enabled and an admin row written.
    function _complianceRouter() internal {
        _skaExec(iss, pkI, address(cr), abi.encodeCall(IAdmin.transferAdmin, (uaD)));
        Sg memory d = Sg(uaD, kD, 2);
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory s) = _auth(d, _ty("UAAcceptAdmin", ""), address(cr), "");
        vm.broadcast(k2);
        gr.mtxAcceptAdmin(e, address(cr), s);
        require(cr.admin() == uaD && cr.pendingAdmin() == bytes32(0), "registry: the derived UA is the admin");
        (e, s) = _auth(d, _ty("UASetKycProvider", "bytes32 provider,bool enabled"), address(cr), abi.encode(_pad(a3), true));
        vm.broadcast(k2);
        gr.mtxSetKycProvider(e, address(cr), _pad(a3), true, s);
        bytes32[] memory who = new bytes32[](1);
        uint64[] memory fl = new uint64[](1);
        uint64[] memory until = new uint64[](1);
        (who[0], fl[0], until[0]) = (_pad(a1), 3, type(uint64).max); // an admin row over the earlier admin row
        (e, s) = _auth(d, _ty("UASetCompliance", "bytes32[] accounts,uint64[] flags,uint64[] until"), address(cr),
            abi.encode(keccak256(abi.encodePacked(who)), keccak256(abi.encodePacked(fl)), keccak256(abi.encodePacked(until))));
        vm.broadcast(k2);
        gr.mtxSetCompliance(e, address(cr), who, fl, until, s);
    }

    // ------------------------------------------------------------------ kind 0 through the router

    function _plain() internal {
        IFactoryToken.TokenConfig memory c =
            _cfg("oG0", 1 << GovernanceBits.PAYABLE | 1 << GovernanceBits.MINTABLE | 1 << GovernanceBits.BURNABLE);
        c.roles.minter = _pad(a1);
        (c.initialSupply, c.initialHolder) = (1_000_000, a1);
        t0 = _create(IOpenFactory.TokenKind.NORMAL, c, "NormalToken");
        c.symbol = "oG0d";
        c.grantDelay = 1 days;
        t0d = _create(IOpenFactory.TokenKind.NORMAL, c, "NormalToken");
        IFactoryToken.TokenConfig memory r = _cfg("oG0r", 1 << GovernanceBits.PAYABLE);
        (r.initialSupply, r.initialHolder) = (1_000, a1);
        t0r = _create(IOpenFactory.TokenKind.NORMAL, r, "NormalToken");
        Sg memory o = _eoa(k1);
        MetaTxLib.UAEnvelope memory e;
        IUARegistry.UASig memory s;
        (e, s) = _auth(o, _ty("UAMint", "address to,uint256 amount"), t0, abi.encode(a3, uint256(100)));
        vm.broadcast(k2);
        gr.mtxMint(e, t0, a3, 100, s);
        // bound relayer (MODE_RESTRICT_RELAYER): only k2 may submit
        (e.from, e.nonce, e.validUntil, e.mode, e.relayer) = (o.from, gr.mtxNonce(o.from, 0), vu, MetaTxLib.MODE_RESTRICT_RELAYER, a2);
        s = _signR(o, _named(address(gr), _ty("UAMintToUA", "bytes32 to,uint256 amount"),
            bytes.concat(abi.encode(t0), abi.encode(uaD, uint256(100))), e));
        vm.broadcast(k2);
        gr.mtxMintToUA(e, t0, uaD, 100, s);
        (e, s) = _auth(o, _ty("UAGrantRole", "uint8 bit,bytes32 account"), t0, abi.encode(GovernanceBits.MINTABLE, _pad(a3)));
        vm.broadcast(k2);
        gr.mtxGrantRole(e, t0, GovernanceBits.MINTABLE, _pad(a3), s);
        (e, s) = _auth(o, _ty("UARevokeRole", "uint8 bit,bytes32 account"), t0, abi.encode(GovernanceBits.MINTABLE, _pad(a3)));
        vm.broadcast(k2);
        gr.mtxRevokeRole(e, t0, GovernanceBits.MINTABLE, _pad(a3), s);
        IGovernance.GrantTerms memory gt;
        (gt.min, gt.max, gt.total) = (1, 100, 1_000);
        (e, s) = _auth(o, string.concat(_ty("UASetGrant", "uint8 bit,bytes32 holder,GrantTerms terms"), TERMS_T), t0,
            abi.encode(GovernanceBits.MINTABLE, _pad(a2), keccak256(abi.encode(keccak256(bytes(TERMS_T)), gt))));
        vm.broadcast(k2);
        gr.mtxSetGrant(e, t0, GovernanceBits.MINTABLE, _pad(a2), gt, s);
        (e, s) = _auth(_eoa(k2), _ty("UARenounceRole", "uint8 bit"), t0, abi.encode(GovernanceBits.MINTABLE));
        vm.broadcast(k2);
        gr.mtxRenounceRole(e, t0, GovernanceBits.MINTABLE, s); // the limited holder renounces its own grant
        // a grant under grantDelay: the first call proposes, the cancel drops it
        (e, s) = _auth(o, _ty("UAGrantRole", "uint8 bit,bytes32 account"), t0d, abi.encode(GovernanceBits.MINTABLE, _pad(a3)));
        vm.broadcast(k2);
        gr.mtxGrantRole(e, t0d, GovernanceBits.MINTABLE, _pad(a3), s);
        (uint64 eta,,,) = IGovernance(t0d).pendingGrant(GovernanceBits.MINTABLE, _pad(a3));
        require(eta != 0, "pending grant");
        (e, s) = _auth(o, _ty("UACancelGrant", "uint8 bit,bytes32 account"), t0d, abi.encode(GovernanceBits.MINTABLE, _pad(a3)));
        vm.broadcast(k2);
        gr.mtxCancelGrant(e, t0d, GovernanceBits.MINTABLE, _pad(a3), s);
        // ownership: transfer, accept by the new owner, renounce
        (e, s) = _auth(o, _ty("UATransferAdmin", "bytes32 newAdmin"), t0r, abi.encode(uaD));
        vm.broadcast(k2);
        gr.mtxTransferAdmin(e, t0r, uaD, s);
        Sg memory du = Sg(uaD, kD, 2); // the registered UA signs through the registry
        (e, s) = _auth(du, _ty("UAAcceptAdmin", ""), t0r, "");
        vm.broadcast(k2);
        gr.mtxAcceptAdmin(e, t0r, s);
        (e, s) = _auth(du, _ty("UARenounceAdmin", ""), t0r, "");
        vm.broadcast(k2);
        gr.mtxRenounceAdmin(e, t0r, s);
        require(IGovernance(t0r).admin() == 0, "renounced");
        // the router's own lanes: a direct cancel and a signed one
        vm.broadcast(k2);
        gr.cancelNonce(7);
        e = _env(a1, 0, gr.mtxNonce(_pad(a1), 0));
        s = _signR(o, _named(address(gr),
            "UACancelNonce(bytes32 from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)",
            abi.encode(uint256(9)), e));
        vm.broadcast(k2);
        gr.mtxCancelNonce(e, 9, s);
    }

    // ------------------------------------------------------------------ kind 1 through the router (rate admin `iss`)

    function _wrapped() internal {
        IFactoryToken.TokenConfig memory c = _cfg("oG1", 1 << GovernanceBits.PAYABLE | 1 << GovernanceBits.MINTABLE
            | 1 << GovernanceBits.RATE_ADJUSTABLE | 1 << GovernanceBits.WRAP_DISABLEABLE);
        (c.roles.minter, c.roles.rateAdmin, c.roles.guardian) = (_pad(a1), _pad(iss), _pad(a1));
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(u), 1, 1);
        c.rate = IFactoryToken.RateConfig(2 days, 100);
        c.maxSupply = 1e15;
        t1 = _create(IOpenFactory.TokenKind.WRAPPED, c, "WrappedToken");
        Sg memory o = _eoa(k1);
        Sg memory ra = _skaSg(iss, pkI);
        MetaTxLib.UAEnvelope memory e;
        IUARegistry.UASig memory s;
        (e, s) = _auth(o, _ty("UAMint", "address to,uint256 amount"), t1, abi.encode(a3, uint256(50)));
        vm.broadcast(k2);
        gr.mtxMint(e, t1, a3, 50, s); // the hybrid's mint
        (e, s) = _auth(ra, _ty("UAProposeRate", "address leg,uint96 num,uint96 den"), t1,
            abi.encode(address(u), uint96(101), uint96(100)));
        vm.broadcast(k2);
        gr.mtxProposeRate{gas: SKA_SIG_GAS}(e, t1, address(u), 101, 100, s);
        (e, s) = _auth(ra, _ty("UACancelRate", ""), t1, "");
        vm.broadcast(k2);
        gr.mtxCancelRate{gas: SKA_SIG_GAS}(e, t1, s);
        (e, s) = _auth(ra, _ty("UAProposeRate", "address leg,uint96 num,uint96 den"), t1,
            abi.encode(address(u), uint96(101), uint96(100)));
        vm.broadcast(k2);
        gr.mtxProposeRate{gas: SKA_SIG_GAS}(e, t1, address(u), 101, 100, s); // stays pending: executeRate waits rateDelay (2 days), a negative
        bytes32 why = _ref();
        (e, s) = _auth(o, _ty("UADisableWrap", "address leg,bytes32 reason"), t1, abi.encode(address(u), why));
        vm.broadcast(k2);
        gr.mtxDisableWrap(e, t1, address(u), why, s);
        (e, s) = _auth(o, _ty("UADisableFeature", "uint8 bit"), t0, abi.encode(GovernanceBits.MINTABLE));
        vm.broadcast(k2);
        gr.mtxDisableFeature(e, t0, GovernanceBits.MINTABLE, s);
    }

    // ------------------------------------------------------------------ kind 8: the powers direct (the roles' accounts call)

    function _regCfg(string memory sym, bool wrapped) internal view returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(sym, 1 << GovernanceBits.PAYABLE | 1 << GovernanceBits.FREEZE | 1 << GovernanceBits.FORCE
            | 1 << GovernanceBits.PAUSE | 1 << GovernanceBits.RECORD | 1 << GovernanceBits.RESCUABLE
            | 1 << GovernanceBits.OPERATOR_TRANSFER | 1 << GovernanceBits.TAX);
        (c.roles.issuer, c.roles.compliance) = (_pad(iss), _pad(cmp));
        (c.reg.termsHash, c.reg.taxRecipient, c.rescueTo) = (keccak256("onchain terms"), _pad(a3), a3);
        if (wrapped) {
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(u), 1, 1);
        } else {
            c.features |= 1 << GovernanceBits.MINTABLE;
            c.roles.minter = _pad(a1);
            (c.initialSupply, c.initialHolder) = (1_000_000, a1);
        }
    }

    /// @dev The direct powers on kind 8, then on the Zether regulated kinds 10 and 11 (their public layer: the same
    ///      RegulatedLib entries through each release's own dispatch; BLS12-381 version 1, no auditor, as ZetherE2E).
    function _regulatedDirect() internal {
        t8 = _regulatedDirect(IOpenFactory.TokenKind.NORMAL_REGULATED, "oG8", false, false, "NormalRegulatedToken");
        _regulatedDirect(IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, "oG10", false, true, "NormalZetherRegulatedToken");
        _regulatedDirect(IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED, "oG11", true, true, "WrappedZetherRegulatedToken");
    }

    function _regulatedDirect(IOpenFactory.TokenKind kind, string memory sym, bool wrapped, bool zether, string memory label)
        internal returns (address t)
    {
        IFactoryToken.TokenConfig memory c = _regCfg(sym, wrapped);
        if (zether) c.conf = IFactoryToken.ConfidentialConfig("", 1, 1 << 40, 0, 0, 0, 0, 0, bytes32(0), false, 0, 0, 0);
        t = _create(kind, c, label);
        if (wrapped) {
            vm.startBroadcast(k1);
            u.approve(t, 100_000);
            IWrappedToken(t).wrap(100_000);
            vm.stopBroadcast();
        }
        vm.broadcast(k1);
        IERC20(t).transfer(a2, 1_000);
        bytes32 r = _ref();
        _skaExec(iss, pkI, t, abi.encodeCall(IRegulatedToken.freeze, (_pad(a3), r, bytes32(0))));
        require(IRegulatedToken(t).isFrozen(_pad(a3)), "frozen");
        _skaExec(iss, pkI, t, abi.encodeCall(IRegulatedToken.unfreeze, (_pad(a3), r)));
        _skaExec(iss, pkI, t, abi.encodeCall(IRegulatedToken.pause, (r, uint64(block.timestamp + 1 hours))));
        _skaExec(iss, pkI, t, abi.encodeCall(IRegulatedToken.unpause, (r)));
        bytes32 oid = _ref();
        _skaExec(cmp, pkC, t, abi.encodeCall(IRegulatedToken.recordOrder,
            (oid, keccak256("order doc"), _pad(a2), _pad(a3), uint256(100), uint64(block.timestamp + 1 days))));
        bytes32 rid = keccak256(abi.encode(oid, _pad(a2), _pad(a3)));
        _skaExec(iss, pkI, t, abi.encodeCall(IRegulatedToken.freeze, (_pad(a2), r, rid)));
        _skaExec(iss, pkI, t, abi.encodeCall(IRegulatedToken.forceTransfer, (rid, uint256(40))));
        _skaExec(cmp, pkC, t, abi.encodeCall(IRegulatedToken.revokeOrder, (rid, _ref())));
        require(!IRegulatedToken(t).isFrozen(_pad(a2)), "revoke ends the record freeze");
        _skaExec(iss, pkI, t, abi.encodeCall(IRegulatedToken.setTaxRate, (uint32(1_000))));
        _skaExec(iss, pkI, t, abi.encodeCall(IRegulatedToken.setTaxRecipient, (_pad(a1))));
        vm.broadcast(k1);
        IGovernance(t).grantRole(GovernanceBits.OPERATOR_TRANSFER, _pad(a1)); // any holder (bit 22)
        vm.broadcast(k1);
        IRegulatedToken(t).operatorTransfer(_pad(a2), _pad(a3), 10, _ref());
        vm.broadcast(k1);
        u2.mint(t, 77); // a stray asset
        vm.broadcast(k2);
        IRescuable(t).rescue(address(u2)); // anyone, to rescueTo
        vm.broadcast(k1);
        IGovernance(t).disableFeature(GovernanceBits.PAUSE); // the regulated override clears the control
    }

    // ------------------------------------------------------------------ kind 9: the powers through the router

    function _regulatedRouter() internal {
        t9 = _create(IOpenFactory.TokenKind.WRAPPED_REGULATED, _regCfg("oG9", true), "WrappedRegulatedToken");
        vm.startBroadcast(k1);
        u.approve(t9, 100_000);
        IWrappedToken(t9).wrap(100_000);
        IERC20(t9).transfer(a2, 1_000);
        vm.stopBroadcast();
        Sg memory is_ = _skaSg(iss, pkI);
        Sg memory cm = _skaSg(cmp, pkC);
        Sg memory o = _eoa(k1);
        MetaTxLib.UAEnvelope memory e;
        IUARegistry.UASig memory s;
        bytes32 r = _ref();
        (e, s) = _auth(is_, _ty("UAFreeze", "bytes32 account,bytes32 ref,bytes32 recordId"), t9, abi.encode(_pad(a3), r, bytes32(0)));
        vm.broadcast(k2);
        gr.mtxFreeze{gas: SKA_SIG_GAS}(e, t9, _pad(a3), r, 0, s);
        (e, s) = _auth(is_, _ty("UAUnfreeze", "bytes32 account,bytes32 ref"), t9, abi.encode(_pad(a3), r));
        vm.broadcast(k2);
        gr.mtxUnfreeze{gas: SKA_SIG_GAS}(e, t9, _pad(a3), r, s);
        uint64 until = uint64(block.timestamp + 1 hours);
        (e, s) = _auth(is_, _ty("UAPause", "bytes32 ref,uint64 until"), t9, abi.encode(r, until));
        vm.broadcast(k2);
        gr.mtxPause{gas: SKA_SIG_GAS}(e, t9, r, until, s);
        (e, s) = _auth(is_, _ty("UAUnpause", "bytes32 ref"), t9, abi.encode(r));
        vm.broadcast(k2);
        gr.mtxUnpause{gas: SKA_SIG_GAS}(e, t9, r, s);
        _routerOrder(cm, is_);
        (e, s) = _auth(is_, _ty("UASetTaxRate", "uint32 ratePpm"), t9, abi.encode(uint32(500)));
        vm.broadcast(k2);
        gr.mtxSetTaxRate{gas: SKA_SIG_GAS}(e, t9, 500, s);
        (e, s) = _auth(is_, _ty("UASetTaxRecipient", "bytes32 taxRecipient"), t9, abi.encode(_pad(a1)));
        vm.broadcast(k2);
        gr.mtxSetTaxRecipient{gas: SKA_SIG_GAS}(e, t9, _pad(a1), s);
        (e, s) = _auth(o, _ty("UAGrantRole", "uint8 bit,bytes32 account"), t9, abi.encode(GovernanceBits.OPERATOR_TRANSFER, _pad(a1)));
        vm.broadcast(k2);
        gr.mtxGrantRole(e, t9, GovernanceBits.OPERATOR_TRANSFER, _pad(a1), s);
        bytes32 r2 = _ref();
        (e, s) = _auth(o, _ty("UAOperatorTransfer", "bytes32 account,bytes32 to,uint256 amount,bytes32 ref"), t9,
            abi.encode(_pad(a2), _pad(a3), uint256(5), r2));
        vm.broadcast(k2);
        gr.mtxOperatorTransfer(e, t9, _pad(a2), _pad(a3), 5, r2, s);
        (e, s) = _auth(o, _ty("UADisableFeature", "uint8 bit"), t9, abi.encode(GovernanceBits.PAUSE));
        vm.broadcast(k2);
        gr.mtxDisableFeature(e, t9, GovernanceBits.PAUSE, s);
        vm.broadcast(k1);
        u2.mint(t9, 33);
        vm.broadcast(k2);
        IRescuable(t9).rescue(address(u2));
        // the last power on t9: the owner a1 frozen (a negative transfers from it)
        bytes32 r3 = _ref();
        (e, s) = _auth(is_, _ty("UAFreeze", "bytes32 account,bytes32 ref,bytes32 recordId"), t9, abi.encode(_pad(a1), r3, bytes32(0)));
        vm.broadcast(k2);
        gr.mtxFreeze{gas: SKA_SIG_GAS}(e, t9, _pad(a1), r3, 0, s);
    }

    function _routerOrder(Sg memory cm, Sg memory is_) internal {
        MetaTxLib.UAEnvelope memory e;
        IUARegistry.UASig memory s;
        bytes32 oid = _ref();
        uint64 fu = uint64(block.timestamp + 1 days);
        (e, s) = _auth(cm, _ty("UARecordOrder",
            "bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,uint256 maxAmount,uint64 freezeUntil"), t9,
            abi.encode(oid, keccak256("order doc"), _pad(a2), _pad(a3), uint256(100), fu));
        vm.broadcast(k2);
        gr.mtxRecordOrder{gas: SKA_SIG_GAS}(e, t9, oid, keccak256("order doc"), _pad(a2), _pad(a3), 100, fu, s);
        bytes32 rid = keccak256(abi.encode(oid, _pad(a2), _pad(a3)));
        bytes32 r = _ref();
        (e, s) = _auth(is_, _ty("UAFreeze", "bytes32 account,bytes32 ref,bytes32 recordId"), t9, abi.encode(_pad(a2), r, rid));
        vm.broadcast(k2);
        gr.mtxFreeze{gas: SKA_SIG_GAS}(e, t9, _pad(a2), r, rid, s);
        (e, s) = _auth(is_, _ty("UAForceTransfer", "bytes32 recordId,uint256 amount"), t9, abi.encode(rid, uint256(30)));
        vm.broadcast(k2);
        gr.mtxForceTransfer{gas: SKA_SIG_GAS}(e, t9, rid, 30, s);
        bytes32 why = _ref();
        (e, s) = _auth(cm, _ty("UARevokeOrder", "bytes32 recordId,bytes32 reasonRef"), t9, abi.encode(rid, why));
        vm.broadcast(k2);
        gr.mtxRevokeOrder{gas: SKA_SIG_GAS}(e, t9, rid, why, s);
    }

    // ------------------------------------------------------------------ the DEX setters and the factory's creations

    function _dexAndCreations() internal {
        bytes memory init = abi.encode(ISCaaSDex.DexConfig(_pad(a1), 0, a1, false, 0, address(0)));
        vm.broadcast(k1);
        dex = f.createDex(1, init, _salt("dex"));
        _book(dex, "SCaaSDex");
        Sg memory o = _eoa(k1);
        MetaTxLib.UAEnvelope memory e;
        IUARegistry.UASig memory s;
        (e, s) = _auth(o, _ty("UASetMarket", "address base,address quote,bool listed"), dex, abi.encode(t0, t8, true));
        vm.broadcast(k2);
        gr.mtxSetMarket(e, dex, t0, t8, true, s);
        (e, s) = _auth(o, _ty("UASetExchangeTarget", "address exchangeTarget,bool listed"), dex, abi.encode(address(u), true));
        vm.broadcast(k2);
        gr.mtxSetExchangeTarget(e, dex, address(u), true, s);
        (e, s) = _auth(o, _ty("UASetListedOnly", "bool on"), dex, abi.encode(true));
        vm.broadcast(k2);
        gr.mtxSetListedOnly(e, dex, true, s);
        (e, s) = _auth(o, _ty("UASetFeeSplit", "uint32 relayerSharePpm,address treasury"), dex, abi.encode(uint32(1_000), a1));
        vm.broadcast(k2);
        gr.mtxSetFeeSplit(e, dex, 1_000, a1, s);
        // the creations: the factory reads the router's subject as the creator
        bytes32 salt = _salt("router dex");
        (e, s) = _auth(o, _ty("UACreateDex", "uint64 version,bytes32 initHash,bytes32 salt"), address(f),
            abi.encode(uint64(1), keccak256(init), salt));
        vm.broadcast(k2);
        gr.mtxCreateDex(e, address(f), 1, init, salt, s);
        IFactoryToken.TokenConfig memory c = _cfg("oGR0", 1 << GovernanceBits.PAYABLE);
        (c.initialSupply, c.initialHolder) = (1_000, a1);
        bytes memory ti = abi.encode(c);
        salt = _salt("router token");
        (e, s) = _auth(o, _ty("UACreateToken", "uint8 kind,uint64 version,bytes32 initHash,bytes32 salt"), address(f),
            abi.encode(uint8(IOpenFactory.TokenKind.NORMAL), uint64(1), keccak256(ti), salt));
        vm.broadcast(k2);
        gr.mtxCreateToken(e, address(f), IOpenFactory.TokenKind.NORMAL, 1, ti, salt, s);
        address made = f.predictAddress(_pad(a1), f.CLASS_TOKEN(), uint16(IOpenFactory.TokenKind.NORMAL), salt);
        require(made.code.length != 0, "router-created token");
        _book(made, "NormalToken");
    }

    // ------------------------------------------------------------------ a router op relayed with a fee (RelayFeeRouter)

    function _relayFee() internal {
        RelayFeeRouter rf = RelayFeeRouter(_dep("relay_fee_router"));
        _book(address(rf), "RelayFeeRouter");
        _book(_dep("relay_fee_executor"), "RelayFeeExecutor");
        // the inner router op (a1 signs, open relayer: the executor submits it); the fee: 1 unit of t8 from a1
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory s) =
            _auth(_eoa(k1), _ty("UAGrantRole", "uint8 bit,bytes32 account"), t8, abi.encode(GovernanceBits.OPERATOR_TRANSFER, _pad(a2)));
        bytes memory cd = abi.encodeWithSelector(gr.mtxGrantRole.selector, e, t8, GovernanceBits.OPERATOR_TRANSFER, _pad(a2), s);
        uint256 fn = IUALedgerViews(t8).mtxNonce(_pad(a1), 2);
        IUARegistry.UASig memory fs = _relayFeeSig(address(rf), cd, fn);
        vm.broadcast(k2);
        rf.relay(address(gr), cd, t8, _pad(a1), _pad(address(rf)), 1, 2, fn, vu, fs);
        require(IGovernance(t8).hasRole(GovernanceBits.OPERATOR_TRANSFER, _pad(a2)), "relayed grant");
    }

    /// @dev a1's `UARelayFee` of 1 unit of t8 (lane 2, payee the router: open mode, paid to the caller), as Smoke.s.sol.
    function _relayFeeSig(address rf, bytes memory cd, uint256 fn) internal view returns (IUARegistry.UASig memory fs) {
        bytes memory h = abi.encode(UA_RELAY_FEE, _pad(a1), address(gr), keccak256(cd), _pad(rf));
        h = bytes.concat(h, abi.encode(uint256(1), uint256(2), fn, vu, rf));
        fs.signature = _ecdsa(k1, _digest(t8, keccak256(h)));
    }

    // ------------------------------------------------------------------ SmartKeyAccount's own entries (`acct`, guardian a2)

    function _ae(uint256 batch) internal view returns (MetaTxLib.Envelope memory) {
        return _aenv(acct, batch, SmartKeyAccount(payable(acct)).mtxNonce(acct, batch));
    }

    function _as(uint256 index, uint256 pk, bytes32 d) internal pure returns (AccountSig memory) {
        return AccountSig(index, new bytes32[](0), _ecdsa(pk, d));
    }

    function _ab(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        return abi.encode(uint256(0), new bytes32[](0), _ecdsa(pk, d));
    }

    function _meta(bytes memory data) internal view returns (MetaTxLib.MetaTransaction memory m) {
        (m.from, m.data, m.nonce, m.validUntil) = (acct, data, SmartKeyAccount(payable(acct)).mtxNonce(acct, 0), vu);
    }

    function _account() internal {
        SmartKeyAccount A = SmartKeyAccount(payable(acct));
        uint256 pkB = _key("acct B", N_K1);
        uint256 pkC2 = _key("acct C", N_K1);
        _accountExec(A);
        _accountKeys(A, pkB, pkC2);
        // the self entries through the generic path: addKey, rotateKey, removeKey, setGuardian, cancelRecovery
        _selfKeys(A, pkB, pkC2);
        _passkey(A);
        _recovery(A);
        // lanes: a direct cancel (k2's own lane on the account) and a signed one of the account's lane 3
        vm.broadcast(k2);
        A.cancelNonce(4);
        MetaTxLib.Envelope memory e = _ae(0);
        bytes32 d = _namedA(acct,
            "CancelNonce(address from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)",
            abi.encode(uint256(3)), e);
        vm.broadcast(k2);
        A.mtxCancelNonce(e, 3, _ab(pkA, d));
    }

    function _accountExec(SmartKeyAccount A) internal {
        bytes memory mintCall = abi.encodeCall(MockERC20.mint, (acct, 5));
        // named execute (key 0)
        MetaTxLib.Envelope memory e = _ae(0);
        bytes32 d = _namedA(acct, EXECUTE_T, abi.encode(address(u), uint256(0), keccak256(mintCall)), e);
        vm.broadcast(k2);
        A.mtxExecute(e, address(u), 0, mintCall, _as(0, pkA, d));
        // the generic forms: mtxExecute(MetaTransaction), executeMetaTransaction, mtxBatch, mtxExecuteAsOwner
        bytes memory ex = abi.encodeCall(SmartKeyAccount.execute, (address(u), 0, mintCall));
        MetaTxLib.MetaTransaction memory m = _meta(ex);
        sgx = _ab(pkA, A.mtxDigest(m));
        vm.broadcast(k2);
        A.mtxExecute(m, sgx);
        m = _meta(ex);
        sgx = _ab(pkA, A.mtxDigest(m));
        vm.broadcast(k2);
        A.executeMetaTransaction(m, sgx);
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](2);
        bytes[] memory ss = new bytes[](2);
        ms[0] = _meta(ex);
        ms[1] = _meta(ex);
        ms[1].nonce += 1;
        (ss[0], ss[1]) = (_ab(pkA, A.mtxDigest(ms[0])), _ab(pkA, A.mtxDigest(ms[1])));
        vm.broadcast(k2);
        A.mtxBatch(ms, ss);
        m = _meta(ex);
        sgx = _ab(pkA, A.mtxDigest(m));
        vm.broadcast(k2);
        A.mtxExecuteAsOwner(ex, m.nonce, vu, sgx);
    }

    string constant ADD_KEY_T =
        "AddKey(address from,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string constant ROTATE_KEY_T =
        "RotateKey(address from,uint256 index,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

    function _kw(SubjectKey memory k) internal pure returns (bytes memory) {
        return abi.encode(uint8(k.kind), k.x, k.y, k.rpIdHash, k.originHash);
    }

    /// @dev `mtxAddKey` of `k`, signed by key `si` (its secp256k1 private key `pk`).
    function _addNamed(SmartKeyAccount A, SubjectKey memory k, uint256 si, uint256 pk) internal returns (uint256) {
        MetaTxLib.Envelope memory e = _ae(0);
        AccountSig memory sg = _as(si, pk, _namedA(acct, ADD_KEY_T, _kw(k), e));
        vm.broadcast(k2);
        A.mtxAddKey(e, uint8(k.kind), k.x, k.y, k.rpIdHash, k.originHash, sg);
        return A.nextKeyIndex() - 1;
    }

    /// @dev Keys: add B (named), rotate B -> C (named, B signs), remove C (named, C signs).
    function _accountKeys(SmartKeyAccount A, uint256 pkB, uint256 pkC2) internal {
        uint256 ib = _addNamed(A, _secp(pkB), 0, pkA);
        SubjectKey memory kc = _secp(pkC2);
        MetaTxLib.Envelope memory e = _ae(0);
        AccountSig memory sg = _as(ib, pkB, _namedA(acct, ROTATE_KEY_T, bytes.concat(abi.encode(ib), _kw(kc)), e));
        vm.broadcast(k2);
        A.mtxRotateKey(e, ib, uint8(kc.kind), kc.x, kc.y, kc.rpIdHash, kc.originHash, sg);
        uint256 ic = A.nextKeyIndex() - 1;
        e = _ae(0);
        sg = _as(ic, pkC2, _namedA(acct,
            "RemoveKey(address from,uint256 index,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)",
            abi.encode(ic), e));
        vm.broadcast(k2);
        A.mtxRemoveKey(e, ic, sg);
    }

    function _selfKeys(SmartKeyAccount A, uint256 pkB, uint256 pkC2) internal {
        MetaTxLib.MetaTransaction memory m = _meta(abi.encodeCall(SmartKeyAccount.addKey, (_secp(pkB))));
        sgx = _ab(pkA, A.mtxDigest(m));
        vm.broadcast(k2);
        A.mtxExecute(m, sgx);
        uint256 ib = A.nextKeyIndex() - 1;
        m = _meta(abi.encodeCall(SmartKeyAccount.rotateKey, (ib, _secp(pkC2))));
        sgx = _ab(pkA, A.mtxDigest(m));
        vm.broadcast(k2);
        A.mtxExecute(m, sgx);
        m = _meta(abi.encodeCall(SmartKeyAccount.removeKey, (A.nextKeyIndex() - 1)));
        sgx = _ab(pkA, A.mtxDigest(m));
        vm.broadcast(k2);
        A.mtxExecute(m, sgx);
    }

    /// @dev A WebAuthn P-256 key added (named), then signing a named execute itself.
    function _passkey(SmartKeyAccount A) internal {
        uint256 pkP = _key("p256", N_P256);
        (uint256 x, uint256 y) = vm.publicKeyP256(pkP);
        bytes32 rp = sha256(bytes(RP_ID));
        _addNamed(A, SubjectKey(KeyKind.P256_WEBAUTHN, bytes32(x), bytes32(y), rp, keccak256(bytes(ORIGIN))), 0, pkA);
        uint256 ip = A.nextKeyIndex() - 1;
        bytes memory mintCall = abi.encodeCall(MockERC20.mint, (acct, 1));
        MetaTxLib.Envelope memory e = _ae(0);
        AccountSig memory sg = AccountSig(ip, new bytes32[](0),
            _webauthn(pkP, rp, _namedA(acct, EXECUTE_T, abi.encode(address(u), uint256(0), keccak256(mintCall)), e)));
        vm.broadcast(k2);
        A.mtxExecute(e, address(u), 0, mintCall, sg);
    }

    /// @dev A WebAuthn assertion over `d` (the challenge), low-s, as the account decodes it.
    function _webauthn(uint256 pkP, bytes32 rp, bytes32 d) internal pure returns (bytes memory) {
        bytes memory authData = abi.encodePacked(rp, bytes1(0x05), uint32(0));
        bytes memory clientData = abi.encodePacked('{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(d)),
            '","origin":"', ORIGIN, '"}');
        (bytes32 r, bytes32 s) = vm.signP256(pkP, sha256(abi.encodePacked(authData, sha256(clientData))));
        if (uint256(s) > N_P256 / 2) s = bytes32(N_P256 - uint256(s));
        return abi.encode(authData, clientData, r, s);
    }

    /// @dev Guardian a2 -> a3 (named), a3 starts a recovery, the account cancels it (named), a3 starts one again, the account
    ///      cancels it (the self entry), the guardian set back by the self entry, a last recovery left pending (its
    ///      `completeRecovery` waits RECOVERY_DELAY, two days: a negative).
    function _recovery(SmartKeyAccount A) internal {
        MetaTxLib.Envelope memory e = _ae(0);
        bytes32 d = _namedA(acct,
            "SetGuardian(address from,address guardian,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)",
            abi.encode(a3), e);
        vm.broadcast(k2);
        A.mtxSetGuardian(e, a3, _as(0, pkA, d));
        SubjectKey memory kr = _secp(_key("recovery", N_K1));
        vm.broadcast(k3);
        A.initiateRecovery(kr);
        e = _ae(0);
        d = _namedA(acct,
            "CancelRecovery(address from,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)",
            "", e);
        vm.broadcast(k2);
        A.mtxCancelRecovery(e, _as(0, pkA, d));
        vm.broadcast(k3);
        A.initiateRecovery(kr);
        MetaTxLib.MetaTransaction memory m = _meta(abi.encodeCall(SmartKeyAccount.cancelRecovery, ()));
        sgx = _ab(pkA, A.mtxDigest(m));
        vm.broadcast(k2);
        A.mtxExecute(m, sgx);
        m = _meta(abi.encodeCall(SmartKeyAccount.setGuardian, (a3)));
        sgx = _ab(pkA, A.mtxDigest(m));
        vm.broadcast(k2);
        A.mtxExecute(m, sgx);
        vm.broadcast(k3);
        A.initiateRecovery(kr);
    }

    // ------------------------------------------------------------------ negatives (eth_call on the final state)

    function _negatives() internal {
        // the regulated refusal: a1 is frozen on t9
        _neg(a1, t9, abi.encodeCall(IERC20.transfer, (a3, 1)), IRegulatedToken.Frozen.selector, "transfer from a frozen account (kind 9)");
        // not attested on the allow-listed token
        _neg(a1, tc, abi.encodeCall(IERC20.transfer, (address(0xdEaD), 1)), IRegulatedToken.NotEligible.selector,
            "transfer to an account the ComplianceRegistry does not attest (kind 8, KYC)");
        // the guard: a governed entry by a non-owner
        _neg(a3, t8, abi.encodeCall(IGovernance.grantRole, (GovernanceBits.OPERATOR_TRANSFER, _pad(a3))), IAdmin.NotAdmin.selector,
            "grantRole by a non-owner (kind 8)");
        // a router op signed by another key than its `from`
        MetaTxLib.UAEnvelope memory e = _env(a1, 0, gr.mtxNonce(_pad(a1), 0));
        IUARegistry.UASig memory s = _signR(_eoa(k2), _named(address(gr), _ty("UAMint", "address to,uint256 amount"),
            abi.encode(t1, a3, uint256(1)), e)); // k2 signs a1's op
        _neg(a2, address(gr), abi.encodeCall(GovernanceRouter.mtxMint, (e, t1, a3, 1, s)), IMetaTx.MetaTxBadSignature.selector,
            "router op whose signature is not its from's");
        // the rate change waits rateDelay (2 days): executeRate refused before its eta
        (e, s) = _auth(_skaSg(iss, pkI), _ty("UAExecuteRate", ""), t1, "");
        (,,, uint64 eta) = WrappedPending(t1).pendingRate();
        _neg(a2, address(gr), abi.encodeCall(GovernanceRouter.mtxExecuteRate, (e, t1, s)), IWrappedToken.RateChangeNotReady.selector,
            string.concat("mtxExecuteRate before the eta ", vm.toString(uint256(eta))));
        // no class release on the Step 5 factory
        bytes memory ic = abi.encodeWithSignature("initialize(bytes32,string)", _pad(a1), "note");
        (e, s) = _auth(_eoa(k1), _ty("UACreateInstance", "uint16 contractClass,uint16 kind,uint64 version,bytes32 initHash,bytes32 salt"),
            address(f), abi.encode(uint16(4), uint16(0), uint64(1), keccak256(ic), _salt("instance")));
        _neg(a2, address(gr), abi.encodeCall(GovernanceRouter.mtxCreateInstance, (e, address(f), 4, 0, 1, ic, _salt("instance"), s)),
            IOpenFactory.ReleaseUnknown.selector, "mtxCreateInstance with no class release on this factory");
        // the router has no generic path (governance spec §3.6, B-14)
        MetaTxLib.UAMetaTransaction memory um;
        (um.from, um.data, um.nonce, um.validUntil) = (_pad(a1), abi.encodeCall(IGovernance.grantRole, (1, _pad(a3))), 0, vu);
        IUARegistry.UASig memory none;
        _neg(a2, address(gr), abi.encodeWithSelector(gr.mtxExecute.selector, um, none), IMetaTx.MtxSelectorNotAllowed.selector,
            "router mtxExecute (no generic path)");
        MetaTxLib.UAMetaTransaction[] memory ums = new MetaTxLib.UAMetaTransaction[](1);
        IUARegistry.UASig[] memory nones = new IUARegistry.UASig[](1);
        ums[0] = um;
        _neg(a2, address(gr), abi.encodeWithSelector(gr.mtxBatch.selector, ums, nones), IMetaTx.MtxSelectorNotAllowed.selector,
            "router mtxBatch (no generic path)");
        MetaTxLib.MetaTransaction memory am;
        (am.from, am.data, am.validUntil) = (a1, um.data, vu);
        _neg(a2, address(gr), abi.encodeWithSelector(gr.executeMetaTransaction.selector, am, bytes("")), IMetaTx.MtxSelectorNotAllowed.selector,
            "router executeMetaTransaction (no generic path)");
        // the account: recovery not ready; initialize only by its factory
        SubjectKey memory kr = _secp(_key("recovery", N_K1));
        _neg(a3, acct, abi.encodeCall(SmartKeyAccount.completeRecovery, (kr)), SmartKeyAccount.RecoveryNotReady.selector,
            "completeRecovery before RECOVERY_DELAY");
        _neg(a2, acct, abi.encodeCall(SmartKeyAccount.initialize, (kr, address(0))), SmartKeyAccount.NotFactory.selector,
            "initialize by another caller than the factory");
        // compliance: a non-admin, non-provider
        _neg(a3, address(cr), abi.encodeCall(ComplianceRegistry.setKycProvider, (_pad(a3), true)), IAdmin.NotAdmin.selector,
            "setKycProvider by a non-admin");
    }
}

interface WrappedPending {
    function pendingRate() external view returns (address, uint96, uint96, uint64);
}
