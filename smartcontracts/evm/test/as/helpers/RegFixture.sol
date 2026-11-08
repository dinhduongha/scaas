// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm, VmSafe} from "forge-std/Vm.sol";
import {OpenFactory} from "../../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {MetaTokenBase} from "../../../src/metatx/MetaTokenBase.sol";
import {NormalToken} from "../../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../../src/metatx/WrappedToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {NormalRegulatedToken} from "../../../src/regulated/NormalRegulatedToken.sol";
import {WrappedRegulatedToken} from "../../../src/regulated/WrappedRegulatedToken.sol";
import {ComplianceRegistry} from "../../../src/regulated/ComplianceRegistry.sol";
import {MockERC20, StubUARegistry} from "../../helpers/Mocks.sol";
import {MtxDigest} from "../../helpers/MtxDigest.sol";
import {Catalogue, plainEnv, regArgs} from "../../helpers/Catalogue.sol";
import {nid} from "../../helpers/Ids.sol";

/// A contract id for the contract-only bits 5-7, 10 (`_check` reads its code only); it acts through `vm.prank`.
contract Holder {}

/// Plan T28's fixture (regulated-kinds spec §2.4, §3): one factory with the releases of kinds 8 and 9 (and their bases 0, 1
/// for the controls), a UA registry stand-in (every derived id a SIGNING UA), and one token of each regulated kind with
/// `FREEZE`, `FORCE`, `PAUSE`, `RECORD`: the issuer and the compliance holders are two contracts (`FORCE` and `RECORD` never
/// one id), the owner an EOA, `grantDelay` one day; `alice` holds 1,000,000 units of each. Plan T29: one canonical
/// `ComplianceRegistry` (`creg`, its admin the contract `cadmin`, one enabled attester `attester`), and `_listed` for a token
/// of kind 8 or 9 with `ALLOWLIST` / `DENYLIST` on it.
abstract contract RegFixture is Test {
    uint256 internal constant ALICE_PK = 0xA11CE;
    uint256 internal constant BOB_PK = 0xB0B;
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    bytes32 internal constant REF = bytes32(uint256(0x5EF));
    bytes32 internal constant TERMS = keccak256("terms");
    uint64 internal constant GD = 1 days;
    uint256 internal constant SUPPLY = 1_000_000;
    uint256 internal constant REG_FEATURES = (1 << 5) | (1 << 6) | (1 << 7) | (1 << 10);
    /// A derived UA id (top 96 bits set): the stub registry calls it a SIGNING UA.
    bytes32 internal constant UA_X = 0xcafe00000000000000000000000000000000000000000000000000000000a11a;

    address internal alice = vm.addr(ALICE_PK);
    address internal bob = vm.addr(BOB_PK);
    address internal ownerA = address(0x0A11);
    address internal relayer = address(0xBEEF);
    address internal issuer;
    address internal compliance;
    OpenFactory internal f;
    StubUARegistry internal ureg;
    MockERC20 internal usd;
    address internal t8;
    address internal t9;
    ComplianceRegistry internal creg;
    address internal cadmin;
    address internal attester = address(0xA77E);
    uint64 internal constant KYC = 1;
    uint64 internal constant SANCTIONED = 1 << 16; // an issuer-defined flag (16-63)
    uint64 internal constant ELIGIBLE = 8; // ELIGIBLE_CONTRACT (CTR-AS-16)

    function _hedera() internal view virtual returns (bool) { return false; }

    function setUp() public virtual {
        vm.warp(1_800_000_000);
        f = new OpenFactory(address(this), UID, 0);
        ureg = new StubUARegistry(UID);
        bool h = _hedera();
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(ureg), address(0), h);
        Catalogue.plain(f, IOpenFactory.TokenKind.WRAPPED, 1, type(WrappedToken).creationCode, address(ureg), address(0), h);
        Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_REGULATED, 1, plainEnv(address(f), address(0), UID, address(ureg), h),
            type(NormalRegulatedToken).creationCode, regArgs());
        Catalogue.release(f, IOpenFactory.TokenKind.WRAPPED_REGULATED, 1, plainEnv(address(f), address(0), UID, address(ureg), h),
            type(WrappedRegulatedToken).creationCode, regArgs());
        f.setKindEnabled(IOpenFactory.TokenKind.NORMAL_REGULATED, true);
        f.setKindEnabled(IOpenFactory.TokenKind.WRAPPED_REGULATED, true);
        issuer = address(new Holder());
        compliance = address(new Holder());
        usd = new MockERC20("USD", "USD", 0);
        t8 = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(_cfg8()), "t8");
        t9 = f.createToken(IOpenFactory.TokenKind.WRAPPED_REGULATED, 1, abi.encode(_cfg9()), "t9");
        _wrapFor(t9, alice, SUPPLY);
        cadmin = address(new Holder());
        creg = new ComplianceRegistry(cadmin);
        vm.prank(cadmin);
        creg.setAttester(attester, true);
    }

    /// A token of kind 8 (`i == 0`, `SUPPLY` minted to `alice`, who is attested `KYC` first) or 9 (`alice` wraps `SUPPLY`)
    /// as the fixture's, with `ALLOWLIST` (`required`, 0 = off) and `DENYLIST` (`denied`, 0 = off) on `creg`.
    function _listed(uint256 i, uint64 required, uint64 denied, bytes32 salt) internal returns (address t) {
        IFactoryToken.TokenConfig memory c = i == 0 ? _cfg8() : _cfg9();
        if (required != 0) c.features |= 1 << GovernanceBits.ALLOWLIST;
        if (denied != 0) c.features |= 1 << GovernanceBits.DENYLIST;
        (c.reg.complianceRegistry, c.reg.requiredFlags, c.reg.deniedFlags) = (address(creg), required, denied);
        _attest(nid(alice), KYC, type(uint64).max);
        t = f.createToken(i == 0 ? IOpenFactory.TokenKind.NORMAL_REGULATED : IOpenFactory.TokenKind.WRAPPED_REGULATED, 1,
            abi.encode(c), salt);
        if (i == 1) _wrapFor(t, alice, SUPPLY);
    }

    /// `attester` attests `a` with `flags` until `until`.
    function _attest(bytes32 a, uint64 flags, uint64 until) internal {
        _attestAs(attester, a, flags, until);
    }

    /// Clears `bob`'s attestation left by an earlier loop round (the admin attests 0, 0).
    function _clearBob() internal {
        _attestAs(cadmin, nid(bob), 0, 0);
    }

    /// Counts the registry's `STATICCALL`s (selector `sel`, 0 = any) between `_countStart` and `_countEnd`.
    function _countStart() internal {
        vm.startStateDiffRecording();
    }

    function _countEnd(bytes4 sel) internal returns (uint256 n) {
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        for (uint256 k; k < acc.length; ++k) {
            if (acc[k].account == address(creg) && acc[k].kind == VmSafe.AccountAccessKind.StaticCall
                && (sel == 0 || bytes4(acc[k].data) == sel)) ++n;
        }
    }

    function _attestAs(address who, bytes32 a, uint64 flags, uint64 until) internal {
        bytes32[] memory as_ = new bytes32[](1);
        uint64[] memory fl = new uint64[](1);
        uint64[] memory vu = new uint64[](1);
        (as_[0], fl[0], vu[0]) = (a, flags, until);
        vm.prank(who);
        creg.attest(as_, fl, vu);
    }

    /// Kind 8: `PAYABLE | MINTABLE | BURNABLE` and the four controls; this test the minter; `SUPPLY` minted to `alice`.
    function _cfg8() internal view returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol) = ("Reg", "REG");
        c.features = (1 << GovernanceBits.PAYABLE) | (1 << GovernanceBits.MINTABLE) | (1 << GovernanceBits.BURNABLE)
            | REG_FEATURES;
        c.owner = nid(ownerA);
        c.grantDelay = GD;
        (c.roles.minter, c.roles.issuer, c.roles.compliance) = (nid(address(this)), nid(issuer), nid(compliance));
        (c.initialSupply, c.initialHolder) = (SUPPLY, alice);
        c.reg.termsHash = TERMS;
    }

    /// Kind 9: one leg `usd` at 1:1, `PAYABLE` and the four controls.
    function _cfg9() internal view returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol) = ("WReg", "WREG");
        c.features = (1 << GovernanceBits.PAYABLE) | REG_FEATURES;
        c.owner = nid(ownerA);
        c.grantDelay = GD;
        (c.roles.issuer, c.roles.compliance) = (nid(issuer), nid(compliance));
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.reg.termsHash = TERMS;
    }

    function _wrapFor(address t, address who, uint256 v) internal {
        usd.mint(who, v);
        vm.startPrank(who);
        usd.approve(t, v);
        WrappedToken(payable(t)).wrap(v);
        vm.stopPrank();
    }

    function _ks() internal view returns (address[2] memory) {
        return [t8, t9];
    }

    function _r(address t) internal pure returns (IRegulatedToken) {
        return IRegulatedToken(t);
    }

    // ------------------------------------------------------------------ the controls, as their holders

    function _freeze(address t, bytes32 a) internal {
        vm.prank(issuer);
        _r(t).freeze(a, REF, 0);
    }

    function _freezeRecord(address t, bytes32 a, bytes32 recordId) internal {
        vm.prank(issuer);
        _r(t).freeze(a, REF, recordId);
    }

    function _unfreeze(address t, bytes32 a) internal {
        vm.prank(issuer);
        _r(t).unfreeze(a, REF);
    }

    function _pause(address t, uint64 until) internal {
        vm.prank(issuer);
        _r(t).pause(REF, until);
    }

    /// Records order `orderId` against `subject` for `beneficiary`; returns its `recordId`.
    function _order(address t, bytes32 orderId, bytes32 subject, bytes32 beneficiary, uint256 maxAmount, uint64 freezeUntil)
        internal returns (bytes32)
    {
        vm.prank(compliance);
        _r(t).recordOrder(orderId, keccak256("document"), subject, beneficiary, maxAmount, freezeUntil);
        return keccak256(abi.encode(orderId, subject, beneficiary));
    }

    function _disable(address t, uint8 bit) internal {
        vm.prank(ownerA);
        MetaTokenBase(t).disableFeature(bit);
    }

    function _now() internal view returns (uint64) {
        return uint64(block.timestamp);
    }

    // ------------------------------------------------------------------ relayed calls

    /// A generic UA meta-transaction of `from` (its native id) on lane 1, nonce 0.
    function _uaTx(address from, bytes memory data, uint32 mode, uint256 fee)
        internal view returns (MetaTxLib.UAMetaTransaction memory m)
    {
        m = MetaTxLib.UAMetaTransaction(nid(from), data, 1, 0, block.timestamp + 300, mode, address(0), fee, address(0));
    }

    function _uaSig(uint256 pk, address t, MetaTxLib.UAMetaTransaction memory m)
        internal view returns (IUARegistry.UASig memory s)
    {
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk, MetaTokenBase(t).mtxDigest(m));
        s.signature = abi.encodePacked(r, ss, v);
    }

    /// The address meta-transaction (`executeMetaTransaction`) of `from` on lane 2, nonce 0.
    function _addrTx(address from, bytes memory data, uint32 mode, uint256 fee)
        internal view returns (MetaTxLib.MetaTransaction memory m)
    {
        m = MetaTxLib.MetaTransaction(from, data, 2, 0, block.timestamp + 300, mode, address(0), fee, address(0));
    }

    function _addrSig(uint256 pk, address t, MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, MtxDigest.metaTx(t, m));
        return abi.encodePacked(r, s, v);
    }

    /// A named entry's envelope of `from` on lane 3, nonce 0.
    function _env(address from, uint32 mode, uint256 fee) internal view returns (MetaTxLib.UAEnvelope memory e) {
        e = MetaTxLib.UAEnvelope(nid(from), 3, 0, block.timestamp + 300, mode, address(0), fee, address(0));
    }

    /// The signature of a named entry over `typehash`, `e.from`, `args` and the envelope (`MtxPipelineLib._namedHash`, no
    /// bound relayer or fee recipient).
    function _namedSig(uint256 pk, address t, string memory typeString, MetaTxLib.UAEnvelope memory e, bytes memory args)
        internal view returns (IUARegistry.UASig memory s)
    {
        bytes32 h = keccak256(bytes.concat(abi.encode(keccak256(bytes(typeString)), e.from), args,
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk, MtxDigest.typed(t, h));
        s.signature = abi.encodePacked(r, ss, v);
    }

    /// A garbage signature: whatever the signer class, the pipeline refuses it (`pre*`).
    function _bad() internal pure returns (IUARegistry.UASig memory s) {
        s.signature = new bytes(65);
    }

    /// `call` returning the revert's selector (0 when it succeeded, `0xffffffff` for a revert without one).
    function _try(address t, bytes memory cd) internal returns (bytes4 err) {
        (bool ok, bytes memory ret) = t.call(cd);
        if (ok) return 0;
        err = ret.length >= 4 ? bytes4(ret) : bytes4(0xffffffff);
    }
}
