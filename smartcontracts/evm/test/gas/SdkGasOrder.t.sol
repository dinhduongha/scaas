// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {ComplianceRegistry} from "../../src/regulated/ComplianceRegistry.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {UID_, normalInit} from "../v2/helpers/V2Fixture.sol";
import {SdkGasRegFix, SdkGasZetherFix, SdkGasPqzFix} from "./SdkGasFixtures.sol";
import {SdkGasOps} from "./SdkGasOps.sol";
import {SdkGasLedger} from "./SdkGasLedger.sol";
import {SdkGasMetered} from "./SdkGasMeter.sol";

/// @notice The order entries' rows (scaas-sdk spec §13.3, owner 2026-11-19, part 3b): `mtxCancelOrder`,
///         `mtxInvalidateNonces` and `mtxWrapOrder` of the token kinds, and the DEX's `mtxCancelOrders` and
///         `mtxInvalidateNonces`. None has an envelope or a meta-tx lane: a token's are signed under the UA purpose `trade`
///         (a native id signs the digest itself), over the order struct, their lane the order's `batch` (one `minNonce`
///         per id, a store apart from the meta-tx nonces). The SDK keys such a struct by its lane state where it has one
///         (`mtxWrapOrder`: the order's nonce 0 fresh, else used) and as used where it has none (a cancel, a floor), so both
///         rows are the worst case, each from the same snapshot with nothing of the signer's on the batch written yet (every
///         write a first write): `fresh` the order's nonce (or the new floor) 1, `used` 2. A call this small with a struct
///         this long sits on EIP-7976's calldata floor: measured inside the transaction (`SdkGasMetered`).
///         A1: where the fixture set a derived signer (`sgUaKind`), the fresh state once more signed by it under `trade`
///         (`<kind>_<entry>_ua_<variant>`).
abstract contract SdkGasOrderOps is SdkGasOps, SdkGasMetered {
    uint256 internal constant SG_BATCH = 1;
    uint256 internal constant SG_ORDER = 1_000;
    /// the trade orders' receive token (an order cancelled is never filled: any address)
    address internal constant SG_RECEIVE = address(0x5E11);
    /// `mtxWrapOrder`'s underlying: a SCaaS token the signer holds and the wrapper under measurement wraps
    address internal sgWrapU;

    /// The signer's authorization of a `trade` digest: a native key signs it itself, a derived UA its purpose message.
    function _tradeSig(bytes32 d) internal view returns (IUARegistry.UASig memory a) {
        if (sgKind == 0) {
            a.signature = _sgSign(sgPk, d);
        } else {
            (a.keyData, a.signature) =
            (sgKeyData, _sgUaSign(sgKind, sgSk, UAKinds.uaMessage(sgKind, UAKinds.PURPOSE_TRADE, d)));
        }
    }

    /// A trade order (this contract its DEX), or its wrap form (`dex == receiveToken`: `CancelUAWrapOrder`).
    function _trOrder(uint256 n, bool wrapForm) internal view returns (ITradeToken.UATradeOrder memory o) {
        (o.from, o.receiveToken, o.amount, o.receiveAmount) = (_sgFrom(), SG_RECEIVE, SG_ORDER, SG_ORDER);
        o.dex = wrapForm ? SG_RECEIVE : address(this);
        (o.batch, o.nonce, o.validUntil) = (SG_BATCH, n, block.timestamp + 600);
    }

    function _cancelOrd(address c, uint256 n) internal view returns (bytes memory) {
        ITradeToken.UATradeOrder memory o = _trOrder(n, false);
        return abi.encodeCall(ITradeToken.mtxCancelOrder, (o, _tradeSig(ITradeToken(c).cancelOrderDigest(o))));
    }

    function _cancelWrapOrd(address c, uint256 n) internal view returns (bytes memory) {
        ITradeToken.UATradeOrder memory o = _trOrder(n, true);
        return abi.encodeCall(ITradeToken.mtxCancelOrder, (o, _tradeSig(ITradeToken(c).cancelOrderDigest(o))));
    }

    /// The floor of the batch raised to `n`.
    function _invalidateOrd(address c, uint256 n) internal view returns (bytes memory) {
        bytes32 from = _sgFrom();
        bytes32 d = ITradeToken(c).invalidateNoncesDigest(from, SG_BATCH, n);
        return abi.encodeCall(ITradeToken.mtxInvalidateNonces, (from, SG_BATCH, n, _tradeSig(d)));
    }

    /// `SG_ORDER` of `sgWrapU` wrapped by the wrapper `c` into the signer, fee 0, any relayer.
    function _wrapOrd(address c, uint256 n) internal view returns (bytes memory) {
        ITradeToken.UAWrapOrder memory o;
        (o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill) = (_sgFrom(), c, SG_ORDER, 1, SG_ORDER);
        (o.batch, o.nonce, o.validUntil) = (SG_BATCH, n, block.timestamp + 600);
        bytes32 d = ITradeToken(sgWrapU).tradeOrderDigest(DexLegs.asTrade(o));
        return abi.encodeCall(IWrappedToken.mtxWrapOrder, (sgWrapU, o, _tradeSig(d)));
    }

    /// One order row on both states (see the contract note), and A1's derived signer on the fresh one.
    function _twice(
        string memory kind,
        string memory entry,
        string memory variant,
        address c,
        function(address, uint256) internal view returns (bytes memory) build
    ) internal {
        string memory k = string.concat(kind, "_", entry, "_");
        uint256 s = vm.snapshotState();
        _measureMetered(string.concat(k, "fresh_", variant), c, build(c, 1));
        vm.revertToState(s);
        _measureMetered(string.concat(k, "used_", variant), c, build(c, 2));
        vm.revertToState(s);
        if (sgUaKind != 0) {
            _sgUaPrep(c);
            (sgKind, sgKeyData, sgSk) = (sgUaKind, sgUaKey, sgUaSk); // the revert below restores the native signer
            _measureMetered(string.concat(k, "ua_", variant), c, build(c, 1));
            vm.revertToState(s);
        }
    }

    /// The cancel (both order forms: `<variant>_wo` the wrap form) and the floor of a token `c`.
    function _orderRows(string memory kind, string memory variant, address c) internal {
        _twice(kind, "mtxCancelOrder", variant, c, _cancelOrd);
        _twice(kind, "mtxCancelOrder", string.concat(variant, "_wo"), c, _cancelWrapOrd);
        _twice(kind, "mtxInvalidateNonces", variant, c, _invalidateOrd);
    }
}

/// The `token` kind's order rows on `NormalToken` (`normal`) and `WrappedToken` (`wrapped`); `mtxWrapOrder` on a fresh
/// wrapper of the ledger token `tok`, which the signer holds (Wrapped only: the entry is the wrapper's). A1: the derived
/// reference signer (`SdkGasLedger`, secp256k1 0x0108) holds 10,000 `tok` in its run only.
contract SdkGasOrderTokenTest is SdkGasLedger, SdkGasOrderOps {
    function setUp() public override {
        super.setUp();
        _sgVerifiers();
        sgPk = ALICE_PK;
        _sgUaSigner();
    }

    function _sgUaPrep(address) internal override {
        vm.prank(alice);
        tok.transferToUA(UAKinds.uaOf(sgUaKind, sgUaKey), 10_000);
    }

    function test_sdkGas_order_token() public {
        _meterControl(address(tok), _cancel(address(tok), 0));
        _meterControl(address(tok), _transfer(address(tok), 0));
        _orderRows("token", "normal", address(tok));
        _orderRows("token", "wrapped", address(wrp));
        sgWrapU = address(tok);
        _twice("token", "mtxWrapOrder", "wrapped", address(_wrapper(address(tok))), _wrapOrd);
    }
}

/// The same on the regulated variants (ruling A), configured as `SdkGasRegulatedTest`: kinds 8 and 9 with `KYC` (every
/// party attested) and `TAX` at 10 %. `mtxWrapOrder` on a fresh kind-9 wrapper of a factory `NORMAL` leg the signer holds
/// (a leg with `FORCE` or `MODERATE`, as the regulated kinds have, is refused). No `_ua_` row: the fixture has no registry
/// with a secp256k1 verifier.
contract SdkGasOrderRegulatedTest is SdkGasOrderOps, SdkGasRegFix {
    address internal constant SG_TAX_TO = address(0x7A0);

    function _cfg(IFactoryToken.TokenConfig memory c) internal view returns (IFactoryToken.TokenConfig memory) {
        c.features |= (1 << GovernanceBits.KYC) | (1 << GovernanceBits.TAX);
        (c.reg.complianceRegistry, c.reg.requiredFlags, c.reg.taxRecipient) = (address(creg), KYC, nid(SG_TAX_TO));
        return c;
    }

    function _reg(bool wrapped, IFactoryToken.TokenConfig memory c, bytes32 salt) internal returns (address t) {
        IOpenFactory.TokenKind k =
            wrapped ? IOpenFactory.TokenKind.WRAPPED_REGULATED : IOpenFactory.TokenKind.NORMAL_REGULATED;
        t = f.createToken(k, 1, abi.encode(_cfg(c)), salt);
        vm.prank(issuer);
        IRegulatedToken(t).setTaxRate(100_000, EnvKit.codeUidOf(t));
    }

    function setUp() public override {
        super.setUp();
        sgPk = ALICE_PK;
        address[4] memory parties = [alice, SG_TAX_TO, SG_RELAYER, address(this)];
        for (uint256 i; i < parties.length; ++i) {
            _attest(nid(parties[i]), KYC, type(uint64).max);
        }
    }

    function test_sdkGas_order_tokenRegulated() public {
        _orderRows("token", "normal_reg", _reg(false, _cfg8(), "sg8"));
        _orderRows("token", "wrapped_reg", _reg(true, _cfg9(), "sg9"));
        IFactoryToken.TokenConfig memory n;
        (n.name, n.symbol, n.features, n.admin, n.grantDelay) =
        ("Leg", "LEG", 1 << GovernanceBits.PAYABLE, nid(ownerA), GD);
        (n.initialSupply, n.initialHolder) = (SUPPLY, address(this));
        sgWrapU = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(n), "sgleg");
        WrappedToken(payable(sgWrapU)).transfer(alice, 10_000);
        IFactoryToken.TokenConfig memory c = _cfg9();
        c.legs[0] = IFactoryToken.Leg(sgWrapU, 1, 1);
        _twice("token", "mtxWrapOrder", "wrapped_reg", _reg(true, c, "sg9w"), _wrapOrd);
    }
}

/// The `zether` and `pqz` kinds' order rows on their Normal, Wrapped and regulated Normal / Wrapped tokens, configured as
/// `SdkGasKind` (a regulated token: the registry check, `KYC` with the deny mask, and `TAX` at 10 %). `mtxWrapOrder` on a
/// fresh wrapper of a plain Normal of the kind (a ledger leg) the signer holds. No `_ua_` row: the fixtures have no
/// registry with a secp256k1 verifier.
abstract contract SdkGasOrderKind is SdkGasOrderOps {
    address internal constant SG_TAX_TO = address(0x7A0);
    uint64 internal constant SG_KYC = 1;
    uint64 internal constant SG_DENIED = 1 << 16;

    function _sgKind() internal pure virtual returns (string memory);
    function _sgCfg(bool reg) internal view virtual returns (IFactoryToken.TokenConfig memory);
    function _sgKindOf(bool wrapped, bool reg) internal pure virtual returns (IOpenFactory.TokenKind);
    function _sgFactory() internal view virtual returns (IOpenFactory);
    function _sgReg() internal view virtual returns (ComplianceRegistry creg, address attester, address issuer);

    /// `SdkGasKind._sgCreate`.
    function _sgCreate(bool wrapped, bool reg, address leg, bytes32 salt) internal returns (address t) {
        IFactoryToken.TokenConfig memory c = _sgCfg(reg);
        if (wrapped) {
            c.features = (1 << GovernanceBits.PAYABLE) | (reg ? c.features & ~uint256(0x1F) : 0);
            (c.lockedFeatures, c.roles.minter) = (0, 0);
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(leg, 1, 1);
        }
        (ComplianceRegistry creg,, address issuer) = _sgReg();
        if (reg) {
            c.features |= (1 << GovernanceBits.KYC) | (1 << GovernanceBits.TAX);
            (c.reg.complianceRegistry, c.reg.requiredFlags, c.reg.deniedFlags) = (address(creg), 0, SG_DENIED);
            c.reg.taxRecipient = nid(SG_TAX_TO);
        }
        t = _sgFactory().createToken(_sgKindOf(wrapped, reg), 1, abi.encode(c), salt);
        if (reg) {
            vm.prank(issuer);
            IRegulatedToken(t).setTaxRate(100_000, EnvKit.codeUidOf(t));
        }
    }

    function _sgAttest(bytes32 a) internal {
        (ComplianceRegistry creg, address attester,) = _sgReg();
        bytes32[] memory as_ = new bytes32[](1);
        uint64[] memory fl = new uint64[](1);
        uint64[] memory vu = new uint64[](1);
        (as_[0], fl[0], vu[0]) = (a, SG_KYC, type(uint64).max);
        vm.prank(attester);
        creg.setCompliance(as_, fl, vu, EnvKit.regUidOf(address(creg)));
    }

    function _sgOrderRows(bool reg) internal {
        string memory k = _sgKind();
        (string memory vn, string memory vw) = reg ? ("normal_reg", "wrapped_reg") : ("normal", "wrapped");
        address alice_ = vm.addr(sgPk);
        if (reg) {
            address[4] memory parties = [alice_, SG_TAX_TO, SG_RELAYER, address(this)];
            for (uint256 i; i < parties.length; ++i) {
                _sgAttest(nid(parties[i]));
            }
        }
        _orderRows(k, vn, _sgCreate(false, reg, address(0), reg ? bytes32("sgonr") : bytes32("sgon")));
        MockERC20 und = new MockERC20("Und", "UND", 6);
        _orderRows(k, vw, _sgCreate(true, reg, address(und), reg ? bytes32("sgowr") : bytes32("sgow")));
        sgWrapU = _sgCreate(false, false, address(0), reg ? bytes32("sgolr") : bytes32("sgol"));
        NormalToken(sgWrapU).mint(alice_, 10_000, EnvKit.codeUidOf(sgWrapU));
        address w = _sgCreate(true, reg, sgWrapU, reg ? bytes32("sgowwr") : bytes32("sgoww"));
        _twice(k, "mtxWrapOrder", vw, w, _wrapOrd);
    }

    function test_sdkGas_order_kind() public {
        _sgOrderRows(false);
    }

    function test_sdkGas_order_kindRegulated() public {
        _sgOrderRows(true);
    }
}

contract SdkGasOrderZetherTest is SdkGasOrderKind, SdkGasZetherFix {
    function _isWrapped() internal pure override returns (bool) {
        return false;
    }

    function setUp() public override {
        super.setUp();
        Catalogue.release(
            factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode
        );
        sgPk = 0xA11CE5EED;
    }

    function _sgKind() internal pure override returns (string memory) {
        return "zether";
    }

    function _sgCfg(bool reg) internal view override returns (IFactoryToken.TokenConfig memory) {
        return reg ? _regCfg(false, uint256(1) << 40) : _cfg(false, uint256(1) << 40);
    }

    function _sgKindOf(bool wrapped, bool reg) internal pure override returns (IOpenFactory.TokenKind) {
        if (reg) {
            return
                wrapped
                    ? IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED
                    : IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED;
        }
        return wrapped ? IOpenFactory.TokenKind.WRAPPED_ZETHER : IOpenFactory.TokenKind.NORMAL_ZETHER;
    }

    function _sgFactory() internal view override returns (IOpenFactory) {
        return IOpenFactory(address(factory));
    }

    function _sgReg() internal view override returns (ComplianceRegistry, address, address) {
        return (creg, attester, issuer);
    }
}

contract SdkGasOrderPqzTest is SdkGasOrderKind, SdkGasPqzFix {
    function _isWrapped() internal pure override returns (bool) {
        return false;
    }

    function setUp() public override {
        super.setUp();
        _releaseWrapped();
        sgPk = 0xA11CE5EED;
    }

    function _sgKind() internal pure override returns (string memory) {
        return "pqz";
    }

    function _sgCfg(bool reg) internal view override returns (IFactoryToken.TokenConfig memory) {
        return reg ? _regCfg() : _cfg(uint256(1) << 40);
    }

    function _sgKindOf(bool wrapped, bool reg) internal pure override returns (IOpenFactory.TokenKind) {
        if (reg) {
            return wrapped ? IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED : IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED;
        }
        return wrapped ? IOpenFactory.TokenKind.WRAPPED_PQZ : IOpenFactory.TokenKind.NORMAL_PQZ;
    }

    function _sgFactory() internal view override returns (IOpenFactory) {
        return IOpenFactory(address(factory));
    }

    function _sgReg() internal view override returns (ComplianceRegistry, address, address) {
        return (creg, attester, issuer);
    }
}

/// The `dex` kind's rows on `SCaaSDex` (variant `dex`), the fixture of `DexOutsideTest`: the outside-token cancel and the
/// floor, signed by an address (the reference signer's EOA, its own key in the DEX's domain). `mtxCancelOrders` takes
/// arrays; the SDK prepares one order and its signature (a one-element list), measured so. No `_ua_` row: the DEX's
/// outside orders are signed by an address (EOA or ERC-1271), never a UA.
contract SdkGasOrderDexTest is SdkGasOrderOps {
    address internal constant SG_SELL = address(0x5E12);
    SCaaSDex internal dex;

    function setUp() public {
        sgPk = 0xDA7E;
        address ska = _sgSkaSetup(UID_); // G4: the deploy's `SmartKeyAccount` implementation
        OpenFactory f = EnvKit.factory(address(this), UID_, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), ska, false);
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, ska);
        dex = SCaaSDex(
            f.createDex(
                1,
                abi.encode(ISCaaSDex.DexConfig(nid(address(0xAD)), 0, address(0x7EA5), false, 0, address(0), 0, 0)),
                "dex"
            )
        );
    }

    function _dexOrd(address c, uint256 n) internal view returns (ITradeToken.TradeOrder memory o) {
        (o.from, o.receiveToken, o.amount, o.receiveAmount) = (vm.addr(sgPk), SG_RECEIVE, SG_ORDER, SG_ORDER);
        (o.dex, o.batch, o.nonce, o.validUntil) = (c, SG_BATCH, n, block.timestamp + 600);
    }

    function _dexCancel(address c, uint256 n) internal view returns (bytes memory) {
        ISCaaSDex.DexOrder[] memory os = new ISCaaSDex.DexOrder[](1);
        os[0] = ISCaaSDex.DexOrder(SG_SELL, _dexOrd(c, n));
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sgSign(sgPk, ISCaaSDex(c).cancelDexOrderDigest(SG_SELL, os[0].order));
        return abi.encodeCall(ISCaaSDex.mtxCancelOrders, (os, sigs));
    }

    function _dexInvalidate(address c, uint256 n) internal view returns (bytes memory) {
        address from = vm.addr(sgPk);
        bytes32 d = ISCaaSDex(c).invalidateNoncesDigest(from, SG_BATCH, n);
        return abi.encodeCall(ISCaaSDex.mtxInvalidateNonces, (from, SG_BATCH, n, _sgSign(sgPk, d)));
    }

    function test_sdkGas_order_dex() public {
        _twice("dex", "mtxCancelOrders", "dex", address(dex), _dexCancel);
        _twice("dex", "mtxInvalidateNonces", "dex", address(dex), _dexInvalidate);
        // a skipped item (a bad signature) is no error: the measured call closed the order
        uint256 s = vm.snapshotState();
        bytes memory cd = _dexCancel(address(dex), 1);
        vm.prank(SG_RELAYER);
        (bool ok,) = address(dex).call(cd);
        assertTrue(ok);
        assertEq(dex.pulled(dex.dexOrderDigest(SG_SELL, _dexOrd(address(dex), 1))), SG_ORDER, "the order closed");
        vm.revertToState(s);
    }
}
