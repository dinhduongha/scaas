// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MtxDigest} from "../helpers/MtxDigest.sol";
import {UAMetaTxBase} from "../../src/metatx/UAMetaTxBase.sol";
import {UACall} from "../ua/UACall.sol";
import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {LegacyMetaTransfer} from "../helpers/LegacyMetaTransfer.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {TokenStore} from "../../src/metatx/TokenStore.sol";
import {Catalogue, plainEnv} from "../helpers/Catalogue.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {VM, TYPED_OPS, TYPED_OPS_LEGACY, checkRow, onChain, domainOf, domainField, ecdsa, rowKey, rowEnvelope2} from "./NamedEntry.t.sol";
import {swap, tryRowAs, UA_CANCEL_NONCE, rowMeta} from "./TypedOps.t.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// The address `WrapOrder` (R39: in legacy/ua-mtx-merge/ after T3), kept here to encode its retired row.
struct LegacyWrapOrder {
    address from;
    address wrappedToken;
    uint256 amount;
    uint256 minMinted;
    uint256 minFill;
    uint256 fee;
    address relayer;
    address destination;
    uint8 flags;
    uint256 batch;
    uint256 nonce;
    uint256 validUntil;
}

/// typed-signing C6: the order, receiver-fee, relay-fee and cancel rows of `typed_ops.json` run on every token kind, under
/// that kind's own domain: the row by itself, its calldata equal to the message's fields, then that calldata on a contract
/// with the signature re-made over the row's `structHash`, so the entry hashes what clientkeys hashed.
abstract contract OrderRows is Test {
    string internal j;
    uint256 internal constant FUNDS = 10_000_000;
    /// The retired address cancel (ua-mtx-merge T6) and the merged one the rows name (T11, MD-7).
    string internal constant OLD_CANCEL_ORDER =
        "mtxCancelOrder((address,address,uint256,uint256,uint256,uint256,address,address,address,uint8,uint256,uint256,uint256),bytes)";
    string internal constant UA_CANCEL_ORDER =
        "mtxCancelOrder((bytes32,address,uint256,uint256,uint256,uint256,address,address,bytes32,uint8,uint256,uint256,uint256),(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))";
    address internal constant ANYONE = address(0x0BEE);

    function _kind() internal pure virtual returns (string memory);
    function _normalKind() internal virtual returns (NormalToken);
    function _wrappedKind(address leg) internal virtual returns (WrappedToken);

    function _f(string memory op, string memory path) private pure returns (string memory) {
        return string.concat(".ops.", op, ".message.", path);
    }

    /// An address or a 32-byte id, as the id it is.
    function _id(string memory path) private view returns (bytes32) {
        bytes memory b = vm.parseJsonBytes(j, path);
        return b.length == 32 ? bytes32(b) : bytes32(uint256(uint160(bytes20(b))));
    }

    function _u(string memory path) private view returns (uint256) {
        return vm.parseJsonUint(j, path);
    }

    function _order(string memory op) private view returns (ITradeToken.UATradeOrder memory o) {
        string memory p = _f(op, "order.");
        o.from = _id(string.concat(p, "from"));
        o.receiveToken = vm.parseJsonAddress(j, string.concat(p, "receiveToken"));
        o.amount = _u(string.concat(p, "amount"));
        o.receiveAmount = _u(string.concat(p, "receiveAmount"));
        o.dex = vm.parseJsonAddress(j, string.concat(p, "dex"));
        _tail(p, o);
    }

    function _tail(string memory p, ITradeToken.UATradeOrder memory o) private view {
        o.minFill = _u(string.concat(p, "minFill"));
        o.fee = _u(string.concat(p, "fee"));
        o.relayer = vm.parseJsonAddress(j, string.concat(p, "relayer"));
        o.destination = _id(string.concat(p, "destination"));
        o.flags = uint8(_u(string.concat(p, "flags")));
        o.batch = _u(string.concat(p, "batch"));
        o.nonce = _u(string.concat(p, "nonce"));
        o.validUntil = _u(string.concat(p, "validUntil"));
    }

    /// A row's wrap order at `p`, in its order form: `dex == receiveToken == wrappedToken`.
    function _wrapAt(string memory p) private view returns (ITradeToken.UATradeOrder memory o) {
        o.from = _id(string.concat(p, "from"));
        o.receiveToken = vm.parseJsonAddress(j, string.concat(p, "wrappedToken"));
        o.dex = o.receiveToken;
        o.amount = _u(string.concat(p, "amount"));
        o.receiveAmount = _u(string.concat(p, "minMinted"));
        _tail(p, o);
    }

    function _native(ITradeToken.UATradeOrder memory c) private pure returns (ITradeToken.TradeOrder memory o) {
        assembly ("memory-safe") { o := c }
    }

    function _sigOf(string memory op) private view returns (bytes memory) {
        return vm.parseJsonBytes(j, domainField(op, _kind(), "signature"));
    }

    function _uaSig(string memory op) private view returns (IUARegistry.UASig memory s) {
        s.signature = _sigOf(op);
    }

    function _run(string memory op, address c, address signedIn, address sender, bytes memory built) private {
        (bool ok, bytes memory ret) = tryRowAs(j, op, _kind(), c, signedIn, sender, built);
        assertTrue(ok, vm.toString(ret));
    }

    /// ua-mtx-merge T11 (MD-7): a `UA…` row names its merged entry `sel` and runs verbatim, the signature under the domain
    /// it was signed in (T2-T7 ran the rows' `ua*` calldata under `sel`, until the rows were regenerated).
    function _runRenamed(string memory op, address c, address signedIn, address sender, bytes memory built, bytes4 sel)
        private
    {
        checkRow(j, op, _kind());
        bytes memory cd = vm.parseJsonBytes(j, domainField(op, _kind(), "calldata"));
        assertEq(bytes4(cd), sel, "the row names the merged mtx entry");
        assertEq(keccak256(built), keccak256(cd), "the row: the merged calldata");
        swap(cd, vm.parseJsonBytes(j, domainField(op, _kind(), "signature")), onChain(j, op, signedIn));
        vm.prank(sender);
        (bool ok, bytes memory ret) = c.call(cd);
        assertTrue(ok, vm.toString(ret));
    }

    /// ua-mtx-merge T2: the row of a retired address entry: its own calldata finds no function on `c`.
    function _rowHasNoEntry(string memory op, address c, bytes memory built) private {
        checkRow(j, op, _kind());
        bytes memory cd = vm.parseJsonBytes(j, domainField(op, _kind(), "calldata"));
        assertEq(keccak256(built), keccak256(cd), "the row: the old calldata");
        (bool ok, bytes memory ret) = c.call(cd);
        assertFalse(ok);
        assertEq(ret.length, 0, "no such function");
    }

    /// The contract at `from` also at the address a row names.
    function _at(address from, address to) private {
        vm.etch(to, from.code);
        vm.copyStorage(from, to);
    }

    /// The signer funded on a token at the row's own domain address, a 1:1 wrapper of it at the row's `wrappedToken`.
    function _wrapPair(string memory op, address signer, address wrapper, uint256 amount) private returns (NormalToken u, WrappedToken w) {
        address at = vm.parseJsonAddress(j, domainField(op, _kind(), "domain.verifyingContract"));
        _at(address(_normalKind()), at);
        u = NormalToken(at);
        u.mint(signer, amount);
        _at(address(_wrappedKind(at)), wrapper);
        w = WrappedToken(wrapper);
    }

    /// ua-mtx-merge T3 (R39), meaning: the address `mtxWrapOrder` / `WrapOrder` left the wrapper; the row (until T11
    /// retires it, MD-7) finds no entry. The wrap order is `UAWrapOrder`'s row, below, under `mtxWrapOrder`.
    function test_typedOpsVectors_WrapOrderRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // T11 (MD-7): the row retired
        ITradeToken.UATradeOrder memory c = _wrapAt(_f("WrapOrder", ""));
        LegacyWrapOrder memory o = LegacyWrapOrder(address(uint160(uint256(c.from))), c.receiveToken, c.amount,
            c.receiveAmount, c.minFill, c.fee, c.relayer, address(uint160(uint256(c.destination))), c.flags, c.batch, c.nonce,
            c.validUntil);
        (NormalToken u, WrappedToken w) = _wrapPair("WrapOrder", o.from, o.wrappedToken, o.amount);
        _rowHasNoEntry("WrapOrder", address(w), abi.encodeWithSignature(
            "mtxWrapOrder(address,(address,address,uint256,uint256,uint256,uint256,address,address,uint8,uint256,uint256,uint256),bytes)",
            address(u), o, _sigOf("WrapOrder")));
        assertEq(w.totalSupply(), 0);
    }

    function test_typedOpsVectors_UAWrapOrderRow() public {
        j = vm.readFile(TYPED_OPS);
        ITradeToken.UATradeOrder memory c = _wrapAt(_f("UAWrapOrder", ""));
        ITradeToken.UAWrapOrder memory o = ITradeToken.UAWrapOrder(c.from, c.receiveToken, c.amount, c.receiveAmount, c.minFill, c.fee,
            c.relayer, c.destination, c.flags, c.batch, c.nonce, c.validUntil);
        address signer = address(uint160(uint256(o.from)));
        (NormalToken u, WrappedToken w) = _wrapPair("UAWrapOrder", signer, o.wrappedToken, o.amount);
        bytes memory built = abi.encodeCall(IWrappedToken.mtxWrapOrder, (address(u), o, _uaSig("UAWrapOrder")));
        // ua-mtx-merge T3 (R39) / T11: the row names `mtxWrapOrder`
        _runRenamed("UAWrapOrder", address(w), address(u), o.relayer, built, IWrappedToken.mtxWrapOrder.selector);
        assertEq(w.balanceOf(signer), 997);
        assertEq(u.pulled(u.tradeOrderDigest(DexLegs.asTrade(o))), o.amount);
    }

    /// ua-mtx-merge T6 (R12, R38), meaning: the address `mtxCancelOrder(TradeOrder, bytes)` left the token; the row
    /// (until T11 retires it, MD-7) finds no entry. The token's cancel is `CancelUAOrder`'s row, below.
    function test_typedOpsVectors_CancelOrderRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // T11 (MD-7): the row retired
        NormalToken t = _normalKind();
        ITradeToken.TradeOrder memory o = _native(_order("CancelOrder"));
        _rowHasNoEntry("CancelOrder", address(t), abi.encodeWithSignature(OLD_CANCEL_ORDER, o, _sigOf("CancelOrder")));
        assertEq(t.pulled(t.tradeOrderDigest(DexLegs.ua(o))), 0);
    }

    /// ua-mtx-merge T6 / T11: the row names the merged `mtxCancelOrder`.
    function test_typedOpsVectors_CancelUAOrderRow() public {
        j = vm.readFile(TYPED_OPS);
        NormalToken t = _normalKind();
        ITradeToken.UATradeOrder memory o = _order("CancelUAOrder");
        _runRenamed("CancelUAOrder", address(t), address(t), ANYONE,
            abi.encodeWithSignature(UA_CANCEL_ORDER, o, _uaSig("CancelUAOrder")), ITradeToken.mtxCancelOrder.selector);
        assertEq(t.pulled(t.tradeOrderDigest(o)), o.amount);
    }

    /// ua-mtx-merge T6, meaning: as `CancelOrder` for the address `CancelWrapOrder` (carried from T3: the address wrap
    /// forms leave the token with the address trade path).
    function test_typedOpsVectors_CancelWrapOrderRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // T11 (MD-7): the row retired
        NormalToken t = _normalKind();
        ITradeToken.TradeOrder memory o = _native(_wrapAt(_f("CancelWrapOrder", "order.")));
        _rowHasNoEntry("CancelWrapOrder", address(t), abi.encodeWithSignature(OLD_CANCEL_ORDER, o, _sigOf("CancelWrapOrder")));
        assertEq(t.pulled(t.tradeOrderDigest(DexLegs.ua(o))), 0);
    }

    function test_typedOpsVectors_CancelUAWrapOrderRow() public {
        j = vm.readFile(TYPED_OPS);
        NormalToken t = _normalKind();
        ITradeToken.UATradeOrder memory o = _wrapAt(_f("CancelUAWrapOrder", "order."));
        _runRenamed("CancelUAWrapOrder", address(t), address(t), ANYONE,
            abi.encodeWithSignature(UA_CANCEL_ORDER, o, _uaSig("CancelUAWrapOrder")), ITradeToken.mtxCancelOrder.selector);
        assertEq(t.pulled(t.tradeOrderDigest(o)), o.amount);
    }

    function _callOf(string memory op) private view returns (address, bytes32) {
        return (vm.parseJsonAddress(j, _f(op, "target")), vm.parseJsonBytes32(j, _f(op, "callDataHash")));
    }

    /// ua-mtx-merge T2 (R28), meaning: the address `mtxRelayFee` / `RelayFee` left the token; the row (until T11
    /// retires it, MD-7) finds no entry. The relay fee is `UARelayFee`'s row, below.
    function test_typedOpsVectors_RelayFeeRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // T11 (MD-7): the row retired
        NormalToken t = _normalKind();
        address from = vm.parseJsonAddress(j, _f("RelayFee", "from"));
        t.mint(from, FUNDS);
        address payee = vm.parseJsonAddress(j, _f("RelayFee", "payee"));
        uint256 value = _u(_f("RelayFee", "value"));
        (address tgt, bytes32 cdh) = _callOf("RelayFee");
        _rowHasNoEntry("RelayFee", address(t), abi.encodeWithSignature(
            "mtxRelayFee(address,address,bytes32,address,uint256,uint256,bytes)",
            from, tgt, cdh, payee, value, _u(_f("RelayFee", "validUntil")), _sigOf("RelayFee")));
        assertEq(t.balanceOf(payee), 0);
    }

    /// pay-meta-tax T38 / T41: the row signs `UARelayFee` with the payer's own lane `(batch, nonce)` and runs.
    function test_typedOpsVectors_UARelayFeeRow() public {
        j = vm.readFile(TYPED_OPS);
        NormalToken t = _normalKind();
        bytes32 from = vm.parseJsonBytes32(j, _f("UARelayFee", "from"));
        t.mint(address(uint160(uint256(from))), FUNDS);
        bytes32 payee = vm.parseJsonBytes32(j, _f("UARelayFee", "payee"));
        uint256 value = _u(_f("UARelayFee", "value"));
        (address tgt, bytes32 cdh) = _callOf("UARelayFee");
        bytes memory built = abi.encodeCall(IERC20MetaTx.mtxRelayFee, (from, tgt, cdh, payee, value, _u(_f("UARelayFee", "batch")),
            _u(_f("UARelayFee", "nonce")), _u(_f("UARelayFee", "validUntil")), _uaSig("UARelayFee")));
        _runRenamed("UARelayFee", address(t), address(t), vm.parseJsonAddress(j, _f("UARelayFee", "relayer")), built,
            IERC20MetaTx.mtxRelayFee.selector);
        assertEq(t.balanceOf(address(uint160(uint256(payee)))), value);
        assertEq(t.mtxNonce(from, _u(_f("UARelayFee", "batch"))), _u(_f("UARelayFee", "nonce")) + 1, "the payer's lane");
    }

    function _payment(string memory op) private view returns (MetaTxLib.UAMetaTransfer memory t) {
        string memory p = _f(op, "payment.");
        t.from = _id(string.concat(p, "from"));
        t.to = _id(string.concat(p, "to"));
        t.value = _u(string.concat(p, "value"));
        t.entryRef = vm.parseJsonBytes32(j, string.concat(p, "entryRef"));
        t.batch = _u(string.concat(p, "batch"));
        t.validUntil = _u(string.concat(p, "validUntil"));
        t.mode = uint32(_u(string.concat(p, "mode")));
        t.relayer = vm.parseJsonAddress(j, string.concat(p, "relayer"));
    }

    /// The row's two signatures, the payer's and the payee's, re-made under `t`'s domain; the payee a wallet of the row's key.
    /// ua-mtx-merge T2 / T11: the row names the merged `mtxPayReceiverFee`.
    function _receiverFee(string memory op, NormalToken t, MetaTxLib.UAMetaTransfer memory x, bytes32 paymentDigest, bytes memory built) private {
        checkRow(j, op, _kind());
        bytes memory cd = vm.parseJsonBytes(j, domainField(op, _kind(), "calldata"));
        assertEq(keccak256(built), keccak256(cd), "calldata");
        swap(cd, vm.parseJsonBytes(j, domainField(op, _kind(), "extra.payerSig")), ecdsa(rowKey(j), paymentDigest));
        swap(cd, _sigOf(op), onChain(j, op, address(t)));
        assertEq(bytes4(cd), IMetaTokenV2.mtxPayReceiverFee.selector, "the row names the merged mtx entry");
        deployCodeTo("WalletMocks.sol:Mock1271Wallet", abi.encode(vm.parseJsonAddress(j, ".key.address")), address(uint160(uint256(x.to))));
        t.mint(address(uint160(uint256(x.from))), FUNDS * 100);
        vm.prank(x.relayer);
        (bool ok, bytes memory ret) = address(t).call(cd);
        assertTrue(ok, vm.toString(ret));
    }

    /// ua-mtx-merge T2 (R21), meaning: the address `mtxPayReceiverFee` / `ReceiverFee` left the token; the row (until
    /// T11 retires it, MD-7) finds no entry. Receiver-pays is `UAReceiverFee`'s row, below.
    function test_typedOpsVectors_ReceiverFeeRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // T11 (MD-7): the row retired
        string memory op = "ReceiverFee";
        NormalToken t = _normalKind();
        MetaTxLib.UAMetaTransfer memory u = _payment(op);
        LegacyMetaTransfer.MetaTransfer memory x = LegacyMetaTransfer.MetaTransfer(address(uint160(uint256(u.from))),
            address(uint160(uint256(u.to))), u.value, u.entryRef, u.batch, 0, u.validUntil, u.mode, u.relayer, 0, address(0));
        address feeTo = vm.parseJsonAddress(j, _f(op, "feeRecipient"));
        _rowHasNoEntry(op, address(t), abi.encodeWithSignature(
            "mtxPayReceiverFee((address,address,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address),bytes,uint256,address,uint256,bytes)",
            x, vm.parseJsonBytes(j, domainField(op, _kind(), "extra.payerSig")), _u(_f(op, "fee")), feeTo,
            _u(_f(op, "validUntil")), _sigOf(op)));
        assertEq(t.balanceOf(feeTo), 0);
    }

    function test_typedOpsVectors_UAReceiverFeeRow() public {
        j = vm.readFile(TYPED_OPS);
        string memory op = "UAReceiverFee";
        NormalToken t = _normalKind();
        MetaTxLib.UAMetaTransfer memory x = _payment(op);
        IUARegistry.UASig memory payer;
        payer.signature = vm.parseJsonBytes(j, domainField(op, _kind(), "extra.payerSig"));
        uint256 fee = _u(_f(op, "fee"));
        address feeTo = vm.parseJsonAddress(j, _f(op, "feeRecipient"));
        // pay-meta-tax T41: the row's `PayMeta` (`extra.meta`) the entry's last parameter, `entryRef` its commitment
        bytes memory built = abi.encodeCall(IMetaTokenV2.mtxPayReceiverFee, (x, payer, fee, feeTo, _u(_f(op, "validUntil")),
            _uaSig(op), rowMeta(j, op, _kind())));
        _receiverFee(op, t, x, t.mtxTransferDigest(x), built);
        assertEq(t.balanceOf(feeTo), fee);
    }

    /// ua-mtx-merge T1, meaning: the old row is the unordered `UACancelNonce(bytes32 ua,uint256 batch,uint256 validUntil)`;
    /// its entry `uaCancelNonce` left the token (Q2), so the row's own calldata finds no function and the lane stays. T11
    /// (MD-7): read from `TYPED_OPS_LEGACY`; the ordered cancel's row runs below.
    function test_typedOpsVectors_UACancelNonceOldRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY);
        string memory op = "UACancelNonce";
        NormalToken t = _normalKind();
        bytes32 ua = vm.parseJsonBytes32(j, _f(op, "ua"));
        uint256 batch = _u(_f(op, "batch"));
        uint256 until = _u(_f(op, "validUntil"));
        IUARegistry.UASig memory s = _uaSig(op);
        checkRow(j, op, _kind());
        bytes memory cd = vm.parseJsonBytes(j, domainField(op, _kind(), "calldata"));
        assertEq(keccak256(abi.encodeWithSignature(
            "uaCancelNonce(bytes32,uint256,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))", ua, batch, until, s)),
            keccak256(cd), "the row: the old calldata");
        (bool ok, bytes memory ret) = address(t).call(cd);
        assertFalse(ok);
        assertEq(ret.length, 0, "no such function");
        assertEq(t.mtxNonce(ua, batch), 0);
    }

    /// T11 (Q2, MD-7): the ordered cancel's row, `UACancelNonce(bytes32 from,uint256 lane,E)` in this kind's domain, on the
    /// merged `mtxCancelNonce`: the row's native id bumps its own lane, nonce-ordered, no registry.
    function test_typedOpsVectors_UACancelNonceRow() public {
        j = vm.readFile(TYPED_OPS);
        string memory op = "UACancelNonce";
        NormalToken t = _normalKind();
        MetaTxLib.Envelope memory r = rowEnvelope2(j, op);
        MetaTxLib.UAEnvelope memory e = MetaTxLib.UAEnvelope(vm.parseJsonBytes32(j, _f(op, "from")), r.batch, r.nonce, r.validUntil,
            r.mode, r.relayer, r.fee, r.feeRecipient);
        uint256 lane = _u(_f(op, "lane"));
        _runRenamed(op, address(t), address(t), e.relayer, abi.encodeWithSignature(UA_CANCEL_NONCE, e, lane, _uaSig(op)),
            bytes4(keccak256(bytes(UA_CANCEL_NONCE))));
        assertEq(t.mtxNonce(e.from, lane), 1);
        assertEq(t.mtxNonce(e.from, e.batch), 1);
    }
}

contract OrderRowsTokenTest is OrderRows, UALedgerBase {
    function setUp() public override {
        UALedgerBase.setUp();
    }

    function _kind() internal pure override returns (string memory) {
        return "token";
    }

    /// A fresh clone: `vm.copyStorage` copies what this test has touched, not `setUp`'s account.
    function _normalKind() internal override returns (NormalToken t) {
        t = NormalToken(EnvKit.clone(address(new NormalToken(address(this), "")), EnvKit.env(chainUidA, REG_L, address(0), false)));
        t.initialize(nid(address(this)), 1, abi.encode(normalInit("Points", "PTS", 6, 1_000_000, alice, address(this))));
    }

    function _wrappedKind(address leg) internal override returns (WrappedToken) {
        return _wrapper(leg);
    }

    /// `CancelDexOrder` under the DEX's own domain: the row's `DexOrder`, closed through `mtxCancelOrders`.
    function test_typedOpsVectors_CancelDexOrderRow() public {
        j = vm.readFile(TYPED_OPS);
        string memory op = "CancelDexOrder";
        SCaaSDex dex = SCaaSDex(EnvKit.clone(address(new SCaaSDex(address(this), "")), EnvKit.env(chainUidA, address(0), address(0), false)));
        dex.initialize(nid(address(this)), 1, abi.encode(ISCaaSDex.DexConfig(nid(address(this)), 200_000, address(0x7EA5), false, 0, address(0))));
        string memory p = ".ops.CancelDexOrder.message.order.";
        address sell = vm.parseJsonAddress(j, string.concat(p, "sellToken"));
        string memory q = string.concat(p, "order.");
        ITradeToken.TradeOrder memory o = ITradeToken.TradeOrder(vm.parseJsonAddress(j, string.concat(q, "from")),
            vm.parseJsonAddress(j, string.concat(q, "receiveToken")), vm.parseJsonUint(j, string.concat(q, "amount")),
            vm.parseJsonUint(j, string.concat(q, "receiveAmount")), vm.parseJsonUint(j, string.concat(q, "minFill")),
            vm.parseJsonUint(j, string.concat(q, "fee")), vm.parseJsonAddress(j, string.concat(q, "relayer")),
            vm.parseJsonAddress(j, string.concat(q, "dex")), vm.parseJsonAddress(j, string.concat(q, "destination")),
            uint8(vm.parseJsonUint(j, string.concat(q, "flags"))), vm.parseJsonUint(j, string.concat(q, "batch")),
            vm.parseJsonUint(j, string.concat(q, "nonce")), vm.parseJsonUint(j, string.concat(q, "validUntil")));
        ISCaaSDex.DexOrder[] memory os = new ISCaaSDex.DexOrder[](1);
        os[0] = ISCaaSDex.DexOrder(sell, o);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = vm.parseJsonBytes(j, domainField(op, "dex", "signature"));
        (bool ok, bytes memory ret) = tryRowAs(j, op, "dex", address(dex), address(dex), address(0x0BEE), abi.encodeCall(ISCaaSDex.mtxCancelOrders, (os, sigs)));
        assertTrue(ok, vm.toString(ret));
        assertEq(dex.pulled(dex.dexOrderDigest(sell, o)), o.amount, "the row's signature cancels: a bad one is a skipped item");
    }

    /// Relaying these entries: each has its own signature and a direct caller, so none is on the allowlist. A validly signed
    /// `executeMetaTransaction` / `mtxExecute` of each is refused at the allowlist, the same envelope with an allowlisted op
    /// runs. (ua-mtx-merge T1, meaning: the address `mtxExecute` left tokens, `executeMetaTransaction` is its alias (R3);
    /// on the merged `mtxExecute` a native signer reads `_mtxRule` (B): `MtxSelectorNotAllowed`, no longer `MetaTxUnknownOp`;
    /// the cancel listed is the merged `mtxCancelNonce`.)
    function test_c6EntriesNotAllowlisted() public {
        bytes4[13] memory sels = [ITradeToken.mtxTrade.selector, ITradeToken.mtxTrade.selector, ITradeToken.mtxCancelOrder.selector,
            ITradeToken.mtxCancelOrder.selector, ITradeToken.mtxInvalidateNonces.selector, ITradeToken.mtxInvalidateNonces.selector,
            IERC20MetaTx.mtxRelayFee.selector, IERC20MetaTx.mtxRelayFee.selector, IMetaTokenV2.mtxPayReceiverFee.selector,
            IMetaTokenV2.mtxPayReceiverFee.selector, IWrappedToken.mtxWrapOrder.selector, IWrappedToken.mtxWrapOrder.selector,
            UAMetaTxBase.mtxCancelNonce.selector];
        bytes32 me = _pad(alice);
        for (uint256 i; i < sels.length; ++i) {
            MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction(alice, abi.encodeWithSelector(sels[i], uint256(0)), 5, 0,
                block.timestamp + 300, 0, address(0), 0, address(0));
            bytes memory sig = ecdsa(ALICE_PK, MtxDigest.metaTx(address(wrpL), m));
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, sels[i]));
            wrpL.executeMetaTransaction(m, sig);
            MetaTxLib.UAMetaTransaction memory u = MetaTxLib.UAMetaTransaction(me, m.data, 5, 0, m.validUntil, 0, address(0), 0, address(0));
            bytes memory auth = ecdsa(ALICE_PK, wrpL.mtxDigest(u));
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, sels[i]));
            wrpL.mtxExecute(u, UACall.auth(u.from, auth));
        }
        // the positive control: one thing differs, the call
        MetaTxLib.MetaTransaction memory ok = MetaTxLib.MetaTransaction(alice, abi.encodeCall(IMetaTx.cancelNonce, (9)), 5, 0,
            block.timestamp + 300, 0, address(0), 0, address(0));
        wrpL.executeMetaTransaction(ok, ecdsa(ALICE_PK, MtxDigest.metaTx(address(wrpL), ok)));
        assertEq(wrpL.mtxNonce(MetaTxLib.pad(alice), 9), 1);
    }
}

contract OrderRowsPqzTest is OrderRows, PqzFixture {
    uint256 internal rowSalt;

    function setUp() public {
        _stack();
        _releaseWrapped();
    }

    function _kind() internal pure override returns (string memory) {
        return "pqz";
    }

    function _normalKind() internal override returns (NormalToken) {
        return NormalToken(address(_newToken(bytes32(++rowSalt))));
    }

    function _wrappedKind(address leg) internal override returns (WrappedToken) {
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = 1 << GovernanceBits.PAYABLE;
        c.lockedFeatures = 0; // the fixture locks MINTABLE for its minter (B-06); this token has neither
        c.roles.minter = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(leg, 1, 1);
        return WrappedToken(factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ, 1, abi.encode(c), "row"));
    }
}

contract OrderRowsZetherTest is OrderRows, ZetherFixture {
    uint256 internal rowSalt;

    function setUp() public {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
    }

    function _kind() internal pure override returns (string memory) {
        return "zether";
    }

    function _normalKind() internal override returns (NormalToken) {
        return NormalToken(address(_newToken(false, bytes32(++rowSalt))));
    }

    function _wrappedKind(address leg) internal override returns (WrappedToken) {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        c.features = 1 << GovernanceBits.PAYABLE;
        c.lockedFeatures = 0; // the fixture locks MINTABLE for its minter (B-06); this token has neither
        c.roles.minter = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(leg, 1, 1);
        return WrappedToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), "row")));
    }
}
