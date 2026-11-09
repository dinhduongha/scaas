// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs, dexArgs} from "../../script/KindModules.sol";

import {IGovernanceRouter} from "../../src/governance/IGovernanceRouter.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {IMetaTxAddress} from "../../src/metatx/IMetaTxAddress.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Test, stdStorage, StdStorage} from "forge-std/Test.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MetaTxBase} from "../../src/metatx/MetaTxBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
import {HederaMandateWallet} from "../../src/hedera/HederaMandateWallet.sol";
import {SmartKeyAccount, SubjectKey, KeyKind, AccountSig} from "../../src/account/SmartKeyAccount.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {UACall} from "../ua/UACall.sol";
import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {TokenStore} from "../../src/metatx/TokenStore.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {regArgs} from "../helpers/Catalogue.sol";
import {Holder} from "../as/helpers/RegFixture.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {VM, TYPED_OPS, TYPED_OPS_LEGACY, SALTED_DOMAIN, checkRow, onChain, domainOf, rowEnvelope, rowEnvelope2, msgField, domainField} from
    "./NamedEntry.t.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// `built` (the entry's call from the message's fields) is the row's calldata under `kind`; that calldata runs on `c` from
/// the row's relayer, the signature replaced by the one under `c`'s domain.
function runRow(string memory j, string memory op, string memory kind, address c, bytes memory built) returns (bytes memory ret) {
    bool ok;
    (ok, ret) = tryRow(j, op, kind, c, built);
    if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
}

/// `runRow` that returns the call's outcome: a row whose fillers the op itself refuses still has to get that far.
function tryRow(string memory j, string memory op, string memory kind, address c, bytes memory built) returns (bool ok, bytes memory ret) {
    return tryRowAs(j, op, kind, c, c, VM.parseJsonAddress(j, msgField(op, "relayer")), built);
}

/// `tryRow` for a row signed in the domain of `signedIn` (an order, in its sell token's), sent by `sender`.
function tryRowAs(string memory j, string memory op, string memory kind, address c, address signedIn, address sender, bytes memory built)
    returns (bool ok, bytes memory ret)
{
    checkRow(j, op, kind);
    bytes memory cd = VM.parseJsonBytes(j, domainField(op, kind, "calldata"));
    require(keccak256(built) == keccak256(cd), "calldata");
    swap(cd, VM.parseJsonBytes(j, domainField(op, kind, "signature")), onChain(j, op, signedIn));
    VM.prank(sender);
    (ok, ret) = c.call(cd);
}

// The ordered cancel on ids (Q2), on the tokens, the router and the mandate wallets.
string constant UA_CANCEL_NONCE = "mtxCancelNonce((bytes32,uint256,uint256,uint256,uint32,address,uint256,address),uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))";

/// pay-meta-tax T41: a pay row's `PayMeta` (`domains.<kind>.extra.meta`), the entry's last parameter.
function rowMeta(string memory j, string memory op, string memory kind) pure returns (MetaTxLib.PayMeta memory m) {
    string memory p = domainField(op, kind, "extra.meta.");
    m.salt = VM.parseJsonBytes32(j, string.concat(p, "salt"));
    m.payNo = VM.parseJsonBytes32(j, string.concat(p, "payNo"));
    m.save = VM.parseJsonBool(j, string.concat(p, "save"));
    m.schema = uint16(VM.parseJsonUint(j, string.concat(p, "schema")));
    m.body = VM.parseJsonBytes(j, string.concat(p, "body"));
}

/// `to` in place of `old`, the same length, in `cd`.
function swap(bytes memory cd, bytes memory old, bytes memory to) pure {
    uint256 at = find(cd, old);
    for (uint256 i; i < old.length; ++i) cd[at + i] = to[i];
}

/// ua-mtx-merge T11 (MD-7): a `UA…` row names its merged entry `sel` (`mtx…`); its own calldata runs on `c`, the signature
/// under `c`'s domain. (T3-T7 ran the `ua*` calldata of the row under `sel`, until the rows were regenerated.)
function runRowRenamed(string memory j, string memory op, string memory kind, address c, bytes memory built, bytes4 sel) {
    checkRow(j, op, kind);
    bytes memory cd = VM.parseJsonBytes(j, domainField(op, kind, "calldata"));
    require(bytes4(cd) == sel, "the row names the merged mtx entry");
    require(keccak256(built) == keccak256(cd), "the row: the merged calldata");
    swap(cd, VM.parseJsonBytes(j, domainField(op, kind, "signature")), onChain(j, op, c));
    VM.prank(VM.parseJsonAddress(j, msgField(op, "relayer")));
    (bool ok, bytes memory ret) = c.call(cd);
    if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
}

/// ua-mtx-merge T3: the row of a retired address entry (R23): its own calldata finds no function on `c`. T11 (MD-7): the row
/// is read from `TYPED_OPS_LEGACY`.
function rowHasNoEntry(string memory j, string memory op, string memory kind, address c, bytes memory built) {
    checkRow(j, op, kind);
    bytes memory cd = VM.parseJsonBytes(j, domainField(op, kind, "calldata"));
    require(keccak256(built) == keccak256(cd), "the row: the old calldata");
    VM.prank(VM.parseJsonAddress(j, msgField(op, "relayer")));
    (bool ok, bytes memory ret) = c.call(cd);
    require(!ok && ret.length == 0, "a retired entry runs");
}

function find(bytes memory hay, bytes memory needle) pure returns (uint256) {
    for (uint256 i; i + needle.length <= hay.length; ++i) {
        uint256 k;
        while (k < needle.length && hay[i + k] == needle[k]) ++k;
        if (k == needle.length) return i;
    }
    revert("signature not in the calldata");
}

/// typed-signing C2 (TS-D14): every named entry of the base and the public tokens runs its `typed_ops.json` row: the row
/// by itself (`checkRow`), its calldata equal to the message's fields, then the row's own calldata on a contract, under
/// that contract's domain (the signature re-made over the row's `structHash`, so the entry hashes what clientkeys hashed).
contract TypedOpsTest is UALedgerBase {
    using stdStorage for StdStorage;

    string internal j;
    uint256 internal pk;
    address internal signer;
    uint256 internal constant SUPPLY = 10_000_000;

    function setUp() public override {
        super.setUp();
        j = vm.readFile(TYPED_OPS);
        pk = uint256(vm.parseJsonBytes32(j, ".key.private"));
        signer = vm.parseJsonAddress(j, ".key.address");
    }

    /// ua-mtx-merge T11 (MD-7): a retired row, from the rows as they stood before the merge (the same key).
    modifier legacyRows() {
        j = vm.readFile(TYPED_OPS_LEGACY);
        _;
    }

    // ------------------------------------------------------------------ the row

    function _uint(string memory op, string memory f) internal view returns (uint256) {
        return vm.parseJsonUint(j, msgField(op, f));
    }

    function _addr(string memory op, string memory f) internal view returns (address) {
        return vm.parseJsonAddress(j, msgField(op, f));
    }

    function _b32(string memory op, string memory f) internal view returns (bytes32) {
        return vm.parseJsonBytes32(j, msgField(op, f));
    }

    function _sigOf(string memory op) internal view returns (bytes memory) {
        return vm.parseJsonBytes(j, domainField(op, "token", "signature"));
    }

    function _uaSigOf(string memory op) internal view returns (IUARegistry.UASig memory s) {
        s.signature = _sigOf(op);
    }

    function _abi(string memory op) internal view returns (string memory) {
        return vm.parseJsonString(j, domainField(op, "token", "abi"));
    }

    function _uaEnv(string memory op) internal view returns (MetaTxLib.UAEnvelope memory u) {
        MetaTxLib.Envelope memory e = rowEnvelope2(j, op);
        u = MetaTxLib.UAEnvelope(_b32(op, "from"), e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee, e.feeRecipient);
    }

    function _run(string memory op, address c, bytes memory built) internal returns (bytes memory) {
        return runRow(j, op, "token", c, built);
    }

    function _feeOf(string memory op, uint256 basis) internal view returns (uint256) {
        return basis * _uint(op, "fee") / 1_000_000;
    }

    // ------------------------------------------------------------------ fixtures of the rows' addresses

    function _fund(WrappedToken w, MockERC20 u, uint256 amount) internal {
        u.mint(signer, amount);
        vm.startPrank(signer);
        u.approve(address(w), amount);
        w.wrap(address(u), amount);
        vm.stopPrank();
    }

    /// A one-leg 1:1 wrapper whose outside leg sits at the row's `underlying`, the signer funded.
    function _rowLeg(string memory op) internal returns (WrappedToken w, MockERC20 u) {
        address at = _addr(op, "underlying");
        deployCodeTo("Mocks.sol:MockERC20", abi.encode("Leg", "LEG", uint8(6)), at);
        u = MockERC20(at);
        w = _wrapper(at);
        u.mint(signer, SUPPLY);
        vm.prank(signer);
        u.approve(address(w), SUPPLY);
    }

    /// A SCaaS ledger leg at the row's `underlying` and a wrapper at ten leg units per unit (the rows' `minOut`s are
    /// fillers above `wrapped`), the signer holding its units; the registry answers for the row's `to`.
    function _rowLedgerLeg(string memory op) internal returns (WrappedToken w, NormalToken l) {
        address at = _addr(op, "underlying");
        l = _tokenAt(at);
        w = _wrapperAt(at, 1, 10);
        l.approve(address(w), SUPPLY);
        w.wrap(SUPPLY);
        w.transfer(signer, SUPPLY / 10);
        vm.mockCall(REG_L, abi.encodeCall(IUARegistry.kindOf, (_b32(op, "to"))), abi.encode(UAKinds.P256));
    }

    /// A SCaaS ledger token at a row's address, its supply here.
    function _tokenAt(address at) internal returns (NormalToken l) {
        address impl = address(new NormalToken(address(this), kindArgs(0, address(this), "")));
        vm.etch(at, EnvKit.runtime(impl, EnvKit.env(chainUidA, REG_L, address(0), false)));
        l = NormalToken(at);
        l.initialize(nid(address(this)), 1, abi.encode(normalInit("Leg", "LEG", 6, SUPPLY, address(this), address(this))));
    }

    // ------------------------------------------------------------------ test_typedOpsVectors_<op>

    function test_typedOpsVectors_CancelNonce() public {
        string memory op = "CancelNonce";
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 lane = _uint(op, "lane");
        bytes memory built = abi.encodeCall(IMetaTxAddress.mtxCancelNonce, (e, lane, _sigOf(op, "account")));
        // ua-mtx-merge T1, meaning: a token has no address `mtxCancelNonce` (Q2, MD-1); the row runs on the wallets only
        (bool ok, bytes memory ret) = address(tok).call(built);
        assertFalse(ok, "no token entry");
        assertEq(ret.length, 0, "no such function");
        assertEq(tok.mtxNonce(MetaTxLib.pad(e.from), lane), 0, "the signed lane, untouched");

        // ua-mtx-merge T3b (Q6), meaning: nor does a mandate wallet (its cancel is `mtxCancelNonce` on ids); the row runs
        // on the account only (MD-7: its `on` narrows to `SmartKeyAccount`, T11)
        MandateWallet wallet = new MandateWallet(MetaTxLib.pad(e.from), chainUidA, address(0), false);
        (ok, ret) = address(wallet).call(built);
        assertFalse(ok, "no wallet entry");
        assertEq(ret.length, 0, "no such function");

        // on an account `from` is not the account: an outside signer cancels its own lane there (`bytes sig`). T11 (MD-7,
        // Q6): the row's `on` is `SmartKeyAccount` only, its one domain `account`
        SmartKeyAccount acct = SmartKeyAccount(payable(new SmartKeyAccountFactory(chainUidA).deploy(
            SubjectKey(KeyKind.SECP256K1, _pad(e.from), 0, 0, 0), address(0xD00D))));
        assertEq(abi.encode(vm.parseJsonKeys(j, string.concat(".ops.", op, ".domains"))), abi.encode(_one("account")));
        built = abi.encodeCall(IMetaTxAddress.mtxCancelNonce, (e, lane, _sigOf(op, "account")));
        runRow(j, op, "account", address(acct), built);
        assertEq(acct.mtxNonce(e.from, lane), 1);
    }

    /// ua-mtx-merge T3 (R23), meaning: the address `mtxBurn` / `Burn` left the token; the row (retired by T11, MD-7) finds no
    /// entry. The burn is `UABurn`'s row, below, under `mtxBurn`.
    function test_typedOpsVectors_BurnRowHasNoEntry() public legacyRows {
        string memory op = "Burn";
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 amount = _uint(op, "amount");
        tok.mint(e.from, SUPPLY);
        rowHasNoEntry(j, op, "token", address(tok), abi.encodeWithSignature(
            "mtxBurn((address,uint256,uint256,uint256,uint32,address,uint256,address),uint256,bytes)", e, amount, _sigOf(op)));
        assertEq(tok.balanceOf(e.from), SUPPLY);
        assertEq(tok.mtxNonce(MetaTxLib.pad(e.from), e.batch), 0);
    }

    function test_typedOpsVectors_UABurn() public {
        string memory op = "UABurn";
        MetaTxLib.UAEnvelope memory u = _uaEnv(op);
        uint256 amount = _uint(op, "amount");
        address from = address(uint160(uint256(u.from)));
        tok.mint(from, SUPPLY);
        runRowRenamed(j, op, "token", address(tok), abi.encodeCall(NormalToken.mtxBurn, (u, amount, _uaSigOf(op))),
            NormalToken.mtxBurn.selector);
        assertEq(tok.balanceOf(from), SUPPLY - amount - _feeOf(op, amount));
        assertEq(tok.balanceOf(u.feeRecipient), _feeOf(op, amount));
        assertEq(tok.mtxNonce(u.from, u.batch), 1);
    }

    function test_typedOpsVectors_Wrap() public {
        string memory op = "Wrap";
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 amount = _uint(op, "amount");
        und.mint(e.from, amount);
        vm.prank(e.from);
        und.approve(address(wrp), amount);
        _run(op, address(wrp), abi.encodeWithSignature(_abi(op), e, amount, _sigOf(op)));
        assertEq(wrp.balanceOf(e.from), amount - e.fee, "the ABSOLUTE fee from the minted units");
        assertEq(wrp.balanceOf(e.feeRecipient), e.fee);
        assertEq(wrp.mtxNonce(MetaTxLib.pad(e.from), e.batch), 1);
    }

    function test_typedOpsVectors_WrapLeg() public {
        string memory op = "WrapLeg";
        (WrappedToken w, MockERC20 u) = _rowLeg(op);
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 amount = _uint(op, "amount");
        _run(op, address(w), abi.encodeCall(WrappedToken.mtxWrapLeg, (e, address(u), amount, _sigOf(op))));
        assertEq(w.balanceOf(e.from), amount - e.fee);
        assertEq(w.balanceOf(e.feeRecipient), e.fee);
    }

    /// ua-mtx-merge T3 (R23), meaning: the address `mtxUnwrap` / `Unwrap` left the token; the row finds no entry (MD-7).
    function test_typedOpsVectors_UnwrapRowHasNoEntry() public legacyRows {
        string memory op = "Unwrap";
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 wrapped = _uint(op, "wrapped");
        address recipient = _addr(op, "recipient");
        _fund(wrp, und, SUPPLY);
        rowHasNoEntry(j, op, "token", address(wrp), abi.encodeWithSignature("mtxUnwrap((address,uint256,uint256,uint256,uint32,address,uint256,address),uint256,address,uint256,bytes)",
            e, wrapped, recipient, _uint(op, "minOut"), _sigOf(op)));
        assertEq(und.balanceOf(recipient), 0);
        assertEq(wrp.balanceOf(e.from), SUPPLY);
    }

    function test_typedOpsVectors_UAUnwrap() public {
        string memory op = "UAUnwrap";
        MetaTxLib.UAEnvelope memory u = _uaEnv(op);
        uint256 wrapped = _uint(op, "wrapped");
        address recipient = _addr(op, "recipient");
        _fund(wrp, und, SUPPLY);
        runRowRenamed(j, op, "token", address(wrp), abi.encodeWithSignature(_abi(op), u, wrapped, recipient,
            _uint(op, "minOut"), _uaSigOf(op)), WrappedToken.mtxUnwrap.selector);
        assertEq(und.balanceOf(recipient), wrapped);
        assertEq(wrp.balanceOf(signer), SUPPLY - wrapped - _feeOf(op, wrapped));
        assertEq(wrp.balanceOf(u.feeRecipient), _feeOf(op, wrapped));
        assertEq(wrp.mtxNonce(u.from, u.batch), 1);
    }

    /// ua-mtx-merge T3 (R23), meaning: the address `mtxUnwrapLeg` / `UnwrapLeg` left the token; no entry (MD-7).
    function test_typedOpsVectors_UnwrapLegRowHasNoEntry() public legacyRows {
        string memory op = "UnwrapLeg";
        (WrappedToken w, MockERC20 leg) = _rowLeg(op);
        vm.prank(rowEnvelope(j, op).from);
        w.wrap(SUPPLY);
        bytes memory args = abi.encode(rowEnvelope(j, op), address(leg), _uint(op, "wrapped"), _addr(op, "recipient"),
            _uint(op, "minOut"), _sigOf(op));
        rowHasNoEntry(j, op, "token", address(w), bytes.concat(bytes4(keccak256(
            "mtxUnwrapLeg((address,uint256,uint256,uint256,uint32,address,uint256,address),address,uint256,address,uint256,bytes)")),
            args));
        assertEq(leg.balanceOf(_addr(op, "recipient")), 0);
    }

    function test_typedOpsVectors_UAUnwrapLeg() public {
        string memory op = "UAUnwrapLeg";
        (WrappedToken w, MockERC20 leg) = _rowLeg(op);
        vm.prank(signer);
        w.wrap(SUPPLY);
        bytes memory args = abi.encode(_uaEnv(op), address(leg), _uint(op, "wrapped"), _addr(op, "recipient"),
            _uint(op, "minOut"), _uaSigOf(op));
        runRowRenamed(j, op, "token", address(w), bytes.concat(WrappedToken.mtxUnwrapLeg.selector, args),
            WrappedToken.mtxUnwrapLeg.selector);
        assertEq(leg.balanceOf(_addr(op, "recipient")), _uint(op, "wrapped"));
        assertEq(w.balanceOf(_uaEnv(op).feeRecipient), _feeOf(op, _uint(op, "wrapped")));
    }

    function test_typedOpsVectors_AddReserve() public {
        string memory op = "AddReserve";
        (WrappedToken w, MockERC20 leg) = _rowLeg(op);
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 amount = _uint(op, "amount");
        vm.prank(e.from);
        w.wrap(e.fee);
        _run(op, address(w), abi.encodeCall(WrappedToken.mtxAddReserve, (e, address(leg), amount, _sigOf(op))));
        (,, uint256 reserve,,) = w.legOf(address(leg));
        assertEq(reserve, e.fee + amount);
        assertEq(w.balanceOf(e.feeRecipient), e.fee);
    }

    function test_typedOpsVectors_WrapToUA() public {
        string memory op = "WrapToUA";
        (WrappedToken w, MockERC20 leg) = _rowLeg(op);
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 amount = _uint(op, "amount");
        bytes32 to = _b32(op, "to");
        vm.mockCall(REG_L, abi.encodeCall(IUARegistry.kindOf, (to)), abi.encode(UAKinds.P256));
        vm.prank(e.from);
        w.wrap(e.fee);
        _run(op, address(w), abi.encodeCall(WrappedToken.mtxWrapToUA, (e, address(leg), amount, to, _sigOf(op))));
        assertEq(w.balanceOfUA(to), amount);
        assertEq(w.balanceOf(e.feeRecipient), e.fee);
    }

    /// ua-mtx-merge T3 (R23), meaning: the address `mtxUnwrapToUA` / `UnwrapToUA` left the token; no entry (MD-7).
    function test_typedOpsVectors_UnwrapToUARowHasNoEntry() public legacyRows {
        string memory op = "UnwrapToUA";
        (WrappedToken w, NormalToken leg) = _rowLedgerLeg(op);
        bytes memory args = abi.encode(rowEnvelope(j, op), address(leg), _uint(op, "wrapped"), _b32(op, "to"),
            _uint(op, "minOut"), _sigOf(op));
        rowHasNoEntry(j, op, "token", address(w), bytes.concat(bytes4(keccak256(
            "mtxUnwrapToUA((address,uint256,uint256,uint256,uint32,address,uint256,address),address,uint256,bytes32,uint256,bytes)")),
            args));
        assertEq(leg.balanceOfUA(_b32(op, "to")), 0);
    }

    function test_typedOpsVectors_UAUnwrapToUA() public {
        string memory op = "UAUnwrapToUA";
        (WrappedToken w, NormalToken leg) = _rowLedgerLeg(op);
        bytes memory args = abi.encode(_uaEnv(op), address(leg), _uint(op, "wrapped"), _b32(op, "to"), _uint(op, "minOut"),
            _uaSigOf(op));
        runRowRenamed(j, op, "token", address(w), bytes.concat(WrappedToken.mtxUnwrapToUA.selector, args),
            WrappedToken.mtxUnwrapToUA.selector);
        assertEq(leg.balanceOfUA(_b32(op, "to")), _uint(op, "wrapped") * 10);
        assertEq(w.balanceOf(_uaEnv(op).feeRecipient), _feeOf(op, _uint(op, "wrapped")));
    }

    // ------------------------------------------------------------------ the wallets and the account (C5)

    function _sigOf(string memory op, string memory kind) internal view returns (bytes memory) {
        return vm.parseJsonBytes(j, domainField(op, kind, "signature"));
    }

    function _abiOf(string memory op, string memory kind) internal view returns (string memory) {
        return vm.parseJsonString(j, domainField(op, kind, "abi"));
    }

    function _accountSig(string memory op) internal view returns (AccountSig memory) {
        return AccountSig(0, new bytes32[](0), _sigOf(op, "account"));
    }

    /// ua-mtx-merge T3b (Q6), meaning: the six address wallet rows (`SetMandate`, `SetPayee`, `RevokeMandate`,
    /// `PayUnderMandate`, `DelegateRevoke`, `Execute` on `wallet`) find no entry on the merged wallets, whose entries take
    /// `UAEnvelope` + `UASig` over `UA<Op>`. T11 (MD-7): the rows are retired, read from `TYPED_OPS_LEGACY`.
    function _walletRowHasNoEntry(string memory op, address c, bytes memory built) internal {
        rowHasNoEntry(j, op, "wallet", c, built);
        assertEq(MandateWallet(payable(c)).mtxNonce(MetaTxLib.pad(_addr(op, "from")), rowEnvelope(j, op).batch), 0);
    }

    function _newWallet(string memory op) internal returns (MandateWallet) {
        return new MandateWallet(MetaTxLib.pad(_addr(op, "from")), chainUidA, address(0), false);
    }

    string internal constant ENV_T = "(address,uint256,uint256,uint256,uint32,address,uint256,address)";

    function _setPayeeCall() internal view returns (bytes memory) {
        string memory op = "SetPayee";
        return abi.encodeWithSignature(string.concat("mtxSetPayee(", ENV_T, ",address,address,bool,bytes)"),
            rowEnvelope(j, op), _addr(op, "token"), _addr(op, "payee"), vm.parseJsonBool(j, msgField(op, "allowed")),
            _sigOf(op, "wallet"));
    }

    function _executeRow(address c, string memory kind, bytes memory built) internal {
        address target = _addr("Execute", "target");
        uint256 value = _uint("Execute", "value");
        vm.deal(c, value);
        runRow(j, "Execute", kind, c, built);
        assertEq(target.balance, value);
    }

    function _walletExecuteCall() internal view returns (bytes memory) {
        return abi.encodeWithSignature(_abiOf("Execute", "wallet"), rowEnvelope(j, "Execute"), _addr("Execute", "target"),
            _uint("Execute", "value"), vm.parseJsonBytes(j, msgField("Execute", "data")), _sigOf("Execute", "wallet"));
    }

    /// The six retired address rows, on `MandateWallet` and on `HederaMandateWallet` (T3b's six `…RowHasNoWalletEntry` tests
    /// and the Hedera one, in one; the merged entries run in the `UA<Op>` row tests below).
    function test_typedOpsVectors_walletAddressRowsHaveNoEntry() public legacyRows {
        string memory op = "SetMandate";
        _walletRowHasNoEntry(op, address(_newWallet(op)), abi.encodeWithSignature(
            string.concat("mtxSetMandate", "(", ENV_T, ",address,address,uint128,uint128,uint64,uint64,bytes)"),
            rowEnvelope(j, op), _addr(op, "token"), _addr(op, "delegate"), uint128(_uint(op, "maxPerPayment")),
            uint128(_uint(op, "maxPerPeriod")), uint64(_uint(op, "periodSeconds")), uint64(_uint(op, "expiry")),
            _sigOf(op, "wallet")));
        _walletRowHasNoEntry("SetPayee", address(_newWallet("SetPayee")), _setPayeeCall());
        op = "RevokeMandate";
        _walletRowHasNoEntry(op, address(_newWallet(op)), abi.encodeWithSignature(
            string.concat("mtxRevokeMandate(", ENV_T, ",address,bytes)"), rowEnvelope(j, op), _addr(op, "token"),
            _sigOf(op, "wallet")));
        op = "PayUnderMandate";
        _walletRowHasNoEntry(op, address(_newWallet(op)), abi.encodeWithSignature(_abiOf(op, "wallet"), rowEnvelope(j, op),
            _addr(op, "token"), _addr(op, "payee"), _uint(op, "amount"), _b32(op, "entryRef"), uint64(_uint(op, "epoch")),
            _sigOf(op, "wallet")));
        op = "DelegateRevoke";
        _walletRowHasNoEntry(op, address(_newWallet(op)), abi.encodeWithSignature(
            string.concat("mtxDelegateRevoke(", ENV_T, ",address,uint64,bytes)"), rowEnvelope(j, op), _addr(op, "token"),
            uint64(_uint(op, "epoch")), _sigOf(op, "wallet")));
        _walletRowHasNoEntry("Execute", address(_newWallet("Execute")), _walletExecuteCall());
        bytes32 id = MetaTxLib.pad(_addr("SetPayee", "from"));
        _walletRowHasNoEntry("SetPayee", address(new HederaMandateWallet(id, chainUidA, address(0))), _setPayeeCall());
        id = MetaTxLib.pad(_addr("Execute", "from"));
        _walletRowHasNoEntry("Execute", address(new HederaMandateWallet(id, chainUidA, address(0))), _walletExecuteCall());
    }

    // ---- ua-mtx-merge T11 (Q6, MD-11): the six `UA<Op>` rows on the merged wallet entries, ids `bytes32`, `UASig`

    function _walletEnv(string memory op) internal view returns (MetaTxLib.UAEnvelope memory u) {
        MetaTxLib.Envelope memory e = rowEnvelope2(j, op);
        u = MetaTxLib.UAEnvelope(_b32(op, "from"), e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee, e.feeRecipient);
    }

    function _walletSig(string memory op) internal view returns (IUARegistry.UASig memory s) {
        s.signature = _sigOf(op, "wallet");
    }

    /// A wallet of `0xA11` whose mandate on the row's token names `delegate_`, at the row's epoch.
    function _rowMandate(string memory op, bytes32 delegate_, uint256 cap) internal returns (MandateWallet w) {
        address token = _addr(op, "token");
        w = new MandateWallet(MetaTxLib.pad(address(0xA11)), chainUidA, address(0), false);
        vm.prank(address(0xA11));
        w.setMandate(token, delegate_, uint128(cap), uint128(cap), 1 days, uint64(block.timestamp + 1 days));
        stdstore.target(address(w)).sig("epoch(address)").with_key(token).checked_write(_uint(op, "epoch"));
    }

    function _walletRow(string memory op, MandateWallet w, bytes memory built) internal {
        assertEq(abi.encode(vm.parseJsonKeys(j, string.concat(".ops.", op, ".domains"))), abi.encode(_one("wallet")), op);
        runRow(j, op, "wallet", address(w), built);
        assertEq(w.mtxNonce(_b32(op, "from"), rowEnvelope2(j, op).batch), 1, op);
    }

    function _one(string memory k) internal pure returns (string[] memory a) {
        a = new string[](1);
        a[0] = k;
    }

    function test_typedOpsVectors_UASetMandate() public {
        string memory op = "UASetMandate";
        MandateWallet w = new MandateWallet(_b32(op, "from"), chainUidA, address(0), false);
        _walletRow(op, w, _setMandateCall(op));
        (bytes32 d,,,,,,) = w.mandates(_addr(op, "token"));
        assertEq(d, _b32(op, "delegate"));
        assertEq(d, MetaTxLib.pad(address(0xd2)), "the delegate an id: the address of the T3b row zero-padded");
        assertEq(w.epoch(_addr(op, "token")), 1);
    }

    function _setMandateCall(string memory op) internal view returns (bytes memory) {
        return abi.encodeCall(MandateWallet.mtxSetMandate, (_walletEnv(op), _addr(op, "token"), _b32(op, "delegate"),
            uint128(_uint(op, "maxPerPayment")), uint128(_uint(op, "maxPerPeriod")), uint64(_uint(op, "periodSeconds")),
            uint64(_uint(op, "expiry")), _walletSig(op)));
    }

    function _uaSetPayeeRow(MandateWallet w) internal {
        string memory op = "UASetPayee";
        address token = _addr(op, "token");
        bytes32 payee = _b32(op, "payee");
        _walletRow(op, w, abi.encodeCall(MandateWallet.mtxSetPayee, (_walletEnv(op), token, payee,
            vm.parseJsonBool(j, msgField(op, "allowed")), _walletSig(op))));
        assertTrue(w.payeeAllowed(token, payee));
    }

    function test_typedOpsVectors_UASetPayee() public {
        _uaSetPayeeRow(new MandateWallet(_b32("UASetPayee", "from"), chainUidA, address(0), false));
    }

    function test_typedOpsVectors_UARevokeMandate() public {
        string memory op = "UARevokeMandate";
        MetaTxLib.UAEnvelope memory u = _walletEnv(op);
        address token = _addr(op, "token");
        MandateWallet w = new MandateWallet(u.from, chainUidA, address(0), false);
        vm.prank(address(uint160(uint256(u.from))));
        w.setMandate(token, bytes32(uint256(0xD)), 1, 1, 1 days, uint64(block.timestamp + 1 days));
        _walletRow(op, w, abi.encodeCall(MandateWallet.mtxRevokeMandate, (u, token, _walletSig(op))));
        (bytes32 d,,,,,,) = w.mandates(token);
        assertEq(d, bytes32(0));
        assertEq(w.epoch(token), 2);
    }

    /// The delegate is the row's key; the payee the row's derived-looking id, registered here, paid by `payWithFeeToUA`.
    /// pay-meta-tax T41: the row carries its `PayMeta` (`extra.meta`), the entry's last parameter; `entryRef` its commitment.
    function test_typedOpsVectors_UAPayUnderMandate() public {
        string memory op = "UAPayUnderMandate";
        address token = _addr(op, "token");
        bytes32 payee = _b32(op, "payee");
        assertFalse(UAKinds.inNativeSpace(payee), "the row's payee is a derived id");
        MetaTxLib.PayMeta memory m = rowMeta(j, op, "wallet");
        assertEq(PayMetaKit.id(m), _b32(op, "entryRef"), "the row's entryRef commits to its PayMeta");
        MandateWallet w = _rowMandate(op, _b32(op, "from"), _uint(op, "amount"));
        _tokenAt(token).transfer(address(w), _uint(op, "amount"));
        vm.mockCall(REG_L, abi.encodeCall(IUARegistry.kindOf, (payee)), abi.encode(UAKinds.P256));
        vm.prank(address(0xA11));
        w.setPayee(token, payee, true);
        _walletRow(op, w, _payUnderMandateCall(op, m));
        assertEq(NormalToken(token).balanceOfUA(payee), _uint(op, "amount"));
        assertTrue(w.refUsed(_b32(op, "entryRef")));
    }

    function _payUnderMandateCall(string memory op, MetaTxLib.PayMeta memory m) internal view returns (bytes memory) {
        return abi.encodeCall(MandateWallet.mtxPayUnderMandate, (_walletEnv(op), _addr(op, "token"), _b32(op, "payee"),
            _uint(op, "amount"), _b32(op, "entryRef"), uint64(_uint(op, "epoch")), _walletSig(op), m));
    }

    function test_typedOpsVectors_UADelegateRevoke() public {
        string memory op = "UADelegateRevoke";
        MetaTxLib.UAEnvelope memory u = _walletEnv(op);
        address token = _addr(op, "token");
        uint64 epoch_ = uint64(_uint(op, "epoch"));
        MandateWallet w = _rowMandate(op, u.from, 1);
        _walletRow(op, w, abi.encodeCall(MandateWallet.mtxDelegateRevoke, (u, token, epoch_, _walletSig(op))));
        (bytes32 d,,,,,,) = w.mandates(token);
        assertEq(d, bytes32(0));
        assertEq(w.epoch(token), epoch_ + 1);
    }

    function _uaExecuteRow(MandateWallet w) internal {
        string memory op = "UAExecute";
        address target = _addr(op, "target");
        uint256 value = _uint(op, "value");
        vm.deal(address(w), value);
        _walletRow(op, w, abi.encodeWithSignature(_abiOf(op, "wallet"), _walletEnv(op), target, value,
            vm.parseJsonBytes(j, msgField(op, "data")), _walletSig(op)));
        assertEq(target.balance, value);
    }

    function test_typedOpsVectors_UAExecute() public {
        _uaExecuteRow(new MandateWallet(_b32("UAExecute", "from"), chainUidA, address(0), false));
    }

    /// The Hedera wallet takes the same rows (an EOA's 65-byte ECDSA; `IS_HEDERA` changes only the 64-byte HIP-632 branch).
    function test_typedOpsVectors_HederaWalletUARows() public {
        _uaSetPayeeRow(MandateWallet(payable(address(new HederaMandateWallet(_b32("UASetPayee", "from"), chainUidA, address(0))))));
        _uaExecuteRow(MandateWallet(payable(address(new HederaMandateWallet(_b32("UAExecute", "from"), chainUidA, address(0))))));
    }

    /// The ordered cancel (Q2) on a mandate wallet: the row's `UACancelNonce` in the wallet's domain.
    function test_typedOpsVectors_UACancelNonceWallet() public {
        string memory op = "UACancelNonce";
        MetaTxLib.UAEnvelope memory u = _walletEnv(op);
        uint256 lane = _uint(op, "lane");
        MandateWallet w = new MandateWallet(u.from, chainUidA, address(0), false);
        runRow(j, op, "wallet", address(w), abi.encodeWithSignature(UA_CANCEL_NONCE, u, lane, _walletSig(op)));
        assertEq(w.mtxNonce(u.from, lane), 1);
        assertEq(w.mtxNonce(u.from, u.batch), 1);
    }

    /// The ordered cancel on a token: an EOA cancels its own lane, nonce-ordered (Q2), no registry call.
    function test_typedOpsVectors_UACancelNonce() public {
        string memory op = "UACancelNonce";
        MetaTxLib.UAEnvelope memory u = _uaEnv(op);
        uint256 lane = _uint(op, "lane");
        vm.expectCall(REG_L, "", 0);
        runRowRenamed(j, op, "token", address(tok), abi.encodeWithSignature(UA_CANCEL_NONCE, u, lane, _uaSigOf(op)),
            bytes4(keccak256(bytes(UA_CANCEL_NONCE))));
        assertEq(tok.mtxNonce(u.from, lane), 1);
        assertEq(tok.mtxNonce(u.from, u.batch), 1);
        // replayed: the envelope's nonce is spent
        IUARegistry.UASig memory s;
        s.signature = onChain(j, op, address(tok));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        vm.prank(u.relayer);
        tok.mtxCancelNonce(u, lane, s);
    }

    /// The row key's signature of `UABurn` under `tok`'s domain, `relayer` / `feeRecipient` hashed as given.
    function _burnSig(string memory op, MetaTxLib.UAEnvelope memory u, uint256 amount, address relayer, address feeTo)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(vm.parseJsonBytes32(j, string.concat(".ops.", op, ".typehash")), u.from, amount, u.batch,
            u.nonce, u.validUntil, u.mode, relayer, u.fee, feeTo));
        return _ecdsa(pk, keccak256(abi.encodePacked(hex"1901", domainOf(address(tok)), sh)));
    }

    /// spec §6 (Codex medium 3): `relayer` / `feeRecipient` hash as 0 unless their mode bit is set (`MetaTxLib.canon`). A
    /// client that hands the wallet a non-zero unbound value gets a signature over another digest, which the contract refuses
    /// (nothing moves, the lane unspent); the canonical 0 under the same envelope runs, the fee to the calldata's recipient.
    function test_typedOpsVectors_unboundNonZeroSignedIsRefused() public {
        string memory op = "UABurn";
        MetaTxLib.UAEnvelope memory u = _uaEnv(op);
        u.mode = MetaTxLib.MODE_FEE_PERCENT; // the row's fee, nothing bound
        assertTrue(u.relayer != address(0) && u.feeRecipient != address(0));
        uint256 amount = _uint(op, "amount");
        address from = address(uint160(uint256(u.from)));
        tok.mint(from, SUPPLY);
        IUARegistry.UASig memory s;
        s.signature = _burnSig(op, u, amount, u.relayer, u.feeRecipient);
        vm.prank(u.relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.mtxBurn(u, amount, s);
        assertEq(tok.mtxNonce(u.from, u.batch), 0);
        s.signature = _burnSig(op, u, amount, address(0), address(0));
        vm.prank(u.relayer);
        tok.mtxBurn(u, amount, s);
        assertEq(tok.mtxNonce(u.from, u.batch), 1);
        assertEq(tok.balanceOf(u.feeRecipient), _feeOf(op, amount));
        assertEq(tok.balanceOf(from), SUPPLY - amount - _feeOf(op, amount));
    }

    /// The account of the row's key at the row's `from`: an account signs as itself (CTR-ACC-10), and the row's signature is
    /// remade under the account's domain, as for every row.
    function _rowAccount(string memory op) internal returns (SmartKeyAccount acct) {
        address from = _addr(op, "from");
        SmartKeyAccountFactory fac = new SmartKeyAccountFactory(chainUidA);
        vm.etch(from, abi.encodePacked(hex"363d3d373d3d3d363d73", fac.IMPLEMENTATION(), hex"5af43d82803e903d91602b57fd5bf3"));
        acct = SmartKeyAccount(payable(from));
        vm.prank(address(fac));
        acct.initialize(SubjectKey(KeyKind.SECP256K1, _pad(from), 0, 0, 0), address(0xD00D));
    }

    /// `kind` is 2 and `x` … `originHash` are fillers: `_checkKey` refuses them, in the self-call, past digest, signature
    /// and nonce. A valid key through the same entry: `NamedAccountTest`.
    function _refusedKeyRow(string memory op, bytes memory built) internal {
        (bool ok, bytes memory ret) = tryRow(j, op, "account", address(_rowAccount(op)), built);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(SmartKeyAccount.BadKey.selector));
    }

    function test_typedOpsVectors_AddKey() public {
        string memory op = "AddKey";
        _refusedKeyRow(op, abi.encodeCall(SmartKeyAccount.mtxAddKey, (rowEnvelope(j, op), uint8(_uint(op, "kind")), _b32(op, "x"),
            _b32(op, "y"), _b32(op, "rpIdHash"), _b32(op, "originHash"), _accountSig(op))));
    }

    function test_typedOpsVectors_RotateKey() public {
        string memory op = "RotateKey";
        _refusedKeyRow(op, abi.encodeCall(SmartKeyAccount.mtxRotateKey, (rowEnvelope(j, op), _uint(op, "index"),
            uint8(_uint(op, "kind")), _b32(op, "x"), _b32(op, "y"), _b32(op, "rpIdHash"), _b32(op, "originHash"), _accountSig(op))));
    }

    function test_typedOpsVectors_RemoveKey() public {
        string memory op = "RemoveKey";
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 index = _uint(op, "index");
        SmartKeyAccount acct = _rowAccount(op);
        stdstore.target(address(acct)).sig("nextKeyIndex()").checked_write(index);
        vm.prank(address(acct));
        assertEq(acct.addKey(SubjectKey(KeyKind.SECP256K1, bytes32(uint256(0xB0B)), 0, 0, 0)), index);
        runRow(j, op, "account", address(acct), abi.encodeCall(SmartKeyAccount.mtxRemoveKey, (e, index, _accountSig(op))));
        assertEq(acct.keyCount(), 1);
        assertEq(uint8(acct.keyAt(index).kind), 0);
    }

    function test_typedOpsVectors_SetGuardian() public {
        string memory op = "SetGuardian";
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        address guardian = _addr(op, "guardian");
        SmartKeyAccount acct = _rowAccount(op);
        runRow(j, op, "account", address(acct), abi.encodeCall(SmartKeyAccount.mtxSetGuardian, (e, guardian, _accountSig(op))));
        assertEq(acct.guardian(), guardian);
        assertEq(acct.mtxNonce(e.from, e.batch), 1);
    }

    function test_typedOpsVectors_CancelRecovery() public {
        string memory op = "CancelRecovery";
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        SmartKeyAccount acct = _rowAccount(op);
        vm.prank(acct.guardian());
        acct.initiateRecovery(SubjectKey(KeyKind.SECP256K1, bytes32(uint256(0xB0B)), 0, 0, 0));
        runRow(j, op, "account", address(acct), abi.encodeCall(SmartKeyAccount.mtxCancelRecovery, (e, _accountSig(op))));
        assertEq(acct.pendingRecovery(), bytes32(0));
        assertEq(acct.recoveryReadyAt(), 0);
    }

    function test_typedOpsVectors_ExecuteAccount() public {
        SmartKeyAccount acct = _rowAccount("Execute");
        _executeRow(address(acct), "account", abi.encodeWithSignature(_abiOf("Execute", "account"), rowEnvelope(j, "Execute"),
            _addr("Execute", "target"), _uint("Execute", "value"), vm.parseJsonBytes(j, msgField("Execute", "data")),
            _accountSig("Execute")));
        assertEq(acct.mtxNonce(signer, 7), 1);
    }

    // ------------------------------------------------------------------ what the entries keep and drop

    string internal constant EXECUTE_WITH_FEE = "mtxExecuteWithFee((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)";
    string internal constant E_TAIL = "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

    function _domain(address c) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) = IERC5267(c).eip712Domain();
        return keccak256(abi.encode(SALTED_DOMAIN, keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt));
    }

    /// The digest of `<head><E>` over `(from, args…, E)`, built here: the wallet's side of a named entry.
    function _digest(address c, string memory head, bytes32 from, bytes memory args, MetaTxLib.Envelope memory e)
        internal view returns (bytes32)
    {
        bytes32 r = e.mode & RR != 0 ? bytes32(uint256(uint160(e.relayer))) : bytes32(0);
        bytes32 f = e.mode & RF != 0 ? bytes32(uint256(uint160(e.feeRecipient))) : bytes32(0);
        bytes32 structHash = keccak256(bytes.concat(abi.encode(keccak256(bytes(string.concat(head, E_TAIL))), from), args,
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, r, e.fee, f)));
        return keccak256(abi.encodePacked(hex"1901", _domain(c), structHash));
    }

    function _env(address from, uint256 nonce, uint32 mode, uint256 fee, address feeTo)
        internal view returns (MetaTxLib.Envelope memory e)
    {
        e = MetaTxLib.Envelope(from, 3, nonce, block.timestamp + 300, mode, address(0), fee, feeTo);
    }

    function _uaE(MetaTxLib.Envelope memory e, bytes32 from) internal pure returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(from, e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee, e.feeRecipient);
    }

    /// ua-mtx-merge T3 (R23): the merged `mtxUnwrap` signs `UAUnwrap` (a native id zero-padded, its own key).
    string internal constant UNWRAP_HEAD = "UAUnwrap(bytes32 from,uint256 wrapped,address recipient,uint256 minOut,";

    function _unwrapSig(uint256 key, WrappedToken w, MetaTxLib.Envelope memory e, uint256 wrapped)
        internal view returns (IUARegistry.UASig memory s)
    {
        s.signature = _ecdsa(key, _digest(address(w), UNWRAP_HEAD, _pad(e.from), abi.encode(wrapped, bob, uint256(0)), e));
    }

    function test_removedAliasesGone() public {
        MetaTxLib.MetaTransaction memory m = _generic(alice, 0);
        address[2] memory kinds = [address(tok), address(wrp)];
        for (uint256 i; i < 2; ++i) {
            (bool ok, bytes memory ret) = kinds[i].call(abi.encodeWithSignature(EXECUTE_WITH_FEE, m, bytes("")));
            assertFalse(ok);
            assertEq(ret.length, 0, "no such function");
        }
    }

    /// The flat `uaUnwrap(bytes32 from, …)` went to legacy (owner 2026-11-01): the named overload is the only one.
    function test_flatUaUnwrapGone() public {
        (bool ok, bytes memory ret) = address(wrp).call(abi.encodeWithSelector(bytes4(0x8de5ca31), uaP));
        assertFalse(ok);
        assertEq(ret.length, 0, "no such function");
    }

    /// ua-mtx-merge T1 (MD-1): `IMetaTx` is the core (`executeMetaTransaction`, `mtxSelectors`, `chainUid`,
    /// `supportedModes`, `cancelNonce`); the five address entries moved to `IMetaTxAddress` (the wallets). Old id
    /// 0x2f1aa7fe = 0xae99c265 ^ 0x8183659b, the id of the five that left; 0xf6695913 is the id before `mtxCancelNonce`
    /// joined (owner 2026-11-01).
    function test_iMetaTxIdPinned() public view {
        assertEq(type(IMetaTx).interfaceId, bytes4(0xae99c265));
        assertEq(type(IMetaTxAddress).interfaceId, bytes4(0x8183659b));
        assertEq(type(IMetaTx).interfaceId ^ type(IMetaTxAddress).interfaceId, bytes4(0x2f1aa7fe));
        assertEq(type(IMetaTx).interfaceId ^ type(IMetaTxAddress).interfaceId ^ IMetaTxAddress.mtxCancelNonce.selector,
            bytes4(0xf6695913));
        assertTrue(tok.supportsInterface(0xae99c265));
        assertTrue(wrp.supportsInterface(0xae99c265));
        assertFalse(tok.supportsInterface(0x2f1aa7fe));
        assertFalse(tok.supportsInterface(0x8183659b));
    }

    function _generic(address from, uint256 nonce) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m = MetaTxLib.MetaTransaction(from, abi.encodeCall(NormalToken.burn, (1)), 3, nonce, block.timestamp + 300, 0,
            address(0), 0, address(0));
    }

    function _genericUA(bytes32 from, uint256 nonce) internal view returns (MetaTxLib.UAMetaTransaction memory m) {
        m = MetaTxLib.UAMetaTransaction(from, abi.encodeCall(NormalToken.burn, (1)), 3, nonce, block.timestamp + 300, 0,
            address(0), 0, address(0));
    }

    /// The generic entries (owner 2026-10-31) and `executeMetaTransaction` (owner 2026-11-01) run, and share the lane.
    /// ua-mtx-merge T1, meaning: the address `mtxExecute` / `mtxBatch` left tokens (MD-1); the address struct runs through
    /// `executeMetaTransaction` (R3), the generic entries are the merged `mtxExecute` / `mtxBatch` on ids.
    function test_genericEntriesKept() public {
        uint256 supply = tok.totalSupply();
        MetaTxLib.MetaTransaction memory m = _generic(alice, 0);
        tok.executeMetaTransaction(m, _ecdsa(ALICE_PK, MtxDigest.metaTx(address(tok), m)));
        m = _generic(alice, 1);
        assertTrue(tok.executeMetaTransaction(m, _ecdsa(ALICE_PK, MtxDigest.metaTx(address(tok), m))));
        bytes[] memory sigs = new bytes[](1);
        MetaTxLib.UAMetaTransaction memory u = _genericUA(_pad(alice), 2);
        tok.mtxExecute(u, UACall.auth(u.from, _authM(address(tok), u)));

        u = _genericUA(_pad(alice), 3);
        tok.mtxExecute(u, UACall.auth(u.from, _authM(address(tok), u)));
        MetaTxLib.UAMetaTransaction[] memory us = new MetaTxLib.UAMetaTransaction[](1);
        us[0] = _genericUA(_pad(alice), 4);
        sigs[0] = _authM(address(tok), us[0]);
        assertTrue(tok.mtxBatch(us, UACall.auths(us, sigs)));

        assertEq(tok.totalSupply(), supply - 5);
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), 3), 5);
    }

    /// ua-mtx-merge T3, meaning: on the `UABurn` row under the merged `mtxBurn` (R23); there is no second (`ua*`) entry.
    function test_namedEntryReplayRefused() public {
        string memory op = "UABurn";
        MetaTxLib.UAEnvelope memory u = _uaEnv(op);
        MetaTxLib.Envelope memory e = rowEnvelope2(j, op);
        e.from = address(uint160(uint256(u.from)));
        tok.mint(e.from, SUPPLY);
        runRowRenamed(j, op, "token", address(tok), abi.encodeCall(NormalToken.mtxBurn, (u, _uint(op, "amount"), _uaSigOf(op))),
            NormalToken.mtxBurn.selector);
        IUARegistry.UASig memory sig;
        sig.signature = onChain(j, op, address(tok));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        vm.prank(e.relayer);
        tok.mtxBurn(u, _uint(op, "amount"), sig);

        // the lane is the generic path's: the generic entry finds nonce 0 gone too
        MetaTxLib.MetaTransaction memory m = _generic(e.from, 0);
        m.batch = e.batch;
        bytes memory generic = _ecdsa(pk, MtxDigest.metaTx(address(tok), m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        tok.executeMetaTransaction(m, generic);
    }

    function test_namedEntryOtherOpDigestRefused() public {
        und.mint(alice, 1_000);
        vm.startPrank(alice);
        und.approve(address(wrp), 1_000);
        wrp.wrap(1_000);
        vm.stopPrank();
        MetaTxLib.Envelope memory e = _env(alice, 0, 0, 0, address(0));
        IUARegistry.UASig memory sig = _unwrapSig(ALICE_PK, wrp, e, 100);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        wrp.mtxUnwrapLeg(_uaE(e, _pad(alice)), address(und), 100, bob, 0, sig);
        wrp.mtxUnwrap(_uaE(e, _pad(alice)), 100, bob, 0, sig);
        assertEq(und.balanceOf(bob), 100);
    }

    function test_namedEntryFeeClass() public {
        und.mint(alice, 1_000_000);
        vm.startPrank(alice);
        und.approve(address(wrp), 1_000_000);
        wrp.wrap(500_000);
        vm.stopPrank();

        // AMOUNT(0): PERCENT on `wrapped`, 1 % at most (CTR-MTX-20)
        MetaTxLib.Envelope memory e = _env(alice, 0, PCT | RF, 10_000, FEE_TO);
        wrp.mtxUnwrap(_uaE(e, _pad(alice)), 100_000, bob, 0, _unwrapSig(ALICE_PK, wrp, e, 100_000));
        assertEq(wrp.balanceOf(FEE_TO), 1_000);

        // ABSOLUTE: PERCENT refused, FIXED the signed amount
        string memory head = "Wrap(address from,uint256 amount,";
        e = _env(alice, 1, PCT, 1, address(0));
        bytes memory sig = _ecdsa(ALICE_PK, _digest(address(wrp), head, _pad(alice), abi.encode(uint256(1_000)), e));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, bytes4(keccak256("wrap(uint256)")), PCT));
        (bool ok, bytes memory ret) = address(wrp).call(abi.encodeWithSignature(_abi("Wrap"), e, uint256(1_000), sig));
        assertTrue(ok, string(ret));

        e = _env(alice, 1, FIX | RF, 77, FEE_TO);
        sig = _ecdsa(ALICE_PK, _digest(address(wrp), head, _pad(alice), abi.encode(uint256(1_000)), e));
        (ok, ret) = address(wrp).call(abi.encodeWithSignature(_abi("Wrap"), e, uint256(1_000), sig));
        assertTrue(ok, string(ret));
        assertEq(wrp.balanceOf(FEE_TO), 1_000 + 77);
    }

    /// A derived signer's `UASig` goes to the registry as it came (no `bytes` blob on a named `ua*` entry).
    function test_namedUADerivedSigner() public {
        tok.mintToUA(uaP, 1_000);
        MetaTxLib.Envelope memory e = _env(address(0), 0, 0, 0, address(0));
        bytes32 d = _digest(address(tok), "UABurn(bytes32 from,uint256 amount,", uaP, abi.encode(uint256(100)), e);
        IUARegistry.UASig memory s = UACall.auth(uaP, _authFor(uaP, d));
        tok.mtxBurn(_uaE(e, uaP), 100, s);
        assertEq(tok.balanceOfUA(uaP), 900);
        assertEq(tok.mtxNonce(uaP, e.batch), 1);

        // the same signature on the next nonce: another digest
        e.nonce = 1;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, uaP));
        tok.mtxBurn(_uaE(e, uaP), 100, s);
    }

    function _uaSigFor(bytes32 ua, address c, string memory head, bytes memory args, MetaTxLib.Envelope memory e)
        internal view returns (IUARegistry.UASig memory)
    {
        return UACall.auth(ua, _authFor(ua, _digest(c, head, ua, args, e)));
    }

    function test_namedUADerivedUnwrap() public {
        _wrapFor(alice, 1_000);
        vm.prank(alice);
        wrp.transferToUA(uaP, 1_000);
        MetaTxLib.Envelope memory e = _env(address(0), 0, 0, 0, address(0));
        bytes memory args = abi.encode(uint256(100), bob, uint256(100));
        wrp.mtxUnwrap(_uaE(e, uaP), 100, bob, 100,
            _uaSigFor(uaP, address(wrp), "UAUnwrap(bytes32 from,uint256 wrapped,address recipient,uint256 minOut,", args, e));
        assertEq(und.balanceOf(bob), 100);
        assertEq(wrp.balanceOfUA(uaP), 900);

        e.nonce = 1;
        args = abi.encode(address(und), uint256(200), bob, uint256(200));
        wrp.mtxUnwrapLeg(_uaE(e, uaP), address(und), 200, bob, 200, _uaSigFor(uaP, address(wrp),
            "UAUnwrapLeg(bytes32 from,address underlying,uint256 wrapped,address recipient,uint256 minOut,", args, e));
        assertEq(und.balanceOf(bob), 300);
        assertEq(wrp.balanceOfUA(uaP), 700);
        assertEq(wrp.mtxNonce(uaP, e.batch), 2);
    }

    function test_namedUADerivedUnwrapToUA() public {
        tok.mint(address(this), 1_000);
        tok.approve(address(wrpL), 1_000);
        wrpL.wrap(1_000);
        wrpL.transferToUA(uaP, 1_000);
        MetaTxLib.Envelope memory e = _env(address(0), 0, 0, 0, address(0));
        bytes memory args = abi.encode(address(tok), uint256(100), uaB, uint256(100));
        wrpL.mtxUnwrapToUA(_uaE(e, uaP), address(tok), 100, uaB, 100, _uaSigFor(uaP, address(wrpL),
            "UAUnwrapToUA(bytes32 from,address underlying,uint256 wrapped,bytes32 to,uint256 minOut,", args, e));
        assertEq(tok.balanceOfUA(uaB), 100);
        assertEq(wrpL.balanceOfUA(uaP), 900);
    }

    /// An `msig` `UASig`: `members` set, at the threshold; one member short is the registry's refusal.
    function test_namedUAMsig() public {
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, _pad(alice), 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(bob), 1);
        bytes memory d = _msigKey(2, m);
        bytes32 ua = UACall.register(lreg, UAKinds.MSIG, d, _none(), "", "");
        lreg.acceptMembership(ua, _acceptEoaSig(d, ALICE_PK));
        lreg.acceptMembership(ua, _acceptEoaSig(d, BOB_PK));
        tok.mintToUA(ua, 1_000);
        MetaTxLib.Envelope memory e = _env(address(0), 0, 0, 0, address(0));
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX,
            _digest(address(tok), "UABurn(bytes32 from,uint256 amount,", ua, abi.encode(uint256(100)), e));
        uint16 ia = _indexOf(d, _pad(alice));
        uint16 ib = 1 - ia;
        IUARegistry.MemberSig[] memory all = new IUARegistry.MemberSig[](2);
        all[ia] = IUARegistry.MemberSig(ia, new IUARegistry.InnerSig[](0), _nativeSig(lreg, ALICE_PK, UAKinds.PURPOSE_MEMBER, md));
        all[ib] = IUARegistry.MemberSig(ib, new IUARegistry.InnerSig[](0), _nativeSig(lreg, BOB_PK, UAKinds.PURPOSE_MEMBER, md));
        IUARegistry.UASig memory s;
        s.members = new IUARegistry.MemberSig[](1);
        s.members[0] = all[0];
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        tok.mtxBurn(_uaE(e, ua), 100, s);

        s.members = all;
        tok.mtxBurn(_uaE(e, ua), 100, s);
        assertEq(tok.balanceOfUA(ua), 900);
    }

    /// CTR-UA-37 in the UA envelope: every member's signature is good, no slot accepted: the token refuses, nothing moves, the
    /// nonce stays; the same call goes through once enough weight accepted, and an `msig` that accepted one slot of two still fails.
    function test_namedUAMsigUnacceptedRefused() public {
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, _pad(alice), 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(bob), 1);
        bytes memory d = _msigKey(2, m);
        bytes32 ua = UACall.register(lreg, UAKinds.MSIG, d, _none(), "", "");
        tok.mintToUA(ua, 1_000);
        MetaTxLib.Envelope memory e = _env(address(0), 0, 0, 0, address(0));
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX,
            _digest(address(tok), "UABurn(bytes32 from,uint256 amount,", ua, abi.encode(uint256(100)), e));
        uint16 ia = _indexOf(d, _pad(alice));
        uint16 ib = 1 - ia;
        IUARegistry.UASig memory s;
        s.members = new IUARegistry.MemberSig[](2);
        s.members[ia] = IUARegistry.MemberSig(ia, new IUARegistry.InnerSig[](0), _nativeSig(lreg, ALICE_PK, UAKinds.PURPOSE_MEMBER, md));
        s.members[ib] = IUARegistry.MemberSig(ib, new IUARegistry.InnerSig[](0), _nativeSig(lreg, BOB_PK, UAKinds.PURPOSE_MEMBER, md));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        tok.mtxBurn(_uaE(e, ua), 100, s);
        lreg.acceptMembership(ua, _acceptEoaSig(d, ALICE_PK));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        tok.mtxBurn(_uaE(e, ua), 100, s);
        assertEq(tok.balanceOfUA(ua), 1_000);
        lreg.acceptMembership(ua, _acceptEoaSig(d, BOB_PK));
        tok.mtxBurn(_uaE(e, ua), 100, s);
        assertEq(tok.balanceOfUA(ua), 900);
    }

    /// `from == account`: the account signs its own cancel with its key set, the `AccountSig` blob as `bytes sig`.
    function test_namedCancelNonceFromAccount() public {
        SmartKeyAccount acct = SmartKeyAccount(payable(new SmartKeyAccountFactory(chainUidA).deploy(
            SubjectKey(KeyKind.SECP256K1, _pad(alice), 0, 0, 0), address(0xD00D))));
        MetaTxLib.Envelope memory e = _env(address(acct), 0, 0, 0, address(0));
        bytes32 d = _digest(address(acct), "CancelNonce(address from,uint256 lane,", _pad(address(acct)), abi.encode(uint256(9)), e);
        acct.mtxCancelNonce(e, 9, abi.encode(uint256(0), new bytes32[](0), _ecdsa(ALICE_PK, d)));
        assertEq(acct.mtxNonce(address(acct), 9), 1);
        assertEq(acct.mtxNonce(address(acct), e.batch), 1);
    }

    /// `lane == batch`: the entry takes nonce 0, the cancel the next, so the lane skips one. (ua-mtx-merge T1, meaning:
    /// the token's cancel is the ordered `mtxCancelNonce(UAEnvelope, lane, UASig)` over `UACancelNonce`, Q2; it emits
    /// `UANonceCancelled` for the id, R18.)
    function test_namedCancelNonceOwnLane() public {
        MetaTxLib.Envelope memory e = _env(alice, 0, 0, 0, address(0));
        bytes32 d = _digest(address(tok), "UACancelNonce(bytes32 from,uint256 lane,", _pad(alice), abi.encode(e.batch), e);
        vm.expectEmit(address(tok));
        emit IUALedger.UANonceCancelled(_pad(alice), e.batch, 2);
        IUARegistry.UASig memory a;
        a.signature = _ecdsa(ALICE_PK, d);
        tok.mtxCancelNonce(_uaE(e, _pad(alice)), e.batch, a);
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), e.batch), 2);
    }

    /// Every bound field is in the digest; an unbound relayer or recipient is hashed as 0 and may be anything.
    /// ua-mtx-merge T3, meaning: on the `UABurn` row and struct under the merged `mtxBurn` (R23).
    function test_namedEntryEnvelopeTamper() public {
        string memory op = "UABurn";
        MetaTxLib.UAEnvelope memory e = _uaEnv(op);
        uint256 amount = _uint(op, "amount");
        tok.mint(address(uint160(uint256(e.from))), SUPPLY);
        IUARegistry.UASig memory sig;
        sig.signature = onChain(j, op, address(tok));
        address signed = e.relayer;

        e.feeRecipient = address(0xBAD);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        vm.prank(signed);
        tok.mtxBurn(e, amount, sig);

        e = _uaEnv(op);
        e.fee += 1;
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        vm.prank(signed);
        tok.mtxBurn(e, amount, sig);

        e = _uaEnv(op);
        e.relayer = address(0xBAD);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnauthorizedRelayer.selector, address(0xBAD), signed));
        vm.prank(signed);
        tok.mtxBurn(e, amount, sig);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        vm.prank(address(0xBAD));
        tok.mtxBurn(e, amount, sig);

        // the signer bound neither: any relayer, any recipient value, the same signature
        MetaTxLib.Envelope memory open = _env(alice, 0, 0, 0, address(0));
        bytes32 d = _digest(address(tok), "UABurn(bytes32 from,uint256 amount,", _pad(alice), abi.encode(uint256(1)), open);
        (open.relayer, open.feeRecipient) = (address(0xBAD), address(0xBAD));
        sig.signature = _ecdsa(ALICE_PK, d);
        tok.mtxBurn(_uaE(open, _pad(alice)), 1, sig);
        assertEq(tok.mtxNonce(MetaTxLib.pad(alice), open.batch), 1);
    }

    /// The token is in the domain: a `UABurn` signed for one token does not run on another (ua-mtx-merge T3: the
    /// merged struct, R23).
    function test_namedEntryOtherToken() public {
        string memory op = "UABurn";
        MetaTxLib.UAEnvelope memory e = _uaEnv(op);
        uint256 amount = _uint(op, "amount");
        NormalToken other = NormalToken(EnvKit.clone(address(new NormalToken(address(this), kindArgs(0, address(this), ""))), EnvKit.env(chainUidA, REG_L, address(0), false)));
        other.initialize(nid(address(this)), 1, abi.encode(normalInit("Other", "OTH", 6, SUPPLY,
            address(uint160(uint256(e.from))), address(this))));
        IUARegistry.UASig memory sig;
        sig.signature = onChain(j, op, address(tok));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        vm.prank(e.relayer);
        other.mtxBurn(e, amount, sig);
    }

    function test_namedUAEmptySignatureRefused() public {
        MetaTxLib.Envelope memory e = _env(alice, 0, 0, 0, address(0));
        IUARegistry.UASig memory none;
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.mtxBurn(_uaE(e, _pad(alice)), 1, none);
    }

    function test_relayFeeRouterRunsNamedEntry() public {
        und.mint(alice, 1_000);
        vm.startPrank(alice);
        und.approve(address(wrp), 1_000);
        wrp.wrap(1_000);
        vm.stopPrank();
        RelayFeeRouter router = new RelayFeeRouter();
        MetaTxLib.Envelope memory e = _env(alice, 0, RR, 0, address(0));
        e.relayer = router.EXECUTOR();
        bytes memory cd = abi.encodeCall(WrappedToken.mtxUnwrap, (_uaE(e, _pad(alice)), 100, bob, 0, _unwrapSig(ALICE_PK, wrp, e, 100)));
        uint256 until = block.timestamp + 300;
        // ua-mtx-merge T2 (R28): the one `relay`, on ids, over `UARelayFee`; alice signs with her own key
        IUARegistry.UASig memory s;
        s.signature = _ecdsa(ALICE_PK, _relayFeeDigest(address(tok), address(wrp), keccak256(cd), until, address(router)));
        vm.prank(RELAYER);
        router.relay(address(wrp), cd, address(tok), MetaTxLib.pad(alice), MetaTxLib.pad(RELAYER), 25, 2, 0, until, s);
        assertEq(und.balanceOf(bob), 100);
        assertEq(tok.balanceOf(RELAYER), 25);
        assertEq(wrp.mtxNonce(MetaTxLib.pad(alice), e.batch), 1);
    }

    /// alice's `UARelayFee` of 25 to `RELAYER` on lane 2, nonce 0 (pay-meta-tax T38; a helper: the test's stack).
    function _relayFeeDigest(address token, address target, bytes32 cdh, uint256 until, address router)
        internal view returns (bytes32)
    {
        return keccak256(abi.encodePacked(hex"1901", domainOf(token), keccak256(abi.encode(
            keccak256("UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)"),
            MetaTxLib.pad(alice), target, cdh, MetaTxLib.pad(RELAYER), uint256(25), uint256(2), uint256(0), until, router))));
    }
}

/// The rows of the base and the public tokens that also stand on a confidential kind: the same entries, the kind's domain.
abstract contract ConfidentialRows is Test {
    string internal j;
    uint256 internal constant FUNDS = 10_000_000;

    function _kind() internal pure virtual returns (string memory);
    function _normalKind() internal virtual returns (NormalToken);
    function _wrappedKind(address leg) internal virtual returns (WrappedToken);

    /// ua-mtx-merge T1, meaning: the address `CancelNonce` row ran on a token; a token has no address `mtxCancelNonce`
    /// any more (Q2, MD-1: the wallets keep it), so the row, re-signed on the token, finds no entry (an empty revert,
    /// no signature check) and the lane stays. MD-7: T11 narrows the row's `on` to the wallets.
    function test_typedOpsVectors_CancelNonceRowHasNoTokenEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // T11 (MD-7): the row's token domains retired
        string memory k = _kind();
        NormalToken t = _normalKind();
        assertTrue(t.supportsInterface(type(IMetaTx).interfaceId));
        MetaTxLib.Envelope memory e = rowEnvelope(j, "CancelNonce");
        uint256 lane = vm.parseJsonUint(j, msgField("CancelNonce", "lane"));
        _noTokenEntry(k, address(t), abi.encodeCall(IMetaTxAddress.mtxCancelNonce,
            (e, lane, vm.parseJsonBytes(j, domainField("CancelNonce", k, "signature")))));
        assertEq(t.mtxNonce(MetaTxLib.pad(e.from), lane), 0);
    }

    function _noTokenEntry(string memory k, address t, bytes memory built) internal {
        (bool ok, bytes memory ret) = tryRow(j, "CancelNonce", k, t, built);
        assertFalse(ok);
        assertEq(ret.length, 0, "no such function");
    }

    /// ua-mtx-merge T3 (R23), meaning: the address `mtxBurn` left every kind; the row finds no entry (MD-7: retired by T11).
    function test_typedOpsVectors_BurnRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY);
        string memory k = _kind();
        NormalToken t = _normalKind();
        MetaTxLib.Envelope memory e = rowEnvelope(j, "Burn");
        uint256 amount = vm.parseJsonUint(j, msgField("Burn", "amount"));
        t.mint(e.from, FUNDS);
        rowHasNoEntry(j, "Burn", k, address(t), abi.encodeWithSignature("mtxBurn((address,uint256,uint256,uint256,uint32,address,uint256,address),uint256,bytes)",
            e, amount, vm.parseJsonBytes(j, domainField("Burn", k, "signature"))));
        assertEq(t.balanceOf(e.from), FUNDS);
    }

    function test_typedOpsVectors_UABurnRow() public {
        j = vm.readFile(TYPED_OPS);
        string memory k = _kind();
        NormalToken t = _normalKind();
        MetaTxLib.Envelope memory u = rowEnvelope2(j, "UABurn");
        MetaTxLib.UAEnvelope memory e = MetaTxLib.UAEnvelope(vm.parseJsonBytes32(j, msgField("UABurn", "from")), u.batch,
            u.nonce, u.validUntil, u.mode, u.relayer, u.fee, u.feeRecipient);
        uint256 amount = vm.parseJsonUint(j, msgField("UABurn", "amount"));
        IUARegistry.UASig memory s;
        s.signature = vm.parseJsonBytes(j, domainField("UABurn", k, "signature"));
        t.mint(address(uint160(uint256(e.from))), FUNDS);
        runRowRenamed(j, "UABurn", k, address(t), abi.encodeCall(NormalToken.mtxBurn, (e, amount, s)), NormalToken.mtxBurn.selector);
        assertEq(t.mtxNonce(e.from, e.batch), 1);
        assertEq(t.balanceOf(e.feeRecipient), amount * e.fee / 1_000_000);
    }

    function test_typedOpsVectors_WrapLegRow() public {
        j = vm.readFile(TYPED_OPS);
        MetaTxLib.Envelope memory e = rowEnvelope(j, "WrapLeg");
        address at = vm.parseJsonAddress(j, msgField("WrapLeg", "underlying"));
        uint256 amount = vm.parseJsonUint(j, msgField("WrapLeg", "amount"));
        deployCodeTo("Mocks.sol:MockERC20", abi.encode("Leg", "LEG", uint8(6)), at);
        WrappedToken w = _wrappedKind(at);
        MockERC20(at).mint(e.from, amount);
        vm.prank(e.from);
        MockERC20(at).approve(address(w), amount);
        bytes memory sig = vm.parseJsonBytes(j, domainField("WrapLeg", _kind(), "signature"));
        runRow(j, "WrapLeg", _kind(), address(w), abi.encodeCall(WrappedToken.mtxWrapLeg, (e, at, amount, sig)));
        assertEq(w.balanceOf(e.from), amount - e.fee);
        assertEq(w.balanceOf(e.feeRecipient), e.fee);
    }
}

contract ConfidentialRowsPqzTest is ConfidentialRows, PqzFixture {
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

contract ConfidentialRowsZetherTest is ConfidentialRows, ZetherFixture {
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

/// Stands in for the factory at a creation row's `target` (plan T76): records the router's call and its `subject()`.
contract CreateSink {
    bytes32 public subject;
    uint256 public calls;
    bytes public init;
    bytes32 public salt;
    uint64 public version;
    uint16 public contractClass;
    bytes4 public selector;

    function _seen(bytes calldata init_, bytes32 salt_, uint64 version_) internal {
        subject = IGovernanceRouter(msg.sender).subject();
        ++calls;
        (init, salt, version, selector) = (init_, salt_, version_, msg.sig);
    }

    function createToken(IOpenFactory.TokenKind, uint64 version_, bytes calldata initArgs, bytes32 salt_)
        external returns (address)
    {
        _seen(initArgs, salt_, version_);
        return address(this);
    }

    function createDex(uint64 version_, bytes calldata initArgs, bytes32 salt_) external returns (address) {
        _seen(initArgs, salt_, version_);
        return address(this);
    }

    function createInstance(IOpenFactory.ReleaseId calldata id, bytes32 salt_, bytes calldata initCall)
        external returns (address)
    {
        _seen(initCall, salt_, id.version);
        contractClass = id.contractClass;
        return address(this);
    }
}

/// governance T12 (spec §3.2; CTR-GOV-15 Change): every `GovernanceRouter` row of `typed_ops.json` runs verbatim on a real
/// router deployed at the row's `verifyingContract` (context A: chain id 31337, `chain_uid` A), so the row's own signature
/// is the router's: no re-signing. Each op's `target` is a real `NormalToken`, `WrappedToken` or `SCaaSDex` cloned at the
/// row's `target`, `GOV_ROUTER` the router, and the op's effect is read there. ua-mtx-merge T7: the `UA<Op>` row runs on the
/// merged `mtx<Op>` (the key's native id signs `UA<Op>` with its own key); the address `<Op>` row finds no entry.
contract TypedOpsRouterTest is UALedgerBase {
    string internal constant K = "gov_router";
    uint8 internal constant MINT = GovernanceBits.MINTABLE;
    string internal j;
    address internal signer;
    bytes32 internal me;
    address internal router;
    address internal normalImpl;
    address internal wrappedImpl;
    address internal dexImpl;

    /// The test is the factory of every clone and registered no token: a market's legs are outside.
    function isToken(address) external pure returns (bool) { return false; }

    /// The factory's notice period the regulated clones read for a tax-rate increase (pay-meta-tax spec §6.2): none here.
    function noticePeriod() external pure returns (uint64) { return 0; }

    function setUp() public override {
        super.setUp();
        j = vm.readFile(TYPED_OPS);
        signer = vm.parseJsonAddress(j, ".key.address");
        me = vm.parseJsonBytes32(j, ".key.ua");
        assertEq(me, bytes32(uint256(uint160(signer))), "the key's UA is its native id");
        router = vm.parseJsonAddress(j, domainField("UAGrantRole", K, "domain.verifyingContract"));
        deployCodeTo("GovernanceRouter.sol:GovernanceRouter", abi.encode(chainUidA, REG_L, address(0), false), router);
        normalImpl = address(new NormalToken(address(this), kindArgs(0, address(this), "")));
        wrappedImpl = address(new WrappedToken(address(this), kindArgs(1, address(this), "")));
        dexImpl = address(new SCaaSDex(address(this), dexArgs(address(this))));
    }

    // ------------------------------------------------------------------ the row, the targets

    function _addr(string memory op, string memory f) internal view returns (address) {
        return vm.parseJsonAddress(j, msgField(op, f));
    }

    function _b32(string memory op, string memory f) internal view returns (bytes32) {
        return vm.parseJsonBytes32(j, msgField(op, f));
    }

    function _uint(string memory op, string memory f) internal view returns (uint256) {
        return vm.parseJsonUint(j, msgField(op, f));
    }

    function _bool(string memory op, string memory f) internal view returns (bool) {
        return vm.parseJsonBool(j, msgField(op, f));
    }

    function _bit(string memory op) internal view returns (uint8) {
        return uint8(_uint(op, "bit"));
    }

    /// The row's calldata, as clientkeys built it, from the row's relayer; its lane's nonce spent. ua-mtx-merge T11 (R14,
    /// MD-7): a `UA<Op>` row names the merged `mtx<Op>` and runs verbatim, its own signature (T7 swapped the `ua<Op>`
    /// selector of the rows of the time for the `mtx<Op>` one).
    function _row(string memory op) internal {
        checkRow(j, op, K);
        bytes memory cd = vm.parseJsonBytes(j, domainField(op, K, "calldata"));
        bytes memory ab = bytes(vm.parseJsonString(j, domainField(op, K, "abi")));
        require(ab[0] == "m" && ab[1] == "t" && ab[2] == "x", "the row names the merged mtx<Op>");
        require(bytes4(cd) == bytes4(keccak256(ab)), "the row: its own selector");
        vm.prank(_addr(op, "relayer"));
        (bool ok, bytes memory ret) = router.call(cd);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        assertEq(GovernanceRouter(router).mtxNonce(me, _uint(op, "batch")), 1, op);
    }

    /// A clone of `impl` at `at` with the env the factory would append (this chain, the registry, the router).
    function _clone(address impl, address at) internal {
        vm.etch(at, EnvKit.runtime(impl, EnvKit.env(chainUidA, REG_L, address(0), false, router)));
    }

    function _normalAt(string memory op, bytes32 owner_, bytes32 minter, uint64 delay) internal returns (NormalToken t) {
        t = NormalToken(_addr(op, "target"));
        _clone(normalImpl, address(t));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features, c.owner, c.grantDelay) = ("G", "G", 6, 1 | (uint256(1) << MINT), owner_, delay);
        c.roles.minter = minter;
        t.initialize(nid(address(this)), 1, abi.encode(c));
    }

    /// Owner, guardian and rate admin the key. `RATE_ADJUSTABLE` is contract-only, so its holder has code at the grant
    /// (spec §1.4): the grant runs with code at the key's address, removed before the row, which the key signs as an EOA.
    function _wrappedAt(string memory op, address leg) internal returns (WrappedToken w) {
        if (leg.code.length == 0) deployCodeTo("Mocks.sol:MockERC20", abi.encode("Leg", "LEG", uint8(6)), leg);
        w = WrappedToken(payable(_addr(op, "target")));
        _clone(wrappedImpl, address(w));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features, c.owner) = ("W", "W", 6,
            1 | (uint256(1) << GovernanceBits.RATE_ADJUSTABLE) | (uint256(1) << GovernanceBits.WRAP_DISABLEABLE), me);
        (c.roles.guardian, c.roles.rateAdmin) = (me, me);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(leg, 1, 1);
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
        vm.etch(signer, hex"00");
        w.initialize(nid(address(this)), 1, abi.encode(c));
        vm.etch(signer, "");
    }

    function _dexAt(string memory op) internal returns (SCaaSDex d) {
        d = SCaaSDex(_addr(op, "target"));
        _clone(dexImpl, address(d));
        d.initialize(nid(address(this)), 1, abi.encode(ISCaaSDex.DexConfig(me, 0, address(0x7EA5), false, 0, address(0))));
    }

    /// ua-mtx-merge T7, meaning: one form per op, the `UA<Op>` row on the merged entry (was both the address `<Op>` row and
    /// the `UA<Op>` row); the address rows find no entry (`test_routerRow_addressRowsHaveNoEntry`; MD-7: T11 retires them).
    function _forms(string memory op) internal pure returns (string[1] memory) {
        return [string.concat("UA", op)];
    }

    function test_routerRow_addressRowsHaveNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // T11 (MD-7): the 19 address rows retired
        string[19] memory ops = ["GrantRole", "RevokeRole", "SetGrant", "CancelGrant", "DisableFeature", "TransferOwnership",
            "AcceptOwnership", "RenounceOwnership", "RenounceRole", "Mint", "MintToUA", "DisableWrap", "ProposeRate",
            "CancelRate", "ExecuteRate", "SetMarket", "SetExchangeTarget", "SetListedOnly", "SetFeeSplit"];
        for (uint256 i; i < ops.length; ++i) _noEntry(ops[i], me, _uint(ops[i], "batch"));
    }

    // ------------------------------------------------------------------ the factory's creations (S3, plan T76)

    /// The three creation rows verbatim, `target` a sink in the factory's place that records what the router hands it and
    /// the subject it names: the router authenticated the key's id, and passed the row's `extra` bytes whose keccak256 is
    /// the signed `initHash`.
    function _sinkAt(string memory op) internal returns (CreateSink s) {
        s = CreateSink(_addr(op, "target"));
        deployCodeTo("TypedOps.t.sol:CreateSink", "", address(s));
    }

    function test_routerRow_CreateToken() public {
        CreateSink s = _sinkAt("UACreateToken");
        _row("UACreateToken");
        bytes memory initArgs = vm.parseJsonBytes(j, domainField("UACreateToken", K, "extra.initArgs"));
        assertEq(s.subject(), me, "the signing UA");
        assertEq(s.calls(), 1);
        assertEq(keccak256(s.init()), _b32("UACreateToken", "initHash"));
        assertEq(s.init(), initArgs);
        assertEq(s.salt(), _b32("UACreateToken", "salt"));
        assertEq(s.version(), _uint("UACreateToken", "version"));
        assertEq(s.selector(), OpenFactory.createToken.selector);
    }

    function test_routerRow_CreateDex() public {
        CreateSink s = _sinkAt("UACreateDex");
        _row("UACreateDex");
        assertEq(s.subject(), me);
        assertEq(keccak256(s.init()), _b32("UACreateDex", "initHash"));
        assertEq(s.salt(), _b32("UACreateDex", "salt"));
        assertEq(s.selector(), OpenFactory.createDex.selector);
    }

    function test_routerRow_CreateInstance() public {
        CreateSink s = _sinkAt("UACreateInstance");
        _row("UACreateInstance");
        assertEq(s.subject(), me);
        assertEq(keccak256(s.init()), _b32("UACreateInstance", "initHash"));
        assertEq(s.salt(), _b32("UACreateInstance", "salt"));
        assertEq(s.contractClass(), _uint("UACreateInstance", "contractClass"));
        assertEq(s.selector(), OpenFactory.createInstance.selector);
    }

    // ------------------------------------------------------------------ the owner and a holder

    function test_routerRow_GrantRole() public {
        string[1] memory f = _forms("GrantRole");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            NormalToken t = _normalAt(f[i], me, 0, 0);
            _row(f[i]);
            assertTrue(t.hasRole(_bit(f[i]), _b32(f[i], "account")), f[i]);
        }
    }

    function test_routerRow_RevokeRole() public {
        string[1] memory f = _forms("RevokeRole");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            NormalToken t = _normalAt(f[i], me, 0, 0);
            vm.prank(signer);
            t.grantRole(_bit(f[i]), _b32(f[i], "account"));
            _row(f[i]);
            assertFalse(t.hasRole(_bit(f[i]), _b32(f[i], "account")), f[i]);
            assertTrue(t.grantOf(_bit(f[i]), _b32(f[i], "account")).barred, f[i]);
        }
    }

    /// The nested `terms` arrive whole: every field of the stored grant is the row's.
    function test_routerRow_SetGrant() public {
        string[1] memory f = _forms("SetGrant");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            NormalToken t = _normalAt(f[i], me, 0, 0);
            _row(f[i]);
            IGovernance.Grant memory g = t.grantOf(_bit(f[i]), _b32(f[i], "holder"));
            string memory op = f[i];
            assertEq(abi.encode(g.min, g.max, g.total, g.perWindow, g.window, g.validUntil, g.maxUses, g.delegable, g.scope),
                abi.encode(_uint(op, "terms.min"), _uint(op, "terms.max"), _uint(op, "terms.total"), _uint(op, "terms.perWindow"),
                    _uint(op, "terms.window"), _uint(op, "terms.validUntil"), _uint(op, "terms.maxUses"), _bool(op, "terms.delegable"),
                    _b32(op, "terms.scope")), op);
        }
    }

    function test_routerRow_CancelGrant() public {
        string[1] memory f = _forms("CancelGrant");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            NormalToken t = _normalAt(f[i], me, 0, 1 hours);
            vm.prank(signer);
            t.grantRole(_bit(f[i]), _b32(f[i], "account"));
            (uint64 eta,,,) = t.pendingGrant(_bit(f[i]), _b32(f[i], "account"));
            assertTrue(eta != 0, "proposed");
            _row(f[i]);
            (eta,,,) = t.pendingGrant(_bit(f[i]), _b32(f[i], "account"));
            assertEq(eta, 0, f[i]);
        }
    }

    function test_routerRow_DisableFeature() public {
        string[1] memory f = _forms("DisableFeature");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            NormalToken t = _normalAt(f[i], me, 0, 0);
            _row(f[i]);
            assertEq(t.features() & (uint256(1) << _bit(f[i])), 0, f[i]);
        }
    }

    function test_routerRow_TransferOwnership() public {
        string[1] memory f = _forms("TransferOwnership");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            NormalToken t = _normalAt(f[i], me, 0, 0);
            _row(f[i]);
            assertEq(t.pendingOwner(), _b32(f[i], "newOwner"), f[i]);
        }
    }

    function test_routerRow_AcceptOwnership() public {
        string[1] memory f = _forms("AcceptOwnership");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            NormalToken t = _normalAt(f[i], bytes32(uint256(uint160(address(this)))), 0, 0);
            t.transferOwnership(me);
            _row(f[i]);
            assertEq(t.owner(), me, f[i]);
        }
    }

    function test_routerRow_RenounceOwnership() public {
        string[1] memory f = _forms("RenounceOwnership");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            NormalToken t = _normalAt(f[i], me, 0, 0);
            _row(f[i]);
            assertEq(t.owner(), bytes32(0), f[i]);
        }
    }

    function test_routerRow_RenounceRole() public {
        string[1] memory f = _forms("RenounceRole");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            NormalToken t = _normalAt(f[i], me, me, 0);
            _row(f[i]);
            assertFalse(t.hasRole(_bit(f[i]), me), f[i]);
        }
    }

    // ------------------------------------------------------------------ the powers on the token kinds

    function test_routerRow_Mint() public {
        string[1] memory f = _forms("Mint");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            NormalToken t = _normalAt(f[i], me, me, 0);
            _row(f[i]);
            assertEq(t.balanceOf(_addr(f[i], "to")), _uint(f[i], "amount"), f[i]);
        }
    }

    function test_routerRow_MintToUA() public {
        string[1] memory f = _forms("MintToUA");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            NormalToken t = _normalAt(f[i], me, me, 0);
            vm.mockCall(REG_L, abi.encodeCall(IUARegistry.kindOf, (_b32(f[i], "to"))), abi.encode(UAKinds.P256));
            _row(f[i]);
            assertEq(t.balanceOfUA(_b32(f[i], "to")), _uint(f[i], "amount"), f[i]);
        }
    }

    function test_routerRow_DisableWrap() public {
        string[1] memory f = _forms("DisableWrap");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            WrappedToken w = _wrappedAt(f[i], _addr(f[i], "leg"));
            _row(f[i]);
            (,,,, bool on) = w.legOf(_addr(f[i], "leg"));
            assertFalse(on, f[i]);
        }
    }

    function test_routerRow_ProposeRate() public {
        string[1] memory f = _forms("ProposeRate");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            WrappedToken w = _wrappedAt(f[i], _addr(f[i], "leg"));
            _row(f[i]);
            (address leg, uint96 num, uint96 den, uint64 eta) = w.pendingRate();
            assertEq(abi.encode(leg, num, den), abi.encode(_addr(f[i], "leg"), _uint(f[i], "num"), _uint(f[i], "den")), f[i]);
            assertTrue(eta != 0, f[i]);
        }
    }

    function test_routerRow_CancelRate() public {
        string[1] memory f = _forms("CancelRate");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            address leg = address(new MockERC20("Leg", "LEG", 6));
            WrappedToken w = _wrappedAt(f[i], leg);
            vm.prank(signer);
            w.proposeRate(leg, 101, 100);
            _row(f[i]);
            (,,, uint64 eta) = w.pendingRate();
            assertEq(eta, 0, f[i]);
        }
    }

    /// Proposed `rateDelay` before the rows' deadline, executed at it.
    function test_routerRow_ExecuteRate() public {
        string[1] memory f = _forms("ExecuteRate");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            address leg = address(new MockERC20("Leg", "LEG", 6));
            WrappedToken w = _wrappedAt(f[i], leg);
            vm.warp(_uint(f[i], "validUntil") - 2 days);
            vm.prank(signer);
            w.proposeRate(leg, 101, 100);
            vm.warp(_uint(f[i], "validUntil"));
            _row(f[i]);
            (uint96 num, uint96 den,,,) = w.legOf(leg);
            assertEq(abi.encode(num, den), abi.encode(uint96(101), uint96(100)), f[i]);
        }
    }

    // ------------------------------------------------------------------ the powers on the DEX

    function test_routerRow_SetMarket() public {
        string[1] memory f = _forms("SetMarket");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            SCaaSDex d = _dexAt(f[i]);
            _row(f[i]);
            assertEq(d.marketListed(_addr(f[i], "base"), _addr(f[i], "quote")), _bool(f[i], "listed"), f[i]);
        }
    }

    function test_routerRow_SetExchangeTarget() public {
        string[1] memory f = _forms("SetExchangeTarget");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            SCaaSDex d = _dexAt(f[i]);
            _row(f[i]);
            assertEq(d.exchangeTarget(_addr(f[i], "exchangeTarget")), _bool(f[i], "listed"), f[i]);
        }
    }

    function test_routerRow_SetListedOnly() public {
        string[1] memory f = _forms("SetListedOnly");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            SCaaSDex d = _dexAt(f[i]);
            _row(f[i]);
            assertEq(d.listedOnly(), _bool(f[i], "on"), f[i]);
        }
    }

    function test_routerRow_SetFeeSplit() public {
        string[1] memory f = _forms("SetFeeSplit");
        uint256 s = vm.snapshotState();
        for (uint256 i; i < f.length; ++i) {
            vm.revertToState(s);
            SCaaSDex d = _dexAt(f[i]);
            _row(f[i]);
            assertEq(abi.encode(d.relayerSharePpm(), d.treasury()),
                abi.encode(uint32(_uint(f[i], "relayerSharePpm")), _addr(f[i], "treasury")), f[i]);
        }
    }

    // ------------------------------------------------------------------ the lane's cancels on the router's domain

    /// ua-mtx-merge T1, meaning: the two cancel rows of the router's domain, the address `CancelNonce` and the unordered
    /// `UACancelNonce(bytes32 ua,uint256 batch,uint256 validUntil)`, find no entry on the router any more (Q2, MD-1): the
    /// row's calldata reverts with no data and the lanes stay. T11 (MD-7): both read from `TYPED_OPS_LEGACY`.
    function test_routerRow_CancelNonceHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY);
        _noEntry("CancelNonce", MetaTxLib.pad(signer), _uint("CancelNonce", "lane"));
    }

    function test_routerRow_UACancelNonceOldFormHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY);
        _noEntry("UACancelNonce", _b32("UACancelNonce", "ua"), _uint("UACancelNonce", "batch"));
    }

    /// T11 (Q2, MD-7): the ordered cancel's row, `UACancelNonce(bytes32 from,uint256 lane,E)` in the router's domain, on the
    /// router's `mtxCancelNonce`: the key's native id bumps its own lane, nonce-ordered.
    function test_routerRow_UACancelNonce() public {
        _row("UACancelNonce");
        assertEq(GovernanceRouter(router).mtxNonce(me, _uint("UACancelNonce", "lane")), 1);
    }

    function _noEntry(string memory op, bytes32 who, uint256 lane) internal {
        checkRow(j, op, K);
        (bool ok, bytes memory ret) = router.call(vm.parseJsonBytes(j, domainField(op, K, "calldata")));
        assertFalse(ok, op);
        assertEq(ret.length, 0, string.concat(op, ": no such function"));
        assertEq(GovernanceRouter(router).mtxNonce(who, lane), 0, op);
    }

    // ------------------------------------------------------------------ ua-mtx-merge T34: the eight regulated controls

    /// The regulated rows (regulated-kinds spec §3.1, plan T34; CTR-GOV-20) run verbatim on a kind-8 token cloned at the row's
    /// `target`, `GOV_ROUTER` the router, at the time the rows were built for (`UAPause.until` within 7 days of it). The key's
    /// native id holds the bit the op uses: 5, 6, 7 (issuer) and 10 (compliance) are contract-only (RK-1), so the key's
    /// address has code at `initialize` only, as `_wrappedAt` does for bit 3; bit 22 takes any holder, granted by the owner
    /// (this test). `FORCE` and `RECORD` never on one id: the other role is a `Holder`. One record runs through the rows:
    /// `UARecordOrder` records it, `UAFreeze` backs a freeze with it, `UAForceTransfer` moves under it, `UARevokeOrder` ends it.
    uint256 internal constant REG_NOW = 1_800_000_000;
    address internal regImpl;
    address internal regOther;

    function _regAt(string memory op, bool keyIsIssuer) internal returns (NormalRegulatedToken t) {
        vm.warp(REG_NOW);
        if (regImpl == address(0)) {
            regImpl = address(new NormalRegulatedToken(address(this), kindArgs(8, address(this), regArgs())));
            regOther = address(new Holder());
        }
        t = NormalRegulatedToken(_addr(op, "target"));
        _clone(regImpl, address(t));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.owner) = ("R", "R", 6, MetaTxLib.pad(address(this)));
        c.features = 1 | (uint256(1) << GovernanceBits.FREEZE) | (uint256(1) << GovernanceBits.FORCE)
            | (uint256(1) << GovernanceBits.PAUSE) | (uint256(1) << GovernanceBits.RECORD)
            | (uint256(1) << GovernanceBits.OPERATOR_TRANSFER) | (uint256(1) << GovernanceBits.TAX);
        c.reg.taxRecipient = MetaTxLib.pad(address(0x7A1)); // pay-meta-tax T41: bit 23, the issuer seat holds it
        (c.roles.issuer, c.roles.compliance) = keyIsIssuer ? (me, MetaTxLib.pad(regOther)) : (MetaTxLib.pad(regOther), me);
        (c.initialSupply, c.initialHolder) = (1000, address(uint160(uint256(_b32("UARecordOrder", "subject")))));
        c.reg.termsHash = keccak256("terms");
        vm.etch(signer, hex"00");
        t.initialize(nid(address(this)), 1, abi.encode(c));
        vm.etch(signer, "");
        t.grantRole(GovernanceBits.OPERATOR_TRANSFER, me);
    }

    /// `UARecordOrder`'s order, recorded directly by `who`; its `recordId`.
    function _regRecord(NormalRegulatedToken t, address who) internal returns (bytes32) {
        string memory op = "UARecordOrder";
        bytes memory args = bytes.concat(abi.encode(_b32(op, "orderId"), _b32(op, "documentHash"), _b32(op, "subject")),
            abi.encode(_b32(op, "beneficiary"), _uint(op, "maxAmount"), _uint(op, "freezeUntil")));
        vm.prank(who);
        (bool ok,) = address(t).call(bytes.concat(t.recordOrder.selector, args));
        assertTrue(ok, "recordOrder");
        return keccak256(abi.encode(_b32(op, "orderId"), _b32(op, "subject"), _b32(op, "beneficiary")));
    }

    function test_routerRow_UARecordOrder() public {
        string memory op = "UARecordOrder";
        NormalRegulatedToken t = _regAt(op, false);
        _row(op);
        bytes32 rid = keccak256(abi.encode(_b32(op, "orderId"), _b32(op, "subject"), _b32(op, "beneficiary")));
        assertEq(t.order(rid).subject, _b32(op, "subject"));
        assertEq(t.order(rid).beneficiary, _b32(op, "beneficiary"));
        assertEq(t.order(rid).maxAmount, _uint(op, "maxAmount"));
        assertEq(t.order(rid).freezeUntil, _uint(op, "freezeUntil"));
    }

    function test_routerRow_UAFreeze() public {
        string memory op = "UAFreeze";
        NormalRegulatedToken t = _regAt(op, true);
        bytes32 rid = _regRecord(t, regOther);
        assertEq(rid, _b32(op, "recordId"), "the row names UARecordOrder's record");
        _row(op);
        assertTrue(t.isFrozen(_b32(op, "account")));
        assertEq(t.freezeOf(_b32(op, "account")).recordId, rid);
    }

    function test_routerRow_UAUnfreeze() public {
        string memory op = "UAUnfreeze";
        NormalRegulatedToken t = _regAt(op, true);
        vm.prank(signer);
        t.freeze(_b32(op, "account"), _b32(op, "ref"), 0);
        assertTrue(t.isFrozen(_b32(op, "account")));
        _row(op);
        assertFalse(t.isFrozen(_b32(op, "account")));
    }

    function test_routerRow_UAForceTransfer() public {
        string memory op = "UAForceTransfer";
        NormalRegulatedToken t = _regAt(op, true);
        bytes32 rid = _regRecord(t, regOther);
        assertEq(rid, _b32(op, "recordId"));
        vm.prank(signer);
        t.freeze(_b32("UARecordOrder", "subject"), _b32("UAFreeze", "ref"), rid);
        _row(op);
        assertEq(t.balanceOf(address(uint160(uint256(_b32("UARecordOrder", "beneficiary"))))), _uint(op, "amount"));
        assertEq(t.order(rid).executed, _uint(op, "amount"));
    }

    function test_routerRow_UAPause() public {
        string memory op = "UAPause";
        NormalRegulatedToken t = _regAt(op, true);
        _row(op);
        assertEq(t.regulatedConfig().pausedUntil, _uint(op, "until"));
    }

    function test_routerRow_UAUnpause() public {
        string memory op = "UAUnpause";
        NormalRegulatedToken t = _regAt(op, true);
        vm.prank(signer);
        t.pause(_b32(op, "ref"), uint64(REG_NOW + 1 days));
        _row(op);
        assertEq(t.regulatedConfig().pausedUntil, REG_NOW);
    }

    function test_routerRow_UARevokeOrder() public {
        string memory op = "UARevokeOrder";
        NormalRegulatedToken t = _regAt(op, false);
        bytes32 rid = _regRecord(t, signer);
        assertEq(rid, _b32(op, "recordId"));
        _row(op);
        assertTrue(t.order(rid).revoked);
    }

    /// Owner 2026-11-06 (CTR-GOV-20): the moved account is `account`, the signer the envelope's `from`.
    function test_routerRow_UAOperatorTransfer() public {
        string memory op = "UAOperatorTransfer";
        NormalRegulatedToken t = _regAt(op, true);
        address from = address(uint160(uint256(_b32(op, "account"))));
        address to = address(uint160(uint256(_b32(op, "to"))));
        assertTrue(_b32(op, "account") != me, "the moved account is not the signer");
        _row(op);
        assertEq(t.balanceOf(to), _uint(op, "amount"));
        assertEq(t.balanceOf(from), 1000 - _uint(op, "amount"));
    }

    /// pay-meta-tax T39 / T41: the router's two tax ops, bit 23 on the key (the issuer seat), the factory's notice 0.
    function test_routerRow_UASetTaxRate() public {
        string memory op = "UASetTaxRate";
        NormalRegulatedToken t = _regAt(op, true);
        _row(op);
        assertEq(t.taxConfig().effectivePpm, _uint(op, "ratePpm"));
    }

    function test_routerRow_UASetTaxRecipient() public {
        string memory op = "UASetTaxRecipient";
        NormalRegulatedToken t = _regAt(op, true);
        _row(op);
        assertEq(t.taxConfig().taxRecipient, _b32(op, "taxRecipient"));
    }

    /// spec §6 on the router (`MetaTxLib.canon`): the rows bind the relayer (mode 1), the fee recipient is unbound. A wallet
    /// that signs a non-zero fee recipient signs another digest, which the router refuses (the lane unspent); the canonical
    /// 0 under the same envelope runs, whatever fee recipient the calldata carries.
    function test_routerRow_regulatedUnboundFeeRecipientSignedIsRefused() public {
        string memory op = "UAPause";
        NormalRegulatedToken t = _regAt(op, true);
        MetaTxLib.Envelope memory a = rowEnvelope2(j, op);
        MetaTxLib.UAEnvelope memory e = MetaTxLib.UAEnvelope(me, a.batch, a.nonce, a.validUntil, a.mode, a.relayer, a.fee,
            address(0xBA));
        assertEq(e.mode & 2, 0, "fee recipient unbound");
        (bytes32 ref, uint64 until) = (_b32(op, "ref"), uint64(_uint(op, "until")));
        IUARegistry.UASig memory s;
        s.signature = _pauseSig(e, address(t), ref, until, address(0xBA));
        vm.prank(e.relayer);
        (bool ok,) = router.call(abi.encodeCall(GovernanceRouter.mtxPause, (e, address(t), ref, until, s)));
        assertFalse(ok, "a non-zero unbound fee recipient signed");
        assertEq(GovernanceRouter(router).mtxNonce(me, e.batch), 0);
        s.signature = _pauseSig(e, address(t), ref, until, address(0));
        vm.prank(e.relayer);
        GovernanceRouter(router).mtxPause(e, address(t), ref, until, s);
        assertEq(t.regulatedConfig().pausedUntil, until);
        assertEq(GovernanceRouter(router).mtxNonce(me, e.batch), 1);
    }

    function _pauseSig(MetaTxLib.UAEnvelope memory e, address target, bytes32 ref, uint64 until, address feeTo)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(bytes.concat(abi.encode(vm.parseJsonBytes32(j, ".ops.UAPause.typehash"), e.from, target, ref, until),
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee, feeTo)));
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(uint256(vm.parseJsonBytes32(j, ".key.private")),
            keccak256(abi.encodePacked(hex"1901", domainOf(router), sh)));
        return abi.encodePacked(r, ss, v);
    }
}
