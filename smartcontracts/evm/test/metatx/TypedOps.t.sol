// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MetaTxBase} from "../../src/metatx/MetaTxBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MtxRelayFee} from "../../src/metatx/MtxRelayFee.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
import {SmartKeyAccount, SubjectKey, KeyKind} from "../../src/account/SmartKeyAccount.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {TYPED_OPS, SALTED_DOMAIN, checkRow, onChain, rowEnvelope, rowEnvelope2, msgField, domainField} from "./NamedEntry.t.sol";

/// typed-signing C2 (TS-D14): every named entry of the base and the public tokens runs its `typed_ops.json` row: the row
/// by itself (`checkRow`), its calldata equal to the message's fields, then the row's own calldata on a contract, under
/// that contract's domain (the signature re-made over the row's `structHash`, so the entry hashes what clientkeys hashed).
contract TypedOpsTest is UALedgerBase {
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

    /// `built` (the entry's call from the message's fields) is the row's calldata; that calldata runs on `c` from the row's
    /// relayer, the signature replaced by the one under `c`'s domain.
    function _run(string memory op, address c, bytes memory built) internal returns (bytes memory ret) {
        checkRow(j, op, "token");
        bytes memory cd = vm.parseJsonBytes(j, domainField(op, "token", "calldata"));
        assertEq(built, cd, "calldata");
        bytes memory rowSig = _sigOf(op);
        bytes memory sig = onChain(j, op, c);
        uint256 at = _find(cd, rowSig);
        for (uint256 i; i < 65; ++i) cd[at + i] = sig[i];
        vm.prank(_addr(op, "relayer"));
        bool ok;
        (ok, ret) = c.call(cd);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    function _find(bytes memory hay, bytes memory needle) internal pure returns (uint256) {
        for (uint256 i; i + needle.length <= hay.length; ++i) {
            uint256 k;
            while (k < needle.length && hay[i + k] == needle[k]) ++k;
            if (k == needle.length) return i;
        }
        revert("signature not in the calldata");
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
        address impl = address(new NormalToken(1, plainEnv(address(this), address(0), chainUidA, REG_L, false), ""));
        vm.etch(at, abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"));
        l = NormalToken(at);
        l.initialize(address(this), 1, abi.encode(normalInit("Leg", "LEG", 6, SUPPLY, address(this), address(this))));
        w = _wrapperAt(at, 1, 10);
        l.approve(address(w), SUPPLY);
        w.wrap(SUPPLY);
        w.transfer(signer, SUPPLY / 10);
        vm.mockCall(REG_L, abi.encodeCall(IUARegistry.kindOf, (_b32(op, "to"))), abi.encode(UAKinds.P256));
    }

    // ------------------------------------------------------------------ test_typedOpsVectors_<op>

    function test_typedOpsVectors_CancelNonce() public {
        string memory op = "CancelNonce";
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 lane = _uint(op, "lane");
        bytes memory built = abi.encodeCall(MetaTxBase.mtxCancelNonce, (e, lane, _sigOf(op)));
        _run(op, address(tok), built);
        assertEq(tok.mtxNonce(e.from, lane), 1, "the signed lane");
        assertEq(tok.mtxNonce(e.from, e.batch), 1, "the cancel's own lane");

        MandateWallet wallet = new MandateWallet(e.from, chainUidA);
        _run(op, address(wallet), built);
        assertEq(wallet.mtxNonce(e.from, lane), 1);

        // on an account `from` is not the account: an outside signer cancels its own lane there (`bytes sig`)
        SmartKeyAccount acct = SmartKeyAccount(payable(new SmartKeyAccountFactory(chainUidA).deploy(
            SubjectKey(KeyKind.SECP256K1, _pad(e.from), 0, 0, 0), address(0xD00D))));
        _run(op, address(acct), built);
        assertEq(acct.mtxNonce(e.from, lane), 1);
    }

    function test_typedOpsVectors_Burn() public {
        string memory op = "Burn";
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 amount = _uint(op, "amount");
        tok.mint(e.from, SUPPLY);
        _run(op, address(tok), abi.encodeCall(NormalToken.mtxBurn, (e, amount, _sigOf(op))));
        assertEq(tok.balanceOf(e.from), SUPPLY - amount - _feeOf(op, amount));
        assertEq(tok.balanceOf(e.feeRecipient), _feeOf(op, amount));
        assertEq(tok.mtxNonce(e.from, e.batch), 1);
    }

    function test_typedOpsVectors_UABurn() public {
        string memory op = "UABurn";
        MetaTxLib.UAEnvelope memory u = _uaEnv(op);
        uint256 amount = _uint(op, "amount");
        address from = address(uint160(uint256(u.from)));
        tok.mint(from, SUPPLY);
        _run(op, address(tok), abi.encodeCall(NormalToken.uaBurn, (u, amount, _uaSigOf(op))));
        assertEq(tok.balanceOf(from), SUPPLY - amount - _feeOf(op, amount));
        assertEq(tok.balanceOf(u.feeRecipient), _feeOf(op, amount));
        assertEq(tok.uaNonce(u.from, u.batch), 1);
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
        assertEq(wrp.mtxNonce(e.from, e.batch), 1);
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

    function test_typedOpsVectors_Unwrap() public {
        string memory op = "Unwrap";
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 wrapped = _uint(op, "wrapped");
        address recipient = _addr(op, "recipient");
        _fund(wrp, und, SUPPLY);
        _run(op, address(wrp), abi.encodeCall(WrappedToken.mtxUnwrap, (e, wrapped, recipient, _uint(op, "minOut"), _sigOf(op))));
        assertEq(und.balanceOf(recipient), wrapped);
        assertEq(wrp.balanceOf(e.from), SUPPLY - wrapped - _feeOf(op, wrapped));
        assertEq(wrp.balanceOf(e.feeRecipient), _feeOf(op, wrapped));
    }

    function test_typedOpsVectors_UAUnwrap() public {
        string memory op = "UAUnwrap";
        MetaTxLib.UAEnvelope memory u = _uaEnv(op);
        uint256 wrapped = _uint(op, "wrapped");
        address recipient = _addr(op, "recipient");
        _fund(wrp, und, SUPPLY);
        _run(op, address(wrp), abi.encodeWithSignature(_abi(op), u, wrapped, recipient, _uint(op, "minOut"), _uaSigOf(op)));
        assertEq(und.balanceOf(recipient), wrapped);
        assertEq(wrp.balanceOf(signer), SUPPLY - wrapped - _feeOf(op, wrapped));
        assertEq(wrp.balanceOf(u.feeRecipient), _feeOf(op, wrapped));
        assertEq(wrp.uaNonce(u.from, u.batch), 1);
    }

    function test_typedOpsVectors_UnwrapLeg() public {
        string memory op = "UnwrapLeg";
        (WrappedToken w, MockERC20 leg) = _rowLeg(op);
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 wrapped = _uint(op, "wrapped");
        address recipient = _addr(op, "recipient");
        vm.prank(e.from);
        w.wrap(SUPPLY);
        _run(op, address(w), abi.encodeCall(WrappedToken.mtxUnwrapLeg,
            (e, address(leg), wrapped, recipient, _uint(op, "minOut"), _sigOf(op))));
        assertEq(leg.balanceOf(recipient), wrapped);
        assertEq(w.balanceOf(e.feeRecipient), _feeOf(op, wrapped), "AMOUNT(1): the basis is `wrapped`");
    }

    function test_typedOpsVectors_UAUnwrapLeg() public {
        string memory op = "UAUnwrapLeg";
        (WrappedToken w, MockERC20 leg) = _rowLeg(op);
        MetaTxLib.UAEnvelope memory u = _uaEnv(op);
        uint256 wrapped = _uint(op, "wrapped");
        address recipient = _addr(op, "recipient");
        vm.prank(signer);
        w.wrap(SUPPLY);
        _run(op, address(w), abi.encodeCall(WrappedToken.uaUnwrapLeg,
            (u, address(leg), wrapped, recipient, _uint(op, "minOut"), _uaSigOf(op))));
        assertEq(leg.balanceOf(recipient), wrapped);
        assertEq(w.balanceOf(u.feeRecipient), _feeOf(op, wrapped));
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

    function test_typedOpsVectors_UnwrapToUA() public {
        string memory op = "UnwrapToUA";
        (WrappedToken w, NormalToken leg) = _rowLedgerLeg(op);
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        uint256 wrapped = _uint(op, "wrapped");
        bytes32 to = _b32(op, "to");
        _run(op, address(w), abi.encodeCall(WrappedToken.mtxUnwrapToUA,
            (e, address(leg), wrapped, to, _uint(op, "minOut"), _sigOf(op))));
        assertEq(leg.balanceOfUA(to), wrapped * 10);
        assertEq(w.balanceOf(e.feeRecipient), _feeOf(op, wrapped));
    }

    function test_typedOpsVectors_UAUnwrapToUA() public {
        string memory op = "UAUnwrapToUA";
        (WrappedToken w, NormalToken leg) = _rowLedgerLeg(op);
        MetaTxLib.UAEnvelope memory u = _uaEnv(op);
        uint256 wrapped = _uint(op, "wrapped");
        bytes32 to = _b32(op, "to");
        _run(op, address(w), abi.encodeCall(WrappedToken.uaUnwrapToUA,
            (u, address(leg), wrapped, to, _uint(op, "minOut"), _uaSigOf(op))));
        assertEq(leg.balanceOfUA(to), wrapped * 10);
        assertEq(w.balanceOf(u.feeRecipient), _feeOf(op, wrapped));
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

    string internal constant UNWRAP_HEAD = "Unwrap(address from,uint256 wrapped,address recipient,uint256 minOut,";

    function _unwrapSig(uint256 key, WrappedToken w, MetaTxLib.Envelope memory e, uint256 wrapped)
        internal view returns (bytes memory)
    {
        return _ecdsa(key, _digest(address(w), UNWRAP_HEAD, _pad(e.from), abi.encode(wrapped, bob, uint256(0)), e));
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

    /// `mtxCancelNonce` joined `IMetaTx`: 0xf6695913 ^ its selector (owner 2026-11-01).
    function test_iMetaTxIdPinned() public view {
        assertEq(type(IMetaTx).interfaceId, bytes4(0x2f1aa7fe));
        assertEq(type(IMetaTx).interfaceId ^ IMetaTx.mtxCancelNonce.selector, bytes4(0xf6695913));
        assertTrue(tok.supportsInterface(0x2f1aa7fe));
        assertTrue(wrp.supportsInterface(0x2f1aa7fe));
        assertFalse(tok.supportsInterface(0xf6695913));
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
    function test_genericEntriesKept() public {
        uint256 supply = tok.totalSupply();
        MetaTxLib.MetaTransaction memory m = _generic(alice, 0);
        tok.mtxExecute(m, _ecdsa(ALICE_PK, tok.mtxDigest(m)));
        m = _generic(alice, 1);
        assertTrue(tok.executeMetaTransaction(m, _ecdsa(ALICE_PK, tok.mtxDigest(m))));
        MetaTxLib.MetaTransaction[] memory ms = new MetaTxLib.MetaTransaction[](1);
        bytes[] memory sigs = new bytes[](1);
        ms[0] = _generic(alice, 2);
        sigs[0] = _ecdsa(ALICE_PK, tok.mtxDigest(ms[0]));
        assertTrue(tok.mtxBatch(ms, sigs));

        MetaTxLib.UAMetaTransaction memory u = _genericUA(_pad(alice), 3);
        tok.uaExecute(u, _authM(address(tok), u));
        MetaTxLib.UAMetaTransaction[] memory us = new MetaTxLib.UAMetaTransaction[](1);
        us[0] = _genericUA(_pad(alice), 4);
        sigs[0] = _authM(address(tok), us[0]);
        assertTrue(tok.uaBatch(us, sigs));

        assertEq(tok.totalSupply(), supply - 5);
        assertEq(tok.mtxNonce(alice, 3), 5);
    }

    function test_namedEntryReplayRefused() public {
        string memory op = "Burn";
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        tok.mint(e.from, SUPPLY);
        _run(op, address(tok), abi.encodeCall(NormalToken.mtxBurn, (e, _uint(op, "amount"), _sigOf(op))));
        bytes memory sig = onChain(j, op, address(tok));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        vm.prank(e.relayer);
        tok.mtxBurn(e, _uint(op, "amount"), sig);

        // the lane is the generic path's: the UA twin and the generic entry find nonce 0 gone too
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        vm.prank(e.relayer);
        tok.uaBurn(_uaE(e, _pad(e.from)), _uint(op, "amount"), _uaSigOf(op));
        MetaTxLib.MetaTransaction memory m = _generic(e.from, 0);
        m.batch = e.batch;
        bytes memory generic = _ecdsa(pk, tok.mtxDigest(m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        tok.mtxExecute(m, generic);
    }

    function test_namedEntryOtherOpDigestRefused() public {
        und.mint(alice, 1_000);
        vm.startPrank(alice);
        und.approve(address(wrp), 1_000);
        wrp.wrap(1_000);
        vm.stopPrank();
        MetaTxLib.Envelope memory e = _env(alice, 0, 0, 0, address(0));
        bytes memory sig = _unwrapSig(ALICE_PK, wrp, e, 100);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        wrp.mtxUnwrapLeg(e, address(und), 100, bob, 0, sig);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        wrp.uaUnwrap(_uaE(e, _pad(alice)), 100, bob, 0, _sigStruct(sig));
        wrp.mtxUnwrap(e, 100, bob, 0, sig);
        assertEq(und.balanceOf(bob), 100);
    }

    function _sigStruct(bytes memory sig) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = sig;
    }

    function test_namedEntryFeeClass() public {
        und.mint(alice, 1_000_000);
        vm.startPrank(alice);
        und.approve(address(wrp), 1_000_000);
        wrp.wrap(500_000);
        vm.stopPrank();

        // AMOUNT(0): PERCENT on `wrapped`, 1 % at most (CTR-MTX-20)
        MetaTxLib.Envelope memory e = _env(alice, 0, PCT | RF, 10_000, FEE_TO);
        wrp.mtxUnwrap(e, 100_000, bob, 0, _unwrapSig(ALICE_PK, wrp, e, 100_000));
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
        IUARegistry.UASig memory s = UAKinds.uaSig(uaP, _authFor(uaP, d));
        tok.uaBurn(_uaE(e, uaP), 100, s);
        assertEq(tok.balanceOfUA(uaP), 900);
        assertEq(tok.uaNonce(uaP, e.batch), 1);

        // the same signature on the next nonce: another digest
        e.nonce = 1;
        vm.expectRevert();
        tok.uaBurn(_uaE(e, uaP), 100, s);
    }

    function test_namedUAEmptySignatureRefused() public {
        MetaTxLib.Envelope memory e = _env(alice, 0, 0, 0, address(0));
        IUARegistry.UASig memory none;
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.uaBurn(_uaE(e, _pad(alice)), 1, none);
    }

    function test_relayFeeRouterRunsNamedEntry() public {
        und.mint(alice, 1_000);
        vm.startPrank(alice);
        und.approve(address(wrp), 1_000);
        wrp.wrap(1_000);
        vm.stopPrank();
        MtxRelayFee router = new MtxRelayFee();
        MetaTxLib.Envelope memory e = _env(alice, 0, RR, 0, address(0));
        e.relayer = router.EXECUTOR();
        bytes memory cd = abi.encodeCall(WrappedToken.mtxUnwrap, (e, 100, bob, 0, _unwrapSig(ALICE_PK, wrp, e, 100)));
        bytes32 ref = keccak256(abi.encodePacked("scaas.relayfee", block.chainid, address(wrp), keccak256(cd)));
        MetaTxLib.MetaTransfer memory t = MetaTxLib.MetaTransfer(alice, RELAYER, 25, ref, tok.payLane(ref), 0,
            block.timestamp + 300, RR, address(router), 0, address(0));
        bytes memory s = _ecdsa(ALICE_PK, tok.mtxTransferDigest(t));
        vm.prank(RELAYER);
        router.relay(address(wrp), cd, address(tok), t, s);
        assertEq(und.balanceOf(bob), 100);
        assertEq(tok.balanceOf(RELAYER), 25);
        assertEq(wrp.mtxNonce(alice, e.batch), 1);
    }
}
