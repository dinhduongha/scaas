// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {MockHederaAccountService} from "../hedera/HederaMocks.sol";

/// Kind NONE on the flags and the owner model (CTR-TOK-21, CTR-TOK-22) and the Hedera branch (CTR-TOK-23).
contract FeaturesTest is Test {
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint256 internal constant PK = 0xA11CE;
    address internal alice = vm.addr(PK);
    address internal ownerA = address(0x0A);
    address internal minter = address(0x111);
    address internal relayer = address(0xBEEF);
    address internal shop = address(0x5409);
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;

    uint256 internal constant PAYABLE = 1 << 0;
    uint256 internal constant MINTABLE = 1 << 1;
    uint256 internal constant BURNABLE = 1 << 2;

    address internal impl;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        impl = address(new NoUnderlyingToken(address(this), address(0), UID, false));
    }

    function _cfg(uint256 features, uint256 locked, address owner_, address minter_, uint256 supply)
        internal view returns (IFactoryToken.TokenConfig memory c)
    {
        (c.name, c.symbol, c.decimals, c.features, c.lockedFeatures, c.owner) =
            ("Points", "PTS", 6, features, locked, owner_);
        c.roles.minter = minter_;
        (c.initialSupply, c.initialHolder) = (supply, alice);
    }

    function _token(address implementation, IFactoryToken.TokenConfig memory cfg)
        internal returns (NoUnderlyingToken t)
    {
        t = NoUnderlyingToken(Clones.clone(implementation));
        t.initialize(address(this), 1, cfg);
    }

    function _sig(bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, d);
        return abi.encodePacked(r, s, v);
    }

    // ------------------------------------------------------------------ init, provenance

    function test_initWritesMetadataProvenanceAndFlags() public {
        NoUnderlyingToken t = _token(impl, _cfg(PAYABLE | MINTABLE | BURNABLE, MINTABLE, ownerA, minter, 1_000));
        assertEq(t.name(), "Points");
        assertEq(t.symbol(), "PTS");
        assertEq(t.decimals(), 6);
        assertEq(t.kind(), 0);
        assertEq(t.creator(), address(this));
        assertEq(t.version(), 1);
        assertEq(t.features(), PAYABLE | MINTABLE | BURNABLE);
        assertEq(t.lockedFeatures(), PAYABLE | MINTABLE | BURNABLE);
        assertEq(t.owner(), ownerA);
        assertTrue(t.hasRole(1, minter));
        assertEq(t.balanceOf(alice), 1_000);
        assertFalse(t.IS_HEDERA());
    }

    function test_initRefusesFlagsOfAnotherKind() public {
        NoUnderlyingToken t = NoUnderlyingToken(Clones.clone(impl));
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, uint8(3)));
        t.initialize(address(this), 1, _cfg(1 << 3, 0, address(0), address(0), 0));
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureNotBuilt.selector, uint8(7)));
        t.initialize(address(this), 1, _cfg(1 << 7, 0, address(0), address(0), 0));
    }

    // ------------------------------------------------------------------ MINTABLE, BURNABLE

    function test_mint_needsTheFlagAndTheRole() public {
        NoUnderlyingToken t = _token(impl, _cfg(MINTABLE, 0, ownerA, minter, 0));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.MissingRole.selector, uint8(1), alice));
        t.mint(alice, 1);
        vm.prank(minter);
        t.mint(alice, 5);
        assertEq(t.balanceOf(alice), 5);
        vm.prank(ownerA);
        t.disableFeature(1);
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, uint8(1)));
        t.mint(alice, 1);
    }

    function test_mint_withoutTheFlag_fixedSupply() public {
        NoUnderlyingToken t = _token(impl, _cfg(0, 0, address(0), address(0), 7));
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, uint8(1)));
        t.mint(alice, 1);
        assertEq(t.totalSupply(), 7);
    }

    function test_burn_onlyWithBurnable_directAndGasless() public {
        NoUnderlyingToken off = _token(impl, _cfg(0, 0, address(0), address(0), 100));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, uint8(2)));
        off.burn(1);
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({from: alice,
            data: abi.encodeCall(NoUnderlyingToken.burn, (1)), batch: 1, nonce: 0, validUntil: block.timestamp + 300,
            mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)});
        bytes memory s = _sig(off.mtxDigest(m));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, uint8(2)));
        off.mtxExecute(m, s);
        NoUnderlyingToken on = _token(impl, _cfg(BURNABLE, 0, address(0), address(0), 100));
        s = _sig(on.mtxDigest(m));
        vm.prank(relayer);
        on.mtxExecute(m, s);
        assertEq(on.balanceOf(alice), 99);
    }

    // ------------------------------------------------------------------ PAYABLE

    function test_payable_off_gatesThePayEntries_notMetaTransfer() public {
        NoUnderlyingToken t = _token(impl, _cfg(0, 0, address(0), address(0), 100));
        bytes memory off = abi.encodeWithSelector(ITokenAdmin.FeatureNotSet.selector, uint8(0));
        vm.prank(alice);
        vm.expectRevert(off);
        t.payWithFee(shop, 1, FeeMode.NONE, 0, address(0), bytes32("r"));
        bytes32 ref = keccak256("r");
        MetaTxLib.MetaTransfer memory x = MetaTxLib.MetaTransfer({from: alice, to: shop, value: 10, entryRef: ref,
            batch: t.payLane(ref), nonce: 0, validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0,
            feeRecipient: address(0)});
        bytes memory s = _sig(t.mtxTransferDigest(x));
        vm.prank(relayer);
        vm.expectRevert(off);
        t.mtxPay(alice, shop, 10, ref, x.validUntil, RR, relayer, 0, address(0), s);
        vm.prank(relayer);
        vm.expectRevert(off);
        t.mtxPayReceiverFee(x, s, 1, address(0xFEE), block.timestamp, s);
        vm.prank(relayer);
        vm.expectEmit(address(t));
        emit IERC20Payment.PaymentSettled(alice, shop, 10, 0, relayer, ref); // a MetaTransfer payment is never gated
        t.mtxExecuteTransfer(x, s);
        assertEq(t.balanceOf(shop), 10);
    }

    function test_payable_on_payWithFeeWorks() public {
        NoUnderlyingToken t = _token(impl, _cfg(PAYABLE, 0, address(0), address(0), 100));
        vm.prank(alice);
        t.payWithFee(shop, 10, FeeMode.NONE, 0, address(0), bytes32("r"));
        assertEq(t.balanceOf(shop), 10);
    }

    function test_supportsInterface_paymentOnlyWhenPayable() public {
        NoUnderlyingToken off = _token(impl, _cfg(0, 0, address(0), address(0), 0));
        NoUnderlyingToken on = _token(impl, _cfg(PAYABLE, 0, address(0), address(0), 0));
        bytes4[4] memory always = [type(IERC165).interfaceId, type(IERC20).interfaceId, type(IMetaTx).interfaceId,
            type(IERC20MetaTx).interfaceId];
        for (uint256 i; i < 4; ++i) {
            assertTrue(off.supportsInterface(always[i]));
            assertTrue(on.supportsInterface(always[i]));
        }
        assertFalse(off.supportsInterface(type(IERC20Payment).interfaceId));
        assertTrue(on.supportsInterface(type(IERC20Payment).interfaceId));
        assertFalse(on.supportsInterface(0xffffffff));
    }

    // ------------------------------------------------------------------ owner through the token

    function test_ownerAdministersThroughTheToken() public {
        NoUnderlyingToken t = _token(impl, _cfg(MINTABLE, 0, ownerA, address(0), 0));
        vm.prank(ownerA);
        vm.expectEmit(address(t));
        emit ITokenAdmin.RoleGranted(1, minter, ownerA);
        t.grantRole(1, minter);
        vm.prank(minter);
        t.mint(alice, 3);
        vm.prank(ownerA);
        t.transferOwnership(address(0x0B));
        vm.prank(address(0x0B));
        t.acceptOwnership();
        assertEq(t.owner(), address(0x0B));
        vm.prank(address(0x0B));
        t.renounceOwnership();
        assertEq(t.owner(), address(0));
        vm.prank(minter);
        t.mint(alice, 1);                                     // holders keep their role after the owner renounces
        vm.prank(minter);
        t.renounceRole(1);
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.MissingRole.selector, uint8(1), minter));
        t.mint(alice, 1);
    }

    function test_adminFunctionsAreNeverSelfCalls() public {
        NoUnderlyingToken t = _token(impl, _cfg(MINTABLE, 0, alice, address(0), 0));
        bytes4[7] memory sels = [t.grantRole.selector, t.revokeRole.selector, t.renounceRole.selector,
            t.disableFeature.selector, t.transferOwnership.selector, t.acceptOwnership.selector,
            t.renounceOwnership.selector];
        for (uint256 i; i < 7; ++i) {
            MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({from: alice,
                data: abi.encodeWithSelector(sels[i]), batch: i, nonce: 0, validUntil: block.timestamp + 300,
                mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)});
            bytes memory s = _sig(t.mtxDigest(m));
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, sels[i]));
            t.mtxExecute(m, s);
        }
    }

    /// AdminLib writes `scaas.token` only: the meta-tx lanes (`scaas.metatx`) and the ERC-20 slots stay put.
    function test_adminWritesDoNotTouchOtherNamespaces() public {
        NoUnderlyingToken t = _token(impl, _cfg(MINTABLE, 0, ownerA, address(0), 100));
        bytes32 lane = keccak256(abi.encode(uint256(1), keccak256(abi.encode(alice,
            bytes32(0x06b01547c739946503c06c80685cc72ae2fec5074fd602f84cd2fa888722ac00)))));
        bytes32 bal = keccak256(abi.encode(alice, uint256(0)));
        vm.prank(alice);
        t.cancelNonce(1);
        bytes32 laneBefore = vm.load(address(t), lane);
        bytes32 balBefore = vm.load(address(t), bal);
        assertEq(uint256(laneBefore), 1);
        assertEq(uint256(balBefore), 100);
        vm.startPrank(ownerA);
        t.grantRole(1, minter);
        t.disableFeature(1);
        t.transferOwnership(minter);
        vm.stopPrank();
        assertEq(vm.load(address(t), lane), laneBefore);
        assertEq(vm.load(address(t), bal), balBefore);
        assertEq(t.balanceOf(alice), 100);
        // the admin state landed in `scaas.token`: features word (MINTABLE disabled) and pendingOwner at slot + 3
        bytes32 tok = 0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00;
        assertEq(uint256(vm.load(address(t), tok)), t.features());
        assertEq(t.features(), 0);
        assertEq(address(uint160(uint256(vm.load(address(t), bytes32(uint256(tok) + 3))))), minter);
        assertEq(t.pendingOwner(), minter);
    }

    // ------------------------------------------------------------------ IS_HEDERA (CTR-TOK-23)

    function test_isHedera_takesTheHip632Path_onlyWhenSet() public {
        address has = address(0x16a);
        vm.etch(has, type(MockHederaAccountService).runtimeCode);
        uint256 edKey = 0xA11CE5;
        address native = address(uint160(1_234_567));
        MockHederaAccountService(has).setEdKey(native, vm.addr(edKey));
        address hImpl = address(new NoUnderlyingToken(address(this), address(0), UID, true));
        IFactoryToken.TokenConfig memory cfg;
        (cfg.name, cfg.symbol, cfg.initialSupply, cfg.initialHolder) = ("P", "P", 100, native);
        NoUnderlyingToken h = _token(hImpl, cfg);
        NoUnderlyingToken e = _token(impl, cfg);
        assertTrue(h.IS_HEDERA());
        MetaTxLib.MetaTransfer memory x = MetaTxLib.MetaTransfer({from: native, to: shop, value: 10, entryRef: 0,
            batch: 1, nonce: 0, validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0,
            feeRecipient: address(0)});
        (bytes32 rr, bytes32 vs) = vm.signCompact(edKey, h.mtxTransferDigest(x));
        vm.prank(relayer);
        h.mtxExecuteTransfer(x, abi.encodePacked(rr, vs));
        assertEq(h.balanceOf(shop), 10);
        (rr, vs) = vm.signCompact(edKey, e.mtxTransferDigest(x));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        e.mtxExecuteTransfer(x, abi.encodePacked(rr, vs));
    }
}
