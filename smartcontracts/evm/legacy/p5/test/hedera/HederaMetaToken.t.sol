// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {OpenFactoryV1} from "../../src/factory/OpenFactoryV1.sol";
import {IOpenFactoryV1} from "../../src/common/IOpenFactoryV1.sol";
import {MetaToken} from "../../src/metatx/MetaToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IERC20MetaTxV1} from "../../src/metatx/IERC20MetaTxV1.sol";
import {IERC20PaymentV1} from "../../src/metatx/IERC20PaymentV1.sol";
import {MetaTxDex} from "../../src/dex/MetaTxDex.sol";
import {HederaMetaToken} from "../../src/hedera/HederaMetaToken.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {MockHederaAccountService, MockHts} from "./HederaMocks.sol";

/// Fixture Hedera: factory + implementation `HederaMetaToken`, precompile 0x16a / 0x167 giả.
abstract contract HederaFixture is Test {
    address constant HAS = address(0x16a);
    address constant HTS = address(0x167);
    uint32 constant R = MetaTxLib.MODE_RESTRICT_RELAYER;
    address internal relayer = address(0xBEEF);
    address internal registrar = address(0xF00D);
    OpenFactoryV1 internal factory;
    HederaMetaToken internal impl;

    function _setUpHedera() internal {
        vm.chainId(296);
        vm.warp(1_800_000_000);
        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        vm.etch(HTS, type(MockHts).runtimeCode);
        factory = new OpenFactoryV1(registrar);
        impl = new HederaMetaToken(address(factory));
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl));
    }

    function _token(string memory sym, uint256 supply) internal returns (HederaMetaToken) {
        bytes memory init = abi.encode(string.concat("Token ", sym), sym, uint8(6), supply, address(0));
        return HederaMetaToken(factory.createMetaToken(1, address(0), init, keccak256(bytes(sym))));
    }

    /// Tài khoản Hedera `0.0.num` khoá ED25519 (mô phỏng bằng khoá `keyPk`, xem MockHederaAccountService).
    function _nativeAccount(uint64 num, uint256 keyPk) internal returns (address acct) {
        acct = address(uint160(num));
        MockHederaAccountService(HAS).setEdKey(acct, vm.addr(keyPk));
    }

    function _edSign(uint256 keyPk, bytes32 digest) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 vs) = vm.signCompact(keyPk, digest);
        return abi.encodePacked(r, vs);
    }

    function _pay(address from, address to, uint256 value, bytes32 ref) internal view
        returns (MetaTxLib.LegacyMetaTransaction memory)
    {
        return MetaTxLib.LegacyMetaTransaction({
            from: from, to: to, value: value,
            data: abi.encodeWithSelector(bytes4(keccak256("pay(bytes32)")), ref),
            batch: uint256(keccak256(abi.encodePacked("scaas.pay.lane", ref))), nonce: 0,
            validUntil: block.timestamp + 300, mode: R, relayer: relayer, fee: 0, feeRecipient: address(0)
        });
    }
}

contract HederaMetaTokenTest is HederaFixture {
    uint256 constant ALICE_KEY = 0xA11CE5;
    uint256 constant MALLORY_KEY = 0xBAD;
    uint256 constant EVM_PK = 0xE0A;
    address alice;            // 0.0.1234567, khoá ED25519
    address shop = address(0x5409);
    HederaMetaToken tok;
    HederaMetaToken tok2;

    function setUp() public {
        _setUpHedera();
        alice = _nativeAccount(1_234_567, ALICE_KEY);
        tok = _token("HBUSD", 1_000_000e6);
        tok2 = _token("HPTS", 1_000_000e6);
        tok.transfer(alice, 1_000e6);
        tok2.transfer(alice, 1_000e6);
    }

    function _exec(HederaMetaToken t, MetaTxLib.LegacyMetaTransaction memory m, bytes memory sig) internal {
        vm.prank(relayer);
        t.executeMetaTransaction(m, sig);
    }

    function test_nativeEd25519AccountPays() public {
        MetaTxLib.LegacyMetaTransaction memory m = _pay(alice, shop, 250e6, bytes32(uint256(0x42)));
        bytes32 digest = tok.metaTxDigest(m);
        vm.expectEmit(address(tok));
        emit IERC20PaymentV1.PaymentSettled(alice, shop, 250e6, 0, relayer, bytes32(uint256(0x42)));
        vm.expectEmit(address(tok));
        emit IERC20MetaTxV1.MetaTransactionExecuted(alice, relayer, m.batch, 0, digest, relayer, 0);
        _exec(tok, m, _edSign(ALICE_KEY, digest));
        assertEq(tok.balanceOf(shop), 250e6);
        assertEq(tok.metaNonce(alice, m.batch), 1);
    }

    function test_precompileGetsAccountDigestAndSignature() public {
        MetaTxLib.LegacyMetaTransaction memory m = _pay(alice, shop, 1e6, bytes32(uint256(1)));
        bytes32 digest = tok.metaTxDigest(m);
        bytes memory sig = _edSign(ALICE_KEY, digest);
        vm.expectCall(HAS, abi.encodeWithSelector(bytes4(0xb2a31da4), alice, abi.encodePacked(digest), sig));
        _exec(tok, m, sig);
    }

    /// Hedera HALT 0x16a trong frame tĩnh (thử trên testnet): gọi bằng STATICCALL thì không bao giờ được uỷ quyền.
    function test_precompileHaltsInStaticFrameLikeHedera() public {
        bytes memory input = abi.encodeWithSelector(bytes4(0xb2a31da4), alice, abi.encodePacked(bytes32(0)), new bytes(64));
        (bool ok,) = HAS.staticcall(input);
        assertFalse(ok);
        (ok,) = HAS.call(input);
        assertTrue(ok);
    }

    function test_otherKeyIsRejected() public {
        MetaTxLib.LegacyMetaTransaction memory m = _pay(alice, shop, 1e6, bytes32(uint256(1)));
        bytes memory sig = _edSign(MALLORY_KEY, tok.metaTxDigest(m));
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTxV1.MetaTxBadSignature.selector);
        tok.executeMetaTransaction(m, sig);
    }

    function test_unknownAccountRevertInPrecompileIsBadSignature() public {
        address ghost = address(uint160(9_999_999));
        MetaTxLib.LegacyMetaTransaction memory m = _pay(ghost, shop, 0, bytes32(uint256(1)));
        bytes memory sig = _edSign(ALICE_KEY, tok.metaTxDigest(m));
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTxV1.MetaTxBadSignature.selector);
        tok.executeMetaTransaction(m, sig);
    }

    function test_complexKeyAccountIsRejected() public {
        address multi = address(uint160(7_777_777));
        MockHederaAccountService(HAS).setComplexKey(multi);
        MetaTxLib.LegacyMetaTransaction memory m = _pay(multi, shop, 0, bytes32(uint256(1)));
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTxV1.MetaTxBadSignature.selector);
        tok.executeMetaTransaction(m, new bytes(64));
    }

    /// Không có precompile (chain không phải Hedera) ⇒ staticcall vào địa chỉ rỗng trả rỗng ⇒ từ chối.
    function test_failsClosedWithoutPrecompile() public {
        vm.etch(HAS, "");
        MetaTxLib.LegacyMetaTransaction memory m = _pay(alice, shop, 1e6, bytes32(uint256(1)));
        bytes memory sig = _edSign(ALICE_KEY, tok.metaTxDigest(m));
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTxV1.MetaTxBadSignature.selector);
        tok.executeMetaTransaction(m, sig);
    }

    /// Một EOA ECDSA không thể dùng chữ ký compact 64 byte để đi vòng: 64 byte tới precompile, nơi tài khoản
    /// này không có khoá ED ⇒ revert ⇒ từ chối.
    function test_compactEcdsaFromEoaDoesNotBypass() public {
        address eoa = vm.addr(EVM_PK);
        tok.transfer(eoa, 10e6);
        MetaTxLib.LegacyMetaTransaction memory m = _pay(eoa, shop, 1e6, bytes32(uint256(1)));
        (bytes32 r, bytes32 vs) = vm.signCompact(EVM_PK, tok.metaTxDigest(m));
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTxV1.MetaTxBadSignature.selector);
        tok.executeMetaTransaction(m, abi.encodePacked(r, vs));
    }

    function test_ecdsaAliasAccountStillPays() public {
        address eoa = vm.addr(EVM_PK);
        tok.transfer(eoa, 10e6);
        MetaTxLib.LegacyMetaTransaction memory m = _pay(eoa, shop, 1e6, bytes32(uint256(1)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(EVM_PK, tok.metaTxDigest(m));
        _exec(tok, m, abi.encodePacked(r, s, v));
        assertEq(tok.balanceOf(shop), 1e6);
    }

    /// Ví hợp đồng (passkey/SubjectAccount) vẫn đi ERC-1271 kể cả khi blob dài đúng 64 byte.
    function test_contractWalletStillUsesErc1271() public {
        Mock1271Wallet w = new Mock1271Wallet(vm.addr(EVM_PK));
        tok.transfer(address(w), 10e6);
        MetaTxLib.LegacyMetaTransaction memory m = _pay(address(w), shop, 1e6, bytes32(uint256(1)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(EVM_PK, tok.metaTxDigest(m));
        _exec(tok, m, abi.encodePacked(r, s, v));
        assertEq(tok.balanceOf(shop), 1e6);
        MetaTxLib.LegacyMetaTransaction memory m2 = _pay(address(w), shop, 1e6, bytes32(uint256(2)));
        vm.expectCall(HAS, bytes(""), 0); // không bao giờ gọi precompile cho ví hợp đồng
        vm.prank(relayer);
        vm.expectRevert();
        tok.executeMetaTransaction(m2, new bytes(64));
    }

    function test_replayIsRejected() public {
        MetaTxLib.LegacyMetaTransaction memory m = _pay(alice, shop, 1e6, bytes32(uint256(1)));
        bytes memory sig = _edSign(ALICE_KEY, tok.metaTxDigest(m));
        _exec(tok, m, sig);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.MetaTxBadNonce.selector, 1, 0));
        tok.executeMetaTransaction(m, sig);
    }

    /// Chữ ký cho Hedera mainnet (295) không chạy trên testnet (296): chainId nằm trong domain.
    function test_crossNetworkReplayIsRejected() public {
        MetaTxLib.LegacyMetaTransaction memory m = _pay(alice, shop, 1e6, bytes32(uint256(1)));
        vm.chainId(295);
        bytes memory sig = _edSign(ALICE_KEY, tok.metaTxDigest(m));
        vm.chainId(296);
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTxV1.MetaTxBadSignature.selector);
        tok.executeMetaTransaction(m, sig);
    }

    /// Chữ ký cho token 1 không chạy trên token 2: verifyingContract nằm trong domain.
    function test_crossContractReplayIsRejected() public {
        MetaTxLib.LegacyMetaTransaction memory m = _pay(alice, shop, 1e6, bytes32(uint256(1)));
        bytes memory sig = _edSign(ALICE_KEY, tok.metaTxDigest(m));
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTxV1.MetaTxBadSignature.selector);
        tok2.executeMetaTransaction(m, sig);
    }

    function test_expiredIsRejected() public {
        MetaTxLib.LegacyMetaTransaction memory m = _pay(alice, shop, 1e6, bytes32(uint256(1)));
        bytes memory sig = _edSign(ALICE_KEY, tok.metaTxDigest(m));
        vm.warp(m.validUntil + 1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.MetaTxExpired.selector, m.validUntil, m.validUntil + 1));
        tok.executeMetaTransaction(m, sig);
    }

    /// ANTI-LOCK (R30/R62): X ở contract 1 bị giữ lại, Y ở contract 2 vẫn chạy; sau đó X chạy.
    function test_antiLock_withheldOpOnOneContractDoesNotBlockAnother() public {
        MetaTxLib.LegacyMetaTransaction memory x = _pay(alice, shop, 3e6, bytes32(uint256(0xA)));
        MetaTxLib.LegacyMetaTransaction memory y = _pay(alice, shop, 5e6, bytes32(uint256(0xB)));
        bytes memory sx = _edSign(ALICE_KEY, tok.metaTxDigest(x));
        bytes memory sy = _edSign(ALICE_KEY, tok2.metaTxDigest(y));
        _exec(tok2, y, sy);                       // Y trước, X vẫn bị giữ
        assertEq(tok2.balanceOf(shop), 5e6);
        assertEq(tok.balanceOf(shop), 0);
        vm.warp(block.timestamp + 120);           // X đến muộn nhưng còn hạn
        _exec(tok, x, sx);
        assertEq(tok.balanceOf(shop), 3e6);
    }

    /// Cùng contract, hai lane (`batch` theo entryRef): lane giữ lại không chặn lane khác.
    function test_antiLock_sameContractOtherLane() public {
        MetaTxLib.LegacyMetaTransaction memory x = _pay(alice, shop, 3e6, bytes32(uint256(0xA)));
        MetaTxLib.LegacyMetaTransaction memory y = _pay(alice, shop, 5e6, bytes32(uint256(0xB)));
        bytes memory sx = _edSign(ALICE_KEY, tok.metaTxDigest(x));
        bytes memory sy = _edSign(ALICE_KEY, tok.metaTxDigest(y));
        _exec(tok, y, sy);
        _exec(tok, x, sx);
        assertEq(tok.balanceOf(shop), 8e6);
    }

    function test_dexSettlesWithAnEd25519Leg() public {
        MetaTxDex dex = new MetaTxDex();
        uint256 bobPk = 0xB0B;
        address bob = vm.addr(bobPk);
        tok2.transfer(bob, 500e6);
        MetaTxLib.LegacyMetaTransaction memory a = _leg(alice, address(dex), 100e6, address(tok2), 60e6, 1);
        MetaTxLib.LegacyMetaTransaction memory b = _leg(bob, address(dex), 60e6, address(tok), 100e6, 2);
        MetaTxDex.Leg memory la = MetaTxDex.Leg(IERC20MetaTxV1(address(tok)), a, _edSign(ALICE_KEY, tok.metaTxDigest(a)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPk, tok2.metaTxDigest(b));
        MetaTxDex.Leg memory lb = MetaTxDex.Leg(IERC20MetaTxV1(address(tok2)), b, abi.encodePacked(r, s, v));
        vm.prank(relayer);
        dex.settle(la, lb);
        assertEq(tok2.balanceOf(alice), 1_000e6 + 60e6);
        assertEq(tok.balanceOf(bob), 100e6);
    }

    function _leg(address from, address dex, uint256 value, address counter, uint256 minCounter, uint256 lane)
        internal view returns (MetaTxLib.LegacyMetaTransaction memory)
    {
        return MetaTxLib.LegacyMetaTransaction({
            from: from, to: dex, value: value,
            data: abi.encodeWithSelector(bytes4(keccak256("trade(address,uint256,address)")), counter, minCounter, address(0)),
            batch: lane, nonce: 0, validUntil: block.timestamp + 300, mode: R, relayer: dex, fee: 0,
            feeRecipient: address(0)
        });
    }
}

contract HederaHtsWrapperTest is HederaFixture {
    MockERC20 hts; // mặt tiền ERC-20 của token HTS (HIP-218)
    HederaMetaToken wrapper;

    function setUp() public {
        _setUpHedera();
        hts = new MockERC20("USD Coin", "USDC", 6);
        bytes memory init = abi.encode("Wrapped USDC", "wUSDC", uint8(0), uint256(0), address(0));
        wrapper = HederaMetaToken(factory.createMetaToken(1, address(hts), init, bytes32("wusdc")));
    }

    function test_associateIsPermissionlessAndIdempotent() public {
        vm.prank(address(0xCAFE));
        wrapper.associateUnderlying();
        assertTrue(MockHts(HTS).associated(address(wrapper), address(hts)));
        wrapper.associateUnderlying(); // 194 = đã associate: vẫn OK
    }

    function test_associateFailureSurfaces() public {
        MockHts(HTS).force(int64(167)); // TOKEN_ID_REPEATED_IN_TOKEN_LIST hay bất kỳ mã lỗi nào
        vm.expectRevert(abi.encodeWithSelector(HederaMetaToken.AssociateFailed.selector, int64(167)));
        wrapper.associateUnderlying();
    }

    function test_noHtsPrecompileFails() public {
        vm.etch(HTS, "");
        vm.expectRevert(abi.encodeWithSelector(HederaMetaToken.AssociateFailed.selector, int64(-1)));
        wrapper.associateUnderlying();
    }

    function test_standaloneHasNothingToAssociate() public {
        HederaMetaToken t = _token("HB", 1);
        vm.expectRevert(MetaToken.NotAWrapper.selector);
        t.associateUnderlying();
    }

    function test_wrapAfterAssociate() public {
        wrapper.associateUnderlying();
        hts.mint(address(this), 10e6);
        hts.approve(address(wrapper), 10e6); // allowance HTS chỉ cho contract wrapper (R26)
        wrapper.wrap(10e6);
        assertEq(wrapper.balanceOf(address(this)), 10e6);
        assertEq(wrapper.decimals(), 6);
    }
}
