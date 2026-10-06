// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherToken} from "../../src/zether/ZetherToken.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {ZetherSafety} from "../../src/zether/ZetherSafety.sol";
import {G1Bn254} from "../../src/zether/ZetherCurves.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode, FeePolicy} from "../../src/common/FeePolicy.sol";
import {FeeOnTransferERC20} from "../helpers/Mocks.sol";
import {Mock1271Wallet, Puller} from "../helpers/WalletMocks.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {AuthScheme} from "../../src/common/AuthScheme.sol";

/// Underlying có thể bị "rút ngầm" (rebase âm / blacklist trừ dần) — để bất biến escrow có việc làm.
contract SlashableERC20 is ERC20 {
    constructor() ERC20("Slash", "SL") {}
    function decimals() public pure override returns (uint8) { return 6; }
    function mint(address to, uint256 v) external { _mint(to, v); }
    function slash(address from, uint256 v) external { _burn(from, v); }
}

/// Underlying gọi ngược vào token trong lúc token chuyển tiền ra (ERC-777 / hook độc hại).
contract ReentrantERC20 is ERC20 {
    address public target;
    bytes public payload;
    constructor() ERC20("Re", "RE") {}
    function decimals() public pure override returns (uint8) { return 6; }
    function mint(address to, uint256 v) external { _mint(to, v); }
    function arm(address t, bytes calldata p) external { target = t; payload = p; }
    function _update(address from, address to, uint256 v) internal override {
        super._update(from, to, v);
        if (target != address(0) && from == target) {
            (bool ok, bytes memory ret) = target.call(payload);
            if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
        }
    }
}

/// @notice Danh mục đường revert (yêu cầu coverage của brief). Mỗi lỗi tuỳ biến của contract Zether
///         được chạm ít nhất một lần — ở đây, hoặc ở file ghi trong bảng:
///
/// | Lỗi | Ở đâu |
/// |---|---|
/// | AccountNotRegistered, AmountOutOfRange, SelfTransfer, BadPayload, ZeroRecipient, EscrowInvariant,
/// |   UnsupportedUnderlying, ZetherOpNotCanonical, NotFactory, AlreadyInitialized, BadInit,
/// |   ZetherNotDevChain (initialize), MetaTx{Expired,BadNonce,BadSignature,UnauthorizedRelayer},
/// |   ModeUnknownBits, ModeFeeInvalid, FeeExceedsCap, SpenderNotContract, CallerNotContract | file này |
/// | ProofRejected, StaleAccSeq, StaleSendCounter, RollOverOwnerOnly, RollOverExpired, PendingSeqMismatch,
/// |   UnknownEntry, OpeningMalformed, PercentFeeForbiddenOnConfidential, MetaTxInsufficientForFee | ZetherToken.t.sol |
/// | ZetherDisabled, NotRegistrar, ZetherNotDevChain (factory/verifier/registry) | ZetherGate.t.sol, registry test |
/// | registry: AccountAlreadyRegistered, InvalidProofOfPossession, UnauthorizedScheme, EVMAlreadyLinked,
/// |   InvalidPublicKey, InvalidAuthData, Unauthorized | UniversalAccountRegistry.t.sol |
/// | G1Bn254/G1Bls12381 BadPoint, BadLength | ZetherKat.t.sol + file này |
/// | Không chạm được (phòng thủ): `GeneratorStoreFailed` (CREATE chỉ fail khi hết gas), `ModexpFailed`
/// |   (precompile 0x05 có từ Byzantium), `require(ok)` trong `_inv` (cùng lý do), `mapToG` hết vòng. |
///
/// Theo từng **chỗ** revert (không chỉ từng lỗi): `forge coverage --ir-minimum` + đối chiếu BRDA của mọi dòng
/// `revert`/`require` trong `src/zether`, `src/registry` — mọi chỗ đều bị chạm trừ 4 chỗ phòng thủ trên và
/// `G1*.mul` (chỉ prover test dùng, không có trong contract). Khoá reentrancy (assembly) không hiện trong
/// coverage nhưng trace xác nhận `test_reentrancyBlocked` revert ở `tload`.
contract ZetherRevertPathsTest is ZetherFixture {
    uint256 constant PK = 0x5EC12E7;

    function setUp() public {
        _deploy(false, false);
    }

    function _vta(bytes32 ref, uint256 amount, ITransferDisclosure.OpeningKind kind, bytes memory opening)
        internal view returns (bool)
    {
        (bool ok, bytes memory ret) = address(tok).staticcall(
            abi.encodeWithSelector(ITransferDisclosure.verifyTransferAmount.selector, ref, amount, uint8(kind), opening)
        );
        if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
        return abi.decode(ret, (bool));
    }

    function _ata(bytes32 ref, uint256 amount, ITransferDisclosure.OpeningKind kind, bytes memory opening) internal {
        (bool ok, bytes memory ret) = address(tok).call(
            abi.encodeWithSelector(ITransferDisclosure.attestTransferAmount.selector, ref, amount, uint8(kind), opening)
        );
        if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
    }

    function test_fundRevertPaths() public {
        bytes memory stranger = ZetherKeys.pub(0x5757, false);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, ZetherTypes.toUA(stranger)));
        tok.fund(stranger, 1);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, 0, uint256(1) << 40));
        tok.fund(alice.y, 0);
        uint256 over = (uint256(1) << 40) + 1;
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, over, uint256(1) << 40));
        tok.fund(alice.y, over);
    }

    function _aliceTx() internal returns (Tx memory) {
        _fund(tok, alice, 100);
        tok.rollOverPublic(alice.ua);
        return _proveTransfer(tok, alice, bob, 10, 100, _none(), 0);
    }

    function _call(bytes memory payload, bytes memory proof, ZetherTypes.UA ben, bytes memory err) internal {
        vm.expectRevert(err);
        tok.transferConfidential(payload, proof, "", ben);
    }

    function test_transferBadPayloadLength() public {
        Tx memory t = _aliceTx();
        bytes memory longPl = bytes.concat(t.payload, hex"00");
        _call(longPl, t.proof, _none(), abi.encodeWithSelector(IZetherToken.BadPayload.selector, longPl.length));
    }

    function test_transferToSelfRejected() public {
        Tx memory t = _aliceTx();
        for (uint256 i; i < 64; ++i) t.payload[128 + i] = t.payload[64 + i]; // Y_to := Y_from
        _call(t.payload, t.proof, _none(), abi.encodeWithSelector(IZetherToken.SelfTransfer.selector));
    }

    function test_transferToUnregisteredRejected() public {
        Tx memory t = _aliceTx();
        bytes memory gy = ZetherKeys.pub(0x6057, false);
        for (uint256 i; i < 64; ++i) t.payload[128 + i] = gy[i];
        _call(t.payload, t.proof, _none(),
            abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, ZetherTypes.toUA(gy)));
    }

    /// Phí không phải cửa sau để "đăng ký hộ": beneficiary phải đã đăng ký.
    function test_unregisteredBeneficiaryRejected() public {
        Tx memory t = _aliceTx();
        ZetherTypes.UA ghost = ZetherTypes.toUA(ZetherKeys.pub(0x6057, false));
        _call(t.payload, t.proof, ghost, abi.encodeWithSelector(IZetherToken.AccountNotRegistered.selector, ghost));
    }

    function test_burnRevertPaths() public {
        _fund(tok, alice, 100);
        tok.rollOverPublic(alice.ua);
        (bytes memory pl, bytes memory pr) = _proveBurn(tok, alice, 10, 100, address(0xD), _none(), 0);
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, 0, uint256(1) << 40));
        tok.burn(pl, 0, address(0xD), _none(), pr, "");
        vm.expectRevert(IZetherToken.ZeroRecipient.selector);
        tok.burn(pl, 10, address(0), _none(), pr, "");
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.BadPayload.selector, pl.length - 1));
        tok.burn(_trim(pl), 10, address(0xD), _none(), pr, "");
        vm.expectRevert(IZetherToken.ProofRejected.selector); // recipient khác cái đã chứng minh
        tok.burn(pl, 10, address(0xE), _none(), pr, "");
        tok.burn(pl, 10, address(0xD), _none(), pr, "");
    }

    function _trim(bytes memory a) internal pure returns (bytes memory out) {
        out = new bytes(a.length - 1);
        for (uint256 i; i < out.length; ++i) out[i] = a[i];
    }

    function test_wrapUnwrapAndEscrowInvariant() public {
        SlashableERC20 sl = new SlashableERC20();
        bytes memory init = abi.encode("Z", "Z", address(reg), uint256(1), uint256(1) << 40, uint256(0), bytes(""));
        ZetherToken z = ZetherToken(factory.createZetherToken(1, address(sl), address(ver), init, "slash"));
        sl.mint(address(this), 100);
        sl.approve(address(z), 100);
        z.wrap(100);
        assertEq(z.balanceOf(address(this)), 100);
        vm.expectRevert(IZetherToken.ZeroRecipient.selector);
        z.unwrap(10, address(0));
        sl.slash(address(z), 1); // issuer trừ ngầm số dư escrow
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.EscrowInvariant.selector, 49, 50));
        z.unwrap(50, address(this));
    }

    function test_feeOnTransferUnderlyingRefused() public {
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        bytes memory init = abi.encode("Z", "Z", address(reg), uint256(1), uint256(1) << 40, uint256(0), bytes(""));
        ZetherToken z = ZetherToken(factory.createZetherToken(1, address(fot), address(ver), init, "fot"));
        fot.mint(address(this), 1000);
        fot.approve(address(z), 1000);
        vm.expectRevert(IZetherToken.UnsupportedUnderlying.selector);
        z.wrap(1000);
    }

    /// Phí tầng trong `< 2^n_v` (n_v = 64) VÀ `< maxDecryptableShielded` (review I3: phí ≥ trần làm mọi transfer
    /// có beneficiary không chứng minh được). 2^32 (trước đây bị từ chối) và trần − 1 tạo được; trần, 2^64 − 1 thì không.
    function test_confidentialFeeBound() public {
        uint256 max = uint256(1) << 40;
        uint256[2] memory ok = [uint256(1) << 32, max - 1];
        for (uint256 i; i < ok.length; ++i) {
            bytes memory init = abi.encode("Z", "Z", address(reg), uint256(1), max, ok[i], bytes(""));
            ZetherToken z = ZetherToken(factory.createZetherToken(1, address(usd), address(ver), init, bytes32(i + 900)));
            assertEq(z.confidentialFee(), ok[i]);
        }
        uint256[2] memory bad = [max, (uint256(1) << 64) - 1];
        for (uint256 i; i < bad.length; ++i) {
            bytes memory init = abi.encode("Z", "Z", address(reg), uint256(1), max, bad[i], bytes(""));
            vm.expectRevert(ZetherToken.BadInit.selector);
            factory.createZetherToken(1, address(usd), address(ver), init, bytes32(i + 910));
        }
    }

    function test_initializeRevertPaths() public {
        vm.expectRevert(ZetherToken.NotFactory.selector);
        impl.initialize(address(this), address(usd), address(ver), 1, "");
        vm.prank(address(factory));
        vm.expectRevert(ZetherToken.AlreadyInitialized.selector);
        tok.initialize(address(this), address(usd), address(ver), 1, "");
        bytes[5] memory bad = [
            abi.encode("Z", "Z", address(reg), uint256(0), uint256(1) << 40, uint256(0), bytes("")),          // scale 0
            abi.encode("Z", "Z", address(reg), uint256(1), (uint256(1) << 54) + 1, uint256(0), bytes("")),   // > 2^54
            abi.encode("Z", "Z", address(reg), uint256(1), uint256(1) << 40, uint256(1) << 64, bytes("")),   // fee ≥ 2^n_v = 2^64
            abi.encode("Z", "Z", address(0x1234), uint256(1), uint256(1) << 40, uint256(0), bytes("")),      // registry
            abi.encode("Z", "Z", address(reg), uint256(1), uint256(1) << 40, uint256(0), new bytes(64))      // auditor = O
        ];
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(ZetherToken.BadInit.selector);
            factory.createZetherToken(1, address(usd), address(ver), bad[i], bytes32(i + 100));
        }
        // underlying = chính clone sắp sinh (địa chỉ đoán trước được, đã có code lúc initialize)
        address self_ = factory.predictAddress(address(impl), address(this), "self");
        vm.expectRevert(ZetherToken.BadInit.selector);
        factory.createZetherToken(1, self_, address(ver), abi.encode("Z", "Z", address(reg), uint256(1), uint256(1) << 40, uint256(0), bytes("")), "self");
        // initialize ngoài chain dev (deploy tay, vòng qua factory flag)
        address c = Clones.clone(address(impl));
        vm.chainId(1);
        vm.prank(address(factory));
        vm.expectRevert(abi.encodeWithSelector(ZetherSafety.ZetherNotDevChain.selector, 1));
        ZetherToken(c).initialize(address(this), address(usd), address(ver), 1, bad[0]);
    }

    // ------------------------------------------------------------------ phong bì

    function _m(bytes memory data) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m = _mt(vm.addr(PK), data, 1, MetaTxLib.MODE_RESTRICT_RELAYER, 0);
    }

    function _exec(MetaTxLib.MetaTransaction memory m, bytes memory sig, bytes memory err) internal {
        vm.prank(relayer);
        vm.expectRevert(err);
        tok.executeMetaTransaction(m, sig);
    }

    function test_envelopeRevertPaths() public {
        MetaTxLib.MetaTransaction memory m = _m(hex"deadbeef");
        bytes memory sig = _sign(PK, tok, m);
        // relayer không được phép
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.MetaTxUnauthorizedRelayer.selector, relayer, address(this)));
        tok.executeMetaTransaction(m, sig);
        // op không biết
        _exec(m, sig, abi.encodeWithSelector(IZetherToken.ZetherOpNotCanonical.selector));
        // op Zether với `to` ≠ 0
        m = _m(abi.encodePacked(tok.OP_ZTRANSFER()));
        m.to = address(1);
        _exec(m, _sign(PK, tok, m), abi.encodeWithSelector(IZetherToken.ZetherOpNotCanonical.selector));
        // hết hạn
        m = _m("");
        m.validUntil = block.timestamp - 1;
        _exec(m, _sign(PK, tok, m), abi.encodeWithSelector(IERC20MetaTx.MetaTxExpired.selector, m.validUntil, block.timestamp));
        // nonce sai
        m = _m("");
        m.nonce = 3;
        _exec(m, _sign(PK, tok, m), abi.encodeWithSelector(IERC20MetaTx.MetaTxBadNonce.selector, 0, 3));
        // chữ ký của người khác
        m = _m("");
        _exec(m, _sign(PK + 1, tok, m), abi.encodeWithSelector(IERC20MetaTx.MetaTxBadSignature.selector));
        // mode lạ / phí lạ
        m = _m("");
        m.mode = 0x100;
        _exec(m, _sign(PK, tok, m), abi.encodeWithSelector(MetaTxLib.ModeUnknownBits.selector, uint32(0x100)));
        m.mode = 0x30;
        _exec(m, _sign(PK, tok, m), abi.encodeWithSelector(MetaTxLib.ModeFeeInvalid.selector, uint32(0x30)));
        // chuyển công khai: PERCENT vượt trần 1%
        m = _m("");
        m.mode = MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_FEE_PERCENT;
        m.fee = 10_001;
        _exec(m, _sign(PK, tok, m), abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 10_001, 10_000));
    }

    function test_smartAccountEnvelopeSignature() public {
        Mock1271Wallet w = new Mock1271Wallet(vm.addr(PK));
        MetaTxLib.MetaTransaction memory m = _mt(address(w), "", 1, MetaTxLib.MODE_RESTRICT_RELAYER, 0);
        m.to = address(0x1); // chuyển công khai value 0 — hợp lệ
        bytes memory sig = _sign(PK, tok, m);
        vm.prank(relayer);
        tok.executeMetaTransaction(m, sig);
        m.batch = 2;
        w.setMode(Mock1271Wallet.Mode.WrongMagic);
        _exec(m, _sign(PK, tok, m), abi.encodeWithSelector(IERC20MetaTx.MetaTxBadSignature.selector));
        tok.cancelMetaNonce(9);
        assertEq(tok.metaNonce(address(this), 9), 1);
        assertEq(tok.supportedModes(), MetaTxLib.MODE_KNOWN_MASK);
    }

    function test_relayedEntryPointsOnlySelf() public {
        vm.expectRevert(IZetherToken.ZetherOpNotCanonical.selector);
        tok.relayedTransfer("", "", "", _none(), bytes32(0), ZetherToken.OuterFee(address(this), address(0), 0));
        vm.expectRevert(IZetherToken.ZetherOpNotCanonical.selector);
        tok.relayedBurn("", bytes32(0), ZetherToken.OuterFee(address(this), address(0), 0));
        vm.expectRevert(IZetherToken.ZetherOpNotCanonical.selector);
        tok.relayedBurnDecoded("", "", "", ZetherToken.BurnArgs(0, address(0), _none(), 0), ZetherToken.OuterFee(address(this), address(0), 0));
    }

    /// R26 trên lớp ERC-20 công khai của Zether token: chỉ hợp đồng giữ/tiêu allowance.
    function test_contractOnlyAllowance() public {
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, address(0xE0A)));
        tok.approve(address(0xE0A), 1);
        vm.prank(address(0xE0A));
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, address(0xE0A)));
        tok.transferFrom(address(1), address(2), 0);
        Puller pl = new Puller();
        usd.mint(address(this), 10);
        usd.approve(address(tok), 10);
        tok.wrap(10);
        tok.approve(address(pl), 10);
        pl.pull(address(tok), address(this), address(0xF1), 10);
        assertEq(tok.balanceOf(address(0xF1)), 10);
    }

    function test_unknownEntryReverts() public {
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.UnknownEntry.selector, bytes32("nope")));
        _vta(bytes32("nope"), 1, ITransferDisclosure.OpeningKind.SENDER_S, abi.encode(uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(ITransferDisclosure.UnknownEntry.selector, bytes32("nope")));
        tok.transferCiphertext(bytes32("nope"));
    }

    /// Bất biến an ninh #1 (§11, SRS §8.1): với scheme ≠ SELF_SCHNORR, biết `x` (conf_custody) KHÔNG đủ để
    ///      chi — cần thêm chữ ký auth_custody trên `authDigest`.
    function test_confKeyAloneCannotSpendMultisigAccount() public {
        User memory dave = _multisigUser(0xDA7E, 0x0DD, address(0xD4));
        _fund(tok, dave, 100);
        tok.rollOverPublic(dave.ua);
        Tx memory t = _proveTransfer(tok, dave, bob, 10, 100, _none(), 0);
        vm.expectRevert(); // proof hợp lệ, nhưng không có chữ ký của chủ multisig
        tok.transferConfidential(t.payload, t.proof, "", _none());
        bytes32 authDigest = keccak256(abi.encodePacked(
            "SCAAS-ZETHER-AUTH-V1", keccak256(tok.transferStatement(t.payload, _none(), 0))
        ));
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _ecdsa(0x0DD, authDigest);
        tok.transferConfidential(t.payload, t.proof, abi.encode(sigs), _none());
        assertEq(tok.sendCounter(dave.ua), 1);
    }

    function _multisigUser(uint256 x, uint256 ownerPk, address evm) internal returns (User memory u) {
        address[] memory owners = new address[](1);
        owners[0] = vm.addr(ownerPk);
        u.x = x;
        u.y = ZetherKeys.pub(x, false);
        u.evm = evm;
        bytes32 c = reg.popChallenge(u.y, evm);
        bytes[] memory pop = new bytes[](1);
        pop[0] = _ecdsa(ownerPk, c);
        bytes memory popSig = abi.encode(ZetherKeys.schnorr(x, c, false), abi.encode(pop));
        vm.prank(evm);
        u.ua = reg.register(u.y, AuthScheme.ECDSA_MULTISIG, abi.encode(owners, uint256(1)), popSig, false);
    }

    function _ecdsa(uint256 pk, bytes32 h) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r, s, v);
    }

    /// Khoá reentrancy theo contract (transient): hook của underlying gọi lại token giữa `unwrap` ⇒ revert.
    function test_reentrancyBlocked() public {
        ReentrantERC20 re = new ReentrantERC20();
        bytes memory init = abi.encode("Z", "Z", address(reg), uint256(1), uint256(1) << 40, uint256(0), bytes(""));
        ZetherToken z = ZetherToken(factory.createZetherToken(1, address(re), address(ver), init, "re"));
        re.mint(address(this), 100);
        re.approve(address(z), 100);
        z.wrap(100);
        re.arm(address(z), abi.encodeCall(ZetherToken.rollOverPublic, (alice.ua)));
        vm.expectRevert(bytes(""));
        z.unwrap(10, address(this));
    }

    /// EOA uỷ quyền EIP-7702 (code = 0xef0100‖addr) vẫn là EOA: không giữ allowance (R26).
    function test_eip7702DelegatedEoaIsNotASpender() public {
        address eoa = address(0x7702);
        vm.etch(eoa, abi.encodePacked(hex"ef0100", address(0x1234)));
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, eoa));
        tok.approve(eoa, 1);
    }

    function test_curveLibBadLength() public {
        vm.expectRevert(abi.encodeWithSelector(G1Bn254.BadLength.selector, 63));
        ver.g1Add(new bytes(63), new bytes(64));
        bytes memory g = ver.g1MulBase(1);
        vm.expectRevert(abi.encodeWithSelector(G1Bn254.BadLength.selector, 63));
        ver.g1Sub(g, new bytes(63)); // neg
        vm.expectRevert(abi.encodeWithSelector(G1Bn254.BadLength.selector, 128));
        ver.g1Msm(bytes.concat(g, g), new uint256[](1)); // msm: pts ≠ k·64
    }
}
