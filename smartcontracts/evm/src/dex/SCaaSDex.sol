// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";

/// @title Thanh toán on-chain cho sổ lệnh off-chain (R35). Thiết kế: `2026-10-03-dex-design.md`.
/// @notice Hai lệnh EIP-712 ký trên DEX (EOA: ECDSA; contract: ERC-1271), giới hạn giá hai bên,
///         `filled[orderHash]` không bao giờ vượt `sellAmount`, khớp một phần, batch nguyên tử
///         từng cặp. Tiền đi thẳng người→người bằng `transferFrom` — DEX là spender (R26) nhưng
///         không bao giờ giữ số dư. Không upgrade, không sweep; admin chỉ `setMarket` (RS5-1).
contract SCaaSDex is EIP712, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    struct Order {
        address maker;
        address taker;        // 0 = ai cũng được
        address sellToken;
        address buyToken;
        uint256 sellAmount;   // tổng bán
        uint256 buyAmount;    // tổng tối thiểu nhận (gross, trước phí DEX)
        uint256 nonce;        // hợp lệ khi >= minNonce[maker]
        uint256 expiry;
        uint32 maxFeePpm;     // phí DEX tối đa người ký chấp nhận
        uint8 flags;          // FLAG_FOK | FLAG_IOC
        address relayer;      // 0 = relayer nào cũng nộp được
        uint8 feeMode;        // phí relayer: FeeMode
        uint256 fee;
        address feeToken;     // 0 = sellToken
        address feeRecipient; // 0 = relayer đã nộp tx
    }

    struct Match {
        bytes32 ref;          // relayer đặt, chỉ echo trong event
        Order maker;
        bytes makerSig;
        Order taker;
        bytes takerSig;
        uint256 makerFill;    // maker.sellToken maker giao
        uint256 takerFill;    // taker.sellToken taker giao
    }

    struct CancelReq {
        Order order;
        bytes sig;              // CancelOrder(orderHash) của order.maker
    }

    struct Market {
        bool listed;
        bool feeOn;
        uint32 makerFeePpm;
        uint32 takerFeePpm;
        address feeRecipient;
    }

    /// @dev Một bên của một cặp, đúng góc nhìn ví đó (Odoo hạch toán từ đây).
    struct Fill {
        address sellToken;
        uint256 sold;
        address buyToken;
        uint256 received;            // net, sau phí DEX
        uint256 dexFee;              // trên buyToken
        address dexFeeRecipient;
        address relayerFeeToken;
        uint256 relayerFee;
        address relayerFeeRecipient;
        uint256 filledTotal;
    }

    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address maker,address taker,address sellToken,address buyToken,uint256 sellAmount,uint256 buyAmount,"
        "uint256 nonce,uint256 expiry,uint32 maxFeePpm,uint8 flags,address relayer,uint8 feeMode,uint256 fee,"
        "address feeToken,address feeRecipient)"
    );
    /// @dev Không có `validUntil`: huỷ chỉ đi một chiều có lợi cho người ký và phát lại là no-op;
    ///      một hạn ở đây chỉ mở cửa sổ "đã huỷ off-chain mà job on-chain hết hạn" (review D4).
    bytes32 public constant CANCEL_TYPEHASH = keccak256("CancelOrder(bytes32 orderHash)");
    bytes32 public constant INVALIDATE_TYPEHASH = keccak256("InvalidateNonces(address maker,uint256 minNonce)");

    uint8 public constant FLAG_FOK = 1;
    uint8 public constant FLAG_IOC = 2;
    uint8 internal constant FLAGS_KNOWN = 3;
    uint256 internal constant MAX_MIN_NONCE = type(uint128).max;
    uint256 internal constant PPM = FeePolicy.PPM_DENOMINATOR;

    // checkOrder status
    uint8 public constant ST_OK = 0;
    uint8 public constant ST_BAD_FLAGS = 1;
    uint8 public constant ST_EXPIRED = 2;
    uint8 public constant ST_NONCE_INVALID = 3;
    uint8 public constant ST_BAD_SIG = 4;
    uint8 public constant ST_CLOSED = 5;
    uint8 public constant ST_NOT_LISTED = 6;
    uint8 public constant ST_BAD_FEE = 7;

    address public immutable admin;
    mapping(bytes32 => Market) public markets;
    mapping(bytes32 => uint256) public filled;
    mapping(address => uint256) public minNonce;

    event MarketSet(bytes32 indexed key, address tokenA, address tokenB, Market market);
    event OrderFilled(bytes32 indexed ref, bytes32 indexed orderHash, address indexed owner, Fill fill);
    event Matched(bytes32 indexed ref, bytes32 indexed makerHash, bytes32 indexed takerHash);
    event MatchFailed(bytes32 indexed ref, bytes reason);
    event OrderCancelled(bytes32 indexed orderHash, address indexed maker);
    event NoncesInvalidated(address indexed maker, uint256 minNonce);

    error NotAdmin();
    error OnlySelf();
    error BadMarket();
    error MarketNotListed();
    error TokenMismatch();
    error SelfTrade();
    error ZeroFill();
    error PriceLimit(bytes32 orderHash);
    error FeeAboveSigned(bytes32 orderHash);
    error BadFlags(bytes32 orderHash);
    error OrderExpired(bytes32 orderHash);
    error NonceInvalidated(bytes32 orderHash);
    error WrongRelayer(bytes32 orderHash);
    error WrongTaker(bytes32 orderHash);
    error BadSignature(bytes32 orderHash);
    error FillOrKill(bytes32 orderHash);
    error Overfill(bytes32 orderHash, uint256 filledBefore, uint256 fill, uint256 sellAmount);
    error PercentFeeNeedsSellToken(bytes32 orderHash);
    error FeeModeInvalid(bytes32 orderHash);
    error FeeWouldStick();
    error NonceNotIncreasing();
    error NothingSettled();

    constructor(address admin_) EIP712("SCaaS Dex", "1") {
        admin = admin_;
    }

    // ------------------------------------------------------------------ admin (RS5-1)

    function setMarket(address tokenA, address tokenB, Market calldata m) external {
        if (msg.sender != admin) revert NotAdmin();
        if (tokenA == tokenB || tokenA == address(0) || tokenB == address(0)) revert BadMarket();
        if (m.makerFeePpm > FeePolicy.MAX_FEE_PPM || m.takerFeePpm > FeePolicy.MAX_FEE_PPM) revert BadMarket();
        if (m.feeOn && (m.feeRecipient == address(0) || m.feeRecipient == address(this))) revert FeeWouldStick();
        bytes32 k = marketKey(tokenA, tokenB);
        markets[k] = m;
        emit MarketSet(k, tokenA, tokenB, m);
    }

    function marketKey(address a, address b) public pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }

    // ------------------------------------------------------------------ hashing

    /// @notice Danh tính lệnh = digest EIP-712 đầy đủ (gắn chain + DEX này).
    function orderHash(Order calldata o) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(ORDER_TYPEHASH, o)));
    }

    function cancelDigest(bytes32 h) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(CANCEL_TYPEHASH, h)));
    }

    function invalidateDigest(address maker, uint256 newMin) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(INVALIDATE_TYPEHASH, maker, newMin)));
    }

    // ------------------------------------------------------------------ settlement

    /// @notice Nhiều cặp một tx; mỗi cặp nguyên tử riêng (`try`), cặp fail emit `MatchFailed`.
    ///         Không cặp nào qua ⇒ cả tx revert: simulate của relayer bắt được, không đốt gas cho
    ///         một batch rỗng (review D10). Lệnh IOC đóng phần còn lại khi tx kết thúc (review D3).
    function settle(Match[] calldata ms) external nonReentrant returns (bool[] memory ok) {
        ok = new bool[](ms.length);
        uint256[] memory ioc = new uint256[](ms.length * 2); // 2·i (maker) | 2·i+1 (taker)
        uint256 n;
        uint256 settled;
        for (uint256 i; i < ms.length; ++i) {
            // Relayer thật đi theo tham số: trong lời gọi tự thân msg.sender là DEX, và phí
            // relayer mặc định về msg.sender sẽ kẹt ở đây (FeeWouldStick).
            try this.settleOne(ms[i], msg.sender) {
                ok[i] = true;
                ++settled;
                if (ms[i].maker.flags & FLAG_IOC != 0) ioc[n++] = 2 * i;
                if (ms[i].taker.flags & FLAG_IOC != 0) ioc[n++] = 2 * i + 1;
            } catch (bytes memory reason) {
                emit MatchFailed(ms[i].ref, reason);
            }
        }
        if (settled == 0) revert NothingSettled();
        for (uint256 j; j < n; ++j) {
            Match calldata m = ms[ioc[j] / 2];
            _closeIoc(ioc[j] % 2 == 0 ? m.maker : m.taker);
        }
    }

    /// @dev IOC: "chỉ trong tx này". Đóng phần còn lại để không relayer nào settle tiếp được.
    function _closeIoc(Order calldata o) private {
        bytes32 h = orderHash(o);
        if (filled[h] < o.sellAmount) {
            filled[h] = o.sellAmount;
            emit OrderCancelled(h, o.maker);
        }
    }

    /// @dev External để `try` cô lập được từng cặp; chỉ chính DEX gọi.
    function settleOne(Match calldata m, address sender) external {
        if (msg.sender != address(this)) revert OnlySelf();
        (bytes32 ha, bytes32 hb, Market memory mk) = _checkMatch(m, sender);
        // Phí DEX trên phần NHẬN của bên chịu phí, làm tròn xuống (RS5-6). Tắt phí ⇒ 0 ⇒ không
        // một lệnh chuyển phí nào (không phải "chuyển 0").
        uint256 aFee = mk.feeOn ? m.takerFill * mk.makerFeePpm / PPM : 0;
        uint256 bFee = mk.feeOn ? m.makerFill * mk.takerFeePpm / PPM : 0;
        _move(m.maker.sellToken, m.maker.maker, m.taker.maker, m.makerFill, bFee, mk.feeRecipient);
        _move(m.taker.sellToken, m.taker.maker, m.maker.maker, m.takerFill, aFee, mk.feeRecipient);
        _emitFill(m.ref, ha, m.maker, _fill(m.makerFill, m.takerFill - aFee, aFee, mk.feeRecipient), sender);
        _emitFill(m.ref, hb, m.taker, _fill(m.takerFill, m.makerFill - bFee, bFee, mk.feeRecipient), sender);
        emit Matched(m.ref, ha, hb);
    }

    function _checkMatch(Match calldata m, address sender)
        private returns (bytes32 ha, bytes32 hb, Market memory mk)
    {
        Order calldata a = m.maker;
        Order calldata b = m.taker;
        if (a.sellToken != b.buyToken || a.buyToken != b.sellToken || a.sellToken == a.buyToken) {
            revert TokenMismatch();
        }
        if (a.maker == b.maker) revert SelfTrade();
        if (m.makerFill == 0 || m.takerFill == 0) revert ZeroFill();
        mk = markets[marketKey(a.sellToken, a.buyToken)];
        if (!mk.listed) revert MarketNotListed();
        ha = _accept(a, m.makerSig, m.makerFill, b.maker, sender);
        hb = _accept(b, m.takerSig, m.takerFill, a.maker, sender);
        // Giới hạn giá, nhân chéo, checked: tràn thì revert, không bao giờ sai giá.
        if (m.takerFill * a.sellAmount < m.makerFill * a.buyAmount) revert PriceLimit(ha);
        if (m.makerFill * b.sellAmount < m.takerFill * b.buyAmount) revert PriceLimit(hb);
        if (mk.feeOn && mk.makerFeePpm > a.maxFeePpm) revert FeeAboveSigned(ha);
        if (mk.feeOn && mk.takerFeePpm > b.maxFeePpm) revert FeeAboveSigned(hb);
    }

    function _fill(uint256 sold, uint256 received, uint256 dexFee, address feeTo)
        private pure returns (Fill memory f)
    {
        f.sold = sold;
        f.received = received;
        f.dexFee = dexFee;
        f.dexFeeRecipient = dexFee == 0 ? address(0) : feeTo;
    }

    /// @dev Kiểm một lệnh và ghi `filled` (effects trước interactions).
    function _accept(Order calldata o, bytes calldata sig, uint256 fill, address counterparty, address sender)
        private returns (bytes32 h)
    {
        h = orderHash(o);
        if (!_flagsOk(o.flags)) revert BadFlags(h);
        if (block.timestamp > o.expiry) revert OrderExpired(h);
        if (o.nonce < minNonce[o.maker]) revert NonceInvalidated(h);
        if (o.relayer != address(0) && o.relayer != sender) revert WrongRelayer(h);
        if (o.taker != address(0) && o.taker != counterparty) revert WrongTaker(h);
        uint256 f = filled[h];
        if (o.flags & FLAG_FOK != 0 && (f != 0 || fill != o.sellAmount)) revert FillOrKill(h);
        if (fill > o.sellAmount - f) revert Overfill(h, f, fill, o.sellAmount);
        if (!_validSig(o.maker, h, sig)) revert BadSignature(h);
        filled[h] = f + fill;
    }

    /// @dev `from` giao `amount`: `fee` cho người thu phí DEX, phần còn lại cho `to`.
    function _move(address token, address from, address to, uint256 amount, uint256 fee, address feeTo) private {
        IERC20(token).safeTransferFrom(from, to, amount - fee);
        if (fee != 0) IERC20(token).safeTransferFrom(from, feeTo, fee);
    }

    /// @dev Trả phí relayer của bên này rồi emit góc nhìn của nó.
    function _emitFill(bytes32 ref, bytes32 h, Order calldata o, Fill memory f, address sender) private {
        f.sellToken = o.sellToken;
        f.buyToken = o.buyToken;
        (address token, uint256 amount, address to) = _relayerFee(h, o, f.sold, sender);
        if (amount != 0) IERC20(token).safeTransferFrom(o.maker, to, amount);
        f.relayerFeeToken = token;
        f.relayerFee = amount;
        f.relayerFeeRecipient = to;
        f.filledTotal = filled[h];
        emit OrderFilled(ref, h, o.maker, f);
    }

    /// @dev Phí relayer của một lệnh cho lần khớp này (§1.5).
    function _relayerFee(bytes32 h, Order calldata o, uint256 sold, address sender)
        private view returns (address token, uint256 amount, address to)
    {
        if (o.feeMode > uint8(FeeMode.FIXED)) revert FeeModeInvalid(h);
        FeeMode mode = FeeMode(o.feeMode);
        if (mode == FeeMode.NONE) return (address(0), 0, address(0));
        token = o.feeToken == address(0) ? o.sellToken : o.feeToken;
        if (mode == FeeMode.PERCENT) {
            if (token != o.sellToken) revert PercentFeeNeedsSellToken(h);
            amount = FeePolicy.compute(FeeMode.PERCENT, sold, o.fee);
        } else {
            // Trả bằng chính token bán thì chịu trần 1 % của tổng lệnh; token phí riêng thì là
            // con số tuyệt đối người ký đã thấy. Pro-rata, làm tròn xuống ⇒ tổng <= fee.
            if (token == o.sellToken) FeePolicy.compute(FeeMode.FIXED, o.sellAmount, o.fee);
            amount = Math.mulDiv(o.fee, sold, o.sellAmount); // 512 bit như node (review agy F1)
        }
        to = o.feeRecipient == address(0) ? sender : o.feeRecipient;
        if (to == address(this)) revert FeeWouldStick();
    }

    // ------------------------------------------------------------------ cancel (meta-tx)

    /// @notice Huỷ bằng chữ ký `CancelOrder` của maker; relayer nào nộp cũng được. Đóng vĩnh viễn
    ///         (`filled = sellAmount`): không relayer nào settle được nữa, kể cả kẻ giữ bản ký.
    ///         Gom nhiều lệnh một tx (chặn spam gas, review D14); mục chữ ký sai bị bỏ qua.
    function cancel(CancelReq[] calldata reqs) external nonReentrant {
        for (uint256 i; i < reqs.length; ++i) {
            Order calldata o = reqs[i].order;
            bytes32 h = orderHash(o);
            if (filled[h] >= o.sellAmount || !_validSig(o.maker, cancelDigest(h), reqs[i].sig)) continue;
            filled[h] = o.sellAmount;
            emit OrderCancelled(h, o.maker);
        }
    }

    /// @notice Huỷ mọi lệnh `nonce < newMin`. `newMin` phải tăng ⇒ phát lại bị từ chối; trần
    ///         2^128 để một chữ ký nhầm không khoá vĩnh viễn địa chỉ (review D23).
    function invalidateNonces(address maker, uint256 newMin, bytes calldata sig) external nonReentrant {
        if (newMin <= minNonce[maker] || newMin > MAX_MIN_NONCE) revert NonceNotIncreasing();
        if (!_validSig(maker, invalidateDigest(maker, newMin), sig)) revert BadSignature(bytes32(0));
        minNonce[maker] = newMin;
        emit NoncesInvalidated(maker, newMin);
    }

    // ------------------------------------------------------------------ intake view

    /// @notice Mọi kiểm ở cửa trong một `eth_call` (§1.6).
    function checkOrder(Order calldata o, bytes calldata sig)
        external view returns (bytes32 h, uint8 status, uint256 remaining, uint256 fundable, uint256 feeFundable)
    {
        h = orderHash(o);
        remaining = o.sellAmount - filled[h];
        fundable = _fundable(o.sellToken, o.maker);
        if (!_flagsOk(o.flags)) return (h, ST_BAD_FLAGS, remaining, fundable, 0);
        if (block.timestamp > o.expiry) return (h, ST_EXPIRED, remaining, fundable, 0);
        if (o.nonce < minNonce[o.maker]) return (h, ST_NONCE_INVALID, remaining, fundable, 0);
        if (!_validSig(o.maker, h, sig)) return (h, ST_BAD_SIG, remaining, fundable, 0);
        if (remaining == 0) return (h, ST_CLOSED, 0, fundable, 0);
        if (!markets[marketKey(o.sellToken, o.buyToken)].listed) return (h, ST_NOT_LISTED, remaining, fundable, 0);
        if (o.feeMode > uint8(FeeMode.FIXED) || o.feeRecipient == address(this)) {
            return (h, ST_BAD_FEE, remaining, fundable, 0);
        }
        if (o.feeMode != uint8(FeeMode.NONE)) {
            address ft = o.feeToken == address(0) ? o.sellToken : o.feeToken;
            if (o.feeMode == uint8(FeeMode.PERCENT) && (ft != o.sellToken || o.fee > FeePolicy.MAX_FEE_PPM)) {
                return (h, ST_BAD_FEE, remaining, fundable, 0);
            }
            if (o.feeMode == uint8(FeeMode.FIXED) && ft == o.sellToken
                && o.fee > o.sellAmount * FeePolicy.MAX_FEE_PPM / PPM) {
                return (h, ST_BAD_FEE, remaining, fundable, 0);
            }
            feeFundable = _fundable(ft, o.maker);
        }
        status = ST_OK;
    }

    /// @dev FOK và IOC loại trừ nhau (review D17); bit lạ bị từ chối.
    function _flagsOk(uint8 flags) private pure returns (bool) {
        return flags & ~FLAGS_KNOWN == 0 && flags != FLAG_FOK | FLAG_IOC;
    }

    function _fundable(address token, address owner) private view returns (uint256) {
        uint256 bal = IERC20(token).balanceOf(owner);
        uint256 alw = IERC20(token).allowance(owner, address(this));
        return bal < alw ? bal : alw;
    }

    // ------------------------------------------------------------------ signatures

    /// @dev Như `ERC20MetaTx`: phân biệt bằng code, không bằng độ dài chữ ký; designator
    ///      EIP-7702 là EOA (khoá của nó vẫn ký được). Contract ⇒ ERC-1271 (account passkey/seed).
    function _validSig(address signer, bytes32 digest, bytes calldata sig) private view returns (bool) {
        if (_isContract(signer)) return SignatureChecker.isValidERC1271SignatureNow(signer, digest, sig);
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
        return err == ECDSA.RecoverError.NoError && rec == signer;
    }

    function _isContract(address a) private view returns (bool) {
        uint256 len = a.code.length;
        if (len == 0) return false;
        if (len == 23) {
            bytes memory c = a.code;
            if (c[0] == 0xef && c[1] == 0x01 && c[2] == 0x00) return false;
        }
        return true;
    }
}
