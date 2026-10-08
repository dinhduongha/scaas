// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {IUniversalAccountRegistry} from "../registry/IUniversalAccountRegistry.sol";
import {ZetherMetaTx} from "./ZetherMetaTx.sol";
import {IZetherToken} from "./IZetherToken.sol";
import {IZetherVerifier} from "./IZetherVerifier.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {ZetherTranscript} from "./ZetherTranscript.sol";
import {ZetherSafety} from "./ZetherSafety.sol";

/// @title ZetherToken v1 — implementation kind ZETHER, deploy bằng clone EIP-1167 qua `OpenFactory`.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Chỉ khởi tạo được trên chain dev (RS2-1).
///
///         Một implementation cho MỌI đường cong: điểm là `bytes`, phép nhóm và proof đi qua `verifier`
///         bất biến chọn lúc tạo. Trạng thái `acc`/`pending` + `accSeq`/`pendingSeq`/`sendCounter`, hai
///         chế độ rollOver, fund/transfer/burn, ràng phong bì meta-tx, phí scalar công khai, tiết lộ có
///         chọn lọc — đặc tả `2026-10-03-zether-design.md` §5–§12.
///
///         Hai lớp số dư: ERC-20 công khai (wrap 1:1 underlying, dùng trả phí ngoài) và số dư mã hoá.
///         Bất biến escrow: `underlying.balanceOf(this) ≥ totalSupply() + totalShielded·shieldScale`,
///         kiểm sau mọi lần tiền rời contract.
contract ZetherToken is ZetherMetaTx, IZetherToken, ITransferDisclosure, IFactoryToken {
    using SafeERC20 for IERC20;

    struct Account {
        bytes accC;
        bytes accD;
        bytes pendC;
        bytes pendD;
        uint64 accSeq;
        uint64 pendingSeq;
        uint64 lastRolledPendingSeq;
        uint64 sendCounter;
        uint64 modeNonce;
        ZetherTypes.RollOverMode mode;
    }

    /// @dev Phí ngoài: ai trả (số dư công khai), trả cho ai, bao nhiêu. Thu SAU verify, TRƯỚC hiệu lực.
    struct OuterFee {
        address payer;
        address recipient;
        uint256 amount;
    }

    struct BurnArgs {
        uint256 amount;
        address recipient;
        ZetherTypes.UA beneficiary;
        bytes32 binding;
    }

    /// @dev Kết quả bước kiểm của một transfer/burn, trước verify proof.
    struct Prepared {
        ZetherTypes.UA from;
        bytes statement;
        uint256 fee;
        uint64 sendCounter;
    }

    bytes4 public constant OP_ZTRANSFER = bytes4(keccak256("zetherTransfer(bytes,bytes,bytes,bytes32)"));
    bytes4 public constant OP_ZBURN = bytes4(keccak256("zetherBurn(bytes,uint256,address,bytes32,bytes,bytes)"));

    bytes32 private constant OP_TRANSFER = keccak256("SCAAS-ZETHER-OP-TRANSFER-V1");
    bytes32 private constant OP_BURN = keccak256("SCAAS-ZETHER-OP-BURN-V1");
    bytes32 private constant OP_MULTI_HASH = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/HASH");
    bytes32 private constant OP_MULTI_BUNDLE = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/BUNDLE");
    bytes32 private constant OP_MULTI_NONE = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/NONE");
    uint256 private constant MAX_RECIPIENTS = 16;
    bytes32 private constant TAG_DIRECT = keccak256("ZTX_V1_DIRECT");
    bytes32 private constant TAG_RELAYED = keccak256("ZTX_V1_RELAYED");
    bytes32 private constant TAG_ENVELOPE = keccak256("SCAAS-ZETHER-ENVELOPE-V1");
    bytes32 private constant TAG_ENTRY = keccak256("SCAAS-ZETHER-ENTRY-V1");
    bytes32 private constant TAG_ROLLOVER = keccak256("ZETHER_ROLLOVER_V1");
    bytes32 private constant TAG_SET_MODE = keccak256("ZETHER_SET_ROLLOVER_MODE_V1");
    bytes private constant AUTH_TAG = "SCAAS-ZETHER-AUTH-V1";
    bytes private constant DISCLOSE_TAG = "SCAAS-ZETHER-DISCLOSE-V1";
    uint256 private constant MAX_TOTAL_SHIELDED = 1 << 54;
    /// @dev `2^n_v` (n_v = 64, RS-NV64-1): trần của `confidentialFee` và của số tiền tiết lộ.
    uint256 private constant VALUE_BOUND = 1 << 64;

    address public immutable FACTORY;
    address private immutable _SELF;

    bool private _initialized;
    string private _tokenName;
    string private _tokenSymbol;
    uint8 private _tokenDecimals;

    address public creator;
    address public underlying;
    uint64 public version;
    IZetherVerifier public verifier;
    address public registry;
    uint256 public shieldScale;
    uint256 public maxDecryptableShielded;
    uint256 public confidentialFee;
    uint256 public totalShielded;
    bytes private _auditorKey;
    bytes32 private _psid;
    uint256 private _p;
    uint256 private _r;

    mapping(ZetherTypes.UA => Account) private _acct;
    /// @dev Bundle tiết lộ theo `entryRef`: `B_1 ‖ … ‖ B_M` với `B_j = Y_t ‖ C_out ‖ D_out ‖ C_aud` (transfer một
    ///      người nhận và mode BUNDLE), hoặc đúng 32 byte `keccak256(B_1 ‖ … ‖ B_M)` (mode HASH; 4P ≥ 256 nên
    ///      không lẫn). Mode NONE không ghi gì.
    mapping(bytes32 => bytes) private _entries;

    error NotFactory();
    error AlreadyInitialized();
    error BadInit();

    constructor(address factory_) ERC20("", "") EIP712("SCaaS ZetherToken", "1") {
        FACTORY = factory_;
        _SELF = address(this);
        _initialized = true;
    }

    /// @param initData `abi.encode(string name, string symbol, address registry, uint256 shieldScale,
    ///        uint256 maxDecryptableShielded, uint256 confidentialFee, bytes auditorKey)`.
    function initialize(address creator_, address underlying_, address verifier_, uint64 version_, bytes calldata initData)
        external
    {
        if (msg.sender != FACTORY) revert NotFactory();
        if (_initialized) revert AlreadyInitialized();
        ZetherSafety.requireDevChain();
        _initialized = true;
        (string memory n, string memory s, address reg, uint256 scale, uint256 maxShielded, uint256 fee, bytes memory aud) =
            abi.decode(initData, (string, string, address, uint256, uint256, uint256, bytes));
        IZetherVerifier v = IZetherVerifier(verifier_);
        uint256 p = v.g1EncodedBytes();
        if (
            underlying_.code.length == 0 || underlying_ == address(this) || reg.code.length == 0 || scale == 0
                || maxShielded == 0
                || maxShielded > MAX_TOTAL_SHIELDED || fee >= VALUE_BOUND
                // phí ≥ trần tổng: không số dư nào trả nổi ⇒ mọi transfer có beneficiary không chứng minh được
                || fee >= maxShielded
                || (aud.length != 0 && (aud.length != p || !v.isValidPoint(aud) || _isO(aud)))
        ) revert BadInit();
        maxShielded * scale; // tràn ⇒ revert (checked)
        creator = creator_;
        underlying = underlying_;
        version = version_;
        verifier = v;
        registry = reg;
        shieldScale = scale;
        maxDecryptableShielded = maxShielded;
        confidentialFee = fee;
        _auditorKey = aud;
        _psid = v.proofSystemId();
        _p = p;
        _r = v.groupOrder();
        _tokenName = n;
        _tokenSymbol = s;
        _tokenDecimals = IERC20Metadata(underlying_).decimals();
    }

    function name() public view override returns (string memory) { return _tokenName; }
    function symbol() public view override returns (string memory) { return _tokenSymbol; }
    function decimals() public view override returns (uint8) { return _tokenDecimals; }
    function factory() external view returns (address) { return FACTORY; }
    function implementation() external view returns (address) { return _SELF; }
    function auditorKey() external view returns (bytes memory) { return _auditorKey; }

    // ------------------------------------------------------------------ đọc

    function registered(ZetherTypes.UA ua) public view returns (bool) {
        return IUniversalAccountRegistry(registry).keyLengthOf(ua) == _p; // đúng đường cong của verifier
    }

    function accountState(ZetherTypes.UA ua) external view returns (AccountState memory s) {
        Account storage a = _acct[ua];
        s = AccountState({
            accC: _pt(a.accC), accD: _pt(a.accD), pendingC: _pt(a.pendC), pendingD: _pt(a.pendD),
            accSeq: a.accSeq, pendingSeq: a.pendingSeq, sendCounter: a.sendCounter, modeNonce: a.modeNonce,
            mode: a.mode
        });
    }

    function sendCounter(ZetherTypes.UA ua) external view returns (uint256) {
        return _acct[ua].sendCounter;
    }

    // ------------------------------------------------------------------ công khai ⇄ underlying

    function wrap(uint256 amount) external nonReentrant {
        _pull(msg.sender, amount);
        _mint(msg.sender, amount);
    }

    function unwrap(uint256 amount, address recipient) external nonReentrant {
        if (recipient == address(0)) revert ZeroRecipient();
        _burn(msg.sender, amount);
        IERC20(underlying).safeTransfer(recipient, amount);
        _checkEscrow();
    }

    // ------------------------------------------------------------------ fund

    function fund(bytes calldata encodedY, uint256 amount) external nonReentrant {
        ZetherTypes.UA ua = ZetherTypes.toUA(encodedY);
        _requireRegistered(ua);
        uint256 room = maxDecryptableShielded - totalShielded;
        if (amount == 0 || amount > room) revert AmountOutOfRange(amount, room);
        _pull(msg.sender, amount * shieldScale);
        totalShielded += amount;
        _credit(ua, verifier.g1MulBase(amount), "");
        emit Funded(ua, amount);
    }

    /// @dev Kéo đúng `raw` underlying; token phí-chuyển bị từ chối (không biểu diễn được phần thiếu).
    function _pull(address from, uint256 raw) private {
        IERC20 u = IERC20(underlying);
        uint256 before = u.balanceOf(address(this));
        u.safeTransferFrom(from, address(this), raw);
        if (u.balanceOf(address(this)) - before != raw) revert UnsupportedUnderlying();
    }

    // ------------------------------------------------------------------ rollOver (SRS §7.6)

    function rollOverPublic(ZetherTypes.UA ua) external nonReentrant {
        if (_acct[ua].mode == ZetherTypes.RollOverMode.OWNER_ONLY) revert RollOverOwnerOnly(ua);
        _rollOver(ua);
    }

    function rollOverBatch(ZetherTypes.UA[] calldata uas) external nonReentrant {
        for (uint256 i; i < uas.length; ++i) {
            if (_acct[uas[i]].mode == ZetherTypes.RollOverMode.PUBLIC) _rollOver(uas[i]);
        }
    }

    function rollOverSigned(ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock, bytes calldata sig)
        external nonReentrant
    {
        if (block.number > validUntilBlock) revert RollOverExpired(validUntilBlock);
        Account storage a = _acct[ua];
        // `≥`, không `==`: credit đến sau khi ký (kể cả transfer v=0 miễn phí của kẻ grief) không được giết
        // rollOver của chủ. Phát lại vẫn chặn: digest ghim `accSeq`, mọi rollOver thật đều tăng nó. Chữ ký phải nêu
        // credit mới (> lastRolled): bản no-op không tăng `accSeq` nên sẽ sống tới credit sau, ai cũng ép rollOver được.
        if (a.pendingSeq < expectedPendingSeq || expectedPendingSeq <= a.lastRolledPendingSeq) {
            revert PendingSeqMismatch(expectedPendingSeq, a.pendingSeq);
        }
        bytes32 digest = keccak256(abi.encode(
            TAG_ROLLOVER, block.chainid, address(this), ua, a.accSeq, expectedPendingSeq, validUntilBlock
        ));
        IUniversalAccountRegistry(registry).requireAuthorized(ua, digest, sig, false);
        _rollOver(ua);
    }

    function setRollOverMode(ZetherTypes.UA ua, ZetherTypes.RollOverMode mode, uint64 validUntilBlock, bytes calldata sig)
        external nonReentrant
    {
        if (block.number > validUntilBlock) revert RollOverExpired(validUntilBlock);
        Account storage a = _acct[ua];
        bytes32 digest = keccak256(abi.encode(
            TAG_SET_MODE, block.chainid, address(this), ua, uint8(mode), a.modeNonce, validUntilBlock
        ));
        IUniversalAccountRegistry(registry).requireAuthorized(ua, digest, sig, false);
        a.mode = mode;
        a.modeNonce += 1;
        emit RollOverModeChanged(ua, mode);
    }

    /// @dev No-op im lặng khi không có credit mới (chặn DoS); không bao giờ gọi từ transfer/burn (QT1).
    function _rollOver(ZetherTypes.UA ua) private {
        Account storage a = _acct[ua];
        if (a.pendingSeq == a.lastRolledPendingSeq) return;
        a.accC = verifier.g1Add(_pt(a.accC), _pt(a.pendC));
        a.accD = verifier.g1Add(_pt(a.accD), _pt(a.pendD));
        delete a.pendC;
        delete a.pendD;
        a.accSeq += 1;
        a.lastRolledPendingSeq = a.pendingSeq;
        emit RolledOver(ua, a.accSeq);
    }

    // ------------------------------------------------------------------ transfer

    /// @notice Một người nhận, định dạng gốc (§5–§9), bundle lưu đầy đủ. Đường phong bì meta-tx dùng đúng hàm này.
    function transferConfidentialSingle(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary
    ) external nonReentrant returns (bytes32) {
        return _transferConfidential(payload, proof, authSig, beneficiary, bytes32(0), OuterFee(msg.sender, address(0), 0));
    }

    /// @notice `M` người nhận (mồi nhận 0), một proof; lưu `keccak256` của các bundle, bundle phát trong event.
    function transferConfidential(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary
    ) external nonReentrant returns (bytes32) {
        return _transferMulti(payload, proof, authSig, beneficiary, ZetherTypes.TransferMode.HASH);
    }

    /// @notice Như `transferConfidential`, lưu nguyên các bundle.
    function transferConfidentialBundle(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary
    ) external nonReentrant returns (bytes32) {
        return _transferMulti(payload, proof, authSig, beneficiary, ZetherTypes.TransferMode.BUNDLE);
    }

    /// @notice Như `transferConfidential`, không lưu gì: tiết lộ chỉ off-chain từ calldata.
    function transferConfidentialNoBundle(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary
    ) external nonReentrant returns (bytes32) {
        return _transferMulti(payload, proof, authSig, beneficiary, ZetherTypes.TransferMode.NONE);
    }

    function burn(
        bytes calldata payload,
        uint256 amount,
        address recipient,
        ZetherTypes.UA beneficiary,
        bytes calldata proof,
        bytes calldata authSig
    ) external nonReentrant {
        _burnShielded(payload, proof, authSig, BurnArgs(amount, recipient, beneficiary, bytes32(0)), OuterFee(msg.sender, address(0), 0));
    }

    function _transferConfidential(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        bytes32 binding,
        OuterFee memory f
    ) private returns (bytes32 entryRef) {
        _requireBalance(f.payer, f.amount);                                   // phí ngoài trước mọi thứ đắt
        Prepared memory pp = _prepareTransfer(payload, beneficiary, binding);  // kiểm rẻ + statement
        IUniversalAccountRegistry(registry).requireAuthorized(
            pp.from, keccak256(abi.encodePacked(AUTH_TAG, keccak256(pp.statement))), authSig, true
        );
        if (!verifier.verifyTransfer(pp.statement, proof)) revert ProofRejected();
        _chargeFee(f);
        // hiệu lực (§5): acc_f −= (C_deb + [fee]G, D_out); pend_t += (C_out, D_out); pend_ben += [fee]G
        uint256 p = _p;
        bytes calldata pts = payload[64:];
        ZetherTypes.UA to = ZetherTypes.toUA(pts[p:2 * p]);
        Account storage a = _acct[pp.from];
        bytes memory c = verifier.g1Sub(_pt(a.accC), pts[4 * p:5 * p]);
        if (pp.fee != 0) c = verifier.g1Sub(c, verifier.g1MulBase(pp.fee));
        a.accC = c;
        a.accD = verifier.g1Sub(_pt(a.accD), pts[3 * p:4 * p]);
        _credit(to, pts[2 * p:3 * p], pts[3 * p:4 * p]);
        if (pp.fee != 0) _credit(beneficiary, verifier.g1MulBase(pp.fee), "");
        entryRef = keccak256(abi.encode(TAG_ENTRY, block.chainid, address(this), pp.from, pp.sendCounter));
        a.sendCounter = pp.sendCounter + 1;
        _entries[entryRef] = bytes.concat(pts[p:2 * p], pts[2 * p:4 * p], pts[5 * p:6 * p]);
        emit ConfidentialTransfer(pp.from, to, beneficiary, pp.fee, pp.sendCounter, entryRef);
    }

    /// @dev Mọi thứ rẻ trước verify: độ dài, đăng ký, tự chuyển, `accSeq`, `sendCounter` (§5, §10).
    function _prepareTransfer(bytes calldata payload, ZetherTypes.UA beneficiary, bytes32 binding)
        private view returns (Prepared memory pp)
    {
        uint256 p = _p;
        if (payload.length != 64 + 6 * p) revert BadPayload(payload.length);
        bytes calldata pts = payload[64:];
        pp.from = ZetherTypes.toUA(pts[0:p]);
        ZetherTypes.UA to = ZetherTypes.toUA(pts[p:2 * p]);
        if (ZetherTypes.UA.unwrap(pp.from) == ZetherTypes.UA.unwrap(to)) revert SelfTransfer();
        _requireRegistered(pp.from);
        _requireRegistered(to);
        pp.fee = _innerFee(beneficiary);
        Account storage a = _acct[pp.from];
        pp.sendCounter = _checkSeqs(a, payload);
        pp.statement = bytes.concat(
            _header(OP_TRANSFER, _psid, binding, a, pp.fee, beneficiary, 0, address(0)),
            pts[0:2 * p], _auditorPoint(), _pt(a.accC), _pt(a.accD), pts[2 * p:6 * p]
        );
    }

    function _checkSeqs(Account storage a, bytes calldata payload) private view returns (uint64) {
        uint256 provedAccSeq = uint256(bytes32(payload[0:32]));
        uint256 provedSend = uint256(bytes32(payload[32:64]));
        if (provedAccSeq != a.accSeq) revert StaleAccSeq(a.accSeq, provedAccSeq);
        if (provedSend != a.sendCounter) revert StaleSendCounter(a.sendCounter, provedSend);
        return a.sendCounter;
    }

    function _innerFee(ZetherTypes.UA beneficiary) private view returns (uint256) {
        if (ZetherTypes.UA.unwrap(beneficiary) == bytes32(0)) return 0;
        _requireRegistered(beneficiary); // phí không được là cửa sau để "đăng ký hộ" (ZSC)
        return confidentialFee;
    }

    function _header(
        bytes32 op,
        bytes32 psid,
        bytes32 binding,
        Account storage a,
        uint256 fee,
        ZetherTypes.UA beneficiary,
        uint256 amount,
        address recipient
    ) private view returns (bytes memory) {
        return abi.encode(
            op, psid, block.chainid, address(this), binding == bytes32(0) ? TAG_DIRECT : TAG_RELAYED, binding,
            uint256(a.sendCounter), uint256(a.accSeq), fee, beneficiary, amount, recipient
        );
    }

    // ------------------------------------------------------------------ transfer nhiều người nhận

    /// @dev Như `_transferConfidential`, trực tiếp (phong bì meta-tx: stream MT-6). Payload
    ///      `be32(accSeq) ‖ be32(sendCounter) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j`.
    function _transferMulti(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode
    ) private returns (bytes32 entryRef) {
        (Prepared memory pp, ZetherTypes.UA[] memory to) = _prepareMulti(payload, beneficiary, mode);
        IUniversalAccountRegistry(registry).requireAuthorized(
            pp.from, keccak256(abi.encodePacked(AUTH_TAG, keccak256(pp.statement))), authSig, true
        );
        if (!verifier.verifyTransferMulti(pp.statement, proof)) revert ProofRejected();
        _applyMulti(pp, to, payload, beneficiary);
        entryRef = keccak256(abi.encode(TAG_ENTRY, block.chainid, address(this), pp.from, pp.sendCounter));
        _acct[pp.from].sendCounter = pp.sendCounter + 1;
        if (mode != ZetherTypes.TransferMode.NONE) _storeBundles(entryRef, payload, to.length, mode);
        emit ConfidentialTransferMulti(pp.from, beneficiary, pp.fee, pp.sendCounter, entryRef, to, mode);
    }

    /// @dev acc_f −= (C_deb + [fee]G, D_out); pend_tj += (C_out_j, D_out); pend_ben += [fee]G.
    function _applyMulti(Prepared memory pp, ZetherTypes.UA[] memory to, bytes calldata payload, ZetherTypes.UA beneficiary)
        private
    {
        uint256 p = _p;
        bytes calldata dOut = payload[96 + p:96 + 2 * p];
        Account storage a = _acct[pp.from];
        bytes memory c = verifier.g1Sub(_pt(a.accC), payload[96 + 2 * p:96 + 3 * p]);
        if (pp.fee != 0) c = verifier.g1Sub(c, verifier.g1MulBase(pp.fee));
        a.accC = c;
        a.accD = verifier.g1Sub(_pt(a.accD), dOut);
        for (uint256 j; j < to.length; ++j) {
            uint256 o = 96 + 3 * p * (j + 1);
            _credit(to[j], payload[o + p:o + 2 * p], dOut);
        }
        if (pp.fee != 0) _credit(beneficiary, verifier.g1MulBase(pp.fee), "");
    }

    function _storeBundles(bytes32 entryRef, bytes calldata payload, uint256 m, ZetherTypes.TransferMode mode) private {
        uint256 p = _p;
        bytes memory bundles = _bundles(payload[96 + 3 * p:], payload[96 + p:96 + 2 * p], m);
        if (mode == ZetherTypes.TransferMode.BUNDLE) {
            _entries[entryRef] = bundles;
        } else {
            _entries[entryRef] = abi.encodePacked(keccak256(bundles));
            emit TransferBundles(entryRef, bundles);
        }
    }

    /// @dev Kiểm rẻ trước verify: độ dài, số người nhận, đăng ký, trùng/tự chuyển, `accSeq`, `sendCounter`.
    function _prepareMulti(bytes calldata payload, ZetherTypes.UA beneficiary, ZetherTypes.TransferMode mode)
        private view returns (Prepared memory pp, ZetherTypes.UA[] memory to)
    {
        uint256 p = _p;
        if (payload.length < 96 + 3 * p) revert BadPayload(payload.length);
        uint256 m = uint256(bytes32(payload[64:96]));
        if (m == 0 || m > MAX_RECIPIENTS) revert BadRecipientCount(m);
        if (payload.length != 96 + 3 * p * (1 + m)) revert BadPayload(payload.length);
        pp.from = ZetherTypes.toUA(payload[96:96 + p]);
        _requireRegistered(pp.from);
        to = _recipients(payload, pp.from, m);
        pp.fee = _innerFee(beneficiary);
        Account storage a = _acct[pp.from];
        pp.sendCounter = _checkSeqs(a, payload);
        pp.statement = _multiStatement(payload, a, pp.fee, beneficiary, mode);
    }

    /// @dev UA của từng người nhận: khác người gửi, đôi một khác nhau, đã đăng ký.
    function _recipients(bytes calldata payload, ZetherTypes.UA from, uint256 m)
        private view returns (ZetherTypes.UA[] memory to)
    {
        uint256 p = _p;
        to = new ZetherTypes.UA[](m);
        for (uint256 j; j < m; ++j) {
            uint256 o = 96 + 3 * p * (j + 1);
            to[j] = ZetherTypes.toUA(payload[o:o + p]);
            bytes32 t = ZetherTypes.UA.unwrap(to[j]);
            if (t == ZetherTypes.UA.unwrap(from)) revert SelfTransfer();
            for (uint256 k; k < j; ++k) if (ZetherTypes.UA.unwrap(to[k]) == t) revert DuplicateRecipient(to[j]);
            _requireRegistered(to[j]);
        }
    }

    /// @dev `header ‖ Y_f ‖ Y_a ‖ C_acc ‖ D_acc ‖ D_out ‖ C_deb ‖ be32(M) ‖ legs`.
    function _multiStatement(
        bytes calldata payload,
        Account storage a,
        uint256 fee,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode
    ) private view returns (bytes memory) {
        uint256 p = _p;
        bytes32 op = mode == ZetherTypes.TransferMode.HASH
            ? OP_MULTI_HASH
            : mode == ZetherTypes.TransferMode.BUNDLE ? OP_MULTI_BUNDLE : OP_MULTI_NONE;
        bytes memory head = bytes.concat(
            _header(op, verifier.proofSystemIdMulti(), bytes32(0), a, fee, beneficiary, 0, address(0)),
            payload[96:96 + p], _auditorPoint(), _pt(a.accC), _pt(a.accD)
        );
        return bytes.concat(head, payload[96 + p:96 + 3 * p], payload[64:96], payload[96 + 3 * p:]);
    }

    /// @dev `B_1 ‖ … ‖ B_M`, `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j`.
    function _bundles(bytes calldata legs, bytes calldata dOut, uint256 m) private view returns (bytes memory b) {
        uint256 p = _p;
        for (uint256 j; j < m; ++j) {
            uint256 o = 3 * p * j;
            b = bytes.concat(b, legs[o:o + 2 * p], dOut, legs[o + 2 * p:o + 3 * p]);
        }
    }

    // ------------------------------------------------------------------ burn

    function _burnShielded(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        BurnArgs memory b,
        OuterFee memory f
    ) private {
        _requireBalance(f.payer, f.amount);
        Prepared memory pp = _prepareBurn(payload, b);
        IUniversalAccountRegistry(registry).requireAuthorized(
            pp.from, keccak256(abi.encodePacked(AUTH_TAG, keccak256(pp.statement))), authSig, true
        );
        if (!verifier.verifyBurn(pp.statement, proof)) revert ProofRejected();
        _chargeFee(f);
        Account storage a = _acct[pp.from];
        a.accC = verifier.g1Sub(_pt(a.accC), verifier.g1MulBase(b.amount + pp.fee));
        a.sendCounter = pp.sendCounter + 1;
        totalShielded -= b.amount;
        if (pp.fee != 0) _credit(b.beneficiary, verifier.g1MulBase(pp.fee), "");
        emit Burned(pp.from, b.amount, b.recipient);
        IERC20(underlying).safeTransfer(b.recipient, b.amount * shieldScale);
        _checkEscrow();
    }

    function _prepareBurn(bytes calldata payload, BurnArgs memory b) private view returns (Prepared memory pp) {
        uint256 p = _p;
        if (payload.length != 64 + p) revert BadPayload(payload.length);
        // amount + fee < 2^54 + 2^64 < r: không có bí danh mod r (review agy #5, RS-NV64-1)
        if (b.amount == 0 || b.amount > maxDecryptableShielded) {
            revert AmountOutOfRange(b.amount, maxDecryptableShielded);
        }
        if (b.recipient == address(0)) revert ZeroRecipient();
        pp.from = ZetherTypes.toUA(payload[64:64 + p]);
        _requireRegistered(pp.from);
        pp.fee = _innerFee(b.beneficiary);
        Account storage a = _acct[pp.from];
        pp.sendCounter = _checkSeqs(a, payload);
        pp.statement = bytes.concat(
            _header(OP_BURN, _psid, b.binding, a, pp.fee, b.beneficiary, b.amount, b.recipient),
            payload[64:64 + p], _pt(a.accC), _pt(a.accD)
        );
    }

    // ------------------------------------------------------------------ meta-tx (§10)

    function _executeOp(MetaTxLib.MetaTransaction calldata m, FeeMode feeMode, address feeRecipient)
        internal override returns (uint256 feeAmount)
    {
        if (m.data.length == 0) {
            // chuyển ERC-20 công khai: số tiền công khai ⇒ FeePolicy đầy đủ (kể cả PERCENT, trần 1%)
            feeAmount = FeePolicy.compute(feeMode, m.value, m.fee);
            _requireBalance(m.from, m.value + feeAmount);
            if (feeAmount != 0) _transfer(m.from, feeRecipient, feeAmount);
            _transfer(m.from, m.to, m.value);
            return feeAmount;
        }
        FeePolicy.requireConfidentialSafe(feeMode);
        if (m.to != address(0) || m.value != 0 || m.data.length < 4) revert ZetherOpNotCanonical();
        feeAmount = feeMode == FeeMode.FIXED ? m.fee : 0;
        OuterFee memory f = OuterFee(m.from, feeRecipient, feeAmount);
        bytes32 binding = _envelopeBinding(m);
        bytes4 op = bytes4(m.data[0:4]);
        if (op == OP_ZTRANSFER) {
            (bytes memory pl, bytes memory proof, bytes memory authSig, bytes32 ben) =
                abi.decode(m.data[4:], (bytes, bytes, bytes, bytes32));
            this.relayedTransfer(pl, proof, authSig, ZetherTypes.UA.wrap(ben), binding, f);
        } else if (op == OP_ZBURN) {
            this.relayedBurn(m.data[4:], binding, f);
        } else {
            revert ZetherOpNotCanonical();
        }
    }

    /// @notice Chỉ chính token gọi (từ `_executeOp`) — tồn tại để đổi `bytes memory` đã giải mã về calldata.
    /// @dev Không qua `nonReentrant` (khoá đang giữ bởi `executeMetaTransaction`); `msg.sender == this`.
    function relayedTransfer(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        bytes32 binding,
        OuterFee calldata f
    ) external {
        if (msg.sender != address(this)) revert ZetherOpNotCanonical();
        _transferConfidential(payload, proof, authSig, beneficiary, binding, f);
    }

    /// @notice Như `relayedTransfer`, cho `OP_ZBURN`; `args` = phần sau selector của `m.data`.
    function relayedBurn(bytes calldata args, bytes32 binding, OuterFee calldata f) external {
        if (msg.sender != address(this)) revert ZetherOpNotCanonical();
        (bytes memory pl, uint256 amount, address recipient, bytes32 ben, bytes memory proof, bytes memory authSig) =
            abi.decode(args, (bytes, uint256, address, bytes32, bytes, bytes));
        this.relayedBurnDecoded(pl, proof, authSig, BurnArgs(amount, recipient, ZetherTypes.UA.wrap(ben), binding), f);
    }

    function relayedBurnDecoded(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        BurnArgs calldata b,
        OuterFee calldata f
    ) external {
        if (msg.sender != address(this)) revert ZetherOpNotCanonical();
        _burnShielded(payload, proof, authSig, b, f);
    }

    function envelopeBinding(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32) {
        return _envelopeBinding(m);
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction calldata m) private view returns (bytes32) {
        (address r, address f) = MetaTxLib.canon(m);
        return keccak256(abi.encode(
            TAG_ENVELOPE, block.chainid, address(this), m.from, m.to, m.value, m.batch, m.nonce, m.validUntil,
            m.mode, r, m.fee, f
        ));
    }

    function transferStatementSingle(bytes calldata payload, ZetherTypes.UA beneficiary, bytes32 binding)
        external view returns (bytes memory)
    {
        return _prepareTransfer(payload, beneficiary, binding).statement;
    }

    function transferStatement(bytes calldata payload, ZetherTypes.UA beneficiary, ZetherTypes.TransferMode mode)
        external view returns (bytes memory)
    {
        (Prepared memory pp,) = _prepareMulti(payload, beneficiary, mode);
        return pp.statement;
    }

    function burnStatement(
        bytes calldata payload,
        uint256 amount,
        address recipient,
        ZetherTypes.UA beneficiary,
        bytes32 binding
    ) external view returns (bytes memory) {
        return _prepareBurn(payload, BurnArgs(amount, recipient, beneficiary, binding)).statement;
    }

    // ------------------------------------------------------------------ tiết lộ (§12, SRS §9.4)

    function verifyTransferAmount(
        bytes32 entryRef,
        uint256 index,
        uint256 amount,
        OpeningKind kind,
        bytes calldata opening,
        bytes calldata bundles
    ) public view returns (bool) {
        bytes memory ent = _bundle(entryRef, index, bundles);
        if (amount >= VALUE_BOUND) return false; // [amount]G chỉ phụ thuộc amount mod r
        uint256 p = _p;
        bytes memory yt = _cut(ent, 0, p);
        bytes memory cOut = _cut(ent, p, p);
        bytes memory dOut = _cut(ent, 2 * p, p);
        if (kind == OpeningKind.SENDER_S) {
            if (opening.length != 32) revert OpeningMalformed();
            uint256 s = abi.decode(opening, (uint256));
            if (s >= _r) return false;
            uint256[] memory sc = new uint256[](3);
            (sc[0], sc[1], sc[2]) = (amount, s, _r - 1);
            return keccak256(verifier.g1MulBase(s)) == keccak256(dOut)
                && _isO(verifier.g1Msm(bytes.concat(verifier.g1MulBase(1), yt, cOut), sc));
        }
        if (kind == OpeningKind.AUDITOR) {
            if (_auditorKey.length == 0) return false;
            return _chaumPedersen(entryRef, amount, kind, opening, bytes.concat(_auditorKey, _cut(ent, 3 * p, p), dOut));
        }
        return _chaumPedersen(entryRef, amount, kind, opening, bytes.concat(yt, cOut, dOut));
    }

    /// @dev `log_G(K) == log_{D_out}(M − [amount]G)`:
    ///      `[z]G − A1 − [e]K == O` và `[z]D_out − A2 − [e]M + [e·amount]G == O`.
    function _chaumPedersen(
        bytes32 entryRef,
        uint256 amount,
        OpeningKind kind,
        bytes calldata opening,
        bytes memory kmd // K ‖ M ‖ D_out
    ) private view returns (bool) {
        (bytes memory a1, bytes memory a2, uint256 z) = abi.decode(opening, (bytes, bytes, uint256));
        if (a1.length != _p || a2.length != _p || z >= _r) revert OpeningMalformed();
        uint256 e = _discloseChallenge(entryRef, amount, kind, bytes.concat(a1, a2));
        if (e == 0) return false;
        amount = mulmod(e, amount, _r); // từ đây: e·amount
        bytes memory g = verifier.g1MulBase(1);
        if (!_cpEq(bytes.concat(g, a1, _cut(kmd, 0, _p)), z, e, 0)) return false;
        return _cpEq(bytes.concat(_cut(kmd, 2 * _p, _p), a2, _cut(kmd, _p, _p), g), z, e, amount);
    }

    /// @dev `[z]P0 − P1 − [e]P2 (+ [extra]P3) == O`.
    function _cpEq(bytes memory pts, uint256 z, uint256 e, uint256 extra) private view returns (bool) {
        uint256 n = pts.length / _p;
        uint256[] memory sc = new uint256[](n);
        (sc[0], sc[1], sc[2]) = (z, _r - 1, _r - e);
        if (n == 4) sc[3] = extra;
        return _isO(verifier.g1Msm(pts, sc));
    }

    function _discloseChallenge(bytes32 entryRef, uint256 amount, OpeningKind kind, bytes memory a1a2)
        private view returns (uint256)
    {
        return ZetherTranscript.hashToScalar(keccak256(abi.encodePacked(
            DISCLOSE_TAG, block.chainid, address(this), entryRef, amount, uint8(kind), a1a2
        )), _r);
    }

    function attestTransferAmount(
        bytes32 entryRef,
        uint256 index,
        uint256 amount,
        OpeningKind kind,
        bytes calldata opening,
        bytes calldata bundles
    ) external returns (bool) {
        if (!verifyTransferAmount(entryRef, index, amount, kind, opening, bundles)) revert OpeningMalformed();
        emit AmountAttested(entryRef, index, amount, kind, msg.sender, block.timestamp);
        return true;
    }

    function transferCiphertext(bytes32 entryRef, uint256 index, bytes calldata bundles)
        external view returns (bytes memory encodedCiphertext, bytes memory encodedYTo)
    {
        bytes memory ent = _bundle(entryRef, index, bundles);
        uint256 p = _p;
        return (_cut(ent, p, 3 * p), _cut(ent, 0, p));
    }

    /// @dev `B_index` của `entryRef`: từ storage, hoặc (mode HASH) từ `bundles` sau khi khớp hash. Không có gì
    ///      lưu (mode NONE, ref lạ) ⇒ `UnknownEntry`. Transfer một người nhận: chỉ `index = 0`.
    function _bundle(bytes32 entryRef, uint256 index, bytes calldata bundles) private view returns (bytes memory) {
        bytes memory all = _entries[entryRef];
        if (all.length == 0) revert UnknownEntry(entryRef);
        if (all.length == 32) {
            if (keccak256(bundles) != bytes32(all)) revert BundlesMismatch(entryRef);
            all = bundles;
        }
        uint256 len = 4 * _p;
        if ((index + 1) * len > all.length) revert BadRecipientIndex(index);
        return _cut(all, index * len, len);
    }

    // ------------------------------------------------------------------ tiện ích

    function _requireRegistered(ZetherTypes.UA ua) private view {
        if (!registered(ua)) revert AccountNotRegistered(ua);
    }

    function _credit(ZetherTypes.UA ua, bytes memory c, bytes memory d) private {
        Account storage a = _acct[ua];
        a.pendC = verifier.g1Add(_pt(a.pendC), c);
        if (d.length != 0) a.pendD = verifier.g1Add(_pt(a.pendD), d);
        a.pendingSeq += 1;
    }

    function _chargeFee(OuterFee memory f) private {
        if (f.amount != 0) _transfer(f.payer, f.recipient, f.amount);
    }

    function _checkEscrow() private view {
        uint256 held = IERC20(underlying).balanceOf(address(this));
        uint256 owed = totalSupply() + totalShielded * shieldScale;
        if (held < owed) revert EscrowInvariant(held, owed);
    }

    function _auditorPoint() private view returns (bytes memory) {
        return _auditorKey.length == 0 ? new bytes(_p) : _auditorKey;
    }

    /// @dev Điểm đã lưu, hoặc `O` nếu chưa từng ghi.
    function _pt(bytes storage s) private view returns (bytes memory) {
        return s.length == 0 ? new bytes(_p) : s;
    }

    function _isO(bytes memory a) private pure returns (bool) {
        return keccak256(a) == keccak256(new bytes(a.length));
    }

    function _cut(bytes memory a, uint256 off, uint256 len) private pure returns (bytes memory out) {
        out = new bytes(len);
        assembly ("memory-safe") {
            let d := add(out, 32)
            let s := add(add(a, 32), off)
            for { let i := 0 } lt(i, len) { i := add(i, 32) } { mstore(add(d, i), mload(add(s, i))) }
        }
    }
}
