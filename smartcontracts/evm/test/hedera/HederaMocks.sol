// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

/// @notice Giả precompile HIP-632 (đặt ở 0x16a bằng `vm.etch`), theo đúng nhánh của `IsAuthorizedRawCall.java`:
///         64 byte = "ED", 65–72 byte = "EC", khác ⇒ revert; ED cần tài khoản có khoá ED đơn đã đăng ký và
///         `messageHash` 32 byte, không thì REVERT (như mạng thật — không phải `false`); EC từ chối long-zero.
///         forge 1.3.5 không có cheatcode ed25519, nên "khoá ED" của một tài khoản ở đây là một khoá secp256k1 và
///         "chữ ký ED 64 byte" là chữ ký compact EIP-2098 trên đúng 32 byte — mock kiểm mạch gọi (đúng tài khoản,
///         đúng digest, đúng chữ ký, xử lý revert), còn toán ed25519 thật được Python và Rust kiểm trên
///         `test/vectors/hedera_kat.json`.
///         Như mạng thật, gọi bằng STATICCALL thì HALT (`allowsStaticFrame() == false`): mock ghi một bộ đếm.
contract MockHederaAccountService {
    mapping(address account => address edKey) public edKey;
    uint256 public calls;
    mapping(address account => bool) public complexKey;

    function setEdKey(address account, address key) external { edKey[account] = key; }
    function setComplexKey(address account) external { complexKey[account] = true; }

    function isAuthorizedRaw(address account, bytes calldata messageHash, bytes calldata sig)
        external returns (bool)
    {
        calls += 1; // SSTORE: halts in a static frame, like the real system contract
        if (sig.length == 64) {
            if (edKey[account] == address(0) && !complexKey[account]) revert("INVALID_ACCOUNT_ID");
            if (complexKey[account]) revert("INVALID_TRANSACTION_BODY");
            require(messageHash.length == 32, "INVALID_TRANSACTION_BODY");
            bytes32 r = bytes32(sig[:32]);
            bytes32 vs = bytes32(sig[32:]);
            bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            uint8 v = uint8(uint256(vs) >> 255) + 27;
            return ecrecover(bytes32(messageHash), v, r, s) == edKey[account];
        }
        if (sig.length >= 65 && sig.length <= 72) {
            if (uint160(account) >> 64 == 0) revert("INVALID_ACCOUNT_ID"); // long-zero
            require(messageHash.length == 32, "INVALID_TRANSACTION_BODY");
            return ecrecover(bytes32(messageHash), uint8(sig[64]), bytes32(sig[:32]), bytes32(sig[32:64])) == account;
        }
        revert("INVALID_TRANSACTION_BODY");
    }
}

/// @notice Giả HTS 0x167: `associateToken` trả SUCCESS (22) lần đầu, TOKEN_ALREADY_ASSOCIATED (194) sau đó,
///         hoặc mã `forced` nếu đặt.
contract MockHts {
    mapping(address => mapping(address => bool)) public associated;
    int64 public forced;

    function force(int64 rc) external { forced = rc; }

    function associateToken(address account, address token) external returns (int64) {
        if (forced != 0) return forced;
        if (associated[account][token]) return 194;
        require(msg.sender == account, "SPENDER_DOES_NOT_HAVE_ALLOWANCE");
        associated[account][token] = true;
        return 22;
    }

    // ---- v2 (TW2 §11): `isToken` + `getTokenCustomFees`, cấu hình được để thử từng nhánh fail-closed.

    struct FixedFee { int64 amount; address tokenId; bool useHbarsForPayment; bool useCurrentTokenForPayment; address feeCollector; }
    struct FractionalFee { int64 numerator; int64 denominator; int64 minimumAmount; int64 maximumAmount; bool netOfTransfers; address feeCollector; }
    struct RoyaltyFee { int64 numerator; int64 denominator; int64 amount; address tokenId; bool useHbarsForPayment; address feeCollector; }

    enum Fees { None, Fixed, Fractional, Royalty, Malformed }

    mapping(address => bool) public hts;
    mapping(address => int64) public isTokenRc;
    mapping(address => int64) public feesRc;
    mapping(address => Fees) public fees;

    function setHts(address t, bool on) external { hts[t] = on; }
    function setIsTokenRc(address t, int64 rc) external { isTokenRc[t] = rc; }
    function setFeesRc(address t, int64 rc) external { feesRc[t] = rc; }
    function setFees(address t, Fees f) external { fees[t] = f; }

    function isToken(address t) external view returns (int64, bool) {
        return (isTokenRc[t] == 0 ? int64(22) : isTokenRc[t], hts[t]);
    }

    function getTokenCustomFees(address t)
        external view returns (int64, FixedFee[] memory f, FractionalFee[] memory fr, RoyaltyFee[] memory r)
    {
        Fees k = fees[t];
        if (k == Fees.Malformed) {
            assembly { mstore(0, 22) return(0, 64) }
        }
        if (k == Fees.Fixed) f = new FixedFee[](1);
        if (k == Fees.Fractional) fr = new FractionalFee[](1);
        if (k == Fees.Royalty) r = new RoyaltyFee[](1);
        return (feesRc[t] == 0 ? int64(22) : feesRc[t], f, fr, r);
    }
}
