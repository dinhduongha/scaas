//! ABI — chép chữ ký từ `smartcontracts/src`, không suy luận. Sai một `indexed` là sai topic.
use alloy::sol;
use alloy::sol_types::SolInterface;

sol! {
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct MetaTransaction {
        address from; address to; uint256 value; bytes data;
        uint256 batch; uint256 nonce; uint256 validUntil; uint32 mode;
        address relayer; uint256 fee; address feeRecipient;
    }

    #[derive(Debug)]
    interface IMetaToken {
        function executeMetaTransaction(MetaTransaction m, bytes signature) external returns (bool);
        function metaTxDigest(MetaTransaction m) external view returns (bytes32);
        function metaNonce(address from, uint256 batch) external view returns (uint256);
        function balanceOf(address who) external view returns (uint256);
        function transfer(address to, uint256 value) external returns (bool);
        event MetaTransactionExecuted(address indexed from, address indexed relayer, uint256 indexed batch,
            uint256 nonce, bytes32 digest, address feeRecipient, uint256 fee);
        event PaymentSettled(address indexed from, address indexed to, uint256 amount, uint256 feeAmount,
            address feeRecipient, bytes32 indexed entryRef);
        error MetaTxExpired(uint256 validUntil, uint256 nowTs);
        error MetaTxBadNonce(uint256 expected, uint256 got);
        error MetaTxBadSignature();
        error MetaTxUnauthorizedRelayer(address allowed, address caller);
        error MetaTxUnknownMode(uint32 mode);
        error MetaTxInsufficientForFee(uint256 needed, uint256 available);
        error MetaTxUnknownOp(bytes4 op);
        error PayToZero();
        error TradeLegNotRestricted();
        error FeeExceedsCap(uint256 feeAmount, uint256 cap);
        error FeeRecipientRequired();
        error ModeFeeInvalid(uint32 mode);
        error ModeUnknownBits(uint32 mode);
    }

    #[derive(Debug)]
    struct Leg { address token; MetaTransaction m; bytes sig; }

    #[derive(Debug)]
    interface IMetaTxDex {
        function settle(Leg a, Leg b) external;
        event TradeSettled(address indexed partyA, address indexed partyB, address tokenA, address tokenB,
            uint256 valueA, uint256 valueB);
        error NotATradeLeg();
        error SameToken();
        error SameParty();
        error CounterTokenMismatch();
        error PriceNotMet(uint256 got, uint256 min);
        error CounterpartyMismatch();
        error LegNotRoutedHere();
        error FeeWouldStick();
        error DeltaMismatch(address token, uint256 got, uint256 expected);
    }

    #[derive(Debug)]
    interface IOpenFactory {
        function createMetaToken(uint64 version, address underlying, bytes initData, bytes32 salt)
            external returns (address token);
    }
}

/// Tên lỗi đọc được cho `last_error` ở Odoo; hex thô nếu không nhận ra.
pub fn decode_revert(data: &[u8]) -> String {
    if let Ok(e) = IMetaToken::IMetaTokenErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    if let Ok(e) = IMetaTxDex::IMetaTxDexErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    format!("revert 0x{}", alloy::hex::encode(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    use alloy::sol_types::SolError;

    #[test]
    fn known_errors_are_named() {
        let e = IMetaToken::MetaTxBadNonce { expected: U256::from(1), got: U256::ZERO }.abi_encode();
        assert!(decode_revert(&e).contains("MetaTxBadNonce"));
        let e = IMetaTxDex::FeeWouldStick {}.abi_encode();
        assert!(decode_revert(&e).contains("FeeWouldStick"));
        assert!(decode_revert(&[1, 2, 3]).starts_with("revert 0x"));
    }
}
