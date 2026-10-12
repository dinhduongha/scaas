// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// CTR-MTX-15: the generic `MetaTransaction` and its pinned typehash; canonical zeroing; `data` hashed.
contract MetaTxLibTest is Test {
    using MetaTxLib for MetaTxLib.MetaTransaction;
    using MetaTxLib for MetaTxLib.UAMetaTransaction;
    using MetaTxLib for MetaTxLib.UAMetaTransfer;

    function _m(uint32 mode) internal pure returns (MetaTxLib.MetaTransaction memory) {
        return MetaTxLib.MetaTransaction({
            from: address(0xA), data: hex"cfdd7aea0000000000000000000000000000000000000000000000000000000000000007",
            batch: 1, nonce: 2, validUntil: 3, mode: mode, relayer: address(0xB), fee: 4, feeRecipient: address(0xC)
        });
    }

    function test_metaTxTypehashIsPinned() public pure {
        assertEq(
            MetaTxLib.METATX_TYPEHASH,
            keccak256(
                "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
            )
        );
        assertEq(MetaTxLib.METATX_TYPEHASH, 0xd22ba5c345e95dfd17f7410a3bebe235f90d2f4e7c3f571b493aa2c8c07dc888);
    }

    function test_hashStruct_encoding() public pure {
        MetaTxLib.MetaTransaction memory m = _m(MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT);
        assertEq(m.hashStruct(), keccak256(abi.encode(
            MetaTxLib.METATX_TYPEHASH, m.from, keccak256(m.data), m.batch, m.nonce, m.validUntil, m.mode,
            m.relayer, m.fee, m.feeRecipient)));
    }

    function test_unboundFieldsAreHashedAsZero() public pure {
        MetaTxLib.MetaTransaction memory a = _m(MetaTxLib.MODE_OPEN);
        MetaTxLib.MetaTransaction memory b = _m(MetaTxLib.MODE_OPEN);
        b.relayer = address(0xDEAD);
        b.feeRecipient = address(0xBEEF);
        assertEq(a.hashStruct(), b.hashStruct());
        a.mode = MetaTxLib.MODE_RESTRICT_RELAYER;
        b.mode = MetaTxLib.MODE_RESTRICT_RELAYER;
        assertTrue(a.hashStruct() != b.hashStruct());
    }

    function _h(uint32 mode, address relayer, address feeRecipient) internal pure returns (bytes32) {
        MetaTxLib.MetaTransaction memory m = _m(mode);
        m.relayer = relayer;
        m.feeRecipient = feeRecipient;
        return m.hashStruct();
    }

    function test_onlyFeeRecipientFlag_bindsFeeRecipientNotRelayer() public pure {
        uint32 f = MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
        assertTrue(_h(f, address(1), address(3)) != _h(f, address(1), address(4)));
        assertEq(_h(f, address(1), address(3)), _h(f, address(2), address(3)));
    }

    function test_onlyRelayerFlag_bindsRelayerNotFeeRecipient() public pure {
        uint32 f = MetaTxLib.MODE_RESTRICT_RELAYER;
        assertTrue(_h(f, address(1), address(3)) != _h(f, address(2), address(3)));
        assertEq(_h(f, address(1), address(3)), _h(f, address(1), address(4)));
    }

    function test_bothFlags_bindBoth() public pure {
        uint32 f = MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
        assertTrue(_h(f, address(1), address(3)) != _h(f, address(2), address(3)));
        assertTrue(_h(f, address(1), address(3)) != _h(f, address(1), address(4)));
    }

    function test_metaTransferTypehashIsPinned() public pure {
        assertEq(
            MetaTxLib.METATRANSFER_TYPEHASH,
            0xe76cb6dc9ab3eb734c6dc32ec8732764c97cf48f22aed55d73690e01d518086e
        );
        assertEq(
            MetaTxLib.METATRANSFER_TYPEHASH,
            keccak256("MetaTransfer(address from,address to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)")
        );
    }

    /// accounts.md CTR-UA-19/26: the UA ledger's two structs (ids as `bytes32`), pinned like their address siblings.
    function test_uaTypehashesArePinned() public pure {
        assertEq(MetaTxLib.UAMETATX_TYPEHASH, 0xd9c5f787db2511a7b745f9724e79bd1dc2549a3281be59336a079e9951c2b859);
        assertEq(
            MetaTxLib.UAMETATX_TYPEHASH,
            keccak256("UAMetaTransaction(bytes32 from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)")
        );
        assertEq(MetaTxLib.UAMETATRANSFER_TYPEHASH, 0xae67b40deb42316e170d67070edffa306de0ded5295d209b1118e70cb47f250e);
        assertEq(
            MetaTxLib.UAMETATRANSFER_TYPEHASH,
            keccak256("UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)")
        );
    }

    /// CTR-UA-18: the pool address; a native id is the address zero-padded.
    function test_uaPoolAndPad() public pure {
        assertEq(MetaTxLib.UA_POOL, 0x41a67Ed99B9DC0332Eecb4D680667CCfc17A5c56);
        assertEq(MetaTxLib.UA_POOL, address(uint160(uint256(keccak256("scaas.ua.pool.v1")))));
        assertEq(MetaTxLib.pad(address(0xBEEF)), bytes32(uint256(0xBEEF)));
    }

    /// The UA structs hash like their address siblings: `data` hashed, `relayer`/`feeRecipient` zero unless bound.
    function test_uaHashStruct_encodingAndZeroing() public pure {
        MetaTxLib.UAMetaTransaction memory m = MetaTxLib.UAMetaTransaction({
            from: keccak256("ua"), data: hex"01020304", batch: 1, nonce: 2, validUntil: 3,
            mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: address(0xB), fee: 4, feeRecipient: address(0xC)
        });
        assertEq(m.hashStruct(), keccak256(abi.encode(MetaTxLib.UAMETATX_TYPEHASH, m.from, keccak256(m.data), m.batch,
            m.nonce, m.validUntil, m.mode, address(0xB), m.fee, address(0))));
        MetaTxLib.UAMetaTransfer memory t = MetaTxLib.UAMetaTransfer({
            from: keccak256("ua"), to: MetaTxLib.pad(address(0xD)), value: 5, entryRef: bytes32(uint256(6)), batch: 1,
            nonce: 2, validUntil: 3, mode: MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT, relayer: address(0xB), fee: 4,
            feeRecipient: address(0xC)
        });
        assertEq(t.hashStruct(), keccak256(abi.encode(MetaTxLib.UAMETATRANSFER_TYPEHASH, t.from, t.to, t.value,
            t.entryRef, t.batch, t.nonce, t.validUntil, t.mode, address(0), t.fee, address(0xC))));
    }
}
