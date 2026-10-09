// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// CTR-MTX-15: the generic `MetaTransaction` and its pinned typehash; canonical zeroing; `data` hashed.
contract MetaTxLibTest is Test {
    using MetaTxLib for MetaTxLib.MetaTransaction;

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
}
