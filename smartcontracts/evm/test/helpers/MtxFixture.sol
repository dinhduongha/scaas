// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MtxRegistryMock} from "./MtxRegistryMock.sol";

/// Shared setup of the `MetaTxBase` tests: chain 7622 with its real `chain_uid` (chain-uids.json, scaas-testnet).
abstract contract MtxFixture is Test {
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint256 internal constant ALICE_PK = 0xA11CE;
    uint256 internal constant BOB_PK = 0xB0B;
    address internal alice = vm.addr(ALICE_PK);
    address internal bob = vm.addr(BOB_PK);
    address internal relayer = address(0xBEEF);
    MtxRegistryMock internal reg;

    function setUp() public virtual {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        reg = new MtxRegistryMock("SCaaS TestRegistry", UID);
    }

    function _m(address from, bytes memory data, uint256 batch, uint256 nonce)
        internal view returns (MetaTxLib.MetaTransaction memory)
    {
        return MetaTxLib.MetaTransaction({
            from: from, data: data, batch: batch, nonce: nonce, validUntil: block.timestamp + 300,
            mode: MetaTxLib.MODE_OPEN, relayer: address(0), fee: 0, feeRecipient: address(0)
        });
    }

    function _sign(uint256 pk, MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, reg.mtxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function _setName(string memory n) internal pure returns (bytes memory) {
        return abi.encodeCall(MtxRegistryMock.setName, (n));
    }
}
