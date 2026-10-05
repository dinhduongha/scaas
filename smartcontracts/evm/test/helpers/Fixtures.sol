// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/common/IOpenFactory.sol";
import {MetaToken} from "../../src/metatx/MetaToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

abstract contract Fixtures is Test {
    OpenFactory internal factory;
    MetaToken internal impl;
    address internal registrar = address(0xF00D);
    address internal relayer = address(0xBEEF);
    /// SubjectAccount implementation whose clones get the 400k ERC-1271 allowance (0 = none).
    address internal subjectImpl;

    function _deployFactory() internal {
        factory = new OpenFactory(registrar);
        impl = new MetaToken(address(factory), subjectImpl);
        vm.prank(registrar);
        factory.registerImplementation(IOpenFactory.TokenKind.META, 1, address(impl));
    }

    function _standalone(address creator, string memory sym, uint8 dec, uint256 supply, address minter)
        internal returns (MetaToken t)
    {
        bytes memory init = abi.encode(string.concat("Token ", sym), sym, dec, supply, minter);
        vm.prank(creator);
        t = MetaToken(factory.createMetaToken(1, address(0), init, keccak256(bytes(sym))));
    }

    function _wrapper(address creator, address underlying, string memory sym) internal returns (MetaToken t) {
        bytes memory init = abi.encode(string.concat("Wrapped ", sym), sym, uint8(0), uint256(0), address(0));
        vm.prank(creator);
        t = MetaToken(factory.createMetaToken(1, underlying, init, keccak256(bytes(sym))));
    }

    function _mt(address from, address to, uint256 value, bytes memory data, uint256 batch, uint32 mode)
        internal view returns (MetaTxLib.MetaTransaction memory m)
    {
        m = MetaTxLib.MetaTransaction({
            from: from, to: to, value: value, data: data, batch: batch, nonce: 0,
            validUntil: block.timestamp + 300, mode: mode, relayer: relayer,
            fee: 0, feeRecipient: address(0)
        });
    }

    function _sign(uint256 pk, MetaToken t, MetaTxLib.MetaTransaction memory m)
        internal view returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, t.metaTxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function _payData(bytes32 ref) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(bytes4(keccak256("pay(bytes32)")), ref);
    }

    function _tradeData(address counterToken, uint256 minCounter, address counterparty)
        internal pure returns (bytes memory)
    {
        return abi.encodeWithSelector(
            bytes4(keccak256("trade(address,uint256,address)")), counterToken, minCounter, counterparty);
    }
}
