// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/common/IOpenFactory.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {HederaMetaToken} from "../../src/hedera/HederaMetaToken.sol";

/// Smoke test on the REAL Hedera EVM without an account or HBAR: the constructor is run as initcode through
/// `eth_call` on the public testnet relay (mirror-node web3 runs the services EVM and system contracts).
/// Driver: `python3 script/hedera/testnet_smoke.py` (after `forge build`). Result 2026-10-03 recorded in
/// docs/superpowers/specs/2026-10-03-net-hedera.md §9.
contract HederaSmoke {
    constructor(address ecdsaFrom, bytes memory ecdsaSig, address edAccount, bytes memory edSig) {
        OpenFactory f = new OpenFactory(address(this));
        HederaMetaToken impl = new HederaMetaToken(address(f));
        f.registerImplementation(IOpenFactory.TokenKind.META, 1, address(impl));
        HederaMetaToken t = HederaMetaToken(f.createMetaToken(1, address(0),
            abi.encode("Smoke", "SMK", uint8(6), uint256(1e12), address(0)), bytes32("smoke")));
        t.transfer(ecdsaFrom, 1000);
        t.transfer(edAccount, 1000);
        MetaTxLib.MetaTransaction memory m1 = _m(ecdsaFrom, 1);
        bytes32 d1 = t.metaTxDigest(m1);
        bytes memory out;
        if (ecdsaSig.length == 0) {
            out = abi.encode(address(t), d1, block.chainid);
        } else {
            bytes memory e1 = _try(t, m1, ecdsaSig);
            uint256 shop = t.balanceOf(address(0x5409));
            bytes memory e2 = _try(t, _m(edAccount, 2), edSig);                    // bad ED sig, real 0x16a
            bytes memory e3 = _try(t, _m(address(uint160(0xffffff01)), 3), edSig);  // unknown account
            uint256 eoaCode = ecdsaFrom.code.length + edAccount.code.length;
            // R6-6: 0x16a answers a CALL but halts in a static frame.
            bytes memory q = abi.encodeWithSelector(0xb2a31da4, edAccount, abi.encodePacked(d1), edSig);
            (bool callOk, bytes memory callRet) = address(0x16a).call(q);
            (bool staticOk,) = address(0x16a).staticcall{gas: 100_000}(q); // a halt burns what it is given
            out = abi.encode(e1, shop, e2, e3, eoaCode, callOk && callRet.length == 32, staticOk);
        }
        assembly { return(add(out, 32), mload(out)) }
    }

    function _m(address from, uint256 batch) private pure returns (MetaTxLib.MetaTransaction memory) {
        return MetaTxLib.MetaTransaction({from: from, to: address(0x5409), value: 100,
            data: abi.encodeWithSelector(bytes4(keccak256("pay(bytes32)")), bytes32(batch)), batch: batch, nonce: 0,
            validUntil: 4102444800, mode: 0, relayer: address(0), fee: 0, feeRecipient: address(0)});
    }

    function _try(HederaMetaToken t, MetaTxLib.MetaTransaction memory m, bytes memory sig) private returns (bytes memory) {
        try t.executeMetaTransaction(m, sig) returns (bool) { return "ok"; } catch (bytes memory e) { return e; }
    }
}
