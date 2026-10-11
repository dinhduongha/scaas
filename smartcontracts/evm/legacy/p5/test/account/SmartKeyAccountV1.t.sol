// SPDX-License-Identifier: Apache-2.0
// legacy/p5 — reference only, not built: cut from `test/account/SmartKeyAccount.t.sol` when the v1 line left the build (P5).
pragma solidity ^0.8.20;

// The test ran inside `SmartKeyAccountTest` (fixtures `fac`, `acct`, `shop`, `relayer`, `RR`, `PASSKEY`, `_pk`).
import {OpenFactoryV1} from "../src/factory/OpenFactoryV1.sol";
import {IOpenFactoryV1} from "../src/common/IOpenFactoryV1.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";

abstract contract SmartKeyAccountV1Test {
    /// v1 `MetaToken` (deployed with the new `IMPLEMENTATION` until P5 retires it) pays from a clone with a passkey,
    /// also without the precompile, where only the clones' 400k ERC-1271 allowance fits the Solidity verifier.
    function test_v1MetaTokenPaysFromCloneWithPasskey() public {
        OpenFactoryV1 f1 = new OpenFactoryV1(address(0xF00D));
        MetaToken impl1 = new MetaToken(address(f1), fac.IMPLEMENTATION());
        vm.prank(address(0xF00D));
        f1.registerImplementation(IOpenFactoryV1.TokenKind.META, 1, address(impl1));
        MetaToken t1 = MetaToken(f1.createMetaToken(1, address(0),
            abi.encode("Token V", "V", uint8(0), uint256(1000), address(this)), keccak256("V")));
        t1.transfer(address(acct), 1000);
        vm.mockCallRevert(address(0x100), bytes(""), bytes(""));
        for (uint256 i; i < 2; ++i) {
            bytes32 ref = bytes32(i + 1);
            MetaTxLib.LegacyMetaTransaction memory m = MetaTxLib.LegacyMetaTransaction({
                from: address(acct), to: shop, value: 400, data: abi.encodeWithSignature("pay(bytes32)", ref),
                batch: i, nonce: 0, validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0,
                feeRecipient: address(0)});
            bytes memory sig = _pk(0, PASSKEY, t1.metaTxDigest(m));
            vm.prank(relayer);
            t1.executeMetaTransaction(m, sig);
            if (i == 0) vm.clearMockedCalls();          // the second with the precompile
        }
        assertEq(t1.balanceOf(shop), 800);
    }
}
