// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {UAMetaTxBase} from "../../src/metatx/UAMetaTxBase.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MockHederaAccountService, MockHts} from "../hedera/HederaMocks.sol";
import {nid} from "../helpers/Ids.sol";

/// Plan T28 (regulated-kinds spec §6.1: kinds 8 and 9 on Hedera, `IS_HEDERA`): the same releases on a Hedera env (chain
/// 296, the account service and HTS stand-ins of `HederaV2.t.sol`): `FREEZE` and `PAUSE` hold on a native Hedera account's
/// HIP-632 transfer and on the direct path; each refusal after its control.
contract RegulatedHederaTest is RegFixture {
    address constant HAS = address(0x16a);
    address constant HTS = address(0x167);
    uint256 constant HED_KEY = 0xA11CE5;
    address hed = address(uint160(1_234_567)); // 0.0.1234567, an ED25519 key (simulated)

    function _hedera() internal pure override returns (bool) { return true; }

    function setUp() public override {
        vm.chainId(296);
        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        vm.etch(HTS, type(MockHts).runtimeCode);
        MockHederaAccountService(HAS).setEdKey(hed, vm.addr(HED_KEY));
        super.setUp();
        for (uint256 i; i < 2; ++i) {
            vm.prank(alice);
            IERC20(_ks()[i]).transfer(hed, 1_000);
        }
    }

    /// A HIP-632 (64-byte ed25519) `UAMetaTransfer` of `hed` on lane `batch`.
    function _hip632(address t, uint256 batch)
        internal view returns (MetaTxLib.UAMetaTransfer memory x, IUARegistry.UASig memory s)
    {
        (x.from, x.to, x.value, x.batch, x.validUntil) = (nid(hed), nid(bob), 10, batch, block.timestamp + 300);
        (bytes32 r, bytes32 vs) = vm.signCompact(HED_KEY, MetaTokenBase(t).mtxTransferDigest(x));
        s.signature = abi.encodePacked(r, vs);
    }

    function test_hederaFreeze_8And9() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            assertTrue(UAMetaTxBase(t).IS_HEDERA());
            (MetaTxLib.UAMetaTransfer memory x, IUARegistry.UASig memory s) = _hip632(t, 1);
            vm.prank(relayer);
            MetaTokenBase(t).mtxExecuteTransfer(x, s); // the control
            assertEq(IERC20(t).balanceOf(bob), 10);
            _freeze(t, nid(hed));
            (x, s) = _hip632(t, 2);
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, nid(hed)));
            MetaTokenBase(t).mtxExecuteTransfer(x, s);
            vm.prank(hed);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, nid(hed)));
            IERC20(t).transfer(bob, 1);
            _unfreeze(t, nid(hed));
            vm.prank(relayer);
            MetaTokenBase(t).mtxExecuteTransfer(x, s);
            assertEq(IERC20(t).balanceOf(bob), 20);
        }
    }

    function test_hederaPause_8And9() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            uint64 until = _now() + 1 days;
            _pause(t, until);
            (MetaTxLib.UAMetaTransfer memory x, IUARegistry.UASig memory s) = _hip632(t, 1);
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.TokenPaused.selector, until));
            MetaTokenBase(t).mtxExecuteTransfer(x, s);
            vm.prank(hed);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.TokenPaused.selector, until));
            IERC20(t).transfer(bob, 1);
            vm.prank(issuer);
            _r(t).unpause(REF);
            vm.prank(relayer);
            MetaTokenBase(t).mtxExecuteTransfer(x, s);
            assertEq(IERC20(t).balanceOf(bob), 10);
        }
    }
}
