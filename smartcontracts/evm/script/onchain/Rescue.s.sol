// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OnchainBase} from "./OnchainBase.sol";
import {RescueVault} from "../../src/governance/RescueVault.sol";
import {RescueLib} from "../../src/governance/RescueLib.sol";
import {IRescuable} from "../../src/governance/IRescuable.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {MockERC20} from "../../test/helpers/Mocks.sol";

/// @notice Group `rescue` (CTR-GOV-25, spec 2026-11-12-rescue-vault.md), local only, after `rescue.sh`: the vault at
///         `RescueLib.SCAAS_DEV_RESCUE` (deployed from the committed `rescue-vault-init.hex` by `DeployRescueVault.s.sol`),
///         its admin set to key 1's native id and its rescuer to key 2 by `anvil_setStorageAt` (test keys only; never the
///         real admin's). `withdraw` of an ERC-20 and of the native coin on both branches (the rescuer with `to` != 0 pays
///         `to`; anyone else, the admin, or `to` == 0 pays the rescuer); `setRescuer` and `rotateAdmin` by the admin's
///         EIP-712 signature, each submitted by another key; the refusals listed for `coverage.py neg`. CTR-GOV-26: a stray
///         balance on the chain singletons (the Step 5 factory and GovernanceRouter) and on a DEX made here with `rescueTo`
///         0, swept by anyone's `rescue(asset)` into this vault. UNAUDITED.
contract Rescue is OnchainBase {
    uint256 constant G = 1_000_000;
    RescueVault constant V = RescueVault(payable(RescueLib.SCAAS_DEV_RESCUE));
    address t; // a MockERC20

    function run() external {
        _init("rescue");
        require(address(V).code.length != 0 && V.admin() == _pad(a1) && V.rescuer() == a2 && V.seq() == 0,
            "the vault at SCAAS_DEV_RESCUE, admin key 1, rescuer key 2, seq 0 (rescue.sh)");
        _book(address(V), "RescueVault");
        _fund();
        _singletons();
        _withdraw();
        _admin();
        _negatives();
        _writeBook();
    }

    /// A MockERC20 through the CREATE2 deployer (Dex.s.sol `_create2`: a top-level CREATE's estimate falls short here), 1e6
    /// of it and 1 ether to the vault.
    function _fund() internal {
        bytes memory init = abi.encodePacked(type(MockERC20).creationCode, abi.encode("Onchain Rescue", "oRSC", uint8(6)));
        bytes32 s = _salt("rescue-token");
        t = vm.computeCreate2Address(s, keccak256(init), CREATE2_FACTORY);
        vm.startBroadcast(k1);
        (bool ok,) = CREATE2_FACTORY.call{gas: 8_000_000}(abi.encodePacked(s, init));
        require(ok && t.code.length != 0, "rescue token");
        MockERC20(t).mint(address(V), 1e6);
        MockERC20(t).mint(a1, 1e6);
        (ok,) = address(V).call{value: 1 ether, gas: G}("");
        require(ok, "fund the vault");
        vm.stopBroadcast();
        _book(t, "MockERC20");
    }

    /// CTR-GOV-26: 1000 of the token sent to the factory, the router and a new DEX (its puller's `rescueTo` 0: the vault);
    /// key 3 (anyone) sweeps each by `rescue(t)`; the vault gains 3000.
    function _singletons() internal {
        OpenFactory f = OpenFactory(_dep("token_factory"));
        address gr = _dep("governance_router");
        _book(address(f), "OpenFactory");
        _book(gr, "GovernanceRouter");
        bytes memory cfg = abi.encode(ISCaaSDex.DexConfig(_pad(a1), 200_000, address(0x7EA5), false, 0, address(0), 0, 0));
        vm.broadcast(k1);
        address d = f.createDex(1, cfg, _salt("rescue-dex"));
        _book(d, "SCaaSDex");
        address[3] memory xs = [address(f), gr, d];
        uint256 b = IERC20(t).balanceOf(address(V));
        for (uint256 i; i < 3; ++i) {
            vm.broadcast(k1);
            IERC20(t).transfer{gas: G}(xs[i], 1000);
            vm.broadcast(k3);
            IRescuable(xs[i]).rescue{gas: G}(t);
        }
        require(IERC20(t).balanceOf(address(V)) == b + 3000, "the singletons' strays reach the vault");
    }

    /// Both branches, ERC-20 and native: the balance that rises is checked (never the sender's, which pays gas).
    function _withdraw() internal {
        uint256 b = IERC20(t).balanceOf(a3);
        vm.broadcast(k2); // the rescuer, to != 0: pays `to`
        V.withdraw{gas: G}(t, 100, a3);
        require(IERC20(t).balanceOf(a3) == b + 100, "rescuer -> to");
        b = IERC20(t).balanceOf(a2);
        vm.broadcast(k3); // anyone: `to` ignored, pays the rescuer
        V.withdraw{gas: G}(t, 200, a3);
        require(IERC20(t).balanceOf(a2) == b + 200, "anyone -> rescuer");
        vm.broadcast(k1); // the admin: never receives, pays the rescuer
        V.withdraw{gas: G}(t, 300, a1);
        require(IERC20(t).balanceOf(a2) == b + 500, "admin -> rescuer");
        vm.broadcast(k2); // the rescuer, to == 0: itself
        V.withdraw{gas: G}(t, 400, address(0));
        require(IERC20(t).balanceOf(a2) == b + 900, "rescuer, to 0 -> rescuer");
        b = a3.balance;
        vm.broadcast(k2); // native, the rescuer to key 3
        V.withdraw{gas: G}(address(0), 0.1 ether, a3);
        require(a3.balance == b + 0.1 ether, "native: rescuer -> to");
        b = a2.balance;
        vm.broadcast(k3); // native, anyone: the rescuer
        V.withdraw{gas: G}(address(0), 0.2 ether, a3);
        require(a2.balance == b + 0.2 ether, "native: anyone -> rescuer");
    }

    /// `setRescuer` (seq 1, key 3) signed by the admin key 1 and submitted by key 2; then withdraw by key 2 (no longer the
    /// rescuer) pays key 3. `rotateAdmin` (seq 2, key 2's native id) signed by key 1, submitted by key 3; the new admin's
    /// `setRescuer` (seq 3, back to key 2) submitted by key 1, the old admin, now anyone.
    function _admin() internal {
        bytes memory s1 = _ecdsa(k1, V.setRescuerDigest(1, a3));
        vm.broadcast(k2);
        V.setRescuer{gas: G}(1, a3, s1);
        require(V.rescuer() == a3 && V.seq() == 1, "setRescuer");
        uint256 b = IERC20(t).balanceOf(a3);
        vm.broadcast(k2);
        V.withdraw{gas: G}(t, 50, a2);
        require(IERC20(t).balanceOf(a3) == b + 50, "the old rescuer's withdraw pays the new one");
        bytes memory s2 = _ecdsa(k1, V.rotateAdminDigest(2, _pad(a2)));
        vm.broadcast(k3);
        V.rotateAdmin{gas: G}(2, _pad(a2), s2);
        require(V.admin() == _pad(a2) && V.seq() == 2, "rotateAdmin");
        bytes memory s3 = _ecdsa(k2, V.setRescuerDigest(3, a2));
        vm.broadcast(k1);
        V.setRescuer{gas: G}(3, a2, s3);
        require(V.rescuer() == a2 && V.seq() == 3, "the new admin's setRescuer");
    }

    /// At the final state (admin key 2, rescuer key 2, seq 3): a seq other than 4, the old admin's signature, a zero
    /// rescuer, a non-native admin.
    function _negatives() internal {
        bytes memory s = _ecdsa(k2, V.setRescuerDigest(5, a1));
        _negData(a3, address(V), abi.encodeCall(RescueVault.setRescuer, (5, a1, s)),
            abi.encodeWithSelector(RescueVault.SeqInvalid.selector, uint64(4), uint64(5)), "setRescuer seq 5 (expected 4)");
        s = _ecdsa(k1, V.setRescuerDigest(3, a2));
        _negData(a3, address(V), abi.encodeCall(RescueVault.setRescuer, (3, a2, s)),
            abi.encodeWithSelector(RescueVault.SeqInvalid.selector, uint64(4), uint64(3)), "setRescuer seq 3 replayed");
        s = _ecdsa(k1, V.setRescuerDigest(4, a1));
        _negData(a3, address(V), abi.encodeCall(RescueVault.setRescuer, (4, a1, s)),
            abi.encodeWithSelector(RescueVault.SignatureInvalid.selector), "setRescuer signed by the old admin");
        s = _ecdsa(k2, V.rotateAdminDigest(4, _pad(a1)));
        _negData(a3, address(V), abi.encodeCall(RescueVault.rotateAdmin, (4, _pad(a3), s)),
            abi.encodeWithSelector(RescueVault.SignatureInvalid.selector), "rotateAdmin to key 3 with the admin's signature for key 1");
        _negData(a3, address(V), abi.encodeCall(RescueVault.setRescuer, (4, address(0), s)),
            abi.encodeWithSelector(RescueVault.RescuerInvalid.selector), "setRescuer to 0");
        bytes32 bad = bytes32(uint256(1) << 160 | uint160(a1));
        _negData(a3, address(V), abi.encodeCall(RescueVault.rotateAdmin, (4, bad, s)),
            abi.encodeWithSelector(RescueVault.AdminInvalid.selector, bad), "rotateAdmin to a non-native UA");
    }
}
