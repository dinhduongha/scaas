// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {RescueVault} from "../src/governance/RescueVault.sol";
import {RescueLib} from "../src/governance/RescueLib.sol";

/// @notice The dev rescue vault (CTR-GOV-25; spec superpowers/specs/2026-11-12-rescue-vault.md §5): deploy it through the
///         deterministic deployer if it is not there, then catch it up by the public rotation log. Any funded account may run
///         it; it holds no power over the vault. The default profile only: another compiler setting moves the address, and
///         the script refuses it.
///   forge script script/DeployRescueVault.s.sol --rpc-url $RPC --broadcast --private-key <any funded key>
/// env: RESCUE_VAULT_LOG (optional, default ./rescue-vault-rotations.json): a JSON array of {"seq","newOwner","sig"}
///      in seq order; rows at or below the vault's seq() are skipped.
contract DeployRescueVault is Script {
    address internal constant DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes32 internal constant SALT = keccak256("scaas.rescue-vault.v1");
    address internal constant FIRST_OWNER = 0x0389f77E846ff687d44db57bcC9DCB55dd6f4131;

    function run() external {
        require(DEPLOYER.code.length != 0,
            "no deterministic CREATE2 deployer at 0x4e59b44847b379578588920ca78fbf26c0b4956c (runbook NET-EVM-05)");
        bytes memory init = abi.encodePacked(type(RescueVault).creationCode, abi.encode(FIRST_OWNER));
        address a = vm.computeCreate2Address(SALT, keccak256(init), DEPLOYER);
        require(a == RescueLib.SCAAS_DEV_RESCUE, "init code is not RescueLib.SCAAS_DEV_RESCUE's: compiler, settings or source moved");
        string memory j = vm.readFile(vm.envOr("RESCUE_VAULT_LOG", string("./rescue-vault-rotations.json")));
        RescueVault v = RescueVault(payable(a));
        vm.startBroadcast();
        if (a.code.length == 0) {
            (bool ok,) = DEPLOYER.call(abi.encodePacked(SALT, init));
            require(ok && a.code.length != 0, "deploy failed");
            console.log("deployed", a);
        }
        for (uint256 i; vm.keyExistsJson(j, string.concat(".[", vm.toString(i), "]")); ++i) {
            string memory k = string.concat(".[", vm.toString(i), "]");
            uint64 s = uint64(vm.parseJsonUint(j, string.concat(k, ".seq")));
            if (s <= v.seq()) continue;
            v.rotate(s, vm.parseJsonAddress(j, string.concat(k, ".newOwner")), vm.parseJsonBytes(j, string.concat(k, ".sig")));
            console.log("rotated to seq", s);
        }
        vm.stopBroadcast();
        console.log("vault", a, "owner", v.owner());
        console.log("seq", v.seq());
    }
}
