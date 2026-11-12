// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {RescueVault} from "../src/governance/RescueVault.sol";
import {RescueLib} from "../src/governance/RescueLib.sol";

/// @notice The dev rescue vault (CTR-GOV-25; spec superpowers/specs/2026-11-12-rescue-vault.md §5): deploy it through the
///         deterministic deployer if it is not there, then catch it up by the public admin log. Any funded account may run
///         it; it holds no power over the vault. It deploys the committed init code `rescue-vault-init.hex` (creation code and
///         constructor arguments, as built by solc 0.8.37 at the pinned settings), never a fresh compile, so a later compiler
///         cannot move the address; it refuses bytes whose CREATE2 address is not `RescueLib.SCAAS_DEV_RESCUE`.
///   forge script script/DeployRescueVault.s.sol --rpc-url $RPC --broadcast --private-key <any funded key>
/// env: RESCUE_VAULT_LOG (optional, default ./rescue-vault-admin-log.json): a JSON array in seq order of
///      {"seq", "op": "setRescuer", "newRescuer", "sig"} and {"seq", "op": "rotateAdmin", "newAdmin", "sig"};
///      rows at or below the vault's seq() are skipped; the vault must end at the log's last seq, rescuer and admin.
contract DeployRescueVault is Script {
    address internal constant DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes32 internal constant SALT = keccak256("scaas.rescue-vault.v1");
    string internal constant INIT = "./rescue-vault-init.hex";

    function run() external {
        deployAndCatchUp(vm.parseBytes(vm.readFile(INIT)),
            vm.readFile(vm.envOr("RESCUE_VAULT_LOG", string("./rescue-vault-admin-log.json"))));
    }

    /// @notice `run()` with the init code and the admin log JSON given (tests). Every row is read; the rows above the vault's
    ///         `seq()` are applied. At the end the vault must hold the log's last `seq` (0 for `[]`), the last `newRescuer`
    ///         and the last `newAdmin` (the init code's for a kind with no row): a chain whose vault took another operation
    ///         (an old or equivocating admin, spec §4 R1 / R3) fails here instead of reading as caught up.
    function deployAndCatchUp(bytes memory init, string memory j) public {
        require(DEPLOYER.code.length != 0,
            "no deterministic CREATE2 deployer at 0x4e59b44847b379578588920ca78fbf26c0b4956c (runbook NET-EVM-05)");
        address a = vm.computeCreate2Address(SALT, keccak256(init), DEPLOYER);
        require(a == RescueLib.SCAAS_DEV_RESCUE, "rescue-vault-init.hex is not RescueLib.SCAAS_DEV_RESCUE's init code");
        bytes32 wantAdmin;
        address wantRescuer;
        assembly ("memory-safe") { // the init code ends with abi.encode(initialAdmin, initialRescuer)
            let e := add(add(init, 0x20), mload(init))
            wantAdmin := mload(sub(e, 0x40))
            wantRescuer := mload(sub(e, 0x20))
        }
        uint64 wantSeq;
        RescueVault v = RescueVault(payable(a));
        vm.startBroadcast();
        if (a.code.length == 0) {
            (bool ok,) = DEPLOYER.call(abi.encodePacked(SALT, init));
            require(ok && a.code.length != 0, "deploy failed");
            console.log("deployed", a);
        }
        for (uint256 i; vm.keyExistsJson(j, string.concat(".[", vm.toString(i), "]")); ++i) {
            string memory k = string.concat(".[", vm.toString(i), "]");
            wantSeq = uint64(vm.parseJsonUint(j, string.concat(k, ".seq")));
            bytes32 op = keccak256(bytes(vm.parseJsonString(j, string.concat(k, ".op"))));
            bytes memory sig = vm.parseJsonBytes(j, string.concat(k, ".sig"));
            bool apply_ = wantSeq > v.seq();
            if (op == keccak256("setRescuer")) {
                wantRescuer = vm.parseJsonAddress(j, string.concat(k, ".newRescuer"));
                if (apply_) v.setRescuer(wantSeq, wantRescuer, sig);
            } else if (op == keccak256("rotateAdmin")) {
                wantAdmin = vm.parseJsonBytes32(j, string.concat(k, ".newAdmin"));
                if (apply_) v.rotateAdmin(wantSeq, wantAdmin, sig);
            } else {
                revert("admin log: op is setRescuer or rotateAdmin");
            }
            if (apply_) console.log("applied seq", wantSeq);
        }
        vm.stopBroadcast();
        console.log("vault", a, "rescuer", v.rescuer());
        console.log("admin");
        console.logBytes32(v.admin());
        console.log("seq", v.seq());
        require(v.seq() == wantSeq && v.rescuer() == wantRescuer && v.admin() == wantAdmin,
            "vault differs from the admin log: another operation was applied on this chain (spec R1 / R3)");
    }
}
