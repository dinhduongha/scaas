// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../src/governance/GovernanceBits.sol";

/// @notice The SDK's merged-tree review M20 (clients/scaas-sdk/runs/2026-11-20-m20-nethermind.sh), test chains only: the
///         calldata of `createToken` for one `NORMAL_PQZ` token (kind 4, release 1, `PRECOMPILE` verify mode, no auditor) whose
///         minter is `MINTER`. Printed, not broadcast: the token's initialisation runs the `PQZ` precompile's self-test, which
///         forge's EVM lacks, so the runner sends it with cast to the node that has it. Env `MINTER`.
contract SdkM20PqzToken is Script {
    function run() external view {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals) = ("M20 PQZ", "m20PQ", 6);
        c.features = (1 << GovernanceBits.PAYABLE) | (1 << GovernanceBits.MINTABLE) | (1 << GovernanceBits.BURNABLE);
        c.lockedFeatures = 1 << GovernanceBits.MINTABLE;
        c.roles.minter = bytes32(uint256(uint160(vm.envAddress("MINTER"))));
        c.conf = IFactoryToken.ConfidentialConfig(
            "", 10_000, uint256(1) << 40, 3, 0, 0, 0, 0, bytes32(0), false, 0, 0, 0, false, false
        );
        bytes memory cd = abi.encodeCall(
            IOpenFactory.createToken, (IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), keccak256("sdk-m20-pqz"))
        );
        console2.log("M20 calldata");
        console2.logBytes(cd);
    }
}
