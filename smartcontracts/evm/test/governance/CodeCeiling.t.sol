// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";

/// @notice The ceiling that lets every kind build (CTR-GOV-19, GD-4). forge 1.8.5 applies no code size limit in tests
///         (measured: 131,073 B deploys), so every kind above 64 KiB runs in forge as it is; `code_size_limit = 131072` in
///         `foundry.toml` would make every suite whose test contract's init code exceeds 2 x 131,072 B fail `setUp` (this
///         one: 423,447 B), so it is not set and the 131,072 B ceiling is held by `scripts/size_gate.py` and by the chain.
///         The deploy refuses a release above the chain's declared code limit by name, before anything is sent.
contract CodeCeilingTest is Test {
    /// Init code returning `n` zero bytes of runtime: `PUSH3 n DUP1 PUSH1 13 PUSH1 0 CODECOPY PUSH1 0 RETURN`, then the runtime.
    function _create(uint256 n) internal returns (address a) {
        bytes memory code = bytes.concat(hex"62", bytes3(uint24(n)), hex"80600d6000396000f3", new bytes(n));
        assembly ("memory-safe") { a := create(0, add(code, 32), mload(code)) }
    }

    /// A pin of the forge environment: a Foundry default that starts refusing above EIP-7954's 65,536 B turns this red.
    function test_createAboveSixtyFourKiBDeploys() public {
        address a = _create(65_537);
        assertEq(a.code.length, 65_537);
        a = _create(100_000);
        assertEq(a.code.length, 100_000);
    }

    /// GD-4: the limit is declared (`CHAIN_CODE_LIMIT`), never derived from a chain id; a release above it is refused
    /// with its name and both figures.
    function test_releaseAboveTheChainLimitIsRefusedByName() public {
        DeployHarness h = new DeployHarness();
        uint256 rt = vm.parseJsonUint(vm.readFile("./size-baseline.json"), ".WrappedPqzToken");
        h.limitBlockGas(type(uint64).max);
        h.limitCode(rt);
        h.requireGas("WrappedPqzToken"); // control: at the limit
        h.limitCode(rt - 1);
        vm.expectRevert(bytes(string.concat("WrappedPqzToken runtime ", vm.toString(rt), " B > chain code limit ",
            vm.toString(rt - 1), " B (CHAIN_CODE_LIMIT, CTR-GOV-19)")));
        h.requireGas("WrappedPqzToken");
        // a contract outside the baseline is under the EIP-170 limit: priced at 24,576 B
        h.limitCode(24_576);
        h.requireGas("UniswapExecutor");
        h.limitCode(24_575);
        vm.expectRevert(bytes("UniswapExecutor runtime 24576 B > chain code limit 24575 B (CHAIN_CODE_LIMIT, CTR-GOV-19)"));
        h.requireGas("UniswapExecutor");
    }

    /// The default without `CHAIN_CODE_LIMIT` is EIP-7954's 65,536 B.
    function test_chainCodeLimitDefaultsToEip7954() public {
        DeployHarness h = new DeployHarness();
        if (vm.envOr("CHAIN_CODE_LIMIT", uint256(0)) == 0) assertEq(h.chainCodeLimit(), 65_536);
    }
}
