// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";

/// deploy.sh evm, the sending run (NET-EVM-27): the transactions of `Deploy.s.sol`'s simulation (`plan`, forge's dry-run
/// file, the linked libraries first), sent in order, each with an explicit gas limit. Every transaction is first run in
/// order on this run's fork of the RPC and measured as `DeployBase._measuredGas` does (regular = `lastCallGas` x 64/63,
/// state = EIP-8037's); its limit is (regular + state) x 1.05 capped at the chain's block gas limit (`block.gaslimit`, read
/// from the RPC). One that needs more than that block gas limit refuses the whole plan by name before anything is sent.
/// A call with an explicit gas is a fixed gas limit to forge: no estimate, no multiplier. No library is linked here, so
/// forge adds no transaction of its own. env PRIVATE_KEY, the plan's sender.
/// Round 3r (spec 2026-11-10-admin-not-owner.md §5.6 "Threats", T10): the factory's release deploys are open to anyone once
/// approved, so a release whose `CREATE2` address already has code (the factory's address, salt and init code with its
/// arguments: the approved bytes, nothing else lands there) and whose registered `envVersion` is the plan's is done, logged
/// and not sent; another `envVersion` there refuses the plan by name. The check runs again right before each send (Fable
/// 3r3s3t P3-5). It reads this run's fork: a front-run that lands between this run and its sends fails that send, and forge
/// stops; re-run the plan, which then skips every release already there. A non-release transaction that already landed
/// reverts on the fork (`PlanTxNotSendable(i, "reverts on the fork")`): re-plan from the deploy script after a front-run.
contract DeploySend is Script {
    error TxGasOverBlockLimit(uint256 index, uint256 regular, uint256 state, uint256 blockGasLimit);
    error PlanTxNotSendable(uint256 index, string why);

    function run(string calldata plan) external {
        string memory j = vm.readFile(plan);
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address sender = vm.addr(pk);
        uint256 n;
        while (vm.keyExistsJson(j, _at(n, ""))) ++n;
        address[] memory to = new address[](n);
        bytes[] memory input = new bytes[](n);
        uint256[] memory limit = new uint256[](n);
        uint256 snap = vm.snapshotState();
        for (uint256 i; i < n; ++i) {
            if (!vm.keyExistsJson(j, _at(i, ".to"))) revert PlanTxNotSendable(i, "a CREATE (no `to`)");
            if (vm.parseJsonAddress(j, _at(i, ".from")) != sender) revert PlanTxNotSendable(i, "another sender");
            if (vm.keyExistsJson(j, _at(i, ".value")) && vm.parseJsonUint(j, _at(i, ".value")) != 0) {
                revert PlanTxNotSendable(i, "a value");
            }
            to[i] = vm.parseJsonAddress(j, _at(i, ".to"));
            input[i] = vm.parseJsonBytes(j, _at(i, ".input"));
            if (_done(to[i], input[i], i)) continue; // limit[i] = 0: not sent
            vm.prank(sender, sender);
            (bool ok,) = to[i].call(input[i]);
            if (!ok) revert PlanTxNotSendable(i, "reverts on the fork");
            Vm.Gas memory g = vm.lastCallGas();
            (uint256 regular, uint256 state) = (uint256(g.gasTotalUsed) * 64 / 63, uint256(int256(g.gasStateUsed)));
            if (regular + state > block.gaslimit) revert TxGasOverBlockLimit(i, regular, state, block.gaslimit);
            limit[i] = (regular + state) * 105 / 100;
            if (limit[i] > block.gaslimit) limit[i] = block.gaslimit;
            console.log(string.concat("tx gas | ", vm.toString(i), " | regular ", vm.toString(regular), " | state ",
                vm.toString(state), " | limit ", vm.toString(limit[i]), " | block gas limit ", vm.toString(block.gaslimit)));
        }
        vm.revertToStateAndDelete(snap);
        vm.startBroadcast(pk);
        for (uint256 i; i < n; ++i) {
            if (limit[i] == 0 || _done(to[i], input[i], i)) continue; // per send: a release landed since (P3-5)
            (bool ok,) = to[i].call{gas: limit[i]}(input[i]);
            if (!ok) revert PlanTxNotSendable(i, "reverts at its limit");
        }
        vm.stopBroadcast();
    }

    /// @notice The `CREATE2` address a factory's release deploy (`deployTokenImplementation`, `deployDexImplementation`,
    ///         `deployImplementation`) lands at, as `OpenFactory._deploy` derives it; 0 for any other call.
    function releaseAt(address f, bytes memory input) public pure returns (address) {
        if (input.length < 4) return address(0);
        bytes4 s = bytes4(input);
        bytes memory a = new bytes(input.length - 4);
        for (uint256 k; k < a.length; ++k) a[k] = input[k + 4];
        bytes32 salt;
        bytes memory code;
        if (s == bytes4(keccak256("deployTokenImplementation(uint8,uint64,uint16,bytes,bytes,bytes32)"))) {
            (uint8 kind, uint64 version,, bytes memory initcode, bytes memory implArgs,) =
                abi.decode(a, (uint8, uint64, uint16, bytes, bytes, bytes32));
            (salt, code) = (keccak256(abi.encode(kind, version)), bytes.concat(initcode, abi.encode(f, implArgs)));
        } else if (s == bytes4(keccak256("deployDexImplementation(uint64,uint16,bytes,bytes,bytes32)"))) {
            (uint64 version,, bytes memory initcode, bytes memory implArgs,) =
                abi.decode(a, (uint64, uint16, bytes, bytes, bytes32));
            (salt, code) = (keccak256(abi.encode("dex", version)), bytes.concat(initcode, abi.encode(f, implArgs)));
        } else if (s == bytes4(keccak256("deployImplementation((uint16,uint16,uint64),uint16,bytes4,bytes4,bytes,bytes,bytes32)"))) {
            (ReleaseId memory id,,,, bytes memory initcode, bytes memory implArgs,) =
                abi.decode(a, (ReleaseId, uint16, bytes4, bytes4, bytes, bytes, bytes32));
            (salt, code) = (keccak256(abi.encode("release", id)), bytes.concat(initcode, abi.encode(id, f, implArgs)));
        } else {
            return address(0);
        }
        return vm.computeCreate2Address(salt, keccak256(code), f);
    }

    /// @notice A release deploy whose address has code: done when the factory's record names that address with the plan's
    ///         `envVersion` (logged), else `PlanTxNotSendable(i, …)`; false for an address without code or any other call.
    function _done(address f, bytes memory input, uint256 i) internal view returns (bool) {
        address at = releaseAt(f, input);
        if (at == address(0) || at.code.length == 0) return false;
        bytes memory a = new bytes(input.length - 4);
        for (uint256 k; k < a.length; ++k) a[k] = input[k + 4];
        bytes4 s = bytes4(input);
        (address impl, uint16 env, uint16 want) = (address(0), 0, 0);
        if (s == bytes4(keccak256("deployTokenImplementation(uint8,uint64,uint16,bytes,bytes,bytes32)"))) {
            (uint8 kind, uint64 version, uint16 e,,,) = abi.decode(a, (uint8, uint64, uint16, bytes, bytes, bytes32));
            (impl, env, want) = _rel(f, abi.encodeWithSignature("releaseOf(uint8,uint64)", kind, version), e);
        } else if (s == bytes4(keccak256("deployDexImplementation(uint64,uint16,bytes,bytes,bytes32)"))) {
            (uint64 version, uint16 e,,,) = abi.decode(a, (uint64, uint16, bytes, bytes, bytes32));
            (impl, env, want) = _rel(f, abi.encodeWithSignature("dexReleaseOf(uint64)", version), e);
        } else {
            (ReleaseId memory id, uint16 e,,,,,) = abi.decode(a, (ReleaseId, uint16, bytes4, bytes4, bytes, bytes, bytes32));
            (impl, env, want) = _rel(f, abi.encodeWithSignature("classReleaseOf((uint16,uint16,uint64))", id), e);
        }
        if (impl != at || env != want) revert PlanTxNotSendable(i, "the release is there, not with the plan's envVersion");
        console.log(string.concat("tx gas | ", vm.toString(i), " | done: the release is at ", vm.toString(at)));
        return true;
    }

    /// @dev The factory's record (`implementation`, `envVersion`: the first two words of `Release` and `ClassRelease`).
    function _rel(address f, bytes memory call, uint16 want) internal view returns (address impl, uint16 env, uint16) {
        (bool ok, bytes memory r) = f.staticcall(call);
        if (ok && r.length >= 64) (impl, env) = abi.decode(r, (address, uint16));
        return (impl, env, want);
    }

    struct ReleaseId {
        uint16 contractClass;
        uint16 kind;
        uint64 version;
    }

    function _at(uint256 i, string memory key) internal pure returns (string memory) {
        return string.concat(".transactions[", vm.toString(i), "].transaction", key);
    }
}
