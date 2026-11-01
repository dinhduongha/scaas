// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";
import {DeployBase} from "../script/DeployBase.sol";
import {OpenFactory} from "../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../src/factory/IFactoryToken.sol";
import {SmartKeyAccountFactory} from "../src/account/SmartKeyAccountFactory.sol";
import {WrappedPqzToken} from "../src/pqz/WrappedPqzToken.sol";
import {pinned} from "../test/helpers/Catalogue.sol";

/// typed-signing deploy-gas measurement (driver: the .sh of the same name). The real deploy (`DeployBase`, DEPLOY_ZETHER)
/// plus the one release it leaves out, `WRAPPED_PQZ`: env deps[0] is any contract here (PqzLayer's constructor checks
/// only that, the verifier needs the chain's PQZ precompile, which anvil does not have). Measurement only.
contract DeployGasProbe is DeployBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        _setup();
        vm.startBroadcast(pk);
        SmartKeyAccountFactory accounts = new SmartKeyAccountFactory{salt: salt}(uid);
        OpenFactory f = _deployTokenFactory(vm.addr(pk), true, accounts.IMPLEMENTATION(), false);
        IOpenFactory.TokenKind kind = IOpenFactory.TokenKind.WRAPPED_PQZ;
        IFactoryToken.Env memory e = f.envOf(IOpenFactory.TokenKind.NORMAL, 1);
        e.deps = new address[](1);
        e.deps[0] = address(accounts);
        f.publishEnv(kind, 1, pinned(e, kind));
        f.deployImplementation(kind, 1, 1, type(WrappedPqzToken).creationCode, "");
        vm.stopBroadcast();
    }

    /// Replays the transactions of a forge dry run (`file`, run on a fresh anvil, no `--broadcast`) in forge's own EVM, which
    /// charges EIP-8037: `vm.lastCallGas()` splits each call frame into regular and state gas. One line per transaction.
    function split(string calldata file) external {
        string memory j = vm.readFile(file);
        address sender = vm.addr(vm.envUint("PRIVATE_KEY"));
        for (uint256 i; vm.keyExistsJson(j, string.concat(".transactions[", vm.toString(i), "]")); ++i) {
            string memory p = string.concat(".transactions[", vm.toString(i), "].transaction");
            address to = vm.parseJsonAddress(j, string.concat(p, ".to"));
            bytes memory input = vm.parseJsonBytes(j, string.concat(p, ".input"));
            vm.prank(sender);
            (bool ok,) = to.call(input);
            if (!ok) continue; // a library: forge links it before the script runs, the replay's CREATE2 collides
            Vm.Gas memory g = vm.lastCallGas();
            console.log(string.concat("SPLIT ", vm.toString(i), " ", vm.toString(uint256(g.gasTotalUsed)), " ",
                vm.toString(uint256(int256(g.gasStateUsed)))));
        }
    }
}
