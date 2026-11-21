// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {console} from "forge-std/Script.sol";
import {UARegistry} from "../src/ua/UARegistry.sol";
import {DeployBase} from "./DeployBase.sol";

/// @notice A later `UARegistry` generation over the book's latest (spec 2026-11-19-registry-verify-only-kinds §9, CTR-UA-64;
///         `DeployBase._deployUARegistryGen`). env: PRIVATE_KEY, TX_GAS_CAP (`script/tx_gas_cap.py`'s value; it must equal the
///         book's), UA_GEN_BOOK (the predecessor's book: the chain's `deployments/<key>.json` for generation 1, else the
///         `-ua-gen<n>` companion), SMART_KEY_ACCOUNT_IMPL (the line's `SmartKeyAccount` implementation, CTR-UA-67 P4), DEPLOY_SALT,
///         CHAIN_UID, DEPLOY_NAME as `Deploy.s.sol`. The book's `gen_verify_only` entries name the verify-only verifiers
///         `script/pq_verifiers.py` built on the chain. Writes `deployments/<key>-ua-gen<g>.json`: the new generation's fields and
///         `ua_registry_line`, the generations below it (`gen1`, `gen2`, …), so the next generation's walk check reads one book.
///         **UNAUDITED.**
contract DeployUAGen is DeployBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        _setup();
        string memory book = vm.readFile(vm.envString("UA_GEN_BOOK"));
        address ska = vm.envAddress("SMART_KEY_ACCOUNT_IMPL");
        string memory line = _lineBelow(book);
        vm.startBroadcast(pk);
        UARegistry reg = _deployUARegistryGen(book, ska);
        vm.stopBroadcast();
        vm.serializeString("deploy", "ua_registry_line", line);
        string memory out = vm.serializeBytes32("deploy", "chain_uid", uid);
        vm.createDir("./deployments", true);
        _writeBook(uid, _bookPath(uid, string.concat("-ua-gen", vm.toString(reg.generation()), ".json")), out);
        console.log(out);
    }

    /// The new generation's line below it, an object keyed `gen<g>` (forge's JSON writer keeps no array of objects): the
    /// predecessor book's `ua_registry_line`, then the predecessor itself.
    function _lineBelow(string memory book) internal view returns (string memory l) {
        uint256 n =
            vm.keyExistsJson(book, ".ua_registry_generation") ? vm.parseJsonUint(book, ".ua_registry_generation") : 1;
        for (uint256 g = 1; g < n; ++g) {
            string memory p = string.concat(".ua_registry_line.gen", vm.toString(g));
            l = string.concat(
                l,
                '"gen',
                vm.toString(g),
                '":',
                _entry(
                    vm.parseJsonAddress(book, string.concat(p, ".registry")),
                    vm.parseJsonBytes32(book, string.concat(p, ".codehash"))
                ),
                ","
            );
        }
        l = string.concat(
            "{",
            l,
            '"gen',
            vm.toString(n),
            '":',
            _entry(vm.parseJsonAddress(book, ".ua_registry"), vm.parseJsonBytes32(book, ".ua_registry_codehash")),
            "}"
        );
    }

    function _entry(address r, bytes32 h) internal pure returns (string memory) {
        return string.concat('{"registry":"', vm.toString(r), '","codehash":"', vm.toString(h), '"}');
    }
}
