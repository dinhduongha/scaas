// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";

/// @notice NET-EVM-13 (owner 2026-11-10): a chain's deployment books are named by its key, `deployments/<key>.json` (its
///         release list `<key>-releases.json`, the e2e books `<key>-<what>.json`, Hedera's `hedera-<key>.json`). The key
///         comes from `chain-uids.json` by (chainId, chain_uid); a chain not in the table needs `DEPLOY_NAME`
///         (`<name>-mainnet` | `<name>-testnet`), else `DEPLOY_NAME_REQUIRED`, never a chain-id fallback. Every book
///         starts with `key`, `name`, `chainId`, `chainUid`, `network`; a reader checks `network` against the key's suffix
///         (a key without one, e.g. `ethereum-hoodi`: its table row's network), else `BOOK_NETWORK_MISMATCH`. An old book
///         by chain id with none by the key: `BOOK_OLD_NAME` (rename it). `script/deploybook.py` is the same rule for the
///         Python and shell readers.
abstract contract DeployBook is Script {
    string private constant TABLE = "./chain-uids.json";

    /// @notice `CHAIN_UID` env (chain-uids.json), default block 0's hash as the RPC reports it; either way it must
    ///         equal that hash (CTR-GEN-05). BLOCKHASH only sees the 256 blocks before the current one, and a script
    ///         runs at the head, so roll to block 1: the fork database then fetches block 0 from the RPC at any head.
    function _chainUid() internal returns (bytes32 u) {
        uint256 head = block.number;
        vm.roll(1);
        bytes32 rpcGenesis = blockhash(0);
        vm.roll(head);
        u = vm.envOr("CHAIN_UID", rpcGenesis);
        require(u == rpcGenesis, "CHAIN_UID differs from the RPC's block 0 hash");
        require(u != bytes32(0), "RPC gave no block 0 hash");
    }

    /// @dev `DEPLOY_NAME` env, empty when unset (a test harness overrides it).
    function _deployName() internal view virtual returns (string memory) {
        return vm.envOr("DEPLOY_NAME", string(""));
    }

    /// @notice This chain's key, name and network: the `chain-uids.json` row with (block.chainid, `uid`), else
    ///         `DEPLOY_NAME`.
    function _bookKey(bytes32 uid) internal view returns (string memory key, string memory name, string memory network) {
        string memory dn = _deployName();
        string memory j = vm.readFile(TABLE);
        for (uint256 i;; ++i) {
            string memory p = string.concat(".chains[", vm.toString(i), "]");
            if (!vm.keyExistsJson(j, p)) break;
            string memory k = vm.parseJsonString(j, string.concat(p, ".key"));
            if (vm.parseJsonUint(j, string.concat(p, ".chainId")) == block.chainid
                && vm.parseJsonBytes32(j, string.concat(p, ".chainUid")) == uid) {
                require(bytes(dn).length == 0 || _bookEq(dn, k),
                    string.concat("DEPLOY_NAME_MISMATCH: DEPLOY_NAME=", dn, ", but this chain is ", k, " in chain-uids.json"));
                return (k, vm.parseJsonString(j, string.concat(p, ".name")), vm.parseJsonString(j, string.concat(p, ".network")));
            }
            require(!_bookEq(dn, k), string.concat("DEPLOY_NAME_TAKEN: ", dn, " names another chain in chain-uids.json"));
        }
        require(bytes(dn).length != 0, string.concat("DEPLOY_NAME_REQUIRED: chain ", vm.toString(block.chainid),
            " is not in chain-uids.json; set DEPLOY_NAME=<name>-testnet or <name>-mainnet (NET-EVM-13)"));
        network = _bookSuffix(dn);
        require(bytes(network).length != 0 && _bookChars(dn),
            string.concat("DEPLOY_NAME_INVALID: ", dn, " is not <name>-mainnet or <name>-testnet ([a-z0-9-])"));
        return (dn, dn, network);
    }

    /// @notice `./deployments/<prefix><key><suffix>` of this chain.
    function _bookPath(bytes32 uid, string memory prefix, string memory suffix) internal view returns (string memory) {
        (string memory k,,) = _bookKey(uid);
        return string.concat("./deployments/", prefix, k, suffix);
    }

    /// @notice A book's text: this chain's header, then `body`'s fields (a JSON object). forge's serializer sorts the
    ///         keys, so the header goes first by hand; write it with `vm.writeFile`.
    function _bookHeader(bytes32 uid, string memory body) internal view returns (string memory) {
        (string memory k, string memory n, string memory net) = _bookKey(uid);
        string memory h = string.concat('{"key":"', k, '","name":"', n, '","chainId":', vm.toString(block.chainid),
            ',"chainUid":"', vm.toString(uid), '","network":"', net, '"');
        bytes memory b = bytes(body);
        require(b.length >= 2 && b[0] == "{", "a book's body is a JSON object");
        if (b.length == 2) return string.concat(h, "}");
        bytes memory rest = new bytes(b.length - 1);
        for (uint256 i; i < rest.length; ++i) rest[i] = b[i + 1];
        return string.concat(h, ",", string(rest));
    }

    /// @notice This chain's book `<prefix><key><suffix>`, read and checked; `BOOK_OLD_NAME` when only the old book by
    ///         chain id is there.
    function _readBook(bytes32 uid, string memory prefix, string memory suffix) internal view returns (string memory) {
        string memory p = _bookPath(uid, prefix, suffix);
        string memory old = string.concat("./deployments/", prefix, vm.toString(block.chainid), suffix);
        require(vm.exists(p) || !vm.exists(old), string.concat("BOOK_OLD_NAME: ", old,
            " is named by chain id; rename it to ", p, " and give it its header (NET-EVM-13)"));
        return _checkBook(vm.readFile(p), p);
    }

    /// @notice The book the env var `name` names (a path), else this chain's `<key><suffix>`; read and checked.
    function _envBook(string memory name, bytes32 uid, string memory suffix) internal view returns (string memory) {
        string memory p = vm.envOr(name, string(""));
        return bytes(p).length != 0 ? _checkBook(vm.readFile(p), p) : _readBook(uid, "", suffix);
    }

    /// @notice A book as read: its header there, its `network` the key's.
    function _checkBook(string memory j, string memory where) internal view returns (string memory) {
        require(vm.keyExistsJson(j, ".key") && vm.keyExistsJson(j, ".name") && vm.keyExistsJson(j, ".chainId")
            && vm.keyExistsJson(j, ".chainUid") && vm.keyExistsJson(j, ".network"),
            string.concat("BOOK_HEADER_MISSING: ", where, " has no key, name, chainId, chainUid, network (a book from before NET-EVM-13)"));
        string memory k = vm.parseJsonString(j, ".key");
        string memory net = vm.parseJsonString(j, ".network");
        require(_bookEq(net, _networkOf(k)), string.concat("BOOK_NETWORK_MISMATCH: ", where, ": network ", net, ", key ", k));
        return j;
    }

    /// @dev The network a key names: its suffix, else its `chain-uids.json` row's.
    function _networkOf(string memory key) internal view returns (string memory net) {
        net = _bookSuffix(key);
        if (bytes(net).length != 0) return net;
        string memory j = vm.readFile(TABLE);
        for (uint256 i;; ++i) {
            string memory p = string.concat(".chains[", vm.toString(i), "]");
            if (!vm.keyExistsJson(j, p)) break;
            if (_bookEq(vm.parseJsonString(j, string.concat(p, ".key")), key)) {
                return vm.parseJsonString(j, string.concat(p, ".network"));
            }
        }
        revert(string.concat("BOOK_KEY_INVALID: ", key, " ends in neither -mainnet nor -testnet and is not in chain-uids.json"));
    }

    function _bookSuffix(string memory s) private pure returns (string memory) {
        bytes memory b = bytes(s);
        if (b.length <= 8) return "";
        bytes memory t = new bytes(8);
        for (uint256 i; i < 8; ++i) t[i] = b[b.length - 8 + i];
        if (_bookEq(string(t), "-mainnet")) return "mainnet";
        if (_bookEq(string(t), "-testnet")) return "testnet";
        return "";
    }

    function _bookChars(string memory s) private pure returns (bool) {
        bytes memory b = bytes(s);
        for (uint256 i; i < b.length; ++i) {
            bytes1 c = b[i];
            if (!((c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-")) return false;
        }
        return true;
    }

    function _bookEq(string memory a, string memory b) private pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
