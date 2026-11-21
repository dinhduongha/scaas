// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {VmSafe} from "forge-std/Vm.sol";

/// @notice NET-EVM-13 (owner 2026-11-10): a chain's deployment books are named by its key: `deployments/<key>.json` its
///         book (a Hedera chain's from `DeployHedera.s.sol`, its only deploy), `<key>-<what>.json` a companion (the
///         release list `-releases`, `-t66b-releases`, the e2e books `-zether-e2e`, `-pqz`, …). The key
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

    /// @dev The table, `chain-uids.json` (a test harness overrides it with a fixture).
    function _bookTable() internal view virtual returns (string memory) {
        return TABLE;
    }

    /// @notice This chain's key, name and network: the `chain-uids.json` row with (block.chainid, `uid`), else
    ///         `DEPLOY_NAME`. NET-ALL-25: a second row of that pair is `CHAIN_PAIR_TAKEN`; a chain with no row whose
    ///         genesis is a private row's (a chain SCaaS runs, `private`) is `CHAIN_UID_PRIVATE` (a fork of ours is a new
    ///         chain with its own genesis). `script/deploybook.py` checks the whole table on every read.
    function _bookKey(bytes32 uid)
        internal
        view
        returns (string memory key, string memory name, string memory network)
    {
        string memory dn = _deployName();
        BookRow[] memory r = _bookRows();
        uint256 hit = type(uint256).max; // the row of (block.chainid, uid)
        string memory priv; // a private row's key with this genesis
        bool taken; // DEPLOY_NAME names another row
        for (uint256 i; i < r.length; ++i) {
            if (r[i].chainUid == uid && r[i].chainId == block.chainid) {
                hit = i; // one at most: bookRows refused a second row of the pair
                continue;
            }
            if (_bookEq(dn, r[i].key)) taken = true;
            if (r[i].chainUid == uid && r[i].priv) priv = r[i].key;
        }
        if (hit != type(uint256).max) {
            key = r[hit].key;
            if (bytes(dn).length != 0 && !_bookEq(dn, key)) {
                revert(
                    string.concat(
                        "DEPLOY_NAME_MISMATCH: DEPLOY_NAME=", dn, ", but this chain is ", key, " in chain-uids.json"
                    )
                );
            }
            return (key, r[hit].name, r[hit].network);
        }
        require(!taken, string.concat("DEPLOY_NAME_TAKEN: ", dn, " names another chain in chain-uids.json"));
        require(
            bytes(priv).length == 0,
            string.concat(
                "CHAIN_UID_PRIVATE: chain ",
                vm.toString(block.chainid),
                " has the genesis of the private chain ",
                priv,
                "; a chain we run that forks is a new chain with its own genesis (NET-ALL-25)"
            )
        );
        require(
            bytes(dn).length != 0,
            string.concat(
                "DEPLOY_NAME_REQUIRED: chain ",
                vm.toString(block.chainid),
                " is not in chain-uids.json; set DEPLOY_NAME=<name>-testnet or <name>-mainnet (NET-EVM-13)"
            )
        );
        network = _bookSuffix(dn);
        require(
            bytes(network).length != 0 && _bookChars(dn),
            string.concat("DEPLOY_NAME_INVALID: ", dn, " is not <name>-mainnet or <name>-testnet ([a-z0-9-])")
        );
        return (dn, dn, network);
    }

    /// @dev A `chain-uids.json` row as the deploy scripts read it (`private` is `priv`: a Solidity keyword).
    struct BookRow {
        uint256 chainId;
        bytes32 chainUid;
        string key;
        string name;
        string network;
        bool priv;
    }

    struct BookRowKey {
        string key;
    }

    /// @dev The table's rows (`bookRows`): in its own frame through `this` (a static call), except under `forge script`,
    ///      which refuses `address(this)` in a script contract (the e2e deploys and `deploy.sh`); there in the script's frame.
    function _bookRows() internal view returns (BookRow[] memory) {
        if (vm.isContext(VmSafe.ForgeContext.ScriptGroup)) return _bookRowsAt(_bookTable());
        return DeployBook(address(this)).bookRows(_bookTable());
    }

    /// @dev The table's kind lists (`bookKinds`), framed as `_bookRows`.
    function _bookKinds() internal view returns (string[] memory, string[] memory) {
        if (vm.isContext(VmSafe.ForgeContext.ScriptGroup)) return _bookKindsAt(_bookTable());
        return DeployBook(address(this)).bookKinds(_bookTable());
    }

    /// @notice NET-ALL-25, the table at `path` as read, whole (review P3-2; `deploybook.py table()` is the twin): every row
    ///         says `private` (`CHAIN_ROW_PRIVATE`), no two rows share the pair (chainId, chainUid) (`CHAIN_PAIR_TAKEN`), and
    ///         a private chain's genesis is in no other row (`CHAIN_UID_PRIVATE`); returns the rows. External and called
    ///         through `this` (a static call, never broadcast): each cheatcode call copies the whole table into memory, so
    ///         it runs in its own frame, whose memory ends with it, and reads the rows in one typed call, never per row and
    ///         field (in the caller's frame those copies grew with every gate of a deploy).
    function bookRows(string calldata path) external view returns (BookRow[] memory) {
        return _bookRowsAt(path);
    }

    /// @dev `bookRows`'s body, in the caller's frame.
    function _bookRowsAt(string memory path) private view returns (BookRow[] memory r) {
        string memory j = vm.readFile(path);
        BookRowKey[] memory ks =
            abi.decode(vm.parseJsonTypeArray(j, ".chains", "ChainUidsKey(string key)"), (BookRowKey[]));
        for (uint256 i; i < ks.length; ++i) {
            if (!vm.keyExistsJson(j, string.concat(".chains[", vm.toString(i), "].private"))) {
                revert(
                    string.concat("CHAIN_ROW_PRIVATE: ", ks[i].key, " in chain-uids.json has no private (true | false)")
                );
            }
        }
        r = abi.decode(
            vm.parseJsonTypeArray(
                j,
                ".chains",
                "ChainUidsRow(uint256 chainId,bytes32 chainUid,string key,string name,string network,bool private)"
            ),
            (BookRow[])
        );
        for (uint256 i; i < r.length; ++i) {
            for (uint256 k; k < i; ++k) {
                if (r[k].chainId == r[i].chainId && r[k].chainUid == r[i].chainUid) {
                    revert(
                        string.concat(
                            "CHAIN_PAIR_TAKEN: ",
                            r[i].key,
                            " repeats the (chainId, chainUid) pair of ",
                            r[k].key,
                            " (NET-ALL-25)"
                        )
                    );
                }
            }
        }
        for (uint256 i; i < r.length; ++i) {
            for (uint256 k; k < r.length && r[i].priv; ++k) {
                if (k != i && r[k].chainUid == r[i].chainUid) {
                    revert(
                        string.concat(
                            "CHAIN_UID_PRIVATE: the private chain ",
                            r[i].key,
                            "'s genesis is also ",
                            r[k].key,
                            "'s (NET-ALL-25)"
                        )
                    );
                }
            }
        }
    }

    /// @notice The table's two kind lists (`homeChainKinds`, `otherKinds`), in their own frame as `bookRows`.
    function bookKinds(string calldata path) external view returns (string[] memory, string[] memory) {
        return _bookKindsAt(path);
    }

    /// @dev `bookKinds`'s body, in the caller's frame.
    function _bookKindsAt(string memory path) private view returns (string[] memory home, string[] memory other) {
        string memory j = vm.readFile(path);
        (home, other) = (vm.parseJsonStringArray(j, ".homeChainKinds"), vm.parseJsonStringArray(j, ".otherKinds"));
    }

    /// @notice NET-ALL-25 (C18), the deploy gate: a kind keeping or checking records bound to `chain_uid` without the chain
    ///         id (`homeChain` records, the registry's portable `UAMsigUpdate` and scoped keys; the table's `homeChainKinds`,
    ///         the one list) is refused on a chain whose `chain_uid` another
    ///         row shares, `HOME_CHAIN_SHARED_GENESIS`; a kind of `otherKinds` passes; a name on neither list is `KIND_UNKNOWN`. `deploybook.py kind_check` is the twin.
    function _requireKindHere(string memory kind, bytes32 uid) internal view {
        (string[] memory ks, string[] memory os) = _bookKinds();
        bool home;
        for (uint256 i; i < ks.length; ++i) {
            if (_bookEq(ks[i], kind)) home = true;
        }
        if (!home) {
            for (uint256 i; i < os.length; ++i) {
                if (_bookEq(os[i], kind)) return;
            }
            revert(
                string.concat("KIND_UNKNOWN: ", kind, " is on neither homeChainKinds nor otherKinds of chain-uids.json")
            );
        }
        BookRow[] memory r = _bookRows();
        for (uint256 i; i < r.length; ++i) {
            if (r[i].chainUid == uid && r[i].chainId != block.chainid) {
                revert(
                    string.concat(
                        "HOME_CHAIN_SHARED_GENESIS: ",
                        kind,
                        " keeps records bound to chain_uid without the chain id; chain ",
                        vm.toString(block.chainid),
                        " shares its chain_uid with ",
                        r[i].key,
                        " (NET-ALL-25)"
                    )
                );
            }
        }
    }

    /// @notice `./deployments/<key><suffix>` of this chain: `.json` its book, `-<what>.json` a companion.
    function _bookPath(bytes32 uid, string memory suffix) internal view returns (string memory) {
        (string memory k,,) = _bookKey(uid);
        return string.concat("./deployments/", k, suffix);
    }

    /// @notice Writes `body` (a JSON object) to `path` behind this chain's header: forge's pretty form (2-space indent,
    ///         the body's key order, which `vm.serialize*` sorts), then the header put first by hand, so the book reads
    ///         `key`, `name`, `chainId`, `chainUid`, `network`, then the rest as forge wrote it (the form of
    ///         `json.dumps(…, indent=2)`).
    function _writeBook(bytes32 uid, string memory path, string memory body) internal {
        (string memory k, string memory n, string memory net) = _bookKey(uid);
        vm.writeJson(body, path);
        bytes memory b = bytes(vm.readFile(path));
        require(b.length >= 2 && b[0] == "{", "a book's body is a JSON object");
        string memory h = string.concat(
            '{\n  "key": "',
            k,
            '",\n  "name": "',
            n,
            '",\n  "chainId": ',
            vm.toString(block.chainid),
            ',\n  "chainUid": "',
            vm.toString(uid),
            '",\n  "network": "',
            net,
            '"'
        );
        if (b[1] != "\n") {
            // an empty body: `{}`
            vm.writeFile(path, string.concat(h, "\n}"));
            return;
        }
        bytes memory rest = new bytes(b.length - 2);
        for (uint256 i; i < rest.length; ++i) {
            rest[i] = b[i + 2];
        }
        vm.writeFile(path, string.concat(h, ",\n", string(rest)));
    }

    /// @notice This chain's book `<key><suffix>`, read and checked; `BOOK_OLD_NAME` when only the old book by chain id
    ///         is there.
    function _readBook(bytes32 uid, string memory suffix) internal view returns (string memory) {
        string memory p = _bookPath(uid, suffix);
        string memory old = string.concat("./deployments/", vm.toString(block.chainid), suffix);
        require(
            vm.exists(p) || !vm.exists(old),
            string.concat(
                "BOOK_OLD_NAME: ",
                old,
                " is named by chain id; rename it to ",
                p,
                " and give it its header (NET-EVM-13)"
            )
        );
        return _checkBook(vm.readFile(p), p);
    }

    /// @notice The book the env var `name` names (a path), else this chain's `<key><suffix>`; read and checked.
    function _envBook(string memory name, bytes32 uid, string memory suffix) internal view returns (string memory) {
        string memory p = vm.envOr(name, string(""));
        return bytes(p).length != 0 ? _checkBook(vm.readFile(p), p) : _readBook(uid, suffix);
    }

    /// @notice A book as read: its header there, its `network` the key's.
    function _checkBook(string memory j, string memory where) internal view returns (string memory) {
        require(
            vm.keyExistsJson(j, ".key") && vm.keyExistsJson(j, ".name") && vm.keyExistsJson(j, ".chainId")
                && vm.keyExistsJson(j, ".chainUid") && vm.keyExistsJson(j, ".network"),
            string.concat(
                "BOOK_HEADER_MISSING: ",
                where,
                " has no key, name, chainId, chainUid, network (a book from before NET-EVM-13)"
            )
        );
        string memory k = vm.parseJsonString(j, ".key");
        string memory net = vm.parseJsonString(j, ".network");
        require(
            _bookEq(net, _networkOf(k)), string.concat("BOOK_NETWORK_MISMATCH: ", where, ": network ", net, ", key ", k)
        );
        return j;
    }

    /// @dev The network a key names: its suffix, else its `chain-uids.json` row's.
    function _networkOf(string memory key) internal view returns (string memory net) {
        net = _bookSuffix(key);
        if (bytes(net).length != 0) return net;
        BookRow[] memory r = _bookRows();
        for (uint256 i; i < r.length; ++i) {
            if (_bookEq(r[i].key, key)) return r[i].network;
        }
        revert(
            string.concat(
                "BOOK_KEY_INVALID: ", key, " ends in neither -mainnet nor -testnet and is not in chain-uids.json"
            )
        );
    }

    function _bookSuffix(string memory s) private pure returns (string memory) {
        bytes memory b = bytes(s);
        if (b.length <= 8) return "";
        bytes memory t = new bytes(8);
        for (uint256 i; i < 8; ++i) {
            t[i] = b[b.length - 8 + i];
        }
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
