// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployBook} from "../../script/DeployBook.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";

contract BookHarness is DeployBook {
    string internal name;

    function setName(string calldata n) external {
        name = n;
    }

    function _deployName() internal view override returns (string memory) {
        return name;
    }

    function key(bytes32 uid) external view returns (string memory, string memory, string memory) {
        return _bookKey(uid);
    }

    function write(bytes32 uid, string calldata path, string calldata body) external {
        _writeBook(uid, path, body);
    }

    function check(string calldata j) external view returns (string memory) {
        return _checkBook(j, "book");
    }

    string internal tablePath;

    function setTable(string calldata p) external {
        tablePath = p;
    }

    function _bookTable() internal view override returns (string memory) {
        return bytes(tablePath).length != 0 ? tablePath : super._bookTable();
    }

    function kind(string calldata k, bytes32 uid) external view {
        _requireKindHere(k, uid);
    }
}

/// NET-EVM-13: a book's key from `chain-uids.json` by (chainId, chain_uid), else `DEPLOY_NAME`, else a named fail; the
/// header first, then the rest in forge's pretty form; a reader checks `network` against the key's suffix.
/// `script/test_deploybook.py` is the Python twin.
contract DeployBookTest is Test {
    bytes32 constant SCAAS_UID = 0x9ae9048bfd6165d6b25290fa9295ad14e38c3e158371b80049d9a554341e5b13;
    bytes32 constant HOODI_UID = 0xbbe312868b376a3001692a646dd2d7d1e4406380dfd86b98aa8a34d1557c971b;
    bytes32 constant AVAX_UID = 0x31ced5b9beb7f8782b014660da0cb18cc409f121f408186886e1ca3e8eeca96b; // 43114 and 43113
    BookHarness h;

    function setUp() public {
        h = new BookHarness();
    }

    function _eq3(
        string memory k,
        string memory n,
        string memory net,
        string memory k2,
        string memory n2,
        string memory net2
    ) internal pure {
        assertEq(k, k2);
        assertEq(n, n2);
        assertEq(net, net2);
    }

    function test_knownChainResolves() public {
        vm.chainId(7622);
        (string memory k, string memory n, string memory net) = h.key(SCAAS_UID);
        _eq3(k, n, net, "scaas-testnet", "SCaaS testnet", "testnet");
        h.setName("scaas-testnet"); // DEPLOY_NAME may name the table's key
        (k, n, net) = h.key(SCAAS_UID);
        _eq3(k, n, net, "scaas-testnet", "SCaaS testnet", "testnet");
        h.setName("other-testnet");
        vm.expectRevert(
            bytes("DEPLOY_NAME_MISMATCH: DEPLOY_NAME=other-testnet, but this chain is scaas-testnet in chain-uids.json")
        );
        h.key(SCAAS_UID);
        vm.chainId(560048); // a second testnet keeps its own name: the table's network
        h.setName("");
        (k, n, net) = h.key(HOODI_UID);
        _eq3(k, n, net, "ethereum-hoodi", "Ethereum Hoodi", "testnet");
    }

    function test_unknownChainNeedsDeployName() public {
        vm.chainId(31337);
        vm.expectRevert(
            bytes(
                "DEPLOY_NAME_REQUIRED: chain 31337 is not in chain-uids.json; set DEPLOY_NAME=<name>-testnet or <name>-mainnet (NET-EVM-13)"
            )
        );
        h.key(bytes32(uint256(1)));
        vm.chainId(7622); // a listed chain id with another genesis (a reset, a copy) is unknown too: no chain-id fallback
        vm.expectRevert(
            bytes(
                "DEPLOY_NAME_REQUIRED: chain 7622 is not in chain-uids.json; set DEPLOY_NAME=<name>-testnet or <name>-mainnet (NET-EVM-13)"
            )
        );
        h.key(bytes32(uint256(1)));
        h.setName("local-testnet");
        (string memory k, string memory n, string memory net) = h.key(bytes32(uint256(1)));
        _eq3(k, n, net, "local-testnet", "local-testnet", "testnet");
        h.setName("local");
        vm.expectRevert(bytes("DEPLOY_NAME_INVALID: local is not <name>-mainnet or <name>-testnet ([a-z0-9-])"));
        h.key(bytes32(uint256(1)));
        h.setName("Local-testnet");
        vm.expectRevert(bytes("DEPLOY_NAME_INVALID: Local-testnet is not <name>-mainnet or <name>-testnet ([a-z0-9-])"));
        h.key(bytes32(uint256(1)));
        h.setName("scaas-testnet"); // the table's key of another chain
        vm.expectRevert(bytes("DEPLOY_NAME_TAKEN: scaas-testnet names another chain in chain-uids.json"));
        h.key(bytes32(uint256(1)));
    }

    function test_headerFirstAndChecked() public {
        vm.chainId(7622);
        string memory p = "./deployments/deploybook-test.json";
        vm.createDir("./deployments", true);
        // the body's keys in its own order (forge's writeJson keeps it), after the header; 2-space indent, as
        // json.dumps(…, indent=2)
        h.write(
            SCAAS_UID,
            p,
            '{"z_last":"0x0000000000000000000000000000000000000002","token_factory":"0x0000000000000000000000000000000000000001","row":{"class":1}}'
        );
        string memory head = string.concat(
            '{\n  "key": "scaas-testnet",\n  "name": "SCaaS testnet",\n  "chainId": 7622,\n',
            '  "chainUid": "',
            vm.toString(SCAAS_UID),
            '",\n  "network": "testnet"'
        );
        string memory b = vm.readFile(p);
        assertEq(
            b,
            string.concat(
                head,
                ',\n  "z_last": "0x0000000000000000000000000000000000000002",\n',
                '  "token_factory": "0x0000000000000000000000000000000000000001",\n  "row": {\n    "class": 1\n  }\n}'
            )
        );
        h.check(b);
        assertEq(vm.parseJsonAddress(b, ".token_factory"), address(1));
        assertEq(vm.parseJsonUint(b, ".row.class"), 1);
        h.write(SCAAS_UID, p, "{}");
        assertEq(vm.readFile(p), string.concat(head, "\n}"));
        h.check(vm.readFile(p));
        vm.removeFile(p);
        // one change at a time: the network, then the key
        string memory u = '"chainUid":"0x01",';
        h.check(string.concat('{"key":"ethereum-hoodi","name":"x","chainId":1,', u, '"network":"testnet"}'));
        vm.expectRevert(bytes("BOOK_NETWORK_MISMATCH: book: network mainnet, key scaas-testnet"));
        h.check(string.concat('{"key":"scaas-testnet","name":"x","chainId":1,', u, '"network":"mainnet"}'));
        vm.expectRevert(bytes("BOOK_NETWORK_MISMATCH: book: network mainnet, key ethereum-hoodi"));
        h.check(string.concat('{"key":"ethereum-hoodi","name":"x","chainId":1,', u, '"network":"mainnet"}'));
        vm.expectRevert(
            bytes(
                "BOOK_HEADER_MISSING: book has no key, name, chainId, chainUid, network (a book from before NET-EVM-13)"
            )
        );
        h.check('{"chain_uid":"0x01","token_factory":"0x0000000000000000000000000000000000000001"}');
    }

    /// NET-ALL-25: the two Avalanche rows (one genesis, chain ids 43114 and 43113) both resolve.
    function test_avalancheRowsResolve() public {
        vm.chainId(43114);
        (string memory k, string memory n, string memory net) = h.key(AVAX_UID);
        _eq3(k, n, net, "avalanche-mainnet", "Avalanche C-Chain", "mainnet");
        vm.chainId(43113);
        (k, n, net) = h.key(AVAX_UID);
        _eq3(k, n, net, "avalanche-testnet", "Avalanche Fuji", "testnet");
    }

    /// NET-ALL-25: a second row of one (chainId, chainUid) pair is refused by name; the same genesis under its own chain id
    /// (public chains sharing one) resolves.
    function test_pairTakenRefused() public {
        string memory p = "./deployments/deploybook-table-test.json";
        vm.createDir("./deployments", true);
        string memory r = string.concat('"chainUid":"', vm.toString(AVAX_UID), '","private":false}');
        vm.writeFile(
            p,
            string.concat(
                '{"chains":[{"key":"avalanche-mainnet","name":"a","chainId":43114,"network":"mainnet",',
                r,
                ',{"key":"copy-testnet","name":"c","chainId":43113,"network":"testnet",',
                r,
                ',{"key":"avalanche-testnet","name":"b","chainId":43113,"network":"testnet",',
                r,
                "]}"
            )
        );
        h.setTable(p);
        vm.chainId(43114);
        (string memory k,,) = h.key(AVAX_UID); // twin: the pair held once
        assertEq(k, "avalanche-mainnet");
        vm.chainId(43113);
        vm.expectRevert(
            bytes(
                "CHAIN_PAIR_TAKEN: avalanche-testnet repeats the (chainId, chainUid) pair of another row (NET-ALL-25)"
            )
        );
        h.key(AVAX_UID);
        vm.removeFile(p);
    }

    /// NET-ALL-25: a private chain's genesis repeated under a new chain id is refused, DEPLOY_NAME or not; its own pair, and
    /// a public chain's genesis under a new chain id, are not.
    function test_privateGenesisRefused() public {
        vm.chainId(7623);
        bytes memory e = bytes(
            "CHAIN_UID_PRIVATE: chain 7623 has the genesis of the private chain scaas-testnet; a chain we run that forks is a new chain with its own genesis (NET-ALL-25)"
        );
        vm.expectRevert(e);
        h.key(SCAAS_UID);
        h.setName("fork-testnet");
        vm.expectRevert(e);
        h.key(SCAAS_UID);
        (string memory k,,) = h.key(bytes32(uint256(1))); // twin: its own genesis
        assertEq(k, "fork-testnet");
        vm.chainId(43112); // twin: a public chain's genesis under a new chain id
        h.setName("avax-copy-testnet");
        (k,,) = h.key(AVAX_UID);
        assertEq(k, "avax-copy-testnet");
        vm.chainId(7622); // twin: the private chain itself
        h.setName("");
        (k,,) = h.key(SCAAS_UID);
        assertEq(k, "scaas-testnet");
    }

    /// NET-ALL-25 (C18): the deploy gate refuses `PqChat`, `OpenFactory` and `PqVault` on a genesis another row shares, and
    /// passes `PqChatStore` there; on a genesis no other row shares, every kind passes.
    function test_homeChainKindsRefused() public {
        string[4] memory ks = ["PqChat", "OpenFactory", "PqVault", "UARegistry"];
        uint256[2] memory ids = [uint256(43114), 43113];
        for (uint256 c; c < 2; ++c) {
            vm.chainId(ids[c]);
            string memory other = c == 0 ? "avalanche-testnet" : "avalanche-mainnet";
            for (uint256 i; i < 4; ++i) {
                vm.expectRevert(
                    bytes(
                        string.concat(
                            "HOME_CHAIN_SHARED_GENESIS: ",
                            ks[i],
                            " keeps records bound to chain_uid without the chain id; chain ",
                            vm.toString(ids[c]),
                            " shares its chain_uid with ",
                            other,
                            " (NET-ALL-25)"
                        )
                    )
                );
                h.kind(ks[i], AVAX_UID);
            }
            h.kind("PqChatStore", AVAX_UID); // twin: the store keeps no homeChain record
        }
        vm.chainId(7622);
        for (uint256 i; i < 4; ++i) {
            h.kind(ks[i], SCAAS_UID); // twin: a genesis no other row shares
        }
    }

    /// Review P3-1: a kind name on neither list of the table (a typo) is refused by name; the gate sits where the factory and
    /// PqChat are created (`_deployTokenFactory`, `_deployPqChat`), so no script that creates them skips it.
    function test_kindGateWhereCreated() public {
        vm.expectRevert(bytes("KIND_UNKNOWN: PqChatt is on neither homeChainKinds nor otherKinds of chain-uids.json"));
        h.kind("PqChatt", SCAAS_UID);
        h.kind("PqChatStore", AVAX_UID); // twin: a kind of the other list
        DeployHarness d = new DeployHarness();
        d.setTxGasCap(1 << 24);
        vm.chainId(43113);
        vm.expectRevert(
            bytes(
                "HOME_CHAIN_SHARED_GENESIS: OpenFactory keeps records bound to chain_uid without the chain id; chain 43113 shares its chain_uid with avalanche-mainnet (NET-ALL-25)"
            )
        );
        d.deploy(AVAX_UID, false, address(0));
        vm.expectRevert(
            bytes(
                "HOME_CHAIN_SHARED_GENESIS: PqChat keeps records bound to chain_uid without the chain id; chain 43113 shares its chain_uid with avalanche-mainnet (NET-ALL-25)"
            )
        );
        d.deployPqChatOnly(AVAX_UID);
    }

    /// NET-ALL-25 (review P1-2): the UA registry is refused where it is created, the gen-1 deploy (`_deployUARegistry`, under
    /// `Deploy.s.sol` and `DeployHedera.s.sol`) and a later generation (`_deployUARegistryGen`, `DeployUAGen.s.sol`), before
    /// anything else of that path.
    function test_registryRefusedOnSharedGenesis() public {
        DeployHarness d = new DeployHarness();
        d.setTxGasCap(1 << 24);
        vm.chainId(43113);
        bytes memory e = bytes(
            "HOME_CHAIN_SHARED_GENESIS: UARegistry keeps records bound to chain_uid without the chain id; chain 43113 shares its chain_uid with avalanche-mainnet (NET-ALL-25)"
        );
        vm.expectRevert(e);
        d.deployRegistry(AVAX_UID);
        vm.expectRevert(e);
        d.deployGen(AVAX_UID, address(0), "{}");
        vm.chainId(7622); // twin: the gate passes, the gen mode then refuses the empty book by its own check
        vm.expectRevert();
        d.deployGen(SCAAS_UID, address(0), "{}");
    }
}
