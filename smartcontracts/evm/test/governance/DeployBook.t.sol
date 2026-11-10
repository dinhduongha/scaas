// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployBook} from "../../script/DeployBook.sol";

contract BookHarness is DeployBook {
    string internal name;

    function setName(string calldata n) external { name = n; }

    function _deployName() internal view override returns (string memory) { return name; }

    function key(bytes32 uid) external view returns (string memory, string memory, string memory) { return _bookKey(uid); }

    function header(bytes32 uid, string calldata body) external view returns (string memory) { return _bookHeader(uid, body); }

    function check(string calldata j) external view returns (string memory) { return _checkBook(j, "book"); }
}

/// NET-EVM-13: a book's key from `chain-uids.json` by (chainId, chain_uid), else `DEPLOY_NAME`, else a named fail; the
/// header first; a reader checks `network` against the key's suffix. `script/test_deploybook.py` is the Python twin.
contract DeployBookTest is Test {
    bytes32 constant SCAAS_UID = 0xf1f491abec46eb7c1784b7fc75a0174171b41831530e510c46b7178c02d63164;
    bytes32 constant HOODI_UID = 0xbbe312868b376a3001692a646dd2d7d1e4406380dfd86b98aa8a34d1557c971b;
    BookHarness h;

    function setUp() public {
        h = new BookHarness();
    }

    function _eq3(string memory k, string memory n, string memory net, string memory k2, string memory n2, string memory net2)
        internal
        pure
    {
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
        vm.expectRevert(bytes("DEPLOY_NAME_MISMATCH: DEPLOY_NAME=other-testnet, but this chain is scaas-testnet in chain-uids.json"));
        h.key(SCAAS_UID);
        vm.chainId(560048); // a second testnet keeps its own name: the table's network
        h.setName("");
        (k, n, net) = h.key(HOODI_UID);
        _eq3(k, n, net, "ethereum-hoodi", "Ethereum Hoodi", "testnet");
    }

    function test_unknownChainNeedsDeployName() public {
        vm.chainId(31337);
        vm.expectRevert(bytes("DEPLOY_NAME_REQUIRED: chain 31337 is not in chain-uids.json; set DEPLOY_NAME=<name>-testnet or <name>-mainnet (NET-EVM-13)"));
        h.key(bytes32(uint256(1)));
        vm.chainId(7622); // a listed chain id with another genesis (a reset, a copy) is unknown too: no chain-id fallback
        vm.expectRevert(bytes("DEPLOY_NAME_REQUIRED: chain 7622 is not in chain-uids.json; set DEPLOY_NAME=<name>-testnet or <name>-mainnet (NET-EVM-13)"));
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
        string memory b = h.header(SCAAS_UID, '{"token_factory":"0x0000000000000000000000000000000000000001"}');
        assertEq(b, string.concat('{"key":"scaas-testnet","name":"SCaaS testnet","chainId":7622,"chainUid":"',
            vm.toString(SCAAS_UID), '","network":"testnet","token_factory":"0x0000000000000000000000000000000000000001"}'));
        h.check(b);
        assertEq(vm.parseJsonAddress(b, ".token_factory"), address(1));
        h.check(h.header(SCAAS_UID, "{}"));
        // one change at a time: the network, then the key
        string memory u = '"chainUid":"0x01",';
        h.check(string.concat('{"key":"ethereum-hoodi","name":"x","chainId":1,', u, '"network":"testnet"}'));
        vm.expectRevert(bytes("BOOK_NETWORK_MISMATCH: book: network mainnet, key scaas-testnet"));
        h.check(string.concat('{"key":"scaas-testnet","name":"x","chainId":1,', u, '"network":"mainnet"}'));
        vm.expectRevert(bytes("BOOK_NETWORK_MISMATCH: book: network mainnet, key ethereum-hoodi"));
        h.check(string.concat('{"key":"ethereum-hoodi","name":"x","chainId":1,', u, '"network":"mainnet"}'));
        vm.expectRevert(bytes("BOOK_HEADER_MISSING: book has no key, name, chainId, chainUid, network (a book from before NET-EVM-13)"));
        h.check('{"chain_uid":"0x01","token_factory":"0x0000000000000000000000000000000000000001"}');
    }
}
