// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";

/// Chain-neutral spec §6.2 (Fable P3-5; plan T73): the release list. The first chain's deploy writes it
/// (`RELEASES_WRITE`); a second chain (another `chain_uid`, the same deployer and salt) deploys the factory, the libraries
/// and every release at the listed addresses with the listed code hashes, so its deploy passes the list; a list naming
/// another code hash or address is refused by name. The factory's `chainUid()` and one instance's are each chain's own
/// (`_gateInstance`). **UNAUDITED.**
contract ReleaseListTest is Test {
    bytes32 constant UID_A = keccak256("chain A");
    bytes32 constant UID_B = keccak256("chain B");
    string constant PATH = "./deployments/releases-test-a.json";
    string constant PATH2 = "./deployments/releases-test-b.json";
    DeployHarness h;

    function setUp() public {
        vm.warp(1_800_000_000);
        vm.createDir("./deployments", true);
        h = new DeployHarness();
    }

    function _deployOn(bytes32 uid, uint256 chainId, bool write) internal returns (OpenFactory f) {
        vm.chainId(chainId);
        h.setReleases(PATH, write);
        (f,) = h.deploy(uid, false, address(0));
        if (write) h.writeReleases();
    }

    function test_releaseList_secondChainMatchesTheFirst() public {
        uint256 snap = vm.snapshotState();
        OpenFactory a = _deployOn(UID_A, 31337, true);
        address relA = a.implementationOf(IOpenFactory.TokenKind.NORMAL, 1);
        address dexA = a.dexImplementationOf(1);
        string memory file = vm.readFile(PATH);
        assertEq(vm.parseJsonAddress(file, ".OpenFactory.address"), address(a));
        assertEq(vm.parseJsonAddress(file, ".NormalToken.address"), relA);
        assertEq(vm.parseJsonBytes32(file, ".NormalToken.codeHash"), relA.codehash);
        assertEq(vm.parseJsonAddress(file, ".SCaaSDex.address"), dexA);
        assertEq(vm.parseJsonUint(file, ".SCaaSDex.class"), 2);
        assertEq(vm.parseJsonAddress(file, ".admin.address"), address(h));
        // NET-EVM-13: the book header first (the harness's chain: DEPLOY_NAME local-testnet)
        assertEq(vm.indexOf(file, '{\n  "key": "local-testnet",\n  "name": "local-testnet",\n  "chainId": 31337,\n  "chainUid": "'), 0);
        assertEq(vm.parseJsonString(file, ".network"), "testnet");
        assertEq(vm.parseJsonBytes32(file, ".chainUid"), UID_A);
        assertEq(a.chainUid(), UID_A);
        vm.revertToState(snap);
        // the second chain: the same addresses, its own chain_uid; the list's reader passes
        OpenFactory b = _deployOn(UID_B, 31338, false);
        assertEq(address(b), address(a), "the factory's address on every chain");
        assertEq(b.implementationOf(IOpenFactory.TokenKind.NORMAL, 1), relA, "a release's address on every chain");
        assertEq(b.dexImplementationOf(1), dexA);
        assertEq(b.chainUid(), UID_B);
        vm.removeFile(PATH);
    }

    function test_releaseList_anotherCodeHashOrAddressRefused() public {
        uint256 snap = vm.snapshotState();
        vm.chainId(31337);
        h.setReleases(PATH2, true);
        h.deploy(UID_A, false, address(0));
        h.writeReleases();
        string memory good = vm.readFile(PATH2);
        vm.revertToState(snap);
        h.setReleases(PATH2, false);
        vm.chainId(31338);
        // another code hash for the NORMAL release
        vm.writeJson(string.concat('"', vm.toString(keccak256("other code")), '"'), PATH2, ".NormalToken.codeHash");
        vm.expectRevert(bytes("release list: NormalToken with another code hash"));
        h.deploy(UID_B, false, address(0));
        // another address for the factory
        vm.writeFile(PATH2, good);
        vm.writeJson(string.concat('"', vm.toString(address(0xF00D)), '"'), PATH2, ".OpenFactory.address");
        vm.expectRevert(bytes("release list: OpenFactory at another address"));
        h.deploy(UID_B, false, address(0));
        // NET-EVM-13: a header whose network is not its key's, or no header
        vm.writeFile(PATH2, good);
        vm.writeJson('"mainnet"', PATH2, ".network");
        vm.expectRevert(bytes("BOOK_NETWORK_MISMATCH: ./deployments/releases-test-b.json: network mainnet, key local-testnet"));
        h.deploy(UID_B, false, address(0));
        vm.writeFile(PATH2, good);
        vm.writeJson('"local"', PATH2, ".key");
        vm.expectRevert(bytes("BOOK_KEY_INVALID: local ends in neither -mainnet nor -testnet and is not in chain-uids.json"));
        h.deploy(UID_B, false, address(0));
        vm.writeFile(PATH2, vm.replace(good, '"key": "local-testnet"', '"keyX": "local-testnet"'));
        vm.expectRevert(bytes("BOOK_HEADER_MISSING: ./deployments/releases-test-b.json has no key, name, chainId, chainUid, network (a book from before NET-EVM-13)"));
        h.deploy(UID_B, false, address(0));
        // positive control: the list as written
        vm.writeFile(PATH2, good);
        h.deploy(UID_B, false, address(0));
        vm.removeFile(PATH2);
    }
}
