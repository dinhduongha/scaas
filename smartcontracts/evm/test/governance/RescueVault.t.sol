// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {RescueVault} from "../../src/governance/RescueVault.sol";
import {RescueLib} from "../../src/governance/RescueLib.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {DeployRescueVault} from "../../script/DeployRescueVault.s.sol";

/// CTR-GOV-25 Change (owner 2026-11-12, spec superpowers/specs/2026-11-12-rescue-vault.md): the dev rescue destination is a
/// one-owner `RescueVault` at one CREATE2 address on every chain. `withdraw(token, amount, to)`: anyone; the owner with `to`
/// not 0 pays `to`, every other call pays the owner. `rotate`: the owner's chain-neutral signature, `seq == seq() + 1`.
contract RescueVaultTest is Test {
    address constant DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes constant DEPLOYER_CODE = hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";
    bytes32 constant SALT = keccak256("scaas.rescue-vault.v1");
    address constant DEV_EOA = 0x0389f77E846ff687d44db57bcC9DCB55dd6f4131;
    address constant STRANGER = address(0x5757);
    address constant PAYEE = address(0xBEEF);
    string constant KAT = "../vectors/governance/rescue_vault_kat.json";
    string constant INIT = "./rescue-vault-init.hex";
    uint256 constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    uint256 internal aliceKey = 0xA11CE;
    uint256 internal bobKey = 0xB0B;
    address internal alice = vm.addr(aliceKey);
    address internal bob = vm.addr(bobKey);
    MockERC20 internal foo = new MockERC20("FOO", "FOO", 18);
    RescueVault internal v = new RescueVault(alice);

    function _deploy(address initialOwner) internal returns (address a) {
        if (DEPLOYER.code.length == 0) vm.etch(DEPLOYER, DEPLOYER_CODE);
        (bool ok, bytes memory ret) =
            DEPLOYER.call(abi.encodePacked(SALT, type(RescueVault).creationCode, abi.encode(initialOwner)));
        require(ok && ret.length == 20, "deploy");
        a = address(bytes20(ret));
    }

    function _sign(uint256 key, RescueVault w, uint64 seq_, address newOwner) internal view returns (bytes memory) {
        (uint8 v_, bytes32 r, bytes32 s) = vm.sign(key, w.rotateDigest(seq_, newOwner));
        return abi.encodePacked(r, s, v_);
    }

    // ------------------------------------------------------------------ the address

    /// The committed init code `rescue-vault-init.hex` is what the deploy script sends: its keccak gives the constant, so a
    /// later compiler cannot move the address; deploying it gives the dev EOA as owner and keeps a counterfactual balance.
    function test_addressIsTheConstant() public {
        bytes memory init = vm.parseBytes(vm.readFile(INIT));
        assertEq(keccak256(init), 0x6e3fba8f9e78c33c4903c66e7836ca0e858f6fb48f9320b8117728572000c677, "init code pin");
        address a = vm.computeCreate2Address(SALT, keccak256(init), DEPLOYER);
        assertEq(a, RescueLib.SCAAS_DEV_RESCUE, "the constant");
        vm.deal(a, 3 ether); // counterfactual: funds before the vault exists
        if (DEPLOYER.code.length == 0) vm.etch(DEPLOYER, DEPLOYER_CODE);
        (bool ok, bytes memory ret) = DEPLOYER.call(abi.encodePacked(SALT, init));
        assertTrue(ok && ret.length == 20 && address(bytes20(ret)) == a, "deploys at the constant");
        assertEq(RescueVault(payable(a)).owner(), DEV_EOA);
        assertEq(RescueVault(payable(a)).seq(), 0);
        assertEq(a.balance, 3 ether, "the balance survives the deploy");
        (ok,) = DEPLOYER.call{gas: 1_000_000}(abi.encodePacked(SALT, init)); // a second deploy fails: one per chain
        assertFalse(ok);
    }

    /// The source compiled today gives exactly the committed bytes, so every other test here (on the compiled source) tests
    /// the deployed vault. An edit of `RescueVault.sol`, an import or a compiler setting fails here; the artifact stays the
    /// deploy truth.
    function test_artifactIsTheSource() public view {
        assertEq(keccak256(type(RescueVault).creationCode), 0x1852908124267432d15f20cf5efecc80bf62b5957de0cdf1a9d2026597d85047, "creation code pin");
        assertEq(abi.encodePacked(type(RescueVault).creationCode, abi.encode(DEV_EOA)), vm.parseBytes(vm.readFile(INIT)));
    }

    function test_zeroInitialOwnerRefused() public {
        vm.expectRevert(RescueVault.OwnerInvalid.selector);
        new RescueVault(address(0));
    }

    // ------------------------------------------------------------------ withdraw

    function test_ownerWithdrawsToTo() public {
        foo.mint(address(v), 10);
        vm.deal(address(v), 2 ether);
        vm.expectEmit(address(v));
        emit RescueVault.Withdrawn(address(foo), PAYEE, 4, alice);
        vm.prank(alice);
        v.withdraw(address(foo), 4, PAYEE);
        vm.prank(alice);
        v.withdraw(address(0), 1 ether, PAYEE);
        assertEq(foo.balanceOf(PAYEE), 4);
        assertEq(PAYEE.balance, 1 ether);
        assertEq(foo.balanceOf(alice) + alice.balance, 0, "nothing to the owner");
    }

    /// The owner with `to` 0 pays the owner (owner 2026-11-12, "chủ gọi, nhưng to = 0 thì cũng về địa chỉ chủ").
    function test_ownerWithZeroToPaysTheOwner() public {
        foo.mint(address(v), 10);
        vm.deal(address(v), 2 ether);
        vm.prank(alice);
        v.withdraw(address(foo), 3, address(0));
        vm.prank(alice);
        v.withdraw(address(0), 1 ether, address(0));
        assertEq(foo.balanceOf(alice), 3);
        assertEq(alice.balance, 1 ether);
    }

    /// Anyone else pays the owner; the stranger's `to` is ignored.
    function test_strangerPaysTheOwner() public {
        foo.mint(address(v), 10);
        vm.deal(address(v), 2 ether);
        vm.expectEmit(address(v));
        emit RescueVault.Withdrawn(address(foo), alice, 5, STRANGER);
        vm.prank(STRANGER);
        v.withdraw(address(foo), 5, PAYEE);
        vm.prank(STRANGER);
        v.withdraw(address(0), 1 ether, PAYEE);
        vm.prank(STRANGER);
        v.withdraw(address(0), 1 ether, address(0));
        assertEq(foo.balanceOf(alice), 5);
        assertEq(alice.balance, 2 ether);
        assertEq(foo.balanceOf(PAYEE) + PAYEE.balance + foo.balanceOf(STRANGER) + STRANGER.balance, 0);
    }

    /// An owner that is an EIP-7702 designator cannot direct funds (an EOA runs no code); a call that pays it still works.
    function test_designatorOwnerCannotDirect() public {
        foo.mint(address(v), 10);
        vm.etch(alice, abi.encodePacked(hex"ef0100", address(0xC0DE)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.CallerDelegated.selector, alice));
        v.withdraw(address(foo), 1, PAYEE);
        vm.prank(alice); // control: to 0 pays the owner (an ERC-20, no code runs there)
        v.withdraw(address(foo), 1, address(0));
        vm.prank(STRANGER);
        v.withdraw(address(foo), 1, address(0));
        assertEq(foo.balanceOf(alice), 2);
    }

    /// The native coin is refused to a designator destination (as `RescueLib.send`); an ERC-20 goes.
    function test_nativeRefusedToADesignator() public {
        foo.mint(address(v), 10);
        vm.deal(address(v), 1 ether);
        vm.etch(PAYEE, abi.encodePacked(hex"ef0100", address(0xC0DE)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.ToInvalid.selector, PAYEE));
        v.withdraw(address(0), 1, PAYEE);
        vm.prank(alice);
        v.withdraw(address(foo), 1, PAYEE);
        assertEq(foo.balanceOf(PAYEE), 1);
        address o = makeAddr("plain");
        vm.prank(alice); // control: a plain address takes the native coin
        v.withdraw(address(0), 1, o);
        assertEq(o.balance, 1);
    }

    // ------------------------------------------------------------------ rotate

    function test_rotateThenOldOwnerIsAStranger() public {
        bytes memory sig = _sign(aliceKey, v, 1, bob);
        vm.expectEmit(address(v));
        emit RescueVault.Rotated(1, alice, bob);
        vm.prank(STRANGER); // anyone submits
        v.rotate(1, bob, sig);
        assertEq(v.owner(), bob);
        assertEq(v.seq(), 1);
        foo.mint(address(v), 10);
        vm.prank(alice);
        v.withdraw(address(foo), 4, PAYEE); // the old owner now pays the new one
        assertEq(foo.balanceOf(bob), 4);
        assertEq(foo.balanceOf(PAYEE), 0);
        vm.prank(bob);
        v.withdraw(address(foo), 6, PAYEE);
        assertEq(foo.balanceOf(PAYEE), 6);
        bytes memory old = _sign(aliceKey, v, 2, alice);
        bytes memory cur = _sign(bobKey, v, 2, alice);
        vm.expectRevert(RescueVault.SignatureInvalid.selector); // the old key no longer rotates
        v.rotate(2, alice, old);
        v.rotate(2, alice, cur); // control
        assertEq(v.owner(), alice);
    }

    function test_rotateStaleOrSkippedSeqRefused() public {
        bytes memory sig = _sign(aliceKey, v, 1, bob);
        bytes memory skipped = _sign(aliceKey, v, 2, bob);
        bytes memory stale = _sign(aliceKey, v, 0, bob);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.SeqInvalid.selector, 1, 2));
        v.rotate(2, bob, skipped);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.SeqInvalid.selector, 1, 0));
        v.rotate(0, bob, stale);
        v.rotate(1, bob, sig);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.SeqInvalid.selector, 2, 1));
        v.rotate(1, bob, sig); // replayed
    }

    function test_rotateBadSignaturesRefused() public {
        bytes memory good = _sign(aliceKey, v, 1, bob);
        bytes memory notOwner = _sign(bobKey, v, 1, bob);
        bytes memory otherVault = _sign(aliceKey, new RescueVault(alice), 1, bob);
        bytes memory zero = _sign(aliceKey, v, 1, address(0));
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.rotate(1, bob, notOwner);
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.rotate(1, PAYEE, good); // another newOwner than signed
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.rotate(1, bob, otherVault); // another vault's domain
        (uint8 v_, bytes32 r, bytes32 s) = vm.sign(aliceKey, v.rotateDigest(1, bob));
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.rotate(1, bob, abi.encodePacked(r, bytes32(N - uint256(s)), v_ == 27 ? uint8(28) : uint8(27))); // high-s twin
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.rotate(1, bob, abi.encodePacked(r, s)); // 64 bytes
        vm.expectRevert(RescueVault.OwnerInvalid.selector);
        v.rotate(1, address(0), zero);
        v.rotate(1, bob, good); // control
        assertEq(v.owner(), bob);
    }

    /// A rotation is chain-neutral: signed once, it brings a vault deployed later at the same address on another chain (another
    /// chain id, another history) to the same owner, once.
    function test_rotationReplaysOnASecondChain() public {
        uint256 before = vm.snapshotState();
        vm.chainId(7622);
        RescueVault a = RescueVault(payable(_deploy(alice)));
        bytes memory sig1 = _sign(aliceKey, a, 1, bob);
        bytes memory sig2 = _sign(bobKey, a, 2, PAYEE);
        a.rotate(1, bob, sig1);
        a.rotate(2, PAYEE, sig2);
        assertEq(a.owner(), PAYEE);

        vm.revertToState(before); // a fresh chain: no vault yet
        vm.chainId(1);
        vm.roll(block.number + 1000);
        vm.warp(block.timestamp + 1 days);
        assertEq(address(a).code.length, 0);
        RescueVault b = RescueVault(payable(_deploy(alice)));
        assertEq(address(b), address(a), "one address");
        assertEq(b.owner(), alice, "the first owner until caught up");
        vm.expectRevert(abi.encodeWithSelector(RescueVault.SeqInvalid.selector, 1, 2));
        b.rotate(2, PAYEE, sig2); // out of order
        b.rotate(1, bob, sig1);
        b.rotate(2, PAYEE, sig2);
        assertEq(b.owner(), PAYEE);
        assertEq(b.seq(), 2);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.SeqInvalid.selector, 3, 2));
        b.rotate(2, PAYEE, sig2);
    }

    // ------------------------------------------------------------------ a real rescue pays the vault

    /// `RescueLib` refuses only a designator destination: a singleton's `rescue` pays the deployed vault (an ERC-20 and the
    /// native coin), and anyone then sweeps it to the dev EOA.
    function test_realRescuePaysTheVault() public {
        address vault = _deploy(DEV_EOA);
        assertEq(vault, RescueLib.SCAAS_DEV_RESCUE);
        RelayFeeRouter r = new RelayFeeRouter();
        foo.mint(address(r), 7);
        vm.deal(address(r), 1 ether);
        r.rescue(address(foo));
        r.rescue(address(0));
        assertEq(foo.balanceOf(vault), 7);
        assertEq(vault.balance, 1 ether);
        vm.startPrank(STRANGER);
        RescueVault(payable(vault)).withdraw(address(foo), 7, address(0));
        RescueVault(payable(vault)).withdraw(address(0), 1 ether, PAYEE);
        vm.stopPrank();
        assertEq(foo.balanceOf(DEV_EOA), 7);
        assertEq(DEV_EOA.balance, 1 ether);
    }

    // ------------------------------------------------------------------ the deploy script

    /// `DeployRescueVault`: deploys at the constant, then applies the log from the vault's `seq() + 1`; a second run with the
    /// same log is a no-op. The dev key is not here, so the test hands the deployed vault to `alice` (slot 0, `seq` 0 kept).
    function test_deployScriptDeploysAndCatchesUp() public {
        vm.etch(DEPLOYER, DEPLOYER_CODE);
        DeployRescueVault s = new DeployRescueVault();
        vm.setEnv("RESCUE_VAULT_LOG", "./rescue-vault-rotations.json"); // the committed log
        s.run();
        RescueVault w = RescueVault(payable(RescueLib.SCAAS_DEV_RESCUE));
        assertEq(w.owner(), DEV_EOA, "the committed log is empty");
        vm.store(address(w), bytes32(0), bytes32(uint256(uint160(alice))));
        string memory path = "./deployments/rescue-vault-log.test.json";
        vm.createDir("./deployments", true);
        vm.writeFile(path, string.concat(
            '[{"seq":1,"newOwner":"', vm.toString(bob), '","sig":"', vm.toString(_sign(aliceKey, w, 1, bob)), '"},',
            '{"seq":2,"newOwner":"', vm.toString(PAYEE), '","sig":"', vm.toString(_sign(bobKey, w, 2, PAYEE)), '"}]'));
        vm.setEnv("RESCUE_VAULT_LOG", path);
        s.run();
        assertEq(w.owner(), PAYEE);
        assertEq(w.seq(), 2);
        s.run(); // again: every row skipped
        assertEq(w.seq(), 2);
        vm.removeFile(path);
    }

    // ------------------------------------------------------------------ KAT (clientkeys)

    /// The rotation digest of the vault at the constant address for fixed fields; `WRITE_RESCUE_VAULT=true` writes the file.
    function test_rotateKat() public {
        RescueVault w = RescueVault(payable(_deploy(DEV_EOA)));
        address newOwner = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF;
        string memory j = string.concat(
            "{\n",
            '  "_comment": "Generated by smartcontracts/evm/test/governance/RescueVault.t.sol (WRITE_RESCUE_VAULT=true); spec superpowers/specs/2026-11-12-rescue-vault.md",\n',
            '  "vault": "', vm.toString(address(w)), '",\n',
            '  "rotateTypehash": "', vm.toString(w.ROTATE_TYPEHASH()), '",\n',
            '  "seq": 1,\n',
            '  "newOwner": "', vm.toString(newOwner), '",\n',
            '  "digest": "', vm.toString(w.rotateDigest(1, newOwner)), '"\n',
            "}\n"
        );
        if (vm.envOr("WRITE_RESCUE_VAULT", false)) vm.writeFile(KAT, j);
        assertEq(vm.readFile(KAT), j, "rescue_vault_kat.json is stale: WRITE_RESCUE_VAULT=true");
    }
}
