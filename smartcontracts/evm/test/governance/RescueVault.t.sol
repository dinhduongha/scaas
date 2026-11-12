// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {RescueVault} from "../../src/governance/RescueVault.sol";
import {RescueLib} from "../../src/governance/RescueLib.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {DeployRescueVault} from "../../script/DeployRescueVault.s.sol";
import {NoReturnERC20} from "../v2/DexOutside.t.sol";

/// CTR-GOV-25 Change (owner 2026-11-12, spec superpowers/specs/2026-11-12-rescue-vault.md): the dev rescue destination is a
/// `RescueVault` at one CREATE2 address on every chain, two roles. `rescuer` receives: `withdraw(token, amount, to)` by
/// anyone; the rescuer with `to` not 0 pays `to`, every other call pays the rescuer. `admin` (a native UA) only administers:
/// `setRescuer` and `rotateAdmin`, its chain-neutral signature, one shared `seq == seq() + 1`.
contract RescueVaultTest is Test {
    address constant DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes constant DEPLOYER_CODE = hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";
    bytes32 constant SALT = keccak256("scaas.rescue-vault.v1");
    address constant DEV_EOA = 0x0389f77E846ff687d44db57bcC9DCB55dd6f4131; // the first rescuer
    address constant ADMIN = 0xAb92b0E9bD2E18F7003c30dAFE93Ef9bc3e1248C; // the first admin, as a native UA (owner 2026-11-12)
    address constant STRANGER = address(0x5757);
    address constant PAYEE = address(0xBEEF);
    string constant KAT = "../vectors/governance/rescue_vault_kat.json";
    string constant INIT = "./rescue-vault-init.hex";
    uint256 constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    uint256 internal aliceKey = 0xA11CE;
    uint256 internal bobKey = 0xB0B;
    address internal alice = vm.addr(aliceKey); // the admin
    address internal bob = vm.addr(bobKey);
    address internal res = makeAddr("rescuer"); // the rescuer
    MockERC20 internal foo = new MockERC20("FOO", "FOO", 18);
    RescueVault internal v = new RescueVault(_ua(alice), res);

    function _ua(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _deploy(bytes32 admin, address rescuer) internal returns (address a) {
        if (DEPLOYER.code.length == 0) vm.etch(DEPLOYER, DEPLOYER_CODE);
        (bool ok, bytes memory ret) =
            DEPLOYER.call(abi.encodePacked(SALT, type(RescueVault).creationCode, abi.encode(admin, rescuer)));
        require(ok && ret.length == 20, "deploy");
        a = address(bytes20(ret));
    }

    function _sig(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v_, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v_);
    }

    function _signRescuer(uint256 key, RescueVault w, uint64 seq_, address r) internal view returns (bytes memory) {
        return _sig(key, w.setRescuerDigest(seq_, r));
    }

    function _signAdmin(uint256 key, RescueVault w, uint64 seq_, bytes32 a) internal view returns (bytes memory) {
        return _sig(key, w.rotateAdminDigest(seq_, a));
    }

    // ------------------------------------------------------------------ the address

    /// The committed init code `rescue-vault-init.hex` is what the deploy script sends: its keccak gives the constant, so a
    /// later compiler cannot move the address; deploying it gives `ADMIN` as admin (a native UA) and the dev EOA as rescuer,
    /// and keeps a counterfactual balance.
    function test_addressIsTheConstant() public {
        bytes memory init = vm.parseBytes(vm.readFile(INIT));
        assertEq(keccak256(init), 0xd42ad5b70d9fb69e4881bcb241d6053df3da0b7818a21e635d92d549d1dcd4fd, "init code pin");
        address a = vm.computeCreate2Address(SALT, keccak256(init), DEPLOYER);
        assertEq(a, RescueLib.SCAAS_DEV_RESCUE, "the constant");
        vm.deal(a, 3 ether); // counterfactual: funds before the vault exists
        if (DEPLOYER.code.length == 0) vm.etch(DEPLOYER, DEPLOYER_CODE);
        (bool ok, bytes memory ret) = DEPLOYER.call(abi.encodePacked(SALT, init));
        assertTrue(ok && ret.length == 20 && address(bytes20(ret)) == a, "deploys at the constant");
        assertEq(RescueVault(payable(a)).admin(), _ua(ADMIN));
        assertEq(RescueVault(payable(a)).rescuer(), DEV_EOA);
        assertEq(RescueVault(payable(a)).seq(), 0);
        assertEq(a.balance, 3 ether, "the balance survives the deploy");
        (ok,) = DEPLOYER.call{gas: 1_000_000}(abi.encodePacked(SALT, init)); // a second deploy fails: one per chain
        assertFalse(ok);
    }

    /// The source compiled today gives exactly the committed bytes, so every other test here (on the compiled source) tests
    /// the deployed vault. An edit of `RescueVault.sol`, an import or a compiler setting fails here; the artifact stays the
    /// deploy truth.
    function test_artifactIsTheSource() public view {
        assertEq(keccak256(type(RescueVault).creationCode), 0xa103dbdc3ecd0a1fc6cd1c96fe8bd904a07b7c5c55cc809eb4e466dcc153dc66, "creation code pin");
        assertEq(abi.encodePacked(type(RescueVault).creationCode, abi.encode(_ua(ADMIN), DEV_EOA)), vm.parseBytes(vm.readFile(INIT)));
    }

    /// The admin is a native UA (not 0, high 96 bits 0); the rescuer is not 0.
    function test_constructorRefusesBadValues() public {
        bytes32 derived = bytes32(uint256(uint160(alice)) | (uint256(1) << 160));
        vm.expectRevert(abi.encodeWithSelector(RescueVault.AdminInvalid.selector, bytes32(0)));
        new RescueVault(bytes32(0), res);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.AdminInvalid.selector, derived));
        new RescueVault(derived, res);
        vm.expectRevert(RescueVault.RescuerInvalid.selector);
        new RescueVault(_ua(alice), address(0));
        new RescueVault(_ua(alice), res); // control
    }

    /// ERC-5267: a tool that builds the domain from `eip712Domain()` alone (bit 0 name, 1 version, 2 chainId,
    /// 3 verifyingContract, 4 salt) gets the digests the vault checks. A wrong field set (0x0d: chainId instead of version)
    /// gives another digest and fails here.
    function test_eip712DomainRebuildsTheDigest() public view {
        (bytes1 f, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt, uint256[] memory ext) =
            v.eip712Domain();
        assertEq(ext.length, 0);
        string memory t = "EIP712Domain(";
        bytes memory enc;
        string memory sep = "";
        if (uint8(f) & 0x01 != 0) { t = string.concat(t, "string name"); enc = abi.encode(keccak256(bytes(name))); sep = ","; }
        if (uint8(f) & 0x02 != 0) { t = string.concat(t, sep, "string version"); enc = bytes.concat(enc, abi.encode(keccak256(bytes(version)))); sep = ","; }
        if (uint8(f) & 0x04 != 0) { t = string.concat(t, sep, "uint256 chainId"); enc = bytes.concat(enc, abi.encode(chainId)); sep = ","; }
        if (uint8(f) & 0x08 != 0) { t = string.concat(t, sep, "address verifyingContract"); enc = bytes.concat(enc, abi.encode(vc)); sep = ","; }
        if (uint8(f) & 0x10 != 0) { t = string.concat(t, sep, "bytes32 salt"); enc = bytes.concat(enc, abi.encode(salt)); }
        assertEq(uint8(f) & 0xe0, 0, "no undefined bits");
        bytes32 domain = keccak256(bytes.concat(keccak256(bytes(string.concat(t, ")"))), enc));
        bytes32 sr = keccak256(abi.encode(v.SET_RESCUER_TYPEHASH(), uint64(1), bob));
        bytes32 ra = keccak256(abi.encode(v.ROTATE_ADMIN_TYPEHASH(), uint64(2), _ua(bob)));
        assertEq(keccak256(abi.encodePacked(hex"1901", domain, sr)), v.setRescuerDigest(1, bob), "setRescuer from ERC-5267");
        assertEq(keccak256(abi.encodePacked(hex"1901", domain, ra)), v.rotateAdminDigest(2, _ua(bob)), "rotateAdmin from ERC-5267");
    }

    // ------------------------------------------------------------------ withdraw

    function test_rescuerWithdrawsToTo() public {
        foo.mint(address(v), 10);
        vm.deal(address(v), 2 ether);
        vm.expectEmit(address(v));
        emit RescueVault.Withdrawn(address(foo), PAYEE, 4, res);
        vm.prank(res);
        v.withdraw(address(foo), 4, PAYEE);
        vm.prank(res);
        v.withdraw(address(0), 1 ether, PAYEE);
        assertEq(foo.balanceOf(PAYEE), 4);
        assertEq(PAYEE.balance, 1 ether);
        assertEq(foo.balanceOf(res) + res.balance, 0, "nothing to the rescuer");
    }

    /// The rescuer with `to` 0 pays the rescuer.
    function test_rescuerWithZeroToPaysTheRescuer() public {
        foo.mint(address(v), 10);
        vm.deal(address(v), 2 ether);
        vm.prank(res);
        v.withdraw(address(foo), 3, address(0));
        vm.prank(res);
        v.withdraw(address(0), 1 ether, address(0));
        assertEq(foo.balanceOf(res), 3);
        assertEq(res.balance, 1 ether);
    }

    /// Anyone else pays the rescuer; the stranger's `to` is ignored.
    function test_strangerPaysTheRescuer() public {
        foo.mint(address(v), 10);
        vm.deal(address(v), 2 ether);
        vm.expectEmit(address(v));
        emit RescueVault.Withdrawn(address(foo), res, 5, STRANGER);
        vm.prank(STRANGER);
        v.withdraw(address(foo), 5, PAYEE);
        vm.prank(STRANGER);
        v.withdraw(address(0), 1 ether, PAYEE);
        vm.prank(STRANGER);
        v.withdraw(address(0), 1 ether, address(0));
        assertEq(foo.balanceOf(res), 5);
        assertEq(res.balance, 2 ether);
        assertEq(foo.balanceOf(PAYEE) + PAYEE.balance + foo.balanceOf(STRANGER) + STRANGER.balance, 0);
    }

    /// The admin only administers: its `withdraw` with a `to` pays the rescuer, never `to` and never the admin; once the admin
    /// sets itself as rescuer, it is the rescuer.
    function test_adminIsNotARescuer() public {
        foo.mint(address(v), 10);
        vm.prank(alice);
        v.withdraw(address(foo), 4, PAYEE);
        assertEq(foo.balanceOf(res), 4);
        assertEq(foo.balanceOf(PAYEE) + foo.balanceOf(alice), 0);
        v.setRescuer(1, alice, _signRescuer(aliceKey, v, 1, alice));
        vm.prank(alice); // control: now set as rescuer
        v.withdraw(address(foo), 6, PAYEE);
        assertEq(foo.balanceOf(PAYEE), 6);
    }

    /// A rescuer that is an EIP-7702 designator cannot direct funds (an EOA runs no code); a call that pays it still works.
    function test_designatorRescuerCannotDirect() public {
        foo.mint(address(v), 10);
        vm.etch(res, abi.encodePacked(hex"ef0100", address(0xC0DE)));
        vm.prank(res);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.CallerDelegated.selector, res));
        v.withdraw(address(foo), 1, PAYEE);
        vm.prank(res); // control: to 0 pays the rescuer (an ERC-20, no code runs there)
        v.withdraw(address(foo), 1, address(0));
        vm.prank(STRANGER);
        v.withdraw(address(foo), 1, address(0));
        assertEq(foo.balanceOf(res), 2);
    }

    /// The native coin is refused to a designator destination (as `RescueLib.send`); an ERC-20 goes.
    function test_nativeRefusedToADesignator() public {
        foo.mint(address(v), 10);
        vm.deal(address(v), 1 ether);
        vm.etch(PAYEE, abi.encodePacked(hex"ef0100", address(0xC0DE)));
        vm.prank(res);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.ToInvalid.selector, PAYEE));
        v.withdraw(address(0), 1, PAYEE);
        vm.prank(res);
        v.withdraw(address(foo), 1, PAYEE);
        assertEq(foo.balanceOf(PAYEE), 1);
        address o = makeAddr("plain");
        vm.prank(res); // control: a plain address takes the native coin
        v.withdraw(address(0), 1, o);
        assertEq(o.balance, 1);
    }

    /// A USDT-style token (no return value) withdraws through `SafeERC20`, to `to` and to the rescuer.
    function test_noReturnTokenWithdraws() public {
        NoReturnERC20 t = new NoReturnERC20();
        t.mint(address(v), 10);
        vm.prank(res);
        v.withdraw(address(t), 4, PAYEE);
        vm.prank(STRANGER);
        v.withdraw(address(t), 6, PAYEE);
        assertEq(t.balanceOf(PAYEE), 4);
        assertEq(t.balanceOf(res), 6);
    }

    // ------------------------------------------------------------------ admin operations

    /// `setRescuer` by the admin's signature, submitted by anyone: the old rescuer is then a stranger.
    function test_setRescuerThenOldRescuerIsAStranger() public {
        bytes memory sig = _signRescuer(aliceKey, v, 1, bob);
        vm.expectEmit(address(v));
        emit RescueVault.RescuerSet(1, res, bob);
        vm.prank(STRANGER); // anyone submits
        v.setRescuer(1, bob, sig);
        assertEq(v.rescuer(), bob);
        assertEq(v.seq(), 1);
        assertEq(v.admin(), _ua(alice), "the admin stays");
        foo.mint(address(v), 10);
        vm.prank(res);
        v.withdraw(address(foo), 4, PAYEE); // the old rescuer now pays the new one
        assertEq(foo.balanceOf(bob), 4);
        assertEq(foo.balanceOf(PAYEE), 0);
        vm.prank(bob);
        v.withdraw(address(foo), 6, PAYEE);
        assertEq(foo.balanceOf(PAYEE), 6);
    }

    /// `rotateAdmin` by the admin's signature: the old admin key no longer signs, the new one does; the rescuer stays.
    function test_rotateAdminThenOldKeyIsVoid() public {
        bytes memory sig = _signAdmin(aliceKey, v, 1, _ua(bob));
        vm.expectEmit(address(v));
        emit RescueVault.AdminRotated(1, _ua(alice), _ua(bob));
        vm.prank(STRANGER);
        v.rotateAdmin(1, _ua(bob), sig);
        assertEq(v.admin(), _ua(bob));
        assertEq(v.rescuer(), res, "the rescuer stays");
        bytes memory oldR = _signRescuer(aliceKey, v, 2, PAYEE);
        bytes memory oldA = _signAdmin(aliceKey, v, 2, _ua(alice));
        bytes memory newR = _signRescuer(bobKey, v, 2, PAYEE);
        vm.expectRevert(RescueVault.SignatureInvalid.selector); // the old key
        v.setRescuer(2, PAYEE, oldR);
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.rotateAdmin(2, _ua(alice), oldA);
        v.setRescuer(2, PAYEE, newR); // control: the new key
        assertEq(v.rescuer(), PAYEE);
    }

    /// The new admin must be a native UA (not 0, high 96 bits 0): a derived or PQ UA cannot be checked chain-neutrally.
    function test_rotateAdminRefusesNonNative() public {
        bytes32 derived = bytes32(uint256(uint160(bob)) | (uint256(0xff) << 248));
        bytes memory sD = _signAdmin(aliceKey, v, 1, derived);
        bytes memory s0 = _signAdmin(aliceKey, v, 1, bytes32(0));
        bytes memory sR0 = _signRescuer(aliceKey, v, 1, address(0));
        bytes memory ok = _signAdmin(aliceKey, v, 1, _ua(bob));
        vm.expectRevert(abi.encodeWithSelector(RescueVault.AdminInvalid.selector, derived));
        v.rotateAdmin(1, derived, sD);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.AdminInvalid.selector, bytes32(0)));
        v.rotateAdmin(1, bytes32(0), s0);
        vm.expectRevert(RescueVault.RescuerInvalid.selector);
        v.setRescuer(1, address(0), sR0);
        v.rotateAdmin(1, _ua(bob), ok); // control
    }

    /// One `seq` for both operations: a signature for `seq` 1 of one kind is void once the other kind used `seq` 1; a
    /// signature of one kind never passes as the other (the typehash), even for the same 32 bytes.
    function test_seqSharedAcrossOps() public {
        bytes memory r1 = _signRescuer(aliceKey, v, 1, bob);
        bytes memory a1 = _signAdmin(aliceKey, v, 1, _ua(bob));
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.rotateAdmin(1, _ua(bob), r1); // a setRescuer signature as rotateAdmin
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.setRescuer(1, bob, a1); // and the reverse
        v.setRescuer(1, bob, r1);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.SeqInvalid.selector, 2, 1));
        v.rotateAdmin(1, _ua(bob), a1); // seq 1 is spent by the other kind
        v.rotateAdmin(2, _ua(bob), _signAdmin(aliceKey, v, 2, _ua(bob)));
        assertEq(v.seq(), 2);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.SeqInvalid.selector, 3, 1));
        v.setRescuer(1, bob, r1); // replayed
    }

    function test_staleOrSkippedSeqRefused() public {
        bytes memory sig = _signRescuer(aliceKey, v, 1, bob);
        bytes memory skipped = _signRescuer(aliceKey, v, 2, bob);
        bytes memory stale = _signAdmin(aliceKey, v, 0, _ua(bob));
        vm.expectRevert(abi.encodeWithSelector(RescueVault.SeqInvalid.selector, 1, 2));
        v.setRescuer(2, bob, skipped);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.SeqInvalid.selector, 1, 0));
        v.rotateAdmin(0, _ua(bob), stale);
        v.setRescuer(1, bob, sig);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.SeqInvalid.selector, 2, 1));
        v.setRescuer(1, bob, sig); // replayed
    }

    function test_badSignaturesRefused() public {
        RescueVault other = new RescueVault(_ua(alice), res);
        bytes memory good = _signRescuer(aliceKey, v, 1, bob);
        bytes memory goodA = _signAdmin(aliceKey, v, 1, _ua(bob));
        bytes memory notAdmin = _signRescuer(bobKey, v, 1, bob);
        uint256 resKey = 0x7E5;
        RescueVault w = new RescueVault(_ua(alice), vm.addr(resKey));
        bytes memory byRescuer = _signRescuer(resKey, w, 1, bob);
        bytes memory otherR = _signRescuer(aliceKey, other, 1, bob);
        bytes memory otherA = _signAdmin(aliceKey, other, 1, _ua(bob));
        (uint8 v_, bytes32 r, bytes32 s) = vm.sign(aliceKey, v.setRescuerDigest(1, bob));
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.setRescuer(1, bob, notAdmin); // not the admin
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        w.setRescuer(1, bob, byRescuer); // the rescuer's key is not the admin's
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.setRescuer(1, PAYEE, good); // another value than signed
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.rotateAdmin(1, _ua(PAYEE), goodA); // another admin than signed
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.setRescuer(1, bob, otherR); // another vault's domain
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.rotateAdmin(1, _ua(bob), otherA);
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.setRescuer(1, bob, abi.encodePacked(r, bytes32(N - uint256(s)), v_ == 27 ? uint8(28) : uint8(27))); // high-s twin
        vm.expectRevert(RescueVault.SignatureInvalid.selector);
        v.setRescuer(1, bob, abi.encodePacked(r, s)); // 64 bytes
        v.setRescuer(1, bob, good); // control
        assertEq(v.rescuer(), bob);
    }

    /// Admin operations are chain-neutral: signed once, they bring a vault deployed later at the same address on another chain
    /// (another chain id, another history) to the same admin and rescuer, in order, once.
    function test_adminLogReplaysOnASecondChain() public {
        uint256 before = vm.snapshotState();
        vm.chainId(7622);
        RescueVault a = RescueVault(payable(_deploy(_ua(alice), res)));
        bytes memory sig1 = _signRescuer(aliceKey, a, 1, PAYEE);
        bytes memory sig2 = _signAdmin(aliceKey, a, 2, _ua(bob));
        bytes memory sig3 = _signRescuer(bobKey, a, 3, bob);
        a.setRescuer(1, PAYEE, sig1);
        a.rotateAdmin(2, _ua(bob), sig2);
        a.setRescuer(3, bob, sig3);
        assertEq(a.rescuer(), bob);

        vm.revertToState(before); // a fresh chain: no vault yet
        vm.chainId(1);
        vm.roll(block.number + 1000);
        vm.warp(block.timestamp + 1 days);
        assertEq(address(a).code.length, 0);
        RescueVault b = RescueVault(payable(_deploy(_ua(alice), res)));
        assertEq(address(b), address(a), "one address");
        assertEq(b.rescuer(), res, "the first rescuer until caught up");
        vm.expectRevert(abi.encodeWithSelector(RescueVault.SeqInvalid.selector, 1, 2));
        b.rotateAdmin(2, _ua(bob), sig2); // out of order
        b.setRescuer(1, PAYEE, sig1);
        b.rotateAdmin(2, _ua(bob), sig2);
        b.setRescuer(3, bob, sig3);
        assertEq(b.admin(), _ua(bob));
        assertEq(b.rescuer(), bob);
        assertEq(b.seq(), 3);
        vm.expectRevert(abi.encodeWithSelector(RescueVault.SeqInvalid.selector, 4, 3));
        b.setRescuer(3, bob, sig3);
    }

    // ------------------------------------------------------------------ a real rescue pays the vault

    /// `RescueLib` refuses only a designator destination: a singleton's `rescue` pays the deployed vault (an ERC-20 and the
    /// native coin), and anyone then sweeps it to the dev EOA, the rescuer.
    function test_realRescuePaysTheVault() public {
        address vault = _deploy(_ua(ADMIN), DEV_EOA);
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

    /// `DeployRescueVault`: deploys at the constant, then applies the admin log from the vault's `seq() + 1`; a second run with
    /// the same log is a no-op. The dev key is not here, so the test hands the deployed vault's admin to `alice` (slot 0, `seq`
    /// 0 kept). The log is passed as JSON (`deployAndCatchUp`), so no file is written.
    function test_deployScriptDeploysAndCatchesUp() public {
        vm.etch(DEPLOYER, DEPLOYER_CODE);
        DeployRescueVault s = new DeployRescueVault();
        vm.setEnv("RESCUE_VAULT_LOG", "./rescue-vault-admin-log.json"); // the committed log
        s.run();
        RescueVault w = RescueVault(payable(RescueLib.SCAAS_DEV_RESCUE));
        assertEq(w.admin(), _ua(ADMIN), "the committed log is empty");
        assertEq(w.rescuer(), DEV_EOA);
        vm.store(address(w), bytes32(0), _ua(alice));
        bytes memory init = vm.parseBytes(vm.readFile(INIT));
        string memory log = _log(w);
        s.deployAndCatchUp(init, log);
        assertEq(w.admin(), _ua(bob));
        assertEq(w.rescuer(), bob);
        assertEq(w.seq(), 3);
        s.deployAndCatchUp(init, log); // again: every row skipped
        assertEq(w.seq(), 3);
    }

    /// The script's refusals: no deterministic deployer; init code whose address is not the constant (one constructor
    /// argument changed); a vault that took an operation outside the log (V-2: a skipped row is still compared), each with
    /// its control.
    function test_deployScriptRefusals() public {
        DeployRescueVault s = new DeployRescueVault();
        bytes memory init = vm.parseBytes(vm.readFile(INIT));
        vm.etch(DEPLOYER, ""); // Foundry places the deployer by default: a chain without it
        vm.expectRevert(bytes(
            "no deterministic CREATE2 deployer at 0x4e59b44847b379578588920ca78fbf26c0b4956c (runbook NET-EVM-05)"));
        s.deployAndCatchUp(init, "[]");
        vm.etch(DEPLOYER, DEPLOYER_CODE);
        bytes memory other = abi.encodePacked(type(RescueVault).creationCode, abi.encode(_ua(ADMIN), PAYEE));
        vm.expectRevert(bytes("rescue-vault-init.hex is not RescueLib.SCAAS_DEV_RESCUE's init code"));
        s.deployAndCatchUp(other, "[]");
        s.deployAndCatchUp(init, "[]"); // control: the committed bytes deploy
        RescueVault w = RescueVault(payable(RescueLib.SCAAS_DEV_RESCUE));
        vm.store(address(w), bytes32(0), _ua(alice));
        string memory log = _log(w);
        s.deployAndCatchUp(init, log);
        w.setRescuer(4, PAYEE, _signRescuer(bobKey, w, 4, PAYEE)); // an operation not in the log
        vm.expectRevert(bytes("vault differs from the admin log: another operation was applied on this chain (spec R1 / R3)"));
        s.deployAndCatchUp(init, log);
    }

    /// The three-row admin log of the script tests: alice sets PAYEE, rotates to bob, bob sets himself.
    function _log(RescueVault w) internal view returns (string memory) {
        return string.concat(
            '[{"seq":1,"op":"setRescuer","newRescuer":"', vm.toString(PAYEE), '","sig":"',
            vm.toString(_signRescuer(aliceKey, w, 1, PAYEE)), '"},',
            '{"seq":2,"op":"rotateAdmin","newAdmin":"', vm.toString(_ua(bob)), '","sig":"',
            vm.toString(_signAdmin(aliceKey, w, 2, _ua(bob))), '"},',
            '{"seq":3,"op":"setRescuer","newRescuer":"', vm.toString(bob), '","sig":"',
            vm.toString(_signRescuer(bobKey, w, 3, bob)), '"}]');
    }

    // ------------------------------------------------------------------ KAT (clientkeys)

    /// Both admin digests of the vault at the constant address for fixed fields; `WRITE_RESCUE_VAULT=true` writes the file.
    function test_adminOpsKat() public {
        RescueVault w = RescueVault(payable(_deploy(_ua(ADMIN), DEV_EOA)));
        address newRescuer = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF;
        bytes32 newAdmin = _ua(0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69);
        string memory j = string.concat(
            "{\n",
            '  "_comment": "Generated by smartcontracts/evm/test/governance/RescueVault.t.sol (WRITE_RESCUE_VAULT=true); spec superpowers/specs/2026-11-12-rescue-vault.md",\n',
            '  "vault": "', vm.toString(address(w)), '",\n',
            '  "setRescuerTypehash": "', vm.toString(w.SET_RESCUER_TYPEHASH()), '",\n',
            '  "rotateAdminTypehash": "', vm.toString(w.ROTATE_ADMIN_TYPEHASH()), '",\n',
            '  "setRescuer": {"seq": 1, "newRescuer": "', vm.toString(newRescuer), '", "digest": "',
            vm.toString(w.setRescuerDigest(1, newRescuer)), '"},\n',
            '  "rotateAdmin": {"seq": 2, "newAdmin": "', vm.toString(newAdmin), '", "digest": "',
            vm.toString(w.rotateAdminDigest(2, newAdmin)), '"}\n',
            "}\n"
        );
        if (vm.envOr("WRITE_RESCUE_VAULT", false)) vm.writeFile(KAT, j);
        assertEq(vm.readFile(KAT), j, "rescue_vault_kat.json is stale: WRITE_RESCUE_VAULT=true");
    }
}
