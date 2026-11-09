// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {normalInit} from "./helpers/V2Fixture.sol";
import {nid} from "../helpers/Ids.sol";
import {plainEnv, withModules} from "../helpers/Catalogue.sol";
import {deployKindModules} from "../../script/KindModules.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {ChainEnvCode} from "../../src/factory/ChainEnvCode.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// Chain-neutral releases spec §8 (plan T74), the two-chain tests in one EVM: each chain a state snapshot with its own
/// chain id and genesis hash (BLOCKHASH(0) and EIP-2935). Chain A id 31901, chain B id 31902 (another genesis), chain C id
/// 31901 with a third genesis (NET-ALL-22: one chain id, two chains). On each the deploy steps of `DeployBase` (the
/// libraries, the factory, `configureChain`, the registry and router, the envs, the `NORMAL` and DEX releases) and one
/// instance per path (`createToken`, `createTokenUnregistered`, `createDex`). The script test on two `anvil`s is T68's dry
/// run. **UNAUDITED.**
contract ChainNeutralTest is Test {
    uint256 constant PK = 0xA11CE;
    uint256 constant A_ID = 31901;
    uint256 constant B_ID = 31902;
    bytes32 constant UID_A = keccak256("genesis A");
    bytes32 constant UID_B = keccak256("genesis B");
    bytes32 constant UID_C = keccak256("genesis C");
    address constant HISTORY = 0x0000F90827F1C53a10cb7A02335B175320002935;
    DeployHarness h;
    address alice;

    struct Seen {
        address factory;
        address normalRelease;
        address dexRelease;
        address token;
        address unregistered;
        address dex;
        bytes32 tokenCode;
        bytes32 dexCode;
        bytes32 salt; // the token's eip712Domain salt
        uint256 chainId; // its eip712Domain chainId
    }

    function setUp() public {
        vm.warp(1_800_000_000);
        alice = vm.addr(PK);
        h = new DeployHarness();
    }

    function _chain(uint256 id, bytes32 uid) internal returns (OpenFactory f, Seen memory s) {
        vm.chainId(id);
        (f,) = h.deploy(uid, false, address(0));
        s.factory = address(f);
        s.normalRelease = f.implementationOf(IOpenFactory.TokenKind.NORMAL, 1);
        s.dexRelease = f.dexImplementationOf(1);
        vm.startPrank(alice);
        s.token = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(normalInit("T", "T", 6, 1e12, alice,
            address(0))), "t");
        s.unregistered = f.createTokenUnregistered(IOpenFactory.TokenKind.NORMAL, s.normalRelease,
            abi.encode(normalInit("U", "U", 6, 0, alice, address(0))), "u");
        s.dex = f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(alice), 0, alice, false, 0, address(0))), "d");
        vm.stopPrank();
        s.tokenCode = s.token.codehash;
        s.dexCode = s.dex.codehash;
        (,,, s.chainId,, s.salt,) = NormalToken(payable(s.token)).eip712Domain();
        // the instance's code is the proxy and the env this factory composes (create3_kat.json's layout)
        IFactoryToken.Env memory e = f.envOf(IOpenFactory.TokenKind.NORMAL, 1);
        IFactoryToken.ChainEnv memory ce = IFactoryToken.ChainEnv(uid, e.registry, f.govRouter(), e.smartKeyAccountImpl,
            e.hedera, e.deps, e.params);
        assertEq(s.tokenCode, keccak256(abi.encodePacked(hex"363d3d373d3d3d363d73", s.normalRelease,
            hex"5af43d82803e903d91602b57fd5bf3", ChainEnvCode.encode(ce))), "proxy || env");
        assertEq(abi.encode(NormalToken(payable(s.token)).chainEnv()), abi.encode(ce), "chainEnv() the composition");
        assertEq(f.predictAddress(nid(alice), 1, 0, "t"), s.token, "predictAddress, createToken");
        assertEq(f.predictAddress(nid(alice), 1, 0, "u"), s.unregistered, "predictAddress, unregistered");
        assertEq(f.predictAddress(nid(alice), 2, 0, "d"), s.dex, "predictAddress, createDex");
        assertTrue(f.predictAddress(nid(address(0xB0B)), 1, 0, "t") != s.token, "another creator");
        assertTrue(f.predictAddress(nid(alice), 2, 0, "t") != s.token, "another class");
        assertTrue(f.predictAddress(nid(alice), 1, 1, "t") != s.token, "another kind");
    }

    /// Alice's signed transfer of 1 to `to` on `token` (nonce 0, lane 0), its digest in `token`'s domain on this chain.
    function _signed(address token, address to) internal view returns (bytes memory cd) {
        MetaTxLib.UAMetaTransfer memory x = MetaTxLib.UAMetaTransfer({from: nid(alice), to: nid(to), value: 1, entryRef: 0,
            batch: 0, nonce: 0, validUntil: block.timestamp + 1 hours, mode: 0, relayer: address(0), fee: 0,
            feeRecipient: address(0)});
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, IERC20MetaTx(token).mtxTransferDigest(x));
        IUARegistry.UASig memory a;
        a.signature = abi.encodePacked(r, s, v);
        cd = abi.encodeCall(IMetaTokenV2.mtxTransfer, (x.from, x.to, x.value, x.batch, x.nonce, x.validUntil, x.mode,
            x.relayer, a));
    }

    function _relay(address token, bytes memory cd) internal returns (bool ok) {
        vm.prank(address(0xBEEF));
        (ok,) = token.call(cd);
    }

    function test_twoChains_sameAddresses_ownCode_signaturesBound() public {
        uint256 snap = vm.snapshotState();
        (, Seen memory a) = _chain(A_ID, UID_A);
        bytes memory onA = _signed(a.token, address(0xCAFE));
        vm.revertToState(snap);
        (, Seen memory b) = _chain(B_ID, UID_B);
        vm.revertToState(snap);
        (, Seen memory c) = _chain(A_ID, UID_C);
        // the same address on A, B, C: the factory, the releases, one instance per path
        assertEq(b.factory, a.factory);
        assertEq(c.factory, a.factory);
        assertEq(b.normalRelease, a.normalRelease);
        assertEq(c.normalRelease, a.normalRelease);
        assertEq(b.dexRelease, a.dexRelease);
        assertEq(b.token, a.token);
        assertEq(c.token, a.token);
        assertEq(b.unregistered, a.unregistered);
        assertEq(b.dex, a.dex);
        assertEq(c.dex, a.dex);
        // each chain's own code and domain: exactly chainId and salt differ
        assertTrue(b.tokenCode != a.tokenCode && c.tokenCode != a.tokenCode && b.tokenCode != c.tokenCode);
        assertTrue(b.dexCode != a.dexCode && c.dexCode != a.dexCode);
        assertEq(a.salt, UID_A);
        assertEq(b.salt, UID_B);
        assertEq(c.salt, UID_C);
        assertEq(a.chainId, A_ID);
        assertEq(b.chainId, B_ID);
        assertEq(c.chainId, A_ID);
        // A's signature on C (only the salt differs): refused; on B (chain id and salt): refused
        assertFalse(_relay(c.token, onA), "C refuses A's signature");
        vm.revertToState(snap);
        _chain(B_ID, UID_B);
        assertFalse(_relay(b.token, onA), "B refuses A's signature");
        vm.revertToState(snap);
        _chain(A_ID, UID_A);
        assertTrue(_relay(a.token, onA), "A accepts it (positive control)");
        assertEq(IERC20(a.token).balanceOf(address(0xCAFE)), 1);
    }

    /// Fable P3-6: the registrar's `configureChain` for A replayed raw on C (the same chain id, the same registrar nonce).
    /// With a reference block it reverts `RefBlockMismatch`; without one, on a chain whose genesis the EVM cannot prove
    /// (past 256 blocks, no EIP-2935 answer), it binds C to A's `chain_uid`, and a signature for A's instance is accepted
    /// on C's twin: the evidence for the gate's sibling order (`DeployBase._configureChain`).
    function test_replayedConfigureChain() public {
        address registrar = address(0x5E6);
        bytes32 salt_ = keccak256("scaas.deploy.v1");
        vm.roll(1000);
        uint256 snap = vm.snapshotState();
        // chain A: block 999's hash is A's own
        vm.chainId(A_ID);
        vm.setBlockhash(999, keccak256("A 999"));
        vm.store(HISTORY, bytes32(0), UID_A);
        OpenFactory f = new OpenFactory{salt: salt_}(registrar);
        bytes memory withRef = abi.encodeCall(OpenFactory.configureChain, (UID_A, 0, address(0), 999, keccak256("A 999")));
        bytes memory noRef = abi.encodeCall(OpenFactory.configureChain, (UID_A, 0, address(0), 0, bytes32(0)));
        vm.prank(registrar);
        (bool ok,) = address(f).call(withRef);
        assertTrue(ok, "A configured");
        address tokA = _plainToken(f, registrar);
        bytes memory onA = _signed(tokA, address(0xCAFE));
        // chain C: the same chain id, another genesis the EVM cannot prove, another block 999
        vm.revertToState(snap);
        vm.chainId(A_ID);
        vm.setBlockhash(999, keccak256("C 999"));
        vm.etch(HISTORY, "");
        f = new OpenFactory{salt: salt_}(registrar);
        vm.prank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.RefBlockMismatch.selector, 999, keccak256("A 999"),
            keccak256("C 999")));
        f.configureChain(UID_A, 0, address(0), 999, keccak256("A 999"));
        // without the reference the replay binds C to A's chain_uid, and A's signature runs on C's twin
        vm.prank(registrar);
        (ok,) = address(f).call(noRef);
        assertTrue(ok, "the replay without a reference binds C");
        assertEq(f.chainUid(), UID_A);
        address tokC = _plainToken(f, registrar);
        assertEq(tokC, tokA, "the twin");
        assertTrue(_relay(tokC, onA), "full replay: A's signature accepted on C");
        // the gate's order: C configured with its own values first, the replay meets ChainAlreadyConfigured
        vm.revertToState(snap);
        vm.chainId(A_ID);
        vm.etch(HISTORY, "");
        f = new OpenFactory{salt: salt_}(registrar);
        vm.prank(registrar);
        f.configureChain(UID_C, 0, address(0), 0, bytes32(0));
        vm.prank(registrar);
        vm.expectRevert(IOpenFactory.ChainAlreadyConfigured.selector);
        f.configureChain(UID_A, 0, address(0), 0, bytes32(0));
        tokC = _plainToken(f, registrar);
        assertFalse(_relay(tokC, onA), "C on its own chain_uid refuses A's signature");
    }

    /// The NORMAL release without a registry and alice's token of it (the same steps on every chain).
    function _plainToken(OpenFactory f, address registrar) internal returns (address t) {
        (address[] memory ms, bytes memory args) = deployKindModules(0, address(f), ""); // T66b: its body modules, pinned
        vm.startPrank(registrar);
        f.publishEnv(IOpenFactory.TokenKind.NORMAL, 1,
            withModules(plainEnv(address(f), address(0), bytes32(0), address(0), false), ms));
        f.deployImplementation(IOpenFactory.TokenKind.NORMAL, 1, 1, type(NormalToken).creationCode, args);
        vm.stopPrank();
        vm.prank(alice);
        t = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(normalInit("T", "T", 6, 1e12, alice, address(0))),
            "t");
    }
}
