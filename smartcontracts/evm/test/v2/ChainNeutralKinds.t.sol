// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {SaltedEIP712Core} from "../../src/common/SaltedEIP712.sol";

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {ChainEnvCode} from "../../src/factory/ChainEnvCode.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {SaltedEIP712} from "../../src/common/SaltedEIP712.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {StubUARegistry} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {UID_, normalInit} from "./helpers/V2Fixture.sol";

/// Plan T72 (chain-neutral spec §2.1, §2.2; Fable P2-1, P3-4): every kind reads its chain values from its clone's code.
/// The implementation reads an all-zero env and signs nothing (`ChainUidZero`); `initialize` needs a well-formed env
/// (`EnvMissing`); a clone made outside the factory cannot be initialized; the domain's salt is the digest's.
/// **UNAUDITED.**
contract ChainNeutralKindsTest is Test {
    uint256 constant PK = 0xA11CE;
    address registrar = address(0xF00D);
    OpenFactory f;
    StubUARegistry ureg;
    GovernanceRouter router;
    NormalToken impl;
    NormalToken tok;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        ureg = new StubUARegistry(UID_);
        router = new GovernanceRouter(UID_, address(ureg), address(0), false);
        f = EnvKit.factory(registrar, UID_, 0, address(router));
        impl = NormalToken(Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(ureg),
            address(0), false));
        tok = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1,
            abi.encode(normalInit("N", "N", 6, 1000, vm.addr(PK), address(0))), "t"));
    }

    function _cfg() internal pure returns (bytes memory) {
        return abi.encode(normalInit("X", "X", 6, 0, address(0), address(0)));
    }

    /// The factory plays itself: `initialize` from its address on a clone `c`.
    function _initAsFactory(address c) internal {
        vm.prank(address(f));
        NormalToken(c).initialize(nid(address(this)), 1, _cfg());
    }

    // ------------------------------------------------------------------ the implementation signs nothing (P2-1)

    function test_implementation_readsAZeroEnvAndSignsNothing() public {
        assertEq(impl.chainUid(), bytes32(0), "a view: 0, no revert");
        assertEq(impl.registry(), address(0));
        assertEq(impl.GOV_ROUTER(), address(0));
        assertFalse(impl.IS_HEDERA());
        vm.expectRevert(SaltedEIP712Core.ChainUidZero.selector);
        impl.eip712Domain();
        MetaTxLib.UAMetaTransfer memory x;
        vm.expectRevert(SaltedEIP712Core.ChainUidZero.selector);
        impl.mtxTransferDigest(x);
        MetaTxLib.UAMetaTransaction memory m;
        IUARegistry.UASig memory a;
        vm.expectRevert(SaltedEIP712Core.ChainUidZero.selector);
        impl.mtxExecute(m, a);
        // positive control: the clone, on the same code
        assertEq(tok.chainUid(), UID_);
        assertEq(tok.registry(), address(ureg));
        assertEq(tok.GOV_ROUTER(), address(router));
        tok.eip712Domain();
    }

    /// The domain's `salt` is the `chain_uid` the digests are built under.
    function test_eip712Domain_saltIsTheDigests() public view {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) = tok.eip712Domain();
        assertEq(salt, UID_);
        MetaTxLib.UAMetaTransfer memory x = MetaTxLib.UAMetaTransfer({from: nid(vm.addr(PK)), to: nid(address(0xCAFE)),
            value: 1, entryRef: 0, batch: 1, nonce: 0, validUntil: 1_800_000_600, mode: 0, relayer: address(0), fee: 0,
            feeRecipient: address(0)});
        bytes32 dom = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt));
        bytes32 sh = keccak256(abi.encode(MetaTxLib.UAMETATRANSFER_TYPEHASH, x.from, x.to, x.value, x.entryRef, x.batch,
            x.nonce, x.validUntil, x.mode, x.relayer, x.fee, x.feeRecipient));
        assertEq(tok.mtxTransferDigest(x), keccak256(abi.encodePacked(hex"1901", dom, sh)));
    }

    // ------------------------------------------------------------------ initialize needs its env (P3-4)

    function test_initialize_refusedWithoutAWellFormedEnv() public {
        // the implementation itself
        vm.prank(address(f));
        vm.expectRevert(IFactoryToken.EnvMissing.selector);
        impl.initialize(nid(address(this)), 1, _cfg());
        // a plain EIP-1167 clone (no env)
        address bare = Clones.clone(address(impl));
        vm.prank(address(f));
        vm.expectRevert(IFactoryToken.EnvMissing.selector);
        NormalToken(bare).initialize(nid(address(this)), 1, _cfg());
        // a truncated env: the head without its counts
        address cut;
        bytes memory code = abi.encodePacked(hex"363d3d373d3d3d363d73", address(impl), hex"5af43d82803e903d91602b57fd5bf3",
            UID_, address(ureg), address(router), address(0), false);
        cut = address(0xC07);
        vm.etch(cut, code);
        vm.prank(address(f));
        vm.expectRevert(IFactoryToken.EnvMissing.selector);
        NormalToken(cut).initialize(nid(address(this)), 1, _cfg());
        // `chain_uid` 0
        address z = EnvKit.clone(address(impl), EnvKit.env(bytes32(0), address(ureg), address(0), false));
        vm.prank(address(f));
        vm.expectRevert(IFactoryToken.EnvMissing.selector);
        NormalToken(z).initialize(nid(address(this)), 1, _cfg());
        // more deps or params than the format holds
        IFactoryToken.ChainEnv memory e = EnvKit.env(UID_, address(ureg), address(0), false);
        e.deps = new address[](5);
        address five = EnvKit.clone(address(impl), e);
        vm.prank(address(f));
        vm.expectRevert(IFactoryToken.EnvMissing.selector);
        NormalToken(five).initialize(nid(address(this)), 1, _cfg());
        e.deps = new address[](4);
        e.params = new bytes32[](3);
        address three = EnvKit.clone(address(impl), e);
        vm.prank(address(f));
        vm.expectRevert(IFactoryToken.EnvMissing.selector);
        NormalToken(three).initialize(nid(address(this)), 1, _cfg());
        // trailing bytes past the counts
        bytes memory longer = bytes.concat(EnvKit.runtime(address(impl), EnvKit.env(UID_, address(ureg), address(0), false)),
            hex"00");
        vm.etch(address(0xC08), longer);
        vm.prank(address(f));
        vm.expectRevert(IFactoryToken.EnvMissing.selector);
        NormalToken(address(0xC08)).initialize(nid(address(this)), 1, _cfg());
        // positive control: four deps, two params, exact length
        e.params = new bytes32[](2);
        address ok = EnvKit.clone(address(impl), e);
        _initAsFactory(ok);
        assertEq(NormalToken(ok).chainEnv().deps.length, 4);
    }

    /// A clone made outside the factory, even with a well-formed (forged) env, is initialized by nobody but the factory:
    /// it is in no index; a second `initialize` of a factory clone is refused.
    function test_initialize_onlyTheFactoryAndOnce() public {
        address forged = EnvKit.clone(address(impl), EnvKit.env(keccak256("forged"), address(ureg), address(0), false));
        vm.expectRevert(MetaTokenBase.NotFactory.selector);
        NormalToken(forged).initialize(nid(address(this)), 1, _cfg());
        assertFalse(f.isToken(forged));
        vm.prank(address(f));
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        tok.initialize(nid(address(this)), 1, _cfg());
    }

    /// A derived creator keeps no address in the token (spec §4.4, Fable P2-3): `creator()` 0, the id in the factory's
    /// record; a native one its address.
    function test_initialize_derivedCreatorIsZeroInTheToken() public {
        address c = EnvKit.clone(address(impl), EnvKit.env(UID_, address(ureg), address(0), false));
        bytes32 derived = 0xcafe00000000000000000000000000000000000000000000000000000000a11a;
        vm.prank(address(f));
        NormalToken(c).initialize(derived, 1, _cfg());
        assertEq(NormalToken(c).creator(), address(0));
        assertEq(tok.creator(), address(this), "native: its address");
    }

    // ------------------------------------------------------------------ the DEX

    function test_dex_readsItsEnvAndItsReleaseSignsNothing() public {
        SCaaSDex dImpl = SCaaSDex(Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0xBEEF)));
        address d = f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(address(this)), 0, address(0xD7), false, 0, address(0))),
            "d");
        assertEq(SCaaSDex(d).chainUid(), UID_);
        assertEq(SCaaSDex(d).GOV_ROUTER(), address(router));
        assertEq(SCaaSDex(d).SMART_KEY_ACCOUNT_IMPL(), address(0xBEEF));
        assertEq(dImpl.chainUid(), bytes32(0));
        assertEq(dImpl.SMART_KEY_ACCOUNT_IMPL(), address(0));
        vm.expectRevert(SaltedEIP712Core.ChainUidZero.selector);
        dImpl.eip712Domain();
        vm.prank(address(f));
        vm.expectRevert(IFactoryToken.EnvMissing.selector);
        dImpl.initialize(nid(address(this)), 1, "");
        assertEq(keccak256(abi.encode(SCaaSDex(d).chainEnv())),
            keccak256(abi.encode(EnvKit.env(UID_, address(0), address(0xBEEF), false, address(router)))));
        dImpl.validateEnv(SCaaSDex(d).chainEnv()); // the DEX checks nothing
    }

    /// The reader decides from the code, not from an immutable (library study §7, CN-1): the implementation called
    /// directly reads its own code after offset 45 as nothing.
    function test_reader_decidesFromTheCode() public view {
        assertTrue(address(impl).code.length > 200, "the implementation has bytes past 45");
        assertEq(impl.chainEnv().chainUid, bytes32(0));
        assertEq(impl.chainEnv().deps.length, 0);
        assertEq(tok.chainEnv().chainUid, UID_);
    }
}
