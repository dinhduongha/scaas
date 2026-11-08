// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {MetaTokenBase} from "../../../src/metatx/MetaTokenBase.sol";
import {NormalToken} from "../../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../../src/metatx/WrappedToken.sol";
import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";
import {WrappedPqzToken} from "../../../src/pqz/WrappedPqzToken.sol";
import {NormalZetherToken} from "../../../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../../../src/zether/WrappedZetherToken.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {UALedgerBase} from "../../ua/UALedgerBase.sol";
import {PqzFixture} from "../../pqz/helpers/PqzFixture.sol";
import {PQZ_UID} from "../../pqz/helpers/PqzRegistryBase.sol";
import {ZetherFixture} from "../../zether/helpers/ZetherFixture.sol";
import {MockERC20} from "../../helpers/Mocks.sol";
import {Catalogue, pqzEnv, plainEnv} from "../../helpers/Catalogue.sol";
import {normalInit} from "../../v2/helpers/V2Fixture.sol";

// The seven token clones of the metatx split's parity rigs (`NORMAL`, `WRAPPED`, `NORMAL_LEDGEROFF`, `NORMAL_PQZ`,
// `WRAPPED_PQZ`, `NORMAL_ZETHER`, `WRAPPED_ZETHER`), their `init` copied unchanged from `MetaTxParity.t.sol`. The parity
// replay itself (its case set and `metatx-parity.json`, recorded on the pre-split code) is in legacy/ua-mtx-merge/: the
// ua-mtx-merge round changes the entries it replays (plan T2 retires it; T1 already removes its generic and cancel
// entries). `MtxCtx.t` and `PayMeta.t` use these rigs for the kinds only.

/// A token under test, with the actors of its rig.
struct Tk {
    string kind;
    address t;
    uint256 pk; // signer
    address signer;
    uint256 payeePk;
    address payee;
    address feeTo;
    address relayer;
    bytes32 uaD; // a derived SIGNING UA with a ledger balance (0 = none)
    uint8 style; // 0: `burn` is the AMOUNT-class call, 1: `unwrap(uint256,address,uint256)`
    address und; // style 1: the sole leg
    address dex; // the contract that is `o.dex` of trade orders
    uint256 lane; // next free lane
    bytes32 oh; // trade cases: the order hash whose `pulled` / floor is recorded
}

/// `o.dex` of the trade cases: only needs code.
contract ParityDex {
    receive() external payable {}
}

interface IRig {
    function setup() external view returns (string[] memory, address[] memory, bytes32[] memory);
}

/// The rigs' common part: the tokens and their domains (`setup`), as `ParityCases` held them.
abstract contract KindRig is Test {
    uint256 internal constant P_T0 = 1_800_000_000;
    uint256 internal constant P_BLOCK = 1_000;

    Tk[] internal tks;

    /// One token and its actors (`test/merge/TransferGroup.t`: the derived UA `uaD` of the rig's registry).
    function tkAt(uint256 i) external view returns (Tk memory) {
        return tks[i];
    }

    function setup() external view returns (string[] memory kinds, address[] memory toks, bytes32[] memory doms) {
        kinds = new string[](tks.length);
        toks = new address[](tks.length);
        doms = new bytes32[](tks.length);
        for (uint256 i; i < tks.length; ++i) {
            (kinds[i], toks[i]) = (tks[i].kind, tks[i].t);
            (, string memory n, string memory v, uint256 cid, address vc, bytes32 salt,) = MetaTokenBase(tks[i].t).eip712Domain();
            doms[i] = keccak256(abi.encode(keccak256(bytes(n)), keccak256(bytes(v)), cid, vc, salt));
        }
    }
}

contract PlainRig is UALedgerBase, KindRig {
    function init() external {
        setUp();
        vm.warp(P_T0);
        vm.roll(P_BLOCK);
        address dex = address(new ParityDex());
        // NONE: alice holds 1_000_000; the rig (the minter) tops her up and funds the derived UA
        tok.mint(alice, 9_000_000);
        vm.prank(alice);
        tok.transferToUA(uaP, 2_000_000);
        tks.push(Tk("NORMAL", address(tok), ALICE_PK, alice, BOB_PK, bob, FEE_TO, RELAYER, uaP, 0, address(0), dex, 0, 0));
        // UNDERLYING: 10_000_000 wrapped units
        _wrapFor(alice, 10_000_000);
        vm.prank(alice);
        wrp.transferToUA(uaP, 2_000_000);
        tks.push(Tk("WRAPPED", address(wrp), ALICE_PK, alice, BOB_PK, bob, FEE_TO, RELAYER, uaP, 1, address(und), dex, 0, 0));
        // NONE with no UA registry (the ledger off)
        address off = Clones.clone(address(new NormalToken(1, plainEnv(address(this), address(0), chainUidA, address(0), false), "")));
        NormalToken(off).initialize(address(this), 1, abi.encode(normalInit("Points", "PTS", 6, 10_000_000, alice, address(this))));
        tks.push(Tk("NORMAL_LEDGEROFF", off, ALICE_PK, alice, BOB_PK, bob, FEE_TO, RELAYER, 0, 2, address(0), dex, 0, 0));
    }
}

/// `NORMAL_PQZ` and `WRAPPED_PQZ` at the committed parameter set, the `PQZ` precompile mocked as in the PQZ suites:
/// the ops are relayed with a proof the mock accepts, everything else is real code.
contract PqzRig is PqzFixture, KindRig {
    uint256 internal constant SK = 0xA11CE;
    uint256 internal constant PK2 = 0xB0B;

    function init() external {
        vm.warp(P_T0);
        vm.roll(P_BLOCK);
        _stack();
        address dex = address(new ParityDex());
        bytes32 uaD = _mldsaUA(9);
        address signer = vm.addr(SK);
        // NORMAL_PQZ
        address t = _pClone(address(normalImpl), _cfg(uint256(1) << 40));
        NormalPqzToken(t).mint(signer, 20_000_000);
        NormalPqzToken(t).mintToUA(uaD, 2_000_000);
        tks.push(Tk("NORMAL_PQZ", t, SK, signer, PK2, vm.addr(PK2), address(0xFEE), address(0xBEEF), uaD, 0, address(0), dex, 0, 0));
        // WRAPPED_PQZ: one 1:1 leg
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        address impl = Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_PQZ, 1,
            pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv)), type(WrappedPqzToken).creationCode);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features = 1 << GovernanceBits.PAYABLE;
        c.lockedFeatures = 0; // the fixture locks MINTABLE for its minter (B-06); this token has neither
        c.roles.minter = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        address w = _pClone(impl, c);
        usd.mint(signer, 20_000_000);
        vm.startPrank(signer);
        usd.approve(w, 20_000_000);
        WrappedToken(payable(w)).wrap(20_000_000);
        WrappedToken(payable(w)).transferToUA(uaD, 2_000_000);
        vm.stopPrank();
        tks.push(Tk("WRAPPED_PQZ", w, SK, signer, PK2, vm.addr(PK2), address(0xFEE), address(0xBEEF), uaD, 1, address(usd), dex, 0, 0));
    }

    /// The test plays the factory: a CREATE clone (its address does not depend on the implementation's code).
    function _pClone(address impl, IFactoryToken.TokenConfig memory c) internal returns (address t) {
        t = Clones.clone(impl);
        vm.prank(address(factory));
        MetaTokenBase(t).initialize(address(this), 1, abi.encode(c));
    }
}

/// `NORMAL_ZETHER` and `WRAPPED_ZETHER` (BLS12-381 classical Zether, real prover, real verifiers).
contract ZetherRig is ZetherFixture, KindRig {
    uint256 internal constant SK = 0xA11CE;
    uint256 internal constant PK2 = 0xB0B;

    function init() external {
        vm.warp(P_T0);
        vm.roll(P_BLOCK);
        _stack();
        _users();
        address dex = address(new ParityDex());
        address signer = vm.addr(SK);
        // NORMAL_ZETHER
        address t = _pClone(address(normalImpl), _cfg(true, uint256(1) << 40));
        NormalZetherToken(t).mint(signer, 20_000_000);
        vm.prank(signer);
        MetaTokenBase(t).transferToUA(ZetherTypes.UA.unwrap(bob.ua), 2_000_000);
        tks.push(Tk("NORMAL_ZETHER", t, SK, signer, PK2, vm.addr(PK2), address(0xFEE), address(0xBEEF), ZetherTypes.UA.unwrap(bob.ua), 0, address(0), dex, 0, 0));
        // WRAPPED_ZETHER: one 1:1 leg
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        address impl = Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(),
            type(WrappedZetherToken).creationCode);
        IFactoryToken.TokenConfig memory c = _cfg(true, uint256(1) << 40);
        c.features = 1 << GovernanceBits.PAYABLE;
        c.lockedFeatures = 0; // the fixture locks MINTABLE for its minter (B-06); this token has neither
        c.roles.minter = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        address w = _pClone(impl, c);
        usd.mint(signer, 20_000_000);
        vm.startPrank(signer);
        usd.approve(w, 20_000_000);
        WrappedToken(payable(w)).wrap(20_000_000);
        WrappedToken(payable(w)).transferToUA(ZetherTypes.UA.unwrap(bob.ua), 2_000_000);
        vm.stopPrank();
        tks.push(Tk("WRAPPED_ZETHER", w, SK, signer, PK2, vm.addr(PK2), address(0xFEE), address(0xBEEF), ZetherTypes.UA.unwrap(bob.ua), 1, address(usd), dex, 0, 0));
    }

    function _pClone(address impl, IFactoryToken.TokenConfig memory c) internal returns (address t) {
        t = Clones.clone(impl);
        vm.prank(address(factory));
        MetaTokenBase(t).initialize(address(this), 1, abi.encode(c));
    }
}
