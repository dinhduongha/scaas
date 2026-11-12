// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {KindRig, Tk} from "./KindRigs.sol";
import {RegFixture, Holder} from "../../as/helpers/RegFixture.sol";
import {PqzFixture} from "../../pqz/helpers/PqzFixture.sol";
import {PQZ_UID} from "../../pqz/helpers/PqzRegistryBase.sol";
import {ZetherFixture} from "../../zether/helpers/ZetherFixture.sol";
import {MockERC20} from "../../helpers/Mocks.sol";
import {Catalogue, pqzEnv, regArgs} from "../../helpers/Catalogue.sol";
import {nid} from "../../helpers/Ids.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {WrappedToken} from "../../../src/metatx/WrappedToken.sol";
import {NormalZetherRegulatedToken} from "../../../src/regulated/NormalZetherRegulatedToken.sol";
import {WrappedZetherRegulatedToken} from "../../../src/regulated/WrappedZetherRegulatedToken.sol";
import {NormalPqzRegulatedToken} from "../../../src/regulated/NormalPqzRegulatedToken.sol";
import {WrappedPqzRegulatedToken} from "../../../src/regulated/WrappedPqzRegulatedToken.sol";
import {EnvKit} from "../../helpers/EnvKit.sol";

// The regulated kinds 8-13 as `KindRig`s (spec 2026-11-09-service-pull §11, plan T77): one token of each kind with
// `FREEZE`, `FORCE`, `PAUSE`, `RECORD` (issuer and compliance two `Holder` contracts, the owner an EOA, `grantDelay` one day,
// the four controls of `test/as`'s fixtures), lists off, and the signer `0xA11CE` holding public units. Built on the plain,
// PQZ and Zether fixtures directly (not on `test/as/confidential`'s, which import whole test files).

uint256 constant RIG_REG_FEATURES = (1 << 5) | (1 << 6) | (1 << 7) | (1 << 10);
uint256 constant RIG_SK = 0xA11CE;
Vm constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

/// Kinds 8 and 9: `RegFixture`'s `t8` (`SUPPLY` minted to alice) and `t9` (alice wrapped `SUPPLY`).
contract RegRig is RegFixture, KindRig {
    function init() external {
        setUp();
        vm.roll(P_BLOCK);
        tks.push(Tk("NORMAL_REGULATED", t8, ALICE_PK, alice, BOB_PK, bob, address(0xFEE), relayer, 0, 0, address(0), address(0), 0, 0));
        tks.push(Tk("WRAPPED_REGULATED", t9, ALICE_PK, alice, BOB_PK, bob, address(0xFEE), relayer, 0, 1, address(usd), address(0), 0, 0));
    }
}

/// The regulated part of a config (as `test/as/confidential`'s fixtures): an owner, the four controls, their holders.
function regulate(IFactoryToken.TokenConfig memory c, address issuer, address compliance, bool wrapped, address leg)
    pure returns (IFactoryToken.TokenConfig memory)
{
    c.lockedFeatures = 0;
    c.admin = nid(address(0x0A11));
    c.grantDelay = 1 days;
    c.features |= RIG_REG_FEATURES;
    (c.roles.issuer, c.roles.compliance) = (nid(issuer), nid(compliance));
    c.reg.termsHash = keccak256("terms");
    if (wrapped) {
        c.features = (1 << GovernanceBits.PAYABLE) | (c.features & ~uint256(0x1F));
        c.roles.minter = 0;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(leg, 1, 1);
    }
    return c;
}

/// Kinds 10 and 11 on the real Zether stack (`ZetherFixture`).
contract ZetherRegRig is ZetherFixture, KindRig {
    function init() external {
        vm.warp(P_T0);
        vm.roll(P_BLOCK);
        _stack();
        _users();
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, 1, _zenv(),
            type(NormalZetherRegulatedToken).creationCode, regArgs());
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED, 1, _zenv(),
            type(WrappedZetherRegulatedToken).creationCode, regArgs());
        vm.startPrank(registrar);
        factory.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, true, EnvKit.uidOf(address(factory)));
        factory.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED, true, EnvKit.uidOf(address(factory)));
        vm.stopPrank();
        (address issuer, address compliance) = (address(new Holder()), address(new Holder()));
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        address signer = vm.addr(RIG_SK);
        address t = factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, 1,
            abi.encode(regulate(_cfg(true, uint256(1) << 40), issuer, compliance, false, address(0))), "zr10");
        NormalZetherRegulatedToken(t).mint(signer, 20_000_000);
        tks.push(Tk("NORMAL_ZETHER_REGULATED", t, RIG_SK, signer, 0xB0B, vm.addr(0xB0B), address(0xFEE), address(0xBEEF), 0, 0, address(0), address(0), 0, 0));
        address w = factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED, 1,
            abi.encode(regulate(_cfg(true, uint256(1) << 40), issuer, compliance, true, address(usd))), "zr11");
        wrapUnits(usd, w, signer);
        tks.push(Tk("WRAPPED_ZETHER_REGULATED", w, RIG_SK, signer, 0xB0B, vm.addr(0xB0B), address(0xFEE), address(0xBEEF), 0, 1, address(usd), address(0), 0, 0));
    }
}

/// Kinds 12 and 13 on the PQZ stack (`PqzFixture`, the precompile mocked).
contract PqzRegRig is PqzFixture, KindRig {
    function init() external {
        vm.warp(P_T0);
        vm.roll(P_BLOCK);
        _stack();
        IFactoryToken.Env memory e = pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv));
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, 1, e,
            type(NormalPqzRegulatedToken).creationCode, regArgs());
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, 1, e,
            type(WrappedPqzRegulatedToken).creationCode, regArgs());
        vm.startPrank(registrar);
        factory.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, true, EnvKit.uidOf(address(factory)));
        factory.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, true, EnvKit.uidOf(address(factory)));
        vm.stopPrank();
        (address issuer, address compliance) = (address(new Holder()), address(new Holder()));
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        address signer = vm.addr(RIG_SK);
        address t = factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, 1,
            abi.encode(regulate(_cfg(uint256(1) << 40), issuer, compliance, false, address(0))), "pr12");
        NormalPqzRegulatedToken(t).mint(signer, 20_000_000);
        tks.push(Tk("NORMAL_PQZ_REGULATED", t, RIG_SK, signer, 0xB0B, vm.addr(0xB0B), address(0xFEE), address(0xBEEF), 0, 0, address(0), address(0), 0, 0));
        address w = factory.createToken(IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, 1,
            abi.encode(regulate(_cfg(uint256(1) << 40), issuer, compliance, true, address(usd))), "pr13");
        wrapUnits(usd, w, signer);
        tks.push(Tk("WRAPPED_PQZ_REGULATED", w, RIG_SK, signer, 0xB0B, vm.addr(0xB0B), address(0xFEE), address(0xBEEF), 0, 1, address(usd), address(0), 0, 0));
    }
}

/// `20_000_000` public units of the one-leg 1:1 wrapper `w` for `who`, by its own wrap.
function wrapUnits(MockERC20 usd, address w, address who) {
    usd.mint(who, 20_000_000);
    VM.startPrank(who);
    usd.approve(w, 20_000_000);
    WrappedToken(payable(w)).wrap(20_000_000);
    VM.stopPrank();
}
