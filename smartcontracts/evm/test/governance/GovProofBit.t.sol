// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";

import {Vm} from "forge-std/Vm.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {noVerdict} from "../pqz/helpers/PqzVerdicts.sol";
import {PqzOffchainBase} from "../pqz/helpers/PqzOffchainBase.sol";
import {PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {NormalPqzRegulatedToken} from "../../src/regulated/NormalPqzRegulatedToken.sol";
import {WrappedPqzRegulatedToken} from "../../src/regulated/WrappedPqzRegulatedToken.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {WrappedRegulatedToken} from "../../src/regulated/WrappedRegulatedToken.sol";
import {NormalZetherRegulatedToken} from "../../src/regulated/NormalZetherRegulatedToken.sol";
import {WrappedZetherRegulatedToken} from "../../src/regulated/WrappedZetherRegulatedToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceRouterTypes} from "../../src/governance/GovernanceRouterBase.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue, pqzEnv, plainEnv, regArgs} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {Holder} from "../as/helpers/RegFixture.sol";
import {UACall} from "../ua/UACall.sol";
import {nid} from "../helpers/Ids.sol";

/// Test only: the masks `GovernanceLib` receives from each PQZ kind (bit 24 on 4, 5, 12, 13).
contract Bit24Masks4 is NormalPqzToken {
    constructor(address f_, bytes memory a) NormalPqzToken(f_, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _delayedRelaxBits());
    }
}

contract Bit24Masks5 is WrappedPqzToken {
    constructor(address f_, bytes memory a) WrappedPqzToken(f_, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _delayedRelaxBits());
    }
}

contract Bit24Masks12 is NormalPqzRegulatedToken {
    constructor(address f_, bytes memory a) NormalPqzRegulatedToken(f_, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _delayedRelaxBits());
    }
}

contract Bit24Masks13 is WrappedPqzRegulatedToken {
    constructor(address f_, bytes memory a) WrappedPqzRegulatedToken(f_, a) {}
    function masks() external pure returns (uint256, uint256, uint256, uint256) {
        return (_validBits(), _roleBits(), _contractOnlyBits(), _delayedRelaxBits());
    }
}

/// Group 3h, T61 (spec 2026-11-06-pqz-proof-path §5, O10; CTR-PQZ-35 draft): bit 24 `PQZ_PROOF`, valid on the PQZ kinds 4, 5,
/// 12, 13 only; any holder (EOA, single-key UA, `msig`, contract), granted with the issuer seat (`ISSUER_BITS`), never
/// contract-only, never delay-relaxed; `setProofStore(next)` gated by `use(24)`, `NONE` <-> `LOG` from the next debit, the
/// current value a no-op without an event; disabling the bit freezes the value; relayed by the router as `mtxSetProofStore`
/// over `UASetProofStore` (fee mode `NONE`), the token's allow-list unchanged. The PQZ precompile is mocked. UNAUDITED.
contract GovProofBitTest is PqzOffchainBase {
    uint8 internal constant BIT = 24;
    uint256 internal constant LANE = 9;
    uint256 internal constant NKEY = 0x24B17;
    bytes32 internal constant EV_SET = keccak256("ProofStoreSet(uint8,uint8)");
    bytes32 internal constant EV_PROOF = keccak256("PqzDebitProof(address,bytes32,uint64,bytes,bytes)");
    bytes internal constant PROOF = hex"c0ffee";

    GovernanceRouter internal router;
    OpenFactory internal f;
    bytes32 internal nId; // a native holder that signs router ops with `NKEY`
    bytes32 internal owner_;

    function setUp() public {
        _offStack();
        nId = nid(vm.addr(NKEY));
        owner_ = nid(address(this));
        router = new GovernanceRouter(PQZ_UID, address(reg), address(0), false);
        f = new OpenFactory(registrar);
        EnvKit.configure(f, PQZ_UID, 0, address(router));
        IFactoryToken.Env memory e = pqzEnv(address(f), PQZ_UID, address(reg), address(pqv));
        Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_PQZ, 1, e, type(NormalPqzToken).creationCode);
        Catalogue.release(f, IOpenFactory.TokenKind.WRAPPED_PQZ, 1, e, type(WrappedPqzToken).creationCode);
        Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, 1, e, type(NormalPqzRegulatedToken).creationCode,
            regArgs());
        Catalogue.release(f, IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, 1, e, type(WrappedPqzRegulatedToken).creationCode,
            regArgs());
        vm.startPrank(registrar);
        f.setKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true);
        f.setKindEnabled(IOpenFactory.TokenKind.WRAPPED_PQZ, true);
        f.setKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, true);
        f.setKindEnabled(IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, true);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ tokens

    /// A token of PQZ kind `k` (4, 5, 12, 13) with bit 24 set (unless `withBit` is false), `issuer` its issuer seat (0: none),
    /// the test its owner, `delay` its grant delay.
    function _tok24(uint8 k, bytes32 issuer, bool withBit, uint64 delay) internal returns (NormalPqzToken t) {
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        (c.owner, c.grantDelay, c.lockedFeatures) = (owner_, delay, 0);
        if (k == 5 || k == 13) {
            c.features = 1 << GovernanceBits.PAYABLE;
            c.roles.minter = 0;
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
        }
        if (withBit) c.features |= uint256(1) << BIT;
        c.roles.issuer = issuer;
        t = NormalPqzToken(f.createToken(IOpenFactory.TokenKind(k), 1, abi.encode(c), keccak256(abi.encode(k, issuer, withBit, delay))));
    }

    function _setEvents(address t) internal returns (uint256 n) {
        Vm.Log[] memory ls = vm.getRecordedLogs();
        for (uint256 i; i < ls.length; ++i) if (ls[i].emitter == t && ls[i].topics[0] == EV_SET) ++n;
    }

    /// `UASetProofStore(next)` for `from`, signed by `sign` (native `NKEY`, or a derived id's filler signature), relayed by
    /// a relayer the struct does not bind (fee mode `NONE`: the envelope's relayer and fee recipient set, zero in the digest).
    function _routerSet(bytes32 from, address target, uint8 next) internal {
        MetaTxLib.UAEnvelope memory u = MetaTxLib.UAEnvelope(from, LANE, router.mtxNonce(from, LANE), block.timestamp + 300, 0,
            address(0xBEEF), 0, address(0xFEE));
        bytes32 sh = keccak256(bytes.concat(abi.encode(GovernanceRouterTypes.UA_SET_PROOF_STORE, u.from), abi.encode(target),
            abi.encode(next), abi.encode(u.batch, u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))));
        IUARegistry.UASig memory auth;
        if (from == nId) {
            (uint8 vv, bytes32 r, bytes32 ss) = vm.sign(NKEY, MessageHashUtils.toTypedDataHash(_sepOf(address(router)), sh));
            auth.signature = abi.encodePacked(r, ss, vv);
        } else {
            auth = UACall.auth(from, _mlAuth());
        }
        vm.prank(address(0x4E1A));
        router.mtxSetProofStore(u, target, next, auth);
    }

    // ------------------------------------------------------------------ the kinds

    function _validKind(uint8 k) internal {
        (uint256 v, uint256 r, uint256 c, uint256 d) = k == 4 ? new Bit24Masks4(address(f), kindArgs(4, address(f), "")).masks()
            : k == 5 ? new Bit24Masks5(address(f), kindArgs(5, address(f), "")).masks() : k == 12 ? new Bit24Masks12(address(f), kindArgs(12, address(f), regArgs())).masks()
            : new Bit24Masks13(address(f), kindArgs(13, address(f), regArgs())).masks();
        uint256 m = uint256(1) << BIT;
        assertTrue(v & m != 0, "valid");
        assertTrue(r & m != 0, "a role bit (a power)");
        assertEq(c & m, 0, "never contract-only");
        assertEq(d & m, 0, "never delay-relaxed");
        assertTrue(GovernanceBits.ISSUER_BITS & m != 0, "granted with the issuer seat");
        NormalPqzToken t = _tok24(k, nId, true, 0);
        assertTrue(IGovernance(address(t)).features() & m != 0);
        assertTrue(IGovernance(address(t)).hasRole(BIT, nId), "init grants it to the issuer");
        assertTrue(IGovernance(address(t)).validBits() & m != 0);
    }

    function test_bit24_validKinds_4() public { _validKind(4); }
    function test_bit24_validKinds_5() public { _validKind(5); }
    function test_bit24_validKinds_12() public { _validKind(12); }
    function test_bit24_validKinds_13() public { _validKind(13); }

    /// Every other kind refuses it: 0-3 and 8-11 (Zether's 2, 3, 10, 11 among them) have it outside `validBits()`, and a
    /// creation that sets it reverts `FeatureInvalidForKind(24)` (kind 0 and kind 2 through a factory).
    function test_bit24_otherKindsRefused() public {
        uint256 m = uint256(1) << BIT;
        address[8] memory impls = [address(new NormalToken(address(f), kindArgs(0, address(f), ""))), address(new WrappedToken(address(f), kindArgs(1, address(f), ""))),
            address(new NormalZetherToken(address(f), kindArgs(2, address(f), ""))), address(new WrappedZetherToken(address(f), kindArgs(3, address(f), ""))),
            address(new NormalRegulatedToken(address(f), kindArgs(8, address(f), regArgs()))), address(new WrappedRegulatedToken(address(f), kindArgs(9, address(f), regArgs()))),
            address(new NormalZetherRegulatedToken(address(f), kindArgs(10, address(f), regArgs()))),
            address(new WrappedZetherRegulatedToken(address(f), kindArgs(11, address(f), regArgs())))];
        for (uint256 i; i < 8; ++i) assertEq(IGovernance(impls[i]).validBits() & m, 0, vm.toString(i));
        // the creation path: a PQZ kind's config with the bit, on kind 4's own factory refused nowhere else (the control)
        _tok24(4, 0, true, 0);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features |= m;
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL, 1, _plain(), type(NormalToken).creationCode);
        vm.prank(registrar);
        factory.setKindEnabled(IOpenFactory.TokenKind.NORMAL, true);
        c.conf = IFactoryToken.ConfidentialConfig("", 0, 0, 0, 0, 0, 0, 0, bytes32(0), false, 0);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, BIT));
        factory.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "plain-24");
    }

    function _plain() internal view returns (IFactoryToken.Env memory) {
        return plainEnv(address(factory), address(0), PQZ_UID, address(reg), false);
    }

    // ------------------------------------------------------------------ the holders (O10: any)

    function _holderSets(NormalPqzToken t, bytes32 h, bool viaRouter) internal {
        if (viaRouter) _routerSet(h, address(t), PqzCore.LOG);
        else {
            vm.prank(address(uint160(uint256(h))));
            t.setProofStore(PqzCore.LOG);
        }
        assertEq(t.proofStore(), PqzCore.LOG);
    }

    function test_bit24_anyHolder_eoa() public {
        // a native EOA id: direct, and through the router with its own key
        address a = vm.addr(0xE0A);
        _holderSets(_tok24(4, nid(a), true, 0), nid(a), false);
        _holderSets(_tok24(12, nId, true, 0), nId, true);
    }

    function test_bit24_anyHolder_singleKey() public {
        bytes32 ua = _mldsaUA(77); // a derived single-key `mldsa65` UA (its precompile mocked)
        _holderSets(_tok24(5, ua, true, 0), ua, true);
        _holderSets(_tok24(13, ua, true, 1 days), ua, true);
    }

    function test_bit24_anyHolder_msig() public {
        bytes32 ms = keccak256("bit 24 msig");
        vm.mockCall(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, ms), "");
        _holderSets(_tok24(4, ms, true, 0), ms, true);
        _holderSets(_tok24(12, ms, true, 1 days), ms, true);
    }

    function test_bit24_anyHolder_contract() public {
        address h = address(new Holder());
        _holderSets(_tok24(5, nid(h), true, 0), nid(h), false);
        _holderSets(_tok24(13, nid(h), true, 1 days), nid(h), false);
    }

    /// Kinds 4 and 5 have no issuer bit but this one: `roles.issuer` takes it alone (a plain PQZ kind's init grant path),
    /// and without the bit the seat is refused as before (`RoleWithoutFeature`).
    function test_bit24_plainKindIssuerGrant() public {
        for (uint8 k = 4; k <= 5; ++k) {
            NormalPqzToken t = _tok24(k, nId, true, 0);
            assertTrue(IGovernance(address(t)).hasRole(BIT, nId));
            assertEq(IGovernance(address(t)).holderCount(BIT), 1);
            IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
            (c.owner, c.lockedFeatures, c.roles.issuer) = (owner_, 0, nId);
            if (k == 5) {
                c.features = 1 << GovernanceBits.PAYABLE;
                c.roles.minter = 0;
                c.legs = new IFactoryToken.Leg[](1);
                c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
            }
            vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, GovernanceBits.FREEZE));
            f.createToken(IOpenFactory.TokenKind(k), 1, abi.encode(c), keccak256(abi.encode("no bit", k)));
        }
    }

    /// Not delay-relaxed: on a regulated kind with a grant delay, the owner's `disableFeature(24)` and `revokeRole` apply at
    /// once (bits 5-7 wait the delay there).
    function test_bit24_notDelayed() public {
        for (uint8 k = 12; k <= 13; ++k) {
            NormalPqzToken t = _tok24(k, nId, true, 1 days);
            IGovernance(address(t)).revokeRole(BIT, nId);
            assertFalse(IGovernance(address(t)).hasRole(BIT, nId), "revoked at once");
            IGovernance(address(t)).disableFeature(BIT);
            assertEq(IGovernance(address(t)).features() & (uint256(1) << BIT), 0, "disabled at once");
        }
    }

    // ------------------------------------------------------------------ the power

    function test_setProofStore_gated() public {
        NormalPqzToken t = _tok24(4, nId, true, 0);
        bytes32 stranger = nid(address(0x5742));
        vm.prank(address(0x5742));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, BIT, stranger));
        t.setProofStore(PqzCore.LOG);
        NormalPqzToken off = _tok24(4, 0, false, 0);
        vm.prank(vm.addr(NKEY));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, BIT));
        off.setProofStore(PqzCore.LOG);
        vm.prank(vm.addr(NKEY));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.ProofStoreInvalid.selector, uint8(2)));
        t.setProofStore(2);
        assertEq(t.proofStore(), PqzCore.NONE);
    }

    /// The current value: no write, no event; a change: `ProofStoreSet(previous, next)`.
    function test_setProofStore_noop() public {
        NormalPqzToken t = _tok24(5, nId, true, 0);
        vm.recordLogs();
        vm.prank(vm.addr(NKEY));
        t.setProofStore(PqzCore.NONE);
        assertEq(_setEvents(address(t)), 0, "same value: no event");
        vm.recordLogs();
        vm.prank(vm.addr(NKEY));
        t.setProofStore(PqzCore.LOG);
        Vm.Log[] memory ls = vm.getRecordedLogs();
        assertEq(ls.length, 1);
        assertEq(ls[0].topics[0], EV_SET);
        assertEq(ls[0].data, abi.encode(PqzCore.NONE, PqzCore.LOG));
        vm.recordLogs();
        vm.prank(vm.addr(NKEY));
        t.setProofStore(PqzCore.LOG);
        assertEq(_setEvents(address(t)), 0, "same value again: no event");
        assertEq(uint8(uint256(vm.load(address(t), PqzCore._STORAGE)) >> 184), PqzCore.LOG, "slot 0 byte 23");
        assertEq(uint8(uint256(vm.load(address(t), PqzCore._STORAGE)) >> 176), 0, "byte 22, pqzVerifyMode, untouched");
    }

    function _debit(NormalPqzToken t, uint64 k, bool wantLog) internal {
        IPqzToken.PqzTransferArgs memory a = _ts(_payloadFor(t, alice, bob, bytes32(0), _out(40 + k, false)));
        vm.recordLogs();
        t.mtxConfidentialTransferSingle(a, PROOF, _pqAuth(), "", noVerdict());
        Vm.Log[] memory ls = vm.getRecordedLogs();
        uint256 n;
        for (uint256 i; i < ls.length; ++i) if (ls[i].emitter == address(t) && ls[i].topics[0] == EV_PROOF) ++n;
        assertEq(n, wantLog ? 1 : 0, "the debit logs by the mode set before it");
        assertEq(t.pqzDebitRecord(alice, k).proofStore, wantLog ? PqzCore.LOG : PqzCore.NONE, "its record");
    }

    /// `NONE` -> `LOG` -> `NONE`, each effective from the next debit.
    function test_proofStore_change_appliesNextDebit() public {
        NormalPqzToken t = _tok24(4, nId, true, 0);
        _shieldOn(t, alice, 10);
        _debit(t, 0, false);
        _routerSet(nId, address(t), PqzCore.LOG);
        _debit(t, 1, true);
        _debit(t, 2, true);
        _routerSet(nId, address(t), PqzCore.NONE);
        _debit(t, 3, false);
    }

    /// Disabling the bit freezes the current value: no holder can change it, debits go on in it.
    function _frozen(uint8 mode) internal {
        NormalPqzToken t = _tok24(12, nId, true, 1 days);
        _shieldOn(t, alice, 10);
        if (mode != PqzCore.NONE) _routerSet(nId, address(t), mode);
        IGovernance(address(t)).disableFeature(BIT);
        vm.prank(vm.addr(NKEY));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, BIT));
        t.setProofStore(mode == PqzCore.NONE ? PqzCore.LOG : PqzCore.NONE);
        assertEq(t.proofStore(), mode, "frozen");
        _debit(t, 0, mode == PqzCore.LOG);
    }

    function test_disable24_freezesValue_none() public { _frozen(PqzCore.NONE); }
    function test_disable24_freezesValue_log() public { _frozen(PqzCore.LOG); }

    /// The router op with a relayer and fee recipient the struct does not bind (fee mode `NONE`), for a native holder; the
    /// nonce spent once; a replay refused.
    function test_router_UASetProofStore() public {
        NormalPqzToken t = _tok24(13, nId, true, 0);
        _routerSet(nId, address(t), PqzCore.LOG);
        assertEq(t.proofStore(), PqzCore.LOG);
        assertEq(router.mtxNonce(nId, LANE), 1);
        _routerSet(nId, address(t), PqzCore.NONE);
        assertEq(t.proofStore(), PqzCore.NONE);
        assertEq(router.mtxNonce(nId, LANE), 2);
    }

    /// `setProofStore` is a direct entry (the router relays it): on none of the four kinds' `mtxSelectors()`, and their lists
    /// are T60's (the hash of each kind's list pinned at 6dbb5d3d).
    function test_mtxSelectors_unchanged() public {
        bytes32[4] memory pin = [MTX_SELECTORS_4, MTX_SELECTORS_5, MTX_SELECTORS_12, MTX_SELECTORS_13];
        uint8[4] memory ks = [4, 5, 12, 13];
        for (uint256 i; i < 4; ++i) {
            NormalPqzToken t = _tok24(ks[i], nId, true, 0);
            (bytes4[] memory s,,) = IMetaTx(address(t)).mtxSelectors();
            for (uint256 j; j < s.length; ++j) assertTrue(s[j] != IPqzToken.setProofStore.selector, "not allow-listed");
            assertEq(keccak256(abi.encode(s)), pin[i], vm.toString(ks[i]));
        }
    }

    // keccak256(abi.encode(mtxSelectors().selectors)) at 6dbb5d3d (T60), before bit 24: 10 entries on 4 and 12, 18 on 5 and 13
    bytes32 internal constant MTX_SELECTORS_4 = 0xf6b2b0249c9faf7bac2d7443099d69a3b581d327aea7bee34feb215a043327e7;
    bytes32 internal constant MTX_SELECTORS_5 = 0x2138d643ab3bd760acfaa297443ccb3bac0b302e96c3063baf82c791e828687e;
    bytes32 internal constant MTX_SELECTORS_12 = MTX_SELECTORS_4;
    bytes32 internal constant MTX_SELECTORS_13 = MTX_SELECTORS_5;
}
