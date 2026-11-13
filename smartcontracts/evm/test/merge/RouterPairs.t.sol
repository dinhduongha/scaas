// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {EnvKit} from "../helpers/EnvKit.sol";
import {Vm} from "forge-std/Test.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {GovRouterFixture, ProbeTarget} from "../governance/GovRouter.t.sol";

/// Takes every call: a signed op that reaches it succeeds, whatever the op.
contract AnyTarget {
    fallback() external {}
}

/// ua-mtx-merge T7 (R14, Q2, spec §3.1): the router's 19 pairs merged. Each op has one signed entry,
/// `mtx<Op>(UAEnvelope, target, <op params>, UASig)` over `UA<Op>` (`target` signed), for a native id by its own key with
/// no registry call and for a derived id through `requireAuthorized`; the address `mtx<Op>(Envelope, …, bytes)` forms and
/// the `ua<Op>` names are gone. Called by selector (built from the type strings below), so this file compiles on the tree
/// before T7 too and each test is red there on its own (plan T7 step 3).
contract RouterPairsTest is GovRouterFixture {
    string constant ENV_UA = "(bytes32,uint256,uint256,uint256,uint32,address,uint256,address)";
    string constant ENV_ADDR = "(address,uint256,uint256,uint256,uint32,address,uint256,address)";
    string constant UASIG = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";

    /// The ABI types of each op's own parameters (after `target`), index = op.
    function _types(uint256 op) internal pure returns (string memory) {
        string[19] memory t = ["uint8,bytes32,bytes32", "uint8,bytes32,bytes32",
            "uint8,bytes32,(uint128,uint128,uint128,uint128,uint32,uint64,uint32,bool,bytes32),bytes32", "uint8,bytes32,bytes32",
            "uint8,bytes32",
            "bytes32,bytes32", "", "bytes32", "uint8,bytes32", "address,uint256", "bytes32,uint256", "address,bytes32", "address,uint96,uint96", "",
            "", "address,address,bool", "address,bool", "bool", "uint32,address"];
        return t[op];
    }

    function _sel(uint256 op, string memory env, string memory sig) internal view returns (bytes4) {
        string memory ty = _types(op);
        return bytes4(keccak256(bytes(string.concat("mtx", rows[op].name, "(", env, ",address",
            bytes(ty).length == 0 ? "" : ",", ty, ",", sig, ")"))));
    }

    /// The merged entry's selector.
    function _merged(uint256 op) internal view returns (bytes4) {
        return _sel(op, ENV_UA, UASIG);
    }

    /// The retired address entry's selector.
    function _old(uint256 op) internal view returns (bytes4) {
        return _sel(op, ENV_ADDR, "bytes");
    }

    function _structHash(uint256 op, bool ua, MetaTxLib.UAEnvelope memory e, address target, bytes memory words)
        internal view returns (bytes32)
    {
        string memory s = string.concat(ua ? "UA" : "", rows[op].name, ua ? "(bytes32 from" : "(address from",
            ",address target", rows[op].params, TAIL);
        if (op == SET_GRANT) s = string.concat(s, TERMS);
        return keccak256(bytes.concat(abi.encode(keccak256(bytes(s)), e.from, target), words,
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
    }

    function _mDigest(GovernanceRouter r, uint256 op, MetaTxLib.UAEnvelope memory e, address target, bytes memory words)
        internal view returns (bytes32)
    {
        return keccak256(abi.encodePacked("\x19\x01", _domain(r), _structHash(op, true, e, target, words)));
    }

    /// `sel` with the envelope, `target`, the op's ABI words `args`, then one dynamic signature value (its encoding `sigTail`).
    function _cd(bytes4 sel, MetaTxLib.UAEnvelope memory e, address target, bytes memory args, bytes memory sigTail)
        internal pure returns (bytes memory)
    {
        bytes memory head = bytes.concat(abi.encode(e), abi.encode(target), args);
        return bytes.concat(sel, head, abi.encode(head.length + 32), sigTail);
    }

    /// The merged call of `op` signed by `from` on `r`, lane `batch`.
    function _mCall(GovernanceRouter r, uint256 op, bytes32 from, uint256 batch, address target, bytes memory args,
        bytes memory words) internal view returns (bytes memory)
    {
        MetaTxLib.UAEnvelope memory e = _envelope(r, from, batch);
        bytes memory tail = _tail(abi.encode(_auth(from, _mDigest(r, op, e, target, words))));
        return _cd(_merged(op), e, target, args, tail);
    }

    function _m(uint256 op, bytes32 from, address target, bytes memory args) internal {
        _runOn(router, _mCall(router, op, from, 0, target, args, args));
    }

    // ------------------------------------------------------------------ every op on the merged entry, EOA and derived

    /// `op` by an EOA (its padded address, its own key) and by a derived id (the PQ key `pq`), from one snapshot.
    function _both(uint256 op) internal {
        uint256 s = vm.snapshotState();
        _rowBy(op, eoa, next);
        vm.revertToState(s);
        _rowBy(op, pq, msig);
    }

    /// The op's effect read on a real token, wrapped token or DEX: `s` signs, `y` is the other party.
    function _rowBy(uint256 op, bytes32 s, bytes32 y) internal {
        if (op == GRANT_ROLE) {
            NormalToken t = _normal(s, 0, 0);
            _m(op, s, address(t), abi.encode(MINT, y, EnvKit.codeUidOf(address(t))));
            assertTrue(t.hasRole(MINT, y), "GrantRole");
        } else if (op == REVOKE_ROLE) {
            NormalToken t = _normal(s, y, 0);
            _m(op, s, address(t), abi.encode(MINT, y, EnvKit.codeUidOf(address(t))));
            assertTrue(t.grantOf(MINT, y).barred, "RevokeRole");
        } else if (op == SET_GRANT) {
            NormalToken t = _normal(s, 0, 0);
            (bytes memory a, bytes memory w) = _setGrantArgs(MINT, y, _limited(100), EnvKit.codeUidOf(address(t)));
            _runOn(router, _mCall(router, op, s, 0, address(t), a, w));
            assertEq(t.grantOf(MINT, y).total, 100, "SetGrant");
        } else if (op == CANCEL_GRANT) {
            NormalToken t = _normal(s, 0, 1 hours);
            _m(GRANT_ROLE, s, address(t), abi.encode(MINT, y, EnvKit.codeUidOf(address(t))));
            _m(op, s, address(t), abi.encode(MINT, y, EnvKit.codeUidOf(address(t))));
            (uint64 eta,,,) = t.pendingGrant(MINT, y);
            assertEq(eta, 0, "CancelGrant");
        } else if (op == DISABLE_FEATURE) {
            NormalToken t = _normal(s, 0, 0);
            _m(op, s, address(t), abi.encode(MINT, EnvKit.codeUidOf(address(t))));
            assertEq(t.features() & (uint256(1) << MINT), 0, "DisableFeature");
        } else if (op == TRANSFER_ADMIN) {
            NormalToken t = _normal(s, 0, 0);
            _m(op, s, address(t), abi.encode(y, EnvKit.codeUidOf(address(t))));
            assertEq(t.pendingAdmin(), y, "TransferAdmin");
        } else if (op == ACCEPT_ADMIN) {
            NormalToken t = _normal(_pad(address(this)), 0, 0);
            t.transferAdmin(s, EnvKit.codeUidOf(address(t)));
            _m(op, s, address(t), "");
            assertEq(t.admin(), s, "AcceptAdmin");
        } else if (op == RENOUNCE_ADMIN) {
            NormalToken t = _normal(s, 0, 0);
            _m(op, s, address(t), abi.encode(EnvKit.codeUidOf(address(t))));
            assertEq(t.admin(), bytes32(0), "RenounceAdmin");
        } else if (op == RENOUNCE_ROLE) {
            NormalToken t = _normal(s, s, 0);
            _m(op, s, address(t), abi.encode(MINT, EnvKit.codeUidOf(address(t))));
            assertFalse(t.hasRole(MINT, s), "RenounceRole");
        } else if (op == OP_MINT) {
            NormalToken t = _normal(s, s, 0);
            _m(op, s, address(t), abi.encode(BOB, uint256(5)));
            assertEq(t.balanceOf(BOB), 5, "Mint");
        } else if (op == MINT_TO_UA) {
            NormalToken t = _normal(s, s, 0);
            _m(op, s, address(t), abi.encode(pq, uint256(3)));
            assertEq(t.balanceOfUA(pq), 3, "MintToUA");
        } else if (op == DISABLE_WRAP) {
            WrappedToken w = _wrapped(s, s, wallet);
            _m(op, s, address(w), abi.encode(address(usd), bytes32("r")));
            (,,,, bool on) = w.legOf(address(usd));
            assertFalse(on, "DisableWrap");
        } else if (op == PROPOSE_RATE || op == CANCEL_RATE || op == EXECUTE_RATE) {
            _rateBy(op, s);
        } else {
            SCaaSDex d = _dex(s);
            if (op == SET_MARKET) {
                address q = address(new MockERC20("Q", "Q", 6));
                _m(op, s, address(d), abi.encode(address(usd), q, true));
                assertTrue(d.marketListed(address(usd), q), "SetMarket");
            } else if (op == SET_EXCHANGE_TARGET) {
                _m(op, s, address(d), abi.encode(address(0xE7), true));
                assertTrue(d.exchangeTarget(address(0xE7)), "SetExchangeTarget");
            } else if (op == SET_LISTED_ONLY) {
                _m(op, s, address(d), abi.encode(true));
                assertTrue(d.listedOnly(), "SetListedOnly");
            } else {
                _m(op, s, address(d), abi.encode(uint32(500_000), TREASURY));
                assertEq(d.relayerSharePpm(), 500_000, "SetFeeSplit");
            }
        }
    }

    /// `RATE_ADJUSTABLE` is contract-only, and a derived UA never holds it (`GovernanceLib._check`): the EOA holds it with
    /// code at its address at the grant only (removed before it signs, so its own key verifies); the derived id reaches the
    /// target on the merged entry and the target refuses it by its own rule (`NotRateAdmin`), the nonce unspent.
    function _rateBy(uint256 op, bytes32 s) internal {
        bytes memory propose = abi.encode(address(usd), uint96(101), uint96(100));
        if (s == pq) {
            WrappedToken w = _wrapped(s, s, wallet);
            bytes memory cd = _mCall(router, op, s, 0, address(w), op == PROPOSE_RATE ? propose : bytes(""),
                op == PROPOSE_RATE ? propose : bytes(""));
            vm.expectRevert(IWrappedToken.NotRateAdmin.selector);
            _runOn(router, cd);
            assertEq(router.mtxNonce(pq, 0), 0, "the target's refusal reverts the call");
            return;
        }
        address a = address(uint160(uint256(s)));
        vm.etch(a, hex"00");
        WrappedToken wt = _wrapped(s, s, s);
        vm.etch(a, "");
        _m(PROPOSE_RATE, s, address(wt), propose);
        (, uint96 num,, uint64 eta) = wt.pendingRate();
        assertTrue(num == 101 && eta != 0, "ProposeRate");
        if (op == CANCEL_RATE) {
            _m(op, s, address(wt), "");
            (,,, eta) = wt.pendingRate();
            assertEq(eta, 0, "CancelRate");
        } else if (op == EXECUTE_RATE) {
            vm.warp(block.timestamp + 2 days);
            _m(op, s, address(wt), "");
            (num,,,,) = wt.legOf(address(usd));
            assertEq(num, 101, "ExecuteRate");
        }
    }

    function test_routerRow_GrantRole() public { _both(GRANT_ROLE); }
    function test_routerRow_RevokeRole() public { _both(REVOKE_ROLE); }
    function test_routerRow_SetGrant() public { _both(SET_GRANT); }
    function test_routerRow_CancelGrant() public { _both(CANCEL_GRANT); }
    function test_routerRow_DisableFeature() public { _both(DISABLE_FEATURE); }
    function test_routerRow_TransferAdmin() public { _both(TRANSFER_ADMIN); }
    function test_routerRow_AcceptAdmin() public { _both(ACCEPT_ADMIN); }
    function test_routerRow_RenounceAdmin() public { _both(RENOUNCE_ADMIN); }
    function test_routerRow_RenounceRole() public { _both(RENOUNCE_ROLE); }
    function test_routerRow_Mint() public { _both(OP_MINT); }
    function test_routerRow_MintToUA() public { _both(MINT_TO_UA); }
    function test_routerRow_DisableWrap() public { _both(DISABLE_WRAP); }
    function test_routerRow_ProposeRate() public { _both(PROPOSE_RATE); }
    function test_routerRow_CancelRate() public { _both(CANCEL_RATE); }
    function test_routerRow_ExecuteRate() public { _both(EXECUTE_RATE); }
    function test_routerRow_SetMarket() public { _both(SET_MARKET); }
    function test_routerRow_SetExchangeTarget() public { _both(SET_EXCHANGE_TARGET); }
    function test_routerRow_SetListedOnly() public { _both(SET_LISTED_ONLY); }
    function test_routerRow_SetFeeSplit() public { _both(SET_FEE_SPLIT); }

    // ------------------------------------------------------------------ the subject, the events, no registry

    /// An EOA's subject is its padded address, what `_mtxCall` wrote (spec §3.1): `_govSubject()` is unchanged. The merged
    /// path emits the `UA…` event only (R18): no address `MetaTransactionExecuted`.
    function test_routerEoaSubjectIsPaddedAddress() public {
        ProbeTarget p = new ProbeTarget(router);
        address a = address(uint160(uint256(eoa)));
        vm.recordLogs();
        _m(SET_LISTED_ONLY, eoa, address(p), abi.encode(true));
        assertEq(p.seen(), bytes32(uint256(uint160(a))), "pad(addr)");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 ua;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(router)) continue;
            assertTrue(logs[i].topics[0] != IMetaTx.MetaTransactionExecuted.selector, "no address event");
            if (logs[i].topics[0] == IUALedger.UAMetaTransactionExecuted.selector) {
                assertEq(logs[i].topics[1], eoa);
                ++ua;
            }
        }
        assertEq(ua, 1, "one UAMetaTransactionExecuted");
    }

    /// A native id needs no registry (B, R9): on a router with none, an EOA runs every kind of op; a derived id there is
    /// `UALedgerOff` by name (C).
    function test_routerEoaWithoutRegistry() public {
        router = new GovernanceRouter(chainUidA, address(0), address(0), false);
        assertEq(address(router.registry()), address(0));
        NormalToken t = _normal(eoa, eoa, 0);
        _m(OP_MINT, eoa, address(t), abi.encode(BOB, uint256(5)));
        assertEq(t.balanceOf(BOB), 5);
        bytes memory cd = _mCall(router, OP_MINT, pq, 0, address(t), abi.encode(BOB, uint256(1)), abi.encode(BOB, uint256(1)));
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        _runOn(router, cd);
    }

    // ------------------------------------------------------------------ the ordered cancel (Q2, R19)

    function test_routerCancelIsNonceOrdered_native() public {
        _ordered(eoa);
    }

    function test_routerCancelIsNonceOrdered_derived() public {
        _ordered(pq);
    }

    function _cancel(bytes32 who, uint256 batch, uint256 nonce, uint256 lane) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e =
            MetaTxLib.UAEnvelope(who, batch, nonce, block.timestamp + 1 hours, 0, address(0), 0, address(0));
        bytes32 d = MtxDigest.typed(address(router), keccak256(abi.encode(MetaTxLib.UA_CANCEL_NONCE_TYPEHASH, who, lane,
            batch, nonce, e.validUntil, uint32(0), address(0), uint256(0), address(0))));
        return abi.encodeWithSignature(string.concat("mtxCancelNonce(", ENV_UA, ",uint256,", UASIG, ")"), e, lane,
            _auth(who, d));
    }

    /// A cancel signed at nonce 0 of lane 3, withheld; a newer merged op consumes nonce 0 of lane 3; the cancel then cannot
    /// land, lane 9 untouched. Positive control: the cancel at nonce 1 lands and bumps lane 9.
    function _ordered(bytes32 who) internal {
        ProbeTarget p = new ProbeTarget(router);
        bytes memory withheld = _cancel(who, 3, 0, 9);
        _runOn(router, _mCall(router, SET_LISTED_ONLY, who, 3, address(p), abi.encode(true), abi.encode(true)));
        assertEq(p.seen(), who, "the newer op ran");
        (bool ok, bytes memory ret) = address(router).call(withheld);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        assertEq(router.mtxNonce(who, 9), 0, "lane 9 untouched");
        _runOn(router, _cancel(who, 3, 1, 9));
        assertEq(router.mtxNonce(who, 9), 1, "positive control");
    }

    // ------------------------------------------------------------------ the generic entries and the retired forms

    /// `mtxExecute`, `mtxBatch` and `executeMetaTransaction` refuse whatever the blob calls, for a native and a derived
    /// signer: a governed op, the router's own merged op, `cancelNonce`, no selector. Nonces unspent; positive control: the
    /// same subjects' merged op runs.
    function test_routerGenericEntriesRefuseEveryCall() public {
        NormalToken t = _normal(pq, pq, 0);
        bytes[4] memory blobs = [abi.encodeCall(IGovernance.grantRole, (MINT, eoa, EnvKit.codeUidOf(address(t)))),
            _mCall(router, OP_MINT, pq, 0, address(t), abi.encode(BOB, uint256(1)), abi.encode(BOB, uint256(1))),
            abi.encodeCall(IMetaTx.cancelNonce, (7)), bytes("")];
        bytes32[2] memory who = [eoa, pq];
        for (uint256 b; b < blobs.length; ++b) {
            bytes4 refused = bytes4(blobs[b]);
            address a = address(uint160(uint256(eoa)));
            MetaTxLib.MetaTransaction memory m =
                MetaTxLib.MetaTransaction(a, blobs[b], 0, 0, block.timestamp + 1 hours, 0, address(0), 0, address(0));
            bytes memory sig = _ecdsa(eoa, MtxDigest.metaTx(address(router), m));
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, refused));
            router.executeMetaTransaction(m, sig);
            for (uint256 i; i < 2; ++i) {
                MetaTxLib.UAMetaTransaction[] memory us = new MetaTxLib.UAMetaTransaction[](1);
                IUARegistry.UASig[] memory as_ = new IUARegistry.UASig[](1);
                us[0] = MetaTxLib.UAMetaTransaction(who[i], blobs[b], 0, 0, block.timestamp + 1 hours, 0, address(0), 0,
                    address(0));
                as_[0] = _auth(who[i], router.mtxDigest(us[0]));
                vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, refused));
                router.mtxExecute(us[0], as_[0]);
                vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(0)));
                router.mtxBatch(us, as_);
            }
        }
        assertEq(router.mtxNonce(eoa, 0) + router.mtxNonce(pq, 0), 0, "nonces unspent");
        _m(OP_MINT, pq, address(t), abi.encode(BOB, uint256(1)));
        ProbeTarget p = new ProbeTarget(router);
        _m(SET_LISTED_ONLY, eoa, address(p), abi.encode(true));
        assertEq(t.balanceOf(BOB), 1);
        assertEq(p.seen(), eoa);
    }

    /// Invariant 3: a signature over the old address `<Op>` struct has no entry: its own calldata finds no function
    /// (empty revert), and put on the merged entry it verifies nothing (another typehash). Positive control per op: the
    /// same signer's `UA<Op>` signature on the merged entry runs. The target takes every call, so only the router refuses.
    function test_routerOldAddressSignatureHasNoEntry() public {
        address target = address(new AnyTarget());
        for (uint256 op; op < 19; ++op) _oldHasNoEntry(op, target);
        assertEq(router.mtxNonce(eoa, 0), 19);
    }

    function _oldHasNoEntry(uint256 op, address target) internal {
        bytes memory args = _anyArgs(op);
        bytes memory words = args;
        if (op == SET_GRANT) (args, words) = _setGrantArgs(MINT, next, _limited(1), keccak256("a chain word"));
        MetaTxLib.UAEnvelope memory e = _envelope(router, eoa, 0);
        bytes memory oldSig = _ecdsa(eoa, keccak256(abi.encodePacked("\x19\x01", _domain(router),
            _structHash(op, false, e, target, words))));
        (bool ok, bytes memory ret) = address(router).call(_cd(_old(op), e, target, args, _tail(abi.encode(oldSig))));
        assertFalse(ok, rows[op].name);
        assertEq(ret.length, 0, rows[op].name);
        IUARegistry.UASig memory a;
        a.signature = oldSig;
        (ok, ret) = address(router).call(_cd(_merged(op), e, target, args, _tail(abi.encode(a))));
        assertFalse(ok, rows[op].name);
        assertEq(bytes4(ret), IMetaTx.MetaTxBadSignature.selector, rows[op].name);
        a = _auth(eoa, _mDigest(router, op, e, target, words));
        _runOn(router, _cd(_merged(op), e, target, args, _tail(abi.encode(a)))); // positive control
    }

    /// Well-formed op words for `op` (the old form never reaches its target).
    function _anyArgs(uint256 op) internal view returns (bytes memory) {
        string memory ty = _types(op);
        if (bytes(ty).length == 0) return "";
        if (op == GRANT_ROLE || op == REVOKE_ROLE || op == CANCEL_GRANT) return abi.encode(MINT, next, keccak256("a chain word"));
        if (op == DISABLE_FEATURE) return abi.encode(MINT, keccak256("a chain word"));
        if (op == RENOUNCE_ROLE) return abi.encode(MINT, keccak256("a chain word"));
        if (op == TRANSFER_ADMIN) return abi.encode(next, keccak256("a chain word"));
        if (op == RENOUNCE_ADMIN) return abi.encode(keccak256("a chain word"));
        if (op == OP_MINT) return abi.encode(BOB, uint256(1));
        if (op == MINT_TO_UA) return abi.encode(pq, uint256(1));
        if (op == DISABLE_WRAP) return abi.encode(address(usd), bytes32("r"));
        if (op == PROPOSE_RATE) return abi.encode(address(usd), uint96(1), uint96(1));
        if (op == SET_MARKET) return abi.encode(address(usd), address(0xBA5E), true);
        if (op == SET_EXCHANGE_TARGET) return abi.encode(address(0xE7), true);
        if (op == SET_LISTED_ONLY) return abi.encode(true);
        return abi.encode(uint32(1), TREASURY); // SET_FEE_SPLIT
    }
}
