// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {EnvKit} from "../helpers/EnvKit.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVault} from "../../src/pqvault/PqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";
import {PqVaultBase} from "./PqVaultBase.sol";

/// PqVault plan V6 (spec §5.14, §5.15): gas rows of `PqVault`, `isolate = true`, so each figure is one transaction's:
/// `vm.lastCallGas()` regular gas (intrinsic and calldata floor included) and the EIP-8037 state gas apart. Signatures go through
/// the stand-in verifier (`MockVerifier`, no work), so a row is `PqVault`'s and the registry's own cost; a real signer adds its
/// verifier's regular gas (FN-DSA-512 about 2.3 M, ML-DSA-65 on the cached key about 5.8 M, an EIP-8355 precompile about 0.2 M).
/// Pins: regular within ±500 gas, state exact (`GAS_MEASURE=true`: the figures, no pin); a move needs old -> new figures in its
/// commit. Members are ML-DSA-65 stand-ins; a wrap is 1,688 B packed. **UNAUDITED.**
contract PqVaultGasTest is PqVaultBase {
    uint256 internal constant SLACK = 500;
    /// FN-DSA-512's verifier, regular gas, once per signed write (spec §5.8: the batch sizing rule's 2.3 M).
    uint256 internal constant FNDSA_VERIFY = 2_300_000;

    function _row(string memory what, uint256 regular, uint256 state) internal returns (uint256 r, uint256 s) {
        Vm.Gas memory g = vm.lastCallGas();
        (r, s) = (g.gasTotalUsed, uint256(int256(g.gasStateUsed)));
        emit log_named_uint(string.concat("GAS ", what, " regular"), r);
        emit log_named_uint(string.concat("GAS ", what, " state"), s);
        emit log_named_uint(string.concat("GAS ", what, " total"), r + s);
        if (!vm.envOr("GAS_MEASURE", false)) {
            assertApproxEqAbs(r, regular, SLACK, string.concat(what, " regular"));
            assertEq(s, state, string.concat(what, " state"));
        }
    }

    function _ct(uint256 n) internal pure returns (bytes memory c) {
        c = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            bytes32 x = keccak256(abi.encode(n, i));
            for (uint256 j; j < 32 && i + j < n; ++j) {
                c[i + j] = x[j];
            }
        }
    }

    function _createVault(uint256 n, uint64 nonce, uint8 mode)
        internal
        returns (bytes32 vid, IPqVault.PqVaultCreate memory v)
    {
        IPqChat.Wrap[] memory w;
        (v, w) = _vault(n, nonce, mode, address(vault));
        IUARegistry.UASig memory sig = _createSig(v, address(vault));
        vm.prank(STRANGER);
        vid = vault.createVault(v, w, sig);
    }

    function _item(bytes32 vid, bytes32 epochId, bytes32 author, uint64 nonce, uint256 len, uint8 mode)
        internal
        returns (bytes32)
    {
        IPqVault.PqVaultItem memory it = IPqVault.PqVaultItem(vid, epochId, author, nonce, _ct(len));
        IUARegistry.UASig memory sig = _sig(author, h.item(it, _ds(mode, address(vault))));
        vm.prank(STRANGER);
        return vault.createItem(it, sig);
    }

    function _edit(bytes32 iid, bytes32 epochId, bytes32 author, uint64 nonce, uint32 version, uint8 mode) internal {
        IPqVault.PqVaultEdit memory d = IPqVault.PqVaultEdit(iid, epochId, author, nonce, version, _ct(288));
        IUARegistry.UASig memory sig = _sig(author, h.edit(d, _ds(mode, address(vault))));
        vm.prank(STRANGER);
        vault.editItem(d, sig);
    }

    function _share(bytes32 vid, bytes32 parent, uint64 nonce, uint256 n, uint8 mode) internal returns (bytes32) {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], nonce, 1, parent, _list(ids[0]), _members(n));
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e, _ds(mode, address(vault))));
        vm.prank(STRANGER);
        return vault.rekeyVault(e, w, sig);
    }

    // ----- mode 0 (portable) -----

    function test_gas_personalVault() public {
        (bytes32 vid,) = _createVault(1, 1, 0);
        _row("createVault 1 member, its wrap", 267_160, 6_675_390);
        _item(vid, vid, ids[0], 1, 288, 0);
        _row("createItem 288 B, new list", 169_328, 1_459_620);
        bytes32 iid = _item(vid, vid, ids[0], 2, 288, 0);
        _row("createItem 288 B, warm list", 169_340, 1_263_780);
        _edit(iid, vid, ids[0], 3, 2, 0);
        _row("editItem 288 B, first", 163_499, 1_263_780);
        _edit(iid, vid, ids[0], 4, 3, 0);
        _row("editItem 288 B, later", 163_499, 1_165_860);
        _item(vid, vid, ids[0], 5, 4128, 0);
        _row("createItem 4,128 B", 310_168, 7_138_980);
        _item(vid, vid, ids[0], 6, 16_416, 0);
        _row("createItem 16,416 B", 1_096_600, 25_939_620);
        _share(vid, vid, 7, 2, 0);
        _row("rekeyVault 1 -> 2 members (share), both wraps", 398_975, 9_943_470);
    }

    function test_gas_sharedVault() public {
        (bytes32 vid, IPqVault.PqVaultCreate memory v) = _createVault(2, 1, 0);
        _row("createVault 2 members, both wraps", 396_184, 9_747_630);
        (vid, v) = _createVault(3, 2, 0);
        IPqVault.PqVaultRemove memory r = IPqVault.PqVaultRemove(vid, vid, 1, _list(ids[2]), ids[0], 1);
        IUARegistry.UASig memory sig = _sig(ids[0], h.remove(r, PqVaultTypes.DS_V));
        vm.prank(STRANGER);
        vault.removeVaultMembers(r, sig);
        _row("removeVaultMembers 1 of 3", 176_568, 1_410_660);
        IPqVault.PqVaultLeave memory l = IPqVault.PqVaultLeave(vid, vid, ids[1], 2);
        sig = _sig(ids[1], h.leave(l, PqVaultTypes.DS_V));
        vm.prank(STRANGER);
        vault.leaveVault(l, sig);
        _row("leaveVault", 111_431, 195_840);
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 3, 1, vid, _list(ids[0]), _members(1));
        sig = _sig(e.author, h.epoch(e, PqVaultTypes.DS_V));
        vm.prank(STRANGER);
        vault.rekeyVault(e, w, sig);
        _row("rekeyVault 3 -> 1 after a removal and a leave", 320_352, 6_773_310);
        (bytes32 v2,) = _createVault(2, 3, 0);
        (e, w) = _epoch(v2, ids[0], 1, 1, v2, _list(ids[0]), _members(1));
        sig = _sig(e.author, h.epoch(e, PqVaultTypes.DS_V));
        vm.prank(STRANGER);
        vault.rekeyVault(e, w, sig);
        _row("rekeyVault 2 -> 1", 310_007, 6_871_230);
    }

    function test_gas_chunks() public {
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(2, 1, 0, address(vault));
        IUARegistry.UASig memory sig = _createSig(v, address(vault));
        IPqChat.Wrap[] memory first = _slice(w, 0, 1);
        vm.prank(STRANGER);
        bytes32 vid = vault.createVault(v, first, sig);
        IPqChat.Wrap[] memory rest = _slice(w, 1, 2);
        vm.prank(STRANGER);
        vault.addVaultWraps(vid, 1, rest);
        _row("addVaultWraps 1 wrap, completing", 144_280, 2_865_690);
    }

    function _batch(bytes32 vid, uint64 nonce, uint256 n) internal view returns (IPqVault.PqVaultBatch memory b) {
        b = IPqVault.PqVaultBatch(vid, vid, ids[0], nonce, new IPqVault.PqVaultItem[](n));
        for (uint256 i; i < n; ++i) {
            b.items[i] = IPqVault.PqVaultItem(vid, vid, ids[0], nonce + 1 + uint64(i), _ct(288));
        }
    }

    function _createItems(IPqVault.PqVaultBatch memory b) internal {
        IUARegistry.UASig memory sig = _sig(b.author, h.batch(b, PqVaultTypes.DS_V));
        vm.prank(STRANGER);
        vault.createItems(b, sig);
    }

    /// The largest batch of password items (288 B) that fits `(regular + state + 2.3 M) x 1.05 <= 60 M` with FN-DSA-512's
    /// verifier added (EIP-8037 inclusion), regular x 1.05 under 2^24 too (spec §5.8, CTR-PQV-09; expected 33-35).
    function test_gas_createItems() public {
        (bytes32 vid,) = _createVault(1, 1, 0);
        _item(vid, vid, ids[0], 1, 288, 0); // the list exists: the batches below are warm
        _createItems(_batch(vid, 100, 10));
        _row("createItems 10 x 288 B", 700_076, 13_754_700);
        uint256 best;
        uint256 snap = vm.snapshotState();
        for (uint256 n = 20; n <= 50; ++n) {
            _createItems(_batch(vid, 1000, n));
            Vm.Gas memory g = vm.lastCallGas();
            uint256 s = uint256(int256(g.gasStateUsed));
            uint256 asked = (g.gasTotalUsed + FNDSA_VERIFY + s) * 105 / 100;
            vm.revertToState(snap);
            if (asked > 60_000_000 || (g.gasTotalUsed + FNDSA_VERIFY) * 105 / 100 >= 1 << 24) break;
            best = n;
        }
        emit log_named_uint("BATCH largest createItems of 288 B items within 60 M (FN-DSA-512)", best);
        _createItems(_batch(vid, 1000, best));
        _row(string.concat("createItems ", vm.toString(best), " x 288 B (the largest)"), 2_314_024, 52_020_000);
        if (!vm.envOr("GAS_MEASURE", false)) assertEq(best, 39, "the largest batch");
    }

    // ----- mode 1 (chain-bound, spec §5.15) -----

    function test_gas_mode1() public {
        (bytes32 vid,) = _createVault(1, 1, 1);
        _row("mode 1: createVault 1 member, its wrap", 267_160, 6_773_310);
        _item(vid, vid, ids[0], 1, 288, 1);
        bytes32 iid = _item(vid, vid, ids[0], 2, 288, 1);
        _row("mode 1: createItem 288 B, warm list", 154_593, 1_263_780);
        _edit(iid, vid, ids[0], 3, 2, 1);
        _row("mode 1: editItem 288 B, first", 148_752, 1_263_780);
        _share(vid, vid, 4, 2, 1);
        _row("mode 1: rekeyVault 1 -> 2 members (share), both wraps", 396_184, 9_943_470);
    }

    // ----- the per-vault UA (spec §5.14: a personal vault's FN-DSA-512 UA with its KEM key, per hosting chain) -----

    function test_gas_perVaultUaRegistration() public {
        bytes memory key = new bytes(897); // FN-DSA-512: header 0x09 (logn 9), coefficients below q
        key[0] = 0x09;
        key[896] = 0x63;
        IUARegistry.UAAttrs memory a;
        a.kem = _kem(99);
        _register(p, UAKinds.FNDSA512, key, a, _pop(p, UAKinds.FNDSA512, key, a), "");
        _row("register a per-vault FN-DSA-512 UA with its KEM key (stand-in verifier)", 459_203, 5_405_490);
    }

    // ----- the release -----

    /// The release's deployment through the factory: one transaction within the 60 M every transaction asks (CTR-TOK-30's line,
    /// 33,594 B at PqChat's split), regular x 1.05 under 2^24.
    function test_gas_deployImplementation() public {
        bytes memory code = type(PqVault).creationCode;
        vm.prank(REGISTRAR);
        address r = f.deployImplementation(
            IOpenFactory.ReleaseId(4, 0, 2),
            1,
            IPqVault.initialize.selector,
            type(IPqVault).interfaceId,
            code,
            "",
            EnvKit.uidOf(address(f))
        );
        Vm.Gas memory g = vm.lastCallGas();
        (uint256 regular, uint256 state) = (uint256(g.gasTotalUsed) * 64 / 63, uint256(int256(g.gasStateUsed)));
        uint256 asked = (regular + state) * 105 / 100;
        emit log_named_uint("SIZE PqVault runtime", r.code.length);
        emit log_named_uint("SIZE PqVault init", code.length);
        emit log_named_uint("GAS deployImplementation PqVault regular x 64/63", regular);
        emit log_named_uint("GAS deployImplementation PqVault state", state);
        emit log_named_uint("GAS deployImplementation PqVault asked x 1.05", asked);
        assertLe(r.code.length, 33_594, "the one-transaction deploy line (stop and ask past it)");
        assertLt(regular * 105 / 100, 1 << 24, "regular gas x 1.05 under 2^24 (EIP-7825)");
        assertLe(asked, 60_000_000, "the release transaction asks at most 60 M");
        if (!vm.envOr("GAS_MEASURE", false)) {
            // CTR-CHAT-23 (`PqGroupBase._authorOf`, the hook `PqChat` overrides for its blobs that keep a signature; PqVault's
            // behaviour and gas rows unchanged): 30,421 -> 30,431 B; state 47,119,410 -> 47,134,710 (+10 x 1,530); regular
            // 2,062,717 unchanged
            assertEq(r.code.length, 30_431, "the PqVault runtime (size-baseline.json row)");
            assertApproxEqAbs(regular, 2_062_717, SLACK, "deployImplementation regular");
            assertEq(state, 47_134_710, "deployImplementation state");
        }
    }

    function test_gas_createInstance() public {
        bytes memory init = abi.encodeCall(IPqVault.initialize, (MetaTxLib.pad(STRANGER)));
        vm.prank(STRANGER);
        f.createInstance(IOpenFactory.ReleaseId(4, 0, 1), "gas", init);
        _row("createInstance PqVault", 189_493, 1_328_040);
    }
}
