// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UAKinds} from "../../src/ua/UAKinds.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {Sha512} from "../../src/common/Sha512.sol";
import {Ed25519} from "../../src/common/Ed25519.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {MtxHash} from "../helpers/MtxHash.sol";
import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {Vm} from "forge-std/Test.sol";
import {SdkGasLedger} from "./SdkGasLedger.sol";

/// The sampled end-to-end check (scaas-sdk spec §13.3, owner 2026-11-19, item 7): entries of the `token` kind on
/// `NormalToken` signed end to end by the native key and by UAs of the forge-signable kinds P-256 (0x0101, `vm.signP256`),
/// ed25519 (0x0102, `vm.signEd25519`) and secp256k1 (0x0108, `vm.sign`), registered with real PoPs on the ledger's
/// registry redeployed with the real verifiers at the gen-1 caps (`SdkGasLedger`). Keys `sample_<signer>_<entry>_<fresh|used>_normal`
/// (`<signer>` `0000` or the kind in 4 hex digits) and `sample_<signer>_sig_bytes` (the `UASig` in calldata less an empty
/// one); `scaas-sdk`'s `sampled_end_to_end_check` holds them to the table. A kind whose verify gas depends on the data
/// (owner 2026-11-19, "approved, as proposed"; here ed25519) is sampled twice per cell: the composition cell signed by a
/// worst-case signature of the class its verify row was measured with (every 4-bit window of `S` and of `k` nonzero, found by
/// moving the clock, hence `validUntil` and the digest), and `<cell>_safety`, the most expensive of 32 ordinary signatures
/// (the clock at 1,000,000 + i seconds on), held to the lower bound only (measured <= base + verify + ua_extra < measured + 2,000; owner 2026-11-19, A1).
contract SdkGasSampleTest is SdkGasLedger {
    function setUp() public override {
        super.setUp();
        _sgVerifiers();
        sgPk = ALICE_PK;
    }

    /// The UA of `kind` from secret `sk`, registered with its PoP, funded with 1,000 units, the sampled signer.
    function _ua(uint16 kind, uint256 sk) internal {
        (bytes32 ua, bytes memory k) = _sgRegister(kind, sk);
        _fund(ua, 1_000);
        (sgKind, sgKeyData, sgSk) = (kind, k, sk);
    }

    function _rows(string memory s) internal {
        bytes32 from = _sgFrom();
        _both(s, "mtxExecuteTransfer", "normal", address(tok), from, _transfer);
        _both(s, "mtxPay", "normal", address(tok), from, _pay);
        _both(s, "mtxCancelNonce", "normal", address(tok), from, _cancel);
        _both(s, "mtxBurn", "normal", address(tok), from, _burn);
        bytes memory cd = _transfer(address(tok), 0);
        sgNoSig = true;
        _pin(string.concat(s, "_sig_bytes"), cd.length - _transfer(address(tok), 0).length);
        sgNoSig = false;
    }

    function _rev(uint256 v) internal pure returns (uint256 r) {
        for (uint256 i; i < 32; ++i) {
            r = (r << 8) | ((v >> (8 * i)) & 0xff);
        }
    }

    function _full(uint256 x) internal pure returns (bool) {
        for (uint256 i; i < 63; ++i) {
            if ((x >> (4 * i)) & 15 == 0) return false;
        }
        return true;
    }

    /// Whether the sampled ed25519 signature over `digest` has every window 0-62 of `S` and of `k` nonzero.
    function _edFull(bytes32 digest) internal pure returns (bool) {
        bytes32 m = UAKinds.uaMessage(UAKinds.ED25519, UAKinds.PURPOSE_METATX, digest);
        return _edFullOf(m, vm.signEd25519("", abi.encodePacked(m), bytes32(uint256(0x5A3B1F))));
    }

    function _edFullOf(bytes32 m, bytes memory sig) internal pure returns (bool) {
        (bytes32 r, bytes32 s) = (bytes32(0), bytes32(0));
        assembly ("memory-safe") {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
        }
        if (!_full(_rev(uint256(s)))) return false;
        bytes32 a = vm.publicKeyEd25519(bytes32(uint256(0x5A3B1F)));
        (bytes32 hi, bytes32 lo) = Sha512.hash(abi.encodePacked(r, a, m));
        uint256 r256 = (type(uint256).max % Ed25519.L + 1) % Ed25519.L;
        return _full(addmod(mulmod(_rev(uint256(lo)), r256, Ed25519.L), _rev(uint256(hi)), Ed25519.L));
    }

    function _dTransfer(address c, uint256 nonce) internal view returns (bytes32) {
        return MtxDigest.typed(c, MtxHash.hashStruct(_sgT(nonce, MetaTxLib.pad(SG_PAYEE), 1, 0)));
    }

    function _dPay(address c, uint256 nonce) internal view returns (bytes32) {
        return MtxDigest.typed(c, MtxHash.hashStruct(_sgT(nonce, MetaTxLib.pad(SG_PAYEE), 1, PayMetaKit.id(_sgMeta()))));
    }

    function _dCancel(address c, uint256 nonce) internal view returns (bytes32) {
        return _sgNamed(c, "UACancelNonce(bytes32 from,uint256 lane,", abi.encode(SG_LANE + 1), nonce);
    }

    function _dBurn(address c, uint256 nonce) internal view returns (bytes32) {
        return _sgNamed(c, "UABurn(bytes32 from,uint256 amount,", abi.encode(_amt(1)), nonce);
    }

    /// The execution gas of `cd` on `c` by the relayer, as `_measure` counts it, pinned nowhere.
    function _gasOnly(address c, bytes memory cd) internal returns (uint256) {
        vm.prank(SG_RELAYER);
        (bool ok,) = c.call(cd);
        assertTrue(ok, "a sampled call");
        Vm.Gas memory used = vm.lastFrameGas();
        return used.gasTotalUsed - 15_000 - _cdGas(cd) + uint256(int256(used.gasStateUsed));
    }

    /// One ed25519 cell (both lanes): the composition run at a worst-case signature, then the safety maximum.
    function _edCell(
        string memory s,
        string memory entry,
        function(address, uint256) internal view returns (bytes memory) build,
        function(address, uint256) internal view returns (bytes32) digest
    ) internal {
        for (uint256 nonce; nonce < 2; ++nonce) {
            string memory key = string.concat(s, "_", entry, nonce == 0 ? "_fresh_" : "_used_", "normal");
            (uint256 snap, uint256 t0) = (vm.snapshotState(), block.timestamp);
            uint256 j;
            while (!_edFull(digest(address(tok), nonce))) {
                vm.warp(t0 + ++j);
            }
            if (nonce != 0) _setNonce(address(tok), _sgFrom(), SG_LANE, 1);
            _measure(key, address(tok), build(address(tok), nonce));
            uint256 most;
            for (uint256 i; i < 32; ++i) {
                vm.revertToState(snap);
                vm.warp(t0 + 1_000_000 + i);
                if (nonce != 0) _setNonce(address(tok), _sgFrom(), SG_LANE, 1);
                uint256 g = _gasOnly(address(tok), build(address(tok), nonce));
                if (g > most) most = g;
            }
            vm.revertToState(snap);
            vm.warp(t0);
            _pin(string.concat(key, "_safety"), most);
        }
    }

    function _edRows(string memory s) internal {
        _edCell(s, "mtxExecuteTransfer", _transfer, _dTransfer);
        _edCell(s, "mtxPay", _pay, _dPay);
        _edCell(s, "mtxCancelNonce", _cancel, _dCancel);
        _edCell(s, "mtxBurn", _burn, _dBurn);
        bytes memory cd = _transfer(address(tok), 0);
        sgNoSig = true;
        _pin(string.concat(s, "_sig_bytes"), cd.length - _transfer(address(tok), 0).length);
        sgNoSig = false;
    }

    function test_sdkGas_sample() public {
        _rows("sample_0000");
        uint16[3] memory kinds = [UAKinds.P256, UAKinds.ED25519, UAKinds.SECP256K1];
        string[3] memory names = ["sample_0101", "sample_0102", "sample_0108"];
        for (uint256 i; i < 3; ++i) {
            _ua(kinds[i], 0x5A3B1E + i);
            if (kinds[i] == UAKinds.ED25519) _edRows(names[i]);
            else _rows(names[i]);
        }
    }
}
