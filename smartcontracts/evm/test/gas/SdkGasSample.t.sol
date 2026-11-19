// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {P256Verifier} from "../../src/ua/verifiers/P256Verifier.sol";
import {Ed25519Verifier} from "../../src/ua/verifiers/Ed25519Verifier.sol";
import {Secp256k1Verifier} from "../../src/ua/verifiers/Secp256k1Verifier.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {UACall} from "../ua/UACall.sol";
import {Vm} from "forge-std/Test.sol";
import {SdkGasOps} from "./SdkGasOps.sol";

/// The sampled end-to-end check (scaas-sdk spec §13.3, owner 2026-11-19, item 7): entries of the `token` kind on
/// `NormalToken` signed end to end by the native key and by UAs of the forge-signable kinds P-256 (0x0101, `vm.signP256`),
/// ed25519 (0x0102, `vm.signEd25519`) and secp256k1 (0x0108, `vm.sign`), registered with real PoPs on the ledger's
/// registry redeployed with the real verifiers at the gen-1 caps. Keys `sample_<signer>_<entry>_<fresh|used>_normal`
/// (`<signer>` `0000` or the kind in 4 hex digits) and `sample_<signer>_sig_bytes` (the `UASig` in calldata less an empty
/// one); `scaas-sdk`'s `sampled_end_to_end_check` holds them to the table (measured <= base + verify < measured + 2,000).
contract SdkGasSampleTest is SdkGasOps, UALedgerBase {
    function setUp() public override {
        super.setUp();
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](3);
        c[0] = UARegistry.KindConfig(UAKinds.P256, address(new P256Verifier()), _cap(UAKinds.P256));
        c[1] = UARegistry.KindConfig(UAKinds.ED25519, address(new Ed25519Verifier()), _cap(UAKinds.ED25519));
        c[2] = UARegistry.KindConfig(UAKinds.SECP256K1, address(new Secp256k1Verifier()), 50_000); // SdkGasVerify's
        lreg = _deploy(REG_L, chainUidA, address(0), false, BUDGET, address(0), true, c);
        sgPk = ALICE_PK;
    }

    /// The UA of `kind` from secret `sk`: its key data, registered with its PoP, funded with 1,000 units.
    function _ua(uint16 kind, uint256 sk) internal {
        bytes memory k;
        if (kind == UAKinds.P256) {
            (uint256 x, uint256 y) = vm.publicKeyP256(sk);
            k = abi.encodePacked(x, y);
        } else if (kind == UAKinds.ED25519) {
            k = abi.encodePacked(vm.publicKeyEd25519(bytes32(sk)));
        } else {
            Vm.Wallet memory w = vm.createWallet(sk);
            k = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        }
        bytes32 ua = UAKinds.uaOf(kind, k);
        bytes memory pop = _sgUaSign(kind, sk, UAKinds.uaMessage(kind, UAKinds.PURPOSE_POP_V2, _regDigest(ua, kind)));
        assertEq(UACall.register(lreg, kind, k, _none(), pop, ""), ua);
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

    function test_sdkGas_sample() public {
        _rows("sample_0000");
        uint16[3] memory kinds = [UAKinds.P256, UAKinds.ED25519, UAKinds.SECP256K1];
        string[3] memory names = ["sample_0101", "sample_0102", "sample_0108"];
        for (uint256 i; i < 3; ++i) {
            _ua(kinds[i], 0x5A3B1E + i);
            _rows(names[i]);
        }
    }
}
