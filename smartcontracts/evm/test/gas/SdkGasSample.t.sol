// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SdkGasLedger} from "./SdkGasLedger.sol";

/// The sampled end-to-end check (scaas-sdk spec §13.3, owner 2026-11-19, item 7): entries of the `token` kind on
/// `NormalToken` signed end to end by the native key and by UAs of the forge-signable kinds P-256 (0x0101, `vm.signP256`),
/// ed25519 (0x0102, `vm.signEd25519`) and secp256k1 (0x0108, `vm.sign`), registered with real PoPs on the ledger's
/// registry redeployed with the real verifiers at the gen-1 caps (`SdkGasLedger`). Keys `sample_<signer>_<entry>_<fresh|used>_normal`
/// (`<signer>` `0000` or the kind in 4 hex digits) and `sample_<signer>_sig_bytes` (the `UASig` in calldata less an empty
/// one); `scaas-sdk`'s `sampled_end_to_end_check` holds them to the table (measured <= base + verify + ua_extra < measured + 2,000; owner 2026-11-19, A1).
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
