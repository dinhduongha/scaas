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

/// The UA ledger fixture for the SDK gas rows with derived signers (owner 2026-11-19, item 7 and A1): the ledger's registry
/// redeployed at `REG_L` with the real verifiers of the forge-signable kinds P-256 (0x0101), ed25519 (0x0102) and secp256k1
/// (0x0108) at the gen-1 caps (secp256k1 at `SdkGasVerify`'s 50,000); the fixture's earlier registrations stay (the storage
/// is kept).
abstract contract SdkGasLedger is SdkGasOps, UALedgerBase {
    /// A1's derived reference signer: secp256k1 (0x0108), forge-signable by `vm.sign`.
    uint256 internal constant SG_UA_SK = 0x5A3B10;

    function _sgVerifiers() internal {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](3);
        c[0] = UARegistry.KindConfig(UAKinds.P256, address(new P256Verifier()), _cap(UAKinds.P256));
        c[1] = UARegistry.KindConfig(UAKinds.ED25519, address(new Ed25519Verifier()), _cap(UAKinds.ED25519));
        c[2] = UARegistry.KindConfig(UAKinds.SECP256K1, address(new Secp256k1Verifier()), 50_000);
        lreg = _deploy(REG_L, chainUidA, address(0), false, BUDGET, address(0), true, c);
    }

    /// The UA of `kind` from secret `sk`, registered with its PoP: its id and key data.
    function _sgRegister(uint16 kind, uint256 sk) internal returns (bytes32 ua, bytes memory k) {
        if (kind == UAKinds.P256) {
            (uint256 x, uint256 y) = vm.publicKeyP256(sk);
            k = abi.encodePacked(x, y);
        } else if (kind == UAKinds.ED25519) {
            k = abi.encodePacked(vm.publicKeyEd25519(bytes32(sk)));
        } else {
            Vm.Wallet memory w = vm.createWallet(sk);
            k = abi.encodePacked(w.publicKeyX, w.publicKeyY);
        }
        ua = UAKinds.uaOf(kind, k);
        bytes memory pop = _sgUaSign(kind, sk, UAKinds.uaMessage(kind, UAKinds.PURPOSE_POP_V2, _regDigest(ua, kind)));
        assertEq(UACall.register(lreg, kind, k, _none(), pop, ""), ua);
    }

    /// A1: the derived reference signer, registered; the fixture gives it what the native signer holds.
    function _sgUaSigner() internal returns (bytes32 ua) {
        bytes memory k;
        (ua, k) = _sgRegister(UAKinds.SECP256K1, SG_UA_SK);
        (sgUaKind, sgUaKey, sgUaSk) = (UAKinds.SECP256K1, k, SG_UA_SK);
    }
}
