// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {P256Verifier} from "../../src/ua/verifiers/P256Verifier.sol";
import {WebAuthnP256Verifier} from "../../src/ua/verifiers/WebAuthnP256Verifier.sol";
import {Bip340Verifier} from "../../src/ua/verifiers/Bip340Verifier.sol";
import {Secp256k1Verifier} from "../../src/ua/verifiers/Secp256k1Verifier.sol";
import {Ed25519Verifier} from "../../src/ua/verifiers/Ed25519Verifier.sol";
import {
    SchnorrBn254Verifier,
    SchnorrBls12381Verifier,
    BlsMinSigBls12381Verifier,
    BlsMinSigBn254Verifier
} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {UARegistryBase} from "../ua/UARegistryBase.sol";
import {UACall} from "../ua/UACall.sol";
import {Vm} from "forge-std/Test.sol";
import {SdkGasRows} from "./SdkGasOps.sol";

/// The copy-cost forwarder (owner 2026-11-19, "OK"): what a token does with a signature, nothing else. A native id is checked
/// here as `MtxPipelineLib._authorizeNative` does (`SigCheck.isValid`); a derived one goes to the registry, the `UASig`
/// copied from calldata into the call, as `MtxPipelineLib` does.
contract SdkGasForwarder {
    IUARegistry internal immutable REG;

    constructor(IUARegistry reg_) {
        REG = reg_;
    }

    function check(bytes32 from, bytes32 purpose, bytes32 digest, IUARegistry.UASig calldata auth) external view {
        if (UAKinds.inNativeSpace(from)) {
            require(SigCheck.isValid(address(uint160(uint256(from))), digest, auth.signature, SigCheck.ERC1271_GAS));
        } else {
            REG.requireAuthorized(from, purpose, digest, auth);
        }
    }
}

/// Meters a call: the gas `target` used, its frame's own.
contract SdkGasMeter {
    function run(address target, bytes calldata cd) external returns (uint256 g) {
        g = gasleft();
        (bool ok, bytes memory ret) = target.call(cd);
        g -= gasleft();
        if (!ok) {
            assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        }
    }
}

/// The verify rows of the classical kinds (owner 2026-11-19, part 3b): the execution gas of the forwarder's `check` for a
/// signer kind, its calldata subtracted, minus the native key's (the reference signer, whose path makes no registry call);
/// the generator stores the difference (both metered by `SdkGasMeter`). Real verifiers on the gen-1 caps (`UARegistryVectors.t.sol`'s registry), each UA
/// registered with its vector PoP and checked with its vector signature under `metatx`
/// (`smartcontracts/vectors/ua/signatures.json`, `derived[]`); P-256 on the 0x100 precompile. Keys `verify_<kind>`
/// (4 hex digits) and `verify_native`, the difference `verify_<kind>_delta`.
contract SdkGasVerifyTest is SdkGasRows, UARegistryBase {
    string internal sj;
    SdkGasForwarder internal fwd;
    SdkGasMeter internal meter;

    function setUp() public override {
        super.setUp();
        sj = vm.readFile("../vectors/ua/signatures.json");
        address[8] memory v = [
            address(new WebAuthnP256Verifier()),
            address(new P256Verifier()),
            address(new Ed25519Verifier()),
            address(new Bip340Verifier()),
            address(new SchnorrBn254Verifier()),
            address(new SchnorrBls12381Verifier()),
            address(new BlsMinSigBls12381Verifier()),
            address(new BlsMinSigBn254Verifier())
        ];
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](9);
        for (uint256 i; i < 8; ++i) {
            c[i] = UARegistry.KindConfig(KINDS[i], v[i], _cap(KINDS[i]));
        }
        c[8] = UARegistry.KindConfig(0x0108, address(new Secp256k1Verifier()), 50_000);
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, c);
        fwd = new SdkGasForwarder(reg);
        meter = new SdkGasMeter();
    }

    function _d(uint256 i, string memory f) internal pure returns (string memory) {
        return string.concat(".derived[", vm.toString(i), "].", f);
    }

    function _hex4(uint16 k) internal pure returns (string memory s) {
        bytes memory h = "0123456789abcdef";
        s = string(abi.encodePacked("0x", h[k >> 12], h[(k >> 8) & 15], h[(k >> 4) & 15], h[k & 15]));
    }

    /// The gas of `fwd`'s `check` inside the meter's call: the native key's `check` is too small for its own transaction to
    /// clear EIP-7976's calldata floor (its total sat on it), so both sides of the difference are metered alike; the
    /// meter's call overhead cancels, its copy of a longer signature counts against the kind (an upper bound).
    function _metered(string memory key, bytes memory cd) internal returns (uint256 g) {
        vm.prank(SG_RELAYER);
        g = meter.run(address(fwd), cd);
        Vm.Gas memory used = vm.lastFrameGas();
        assertEq(used.gasStateUsed, 0, "a check writes nothing");
        _pin(key, g);
    }

    function test_sdkGas_verify() public {
        bytes32 dg = keccak256("sdk-gas-verify");
        uint256 pk = 0xA11CE;
        IUARegistry.UASig memory a;
        a.signature = _ecdsa(pk, dg);
        bytes32 native = bytes32(uint256(uint160(vm.addr(pk))));
        uint256 n =
            _metered("verify_native", abi.encodeCall(SdkGasForwarder.check, (native, UAKinds.PURPOSE_METATX, dg, a)));
        uint256 rows;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            uint16 kind = uint16(vm.parseJsonUint(sj, _d(i, "kind")));
            if (kind > 0x0108) continue; // the stored Zether kind signs no SCaaS op
            bytes memory k = vm.parseJsonBytes(sj, _d(i, "keyData"));
            bytes32 ua = vm.parseJsonBytes32(sj, _d(i, "ua"));
            UACall.register(reg, kind, k, _none(), vm.parseJsonBytes(sj, _d(i, "pop.sig")), "");
            uint256 s;
            while (
                keccak256(bytes(vm.parseJsonString(sj, _d(i, string.concat("sigs[", vm.toString(s), "].purpose")))))
                    != keccak256("metatx")
            ) {
                ++s;
            }
            string memory row = string.concat("sigs[", vm.toString(s), "].");
            IUARegistry.UASig memory u =
                UACall.auth(ua, abi.encode(k, vm.parseJsonBytes(sj, _d(i, string.concat(row, "sig")))));
            bytes memory cd = abi.encodeCall(
                SdkGasForwarder.check,
                (ua, UAKinds.PURPOSE_METATX, vm.parseJsonBytes32(sj, _d(i, string.concat(row, "digest"))), u)
            );
            string memory key = string.concat("verify_", _hex4(kind));
            _pin(string.concat(key, "_delta"), _metered(key, cd) - n); // the verify row's figure
            ++rows;
        }
        assertEq(rows, 9, "0x0100 - 0x0108");
    }
}
