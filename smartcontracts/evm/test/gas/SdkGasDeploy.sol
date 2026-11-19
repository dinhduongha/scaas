// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {WebAuthnP256Verifier} from "../../src/ua/verifiers/WebAuthnP256Verifier.sol";
import {P256Verifier} from "../../src/ua/verifiers/P256Verifier.sol";
import {Ed25519Verifier} from "../../src/ua/verifiers/Ed25519Verifier.sol";
import {Bip340Verifier} from "../../src/ua/verifiers/Bip340Verifier.sol";
import {Secp256k1Verifier} from "../../src/ua/verifiers/Secp256k1Verifier.sol";
import {
    SchnorrBn254Verifier,
    SchnorrBls12381Verifier,
    BlsMinSigBls12381Verifier,
    BlsMinSigBn254Verifier,
    ZetherSchnorrBls12381Verifier
} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {Musig2Secp256k1Verifier} from "../../src/ua/verifiers/Musig2Secp256k1Verifier.sol";
import {FrostSecp256k1Verifier} from "../../src/ua/verifiers/FrostSecp256k1Verifier.sol";
import {Musig2Bn254Verifier} from "../../src/ua/verifiers/Musig2Bn254Verifier.sol";
import {FrostBn254Verifier} from "../../src/ua/verifiers/FrostBn254Verifier.sol";
import {MldsaVerifier} from "../../src/ua/MlDsa.sol";
import {FndsaVerifier} from "../../src/ua/FnDsa.sol";
import {SlhdsaVerifier} from "../../src/ua/SlhDsa.sol";

/// @notice The deploy's gen-1 kind table (`SdkGasDeploy`), its verifiers made by this contract's constructor.
contract SdkGasKindTable {
    UARegistry.KindConfig[] internal table;

    constructor() {
        UARegistry.KindConfig[19] memory d = [
            UARegistry.KindConfig(UAKinds.WEBAUTHN_P256, address(new WebAuthnP256Verifier()), 400_000),
            UARegistry.KindConfig(UAKinds.P256, address(new P256Verifier()), 400_000),
            UARegistry.KindConfig(UAKinds.ED25519, address(new Ed25519Verifier()), 210_000),
            UARegistry.KindConfig(UAKinds.BIP340, address(new Bip340Verifier()), 50_000),
            UARegistry.KindConfig(UAKinds.SECP256K1, address(new Secp256k1Verifier()), 50_000),
            UARegistry.KindConfig(UAKinds.SCHNORR_BN254, address(new SchnorrBn254Verifier()), 50_000),
            UARegistry.KindConfig(UAKinds.SCHNORR_BLS12381, address(new SchnorrBls12381Verifier()), 70_000),
            UARegistry.KindConfig(UAKinds.BLS12381_MINSIG, address(new BlsMinSigBls12381Verifier()), 200_000),
            UARegistry.KindConfig(UAKinds.BLS_BN254_MINSIG, address(new BlsMinSigBn254Verifier()), 345_000),
            UARegistry.KindConfig(UAKinds.MUSIG2_SECP256K1, address(new Musig2Secp256k1Verifier()), 50_000),
            UARegistry.KindConfig(UAKinds.FROST_SECP256K1, address(new FrostSecp256k1Verifier()), 50_000),
            UARegistry.KindConfig(UAKinds.MUSIG2_BN254, address(new Musig2Bn254Verifier()), 50_000),
            UARegistry.KindConfig(UAKinds.FROST_BN254, address(new FrostBn254Verifier()), 50_000),
            UARegistry.KindConfig(UAKinds.ZETHER_BLS12381, address(new ZetherSchnorrBls12381Verifier()), 70_000),
            UARegistry.KindConfig(
                UAKinds.MLDSA44, address(new MldsaVerifier(UAKinds.MLDSA44, address(0), "", "")), 4_250_000
            ),
            UARegistry.KindConfig(
                UAKinds.MLDSA65, address(new MldsaVerifier(UAKinds.MLDSA65, address(0), "", "")), 5_950_000
            ),
            UARegistry.KindConfig(UAKinds.FNDSA512, address(new FndsaVerifier(UAKinds.FNDSA512)), 2_500_000),
            UARegistry.KindConfig(UAKinds.SLHDSA128S, address(new SlhdsaVerifier()), 1_400_000),
            UARegistry.KindConfig(UAKinds.FNDSA1024, address(new FndsaVerifier(UAKinds.FNDSA1024)), 5_250_000)
        ];
        for (uint256 i; i < d.length; ++i) {
            table.push(d[i]);
        }
    }

    function kinds() external view returns (UARegistry.KindConfig[] memory) {
        return table;
    }
}

/// @notice G4 (owner 2026-11-19, "approved"): the gas fixtures' registry configured as a real deploy configures it,
///         `DeployBase._deployUARegistry` on a chain like forge's (EIP-2537 and the bn254 G2 check answer, not Hedera,
///         `MLDSA_PRECOMPILE=off`): generation 1 (no predecessor), budget `UA_VERIFY_BUDGET` 12,000,000, the chain's
///         `SmartKeyAccount` implementation (`Deploy.s.sol`: `SmartKeyAccountFactory(uid).IMPLEMENTATION()`, also the router's and
///         every release env's, so a native signer's check reads its code hash), `msig` on, and the gen-1 kind table at the
///         deploy's caps with the real verifiers (`SdkGasKindTable`): the classical and group kinds, `zether-bls12381`,
///         ML-DSA-44 / -65 on the registry's cache, FN-DSA-512 / -1024 and SLH-DSA-128s (ML-DSA-87 is enabled only where its
///         precompile answers; `pqz-mlwe` only with a `PqzKeyVerifier`, which a PQZ fixture keeps). A fixture keeps its own
///         verifier for a kind its own registrations rely on (`keep`: a stand-in for a PQ precompile, the PQZ key verifier).
///         The account factory and the kind table are deployed by `SG_DEPLOYER`: the fixture's own deployments keep their
///         addresses, so a figure moves by the configuration only (a signature over a token's domain stays the same).
abstract contract SdkGasDeploy is Test {
    /// the deployer of the account factory and the kind table: not this contract, whose nonce (each call of an isolated test
    /// is a transaction from it) places the fixture's own contracts
    address internal constant SG_DEPLOYER = address(0x5CAF0D);
    /// the deploy's `SmartKeyAccountFactory` and its implementation (0 until `_sgSkaSetup`), the kind table
    SmartKeyAccountFactory internal sgSkaf;
    address internal sgSka;
    SdkGasKindTable internal sgKinds;

    /// The chain's `SmartKeyAccount` implementation, made once (before the fixture's `setUp`: its releases name it).
    function _sgSkaSetup(bytes32 uid) internal returns (address) {
        if (sgSka == address(0)) {
            uint64 n = vm.getNonce(address(this));
            vm.prank(SG_DEPLOYER);
            sgSkaf = new SmartKeyAccountFactory(uid);
            sgSka = sgSkaf.IMPLEMENTATION();
            assertEq(vm.getNonce(address(this)), n, "the fixture's addresses kept");
        }
        return sgSka;
    }

    /// The deploy's kind table, a kind of `keep` on `keep`'s verifier and cap (added when the table has no such kind).
    function _sgDeployKinds(UARegistry.KindConfig[] memory keep) internal returns (UARegistry.KindConfig[] memory c) {
        if (address(sgKinds) == address(0)) {
            vm.prank(SG_DEPLOYER);
            sgKinds = new SdkGasKindTable();
        }
        UARegistry.KindConfig[] memory d = sgKinds.kinds();
        c = new UARegistry.KindConfig[](d.length + keep.length);
        uint256 n;
        for (; n < d.length; ++n) {
            c[n] = d[n];
        }
        for (uint256 i; i < keep.length; ++i) {
            uint256 j;
            while (j < d.length && c[j].kind != keep[i].kind) ++j;
            c[j < d.length ? j : n++] = keep[i];
        }
        assembly ("memory-safe") {
            mstore(c, n)
        }
    }

    /// The registry at `at` made again with the deploy's settings on chain `uid` (`_sgSkaSetup` first), its storage kept (the
    /// fixture's registrations stay), `keep` as `_sgDeployKinds`.
    function _sgDeployRegistry(address at, bytes32 uid, UARegistry.KindConfig[] memory keep) internal {
        require(sgSka != address(0), "_sgSkaSetup first");
        deployCodeTo(
            "UARegistry.sol:UARegistry",
            abi.encode(uid, address(0), false, uint64(12_000_000), sgSka, true, _sgDeployKinds(keep)),
            at
        );
    }

    function _sgNoKeep() internal pure returns (UARegistry.KindConfig[] memory) {}
}
