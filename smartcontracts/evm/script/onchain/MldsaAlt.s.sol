// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console} from "forge-std/Script.sol";
import {OnchainBase} from "./OnchainBase.sol";
import {DeployBase} from "../DeployBase.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {MldsaVerifier} from "../../src/ua/MlDsa.sol";

/// @notice Round 3zh (owner 2026-11-15, MD-8), group `mldsaalt`: a throwaway gen-1 UA registry built by `DeployBase` itself (no code
///         of its own) in the **opposite** `MLDSA_PRECOMPILE` mode of the target's main deploy, with its own `DEPLOY_SALT` per run
///         (`MLDSAALT_SALT`, F-10: no CREATE2 collision with the main deploy or an earlier run), so one matrix run measures the
///         precompile path against the cache on the same chain under its real 2^24 cap. Per ML-DSA kind the registry enables
///         (`pq_signatures.json` rows 0, 1, 4): on the cache (`PRECOMPILE()` 0) each `cacheExpandedKey` part, `register`, a
///         `requireAuthorized` as a transaction of its own, and the `UAKeyNotCached` refusals (a key with no part, a key with part 0
///         only: `mldsa_cache.json` keys 1 and 2); on a precompile `register`, `requireAuthorized`, and `cacheExpandedKey`'s
///         `UAKeyCache` refusal. `mldsaalt.sh` chooses the mode and, for `on`, has `script/pq_verifiers.py` build the precompile
///         verifiers first (none where no ML-DSA precompile answers: there the `on` side is not run, by name). Test chains only.
///         UNAUDITED.
contract MldsaAlt is OnchainBase, DeployBase {
    UARegistry internal alt;
    string internal pj;
    string internal mc;

    function run() external {
        _init("mldsaalt");
        salt = vm.envBytes32("MLDSAALT_SALT");
        uid = _chainUid();
        txGasCap = _txGasCapEnv(); // owner X1: the book's TX_GAS_CAP
        bytes32 m = keccak256(bytes(vm.envString("MLDSA_PRECOMPILE")));
        require(m == keccak256("on") || m == keccak256("off"), "MLDSA_PRECOMPILE: on or off");
        mldsaPrecompile = m == keccak256("on");
        mldsa44Verifier = vm.envOr("MLDSA44_VERIFIER", address(0));
        mldsa65Verifier = vm.envOr("MLDSA65_VERIFIER", address(0));
        mldsa87Verifier = vm.envOr("MLDSA87_VERIFIER", address(0));
        // reset 5: a chain whose PQZ precompile answers needs 0x0142 in every gen-1 registry (DeployBase's gate); the
        // throwaway one takes the main deploy's PqzKeyVerifier (mldsaalt.sh, the book's pqz_key_verifier)
        pqzKeyVerifier = vm.envOr("PQZ_KEY_VERIFIER", address(0));
        pj = vm.readFile("../vectors/ua/pq_signatures.json");
        mc = vm.readFile("../vectors/ua/mldsa_cache.json");
        vm.startBroadcast(k1);
        alt = _deployUARegistry(address(0), false);
        vm.stopBroadcast();
        _book(address(alt), "UARegistry");
        console.log(
            string.concat(
                "mldsaalt: registry ", vm.toString(address(alt)), " MLDSA_PRECOMPILE=", mldsaPrecompile ? "on" : "off"
            )
        );
        uint16[3] memory ks = [UAKinds.MLDSA44, UAKinds.MLDSA65, UAKinds.MLDSA87];
        uint256[3] memory rows = [uint256(0), 1, 4];
        string[3] memory names = ["mldsa44", "mldsa65", "mldsa87"];
        for (uint256 i; i < 3; ++i) {
            if (!alt.kindEnabled(ks[i])) {
                console.log(string.concat("mldsaalt: ", names[i], " not enabled on this registry (MD-1 / MD-5)"));
                continue;
            }
            _kind(ks[i], rows[i], names[i]);
        }
        _writeBook();
    }

    /// The verifier the registry lists for `kind`: the one `_deployUARegistry` built or took (read back from its JSON object).
    function _verifier(string memory name) internal returns (address) {
        return vm.parseJsonAddress(vm.serializeString("deploy", "_mldsaalt", ""), string.concat(".", name, "_verifier"));
    }

    function _kind(uint16 kind, uint256 row, string memory name) internal {
        address v = _verifier(name);
        _book(v, "MldsaVerifier");
        bool cache = MldsaVerifier(v).PRECOMPILE() == address(0);
        string memory r = string.concat(".kinds[", vm.toString(row), "].");
        bytes memory pk = vm.parseJsonBytes(pj, string.concat(r, "keyData"));
        bytes memory pop = vm.parseJsonBytes(pj, string.concat(r, "pop.sig"));
        bytes32 ua = alt.uaOf(kind, pk);
        IUARegistry.UAAttrs memory none;
        console.log(
            string.concat(
                "mldsaalt: ",
                name,
                cache ? " on the cache" : " on the precompile ",
                cache ? "" : vm.toString(MldsaVerifier(v).PRECOMPILE())
            )
        );
        vm.startBroadcast(k1);
        if (cache) {
            for (uint256 p; p < PqUA.mldsaParts(kind); ++p) {
                alt.cacheExpandedKey(kind, pk, p);
            }
        }
        require(alt.register(kind, pk, none, pop, "") == ua, "mldsaalt: register");
        // the verify as a transaction of its own (a CALL, so it is sent): the chain's real cap applies to it
        (bool ok,) = address(alt)
            .call(
                abi.encodeCall(
                    IUARegistry.requireAuthorized,
                    (
                        ua,
                        _purpose(r),
                        vm.parseJsonBytes32(pj, ".digest"),
                        IUARegistry.UASig(
                            "", vm.parseJsonBytes(pj, string.concat(r, "sigs[0].sig")), new IUARegistry.MemberSig[](0)
                        )
                    )
                )
            );
        require(ok, "mldsaalt: requireAuthorized");
        vm.stopBroadcast();
        if (cache) {
            _refusals(kind, name);
        } else {
            _neg(
                a1,
                address(alt),
                abi.encodeCall(IUARegistry.cacheExpandedKey, (kind, pk, 0)),
                IUARegistry.UAKeyCache.selector,
                string.concat("mldsaalt: cacheExpandedKey of ", name, " on the precompile path")
            );
        }
    }

    function _purpose(string memory r) internal view returns (bytes32) {
        return keccak256(
            bytes(
                string.concat("scaas.ua.purpose.", vm.parseJsonString(pj, string.concat(r, "sigs[0].purpose")), ".v1")
            )
        );
    }

    /// `UAKeyNotCached` with no part (`mldsa_cache.json` key 1) and with part 0 only (key 2, its part 0 sent here): `register`
    /// by eth_call after the run (`coverage.py neg`), a PoP of any bytes (the cache check comes before the PoP).
    function _refusals(uint16 kind, string memory name) internal {
        IUARegistry.UAAttrs memory none;
        bytes memory k1_ = vm.parseJsonBytes(mc, string.concat(".levels.", name, ".keys[1].pk"));
        bytes memory k2_ = vm.parseJsonBytes(mc, string.concat(".levels.", name, ".keys[2].pk"));
        _negData(
            a1,
            address(alt),
            abi.encodeCall(IUARegistry.register, (kind, k1_, none, hex"01", "")),
            abi.encodeWithSelector(IUARegistry.UAKeyNotCached.selector, alt.uaOf(kind, k1_)),
            string.concat("mldsaalt: register of ", name, " without its cache")
        );
        if (PqUA.mldsaParts(kind) < 2) return;
        vm.broadcast(k1);
        alt.cacheExpandedKey(kind, k2_, 0);
        _negData(
            a1,
            address(alt),
            abi.encodeCall(IUARegistry.register, (kind, k2_, none, hex"01", "")),
            abi.encodeWithSelector(IUARegistry.UAKeyNotCached.selector, alt.uaOf(kind, k2_)),
            string.concat("mldsaalt: register of ", name, " with part 0 only")
        );
    }
}
