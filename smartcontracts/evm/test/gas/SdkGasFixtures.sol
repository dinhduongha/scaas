// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {RegFixture} from "../as/helpers/RegFixture.sol";
import {ZetherRegFixture} from "../as/confidential/ZetherRegFixture.sol";
import {PqzRegFixture} from "../as/confidential/PqzRegFixture.sol";
import {GovRouterFixture} from "../governance/GovRouter.t.sol";
import {ZUID} from "../zether/helpers/ZetherFixture.sol";
import {PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";
import {SdkGasOps} from "./SdkGasOps.sol";

/// G4 (owner 2026-11-19, "approved"): the shared fixtures of the gas rows with the registry, the router and the release envs
/// as a real deploy configures them (`SdkGasDeploy`): the `SmartKeyAccount` implementation made before the fixture's own
/// `setUp` (its releases and router name it), the fixture's registry made again at its address with the deploy's settings
/// after it (its registrations kept), a kind the fixture's own registrations rely on on the fixture's verifier.

/// `RegFixture` (kinds 8 and 9): its stand-in registry replaced by a real one.
abstract contract SdkGasRegFix is SdkGasOps, RegFixture {
    function setUp() public virtual override {
        _sgSkaSetup(UID);
        super.setUp();
        _sgDeployRegistry(address(ureg), UID, _sgNoKeep());
    }

    function _fixtureSka() internal view override returns (address) {
        return sgSka;
    }
}

/// `ZetherRegFixture` (kinds 4, 5, 10, 11).
abstract contract SdkGasZetherFix is SdkGasOps, ZetherRegFixture {
    function setUp() public virtual override {
        _sgSkaSetup(ZUID);
        super.setUp();
        _sgDeployRegistry(address(reg), ZUID, _sgNoKeep());
    }

    function _fixtureSka() internal view override returns (address) {
        return sgSka;
    }
}

/// `PqzRegFixture` (kinds 6, 7, 12, 13): ML-DSA-65 on the fixture's precompile stand-in (its PQZ accounts are `mldsa65`
/// UAs) and `pqz-mlwe` on its `PqzKeyVerifier`, as a deploy with `PQZ_KEY_VERIFIER` lists it.
abstract contract SdkGasPqzFix is SdkGasOps, PqzRegFixture {
    function setUp() public virtual override {
        _sgSkaSetup(PQZ_UID);
        super.setUp();
        _sgDeployRegistry(address(reg), PQZ_UID, _sgPqzKeep(address(mlv), address(pqv)));
    }

    function _fixtureSka() internal view override returns (address) {
        return sgSka;
    }
}

/// `GovRouterFixture`: the router at `PREG`'s registry, ML-DSA-44 on the fixture's stand-in (its `pq` and `msig` signers).
abstract contract SdkGasRouterFix is SdkGasOps, GovRouterFixture {
    function setUp() public virtual override {
        _sgSkaSetup(vm.parseJsonBytes32(_structures(), ".contexts.A.chainUid"));
        super.setUp();
        _sgDeployRegistry(PREG, chainUidA, _mockPqCfg());
    }

    function _fixtureSka() internal view override returns (address) {
        return sgSka;
    }
}

/// The PQZ fixtures' own kinds: ML-DSA-65 `mlv` at the precompile cap 200,000 and `pqz-mlwe` `pqv` at `DeployBase`'s
/// `CAP_PQZ_MLWE` 4,500,000.
function _sgPqzKeep(address mlv, address pqv) pure returns (UARegistry.KindConfig[] memory k) {
    k = new UARegistry.KindConfig[](2);
    k[0] = UARegistry.KindConfig(UAKinds.MLDSA65, mlv, 200_000);
    k[1] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, pqv, 4_500_000);
}
