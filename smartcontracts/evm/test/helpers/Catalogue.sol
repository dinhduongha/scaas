// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";

/// @notice A plain release environment (plan 5g-Z2): no dependencies, no pinned libraries.
function plainEnv(address factory, address ska, bytes32 uid, address registry, bool hedera)
    pure returns (IFactoryToken.Env memory e)
{
    (e.factory, e.chainUid, e.registry, e.smartKeyAccountImpl, e.hedera) = (factory, uid, registry, ska, hedera);
}

/// @notice A `*_ZETHER` environment: `deps` = transfer, burn, inner-product verifier, disclosure (CTR-ZTH-20).
function zetherEnv(address factory, bytes32 uid, address registry, address transfer, address burn, address innerProduct,
    address disclosure) pure returns (IFactoryToken.Env memory e)
{
    e = plainEnv(factory, address(0), uid, registry, false);
    e.deps = new address[](4);
    (e.deps[0], e.deps[1], e.deps[2], e.deps[3]) = (transfer, burn, innerProduct, disclosure);
}

/// @notice A `*_PQZ` environment: `deps` = the `UAPqzVerifier`.
function pqzEnv(address factory, bytes32 uid, address registry, address verifier)
    pure returns (IFactoryToken.Env memory e)
{
    e = plainEnv(factory, address(0), uid, registry, false);
    e.deps = new address[](1);
    e.deps[0] = verifier;
}

/// @notice The registrar's catalogue calls for tests (plan 5g-Z2): publish an env, deploy a release from init code.
///         Each call pranks the registrar once, so a caller must not hold a `startPrank`.
library Catalogue {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @dev `e` as the kind's latest env: reused when equal to the latest, else published as the next version.
    function env(OpenFactory f, IOpenFactory.TokenKind kind, IFactoryToken.Env memory e) internal returns (uint16 v) {
        v = f.latestEnvVersion(kind);
        if (v != 0 && keccak256(abi.encode(f.envOf(kind, v))) == keccak256(abi.encode(e))) return v;
        v += 1;
        vm.prank(f.registrar());
        f.publishEnv(kind, v, e);
    }

    /// @dev Release `version` of `kind` from `code` (init code without arguments) on env `e`.
    function release(OpenFactory f, IOpenFactory.TokenKind kind, uint64 version, IFactoryToken.Env memory e,
        bytes memory code) internal returns (address)
    {
        uint16 v = env(f, kind, e);
        vm.prank(f.registrar());
        return f.deployImplementation(kind, version, v, code, "");
    }

    /// @dev A plain release on `plainEnv(f, ska, f.chainUid(), registry, hedera)`.
    function plain(OpenFactory f, IOpenFactory.TokenKind kind, uint64 version, bytes memory code, address registry,
        address ska, bool hedera) internal returns (address)
    {
        return release(f, kind, version, plainEnv(address(f), ska, f.chainUid(), registry, hedera), code);
    }

    /// @dev DEX release `version` from `code` on a DEX env with `ska` (published once per distinct env).
    function dex(OpenFactory f, uint64 version, bytes memory code, address ska) internal returns (address) {
        IFactoryToken.Env memory e = plainEnv(address(f), ska, f.chainUid(), address(0), false);
        uint16 v = f.latestDexEnvVersion();
        if (v == 0 || keccak256(abi.encode(f.dexEnvOf(v))) != keccak256(abi.encode(e))) {
            vm.prank(f.registrar());
            f.publishDexEnv(++v, e);
        }
        vm.prank(f.registrar());
        return f.deployDexImplementation(version, v, code, "");
    }

    /// @dev Where `deployImplementation(kind, version, latest env, code, "")` puts the release.
    function predict(OpenFactory f, IOpenFactory.TokenKind kind, uint64 version, bytes memory code)
        internal view returns (address)
    {
        uint16 v = f.latestEnvVersion(kind);
        return vm.computeCreate2Address(keccak256(abi.encode(kind, version)),
            keccak256(bytes.concat(code, abi.encode(v, f.envOf(kind, v), bytes("")))), address(f));
    }
}
