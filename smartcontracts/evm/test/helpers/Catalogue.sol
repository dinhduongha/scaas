// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {TokenStore} from "../../src/metatx/TokenStore.sol";
import {WrappedLib} from "../../src/metatx/WrappedLib.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {HederaLib} from "../../src/hedera/HederaLib.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {ZetherLib} from "../../src/zether/ZetherLib.sol";
import {ZetherWrappedLib} from "../../src/zether/ZetherWrappedLib.sol";
import {PqzStateLib} from "../../src/pqz/PqzStateLib.sol";
import {PqzTransferLib} from "../../src/pqz/PqzTransferLib.sol";
import {PqzBurnLib} from "../../src/pqz/PqzBurnLib.sol";
import {PqzViewLib} from "../../src/pqz/PqzViewLib.sol";
import {PqzWrappedLib} from "../../src/pqz/PqzWrappedLib.sol";
import {UARegistryCoreLib} from "../../src/ua/UARegistryCoreLib.sol";
import {UARegistryAuxLib} from "../../src/ua/UARegistryAuxLib.sol";
import {RegulatedLib} from "../../src/regulated/RegulatedLib.sol";
import {ComplianceRegistry} from "../../src/regulated/ComplianceRegistry.sol";

/// @notice A regulated release's `implArgs` (regulated-kinds spec §5, F-11; plan T29): the canonical `ComplianceRegistry`
///         runtime's code hash, `REGISTRY_CODEHASH`.
function regArgs() pure returns (bytes memory) {
    return abi.encode(keccak256(type(ComplianceRegistry).runtimeCode));
}

/// @notice A plain release environment (plan 5g-Z2): no dependencies, no pinned libraries. Chain-neutral releases (plan
///         T71): the factory and `chain_uid` are the factory's own, not the env's; `factory` and `uid` stay as
///         arguments for the callers that also build the instance env (`instanceEnv`).
function plainEnv(address, /* factory */ address ska, bytes32, /* uid */ address registry, bool hedera)
    pure returns (IFactoryToken.Env memory e)
{
    (e.registry, e.smartKeyAccountImpl, e.hedera) = (registry, ska, hedera);
}

/// @notice A `*_ZETHER` environment: `deps` = transfer, burn, inner-product verifier, disclosure (CTR-ZTH-20).
function zetherEnv(address factory, bytes32 uid, address registry, address transfer, address burn, address innerProduct,
    address disclosure) pure returns (IFactoryToken.Env memory e)
{
    e = plainEnv(factory, address(0), uid, registry, false);
    e.deps = new address[](4);
    (e.deps[0], e.deps[1], e.deps[2], e.deps[3]) = (transfer, burn, innerProduct, disclosure);
}

/// @notice A `*_PQZ` environment: `deps` = the `UAPqzVerifier`; the libraries are the kind's link closure
///         (`Catalogue.env` pins them, task 6).
function pqzEnv(address factory, bytes32 uid, address registry, address verifier)
    pure returns (IFactoryToken.Env memory e)
{
    e = plainEnv(factory, address(0), uid, registry, false);
    e.deps = new address[](1);
    e.deps[0] = verifier;
}

/// @notice The instance env a factory on chain `uid` with router `govRouter` composes from `e` (chain-neutral spec §3.2).
function instanceEnv(IFactoryToken.Env memory e, bytes32 uid, address govRouter)
    pure returns (IFactoryToken.ChainEnv memory c)
{
    return IFactoryToken.ChainEnv(uid, e.registry, govRouter, e.smartKeyAccountImpl, e.hedera, e.deps, e.params);
}

/// @notice The transitive link closure of `kind`'s implementation (metatx-split §4, R5), each library with its code
///         hash. Checked against the artifacts' `linkReferences` by `LinkClosure.t.sol`.
function closureLibs(IOpenFactory.TokenKind kind) view returns (address[] memory l) {
    if (uint8(kind) >= 8) { // a regulated kind 8-13: its base kind's closure and `RegulatedLib` (regulated-kinds spec §6.1)
        address[] memory base = closureLibs(IOpenFactory.TokenKind(uint8(kind) - 8));
        l = new address[](base.length + 1);
        for (uint256 i; i < base.length; ++i) l[i] = base[i];
        l[base.length] = address(RegulatedLib);
        return l;
    }
    bool und = kind == IOpenFactory.TokenKind.WRAPPED || kind == IOpenFactory.TokenKind.WRAPPED_ZETHER
        || kind == IOpenFactory.TokenKind.WRAPPED_PQZ;
    bool zth = kind == IOpenFactory.TokenKind.NORMAL_ZETHER || kind == IOpenFactory.TokenKind.WRAPPED_ZETHER;
    bool pqz = kind == IOpenFactory.TokenKind.NORMAL_PQZ || kind == IOpenFactory.TokenKind.WRAPPED_PQZ;
    bool zwr = kind == IOpenFactory.TokenKind.WRAPPED_ZETHER;
    bool pwr = kind == IOpenFactory.TokenKind.WRAPPED_PQZ;
    l = new address[](4 + (und ? 1 : 0) + (zth ? 1 : 0) + (zwr ? 1 : 0) + (pqz ? 4 : 0) + (pwr ? 1 : 0));
    (l[0], l[1], l[2], l[3]) = (address(GovernanceLib), address(HederaLib), address(TradeLib), address(MtxPipelineLib));
    uint256 n = 4;
    if (und) l[n++] = address(WrappedLib);
    if (zth) l[n++] = address(ZetherLib);
    if (zwr) l[n++] = address(ZetherWrappedLib);
    if (pqz) {
        (l[n], l[n + 1], l[n + 2], l[n + 3]) =
            (address(PqzStateLib), address(PqzTransferLib), address(PqzBurnLib), address(PqzViewLib));
        n += 4;
    }
    if (pwr) l[n] = address(PqzWrappedLib);
}

/// @notice The link closure of `UARegistry` (typed-signing R2; T66b 3.1b: two libraries by domain, in the order of its
///         `linkReferences`, by source path). No release env pins it: the registry has no factory, its init code embeds the
///         addresses. Checked against `linkReferences` by `LinkClosure.t.sol`.
function registryClosureLibs() pure returns (address[] memory l) {
    l = new address[](2);
    (l[0], l[1]) = (address(UARegistryAuxLib), address(UARegistryCoreLib));
}

/// @notice `e` with `kind`'s link closure pinned (libraries and their code hashes).
function pinned(IFactoryToken.Env memory e, IOpenFactory.TokenKind kind) view returns (IFactoryToken.Env memory) {
    e.libs = closureLibs(kind);
    e.libCodeHashes = new bytes32[](e.libs.length);
    for (uint256 i; i < e.libs.length; ++i) e.libCodeHashes[i] = e.libs[i].codehash;
    return e;
}

/// @notice The registrar's catalogue calls for tests (plan 5g-Z2): publish an env, deploy a release from init code.
///         Each call pranks the registrar once, so a caller must not hold a `startPrank`.
library Catalogue {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @dev `e` as the kind's latest env: reused when equal to the latest, else published as the next version.
    function env(OpenFactory f, IOpenFactory.TokenKind kind, IFactoryToken.Env memory e) internal returns (uint16 v) {
        if (e.libs.length == 0) e = pinned(e, kind); // an env with no pins gets the kind's link closure
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
        return release(f, kind, version, e, code, "");
    }

    /// @dev As above with the release's `implArgs` (a regulated kind 8-13: `regArgs()`, plan T29).
    function release(OpenFactory f, IOpenFactory.TokenKind kind, uint64 version, IFactoryToken.Env memory e,
        bytes memory code, bytes memory implArgs) internal returns (address)
    {
        uint16 v = env(f, kind, e);
        vm.prank(f.registrar());
        return f.deployImplementation(kind, version, v, code, implArgs);
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
        e.libs = new address[](2);
        (e.libs[0], e.libs[1]) = (address(GovernanceLib), address(TradeLib));
        e.libCodeHashes = new bytes32[](2);
        (e.libCodeHashes[0], e.libCodeHashes[1]) = (address(GovernanceLib).codehash, address(TradeLib).codehash);
        uint16 v = f.latestDexEnvVersion();
        if (v == 0 || keccak256(abi.encode(f.dexEnvOf(v))) != keccak256(abi.encode(e))) {
            vm.prank(f.registrar());
            f.publishDexEnv(++v, e);
        }
        vm.prank(f.registrar());
        return f.deployDexImplementation(version, v, code, "");
    }

    /// @dev Where `deployImplementation(kind, version, any env, code, "")` puts the release: chain-neutral, the env is not
    ///      in its init code (chain-neutral spec §6.1).
    function predict(OpenFactory f, IOpenFactory.TokenKind kind, uint64 version, bytes memory code)
        internal pure returns (address)
    {
        return vm.computeCreate2Address(keccak256(abi.encode(kind, version)),
            keccak256(bytes.concat(code, abi.encode(address(f), bytes("")))), address(f));
    }
}
