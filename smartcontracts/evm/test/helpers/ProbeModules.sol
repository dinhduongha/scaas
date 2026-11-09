// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {kindModuleNames, kindImplArgs} from "../../script/KindModules.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {Catalogue, pinned, withModules} from "./Catalogue.sol";
import {ITokenModules} from "../../src/metatx/ITokenModule.sol";

/// @notice T66b (spec 2026-11-09-t66b-library-organisation.md §4.4): a test's subclass `probe` of a token face whose internal
///         overrides must hold in every frame (the bodies run in the body modules) has a twin `<probe><G>` of each module
///         `<Face><G>` of the face's kind `kind`, with the same overrides; `probe` names its artifact ("PlusZero.t.sol:NormalProbe").
///         Deploys them for `factory` (`vm.deployCode`, so the test does not embed their init code) and returns the release's
///         `implArgs` (`coreArgs`: "" on 0-5, `abi.encode(bytes32)` on 8-13).
function probeArgs(string memory probe, uint8 kind, address factory, bytes memory coreArgs)
    returns (bytes memory implArgs)
{
    (, implArgs) = probeModules(probe, kind, factory, coreArgs);
}

/// @notice As `probeArgs`, with the module addresses.
function probeModules(string memory probe, uint8 kind, address factory, bytes memory coreArgs)
    returns (address[] memory ms, bytes memory implArgs)
{
    Vm vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    string[] memory n = kindModuleNames(kind);
    ms = new address[](n.length);
    for (uint256 i; i < n.length; ++i) ms[i] = vm.deployCode(string.concat(probe, _group(n[i])), abi.encode(factory, coreArgs));
    implArgs = kindImplArgs(kind, ms, coreArgs);
}

/// @notice `Catalogue.release` for a probe: release `version` of `kind` from `code` on env `e` (the kind's link closure when
///         `e` pins none) with the probe's modules pinned beside it and named in `implArgs`.
function probeRelease(OpenFactory f, IOpenFactory.TokenKind kind, uint64 version, IFactoryToken.Env memory e,
    bytes memory code, string memory probe, bytes memory coreArgs) returns (address)
{
    (address[] memory ms, bytes memory implArgs) = probeModules(probe, uint8(kind), address(f), coreArgs);
    return _probeRelease(f, kind, version, withModules(e.libs.length == 0 ? pinned(e, kind) : e, ms), code, implArgs);
}

function _probeRelease(OpenFactory f, IOpenFactory.TokenKind kind, uint64 version, IFactoryToken.Env memory e,
    bytes memory code, bytes memory implArgs) returns (address)
{
    Vm vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint16 v = Catalogue.env(f, kind, e);
    vm.prank(f.registrar());
    return f.deployImplementation(kind, version, v, code, implArgs);
}

/// @dev The group suffix of a module artifact name ("…:WrappedPqzTokenQ2" -> "Q2", "…:NormalTokenP" -> "P").
function _group(string memory name) pure returns (string memory g) {
    bytes memory b = bytes(name);
    uint256 k = b[b.length - 1] >= "0" && b[b.length - 1] <= "9" ? 2 : 1;
    bytes memory s = new bytes(k);
    for (uint256 i; i < k; ++i) s[i] = b[b.length - k + i];
    return string(s);
}

/// @notice T66b §4.5: the env `e` of release `impl` pins the release's link closure, then its body modules (`modules()`, in
///         order, each with its code hash). Checks that tail and returns `e` without it (the closure part), so a test of
///         the closure reads as before.
function envClosure(IFactoryToken.Env memory e, address impl) view returns (IFactoryToken.Env memory) {
    address[] memory m = ITokenModules(impl).modules();
    require(e.libs.length >= m.length, "env: fewer pins than modules");
    uint256 n = e.libs.length - m.length;
    for (uint256 i; i < m.length; ++i) {
        require(e.libs[n + i] == m[i] && e.libCodeHashes[n + i] == m[i].codehash, "env: a body module not pinned in order");
    }
    address[] memory l = new address[](n);
    bytes32[] memory h = new bytes32[](n);
    for (uint256 i; i < n; ++i) (l[i], h[i]) = (e.libs[i], e.libCodeHashes[i]);
    (e.libs, e.libCodeHashes) = (l, h);
    return e;
}
