// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";
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
import {UARegistryLib} from "../../src/ua/UARegistryLib.sol";
import {RegulatedLib} from "../../src/regulated/RegulatedLib.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {ZUID} from "../zether/helpers/ZetherFixture.sol";
import {closureLibs, registryClosureLibs} from "../helpers/Catalogue.sol";

/// @notice metatx-split task 6 (spec §4, R5, R6): a release's `Env.libs` is the transitive link closure of its
///         implementation, read from the artifacts' `linkReferences` (each library's own, recursively); and no closure
///         library can self-destruct, CALLCODE or (bar the named ones) DELEGATECALL.
contract LinkClosureTest is Test {
    IOpenFactory.TokenKind constant NORMAL = IOpenFactory.TokenKind.NORMAL;
    string[] internal names = [
        "GovernanceLib", "HederaLib", "TradeLib", "MtxPipelineLib", "WrappedLib", "ZetherLib", "ZetherWrappedLib",
        "PqzStateLib", "PqzTransferLib", "PqzBurnLib", "PqzViewLib", "PqzWrappedLib", "UARegistryLib", "RegulatedLib"
    ];

    function _addr(string memory n) internal pure returns (address a) {
        bytes32 h = keccak256(bytes(n));
        if (h == keccak256("GovernanceLib")) return address(GovernanceLib);
        if (h == keccak256("HederaLib")) return address(HederaLib);
        if (h == keccak256("TradeLib")) return address(TradeLib);
        if (h == keccak256("MtxPipelineLib")) return address(MtxPipelineLib);
        if (h == keccak256("WrappedLib")) return address(WrappedLib);
        if (h == keccak256("ZetherLib")) return address(ZetherLib);
        if (h == keccak256("ZetherWrappedLib")) return address(ZetherWrappedLib);
        if (h == keccak256("PqzStateLib")) return address(PqzStateLib);
        if (h == keccak256("PqzTransferLib")) return address(PqzTransferLib);
        if (h == keccak256("PqzBurnLib")) return address(PqzBurnLib);
        if (h == keccak256("PqzViewLib")) return address(PqzViewLib);
        if (h == keccak256("PqzWrappedLib")) return address(PqzWrappedLib);
        if (h == keccak256("UARegistryLib")) return address(UARegistryLib);
        if (h == keccak256("RegulatedLib")) return address(RegulatedLib);
        revert(string.concat("unknown library ", n));
    }

    /// @dev The artifacts of this build: `FOUNDRY_OUT` when set (`script/pqz/at-set.sh` builds into `out/at-set-<set>`), else
    ///      `out`. A fixed `out/` read another build's artifacts, or none on a fresh checkout.
    function _json(string memory contractName) internal view returns (string memory) {
        string memory out = vm.envOr("FOUNDRY_OUT", string("out"));
        return vm.readFile(string.concat(out, "/", contractName, ".sol/", contractName, ".json"));
    }

    /// @dev `n`'s transitive link closure, appended to `acc` (names, no duplicates).
    function _closure(string memory n, string[] memory acc) internal view returns (string[] memory) {
        string memory j = _json(n);
        string memory base = ".bytecode.linkReferences";
        string[] memory files = vm.parseJsonKeys(j, base);
        for (uint256 i; i < files.length; ++i) {
            string[] memory libs = vm.parseJsonKeys(j, string.concat(base, "[\"", files[i], "\"]"));
            for (uint256 k; k < libs.length; ++k) {
                bool seen;
                for (uint256 m; m < acc.length; ++m) if (keccak256(bytes(acc[m])) == keccak256(bytes(libs[k]))) seen = true;
                if (seen) continue;
                string[] memory grown = new string[](acc.length + 1);
                for (uint256 m; m < acc.length; ++m) grown[m] = acc[m];
                grown[acc.length] = libs[k];
                acc = _closure(libs[k], grown);
            }
        }
        return acc;
    }

    function _assertEnvIsClosure(string memory label, string memory impl, IFactoryToken.Env memory e) internal view {
        string[] memory c = _closure(impl, new string[](0));
        assertEq(e.libs.length, c.length, string.concat(label, ": number of libraries"));
        assertEq(e.libCodeHashes.length, c.length, string.concat(label, ": number of pins"));
        for (uint256 k; k < c.length; ++k) {
            bool found;
            for (uint256 i; i < e.libs.length; ++i) {
                if (e.libs[i] == _addr(c[k])) { found = true; assertEq(e.libCodeHashes[i], e.libs[i].codehash); }
            }
            assertTrue(found, string.concat(label, ": missing ", c[k]));
        }
    }

    /// Every kind: the env `DeployBase` publishes (NORMAL, both Zether kinds, the DEX) and the one the fixtures build
    /// (`closureLibs`, all six token kinds).
    function test_envLibsEqualLinkClosure() public {
        address ska = new SmartKeyAccountFactory(ZUID).IMPLEMENTATION();
        DeployHarness h = new DeployHarness();
        (OpenFactory f,) = h.deploy(ZUID, true, ska);
        _assertEnvIsClosure("DeployBase NONE", "NormalToken", f.envOf(NORMAL, 1));
        _assertEnvIsClosure("DeployBase NORMAL_ZETHER", "NormalZetherToken",
            f.envOf(IOpenFactory.TokenKind.NORMAL_ZETHER, 1));
        _assertEnvIsClosure("DeployBase WRAPPED_ZETHER", "WrappedZetherToken",
            f.envOf(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1));
        _assertEnvIsClosure("DeployBase DEX", "SCaaSDex", f.dexEnvOf(1));

        // plan T27: the regulated kinds 9 and 13 (their base kind's closure and `RegulatedLib`); T28: kind 8; T31: kind 12
        string[14] memory impls = ["NormalToken", "WrappedToken", "NormalZetherToken",
            "WrappedZetherToken", "NormalPqzToken", "WrappedPqzToken", "", "", "NormalRegulatedToken", "WrappedRegulatedToken",
            "", "", "NormalPqzRegulatedToken", "WrappedPqzRegulatedToken"];
        for (uint8 k; k < 14; ++k) {
            if (bytes(impls[k]).length == 0) continue;
            IFactoryToken.Env memory e;
            e.libs = closureLibs(IOpenFactory.TokenKind(k));
            e.libCodeHashes = new bytes32[](e.libs.length);
            for (uint256 i; i < e.libs.length; ++i) e.libCodeHashes[i] = e.libs[i].codehash;
            _assertEnvIsClosure(impls[k], impls[k], e);
        }
    }

    /// typed-signing R2: the registry's link closure is `UARegistryLib` alone, and that library links nothing. The deployed
    /// registry (through `DeployBase`, CREATE2) holds exactly one DELEGATECALL, `_lib`'s, whose target is that library.
    function test_registryClosure() public {
        string[] memory c = _closure("UARegistry", new string[](0));
        address[] memory want = registryClosureLibs();
        assertEq(c.length, want.length, "number of libraries");
        assertEq(_addr(c[0]), want[0]);
        assertEq(_closure("UARegistryLib", new string[](0)).length, 0, "UARegistryLib links nothing");

        DeployHarness h = new DeployHarness();
        (, string memory json) = h.deploy(ZUID, false, new SmartKeyAccountFactory(ZUID).IMPLEMENTATION());
        address reg = vm.parseJsonAddress(json, ".ua_registry");
        assertEq(vm.parseJsonAddress(json, ".ua_registry_lib"), want[0]);
        (uint256 delegates, bool destruct, bool callcode) = _walk(reg.code);
        assertEq(delegates, 1, "UARegistry: DELEGATECALL count");
        assertFalse(destruct, "UARegistry: SELFDESTRUCT");
        assertFalse(callcode, "UARegistry: CALLCODE");
        assertTrue(_holds(reg.code, want[0]), "the DELEGATECALL's target is in the code");
    }

    /// `code` holds the 20 bytes of `a`.
    function _holds(bytes memory code, address a) internal pure returns (bool) {
        for (uint256 i; i + 20 <= code.length; ++i) {
            bool m = true;
            for (uint256 j; j < 20 && m; ++j) m = code[i + j] == bytes20(a)[j];
            if (m) return true;
        }
        return false;
    }

    /// R6: over every library of every closure, PUSH data skipped, from the start to the last `INVALID` (solc puts its
    /// trailing data and the CBOR metadata after it): no SELFDESTRUCT (0xff), no CALLCODE (0xf2); DELEGATECALL (0xf4)
    /// only in `MtxPipelineLib` (exactly 2, -> `HederaLib`), in `WrappedLib` (exactly 1, -> `GovernanceLib`, its own link
    /// reference), in `ZetherWrappedLib` (exactly 2, -> `WrappedLib`, `ZetherLib`, its init: size lever 1, owner 2026-11-01),
    /// in `PqzWrappedLib` (exactly 2, -> `WrappedLib`, `PqzStateLib`, the same) and in `RegulatedLib` (exactly 1, ->
    /// `GovernanceLib.useLimited`, plan T28).
    function test_libraryOpcodes() public view {
        for (uint256 n; n < names.length; ++n) {
            string memory name = names[n];
            bytes memory code = _deployedCode(name);
            (uint256 delegates, bool destruct, bool callcode) = _walk(code);
            assertFalse(destruct, string.concat(name, ": SELFDESTRUCT"));
            assertFalse(callcode, string.concat(name, ": CALLCODE"));
            bytes32 h = keccak256(bytes(name));
            // WrappedLib: `GovernanceLib.init` and, since B-26, `GovernanceUse.use`'s one call to `useLimited` (1 -> 2).
            // RegulatedLib: plan T28's bodies inline `GovernanceUse.use`, whose one call to `GovernanceLib.useLimited` is
            // its only DELEGATECALL (0 -> 1; its link reference, already in every regulated kind's closure)
            uint256 want = h == keccak256("MtxPipelineLib") || h == keccak256("ZetherWrappedLib") || h == keccak256("PqzWrappedLib")
                || h == keccak256("WrappedLib") ? 2 : h == keccak256("RegulatedLib") ? 1 : 0;
            assertEq(delegates, want, string.concat(name, ": DELEGATECALL count"));
        }
    }

    function _deployedCode(string memory name) internal view returns (bytes memory c) {
        // the code deployed at the library's address in this test, not the artifact's `deployedBytecode`: the deployed
        // copy has the library's `address(this)` call-guard immutable filled in, so it is the code that actually runs
        c = _addr(name).code;
    }

    function _walk(bytes memory c) internal pure returns (uint256 delegates, bool destruct, bool callcode) {
        uint256 end = c.length;
        // cut the CBOR metadata first (its length is the last two bytes): its hash bytes can hold 0xfe / 0xff (T8: the
        // `PqzStateLib` hash did after the `debit_min_gas` re-pin, which put a false SELFDESTRUCT before the last 0xfe)
        uint256 mlen = (uint256(uint8(c[end - 2])) << 8) | uint8(c[end - 1]);
        require(end >= mlen + 2 && uint8(c[end - 2 - mlen]) >= 0xa1 && uint8(c[end - 2 - mlen]) <= 0xa3, "no CBOR metadata trailer");
        end -= 2 + mlen;
        // cut at the last 0xfe: assumes solc ends the runtime code with INVALID, then its data and the CBOR metadata
        while (end > 0 && c[end - 1] != 0xfe) --end;
        for (uint256 i; i < end; ++i) {
            uint8 op = uint8(c[i]);
            if (op >= 0x60 && op <= 0x7f) i += op - 0x5f;
            else if (op == 0xf4) ++delegates;
            else if (op == 0xff) destruct = true;
            else if (op == 0xf2) callcode = true;
        }
    }
}
