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
import {UARegistryCoreLib} from "../../src/ua/UARegistryCoreLib.sol";
import {UARegistryAuxLib} from "../../src/ua/UARegistryAuxLib.sol";
import {RegulatedLib} from "../../src/regulated/RegulatedLib.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {ZUID} from "../zether/helpers/ZetherFixture.sol";
import {closureLibs, registryClosureLibs, regArgs} from "../helpers/Catalogue.sol";
import {kindModuleNames, deployKindModules, deployDexModules} from "../../script/KindModules.sol";
import {ITokenModules} from "../../src/metatx/ITokenModule.sol";

/// @notice metatx-split task 6 (spec §4, R5, R6): a release's `Env.libs` is the transitive link closure of its
///         implementation, read from the artifacts' `linkReferences` (each library's own, recursively); and no closure
///         library can self-destruct, CALLCODE or (bar the named ones) DELEGATECALL. T66b §4.5 (Fable P2-3): the closure is
///         the implementation's link references, its body modules (`modules()`) and each module's link references,
///         recursively; the env pins the modules after the libraries; every module passes the opcode scan.
contract LinkClosureTest is Test {
    IOpenFactory.TokenKind constant NORMAL = IOpenFactory.TokenKind.NORMAL;
    string[] internal names = [
        "GovernanceLib", "HederaLib", "TradeLib", "MtxPipelineLib", "WrappedLib", "ZetherLib", "ZetherWrappedLib",
        "PqzStateLib", "PqzTransferLib", "PqzBurnLib", "PqzViewLib", "PqzWrappedLib", "UARegistryCoreLib", "UARegistryAuxLib", "RegulatedLib"
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
        if (h == keccak256("UARegistryCoreLib")) return address(UARegistryCoreLib);
        if (h == keccak256("UARegistryAuxLib")) return address(UARegistryAuxLib);
        if (h == keccak256("RegulatedLib")) return address(RegulatedLib);
        revert(string.concat("unknown library ", n));
    }

    /// @dev The artifacts of this build: `FOUNDRY_OUT` when set (`script/pqz/at-set.sh` builds into `out/at-set-<set>`), else
    ///      `out`. A fixed `out/` read another build's artifacts, or none on a fresh checkout.
    function _json(string memory file, string memory contractName) internal view returns (string memory) {
        string memory out = vm.envOr("FOUNDRY_OUT", string("out"));
        return vm.readFile(string.concat(out, "/", file, ".sol/", contractName, ".json"));
    }

    /// @dev `n`'s transitive link closure, appended to `acc` (names, no duplicates).
    function _closure(string memory n, string[] memory acc) internal view returns (string[] memory) {
        return _closure(n, n, acc);
    }

    /// @dev The same for contract `n` of source file `file` (a body module sits in its kind's `<Kind>Modules.sol`).
    function _closure(string memory file, string memory n, string[] memory acc) internal view returns (string[] memory) {
        string memory j = _json(file, n);
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
                acc = _closure(libs[k], libs[k], grown);
            }
        }
        return acc;
    }

    /// @dev The library closure of a release (T66b §4.5): `impl`'s link references and those of each module artifact in
    ///      `mods` (`File.sol:Name`), recursively; the DEX's `mods` is its D.
    function _releaseClosure(string memory impl, string[] memory mods) internal view returns (string[] memory c) {
        c = _closure(impl, new string[](0));
        for (uint256 i; i < mods.length; ++i) {
            string[] memory p = vm.split(mods[i], ":");
            c = _closure(vm.replace(p[0], ".sol", ""), p[1], c);
        }
    }

    /// @dev `e.libs` is exactly `impl`'s release closure followed by `modules` (the release's `modules()`; none for a
    ///      fixture env, which `withModules` completes), each with its code hash. Its own call frame (`this.`), so the
    ///      artifacts it parses leave memory with it (12 kinds' modules in one frame ran out of memory).
    function _assertEnvIsClosure(string memory label, string memory impl, string[] memory mods, address[] memory modules,
        IFactoryToken.Env memory e) internal view
    {
        this.assertEnvIsClosure(label, impl, mods, modules, e);
    }

    function assertEnvIsClosure(string memory label, string memory impl, string[] memory mods, address[] memory modules,
        IFactoryToken.Env memory e) external view
    {
        string[] memory c = _releaseClosure(impl, mods);
        assertEq(e.libs.length, c.length + modules.length, string.concat(label, ": number of libraries and modules"));
        assertEq(e.libCodeHashes.length, e.libs.length, string.concat(label, ": number of pins"));
        for (uint256 k; k < c.length; ++k) {
            bool found;
            for (uint256 i; i < c.length; ++i) {
                if (e.libs[i] == _addr(c[k])) { found = true; assertEq(e.libCodeHashes[i], e.libs[i].codehash); }
            }
            assertTrue(found, string.concat(label, ": missing ", c[k]));
        }
        for (uint256 i; i < modules.length; ++i) {
            assertEq(e.libs[c.length + i], modules[i], string.concat(label, ": module pin"));
            assertEq(e.libCodeHashes[c.length + i], modules[i].codehash, string.concat(label, ": module code hash"));
        }
    }

    function _dexMods() internal pure returns (string[] memory m) {
        m = new string[](2);
        m[0] = "SCaaSDexAdmin.sol:SCaaSDexGovernanceModule";
        m[1] = "SCaaSDexLiquidityModule.sol:SCaaSDexLiquidityModule";
    }

    function _mods(IOpenFactory.TokenKind k) internal pure returns (string[] memory) {
        return kindModuleNames(uint8(k));
    }

    function _modulesOf(OpenFactory f, IOpenFactory.TokenKind k) internal view returns (address[] memory) {
        return ITokenModules(f.implementationOf(k, 1)).modules();
    }

    /// Every kind: the env `DeployBase` publishes (NORMAL, both Zether kinds, the DEX) and the one the fixtures build
    /// (`closureLibs`, all six token kinds).
    function test_envLibsEqualLinkClosure() public {
        address ska = new SmartKeyAccountFactory(ZUID).IMPLEMENTATION();
        DeployHarness h = new DeployHarness();
        (OpenFactory f,) = h.deploy(ZUID, true, ska);
        _assertEnvIsClosure("DeployBase NONE", "NormalToken", _mods(NORMAL), _modulesOf(f, NORMAL), f.envOf(NORMAL, 1));
        IOpenFactory.TokenKind z = IOpenFactory.TokenKind.NORMAL_ZETHER;
        _assertEnvIsClosure("DeployBase NORMAL_ZETHER", "NormalZetherToken", _mods(z), _modulesOf(f, z), f.envOf(z, 1));
        z = IOpenFactory.TokenKind.WRAPPED_ZETHER;
        _assertEnvIsClosure("DeployBase WRAPPED_ZETHER", "WrappedZetherToken", _mods(z), _modulesOf(f, z), f.envOf(z, 1));
        _assertEnvIsClosure("DeployBase DEX", "SCaaSDex", _dexMods(), ITokenModules(f.dexImplementationOf(1)).modules(),
            f.dexEnvOf(1));

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
            _assertEnvIsClosure(impls[k], impls[k], _mods(IOpenFactory.TokenKind(k)), new address[](0), e);
        }
    }

    /// Plan T33 (regulated-kinds spec §6.1): every regulated kind's env equals its implementation's link closure with
    /// `RegulatedLib` in it, its code hash in `libCodeHashes`: the envs `DeployBase` publishes (8, 9 by `DEPLOY_REGULATED`,
    /// 10, 11 by `DEPLOY_ZETHER`) and `closureLibs` for all six (12, 13 are `script/pqz/e2e.py`'s, its self-test checks them).
    function test_linkClosureWithRegulatedLib() public {
        DeployHarness h = new DeployHarness();
        h.setRegulated(true);
        h.setComplianceAdmin(address(this));
        (OpenFactory f,) = h.deploy(ZUID, true, new SmartKeyAccountFactory(ZUID).IMPLEMENTATION());
        string[6] memory impls = ["NormalRegulatedToken", "WrappedRegulatedToken", "NormalZetherRegulatedToken",
            "WrappedZetherRegulatedToken", "NormalPqzRegulatedToken", "WrappedPqzRegulatedToken"];
        for (uint8 i; i < 6; ++i) {
            IOpenFactory.TokenKind k = IOpenFactory.TokenKind(8 + i);
            IFactoryToken.Env memory e;
            address[] memory ms;
            if (i < 4) (e, ms) = (f.envOf(k, 1), _modulesOf(f, k));
            else (e.libs, e.libCodeHashes) = (closureLibs(k), _pins(closureLibs(k)));
            _assertEnvIsClosure(impls[i], impls[i], _mods(k), ms, e);
            bool lib;
            for (uint256 j; j < e.libs.length; ++j) {
                lib = lib || (e.libs[j] == address(RegulatedLib) && e.libCodeHashes[j] == address(RegulatedLib).codehash);
            }
            assertTrue(lib, string.concat(impls[i], ": RegulatedLib and its code hash"));
        }
    }

    function _pins(address[] memory libs) internal view returns (bytes32[] memory h) {
        h = new bytes32[](libs.length);
        for (uint256 i; i < libs.length; ++i) h[i] = libs[i].codehash;
    }

    /// typed-signing R2, T66b 3.1b: the registry's link closure is `UARegistryCoreLib` and `UARegistryAuxLib` (1 -> 2); T66b 3.1c:
    /// the auxiliary library links the core (its shared helpers, by a nested DELEGATECALL), the core links nothing. The deployed registry
    /// (through `DeployBase`, CREATE2) holds exactly two DELEGATECALLs, `_lib`'s (to either library, by the entry) and (T66b R-1)
    /// `_libRaw`'s (1 -> 2), and both targets are in its code.
    function test_registryClosure() public {
        string[] memory c = _closure("UARegistry", new string[](0));
        address[] memory want = registryClosureLibs();
        assertEq(c.length, want.length, "number of libraries");
        for (uint256 i; i < c.length; ++i) assertEq(_addr(c[i]), want[i], c[i]);
        assertEq(_closure("UARegistryCoreLib", new string[](0)).length, 0, "UARegistryCoreLib links nothing");
        string[] memory aux = _closure("UARegistryAuxLib", new string[](0));
        assertEq(aux.length, 1, "UARegistryAuxLib links one library");
        assertEq(_addr(aux[0]), address(UARegistryCoreLib), "UARegistryAuxLib links the core");
        assertTrue(_holds(address(UARegistryAuxLib).code, address(UARegistryCoreLib)), "the core is in the auxiliary code");

        DeployHarness h = new DeployHarness();
        (, string memory json) = h.deploy(ZUID, false, new SmartKeyAccountFactory(ZUID).IMPLEMENTATION());
        address reg = vm.parseJsonAddress(json, ".ua_registry");
        assertEq(vm.parseJsonAddress(json, ".ua_registry_aux_lib"), want[0]);
        assertEq(vm.parseJsonAddress(json, ".ua_registry_core_lib"), want[1]);
        (uint256 delegates, bool destruct, bool callcode) = _walk(reg.code);
        assertEq(delegates, 2, "UARegistry: DELEGATECALL count");
        assertFalse(destruct, "UARegistry: SELFDESTRUCT");
        assertFalse(callcode, "UARegistry: CALLCODE");
        assertTrue(_holds(reg.code, want[0]), "the auxiliary library is in the code");
        assertTrue(_holds(reg.code, want[1]), "the core library is in the code");
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
    /// `GovernanceLib.useLimited`, plan T28) and in `UARegistryAuxLib` (exactly 1, -> `UARegistryCoreLib`'s shared helpers,
    /// T66b 3.1c, owner 2026-11-09).
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
                || h == keccak256("WrappedLib") ? 2 : h == keccak256("RegulatedLib") || h == keccak256("UARegistryAuxLib") ? 1 : 0;
            assertEq(delegates, want, string.concat(name, ": DELEGATECALL count"));
        }
    }

    /// T66b §4.5 (M5), the opcode scan of every body module of every kind and of the DEX's D, on the deployed code
    /// (modules deployed here for a stand-in factory; the regulated kinds with `regArgs()`): no SELFDESTRUCT, no CALLCODE;
    /// the DELEGATECALL count is the module's pin in `module-opcodes.json`, and each DELEGATECALL's last PUSH20 before it
    /// is a library of the kind's closure, but for the pinned sites whose target is an argument (`ZetherLayer._lib`).
    function test_moduleOpcodes() public {
        string memory pins = vm.readFile("test/v2/module-opcodes.json");
        uint256 seen;
        for (uint8 k; k < 14; ++k) {
            if (k == 6 || k == 7) continue;
            (address[] memory ms,) = deployKindModules(k, address(0xFAC), k >= 8 ? regArgs() : bytes(""));
            string[] memory n = kindModuleNames(k);
            for (uint256 i; i < ms.length; ++i) seen += _scanModule(vm.split(n[i], ":")[1], ms[i].code, closureLibs(IOpenFactory.TokenKind(k)), pins);
        }
        (address[] memory d,) = deployDexModules(address(0xFAC));
        address[] memory dl = new address[](2);
        (dl[0], dl[1]) = (address(GovernanceLib), address(TradeLib));
        seen += _scanModule("SCaaSDexGovernanceModule", d[0].code, dl, pins);
        seen += _scanModule("SCaaSDexLiquidityModule", d[1].code, dl, pins);
        assertEq(seen, vm.parseJsonKeys(pins, ".").length - 1, "every pinned module scanned");
    }

    function _scanModule(string memory name, bytes memory c, address[] memory closure, string memory pins)
        internal pure returns (uint256)
    {
        (uint256 delegates, bool destruct, bool callcode) = _walk(c);
        assertFalse(destruct, string.concat(name, ": SELFDESTRUCT"));
        assertFalse(callcode, string.concat(name, ": CALLCODE"));
        uint256[] memory want = vm.parseJsonUintArray(pins, string.concat(".", name));
        assertEq(delegates, want[0], string.concat(name, ": DELEGATECALL count"));
        assertEq(_stackTargets(c, closure), want[1], string.concat(name, ": DELEGATECALLs without a closure PUSH20"));
        return 1;
    }

    /// @dev The DELEGATECALLs (up to the last INVALID) whose last PUSH20 before them is no address of `closure`.
    function _stackTargets(bytes memory c, address[] memory closure) internal pure returns (uint256 n) {
        uint256 end = c.length - 2 - ((uint256(uint8(c[c.length - 2])) << 8) | uint8(c[c.length - 1]));
        while (end > 0 && c[end - 1] != 0xfe) --end;
        address last;
        for (uint256 i; i < end; ++i) {
            uint8 op = uint8(c[i]);
            if (op == 0x73) {
                bytes20 a;
                for (uint256 j; j < 20; ++j) a |= bytes20(c[i + 1 + j]) >> (8 * j);
                last = address(a);
            }
            if (op == 0xf4) {
                bool ok;
                for (uint256 j; j < closure.length; ++j) ok = ok || closure[j] == last;
                if (!ok) ++n;
            }
            if (op >= 0x60 && op <= 0x7f) i += op - 0x5f;
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
