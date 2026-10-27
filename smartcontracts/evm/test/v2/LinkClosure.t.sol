// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployHarness} from "../helpers/DeployHarness.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {UnderlyingLib} from "../../src/metatx/UnderlyingLib.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {HederaLib} from "../../src/hedera/HederaLib.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {ZetherLib} from "../../src/zether/ZetherLib.sol";
import {PqzStateLib} from "../../src/pqz/PqzStateLib.sol";
import {PqzTransferLib} from "../../src/pqz/PqzTransferLib.sol";
import {PqzBurnLib} from "../../src/pqz/PqzBurnLib.sol";
import {PqzViewLib} from "../../src/pqz/PqzViewLib.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {ZUID} from "../zether/helpers/ZetherFixture.sol";
import {closureLibs} from "../helpers/Catalogue.sol";

/// @notice metatx-split task 6 (spec §4, R5, R6): a release's `Env.libs` is the transitive link closure of its
///         implementation, read from the artifacts' `linkReferences` (each library's own, recursively); and no closure
///         library can self-destruct, CALLCODE or (bar the named ones) DELEGATECALL.
contract LinkClosureTest is Test {
    IOpenFactory.TokenKind constant NONE = IOpenFactory.TokenKind.NONE;
    string[] internal names = [
        "AdminLib", "HederaLib", "TradeLib", "MtxPipelineLib", "UnderlyingLib", "ZetherLib",
        "PqzStateLib", "PqzTransferLib", "PqzBurnLib", "PqzViewLib"
    ];

    function _addr(string memory n) internal pure returns (address a) {
        bytes32 h = keccak256(bytes(n));
        if (h == keccak256("AdminLib")) return address(AdminLib);
        if (h == keccak256("HederaLib")) return address(HederaLib);
        if (h == keccak256("TradeLib")) return address(TradeLib);
        if (h == keccak256("MtxPipelineLib")) return address(MtxPipelineLib);
        if (h == keccak256("UnderlyingLib")) return address(UnderlyingLib);
        if (h == keccak256("ZetherLib")) return address(ZetherLib);
        if (h == keccak256("PqzStateLib")) return address(PqzStateLib);
        if (h == keccak256("PqzTransferLib")) return address(PqzTransferLib);
        if (h == keccak256("PqzBurnLib")) return address(PqzBurnLib);
        if (h == keccak256("PqzViewLib")) return address(PqzViewLib);
        revert(string.concat("unknown library ", n));
    }

    function _json(string memory contractName) internal view returns (string memory) {
        return vm.readFile(string.concat("out/", contractName, ".sol/", contractName, ".json"));
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

    /// Every kind: the env `DeployBase` publishes (NONE, both Zether kinds, the DEX) and the one the fixtures build
    /// (`closureLibs`, all six token kinds).
    function test_envLibsEqualLinkClosure() public {
        address ska = new SmartKeyAccountFactory(ZUID).IMPLEMENTATION();
        DeployHarness h = new DeployHarness();
        (OpenFactory f,) = h.deploy(ZUID, true, ska);
        _assertEnvIsClosure("DeployBase NONE", "NoUnderlyingToken", f.envOf(NONE, 1));
        _assertEnvIsClosure("DeployBase NONE_ZETHER", "NoUnderlyingZetherToken",
            f.envOf(IOpenFactory.TokenKind.NONE_ZETHER, 1));
        _assertEnvIsClosure("DeployBase UNDERLYING_ZETHER", "UnderlyingZetherToken",
            f.envOf(IOpenFactory.TokenKind.UNDERLYING_ZETHER, 1));
        _assertEnvIsClosure("DeployBase DEX", "SCaaSDex", f.dexEnvOf(1));

        string[6] memory impls = ["NoUnderlyingToken", "UnderlyingToken", "NoUnderlyingZetherToken",
            "UnderlyingZetherToken", "NoUnderlyingPqzToken", "UnderlyingPqzToken"];
        for (uint8 k; k < 6; ++k) {
            IFactoryToken.Env memory e;
            e.libs = closureLibs(IOpenFactory.TokenKind(k));
            e.libCodeHashes = new bytes32[](e.libs.length);
            for (uint256 i; i < e.libs.length; ++i) e.libCodeHashes[i] = e.libs[i].codehash;
            _assertEnvIsClosure(impls[k], impls[k], e);
        }
    }

    /// R6: over every library of every closure, PUSH data skipped, from the start to the last `INVALID` (solc puts its
    /// trailing data and the CBOR metadata after it): no SELFDESTRUCT (0xff), no CALLCODE (0xf2); DELEGATECALL (0xf4)
    /// only in `MtxPipelineLib` (-> `HederaLib`) and in `UnderlyingLib` (-> `AdminLib`, its own link reference).
    function test_libraryOpcodes() public view {
        for (uint256 n; n < names.length; ++n) {
            string memory name = names[n];
            bytes memory code = _deployedCode(name);
            (uint256 delegates, bool destruct, bool callcode) = _walk(code);
            assertFalse(destruct, string.concat(name, ": SELFDESTRUCT"));
            assertFalse(callcode, string.concat(name, ": CALLCODE"));
            bytes32 h = keccak256(bytes(name));
            if (h != keccak256("MtxPipelineLib") && h != keccak256("UnderlyingLib")) {
                assertEq(delegates, 0, string.concat(name, ": DELEGATECALL"));
            } else {
                assertGt(delegates, 0, string.concat(name, ": expected its DELEGATECALL"));
            }
        }
    }

    function _deployedCode(string memory name) internal view returns (bytes memory c) {
        // the deployed library's own code: its address in this test
        c = _addr(name).code;
        // the artifact's runtime code carries the `address(this)` guard immutable; the on-chain code is what runs
    }

    function _walk(bytes memory c) internal pure returns (uint256 delegates, bool destruct, bool callcode) {
        uint256 end = c.length;
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
