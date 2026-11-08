// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {IUAPopVerifier} from "../../../src/ua/IUAVerifier.sol";
import {Secp256k1Verifier} from "../../../src/ua/verifiers/Secp256k1Verifier.sol";
import {Ed25519Verifier} from "../../../src/ua/verifiers/Ed25519Verifier.sol";

/// ua-rs-sign T20c (owner 2026-11-08, the CLI-SGN-29 Change): an imported native key's UA, the derived kind of its own scheme
/// (secp256k1 0x0108, ed25519 0x0102), as the registry's verifiers check it, read from vectors/ua/sign.json `imported`
/// (clientkeys scripts/ua-wallet-vectors.mjs; ua-rs and clientkeys reproduce the same rows). A test only: no contract changes.
/// The separation rows: the key's native signature over an operation's own digest is no UA signature, the UA signature is (the
/// positive control). UNAUDITED.
contract ImportedKeyVectorsTest is Test {
    Secp256k1Verifier secp;
    Ed25519Verifier ed;
    string sj;

    function setUp() public {
        secp = new Secp256k1Verifier();
        ed = new Ed25519Verifier();
        sj = vm.readFile(string.concat(vm.projectRoot(), "/../vectors/ua/sign.json"));
    }

    function _v(uint16 kind) internal view returns (IUAPopVerifier) {
        if (kind == 0x0108) return secp;
        if (kind == 0x0102) return ed;
        revert("kind");
    }

    function test_ImportedRowsVerify() public view {
        uint256 n;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".imported.rows[", vm.toString(i), "]")); ++i) {
            string memory e = string.concat(".imported.rows[", vm.toString(i), "]");
            uint16 kind = uint16(vm.parseJsonUint(sj, string.concat(e, ".kind")));
            bytes memory key = vm.parseJsonBytes(sj, string.concat(e, ".keyData"));
            assertEq(vm.parseJsonBytes32(sj, string.concat(e, ".ua")), UAKinds.uaOf(kind, key), "ua");
            bytes32 m = vm.parseJsonBytes32(sj, string.concat(e, ".uaMsg"));
            assertEq(
                m,
                UAKinds.uaMessage(
                    kind, vm.parseJsonBytes32(sj, string.concat(e, ".purposeTag")), vm.parseJsonBytes32(sj, string.concat(e, ".digest"))
                ),
                e
            );
            bytes memory sig = vm.parseJsonBytes(sj, string.concat(e, ".signature"));
            bool pop = keccak256(bytes(vm.parseJsonString(sj, string.concat(e, ".role")))) == keccak256("pop");
            assertTrue(pop ? _v(kind).verifyPop(key, m, sig) : _v(kind).verify(key, m, sig), e);
            ++n;
        }
        assertEq(n, 6, "pop, metatx, member for the evm and the solana import");
    }

    function test_ImportedSeparation() public view {
        uint256 n;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".imported.separation[", vm.toString(i), "]")); ++i) {
            string memory e = string.concat(".imported.separation[", vm.toString(i), "]");
            uint16 kind = uint16(vm.parseJsonUint(sj, string.concat(e, ".kind")));
            string memory net = vm.parseJsonString(sj, string.concat(e, ".network"));
            bytes memory key = _keyOf(net);
            bytes32 m = vm.parseJsonBytes32(sj, string.concat(e, ".uaMsg"));
            assertTrue(_v(kind).verify(key, m, vm.parseJsonBytes(sj, string.concat(e, ".uaSignature"))), "UA positive control");
            assertFalse(_v(kind).verify(key, m, vm.parseJsonBytes(sj, string.concat(e, ".nativeSignature"))), e);
            ++n;
        }
        assertEq(n, 4, "typed, tx, key proof (evm); key proof (solana)");
    }

    function _keyOf(string memory net) internal view returns (bytes memory) {
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".imported.rows[", vm.toString(i), "]")); ++i) {
            string memory e = string.concat(".imported.rows[", vm.toString(i), "]");
            if (keccak256(bytes(vm.parseJsonString(sj, string.concat(e, ".network")))) == keccak256(bytes(net))) {
                return vm.parseJsonBytes(sj, string.concat(e, ".keyData"));
            }
        }
        revert("network");
    }
}
