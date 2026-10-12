// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UAMldsaVerifier} from "../../src/ua/MlDsa.sol";
import {UAFndsaVerifier} from "../../src/ua/FnDsa.sol";
import {UASlhdsaVerifier} from "../../src/ua/SlhDsa.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";
import {UARegistryBase} from "./UARegistryBase.sol";

/// The UA ledger with PQ signers (P6c; accounts.md CTR-UA-26, §1.16): pq_signatures.json's `metatx3` rows — the
/// metatx3.json structs and domain, one row per PQ kind — on a `NONE` clone at the vector token address, context A,
/// the real PQ verifiers (ML-DSA on its cached expanded key). Every digest is recomputed by the token, every auth passes
/// `requireAuthorized` under `metatx`, every `UAMetaTransfer` row executes. Gas of `uaExecuteTransfer` per kind is logged.
contract UAMetaTx3PqTest is UARegistryBase {
    NoUnderlyingToken internal tok;

    function _pj() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/pq_signatures.json");
    }

    function setUp() public override {
        super.setUp();
        string memory pj = _pj();
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](4);
        c[0] = UARegistry.KindConfig(0x0130, address(new UAMldsaVerifier(0x0130, address(0), "", "")), 4_250_000);
        c[1] = UARegistry.KindConfig(0x0131, address(new UAMldsaVerifier(0x0131, address(0), "", "")), 5_950_000);
        c[2] = UARegistry.KindConfig(0x0132, address(new UAFndsaVerifier()), 2_500_000);
        c[3] = UARegistry.KindConfig(0x0133, address(new UASlhdsaVerifier()), 1_400_000);
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, c);
        for (uint256 i; i < 4; ++i) {
            string memory k = string.concat(".kinds[", vm.toString(i), "].");
            uint16 kind = uint16(vm.parseJsonUint(pj, string.concat(k, "kind")));
            bytes memory pk = vm.parseJsonBytes(pj, string.concat(k, "keyData"));
            for (uint256 p; kind <= 0x0131 && p < (kind == 0x0130 ? 1 : 2); ++p) reg.cacheExpandedKey(kind, pk, p);
            reg.register(kind, pk, vm.parseJsonBytes(pj, string.concat(k, "pop.sig")), 0, "");
        }
        address token = vm.parseJsonAddress(pj, ".metatx3.token");
        address impl = address(new NoUnderlyingToken(address(this), address(0), chainUidA, REG_A, false));
        vm.etch(token, abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"));
        tok = NoUnderlyingToken(token);
        tok.initialize(address(this), 1, noneInit("Points", "PTS", 6, 0, address(0), address(this)));
        vm.warp(1_800_000_000);
    }

    function _f(string memory row, string memory field) internal pure returns (string memory) {
        return string.concat(row, "typedData.message.", field);
    }

    function _call(string memory pj, string memory r) internal pure returns (MetaTxLib.UAMetaTransaction memory m) {
        m.from = vm.parseJsonBytes32(pj, _f(r, "from"));
        m.data = vm.parseJsonBytes(pj, _f(r, "data"));
        m.batch = vm.parseJsonUint(pj, _f(r, "batch"));
        m.nonce = vm.parseJsonUint(pj, _f(r, "nonce"));
        m.validUntil = vm.parseJsonUint(pj, _f(r, "validUntil"));
        m.mode = uint32(vm.parseJsonUint(pj, _f(r, "mode")));
        m.relayer = vm.parseJsonAddress(pj, _f(r, "relayer"));
        m.fee = vm.parseJsonUint(pj, _f(r, "fee"));
        m.feeRecipient = vm.parseJsonAddress(pj, _f(r, "feeRecipient"));
    }

    function _transfer(string memory pj, string memory r) internal pure returns (MetaTxLib.UAMetaTransfer memory t) {
        t.from = vm.parseJsonBytes32(pj, _f(r, "from"));
        t.to = vm.parseJsonBytes32(pj, _f(r, "to"));
        t.value = vm.parseJsonUint(pj, _f(r, "value"));
        t.entryRef = vm.parseJsonBytes32(pj, _f(r, "entryRef"));
        t.batch = vm.parseJsonUint(pj, _f(r, "batch"));
        t.nonce = vm.parseJsonUint(pj, _f(r, "nonce"));
        t.validUntil = vm.parseJsonUint(pj, _f(r, "validUntil"));
        t.mode = uint32(vm.parseJsonUint(pj, _f(r, "mode")));
        t.relayer = vm.parseJsonAddress(pj, _f(r, "relayer"));
        t.fee = vm.parseJsonUint(pj, _f(r, "fee"));
        t.feeRecipient = vm.parseJsonAddress(pj, _f(r, "feeRecipient"));
    }

    /// `UAMetaTransaction` rows: digest and auth (the `unwrap` itself is not on the `NONE` kind's allowlist).
    function test_callRows() public view {
        string memory pj = _pj();
        uint256 n;
        for (uint256 i; vm.keyExistsJson(pj, string.concat(".metatx3.call[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".metatx3.call[", vm.toString(i), "].");
            MetaTxLib.UAMetaTransaction memory m = _call(pj, r);
            bytes32 digest = vm.parseJsonBytes32(pj, string.concat(r, "digest"));
            assertEq(MetaTxLib.hashStruct(m), vm.parseJsonBytes32(pj, string.concat(r, "structHash")));
            assertEq(tok.uaDigest(m), digest);
            reg.requireAuthorized(m.from, UAKinds.PURPOSE_METATX, digest, vm.parseJsonBytes(pj, string.concat(r, "auth")));
            ++n;
        }
        assertEq(n, 4);
    }

    /// `UAMetaTransfer` rows: a payment with a FIXED fee from each PQ UA to a native payee, executed.
    function test_transferRows() public {
        string memory pj = _pj();
        uint256 n;
        for (uint256 i; vm.keyExistsJson(pj, string.concat(".metatx3.transfer[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".metatx3.transfer[", vm.toString(i), "].");
            MetaTxLib.UAMetaTransfer memory t = _transfer(pj, r);
            bytes32 digest = vm.parseJsonBytes32(pj, string.concat(r, "digest"));
            assertEq(MetaTxLib.hashStruct(t), vm.parseJsonBytes32(pj, string.concat(r, "structHash")));
            assertEq(tok.uaTransferDigest(t), digest);
            bytes memory auth = vm.parseJsonBytes(pj, string.concat(r, "auth"));
            tok.mint(address(this), t.value + t.fee);
            tok.transferToUA(t.from, t.value + t.fee);
            vm.prank(t.relayer);
            uint256 g = gasleft();
            tok.uaExecuteTransfer(t, auth);
            g -= gasleft();
            emit log_named_uint(string.concat("uaExecuteTransfer ", vm.parseJsonString(pj, string.concat(r, "name"))), g);
            assertEq(tok.balanceOfUA(t.from), 0);
            ++n;
        }
        assertEq(n, 4);
        assertEq(tok.balanceOf(address(0x5409)), 4 * 100_000_000);
        assertEq(tok.balanceOf(address(0xFEE)), 4 * 100_000);
        assertEq(tok.balanceOf(MetaTxLib.UA_POOL), 0);
    }
}
