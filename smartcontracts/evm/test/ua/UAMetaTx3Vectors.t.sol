// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {P256Verifier} from "../../src/ua/verifiers/P256Verifier.sol";
import {WebAuthnP256Verifier} from "../../src/ua/verifiers/WebAuthnP256Verifier.sol";
import {Bip340Verifier} from "../../src/ua/verifiers/Bip340Verifier.sol";
import {Secp256k1Verifier} from "../../src/ua/verifiers/Secp256k1Verifier.sol";
import {Ed25519Verifier} from "../../src/ua/verifiers/Ed25519Verifier.sol";
import {
    SchnorrBn254Verifier,
    SchnorrBls12381Verifier,
    BlsMinSigBls12381Verifier,
    BlsMinSigBn254Verifier
} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {plainEnv} from "../helpers/Catalogue.sol";

/// smartcontracts/vectors/ua/metatx3.json (accounts.md §1.16, the v3 KAT): a `NONE` clone at the vector's token
/// address on context A with the real UA-2a/UA-2b verifiers. Every row's struct (built from the file's typed data)
/// hashes to the file's digest here, every auth passes (native: ECDSA over the digest; derived: `requireAuthorized`
/// under `metatx`), and every `UAMetaTransfer` row really executes. Gas of `uaExecuteTransfer` per signer is logged.
/// UA-5a (accounts.md CTR-UA-26/28, metatx.md CTR-MTX-05/06): the `burn` rows execute under `uaExecute`, the
/// `unwrapToUA` rows are checked as the `call` rows, every `receiverFee` row executes `uaPayReceiverFee` (gas logged).
contract UAMetaTx3VectorsTest is UARegistryBase {
    string internal sj;
    string internal vj;
    NoUnderlyingToken internal tok;

    function setUp() public override {
        super.setUp();
        sj = vm.readFile("../vectors/ua/signatures.json");
        vj = vm.readFile("../vectors/ua/metatx3.json");
        assertEq(vm.parseJsonAddress(vj, ".registry"), REG_A);
        assertEq(vm.parseJsonBytes32(vj, ".chainUid"), chainUidA);
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _realCfgs());
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            string memory d = string.concat(".derived[", vm.toString(i), "].");
            reg.register(
                uint16(vm.parseJsonUint(sj, string.concat(d, "kind"))),
                vm.parseJsonBytes(sj, string.concat(d, "keyData")),
                vm.parseJsonBytes(sj, string.concat(d, "pop.sig")),
                "",
                ""
            );
        }
        address token = vm.parseJsonAddress(vj, ".token");
        address impl = address(new NoUnderlyingToken(1, plainEnv(address(this), address(0), chainUidA, REG_A, false), ""));
        vm.etch(token, abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"));
        tok = NoUnderlyingToken(token);
        tok.initialize(address(this), 1, abi.encode(noneInit("Points", "PTS", 6, 0, address(0), address(this))));
        vm.warp(1_800_000_000);
    }

    function _realCfgs() internal returns (UARegistry.KindConfig[] memory c) {
        address[8] memory v = [
            address(new WebAuthnP256Verifier()),
            address(new P256Verifier()),
            address(new Ed25519Verifier()),
            address(new Bip340Verifier()),
            address(new SchnorrBn254Verifier()),
            address(new SchnorrBls12381Verifier()),
            address(new BlsMinSigBls12381Verifier()),
            address(new BlsMinSigBn254Verifier())
        ];
        c = new UARegistry.KindConfig[](9);
        for (uint256 i; i < 8; ++i) {
            c[i] = UARegistry.KindConfig(KINDS[i], v[i], _cap(KINDS[i]));
        }
        c[8] = UARegistry.KindConfig(0x0108, address(new Secp256k1Verifier()), 50_000);
    }

    function _f(string memory row, string memory field) internal pure returns (string memory) {
        return string.concat(row, "typedData.message.", field);
    }

    function _call(string memory r) internal view returns (MetaTxLib.UAMetaTransaction memory m) {
        m.from = vm.parseJsonBytes32(vj, _f(r, "from"));
        m.data = vm.parseJsonBytes(vj, _f(r, "data"));
        m.batch = vm.parseJsonUint(vj, _f(r, "batch"));
        m.nonce = vm.parseJsonUint(vj, _f(r, "nonce"));
        m.validUntil = vm.parseJsonUint(vj, _f(r, "validUntil"));
        m.mode = uint32(vm.parseJsonUint(vj, _f(r, "mode")));
        m.relayer = vm.parseJsonAddress(vj, _f(r, "relayer"));
        m.fee = vm.parseJsonUint(vj, _f(r, "fee"));
        m.feeRecipient = vm.parseJsonAddress(vj, _f(r, "feeRecipient"));
    }

    function _transfer(string memory r) internal view returns (MetaTxLib.UAMetaTransfer memory) {
        return _transferAt(string.concat(r, "typedData.message."));
    }

    /// A `UAMetaTransfer` from the message at path prefix `p`.
    function _transferAt(string memory p) internal view returns (MetaTxLib.UAMetaTransfer memory t) {
        t.from = vm.parseJsonBytes32(vj, string.concat(p, "from"));
        t.to = vm.parseJsonBytes32(vj, string.concat(p, "to"));
        t.value = vm.parseJsonUint(vj, string.concat(p, "value"));
        t.entryRef = vm.parseJsonBytes32(vj, string.concat(p, "entryRef"));
        t.batch = vm.parseJsonUint(vj, string.concat(p, "batch"));
        t.nonce = vm.parseJsonUint(vj, string.concat(p, "nonce"));
        t.validUntil = vm.parseJsonUint(vj, string.concat(p, "validUntil"));
        t.mode = uint32(vm.parseJsonUint(vj, string.concat(p, "mode")));
        t.relayer = vm.parseJsonAddress(vj, string.concat(p, "relayer"));
        t.fee = vm.parseJsonUint(vj, string.concat(p, "fee"));
        t.feeRecipient = vm.parseJsonAddress(vj, string.concat(p, "feeRecipient"));
    }

    function test_typeHashesAndDomain() public view {
        assertEq(vm.parseJsonBytes32(vj, ".typeHashes.UAMetaTransaction"), MetaTxLib.UAMETATX_TYPEHASH);
        assertEq(vm.parseJsonBytes32(vj, ".typeHashes.UAMetaTransfer"), MetaTxLib.UAMETATRANSFER_TYPEHASH);
        (,,,,, bytes32 salt,) = tok.eip712Domain();
        assertEq(salt, chainUidA);
        bytes32 ds = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), block.chainid, address(tok), chainUidA));
        assertEq(vm.parseJsonBytes32(vj, ".domainSeparator"), ds);
    }

    /// `UAMetaTransaction` rows: digest and auth (the `unwrap` itself is not on the `NONE` kind's allowlist).
    function test_callRows() public view {
        uint256 n;
        for (uint256 i; vm.keyExistsJson(vj, string.concat(".call[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".call[", vm.toString(i), "].");
            MetaTxLib.UAMetaTransaction memory m = _call(r);
            bytes32 digest = vm.parseJsonBytes32(vj, string.concat(r, "digest"));
            assertEq(MetaTxLib.hashStruct(m), vm.parseJsonBytes32(vj, string.concat(r, "structHash")));
            assertEq(tok.uaDigest(m), digest);
            _authorized(m.from, digest, vm.parseJsonBytes(vj, string.concat(r, "auth")));
            ++n;
        }
        assertEq(n, 10);
    }

    /// `UAMetaTransfer` rows: a payment with a FIXED fee from each signer to a native payee, executed.
    function test_transferRows() public {
        uint256 n;
        for (uint256 i; vm.keyExistsJson(vj, string.concat(".transfer[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".transfer[", vm.toString(i), "].");
            MetaTxLib.UAMetaTransfer memory t = _transfer(r);
            bytes32 digest = vm.parseJsonBytes32(vj, string.concat(r, "digest"));
            assertEq(MetaTxLib.hashStruct(t), vm.parseJsonBytes32(vj, string.concat(r, "structHash")));
            assertEq(tok.uaTransferDigest(t), digest);
            bytes memory auth = vm.parseJsonBytes(vj, string.concat(r, "auth"));
            _fund(t.from, t.value + t.fee);
            vm.prank(t.relayer);
            uint256 g = gasleft();
            tok.uaExecuteTransfer(t, auth);
            g -= gasleft();
            emit log_named_uint(string.concat("uaExecuteTransfer ", vm.parseJsonString(vj, string.concat(r, "name"))), g);
            assertEq(tok.balanceOfUA(t.from), 0);
            ++n;
        }
        assertEq(n, 10);
        assertEq(tok.balanceOf(address(0x5409)), 10 * 100_000_000);
        assertEq(tok.balanceOf(address(0xFEE)), 10 * 100_000);
        assertEq(tok.balanceOf(MetaTxLib.UA_POOL), 0);
    }

    /// `burn` rows: each signer burns 1,000,000 under `uaExecute` (fee PERCENT 0.5 % of it, `AMOUNT(0)`), executed.
    function test_vectors_burn() public {
        uint256 n;
        for (uint256 i; vm.keyExistsJson(vj, string.concat(".burn[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".burn[", vm.toString(i), "].");
            MetaTxLib.UAMetaTransaction memory m = _call(r);
            assertEq(MetaTxLib.hashStruct(m), vm.parseJsonBytes32(vj, string.concat(r, "structHash")));
            assertEq(tok.uaDigest(m), vm.parseJsonBytes32(vj, string.concat(r, "digest")));
            _fund(m.from, 1_005_000);
            uint256 supply = tok.totalSupply();
            bytes memory auth = vm.parseJsonBytes(vj, string.concat(r, "auth"));
            vm.prank(m.relayer);
            uint256 g = gasleft();
            tok.uaExecute(m, auth);
            g -= gasleft();
            emit log_named_uint(string.concat("uaExecute(burn) ", vm.parseJsonString(vj, string.concat(r, "name"))), g);
            assertEq(tok.balanceOfUA(m.from), 0);
            assertEq(tok.totalSupply(), supply - 1_000_000);
            ++n;
        }
        assertEq(n, 10);
        assertEq(tok.balanceOf(address(0xFEE)), 10 * 5_000);
        assertEq(tok.balanceOf(MetaTxLib.UA_POOL), 0);
    }

    /// `unwrapToUA` rows: digest and auth (the call is not on the `NONE` kind's allowlist; it runs in UAAllowlist5a).
    function test_vectors_unwrapToUA() public view {
        uint256 n;
        for (uint256 i; vm.keyExistsJson(vj, string.concat(".unwrapToUA[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".unwrapToUA[", vm.toString(i), "].");
            MetaTxLib.UAMetaTransaction memory m = _call(r);
            bytes32 digest = vm.parseJsonBytes32(vj, string.concat(r, "digest"));
            assertEq(bytes4(m.data), bytes4(keccak256("unwrapToUA(address,uint256,bytes32,uint256)")));
            assertEq(MetaTxLib.hashStruct(m), vm.parseJsonBytes32(vj, string.concat(r, "structHash")));
            assertEq(tok.uaDigest(m), digest);
            _authorized(m.from, digest, vm.parseJsonBytes(vj, string.concat(r, "auth")));
            ++n;
        }
        assertEq(n, 10);
    }

    /// `receiverFee` rows: the payment digest and the `ReceiverFee` digest recomputed by the token, then
    /// `uaPayReceiverFee` executed with the row's two auth blobs (a derived payee under `receiver-fee`).
    function test_vectors_receiverFee() public {
        uint256 n;
        for (uint256 i; vm.keyExistsJson(vj, string.concat(".receiverFee[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".receiverFee[", vm.toString(i), "].");
            MetaTxLib.UAMetaTransfer memory t = _transferAt(string.concat(r, "transfer.message."));
            bytes32 d = vm.parseJsonBytes32(vj, string.concat(r, "paymentDigest"));
            assertEq(tok.uaTransferDigest(t), d);
            uint256 fee = vm.parseJsonUint(vj, string.concat(r, "receiverFee.message.fee"));
            address feeTo = vm.parseJsonAddress(vj, string.concat(r, "receiverFee.message.feeRecipient"));
            uint256 until = vm.parseJsonUint(vj, string.concat(r, "receiverFee.message.validUntil"));
            assertEq(vm.parseJsonBytes32(vj, string.concat(r, "receiverFee.message.paymentDigest")), d);
            assertEq(tok.receiverFeeDigest(d, fee, feeTo, until), vm.parseJsonBytes32(vj, string.concat(r, "receiverFeeDigest")));
            _fund(t.from, t.value);
            uint256 before = tok.balanceOfUA(t.to);
            bytes memory payerAuth = vm.parseJsonBytes(vj, string.concat(r, "payerAuth"));
            bytes memory payeeAuth = vm.parseJsonBytes(vj, string.concat(r, "payeeAuth"));
            vm.prank(t.relayer);
            uint256 g = gasleft();
            tok.uaPayReceiverFee(t, payerAuth, fee, feeTo, until, payeeAuth);
            g -= gasleft();
            emit log_named_uint(string.concat("uaPayReceiverFee ", vm.parseJsonString(vj, string.concat(r, "payer")), " > ",
                vm.parseJsonString(vj, string.concat(r, "payee"))), g);
            assertEq(tok.balanceOfUA(t.to), before + t.value - fee);
            ++n;
        }
        assertEq(n, 10);
        assertEq(tok.balanceOf(address(0xFEE)), 10 * 300_000);
    }

    function _authorized(bytes32 from, bytes32 digest, bytes memory auth) internal view {
        if (UAKinds.inNativeSpace(from)) {
            assertEq(ECDSA.recover(digest, auth), address(uint160(uint256(from))));
        } else {
            reg.requireAuthorized(from, UAKinds.PURPOSE_METATX, digest, auth);
        }
    }

    function _fund(bytes32 id, uint256 amount) internal {
        if (UAKinds.inNativeSpace(id)) {
            tok.mint(address(uint160(uint256(id))), amount);
        } else {
            tok.mint(address(this), amount);
            tok.transferToUA(id, amount);
        }
    }
}
