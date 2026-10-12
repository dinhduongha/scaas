// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";

/// KATs of the two structs on a real token (metatx.md "One rule, four places"): `metatx_kat.json` (v3
/// `MetaTransaction`, `cancelNonce(42)`) and `metatransfer_kat.json` (`MetaTransfer`, a payment on its pay lane
/// with a bound FIXED fee), both in the token domain "SCaaS MetaToken" of a `NoUnderlyingToken` clone on chain
/// 7622 with its real `chain_uid`, each with the relayed `calldata` (`mtxExecute` / `mtxExecuteTransfer`) that scaas-node
/// and clientkeys must encode byte for byte. `WRITE_KAT=true forge test --match-contract TokenKatTest` rewrites them.
contract TokenKatTest is Test {
    using MetaTxLib for MetaTxLib.MetaTransaction;
    using MetaTxLib for MetaTxLib.MetaTransfer;

    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint256 internal constant ALICE_PK = 0xA11CE;
    address internal constant RELAYER = address(0xBEEF);
    string internal constant OUT_TX = "./test/vectors/metatx_kat.json";
    string internal constant OUT_TRANSFER = "./test/vectors/metatransfer_kat.json";
    NoUnderlyingToken internal tok;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        tok = NoUnderlyingToken(Clones.clone(address(new NoUnderlyingToken(address(this), address(0), UID, address(0), false))));
        tok.initialize(address(this), 1, noneInit("Points", "PTS", 6, 0, address(this), address(this)));
        tok.mint(vm.addr(ALICE_PK), 1_000e6);
    }

    function _domainSep() internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), uint256(7622), address(tok), UID));
    }

    function _sign(bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    function _common(string memory k, bytes32 domainSep) internal {
        vm.serializeString(k, "domain_name", "SCaaS MetaToken");
        vm.serializeString(k, "domain_version", "1");
        vm.serializeString(k, "chain_id", "7622");
        vm.serializeString(k, "verifying_contract", vm.toString(address(tok)));
        vm.serializeString(k, "salt", vm.toString(UID));
        vm.serializeString(k, "domain_separator", vm.toString(domainSep));
        vm.serializeString(k, "signer", vm.toString(vm.addr(ALICE_PK)));
    }

    function _check(string memory path, bytes32 typeHash, bytes32 structHash, bytes32 digest, bytes memory sig,
        bytes memory data) internal view
    {
        string memory onDisk = vm.readFile(path);
        assertEq(vm.parseJsonBytes(onDisk, ".calldata"), data);
        assertEq(vm.parseJsonBytes32(onDisk, ".type_hash"), typeHash);
        assertEq(vm.parseJsonBytes32(onDisk, ".salt"), UID);
        assertEq(vm.parseJsonAddress(onDisk, ".verifying_contract"), address(tok));
        assertEq(vm.parseJsonBytes32(onDisk, ".struct_hash"), structHash);
        assertEq(vm.parseJsonBytes32(onDisk, ".digest"), digest);
        assertEq(vm.parseJsonBytes(onDisk, ".signature"), sig);
    }

    function test_metaTxKat() public {
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({
            from: vm.addr(ALICE_PK), data: abi.encodeCall(IMetaTx.cancelNonce, (42)),
            batch: 7, nonce: 0, validUntil: 1_800_000_300, mode: MetaTxLib.MODE_RESTRICT_RELAYER,
            relayer: RELAYER, fee: 0, feeRecipient: address(0xFEE)       // flag off: hashed as 0
        });
        bytes32 structHash = m.hashStruct();
        bytes32 domainSep = _domainSep();
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
        assertEq(digest, tok.mtxDigest(m));
        bytes memory sig = _sign(digest);
        bytes memory data = abi.encodeCall(IMetaTx.mtxExecute, (m, sig));
        vm.prank(RELAYER);                                                // the vector really executes, as calldata
        (bool ok,) = address(tok).call(data);
        assertTrue(ok);
        assertEq(tok.mtxNonce(m.from, 7), 1);

        string memory k = "tx";
        _common(k, domainSep);
        vm.serializeString(k, "from", vm.toString(m.from));
        vm.serializeString(k, "data", vm.toString(m.data));
        vm.serializeString(k, "batch", vm.toString(m.batch));
        vm.serializeString(k, "nonce", vm.toString(m.nonce));
        vm.serializeString(k, "valid_until", vm.toString(m.validUntil));
        vm.serializeString(k, "mode", vm.toString(uint256(m.mode)));
        vm.serializeString(k, "relayer", vm.toString(m.relayer));
        vm.serializeString(k, "fee", vm.toString(m.fee));
        vm.serializeString(k, "fee_recipient", vm.toString(m.feeRecipient));
        vm.serializeString(k, "type_hash", vm.toString(MetaTxLib.METATX_TYPEHASH));
        vm.serializeString(k, "struct_hash", vm.toString(structHash));
        vm.serializeString(k, "digest", vm.toString(digest));
        vm.serializeString(k, "calldata", vm.toString(data));
        string memory out = vm.serializeString(k, "signature", vm.toString(sig));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT_TX);
        _check(OUT_TX, MetaTxLib.METATX_TYPEHASH, structHash, digest, sig, data);
    }

    function test_metaTransferKat() public {
        bytes32 ref = keccak256("scaas.kat.entryRef");
        MetaTxLib.MetaTransfer memory t = MetaTxLib.MetaTransfer({
            from: vm.addr(ALICE_PK), to: address(0x5409), value: 100e6, entryRef: ref, batch: tok.payLane(ref),
            nonce: 0, validUntil: 1_800_000_300,
            mode: MetaTxLib.MODE_RESTRICT_RELAYER | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT | MetaTxLib.MODE_FEE_FIXED,
            relayer: RELAYER, fee: 1e5, feeRecipient: address(0xFEE)
        });
        bytes32 structHash = t.hashStruct();
        bytes32 domainSep = _domainSep();
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
        assertEq(digest, tok.mtxTransferDigest(t));
        bytes memory sig = _sign(digest);
        bytes memory data = abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (t, sig));
        vm.prank(RELAYER);
        (bool ok,) = address(tok).call(data);
        assertTrue(ok);
        assertEq(tok.balanceOf(address(0x5409)), 100e6);
        assertEq(tok.balanceOf(address(0xFEE)), 1e5);

        string memory k = "transfer";
        _common(k, domainSep);
        vm.serializeString(k, "from", vm.toString(t.from));
        vm.serializeString(k, "to", vm.toString(t.to));
        vm.serializeString(k, "value", vm.toString(t.value));
        vm.serializeString(k, "entry_ref", vm.toString(t.entryRef));
        vm.serializeString(k, "batch", vm.toString(t.batch));
        vm.serializeString(k, "nonce", vm.toString(t.nonce));
        vm.serializeString(k, "valid_until", vm.toString(t.validUntil));
        vm.serializeString(k, "mode", vm.toString(uint256(t.mode)));
        vm.serializeString(k, "relayer", vm.toString(t.relayer));
        vm.serializeString(k, "fee", vm.toString(t.fee));
        vm.serializeString(k, "fee_recipient", vm.toString(t.feeRecipient));
        vm.serializeString(k, "type_hash", vm.toString(MetaTxLib.METATRANSFER_TYPEHASH));
        vm.serializeString(k, "struct_hash", vm.toString(structHash));
        vm.serializeString(k, "digest", vm.toString(digest));
        vm.serializeString(k, "calldata", vm.toString(data));
        string memory out = vm.serializeString(k, "signature", vm.toString(sig));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT_TRANSFER);
        _check(OUT_TRANSFER, MetaTxLib.METATRANSFER_TYPEHASH, structHash, digest, sig, data);
    }
}
