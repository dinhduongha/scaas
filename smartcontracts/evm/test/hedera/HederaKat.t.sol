// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MtxHash} from "../helpers/MtxHash.sol";
import {kindArgs} from "../../script/KindModules.sol";

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {MockHederaAccountService} from "./HederaMocks.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// The Hedera vector (NET-HED-03, CTR-TOK-23; ua-mtx-merge T8, R42): `MetaOp` v1 is the token's `UAMetaTransfer`, here a
/// payment of the Hedera ED25519 account 0.0.1234567, its `from` the account's long-zero EVM address zero-padded to
/// `bytes32`, on an `IS_HEDERA` `NormalToken` clone on chain 296, in the salted token domain; `relayer` bound, the
/// `feeRecipient` unbound but non-zero (hashed as 0, spec §6). Forge writes every struct field, the type hash, the
/// struct hash and the digest (`WRITE_KAT=true forge test --match-contract HederaKatTest`); then
/// `python3 test/hedera/gen_hedera_kat.py` adds the RFC 8032 ed25519 signature over the digest (the bytes HIP-632's
/// `isAuthorizedRaw` checks); scaas-node (`adapters::hedera` tests) verifies both. The address `MetaTransfer` vector this
/// replaced is in `test/vectors/legacy/ua-mtx-merge/`; the v1 vector in `legacy/p5/`.
contract HederaKatTest is Test {
    using MetaTxLib for MetaTxLib.UAMetaTransfer;
    using MtxHash for MetaTxLib.UAMetaTransfer;

    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    address internal constant NATIVE = address(uint160(1_234_567)); // 0.0.1234567, long-zero
    address internal constant HAS = address(0x16a);
    uint256 internal constant ED_KEY = 0xA11CE5; // the mock's secp256k1 stand-in for the account's ED25519 key
    address internal constant RELAYER = address(0xBEEF);
    string internal constant OUT = "./test/vectors/hedera_kat.json";
    NormalToken internal tok;

    function setUp() public {
        vm.chainId(296);
        tok = NormalToken(EnvKit.clone(address(new NormalToken(address(this), kindArgs(0, address(this), ""))), EnvKit.env(UID, address(0), address(0), true)));
        tok.initialize(nid(address(this)), 1, abi.encode(normalInit("HBUSD", "HBUSD", 6, 0, address(this), address(this))));
    }

    function _transfer() internal view returns (MetaTxLib.UAMetaTransfer memory) {
        bytes32 ref = bytes32(uint256(0x42));
        return MetaTxLib.UAMetaTransfer({
            from: MetaTxLib.pad(NATIVE), to: MetaTxLib.pad(address(0x5409)), value: 250_000_000, entryRef: ref,
            batch: tok.payLane(ref), nonce: 0, validUntil: 1_800_000_300, mode: MetaTxLib.MODE_RESTRICT_RELAYER,
            relayer: RELAYER, fee: 0, feeRecipient: address(0xFEE)
        });
    }

    function test_hederaKat() public {
        MetaTxLib.UAMetaTransfer memory t = _transfer();
        bytes32 digest = MtxDigest.typed(address(tok), t.hashStruct());
        assertEq(digest, tok.mtxTransferDigest(t));
        string memory k = "hedera";
        vm.serializeString(k, "chain_id", "296");
        vm.serializeString(k, "hedera_account", "0.0.1234567");
        vm.serializeString(k, "verifying_contract", vm.toString(address(tok)));
        vm.serializeString(k, "salt", vm.toString(UID));
        vm.serializeString(k, "from", vm.toString(t.from));
        vm.serializeString(k, "to", vm.toString(t.to));
        vm.serializeString(k, "value", vm.toString(t.value));
        vm.serializeString(k, "entry_ref", vm.toString(t.entryRef));
        vm.serializeString(k, "batch", vm.toString(t.batch));
        vm.serializeString(k, "nonce", "0");
        vm.serializeString(k, "valid_until", vm.toString(t.validUntil));
        vm.serializeString(k, "mode", vm.toString(uint256(t.mode)));
        vm.serializeString(k, "relayer", vm.toString(t.relayer));
        vm.serializeString(k, "fee", vm.toString(t.fee));
        vm.serializeString(k, "fee_recipient", vm.toString(t.feeRecipient));
        vm.serializeString(k, "type_hash", vm.toString(MetaTxLib.UAMETATRANSFER_TYPEHASH));
        vm.serializeString(k, "struct_hash", vm.toString(t.hashStruct()));
        string memory out = vm.serializeString(k, "digest", vm.toString(digest));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT);

        string memory onDisk = vm.readFile(OUT);
        string[] memory keys = vm.parseJsonKeys(out, "$");
        assertEq(keys.length, 18);
        for (uint256 i; i < keys.length; ++i) {
            assertEq(vm.parseJsonString(onDisk, string.concat(".", keys[i])),
                vm.parseJsonString(out, string.concat(".", keys[i])), keys[i]);
        }
        if (!vm.envOr("WRITE_KAT", false)) assertEq(vm.parseJsonBytes(onDisk, ".ed25519_signature").length, 64);
    }

    /// R42: the vector on disk is a `UAMetaTransfer` (its type hash, its struct hash rebuilt from its own fields), its
    /// `from` the long-zero address of 0.0.1234567 zero-padded, its digest the one the token's merged
    /// `mtxExecuteTransfer` checks; a 64-byte signature over that digest (the mock's stand-in for the account's ed25519
    /// key) runs the transfer through HIP-632 with no registry.
    function test_hederaKatIsUAMetaTransfer() public {
        string memory j = vm.readFile(OUT);
        assertEq(vm.parseJsonBytes32(j, ".type_hash"), MetaTxLib.UAMETATRANSFER_TYPEHASH, "type hash");
        bytes32 from = vm.parseJsonBytes32(j, ".from");
        assertEq(from, bytes32(uint256(1_234_567)), "from: the long-zero address of 0.0.1234567, zero-padded");
        MetaTxLib.UAMetaTransfer memory t = MetaTxLib.UAMetaTransfer({
            from: from, to: vm.parseJsonBytes32(j, ".to"), value: vm.parseJsonUint(j, ".value"),
            entryRef: vm.parseJsonBytes32(j, ".entry_ref"), batch: vm.parseJsonUint(j, ".batch"),
            nonce: vm.parseJsonUint(j, ".nonce"), validUntil: vm.parseJsonUint(j, ".valid_until"),
            mode: uint32(vm.parseJsonUint(j, ".mode")), relayer: vm.parseJsonAddress(j, ".relayer"),
            fee: vm.parseJsonUint(j, ".fee"), feeRecipient: vm.parseJsonAddress(j, ".fee_recipient")
        });
        assertTrue(t.feeRecipient != address(0) && t.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT == 0,
            "a non-zero unbound fee recipient (spec 6)");
        assertEq(vm.parseJsonBytes32(j, ".struct_hash"), t.hashStruct(), "struct hash");
        assertEq(vm.parseJsonAddress(j, ".verifying_contract"), address(tok));
        bytes32 digest = vm.parseJsonBytes32(j, ".digest");
        assertEq(digest, tok.mtxTransferDigest(t), "digest: the merged entry's");

        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        MockHederaAccountService(HAS).setEdKey(NATIVE, vm.addr(ED_KEY));
        tok.mint(NATIVE, t.value);
        (bytes32 r, bytes32 vs) = vm.signCompact(ED_KEY, digest);
        IUARegistry.UASig memory a;
        a.signature = abi.encodePacked(r, vs);
        vm.warp(t.validUntil - 1);
        vm.expectCall(HAS, abi.encodeWithSelector(bytes4(0xb2a31da4), NATIVE, abi.encodePacked(digest), a.signature));
        vm.prank(t.relayer);
        IERC20MetaTx(address(tok)).mtxExecuteTransfer(t, a);
        assertEq(tok.balanceOf(address(0x5409)), t.value);
    }
}
