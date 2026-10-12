// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";

/// The Hedera vector (NET-HED-03, CTR-TOK-23): a payment `MetaTransfer` of the Hedera account 0.0.1234567 (long-zero
/// `from`) on an `IS_HEDERA` `NoUnderlyingToken` clone on chain 296, in the salted token domain. Forge writes every
/// struct field, the struct hash and the digest (`WRITE_KAT=true forge test --match-contract HederaKatTest`); it
/// writes no calldata and executes nothing. Then `python3 test/hedera/gen_hedera_kat.py` adds the RFC 8032 ed25519
/// signature over the digest (the bytes HIP-632's `isAuthorizedRaw` checks); scaas-node (`adapters::hedera` tests)
/// verifies both. The v1 vector is in `legacy/p5/`.
contract HederaKatTest is Test {
    using MetaTxLib for MetaTxLib.MetaTransfer;

    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    address internal constant NATIVE = address(uint160(1_234_567)); // 0.0.1234567
    string internal constant OUT = "./test/vectors/hedera_kat.json";

    function test_hederaKat() public {
        vm.chainId(296);
        NoUnderlyingToken tok =
            NoUnderlyingToken(Clones.clone(address(new NoUnderlyingToken(address(this), address(0), UID, address(0), true))));
        tok.initialize(address(this), 1, noneInit("HBUSD", "HBUSD", 6, 0, address(this), address(0)));
        bytes32 ref = bytes32(uint256(0x42));
        MetaTxLib.MetaTransfer memory t = MetaTxLib.MetaTransfer({
            from: NATIVE, to: address(0x5409), value: 250_000_000, entryRef: ref, batch: tok.payLane(ref), nonce: 0,
            validUntil: 1_800_000_300, mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: address(0xBEEF), fee: 0,
            feeRecipient: address(0)
        });
        bytes32 digest = tok.mtxTransferDigest(t);
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
        vm.serializeString(k, "struct_hash", vm.toString(t.hashStruct()));
        string memory out = vm.serializeString(k, "digest", vm.toString(digest));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, OUT);

        string memory onDisk = vm.readFile(OUT);
        string[] memory keys = vm.parseJsonKeys(out, "$");
        assertEq(keys.length, 17);
        for (uint256 i; i < keys.length; ++i) {
            assertEq(vm.parseJsonString(onDisk, string.concat(".", keys[i])),
                vm.parseJsonString(out, string.concat(".", keys[i])), keys[i]);
        }
        if (!vm.envOr("WRITE_KAT", false)) assertEq(vm.parseJsonBytes(onDisk, ".ed25519_signature").length, 64);
    }
}
