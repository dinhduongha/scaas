// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {SmartKeyAccount, SubjectKey, KeyKind} from "../../src/account/SmartKeyAccount.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";

/// Shared writer of the account-side `MetaTransaction` KATs (metatx.md §15: the `MandateWallet` and `SmartKeyAccount`
/// vectors are `MetaTransaction` vectors in their own domains), chain 7622 with its real `chain_uid`.
/// `WRITE_KAT=true forge test --match-path test/account/AccountKat.t.sol` rewrites them; clientkeys reads them.
abstract contract MtxKatBase is Test {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;

    function _domainSep(string memory name, address vc) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256("1"), uint256(7622), vc, UID));
    }

    /// Serialises domain, struct, hashes and `sig` under `k`; writes `path` with `WRITE_KAT`, then checks the file.
    function _kat(string memory k, string memory path, string memory name, address vc, MetaTxLib.MetaTransaction memory m,
        bytes32 digest, bytes memory sig) internal returns (string memory out)
    {
        assertEq(digest, keccak256(abi.encodePacked(hex"1901", _domainSep(name, vc), m.hashStruct())), "digest formula");
        vm.serializeString(k, "domain_name", name);
        vm.serializeString(k, "domain_version", "1");
        vm.serializeString(k, "chain_id", "7622");
        vm.serializeString(k, "verifying_contract", vm.toString(vc));
        vm.serializeString(k, "salt", vm.toString(UID));
        vm.serializeString(k, "domain_separator", vm.toString(_domainSep(name, vc)));
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
        vm.serializeString(k, "struct_hash", vm.toString(m.hashStruct()));
        vm.serializeString(k, "digest", vm.toString(digest));
        out = vm.serializeString(k, "signature", vm.toString(sig));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, path);
        string memory onDisk = vm.readFile(path);
        assertEq(vm.parseJsonString(onDisk, ".domain_name"), name);
        assertEq(vm.parseJsonAddress(onDisk, ".verifying_contract"), vc);
        assertEq(vm.parseJsonBytes32(onDisk, ".salt"), UID);
        assertEq(vm.parseJsonBytes(onDisk, ".data"), m.data);
        assertEq(vm.parseJsonUint(onDisk, ".batch"), m.batch);
        assertEq(vm.parseJsonBytes32(onDisk, ".struct_hash"), m.hashStruct());
        assertEq(vm.parseJsonBytes32(onDisk, ".digest"), digest);
        assertEq(vm.parseJsonBytes(onDisk, ".signature"), sig);
    }

    function _ecdsa(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }
}

/// `smart_key_account_kat.json`: the account's own `addKey(SECP256K1(0x77…77))` on lane 0 (what `mtxExecuteAsOwner`
/// builds and clientkeys' `checkOwnerCall` rebuilds), signed by its seed key 0 in the account encoding
/// `abi.encode(0, [], ecdsa)`; it really executes.
contract SmartKeyAccountKatTest is MtxKatBase {
    uint256 internal constant SEED = 0x5EED;

    function test_smartKeyAccountKat() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        SmartKeyAccountFactory fac = new SmartKeyAccountFactory(UID);
        SubjectKey memory first = SubjectKey(KeyKind.SECP256K1, bytes32(uint256(uint160(vm.addr(SEED)))), 0, 0, 0);
        SmartKeyAccount a = SmartKeyAccount(payable(fac.deploy(first, address(0))));
        SubjectKey memory added = SubjectKey(KeyKind.SECP256K1, bytes32(uint256(uint160(address(0x7777777777777777777777777777777777777777)))), 0, 0, 0);
        MetaTxLib.MetaTransaction memory m;
        m.from = address(a);
        m.data = abi.encodeCall(SmartKeyAccount.addKey, (added));
        m.validUntil = 1_800_000_300;
        bytes32 digest = a.mtxDigest(m);
        bytes memory sig = abi.encode(uint256(0), new bytes32[](0), _ecdsa(SEED, digest));
        a.mtxExecuteAsOwner(m.data, 0, m.validUntil, sig);
        assertEq(a.keyCount(), 2);
        vm.serializeString("ska", "signer_key", vm.toString(vm.addr(SEED)));
        _kat("ska", "./test/vectors/smart_key_account_kat.json", "SCaaS SmartKeyAccount", address(a), m, digest, sig);
    }
}

/// `mandate_pay_kat.json` and `mandate_revoke_kat.json`: the delegate's `payUnderMandate(…, epoch 1)` on its derived pay lane and
/// its epoch-bound `revoke(token, 1)` on the derived revoke lane, as `mtxPayUnderMandate` / `mtxRevoke` build them
/// (mode 0, no fee); both really execute.
contract MandateWalletKatTest is MtxKatBase {
    uint256 internal constant OWNER_PK = 0x0A11CE;
    uint256 internal constant DELEGATE_PK = 0xDE1E;
    address internal constant PAYEE = address(0x4EE);

    function test_mandateWalletKat() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        NoUnderlyingToken tok =
            NoUnderlyingToken(Clones.clone(address(new NoUnderlyingToken(address(this), address(0), UID, false))));
        tok.initialize(address(this), 1, noneInit("Points", "PTS", 6, 0, address(this), address(this)));
        MandateWallet w = new MandateWallet(vm.addr(OWNER_PK), UID);
        tok.mint(address(w), 1_000e6);
        vm.startPrank(vm.addr(OWNER_PK));
        w.setMandate(address(tok), vm.addr(DELEGATE_PK), 100e6, 250e6, 1 days, 1_900_000_000);
        w.setPayee(address(tok), PAYEE, true);
        vm.stopPrank();

        bytes32 ref = keccak256("scaas.kat.entryRef");
        MetaTxLib.MetaTransaction memory m;
        m.from = vm.addr(DELEGATE_PK);
        m.data = abi.encodeCall(MandateWallet.payUnderMandate, (address(tok), PAYEE, 12_345_678, ref, uint64(1)));
        m.batch = w.mandatePayLane(ref);
        m.validUntil = 1_800_000_300;
        bytes32 digest = w.mtxDigest(m);
        bytes memory sig = _ecdsa(DELEGATE_PK, digest);
        w.mtxPayUnderMandate(address(tok), PAYEE, 12_345_678, ref, 1, m.validUntil, sig);
        assertEq(tok.balanceOf(PAYEE), 12_345_678);
        _kat("pay", "./test/vectors/mandate_pay_kat.json", "SCaaS MandateWallet", address(w), m, digest, sig);

        m.data = abi.encodeWithSignature("revoke(address,uint64)", address(tok), uint64(1));
        m.batch = w.mandateRevokeLane(address(tok), 1);
        digest = w.mtxDigest(m);
        sig = _ecdsa(DELEGATE_PK, digest);
        w.mtxRevoke(address(tok), 1, m.validUntil, sig);
        assertEq(w.epoch(address(tok)), 2);
        _kat("revoke", "./test/vectors/mandate_revoke_kat.json", "SCaaS MandateWallet", address(w), m, digest, sig);
    }
}
