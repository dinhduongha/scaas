// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";

import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {Test} from "forge-std/Test.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {SmartKeyAccount, SubjectKey, KeyKind} from "../../src/account/SmartKeyAccount.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {uaDigest, UA_PAY_UNDER_MANDATE, UA_DELEGATE_REVOKE} from "../wallet/MandateWalletMerged.t.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// Shared writer of the account-side KATs (metatx.md §15: the `SmartKeyAccount` vector is a `MetaTransaction` vector in
/// its own domain; the `MandateWallet` one, since ua-mtx-merge T3b, its `UA<Op>` structs), chain 7622 with its real
/// `chain_uid`.
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

/// `mandate_kat.json` (ua-mtx-merge T3b, Q6; the address `mandate_pay_kat.json` / `mandate_revoke_kat.json` are in
/// `test/vectors/legacy/ua-mtx-merge/`): the delegate's `mtxPayUnderMandate` (struct `UAPayUnderMandate`) on its pay lane
/// `mandatePayLane(entryRef)` and its `mtxDelegateRevoke` (`UADelegateRevoke`, epoch 1) on `mandateRevokeLane(token, 1)`,
/// nonce 0, mode 0, no fee, the unbound `relayer` / `feeRecipient` 0; an EOA signer (its id zero-padded); both really
/// execute. `WRITE_KAT=true` rewrites it.
contract MandateWalletKatTest is MtxKatBase {
    uint256 internal constant OWNER_PK = 0x0A11CE;
    uint256 internal constant DELEGATE_PK = 0xDE1E;
    address internal constant PAYEE = address(0x4EE);
    string internal constant PATH = "./test/vectors/mandate_kat.json";

    function _entry(string memory k, string memory typeString, MetaTxLib.UAEnvelope memory e, bytes memory args,
        bytes32 digest, bytes memory sig, bytes memory cd) internal returns (string memory)
    {
        bytes32 sh = keccak256(bytes.concat(abi.encode(keccak256(bytes(typeString)), e.from), args,
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        vm.serializeString(k, "type_string", typeString);
        vm.serializeString(k, "type_hash", vm.toString(keccak256(bytes(typeString))));
        vm.serializeString(k, "from", vm.toString(e.from));
        vm.serializeString(k, "args", vm.toString(args));
        vm.serializeString(k, "batch", vm.toString(e.batch));
        vm.serializeString(k, "nonce", vm.toString(e.nonce));
        vm.serializeString(k, "valid_until", vm.toString(e.validUntil));
        vm.serializeString(k, "mode", vm.toString(uint256(e.mode)));
        vm.serializeString(k, "relayer", vm.toString(e.relayer));
        vm.serializeString(k, "fee", vm.toString(e.fee));
        vm.serializeString(k, "fee_recipient", vm.toString(e.feeRecipient));
        vm.serializeString(k, "struct_hash", vm.toString(sh));
        vm.serializeString(k, "digest", vm.toString(digest));
        vm.serializeString(k, "calldata", vm.toString(cd));
        return vm.serializeString(k, "signature", vm.toString(sig));
    }

    NormalToken internal tok;
    MandateWallet internal w;

    function test_mandateWalletKat() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        tok = NormalToken(EnvKit.clone(address(new NormalToken(address(this), kindArgs(0, address(this), ""))), EnvKit.env(UID, address(0), address(0), false)));
        tok.initialize(nid(address(this)), 1, abi.encode(normalInit("Points", "PTS", 6, 0, address(this), address(this))));
        w = new MandateWallet(MetaTxLib.pad(vm.addr(OWNER_PK)), UID, address(0), false);
        tok.mint(address(w), 1_000e6);
        vm.startPrank(vm.addr(OWNER_PK));
        w.setMandate(address(tok), MetaTxLib.pad(vm.addr(DELEGATE_PK)), 100e6, 250e6, 1 days, 1_900_000_000);
        w.setPayee(address(tok), MetaTxLib.pad(PAYEE), true);
        vm.stopPrank();
        (string memory pay, bytes32 payDigest) = _pay();
        assertEq(tok.balanceOf(PAYEE), 12_345_678);
        (string memory rev, bytes32 revDigest) = _revoke();
        assertEq(w.epoch(address(tok)), 2);

        vm.serializeString("kat", "domain_name", "SCaaS MandateWallet");
        vm.serializeString("kat", "domain_version", "1");
        vm.serializeString("kat", "chain_id", "7622");
        vm.serializeString("kat", "verifying_contract", vm.toString(address(w)));
        vm.serializeString("kat", "salt", vm.toString(UID));
        vm.serializeString("kat", "domain_separator", vm.toString(_domainSep("SCaaS MandateWallet", address(w))));
        vm.serializeString("kat", "signer", vm.toString(vm.addr(DELEGATE_PK)));
        vm.serializeString("kat", "pay", pay);
        string memory out = vm.serializeString("kat", "revoke", rev);
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, PATH);
        string memory onDisk = vm.readFile(PATH);
        assertEq(vm.parseJsonAddress(onDisk, ".verifying_contract"), address(w));
        assertEq(vm.parseJsonBytes32(onDisk, ".pay.digest"), payDigest);
        assertEq(vm.parseJsonBytes32(onDisk, ".revoke.digest"), revDigest);
        assertEq(vm.parseJsonBytes(onDisk, ".pay.calldata"), vm.parseJsonBytes(pay, ".calldata"));
        assertEq(vm.parseJsonBytes(onDisk, ".revoke.calldata"), vm.parseJsonBytes(rev, ".calldata"));
        assertEq(vm.parseJsonBytes(onDisk, ".revoke.signature"), vm.parseJsonBytes(rev, ".signature"));
        assertEq(vm.parseJsonUint(onDisk, ".pay.batch"), w.mandatePayLane(PayMetaKit.ref(keccak256("scaas.kat.entryRef"))));
        assertEq(vm.parseJsonBytes32(onDisk, ".pay.meta_salt"), PayMetaKit.meta(keccak256("scaas.kat.entryRef")).salt);
        assertEq(vm.parseJsonUint(onDisk, ".revoke.batch"), w.mandateRevokeLane(address(tok), 1));
    }

    /// The delegate's pay on its pay lane, nonce 0, executed.
    function _pay() internal returns (string memory, bytes32 digest) {
        bytes32 ref = PayMetaKit.ref(keccak256("scaas.kat.entryRef")); // pay-meta-tax T37: a `PayMeta` commitment
        MetaTxLib.UAEnvelope memory e = MetaTxLib.UAEnvelope(MetaTxLib.pad(vm.addr(DELEGATE_PK)), w.mandatePayLane(ref), 0,
            1_800_000_300, 0, address(0), 0, address(0));
        bytes memory args = abi.encode(address(tok), MetaTxLib.pad(PAYEE), uint256(12_345_678), ref, uint64(1));
        digest = uaDigest(address(w), UA_PAY_UNDER_MANDATE, e, args);
        IUARegistry.UASig memory a;
        a.signature = _ecdsa(DELEGATE_PK, digest);
        bytes memory cd = abi.encodeCall(MandateWallet.mtxPayUnderMandate,
            (e, address(tok), MetaTxLib.pad(PAYEE), 12_345_678, ref, 1, a, PayMetaKit.meta(keccak256("scaas.kat.entryRef"))));
        (bool ok, bytes memory ret) = address(w).call(cd);
        assertTrue(ok, string(ret));
        // pay-meta-tax T41: the `PayMeta` the entry takes last (unsigned; `entryRef` its commitment), for the readers
        MetaTxLib.PayMeta memory m = PayMetaKit.meta(keccak256("scaas.kat.entryRef"));
        vm.serializeBytes32("pay", "meta_salt", m.salt);
        vm.serializeBytes32("pay", "meta_pay_no", m.payNo); // plan T83: a `bytes32`, `save` committed
        vm.serializeBool("pay", "meta_save", m.save);
        vm.serializeUint("pay", "meta_schema", m.schema);
        vm.serializeBytes("pay", "meta_body", m.body);
        return (_entry("pay", UA_PAY_UNDER_MANDATE, e, args, digest, a.signature, cd), digest);
    }

    /// The delegate's epoch-1 revoke on its revoke lane, nonce 0, executed.
    function _revoke() internal returns (string memory, bytes32 digest) {
        MetaTxLib.UAEnvelope memory e = MetaTxLib.UAEnvelope(MetaTxLib.pad(vm.addr(DELEGATE_PK)),
            w.mandateRevokeLane(address(tok), 1), 0, 1_800_000_300, 0, address(0), 0, address(0));
        bytes memory args = abi.encode(address(tok), uint64(1));
        digest = uaDigest(address(w), UA_DELEGATE_REVOKE, e, args);
        IUARegistry.UASig memory a;
        a.signature = _ecdsa(DELEGATE_PK, digest);
        bytes memory cd = abi.encodeCall(MandateWallet.mtxDelegateRevoke, (e, address(tok), 1, a));
        (bool ok, bytes memory ret) = address(w).call(cd);
        assertTrue(ok, string(ret));
        return (_entry("revoke", UA_DELEGATE_REVOKE, e, args, digest, a.signature, cd), digest);
    }
}
