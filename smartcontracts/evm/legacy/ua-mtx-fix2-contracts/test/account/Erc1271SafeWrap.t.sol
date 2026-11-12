// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// Backup, not built (B P3-2, commit be8d0772): the tests of the Safe-style ERC-1271 wrap, superseded by ERC-7739 (owner
// 2026-11-12). From test/account/AccountKat.t.sol (`Erc1271KatTest`, writing legacy/ua-mtx-fix2-contracts/test/vectors/
// erc1271_kat.json, then test/vectors/erc1271_kat.json) and test/account/SmartKeyAccount.t.sol (two tests of
// `SmartKeyAccountTest`), as they stood.

/// `erc1271_kat.json` (B P3-2, CTR-ACC-02): ERC-1271 over `hash` wrapped as `ERC1271Message(bytes32 hash)` in the wallet's
/// own domain, for a `SmartKeyAccount` (seed key 0, the account encoding) and a `MandateWallet` (its native owner's
/// ECDSA); each answers the magic value, never over the raw `hash`. `WRITE_KAT=true` rewrites it; clientkeys'
/// `erc1271Digest` reads it.
contract Erc1271KatTest is MtxKatBase {
    uint256 internal constant SEED = 0x5EED;
    uint256 internal constant OWNER_PK = 0x0A11CE;
    bytes32 internal constant HASH = keccak256("scaas.kat.erc1271");
    string internal constant PATH = "./test/vectors/erc1271_kat.json";

    function _row(string memory k, string memory name, address vc, bytes32 digest, address signer, bytes memory sig)
        internal returns (string memory)
    {
        assertEq(digest, keccak256(abi.encodePacked(hex"1901", _domainSep(name, vc),
            keccak256(abi.encode(keccak256("ERC1271Message(bytes32 hash)"), HASH)))), "digest formula");
        assertEq(SmartKeyAccount(payable(vc)).isValidSignature(HASH, sig), bytes4(0x1626ba7e), k);
        vm.serializeString(k, "domain_name", name);
        vm.serializeString(k, "verifying_contract", vm.toString(vc));
        vm.serializeString(k, "domain_separator", vm.toString(_domainSep(name, vc)));
        vm.serializeString(k, "digest", vm.toString(digest));
        vm.serializeString(k, "signer_key", vm.toString(signer));
        return vm.serializeString(k, "signature", vm.toString(sig));
    }

    function test_erc1271Kat() public {
        vm.chainId(7622);
        SmartKeyAccountFactory fac = new SmartKeyAccountFactory(UID);
        SmartKeyAccount a = SmartKeyAccount(payable(fac.deploy(
            SubjectKey(KeyKind.SECP256K1, bytes32(uint256(uint160(vm.addr(SEED)))), 0, 0, 0), address(0))));
        bytes32 da = a.erc1271Digest(HASH);
        bytes memory sa = abi.encode(uint256(0), new bytes32[](0), _ecdsa(SEED, da));
        MandateWallet w = new MandateWallet(MetaTxLib.pad(vm.addr(OWNER_PK)), UID, address(0), false);
        bytes32 dw = w.erc1271Digest(HASH);
        bytes memory sw = _ecdsa(OWNER_PK, dw);
        vm.serializeString("kat", "chain_id", "7622");
        vm.serializeString("kat", "domain_version", "1");
        vm.serializeString("kat", "salt", vm.toString(UID));
        vm.serializeString("kat", "type_string", "ERC1271Message(bytes32 hash)");
        vm.serializeString("kat", "type_hash", vm.toString(MetaTxLib.ERC1271_MESSAGE_TYPEHASH));
        vm.serializeString("kat", "hash", vm.toString(HASH));
        vm.serializeString("kat", "smart_key_account", _row("ska", "SCaaS SmartKeyAccount", address(a), da, vm.addr(SEED), sa));
        string memory out =
            vm.serializeString("kat", "mandate_wallet", _row("mw", "SCaaS MandateWallet", address(w), dw, vm.addr(OWNER_PK), sw));
        if (vm.envOr("WRITE_KAT", false)) vm.writeJson(out, PATH);
        string memory onDisk = vm.readFile(PATH);
        assertEq(vm.parseJsonBytes32(onDisk, ".type_hash"), MetaTxLib.ERC1271_MESSAGE_TYPEHASH);
        assertEq(vm.parseJsonBytes32(onDisk, ".hash"), HASH);
        assertEq(vm.parseJsonAddress(onDisk, ".smart_key_account.verifying_contract"), address(a));
        assertEq(vm.parseJsonBytes32(onDisk, ".smart_key_account.digest"), da);
        assertEq(vm.parseJsonBytes(onDisk, ".smart_key_account.signature"), sa);
        assertEq(vm.parseJsonAddress(onDisk, ".mandate_wallet.verifying_contract"), address(w));
        assertEq(vm.parseJsonBytes32(onDisk, ".mandate_wallet.digest"), dw);
        assertEq(vm.parseJsonBytes(onDisk, ".mandate_wallet.signature"), sw);
    }
}


// ---- from SmartKeyAccountTest (test/account/SmartKeyAccount.t.sol)
/*
    /// CTR-ACC-02 (B P3-2): ERC-1271 answers over `hash` wrapped as `ERC1271Message(bytes32 hash)` in the account's own
    /// domain, never the raw hash: a key shared by two accounts answers for the one it signed for, on one chain; the raw
    /// verifier is the account's own self-call only.
    function test_erc1271IsBoundToTheAccount() public {
        assertEq(MetaTxLib.ERC1271_MESSAGE_TYPEHASH, keccak256("ERC1271Message(bytes32 hash)"));
        bytes32 ds = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS SmartKeyAccount"), keccak256("1"), uint256(7622), address(acct), UID_));
        bytes32 w = keccak256(abi.encodePacked(hex"1901", ds, keccak256(abi.encode(MetaTxLib.ERC1271_MESSAGE_TYPEHASH, D))));
        assertEq(acct.erc1271Digest(D), w);
        SmartKeyAccount b = SmartKeyAccount(payable(fac.deploy(_passkey(PASSKEY), address(0))));
        bytes memory sig = _pk(0, PASSKEY, w);
        assertEq(acct.isValidSignature(D, sig), MAGIC, "positive control: the wrapped message");
        assertEq(b.isValidSignature(D, sig), bytes4(0xffffffff), "same key, other account");
        assertEq(acct.isValidSignature(D, _pk(0, PASSKEY, D)), bytes4(0xffffffff), "the raw hash");
        assertEq(b.isValidSignature(D, _pk(0, PASSKEY, b.erc1271Digest(D))), MAGIC, "positive control: b's own");
        bytes memory raw = _pk(0, PASSKEY, D);
        vm.prank(address(acct));
        assertTrue(acct.isValidOwnDigest(D, raw), "positive control: the account's own self-call");
        vm.expectRevert(SmartKeyAccount.NotSelf.selector);
        acct.isValidOwnDigest(D, raw);
        vm.chainId(7623);
        assertEq(acct.isValidSignature(D, sig), bytes4(0xffffffff), "other chain");
    }

    /// CTR-ACC-02: the ERC-1271 message struct, verbatim (`cast keccak "ERC1271Message(bytes32 hash)"`).
    function test_erc1271MessageTypehashIsPinned() public pure {
        assertEq(MetaTxLib.ERC1271_MESSAGE_TYPEHASH, 0xff8bbe299de1266e571c68af5b71b4e716412184ca1bd495927110f9581950cb);
    }


*/
