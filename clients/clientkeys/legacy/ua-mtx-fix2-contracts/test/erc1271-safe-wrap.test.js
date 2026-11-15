// Backup, not run (B P3-2, commit be8d0772): the test of the Safe-style wrap, read against
// smartcontracts/evm/legacy/ua-mtx-fix2-contracts/test/vectors/erc1271_kat.json; superseded by ERC-7739 (owner 2026-11-12).
// As it stood in test/evm.test.js (that file's imports and `read`).

// B P3-2 (CTR-ACC-02): a key signs `erc1271Digest`, the hash wrapped in the wallet's own domain, never the raw hash.
test('erc1271Digest = forge KAT (AccountKat.t.sol, erc1271_kat.json): SmartKeyAccount and MandateWallet', () => {
  const k = read('erc1271_kat.json');
  assert.equal(hex(keccak_256(utf8ToBytes(k.type_string))), k.type_hash);
  for (const [wallet, row, inner] of [['SmartKeyAccount', k.smart_key_account, (s) => s.subarray(160, 225)],
    ['MandateWallet', k.mandate_wallet, (s) => s]]) {
    const args = { wallet, address: row.verifying_contract, chainId: Number(k.chain_id), chainUid: k.salt, hash: k.hash };
    const d = erc1271Digest(args);
    assert.equal(hex(d), row.digest, wallet);
    assert.equal(erc1271TypedData(args).domain.name, row.domain_name);
    assert.notEqual(hex(erc1271Digest({ ...args, address: '0x' + '11'.repeat(20) })), row.digest, 'bound to the wallet');
    assert.notEqual(hex(erc1271Digest({ ...args, chainId: 7623 })), row.digest, 'bound to the chain');
    const sig = inner(fromHex(row.signature));
    const r = secp256k1.Signature.fromBytes(sig.subarray(0, 64), 'compact').addRecoveryBit(sig[64] - 27);
    assert.equal(evmAddress(r.recoverPublicKey(d).toBytes(false)), row.signer_key, wallet);
  }
  assert.equal(hex(accountSignature(0, [], fromHex(k.smart_key_account.signature).subarray(160, 225))), k.smart_key_account.signature);
  assert.throws(() => erc1271Digest({ wallet: 'NormalToken', address: k.smart_key_account.verifying_contract, chainId: 7622,
    chainUid: k.salt, hash: k.hash }), /no ERC-1271 wrap/);
});
