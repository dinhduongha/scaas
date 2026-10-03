// Seed wallet: published vectors (BIP-39 Trezor, BIP-32 #1, SLIP-10 ed25519 #1, SEP-0005) and
// per-network vectors generated with installed reference tooling. Exact commands (2026-10-03):
//
//   M="bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author \
//      capable act festival slice deposit sauce coconut afford frown better"      # SEP-0005 test 3
//   EVM:     cast wallet address --mnemonic "$M" --mnemonic-index 0|1                  (foundry 1.3.5)
//   Hedera ECDSA: cast wallet address --mnemonic "$M" --mnemonic-derivation-path "m/44'/3030'/0'/0/0"
//            + @hashgraph/sdk 2.81.0: (await Mnemonic.fromString(M)).toStandardECDSAsecp256k1PrivateKey('', i)
//              / toStandardEd25519PrivateKey('', i) → publicKey.toStringRaw(), toStringDer(), toEvmAddress()
//   Stellar: stellar keys address t3 --hd-path 0|1   (stellar 22.2, identity file seed_phrase = "$M")
//   Sui:     SUI_CONFIG_DIR=<tmp> sui keytool --json import --alias t0 "$M" ed25519 "m/44'/784'/0'/0'/0'"
//            (sui 1.81.0; and m/44'/784'/1'/0'/0')
//   Cosmos:  @cosmjs/proto-signing 0.36.2: DirectSecp256k1HdWallet.fromMnemonic(M,
//              { hdPaths: [makeCosmoshubPath(i)], prefix: 'cosmos' }).getAccounts()
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  entropyToWords, wordsToEntropy, seedFromWords, seedFromEntropy, slip10Ed25519, deriveKey, signDigest,
  strkey, normalizeMnemonic, generateEntropy,
} from '../src/seed.js';
import { bytesToHex, fromHex, keccak_256 } from '../src/bytes.js';

const trezor = JSON.parse(readFileSync(new URL('./vectors/bip39-trezor.json', import.meta.url)));
const M = 'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author '
  + 'capable act festival slice deposit sauce coconut afford frown better';

test('BIP-39 Trezor vectors (passphrase TREZOR): words, checksum import, seed, BIP-32 root', () => {
  assert.equal(trezor.english.length, 24);
  for (const [entropy, mnemonic, seed, xprv] of trezor.english) {
    assert.equal(entropyToWords(fromHex(entropy)).join(' '), mnemonic);
    assert.equal(bytesToHex(wordsToEntropy(mnemonic)), entropy);
    const s = seedFromWords(mnemonic, 'TREZOR');
    assert.equal(bytesToHex(s), seed);
    assert.equal(HDKey.fromMasterSeed(s).privateExtendedKey, xprv);
  }
});

test('BIP-39 import refuses a bad checksum and tolerates spacing/case', () => {
  const [, mnemonic] = trezor.english.at(-1);
  const words = mnemonic.split(' ');
  words[23] = words[23] === 'zoo' ? 'abandon' : 'zoo';
  assert.throws(() => wordsToEntropy(words.join(' ')), /checksum/);
  assert.equal(normalizeMnemonic(`  ${mnemonic.toUpperCase().replace(/ /g, '   ')} `), mnemonic);
  assert.equal(bytesToHex(wordsToEntropy(mnemonic.toUpperCase())), trezor.english.at(-1)[0]);
});

test('generated phrases are 24 words', () => {
  assert.equal(entropyToWords(generateEntropy()).length, 24);
});

test('BIP-32 test vector 1 (published, bip-0032.mediawiki)', () => {
  const root = HDKey.fromMasterSeed(fromHex('000102030405060708090a0b0c0d0e0f'));
  assert.equal(root.derive("m/0'/1/2'/2/1000000000").privateExtendedKey,
    'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76');
  assert.equal(root.derive("m/0'/1").publicExtendedKey,
    'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ');
});

test('SLIP-10 ed25519 test vector 1 (published, slip-0010.md)', () => {
  const seed = fromHex('000102030405060708090a0b0c0d0e0f');
  const cases = [
    ['m', '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7',
      '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb',
      'a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed'],
    ["m/0'", '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3',
      '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69',
      '8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c'],
    ["m/0'/1'/2'/2'/1000000000'", '8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793',
      '68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230',
      '3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a'],
  ];
  for (const [path, priv, chain, pub] of cases) {
    const k = slip10Ed25519(seed, path);
    assert.equal(bytesToHex(k.privateKey), priv, path);
    assert.equal(bytesToHex(k.chainCode), chain, path);
    assert.equal(bytesToHex(ed25519.getPublicKey(k.privateKey)), pub, path);
  }
  assert.throws(() => slip10Ed25519(seed, 'm/0'), /hardened-only/);
});

test('SEP-0005 (published): seed, m/44\'/148\' key, Stellar G/S keys', () => {
  const t3seed = '937ae91f6ab6f12461d9936dfc1375ea5312d097f3f1eb6fed6a82fbe38c85824da8704389831482db0433e5f6c6c9700ff1946aa75ad8cc2654d6e40f567866';
  assert.equal(bytesToHex(seedFromWords(M)), t3seed);
  assert.equal(bytesToHex(slip10Ed25519(fromHex(t3seed), "m/44'/148'").privateKey),
    'df474e0dc2711089b89af6b089aceeb77e73120e9f895bd330a36fa952835ea8');
  const k9 = deriveKey(fromHex(t3seed), 'stellar', 9);
  assert.equal(k9.address, 'GDXOY6HXPIDT2QD352CH7VWX257PHVFR72COWQ74QE3TEV4PK2KCKZX7');
  assert.equal(strkey(18 << 3, k9.privateKey), 'SCPA5OX4EYINOPAUEQCPY6TJMYICUS5M7TVXYKWXR3G5ZRAJXY3C37GF');
  // Test 4: 24 words + BIP-39 passphrase.
  const t4 = seedFromWords('cable spray genius state float twenty onion head street palace net private method loan '
    + 'turn phrase state blanket interest dry amazing dress blast tube', 'p4ssphr4se');
  assert.equal(bytesToHex(t4), 'd425d39998fb42ce4cf31425f0eaec2f0a68f47655ea030d6d26e70200d8ff8bd4326b4bdf562ea8640a1501ae93ccd0fd7992116da5dfa24900e570a742a489');
  assert.equal(deriveKey(t4, 'stellar', 0).address, 'GDAHPZ2NSYIIHZXM56Y36SBVTV5QKFIZGYMMBHOU53ETUSWTP62B63EQ');
});

test('per-network keys match reference tooling', () => {
  const seed = seedFromEntropy(wordsToEntropy(M));
  const want = {
    evm: ['0x1C6C7EF166c962c2ed755daf726A42cfE4fc77dB', '0x2ee927314c25475f5FD81DCD446d59Dfa4B7b0D1'],
    cosmos: ['cosmos1tydzmvyad5zh2egqk585d8q4sskk5nk33wsper', 'cosmos174zrqgvrhq6rtvusxv0gm5ceuufjndfjahacgv'],
    hedera_ecdsa: ['0xF37DE893579fFd1457C0f209A238fe2fbF974B75', '0xc8198bf044ade05DFb017794f7DF3533534b9b4C'],
    stellar: ['GC3MMSXBWHL6CPOAVERSJITX7BH76YU252WGLUOM5CJX3E7UCYZBTPJQ', 'GB3MTYFXPBZBUINVG72XR7AQ6P2I32CYSXWNRKJ2PV5H5C7EAM5YYISO'],
    sui: ['0x23ac6c2e0ce236e26a61cee3cf292ea07fac33d4bfff81cefe101bfb7fda35fd',
      '0x40dde4d7c594bc0293ca6d0023edbcd7791026da1ead0f97f4b882229fb02679'],
  };
  for (const [net, addrs] of Object.entries(want)) {
    addrs.forEach((a, i) => assert.equal(deriveKey(seed, net, i).address.toLowerCase(), a.toLowerCase(), `${net} ${i}`));
  }
  assert.equal(deriveKey(seed, 'cosmos', 0).publicKey, '027914d47e57835eb5772b2834ce3d90313167456489112f7d07e46488fd9b0a71');
  assert.equal(deriveKey(seed, 'hedera_ecdsa', 1).publicKeyDer,
    '302d300706052b8104000a0322000377c9fcee6d178d8f11f2f46b09e11ff7c87284f2a7e49636d6b240212e56f3f7');
  assert.equal(deriveKey(seed, 'hedera_ed25519', 0).publicKeyDer,
    '302a300506032b6570032100ecbc1c11f7a1a30902f6cf0f9c4785a40c22cfebb443372f4661b144ca437073');
  assert.equal(deriveKey(seed, 'hedera_ed25519', 1).publicKey, 'f34d1d672e4adf81459e4bb4777366f96fdf46fe3bce67519e9fbd9d1af5f5f2');
  // Sui public key (base64 of flag 0x00 ‖ pk) as sui keytool printed it.
  assert.equal(Buffer.from(deriveKey(seed, 'sui', 0).publicKey, 'hex').toString('base64'), 'mUCKSLylZOnKr6aeAI1OgA/+HvDmWtgVg0Ho/AA0p2M=');
  // TON: public key only (m/44'/607'/0'); W5R1 address not shipped.
  assert.equal(deriveKey(seed, 'ton', 0).publicKey.length, 64);
});

test('signing: secp256k1 r‖s‖v recovers the EVM address; ed25519 verifies', () => {
  const seed = seedFromWords(M);
  const digest = keccak_256(new TextEncoder().encode('operation'));
  const evm = deriveKey(seed, 'evm', 0);
  const sig = signDigest(evm, digest);
  assert.equal(sig.length, 65);
  assert.ok(sig[64] === 27 || sig[64] === 28);
  const rec = secp256k1.Signature.fromBytes(sig.subarray(0, 64), 'compact').addRecoveryBit(sig[64] - 27)
    .recoverPublicKey(digest).toBytes(false);
  assert.equal(bytesToHex(keccak_256(rec.subarray(1)).subarray(12)), evm.address.slice(2).toLowerCase());
  const stellar = deriveKey(seed, 'stellar', 0);
  assert.ok(ed25519.verify(signDigest(stellar, digest), digest, fromHex(stellar.publicKey)));
});
