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
import { p256 } from '@noble/curves/nist.js';
import {
  entropyToWords, wordsToEntropy, seedFromWords, seedFromEntropy, slip10Ed25519, deriveKey, signDigest, signTyped, signKeyProof,
  strkey, normalizeMnemonic, generateEntropy, slip10,
} from '../src/seed.js';
import { bytesToHex, concatBytes, fromHex, keccak_256 } from '../src/bytes.js';
import { hashTypedData, keyProofMessage, uaMetaTransferTypedData, padId } from '../src/evm.js';

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

// ua-rs-sign T1a: the UA tree's P-256 keys (kind 0x0101). Source: satoshilabs/slips a00312491693714d9bc1b6e4cb5b2e356e6c511e
// slip-0010.md (sha256 dbd5a324f2a6014bf78fc8cfa85833e4a16256a02283b93d648fccba18ed1ce7): "Test vector 1", "Test derivation
// retry" and "Test seed retry" for nist256p1 (the UA tree takes hardened steps only; the retry vector's retry is a non-hardened step).
test('SLIP-10 nist256p1: test vector 1, derivation retry, seed retry (published, slip-0010.md)', () => {
  const v1 = fromHex('000102030405060708090a0b0c0d0e0f');
  const cases = [
    [v1, 'm', '612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2',
      'beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea', '0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8'],
    [v1, "m/0'", '6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c',
      '3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11', '0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c'],
    [v1, "m/0'/1", '284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129',
      '4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c', '03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844'],
    [v1, "m/0'/1/2'/2/1000000000", '21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119',
      'b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059', '02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4'],
    [v1, "m/28578'", '06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669',
      'e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2', '02519b5554a4872e8c9c1c847115363051ec43e93400e030ba3c36b52a3e70a5b7'],
    [v1, "m/28578'/33941", '092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a', // the child retry (IL ≥ n)
      '9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071', '0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120'],
    [fromHex('a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446'), 'm',
      '3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f',
      '7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c', '0383619fadcde31063d8c5cb00dbfe1713f3e6fa169d8541a798752a1c1ca0cb20'],
  ];
  for (const [seed, path, priv, chain, pub] of cases) {
    const k = slip10('nist256p1', seed, path);
    assert.equal(bytesToHex(k.privateKey), priv, path);
    assert.equal(bytesToHex(k.chainCode), chain, path);
    assert.equal(bytesToHex(p256.getPublicKey(k.privateKey, true)), pub, path);
  }
  for (const bad of ['m/x', "m/2147483648'", 'm/2147483648', "m/0''"]) assert.throws(() => slip10('nist256p1', v1, bad), /bad path/, bad);
  assert.equal(bytesToHex(slip10('ed25519', v1, "m/0'").privateKey), bytesToHex(slip10Ed25519(v1, "m/0'").privateKey));
});

test('native index and coin type in [0, 2^31); solana m/44\'/501\'/i\'/0\' base58 address', () => {
  const seed = seedFromWords('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
  // the widely published address of this phrase at m/44'/501'/0'/0' (solana-keygen `prompt://?key=0/0`); not re-run here
  assert.equal(deriveKey(seed, 'solana', 0).address, 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk');
  deriveKey(seed, 'evm', 2 ** 31 - 1); // positive control
  for (const bad of [2 ** 31, -1, 1.5]) for (const net of ['evm', 'solana']) assert.throws(() => deriveKey(seed, net, bad), /index/);
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

test('Pi Network: Stellar keys at the chain\'s SLIP-44 coin type 314159', () => {
  // bip_utils 2.9.3 Bip32Slip10Ed25519 at m/44'/314159'/{0,1}' of the SEP-0005 test 1 words.
  const seed = seedFromWords('illness spike retreat truth genius clock brain pass fit cave bargain toe');
  const pi = deriveKey(seed, 'stellar', 0, { coinType: 314159 });
  assert.equal(pi.path, "m/44'/314159'/0'");
  assert.equal(pi.address, 'GASWRHYE32A5A27TQWNRITIOZKOX7XQ6IVI4WEDGPVGX253D63UW2GJ3');
  assert.equal(deriveKey(seed, 'stellar', 1, { coinType: 314159 }).address, 'GBSIS3JSLARC3D5WXRE3343Y2IMQBKRXHPC672RELHWXVUW4QWCWM2UT');
  assert.equal(deriveKey(seed, 'stellar', 0).address, 'GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6');
  assert.equal(deriveKey(seed, 'stellar', 0, { coinType: null }).path, "m/44'/148'/0'");
  for (const bad of [-1, 2 ** 31, 1.5, '314159']) assert.throws(() => deriveKey(seed, 'stellar', 0, { coinType: bad }), /coin type/);
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
    // @aptos-labs/ts-sdk 7.3.0 Account.fromDerivationPath(m/44'/637'/i'/0'/0').accountAddress
    aptos: ['0xb0405f24b79f5422d7ba552d1805822b77ced7de61d99bb2e98bdc2894c91b23',
      '0xb722a3cf97b920c693a227d2e3d40c893f7a432776c8a68ba74685b5010df291'],
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
  const sig = signDigest(evm, digest, { allowRawDigest: true });
  assert.equal(sig.length, 65);
  assert.ok(sig[64] === 27 || sig[64] === 28);
  const rec = secp256k1.Signature.fromBytes(sig.subarray(0, 64), 'compact').addRecoveryBit(sig[64] - 27)
    .recoverPublicKey(digest).toBytes(false);
  assert.equal(bytesToHex(keccak_256(rec.subarray(1)).subarray(12)), evm.address.slice(2).toLowerCase());
  const stellar = deriveKey(seed, 'stellar', 0);
  assert.ok(ed25519.verify(signDigest(stellar, digest, { allowRawDigest: true }), digest, fromHex(stellar.publicKey)));
});

// Owner rule 2026-10-30: never sign an EIP-7702 authorization. A raw digest needs the explicit opt-in; typed data and
// the key proof are hashed here, so their preimage is never `0x05 ‖ rlp(…)`.
test('signing: a raw digest is refused without the opt-in; signTyped / signKeyProof hash it themselves', () => {
  const evm = deriveKey(seedFromWords(M), 'evm', 0);
  // keccak256(0x05 ‖ rlp([chainId 0, address, nonce 0])): what a sweeper would ask a wallet to sign
  const auth = keccak_256(concatBytes(new Uint8Array([0x05]), fromHex('d78094' + '00'.repeat(18) + 'dead80')));
  assert.throws(() => signDigest(evm, auth), /raw digest refused/);
  assert.throws(() => signDigest(evm, auth, { allowRawDigest: 1 }), /raw digest refused/, 'only literal true');
  const td = uaMetaTransferTypedData({ contract: '0x' + '11'.repeat(20), chainId: 7622, chainUid: '0x' + '22'.repeat(32),
    message: { from: padId(evm.address), to: padId('0x' + '33'.repeat(20)), value: '1', validUntil: '9' } });
  assert.deepEqual(signTyped(evm, td), signDigest(evm, hashTypedData(td), { allowRawDigest: true }));
  const ch = new Uint8Array(32).fill(7);
  assert.deepEqual(signKeyProof(evm, ch), signDigest(evm, keyProofMessage(ch), { allowRawDigest: true }));
});
