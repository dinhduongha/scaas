// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-rs-native (spec 2026-11-17-ua-rs-native): the four native networks of an app's native backend (CLI-SGN-52), beside the nine
// of NETWORKS. Known answers are the published ones re-read at plan T0 (clients/ua-rs/runs/2026-11-17-ua-rs-native-t0.md):
// BIP-84 / BIP-86 (`abandon ×11 about`), BIP-143 native P2WPKH, BIP-341 wallet-test-vectors.json (scriptPubKey[0] and
// keyPathSpending input 0, the rows with a null scriptTree / merkleRoot), bitcoin/bips c1a652c7.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { schnorr } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { base58 } from '@scure/base';
import * as S from '../src/seed.js';
import * as signer from '../src/seed-signer.js';
import * as U from '../src/uakey.js';
import { fromHex, hex } from '../src/bytes.js';

const B = (h) => fromHex(h.startsWith('0x') ? h : '0x' + h);
const H = (b) => hex(b).slice(2);
const codeOf = (f) => { try { f(); return null; } catch (e) { return e.code ?? `plain: ${e.message}`; } };
const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const seed = S.seedFromWords(ABANDON);
const NINE = ['evm', 'cosmos', 'hedera_ecdsa', 'hedera_ed25519', 'sui', 'stellar', 'ton', 'aptos', 'solana'];
const FOUR = ['bitcoin_p2wpkh', 'bitcoin_p2tr', 'near', 'polkadot'];

test('NETWORKS stays the nine; NATIVE_NETWORKS is the four, exported by seed-signer too', () => {
  assert.deepEqual(Object.keys(S.NETWORKS), NINE);
  assert.deepEqual(Object.keys(S.NATIVE_NETWORKS), FOUR);
  assert.equal(signer.NATIVE_NETWORKS, S.NATIVE_NETWORKS);
});

test('BIP-84 receive and change addresses of abandon ×11 about', () => {
  const k = (i, change) => S.deriveKey(seed, 'bitcoin_p2wpkh', i, { change });
  assert.equal(k(0).path, "m/84'/0'/0'/0/0");
  assert.equal(k(0).publicKey, '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c');
  assert.equal(k(0).address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
  assert.equal(k(1).address, 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g');
  assert.equal(k(0, 1).path, "m/84'/0'/0'/1/0");
  assert.equal(k(0, 1).address, 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el');
  assert.deepEqual(k(0).witnessProgram, { version: 0, program: 'c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2' });
  assert.notEqual(k(1, 1).address, k(0, 1).address);
  assert.equal(k(0, 0).address, k(0).address);
});

test('BIP-86 receive and change addresses, internal key, tweak and output key', () => {
  const k = (i, change) => S.deriveKey(seed, 'bitcoin_p2tr', i, { change });
  const r0 = k(0);
  assert.equal(r0.path, "m/86'/0'/0'/0/0");
  assert.equal(r0.internalKey, 'cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115');
  assert.equal(r0.outputKey, 'a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c');
  assert.equal(r0.address, 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr');
  assert.deepEqual(r0.witnessProgram, { version: 1, program: r0.outputKey });
  assert.equal(r0.publicKey.slice(2), r0.internalKey, 'publicKey is the compressed internal key P');
  assert.equal(k(1).address, 'bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh');
  const c0 = k(0, 1);
  assert.equal(c0.path, "m/86'/0'/0'/1/0");
  assert.equal(c0.internalKey, '399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef');
  assert.equal(c0.outputKey, '882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc');
  assert.equal(c0.address, 'bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7');
  assert.notEqual(k(1, 1).address, c0.address);
});

test('BIP-341 scriptPubKey[0] (null scriptTree): taprootTweak gives tweak, output key and address', () => {
  const t = S.taprootTweak(B('d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d'));
  assert.equal(H(t.tweak), 'b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70');
  assert.equal(H(t.outputKey), '53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343');
  assert.equal(S.segwitAddress('bc', 1, t.outputKey), 'bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5');
});

test('Bitcoin coin type: 1 gives tb1…, 0 is the default, 2 refused; change 2 refused; change off Bitcoin refused', () => {
  const t = S.deriveKey(seed, 'bitcoin_p2wpkh', 0, { coinType: 1 });
  assert.equal(t.path, "m/84'/1'/0'/0/0");
  assert.match(t.address, /^tb1q/);
  assert.match(S.deriveKey(seed, 'bitcoin_p2tr', 0, { coinType: 1 }).address, /^tb1p/);
  assert.equal(S.deriveKey(seed, 'bitcoin_p2wpkh', 0, { coinType: 0 }).address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
  assert.equal(codeOf(() => S.deriveKey(seed, 'bitcoin_p2wpkh', 0, { coinType: 2 })), 'Argument');
  assert.equal(codeOf(() => S.deriveKey(seed, 'bitcoin_p2tr', 0, { coinType: 2 })), 'Argument');
  assert.equal(codeOf(() => S.deriveKey(seed, 'bitcoin_p2wpkh', 0, { change: 2 })), 'Argument');
  assert.equal(codeOf(() => S.deriveKey(seed, 'bitcoin_p2wpkh', 0, { change: 1 })), null);
  assert.equal(codeOf(() => S.deriveKey(seed, 'evm', 0, { change: 1 })), 'Argument');
  assert.equal(codeOf(() => S.deriveKey(seed, 'near', 0, { change: 0 })), 'Argument');
  assert.equal(codeOf(() => S.deriveKey(seed, 'evm', 0)), null);
});

test('NEAR: m/44\'/397\'/i\', implicit account id, ed25519:base58 text; no coin-type override', () => {
  const k = S.deriveKey(seed, 'near', 0);
  assert.equal(k.path, "m/44'/397'/0'");
  assert.equal(S.deriveKey(seed, 'near', 3).path, "m/44'/397'/3'");
  assert.equal(k.address, k.publicKey);
  assert.match(k.address, /^[0-9a-f]{64}$/);
  assert.equal(k.publicKeyText, 'ed25519:' + base58.encode(B(k.publicKey)));
  assert.equal(H(ed25519.getPublicKey(k.privateKey)), k.publicKey);
  for (const c of [148, 397, 0]) assert.equal(codeOf(() => S.deriveKey(seed, 'near', 0, { coinType: c })), 'Argument', `coin ${c}`);
  assert.equal(codeOf(() => S.deriveKey(seed, 'stellar', 0, { coinType: 397 })), null, 'stellar keeps its override');
});

test('polkadot is not derived by deriveKey (it needs the entropy and the passphrase)', () => {
  assert.throws(() => S.deriveKey(seed, 'polkadot', 0), (e) => e.code === 'Argument' && /polkadotKey/.test(e.message));
});

test('BIP-143 native P2WPKH: signDigest is RFC 6979 with no extra data, r ‖ s ‖ v', () => {
  const key = { network: 'bitcoin_p2wpkh', curve: 'secp256k1', privateKey: B('619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9') };
  const sig = S.signDigest(key, B('c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670'), { allowRawDigest: true });
  assert.equal(H(sig.subarray(0, 32)), '3609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a');
  assert.equal(H(sig.subarray(32, 64)), '573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee');
  assert.ok(sig[64] === 27 || sig[64] === 28);
});

test('BIP-341 keyPathSpending input 0: signDigest on a P2TR key (negate, tweak, BIP-340, aux zero) and verify under x(Q)', () => {
  const key = { network: 'bitcoin_p2tr', curve: 'secp256k1', privateKey: B('6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa') };
  const d = B('2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555');
  const sig = S.signDigest(key, d, { allowRawDigest: true, aux: new Uint8Array(32) });
  assert.equal(H(sig), 'ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c');
  assert.ok(schnorr.verify(sig, d, B('53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343')));
  // without aux: fresh randomness, still a valid signature under x(Q)
  const a = S.signDigest(key, d, { allowRawDigest: true }), b = S.signDigest(key, d, { allowRawDigest: true });
  assert.notEqual(H(a), H(b));
  assert.ok(schnorr.verify(a, d, B('53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343')));
});

test('P2TR keys of the mnemonic sign under their own output key, both y parities of P', () => {
  // receive 0 has an odd-y internal key, receive 1 an even one (T0)
  for (const i of [0, 1]) {
    const k = S.deriveKey(seed, 'bitcoin_p2tr', i);
    const d = new Uint8Array(32).fill(7 + i);
    assert.ok(schnorr.verify(S.signDigest(k, d, { allowRawDigest: true }), d, B(k.outputKey)), `index ${i}`);
  }
});

test('Bitcoin and NEAR keys: no key proof, no EIP-712, no EVM transaction (Argument); evm and solana keep theirs', () => {
  const tx = { type: 2, chainId: 1, nonce: 0, maxPriorityFeePerGas: 1, maxFeePerGas: 2, gasLimit: 21000, to: '0x' + '11'.repeat(20), value: 0, data: '0x', accessList: [] };
  const td = { types: { EIP712Domain: [{ name: 'name', type: 'string' }], M: [{ name: 'x', type: 'uint256' }] }, primaryType: 'M', domain: { name: 'n' }, message: { x: 1 } };
  for (const n of ['bitcoin_p2wpkh', 'bitcoin_p2tr', 'near']) {
    const k = S.deriveKey(seed, n, 0);
    assert.equal(codeOf(() => S.signKeyProof(k, new Uint8Array(32))), 'Argument', `${n} key proof`);
    assert.equal(codeOf(() => S.signTyped(k, td)), 'Argument', `${n} typed`);
    assert.equal(codeOf(() => S.signTransaction(k, tx)), 'Argument', `${n} transaction`);
  }
  const evm = S.deriveKey(seed, 'evm', 0);
  assert.equal(S.signTyped(evm, td).length, 65);
  assert.equal(S.signKeyProof(evm, new Uint8Array(32)).length, 65);
  assert.ok(S.signTransaction(evm, tx).raw);
  assert.equal(S.signKeyProof(S.deriveKey(seed, 'solana', 0), new Uint8Array(32)).length, 64);
});

test('no import and no imported UA of the four networks (Argument); evm accepted', () => {
  const secret = new Uint8Array(32).fill(1);
  for (const n of FOUR) {
    assert.equal(codeOf(() => S.importKey(n, secret)), 'Argument', `importKey ${n}`);
    for (const kind of [0x0108, 0x0102]) assert.equal(codeOf(() => U.importedUAKey({ network: n, secret, kind })), 'Argument', `importedUAKey ${n} ${kind}`);
  }
  assert.equal(S.importKey('evm', secret).network, 'evm');
  assert.ok(U.importedUAKey({ network: 'evm', secret, kind: 0x0108 }).ua);
});

// ------------------------------------------------------------------ T3: Polkadot sr25519, signMessage, raw-signing guards
// Known answers: substrate-bip39's VECTORS (password "Substrate"), the subkey answers of spec §7.3, the junction-length rows of
// plan T0 (schnorrkel, @scure/sr25519 and polkadot.js agree), the polkadot.js //Alice signature of T0.
const DEV = 'bottom drive obey lake curtain smoke basket hold race lonely fit walk';
const PQ_KAT = 'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better';
const devE = S.wordsToEntropy(DEV);
const dot = (path, opts) => P.polkadotKey(devE, '', path, opts);
const X = (n) => 'x'.repeat(n);
const DEV_KEYS = {
  '': '46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a',
  '//Alice': 'd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d',
  '//Bob': '8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48',
  '//0': '2afba9278e30ccf6a6ceb3a8b6e336b70068f045c666f2e7f4f9cc5f47db8972',
  '/0': 'b696d3a7fbc9dd6648e18fd56169b90f3be49714133eaa464cbfd6ca79ab1310',
  '//1/2': '509efd067a5a345cea7185745c2996a36733711651f6cc41087c0bcc66a68a1d',
  '/soft//hard': 'b692f2e809e8805a1814fab0baea78841806544446ebb8280b4e593962706f4a',
  '//18446744073709551615': 'a4ca284d5222ef916e2e181430785972ed22cb51ef91a0c6cdbbd390ee74bc77',
  '//polkadot': 'f606519cb8726753885cd4d0f518804a69a5e0badf36fee70feadd8044081730',
  ['//' + X(31)]: 'd08d581c9755746d091ef753234388455eb5f847ae6061ceae8c77b38fcb030f',
  ['/' + X(31)]: '2a72e28d57ef0263eccad32fef0b2c6c9c37358821e4be63773df52f52edd87c',
  ['//' + X(32)]: '9644ab5b228ce544dfff7f8f021e06120d26f2c0a856096cbbce37abc1541a5c',
  ['/' + X(32)]: 'f24dd03839f881a9ba7e18bfc99b57f590c3b397a631534bc6c5702d14963a1e',
  ['//' + X(63)]: '76dab0a15bee6bc691c04d2b7ee92b7e89596040e6565d75a17ec1da6c0eab1c',
  ['/' + X(63)]: '5a8a9a1cd97dff92b58c8c59655e3b112f6cf315e82e9e776b2f95f276c10870',
  ['//' + X(64)]: '4e7a9573fa04dafa01aa9d0eeda5dd5f6685879a2bfd024a75c17c231b488556',
  ['/' + X(64)]: '827385d21b2e6b7db061391eb9839b0eb5e9f8c9b012d64e7d02d10b6abc4f65',
};
let P;
test('substrate.js loads', async () => { P = await import('../src/substrate.js'); });

test('substrate-bip39 VECTORS: the mini-secret is the first half of PBKDF2(entropy, "mnemonic" ‖ "Substrate")', () => {
  const rows = [ // a slice of substrate-bip39 src/lib.rs VECTORS (ceb4fe5a), entropy → seed[0..32]
    ['00000000000000000000000000000000', '44e9d125f037ac1d51f0a7d3649689d422c2af8b1ec8e00d71db4d7bf6d127e3'],
    ['7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f', '4313249608fe8ac10fd5886c92c4579007272cb77c21551ee5b8d60b78041685'],
    ['80808080808080808080808080808080', '27f3eb595928c60d5bc91a4d747da40ed236328183046892ed6cd5aa9ae38122'],
  ];
  for (const [e, mini] of rows) assert.equal(H(P.miniSecretFromEntropy(B(e), 'Substrate')), mini, e);
});

test('the subkey answers and the junction rows of T0 (hard and soft, 31 / 32 / 63 / 64-byte junctions)', () => {
  for (const [path, pk] of Object.entries(DEV_KEYS)) assert.equal(dot(path).publicKey, pk, `'${path}'`);
  assert.equal(dot('').address, '12bzRJfh7arnnfPPUZHeJUaE62QLEwhK48QnH9LXeK2m1iZU');
  assert.equal(P.ss58(B(DEV_KEYS['//Alice']), 42), '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY');
  assert.equal(P.ss58(B(DEV_KEYS['//Bob']), 42), '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty');
});

test('the passphrase as given: NFC and NFD give one BIP-39 seed and two Polkadot keys; the mini-secret is not the seed', () => {
  const e = S.wordsToEntropy(PQ_KAT);
  const nfc = 'Ünïcödé パスワード'.normalize('NFC'), nfd = nfc.normalize('NFD');
  assert.notEqual(nfc, nfd);
  assert.equal(H(S.seedFromEntropy(e, nfc)), H(S.seedFromEntropy(e, nfd)));
  assert.notEqual(P.polkadotKey(e, nfc, '').publicKey, P.polkadotKey(e, nfd, '').publicKey);
  assert.notEqual(H(P.miniSecretFromEntropy(e, '')), H(S.seedFromEntropy(e, '').subarray(0, 32)));
});

test('path refusals, each beside its accepted neighbour (Argument)', () => {
  const pairs = [
    ['///pw', '//pw'], ['//', '//a'], ['/0x12', '/x12'], ['//+1', '//1'],
    ['//18446744073709551616', '//18446744073709551615'], ['//007', '//7'], ['//00', '//0'],
    [Array(17).fill('//a').join(''), Array(16).fill('//a').join('')],
    [Array(15).fill('//' + X(30)).join('') + '//' + X(31), Array(16).fill('//' + X(30)).join('')],
    ['//' + X(65), '//' + X(64)], ['//a b', '//ab'], ['//é', '//e'], ['Alice', '//Alice'],
  ];
  for (const [bad, good] of pairs) {
    assert.equal(codeOf(() => P.polkadotKey(devE, '', bad)), 'Argument', `refused ${bad.slice(0, 40)}`);
    assert.equal(codeOf(() => P.polkadotKey(devE, '', good)), null, `accepted ${good.slice(0, 40)}`);
  }
  assert.equal(new TextEncoder().encode(Array(16).fill('//' + X(30)).join('')).length, 512);
});

test('SS58 prefixes: 0, 2, 42, 64 (two-byte form), 16383; 46, 47, 16384 refused', () => {
  const pk = B(DEV_KEYS['']);
  const want = { 0: '12bzRJfh7arnnfPPUZHeJUaE62QLEwhK48QnH9LXeK2m1iZU', 2: 'EBJwHkVtAcF6nCKHd3h4H75NzgvMJxMS1X3WWd8a2DjaQx9',
    42: '5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV', 64: 'cEXBCBPEn84gHSpZtrHx5fmAvFR4UGKD2DL5kFGUnGLj2ksXy',
    16383: 'yNWw4BEqdLrtrV4Gja14vK2s7JN7Td9tKvJvzcTXENhkJiVUD' };
  for (const [p, a] of Object.entries(want)) assert.equal(P.ss58(pk, Number(p)), a, `prefix ${p}`);
  for (const p of [46, 47, 16384, -1]) assert.equal(codeOf(() => P.ss58(pk, p)), 'Argument', `prefix ${p}`);
});

test('Polkadot: no index, no coin type through deriveKey; no key proof, EIP-712 or EVM transaction (Argument)', () => {
  for (const [i, coinType] of [[0, null], [1, null], [0, 0], [0, 354]]) assert.equal(codeOf(() => S.deriveKey(seed, 'polkadot', i, { coinType })), 'Argument');
  const k = dot('//Alice');
  assert.equal(codeOf(() => S.signKeyProof(k, new Uint8Array(32))), 'Argument');
  assert.equal(codeOf(() => S.signTyped(k, {})), 'Argument');
  assert.equal(codeOf(() => S.signTransaction(k, {})), 'Argument');
});

test('signMessage on the ed25519 networks (1 B to 131,072 B): RFC 8032, deterministic', () => {
  for (const n of ['hedera_ed25519', 'sui', 'stellar', 'ton', 'aptos', 'solana', 'near']) {
    const k = S.deriveKey(seed, n, 0);
    for (const len of [1, 32, 1232, 131072]) {
      const m = Uint8Array.from({ length: len }, (_, i) => (i * 13 + len) & 255);
      const sig = S.signMessage(k, m, { allowRawDigest: true });
      assert.ok(ed25519.verify(sig, m, B(k.publicKey)), `${n} ${len}`);
      assert.equal(H(sig), H(ed25519.sign(m, k.privateKey)));
    }
  }
});

test('signMessage and signDigest on Polkadot keys verify under @scure/sr25519; fixed randomness is test-only; T0 polkadot.js signature verifies', async () => {
  const sr = await import('@scure/sr25519');
  for (const path of ['', '//Alice', '/soft']) {
    const k = dot(path);
    for (const len of [1, 32, 257]) {
      const m = new Uint8Array(len).fill(len & 255);
      const a = S.signMessage(k, m, { allowRawDigest: true }), b = S.signMessage(k, m, { allowRawDigest: true });
      assert.ok(sr.verify(m, a, B(k.publicKey)) && sr.verify(m, b, B(k.publicKey)), `'${path}' ${len}`);
      assert.notEqual(H(a), H(b), 'release signatures are fresh');
    }
    const d = new Uint8Array(32).fill(9);
    assert.ok(sr.verify(d, S.signDigest(k, d, { allowRawDigest: true }), B(k.publicKey)));
  }
  const r = new Uint8Array(32).fill(5), m = new Uint8Array([1, 2, 3]);
  assert.equal(H(S.signMessage(dot('//Alice'), m, { allowRawDigest: true, aux: r })), H(S.signMessage(dot('//Alice'), m, { allowRawDigest: true, aux: r })));
  assert.ok(sr.verify(B('73636161732075612d72732d6e61746976652054303a20706f6c6b61646f742e6a73202f2f416c696365207369676e6174757265'),
    B('24a27936a2b09621ea541fa427b3ea60c52199cf7e3f8966c4ffbc6620833b69f57592f47c8bd86b4076f74aef554817a434c65c16a34d5eba30030728a31f8c'),
    B(DEV_KEYS['//Alice'])));
});

test('signMessage refusals (Argument), each beside the call accepted', () => {
  const k = S.deriveKey(seed, 'solana', 0), m = new Uint8Array([1]);
  assert.equal(codeOf(() => S.signMessage(k, m)), 'Argument', 'no opt-in');
  assert.equal(codeOf(() => S.signMessage(k, m, { allowRawDigest: true })), null);
  assert.equal(codeOf(() => S.signMessage(k, new Uint8Array(0), { allowRawDigest: true })), 'Argument', '0 bytes');
  assert.equal(codeOf(() => S.signMessage(k, new Uint8Array(131073), { allowRawDigest: true })), 'Argument', '131,073 bytes');
  assert.equal(codeOf(() => S.signMessage(k, new Uint8Array(131072), { allowRawDigest: true })), null, '131,072 bytes');
  const solana = Uint8Array.of(0xff, ...new TextEncoder().encode('solana offchain'), 1, 2);
  const aptos = new TextEncoder().encode('APTOS\nmessage: x');
  for (const [env, rest] of [[solana, solana.subarray(1)], [aptos, aptos.subarray(1)]]) {
    for (const key of [k, dot('')]) {
      assert.equal(codeOf(() => S.signMessage(key, env, { allowRawDigest: true })), 'Argument', 'envelope');
      assert.equal(codeOf(() => S.signMessage(key, rest, { allowRawDigest: true })), null, 'without the prefix');
    }
  }
  for (const n of ['evm', 'cosmos', 'bitcoin_p2wpkh', 'bitcoin_p2tr']) {
    assert.equal(codeOf(() => S.signMessage(S.deriveKey(seed, n, 0), m, { allowRawDigest: true })), 'Argument', n);
  }
  assert.equal(signer.signMessage, S.signMessage);
  assert.equal(signer.MAX_RAW_MESSAGE, 131072);
});

// ------------------------------------------------------------------ T4: native.json (written by scripts/native-vectors.mjs)
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { UAError } from '../src/ua.js';
const NATIVE = new URL('../../../smartcontracts/vectors/native/native.json', import.meta.url);
const readNative = () => JSON.parse(readFileSync(NATIVE, 'utf8'));
const nat = (() => { try { return readNative(); } catch { return null; } })();
const mn = (id) => { const m = nat.mnemonics.find((x) => x.id === id); return { ...m, e: B(m.entropy), seed: S.seedFromEntropy(B(m.entropy), m.passphrase) }; };
const msgOf = (r) => (r.messageRepeat ? new Uint8Array(r.messageRepeat.length).fill(parseInt(r.messageRepeat.byte, 16)) : B(r.message));
function call(c, a) {
  const m = a.mnemonic && mn(a.mnemonic);
  const nativeKey = () => {
    if (a.network !== 'polkadot') return S.deriveKey(m.seed, a.network, a.index, { coinType: a.coinType });
    if (a.index !== 0 || a.coinType != null) throw new UAError('Argument', 'polkadot: index 0 and no coin type');
    return P.polkadotKey(m.e, m.passphrase, '');
  };
  const key = () => (a.network === 'polkadot' && a.path !== undefined ? P.polkadotKey(m.e, m.passphrase, a.path) : nativeKey());
  switch (c) {
    case 'polkadot_key': return P.polkadotKey(m.e, m.passphrase, a.path);
    case 'ss58': return P.ss58(B(P.polkadotKey(m.e, m.passphrase, '').publicKey), a.prefix);
    case 'native_key': return nativeKey();
    case 'bitcoin_key': return S.deriveKey(m.seed, a.network, a.index, { coinType: a.coinType, change: a.change });
    case 'sign_message': return S.signMessage(key(), msgOf(a), { allowRawDigest: true });
    case 'sign_digest': return S.signDigest(key(), msgOf(a), { allowRawDigest: true });
    case 'sign_key_proof': return S.signKeyProof(key(), B(a.challenge));
    case 'sign_typed': return S.signTyped(key(), a.typedData);
    case 'import_native_key': return S.importKey(a.network, B(a.secret));
    case 'imported_ua_key': return U.importedUAKey({ network: a.network, secret: B(a.secret), kind: a.kind });
    case 'sign_near_transaction': return S.signNearTransaction(key(), msgOf(a), { allowRawDigest: true });
    case 'sign_sui_transaction': return S.signSuiTransaction(key(), msgOf(a), { allowRawDigest: true });
    case 'sign_stellar_transaction': return S.signStellarTransaction(key(), B(a.networkId), msgOf(a), { allowRawDigest: true });
    case 'sign_hedera_transaction': return S.signHederaTransaction(key(), msgOf(a), { allowRawDigest: true });
    default: throw new Error(`unknown call ${c}`);
  }
}

test('native.json is tracked (not git-ignored) and lists the thirteen networks in ua-rs\'s order', () => {
  assert.ok(nat, 'smartcontracts/vectors/native/native.json');
  assert.deepEqual(nat.networks, [...NINE, ...FOUR]);
});

test('native.json addresses: every row re-derived (Bitcoin both chains and coins, NEAR, the bare Polkadot key)', () => {
  assert.ok(nat.addresses.length > 0);
  for (const r of nat.addresses) {
    const m = mn(r.mnemonic);
    const k = r.network === 'polkadot' ? P.polkadotKey(m.e, m.passphrase, '') : S.deriveKey(m.seed, r.network, r.index, { coinType: r.coinType, change: r.change });
    const id = `${r.mnemonic} ${r.network} ${r.coinType}/${r.change}/${r.index}`;
    assert.equal(k.path, r.path, id); assert.equal(k.publicKey, r.publicKey, id); assert.equal(k.address, r.address, id);
    assert.deepEqual(k.witnessProgram ?? null, r.witnessProgram, id);
    if (r.network === 'bitcoin_p2tr') { assert.equal(k.internalKey, r.internalKey); assert.equal(k.tweak, r.tweak); assert.equal(k.outputKey, r.outputKey); }
    if (r.network === 'near') assert.equal(k.publicKeyText, r.publicKeyText);
    if (r.network === 'polkadot') {
      assert.equal(H(P.miniSecretFromEntropy(m.e, m.passphrase)), r.miniSecret, id);
      for (const [p, a] of Object.entries(r.ss58)) assert.equal(P.ss58(B(k.publicKey), Number(p)), a, `${id} ss58 ${p}`);
    }
  }
});

test('native.json polkadotPaths: chain codes and keys of every path', () => {
  for (const r of nat.polkadotPaths) {
    const m = mn(r.mnemonic);
    assert.deepEqual(P.parsePolkadotPath(r.path).map((j) => ({ hard: j.hard, chainCode: H(j.chainCode) })), r.junctions, r.path);
    const k = P.polkadotKey(m.e, m.passphrase, r.path);
    assert.equal(k.publicKey, r.publicKey, `${r.mnemonic} '${r.path}'`); assert.equal(k.address, r.address);
  }
});

test('native.json signatures: deterministic and fixed-randomness rows byte-equal, verify-only rows verify', async () => {
  const sr = await import('@scure/sr25519');
  for (const r of nat.signatures) {
    const m = mn(r.mnemonic), msg = msgOf(r);
    const k = r.network === 'polkadot' ? P.polkadotKey(m.e, m.passphrase, r.path) : S.deriveKey(m.seed, r.network, r.index, { coinType: r.coinType, change: r.change });
    if (r.mode !== 'verify-only') {
      const opts = { allowRawDigest: true, ...(r.mode === 'fixed-randomness' ? { aux: B(r.aux) } : {}) };
      assert.equal(H(r.call === 'sign_digest' ? S.signDigest(k, msg, opts) : S.signMessage(k, msg, opts)), r.signature, r.id);
    }
    const sig = B(r.signature), pk = B(r.publicKey);
    const ok = r.scheme === 'secp256k1-ecdsa' ? secp256k1.verify(sig.subarray(0, 64), msg, pk, { prehash: false, format: 'compact' })
      : r.scheme === 'bip340-taproot' ? schnorr.verify(sig, msg, pk) : r.scheme === 'ed25519' ? ed25519.verify(sig, msg, pk) : sr.verify(msg, sig, pk);
    assert.ok(ok, `${r.id} verifies`);
    assert.equal(r.network === 'bitcoin_p2tr' ? k.outputKey : k.publicKey, r.publicKey, `${r.id} key`);
  }
});

test('native.json refusals: each refused (Argument), its accepted neighbour accepted', () => {
  assert.ok(nat.refusals.length > 0);
  for (const r of nat.refusals) {
    assert.equal(codeOf(() => call(r.call, r.args)), r.error, r.id);
    assert.equal(codeOf(() => call(r.call, r.accepted)), null, `neighbour of ${r.id}`);
  }
});

test('native.json external: BIP-84 / BIP-86 / BIP-143 / BIP-340 / BIP-341 / BIP-350 / substrate-bip39 / subkey / polkadot.js rows', async () => {
  const x = nat.external, ab = mn('bip39_abandon'), dev = mn('substrate_dev');
  for (const r of x.bip84.rows) assert.equal(S.deriveKey(ab.seed, 'bitcoin_p2wpkh', r.index, { change: r.change }).address, r.address);
  for (const r of x.bip86.rows) assert.equal(S.deriveKey(ab.seed, 'bitcoin_p2tr', r.index, { change: r.change }).outputKey, r.outputKey);
  const b143 = S.signDigest({ network: 'bitcoin_p2wpkh', curve: 'secp256k1', privateKey: B(x.bip143.privateKey) }, B(x.bip143.sigHash), { allowRawDigest: true });
  assert.equal(H(b143.subarray(0, 64)), x.bip143.signature);
  for (const r of x.bip340.rows.filter((y) => y.secretKey)) assert.equal(H(schnorr.sign(B(r.message), B(r.secretKey), B(r.aux))).toUpperCase(), r.signature);
  for (const r of x.bip341.scriptPubKey) assert.equal(H(S.taprootTweak(B(r.internalPubkey)).outputKey), r.tweakedPubkey);
  for (const r of x.bip341.keyPathSpending) {
    assert.equal(H(S.signDigest({ network: 'bitcoin_p2tr', curve: 'secp256k1', privateKey: B(r.internalPrivkey) }, B(r.sigHash), { allowRawDigest: true, aux: B(r.aux) })), r.signature);
  }
  for (const r of x.bip350.rows) assert.equal(S.segwitAddress(r.hrp, r.version, B(r.program)), r.address);
  for (const r of x.substrateBip39.rows) assert.equal(H(P.miniSecretFromEntropy(B(r.entropy), x.substrateBip39.passphrase)), r.miniSecret);
  for (const r of x.subkey.rows) assert.equal(P.polkadotKey(dev.e, '', r.path).publicKey, r.publicKey);
  const sr = await import('@scure/sr25519'), j = x.polkadotJsSignature;
  assert.ok(sr.verify(B(j.message), B(j.signature), B(j.publicKey)));
  assert.ok(!sr.verify(new Uint8Array([...B(j.message), 0]), B(j.signature), B(j.publicKey)), 'one byte appended: refused');
});

// ------------------------------------------------------------------ T6a: spec §8.1 (after the scaas-sdk review)
import { blake2b } from '@noble/hashes/blake2.js';
import { sha256 } from '@noble/hashes/sha2.js';

test('signMessage has no first-byte rule: 0x05 and 0x19 0x01 sign on Ed25519 and sr25519 keys (T13 C1)', async () => {
  const sr = await import('@scure/sr25519');
  for (const k of [S.deriveKey(seed, 'solana', 0), dot('')]) {
    for (const m of [[0x05, 1, 2], [0x05], [0x05, 0x00, 0x00], [0x19, 0x01, 7], [0x19, 0x01]]) {
      const msg = Uint8Array.from(m), sig = S.signMessage(k, msg, { allowRawDigest: true });
      assert.ok(k.curve === 'ed25519' ? ed25519.verify(sig, msg, B(k.publicKey)) : sr.verify(msg, sig, B(k.publicKey)), `${k.network} ${m}`);
    }
  }
  const evm = S.deriveKey(seed, 'evm', 0);
  assert.equal(S.signDigest(evm, new Uint8Array(32).fill(5), { allowRawDigest: true }).length, 65);
});

const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const ENV = {
  near: { f: (k, tx) => S.signNearTransaction(k, tx, { allowRawDigest: true }), hash: (tx) => sha256(tx) },
  sui: { f: (k, tx) => S.signSuiTransaction(k, tx, { allowRawDigest: true }), hash: (tx) => blake2b(cat(new Uint8Array(3), tx), { dkLen: 32 }) },
  stellar: { f: (k, tx) => S.signStellarTransaction(k, new Uint8Array(32).fill(0xce), tx, { allowRawDigest: true }),
    hash: (tx) => sha256(cat(new Uint8Array(32).fill(0xce), Uint8Array.of(0, 0, 0, 2), tx)) },
  hedera_ed25519: { f: (k, tx) => S.signHederaTransaction(k, tx, { allowRawDigest: true }), hash: (tx) => tx },
};

test('envelope calls: NEAR sha256, Sui intent + blake2b-256, Stellar network id + ENVELOPE_TYPE_TX, Hedera body bytes', () => {
  for (const [network, e] of Object.entries(ENV)) {
    const k = S.deriveKey(seed, network, 0);
    for (const tx of [Uint8Array.of(0x05), new Uint8Array(200).fill(3), new Uint8Array(131072).fill(9)]) {
      const sig = e.f(k, tx);
      assert.ok(ed25519.verify(sig, e.hash(tx), B(k.publicKey)), `${network} ${tx.length}`);
      assert.equal(H(sig), H(ed25519.sign(e.hash(tx), k.privateKey)), 'deterministic');
    }
    assert.equal(codeOf(() => e.f(k, new Uint8Array(0))), 'Argument', `${network} 0 bytes`);
    assert.equal(codeOf(() => e.f(k, new Uint8Array(131073))), 'Argument', `${network} 131,073 bytes`);
    for (const other of ['solana', 'aptos', 'ton', ...Object.keys(ENV).filter((n) => n !== network)]) {
      assert.equal(codeOf(() => e.f(S.deriveKey(seed, other, 0), Uint8Array.of(1))), 'Argument', `${network} call on ${other}`);
    }
  }
  const k = S.deriveKey(seed, 'near', 0);
  assert.equal(codeOf(() => S.signNearTransaction(k, Uint8Array.of(1))), 'Argument', 'no opt-in');
  assert.equal(codeOf(() => S.signStellarTransaction(S.deriveKey(seed, 'stellar', 0), new Uint8Array(31), Uint8Array.of(1), { allowRawDigest: true })), 'Argument', 'network id 32 bytes');
  for (const n of ['signNearTransaction', 'signSuiTransaction', 'signStellarTransaction', 'signHederaTransaction']) assert.equal(signer[n], S[n], n);
});

test('native.json envelopes rows byte-equal; the appended refusal rows of spec §8.1 are present', () => {
  assert.ok(Array.isArray(nat.envelopes) && nat.envelopes.length > 0, 'envelopes');
  const calls = { sign_near_transaction: 'near', sign_sui_transaction: 'sui', sign_stellar_transaction: 'stellar', sign_hedera_transaction: 'hedera_ed25519' };
  for (const r of nat.envelopes) {
    const m = mn(r.mnemonic), k = S.deriveKey(m.seed, r.network, r.index);
    assert.equal(calls[r.call], r.network, r.id);
    const tx = msgOf(r), opts = { allowRawDigest: true };
    const sig = r.call === 'sign_stellar_transaction' ? S.signStellarTransaction(k, B(r.networkId), tx, opts)
      : r.call === 'sign_near_transaction' ? S.signNearTransaction(k, tx, opts) : r.call === 'sign_sui_transaction' ? S.signSuiTransaction(k, tx, opts)
        : S.signHederaTransaction(k, tx, opts);
    assert.equal(H(sig), r.signature, r.id);
    assert.ok(ed25519.verify(sig, B(r.signed), B(r.publicKey)), `${r.id} signs ${r.signed.slice(0, 16)}`);
  }
  // T13 C1: the EVM-prefix refusal rows left with their rule; the rows that sign such messages took their place
  for (const id of ['sign_message EIP-7702 magic 0x05', 'sign_message EIP-712 prefix 0x19 0x01']) assert.ok(!nat.refusals.some((r) => r.id.startsWith(id)), id);
  for (const id of ['ed25519-solana-five-signers', 'sr25519-bare-balances-0500']) assert.equal(B(nat.signatures.find((r) => r.id === id).message)[0], 0x05, id);
});

// ------------------------------------------------------------------ T9: rs_native.json (written by ua-rs, read here)
const RS_NATIVE = new URL('../../../smartcontracts/vectors/native/rs_native.json', import.meta.url);

test('rs_native.json: every ua-rs Taproot and sr25519 row is of its mnemonic\'s key and verifies here', async () => {
  const sr = await import('@scure/sr25519');
  const rs = JSON.parse(readFileSync(RS_NATIVE, 'utf8'));
  assert.ok(rs.rows.length >= 7);
  for (const r of rs.rows) {
    const m = mn(r.mnemonic), msg = B(r.message), sig = B(r.signature);
    if (r.scheme === 'bip340-taproot') {
      assert.equal(S.deriveKey(m.seed, 'bitcoin_p2tr', r.index, { coinType: r.coinType, change: r.change }).outputKey, r.publicKey, r.id);
      assert.ok(schnorr.verify(sig, msg, B(r.publicKey)), r.id);
    } else {
      assert.equal(P.polkadotKey(m.e, m.passphrase, r.path).publicKey, r.publicKey, r.id);
      assert.ok(sr.verify(msg, sig, B(r.publicKey)), r.id);
    }
  }
});

// ------------------------------------------------------------------ T13 C2: signDigest takes exactly 32 bytes (ua-rs's &[u8; 32])
test('signDigest refuses anything but 32 bytes on every scheme, beside 32 bytes accepted (T13 C2)', () => {
  const opt = { allowRawDigest: true };
  for (const k of [S.deriveKey(seed, 'evm', 0), S.deriveKey(seed, 'solana', 0), S.deriveKey(seed, 'aptos', 0), S.deriveKey(seed, 'bitcoin_p2tr', 0),
    S.deriveKey(seed, 'bitcoin_p2wpkh', 0), dot('')]) {
    for (const n of [0, 5, 31, 33, 200000]) assert.equal(codeOf(() => S.signDigest(k, new Uint8Array(n), opt)), 'Argument', `${k.network} ${n}`);
    assert.equal(codeOf(() => S.signDigest(k, new Uint8Array(32).fill(7), opt)), null, `${k.network} 32`);
    assert.equal(codeOf(() => S.signDigest(k, Array(32).fill(7), opt)), 'Argument', `${k.network} not a Uint8Array`);
  }
  const aptos = S.deriveKey(seed, 'aptos', 0), env = new TextEncoder().encode('APTOS\nmessage: scaas');
  assert.equal(codeOf(() => S.signDigest(aptos, env, opt)), 'Argument', 'the AIP-62 envelope cannot pass as a digest');
  assert.equal(codeOf(() => S.signMessage(aptos, env, opt)), 'Argument', 'nor as a message');
});
