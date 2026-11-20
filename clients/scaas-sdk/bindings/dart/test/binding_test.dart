// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T20 (from the T3 spike): the generated FRB surface over the whole SDK. The load check, async calls, the
// foreign async store and authenticator, the reveal by the copy calls, an abandoned future, a foreign exception, no secret
// byte in the generated codec, the module objects and the JSON helpers. Needs the reference library: run.sh builds
// clients/scaas-sdk/ffi first.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:scaas_sdk/scaas_sdk.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  setUpAll(() async => loadScaasSdk(lib));

  test('load_check: this library passes; another api_version or a missing feature is AbiMismatch', () async {
    checkAbi();
    expect(() => checkAbi(expectApi: generatedApiVersion + 1), throwsA(isA<AbiMismatch>()));
    expect(() => checkAbi(needFeatures: 1 << 12), throwsA(isA<AbiMismatch>()), reason: 'bit 12 is never set');
    // the loader itself runs the check
    await expectLater(loadScaasSdk(lib, expectApi: generatedApiVersion + 1), throwsA(isA<AbiMismatch>()));
    await expectLater(loadScaasSdk(lib, needFeatures: 1 << 12), throwsA(isA<AbiMismatch>()));
    await loadScaasSdk(lib);
    expect(features().toInt() & (1 << 23), 0, reason: 'raw-native is never in the generated surface');
  });

  test('generate, seeds, the reveal by the copy call, the backup check, an event', () async {
    final store = MemStore();
    final sdk = await openSdk(store, FakeAuth());
    final vault = sdk.vault();
    final events = sdk.subscribe();
    expect(await vault.seeds(), isEmpty);
    final made = await vault.generate(req: Generate(label: 'Main', vaultPassphrase: sec(pass)));
    expect((made.info.label, made.info.words, made.info.backup, made.info.unlocked), ('Main', 24, 'pending', true));
    final seeds = await vault.seeds();
    expect(seeds.map((s) => (s.label, s.words, s.backup, s.unlocked)), [('Main', 24, 'pending', true)]);
    final e = await eventsNext(events: events, timeoutMs: BigInt.from(1000));
    expect(e, isA<Event_KeystoreChanged>());
    expect(store.policies['keystore'], isNotNull, reason: 'the store gets the item policy');
    final words = backupReveal(b: made.backup);
    final text = utf8.decode(secretRead(words));
    expect(text.split(' '), hasLength(24));
    secretDispose(words);
    expect(await failure(() async => backupReveal(b: made.backup)), 'Argument', reason: 'revealed once');
    // the three-word check through a secret
    final ask = backupChallenge(b: made.backup);
    expect(ask, hasLength(3));
    final answer = ask.map((i) => text.split(' ')[i - 1]).join(' '); // 1-based positions
    expect(backupVerify(b: made.backup, answers: sec(answer)), isTrue);
    await vault.confirmBackup(seed: made.info.id);
    expect((await vault.seed(seed: made.info.id)).backup, 'verified');
    // the keystore holds no passphrase and no word
    final ks = utf8.decode(store.items['keystore']!);
    expect(ks.contains('river-otter'), isFalse);
    expect(ks.contains('${text.split(' ')[0]} ${text.split(' ')[1]}'), isFalse);
    // an error by its code
    expect(await failure(() => vault.generate(req: Generate(label: 'Main', vaultPassphrase: sec(pass)))), 'LabelTaken');
    expect(await failure(() => vault.generate(req: Generate(label: 'Two', vaultPassphrase: sec('1234567')))),
        'VaultPassphraseWeak');
    // lock, a wrong passphrase, the right one
    expect(await vault.lock(seed: made.info.id), isEmpty);
    expect(await failure(() => vault.unlock(seed: made.info.id, unlock: Unlock.passphrase(sec('not the one 9')))),
        'VaultOpen');
    await vault.unlock(seed: made.info.id, unlock: Unlock.passphrase(sec(pass)));
    expect((await vault.seed(seed: made.info.id)).unlocked, isTrue);
    expect((await vault.memoryProtection(seed: made.info.id)).chunks, greaterThan(BigInt.zero));
  });

  test('the module objects: account rows, a native address, a refused chain', () async {
    final sdk = await openSdk(MemStore(), FakeAuth());
    final info = await sdk.vault().importWords(
        req: ImportWords(label: 'main', words: sec(repo), vaultPassphrase: sec(pass)));
    final row = await sdk
        .account()
        .addNative(req: AddNative(seed: info.id, network: 'evm', index: 0, name: 'EVM 0'));
    expect(row.shape, 'native');
    expect(row.idText, matches(RegExp(r'^0x[0-9a-fA-F]{40}$')));
    final rows = await sdk.account().accounts(seed: info.id);
    expect(rows.map((r) => r.name), ['EVM 0']);
    final key = KeyRef.native(seed: info.id, network: 'evm', index: 0);
    expect(
        await failure(() => sdk.wallet().prepareNativeSend(
            req: NativeSend(key: key, chain: 'nowhere', to: '0x${'11' * 20}', value: '1'))),
        'ChainUnknown');
    expect(sdk.limits().maxValidSecs, BigInt.from(86400));
  });

  test('a foreign exception in a callback is Unexpected, never a Rust panic', () async {
    final store = MemStore();
    final sdk = await openSdk(store, FakeAuth());
    store.explode = true;
    expect(await failure(() => sdk.vault().seeds()), 'VaultIo');
    store.explode = false;
    expect(await sdk.vault().seeds(), isEmpty, reason: 'the SDK goes on');
  });

  test('an abandoned future: the generate completes on the SDK runtime', () async {
    final store = MemStore()..gate = Completer<void>();
    final sdk = await openSdk(store, FakeAuth());
    final events = sdk.subscribe();
    // the caller stops waiting (Dart futures cannot be cancelled: the caller abandons it)
    await expectLater(
        sdk.vault().generate(req: Generate(label: 'Late', vaultPassphrase: sec(pass))).timeout(const Duration(milliseconds: 50)),
        throwsA(isA<TimeoutException>()));
    expect(store.items.containsKey('keystore'), isFalse);
    store.gate!.complete();
    expect(await eventsNext(events: events, timeoutMs: BigInt.from(20000)), isA<Event_KeystoreChanged>());
    expect((await sdk.vault().seeds()).map((s) => s.label), ['Late']);
  });

  test('json helpers: a value round-trips; text that does not parse is Argument', () async {
    expect(jsonText(v: jsonParse(text: '{"a":[1,"b"]}')), '{"a":[1,"b"]}');
    expect(await failure(() async => jsonParse(text: '{')), 'Argument');
  });

  test('every generated Dart module is exported by the binding', () {
    final exported = File('lib/scaas_sdk.dart').readAsStringSync();
    final files = Directory('lib/src/rust')
        .listSync(recursive: true)
        .whereType<File>()
        .map((f) => f.path.replaceAll(r'\\', '/').substring('lib/'.length))
        .where((p) => p.endsWith('.dart') && !p.endsWith('.freezed.dart') && !p.contains('frb_generated'))
        .toList();
    expect(files.length, greaterThan(10), reason: 'control: the generated tree is read');
    for (final p in files) {
      expect(exported.contains("export '$p'"), isTrue, reason: p);
    }
  });

  test('no spike call is exported (closing review P2-10)', () {
    final api = File('../../ffi/src/api/mod.rs').readAsStringSync();
    final wire = File('../../ffi/src/frb_generated.rs').readAsStringSync();
    expect(RegExp(r'pub (async )?fn spike_').hasMatch(api), isFalse, reason: 'the Rust surface');
    expect(wire.contains('spike_'), isFalse, reason: 'the generated wire');
    expect(RegExp(r'pub (async )?fn sdk_open').hasMatch(api), isTrue, reason: 'control: the surface is read');
  });

  test('secret_never_in_the_codec: every secret of the generated wire is an opaque handle', () {
    final wire = File('../../ffi/src/frb_generated.rs').readAsStringSync().replaceAll(RegExp(r'\s+'), '');
    // a secret decodes only as the opaque handle, moved out of it; no SecretBytes is built from bytes
    final dec = wire.substring(wire.indexOf('implSseDecodeforArc<SecretBytes>{'));
    final body = dec.substring(0, dec.indexOf('}}') + 2);
    expect(body.contains('RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<Arc<SecretBytes>>,>'), isTrue,
        reason: body);
    expect(body.contains('rust_auto_opaque_decode_owned'), isTrue);
    expect(RegExp(r'<(Vec<u8>|String)>::sse_decode').hasMatch(body), isFalse);
    // the request records' secret fields decode as that handle (control: a plain field decodes as bytes)
    expect(wire.contains('letmutvar_label=<String>::sse_decode'), isTrue, reason: 'control');
    for (final f in ['vaultPassphrase', 'words', 'secret', 'answers', 'bip39Passphrase', 'old', 'new']) {
      for (final m in RegExp('letmutvar_$f=<([^;]*?)>::sse_decode').allMatches(wire)) {
        expect(m.group(1), anyOf('Arc<SecretBytes>', 'u32'), reason: '$f decodes as ${m.group(1)}');
      }
    }
    expect(RegExp('letmutvar_vaultPassphrase=<Arc<SecretBytes>>::sse_decode').hasMatch(wire), isTrue,
        reason: 'control: the fields are found');
    expect(RegExp(r'SecretBytes::(from|new)').hasMatch(wire), isFalse, reason: 'no secret built by the codec');
  });
}

const repo =
    'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better';
