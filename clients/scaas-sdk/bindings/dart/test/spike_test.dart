// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T3, the FRB half of the bindings spike (spec §16.1): async calls, the foreign async store and authenticator,
// the PRF return by the copy calls, an abandoned future, a panic, a reactor-bound call, a foreign exception, the load check,
// and no secret byte in the generated codec. Needs the reference library: run.sh builds clients/scaas-sdk/ffi first.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:scaas_sdk/scaas_sdk.dart';
import 'package:test/test.dart';

final lib = Platform.environment['SCAAS_SDK_LIB'] ?? '../../ffi/target/debug/libscaas_sdk_ffi.so';

/// A store in memory; `gate` holds every `putIf` until it completes; `explode` throws from every call.
class MemStore implements SecureStore {
  final items = <String, Uint8List>{};
  Completer<void>? gate;
  bool explode = false;
  int puts = 0;
  int _token = 0;
  final _held = <String>{};
  final _waiters = <String, List<Completer<void>>>{};
  final _tokens = <int, String>{};

  int revOf(Uint8List b) {
    try {
      return (jsonDecode(utf8.decode(b)) as Map)['rev'] as int;
    } catch (_) {
      return -1;
    }
  }

  @override
  Future<(Uint8List, int)?> get(String name) async {
    if (explode) throw StateError('a foreign exception');
    final b = items[name];
    return b == null ? null : (b, revOf(b));
  }

  @override
  Future<bool> putIf(String name, int? prevRev, Uint8List bytes) async {
    if (explode) throw StateError('a foreign exception');
    if (gate != null) await gate!.future;
    final now = items[name];
    if ((now == null ? null : revOf(now)) != prevRev) return false;
    items[name] = Uint8List.fromList(bytes);
    puts++;
    return true;
  }

  @override
  Future<void> delete(String name) async => items.remove(name);

  @override
  Future<int> lock(String name) async {
    if (explode) throw StateError('a foreign exception');
    while (_held.contains(name)) {
      final c = Completer<void>();
      (_waiters[name] ??= []).add(c);
      await c.future;
    }
    _held.add(name);
    _tokens[++_token] = name;
    return _token;
  }

  @override
  Future<void> unlock(int token) async {
    final name = _tokens.remove(token);
    if (name == null) return;
    _held.remove(name);
    final w = _waiters[name];
    if (w != null && w.isNotEmpty) w.removeAt(0).complete();
  }
}

/// A passkey fake: writes 1..32 as the PRF output; `explode` throws.
class FakeAuth implements Authenticator {
  bool explode = false;
  @override
  Future<AuthAnswer> getAssertion(String rpId, Uint8List challenge, List<Uint8List> allow, Uint8List? prfSalt, BigInt prfOutId) async {
    if (explode) throw StateError('a foreign exception');
    secretWrite(prfOutId, Uint8List.fromList(List.generate(32, (i) => i + 1)));
    return AuthAnswer(
        credentialId: Uint8List.fromList([1]),
        authenticatorData: Uint8List(37),
        clientDataJson: Uint8List(0),
        signature: Uint8List(64),
        prf: true);
  }
}

String code(Object e) => e is SdkFailure ? e.code : 'not an SdkFailure: $e';

void main() {
  setUpAll(() async => loadScaasSdk(lib));

  test('load_check: this library passes; another api_version or a missing feature is AbiMismatch', () {
    checkAbi();
    expect(() => checkAbi(expectApi: generatedApiVersion + 1), throwsA(isA<AbiMismatch>()));
    expect(() => checkAbi(needFeatures: 1 << 12), throwsA(isA<AbiMismatch>()), reason: 'bit 12 is never set');
  });

  test('generate, seeds, the reveal by the copy call, an event', () async {
    final store = MemStore();
    final sdk = await openSdk(store, FakeAuth());
    final events = sdk.subscribe();
    expect(await sdk.seeds(), isEmpty);
    final pass = secretOf(Uint8List.fromList(utf8.encode('river-otter-7 ünï')));
    final backup = await sdk.generate(label: 'Main', vaultPassphrase: pass);
    final seeds = await sdk.seeds();
    expect(seeds.map((s) => (s.label, s.words, s.backup, s.unlocked)), [('Main', 24, 'pending', true)]);
    expect(await events.next(timeoutMs: BigInt.from(1000)), startsWith('KeystoreChanged'));
    final words = backup.reveal();
    final text = utf8.decode(secretRead(words));
    expect(text.split(' '), hasLength(24));
    secretDispose(words);
    expect(() => backup.reveal(), throwsA(predicate((e) => code(e!) == 'Argument')), reason: 'revealed once');
    // the keystore holds no passphrase and no word
    final ks = utf8.decode(store.items['keystore']!);
    expect(ks.contains('river-otter'), isFalse);
    expect(ks.contains(text.split(' ').first + ' ' + text.split(' ')[1]), isFalse);
    // an error by its code: the label is taken
    final again = secretOf(Uint8List.fromList(utf8.encode('river-otter-7 ünï')));
    await expectLater(sdk.generate(label: 'Main', vaultPassphrase: again), throwsA(predicate((e) => code(e!) == 'LabelTaken')));
    final weak = secretOf(Uint8List.fromList(utf8.encode('1234567')));
    await expectLater(sdk.generate(label: 'Two', vaultPassphrase: weak), throwsA(predicate((e) => code(e!) == 'VaultPassphraseWeak')));
  });

  test('a foreign exception in a callback is Unexpected, never a Rust panic', () async {
    final store = MemStore();
    final sdk = await openSdk(store, FakeAuth());
    store.explode = true;
    await expectLater(sdk.seeds(), throwsA(predicate((e) => code(e!) == 'VaultIo')));
    store.explode = false;
    expect(await sdk.seeds(), isEmpty, reason: 'the SDK goes on');
  });

  test('an abandoned future: the generate completes on the SDK runtime', () async {
    final store = MemStore()..gate = Completer<void>();
    final sdk = await openSdk(store, FakeAuth());
    final events = sdk.subscribe();
    final pass = secretOf(Uint8List.fromList(utf8.encode('river-otter-7 ünï')));
    // the caller stops waiting (Dart futures cannot be cancelled: the caller abandons it)
    await expectLater(sdk.generate(label: 'Late', vaultPassphrase: pass).timeout(const Duration(milliseconds: 50)),
        throwsA(isA<TimeoutException>()));
    expect(store.items.containsKey('keystore'), isFalse);
    store.gate!.complete();
    expect(await events.next(timeoutMs: BigInt.from(20000)), startsWith('KeystoreChanged'));
    expect((await sdk.seeds()).map((s) => s.label), ['Late']);
  });

  test('no spike call is exported (closing review P2-10)', () {
    final api = File('../../ffi/src/api/mod.rs').readAsStringSync();
    final wire = File('../../ffi/src/frb_generated.rs').readAsStringSync();
    expect(RegExp(r'pub (async )?fn spike_').hasMatch(api), isFalse, reason: 'the Rust surface');
    expect(wire.contains('spike_'), isFalse, reason: 'the generated wire');
    expect(RegExp(r'pub (async )?fn sdk_open').hasMatch(api), isTrue, reason: 'control: the surface is read');
  });

  test('secret_never_in_the_codec: every secret parameter of the generated wire is an opaque handle', () {
    final wire = File('../../ffi/src/frb_generated.rs').readAsStringSync();
    final api = File('../../ffi/src/api/mod.rs').readAsStringSync();
    // the Rust surface: the passphrase is `&Secret`; no parameter named like a secret has a byte type
    expect(api.contains('vault_passphrase: &Secret'), isTrue);
    for (final p in ['passphrase', 'words', 'prf_out', 'mnemonic']) {
      expect(RegExp('$p\\w*: (Vec<u8>|String|&str)').hasMatch(api), isFalse, reason: p);
    }
    // the generated decode of `generate` takes the passphrase as an opaque reference, never bytes
    final gen = wire.substring(wire.indexOf('fn wire__crate__api__SdkHandle_generate_impl'));
    // (rustfmt wraps the generated code: compared without white space)
    final body = gen.substring(0, gen.indexOf('\nfn ')).replaceAll(RegExp(r'\s+'), '');
    expect(body.contains('letapi_label=<String>::sse_decode'), isTrue, reason: 'control: a plain field decodes as bytes');
    expect(body.contains('letapi_vault_passphrase=<RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<Secret>,>>::sse_decode'),
        isTrue);
    expect(RegExp(r'letapi_vault_passphrase=<(Vec<u8>|String)>').hasMatch(body), isFalse);
  });
}
