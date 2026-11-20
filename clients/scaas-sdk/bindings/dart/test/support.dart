// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The Dart tests' store and authenticator fakes (plan T20) and the reference library's path (run.sh builds it first).
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:scaas_sdk/scaas_sdk.dart';

final lib = Platform.environment['SCAAS_SDK_LIB'] ?? '../../ffi/target/debug/libscaas_sdk_ffi.so';

const pass = 'river-otter-7 ünï';

/// A secret of [text]'s UTF-8 bytes.
ArcSecretBytes sec(String text) => secretOf(Uint8List.fromList(utf8.encode(text)));

/// A store in memory; `gate` holds every `putIf` until it completes; `explode` throws from every call.
class MemStore implements SecureStore {
  final items = <String, Uint8List>{};
  final policies = <String, StorePolicy>{};
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
  Future<(Uint8List, int)?> get(String name, String reason) async {
    if (explode) throw StateError('a foreign exception');
    final b = items[name];
    return b == null ? null : (b, revOf(b));
  }

  @override
  Future<bool> putIf(String name, int? prevRev, Uint8List bytes, StorePolicy policy) async {
    if (explode) throw StateError('a foreign exception');
    if (gate != null) await gate!.future;
    final now = items[name];
    if ((now == null ? null : revOf(now)) != prevRev) return false;
    items[name] = Uint8List.fromList(bytes);
    policies[name] = policy;
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

/// A passkey fake: writes 1..32 as the PRF output; `explode` throws. Every other call: the default `unavailable`.
class FakeAuth extends Authenticator {
  bool explode = false;
  @override
  Future<Assertion> getAssertion(AssertionRequest req, BigInt prfOutId) async {
    if (explode) throw StateError('a foreign exception');
    secretWrite(prfOutId, Uint8List.fromList(List.generate(32, (i) => i + 1)));
    return Assertion(
        credentialId: Uint8List.fromList([1]),
        authenticatorData: Uint8List(37),
        clientDataJson: Uint8List(0),
        signature: Uint8List(64),
        prf: true);
  }
}

/// [f]'s SDK error code (it must fail).
Future<String> failure(Future<Object?> Function() f) async {
  try {
    await f();
  } catch (e) {
    return codeOf(e);
  }
  return 'no error';
}
