// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The Dart binding of scaas-sdk (spec §16.1; plan T3): the generated FRB surface, the load check (§16.3), the secret copy calls
// (§5: through dart:ffi with our own buffers, never FRB's codec) and the platform interfaces as records of async closures, each
// answering a Dart exception as `Unexpected` (no exception reaches Rust).
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

import 'src/rust/api.dart';
import 'src/rust/frb_generated.dart';

export 'src/rust/api.dart';
export 'src/rust/frb_generated.dart' show ScaasSdk;

/// The binding surface's version and the feature bits this binding was generated against (spec §16.3): `vault` (bit 0).
const int generatedApiVersion = 1;
const int requiredFeatures = 1 << 0;

/// A library this binding cannot speak to (another `api_version`, a needed feature missing).
class AbiMismatch implements Exception {
  final String why;
  AbiMismatch(this.why);
  @override
  String toString() => 'AbiMismatch: $why';
}

late int Function(int, ffi.Pointer<ffi.Uint8>, int) _write;
late int Function(int, ffi.Pointer<ffi.Uint8>, int) _read;
late int Function(int) _dispose;

/// Loads the library at [path], then the load check.
Future<void> loadScaasSdk(String path) async {
  await ScaasSdk.init(externalLibrary: ExternalLibrary.open(path));
  final lib = ffi.DynamicLibrary.open(path);
  _write = lib.lookupFunction<ffi.Int32 Function(ffi.Uint64, ffi.Pointer<ffi.Uint8>, ffi.Size),
      int Function(int, ffi.Pointer<ffi.Uint8>, int)>('scaas_sdk_secret_write');
  _read = lib.lookupFunction<ffi.Int64 Function(ffi.Uint64, ffi.Pointer<ffi.Uint8>, ffi.Size),
      int Function(int, ffi.Pointer<ffi.Uint8>, int)>('scaas_sdk_secret_read');
  _dispose = lib.lookupFunction<ffi.Int32 Function(ffi.Uint64), int Function(int)>('scaas_sdk_secret_dispose');
  checkAbi();
}

/// The load check: refuses a library of another `api_version` or without a needed feature.
void checkAbi({int expectApi = generatedApiVersion, int needFeatures = requiredFeatures}) {
  if (apiVersion() != expectApi) throw AbiMismatch('api_version ${apiVersion()}, generated against $expectApi');
  final f = features().toInt();
  if (f & needFeatures != needFeatures) {
    throw AbiMismatch('features 0x${f.toRadixString(16)} lack 0x${needFeatures.toRadixString(16)}');
  }
}

/// Writes [src] into the secret [id] through the copy call; [src] and the native buffer are zeroed whatever the outcome.
void secretWrite(BigInt id, Uint8List src) {
  final n = src.isEmpty ? 1 : src.length;
  final p = calloc<ffi.Uint8>(n);
  try {
    p.asTypedList(src.length).setAll(0, src);
    if (_write(id.toInt(), p, src.length) != 0) throw ArgumentError('secret write refused');
  } finally {
    p.asTypedList(n).fillRange(0, n, 0);
    calloc.free(p);
    src.fillRange(0, src.length, 0);
  }
}

/// A new secret holding [src] ([src] zeroed).
Secret secretOf(Uint8List src) {
  final s = secretNew(len: src.length);
  secretWrite(s.id(), src);
  return s;
}

/// A copy of secret [s] (the caller zeroes it when done).
Uint8List secretRead(Secret s) {
  final n = s.size() == 0 ? 1 : s.size();
  final p = calloc<ffi.Uint8>(n);
  try {
    final got = _read(s.id().toInt(), p, n);
    if (got < 0) throw ArgumentError('secret read refused');
    return Uint8List.fromList(p.asTypedList(got));
  } finally {
    p.asTypedList(n).fillRange(0, n, 0);
    calloc.free(p);
  }
}

/// Disposes of secret [s] (zeroed and freed in Rust).
void secretDispose(Secret s) => _dispose(s.id().toInt());

/// The app's store (spec §6.9). Throwing is answered `Unexpected`.
abstract class SecureStore {
  /// `(bytes, rev)` or null.
  Future<(Uint8List, int)?> get(String name);

  /// Replaces [name] only at [prevRev] (null: absent); false: a conflict.
  Future<bool> putIf(String name, int? prevRev, Uint8List bytes);
  Future<void> delete(String name);

  /// A lock token; [unlock] releases it.
  Future<int> lock(String name);
  Future<void> unlock(int token);
}

/// The app's authenticator (spec §6.10); `getAssertion` writes the PRF output into the secret [prfOutId] by the copy call.
abstract class Authenticator {
  Future<AuthAnswer> getAssertion(String rpId, Uint8List challenge, Uint8List? prfSalt, BigInt prfOutId);
}

StoreAnswer _ok([int token = 0]) => StoreAnswer(token: BigInt.from(token));
StoreAnswer _failed(StoreFailure e) => StoreAnswer(token: BigInt.zero, error: e);
final _none = Uint8List(0);

/// Opens the SDK over [store] and [auth] (the records of closures the SDK wraps into its traits).
Future<SdkHandle> openSdk(SecureStore store, Authenticator auth) => sdkOpen(
      storeGet: (name) async {
        try {
          final r = await store.get(name);
          return StoreGetAnswer(found: r != null, bytes: r?.$1 ?? _none, rev: BigInt.from(r?.$2 ?? 0));
        } catch (_) {
          return StoreGetAnswer(found: false, bytes: _none, rev: BigInt.zero, error: StoreFailure.unexpected);
        }
      },
      storePutIf: (name, prev, bytes) async {
        try {
          return await store.putIf(name, prev?.toInt(), bytes) ? _ok() : _failed(StoreFailure.conflict);
        } catch (_) {
          return _failed(StoreFailure.unexpected);
        }
      },
      storeDelete: (name) async {
        try {
          await store.delete(name);
          return _ok();
        } catch (_) {
          return _failed(StoreFailure.unexpected);
        }
      },
      storeLock: (name) async {
        try {
          return _ok(await store.lock(name));
        } catch (_) {
          return _failed(StoreFailure.unexpected);
        }
      },
      storeUnlock: (token) async {
        try {
          await store.unlock(token.toInt());
        } catch (_) {}
      },
      authGetAssertion: (rpId, challenge, salt, prfOut) async {
        try {
          return await auth.getAssertion(rpId, challenge, salt, prfOut);
        } catch (_) {
          return AuthAnswer(
              credentialId: _none,
              authenticatorData: _none,
              clientDataJson: _none,
              signature: _none,
              prf: false,
              error: AuthFailure.unexpected);
        }
      },
    );
