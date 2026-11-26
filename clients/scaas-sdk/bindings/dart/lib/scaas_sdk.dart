// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The Dart binding of scaas-sdk (spec §16.1; plan T20): the generated FRB surface (every public item of the SDK, under
// lib/src/rust/), the load check (§16.3), the secret copy calls (§5: through dart:ffi with our own buffers, never FRB's codec)
// and the platform interfaces as records of async closures, each answering a Dart exception as `unexpected` (no exception
// reaches Rust).
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

import 'src/rust/api.dart';
import 'src/rust/frb_generated.dart';
import 'src/rust/third_party/scaas_sdk/config.dart';
import 'src/rust/third_party/scaas_sdk/error.dart';
import 'src/rust/third_party/scaas_sdk/platform.dart';
import 'src/rust/third_party/scaas_sdk/vault/prf.dart';
import 'src/rust/third_party/scaas_sdk/vault/store.dart';

export 'src/rust/api.dart';
export 'src/rust/frb_generated.dart' show ScaasSdk;
export 'src/rust/lib.dart';
export 'src/rust/third_party/scaas_sdk/account.dart';
export 'src/rust/third_party/scaas_sdk/account/msig.dart';
export 'src/rust/third_party/scaas_sdk/account/smart.dart';
export 'src/rust/third_party/scaas_sdk/admin.dart';
export 'src/rust/third_party/scaas_sdk/admin/delay.dart';
export 'src/rust/third_party/scaas_sdk/confidential.dart';
export 'src/rust/third_party/scaas_sdk/config.dart';
export 'src/rust/third_party/scaas_sdk/dex.dart';
export 'src/rust/third_party/scaas_sdk/error.dart';
export 'src/rust/third_party/scaas_sdk/events.dart';
export 'src/rust/third_party/scaas_sdk/line.dart';
export 'src/rust/third_party/scaas_sdk/op.dart';
export 'src/rust/third_party/scaas_sdk/platform.dart';
export 'src/rust/third_party/scaas_sdk/vault.dart';
export 'src/rust/third_party/scaas_sdk/vault/keystore.dart';
export 'src/rust/third_party/scaas_sdk/vault/prf.dart';
export 'src/rust/third_party/scaas_sdk/vault/seeds.dart';
export 'src/rust/third_party/scaas_sdk/vault/store.dart';
export 'src/rust/third_party/scaas_sdk/wallet.dart';

/// The binding surface's version and the feature bits this binding was generated against (spec §16.3): `vault` (0),
/// `account` (1), `wallet` (2), `native-networks` (3), `zether` (4), `pqz` (5), `dex` (10), `admin` (11),
/// `classical-roots` (24): the modules the generated surface calls.
const int generatedApiVersion = 1;
const int requiredFeatures = 1 << 0 | 1 << 1 | 1 << 2 | 1 << 3 | 1 << 4 | 1 << 5 | 1 << 10 | 1 << 11 | 1 << 24;

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

/// Loads the library at [path] (once per process), then the load check (every call).
Future<void> loadScaasSdk(String path,
    {int expectApi = generatedApiVersion, int needFeatures = requiredFeatures}) async {
  if (!ScaasSdk.instance.initialized) await ScaasSdk.init(externalLibrary: ExternalLibrary.open(path));
  final lib = ffi.DynamicLibrary.open(path);
  _write = lib.lookupFunction<ffi.Int32 Function(ffi.Uint64, ffi.Pointer<ffi.Uint8>, ffi.Size),
      int Function(int, ffi.Pointer<ffi.Uint8>, int)>('scaas_sdk_secret_write');
  _read = lib.lookupFunction<ffi.Int64 Function(ffi.Uint64, ffi.Pointer<ffi.Uint8>, ffi.Size),
      int Function(int, ffi.Pointer<ffi.Uint8>, int)>('scaas_sdk_secret_read');
  _dispose = lib.lookupFunction<ffi.Int32 Function(ffi.Uint64), int Function(int)>('scaas_sdk_secret_dispose');
  checkAbi(expectApi: expectApi, needFeatures: needFeatures);
}

/// The load check: refuses a library of another `api_version` or without a needed feature (the early message; the Rust
/// opening runs the full check again, the `vectors` build included).
void checkAbi({int expectApi = generatedApiVersion, int needFeatures = requiredFeatures}) {
  if (apiVersion() != expectApi) throw AbiMismatch('api_version ${apiVersion()}, generated against $expectApi');
  final f = features().toInt();
  if (f & needFeatures != needFeatures) {
    throw AbiMismatch('features 0x${f.toRadixString(16)} lack 0x${needFeatures.toRadixString(16)}');
  }
}

/// An SDK error's stable code (spec §15); any other object as itself.
String codeOf(Object e) => e is SdkError ? errorCode(e: e) : 'not an SdkError: $e';

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

/// A new secret holding [src] ([src] zeroed). A request record that takes it moves it into Rust: one secret per call.
ArcSecretBytes secretOf(Uint8List src) {
  final s = secretNew(len: src.length);
  secretWrite(secretId(s: s), src);
  return s;
}

/// A copy of secret [s] (the caller zeroes it when done).
Uint8List secretRead(ArcSecretBytes s) {
  final len = secretLen(s: s);
  final n = len == 0 ? 1 : len;
  final p = calloc<ffi.Uint8>(n);
  try {
    final got = _read(secretId(s: s).toInt(), p, n);
    if (got < 0) throw ArgumentError('secret read refused');
    return Uint8List.fromList(p.asTypedList(got));
  } finally {
    p.asTypedList(n).fillRange(0, n, 0);
    calloc.free(p);
  }
}

/// Disposes of secret [s] (zeroed and freed in Rust).
void secretDispose(ArcSecretBytes s) => _dispose(secretId(s: s).toInt());

/// The app's store (spec §6.9). Throwing is answered `unexpected`.
abstract class SecureStore {
  /// `(bytes, rev)` or null; [reason] is shown at a presence check.
  Future<(Uint8List, int)?> get(String name, String reason);

  /// Replaces [name] only at [prevRev] (null: absent) under [policy]; false: a conflict.
  Future<bool> putIf(String name, int? prevRev, Uint8List bytes, StorePolicy policy);
  Future<void> delete(String name);

  /// A lock token; [unlock] releases it.
  Future<int> lock(String name);
  Future<void> unlock(int token);
}

/// The app's authenticator (spec §6.10). A PRF output or a platform secret is written into the secret of the given id by
/// [secretWrite]. Throwing is answered `unexpected`; the default answers are `unavailable`.
abstract class Authenticator {
  Future<PasskeyCreated> createPasskey(String rpId, String userName, List<Uint8List> exclude) =>
      throw const AuthException(AuthError.unavailable);
  Future<Assertion> getAssertion(AssertionRequest req, BigInt prfOutId) =>
      throw const AuthException(AuthError.unavailable);
  Future<void> platformSecret(String handle, Uint8List salt, String reason, KeyPolicy? policy, BigInt outId) =>
      throw const AuthException(AuthError.unavailable);
  Future<SePublic> p256Generate(KeyPolicy policy) => throw const AuthException(AuthError.unavailable);
  Future<Uint8List> p256Sign(String handle, Uint8List uaMsg, String reason) =>
      throw const AuthException(AuthError.unavailable);
}

/// An authenticator's named failure.
class AuthException implements Exception {
  final AuthError error;
  const AuthException(this.error);
}

StoreAnswer _ok([int token = 0]) => StoreAnswer(token: BigInt.from(token));
StoreAnswer _failed(StoreError e) => StoreAnswer(token: BigInt.zero, error: e);
AuthError _authError(Object e) => e is AuthException ? e.error : AuthError.unexpected;
final _none = Uint8List(0);

/// Opens the SDK over [store] and [auth] (the records of closures the SDK wraps into its traits). The Rust side runs the load
/// check first ([expectApi], [needFeatures], and a test-only `vectors` build refused): `AbiMismatch` (review T26 C-2).
Future<SdkHandle> openSdk(SecureStore store, Authenticator auth,
        {List<ChainProfile> profiles = const [],
        String? rpId,
        Limits? limits,
        List<GasTable> gasTables = const [],
        int expectApi = generatedApiVersion,
        int needFeatures = requiredFeatures}) =>
    sdkOpen(
      expectApi: expectApi,
      needFeatures: BigInt.from(needFeatures),
      profiles: profiles,
      rpId: rpId,
      limits: limits ?? limitsDefault(),
      gasTables: gasTables,
      storeGet: (name, reason) async {
        try {
          final r = await store.get(name, reason);
          return StoreGetAnswer(found: r != null, bytes: r?.$1 ?? _none, rev: BigInt.from(r?.$2 ?? 0));
        } catch (_) {
          return StoreGetAnswer(found: false, bytes: _none, rev: BigInt.zero, error: StoreError.unexpected);
        }
      },
      storePutIf: (name, prev, bytes, policy) async {
        try {
          return await store.putIf(name, prev?.toInt(), bytes, policy) ? _ok() : _failed(StoreError.conflict);
        } catch (_) {
          return _failed(StoreError.unexpected);
        }
      },
      storeDelete: (name) async {
        try {
          await store.delete(name);
          return _ok();
        } catch (_) {
          return _failed(StoreError.unexpected);
        }
      },
      storeLock: (name) async {
        try {
          return _ok(await store.lock(name));
        } catch (_) {
          return _failed(StoreError.unexpected);
        }
      },
      storeUnlock: (token) async {
        try {
          await store.unlock(token.toInt());
        } catch (_) {}
      },
      authCreatePasskey: (rp, user, exclude) async {
        try {
          return PasskeyAnswer(created: await auth.createPasskey(rp, user, exclude));
        } catch (e) {
          return PasskeyAnswer(error: _authError(e));
        }
      },
      authGetAssertion: (req, prfOut) async {
        try {
          return AssertionAnswer(assertion: await auth.getAssertion(req, prfOut));
        } catch (e) {
          return AssertionAnswer(error: _authError(e));
        }
      },
      authPlatformSecret: (handle, salt, reason, policy, out) async {
        try {
          await auth.platformSecret(handle, salt, reason, policy, out);
          return null;
        } catch (e) {
          return _authError(e);
        }
      },
      authP256Generate: (policy) async {
        try {
          return SeKeyAnswer(public: await auth.p256Generate(policy));
        } catch (e) {
          return SeKeyAnswer(error: _authError(e));
        }
      },
      authP256Sign: (handle, msg, reason) async {
        try {
          return SignAnswer(signature: await auth.p256Sign(handle, msg, reason));
        } catch (e) {
          return SignAnswer(signature: _none, error: _authError(e));
        }
      },
    );
