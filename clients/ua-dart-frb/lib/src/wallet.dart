// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-rs-sign T13c: the Dart facade of the wallet (rust/src/api/wallet.rs, generated into lib/src/rust/api/wallet.dart). Every
// entry point without a handle runs [load] (abi_version and the required features of the linked library, `UAAbiMismatch`
// otherwise). Every secret, in or out (mnemonic, passphrases, PRF secret, an imported key, the seed-backup answers, a seal or
// AEAD plaintext, an AEAD / HKDF / HMAC key, a cache's entries; an opened plaintext, a shared secret, the revealed phrase, the
// entropy, HKDF output, the PQZ leaf) is a `SecretBytes`: Rust-owned memory, locked where the platform allows, zeroed when
// disposed, that Dart writes and reads in place through `dart:ffi`, never through frb's codec. `SecretBytes.take(src)` moves
// a caller's `Uint8List` in and zeroes it; `SecretBytes.view(s)` reads one without a copy; the caller disposes each. The
// handles are frb opaque objects: `dispose()` frees one exactly once; after `lock()` or the wallet's disposal a key answers
// `UAKeyRevoked`. UNAUDITED.
//
// Residual: copies a caller makes before `take` (a `String` from a text field is immutable and cannot be zeroed: the API takes
// bytes only) and copies of a `view` are the caller's. Native targets only: `dart:ffi` does not exist on the web, so this
// package does not build there.

import 'rust/api/ua.dart' show UAError;
import 'rust/api/wallet.dart' as g;
import 'rust/api/wallet.dart' show SecretBytes;

/// The surface generation this facade was written for (the C ABI's `SCAAS_UA_ABI_VERSION`, 6).
const int kAbiVersion = 6;

/// The bits of `scaas_ua_features()`.
abstract final class UaFeature {
  static const int wallet = 1 << 0, pq = 1 << 1, falcon = 1 << 2, zether = 1 << 3, pqz = 1 << 4;
  static const int pqzSetN2048Kmax1024 = 1 << 5, pqzSetN2304Kmax4096 = 1 << 6, pqzSetN2560Kmax16384 = 1 << 7;
  static const int pqzSetN2816Kmax65536 = 1 << 8, external = 1 << 9, mlock = 1 << 10;
  /// A test build (scaas-ua feature `vectors`): [load] refuses it (spec no-decryption-oracle §4.8, Codex C1).
  static const int vectors = 1 << 11;
}

/// What this facade needs of the library.
final BigInt kRequiredFeatures =
    BigInt.from(UaFeature.wallet | UaFeature.pq | UaFeature.zether | UaFeature.pqz | UaFeature.pqzSetN2304Kmax4096);

/// The PQZ facade's largest output: a call returns its whole JSON, never sized by a query.
const int kPqzOutMax = 1052672;

/// Where [load] reads the library's values: the library itself unless a test points them elsewhere.
abstract final class UaLoadHook {
  static int Function() reportedAbiVersion = g.abiVersion;
  static BigInt Function() reportedFeatures = g.features;
  static void reset() {
    reportedAbiVersion = g.abiVersion;
    reportedFeatures = g.features;
  }
}

/// Refuses a library of another surface generation, without the required features, or a test build ([UaFeature.vectors]).
void load() {
  if (UaLoadHook.reportedAbiVersion() != kAbiVersion) throw const UAError(code: 'UAAbiMismatch', reason: 'abi_version');
  final f = UaLoadHook.reportedFeatures();
  if (f & kRequiredFeatures != kRequiredFeatures || f & BigInt.from(UaFeature.vectors) != BigInt.zero) {
    throw const UAError(code: 'UAAbiMismatch', reason: 'features');
  }
}

/// Zeroes [b] in place (a caller's own buffer; a `SecretBytes` is zeroed when disposed).
void wipe(List<int>? b) {
  if (b != null) b.fillRange(0, b.length, 0);
}

Future<T> _loaded<T>(Future<T> Function() f) async {
  load();
  return f();
}

/// A version is a Rust u64; frb encodes a BigInt with toSigned(64), so one outside 0 ... 2^64 - 1 is refused here first.
BigInt _u64(BigInt v) =>
    v.isNegative || v.bitLength > 64 ? throw const UAError(code: 'UAArgument', reason: '') : v;

/// A new wallet of 24 words (OS entropy) and its recovery phrase.
Future<(g.UaWallet, g.UaSeedBackup)> walletGenerate() => _loaded(g.walletGenerate);

Future<g.UaWallet> walletFromMnemonic({required SecretBytes words, required SecretBytes bip39Passphrase}) =>
    _loaded(() => g.walletFromMnemonic(words: words, bip39Passphrase: bip39Passphrase));

/// Exactly one of [vaultPassphrase] / [prf32] (both: the PRF secret, the passphrase not tried; neither: `UAArgument`).
Future<g.UaWallet> walletOpenVault(
        {required String vaultJson, SecretBytes? vaultPassphrase, SecretBytes? prf32, required SecretBytes bip39Passphrase}) =>
    _loaded(() => g.walletOpenVault(vaultJson: vaultJson, vaultPassphrase: vaultPassphrase, prf32: prf32, bip39Passphrase: bip39Passphrase));

Future<void> walletUnlock(
        {required g.UaWallet w,
        required String vaultJson,
        SecretBytes? vaultPassphrase,
        SecretBytes? prf32,
        required SecretBytes bip39Passphrase}) =>
    _loaded(() => g.walletUnlock(w: w, vaultJson: vaultJson, vaultPassphrase: vaultPassphrase, prf32: prf32, bip39Passphrase: bip39Passphrase));

Future<String> walletSealVault({required g.UaWallet w, required SecretBytes vaultPassphrase}) =>
    _loaded(() => g.walletSealVault(w: w, vaultPassphrase: vaultPassphrase));

Future<g.UaKey> walletImportNativeKey({required g.UaWallet w, required String networkName, required SecretBytes secretKey}) =>
    _loaded(() => g.walletImportNativeKey(w: w, networkName: networkName, secretKey: secretKey));

Future<String> walletSealLabelVault({required g.UaWallet w, required String label, required SecretBytes vaultPassphrase}) =>
    _loaded(() => g.walletSealLabelVault(w: w, label: label, vaultPassphrase: vaultPassphrase));

Future<void> walletOpenLabelVault(
        {required g.UaWallet w, required String vaultJson, SecretBytes? vaultPassphrase, SecretBytes? prf32}) =>
    _loaded(() => g.walletOpenLabelVault(w: w, vaultJson: vaultJson, vaultPassphrase: vaultPassphrase, prf32: prf32));

/// The wallet of a backup container; null: an equal generation installed nothing. [membersJson] / [acceptedJson] null = none.
Future<g.UaWallet?> walletRestoreBackup(
        {required g.UaKemKey kk,
        required String containerJson,
        required String expectJson,
        String? membersJson,
        String? acceptedJson,
        required SecretBytes bip39Passphrase}) =>
    _loaded(() => g.walletRestoreBackup(
            kk: kk,
            containerJson: containerJson,
            expectJson: expectJson,
            membersJson: membersJson,
            acceptedJson: acceptedJson,
            bip39Passphrase: bip39Passphrase));

/// As [walletRestoreBackup] over [current] (an older generation: `UABackupRollback`).
Future<g.UaWallet?> walletRestoreBackupOver(
        {required g.UaWallet current,
        required g.UaKemKey kk,
        required String containerJson,
        required String expectJson,
        String? membersJson,
        String? acceptedJson,
        required SecretBytes bip39Passphrase}) =>
    _loaded(() => g.walletRestoreBackupOver(
            current: current,
            kk: kk,
            containerJson: containerJson,
            expectJson: expectJson,
            membersJson: membersJson,
            acceptedJson: acceptedJson,
            bip39Passphrase: bip39Passphrase));

/// The rollback, by its own name.
Future<g.UaWallet?> walletRestoreBackupRollback(
        {required g.UaWallet current,
        required g.UaKemKey kk,
        required String containerJson,
        required String expectJson,
        String? membersJson,
        String? acceptedJson,
        required SecretBytes bip39Passphrase}) =>
    _loaded(() => g.walletRestoreBackupRollback(
            current: current,
            kk: kk,
            containerJson: containerJson,
            expectJson: expectJson,
            membersJson: membersJson,
            acceptedJson: acceptedJson,
            bip39Passphrase: bip39Passphrase));

/// Consumes [session] (later calls on it: `UAKeyRevoked`).
Future<g.UaWallet> walletFromLink(
        {required g.UaLinkSession session,
        required String containerJson,
        required String expectJson,
        String? membersJson,
        String? acceptedJson,
        required SecretBytes bip39Passphrase}) =>
    _loaded(() => g.walletFromLink(
            session: session,
            containerJson: containerJson,
            expectJson: expectJson,
            membersJson: membersJson,
            acceptedJson: acceptedJson,
            bip39Passphrase: bip39Passphrase));

Future<List<String>> walletBackupSeal(
        {required g.UaWallet w, required g.UaKey sender, required List<g.UaRecipient> recipients}) =>
    _loaded(() {
      for (final r in recipients) {
        _u64(r.version);
      }
      return g.walletBackupSeal(w: w, sender: sender, recipients: recipients);
    });

Future<g.UaKemKey> keyKemKey({required g.UaKey k, required BigInt version}) =>
    _loaded(() => g.keyKemKey(k: k, version: _u64(version)));

/// The answers, in the challenged order; the call consumes them (each disposed).
Future<bool> seedBackupVerify({required g.UaSeedBackup b, required List<SecretBytes> answers}) =>
    _loaded(() => g.seedBackupVerify(b: b, answers: answers));

Future<bool> vaultNeedsRewrap({required String vaultJson}) => _loaded(() => g.vaultNeedsRewrap(vaultJson: vaultJson));

Future<String> vaultRewrapPin({required String vaultJson, required SecretBytes oldPassphrase, required SecretBytes newPassphrase}) =>
    _loaded(() => g.vaultRewrapPin(vaultJson: vaultJson, oldPassphrase: oldPassphrase, newPassphrase: newPassphrase));

Future<String> vaultEnablePrf(
        {required String vaultJson,
        required SecretBytes vaultPassphrase,
        required SecretBytes prf32,
        required String credentialId,
        required List<int> salt}) =>
    _loaded(() => g.vaultEnablePrf(
            vaultJson: vaultJson, vaultPassphrase: vaultPassphrase, prf32: prf32, credentialId: credentialId, salt: salt));

Future<g.UaKemKey> kemEphemeral() => _loaded(g.kemEphemeral);
Future<g.UaEncapsulated> kemEncaps({required List<int> kemPk}) => _loaded(() => g.kemEncaps(kemPk: kemPk));

/// A seal to [kemPk] (authenticates no sender).
Future<g.UaSealed> seal({required List<int> kemPk, required String purpose, required List<int> aad, required SecretBytes pt}) =>
    _loaded(() => g.seal(kemPk: kemPk, purpose: purpose, aad: aad, pt: pt));

Future<g.UaLinkSession> linkSessionNew() => _loaded(g.linkSessionNew);
Future<g.UaKeyList> keyListNew() => _loaded(g.keyListNew);
Future<String> uasig({required String requestJson, required g.UaKeyList keys}) =>
    _loaded(() => g.uasig(requestJson: requestJson, keys: keys));

/// [algId] 1 = AES-256-GCM, 2 = AES-256-GCM-SIV; [pt] the plaintext.
Future<List<int>> aeadSeal(
        {required int algId, required SecretBytes key32, required List<int> nonce12, required List<int> aad, required SecretBytes pt}) =>
    _loaded(() => g.aeadSeal(algId: algId, key32: key32, nonce12: nonce12, aad: aad, pt: pt));
/// The plaintext of [data].
Future<SecretBytes> aeadOpen(
        {required int algId, required SecretBytes key32, required List<int> nonce12, required List<int> aad, required List<int> data}) =>
    _loaded(() => g.aeadOpen(algId: algId, key32: key32, nonce12: nonce12, aad: aad, data: data));
/// The output keying material.
Future<SecretBytes> hkdfSha256({required SecretBytes ikm, required List<int> salt, required List<int> info, required int len}) =>
    _loaded(() => g.hkdfSha256(ikm: ikm, salt: salt, info: info, len: len));
/// The MAC (not a secret).
Future<List<int>> hmacSha256({required SecretBytes keyBytes, required List<int> data}) =>
    _loaded(() => g.hmacSha256(keyBytes: keyBytes, data: data));
Future<List<int>> webauthnChallenge({required List<int> purpose, required List<int> digest}) =>
    _loaded(() => g.webauthnChallenge(purpose: purpose, digest: digest));
Future<List<int>> webauthnAssertion(
        {required List<int> keyData,
        required List<int> expectedChallenge,
        required List<int> authData,
        required List<int> clientDataJson,
        required List<int> r,
        required List<int> s}) =>
    _loaded(() => g.webauthnAssertion(
        keyData: keyData, expectedChallenge: expectedChallenge, authData: authData, clientDataJson: clientDataJson, r: r, s: s));
Future<String> pqzSet() => _loaded(g.pqzSet);
Future<void> pqzCheckSet({required String deployedJson}) => _loaded(() => g.pqzCheckSet(deployedJson: deployedJson));
