// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-rs-sign T13c: the Dart facade of the wallet (rust/src/api/wallet.rs, generated into lib/src/rust/api/wallet.dart). Every
// entry point without a handle runs [load] (abi_version and the required features of the linked library, `UAAbiMismatch`
// otherwise); every call that takes a secret (mnemonic, passphrases, PRF secret, an imported key, the seed-backup answers)
// zeroes the caller's buffer after the call, whatever its outcome (the Rust copy is `Zeroizing`). Secret outputs (an opened
// plaintext, a shared secret, a revealed phrase, the PQZ leaf) are the caller's to [wipe]. The handles are frb opaque objects:
// `dispose()` frees one exactly once; after `lock()` or the wallet's disposal a key answers `UAKeyRevoked`. UNAUDITED.
//
// Residual: frb copies a `List<int>` argument into its transfer buffer, which is freed, not zeroed.
import 'dart:typed_data';

import 'rust/api/ua.dart' show UAError;
import 'rust/api/wallet.dart' as g;

/// The surface generation this facade was written for (the C ABI's `SCAAS_UA_ABI_VERSION`, 6).
const int kAbiVersion = 6;

/// The bits of `scaas_ua_features()`.
abstract final class UaFeature {
  static const int wallet = 1 << 0, pq = 1 << 1, falcon = 1 << 2, zether = 1 << 3, pqz = 1 << 4;
  static const int pqzSetN2048Kmax1024 = 1 << 5, pqzSetN2304Kmax4096 = 1 << 6, pqzSetN2560Kmax16384 = 1 << 7;
  static const int pqzSetN2816Kmax65536 = 1 << 8, external = 1 << 9, mlock = 1 << 10;
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

/// Refuses a library of another surface generation or without the required features.
void load() {
  if (UaLoadHook.reportedAbiVersion() != kAbiVersion) throw const UAError(code: 'UAAbiMismatch', reason: 'abi_version');
  if (UaLoadHook.reportedFeatures() & kRequiredFeatures != kRequiredFeatures) {
    throw const UAError(code: 'UAAbiMismatch', reason: 'features');
  }
}

/// Zeroes [b] in place.
void wipe(List<int>? b) {
  if (b != null) b.fillRange(0, b.length, 0);
}

Future<T> _loaded<T>(Future<T> Function() f) async {
  load();
  return f();
}

/// [load], then [f]; every buffer of [secrets] zeroed afterwards, success or not.
Future<T> _secret<T>(List<List<int>?> secrets, Future<T> Function() f) async {
  try {
    load();
    return await f();
  } finally {
    secrets.forEach(wipe);
  }
}

/// A version is a Rust u64; frb encodes a BigInt with toSigned(64), so one outside 0 ... 2^64 - 1 is refused here first.
BigInt _u64(BigInt v) =>
    v.isNegative || v.bitLength > 64 ? throw const UAError(code: 'UAArgument', reason: '') : v;

/// A new wallet of 24 words (OS entropy) and its recovery phrase.
Future<(g.UaWallet, g.UaSeedBackup)> walletGenerate() => _loaded(g.walletGenerate);

Future<g.UaWallet> walletFromMnemonic({required List<int> words, required List<int> bip39Passphrase}) =>
    _secret([words, bip39Passphrase], () => g.walletFromMnemonic(words: words, bip39Passphrase: bip39Passphrase));

/// Exactly one of [vaultPassphrase] / [prf32] (both: the PRF secret, the passphrase not tried; neither: `UAArgument`).
Future<g.UaWallet> walletOpenVault(
        {required String vaultJson, Uint8List? vaultPassphrase, Uint8List? prf32, required List<int> bip39Passphrase}) =>
    _secret([vaultPassphrase, prf32, bip39Passphrase],
        () => g.walletOpenVault(vaultJson: vaultJson, vaultPassphrase: vaultPassphrase, prf32: prf32, bip39Passphrase: bip39Passphrase));

Future<void> walletUnlock(
        {required g.UaWallet w,
        required String vaultJson,
        Uint8List? vaultPassphrase,
        Uint8List? prf32,
        required List<int> bip39Passphrase}) =>
    _secret([vaultPassphrase, prf32, bip39Passphrase],
        () => g.walletUnlock(w: w, vaultJson: vaultJson, vaultPassphrase: vaultPassphrase, prf32: prf32, bip39Passphrase: bip39Passphrase));

Future<String> walletSealVault({required g.UaWallet w, required List<int> vaultPassphrase}) =>
    _secret([vaultPassphrase], () => g.walletSealVault(w: w, vaultPassphrase: vaultPassphrase));

Future<g.UaKey> walletImportNativeKey({required g.UaWallet w, required String networkName, required List<int> secretKey}) =>
    _secret([secretKey], () => g.walletImportNativeKey(w: w, networkName: networkName, secretKey: secretKey));

Future<String> walletSealLabelVault({required g.UaWallet w, required String label, required List<int> vaultPassphrase}) =>
    _secret([vaultPassphrase], () => g.walletSealLabelVault(w: w, label: label, vaultPassphrase: vaultPassphrase));

Future<void> walletOpenLabelVault(
        {required g.UaWallet w, required String vaultJson, Uint8List? vaultPassphrase, Uint8List? prf32}) =>
    _secret([vaultPassphrase, prf32],
        () => g.walletOpenLabelVault(w: w, vaultJson: vaultJson, vaultPassphrase: vaultPassphrase, prf32: prf32));

/// The wallet of a backup container; null: an equal generation installed nothing. [membersJson] / [acceptedJson] null = none.
Future<g.UaWallet?> walletRestoreBackup(
        {required g.UaKemKey kk,
        required String containerJson,
        required String expectJson,
        String? membersJson,
        String? acceptedJson,
        required List<int> bip39Passphrase}) =>
    _secret(
        [bip39Passphrase],
        () => g.walletRestoreBackup(
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
        required List<int> bip39Passphrase}) =>
    _secret(
        [bip39Passphrase],
        () => g.walletRestoreBackupOver(
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
        required List<int> bip39Passphrase}) =>
    _secret(
        [bip39Passphrase],
        () => g.walletRestoreBackupRollback(
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
        required List<int> bip39Passphrase}) =>
    _secret(
        [bip39Passphrase],
        () => g.walletFromLink(
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

/// The answers, in the challenged order; each zeroed after the call.
Future<bool> seedBackupVerify({required g.UaSeedBackup b, required List<Uint8List> answers}) =>
    _secret(answers, () => g.seedBackupVerify(b: b, answers: answers));

Future<bool> vaultNeedsRewrap({required String vaultJson}) => _loaded(() => g.vaultNeedsRewrap(vaultJson: vaultJson));

Future<String> vaultRewrapPin({required String vaultJson, required List<int> oldPassphrase, required List<int> newPassphrase}) =>
    _secret([oldPassphrase, newPassphrase],
        () => g.vaultRewrapPin(vaultJson: vaultJson, oldPassphrase: oldPassphrase, newPassphrase: newPassphrase));

Future<String> vaultEnablePrf(
        {required String vaultJson,
        required List<int> vaultPassphrase,
        required List<int> prf32,
        required String credentialId,
        required List<int> salt}) =>
    _secret(
        [vaultPassphrase, prf32],
        () => g.vaultEnablePrf(
            vaultJson: vaultJson, vaultPassphrase: vaultPassphrase, prf32: prf32, credentialId: credentialId, salt: salt));

Future<g.UaKemKey> kemEphemeral() => _loaded(g.kemEphemeral);
Future<g.UaEncapsulated> kemEncaps({required List<int> kemPk}) => _loaded(() => g.kemEncaps(kemPk: kemPk));

/// A seal to [kemPk] (authenticates no sender).
Future<g.UaSealed> seal({required List<int> kemPk, required String purpose, required List<int> aad, required List<int> pt}) =>
    _loaded(() => g.seal(kemPk: kemPk, purpose: purpose, aad: aad, pt: pt));

Future<g.UaLinkSession> linkSessionNew() => _loaded(g.linkSessionNew);
Future<g.UaKeyList> keyListNew() => _loaded(g.keyListNew);
Future<String> uasig({required String requestJson, required g.UaKeyList keys}) =>
    _loaded(() => g.uasig(requestJson: requestJson, keys: keys));

Future<List<int>> aeadSeal(
        {required int algId, required List<int> key32, required List<int> nonce12, required List<int> aad, required List<int> data}) =>
    _loaded(() => g.aeadSeal(algId: algId, key32: key32, nonce12: nonce12, aad: aad, data: data));
Future<List<int>> aeadOpen(
        {required int algId, required List<int> key32, required List<int> nonce12, required List<int> aad, required List<int> data}) =>
    _loaded(() => g.aeadOpen(algId: algId, key32: key32, nonce12: nonce12, aad: aad, data: data));
Future<List<int>> hkdfSha256({required List<int> ikm, required List<int> salt, required List<int> info, required int len}) =>
    _loaded(() => g.hkdfSha256(ikm: ikm, salt: salt, info: info, len: len));
Future<List<int>> hmacSha256({required List<int> keyBytes, required List<int> data}) =>
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
