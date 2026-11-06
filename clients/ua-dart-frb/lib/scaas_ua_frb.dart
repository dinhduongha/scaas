// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show PlatformInt64;

import 'src/rust/api/ua.dart' as g;

export 'src/rust/api/ua.dart' hide kemRecordHash, kemRecordDigest, kemRecordMessage;
export 'src/rust/frb_generated.dart' show ScaasUa;
// ua-rs-sign T13c: the wallet. The handle types and their methods from the generated API; every entry point without a handle
// and every call that takes a secret through the facade (lib/src/wallet.dart: the load check, the caller's buffers wiped).
export 'src/rust/api/wallet.dart'
    hide
        walletGenerate,
        walletFromMnemonic,
        walletOpenVault,
        walletUnlock,
        walletSealVault,
        walletImportNativeKey,
        walletSealLabelVault,
        walletOpenLabelVault,
        walletRestoreBackup,
        walletRestoreBackupOver,
        walletRestoreBackupRollback,
        walletFromLink,
        walletBackupSeal,
        keyKemKey,
        seedBackupVerify,
        vaultNeedsRewrap,
        vaultRewrapPin,
        vaultEnablePrf,
        kemEphemeral,
        kemEncaps,
        seal,
        linkSessionNew,
        keyListNew,
        uasig,
        aeadSeal,
        aeadOpen,
        hkdfSha256,
        hmacSha256,
        webauthnChallenge,
        webauthnAssertion,
        pqzSet,
        pqzCheckSet,
        secretAlloc;
export 'src/wallet.dart';

// A KEM version is a Rust u64, and flutter_rust_bridge encodes a BigInt with toSigned(64): 2^64 + 1 would reach Rust as 1
// and -1 as 2^64 - 1. These three keep the generated signatures and refuse such a version first (UAKemVersion, as ua-dart
// and the JS reference); holderPopMessage / pqzRegMessage take no version (the register KEM key is version 0, owner 2026-10-31).
BigInt _v(BigInt v) => v.isNegative || v.bitLength > 64 ? throw const g.UAError(code: 'UAKemVersion', reason: '') : v;

/// `hashStruct(UAKemRecord{ua, version, scheme, kemPkHash})`, the `kem` word of a portable record; `(0, [])` is the zero record
/// `UAKemRecord{ua, 0, 0, 0}` (no KEM record), `(0, key)` the `register` key's record, otherwise the rules of [kemRecordDigest].
g.U8Array32 kemRecordHash({required g.U8Array32 ua, required BigInt version, required List<int> kemPk}) =>
    g.kemRecordHash(ua: ua, version: _v(version), kemPk: kemPk);

/// The typed `UAKemRecord` digest `setKemKey` signs (`UAKemVersion` for 0 or outside 1 ... 2^64 - 1,
/// `UAKemScheme` unless the first byte is 1, `UAKemKeyLength` unless 1,601 bytes).
g.U8Array32 kemRecordDigest({required g.U8Array32 ua, required BigInt version, required List<int> kemPk}) =>
    g.kemRecordDigest(ua: ua, version: _v(version), kemPk: kemPk);

/// What the UA signs for a KEM record: `ua_message(kind, PURPOSE_KEM, kem_record_digest)`.
g.U8Array32 kemRecordMessage({required PlatformInt64 kind, required g.U8Array32 ua, required BigInt version, required List<int> kemPk}) =>
    g.kemRecordMessage(kind: kind, ua: ua, version: _v(version), kemPk: kemPk);
