// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
import 'dart:typed_data';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show PlatformInt64;

import 'src/rust/api/ua.dart' as g;

export 'src/rust/api/ua.dart' hide kemRecordDigest, kemRecordMessage, holderPopMessage, pqzRegMessage;
export 'src/rust/frb_generated.dart' show ScaasUa;

// A KEM version is a Rust u64, and flutter_rust_bridge encodes a BigInt with toSigned(64): 2^64 + 1 would reach Rust as 1
// and -1 as 2^64 - 1. These four keep the generated signatures and refuse such a version first (UAKemVersion, as ua-dart
// and the JS reference).
BigInt _v(BigInt v) => v.isNegative || v.bitLength > 64 ? throw const g.UAError(code: 'UAKemVersion', reason: '') : v;
g.KemRecord? _k(g.KemRecord? k) {
  if (k != null) _v(k.version);
  return k;
}

/// `keccak256(KEM_RECORD_TAG ‖ ua ‖ uint256(version) ‖ keccak256(kem_pk))` (`UAKemVersion` for 0 or outside 1 ... 2^64 - 1,
/// `UAKemKeyLength` unless 1,600 bytes).
g.U8Array32 kemRecordDigest({required g.U8Array32 ua, required BigInt version, required List<int> kemPk}) =>
    g.kemRecordDigest(ua: ua, version: _v(version), kemPk: kemPk);

/// What the UA signs for a KEM record: `ua_message(kind, PURPOSE_KEM, kem_record_digest)`.
g.U8Array32 kemRecordMessage({required PlatformInt64 kind, required g.U8Array32 ua, required BigInt version, required List<int> kemPk}) =>
    g.kemRecordMessage(kind: kind, ua: ua, version: _v(version), kemPk: kemPk);

/// The portable PoP message of a registration (see the generated `holderPopMessage`); a KEM version outside 0 ... 2^64 - 1
/// is `UAKemVersion`.
g.HolderPop holderPopMessage({
  required PlatformInt64 kind,
  required g.U8Array32 ua,
  required List<int> keyData,
  Uint8List? pqzKey,
  Uint8List? pqzPop,
  Uint8List? pqzPopHash,
  g.KemRecord? kemRecord,
}) =>
    g.holderPopMessage(
        kind: kind, ua: ua, keyData: keyData, pqzKey: pqzKey, pqzPop: pqzPop, pqzPopHash: pqzPopHash, kemRecord: _k(kemRecord));

/// The message `R_REG` proves over (see the generated `pqzRegMessage`); a KEM version outside 0 ... 2^64 - 1 is `UAKemVersion`.
g.U8Array32 pqzRegMessage({required g.U8Array32 ua, required List<int> pqzKey, g.KemRecord? kemRecord}) =>
    g.pqzRegMessage(ua: ua, pqzKey: pqzKey, kemRecord: _k(kemRecord));
