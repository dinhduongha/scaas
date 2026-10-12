// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
/// An error whose [code] every implementation and the vector files share.
class UAError implements Exception {
  final String code;
  final String? reason;
  UAError(this.code, [this.reason]);
  @override
  String toString() => reason == null ? code : '$code: $reason';
}

/// One row of the kind table; [lengths] empty = variable-length key data; [group] null = none.
class Kind {
  final int number;
  final String name;
  final bool native;
  final List<int> lengths;
  final String? group;
  const Kind(this.number, this.name, this.native, this.lengths, this.group);
}

const kinds = <Kind>[
  Kind(0x0001, 'evm-eoa', true, [20], null),
  Kind(0x0002, 'evm-contract', true, [20], null),
  Kind(0x0003, 'hedera-native', true, [20], null),
  Kind(0x0010, 'solana-ed25519', true, [32], null),
  Kind(0x0011, 'stellar-account', true, [32], null),
  Kind(0x0012, 'soroban-contract', true, [32], null),
  Kind(0x0013, 'aptos-account', true, [32], null),
  Kind(0x0014, 'sui-address', true, [32], null),
  Kind(0x0015, 'cosmos-account', true, [20, 32], null),
  Kind(0x0016, 'ton-wallet', true, [32], null),
  Kind(0x0100, 'webauthn-p256', false, [96], 'p256'),
  Kind(0x0101, 'p256', false, [64], 'p256'),
  Kind(0x0102, 'ed25519', false, [32], 'ed25519'),
  Kind(0x0103, 'bip340', false, [32], 'secp256k1'),
  Kind(0x0104, 'schnorr-bn254', false, [64], 'bn254-g1'),
  Kind(0x0105, 'schnorr-bls12381', false, [128], 'bls12381-g1'),
  Kind(0x0106, 'bls12381-minsig', false, [256], 'bls12381-g2'),
  Kind(0x0107, 'bls-bn254-minsig', false, [128], 'bn254-g2'),
  Kind(0x0110, 'musig2-secp256k1', false, [], 'secp256k1'),
  Kind(0x0111, 'frost-secp256k1', false, [], 'secp256k1'),
  Kind(0x0112, 'musig2-bn254', false, [], 'bn254-g1'),
  Kind(0x0113, 'frost-bn254', false, [], 'bn254-g1'),
  Kind(0x0120, 'msig', false, [], null),
  Kind(0x0130, 'mldsa44', false, [1312], 'mldsa44'),
  Kind(0x0131, 'mldsa65', false, [1952], 'mldsa65'),
  Kind(0x0132, 'fndsa512', false, [897], 'fndsa512'),
  Kind(0x0133, 'slhdsa128s', false, [32], 'slhdsa128s'),
  Kind(0x0140, 'zether-bn254', false, [64], 'bn254-g1'),
  Kind(0x0141, 'zether-bls12381', false, [128], 'bls12381-g1'),
  Kind(0x0142, 'pqz-mlwe', false, [16384], 'pqz-mlwe'),
];

const groups = <String>[
  'p256', 'ed25519', 'secp256k1', 'bn254-g1', 'bls12381-g1', 'bls12381-g2', 'bn254-g2', 'mldsa44', 'mldsa65',
  'fndsa512', 'slhdsa128s', 'pqz-mlwe',
];

const purposes = <String>[
  'pop', 'authref', 'metatx', 'metatx-cancel', 'member', 'zether-auth', 'zether-owner', 'keyop', 'receiver-fee', 'vp',
  'vc-anchor',
];

/// Throws UAKindUnknown. [kind] must be 0..0xffff to match (a wider int is simply unknown).
Kind kindInfo(int kind) {
  for (final k in kinds) {
    if (k.number == kind) return k;
  }
  throw UAError('UAKindUnknown', '0x${kind.toRadixString(16).padLeft(4, '0')}');
}

bool _single(int k) => (k >= 0x0100 && k <= 0x0107) || (k >= 0x0110 && k <= 0x0113) || (k >= 0x0130 && k <= 0x0133);
bool isNative(int kind) => kinds.any((k) => k.number == kind && k.native);
bool isZether(int kind) => kind >= 0x0140 && kind <= 0x0142;
bool isSigning(int kind) => kind == 0x0120 || _single(kind);
bool isMember(int kind, [bool hederaNative = false]) =>
    _single(kind) || kind == 0x0001 || kind == 0x0002 || (hederaNative && kind == 0x0003);
