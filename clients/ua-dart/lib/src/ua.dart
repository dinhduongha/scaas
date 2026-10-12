// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
import 'dart:convert';
import 'dart:typed_data';

import 'keccak.dart';
import 'keydata.dart';
import 'table.dart';

const domainType = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)';
const uaAuthType = 'UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)';
const registryName = 'SCaaS UARegistry';

Uint8List _utf8(String s) => Uint8List.fromList(utf8.encode(s));
Uint8List _k(List<Uint8List> p) => keccak256(p);

final Uint8List msgTag = _k([_utf8('scaas.ua.msg.v1')]);

Kind _derived(int kind) {
  final k = kindInfo(kind);
  if (k.native) throw UAError('UAKindNotDerived', k.name);
  return k;
}

String kindTagString(int kind) => 'scaas.ua.${_derived(kind).name}.v1';
Uint8List tag(int kind) => _k([_utf8(kindTagString(kind))]);

/// Throws ArgumentError for a group outside the table (a programming error; the table is closed).
String groupTagString(String group) {
  if (!groups.contains(group)) throw ArgumentError('unknown keyHash group $group');
  return 'scaas.ua.group.$group.v1';
}

Uint8List groupTag(String group) => _k([_utf8(groupTagString(group))]);

Uint8List purposeTag(String purpose) {
  if (!purposes.contains(purpose)) throw UAError('UAPurposeUnknown', purpose);
  return _k([_utf8('scaas.ua.purpose.$purpose.v1')]);
}

Uint8List _sized(Uint8List b, int n, String what) {
  if (b.length != n) throw ArgumentError('$what must be $n bytes');
  return b;
}

String _hex(Uint8List b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// keccak256(TAG(kind) ‖ keyData); no validation (see [deriveUA]). [keyData]: Uint8List or hex String.
Uint8List uaOf(int kind, Object? keyData) => _k([tag(kind), keyBytes(keyData)]);

bool inNativeSpace(Uint8List id) {
  _sized(id, 32, 'id');
  for (var i = 0; i < 12; i++) {
    if (id[i] != 0) return false;
  }
  return true;
}

/// Validate, derive, refuse an id whose top 96 bits are zero (CTR-UA-03).
Uint8List deriveUA(int kind, Object? keyData, {bool hederaNative = false}) {
  validateKeyData(kind, keyData, hederaNative: hederaNative);
  final ua = uaOf(kind, keyData);
  if (inNativeSpace(ua)) throw UAError('UAIdInNativeSpace', _hex(ua));
  return ua;
}

/// A native id left-padded to 32 bytes. [raw]: Uint8List or hex String.
Uint8List nativeId(int kind, Object? raw) {
  final k = kindInfo(kind);
  if (!k.native) throw UAError('UAKindNotNative', k.name);
  final r = keyBytes(raw);
  if (!k.lengths.contains(r.length)) throw UAError('UAKeyData', 'length');
  final id = Uint8List(32);
  id.setRange(32 - r.length, 32, r);
  return id;
}

/// keccak256(GROUP(g) ‖ canonical pubkey), null for structures. Call on validated key data.
Uint8List? keyHashOf(int kind, Object? keyData) {
  final k = _derived(kind);
  final g = k.group;
  if (g == null) return null;
  final d = keyBytes(keyData);
  final (lo, hi) = switch (kind) {
    0x0100 || 0x0101 => (0, 32),
    0x0110 || 0x0111 => (1, 33),
    0x0112 || 0x0113 => (0, 64),
    _ => (0, d.length),
  };
  if (d.length < hi) throw UAError('UAKeyData', 'length');
  return _k([groupTag(g), Uint8List.sublistView(d, lo, hi)]);
}

Uint8List uaMessage(int kind, Uint8List purpose, Uint8List digest) =>
    _k([msgTag, tag(kind), _sized(purpose, 32, 'purposeTag'), _sized(digest, 32, 'digest')]);

BigInt _id(int v) {
  if (v < 0) throw ArgumentError('chainId must be non-negative');
  return BigInt.from(v);
}

/// [chainId] is a Dart int: exact up to 2^63-1 on the VM, up to 2^53 when compiled to JS.
Uint8List chainKeyHash(int chainId) => _k([_utf8('evm:${_id(chainId)}')]);

Uint8List _word(int v) {
  var x = _id(v);
  final w = Uint8List(32);
  for (var i = 31; i >= 24; i--) {
    w[i] = (x & BigInt.from(0xff)).toInt();
    x >>= 8;
  }
  return w;
}

Uint8List _addressWord(Uint8List a) {
  final w = Uint8List(32);
  w.setRange(12, 32, _sized(a, 20, 'registry'));
  return w;
}

/// pop_digest (CTR-UA-07).
Uint8List popDigest(int chainId, Uint8List chainUid, Uint8List registry, Uint8List ua, Uint8List authRef) => _k([
      purposeTag('pop'),
      chainKeyHash(chainId),
      _sized(chainUid, 32, 'chainUid'),
      _addressWord(registry),
      _sized(ua, 32, 'ua'),
      _sized(authRef, 32, 'authRef'),
    ]);

/// The registry's EIP-712 domain ("SCaaS UARegistry", "<generation>", chainId, registry, salt = chainUid).
class Domain {
  final int generation, chainId;
  final Uint8List registry, chainUid;
  Domain(this.generation, this.chainId, this.registry, this.chainUid);
}

Uint8List uaAuthDomainSeparator(Domain d) => _k([
      _k([_utf8(domainType)]),
      _k([_utf8(registryName)]),
      _k([_utf8('${_id(d.generation)}')]),
      _word(d.chainId),
      _addressWord(d.registry),
      _sized(d.chainUid, 32, 'chainUid'),
    ]);

/// EIP-712 digest of UAAuth(ua, purpose, digest): what native signers behind the registry sign.
Uint8List uaAuthDigest(Domain d, Uint8List ua, Uint8List purpose, Uint8List digest) => _k([
      Uint8List.fromList([0x19, 0x01]),
      uaAuthDomainSeparator(d),
      _k([_k([_utf8(uaAuthType)]), _sized(ua, 32, 'ua'), _sized(purpose, 32, 'purposeTag'), _sized(digest, 32, 'digest')]),
    ]);

Uint8List memberDigest(Uint8List structureUa, Uint8List uaMsg) =>
    _k([_sized(structureUa, 32, 'structureUa'), _sized(uaMsg, 32, 'uaMsg')]);

final _idPattern = RegExp(r'^0x([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$');

/// Lower-case hex; a 32-byte id with the top 96 bits zero is written as its 20-byte native id (CTR-UA-03).
String canonicalId(String text) {
  // `$` in Dart matches only at the end (not before a trailing \n) unless multiLine is set.
  final m = _idPattern.firstMatch(text);
  if (m == null) throw UAError('UAIdFormat', text);
  final h = m.group(1)!.toLowerCase();
  return '0x${h.length == 64 && h.startsWith('0' * 24) ? h.substring(24) : h}';
}

/// u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight). Members: (kind, id, weight).
Uint8List encodeMsig(int threshold, List<(int, Uint8List, int)> members) {
  void u16(List<int> o, int v) {
    if (v < 0 || v > 0xffff) throw ArgumentError('u16 out of range');
    o..add(v >> 8)..add(v & 0xff);
  }

  final o = <int>[];
  u16(o, threshold);
  u16(o, members.length);
  for (final (kind, id, weight) in members) {
    u16(o, kind);
    o.addAll(_sized(id, 32, 'member id'));
    u16(o, weight);
  }
  return Uint8List.fromList(o);
}
