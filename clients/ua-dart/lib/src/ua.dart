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
  for (final s in schemes) {
    if (s.number == kind) throw UAError('UAKindNotDerived', s.name);
  }
  final k = kindInfo(kind);
  if (k.native) throw UAError('UAKindNotDerived', k.name);
  return k;
}

// tag / keyHash / message accept a kind or a scheme; id derivation and key-data validation accept kinds only
Kind _tagged(int kind) {
  for (final s in schemes) {
    if (s.number == kind) return s;
  }
  return _derived(kind);
}

String kindTagString(int kind) => 'scaas.ua.${_tagged(kind).name}.v1';
Uint8List tag(int kind) => _k([_utf8(kindTagString(kind))]);

/// Throws ArgumentError for a group outside the table (a programming error; the table is closed).
String groupTagString(String group) {
  if (!groups.contains(group)) throw ArgumentError('unknown keyHash group $group');
  return 'scaas.ua.group.$group.v1';
}

Uint8List groupTag(String group) => _k([_utf8(groupTagString(group))]);

/// The tag of a purpose version: every purpose is v1, `pop` is also v2 (UA-8: the portable PoP).
Uint8List purposeTag(String purpose, [int version = 1]) {
  if (!purposes.contains(purpose) || !(version == 1 || (purpose == 'pop' && version == 2))) {
    throw UAError('UAPurposeUnknown', purpose);
  }
  return _k([_utf8('scaas.ua.purpose.$purpose.v$version')]);
}

/// PURPOSE_POP_V2: the portable proof of possession (UA-8 P1).
final Uint8List popV2Tag = purposeTag('pop', 2);

/// `kemPk[0]` of the one enabled KEM scheme (CTR-UA-32); 2 (ML-KEM-1024 + HQC + X25519, after FIPS 207) is reserved (`UAKemScheme`).
const kemSchemeMlkem1024X25519 = 1;

/// `0x01 ‖` ML-KEM-1024 ek ‖ X25519 pk (X-Wing order): the only KEM key the registry stores (UA-8 P7).
const kemPkLength = 1601;

Uint8List _sized(Uint8List b, int n, String what) {
  if (b.length != n) throw ArgumentError('$what must be $n bytes');
  return b;
}

String _hex(Uint8List b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// keccak256(TAG(kind) ‖ keyData); no validation (see [deriveUA]). [keyData]: Uint8List or hex String.
Uint8List uaOf(int kind, Object? keyData) => _k([tag(_derived(kind).number), keyBytes(keyData)]);

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
  final k = _tagged(kind);
  final g = k.group;
  if (g == null) return null;
  final d = keyBytes(keyData);
  final (lo, hi) = switch (kind) {
    0x0100 || 0x0101 || 0x0108 => (0, 32),
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

bool _isZero(Uint8List b) => b.every((x) => x == 0);
bool _same(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

String _kindHex(int kind) => '0x${kind.toRadixString(16).padLeft(4, '0')}';

/// The portable EIP-712 domain (typed-signing TS-D1): name and version only, no chainId / verifyingContract / salt (the
/// records register a UA on every chain, CTR-UA-07).
const portableDomainType = 'EIP712Domain(string name,string version)';
const portableDomainName = 'SCaaS UA Portable';
const portableDomainVersion = '1';

/// `DS_P = keccak256(keccak256(type) ‖ keccak256(name) ‖ keccak256(version))`.
final Uint8List portableDomainSeparator =
    _k([for (final x in [portableDomainType, portableDomainName, portableDomainVersion]) _k([_utf8(x)])]);

const _kemType = 'UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)';
const _recordType = 'UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)';
const _pqzKeyType = 'UAPqzKey(bytes32 ua,bytes32 pqzKeyHash)';

/// The EIP-712 `encodeType` of each portable struct (primary, then the referenced types sorted by name).
const portableTypes = {
  'UAKemRecord': _kemType,
  'UAPortableRecord': _recordType + _kemType,
  'UARegistration': 'UARegistration(UAPortableRecord record,bytes32 pqzPopHash)' + _kemType + _recordType,
  'UAPqzKey': _pqzKeyType,
  'UAPqzKeyRecord': 'UAPqzKeyRecord(UAPqzKey key,bytes32 pqzPopHash)' + _pqzKeyType,
};

Uint8List portableTypehash(String name) =>
    _k([_utf8(portableTypes[name] ?? (throw ArgumentError('not a portable struct: $name')))]);

/// `keccak256(typehash(name) ‖ words)`: every portable field is a 32-byte word or a nested struct hash.
Uint8List hashStruct(String name, List<Uint8List> words) =>
    _k([portableTypehash(name), for (final w in words) _sized(w, 32, 'word')]);

/// `keccak256(0x1901 ‖ DS_P ‖ structHash)`: what `eth_signTypedData_v4` returns for a portable record.
Uint8List _typed(Uint8List structHash) => _k([Uint8List.fromList([0x19, 0x01]), portableDomainSeparator, structHash]);

final _two64 = BigInt.one << 64;

/// `hashStruct(UAKemRecord{ua, version, scheme = kemPk[0], kemPkHash = keccak256(kemPk)})`: version 1 … 2^64 − 1 (a [BigInt]:
/// a Dart int cannot hold it on the VM or in JS), `kemPk` = scheme byte ‖ key (`UAKemScheme` for an id other than 1). No
/// record (version 0, no key) is the zero record `UAKemRecord{ua, 0, 0, 0}` (TS-D2): the `kem` word of a `UAPortableRecord`.
Uint8List kemRecordHash(Uint8List ua, BigInt version, Uint8List kemPk) {
  if (version == BigInt.zero && kemPk.isEmpty) return hashStruct('UAKemRecord', [ua, Uint8List(32), Uint8List(32), Uint8List(32)]);
  if (version < BigInt.one || version >= _two64) throw UAError('UAKemVersion', '$version');
  if (kemPk.isNotEmpty && kemPk[0] != kemSchemeMlkem1024X25519) throw UAError('UAKemScheme', '${kemPk[0]}');
  if (kemPk.length != kemPkLength) throw UAError('UAKemKeyLength', '${kemPk.length}');
  final v = Uint8List(32);
  var x = version;
  for (var i = 31; i >= 24; i--) {
    v[i] = (x & BigInt.from(0xff)).toInt();
    x >>= 8;
  }
  return hashStruct('UAKemRecord', [ua, v, _word(kemPk[0]), _k([kemPk])]);
}

/// The typed `UAKemRecord` digest `setKemKey` signs (a real record: version 0 is `UAKemVersion`).
Uint8List kemRecordDigest(Uint8List ua, BigInt version, Uint8List kemPk) {
  if (version == BigInt.zero) throw UAError('UAKemVersion', '0');
  return _typed(kemRecordHash(ua, version, kemPk));
}

/// `hashStruct(UAPortableRecord{ua, kind, pqzKeyHash, kem})`; [kemRecordHash] = [kemRecordHash] (the zero record's when none).
Uint8List portableRecordHash(Uint8List ua, int kind, Uint8List pqzKeyHash, Uint8List kemRecordHash) =>
    hashStruct('UAPortableRecord', [ua, _word(kind), pqzKeyHash, kemRecordHash]);

/// The typed `UAPortableRecord`: what `R_REG` proves over at `register` / the first `storePqzPop`.
Uint8List portableRecordDigest(Uint8List ua, int kind, Uint8List pqzKeyHash, Uint8List kemRecordHash) =>
    _typed(portableRecordHash(ua, kind, pqzKeyHash, kemRecordHash));

/// The typed `UARegistration{record, pqzPopHash}`: what the signer's `pop` signs under `uaMessage(kind, POP_V2, ·)` (and a
/// native msig member signs itself, TS-D4).
Uint8List registrationDigest(Uint8List ua, int kind, Uint8List pqzKeyHash, Uint8List kemRecordHash, Uint8List pqzPopHash) =>
    _typed(hashStruct('UARegistration', [portableRecordHash(ua, kind, pqzKeyHash, kemRecordHash), pqzPopHash]));

/// What the UA signs for a KEM record: `uaMessage(kind, PURPOSE_KEM, kemRecordDigest)`.
Uint8List kemRecordMessage(int kind, Uint8List ua, BigInt version, Uint8List kemPk) =>
    uaMessage(kind, purposeTag('kem'), kemRecordDigest(ua, version, kemPk));

/// A KEM record attribute; `null` or `(0, empty)` = absent.
typedef Kem = (BigInt version, Uint8List pk);

Uint8List _kemHash(Uint8List ua, Kem? kem) => kemRecordHash(ua, kem?.$1 ?? BigInt.zero, kem?.$2 ?? Uint8List(0));

/// A PQZ / KEM holder: a single-key PQ kind, or an `msig` whose key data is PQ-eligible (malformed key data is UAKeyData).
bool _holds(int kind, Uint8List keyData) {
  if (isPqzHolder(kind)) return true;
  return kind == 0x0120 && keyData.isNotEmpty && msigPqzEligible(keyData);
}

/// `keyHashOf(0x0142, pqzKey)`; a key of no parameter set's length is UAKeyData.
Uint8List _pqzKeyHashOf(Object? pqzKey) {
  final k = keyBytes(pqzKey);
  if (!pqzKeyLengths.contains(k.length)) throw UAError('UAKeyData', 'PQZ key length');
  return keyHashOf(0x0142, k)!;
}

/// The proof hash from the proof bytes and / or the hash (absent = zeros; an empty or all-zero hash is absent); both given and
/// different is UAPqzPopHash, and so is `keccak256("")` (an empty proof is no proof).
Uint8List _proofHashOf(Uint8List? pqzPop, Uint8List? pqzPopHash) {
  final proof = pqzPop != null && pqzPop.isNotEmpty ? _k([pqzPop]) : null;
  if (pqzPopHash != null && pqzPopHash.isNotEmpty && pqzPopHash.length != 32) {
    throw UAError('UAPqzPopHash', 'hash must be 32 bytes');
  }
  final given = pqzPopHash != null && pqzPopHash.isNotEmpty && !_isZero(pqzPopHash) ? pqzPopHash : null;
  if (proof != null && given != null && !_same(proof, given)) throw UAError('UAPqzPopHash', 'proof and hash differ');
  final h = proof ?? given ?? Uint8List(32);
  if (_same(h, _k([Uint8List(0)]))) throw UAError('UAPqzPopHash', 'empty proof');
  return h;
}

/// The portable PoP of a registration (UA-8 P1, P2; typed-signing TS-D3), as [holderPopMessage] returns it. `kemRecordHash`
/// is hashStruct(UAKemRecord) (the zero record's when none), `portableRecordDigest` / `registrationDigest` the typed records.
/// `message` is `uaMessage(kind, POP_V2, registrationDigest)`: what the signer's `pop` signs (every kind). `memberDigest`
/// (msig only, else null) is `memberDigest(ua, message)`, what each derived member signs under `member`; a native member signs
/// `registrationDigest` itself (eth_signTypedData_v4, TS-D4).
typedef HolderPop = ({
  Uint8List pqzKeyHash,
  Uint8List pqzPopHash,
  Uint8List kemRecordHash,
  Uint8List portableRecordDigest,
  Uint8List registrationDigest,
  Uint8List message,
  Uint8List? memberDigest,
});

/// The portable PoP message of a registration. Attributes: [pqzKey] with its proof [pqzPop] (or only its hash [pqzPopHash]; a
/// relayer may hold only that) and the initial KEM record [kem] (`version >= 1`, key); null / `(0, empty)` = absent. Only
/// holders may carry them (UAPqzHolder, UAKemHolder; an `msig` needs [keyData] to show it is PQ-eligible); a PQZ key always
/// comes with its proof hash and only with it (UAPqzPopHash).
HolderPop holderPopMessage(int kind, Uint8List ua,
    {Uint8List? keyData, Object? pqzKey, Uint8List? pqzPop, Uint8List? pqzPopHash, Kem? kem}) {
  final hasKey = pqzKey != null && keyBytes(pqzKey).isNotEmpty;
  final hasKem = kem != null && (kem.$1 != BigInt.zero || kem.$2.isNotEmpty);
  if ((hasKey || hasKem) && !_holds(kind, keyData ?? Uint8List(0))) {
    throw hasKey
        ? UAError('UAPqzHolder', '${_kindHex(kind)} may not hold a PQZ key')
        : UAError('UAKemHolder', '${_kindHex(kind)} may not hold a KEM key');
  }
  final popHash = _proofHashOf(pqzPop, pqzPopHash);
  if (hasKey != !_isZero(popHash)) throw UAError('UAPqzPopHash', 'a PQZ key comes with its proof hash and only with it');
  final kh = hasKey ? _pqzKeyHashOf(pqzKey) : Uint8List(32);
  final kr = _kemHash(ua, kem);
  final reg = registrationDigest(ua, kind, kh, kr, popHash);
  final msg = uaMessage(kind, popV2Tag, reg);
  return (
    pqzKeyHash: kh,
    pqzPopHash: popHash,
    kemRecordHash: kr,
    portableRecordDigest: portableRecordDigest(ua, kind, kh, kr),
    registrationDigest: reg,
    message: msg,
    memberDigest: kind == 0x0120 ? memberDigest(ua, msg) : null,
  );
}

/// The message `R_REG` proves over: `uaMessage(0x0142, POP_V2, portableRecordDigest(ua, kind, keyHash(0x0142, pqzKey),
/// kemRecordHash))`, [kind] the registering kind (TS-D3); [kem] null / `(0, empty)` = no KEM record.
Uint8List pqzRegMessage(int kind, Uint8List ua, Object? pqzKey, [Kem? kem]) {
  final kr = _kemHash(ua, kem); // the KEM record first, as ua-rs and the JS
  return uaMessage(0x0142, popV2Tag, portableRecordDigest(ua, kind, _pqzKeyHashOf(pqzKey), kr));
}

/// The typed `UAPqzKey{ua, pqzKeyHash}`: what a later PQZ key's `R_REG` proves over (no proof hash: no cycle).
Uint8List pqzKeyDigest(Uint8List ua, Uint8List pqzKeyHash) => _typed(hashStruct('UAPqzKey', [ua, pqzKeyHash]));

/// The typed `UAPqzKeyRecord{UAPqzKey{ua, pqzKeyHash}, pqzPopHash}`: what `setPqzKey`'s signature signs under
/// `uaMessage(kind, PURPOSE_PQZ_KEY, ·)` (and a native msig member signs itself, TS-D4).
Uint8List pqzKeyRecordDigest(Uint8List ua, Uint8List pqzKeyHash, Uint8List pqzPopHash) =>
    _typed(hashStruct('UAPqzKeyRecord', [hashStruct('UAPqzKey', [ua, pqzKeyHash]), pqzPopHash]));

/// The PQZ key record of `setPqzKey` (ruling A1-I1), see [pqzKeyRecordMessage]. [message] is what the UA signs,
/// [pqzRegMessage] what the key's `R_REG` proves over.
typedef PqzKeyRecord = ({
  Uint8List pqzKeyHash,
  Uint8List pqzPopHash,
  Uint8List pqzKeyDigest,
  Uint8List recordDigest,
  Uint8List message,
  Uint8List pqzRegMessage,
  Uint8List? memberDigest,
});

/// The signed, portable, write-once PQZ key record: accepted only by a registration without a PQZ key ([alreadySet] = it has
/// one: UAPqzKeySet). The holder rules of [holderPopMessage]; the key and its proof hash are both required.
PqzKeyRecord pqzKeyRecordMessage(int kind, Uint8List ua, Uint8List keyData, Object? pqzKey,
    {Uint8List? pqzPop, Uint8List? pqzPopHash, bool alreadySet = false}) {
  if (!_holds(kind, keyData)) throw UAError('UAPqzHolder', '${_kindHex(kind)} may not hold a PQZ key');
  if (alreadySet) throw UAError('UAPqzKeySet', 'write-once');
  final kh = _pqzKeyHashOf(pqzKey);
  final popHash = _proofHashOf(pqzPop, pqzPopHash);
  if (_isZero(popHash)) throw UAError('UAPqzPopHash', 'a PQZ key record needs its proof hash');
  final kd = pqzKeyDigest(ua, kh);
  final rd = pqzKeyRecordDigest(ua, kh, popHash);
  final tag = purposeTag('pqz-key');
  final msg = uaMessage(kind, tag, rd);
  return (
    pqzKeyHash: kh,
    pqzPopHash: popHash,
    pqzKeyDigest: kd,
    recordDigest: rd,
    message: msg,
    pqzRegMessage: uaMessage(0x0142, tag, kd),
    memberDigest: kind == 0x0120 ? memberDigest(ua, msg) : null,
  );
}

/// POP_V2, KEM, PQZ_KEY: the only purposes where a code-less native `msig` member signs the record's typed digest itself
/// (eth_signTypedData_v4, 65-byte r ‖ s ‖ v; a contract member answers ERC-1271 over it; TS-D4); every other purpose stays
/// UAAuth (CTR-MTX-14).
bool isPortablePurpose(Uint8List tag) =>
    [popV2Tag, purposeTag('kem'), purposeTag('pqz-key')].any((t) => _same(t, tag));

/// True when the msig members outside kinds 0x0130-0x0133 weigh less than its threshold (CTR-PQZ-12).
bool msigPqzEligible(Object? keyData) {
  final d = keyBytes(keyData);
  if (d.length < 4 || d.length != 4 + 36 * ((d[2] << 8) | d[3])) throw UAError('UAKeyData', 'length');
  var classical = 0;
  for (var o = 4; o < d.length; o += 36) {
    final k = (d[o] << 8) | d[o + 1];
    if (k < 0x0130 || k > 0x0133) classical += (d[o + 34] << 8) | d[o + 35];
  }
  return classical < ((d[0] << 8) | d[1]);
}

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

/// EIP-712 digest of UAAuth(ua, purpose, digest): what native signers behind the registry sign, except that
/// under the three portable purposes ([isPortablePurpose]) a code-less native msig member signs the record's typed digest
/// instead (CTR-MTX-14, TS-D4).
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
