// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas_ua against smartcontracts/vectors/ua/{kinds,structures,portable}.json. The files are found by walking up from the
// current directory (the package dir under `dart test`) to <ancestor>/smartcontracts/vectors/ua, or from the
// directory named by $UA_VECTORS. Works on the VM and under `dart test -p node` (chain id 2^40+7 needs > 32 bits).
import 'dart:convert';
import 'dart:typed_data';

import 'package:scaas_ua/scaas_ua.dart';
import 'package:test/test.dart';

import 'host_io.dart' if (dart.library.js_interop) 'host_node.dart';

String? _find(String name) {
  final e = env('UA_VECTORS');
  if (e != null) return readIfExists('$e/$name');
  var dir = cwd();
  while (true) {
    final t = readIfExists('$dir/smartcontracts/vectors/ua/$name');
    if (t != null) return t;
    final i = dir.lastIndexOf('/');
    if (i <= 0) return null;
    dir = dir.substring(0, i);
  }
}

dynamic _load(String name) =>
    jsonDecode(_find(name) ?? (throw StateError('smartcontracts/vectors/ua/$name not found above ${cwd()}; set UA_VECTORS')));

Uint8List _b(Object? s) {
  final h = (s as String).substring(2);
  return Uint8List.fromList([for (var i = 0; i < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)]);
}

String _hx(Uint8List b) => '0x${b.map((x) => x.toRadixString(16).padLeft(2, '0')).join()}';
int _kind(Map r) => r['kind'] as int;
UAError _err(void Function() f) {
  try {
    f();
  } on UAError catch (e) {
    return e;
  }
  throw TestFailure('expected a UAError');
}

/// A KEM key of [n] bytes: the scheme byte, then zeros.
Uint8List _kem(int n, [int scheme = 1]) => Uint8List(n)..[0] = scheme;

Uint8List _utf8(String s) => Uint8List.fromList(utf8.encode(s));

Uint8List _word(int v) {
  final w = Uint8List(32);
  var x = BigInt.from(v);
  for (var i = 31; i >= 24; i--) {
    w[i] = (x & BigInt.from(0xff)).toInt();
    x >>= 8;
  }
  return w;
}

/// EIP-712 encodeType from a wallet's typed-data JSON: primary, then the referenced types sorted by name.
String _encodeType(Map types, String name) {
  final deps = <String>{}, todo = [name];
  while (todo.isNotEmpty) {
    for (final f in (types[todo.removeLast()] as List).cast<Map>()) {
      final ft = f['type'] as String;
      if (types.containsKey(ft) && deps.add(ft)) todo.add(ft);
    }
  }
  String one(String n) => '$n(${(types[n] as List).cast<Map>().map((f) => '${f['type']} ${f['name']}').join(',')})';
  return one(name) + ((deps..remove(name)).toList()..sort()).map(one).join();
}

/// An independent EIP-712 hashStruct over the field types the portable records use.
Uint8List _hashStructJson(Map types, String name, Map data) {
  final enc = <Uint8List>[keccak256([_utf8(_encodeType(types, name))])];
  for (final f in (types[name] as List).cast<Map>()) {
    final ft = f['type'] as String, v = data[f['name']];
    enc.add(switch (ft) {
      _ when types.containsKey(ft) => _hashStructJson(types, ft, v as Map),
      'string' => keccak256([_utf8(v as String)]),
      'bytes32' => _b(v),
      'uint8' || 'uint16' || 'uint64' => _word(v as int),
      _ => throw StateError('field type $ft'),
    });
  }
  return keccak256(enc);
}

String _hashTypedData(Map td, [String? primary, Map? message]) {
  final t = td['types'] as Map;
  return _hx(keccak256([
    Uint8List.fromList([0x19, 0x01]),
    _hashStructJson(t, 'EIP712Domain', td['domain'] as Map),
    _hashStructJson(t, primary ?? td['primaryType'] as String, message ?? td['message'] as Map),
  ]));
}

void main() {
  final k = _load('kinds.json') as Map;

  test('table, groups, purposes, constants', () {
    final rows = k['kinds'] as List;
    expect(kinds.length, rows.length);
    for (final r in rows.cast<Map>()) {
      final n = _kind(r), info = kindInfo(n);
      expect(info.name, r['name']);
      expect(info.native, r['native']);
      expect(info.lengths, (r['lengths'] as List).cast<int>());
      expect(info.group, r['group']);
      expect(isSigning(n), r['signing']);
      expect(isZether(n), r['zether']);
      expect(isMember(n), r['member']);
      expect(isMember(n, true), r['memberHedera']);
      expect(isPqzHolder(n), r['pqzHolder']);
      if (info.native) {
        expect(_err(() => tag(n)).code, 'UAKindNotDerived');
        continue;
      }
      expect(kindTagString(n), r['tag']);
      expect(_hx(tag(n)), r['TAG']);
    }
    final sch = (k['schemes'] as List).cast<Map>();
    expect(schemes.length, sch.length);
    for (var i = 0; i < sch.length; i++) {
      final s = sch[i], n = _kind(s);
      expect([schemes[i].number, schemes[i].name, schemes[i].group, schemes[i].lengths], [n, s['name'], s['group'], s['lengths']]);
      expect(kindTagString(n), s['tag']);
      expect(_hx(tag(n)), s['TAG']);
      expect(_err(() => uaOf(n, Uint8List(16384))).code, 'UAKindNotDerived');
      expect(_err(() => validateKeyData(n, Uint8List(16384))).code, 'UAKindNotDerived');
    }
    expect(_hx(keyHashOf(0x0142, _b(k['pqzKey']))!), k['pqzKeyHash']);
    for (final r in (k['groups'] as List).cast<Map>()) {
      expect(groupTagString(r['group']), r['tag']);
      expect(_hx(groupTag(r['group'])), r['GROUP']);
    }
    final pur = (k['purposes'] as List).cast<Map>();
    expect(pur.length, purposes.length + 1); // `pop` has v1 and v2
    for (final r in pur) {
      expect(_hx(purposeTag(r['purpose'], r['version'])), r['purposeTag']);
    }
    for (final bad in <(String, int)>[('metatx', 2), ('pop', 3), ('pop', 0), ('nope', 1)]) {
      expect(_err(() => purposeTag(bad.$1, bad.$2)).code, 'UAPurposeUnknown');
    }
    final c = k['constants'] as Map;
    expect(_hx(msgTag), c['MSG_TAG']);
    expect(_hx(purposeTag('pop')), c['POP_TAG']);
    expect(_hx(keccak256([Uint8List.fromList(utf8.encode(domainType))])), c['DOMAIN_TYPEHASH']);
    expect(_hx(keccak256([Uint8List.fromList(utf8.encode(uaAuthType))])), c['UAAUTH_TYPEHASH']);
    expect(_hx(keccak256([Uint8List.fromList(utf8.encode(registryName))])), c['NAME_HASH']);
  });

  test('valid rows', () {
    for (final r in (k['valid'] as List).cast<Map>()) {
      final d = _b(r['keyData']);
      expect(_hx(deriveUA(_kind(r), d, hederaNative: r['hederaNative'])), r['ua']);
      expect(deriveUA(_kind(r), r['keyData'], hederaNative: r['hederaNative']), deriveUA(_kind(r), d, hederaNative: r['hederaNative']));
      final h = keyHashOf(_kind(r), d);
      expect(h == null ? null : _hx(h), r['keyHash']);
    }
  });

  test('invalid rows', () {
    for (final r in (k['invalid'] as List).cast<Map>()) {
      final e = _err(() => validateKeyData(_kind(r), _b(r['keyData']), hederaNative: r['hederaNative']));
      expect(e.code, r['error'], reason: '${_kind(r)} ${r['reason']}: $e');
    }
  });

  test('natives, nativeInvalid, nativeSpace, canonicalIds', () {
    for (final r in (k['natives'] as List).cast<Map>()) {
      final id = nativeId(_kind(r), _b(r['raw']));
      expect(_hx(id), r['id']);
      expect(canonicalId(_hx(id)), r['canonical']);
    }
    for (final r in (k['nativeInvalid'] as List).cast<Map>()) {
      expect(_err(() => nativeId(_kind(r), _b(r['raw']))).code, r['error']);
    }
    for (final r in (k['nativeSpace'] as List).cast<Map>()) {
      expect(inNativeSpace(_b(r['id'])), r['inNativeSpace']);
    }
    for (final r in (k['canonicalIds'] as List).cast<Map>()) {
      if (r.containsKey('canonical')) {
        expect(canonicalId(r['input']), r['canonical']);
      } else {
        expect(_err(() => canonicalId(r['input'])).code, r['error']);
      }
    }
  });

  test('messages', () {
    for (final r in (k['messages'] as List).cast<Map>()) {
      // each row carries its purpose `version` (A4-c1)
      final p = purposeTag(r['purpose'], r['version']);
      expect(_hx(p), r['purposeTag']);
      expect(_hx(uaMessage(_kind(r), p, _b(r['digest']))), r['uaMsg']);
    }
  });

  test('structures', () {
    final s = _load('structures.json') as Map;
    final ctx = s['contexts'] as Map;
    for (final p in (s['pop'] as List).cast<Map>()) {
      final ua = _b(p['ua']), h = _b(p['pqzKeyHash']), kr = _b(p['kemRecordHash']);
      expect(_hx(portableRecordDigest(ua, _kind(p), h, kr)), p['portableRecordDigest']);
      expect(_hx(registrationDigest(ua, _kind(p), h, kr, _b(p['pqzPopHash']))), p['registrationDigest']);
    }
    final pqzKey = _b(k['pqzKey']);
    final proof = Uint8List.fromList(List.filled(32, 7));
    for (final r in (s['pqzReg'] as List).cast<Map>()) {
      final ua = _b(r['ua']), kem = _b(r['kemRecordHash']), h = keyHashOf(0x0142, pqzKey)!;
      expect(_hx(h), r['pqzKeyHash']);
      final portable = portableRecordDigest(ua, _kind(r), h, kem);
      expect(_hx(portable), r['portableRecordDigest']);
      expect(_hx(uaMessage(0x0142, popV2Tag, portable)), r['pqzRegMessage']);
      // the row's KEM record hash is opaque (a label); the real records are in portable.json
      if (_hx(kem) != _hx(kemRecordHash(ua, BigInt.zero, Uint8List(0)))) continue;
      expect(_hx(pqzRegMessage(_kind(r), ua, pqzKey)), r['pqzRegMessage']);
      final got = holderPopMessage(_kind(r), ua, pqzKey: pqzKey, pqzPopHash: proof);
      expect([_hx(got.pqzKeyHash), _hx(got.portableRecordDigest)], [r['pqzKeyHash'], r['portableRecordDigest']]);
      for (final bad in [0x0101, 0x0133]) {
        expect(_err(() => holderPopMessage(bad, ua, pqzKey: pqzKey, pqzPopHash: proof)).code, 'UAPqzHolder');
      }
    }
    for (final r in (s['pqzMsig'] as List).cast<Map>()) {
      final d = _b(r['keyData']);
      expect(msigPqzEligible(d), r['eligible'], reason: r['reason'] as String);
      expect(_hx(deriveUA(0x0120, d)), r['ua']);
      final h = r['eligible'] as bool ? _b(k['pqzKeyHash']) : Uint8List(32), u = _b(r['ua']);
      expect(_hx(portableRecordDigest(u, 0x0120, h, kemRecordHash(u, BigInt.zero, Uint8List(0)))), r['portableRecordDigest']);
    }
    for (final a in (s['uaAuth'] as List).cast<Map>()) {
      final c = ctx[a['context']] as Map;
      final d = Domain(a['generation'] as int, c['chainId'] as int, _b(c['registry']), _b(c['chainUid']));
      expect(_hx(uaAuthDomainSeparator(d)), a['domainSeparator']);
      expect(_hx(uaAuthDigest(d, _b(a['ua']), _b(a['purposeTag']), _b(a['digest']))), a['uaAuthDigest']);
    }
    for (final m in (s['member'] as List).cast<Map>()) {
      expect(_hx(memberDigest(_b(m['structureUa']), _b(m['uaMsg']))), m['memberDigest']);
    }
  });

  test('malformed input is a UAError, never a RangeError', () {
    for (final bad in <Object?>[null, 5, [1, 2], 'zz', 'abc', Uint8List(0), Uint8List(3)]) {
      for (final n in kinds.where((x) => !x.native).map((x) => x.number)) {
        final e = _err(() => validateKeyData(n, bad));
        expect(e.code, 'UAKeyData');
      }
    }
    expect(_err(() => validateKeyData(0x0102, [1, 2])).reason, 'type');
    // variable-length kinds truncated at every length up to a few bytes
    for (final n in [0x0110, 0x0111, 0x0112, 0x0113, 0x0120]) {
      for (var len = 0; len < 80; len++) {
        _err(() => validateKeyData(n, Uint8List(len)));
      }
    }
    expect(_err(() => validateKeyData(0xffff, Uint8List(1))).code, 'UAKindUnknown');
    expect(_err(() => canonicalId('0x${'a' * 40}\n')).code, 'UAIdFormat');
  });

  final p = _load('portable.json') as Map;
  final regs = (p['registrations'] as List).cast<Map>();
  Map byKey(List<Map> rs, String key, Object? v) => rs.firstWhere((r) => r[key] == v, orElse: () => throw StateError('no $key = $v'));
  String? hxn(Uint8List? b) => b == null ? null : _hx(b);

  /// The holder call over a registration row's attrs (and the proof bytes, or only their hash).
  HolderPop register(Map row, {bool hashOnly = false}) {
    final a = row['attrs'] as Map;
    final key = _b(a['pqzKey']), pop = _b(row['pqzPop']), hash = _b(a['pqzPopHash']), pk = _b(a['kemPk']);
    final ver = BigInt.from(a['kemVersion'] as int);
    return holderPopMessage(_kind(row), _b(row['ua']),
        keyData: _b(row['keyData']),
        pqzKey: key.isEmpty ? null : key,
        pqzPop: hashOnly || pop.isEmpty ? null : pop,
        pqzPopHash: hash.every((x) => x == 0) ? null : hash,
        kem: ver == BigInt.zero && pk.isEmpty ? null : (ver, pk));
  }

  // TS-D1: the domain separator and the five typehashes pinned and re-derived; every row's typedData (the JSON
  // eth_signTypedData_v4 signs) hashes to its digest and its message carries the row's words (kind included).
  test('portable typed', () {
    final ty = p['typed'] as Map, dom = ty['domain'] as Map, types = ty['types'] as Map;
    const ds = '0x9a2c390d4dc940ccdb5fa6b21e673e87159bdd99aeef22ea791bcea9efc64ca1';
    expect([_hx(portableDomainSeparator), ty['domainSeparator']], [ds, ds]);
    expect([portableDomainType, portableDomainName, portableDomainVersion],
        ['EIP712Domain(string name,string version)', 'SCaaS UA Portable', '1']);
    expect([ty['domainType'], dom['name'], dom['version']], [portableDomainType, portableDomainName, portableDomainVersion]);
    expect(_hx(keccak256([for (final x in [portableDomainType, portableDomainName, portableDomainVersion]) keccak256([_utf8(x)])])), ds);
    const pinned = {
      'UAKemRecord': '0x0ab7989827627b89c268e88a0a0b06b62aefa70b0a466014931ca44acfa9a201',
      'UAPortableRecord': '0x0c1553cfab3c35326558484df79963dced75ead85272d2a85985f264757bfe7f',
      'UARegistration': '0xc78b548ceb2fadf1f0a895f79f88b517327c120f0f9ab345f02981441048c87e',
      'UAPqzKey': '0x827d90728b100bc830d06b04dd2b9b5f7853adaa05502b4082875f881d925a00',
      'UAPqzKeyRecord': '0xaba20a80603724f71232573a76d2506ae38f60f39ea9cd8e71f4b64775dd7567',
    };
    expect([types.length, portableTypes.length], [pinned.length, pinned.length]);
    pinned.forEach((name, th) {
      expect([_hx(portableTypehash(name)), (types[name] as Map)['typehash'], (types[name] as Map)['type']], [th, th, portableTypes[name]],
          reason: name);
    });
    var n = 0;
    for (final r in regs) {
      final td = r['typedData'] as Map, tt = td['types'] as Map, name = r['name'] as String;
      final ua = _b(r['ua']), kind = _kind(r), a = r['attrs'] as Map;
      expect(td['primaryType'], 'UARegistration', reason: name);
      expect(_hashTypedData(td), r['registrationDigest'], reason: name);
      for (final x in ['UARegistration', 'UAPortableRecord', 'UAKemRecord']) {
        expect(_encodeType(tt, x), portableTypes[x], reason: x);
      }
      final rec = (td['message'] as Map)['record'] as Map, kem = rec['kem'] as Map;
      expect([rec['kind'], rec['ua'], kem['ua'], rec['pqzKeyHash']], [kind, r['ua'], r['ua'], r['pqzKeyHash']], reason: name);
      expect((td['message'] as Map)['pqzPopHash'], a['pqzPopHash'], reason: name);
      final pk = _b(a['kemPk']), v = a['kemVersion'] as int;
      expect(_hx(_hashStructJson(tt, 'UAKemRecord', kem)), r['kemRecordHash'], reason: name);
      expect(_hx(kemRecordHash(ua, BigInt.from(v), pk)), r['kemRecordHash'], reason: name);
      // TS-D2: no KEM record = {ua, 0, 0, 0}
      expect([kem['version'], kem['scheme'], kem['kemPkHash']],
          pk.isEmpty ? [0, 0, _hx(Uint8List(32))] : [v, pk[0], _hx(keccak256([pk]))], reason: name);
      final h = _b(r['pqzKeyHash']), kr = _b(r['kemRecordHash']);
      expect(_hx(portableRecordHash(ua, kind, h, kr)), _hx(_hashStructJson(tt, 'UAPortableRecord', rec)), reason: name);
      expect(_hashTypedData(td, 'UAPortableRecord', rec), r['portableRecordDigest'], reason: name); // the R_REG record alone
      expect(_hx(portableRecordDigest(ua, kind, h, kr)), r['portableRecordDigest'], reason: name);
      n++;
    }
    for (final r in (p['kemRecords'] as List).cast<Map>()) {
      final td = r['typedData'] as Map, m = td['message'] as Map, ua = _b(r['ua']), pk = _b(r['kemPk']), v = r['version'] as int;
      expect(td['primaryType'], 'UAKemRecord');
      expect(_hashTypedData(td), r['digest'], reason: r['id'] as String);
      expect(_hx(_hashStructJson(td['types'] as Map, 'UAKemRecord', m)), r['structHash']);
      expect(_hx(kemRecordHash(ua, BigInt.from(v), pk)), r['structHash']);
      expect([m['version'], m['scheme'], m['ua']], [v, pk[0], r['ua']]);
      n++;
    }
    for (final r in (p['pqzKeyRecords'] as List).cast<Map>()) {
      final td = r['typedData'] as Map, m = td['message'] as Map, key = m['key'] as Map;
      final ua = _b(r['ua']), h = _b(r['pqzKeyHash']), ph = _b(r['pqzPopHash']);
      expect(td['primaryType'], 'UAPqzKeyRecord');
      expect(_hashTypedData(td), r['recordDigest'], reason: r['name'] as String);
      expect([key['ua'], key['pqzKeyHash'], m['pqzPopHash']], [r['ua'], r['pqzKeyHash'], r['pqzPopHash']]);
      expect(_hx(pqzKeyRecordDigest(ua, h, ph)), r['recordDigest']);
      expect(_hashTypedData(td, 'UAPqzKey', key), r['pqzKeyDigest']);
      expect(_hx(pqzKeyDigest(ua, h)), r['pqzKeyDigest']);
      n++;
    }
    expect(n, regs.length + (p['kemRecords'] as List).length + (p['pqzKeyRecords'] as List).length);
  });

  test('portable', () {
    final t = p['tags'] as Map;
    String tg(String n) => (t[n] as Map)['hash'] as String;
    expect(_hx(popV2Tag), tg('PURPOSE_POP_V2'));
    expect(_hx(purposeTag('kem')), tg('PURPOSE_KEM'));
    expect(_hx(purposeTag('pqz-key')), tg('PURPOSE_PQZ_KEY'));
    expect(t.containsKey('KEM_RECORD_TAG') || t.containsKey('PQZ_KEY_RECORD_TAG'), isFalse); // raw record tags are legacy (TS-D3)
    var n = 0, withPqz = 0, msigs = 0;
    for (final r in regs) {
      final ua = _b(r['ua']), name = r['name'] as String;
      expect(_hx(uaOf(_kind(r), _b(r['keyData']))), r['ua'], reason: name);
      for (final hashOnly in [false, true]) {
        final h = register(r, hashOnly: hashOnly);
        expect(_hx(h.pqzKeyHash), r['pqzKeyHash'], reason: name);
        expect(_hx(h.pqzPopHash), (r['attrs'] as Map)['pqzPopHash'], reason: name);
        expect(_hx(h.kemRecordHash), r['kemRecordHash'], reason: name);
        expect(_hx(h.portableRecordDigest), r['portableRecordDigest'], reason: name);
        expect(_hx(h.registrationDigest), r['registrationDigest'], reason: name);
        expect(_hx(h.message), r['popMessage'], reason: name);
        expect(_hx(portableRecordDigest(ua, _kind(r), h.pqzKeyHash, h.kemRecordHash)), _hx(h.portableRecordDigest));
        expect(_hx(registrationDigest(ua, _kind(r), h.pqzKeyHash, h.kemRecordHash, h.pqzPopHash)), _hx(h.registrationDigest));
        expect(_hx(uaMessage(_kind(r), popV2Tag, h.registrationDigest)), _hx(h.message));
        expect(hxn(h.memberDigest) ?? '', r['memberDigest'] ?? '', reason: name);
      }
      final a = r['attrs'] as Map, pk = _b(a['pqzKey']);
      if (pk.isNotEmpty) {
        withPqz++;
        final got = pqzRegMessage(_kind(r), ua, pk, (BigInt.from(a['kemVersion'] as int), _b(a['kemPk'])));
        expect(_hx(got), r['pqzRegMessage'], reason: name);
        // TS-D3: R_REG proves over the typed UAPortableRecord of the registering kind
        expect(_hx(got), _hx(uaMessage(0x0142, popV2Tag, _b(r['portableRecordDigest']))), reason: name);
      } else {
        expect(_b(r['pqzRegMessage']).every((x) => x == 0), isTrue);
      }
      if (_kind(r) == 0x0120) msigs++;
      n++;
    }
    expect([n, withPqz, msigs], [regs.length, 8, 6]);
  });

  test('kem record', () {
    for (final r in (p['kemRecords'] as List).cast<Map>()) {
      final ua = _b(r['ua']), pk = _b(r['kemPk']), v = BigInt.from(r['version'] as int);
      final d = kemRecordDigest(ua, v, pk);
      expect(_hx(d), r['digest']);
      expect(_hx(kemRecordHash(ua, v, pk)), r['structHash']);
      final m = kemRecordMessage(_kind(r), ua, v, pk);
      expect(_hx(m), r['message']);
      expect(_hx(m), _hx(uaMessage(_kind(r), purposeTag('kem'), d)));
      if (_kind(r) == 0x0120) expect(_hx(memberDigest(ua, m)), r['memberDigest']);
    }
    expect((p['kemRecords'] as List), isNotEmpty);
    final u = Uint8List.fromList(List.filled(32, 1));
    expect(_err(() => kemRecordDigest(u, BigInt.zero, _kem(1601))).code, 'UAKemVersion');
    expect(_err(() => kemRecordDigest(u, BigInt.one << 64, _kem(1601))).code, 'UAKemVersion');
    expect(_err(() => kemRecordDigest(u, BigInt.one, _kem(1600))).code, 'UAKemKeyLength');
    expect(_err(() => kemRecordDigest(u, BigInt.one, _kem(1602))).code, 'UAKemKeyLength');
    expect(_err(() => kemRecordDigest(u, BigInt.one, Uint8List(0))).code, 'UAKemKeyLength');
    for (final scheme in [0, 2, 255]) {
      expect(_err(() => kemRecordDigest(u, BigInt.one, _kem(1601, scheme))).code, 'UAKemScheme');
    }
    // TS-D2: (0, no key) is the zero record's hash (never a signed record); version 0 with a key is UAKemVersion
    final th = keccak256([_utf8('UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)')]);
    expect(_hx(kemRecordHash(u, BigInt.zero, Uint8List(0))), _hx(keccak256([th, u, Uint8List(96)])));
    expect(_err(() => kemRecordHash(u, BigInt.zero, _kem(1601))).code, 'UAKemVersion');
    expect(_err(() => kemRecordHash(u, BigInt.one, Uint8List(0))).code, 'UAKemKeyLength');
    expect(_err(() => kemRecordDigest(u, BigInt.zero, Uint8List(0))).code, 'UAKemVersion');
    // known answer shared with ua-rs: pins the 8-byte version word
    expect(_hx(kemRecordDigest(u, (BigInt.one << 64) - BigInt.one, _kem(1601))), '0xa0063a84b56d80c83688d8caf5aeb4be8fb4556928e8bc649686449573938f07');
    expect(_hx(chainKeyHash(0x10000000007)), '0x6e45d591a544f53396f6e86d49f5809196c5725f9d99dbd2ca97f9925c7ce950'); // keccak256("evm:1099511627783")
  });

  test('pqz key record', () {
    var n = 0, msigRows = 0;
    for (final r in (p['pqzKeyRecords'] as List).cast<Map>()) {
      final ua = _b(r['ua']), key = _b(r['pqzKey']), hash = _b(r['pqzPopHash']), kind = _kind(r);
      final kd = _b(byKey(regs, 'ua', r['ua'])['keyData']), pop = _b(byKey(regs, 'set', r['set'])['pqzPop']);
      for (final hashOnly in [false, true]) {
        final g = pqzKeyRecordMessage(kind, ua, kd, key, pqzPop: hashOnly ? null : pop, pqzPopHash: hashOnly ? hash : null);
        expect(_hx(g.pqzKeyHash), r['pqzKeyHash']);
        expect(_hx(g.pqzPopHash), r['pqzPopHash']);
        expect(_hx(g.pqzKeyDigest), r['pqzKeyDigest']);
        expect(_hx(g.recordDigest), r['recordDigest']);
        expect(_hx(g.message), r['message']);
        expect(_hx(g.pqzRegMessage), r['pqzRegMessage']);
        expect(_hx(pqzKeyDigest(ua, g.pqzKeyHash)), _hx(g.pqzKeyDigest));
        expect(_hx(pqzKeyRecordDigest(ua, g.pqzKeyHash, g.pqzPopHash)), _hx(g.recordDigest));
        expect(g.memberDigest != null, kind == 0x0120);
        expect(hxn(g.memberDigest) ?? '', r['memberDigest'] ?? '');
        if (kind == 0x0120) {
          msigRows++;
          expect(_hx(memberDigest(ua, g.message)), _hx(g.memberDigest!));
        }
      }
      // write-once: a key already set refuses
      expect(_err(() => pqzKeyRecordMessage(kind, ua, kd, key, pqzPopHash: hash, alreadySet: true)).code, 'UAPqzKeySet');
      n++;
    }
    expect([n, msigRows], [(p['pqzKeyRecords'] as List).length, 8]); // 4 msig rows, each with the proof bytes and hash-only
  });

  // TS-D4: a native msig member signs the record's typed digest itself (what eth_signTypedData_v4 of typedData returns), a
  // derived member keeps memberDigest(ua, message); only under the portable purposes.
  test('native member typed digest', () {
    expect([for (final t in [popV2Tag, purposeTag('kem'), purposeTag('pqz-key')]) isPortablePurpose(t)], [true, true, true]);
    expect(isPortablePurpose(purposeTag('metatx')) || isPortablePurpose(purposeTag('pop')), isFalse);
    final r = byKey(regs, 'name', 'msig-pq-native'), h = register(r);
    expect(_hashTypedData(r['typedData'] as Map), _hx(h.registrationDigest));
    expect(_hx(h.memberDigest!), _hx(memberDigest(_b(r['ua']), h.message)));
    expect(_hx(h.memberDigest!), isNot(_hx(h.registrationDigest)));
    for (final k in (p['pqzKeyRecords'] as List).cast<Map>().where((x) => x['ua'] == r['ua'])) {
      expect(_hashTypedData(k['typedData'] as Map), k['recordDigest']);
    }
    final negs = (p['negatives'] as List).cast<Map>();
    final n = byKey(negs, 'name', 'native-personal-sign-under-metatx');
    expect(isPortablePurpose(_b(((n['mutation'] as Map)['set'] as Map)['purposeTag'])), isFalse);
    expect(byKey(negs, 'name', 'native-member-personal-sign')['error'], 'UAPoP');
  });

  test('holder refusals', () {
    var run = 0, sigLevel = 0;
    for (final n in (p['negatives'] as List).cast<Map>()) {
      final entry = n['entry'], name = n['name'], err = n['error'];
      final m = n['mutation'] as Map, set = (m['set'] ?? <String, Object?>{}) as Map;
      if ((entry == 'register' || entry == 'storePqzPop') && set.keys.every((k) => (k as String).startsWith('attrs.') || k == 'pqzPop')) {
        final row = byKey(regs, 'name', m['row']);
        final mut = Map<String, Object?>.from(row), attrs = Map<String, Object?>.from(row['attrs'] as Map);
        for (final o in [(m['registerWith'] ?? {}) as Map, set]) {
          // registerWith first (the state the registry holds), then the mutation
          o.forEach((k, v) {
            if ((k as String).startsWith('attrs.')) {
              attrs[k.substring(6)] = v;
            } else {
              mut[k] = v;
            }
          });
        }
        mut['attrs'] = attrs;
        if (err == 'UAPoP') {
          // the digest layer accepts it; the PoP of the unmutated row does not cover it
          expect(_hx(register(mut).message), isNot(row['popMessage']), reason: '$name');
        } else {
          expect(_err(() => register(mut)).code, err, reason: '$name');
        }
        run++;
      } else if (entry == 'setPqzKey' && (err == 'UAPqzKeySet' || err == 'UAPqzHolder' || err == 'UAPqzPopHash')) {
        final rec = byKey((p['pqzKeyRecords'] as List).cast<Map>(), 'name', m['row']);
        final uaHex = (set['ua'] ?? rec['ua']) as String, holder = byKey(regs, 'ua', uaHex);
        final hash = _b(set['pqzPopHash'] ?? rec['pqzPopHash']);
        final e = _err(() => pqzKeyRecordMessage(_kind(holder), _b(uaHex), _b(holder['keyData']), _b(rec['pqzKey']),
            pqzPopHash: hash, alreadySet: (holder['attrs'] as Map)['pqzKey'] != '0x'));
        expect(e.code, err, reason: '$name');
        run++;
      } else if (entry == 'setKemKey' && name == 'kem-record-of-other-ua') {
        // the record of one UA offered for another: the signed message differs, so the signature cannot verify
        final k = byKey((p['kemRecords'] as List).cast<Map>(), 'id', m['row']);
        final t = byKey(regs, 'ua', set['ua']);
        final msg = kemRecordMessage(_kind(t), _b(set['ua']), BigInt.from(k['version'] as int), _b(k['kemPk']));
        expect(_hx(msg), isNot(k['message']));
        run++;
      } else {
        sigLevel++; // signatures / native personal_sign / another record's pop: verified by the signature vectors
      }
    }
    expect([run, sigLevel], [60, (p['negatives'] as List).length - 60]);
    final u = Uint8List.fromList(List.filled(32, 1)), key = Uint8List(16384), proof = Uint8List.fromList(List.filled(32, 7));
    // malformed msig key data is UAKeyData, not "not a holder"; an msig without key data is not a holder
    for (final kd in [Uint8List.fromList([0, 2, 0]), Uint8List.fromList([0, 2, 0, 2, 9, 9])]) {
      expect(_err(() => holderPopMessage(0x0120, u, keyData: kd, pqzKey: key, pqzPopHash: proof)).code, 'UAKeyData');
    }
    expect(_err(() => holderPopMessage(0x0120, u, pqzKey: key, pqzPopHash: proof)).code, 'UAPqzHolder');
    expect(_err(() => holderPopMessage(0x0130, u, pqzKey: key, pqzPopHash: Uint8List(31))).code, 'UAPqzPopHash');
    expect(_err(() => holderPopMessage(0x0130, u, pqzKey: key, pqzPop: Uint8List(0))).code, 'UAPqzPopHash');
    expect(_err(() => holderPopMessage(0x0130, u, pqzKey: Uint8List(100), pqzPopHash: proof)).code, 'UAKeyData');
    expect(_err(() => holderPopMessage(0x0130, u, kem: (BigInt.one, Uint8List(0)))).code, 'UAKemKeyLength');
    expect(_err(() => holderPopMessage(0x0101, u, kem: (BigInt.one, _kem(1601)))).code, 'UAKemHolder');
    // a zero-length proof hash is absent (same as no hash)
    expect(_hx(holderPopMessage(0x0130, u, pqzPopHash: Uint8List(0)).message), _hx(holderPopMessage(0x0130, u).message));
  });
}
