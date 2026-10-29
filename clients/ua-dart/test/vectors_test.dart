// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas_ua against smartcontracts/vectors/ua/{kinds,structures}.json. The files are found by walking up from the
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
      final portable = portablePopDigest(_b(p['ua']), _b(p['pqzKeyHash']), _b(p['kemRecordHash']));
      expect(_hx(portable), p['portablePopDigest']);
      expect(_hx(registrationDigest(portable, _b(p['pqzPopHash']))), p['registrationDigest']);
    }
    final pqzKey = _b(k['pqzKey']);
    final proof = Uint8List.fromList(List.filled(32, 7));
    for (final r in (s['pqzReg'] as List).cast<Map>()) {
      final ua = _b(r['ua']), kem = _b(r['kemRecordHash']), h = keyHashOf(0x0142, pqzKey)!;
      expect(_hx(h), r['pqzKeyHash']);
      final portable = portablePopDigest(ua, h, kem);
      expect(_hx(portable), r['portablePopDigest']);
      expect(_hx(uaMessage(0x0142, popV2Tag, portable)), r['pqzRegMessage']);
      if (kem.any((x) => x != 0)) continue; // the row's KEM record hash is opaque; the real records are in portable.json
      expect(_hx(pqzRegMessage(ua, pqzKey)), r['pqzRegMessage']);
      final got = holderPopMessage(_kind(r), ua, pqzKey: pqzKey, pqzPopHash: proof);
      expect([_hx(got.pqzKeyHash), _hx(got.portablePopDigest)], [r['pqzKeyHash'], r['portablePopDigest']]);
      for (final bad in [0x0101, 0x0133]) {
        expect(_err(() => holderPopMessage(bad, ua, pqzKey: pqzKey, pqzPopHash: proof)).code, 'UAPqzHolder');
      }
    }
    for (final r in (s['pqzMsig'] as List).cast<Map>()) {
      final d = _b(r['keyData']);
      expect(msigPqzEligible(d), r['eligible'], reason: r['reason'] as String);
      expect(_hx(deriveUA(0x0120, d)), r['ua']);
      final h = r['eligible'] as bool ? _b(k['pqzKeyHash']) : Uint8List(32);
      expect(_hx(portablePopDigest(_b(r['ua']), h, Uint8List(32))), r['portablePopDigest']);
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

  test('portable', () {
    final t = p['tags'] as Map;
    String tg(String n) => (t[n] as Map)['hash'] as String;
    expect(_hx(popV2Tag), tg('PURPOSE_POP_V2'));
    expect(_hx(purposeTag('kem')), tg('PURPOSE_KEM'));
    expect(_hx(purposeTag('pqz-key')), tg('PURPOSE_PQZ_KEY'));
    expect(_hx(kemRecordTag), tg('KEM_RECORD_TAG'));
    expect(_hx(pqzKeyRecordTag), tg('PQZ_KEY_RECORD_TAG'));
    var n = 0, withPqz = 0, msigs = 0;
    for (final r in regs) {
      final ua = _b(r['ua']), name = r['name'] as String;
      expect(_hx(uaOf(_kind(r), _b(r['keyData']))), r['ua'], reason: name);
      for (final hashOnly in [false, true]) {
        final h = register(r, hashOnly: hashOnly);
        expect(_hx(h.pqzKeyHash), r['pqzKeyHash'], reason: name);
        expect(_hx(h.pqzPopHash), (r['attrs'] as Map)['pqzPopHash'], reason: name);
        expect(_hx(h.kemRecordHash), r['kemRecordHash'], reason: name);
        expect(_hx(h.portablePopDigest), r['portablePopDigest'], reason: name);
        expect(_hx(h.registrationDigest), r['registrationDigest'], reason: name);
        expect(_hx(h.message), r['popMessage'], reason: name);
        expect(_hx(portablePopDigest(ua, h.pqzKeyHash, h.kemRecordHash)), _hx(h.portablePopDigest));
        expect(_hx(registrationDigest(h.portablePopDigest, h.pqzPopHash)), _hx(h.registrationDigest));
        expect(_hx(uaMessage(_kind(r), popV2Tag, h.registrationDigest)), _hx(h.message));
        expect(hxn(h.memberDigest) ?? '', r['memberDigest'] ?? '', reason: name);
      }
      final a = r['attrs'] as Map, pk = _b(a['pqzKey']);
      if (pk.isNotEmpty) {
        withPqz++;
        final v = a['kemVersion'] as int;
        expect(_hx(pqzRegMessage(ua, pk, v != 0 ? (BigInt.from(v), _b(a['kemPk'])) : null)), r['pqzRegMessage'], reason: name);
      } else {
        expect(_b(r['pqzRegMessage']).every((x) => x == 0), isTrue);
      }
      if (_kind(r) == 0x0120) msigs++;
      n++;
    }
    expect([n, withPqz, msigs], [25, 8, 6]);
  });

  test('kem record', () {
    for (final r in (p['kemRecords'] as List).cast<Map>()) {
      final ua = _b(r['ua']), pk = _b(r['kemPk']), v = BigInt.from(r['version'] as int);
      final d = kemRecordDigest(ua, v, pk);
      expect(_hx(d), r['digest']);
      final m = kemRecordMessage(_kind(r), ua, v, pk);
      expect(_hx(m), r['message']);
      expect(_hx(m), _hx(uaMessage(_kind(r), purposeTag('kem'), d)));
      if (_kind(r) == 0x0120) expect(_hx(memberDigest(ua, m)), r['memberDigest']);
    }
    expect((p['kemRecords'] as List).length, 9);
    final u = Uint8List.fromList(List.filled(32, 1));
    expect(_err(() => kemRecordDigest(u, BigInt.zero, Uint8List(1600))).code, 'UAKemVersion');
    expect(_err(() => kemRecordDigest(u, BigInt.one << 64, Uint8List(1600))).code, 'UAKemVersion');
    expect(_err(() => kemRecordDigest(u, BigInt.one, Uint8List(1599))).code, 'UAKemKeyLength');
    expect(_err(() => kemRecordDigest(u, BigInt.one, Uint8List(1601))).code, 'UAKemKeyLength');
    expect(kemRecordDigest(u, (BigInt.one << 64) - BigInt.one, Uint8List(1600)).length, 32);
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
        expect(_hx(pqzKeyRecordDigest(g.pqzKeyDigest, g.pqzPopHash)), _hx(g.recordDigest));
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
    expect([n, msigRows], [8, 8]); // 4 msig rows, each with the proof bytes and hash-only
  });

  test('personal_sign of the portable purposes', () {
    expect([for (final t in [popV2Tag, purposeTag('kem'), purposeTag('pqz-key')]) isPortablePurpose(t)], [true, true, true]);
    expect(isPortablePurpose(purposeTag('metatx')) || isPortablePurpose(purposeTag('pop')), isFalse);
    final md = _b(byKey(regs, 'name', 'msig-pq-native')['memberDigest']);
    // known answer from the JS reference (clientkeys ua.js); prefix = 0x19 + "Ethereum Signed Message:\n32" (28 bytes)
    expect(_hx(md), '0x606d9a70c70d39e5d8d079c3ae31eefa6db574219dab56d6c776cb6731e61a7c');
    expect(_hx(personalSignDigest(md)), '0xe5d24987e9b4e710063a5432d6215eaead64d8dc073f7561726d21644d54c3d8');
    final n = byKey((p['negatives'] as List).cast<Map>(), 'name', 'native-personal-sign-under-metatx');
    expect(isPortablePurpose(_b(((n['mutation'] as Map)['set'] as Map)['purposeTag'])), isFalse);
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
            pqzPopHash: hash, alreadySet: err == 'UAPqzKeySet'));
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
        sigLevel++; // signatures / native personal_sign: verified by the signature vectors
      }
    }
    expect([run, sigLevel], [56, 7]);
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
    expect(_err(() => holderPopMessage(0x0101, u, kem: (BigInt.one, Uint8List(1600)))).code, 'UAKemHolder');
    // a zero-length proof hash is absent (same as no hash)
    expect(_hx(holderPopMessage(0x0130, u, pqzPopHash: Uint8List(0)).message), _hx(holderPopMessage(0x0130, u).message));
  });
}
