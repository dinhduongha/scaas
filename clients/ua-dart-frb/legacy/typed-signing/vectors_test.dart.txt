// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Mirrors clients/ua-rs/tests/vectors.rs against smartcontracts/vectors/ua/. Needs the native library:
//   (cd rust && cargo build)   # -> rust/target/debug/libscaas_ua_frb.so, or set SCAAS_UA_LIB to its path
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:scaas_ua_frb/scaas_ua_frb.dart';
import 'package:test/test.dart';

final vectors = Platform.environment['SCAAS_UA_VECTORS'] ?? '../../smartcontracts/vectors/ua';

Map<String, dynamic> load(String name) => jsonDecode(File('$vectors/$name').readAsStringSync());

Uint8List bytes(String s) {
  final h = s.substring(2);
  return Uint8List.fromList([for (var i = 0; i < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)]);
}

U8Array32 b32(String s) => U8Array32(bytes(s));
U8Array20 b20(String s) => U8Array20(bytes(s));

String hx(List<int> b) => '0x${b.map((x) => x.toRadixString(16).padLeft(2, '0')).join()}';

/// Runs [f]; returns the UAError code it throws, or null if it does not throw.
String? errCode(void Function() f) {
  try {
    f();
  } on UAError catch (e) {
    return e.code;
  }
  return null;
}

List rows(Map<String, dynamic> m, String k) => m[k] as List;

/// A KEM key of [n] bytes: the scheme byte, then zeros.
Uint8List _kem(int n, [int scheme = 1]) => Uint8List(n)..[0] = scheme;

void main() {
  setUpAll(() async {
    final path = Platform.environment['SCAAS_UA_LIB'] ?? 'rust/target/debug/libscaas_ua_frb.so';
    await ScaasUa.init(externalLibrary: ExternalLibrary.open(path));
  });

  test('table, groups, purposes, constants', () {
    final k = load('kinds.json');
    for (final r in rows(k, 'kinds')) {
      final n = r['kind'] as int;
      final info = kindInfo(kind: n);
      expect(info.name, r['name']);
      expect(info.native, r['native']);
      expect(info.lengths, r['lengths']);
      expect(info.group, r['group']);
      expect(isSigning(kind: n), r['signing']);
      expect(isZether(kind: n), r['zether']);
      expect(isNative(kind: n), r['native']);
      expect(isPqzHolder(kind: n), r['pqzHolder']);
      expect(isMember(kind: n, hederaNative: false), r['member']);
      expect(isMember(kind: n, hederaNative: true), r['memberHedera']);
      if (info.native) {
        expect(errCode(() => tag(kind: n)), 'UAKindNotDerived');
      } else {
        expect(kindTagString(kind: n), r['tag']);
        expect(hx(tag(kind: n)), r['TAG']);
      }
    }
    for (final r in rows(k, 'schemes')) {
      // schemes are not kinds: tag and keyHash only
      final n = r['kind'] as int;
      expect(kindTagString(kind: n), r['tag']);
      expect(hx(tag(kind: n)), r['TAG']);
      expect(errCode(() => kindInfo(kind: n)), 'UAKindUnknown');
      expect(errCode(() => uaOf(kind: n, keyData: Uint8List(0))), 'UAKindNotDerived');
      expect(errCode(() => validateKeyData(kind: n, keyData: Uint8List(0), hederaNative: false)), 'UAKindNotDerived');
    }
    expect(hx(keyHashOf(kind: 0x0142, keyData: bytes(k['pqzKey']))!), k['pqzKeyHash']);
    for (final r in rows(k, 'groups')) {
      expect(groupTagString(group: r['group']), r['tag']);
      expect(hx(groupTag(group: r['group'])!), r['GROUP']);
    }
    expect(groupTag(group: 'nope'), isNull);
    expect(rows(k, 'purposes').length, 14); // 13 purposes, `pop` has v1 and v2
    for (final r in rows(k, 'purposes')) {
      expect(hx(purposeTagV(purpose: r['purpose'], version: r['version'])), r['purposeTag']);
      if (r['version'] == 1) expect(hx(purposeTag(purpose: r['purpose'])), r['purposeTag']);
    }
    for (final bad in <(String, int)>[('metatx', 2), ('pop', 3), ('pop', 0), ('nope', 1)]) {
      expect(errCode(() => purposeTagV(purpose: bad.$1, version: bad.$2)), 'UAPurposeUnknown');
    }
    expect(errCode(() => purposeTag(purpose: 'nope')), 'UAPurposeUnknown');
    expect(errCode(() => kindInfo(kind: 0xffff)), 'UAKindUnknown');
    final c = k['constants'];
    expect(hx(msgTag()), c['MSG_TAG']);
    expect(hx(purposeTag(purpose: 'pop')), c['POP_TAG']);
  });

  test('valid rows', () {
    for (final r in rows(load('kinds.json'), 'valid')) {
      final n = r['kind'] as int, d = bytes(r['keyData']), hn = r['hederaNative'] as bool;
      expect(hx(deriveUa(kind: n, keyData: d, hederaNative: hn)), r['ua'], reason: r['name']);
      final kh = keyHashOf(kind: n, keyData: d);
      expect(kh == null ? null : hx(kh), r['keyHash'], reason: r['name']);
    }
  });

  test('invalid rows', () {
    for (final r in rows(load('kinds.json'), 'invalid')) {
      final n = r['kind'] as int;
      expect(errCode(() => validateKeyData(kind: n, keyData: bytes(r['keyData']), hederaNative: r['hederaNative'])),
          r['error'], reason: '$n ${r['reason']}');
    }
  });

  test('natives, native space, canonical ids', () {
    final k = load('kinds.json');
    for (final r in rows(k, 'natives')) {
      final id = nativeId(kind: r['kind'], raw: bytes(r['raw']));
      expect(hx(id), r['id']);
      expect(canonicalId(text: hx(id)), r['canonical']);
    }
    for (final r in rows(k, 'nativeInvalid')) {
      expect(errCode(() => nativeId(kind: r['kind'], raw: bytes(r['raw']))), r['error']);
    }
    for (final r in rows(k, 'nativeSpace')) {
      expect(inNativeSpace(id: b32(r['id'])), r['inNativeSpace']);
    }
    for (final r in rows(k, 'canonicalIds')) {
      if (r.containsKey('canonical')) {
        expect(canonicalId(text: r['input']), r['canonical']);
      } else {
        expect(errCode(() => canonicalId(text: r['input'])), r['error']);
      }
    }
  });

  test('messages', () {
    for (final r in rows(load('kinds.json'), 'messages')) {
      final p = purposeTagV(purpose: r['purpose'], version: r['version']); // each row carries its purpose `version` (A4-c1)
      expect(hx(p), r['purposeTag']);
      expect(hx(uaMessage(kind: r['kind'], purpose: p, digest: b32(r['digest']))), r['uaMsg']);
    }
  });

  test('structures', () {
    final s = load('structures.json');
    for (final p in rows(s, 'pop')) {
      final portable = portablePopDigest(ua: b32(p['ua']), pqzKeyHash: b32(p['pqzKeyHash']), kemRecordHash: b32(p['kemRecordHash']));
      expect(hx(portable), p['portablePopDigest']);
      expect(hx(registrationDigest(portable: portable, pqzPopHash: b32(p['pqzPopHash']))), p['registrationDigest']);
    }
    expect(hx(chainKeyHash(chainId: 0x10000000007)), '0x6e45d591a544f53396f6e86d49f5809196c5725f9d99dbd2ca97f9925c7ce950'); // keccak256("evm:1099511627783")
    final kinds = load('kinds.json');
    final pk = bytes(kinds['pqzKey']), proof = Uint8List.fromList(List.filled(32, 7));
    for (final p in rows(s, 'pqzReg')) {
      final ua = b32(p['ua']), kem = bytes(p['kemRecordHash']), h = keyHashOf(kind: 0x0142, keyData: pk)!;
      expect(hx(h), p['pqzKeyHash']);
      final portable = portablePopDigest(ua: ua, pqzKeyHash: h, kemRecordHash: U8Array32(kem));
      expect(hx(portable), p['portablePopDigest']);
      expect(hx(uaMessage(kind: 0x0142, purpose: purposeTagV(purpose: 'pop', version: 2), digest: portable)), p['pqzRegMessage']);
      if (kem.any((x) => x != 0)) continue; // the row's KEM record hash is opaque; the real records are in portable.json
      expect(hx(pqzRegMessage(ua: ua, pqzKey: pk)), p['pqzRegMessage']);
      final got = holderPopMessage(kind: p['kind'], ua: ua, keyData: Uint8List(0), pqzKey: pk, pqzPopHash: proof);
      expect([hx(got.pqzKeyHash), hx(got.portablePopDigest)], [p['pqzKeyHash'], p['portablePopDigest']]);
      for (final bad in [0x0101, 0x0133]) {
        expect(errCode(() => holderPopMessage(kind: bad, ua: ua, keyData: Uint8List(0), pqzKey: pk, pqzPopHash: proof)), 'UAPqzHolder');
      }
    }
    for (final p in rows(s, 'pqzMsig')) {
      final d = bytes(p['keyData']);
      expect(msigPqzEligible(keyData: d), p['eligible'], reason: p['reason']);
      expect(hx(deriveUa(kind: 0x0120, keyData: d, hederaNative: false)), p['ua']);
      final eligibleHash = bytes(kinds['pqzKeyHash']);
      final h = U8Array32(p['eligible'] as bool ? eligibleHash : Uint8List(32));
      expect(hx(portablePopDigest(ua: b32(p['ua']), pqzKeyHash: h, kemRecordHash: U8Array32(Uint8List(32)))), p['portablePopDigest']);
    }
    for (final a in rows(s, 'uaAuth')) {
      final c = s['contexts'][a['context']];
      final d = UaDomain(
          generation: a['generation'],
          chainId: c['chainId'] as int,
          registry: b20(c['registry']),
          chainUid: b32(c['chainUid']));
      expect(hx(uaAuthDomainSeparator(domain: d)), a['domainSeparator']);
      expect(hx(uaAuthDigest(domain: d, ua: b32(a['ua']), purpose: b32(a['purposeTag']), digest: b32(a['digest']))),
          a['uaAuthDigest']);
    }
    for (final m in rows(s, 'member')) {
      expect(hx(memberDigest(structureUa: b32(m['structureUa']), uaMsg: b32(m['uaMsg']))), m['memberDigest']);
    }
  });

  test('encodeMsig and UAError reason', () {
    final id = U8Array32(Uint8List(32)..[31] = 7);
    final out = encodeMsig(threshold: 1, members: [(1, id, 1)]);
    expect(out.length, 4 + 36);
    expect(out.sublist(0, 4), [0, 1, 0, 1]);
    try {
      validateKeyData(kind: 0x0104, keyData: Uint8List(3), hederaNative: false);
      fail('accepted');
    } on UAError catch (e) {
      expect(e.code, 'UAKeyData');
      expect(e.reason, 'length');
    }
    expect(errCode(() => kindInfo(kind: 0x10100)), 'UAKindUnknown'); // would wrap to 0x0100 as u16
    expect(errCode(() => kindInfo(kind: -1)), 'UAKindUnknown');
    expect(errCode(() => chainKeyHash(chainId: -1)), 'UAArgument'); // would wrap to 2^64-1 as u64
    expect(errCode(() => encodeMsig(threshold: 0x10001, members: [(1, id, 1)])), 'UAArgument');
    expect(errCode(() => encodeMsig(threshold: 1, members: [(0x10001, id, 1)])), 'UAKindUnknown');
    expect(isNative(kind: 0x10000), false);
  });

  final pv = load('portable.json');
  final regs = rows(pv, 'registrations');
  Map byKey(List rs, String key, Object? v) => rs.firstWhere((r) => r[key] == v, orElse: () => throw StateError('no $key = $v'));
  String? hxn(U8Array32? b) => b == null ? null : hx(b);

  /// The holder call over a registration row's attrs (and the proof bytes, or only their hash).
  HolderPop register(Map row, {bool hashOnly = false}) {
    final a = row['attrs'] as Map;
    final key = bytes(a['pqzKey']), pop = bytes(row['pqzPop']), hash = bytes(a['pqzPopHash']), pk = bytes(a['kemPk']);
    final ver = BigInt.from(a['kemVersion'] as int);
    return holderPopMessage(
        kind: row['kind'],
        ua: b32(row['ua']),
        keyData: bytes(row['keyData']),
        pqzKey: key.isEmpty ? null : key,
        pqzPop: hashOnly || pop.isEmpty ? null : pop,
        pqzPopHash: hash.every((x) => x == 0) ? null : hash,
        kemRecord: ver == BigInt.zero && pk.isEmpty ? null : KemRecord(version: ver, pk: pk));
  }

  test('portable', () {
    final t = pv['tags'] as Map;
    String tg(String n) => (t[n] as Map)['hash'] as String;
    expect(hx(purposeTagV(purpose: 'pop', version: 2)), tg('PURPOSE_POP_V2'));
    expect(hx(purposeTag(purpose: 'kem')), tg('PURPOSE_KEM'));
    expect(hx(purposeTag(purpose: 'pqz-key')), tg('PURPOSE_PQZ_KEY'));
    expect(hx(kemRecordTag()), tg('KEM_RECORD_TAG'));
    expect(hx(pqzKeyRecordTag()), tg('PQZ_KEY_RECORD_TAG'));
    var n = 0, withPqz = 0, msigs = 0;
    for (final r in regs) {
      final ua = b32(r['ua']), name = r['name'] as String;
      expect(hx(uaOf(kind: r['kind'], keyData: bytes(r['keyData']))), r['ua'], reason: name);
      for (final hashOnly in [false, true]) {
        final h = register(r, hashOnly: hashOnly);
        expect(hx(h.pqzKeyHash), r['pqzKeyHash'], reason: name);
        expect(hx(h.pqzPopHash), (r['attrs'] as Map)['pqzPopHash'], reason: name);
        expect(hx(h.kemRecordHash), r['kemRecordHash'], reason: name);
        expect(hx(h.portablePopDigest), r['portablePopDigest'], reason: name);
        expect(hx(h.registrationDigest), r['registrationDigest'], reason: name);
        expect(hx(h.message), r['popMessage'], reason: name);
        expect(hx(portablePopDigest(ua: ua, pqzKeyHash: h.pqzKeyHash, kemRecordHash: h.kemRecordHash)), hx(h.portablePopDigest));
        expect(hx(registrationDigest(portable: h.portablePopDigest, pqzPopHash: h.pqzPopHash)), hx(h.registrationDigest));
        expect(hx(uaMessage(kind: r['kind'], purpose: purposeTagV(purpose: 'pop', version: 2), digest: h.registrationDigest)), hx(h.message));
        expect(hxn(h.memberDigest) ?? '', r['memberDigest'] ?? '', reason: name);
      }
      final a = r['attrs'] as Map, pk = bytes(a['pqzKey']);
      if (pk.isNotEmpty) {
        withPqz++;
        final v = a['kemVersion'] as int;
        expect(hx(pqzRegMessage(ua: ua, pqzKey: pk, kemRecord: v != 0 ? KemRecord(version: BigInt.from(v), pk: bytes(a['kemPk'])) : null)),
            r['pqzRegMessage'], reason: name);
      } else {
        expect(bytes(r['pqzRegMessage']).every((x) => x == 0), isTrue);
      }
      if (r['kind'] == 0x0120) msigs++;
      n++;
    }
    expect([n, withPqz, msigs], [25, 8, 6]);
  });

  test('kem record', () {
    for (final r in rows(pv, 'kemRecords')) {
      final ua = b32(r['ua']), pk = bytes(r['kemPk']), v = BigInt.from(r['version'] as int);
      final d = kemRecordDigest(ua: ua, version: v, kemPk: pk);
      expect(hx(d), r['digest']);
      final m = kemRecordMessage(kind: r['kind'], ua: ua, version: v, kemPk: pk);
      expect(hx(m), r['message']);
      expect(hx(m), hx(uaMessage(kind: r['kind'], purpose: purposeTag(purpose: 'kem'), digest: d)));
      if (r['kind'] == 0x0120) expect(hx(memberDigest(structureUa: ua, uaMsg: m)), r['memberDigest']);
    }
    expect(rows(pv, 'kemRecords').length, 9);
    final u = U8Array32(Uint8List.fromList(List.filled(32, 1)));
    expect(errCode(() => kemRecordDigest(ua: u, version: BigInt.zero, kemPk: _kem(1601))), 'UAKemVersion');
    expect(errCode(() => kemRecordDigest(ua: u, version: BigInt.one, kemPk: _kem(1600))), 'UAKemKeyLength');
    expect(errCode(() => kemRecordDigest(ua: u, version: BigInt.one, kemPk: _kem(1602))), 'UAKemKeyLength');
    expect(errCode(() => kemRecordDigest(ua: u, version: BigInt.one, kemPk: Uint8List(0))), 'UAKemKeyLength');
    for (final scheme in [0, 2, 255]) {
      expect(errCode(() => kemRecordDigest(ua: u, version: BigInt.one, kemPk: _kem(1601, scheme))), 'UAKemScheme');
    }
    expect(hx(kemRecordDigest(ua: u, version: (BigInt.one << 64) - BigInt.one, kemPk: _kem(1601))), '0x8c997440926a352465f61b53b75606d794efa60c66ac4a7a63f25369a15f7092'); // pins the 8-byte version word
    // m-C3: frb would wrap 2^64 + 1 to 1 and -1 to 2^64 - 1; the package refuses them (as ua-dart / JS)
    final pk = _kem(1601), big = (BigInt.one << 64) + BigInt.one;
    for (final bad in [BigInt.one << 64, big, -BigInt.one]) {
      expect(errCode(() => kemRecordDigest(ua: u, version: bad, kemPk: pk)), 'UAKemVersion', reason: '$bad');
      expect(errCode(() => kemRecordMessage(kind: 0x0130, ua: u, version: bad, kemPk: pk)), 'UAKemVersion', reason: '$bad');
      expect(errCode(() => holderPopMessage(kind: 0x0130, ua: u, keyData: Uint8List(0), kemRecord: KemRecord(version: bad, pk: pk))), 'UAKemVersion', reason: '$bad');
      expect(errCode(() => pqzRegMessage(ua: u, pqzKey: Uint8List(16384), kemRecord: KemRecord(version: bad, pk: pk))), 'UAKemVersion', reason: '$bad');
    }
  });

  test('pqz key record', () {
    var n = 0, msigRows = 0;
    for (final r in rows(pv, 'pqzKeyRecords')) {
      final ua = b32(r['ua']), key = bytes(r['pqzKey']), hash = bytes(r['pqzPopHash']), kind = r['kind'] as int;
      final kd = bytes(byKey(regs, 'ua', r['ua'])['keyData']), pop = bytes(byKey(regs, 'set', r['set'])['pqzPop']);
      for (final hashOnly in [false, true]) {
        final g = pqzKeyRecordMessage(
            kind: kind, ua: ua, keyData: kd, pqzKey: key, pqzPop: hashOnly ? null : pop, pqzPopHash: hashOnly ? hash : null, alreadySet: false);
        expect(hx(g.pqzKeyHash), r['pqzKeyHash']);
        expect(hx(g.pqzPopHash), r['pqzPopHash']);
        expect(hx(g.pqzKeyDigest), r['pqzKeyDigest']);
        expect(hx(g.recordDigest), r['recordDigest']);
        expect(hx(g.message), r['message']);
        expect(hx(g.pqzRegMessage), r['pqzRegMessage']);
        expect(hx(pqzKeyDigest(ua: ua, pqzKeyHash: g.pqzKeyHash)), hx(g.pqzKeyDigest));
        expect(hx(pqzKeyRecordDigest(keyDigest: g.pqzKeyDigest, pqzPopHash: g.pqzPopHash)), hx(g.recordDigest));
        expect(g.memberDigest != null, kind == 0x0120);
        expect(hxn(g.memberDigest) ?? '', r['memberDigest'] ?? '');
        if (kind == 0x0120) {
          msigRows++;
          expect(hx(memberDigest(structureUa: ua, uaMsg: g.message)), hx(g.memberDigest!));
        }
      }
      // write-once: a key already set refuses
      expect(errCode(() => pqzKeyRecordMessage(kind: kind, ua: ua, keyData: kd, pqzKey: key, pqzPopHash: hash, alreadySet: true)), 'UAPqzKeySet');
      n++;
    }
    expect([n, msigRows], [8, 8]); // 4 msig rows, each with the proof bytes and hash-only
  });

  test('personal_sign of the portable purposes', () {
    final tags = [purposeTagV(purpose: 'pop', version: 2), purposeTag(purpose: 'kem'), purposeTag(purpose: 'pqz-key')];
    expect([for (final t in tags) isPortablePurpose(tag: t)], [true, true, true]);
    expect(isPortablePurpose(tag: purposeTag(purpose: 'metatx')) || isPortablePurpose(tag: purposeTag(purpose: 'pop')), isFalse);
    final md = b32(byKey(regs, 'name', 'msig-pq-native')['memberDigest']);
    // known answer from the JS reference (clientkeys ua.js); prefix = 0x19 + "Ethereum Signed Message:\n32" (28 bytes)
    expect(hx(md), '0x606d9a70c70d39e5d8d079c3ae31eefa6db574219dab56d6c776cb6731e61a7c');
    expect(hx(personalSignDigest(digest: md)), '0xe5d24987e9b4e710063a5432d6215eaead64d8dc073f7561726d21644d54c3d8');
    final n = byKey(rows(pv, 'negatives'), 'name', 'native-personal-sign-under-metatx');
    expect(isPortablePurpose(tag: b32(n['mutation']['set']['purposeTag'])), isFalse);
  });

  test('holder refusals', () {
    var run = 0, sigLevel = 0;
    for (final n in rows(pv, 'negatives')) {
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
          expect(hx(register(mut).message), isNot(row['popMessage']), reason: '$name');
        } else {
          expect(errCode(() => register(mut)), err, reason: '$name');
        }
        run++;
      } else if (entry == 'setPqzKey' && (err == 'UAPqzKeySet' || err == 'UAPqzHolder' || err == 'UAPqzPopHash')) {
        final rec = byKey(rows(pv, 'pqzKeyRecords'), 'name', m['row']);
        final uaHex = (set['ua'] ?? rec['ua']) as String, holder = byKey(regs, 'ua', uaHex);
        final hash = bytes((set['pqzPopHash'] ?? rec['pqzPopHash']) as String);
        expect(
            errCode(() => pqzKeyRecordMessage(
                kind: holder['kind'], ua: b32(uaHex), keyData: bytes(holder['keyData']), pqzKey: bytes(rec['pqzKey']),
                pqzPopHash: hash, alreadySet: (holder['attrs'] as Map)['pqzKey'] != '0x')),
            err, reason: '$name');
        run++;
      } else if (entry == 'setKemKey' && name == 'kem-record-of-other-ua') {
        // the record of one UA offered for another: the signed message differs, so the signature cannot verify
        final k = byKey(rows(pv, 'kemRecords'), 'id', m['row']);
        final t = byKey(regs, 'ua', set['ua']);
        final msg = kemRecordMessage(kind: t['kind'], ua: b32(set['ua']), version: BigInt.from(k['version'] as int), kemPk: bytes(k['kemPk']));
        expect(hx(msg), isNot(k['message']));
        run++;
      } else {
        sigLevel++; // signatures / native personal_sign: verified by the signature vectors
      }
    }
    expect([run, sigLevel], [60, 7]);
    final u = U8Array32(Uint8List.fromList(List.filled(32, 1))), key = Uint8List(16384), proof = Uint8List.fromList(List.filled(32, 7));
    HolderPop holder({required int kind, Uint8List? keyData, Uint8List? pqzKey, Uint8List? pqzPop, Uint8List? pqzPopHash, KemRecord? kem}) =>
        holderPopMessage(
            kind: kind, ua: u, keyData: keyData ?? Uint8List(0), pqzKey: pqzKey, pqzPop: pqzPop, pqzPopHash: pqzPopHash, kemRecord: kem);
    // malformed msig key data is UAKeyData, not "not a holder"; an msig without key data is not a holder
    for (final kd in [Uint8List.fromList([0, 2, 0]), Uint8List.fromList([0, 2, 0, 2, 9, 9])]) {
      expect(errCode(() => holder(kind: 0x0120, keyData: kd, pqzKey: key, pqzPopHash: proof)), 'UAKeyData');
    }
    expect(errCode(() => holder(kind: 0x0120, pqzKey: key, pqzPopHash: proof)), 'UAPqzHolder');
    expect(errCode(() => holder(kind: 0x0130, pqzKey: key, pqzPopHash: Uint8List(31))), 'UAPqzPopHash');
    expect(errCode(() => holder(kind: 0x0130, pqzKey: key, pqzPop: Uint8List(0))), 'UAPqzPopHash');
    expect(errCode(() => holder(kind: 0x0130, pqzKey: Uint8List(100), pqzPopHash: proof)), 'UAKeyData');
    expect(errCode(() => holder(kind: 0x0130, kem: KemRecord(version: BigInt.one, pk: Uint8List(0)))), 'UAKemKeyLength');
    expect(errCode(() => holder(kind: 0x0101, kem: KemRecord(version: BigInt.one, pk: _kem(1601)))), 'UAKemHolder');
    // a zero-length proof hash is absent (same as no hash)
    expect(hx(holder(kind: 0x0130, pqzPopHash: Uint8List(0)).message), hx(holder(kind: 0x0130).message));
  });
}
