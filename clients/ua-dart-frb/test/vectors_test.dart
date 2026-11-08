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
    expect(rows(k, 'purposes').length, 15); // 14 purposes, `pop` has v1 and v2
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

  // ua-mtx-merge spec §6, MD-9: every row of id_display.json, and a row for every kind of the table.
  test('id_display.json rows', () {
    final d = rows(load('id_display.json'), 'rows');
    for (final r in d) {
      final w = r['display'] as Map?;
      if (w != null) {
        expect(idDisplay(id: r['id'], kind: r['kind']), w['address'] ?? w['urn'], reason: r['name']);
      } else {
        expect(errCode(() => idDisplay(id: r['id'], kind: r['kind'])), r['error'], reason: r['name']);
      }
    }
    for (final t in rows(load('kinds.json'), 'kinds')) {
      final info = kindInfo(kind: t['kind']);
      bool want(Map r) => info.native ? r['error'] == 'UAKindNotDerived' : (r['display'] as Map?)?['urn'] != null;
      expect(d.any((r) => r['kind'] == info.kind && want(r)), isTrue, reason: 'no row for ${info.name}');
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
      final ua = b32(p['ua']), kh = b32(p['pqzKeyHash']), kr = b32(p['kemRecordHash']);
      expect(hx(portableRecordDigest(ua: ua, kind: p['kind'], pqzKeyHash: kh, kemRecordHash: kr)), p['portableRecordDigest']);
      expect(hx(registrationDigest(ua: ua, kind: p['kind'], pqzKeyHash: kh, kemRecordHash: kr, pqzPopHash: b32(p['pqzPopHash']))),
          p['registrationDigest']);
    }
    expect(hx(chainKeyHash(chainId: 0x10000000007)), '0x6e45d591a544f53396f6e86d49f5809196c5725f9d99dbd2ca97f9925c7ce950'); // keccak256("evm:1099511627783")
    final kinds = load('kinds.json');
    final pk = bytes(kinds['pqzKey']), proof = Uint8List.fromList(List.filled(32, 7));
    for (final p in rows(s, 'pqzReg')) {
      final ua = b32(p['ua']), kem = bytes(p['kemRecordHash']), h = keyHashOf(kind: 0x0142, keyData: pk)!;
      expect(hx(h), p['pqzKeyHash']);
      final portable = portableRecordDigest(ua: ua, kind: p['kind'], pqzKeyHash: h, kemRecordHash: U8Array32(kem));
      expect(hx(portable), p['portableRecordDigest']);
      expect(hx(uaMessage(kind: 0x0142, purpose: purposeTagV(purpose: 'pop', version: 2), digest: portable)), p['pqzRegMessage']);
      // the row's KEM record hash is opaque unless it is the zero record; the real records are in portable.json
      if (hx(kem) != hx(kemRecordHash(ua: ua, version: BigInt.zero, kemPk: Uint8List(0)))) continue;
      expect(hx(pqzRegMessage(kind: p['kind'], ua: ua, pqzKey: pk)), p['pqzRegMessage']);
      final got = holderPopMessage(kind: p['kind'], ua: ua, keyData: Uint8List(0), pqzKey: pk, pqzPopHash: proof);
      expect([hx(got.pqzKeyHash), hx(got.portableRecordDigest)], [p['pqzKeyHash'], p['portableRecordDigest']]);
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
      final ua = b32(p['ua']), none = kemRecordHash(ua: ua, version: BigInt.zero, kemPk: Uint8List(0));
      expect(hx(portableRecordDigest(ua: ua, kind: 0x0120, pqzKeyHash: h, kemRecordHash: none)), p['portableRecordDigest']);
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
    return holderPopMessage(
        kind: row['kind'],
        ua: b32(row['ua']),
        keyData: bytes(row['keyData']),
        pqzKey: key.isEmpty ? null : key,
        pqzPop: hashOnly || pop.isEmpty ? null : pop,
        pqzPopHash: hash.every((x) => x == 0) ? null : hash,
        kemPk: pk.isEmpty ? null : pk);
  }

  test('portable', () {
    final t = pv['tags'] as Map;
    String tg(String n) => (t[n] as Map)['hash'] as String;
    expect(hx(purposeTagV(purpose: 'pop', version: 2)), tg('PURPOSE_POP_V2'));
    expect(hx(purposeTag(purpose: 'kem')), tg('PURPOSE_KEM'));
    expect(hx(purposeTag(purpose: 'pqz-key')), tg('PURPOSE_PQZ_KEY'));
    expect(t.containsKey('KEM_RECORD_TAG'), isFalse); // the raw record tags are legacy (TS-D3)
    expect(hx(portableDomainSeparator()), (pv['typed'] as Map)['domainSeparator']);
    var n = 0, withPqz = 0, msigs = 0;
    for (final r in regs) {
      final ua = b32(r['ua']), name = r['name'] as String;
      expect(hx(uaOf(kind: r['kind'], keyData: bytes(r['keyData']))), r['ua'], reason: name);
      for (final hashOnly in [false, true]) {
        final h = register(r, hashOnly: hashOnly);
        expect(hx(h.pqzKeyHash), r['pqzKeyHash'], reason: name);
        expect(hx(h.pqzPopHash), (r['attrs'] as Map)['pqzPopHash'], reason: name);
        expect(hx(h.kemRecordHash), r['kemRecordHash'], reason: name);
        expect(hx(h.portableRecordDigest), r['portableRecordDigest'], reason: name);
        expect(hx(h.registrationDigest), r['registrationDigest'], reason: name);
        expect(hx(h.message), r['popMessage'], reason: name);
        final k = r['kind'] as int;
        expect(hx(portableRecordDigest(ua: ua, kind: k, pqzKeyHash: h.pqzKeyHash, kemRecordHash: h.kemRecordHash)), hx(h.portableRecordDigest));
        expect(hx(registrationDigest(ua: ua, kind: k, pqzKeyHash: h.pqzKeyHash, kemRecordHash: h.kemRecordHash, pqzPopHash: h.pqzPopHash)),
            hx(h.registrationDigest));
        expect(hx(uaMessage(kind: r['kind'], purpose: purposeTagV(purpose: 'pop', version: 2), digest: h.registrationDigest)), hx(h.message));
        expect(hxn(h.memberDigest) ?? '', r['memberDigest'] ?? '', reason: name);
      }
      final a = r['attrs'] as Map, pk = bytes(a['pqzKey']), kpk = bytes(a['kemPk']), v = BigInt.zero; // the register KEM key: version 0
      expect(hx(kemRecordHash(ua: ua, version: v, kemPk: kpk)), r['kemRecordHash'], reason: name);
      if (pk.isNotEmpty) {
        withPqz++;
        expect(hx(pqzRegMessage(kind: r['kind'], ua: ua, pqzKey: pk, kemPk: kpk.isEmpty ? null : kpk)),
            r['pqzRegMessage'], reason: name);
        // TS-D3: R_REG proves over the typed UAPortableRecord of the registering kind
        expect(hx(uaMessage(kind: 0x0142, purpose: purposeTagV(purpose: 'pop', version: 2), digest: b32(r['portableRecordDigest']))),
            r['pqzRegMessage'], reason: name);
      } else {
        expect(bytes(r['pqzRegMessage']).every((x) => x == 0), isTrue);
      }
      if (r['kind'] == 0x0120) msigs++;
      n++;
    }
    expect(n, regs.length);
    expect(withPqz > 0 && msigs > 0, isTrue);
    // mldsa87 (CTR-UA-39), fndsa1024 (CTR-UA-40): holders, read here and in the record tests: a registration with its KEM register
    // key, KEM records v1-v3, PQZ key records at the four sets
    for (final k in [0x0134, 0x0135]) {
      expect([for (final s in ['registrations', 'kemRecords', 'pqzKeyRecords']) rows(pv, s).where((r) => r['kind'] == k).length],
          [1, 3, 4], reason: '$k');
    }
  });

  test('kem record', () {
    for (final r in rows(pv, 'kemRecords')) {
      final ua = b32(r['ua']), pk = bytes(r['kemPk']), v = BigInt.from(r['version'] as int);
      final d = kemRecordDigest(ua: ua, version: v, kemPk: pk);
      expect(hx(d), r['digest']);
      expect(hx(kemRecordHash(ua: ua, version: v, kemPk: pk)), r['structHash']);
      final m = kemRecordMessage(kind: r['kind'], ua: ua, version: v, kemPk: pk);
      expect(hx(m), r['message']);
      expect(hx(m), hx(uaMessage(kind: r['kind'], purpose: purposeTag(purpose: 'kem'), digest: d)));
      if (r['kind'] == 0x0120) expect(hx(memberDigest(structureUa: ua, uaMsg: m)), r['memberDigest']);
    }
    final u = U8Array32(Uint8List.fromList(List.filled(32, 1)));
    expect(errCode(() => kemRecordDigest(ua: u, version: BigInt.zero, kemPk: _kem(1601))), 'UAKemVersion');
    // owner 2026-10-31: version 0 with a key is the register key's record (scheme != 0; its words against portable.json's
    // registrations above), never a setKemKey record
    expect(hx(kemRecordHash(ua: u, version: BigInt.zero, kemPk: _kem(1601))), isNot(hx(kemRecordHash(ua: u, version: BigInt.zero, kemPk: Uint8List(0)))));
    expect(errCode(() => kemRecordHash(ua: u, version: BigInt.zero, kemPk: _kem(1601, 0))), 'UAKemScheme');
    expect(errCode(() => kemRecordDigest(ua: u, version: BigInt.one, kemPk: _kem(1600))), 'UAKemKeyLength');
    expect(errCode(() => kemRecordDigest(ua: u, version: BigInt.one, kemPk: _kem(1602))), 'UAKemKeyLength');
    expect(errCode(() => kemRecordDigest(ua: u, version: BigInt.one, kemPk: Uint8List(0))), 'UAKemKeyLength');
    for (final scheme in [0, 2, 255]) {
      expect(errCode(() => kemRecordDigest(ua: u, version: BigInt.one, kemPk: _kem(1601, scheme))), 'UAKemScheme');
    }
    expect(hx(kemRecordDigest(ua: u, version: (BigInt.one << 64) - BigInt.one, kemPk: _kem(1601))), '0xa0063a84b56d80c83688d8caf5aeb4be8fb4556928e8bc649686449573938f07'); // pins the 8-byte version word
    // m-C3: frb would wrap 2^64 + 1 to 1 and -1 to 2^64 - 1; the package refuses them (as ua-dart / JS)
    final pk = _kem(1601), big = (BigInt.one << 64) + BigInt.one;
    for (final bad in [BigInt.one << 64, big, -BigInt.one]) {
      expect(errCode(() => kemRecordDigest(ua: u, version: bad, kemPk: pk)), 'UAKemVersion', reason: '$bad');
      expect(errCode(() => kemRecordHash(ua: u, version: bad, kemPk: pk)), 'UAKemVersion', reason: '$bad');
      expect(errCode(() => kemRecordMessage(kind: 0x0130, ua: u, version: bad, kemPk: pk)), 'UAKemVersion', reason: '$bad');
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
        expect(hx(pqzKeyRecordDigest(ua: ua, pqzKeyHash: g.pqzKeyHash, pqzPopHash: g.pqzPopHash)), hx(g.recordDigest));
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
    expect(n, rows(pv, 'pqzKeyRecords').length);
    expect(msigRows > 0, isTrue);
  });

  test('membership rows', () {
    expect(rows(pv, 'memberships').length, 6);
    for (final r in rows(pv, 'memberships')) {
      final ua = b32(r['ua']);
      final d = membershipDigest(ua: ua, member: b32(r['member']));
      expect(hx(d), r['digest']);
      final m = uaMessage(kind: 0x0120, purpose: purposeTag(purpose: 'membership'), digest: d);
      expect(hx(m), r['message']);
      expect(hx(memberDigest(structureUa: ua, uaMsg: m)), r['memberDigest']);
    }
  });

  test('portable purposes', () {
    final tags = [purposeTagV(purpose: 'pop', version: 2), purposeTag(purpose: 'kem'), purposeTag(purpose: 'pqz-key')];
    expect([for (final t in tags) isPortablePurpose(tag: t)], [true, true, true]);
    expect(isPortablePurpose(tag: purposeTag(purpose: 'metatx')) || isPortablePurpose(tag: purposeTag(purpose: 'pop')), isFalse);
    final n = byKey(rows(pv, 'negatives'), 'name', 'native-personal-sign-under-metatx');
    expect(isPortablePurpose(tag: b32(n['mutation']['set']['purposeTag'])), isFalse);
  });

  test('holder refusals', () {
    var run = 0, sigLevel = 0;
    for (final n in rows(pv, 'negatives')) {
      if (n['rule'] == 'msig-minimal') continue; // a registry rule over a full registration (msig minimal form)
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
      } else if (name == 'record-kind-mismatch') {
        // the typed record binds `kind`: the same UA and attributes under another kind is another message
        final row = byKey(regs, 'name', m['row']), ua = b32(row['ua']), z = U8Array32(Uint8List(32));
        final none = kemRecordHash(ua: ua, version: BigInt.zero, kemPk: Uint8List(0));
        final d = registrationDigest(ua: ua, kind: m['otherKind'], pqzKeyHash: z, kemRecordHash: none, pqzPopHash: z);
        expect(hx(uaMessage(kind: row['kind'], purpose: purposeTagV(purpose: 'pop', version: 2), digest: d)), isNot(row['popMessage']));
        run++;
      } else if (name == 'kem-record-as-registration') {
        // the row's own typed KEM record is not its registration (struct type)
        final row = byKey(regs, 'name', m['row']);
        expect(byKey(rows(pv, 'kemRecords'), 'ua', row['ua'])['digest'], isNot(row['registrationDigest']));
        run++;
      } else {
        sigLevel++; // signatures / native members: verified by the signature vectors
      }
    }
    expect(run + sigLevel + 1, rows(pv, 'negatives').length); // + the skipped msig-minimal row
    expect(run > 0 && sigLevel > 0, isTrue);
    final u = U8Array32(Uint8List.fromList(List.filled(32, 1))), key = Uint8List(16384), proof = Uint8List.fromList(List.filled(32, 7));
    HolderPop holder({required int kind, Uint8List? keyData, Uint8List? pqzKey, Uint8List? pqzPop, Uint8List? pqzPopHash, Uint8List? kemPk}) =>
        holderPopMessage(
            kind: kind, ua: u, keyData: keyData ?? Uint8List(0), pqzKey: pqzKey, pqzPop: pqzPop, pqzPopHash: pqzPopHash, kemPk: kemPk);
    // malformed msig key data is UAKeyData, not "not a holder"; an msig without key data is not a holder
    for (final kd in [Uint8List.fromList([0, 2, 0]), Uint8List.fromList([0, 2, 0, 2, 9, 9])]) {
      expect(errCode(() => holder(kind: 0x0120, keyData: kd, pqzKey: key, pqzPopHash: proof)), 'UAKeyData');
    }
    expect(errCode(() => holder(kind: 0x0120, pqzKey: key, pqzPopHash: proof)), 'UAPqzHolder');
    expect(errCode(() => holder(kind: 0x0130, pqzKey: key, pqzPopHash: Uint8List(31))), 'UAPqzPopHash');
    expect(errCode(() => holder(kind: 0x0130, pqzKey: key, pqzPop: Uint8List(0))), 'UAPqzPopHash');
    expect(errCode(() => holder(kind: 0x0130, pqzKey: Uint8List(100), pqzPopHash: proof)), 'UAKeyData');
    expect(errCode(() => holder(kind: 0x0130, kemPk: _kem(1600))), 'UAKemKeyLength');
    expect(errCode(() => holder(kind: 0x0130, kemPk: _kem(1601, 0))), 'UAKemScheme');
    expect(errCode(() => holder(kind: 0x0101, kemPk: _kem(1601))), 'UAKemHolder');
    expect(hx(holder(kind: 0x0130, kemPk: Uint8List(0)).message), hx(holder(kind: 0x0130).message));
    // a zero-length proof hash is absent (same as no hash)
    expect(hx(holder(kind: 0x0130, pqzPopHash: Uint8List(0)).message), hx(holder(kind: 0x0130).message));
  });

  /// clientkeys registrationArgs' input of a registration row; an msig's pop is its typed member list.
  Map<String, dynamic> regInput(Map r) => {
        'kind': r['kind'],
        'keyData': r['keyData'],
        'pqzKey': r['attrs']['pqzKey'],
        'pqzPopHash': r['attrs']['pqzPopHash'],
        'pqzPop': r['pqzPop'],
        'kemPk': r['attrs']['kemPk'],
        'pop': r['args']['pop'],
      };
  Map<String, dynamic> regArgs(Map<String, dynamic> i) => jsonDecode(registrationArgs(input: jsonEncode(i)));

  // Nested msig (nested.json): the digest chain from the low-level calls, the JSON calls with `inner`. Key data alone refuses an msig member by
  // name, so holderPopMessage and pqzKeyRecordMessage stop there on a record that needs its inner keys; their `With` forms take `inner`
  // ('nested inner'). This API verifies no signature.
  test('nested rows', () {
    final n = load('nested.json');
    final regs = (n['registrations'] as List).cast<Map<String, dynamic>>();
    final inner = {for (final r in regs.where((r) => r['kind'] == 0x0120)) r['ua']: r['keyData']};
    final zero = U8Array32(Uint8List(32)), popTag = purposeTagV(purpose: 'pop', version: 2), memberTag = purposeTag(purpose: 'member');
    final all = [...regs, ...(n['afterAcceptance'] as List).cast<Map<String, dynamic>>()];
    expect(all.length, 17);
    for (final r in all) {
      final name = r['name'] as String, k = r['kind'] as int, ua = b32(r['ua']), kemPk = bytes(r['attrs']['kemPk']);
      expect(hx(uaOf(kind: k, keyData: bytes(r['keyData']))), r['ua'], reason: name);
      final kem = kemRecordHash(ua: ua, version: BigInt.zero, kemPk: kemPk);
      final rd = registrationDigest(ua: ua, kind: k, pqzKeyHash: zero, kemRecordHash: kem, pqzPopHash: zero);
      final msg = uaMessage(kind: k, purpose: popTag, digest: rd);
      expect([hx(kem), hx(portableRecordDigest(ua: ua, kind: k, pqzKeyHash: zero, kemRecordHash: kem)), hx(rd), hx(msg)],
          [r['kemRecordHash'], r['portableRecordDigest'], r['registrationDigest'], r['popMessage']],
          reason: name);
      expect(regArgs({...regInput(r), 'kemCommit': false, 'inner': inner})['args'], r['args'], reason: name);
      if (r['kemCommit'] != null) {
        final c = regArgs({...regInput(r), 'kemCommit': true, 'inner': inner});
        expect([c['args'], c['kemFill']], [r['kemCommit']['register'], r['kemCommit']['fill']], reason: name);
        expect(errCode(() => holderPopMessage(kind: k, ua: ua, keyData: bytes(r['keyData']), kemPk: kemPk)), 'UAMemberUnknown', reason: name);
      }
      if (k != 0x0120) continue;
      final md = memberDigest(structureUa: ua, uaMsg: msg);
      expect(hx(md), r['memberDigest'], reason: name);
      for (final x in ((r['innerDigests'] as List?) ?? const []).cast<Map>()) {
        expect(hx(memberDigest(structureUa: b32(x['inner']), uaMsg: uaMessage(kind: 0x0120, purpose: memberTag, digest: md))), x['memberDigest'], reason: name);
      }
    }
    expect([rows(n, 'kemRecords').length, rows(n, 'pqzKeyRecords').length], [1, 4]);
    Map<String, dynamic> slots(Map r) => {'members': r['args']['sig']['members']};
    for (final r in rows(n, 'kemRecords').cast<Map>()) {
      final ua = b32(r['ua']), v = BigInt.from(r['version'] as int), pk = bytes(r['kemPk']);
      final m = kemRecordMessage(kind: r['kind'], ua: ua, version: v, kemPk: pk);
      expect([hx(kemRecordDigest(ua: ua, version: v, kemPk: pk)), hx(m), hx(memberDigest(structureUa: ua, uaMsg: m))],
          [r['digest'], r['message'], r['memberDigest']]);
      final i = {'ua': r['ua'], 'version': r['version'], 'kemPk': r['kemPk'], 'sig': slots(r)};
      expect(jsonDecode(setKemKeyArgs(input: jsonEncode(i))), r['args']);
    }
    for (final r in rows(n, 'pqzKeyRecords').cast<Map>()) {
      final name = r['name'] as String, ua = b32(r['ua']), h = b32(r['pqzKeyHash']), tag = purposeTag(purpose: 'pqz-key');
      final kd = pqzKeyDigest(ua: ua, pqzKeyHash: h), rd = pqzKeyRecordDigest(ua: ua, pqzKeyHash: h, pqzPopHash: b32(r['pqzPopHash']));
      final m = uaMessage(kind: r['kind'], purpose: tag, digest: rd);
      expect([hx(kd), hx(rd), hx(m), hx(uaMessage(kind: 0x0142, purpose: tag, digest: kd)), hx(memberDigest(structureUa: ua, uaMsg: m))],
          [r['pqzKeyDigest'], r['recordDigest'], r['message'], r['pqzRegMessage'], r['memberDigest']],
          reason: name);
      final i = {'ua': r['ua'], 'pqzKey': r['pqzKey'], 'pqzPopHash': r['pqzPopHash'], 'sig': slots(r)};
      expect(jsonDecode(setPqzKeyArgs(input: jsonEncode(i))), r['args'], reason: name);
      expect(errCode(() => pqzKeyRecordMessage(kind: r['kind'], ua: ua, keyData: bytes(inner[r['ua']]), pqzKey: bytes(r['pqzKey']), pqzPopHash: bytes(r['pqzPopHash']), alreadySet: false)),
          'UAMemberUnknown', reason: name);
    }
    expect(rows(n, 'memberships').length, 4);
    for (final m in rows(n, 'memberships').cast<Map>()) {
      final ua = b32(m['ua']), d = membershipDigest(ua: ua, member: b32(m['member']));
      final msg = uaMessage(kind: 0x0120, purpose: purposeTag(purpose: 'membership'), digest: d);
      expect([hx(d), hx(msg), hx(memberDigest(structureUa: ua, uaMsg: msg))], [m['digest'], m['message'], m['memberDigest']], reason: m['name'] as String);
    }
    expect(rows(n, 'authorizations').length, 5);
    final k = rows(n, 'kemRecords').first as Map;
    for (final a in rows(n, 'authorizations').cast<Map>()) {
      final name = a['name'] as String;
      final md = memberDigest(structureUa: b32(a['ua']), uaMsg: uaMessage(kind: 0x0120, purpose: b32(a['purposeTag']), digest: b32(a['digest'])));
      expect(hx(md), a['memberDigest'], reason: name);
      final i = {'ua': k['ua'], 'version': k['version'], 'kemPk': k['kemPk'], 'sig': a['uaSig']};
      expect(jsonDecode(setKemKeyArgs(input: jsonEncode(i)))['sig'], a['uaSig'], reason: name);
    }
    // the builder's own refusal is the minimal rule at both levels; the others are the registry's, on the signatures
    const minimal = {'inner-below-threshold', 'inner-index-past-the-members', 'inner-unsorted', 'inner-not-minimal', 'outer-not-minimal'};
    expect(rows(n, 'negatives').length, 13);
    for (final x in rows(n, 'negatives').cast<Map>()) {
      final name = x['name'] as String;
      final i = {...regInput(all.firstWhere((r) => r['name'] == x['row'])), 'kemCommit': false, 'inner': inner, 'pop': x['popTyped']};
      if (minimal.contains(name)) {
        expect(errCode(() => regArgs(i)), x['error'], reason: name);
      } else {
        expect(regArgs(i)['args']['pop'], x['popTyped'], reason: name);
      }
    }
    expect(rows(n, 'structures').length, 2);
    for (final s in rows(n, 'structures').cast<Map>()) {
      expect(hx(uaOf(kind: 0x0120, keyData: bytes(s['keyData']))), s['ua'], reason: s['name'] as String);
      expect(errCode(() => msigPqzEligible(keyData: bytes(s['keyData']))), s['error'], reason: s['name'] as String);
    }
    for (final r in rows(n, 'eligibility').cast<Map>()) {
      expect(errCode(() => msigPqzEligible(keyData: bytes(r['keyData']))), 'UAMemberUnknown', reason: r['reason'] as String);
    }
  });

  // The With forms with inner ({id: keyData}, the JSON calls' form): msig-nested-pq's eligibility and holder record, every eligibility row
  // and every nested PQZ key record reproduce; without inner they stay UAMemberUnknown, so does a third level. Every memberships row's
  // stored bytes turn back into its slot through replayedMemberSig.
  test('nested inner', () {
    final n = load('nested.json');
    final regs = (n['registrations'] as List).cast<Map<String, dynamic>>();
    final inner = {for (final r in regs.where((r) => r['kind'] == 0x0120)) r['ua']: r['keyData']};
    final all = jsonEncode(inner);
    String? mh(U8Array32? m) => m == null ? null : hx(m);
    final holders = [...regs, ...(n['afterAcceptance'] as List).cast<Map<String, dynamic>>()]
        .where((r) => r['attrs']['kemPk'] != '0x' || r['attrs']['pqzKey'] != '0x')
        .toList();
    expect(holders.map((r) => r['name']), ['msig-nested-pq']);
    for (final r in holders) {
      final name = r['name'] as String, ua = b32(r['ua']), d = bytes(r['keyData']), pk = bytes(r['attrs']['kemPk']);
      expect(msigPqzEligibleWith(keyData: d, inner: all), isTrue, reason: name);
      expect(errCode(() => msigPqzEligible(keyData: d)), 'UAMemberUnknown', reason: name);
      final h = holderPopMessageWith(kind: 0x0120, ua: ua, keyData: d, kemPk: pk, inner: all);
      expect([hx(h.kemRecordHash), hx(h.portableRecordDigest), hx(h.registrationDigest), hx(h.message), mh(h.memberDigest)],
          [r['kemRecordHash'], r['portableRecordDigest'], r['registrationDigest'], r['popMessage'], r['memberDigest']],
          reason: name);
      expect(errCode(() => holderPopMessageWith(kind: 0x0120, ua: ua, keyData: d, kemPk: pk, inner: '')), 'UAMemberUnknown', reason: name);
    }
    for (final r in rows(n, 'eligibility').cast<Map>()) {
      final why = r['reason'] as String, d = bytes(r['keyData']);
      expect(msigPqzEligibleWith(keyData: d, inner: jsonEncode(r['inner'])), r['eligible'], reason: why);
      for (final none in ['', 'null', '{}']) {
        expect(errCode(() => msigPqzEligibleWith(keyData: d, inner: none)), 'UAMemberUnknown', reason: why);
      }
    }
    final third = rows(n, 'structures').first as Map, pq = holders.first['keyData'] as String;
    expect(errCode(() => msigPqzEligibleWith(keyData: bytes(third['keyData']), inner: jsonEncode({third['member']: pq}))), 'UAMemberUnknown',
        reason: 'a third level');
    for (final bad in ['not json', '[]', jsonEncode({'0x01': '0x'}), ' ' * 65537]) {
      expect(errCode(() => msigPqzEligibleWith(keyData: bytes(pq), inner: bad)), 'UAArgument', reason: bad.length > 12 ? bad.substring(0, 12) : bad);
    }
    expect(rows(n, 'pqzKeyRecords').length, 4);
    for (final r in rows(n, 'pqzKeyRecords').cast<Map>()) {
      final name = r['name'] as String, ua = b32(r['ua']), d = bytes(inner[r['ua']]), key = bytes(r['pqzKey']), h = bytes(r['pqzPopHash']);
      final g = pqzKeyRecordMessageWith(kind: 0x0120, ua: ua, keyData: d, pqzKey: key, pqzPopHash: h, alreadySet: false, inner: all);
      expect([hx(g.pqzKeyHash), hx(g.pqzPopHash), hx(g.pqzKeyDigest), hx(g.recordDigest), hx(g.message), hx(g.pqzRegMessage), mh(g.memberDigest)],
          [r['pqzKeyHash'], r['pqzPopHash'], r['pqzKeyDigest'], r['recordDigest'], r['message'], r['pqzRegMessage'], r['memberDigest']],
          reason: name);
      expect(errCode(() => pqzKeyRecordMessageWith(kind: 0x0120, ua: ua, keyData: d, pqzKey: key, pqzPopHash: h, alreadySet: false, inner: '')),
          'UAMemberUnknown', reason: name);
    }
    expect(rows(n, 'memberships').length, 4);
    for (final m in rows(n, 'memberships').cast<Map>()) {
      final name = m['name'] as String, d = bytes(regs.firstWhere((r) => r['ua'] == m['ua'])['keyData']), st = bytes(m['stored']);
      final index = m['index'] as int;
      expect(jsonDecode(replayedMemberSig(keyData: d, index: index, stored: st)), {'index': index, 'members': m['members'], 'sig': m['sig']},
          reason: name);
      expect(errCode(() => replayedMemberSig(keyData: d, index: 16, stored: st)), 'UAUnauthorized', reason: name);
      if ((m['members'] as List).isNotEmpty) {
        expect(errCode(() => replayedMemberSig(keyData: d, index: index, stored: Uint8List.fromList([...st, 0]))), 'UAUnauthorized',
            reason: '$name: not canonical');
      }
    }
  });

  /// abi.encode(InnerSig[]) of a typed list [{index, sig}]: the bytes an msig member's UAMemberSig carries.
  Uint8List encodeInnerSigs(List list) {
    Uint8List word(int v) => Uint8List(32)..buffer.asByteData().setUint64(24, v);
    final head = <int>[...word(0x20), ...word(list.length)], tail = <int>[];
    for (final x in list.cast<Map>()) {
      final s = bytes(x['sig']);
      head.addAll(word(32 * list.length + tail.length));
      tail
        ..addAll(word(x['index'] as int))
        ..addAll(word(0x40))
        ..addAll(word(s.length))
        ..addAll(s)
        ..addAll(Uint8List((32 - s.length % 32) % 32));
    }
    return Uint8List.fromList([...head, ...tail]);
  }

  // owner 2026-11-03: memberSigHashOf(ua, index) is keccak256 of the bytes the slot's UAMemberSig carries: its sig, or an msig member's
  // abi.encode(InnerSig[]). Every msig registration row's memberSigHashes (portable.json, its negative, nested.json), and every memberships
  // row's storedHash = keccak256(stored), stored being that slot's bytes.
  test('member sig hashes', () {
    final p = load('portable.json'), n = load('nested.json');
    final regs = [
      ...rows(p, 'registrations'),
      ...rows(p, 'negatives').where((x) => x['registration'] != null).map((x) => x['registration']),
      ...rows(n, 'registrations'),
      ...rows(n, 'afterAcceptance'),
    ].cast<Map>().where((r) => r['kind'] == 0x0120).toList();
    var slots = 0, inner = 0;
    for (final r in regs) {
      final pop = r['args']['pop'] as List, hs = r['memberSigHashes'] as List;
      expect(hs.length, pop.length, reason: r['name']);
      for (var i = 0; i < pop.length; i++, slots++) {
        final s = pop[i] as Map, members = s['members'] as List;
        if (members.isNotEmpty) inner++;
        expect([hs[i]['index'], hs[i]['hash']], [s['index'], hx(keccak256(data: members.isNotEmpty ? encodeInnerSigs(members) : bytes(s['sig'])))],
            reason: '${r['name']} slot $i');
      }
    }
    expect([regs.length, slots, inner], [19, 30, 7], reason: 'msig rows, slots, msig-member slots');
    expect(rows(n, 'memberships').length, 4);
    for (final m in rows(n, 'memberships').cast<Map>()) {
      final stored = bytes(m['stored']), members = m['members'] as List;
      expect(hx(keccak256(data: stored)), m['storedHash'], reason: m['name']);
      expect(hx(members.isNotEmpty ? encodeInnerSigs(members) : bytes(m['sig'])), m['stored'], reason: "${m['name']}: the encoder's control");
    }
    expect(hx(keccak256(data: Uint8List(0))), '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  });

  test('registration args', () {
    var commits = 0;
    for (final r in regs) {
      final name = r['name'] as String;
      final a = regArgs({...regInput(r), 'kemCommit': false});
      expect(a['args'], r['args'], reason: name);
      expect(a['kemFill'], isNull, reason: name);
      expect(a['kemFillCalldataLength'], isNull, reason: name);
      expect(regArgs(regInput(r))['args'], r['args'], reason: '$name: under the limit, the full key');
      if (r['attrs']['kemPk'] == '0x') {
        expect((r as Map).containsKey('kemCommit'), isFalse, reason: name);
        continue;
      }
      final c = regArgs({...regInput(r), 'kemCommit': true});
      expect(c['args'], r['kemCommit']['register'], reason: name);
      expect(c['kemFill'], r['kemCommit']['fill'], reason: name);
      expect(c['kemFillCalldataLength'], 2020, reason: name);
      commits++;
    }
    expect(commits, regs.where((r) => (r as Map).containsKey('kemCommit')).length);
    expect(commits, greaterThan(0));
    const typed = {
      0x0100: ('registerWebAuthn', 580),
      0x0110: ('registerMuSig2', 1124),
      0x0112: ('registerMuSig2', 1124),
      0x0111: ('registerFrost', 2308),
      0x0113: ('registerFrost', 2308),
    };
    final valid = rows(load('kinds.json'), 'valid');
    final keyed = valid.where((v) => typed.containsKey(v['kind'])).toList();
    expect(keyed.length, 6);
    for (final v in keyed) {
      // no attributes, a 32-byte pop (cast 1.8.5)
      final a = regArgs({'kind': v['kind'], 'keyData': v['keyData'], 'pop': '0x${'00' * 32}'});
      expect((a['args']['entry'], a['calldataLength']), typed[v['kind']], reason: v['name']);
    }
    expect(regArgs({'kind': 0x0101, 'keyData': valid[1]['keyData']})['args']['entry'], 'register');
    // the hash commit only over 261,909 B (PQZH n2560-kmax16384's sizes; ua-rs registration_hash_commit_when_over_limit)
    final x = {
      'kind': 0x0131,
      'keyData': '0x${'5a' * 1952}',
      'pqzKey': '0x${'5a' * 20480}',
      'pqzPop': '0x${'5a' * 234238}',
      'kemPk': '0x01${'5a' * 1600}',
      'pop': '0x${'5a' * 3309}',
    };
    expect(regArgs({...x, 'kemCommit': false})['calldataLength'], 262116);
    final auto = regArgs(x);
    expect([auto['calldataLength'], auto['kemFillCalldataLength'], auto['kemFill']['version']], [260548, 2020, 0]);
    for (final (bad, code) in [
      ('not json', 'UAArgument'),
      ('{"kind": 65536}', 'UAArgument'),
      ('{"kind": 257, "keyData": "0xzz"}', 'UAArgument'),
      ('{"kind": 288, "keyData": "0x00020000", "pop": "0x"}', 'UAArgument'),
      ('{"kind": 288, "keyData": "0x000200"}', 'UAKeyData'),
      ('{"kind": 305, "kemPk": "0x0101"}', 'UAKemKeyLength'),
      ('{"kind": 305, "pqzKey": "0x01", "pqzPopHash": "0x01", "pqzPop": "0x01"}', 'UAPqzPopHash'),
    ]) {
      expect(errCode(() => registrationArgs(input: bad)), code, reason: bad);
    }
  });

  /// A record row's `UASig`: its `sig`, an msig's as the typed member list; absent fields are empty.
  Map recordSig(Map r) => r['kind'] == 0x0120 ? {'members': r['args']['sig']['members']} : {'signature': r['sig']};

  test('set key args', () {
    final kems = rows(pv, 'kemRecords'), pqz = rows(pv, 'pqzKeyRecords');
    expect(kems, hasLength(15)); // + v1-v3 of mldsa87, fndsa1024
    for (final k in kems) {
      final i = {'ua': k['ua'], 'version': k['version'], 'kemPk': k['kemPk'], 'sig': recordSig(k)};
      expect(jsonDecode(setKemKeyArgs(input: jsonEncode(i))), k['args'], reason: k['id']);
    }
    expect(pqz, hasLength(16)); // + mldsa87, fndsa1024 at the four sets
    for (final r in pqz) {
      final i = {'ua': r['ua'], 'pqzKey': r['pqzKey'], 'pqzPopHash': r['pqzPopHash'], 'sig': recordSig(r)};
      expect(jsonDecode(setPqzKeyArgs(input: jsonEncode(i))), r['args'], reason: r['name']);
    }
    final ua = '0x${'11' * 32}';
    for (final (bad, code) in [
      ('not json', 'UAArgument'),
      ('{"ua": "0x11", "version": 1}', 'UAArgument'),
      (jsonEncode({'ua': ua}), 'UAArgument'),
      (jsonEncode({'ua': ua, 'version': 1, 'kemPk': '0x0101'}), 'UAKemKeyLength'),
    ]) {
      expect(errCode(() => setKemKeyArgs(input: bad)), code, reason: bad);
    }
    for (final (bad, code) in [
      ('not json', 'UAArgument'),
      (jsonEncode({'ua': ua, 'pqzPopHash': '0x01'}), 'UAPqzPopHash'),
      (jsonEncode({'ua': ua, 'pqzPopHash': ua, 'sig': '0x01'}), 'UAArgument'),
    ]) {
      expect(errCode(() => setPqzKeyArgs(input: bad)), code, reason: bad);
    }
  });

  // governance T14: governanceBit against governance_bits.json on disk, every row; past bit 23 UAArgument
  test('governance bits rows', () {
    final v = jsonDecode(File('$vectors/../governance/governance_bits.json').readAsStringSync()) as Map;
    final rows = v['bits'] as List;
    expect(rows.length, 24);
    for (final r in rows) {
      expect(jsonDecode(governanceBit(bit: r['bit'] as int)), r, reason: 'bit ${r['bit']}');
    }
    for (final bit in [24, 127, 128, 255, 256, -1]) {
      expect(errCode(() => governanceBit(bit: bit)), 'UAArgument', reason: '$bit');
    }
  });

  // pay-meta-tax T41: paymeta.json v2 rows (257 bytes refused) and paytax.json's UAPayWithTax digest row
  test('pay rows', () {
    final pm = jsonDecode(File('$vectors/../metatx/paymeta.json').readAsStringSync()) as List;
    for (final r in pm) {
      final i = jsonEncode({'salt': r['salt'], 'payNo': r['payNo'], 'schema': r['schema'], 'body': r['body']});
      if (r['accepted'] as bool) {
        expect((jsonDecode(metaPayId(input: i)) as Map)['payId'], r['payId'], reason: r['name'] as String);
      } else {
        expect(errCode(() => metaPayId(input: i)), 'UAArgument', reason: r['name'] as String);
      }
    }
    final pt = jsonDecode(File('$vectors/../metatx/paytax.json').readAsStringSync()) as List;
    final r = pt.firstWhere((x) => x['name'] == 'digest_unbound_relayer_fee_recipient') as Map;
    final payment = {for (final k in ['from', 'to', 'value', 'entryRef', 'batch', 'nonce', 'validUntil', 'mode', 'relayer', 'fee', 'feeRecipient']) k: r[k]};
    final got = jsonDecode(payDigest(input: jsonEncode({'struct': 'UAPayWithTax', 'domain': r['domain'],
        'message': {'payment': payment, 'taxMode': r['taxMode'], 'tax': r['tax']}}))) as Map;
    expect(got['digest'], r['digest']);
    expect(got['structHash'], r['structHash']);
  });
}
