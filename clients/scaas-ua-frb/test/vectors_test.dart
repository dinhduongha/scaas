// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
// Mirrors clients/scaas-ua/tests/vectors.rs against smartcontracts/vectors/ua/. Needs the native library:
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
      expect(isMember(kind: n, hederaNative: false), r['member']);
      expect(isMember(kind: n, hederaNative: true), r['memberHedera']);
      if (info.native) {
        expect(errCode(() => tag(kind: n)), 'UAKindNotDerived');
      } else {
        expect(kindTagString(kind: n), r['tag']);
        expect(hx(tag(kind: n)), r['TAG']);
      }
    }
    for (final r in rows(k, 'groups')) {
      expect(groupTagString(group: r['group']), r['tag']);
      expect(hx(groupTag(group: r['group'])!), r['GROUP']);
    }
    expect(groupTag(group: 'nope'), isNull);
    for (final r in rows(k, 'purposes')) {
      expect(hx(purposeTag(purpose: r['purpose'])), r['purposeTag']);
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
      final p = purposeTag(purpose: r['purpose']);
      expect(hx(p), r['purposeTag']);
      expect(hx(uaMessage(kind: r['kind'], purpose: p, digest: b32(r['digest']))), r['uaMsg']);
    }
  });

  test('structures', () {
    final s = load('structures.json');
    for (final p in rows(s, 'pop')) {
      final c = s['contexts'][p['context']];
      final id = c['chainId'] as int; // 2^40+7 in context E
      expect(hx(chainKeyHash(chainId: id)), p['chainKeyHash']);
      expect(
          hx(popDigest(
              chainId: id,
              chainUid: b32(c['chainUid']),
              registry: b20(c['registry']),
              ua: b32(p['ua']),
              authRef: b32(p['authRef']))),
          p['popDigest']);
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
      validateKeyData(kind: 0x0140, keyData: Uint8List(3), hederaNative: false);
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
}
