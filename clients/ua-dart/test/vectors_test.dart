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
      if (info.native) {
        expect(_err(() => tag(n)).code, 'UAKindNotDerived');
        continue;
      }
      expect(kindTagString(n), r['tag']);
      expect(_hx(tag(n)), r['TAG']);
    }
    for (final r in (k['groups'] as List).cast<Map>()) {
      expect(groupTagString(r['group']), r['tag']);
      expect(_hx(groupTag(r['group'])), r['GROUP']);
    }
    for (final r in (k['purposes'] as List).cast<Map>()) {
      expect(_hx(purposeTag(r['purpose'])), r['purposeTag']);
    }
    expect(_err(() => purposeTag('nope')).code, 'UAPurposeUnknown');
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
      expect(_hx(uaMessage(_kind(r), purposeTag(r['purpose']), _b(r['digest']))), r['uaMsg']);
    }
  });

  test('structures', () {
    final s = _load('structures.json') as Map;
    final ctx = s['contexts'] as Map;
    for (final p in (s['pop'] as List).cast<Map>()) {
      final c = ctx[p['context']] as Map;
      final id = c['chainId'] as int;
      expect(_hx(chainKeyHash(id)), p['chainKeyHash']);
      expect(_hx(popDigest(id, _b(c['chainUid']), _b(c['registry']), _b(p['ua']), _b(p['authRef']))), p['popDigest']);
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
}
