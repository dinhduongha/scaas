// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-rs-sign T13c: the wallet surface (the Rust API through flutter_rust_bridge) against smartcontracts/vectors/ua/{keys,sign,kem,
// seal,vault,rs_vault,rs_signatures,zether}.json and the facades; mirrors clients/ua-cxx/tests/wallet_test.cpp. Needs the
// native library: (cd rust && cargo build) -> rust/target/debug/libscaas_ua_frb.so, or SCAAS_UA_LIB.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:scaas_ua_frb/scaas_ua_frb.dart';
import 'package:test/test.dart';

final vectors = Platform.environment['SCAAS_UA_VECTORS'] ?? '../../smartcontracts/vectors/ua';
Map<String, dynamic> load_(String name) => jsonDecode(File('$vectors/$name').readAsStringSync());

Uint8List bytes(String s) {
  final h = s.startsWith('0x') ? s.substring(2) : s;
  return Uint8List.fromList([for (var i = 0; i < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)]);
}

String hx(List<int> b) => '0x${b.map((x) => x.toRadixString(16).padLeft(2, '0')).join()}';
Uint8List utf8b(String s) => Uint8List.fromList(utf8.encode(s));
bool allZero(List<int> b) => b.every((x) => x == 0);
SecretBytes sec(List<int> b) => SecretBytes.take(Uint8List.fromList(b));
SecretBytes secs(String s) => sec(utf8.encode(s));
SecretBytes none() => SecretBytes.take(Uint8List(0));
Uint8List view(SecretBytes s) => SecretBytes.view(s);
int num_(dynamic v) => v is String ? int.parse(v) : v as int;

/// The UAError code [f] throws, or null.
Future<String?> code(Future<void> Function() f) async {
  try {
    await f();
  } on UAError catch (e) {
    return e.code;
  }
  return null;
}

final keys = load_('keys.json');
final mn = {for (final m in keys['mnemonics'] as List) m['id'] as String: m as Map<String, dynamic>};
const deterministic = {0x0101, 0x0102, 0x0106, 0x0107, 0x0108};
final _wallets = <String, UaWallet>{};

Future<UaWallet> walletOf(String id) =>
    walletFromMnemonic(words: secs(mn[id]!['words'] as String), bip39Passphrase: secs(mn[id]!['passphrase'] as String));
Future<UaWallet> w(String id) async => _wallets[id] ??= await walletOf(id);
Future<UaKemKey> kemOf(Map r) async {
  final k = await (await w((r['mnemonic'] ?? 'pq_kat') as String)).uaKey(kind: num_(r['kind']), account: num_(r['account']), index: num_(r['index']));
  return keyKemKey(k: k, version: BigInt.parse('${r['version']}'));
}

bool get falcon => features() & BigInt.from(UaFeature.falcon) != BigInt.zero;

void main() {
  setUpAll(() async {
    final path = Platform.environment['SCAAS_UA_LIB'] ?? 'rust/target/debug/libscaas_ua_frb.so';
    await ScaasUa.init(externalLibrary: ExternalLibrary.open(path));
  });
  tearDown(UaLoadHook.reset);

  test('load_refuses_wrong_abi_or_features', () async {
    load(); // positive control
    expect(features() & kRequiredFeatures, kRequiredFeatures);
    UaLoadHook.reportedAbiVersion = () => 5; // an older library
    expect(() => load(), throwsA(isA<UAError>().having((e) => e.code, 'code', 'UAAbiMismatch')));
    final words = secs(mn['pq_kat']!['words'] as String);
    expect(await code(() => walletFromMnemonic(words: words, bip39Passphrase: none())), 'UAAbiMismatch');
    expect(await code(kemEphemeral), 'UAAbiMismatch');
    expect(await code(linkSessionNew), 'UAAbiMismatch');
    expect(await code(() => seal(kemPk: Uint8List(1601)..[0] = 1, purpose: 'scaas/backup/v1', aad: [], pt: none())), 'UAAbiMismatch');
    UaLoadHook.reportedAbiVersion = () => 7;
    expect(await code(() async => load()), 'UAAbiMismatch');
    UaLoadHook.reset();
    UaLoadHook.reportedFeatures = () => kRequiredFeatures & ~BigInt.from(UaFeature.pqz);
    expect(await code(() async => load()), 'UAAbiMismatch');
    UaLoadHook.reportedFeatures = () => kRequiredFeatures & ~BigInt.from(UaFeature.pqzSetN2304Kmax4096);
    expect(await code(kemEphemeral), 'UAAbiMismatch');
    UaLoadHook.reset();
    load();
  });

  test('secret_bytes_take_and_dispose', () async {
    final src = utf8b(mn['pq_kat']!['words'] as String), copy = Uint8List.fromList(src);
    final words = SecretBytes.take(src);
    expect(src.length == copy.length && allZero(src), true, reason: 'take zeroes the source');
    expect(view(words), copy, reason: 'the secret is in Rust memory');
    expect(words.size(), copy.length);
    final addr = words.addr();
    expect(words.addr(), addr, reason: 'never moved');
    final pass = secs(mn['pq_kat']!['passphrase'] as String);
    final wl = await walletFromMnemonic(words: words, bip39Passphrase: pass);
    expect(view(words), copy, reason: 'borrowed by the call, not consumed');
    expect(hx((await wl.uaKey(kind: 0x0102, account: 0, index: 0)).keyData()),
        hx((await (await w('pq_kat')).uaKey(kind: 0x0102, account: 0, index: 0)).keyData()));
    words.dispose();
    expect(words.isDisposed, true);
    expect(await code(() => walletFromMnemonic(words: secs('not a mnemonic at all'), bip39Passphrase: none())), 'UAArgument');
    expect(SecretBytes.take(Uint8List(0)).size(), 0);
    final over = Uint8List((1 << 24) + 1)..[0] = 7;
    expect(() => SecretBytes.take(over), throwsA(isA<UAError>().having((e) => e.code, 'code', 'UAArgument')));
    expect(over[0], 0, reason: 'zeroed when refused too');
    final leaf = await wl.exportPqzLeafRaw(account: 0, index: 0);
    expect([leaf.size(), allZero(view(leaf))], [32, false]);
    leaf.dispose();
    final (wg, sb) = await walletGenerate();
    final answers = [secs('a'), secs('b'), secs('c')];
    await code(() => seedBackupVerify(b: sb, answers: answers));
    expect(answers.every((a) => a.isDisposed), true, reason: 'the answers are consumed');
    wg.dispose();
  });

  test('handle_freed_once', () async {
    final wl = await walletOf('twelve_words');
    final before = liveHandles();
    final k = await wl.uaKey(kind: 0x0102, account: 0, index: 0);
    final k30 = await wl.uaKey(kind: 0x0130, account: 0, index: 0);
    final kk = await keyKemKey(k: k30, version: BigInt.zero);
    expect(liveHandles(), before + 3);
    k.dispose();
    k.dispose(); // a second dispose frees nothing
    expect(liveHandles(), before + 2);
    expect(() => k.keyData(), throwsA(isA<Object>()), reason: 'a disposed handle is refused');
    kk.dispose();
    k30.dispose();
    wl.dispose();
    expect(liveHandles(), before - 1, reason: 'each handle freed once, the wallet too');
  });

  test('keys_json', () async {
    var n = 0;
    for (final r in keys['ua'] as List) {
      final kind = r['kind'] as int;
      if ((kind == 0x0132 || kind == 0x0135) && !falcon) continue;
      final k = await (await w(r['mnemonic'])).uaKey(kind: kind, account: r['account'], index: r['index']);
      expect(hx(k.keyData()), r['keyData'], reason: r['name']);
      if (r['ua'] != null && kind != 0x0110 && kind != 0x0112) expect(hx(k.uaId()), r['ua'], reason: r['name']);
      n++;
    }
    expect(n, greaterThanOrEqualTo(184));
    for (final r in keys['native'] as List) {
      final k = await (await w(r['mnemonic'])).nativeKey(networkName: r['network'], index: r['index'], coinType: r['coinType']);
      expect(hx(k.keyData()), '0x${r['publicKey']}', reason: r['network']);
      if (r['address'] == null) {
        expect(await code(() async => k.address()), 'UAArgument');
      } else {
        expect(k.address(), r['address'], reason: r['network']);
      }
    }
    for (final r in keys['refusals'] as List) {
      final got = await code(() async {
        final wl = await w(r['mnemonic']);
        if (r['what'] == 'ua') {
          await wl.uaKey(kind: r['kind'], account: r['account'], index: r['index']);
        } else {
          await wl.nativeKey(networkName: r['network'], index: r['index'], coinType: r['coinType']);
        }
      });
      expect(got, 'UA${r['error']}', reason: r['reason']);
    }
  });

  test('sign_json', () async {
    final s = load_('sign.json');
    var exact = 0;
    for (final r in s['ua'] as List) {
      final kind = r['kind'] as int;
      if ((kind == 0x0132 || kind == 0x0135) && !falcon) continue;
      final k = await (await w(r['mnemonic'])).uaKey(kind: kind, account: r['account'], index: r['index']);
      final sig = await k.signUa(purpose: bytes(r['purposeTag']), digest: bytes(r['digest']));
      if (deterministic.contains(kind)) {
        expect(hx(sig), r['signature'], reason: r['name']);
        exact++;
      } else if (kind != 0x0132 && kind != 0x0135) {
        expect(sig.length, bytes(r['signature']).length, reason: r['name']);
      }
    }
    expect(exact, greaterThanOrEqualTo(10));
    for (final r in s['member'] as List) {
      final k = await (await w(r['mnemonic'])).uaKey(kind: r['kind'], account: r['account'], index: r['index']);
      final sig = await k.signMember(structureUa: bytes(r['structureUa']), structureUaMsg: bytes(r['structureUaMsg']));
      if (deterministic.contains(r['kind'])) expect(hx(sig), r['signature'], reason: r['name']);
    }
    final evm = await (await w('pq_kat')).nativeKey(networkName: 'evm', index: 0);
    var signed = 0, refused = 0;
    for (final r in s['policy'] as List) {
      if (r.containsKey('refused')) {
        expect(await code(() => evm.signTyped(typedDataJson: jsonEncode(r['td']), expectJson: jsonEncode(r['expect']))), 'UAPolicyRefused',
            reason: r['id']);
        refused++;
      } else {
        expect(await evm.signTyped(typedDataJson: jsonEncode(r['td']), expectJson: jsonEncode(r['expect'])),
            await evm.signDigestRaw(digest: bytes(r['digest'])),
            reason: r['id']);
        signed++;
      }
    }
    expect([signed, refused], [10, 14]);
    for (final r in s['typed']['generic'] as List) {
      expect(await evm.signTypedAny(typedDataJson: jsonEncode(r['td'])), await evm.signDigestRaw(digest: bytes(r['digest'])));
    }
    for (final r in s['typed']['refusals'] as List) {
      expect(await code(() => evm.signTypedAny(typedDataJson: jsonEncode(r['td']))), 'UAArgument', reason: r['id']);
    }
    for (final r in s['tx']['rows'] as List) {
      final sg = r['signer'];
      final k = await (await w(sg['mnemonic'])).nativeKey(networkName: sg['network'], index: sg['index']);
      expect(hx(await k.signTransaction(txJson: jsonEncode(r['tx']))), r['raw']);
    }
    for (final r in s['tx']['refusals'] as List) {
      expect(await code(() => evm.signTransaction(txJson: jsonEncode(r['tx']))), 'UAArgument', reason: r['id']);
    }
    for (final r in s['webauthn']['accepted'] as List) {
      expect(hx(await webauthnChallenge(purpose: bytes(r['purposeTag']), digest: bytes(r['digest']))), r['expectedChallenge']);
      expect(
          hx(await webauthnAssertion(
              keyData: bytes(r['keyData']),
              expectedChallenge: bytes(r['expectedChallenge']),
              authData: bytes(r['authData']),
              clientDataJson: bytes(r['clientDataJSON']),
              r: bytes(r['r']),
              s: bytes(r['s']))),
          r['assertion']);
    }
    for (final r in s['webauthn']['refusals'] as List) {
      expect(
          await code(() => webauthnAssertion(
              keyData: bytes(r['keyData']),
              expectedChallenge: bytes(r['expectedChallenge']),
              authData: bytes(r['authData']),
              clientDataJson: bytes(r['clientDataJSON']),
              r: bytes(r['r']),
              s: bytes(r['s']))),
          'UA${r['error']}',
          reason: r['case']);
    }
    var built = 0, mrefused = 0;
    for (final r in s['msig'] as List) {
      final list = await keyListNew();
      var n = 0;
      Future<int> pos(Map x) async {
        final k = x['key'];
        list.push(k: await (await w(k['mnemonic'])).uaKey(kind: k['kind'], account: k['account'], index: k['index']));
        return n++;
      }

      final slots = [];
      for (final sl in r['slots'] as List) {
        if (sl.containsKey('members')) {
          slots.add({
            'index': sl['index'],
            'members': [for (final x in sl['members'] as List) {'index': x['index'], 'key': await pos(x)}]
          });
        } else {
          slots.add({'index': sl['index'], 'key': await pos(sl)});
        }
      }
      final m = {'keyData': r['keyData'], 'slots': slots, if (r.containsKey('inner')) 'inner': r['inner']};
      final req = jsonEncode({'purpose': r['purposeTag'], 'digest': r['digest'], 'msig': m});
      if (r.containsKey('refused')) {
        expect(await code(() => uasig(requestJson: req, keys: list)), r['refused'], reason: r['case']);
        mrefused++;
      } else {
        final sig = jsonDecode(await uasig(requestJson: req, keys: list));
        expect([sig['keyData'], sig['signature']], ['0x', '0x'], reason: r['case']);
        built++;
      }
    }
    expect([built, mrefused], [3, 4]);
    final uak = await (await w('pq_kat')).uaKey(kind: 0x0108, account: 0, index: 0);
    expect(await code(() => uak.signDigestRaw(digest: Uint8List(32))), 'UARawDigestRefused');
    expect((await evm.signKeyProof(challenge: utf8b('challenge'))).length, 65);
  });

  test('rs_signatures_json', () async {
    for (final r in load_('rs_signatures.json')['rows'] as List) {
      final kind = r['kind'] as int;
      if ((kind == 0x0132 || kind == 0x0135) && !falcon) continue;
      final k = await (await w(r['mnemonic'])).uaKey(kind: kind, account: r['account'], index: r['index']);
      expect(hx(k.keyData()), r['keyData'], reason: r['name']);
      final sig = await k.signUa(purpose: bytes(r['purposeTag']), digest: bytes(r['digest']));
      if (kind != 0x0132 && kind != 0x0135) expect(sig.length, bytes(r['signature']).length, reason: r['name']);
    }
  });

  test('kem_json', () async {
    final k = load_('kem.json');
    for (final r in k['keys'] as List) {
      expect(hx((await kemOf(r)).kemPk()), r['kemPk']);
    }
    var refusals = 0;
    for (final r in k['refusals'] as List) {
      if (r['mnemonic'] == null || '${r['version']}'.length > 19) continue;
      final key = await (await w(r['mnemonic'])).uaKey(kind: num_(r['kind']), account: num_(r['account']), index: num_(r['index']));
      expect(await code(() => keyKemKey(k: key, version: BigInt.parse('${r['version']}'))), 'UA${r['error']}', reason: r['reason']);
      refusals++;
    }
    expect(refusals, 9);
    final k30 = await (await w('pq_kat')).uaKey(kind: 0x0130, account: 0, index: 0);
    expect(await code(() => keyKemKey(k: k30, version: -BigInt.one)), 'UAArgument', reason: 'a version below 0, before frb wraps it');
    expect(await code(() => keyKemKey(k: k30, version: BigInt.one << 64)), 'UAArgument', reason: 'past 2^64 - 1');
    for (final r in k['encapsRefusals'] as List) {
      expect(await code(() => kemEncaps(kemPk: bytes(r['kemPk']))), 'UA${r['error']}', reason: r['id']);
    }
    final kk = await kemOf(k['keys'][0]);
    final e = await kemEncaps(kemPk: bytes(k['keys'][0]['kemPk']));
    expect(view(await kk.decaps(mlkemCt: e.mlkemCt, x25519Eph: e.x25519Eph)), view(e.ss));
    for (final r in k['decaps'] as List) {
      final eph = bytes(r['x25519Eph']);
      if (eph.length != 32) continue;
      final kd = await kemOf(r['key']);
      if (r['error'] != null) {
        expect(await code(() => kd.decaps(mlkemCt: bytes(r['mlkemCt']), x25519Eph: eph)), 'UA${r['error']}', reason: r['id']);
      } else {
        expect(hx(view(await kd.decaps(mlkemCt: bytes(r['mlkemCt']), x25519Eph: eph))), r['ss'], reason: r['id']);
      }
    }
    expect((await kemEphemeral()).kemPk().length, 1601);
  });

  test('seal_json', () async {
    final s = load_('seal.json');
    for (final r in s['seal'] as List) {
      if (!(r['recipient'] as Map).containsKey('kind')) continue;
      final kk = await kemOf(r['recipient']);
      final sealed = UaSealed(mlkemCt: bytes(r['mlkemCt']), x25519Eph: bytes(r['x25519Eph']), ciphertext: bytes(r['ciphertext']));
      expect(hx(view(await kk.open(purpose: r['purpose'], aad: bytes(r['aad']), sealed: sealed))), hx(bytes(r['pt'])), reason: r['id']);
      final fresh = await seal(kemPk: bytes(r['kemPk']), purpose: r['purpose'], aad: bytes(r['aad']), pt: sec(bytes(r['pt'])));
      expect(hx(view(await kk.open(purpose: r['purpose'], aad: bytes(r['aad']), sealed: fresh))), hx(bytes(r['pt'])));
    }
    final base = (s['seal'] as List).firstWhere((r) => r['id'] == s['refusals']['base']);
    for (final r in s['refusals']['rows'] as List) {
      final wire = bytes(r['wire'] ?? base['wire']);
      if (wire[0] != 1 || wire[1] != 1) continue;
      final kk = await kemOf(r['key'] ?? s['refusals']['key']);
      final sealed = UaSealed(mlkemCt: wire.sublist(2, 1570), x25519Eph: wire.sublist(1570, 1602), ciphertext: wire.sublist(1602));
      expect(await code(() => kk.open(purpose: r['purpose'] ?? base['purpose'], aad: bytes(r['aad'] ?? base['aad']), sealed: sealed)),
          'UA${r['error']}',
          reason: r['id']);
    }
    var n = 0;
    for (final r in s['containers'] as List) {
      if ((r['opener'] as Map).containsKey('session')) continue;
      final kk = await kemOf(r['opener']['kem']);
      final members = r['members'] == null ? null : jsonEncode(r['members']);
      final accepted = r['accepted'] == null ? null : jsonEncode(r['accepted']);
      expect(
          hx(view(await kk.openContainer(
              containerJson: jsonEncode(r['container']), expectJson: jsonEncode(r['expect']), membersJson: members, acceptedJson: accepted))),
          hx(bytes(r['pt'])),
          reason: r['id']);
      if (accepted != null) {
        expect(
            await code(() =>
                kk.openContainer(containerJson: jsonEncode(r['container']), expectJson: jsonEncode(r['expect']), membersJson: members)),
            'UAContainerSender');
      }
      n++;
    }
    expect(n, 3);
    n = 0;
    for (final r in s['acceptance'] as List) {
      if (r.containsKey('link')) continue;
      final kk = await kemOf(r['opener']['kem']);
      final members = r['members'] == null ? null : jsonEncode(r['members']);
      final accepted = r['accepted'] == null ? null : jsonEncode(r['accepted']);
      final got = await code(() => r['restore'] == true
          ? walletRestoreBackup(
              kk: kk,
              containerJson: jsonEncode(r['container']),
              expectJson: jsonEncode(r['expect']),
              membersJson: members,
              acceptedJson: accepted,
              bip39Passphrase: none())
          : kk.openContainer(
              containerJson: jsonEncode(r['container']), expectJson: jsonEncode(r['expect']), membersJson: members, acceptedJson: accepted));
      expect(got, r['error'] == null ? null : 'UA${r['error']}', reason: r['id']);
      n++;
    }
    expect(n, 28);
  });

  test('backup_link_restore', () async {
    final k = load_('kem.json');
    final wl = await walletOf('twelve_words');
    final sender = await wl.uaKey(kind: 0x0102, account: 0, index: 0);
    final rec = await (await w('pq_kat')).uaKey(kind: 0x0130, account: 0, index: 0);
    final pk = bytes(k['keys'][0]['kemPk']);
    final cs = await walletBackupSeal(w: wl, sender: sender, recipients: [
      UaRecipient(kind: 0x0130, keyData: rec.keyData(), version: BigInt.zero, kemPk: pk, ephemeral: false),
      UaRecipient(kind: 0, keyData: Uint8List(0), version: BigInt.zero, kemPk: pk, ephemeral: true),
    ]);
    expect(cs.length, 2);
    final expectJson = jsonEncode({
      'purpose': 'scaas/backup/v1',
      'sender': {'ua': hx(sender.uaId())},
      'recipient': {'ua': hx(rec.uaId()), 'version': 0}
    });
    final kk = await kemOf(k['keys'][0]);
    final r = await walletRestoreBackup(kk: kk, containerJson: cs[0], expectJson: expectJson, bip39Passphrase: none());
    expect(hx((await r!.uaKey(kind: 0x0102, account: 0, index: 0)).keyData()), hx(sender.keyData()));
    expect(jsonDecode(r.manifestJson())['backupGeneration'], 1);
    expect(
        await walletRestoreBackupOver(current: r, kk: kk, containerJson: cs[0], expectJson: expectJson, bip39Passphrase: none()),
        isNull,
        reason: 'an equal generation installs nothing');
    await walletBackupSeal(w: wl, sender: sender, recipients: [
      UaRecipient(kind: 0x0130, keyData: rec.keyData(), version: BigInt.zero, kemPk: pk, ephemeral: false)
    ]);
    expect(
        await code(() =>
            walletRestoreBackupOver(current: wl, kk: kk, containerJson: cs[0], expectJson: expectJson, bip39Passphrase: none())),
        'UABackupRollback');
    expect(
        await walletRestoreBackupRollback(current: wl, kk: kk, containerJson: cs[0], expectJson: expectJson, bip39Passphrase: none()),
        isNotNull);
    final s = await linkSessionNew();
    final c = await wl.linkSeal(sender: sender, sessionKemPk: s.kemPk(), shortCode: s.shortCode());
    final lexp = jsonEncode({
      'purpose': 'scaas/link/v1',
      'sender': {'ua': hx(sender.uaId())},
      'recipient': {'kemPkHash': hx(keccak256(data: s.kemPk()))}
    });
    final linked = await walletFromLink(session: s, containerJson: c, expectJson: lexp, bip39Passphrase: none());
    expect(hx((await linked.uaKey(kind: 0x0102, account: 0, index: 0)).keyData()), hx(sender.keyData()));
    expect(await code(() => walletFromLink(session: s, containerJson: c, expectJson: lexp, bip39Passphrase: none())), 'UAKeyRevoked');
    expect(await code(() async => s.kemPk()), 'UAKeyRevoked');
  });

  test('vault_json and rs_vault_json', () async {
    final v = load_('vault.json');
    final byEntropy = {for (final m in keys['mnemonics'] as List) if (m['passphrase'] == '') m['entropy']: m['id']};
    Future<UaWallet> open(Map vault, Map u) => walletOpenVault(
        vaultJson: jsonEncode(vault),
        vaultPassphrase: u.containsKey('pin') ? secs(u['pin']) : null,
        prf32: u.containsKey('prfOutput') ? sec(bytes(u['prfOutput'])) : null,
        bip39Passphrase: none());
    for (final r in v['vaults'] as List) {
      final wl = await open(r['vault'], r['unlock']);
      expect(hx((await wl.uaKey(kind: 0x0102, account: 0, index: 0)).keyData()),
          hx((await (await w(byEntropy[r['plaintext']])).uaKey(kind: 0x0102, account: 0, index: 0)).keyData()),
          reason: r['id']);
    }
    for (final r in v['refusals'] as List) {
      expect(await code(() => open(r['vault'], r['unlock'])), 'UA${r['error']}', reason: r['id']);
    }
    final prfRow = (v['vaults'] as List).firstWhere((r) => (r['unlock'] as Map).containsKey('prfOutput'));
    expect(await code(() => open(prfRow['vault'], {})), 'UAArgument', reason: 'neither');
    await open(prfRow['vault'], {'pin': 'not the passphrase', 'prfOutput': prfRow['unlock']['prfOutput']}); // both: PRF first
    final rs = load_('rs_vault.json');
    for (final r in rs['vaults'] as List) {
      final wl = await open(r['vault'], r['unlock']);
      expect(hx((await wl.uaKey(kind: 0x0102, account: 0, index: 0)).keyData()),
          hx((await (await w(r['mnemonic'])).uaKey(kind: 0x0102, account: 0, index: 0)).keyData()),
          reason: r['id']);
    }
    for (final b in rs['backups'] as List) {
      final o = b['opener']['kem'];
      final rua = (await (await w(o['mnemonic'])).uaKey(kind: o['kind'], account: 0, index: 0)).uaId();
      final restored = await walletRestoreBackup(
          kk: await kemOf(o),
          containerJson: jsonEncode(b['container']),
          expectJson: jsonEncode({
            'purpose': 'scaas/backup/v1',
            'sender': {'ua': b['senderUa']},
            'recipient': {'ua': hx(rua), 'version': 0}
          }),
          bip39Passphrase: none());
      final m = jsonDecode(restored!.manifestJson());
      expect(m['backupGeneration'], b['generation']);
      expect((m['imports'] as List).length, (b['secrets'] as List).length);
      await restored.importedKey(networkName: 'evm', n: 0);
    }
  });

  test('custody', () async {
    final wl = await walletOf('twelve_words');
    final v = await walletSealVault(w: wl, vaultPassphrase: secs('correct horse 9'));
    final k = await wl.uaKey(kind: 0x0101, account: 0, index: 0);
    final metatx = purposeTag(purpose: 'metatx');
    final before = await k.signUa(purpose: metatx, digest: Uint8List(32));
    wl.lock();
    expect(await code(() => k.signUa(purpose: metatx, digest: Uint8List(32))), 'UAKeyRevoked');
    expect(await code(() => wl.uaKey(kind: 0x0101, account: 0, index: 0)), 'UAWalletLocked');
    expect(wl.memoryProtection().chunks, 0);
    await walletUnlock(w: wl, vaultJson: v, vaultPassphrase: secs('correct horse 9'), bip39Passphrase: none());
    expect(await code(() => k.signUa(purpose: metatx, digest: Uint8List(32))), 'UAKeyRevoked', reason: 'unlock does not revive');
    expect(await (await wl.uaKey(kind: 0x0101, account: 0, index: 0)).signUa(purpose: metatx, digest: Uint8List(32)), before);
    final ik = await walletImportNativeKey(w: wl, networkName: 'evm', secretKey: sec(List.generate(32, (i) => i + 1)));
    final d = Uint8List(32)..fillRange(0, 32, 7);
    final sig = await ik.signDigestRaw(digest: d);
    final label = await walletSealLabelVault(w: wl, label: 'native-import:evm:0', vaultPassphrase: secs('correct horse 9'));
    wl.lock();
    await walletUnlock(w: wl, vaultJson: v, vaultPassphrase: secs('correct horse 9'), bip39Passphrase: none());
    expect(await code(() => wl.importedKey(networkName: 'evm', n: 0)), 'UAArgument');
    await walletOpenLabelVault(w: wl, vaultJson: label, vaultPassphrase: secs('correct horse 9'));
    expect(await (await wl.importedKey(networkName: 'evm', n: 0)).signDigestRaw(digest: d), sig);
    // a child after its wallet's disposal
    final tmp = await walletOf('pq_kat');
    final child = await tmp.uaKey(kind: 0x0130, account: 0, index: 0);
    tmp.dispose();
    expect(await code(() => child.signUa(purpose: metatx, digest: Uint8List(32))), 'UAKeyRevoked');
    expect(child.keyData().length, 1312, reason: 'public data stays readable');
    // another wallet's vault
    final w5 = await walletOf('twelve_words');
    await w5.uaKey(kind: 0x0102, account: 0, index: 0);
    final other = await walletSealVault(w: await w('pq_kat'), vaultPassphrase: secs('correct horse 9'));
    w5.lock();
    expect(
        await code(() => walletUnlock(w: w5, vaultJson: other, vaultPassphrase: secs('correct horse 9'), bip39Passphrase: none())),
        'UAWalletMismatch');
    final disc = jsonDecode(await (await w('pq_kat')).discoverCandidates(kind: 0x0102, account: 0, gap: 3)) as List;
    expect(disc.length, 3);
  });

  test('seed_backup_sequence', () async {
    final (wl, sb) = await walletGenerate();
    final phrase = await sb.reveal();
    final words = utf8.decode(view(phrase)).split(' ');
    expect(words.length, 24);
    expect(await code(() => sb.reveal()), 'UAArgument', reason: 'shown once');
    expect(await sb.take(), isNull);
    final pos = await sb.challenge();
    final answers = [for (final p in pos) secs(words[p - 1])];
    expect(await seedBackupVerify(b: sb, answers: answers), true);
    expect(answers.every((a) => a.isDisposed), true, reason: 'answers consumed');
    expect((await sb.take())!.size(), 32);
    expect(await sb.take(), isNull, reason: 'handed out once');
    final w2 = await walletFromMnemonic(words: phrase, bip39Passphrase: none());
    phrase.dispose();
    expect(hx((await w2.uaKey(kind: 0x0102, account: 0, index: 0)).keyData()),
        hx((await wl.uaKey(kind: 0x0102, account: 0, index: 0)).keyData()));
  });

  test('aead_hkdf_hmac', () async {
    expect(hx(await hmacSha256(keyBytes: sec(Uint8List(20)..fillRange(0, 20, 0x0b)), data: utf8b('Hi There'))),
        '0xb0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
    expect(
        hx(view(await hkdfSha256(
            ikm: sec(Uint8List(22)..fillRange(0, 22, 0x0b)),
            salt: List.generate(13, (i) => i),
            info: List.generate(10, (i) => 0xf0 + i),
            len: 42))),
        '0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
    for (final alg in [1, 2]) {
      final key = sec(Uint8List(32));
      final ct = await aeadSeal(algId: alg, key32: key, nonce12: Uint8List(12), aad: utf8b('aad'), pt: secs('plaintext'));
      expect(utf8.decode(view(await aeadOpen(algId: alg, key32: key, nonce12: Uint8List(12), aad: utf8b('aad'), data: ct))),
          'plaintext');
      expect(await code(() => aeadOpen(algId: alg, key32: sec(Uint8List(31)), nonce12: Uint8List(12), aad: utf8b('aad'), data: ct)),
          'UAArgument');
      ct[ct.length - 1] ^= 1;
      expect(await code(() => aeadOpen(algId: alg, key32: key, nonce12: Uint8List(12), aad: utf8b('aad'), data: ct)), 'UAAead');
    }
  });

  test('zether_facade', () async {
    final z = load_('zether.json');
    for (final r in z['cacheBox'] as List) {
      final zk = await (await w(r['mnemonic'])).zetherKey(coin: r['coin'], account: r['account'], keyUse: r['use']);
      expect([hx(zk.y()), hx(zk.uaId())], [r['Y'], r['UA']], reason: r['id']);
      final pt = await zk.openBalanceCache(boxJson: jsonEncode(r['box']));
      expect(hx(view(pt)), r['plaintext'], reason: r['id']);
      expect(hx(view(await zk.openBalanceCache(boxJson: await zk.sealBalanceCache(entriesJson: pt)))), hx(view(pt)));
    }
    for (final r in z['cacheRefusals'] as List) {
      final zk = await (await w(r['mnemonic'])).zetherKey(coin: r['coin'], account: r['account'], keyUse: r['use']);
      expect(await code(() => zk.openBalanceCache(boxJson: jsonEncode(r['box']))), 'UAAead', reason: r['id']);
    }
    final wl = await walletOf('pq_kat');
    final zk = await wl.zetherKey(coin: 60, account: 0, keyUse: 7);
    expect(jsonDecode(await zk.call(cmd: 'pop', requestJson: '{"curve":"bls12381"}'))['uaMsg'], isNotNull);
    expect(await code(() => zk.call(cmd: 'pop', requestJson: '{"key":{"seed":"0x11","coin":60,"account":0}}')), 'UAArgument');
    wl.lock();
    expect(await code(() => zk.call(cmd: 'pop', requestJson: '{}')), 'UAKeyRevoked');
    expect(zk.y().length, 128, reason: 'public data stays readable');
  });

  test('pqz_facade', () async {
    final set = jsonDecode(await pqzSet());
    expect([set['set'], set['pkLen']], ['n2304-kmax4096', 18432]);
    await pqzCheckSet(deployedJson: jsonEncode(set));
    expect(await code(() => pqzCheckSet(deployedJson: jsonEncode({...set, 'set': 'n2048-kmax1024'}))), 'UAPqzSetMismatch');
    final wl = await walletOf('pq_kat');
    final k = await wl.pqzKey(account: 0, index: 0);
    expect(k.pk().length, 18432);
    final req = {'proofSystemId': set['pqzlId'], 'kind': 0x0131, 'ua': '0x${'11' * 32}'};
    final proof = await k.call(cmd: 'proveRegister', requestJson: jsonEncode(req));
    expect(proof.length, lessThanOrEqualTo(kPqzOutMax));
    expect(await code(() => k.call(cmd: 'proveRegister', requestJson: jsonEncode({...req, 'proofSystemId': '0x${'de' * 32}'}))),
        'UAPqzSetMismatch');
    expect(await code(() => k.call(cmd: 'proveRegister', requestJson: jsonEncode({...req, 'key': {'seed32': '0x${'11' * 32}'}}))),
        'UAArgument');
    final e = jsonDecode(await k.call(cmd: 'enc', requestJson: jsonEncode({'pks': [hx(k.pk())], 'values': [123456]})));
    final dec = jsonDecode(await k.call(cmd: 'dec', requestJson: jsonEncode({'ct': e['u'] + (e['vs'][0] as String).substring(2)})));
    expect(dec['value'], 123456);
    final box = await k.sealBalanceCache(entries: secs('{"v":1}'));
    expect(utf8.decode(view(await k.openBalanceCache(boxJson: box))), '{"v":1}');
    wl.lock();
    expect(await code(() => k.call(cmd: 'proveRegister', requestJson: jsonEncode(req))), 'UAKeyRevoked');
    expect(await code(() => wl.exportPqzLeafRaw(account: 0, index: 0)), 'UAWalletLocked');
  });
}
