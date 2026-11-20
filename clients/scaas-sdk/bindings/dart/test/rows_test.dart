// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T20: the keystore and vault rows of smartcontracts/vectors/keystore/keystore.json (clientkeys' rows, the
// SDK's tests/keystore_vectors.rs) through the Dart binding: each container put in the Dart store as `keystore`. Valid rows
// list their seeds, and every seed's vaults open with the rows' passphrase (the index MAC verified on the way); refused rows
// fail with their named error; a wrong passphrase is VaultOpen.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:scaas_sdk/scaas_sdk.dart';
import 'package:test/test.dart';

import 'support.dart';

final rows = jsonDecode(File('../../../../smartcontracts/vectors/keystore/keystore.json').readAsStringSync()) as Map;

Future<SdkHandle> over(String text) async {
  final store = MemStore()..items['keystore'] = Uint8List.fromList(utf8.encode(text));
  return openSdk(store, FakeAuth());
}

void main() {
  setUpAll(() async => loadScaasSdk(lib));

  test('the rows passphrase is the tests one', () => expect(rows['passphrase'], pass));

  test('keystore rows: every valid container lists its seeds in order', () async {
    final valid = rows['valid'] as List;
    expect(valid.length, greaterThanOrEqualTo(5));
    for (final r in valid) {
      final want = ((jsonDecode(r['text'] as String) as Map)['seeds'] as List).cast<Map>();
      final got = await (await over(r['text'] as String)).vault().seeds();
      expect(got.map((s) => (s.id, s.label, s.words, s.backup, s.unlocked)),
          want.map((s) => (s['id'], s['label'], s['words'], s['backup'], false)),
          reason: r['id'] as String);
    }
  });

  test('keystore rows: every refused container fails with its named error', () async {
    final refused = rows['refused'] as List;
    expect(refused.length, greaterThanOrEqualTo(19));
    for (final r in refused) {
      // refused at the open (the SDK reads the keystore there) or at the first read, by its name
      expect(await failure(() async => (await over(r['text'] as String)).vault().seeds()), r['error'],
          reason: r['id'] as String);
    }
  });

  test('vault rows: every seed of every valid row unlocks with the passphrase, its accounts listed', () async {
    var opened = 0;
    for (final r in rows['valid'] as List) {
      final want = ((jsonDecode(r['text'] as String) as Map)['seeds'] as List).cast<Map>();
      final sdk = await over(r['text'] as String);
      for (final s in want) {
        final id = s['id'] as String;
        await sdk.vault().unlock(seed: id, unlock: Unlock.passphrase(sec(pass)));
        expect((await sdk.vault().seed(seed: id)).unlocked, isTrue, reason: '${r['id']} $id');
        expect((await sdk.account().accounts(seed: id)).map((a) => a.id), (s['accounts'] as List).map((a) => a['id']),
            reason: '${r['id']} $id');
        opened++;
      }
      if (want.isNotEmpty) {
        final first = want.first['id'] as String;
        await sdk.vault().lock(seed: first);
        expect(await failure(() => sdk.vault().unlock(seed: first, unlock: Unlock.passphrase(sec('not the one 9')))),
            'VaultOpen', reason: '${r['id']}: a wrong passphrase');
      }
    }
    expect(opened, greaterThanOrEqualTo(5), reason: 'control: seeds were opened');
  });
}
