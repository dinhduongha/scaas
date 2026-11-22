// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T20: the e2e smoke through the Dart binding on a local `anvil` (in PATH; stopped when the test ends):
// anvil's accounts come from the repository mnemonic, so the seed's EVM key 0 is funded. The SDK imports those words,
// quotes a native send of 1 wei to an empty address (prepare_native_send), signs and sends it (submit_native_send: sign ->
// write -> send) and follows it to `Landed` (Op::state); the receiver's balance is read back over RPC. Local only.
import 'dart:convert';
import 'dart:io';

import 'package:scaas_sdk/scaas_sdk.dart';
import 'package:test/test.dart';

import 'support.dart';

const repo =
    'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better';
const to = '0x00000000000000000000000000000000000d0a17';

Future<Object?> rpc(String url, String method, List<Object?> params) async {
  final c = HttpClient();
  try {
    final req = await c.postUrl(Uri.parse(url));
    req.headers.contentType = ContentType.json;
    req.write(jsonEncode({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}));
    final body = await utf8.decodeStream(await req.close());
    return (jsonDecode(body) as Map)['result'];
  } finally {
    c.close(force: true);
  }
}

void main() {
  late Process anvil;
  late String url;

  setUpAll(() async {
    await loadScaasSdk(lib);
    final s = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = s.port;
    await s.close();
    url = 'http://127.0.0.1:$port';
    anvil = await Process.start('anvil', [
      '--chain-id', '31337', '--port', '$port', '--mnemonic', repo, '--silent', //
    ]);
    for (var i = 0; i < 100; i++) {
      try {
        if (await rpc(url, 'eth_chainId', []) == '0x7a69') return;
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    fail('anvil did not answer');
  });

  tearDownAll(() async {
    anvil.kill();
    await anvil.exitCode;
  });

  test('e2e smoke: a native send prepared, signed, sent and followed to Landed through the binding', () async {
    final uid = ((await rpc(url, 'eth_getBlockByNumber', ['0x0', false])) as Map)['hash'] as String;
    final profile = ChainProfile(
      key: 'anvil',
      family: Family.evm,
      chainId: BigInt.from(31337),
      chainUid: uid,
      rpc: [EndpointConfig(url: url, class_: Class.named)],
      rpcPolicy: Policy.failover,
      gateways: const [],
      finality: Finality.depth(BigInt.zero),
      txGasCap: BigInt.from(1 << 24),
      tokens: const [],
      gas: const GasRows(base: [], verify: []),
      gasOptIn: const [],
      verifiers: const [],
      verifierPolicy: Policy.failover,
      dexes: const [],
      wrappers: const [],
      disabledKinds: const [],
      pinnedReads: true,
    );
    final sdk = await openSdk(MemStore(), FakeAuth(), profiles: [profile]);
    final seed = await sdk.vault().importWords(req: ImportWords(label: 'main', words: sec(repo), vaultPassphrase: sec(pass)));
    final key = KeyRef.native(seed: seed.id, network: 'evm', index: 0);
    final q = await sdk.wallet().prepareNativeSend(req: NativeSend(key: key, chain: 'anvil', to: to, value: '1'));
    final funded = ((await rpc(url, 'eth_accounts', [])) as List).first as String;
    expect(q.from, funded.toLowerCase(), reason: "the seed's EVM key 0 is anvil's first account");
    expect((q.to, q.value, q.quote.gasLimit), (to, '1', BigInt.from(21000)));
    final op = await sdk.wallet().submitNativeSend(q: q);
    OpState st = await sdk.op().state(op: op);
    for (var i = 0; i < 60 && st is! OpState_Landed; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 250));
      st = await sdk.op().state(op: op);
    }
    expect(st, isA<OpState_Landed>(), reason: '$st');
    expect(await rpc(url, 'eth_getBalance', [to, 'latest']), '0x1');
  });
}
