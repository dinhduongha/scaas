// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The factory's chain-neutral addresses off chain (chain-neutral releases spec §2.1, §4; CTR-TOK-29): the CREATE3 address of
// a creation, which depends only on the factory, the creator's UA id, the class, the kind and the salt, and the instance
// env appended to every clone's code. Against smartcontracts/vectors/factory/create3_kat.json (written by forge,
// Create3Kat.t.sol). The address says nothing about the version, the code or the configuration on a chain: read
// `infoOf(addr)` and the instance per chain (spec §4.3). UNAUDITED.
import { hex, fromHex, keccak_256, concatBytes, abiEncode, utf8ToBytes } from './bytes.js';

/** `PUSH8 363d3d37363d34f0 RETURNDATASIZE MSTORE PUSH1 8 PUSH1 24 RETURN`: deposits the proxy's runtime. */
export const PROXY_INITCODE = '0x67363d3d37363d34f03d5260086018f3';
export const PROXY_INITCODE_HASH = hex(keccak_256(fromHex(PROXY_INITCODE)));
export const CLASS_TOKEN = 1;
export const CLASS_DEX = 2;

const addr = (a) => {
  const b = fromHex(a);
  if (b.length !== 20) throw new Error(`not an address: ${a}`);
  return b;
};
const b32 = (v, name) => {
  const b = fromHex(v);
  if (b.length !== 32) throw new Error(`${name}: 32 bytes`);
  return b;
};
const lastAddress = (h) => '0x' + hex(h).slice(-40);

/** `s = keccak256(abi.encode(creatorId, contractClass, kind, salt))`. */
export function create3Salt({ creatorId, contractClass, kind, salt }) {
  return hex(keccak_256(abiEncode(['bytes32', 'uint16', 'uint16', 'bytes32'],
    [hex(b32(creatorId, 'creatorId')), BigInt(contractClass), BigInt(kind), hex(b32(salt, 'salt'))])));
}

/** The CREATE2 proxy of `s` and the instance at its nonce 1: `{ s, proxy, instance }`. */
export function create3Address({ factory, creatorId, contractClass, kind, salt }) {
  const s = create3Salt({ creatorId, contractClass, kind, salt });
  const proxy = lastAddress(keccak_256(concatBytes(Uint8Array.of(0xff), addr(factory), fromHex(s), fromHex(PROXY_INITCODE_HASH))));
  const instance = lastAddress(keccak_256(concatBytes(Uint8Array.of(0xd6, 0x94), addr(proxy), Uint8Array.of(0x01))));
  return { s, proxy, instance };
}

/** The env bytes of a clone: `chainUid ‖ registry ‖ govRouter ‖ smartKeyAccountImpl ‖ hedera ‖ nDeps ‖ deps ‖ nParams ‖
 *  params` (at most 4 deps, 2 params). */
export function chainEnvBytes({ chainUid, registry, govRouter, smartKeyAccountImpl, hedera, deps = [], params = [] }) {
  if (deps.length > 4 || params.length > 2) throw new Error('ChainEnv: at most 4 deps and 2 params');
  return concatBytes(b32(chainUid, 'chainUid'), addr(registry), addr(govRouter), addr(smartKeyAccountImpl),
    Uint8Array.of(hedera ? 1 : 0), Uint8Array.of(deps.length), ...deps.map(addr), Uint8Array.of(params.length),
    ...params.map((p) => b32(p, 'param')));
}

const PROXY_HEAD = fromHex('0x363d3d373d3d3d363d73');
const PROXY_TAIL = fromHex('0x5af43d82803e903d91602b57fd5bf3');

/** The clone's runtime: the 45-byte EIP-1167 proxy of `implementation`, then the env. */
export function cloneRuntime(implementation, envBytes) {
  return concatBytes(PROXY_HEAD, addr(implementation), PROXY_TAIL, envBytes);
}

/** Its init code: `PUSH2 n RETURNDATASIZE DUP2 PUSH1 10 RETURNDATASIZE CODECOPY RETURN`, then the runtime. */
export function cloneInitCode(implementation, envBytes) {
  const rt = cloneRuntime(implementation, envBytes);
  return concatBytes(Uint8Array.of(0x61, rt.length >> 8, rt.length & 0xff, 0x3d, 0x81, 0x60, 0x0a, 0x3d, 0x39, 0xf3), rt);
}

const RELEASE_KEY = {
  token: ['scaas.factory.release.token', ['uint8 kind', 'uint64 version', 'uint16 envVersion']],
  dex: ['scaas.factory.release.dex', ['uint64 version', 'uint16 envVersion']],
  class: ['scaas.factory.release.class', ['uint16 contractClass', 'uint16 kind', 'uint64 version', 'uint16 envVersion',
    'bytes4 initSelector', 'bytes4 interfaceId']],
};

/** Round 3r (spec 2026-11-10-admin-not-owner.md §5.6 table): the factory's release approval key, what `approvalOf` and
 *  `revokeApproval` take: `keccak256(abi.encode(keccak256(tag), chainUid, factory, <the deploy's fields>, initcodeHash,
 *  implArgsHash))`, `domain` one of `token`, `dex`, `class`; the fields by their names in the approval op's message. */
export function releaseApprovalKey(domain, m) {
  const [tag, fields] = RELEASE_KEY[domain] ?? (() => { throw new Error(`no release domain ${domain}`); })();
  const ts = ['bytes32', 'bytes32', 'address', ...fields.map((f) => f.split(' ')[0]), 'bytes32', 'bytes32'];
  const vs = [hex(keccak_256(utf8ToBytes(tag))), hex(b32(m.chainUid, 'chainUid')), m.factory,
    ...fields.map((f) => { const [t, n] = f.split(' '); return t.startsWith('uint') ? BigInt(m[n]) : m[n]; }),
    hex(b32(m.initcodeHash, 'initcodeHash')), hex(b32(m.implArgsHash, 'implArgsHash'))];
  return hex(keccak_256(abiEncode(ts, vs)));
}
