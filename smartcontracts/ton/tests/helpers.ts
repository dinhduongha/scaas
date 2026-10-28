// Off-chain builders shared by the tests and by the vector generator: the exact bytes Odoo
// (dms_blockchain/lib/fam_ton.py) and the relayer (scaas-node/src/adapters/ton.rs) must produce.
import { Address, beginCell, Builder, Cell, storeStateInit, StateInit } from '@ton/core';
import { KeyPair, keyPairFromSeed, sign } from '@ton/crypto';
import { WalletContractV5R1 } from '@ton/ton';
import { createHash, createSign, generateKeyPairSync, KeyObject } from 'crypto';
import { crc32 } from 'zlib';

export const METAOP_SCHEMA =
    'metaop$_ domain:bits120 network:int32 op:uint8 amount:uint128 nonce:uint64 valid_until:uint64 ' +
    'contract:MsgAddress parties:^[ from:MsgAddress to:MsgAddress relayer:MsgAddress ] ' +
    'refs:^[ pay_ref:bits256 lane:bits256 extra:bits256 ] = MetaOp;';
export const SCHEMA_CRC = crc32(Buffer.from(METAOP_SCHEMA)) >>> 0;

export const OP = { pay: 1, trade: 2, mandate_pay: 3, revoke: 4, set_key: 5 } as const;

export interface MetaOpFields {
    network: number;
    op: number;
    amount: bigint;
    nonce: bigint;
    validUntil: number;
    contract: Address;
    from: Address;
    to: Address;
    relayer?: Address | null;
    payRef: bigint;
    lane: bigint;
    extra: bigint;
}

export function metaOpCell(f: MetaOpFields): Cell {
    return beginCell()
        .storeBuffer(Buffer.from('scaas.metaop.v1'))
        .storeInt(f.network, 32)
        .storeUint(f.op, 8)
        .storeUint(f.amount, 128)
        .storeUint(f.nonce, 64)
        .storeUint(f.validUntil, 64)
        .storeAddress(f.contract)
        .storeRef(beginCell().storeAddress(f.from).storeAddress(f.to).storeAddress(f.relayer ?? null).endCell())
        .storeRef(beginCell().storeUint(f.payRef, 256).storeUint(f.lane, 256).storeUint(f.extra, 256).endCell())
        .endCell();
}

/// TEP-81 DNS wire form used by TON Connect: labels reversed, each terminated by \0.
export function encodeDomain(domain: string): Buffer {
    return Buffer.from(domain.split('.').reverse().map((l) => l + '\0').join(''));
}

export function domainCell(domain: string): Cell {
    return beginCell().storeStringTail(encodeDomain(domain).toString('latin1')).endCell();
}

export function signDataCell(owner: Address, timestamp: number, domain: string, payload: Cell): Cell {
    return beginCell()
        .storeUint(0x75569022, 32)
        .storeUint(SCHEMA_CRC, 32)
        .storeUint(timestamp, 64)
        .storeAddress(owner)
        .storeRef(domainCell(domain))
        .storeRef(payload)
        .endCell();
}

export function tonConnectAuth(kp: KeyPair, owner: Address, timestamp: number, domain: string, op: Cell): Cell {
    const sig = sign(signDataCell(owner, timestamp, domain, op).hash(), kp.secretKey);
    return beginCell().storeUint(0, 8).storeBuffer(sig).storeUint(timestamp, 64).storeRef(domainCell(domain)).endCell();
}

export function tradeParamsCell(p: { tokenIn: Address; tokenOut: Address; minOut: bigint; counterparty?: Address | null; maxFeePpm: number; forwardTon?: bigint }): Cell {
    return beginCell()
        .storeAddress(p.tokenIn)
        .storeAddress(p.tokenOut)
        .storeUint(p.minOut, 128)
        .storeAddress(p.counterparty ?? null)
        .storeUint(p.maxFeePpm, 32)
        .storeCoins(p.forwardTon ?? 0n)
        .endCell();
}

/// CTR-MTX-26 `meta` as snake bytes: 127 bytes per cell along the first ref (`ton.rs` `snake`, the same chunking as
/// `storeStringTail`); an empty `meta` is one empty cell.
export function snakeCell(b: Buffer): Cell {
    const chunks: Buffer[] = [];
    for (let i = 0; i < Math.max(b.length, 1); i += 127) chunks.push(b.subarray(i, i + 127));
    let c: Cell | null = null;
    for (const ch of chunks.reverse()) {
        const bb = beginCell().storeBuffer(ch);
        if (c) bb.storeRef(c);
        c = bb.endCell();
    }
    return c!;
}

/// `SignedOp.params` of a pay-meta: `salt:uint256 ^meta`.
export function payMetaParams(salt: bigint, meta: Cell): Cell {
    return beginCell().storeUint(salt, 256).storeRef(meta).endCell();
}

export function stateInitCell(init: StateInit): Cell {
    const b = beginCell();
    storeStateInit(init)(b);
    return b.endCell();
}

/// A subject: Ed25519 key + its W5R1 wallet (the TON Connect account), never deployed in tests.
export async function subject(seedByte: number) {
    const kp = keyPairFromSeed(Buffer.alloc(32, seedByte));
    const w5 = WalletContractV5R1.create({ workchain: 0, publicKey: kp.publicKey });
    return { kp, address: w5.address, stateInit: stateInitCell(w5.init) };
}

// ------------------------------------------------------------------ WebAuthn (software authenticator)

export const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export function b64url(buf: Buffer): string {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function newPasskey() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-65);
    const compressed = Buffer.concat([Buffer.from([raw[64] & 1 ? 3 : 2]), raw.subarray(1, 33)]);
    return { privateKey, compressed };
}

export function passkeyRecord(compressed: Buffer, rpId: string, origin: string): Cell {
    const rpIdHash = createHash('sha256').update(rpId).digest();
    return beginCell()
        .storeBuffer(compressed)
        .storeBuffer(rpIdHash)
        .storeRef(beginCell().storeStringTail(`","origin":"${origin}"`).endCell())
        .endCell();
}

/// WebAuthn assertion over `digest`, normalised to low-s (client does this — review S5).
export function passkeyAuth(privateKey: KeyObject, rpId: string, origin: string, digest: Buffer, flags = 0x05, extraClientData = ''): Cell {
    const authData = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([flags]), Buffer.from([0, 0, 0, 1])]);
    const prefix = '{"type":"webauthn.get","challenge":"';
    const suffix = `","origin":"${origin}","crossOrigin":false${extraClientData}}`;
    const cdj = prefix + b64url(digest) + suffix;
    const signed = Buffer.concat([authData, createHash('sha256').update(cdj).digest()]);
    const s = createSign('SHA256');
    s.update(signed);
    const der = s.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' });
    let r = BigInt('0x' + der.subarray(0, 32).toString('hex'));
    let sv = BigInt('0x' + der.subarray(32).toString('hex'));
    if (sv > P256_N / 2n) sv = P256_N - sv;
    // suffix starts after the challenge: `","origin":...` — the record holds `,"origin":"<origin>"`, so the
    // contract sees the closing quote of the challenge as part of the suffix.
    const suffixBytes = Buffer.from(suffix);
    const first = suffixBytes.subarray(0, 127);
    const rest = suffixBytes.subarray(127);
    const sc = rest.length
        ? beginCell().storeBuffer(first).storeRef(beginCell().storeBuffer(rest).endCell()).endCell()
        : beginCell().storeBuffer(first).endCell();
    return beginCell()
        .storeUint(1, 8)
        .storeUint(r, 256)
        .storeUint(sv, 256)
        .storeRef(beginCell().storeBuffer(authData).endCell())
        .storeRef(sc)
        .endCell();
}

export function u256(buf: Buffer): bigint {
    return BigInt('0x' + buf.toString('hex'));
}

export function randomU256(): bigint {
    return u256(require('crypto').randomBytes(32));
}

export type { Builder };
