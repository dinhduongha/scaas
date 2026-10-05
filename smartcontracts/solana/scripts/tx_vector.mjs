// Ghim tx v1 viết tay của adapter (bamboo-node/src/adapters/solana.rs) vào @solana/kit 8.4.0: message v1 encode bằng
// codec của kit, ký bằng khoá lane qua kit, tx trên dây bằng getTransactionEncoder (message trước, chữ ký sau).
// Thứ tự account (fee payer, signer ghi/đọc, ghi/đọc; trong nhóm theo lần xuất hiện đầu) là lựa chọn của adapter —
// validator không đòi thứ tự; e2e đối chiếu chữ ký với RPC.
//   cd chains/solana/scripts && npm i && node tx_vector.mjs
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
    createAddressWithSeed, createKeyPairFromPrivateKeyBytes, getAddressDecoder, getAddressEncoder,
    getAddressFromPublicKey, getCompiledTransactionMessageEncoder, getProgramDerivedAddress, getTransactionEncoder,
    signBytes,
} from '@solana/kit';

const PROGRAM = 'BDo6exf1vzqX44BJc1WDf4Pw6sGZcxqmuVmQPfgUgS3d';
const V = Object.fromEntries([...readFileSync(new URL('../programs/bamboo/tests/vectors.rs', import.meta.url), 'utf8')
    .matchAll(/pub const (\w+): &str = "(.*)";/g)].map(m => [m[1], m[2]]));
const PAYLOAD = V.PAYLOAD;
const SIG = V.SIG_RAW;
const enc = getAddressEncoder();
const dec = getAddressDecoder();
const hex = b => Buffer.from(b).toString('hex');
const sha = (...p) => { const h = createHash('sha256'); p.forEach(x => h.update(x)); return h.digest(); };
const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const addr = b => dec.decode(new Uint8Array(b));
const pda = async (seeds, program) => (await getProgramDerivedAddress({ programAddress: program, seeds }))[0];

const p = Buffer.from(PAYLOAD, 'hex');
const f = (o, n) => p.subarray(o, o + n);
const [from, to, asset] = [f(113, 32), f(145, 32), f(80, 32)];
const amount = p.readBigUInt64LE(177);
const [payRef, laneId, nonce, validUntil, relayer, extra] = [f(193, 32), f(225, 32), f(257, 8), f(265, 8), f(273, 32), f(305, 32)];
const digest = sha(p);
const text = Buffer.from('bamboo.metaop.v1:' + digest.toString('hex'));

const kp = await createKeyPairFromPrivateKeyBytes(sha('lane0'));
const lane = await getAddressFromPublicKey(kp.publicKey);
const SYSTEM = '11111111111111111111111111111111';
const TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const ATA = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const nonceAcct = await createAddressWithSeed({ baseAddress: lane, programAddress: SYSTEM, seed: 'bamboo-nonce-v1' });
const subject = await pda([Buffer.from('acct'), from], PROGRAM);
const ataOf = (owner, mint) => pda([enc.encode(owner), enc.encode(TOKEN), enc.encode(mint)], ATA);

// instruction 1: Ed25519 precompile, one signature, offsets inside itself (u16::MAX)
const pk = from;
const pre = Buffer.concat([Buffer.from([1, 0]), u16(16 + 32), u16(0xffff), u16(16), u16(0xffff), u16(16 + 32 + 64),
    u16(text.length), u16(0xffff), pk, Buffer.from(SIG, 'hex'), text]);
// instruction 2: bamboo::relay_pay(owner, PayArgs, Auth{kind 0, key 0, precompile 1, sig 0, cdj []})
const data = Buffer.concat([sha('global:relay_pay').subarray(0, 8), from, to, u64(amount), payRef, laneId, nonce, validUntil,
    relayer, extra, Buffer.from([0, 0, 1, 0]), u32(0)]);
const W = (a, s = false) => ({ a, s, w: true }), R = (a, s = false) => ({ a, s, w: false });
const ixs = [
    { program: SYSTEM, accounts: [W(nonceAcct), R('SysvarRecentB1ockHashes11111111111111111111'), R(lane, true)], data: u32(4) },
    { program: 'Ed25519SigVerify111111111111111111111111111', accounts: [], data: pre },
    { program: PROGRAM, data, accounts: [W(lane, true), R(await pda([Buffer.from('config')], PROGRAM)), R(subject),
        W(await pda([Buffer.from('lane'), enc.encode(subject), laneId], PROGRAM)), W(await ataOf(subject, addr(asset))),
        R(addr(to)), W(await ataOf(addr(to), addr(asset))), R(addr(asset)), R(TOKEN), R(ATA), R(SYSTEM),
        R('Sysvar1nstructions1111111111111111111111111'), R(await pda([Buffer.from('__event_authority')], PROGRAM)), R(PROGRAM)] },
];
// static accounts: fee payer, then signer-writable, signer-readonly, writable, readonly; first appearance inside a group
const keys = [{ a: lane, s: true, w: true }];
const add = x => { const e = keys.find(k => k.a === x.a); if (e) { e.s ||= x.s; e.w ||= x.w; } else keys.push({ ...x }); };
for (const ix of ixs) { add(R(ix.program)); ix.accounts.forEach(add); }
const rank = e => (e.a === lane ? 0 : 1) * 4 + (e.s ? 0 : 2) + (e.w ? 0 : 1);
const ordered = keys.map((e, i) => [e, i]).sort((x, y) => rank(x[0]) - rank(y[0]) || x[1] - y[1]).map(x => x[0]);
const index = a => ordered.findIndex(e => e.a === a);
const compiled = {
    version: 1,
    header: {
        numSignerAccounts: ordered.filter(e => e.s).length,
        numReadonlySignerAccounts: ordered.filter(e => e.s && !e.w).length,
        numReadonlyNonSignerAccounts: ordered.filter(e => !e.s && !e.w).length,
    },
    configMask: 0b1111,
    configValues: [{ kind: 'u64', value: 5000n }, { kind: 'u32', value: 200000 }, { kind: 'u32', value: 4 * 1024 * 1024 }],
    lifetimeToken: addr(Buffer.alloc(32, 0x42)),
    numInstructions: ixs.length,
    numStaticAccounts: ordered.length,
    staticAccounts: ordered.map(e => e.a),
    instructionHeaders: ixs.map(ix => ({ programAccountIndex: index(ix.program), numInstructionAccounts: ix.accounts.length,
        numInstructionDataBytes: ix.data.length })),
    instructionPayloads: ixs.map(ix => ({ instructionAccountIndices: ix.accounts.map(x => index(x.a)), instructionData: new Uint8Array(ix.data) })),
};
const messageBytes = getCompiledTransactionMessageEncoder().encode(compiled);
const sig = await signBytes(kp.privateKey, messageBytes);
const tx = getTransactionEncoder().encode({ messageBytes, signatures: { [lane]: sig } });
console.log(JSON.stringify({ lane, nonce: nonceAcct, message: hex(messageBytes), tx: hex(tx), bytes: tx.length }, null, 1));
