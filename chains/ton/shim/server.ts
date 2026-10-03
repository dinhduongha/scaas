// TON Center API v3 subset over @ton/sandbox (real TVM, fake blocks) — the e2e devnet stand-in for
// bamboo-node's TON adapter when MyLocalTon cannot run (spec §11). One "masterchain block" per accepted
// external message; every transaction of that message's trace gets that block's seqno.
//
//   npm run shim -- --port 32001
//   GET  /api/v3/masterchainInfo | blocks | transactionsByMasterchainBlock | transactionsByMessage | walletInformation
//   POST /api/v3/message | runGetMethod
//   GET  /shim/state            deployed masters (A, B), global id, wallet code hash/depth
//   POST /shim/fund {address, nanoton} | /shim/mint {master, to, amount}
import { Blockchain, SandboxContract, TreasuryContract } from '@ton/sandbox';
import { Address, beginCell, Cell, loadMessage, storeMessage, toNano, TupleItem, Dictionary } from '@ton/core';
import { createServer, IncomingMessage, ServerResponse } from 'http';
import { createHash } from 'crypto';
import { BambooJettonMaster } from '../build/jetton/jetton_BambooJettonMaster';

type Tx = Record<string, unknown>;

const b64 = (b: Buffer) => b.toString('base64');
const msgHash = (m: any) => beginCell().store(storeMessage(m)).endCell().hash();

async function main() {
    const port = Number(process.argv[process.argv.indexOf('--port') + 1] || 32001);
    const bc = await Blockchain.create();
    const admin: SandboxContract<TreasuryContract> = await bc.treasury('admin');
    const funder = await bc.treasury('funder', { balance: toNano('1000000') });
    const masters: Record<string, SandboxContract<BambooJettonMaster>> = {};
    for (const tag of ['A', 'B']) {
        const m = bc.openContract(await BambooJettonMaster.fromInit(admin.address, 0n, beginCell().storeStringTail(tag).endCell()));
        await m.send(admin.getSender(), { value: toNano('0.1') }, { $$type: 'Mint', queryId: 0n, to: admin.address, amount: 1n, responseDestination: admin.address });
        masters[tag] = m;
    }
    const code = (await masters.A.getGetJettonData()).jettonWalletCode;
    const cfg = Dictionary.loadDirect(Dictionary.Keys.Int(32), Dictionary.Values.Cell(), bc.config);
    const globalId = cfg.get(19)!.beginParse().loadInt(32);

    let seqno = 1;
    const blocks: { seqno: number; root_hash: string; txs: Tx[] }[] = [{ seqno: 1, root_hash: b64(createHash('sha256').update('mc1').digest()), txs: [] }];
    const byInMsg = new Map<string, Tx>();

    function record(txs: any[]) {
        seqno += 1;
        const block = { seqno, root_hash: b64(createHash('sha256').update('mc' + seqno).digest()), txs: [] as Tx[] };
        for (const t of txs) {
            const d = t.description;
            const account = '0:' + t.address.toString(16).padStart(64, '0');
            const inHash = t.inMessage ? b64(msgHash(t.inMessage)) : null;
            const tx: Tx = {
                account, hash: b64(t.hash()), lt: t.lt.toString(), now: t.now, mc_block_seqno: seqno,
                description: {
                    aborted: d.aborted,
                    compute_ph: d.computePhase.type === 'vm' ? { success: d.computePhase.success, exit_code: d.computePhase.exitCode } : { skipped: true },
                    action: d.actionPhase ? { success: d.actionPhase.success } : undefined,
                },
                in_msg: t.inMessage ? { hash: inHash } : null,
                out_msgs: [...t.outMessages.values()].map((m: any) => ({
                    hash: b64(msgHash(m)),
                    destination: m.info.type === 'external-out' ? null : m.info.dest.toRawString(),
                    message_content: { body: b64(m.body.toBoc()) },
                })),
                account_state_after: { code_hash: null as string | null },
            };
            if (inHash) byInMsg.set(Buffer.from(inHash, 'base64').toString('hex'), tx);
            block.txs.push(tx);
        }
        blocks.push(block);
        return block;
    }

    // account_state_after.code_hash: filled lazily from the current state (enough for a devnet).
    async function withCode(tx: Tx) {
        const c = await bc.getContract(Address.parse(tx.account as string));
        const st: any = c.accountState;
        (tx.account_state_after as any).code_hash = st?.type === 'active' && st.state.code ? b64(st.state.code.hash()) : null;
        return tx;
    }

    async function api(path: string, q: URLSearchParams, body: any): Promise<[number, unknown]> {
        switch (path) {
            case '/api/v3/masterchainInfo': {
                const last = blocks[blocks.length - 1];
                return [200, { last: { seqno: last.seqno, root_hash: last.root_hash, workchain: -1, shard: '8000000000000000' }, first: { seqno: 1 } }];
            }
            case '/api/v3/blocks': {
                const b = blocks.find((x) => x.seqno === Number(q.get('seqno')));
                return [200, { blocks: b ? [{ seqno: b.seqno, root_hash: b.root_hash, workchain: -1, shard: '8000000000000000' }] : [] }];
            }
            case '/api/v3/transactionsByMasterchainBlock': {
                const b = blocks.find((x) => x.seqno === Number(q.get('seqno')));
                const off = Number(q.get('offset') || 0), lim = Number(q.get('limit') || 256);
                return [200, { transactions: await Promise.all((b?.txs ?? []).slice(off, off + lim).map(withCode)), address_book: {} }];
            }
            case '/api/v3/transactionsByMessage': {
                const t = byInMsg.get((q.get('msg_hash') || '').toLowerCase());
                return [200, { transactions: t ? [await withCode(t)] : [], address_book: {} }];
            }
            case '/api/v3/message': {
                const cell = Cell.fromBase64(body.boc);
                const msg = loadMessage(cell.beginParse());
                const res = await bc.sendMessage(msg);
                const block = record(res.transactions);
                // TON Center indexes the hash of the cell as sent; re-serializing the parsed message may lay the
                // stateInit out differently (inline vs ref), so pin the external-in tx under the original hash.
                const ext = block.txs.find((t) => (t.in_msg as any)?.hash === b64(msgHash(msg)));
                if (ext) {
                    (ext.in_msg as any).hash = b64(cell.hash());
                    byInMsg.set(cell.hash().toString('hex'), ext);
                }
                return [200, { message_hash: b64(cell.hash()) }];
            }
            case '/api/v3/runGetMethod': {
                const stack: TupleItem[] = (body.stack || []).map((e: any) =>
                    e.type === 'num' ? { type: 'int', value: BigInt(e.value) } : { type: 'slice', cell: Cell.fromBase64(e.value) });
                try {
                    const r = await bc.runGetMethod(Address.parse(body.address), body.method, stack);
                    const out = r.stack.map((i: any) => i.type === 'int' ? { type: 'num', value: '0x' + i.value.toString(16) }
                        : i.type === 'null' ? { type: 'null' } : { type: i.type, value: b64(i.cell.toBoc()) });
                    return [200, { gas_used: Number(r.gasUsed), exit_code: r.exitCode, stack: out }];
                } catch (e: any) {
                    return [200, { exit_code: e?.exitCode ?? -256, stack: [] }];
                }
            }
            case '/api/v3/walletInformation': {
                const c = await bc.getContract(Address.parse(q.get('address')!));
                const st: any = c.accountState;
                if (st?.type !== 'active') return [200, { status: st?.type ?? 'uninit', seqno: 0, balance: c.balance.toString() }];
                const r = await bc.runGetMethod(c.address, 'seqno', []);
                return [200, { status: 'active', seqno: Number((r.stack[0] as any).value), balance: c.balance.toString() }];
            }
            case '/shim/state':
                return [200, {
                    global_id: globalId, masters: { A: masters.A.address.toRawString(), B: masters.B.address.toRawString() },
                    wallet_code_hash: '0x' + code.hash().toString('hex'), wallet_code_depth: code.depth(),
                }];
            case '/shim/fund': {
                record((await funder.send({ to: Address.parse(body.address), value: BigInt(body.nanoton), bounce: false })).transactions);
                return [200, { ok: true }];
            }
            case '/shim/mint': {
                const m = Object.values(masters).find((x) => x.address.equals(Address.parse(body.master)))!;
                record((await m.send(admin.getSender(), { value: toNano('0.1') }, { $$type: 'Mint', queryId: 0n, to: Address.parse(body.to), amount: BigInt(body.amount), responseDestination: admin.address })).transactions);
                return [200, { ok: true }];
            }
        }
        return [404, { error: 'not found' }];
    }

    let queue = Promise.resolve();
    createServer((req: IncomingMessage, res: ServerResponse) => {
        let raw = '';
        req.on('data', (c) => (raw += c));
        req.on('end', () => {
            // Serialize: the sandbox is single-threaded state.
            queue = queue.then(async () => {
                const url = new URL(req.url || '/', 'http://x');
                try {
                    const [code, out] = await api(url.pathname, url.searchParams, raw ? JSON.parse(raw) : {});
                    res.writeHead(code, { 'content-type': 'application/json' });
                    res.end(JSON.stringify(out));
                } catch (e: any) {
                    res.writeHead(500, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ error: String(e?.message ?? e) }));
                }
            });
        });
    }).listen(port, '127.0.0.1', () => console.log(`ton-shim listening on ${port}`));
}

main();
