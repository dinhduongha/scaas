// Cross-implementation vectors (deliverable 4): the SAME bytes/digests computed here (@ton/core, the
// reference) must come out of dms_blockchain/lib/fam_ton.py and scaas-node/src/adapters/ton.rs.
// UPDATE_VECTORS=1 npx jest tests/vectors.spec.ts rewrites vectors/ton-vectors.json.
import { Address, beginCell, Cell, external, internal, storeMessage, storeMessageRelaxed, toNano } from '@ton/core';
import { keyPairFromSeed, sign } from '@ton/crypto';
import { WalletContractV5R1 } from '@ton/ton';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { ScaasJettonWallet, storeMetaTransactionExecuted, storePaymentSettled, storeSignedOp } from '../build/jetton/jetton_ScaasJettonWallet';
import { ScaasJettonMaster } from '../build/jetton/jetton_ScaasJettonMaster';
import { domainCell, metaOpCell, METAOP_SCHEMA, SCHEMA_CRC, signDataCell, stateInitCell, tonConnectAuth, tradeParamsCell } from './helpers';

const FILE = join(__dirname, '..', 'vectors', 'ton-vectors.json');
const hex = (c: Cell) => c.toBoc({ idx: false, crc32: false }).toString('hex');
const h = (c: Cell) => '0x' + c.hash().toString('hex');
const raw = (a: Address) => a.toRawString();

async function build() {
    const payerKp = keyPairFromSeed(Buffer.alloc(32, 1));
    const payer = WalletContractV5R1.create({ workchain: 0, publicKey: payerKp.publicKey });
    const payee = Address.parse('0:' + '22'.repeat(32));
    const master = await ScaasJettonMaster.fromInit(Address.parse('0:' + '33'.repeat(32)), 0n, beginCell().storeStringTail('A').endCell());
    const { Dictionary } = await import('@ton/core');
    const walletInit = await ScaasJettonWallet.fromInit(payer.address, master.address, 0n, 0n, null, Dictionary.empty(), Dictionary.empty(), 0n, 0n, 0n);
    const payerWallet = walletInit.address;
    const fields = {
        network: -239, op: 1, amount: 1_234_567n, nonce: 0n, validUntil: 1_800_000_300,
        contract: payerWallet, from: payer.address, to: payee, relayer: null,
        payRef: BigInt('0x' + 'ab'.repeat(32)), lane: BigInt('0x' + 'cd'.repeat(32)), extra: 0n,
    };
    const op = metaOpCell(fields);
    const domain = 'pay.scaas.example';
    const ts = 1_800_000_000;
    const envelope = signDataCell(payer.address, ts, domain, op);
    const auth = tonConnectAuth(payerKp, payer.address, ts, domain, op);
    const params = tradeParamsCell({ tokenIn: master.address, tokenOut: payee, minOut: 99n, counterparty: null, maxFeePpm: 3000, forwardTon: toNano('0.2') });

    // Relayer lane: W5R1 from a fixed ed25519 seed, external message carrying one SignedOp.
    const laneKp = keyPairFromSeed(Buffer.alloc(32, 0x11));
    const lane = WalletContractV5R1.create({ workchain: 0, publicKey: laneKp.publicKey, walletId: { networkGlobalId: -239 } });
    const signedOp = beginCell().store(storeSignedOp({
        $$type: 'SignedOp', op, auth, params: null, stateInit: stateInitCell(payer.init),
        responseDestination: lane.address, forwardTon: 0n, matchWith: 0n,
    })).endCell();
    const intMsg = internal({ to: payerWallet, value: toNano('0.15'), bounce: true, body: signedOp });
    const relaxed = beginCell().store(storeMessageRelaxed(intMsg, { forceRef: true })).endCell();
    const outList = beginCell().storeRef(beginCell().endCell()).storeUint(0x0ec3c86d, 32).storeUint(3, 8).storeRef(relaxed).endCell();
    const seqno = 0;
    const validUntil = 1_800_000_300;
    const walletId = (-239 ^ 0x80000000) >>> 0;
    const signing = beginCell().storeUint(0x7369676e, 32).storeUint(walletId, 32).storeUint(validUntil, 32).storeUint(seqno, 32).storeMaybeRef(outList).storeUint(0, 1);
    const sig = sign(signing.endCell().hash(), laneKp.secretKey);
    const w5body = beginCell().storeBuilder(signing).storeBuffer(sig).endCell();
    const ext = beginCell().store(storeMessage(external({ to: lane.address, init: lane.init, body: w5body }), { forceRef: true })).endCell();
    const norm = beginCell().store(storeMessage(external({ to: lane.address, body: w5body }), { forceRef: true })).endCell();

    const mte = beginCell().store(storeMetaTransactionExecuted({ $$type: 'MetaTransactionExecuted', master: master.address, from: payer.address, digest: BigInt(h(op)) })).endCell();
    const ps = beginCell().store(storePaymentSettled({ $$type: 'PaymentSettled', from: payer.address, to: payee, amount: 1_234_567n, payRef: fields.payRef })).endCell();
    const code = walletInit.init!.code;
    return {
        schema: METAOP_SCHEMA, schema_crc32: SCHEMA_CRC,
        metaop: {
            network: fields.network, op: fields.op, amount: fields.amount.toString(), nonce: fields.nonce.toString(),
            valid_until: fields.validUntil, contract: raw(payerWallet), from: raw(payer.address), to: raw(payee),
            pay_ref: '0x' + 'ab'.repeat(32), lane: '0x' + 'cd'.repeat(32), extra: '0x' + '00'.repeat(32),
            boc: hex(op), digest: h(op),
        },
        sign_data: { domain, domain_cell_hash: h(domainCell(domain)), timestamp: ts, envelope_hash: h(envelope), pubkey: payerKp.publicKey.toString('hex'), signature: auth.beginParse().skip(8).loadBuffer(64).toString('hex'), auth_cell_hash: h(auth) },
        payer_w5: { address: raw(payer.address), state_init_boc: hex(stateInitCell(payer.init)), wallet_id: walletId },
        jetton: { master: raw(master.address), wallet_code_hash: '0x' + code.hash().toString('hex'), wallet_code_depth: code.depth(), payer_wallet: raw(payerWallet), wallet_code_boc: hex(code) },
        trade_params: { boc: hex(params), hash: h(params) },
        signed_op: { boc: hex(signedOp), hash: h(signedOp) },
        lane_w5: {
            seed: '11'.repeat(32), pubkey: laneKp.publicKey.toString('hex'), address: raw(lane.address), wallet_id: walletId,
            code_boc: hex(lane.init.code), data_hash: h(lane.init.data), seqno, valid_until: validUntil, value: toNano('0.15').toString(),
            relaxed_hash: h(relaxed), body_hash: h(w5body), ext_boc: hex(ext), ext_hash: h(ext), norm_hash: h(norm),
        },
        events: { mte_boc: hex(mte), ps_boc: hex(ps) },
    };
}

describe('cross-implementation vectors', () => {
    it('match vectors/ton-vectors.json', async () => {
        const v = JSON.parse(JSON.stringify(await build()));
        if (process.env.UPDATE_VECTORS || !existsSync(FILE)) {
            mkdirSync(join(__dirname, '..', 'vectors'), { recursive: true });
            writeFileSync(FILE, JSON.stringify(v, null, 2) + '\n');
        }
        expect(v).toEqual(JSON.parse(readFileSync(FILE, 'utf8')));
    });
});
