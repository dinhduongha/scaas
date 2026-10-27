// Cross-implementation vectors (deliverable 4): the SAME bytes/digests computed here (@ton/core, the
// reference) must come out of dms_blockchain/lib/fam_ton.py and scaas-node/src/adapters/ton.rs.
// UPDATE_VECTORS=1 npx jest tests/vectors.spec.ts rewrites vectors/ton-vectors.json.
import { Address, beginCell, Cell, external, internal, storeMessage, storeMessageRelaxed, toNano } from '@ton/core';
import { keyPairFromSeed, sign } from '@ton/crypto';
import { WalletContractV5R1 } from '@ton/ton';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { ScaasJettonWallet, storeMetaTransactionExecuted, storePaymentMeta, storePaymentSettled, storeSignedOp } from '../build/jetton/jetton_ScaasJettonWallet';
import { ScaasJettonMaster } from '../build/jetton/jetton_ScaasJettonMaster';
import { ScaasRelayFee, storeRelayCall, storeRelayRefund } from '../build/relayfee/relayfee_ScaasRelayFee';
import { setup } from './fixture';
import { domainCell, metaOpCell, METAOP_SCHEMA, payMetaParams, SCHEMA_CRC, signDataCell, snakeCell, stateInitCell, tonConnectAuth, tradeParamsCell } from './helpers';

const FILE = join(__dirname, '..', 'vectors', 'ton-vectors.json');
// CTR-MTX-26 shared vectors (`[{name, schema, salt, meta, payId, payLane}]`, hex), read by every family.
const PAYMETA: { name: string; salt: string; meta: string; payId: string; payLane: string }[] =
    JSON.parse(readFileSync(join(__dirname, '..', '..', 'vectors', 'metatx', 'paymeta.json'), 'utf8'));
const bytes = (h: string) => Buffer.from(h.slice(2), 'hex');
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
    // Pay-meta (CTR-MTX-26): the `params` cell and the `PaymentMeta` event of the first shared vector.
    const pmRow = PAYMETA[0];
    const pmMeta = snakeCell(bytes(pmRow.meta));
    const pmParams = payMetaParams(BigInt(pmRow.salt), pmMeta);
    const pm = beginCell().store(storePaymentMeta({ $$type: 'PaymentMeta', master: master.address, payId: BigInt(pmRow.payId), meta: pmMeta })).endCell();
    const code = walletInit.init!.code;
    // Relay fee (CTR-MTX-27): ref of a call with refs two levels down, the escrow key, and the router's message bodies.
    const { bc, admin, newToken, mint, walletOf } = await setup();
    const laneToken = await newToken('L');
    await mint(laneToken, admin.address, 1n);
    const laneWallet = await walletOf(laneToken, admin.address);
    const router = bc.openContract(await ScaasRelayFee.fromInit());
    await router.send((await bc.treasury('deployer')).getSender(), { value: toNano('1') }, null);
    const rfTarget = Address.parse('0:' + '44'.repeat(32));
    const rfCall = beginCell().storeUint(0x5b0a1d01, 32).storeRef(beginCell().storeRef(beginCell().storeUint(1, 8).endCell()).endCell())
        .storeRef(beginCell().storeUint(2, 8).endCell()).endCell();
    const rfSalt = BigInt('0x' + '5a'.repeat(32));
    const rfRef = await router.getGetRelayRef(rfTarget, rfCall, rfSalt);
    const u = (x: bigint) => '0x' + x.toString(16).padStart(64, '0');
    const rfOp = metaOpCell({ ...fields, to: router.address, relayer: router.address, payRef: rfRef, lane: await laneWallet.getGetPayLane(rfRef), amount: 25n });
    const rfAuth = tonConnectAuth(payerKp, payer.address, ts, domain, rfOp);
    const relayCall = beginCell().store(storeRelayCall({ $$type: 'RelayCall', target: rfTarget, call: rfCall, salt: rfSalt, payWallet: payerWallet,
        payOp: rfOp, payAuth: rfAuth, payStateInit: stateInitCell(payer.init), master: master.address, deadline: 1_800_000_600n })).endCell();
    const relayRefund = beginCell().store(storeRelayRefund({ $$type: 'RelayRefund', from: payer.address, ref: rfRef })).endCell();
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
        events: { mte_boc: hex(mte), ps_boc: hex(ps), pm_boc: hex(pm) },
        pay_meta: { name: pmRow.name, salt: pmRow.salt, meta: pmRow.meta, pay_id: pmRow.payId, pay_lane: pmRow.payLane,
                    meta_boc: hex(pmMeta), params_boc: hex(pmParams), params_hash: h(pmParams) },
        relay_fee: {
            router: raw(router.address), target: raw(rfTarget), call_boc: hex(rfCall), salt: u(rfSalt), ref: u(rfRef), from: raw(payer.address),
            escrow_key: h(beginCell().storeAddress(payer.address).storeUint(rfRef, 256).endCell()),
            pay_op_boc: hex(rfOp), relay_call_boc: hex(relayCall), relay_call_hash: h(relayCall), relay_refund_boc: hex(relayRefund),
        },
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

describe('paymeta vectors match', () => {
    // Rule 1: every row's payId / payLane from the wallet's own metaPayId / payLane (Tact keccak256 over the snake
    // chain), the 4,192-byte `long_body_4096` included; the chunking of the snake does not change the hash.
    it('metaPayId and payLane of every paymeta.json row', async () => {
        const { admin, newToken, walletOf } = await setup();
        const w = await walletOf(await newToken('A'), admin.address);
        expect(PAYMETA.map((r) => r.name)).toEqual(['note_utf8', 'structured_reference', 'bound_call', 'encrypted_illustrative', 'empty_body', 'long_body_4096']);
        for (const r of PAYMETA) {
            const meta = bytes(r.meta);
            const id = await w.getGetMetaPayId(BigInt(r.salt), snakeCell(meta));
            expect('0x' + id.toString(16).padStart(64, '0')).toBe(r.payId);
            expect('0x' + (await w.getGetPayLane(id)).toString(16).padStart(64, '0')).toBe(r.payLane);
            // 32 bytes per cell instead of 127: same bytes, same id
            let c: Cell | null = null;
            for (let i = Math.floor(Math.max(meta.length - 1, 0) / 32) * 32; i >= 0; i -= 32) {
                const b = beginCell().storeBuffer(meta.subarray(i, i + 32));
                if (c) b.storeRef(c);
                c = b.endCell();
            }
            expect(await w.getGetMetaPayId(BigInt(r.salt), c!)).toBe(id);
        }
        expect(bytes(PAYMETA[5].meta).length).toBe(4192);
    });
});
