import { Address, beginCell, internal, SendMode, toNano } from '@ton/core';
import { keyPairFromSeed } from '@ton/crypto';
import { WalletContractV5R1 } from '@ton/ton';
import '@ton/test-utils';
import { storeSignedOp } from '../build/jetton/jetton_ScaasJettonWallet';
import { DOMAIN, events, globalIdOf, setup, signedPay, Subject } from './fixture';
import { domainCell, metaOpCell, newPasskey, OP, passkeyAuth, passkeyRecord, payMetaParams, randomU256, snakeCell, subject, tonConnectAuth } from './helpers';

const E = { domain: 701, network: 702, contract: 703, from: 704, expired: 705, nonce: 706, relayer: 707, sig: 708, noKey: 709, stateInit: 710, balance: 711, params: 713, value: 714, auth: 715, sender: 716, ttl: 717 };

describe('ScaasJettonWallet meta-tx (R30, R67)', () => {
    it('sandbox global id is what MetaOp.network must carry', async () => {
        const { bc } = await setup();
        expect(globalIdOf(bc)).toBe(-239);
    });

    it('relayer pays a signed transfer; payer never sends a tx; events carry digest and payRef', async () => {
        const { bc, relayer, network, newToken, mint, walletOf, balanceOf } = await setup();
        const token = await newToken('A');
        const alice = await subject(1);
        const bob = await subject(2);
        await mint(token, alice.address, 1000n);
        const aw = await walletOf(token, alice.address);
        const sp = signedPay(alice, { contract: aw.address, to: bob.address, amount: 300n, network }, { responseDestination: relayer.address });
        const r = await aw.send(relayer.getSender(), { value: toNano('0.15') }, sp.body);
        expect(r.transactions).toHaveTransaction({ from: relayer.address, to: aw.address, success: true });
        expect(await balanceOf(token, alice.address)).toBe(700n);
        expect(await balanceOf(token, bob.address)).toBe(300n);
        const ev = events(r.transactions);
        const mte = ev.find((e) => e.name === 'MetaTransactionExecuted');
        expect(mte.digest).toBe(BigInt('0x' + sp.digest.toString('hex')));
        expect(mte.from.equals(alice.address)).toBe(true);
        expect(mte.master.equals(token.address)).toBe(true);
        expect(mte.src.equals(aw.address)).toBe(true);
        const ps = ev.find((e) => e.name === 'PaymentSettled');
        expect(ps.payRef).toBe(sp.fields.payRef);
        expect(ps.amount).toBe(300n);
        expect(ps.src.equals((await walletOf(token, bob.address)).address)).toBe(true);
        // excess TON goes back to the relayer lane
        expect(r.transactions).toHaveTransaction({ to: relayer.address, op: 0xd53276db });
        expect(await aw.getGetOwnerPubkey()).toBe(BigInt('0x' + alice.kp.publicKey.toString('hex')));
        expect(await aw.getGetLaneNonce(sp.fields.lane)).toBe(1n);
    });

    it('rejects replay, expiry, wrong network/contract/relayer/from, foreign key, missing key, bad domain cell', async () => {
        const { bc, relayer, admin, network, newToken, mint, walletOf, balanceOf } = await setup();
        const token = await newToken('A');
        const alice = await subject(1);
        const mallory = await subject(9);
        const bob = await subject(2);
        await mint(token, alice.address, 1000n);
        const aw = await walletOf(token, alice.address);
        const base = { contract: aw.address, to: bob.address, amount: 10n, network };
        const send = (body: any, via = relayer) => aw.send(via.getSender(), { value: toNano('0.15') }, body);
        const fail = async (body: any, code: number, via = relayer) =>
            expect((await send(body, via)).transactions).toHaveTransaction({ to: aw.address, success: false, exitCode: code });

        await fail(signedPay(alice, base, { withInit: false, responseDestination: relayer.address }).body, E.noKey);
        await fail(signedPay(alice, base, { responseDestination: relayer.address }).body.stateInit ? { ...signedPay(alice, base, { responseDestination: relayer.address }).body, stateInit: mallory.stateInit } : null, E.stateInit);
        await fail(signedPay(alice, { ...base, network: -3 }, { responseDestination: relayer.address }).body, E.network);
        await fail(signedPay(alice, { ...base, contract: bob.address }, { responseDestination: relayer.address }).body, E.contract);
        await fail(signedPay(alice, { ...base, validUntil: 1_800_000_000 }, { responseDestination: relayer.address }).body, E.expired);
        // valid further ahead than one lane window: its replay entry could be pruned while it is still valid
        await fail(signedPay(alice, { ...base, validUntil: 1_800_000_000 + 30 * 86400 + 1 }, { responseDestination: relayer.address }).body, E.ttl);
        await fail(signedPay(alice, { ...base, relayer: admin.address }, { responseDestination: relayer.address }).body, E.relayer);
        await fail(signedPay(alice, { ...base, from: bob.address }, { responseDestination: relayer.address }).body, E.from);
        // mallory signs alice's op with her own key: the wallet binds alice's key from alice's StateInit
        const forged = signedPay(mallory, { ...base, from: alice.address }, { responseDestination: relayer.address });
        await fail({ ...forged.body, stateInit: alice.stateInit }, E.sig);
        // signature over a different domain cell than the one supplied
        const ok = signedPay(alice, base, { responseDestination: relayer.address });
        const otherDomain = tonConnectAuth(alice.kp, alice.address, 1_800_000_000, 'evil.example', ok.op);
        const swapped = beginCell().storeBits(otherDomain.beginParse().loadBits(8 + 512 + 64)).storeRef(domainCell(DOMAIN)).endCell();
        await fail({ ...ok.body, auth: swapped }, E.sig);
        // gas below minimum
        expect((await aw.send(relayer.getSender(), { value: toNano('0.02') }, ok.body)).transactions).toHaveTransaction({ to: aw.address, success: false, exitCode: E.value });
        // first run succeeds, replay fails
        expect((await send(ok.body)).transactions).toHaveTransaction({ to: aw.address, success: true });
        await fail(ok.body, E.nonce);
        // relayer-bound op accepted from that relayer only
        const bound = signedPay(alice, { ...base, relayer: relayer.address }, { responseDestination: relayer.address });
        expect((await send(bound.body)).transactions).toHaveTransaction({ to: aw.address, success: true });
        // amount above balance
        await fail(signedPay(alice, { ...base, amount: 10_000n }, { responseDestination: relayer.address }).body, E.balance);
        expect(await balanceOf(token, alice.address)).toBe(980n);
    });

    it('same lane, increasing nonces; nonce gap refused', async () => {
        const { relayer, network, newToken, mint, walletOf } = await setup();
        const token = await newToken('A');
        const alice = await subject(1);
        const bob = await subject(2);
        await mint(token, alice.address, 1000n);
        const aw = await walletOf(token, alice.address);
        const lane = randomU256();
        const mk = (nonce: bigint) => signedPay(alice, { contract: aw.address, to: bob.address, amount: 1n, network, lane, nonce }, { responseDestination: relayer.address }).body;
        expect((await aw.send(relayer.getSender(), { value: toNano('0.15') }, mk(1n))).transactions).toHaveTransaction({ to: aw.address, exitCode: E.nonce });
        expect((await aw.send(relayer.getSender(), { value: toNano('0.15') }, mk(0n))).transactions).toHaveTransaction({ to: aw.address, success: true });
        expect((await aw.send(relayer.getSender(), { value: toNano('0.15') }, mk(1n))).transactions).toHaveTransaction({ to: aw.address, success: true });
        expect(await aw.getGetLaneNonce(lane)).toBe(2n);
    });

    it('ANTI-LOCK: op X on contract 1 withheld, op Y on contract 2 succeeds, then X succeeds', async () => {
        const { relayer, network, newToken, mint, walletOf, balanceOf } = await setup();
        const tokenA = await newToken('A');
        const tokenB = await newToken('B');
        const alice = await subject(1);
        const bob = await subject(2);
        await mint(tokenA, alice.address, 100n);
        await mint(tokenB, alice.address, 100n);
        const wa = await walletOf(tokenA, alice.address);
        const wb = await walletOf(tokenB, alice.address);
        // Same lane id and nonce 0 on both contracts: lanes are per contract, nothing is shared.
        const lane = randomU256();
        const x = signedPay(alice, { contract: wa.address, to: bob.address, amount: 40n, network, lane }, { responseDestination: relayer.address });
        const y = signedPay(alice, { contract: wb.address, to: bob.address, amount: 25n, network, lane }, { responseDestination: relayer.address });
        expect((await wb.send(relayer.getSender(), { value: toNano('0.15') }, y.body)).transactions).toHaveTransaction({ to: wb.address, success: true });
        expect(await balanceOf(tokenB, bob.address)).toBe(25n);
        expect(await balanceOf(tokenA, bob.address)).toBe(0n);
        expect((await wa.send(relayer.getSender(), { value: toNano('0.15') }, x.body)).transactions).toHaveTransaction({ to: wa.address, success: true });
        expect(await balanceOf(tokenA, bob.address)).toBe(40n);
    });

    it('works for a V4R2 owner too (StateInit binding by code hash)', async () => {
        const { relayer, network, newToken, mint, walletOf, balanceOf } = await setup();
        const { WalletContractV4 } = require('@ton/ton');
        const { keyPairFromSeed } = require('@ton/crypto');
        const { stateInitCell } = require('./helpers');
        const kp = keyPairFromSeed(Buffer.alloc(32, 7));
        const w4 = WalletContractV4.create({ workchain: 0, publicKey: kp.publicKey });
        const carol = { kp, address: w4.address, stateInit: stateInitCell(w4.init) };
        const bob = await subject(2);
        const token = await newToken('A');
        await mint(token, carol.address, 50n);
        const cw = await walletOf(token, carol.address);
        const sp = signedPay(carol, { contract: cw.address, to: bob.address, amount: 50n, network }, { responseDestination: relayer.address });
        expect((await cw.send(relayer.getSender(), { value: toNano('0.15') }, sp.body)).transactions).toHaveTransaction({ to: cw.address, success: true });
        expect(await balanceOf(token, bob.address)).toBe(50n);
    });

    it('standard TEP-74 transfer by the owner still works and only the owner may send it', async () => {
        const { bc, relayer, newToken, mint, walletOf, balanceOf } = await setup();
        const token = await newToken('A');
        const owner = await bc.treasury('owner');
        await mint(token, owner.address, 10n);
        const w = await walletOf(token, owner.address);
        const t = { $$type: 'JettonTransfer' as const, queryId: 0n, amount: 4n, destination: relayer.address, responseDestination: owner.address, customPayload: null, forwardTonAmount: 0n, forwardPayload: beginCell().storeBit(false).asSlice() };
        expect((await w.send(relayer.getSender(), { value: toNano('0.1') }, t)).transactions).toHaveTransaction({ to: w.address, success: false, exitCode: E.sender });
        expect((await w.send(owner.getSender(), { value: toNano('0.1') }, t)).transactions).toHaveTransaction({ to: w.address, success: true });
        expect(await balanceOf(token, relayer.address)).toBe(4n);
    });

    it('a forged JettonTransferInternal (not from the master or a sibling wallet) cannot credit a real wallet', async () => {
        const { bc, newToken, mint, walletOf, balanceOf } = await setup();
        const real = await newToken('A');
        const fake = await newToken('FAKE');
        const alice = await subject(1);
        const bob = await subject(2);
        await mint(real, bob.address, 1n);
        await mint(fake, alice.address, 1000n);
        const bobReal = await walletOf(real, bob.address);
        const forged = { $$type: 'JettonTransferInternal' as const, queryId: 0n, amount: 5n, sender: alice.address, responseDestination: null, forwardTonAmount: 0n, forwardPayload: beginCell().storeBit(false).asSlice() };
        // from a plain account claiming to be alice's wallet, and from alice's REAL-code wallet of another master
        const mallory = await bc.treasury('mallory');
        expect((await bobReal.send(mallory.getSender(), { value: toNano('0.1') }, forged)).transactions).toHaveTransaction({ to: bobReal.address, success: false, exitCode: E.sender });
        const fw = await walletOf(fake, alice.address);
        const { internal } = require('@ton/sandbox');
        const { storeJettonTransferInternal } = require('../build/jetton/jetton_ScaasJettonWallet');
        const r = await bc.sendMessage(internal({ from: fw.address, to: bobReal.address, value: toNano('0.1'), body: beginCell().store(storeJettonTransferInternal(forged)).endCell() }));
        expect(r.transactions).toHaveTransaction({ to: bobReal.address, success: false, exitCode: E.sender });
        expect(await balanceOf(real, bob.address)).toBe(1n);
    });

    it('passkey (P-256 WebAuthn via P256_CHKSIGNS): set by the ed25519 key, then signs a pay', async () => {
        const { relayer, network, newToken, mint, walletOf, balanceOf } = await setup();
        const token = await newToken('A');
        const alice = await subject(1);
        const bob = await subject(2);
        await mint(token, alice.address, 100n);
        const aw = await walletOf(token, alice.address);
        const pk = newPasskey();
        const rec = passkeyRecord(pk.compressed, 'pay.scaas.example', 'https://pay.scaas.example');
        const setKey = signedPay(alice, { contract: aw.address, to: alice.address, amount: 0n, network, op: OP.set_key, extra: BigInt('0x' + rec.hash().toString('hex')) }, { params: rec, responseDestination: relayer.address });
        expect((await aw.send(relayer.getSender(), { value: toNano('0.15') }, setKey.body)).transactions).toHaveTransaction({ to: aw.address, success: true });
        expect((await aw.getGetPasskey())!.hash().equals(rec.hash())).toBe(true);

        const fields = { op: OP.pay, network, amount: 30n, nonce: 0n, validUntil: 1_800_000_600, contract: aw.address, from: alice.address, to: bob.address, payRef: randomU256(), lane: randomU256(), extra: 0n };
        // Both halves of the digest space (review: the success case used to run on top-bit-set digests only).
        const withTopBit = (set: boolean) => {
            const f = { ...fields, lane: randomU256() };
            while ((metaOpCell(f).hash()[0] >= 0x80) !== set) f.lane = randomU256();
            return metaOpCell(f);
        };
        const low = withTopBit(false);
        const rl = await aw.send(relayer.getSender(), { value: toNano('0.2') }, { $$type: 'SignedOp', op: low, auth: passkeyAuth(pk.privateKey, 'pay.scaas.example', 'https://pay.scaas.example', low.hash()), params: null, stateInit: null, responseDestination: relayer.address, forwardTon: 0n, matchWith: 0n });
        expect(rl.transactions).toHaveTransaction({ to: aw.address, success: true });
        expect(await balanceOf(token, bob.address)).toBe(30n);
        const op = withTopBit(true);
        const send = (auth: any) => aw.send(relayer.getSender(), { value: toNano('0.2') }, { $$type: 'SignedOp', op, auth, params: null, stateInit: null, responseDestination: relayer.address, forwardTon: 0n, matchWith: 0n });
        // wrong origin, missing UV, wrong digest, long client data (two suffix cells) — then the good one
        expect((await send(passkeyAuth(pk.privateKey, 'pay.scaas.example', 'https://evil.example', op.hash()))).transactions).toHaveTransaction({ to: aw.address, exitCode: E.sig });
        expect((await send(passkeyAuth(pk.privateKey, 'pay.scaas.example', 'https://pay.scaas.example', op.hash(), 0x01))).transactions).toHaveTransaction({ to: aw.address, exitCode: E.sig });
        expect((await send(passkeyAuth(pk.privateKey, 'pay.scaas.example', 'https://pay.scaas.example', Buffer.alloc(32, 1)))).transactions).toHaveTransaction({ to: aw.address, exitCode: E.sig });
        const long = ',"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"';
        const r = await send(passkeyAuth(pk.privateKey, 'pay.scaas.example', 'https://pay.scaas.example', op.hash(), 0x05, long));
        expect(r.transactions).toHaveTransaction({ to: aw.address, success: true });
        expect(await balanceOf(token, bob.address)).toBe(60n);

        // a passkey cannot change keys
        const rm = metaOpCell({ ...fields, op: OP.set_key, to: alice.address, amount: 0n, lane: randomU256() });
        const r2 = await aw.send(relayer.getSender(), { value: toNano('0.2') }, { $$type: 'SignedOp', op: rm, auth: passkeyAuth(pk.privateKey, 'pay.scaas.example', 'https://pay.scaas.example', rm.hash()), params: null, stateInit: null, responseDestination: relayer.address, forwardTon: 0n, matchWith: 0n });
        expect(r2.transactions).toHaveTransaction({ to: aw.address, exitCode: E.auth });
    });

    it('signature over the TON Connect envelope uses the domain the wallet reports', async () => {
        const { relayer, network, newToken, mint, walletOf, balanceOf } = await setup();
        const token = await newToken('A');
        const alice = await subject(1);
        const bob = await subject(2);
        await mint(token, alice.address, 10n);
        const aw = await walletOf(token, alice.address);
        const sp = signedPay(alice, { contract: aw.address, to: bob.address, amount: 10n, network }, { domain: 'other.example', ts: 1_700_000_000, responseDestination: relayer.address });
        expect((await aw.send(relayer.getSender(), { value: toNano('0.15') }, sp.body)).transactions).toHaveTransaction({ to: aw.address, success: true });
        expect(await balanceOf(token, bob.address)).toBe(10n);
        expect(DOMAIN).toBe('pay.scaas.example');
    });

    it('a long-idle, heavily used wallet keeps its jettons: lanes are pruned and storage is reserved (review M4)', async () => {
        const { bc, relayer, network, newToken, mint, walletOf, balanceOf } = await setup();
        const token = await newToken('A');
        const alice = await subject(1);
        const bob = await subject(2);
        await mint(token, alice.address, 1000n);
        const aw = await walletOf(token, alice.address);
        for (let i = 0; i < 150; i++) {
            const sp = signedPay(alice, { contract: aw.address, to: bob.address, amount: 1n, network, validUntil: bc.now! + 600 }, { responseDestination: relayer.address });
            expect((await aw.send(relayer.getSender(), { value: toNano('0.15') }, sp.body)).transactions).toHaveTransaction({ to: aw.address, success: true });
        }
        // ~0.00015 TON per entry-year in the sandbox: 10 idle years put the old wallet past the 0.1 TON freeze limit
        bc.now = bc.now! + 10 * 365 * 86400;
        const sp = signedPay(alice, { contract: aw.address, to: bob.address, amount: 1n, network, validUntil: bc.now! + 600 }, { responseDestination: relayer.address });
        expect((await aw.send(relayer.getSender(), { value: toNano('0.15') }, sp.body)).transactions).toHaveTransaction({ to: aw.address, success: true });
        expect((await bc.getContract(aw.address)).accountState?.type).toBe('active');
        expect(await balanceOf(token, alice.address)).toBe(849n);
    });
});

// CTR-MTX-26 (metatx-split T15): pay-meta is `OP_PAY` with `params = salt:uint256 ^meta`.
describe('pay-meta on OP_PAY (CTR-MTX-26)', () => {
    const META = snakeCell(Buffer.from('invoice 2026-0042: thanh toán đợt 1'));
    const SALT = BigInt('0x' + '5a'.repeat(32));

    async function ctx() {
        const f = await setup();
        const token = await f.newToken('A');
        const alice = await subject(1);
        const bob = await subject(2);
        const mallory = await subject(9);
        await f.mint(token, alice.address, 1000n);
        await f.mint(token, mallory.address, 1000n);
        const aw = await f.walletOf(token, alice.address);
        const mw = await f.walletOf(token, mallory.address);
        /// A pay-meta signed by `s` on its wallet `w`: payRef = metaPayId(salt, meta), lane = payLane(payRef), nonce 0.
        const metaPay = async (s: Subject, w: typeof aw, amount: bigint, salt = SALT, meta = META, over: Record<string, any> = {}) => {
            const payRef = await w.getGetMetaPayId(salt, meta);
            const lane = await w.getGetPayLane(payRef);
            return signedPay(s, { contract: w.address, to: bob.address, amount, network: f.network, payRef, lane, ...over },
                { params: payMetaParams(salt, meta), responseDestination: f.relayer.address });
        };
        const send = (w: typeof aw, body: any, value = toNano('0.15')) => w.send(f.relayer.getSender(), { value }, body);
        return { ...f, token, alice, bob, mallory, aw, mw, metaPay, send };
    }

    it('pay with params emits PaymentMeta then PaymentSettled', async () => {
        const c = await ctx();
        const sp = await c.metaPay(c.alice, c.aw, 300n);
        const r = await c.send(c.aw, sp.body);
        expect(r.transactions).toHaveTransaction({ from: c.relayer.address, to: c.aw.address, success: true });
        expect(await c.balanceOf(c.token, c.bob.address)).toBe(300n);
        const ev = events(r.transactions);
        expect(ev.map((e) => e.name)).toEqual(['MetaTransactionExecuted', 'PaymentMeta', 'PaymentSettled']);
        const [mte, pm, ps] = ev;
        expect(mte.digest).toBe(BigInt('0x' + sp.digest.toString('hex')));
        expect(pm.src.equals(c.aw.address)).toBe(true);
        expect(pm.master.equals(c.token.address)).toBe(true);
        expect(pm.payId).toBe(sp.fields.payRef);
        expect(pm.meta.hash().equals(META.hash())).toBe(true);
        expect(ps.payRef).toBe(sp.fields.payRef);
        expect(ps.src.equals((await c.walletOf(c.token, c.bob.address)).address)).toBe(true);
        // the payer wallet's tx (PaymentMeta) precedes the payee wallet's (PaymentSettled) in logical time
        const lt = (src: Address) => r.transactions.find((t) => t.outMessages.values().some((m) => m.info.type === 'external-out' && m.info.src.equals(src)))!.lt;
        expect(lt(c.aw.address) < lt(ps.src)).toBe(true);
        expect(await c.aw.getGetLaneNonce(sp.fields.lane)).toBe(1n);
    });

    it('ton pay meta mismatch and replay', async () => {
        const c = await ctx();
        const fail = async (body: any, code: number) =>
            expect((await c.send(c.aw, body)).transactions).toHaveTransaction({ to: c.aw.address, success: false, exitCode: code });
        const sp = await c.metaPay(c.alice, c.aw, 10n);
        const other = snakeCell(Buffer.from('invoice 2026-0043'));
        // (salt, meta) must hash to the signed payRef
        await fail({ ...sp.body, params: payMetaParams(SALT, other) }, E.params);
        await fail({ ...sp.body, params: payMetaParams(SALT + 1n, META) }, E.params);
        // lane must be payLane(payRef)
        const id = await c.aw.getGetMetaPayId(SALT, META);
        await fail(signedPay(c.alice, { contract: c.aw.address, to: c.bob.address, amount: 10n, network: c.network, payRef: id, lane: randomU256() },
            { params: payMetaParams(SALT, META), responseDestination: c.relayer.address }).body, E.params);
        // malformed params: no ^meta, or trailing bits (cell underflow)
        await fail({ ...sp.body, params: beginCell().storeUint(SALT, 256).endCell() }, 9);
        await fail({ ...sp.body, params: beginCell().storeUint(SALT, 256).storeRef(META).storeBit(true).endCell() }, 9);
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n);
        // first run pays; the same body again is refused by the lane
        expect((await c.send(c.aw, sp.body)).transactions).toHaveTransaction({ to: c.aw.address, success: true });
        await fail(sp.body, E.nonce);
        // a fresh signature at the lane's next nonce: nonce must be 0
        await fail((await c.metaPay(c.alice, c.aw, 10n, SALT, META, { nonce: 1n })).body, E.params);
        // the off-chain variant (plain OP_PAY, same payRef and lane) shares the once-set
        await fail(signedPay(c.alice, { contract: c.aw.address, to: c.bob.address, amount: 10n, network: c.network, payRef: id, lane: sp.fields.lane },
            { responseDestination: c.relayer.address }).body, E.nonce);
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(990n);
        expect(await c.aw.getGetLaneNonce(sp.fields.lane)).toBe(1n);
    });

    it("an attacker's minimal pre-burn of the victim's payId does not block the victim (per payer)", async () => {
        const c = await ctx();
        // mallory learns alice's (salt, meta) and pays 1 unit with it from her own wallet first
        const pre = await c.metaPay(c.mallory, c.mw, 1n);
        expect((await c.send(c.mw, pre.body)).transactions).toHaveTransaction({ to: c.mw.address, success: true });
        const sp = await c.metaPay(c.alice, c.aw, 250n);
        expect(sp.fields.payRef).toBe(pre.fields.payRef);
        const r = await c.send(c.aw, sp.body);
        expect(r.transactions).toHaveTransaction({ to: c.aw.address, success: true });
        expect(events(r.transactions).find((e) => e.name === 'PaymentMeta').payId).toBe(sp.fields.payRef);
        expect(await c.balanceOf(c.token, c.bob.address)).toBe(251n);
        // mallory's own lane is spent
        expect((await c.send(c.mw, (await c.metaPay(c.mallory, c.mw, 1n)).body)).transactions).toHaveTransaction({ to: c.mw.address, exitCode: E.nonce });
    });

    it('pay without params unchanged', async () => {
        const c = await ctx();
        const sp = signedPay(c.alice, { contract: c.aw.address, to: c.bob.address, amount: 7n, network: c.network }, { responseDestination: c.relayer.address });
        expect(sp.body.params).toBeNull();
        const r = await c.send(c.aw, sp.body);
        expect(r.transactions).toHaveTransaction({ to: c.aw.address, success: true });
        expect(events(r.transactions).map((e) => e.name)).toEqual(['MetaTransactionExecuted', 'PaymentSettled']);
        expect(await c.balanceOf(c.token, c.bob.address)).toBe(7n);
    });

    // Rule 1: the TON meta size limit, measured. The node's cap (`max_pay_meta_bytes`, 2,048 B) and the shared vectors'
    // `long_body_4096` (4,192 B) both settle at the node's default attach (0.15 TON) through a real W5R1 lane (an external
    // message, the path `ton.rs` takes). The largest meta that still settles is searched up to config param 43's
    // `max_ext_msg_size` (65,535 B; `max_ext_msg_depth` 512, and a 127-byte snake is one level per cell) with a fresh
    // chain per probe (an emulator abort poisons its instance).
    it('meta size limit: measured through a W5R1 lane', async () => {
        const laneKp = keyPairFromSeed(Buffer.alloc(32, 0x11));
        // One lane tx carrying a pay-meta of `n` bytes on a fresh chain; ok when the payer wallet settled it.
        const viaLane = async (n: number, value = toNano('0.15'), plain = false) => {
            const c = await ctx();
            const lane = c.bc.openContract(WalletContractV5R1.create({ workchain: 0, publicKey: laneKp.publicKey, walletId: { networkGlobalId: -239 } }));
            await c.relayer.send({ to: lane.address, value: toNano('100'), bounce: false });
            try {
                const meta = snakeCell(Buffer.alloc(n, 0x61));
                const sp = plain
                    ? signedPay(c.alice, { contract: c.aw.address, to: c.bob.address, amount: 1n, network: c.network }, { responseDestination: lane.address })
                    : await c.metaPay(c.alice, c.aw, 1n, randomU256(), meta);
                const body = beginCell().store(storeSignedOp({ ...sp.body, responseDestination: lane.address })).endCell();
                const r = await lane.sendTransfer({ seqno: 0, secretKey: laneKp.secretKey, timeout: c.bc.now! + 60, sendMode: SendMode.PAY_GAS_SEPARATELY,
                    messages: [internal({ to: c.aw.address, value, bounce: true, body })] });
                const tx = r.transactions.find((t) => t.inMessage?.info.type === 'internal' && t.inMessage.info.dest.equals(c.aw.address));
                const d = tx?.description as any;
                const ok = !!tx && d.computePhase?.success === true && d.actionPhase?.success === true && (await c.balanceOf(c.token, c.bob.address)) === 1n;
                return { ok, why: tx ? `compute ${d.computePhase?.exitCode} action ${d.actionPhase?.resultCode}` : 'not delivered', fees: tx?.totalFees.coins, gas: d?.computePhase?.gasUsed };
            } catch (e) {
                return { ok: false, why: String(e).split('\n')[0].slice(0, 120) };
            }
        };
        const rows: Record<string, any> = { plain: await viaLane(0, toNano('0.15'), true) };
        for (const n of [0, 160, 2048, 4192]) {
            rows[n] = await viaLane(n);
            expect(rows[n].ok).toBe(true);
        }
        expect(rows.plain.ok).toBe(true);
        let lo = 4192, hi = 65535;
        while (hi - lo > 1) {
            const mid = Math.floor((lo + hi) / 2);
            if ((await viaLane(mid)).ok) lo = mid; else hi = mid;
        }
        const above = await viaLane(hi, toNano('10'));
        // @ton/sandbox 0.45.0: 300 snake cells (38,100 B) settle; the 301st cell aborts the emulator, whatever the TON.
        expect(lo).toBe(300 * 127);
        console.log('TON pay-meta size', JSON.stringify({ rows, largest: lo, above: { n: hi, ...above } }, (_, v) => (typeof v === 'bigint' ? v.toString() : v)));
        expect(above.ok).toBe(false);
    });
});
