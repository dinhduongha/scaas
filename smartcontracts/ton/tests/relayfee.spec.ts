// CTR-MTX-27 on TON (metatx-split T16): the relay-fee escrow router (spec §7.2 TON row).
import { Address, beginCell, Cell, toNano } from '@ton/core';
import { internal } from '@ton/sandbox';
import '@ton/test-utils';
import { storeSignedOp } from '../build/jetton/jetton_ScaasJettonWallet';
import { ScaasDex } from '../build/dex/dex_ScaasDex';
import { ScaasRelayFee, loadRelayFeePaid, storeJettonNotification, storeRelayCall, storeRelayOutcome, storeRelayProbe } from '../build/relayfee/relayfee_ScaasRelayFee';
import { DOMAIN, setup, signedPay, Subject } from './fixture';
import { metaOpCell, MetaOpFields, OP, randomU256, subject, tonConnectAuth } from './helpers';

const E = { relayer: 707, sig: 708, value: 714, shape: 741, pending: 742, deadline: 743, unknown: 744, early: 745 };
const RELAY_TIMEOUT = 3600;
const FEE = 25n;

async function ctx() {
    const f = await setup();
    const token = await f.newToken('A');
    const alice = await subject(1);
    const carol = await subject(3);
    const mallory = await subject(9);
    for (const s of [alice, carol, mallory]) await f.mint(token, s.address, 1000n);
    const router = f.bc.openContract(await ScaasRelayFee.fromInit());
    await router.send(f.admin.getSender(), { value: toNano('1') }, null);
    const aw = await f.walletOf(token, alice.address);
    const cw = await f.walletOf(token, carol.address);
    const mw = await f.walletOf(token, mallory.address);
    const relayerBalance = () => f.balanceOf(token, f.relayer.address);
    const routerBalance = () => f.balanceOf(token, router.address);

    /// A fee-less SCaaS call: `s`'s signed set_key (clears the passkey) on its own wallet `w`, relayer open, its excess
    /// to `response` (the executor, by the client rule). `signer` signs (another key = a call the wallet refuses).
    function setKeyCall(s: Subject, w: Address, response: Address, signer: Subject = s) {
        const op = metaOpCell({ network: f.network, op: OP.set_key, amount: 0n, nonce: 0n, validUntil: 1_800_000_600, contract: w,
            from: s.address, to: s.address, relayer: null, payRef: 0n, lane: randomU256(), extra: 0n });
        const auth = tonConnectAuth(signer.kp, s.address, 1_800_000_000, DOMAIN, op);
        return beginCell().store(storeSignedOp({ $$type: 'SignedOp', op, auth, params: null, stateInit: s.stateInit, responseDestination: response, forwardTon: 0n, matchWith: 0n })).endCell();
    }

    /// The payer's router-bound payment for (target, call, salt) and the RelayCall the relayer sends.
    async function relayCall(payer: Subject, target: Address, call: Cell, salt: bigint, o: { amount?: bigint; deadline?: number; over?: Partial<MetaOpFields>; signer?: Subject } = {}) {
        const w = await f.walletOf(token, payer.address);
        const ref = await router.getGetRelayRef(target, call, salt);
        const fields = { contract: w.address, to: router.address, relayer: router.address, amount: o.amount ?? FEE, network: f.network,
            payRef: ref, lane: await w.getGetPayLane(ref), ...o.over };
        const sp = signedPay(o.signer ?? payer, { ...fields, from: payer.address }, { responseDestination: router.address });
        return {
            ref, sp, body: {
                $$type: 'RelayCall' as const, target, call, salt, payWallet: w.address, payOp: sp.op, payAuth: sp.body.auth,
                payStateInit: payer.stateInit, master: token.address, deadline: BigInt(o.deadline ?? f.bc.now! + 600),
            },
        };
    }
    const value = () => router.getGetRelayValue(0n);
    const send = async (body: any, via = f.relayer, v?: bigint) => router.send(via.getSender(), { value: v ?? (await value()) }, body);
    const refund = (from: Address, ref: bigint, via = f.relayer) => router.send(via.getSender(), { value: toNano('0.1') }, { $$type: 'RelayRefund', from, ref });
    const paid = (txs: any[]) => txs.flatMap((t) => t.outMessages.values().filter((m: any) => m.info.type === 'external-out' && m.body.beginParse().preloadUint(32) === 0x9b1c0d05)
        .map((m: any) => loadRelayFeePaid(m.body.beginParse())));
    return { ...f, token, alice, carol, mallory, router, aw, cw, mw, setKeyCall, relayCall, send, refund, paid, value, relayerBalance, routerBalance };
}

describe('relay-fee escrow router (CTR-MTX-27, TON)', () => {
    it('release on the call\'s provable success: the executor calls, its probe bounce proves the call ran', async () => {
        const c = await ctx();
        const salt = randomU256();
        const exec = await c.router.getGetExecutor(c.alice.address, salt);
        const call = c.setKeyCall(c.carol, c.cw.address, exec);
        const { ref, body } = await c.relayCall(c.alice, c.cw.address, call, salt);
        const ton0 = (await c.bc.getContract(c.router.address)).balance;
        const r = await c.send(body);
        const ton1 = (await c.bc.getContract(c.router.address)).balance;
        // the target sees the executor, never the router (rule 4 / R18)
        expect(r.transactions).toHaveTransaction({ from: exec, to: c.cw.address, success: true });
        expect(r.transactions).not.toHaveTransaction({ from: c.router.address, to: c.cw.address });
        expect(await c.cw.getGetOwnerPubkey()).toBe(BigInt('0x' + c.carol.kp.publicKey.toString('hex')));
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n - FEE);
        expect(await c.relayerBalance()).toBe(FEE);
        expect(await c.routerBalance()).toBe(0n); // the escrow holds nothing once settled
        expect(await c.router.getGetPending(c.alice.address, ref)).toBeNull();
        const [ev, ...more] = c.paid(r.transactions);
        expect(more).toHaveLength(0);
        expect(ev.ref).toBe(ref);
        expect(ev.target.equals(c.cw.address) && ev.token.equals(c.token.address) && ev.payer.equals(c.alice.address) && ev.payee.equals(c.relayer.address)).toBe(true);
        expect(ev.amount).toBe(FEE);
        const fees = r.transactions.reduce((s, t) => s + t.totalFees.coins, 0n);
        console.log('relay-fee release', JSON.stringify({ txs: r.transactions.length, fees: fees.toString(), value: (await c.value()).toString(), routerTon: (ton1 - ton0).toString() }));
        expect(ton1 - ton0 < toNano('0.001') && ton0 - ton1 < toNano('0.001')).toBe(true); // nor TON: the relayer's comes back
    });

    it('refund on call bounce: payer refunded, nothing to the relayer', async () => {
        const c = await ctx();
        const salt = randomU256();
        const exec = await c.router.getGetExecutor(c.alice.address, salt);
        // carol's wallet refuses a set_key signed by mallory (E_SIG): the call bounces back to the executor
        const call = c.setKeyCall(c.carol, c.cw.address, exec, c.mallory);
        const { ref, body } = await c.relayCall(c.alice, c.cw.address, call, salt);
        const r = await c.send(body);
        expect(r.transactions).toHaveTransaction({ from: exec, to: c.cw.address, success: false, exitCode: E.sig });
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n);
        expect(await c.relayerBalance()).toBe(0n);
        expect(await c.routerBalance()).toBe(0n);
        expect(c.paid(r.transactions)).toHaveLength(0);
        expect(await c.router.getGetPending(c.alice.address, ref)).toBeNull();
        // the relayer's TON comes back on the refund's excess
        expect(r.transactions).toHaveTransaction({ to: c.relayer.address, op: 0xd53276db });
        console.log('relay-fee refund', JSON.stringify({ txs: r.transactions.length, fees: r.transactions.reduce((s, t) => s + t.totalFees.coins, 0n).toString() }));
    });

    it('refund when the target does not exist: the call to an empty account bounces (rule 5)', async () => {
        const c = await ctx();
        const ghost = Address.parse('0:' + '77'.repeat(32));
        const salt = randomU256();
        const { ref, body } = await c.relayCall(c.alice, ghost, beginCell().storeUint(0, 32).endCell(), salt);
        const r = await c.send(body);
        expect(r.transactions).toHaveTransaction({ to: ghost, success: false });
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n);
        expect(await c.relayerBalance()).toBe(0n);
        expect(await c.router.getGetPending(c.alice.address, ref)).toBeNull();
    });

    it('refund by RelayRefund after deadline, refused before; permissionless', async () => {
        const c = await ctx();
        // a target that accepts the call and swallows the probe: no outcome ever comes back
        const sink = await c.bc.treasury('sink');
        const salt = randomU256();
        const { ref, body } = await c.relayCall(c.alice, sink.address, beginCell().storeUint(0, 32).endCell(), salt);
        await c.send(body);
        expect(await c.router.getGetEscrowState(escrowKey(c.alice.address, ref))).toBe(2n);
        expect(await c.routerBalance()).toBe(FEE);
        const deadline = Number(body.deadline);
        c.bc.now = deadline - 1;
        const anyone = await c.bc.treasury('anyone');
        expect((await c.refund(c.alice.address, ref, anyone)).transactions).toHaveTransaction({ to: c.router.address, success: false, exitCode: E.early });
        c.bc.now = deadline;
        const r = await c.refund(c.alice.address, ref, anyone);
        expect(r.transactions).toHaveTransaction({ to: c.router.address, success: true });
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n);
        expect(await c.relayerBalance()).toBe(0n);
        expect(await c.routerBalance()).toBe(0n);
        expect((await c.refund(c.alice.address, ref, anyone)).transactions).toHaveTransaction({ to: c.router.address, exitCode: E.unknown });
    });

    it('release and refund are exclusive', async () => {
        const c = await ctx();
        // (a) released; a refund after that is refused, a forged failure report from the executor moves nothing
        const salt2 = randomU256();
        const exec2 = await c.router.getGetExecutor(c.alice.address, salt2);
        const rc = await c.relayCall(c.alice, c.cw.address, c.setKeyCall(c.carol, c.cw.address, exec2), salt2);
        await c.send(rc.body);
        expect(await c.relayerBalance()).toBe(FEE);
        c.bc.now = Number(rc.body.deadline);
        expect((await c.refund(c.alice.address, rc.ref)).transactions).toHaveTransaction({ to: c.router.address, exitCode: E.unknown });
        const forged = beginCell().store(storeRelayOutcome({ $$type: 'RelayOutcome', from: c.alice.address, ref: rc.ref, ok: false })).endCell();
        await c.bc.sendMessage(internal({ from: exec2, to: c.router.address, value: toNano('0.1'), bounce: false, body: forged }));
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n - FEE);
        expect(await c.relayerBalance()).toBe(FEE);
        expect(await c.routerBalance()).toBe(0n);
        // (b) no outcome, refund after deadline; a late success from the real executor then pays nothing
        const sink = await c.bc.treasury('sink');
        const salt = randomU256();
        const exec = await c.router.getGetExecutor(c.alice.address, salt);
        const { ref, body } = await c.relayCall(c.alice, sink.address, beginCell().storeUint(0, 32).endCell(), salt, { over: { validUntil: c.bc.now! + 1200 } });
        const r0 = await c.send(body);
        const probe = r0.transactions.flatMap((t) => t.outMessages.values()).find((m) => m.info.type === 'internal' && m.info.src.equals(exec) && m.body.beginParse().preloadUint(32) === 0x5b0a1d32)!;
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n - 2n * FEE);
        c.bc.now = Number(body.deadline);
        await c.refund(c.alice.address, ref);
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n - FEE);
        const bounced = beginCell().storeUint(0xffffffff, 32).storeSlice(probe.body.beginParse()).endCell();
        const late = await c.bc.sendMessage(internal({ from: sink.address, to: exec, value: toNano('0.05'), bounce: false, bounced: true, body: bounced }));
        expect(late.transactions).toHaveTransaction({ from: exec, to: c.router.address, success: true }); // the report arrives…
        expect(c.paid(late.transactions)).toHaveLength(0); // …and pays nothing
        expect(await c.relayerBalance()).toBe(FEE);
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n - FEE);
        expect(await c.routerBalance()).toBe(0n);
    });

    it('second RelayCall for a pending (payer, ref) refused; another payer on the same target is not blocked', async () => {
        const c = await ctx();
        const sink = await c.bc.treasury('sink');
        const call = beginCell().storeUint(0, 32).endCell();
        const salt = randomU256();
        const first = await c.relayCall(c.alice, sink.address, call, salt);
        await c.send(first.body);
        const again = await c.send((await c.relayCall(c.alice, sink.address, call, salt)).body);
        expect(again.transactions).toHaveTransaction({ to: c.router.address, success: false, exitCode: E.pending });
        // the same target, the same call and salt, another payer: its own escrow
        const other = await c.send((await c.relayCall(c.mallory, sink.address, call, salt)).body);
        expect(other.transactions).toHaveTransaction({ to: c.router.address, success: true });
        expect(await c.routerBalance()).toBe(2n * FEE);
    });

    it("an attacker's minimal pre-burn of the victim's ref does not block the victim (per payer)", async () => {
        const c = await ctx();
        // an idempotent SCaaS target: the DEX's empty-body top-up runs every time, and the DEX bounces the probe
        const { Dictionary } = require('@ton/core');
        const dex = c.bc.openContract(await ScaasDex.fromInit(c.admin.address, 0n, Dictionary.empty(), Dictionary.empty(), Dictionary.empty(), Dictionary.empty()));
        await dex.send(c.admin.getSender(), { value: toNano('1') }, null);
        const call = new Cell();
        const salt = randomU256();
        // mallory copies alice's (target, call, salt) and pays 1 from her own wallet first
        const pre = await c.relayCall(c.mallory, dex.address, call, salt, { amount: 1n });
        expect((await c.send(pre.body)).transactions).toHaveTransaction({ from: await c.router.getGetExecutor(c.mallory.address, salt), to: dex.address, success: true });
        expect(await c.relayerBalance()).toBe(1n);
        const victim = await c.relayCall(c.alice, dex.address, call, salt);
        expect(victim.ref).toBe(pre.ref);
        const r = await c.send(victim.body);
        expect(r.transactions).toHaveTransaction({ from: await c.router.getGetExecutor(c.alice.address, salt), to: dex.address, success: true });
        expect(await c.relayerBalance()).toBe(1n + FEE);
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n - FEE);
        expect(await c.balanceOf(c.token, c.mallory.address)).toBe(999n);
        expect(await c.routerBalance()).toBe(0n);
    });

    it('payment bounce clears pending', async () => {
        const c = await ctx();
        const call = beginCell().storeUint(0, 32).endCell();
        const target = Address.parse('0:' + '77'.repeat(32));
        const salt = randomU256();
        // signed by mallory's key: alice's wallet refuses it (E_SIG) and the SignedOp bounces to the router
        const bad = await c.relayCall(c.alice, target, call, salt, { signer: c.mallory });
        const r = await c.send(bad.body);
        expect(r.transactions).toHaveTransaction({ from: c.router.address, to: c.aw.address, success: false, exitCode: E.sig });
        expect(await c.router.getGetPending(c.alice.address, bad.ref)).toBeNull();
        expect(r.transactions).toHaveTransaction({ from: c.router.address, to: c.relayer.address }); // its TON goes back
        // the same (payer, ref) can be relayed again
        const good = await c.relayCall(c.alice, target, call, salt);
        expect((await c.send(good.body)).transactions).toHaveTransaction({ from: c.router.address, to: c.aw.address, success: true });
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n); // the ghost target bounced: refunded
    });

    it('ton router bound pay refused direct', async () => {
        const c = await ctx();
        const { sp } = await c.relayCall(c.alice, c.cw.address, new Cell(), randomU256());
        const body = { ...sp.body, responseDestination: c.relayer.address };
        for (const via of [c.relayer, await c.bc.treasury('mallory')]) {
            expect((await c.aw.send(via.getSender(), { value: toNano('0.15') }, body)).transactions)
                .toHaveTransaction({ to: c.aw.address, success: false, exitCode: E.relayer });
        }
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n);
    });

    it('call that is a SignedOp naming the router refused', async () => {
        const c = await ctx();
        // mallory's own router-bound payment (relayer = router) as the call: the router never sends it
        const inner = await c.relayCall(c.mallory, c.mw.address, new Cell(), randomU256());
        const call = beginCell().store(storeSignedOp({ ...inner.sp.body, responseDestination: c.router.address })).endCell();
        const r = await c.send((await c.relayCall(c.alice, c.mw.address, call, randomU256())).body);
        expect(r.transactions).toHaveTransaction({ to: c.router.address, success: false, exitCode: E.relayer });
        expect(await c.balanceOf(c.token, c.mallory.address)).toBe(1000n);
    });

    it('notification from a foreign jetton wallet ignored; a stray payment is handed back', async () => {
        const c = await ctx();
        const salt = randomU256();
        const rc = await c.relayCall(c.alice, Address.parse('0:' + '77'.repeat(32)), new Cell(), salt);
        // stop after the router's own transaction: the payment is still in flight (the entry is unfunded)
        const iter = await c.bc.sendMessageIter(internal({ from: c.relayer.address, to: c.router.address, value: await c.value(), body: beginCell().store(storeRelayCall(rc.body)).endCell() }), { allowParallel: true });
        const first = await iter.next();
        expect((first.value as any).description.computePhase.success).toBe(true);
        const key = escrowKey(c.alice.address, rc.ref);
        expect(await c.router.getGetEscrowState(key)).toBe(1n);
        // a real SCaaS-code wallet of another master, owned by the router, claims alice paid the ref
        const other = await c.newToken('B');
        const foreign = await c.walletOf(other, c.router.address);
        const note = beginCell().store(storeJettonNotification({ $$type: 'JettonNotification', queryId: 0n, amount: FEE, sender: c.alice.address,
            forwardPayload: beginCell().storeBit(true).storeRef(beginCell().storeUint(0x626d7074, 32).storeUint(rc.ref, 256).endCell()).asSlice() })).endCell();
        const r = await c.bc.sendMessage(internal({ from: foreign.address, to: c.router.address, value: toNano('0.6'), bounce: false, body: note }));
        expect(r.transactions).not.toHaveTransaction({ from: c.router.address, to: await c.router.getGetExecutor(c.alice.address, salt) });
        expect(await c.router.getGetEscrowState(key)).toBe(1n);
        // a plain transfer into the router (with a notification) goes straight back to its sender
        await c.mint(other, c.carol.address, 10n);
        const cb = await c.walletOf(other, c.carol.address);
        const sent = await c.bc.sendMessage(internal({ from: c.carol.address, to: cb.address, value: toNano('0.5'), body: beginCell().storeUint(0x0f8a7ea5, 32).storeUint(0, 64).storeCoins(4n)
            .storeAddress(c.router.address).storeAddress(c.carol.address).storeBit(false).storeCoins(toNano('0.1')).storeBit(false).endCell() }));
        expect(sent.transactions).toHaveTransaction({ from: c.router.address, to: foreign.address, success: true });
        expect(await c.balanceOf(other, c.carol.address)).toBe(10n);
        expect(await c.balanceOf(other, c.router.address)).toBe(0n);
        // the unfunded entry is cleared after its deadline (nothing to refund)
        c.bc.now = Number(rc.body.deadline);
        expect((await c.refund(c.alice.address, rc.ref)).transactions).toHaveTransaction({ to: c.router.address, success: true });
        expect(await c.router.getGetEscrowState(key)).toBe(0n);
    });

    it('shape, deadline and value refusals (exact exit codes)', async () => {
        const c = await ctx();
        const call = new Cell();
        const t = c.cw.address;
        const fail = async (body: any, code: number, v?: bigint) =>
            expect((await c.send(body, c.relayer, v)).transactions).toHaveTransaction({ to: c.router.address, success: false, exitCode: code });
        const salt = randomU256();
        const ok = await c.relayCall(c.alice, t, call, salt);
        await fail({ ...ok.body, salt: salt + 1n }, E.shape); // ref recomputed from the actual call and salt
        await fail({ ...ok.body, call: beginCell().storeUint(1, 1).endCell() }, E.shape);
        await fail((await c.relayCall(c.alice, t, call, salt, { over: { lane: randomU256() } })).body, E.shape);
        await fail((await c.relayCall(c.alice, t, call, salt, { over: { nonce: 1n } })).body, E.shape);
        await fail((await c.relayCall(c.alice, t, call, salt, { over: { relayer: c.relayer.address } })).body, E.shape);
        await fail((await c.relayCall(c.alice, t, call, salt, { over: { to: c.relayer.address } })).body, E.shape);
        await fail((await c.relayCall(c.alice, t, call, salt, { over: { op: OP.trade } })).body, E.shape);
        await fail((await c.relayCall(c.alice, t, call, salt, { amount: 0n })).body, E.shape);
        await fail({ ...ok.body, payWallet: c.cw.address }, E.shape);
        await fail((await c.relayCall(c.alice, c.router.address, call, salt)).body, E.shape); // the router is never a target
        await fail({ ...ok.body, deadline: BigInt(c.bc.now!) }, E.deadline);
        await fail({ ...ok.body, deadline: BigInt(c.bc.now! + RELAY_TIMEOUT + 1) }, E.deadline);
        await fail(ok.body, E.value, (await c.value()) - 1n);
        // the probe opcode is never a call (its bounce is the success signal)
        await fail((await c.relayCall(c.alice, t, beginCell().store(storeRelayProbe({ $$type: 'RelayProbe', queryId: 1n })).endCell(), salt)).body, E.shape);
        expect((await c.send({ ...ok.body, deadline: BigInt(c.bc.now! + RELAY_TIMEOUT) })).transactions).toHaveTransaction({ to: c.router.address, success: true });
    });

    it('relay ref vectors: every ref of the call is hashed, and the salt and target', async () => {
        const c = await ctx();
        const t = c.cw.address;
        const deep = (x: number) => beginCell().storeUint(7, 8).storeRef(beginCell().storeRef(beginCell().endCell()).storeRef(beginCell().storeUint(x, 8).endCell()).endCell()).endCell();
        const base = await c.router.getGetRelayRef(t, deep(1), 5n);
        expect(await c.router.getGetRelayRef(t, deep(2), 5n)).not.toBe(base); // a change in a second ref, two levels down
        expect(await c.router.getGetRelayRef(t, deep(1), 6n)).not.toBe(base);
        expect(await c.router.getGetRelayRef(c.aw.address, deep(1), 5n)).not.toBe(base);
        // the pinned vector (vectors.spec.ts writes it; ton.rs recomputes it with keccak)
        const v = JSON.parse(require('fs').readFileSync(require('path').join(__dirname, '..', 'vectors', 'ton-vectors.json'), 'utf8')).relay_fee;
        const call = Cell.fromBoc(Buffer.from(v.call_boc, 'hex'))[0];
        expect('0x' + (await c.router.getGetRelayRef(Address.parse(v.target), call, BigInt(v.salt))).toString(16).padStart(64, '0')).toBe(v.ref);
        expect('0x' + (escrowKey(Address.parse(v.from), BigInt(v.ref))).toString(16).padStart(64, '0')).toBe(v.escrow_key);
    });
});

/// `escrowKey(from, ref)` = the hash of the cell `from:MsgAddress ref:uint256` (relayfee.tact).
function escrowKey(from: Address, ref: bigint) {
    return BigInt('0x' + beginCell().storeAddress(from).storeUint(ref, 256).endCell().hash().toString('hex'));
}
