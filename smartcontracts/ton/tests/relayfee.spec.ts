// CTR-MTX-27 on TON (metatx-split T16, fix 1): the relay-fee escrow router (spec §7.2 TON row). Release only on a
// positive acknowledgment from a known SCaaS target.
import { Address, beginCell, Cell, Dictionary, toNano } from '@ton/core';
import { internal } from '@ton/sandbox';
import '@ton/test-utils';
import { ScaasJettonWallet, storeSignedOp } from '../build/jetton/jetton_ScaasJettonWallet';
import { ScaasDex } from '../build/dex/dex_ScaasDex';
import { RelayExecutor } from '../build/relayfee/relayfee_RelayExecutor';
import {
    ScaasRelayFee, loadRelayFeePaid, loadRelayFeeRefunded, loadRelayOutcome, storeJettonNotification, storeRelayAck, storeRelayCall,
    storeRelayExec, storeRelayOutcome, storeRelayProbe,
} from '../build/relayfee/relayfee_ScaasRelayFee';
import { ActFail } from '../build/testkit/testkit_ActFail';
import { Mandate } from '../build/mandate/mandate_Mandate';
import { DOMAIN, setup, signedPay, Subject } from './fixture';
import { metaOpCell, MetaOpFields, OP, randomU256, stateInitCell, subject, tonConnectAuth } from './helpers';

const E = { relayer: 707, sig: 708, value: 714, shape: 741, pending: 742, deadline: 743, unknown: 744, early: 745 };
const RELAY_TIMEOUT = 3600;
const FEE = 25n;
const OPS = { ack: 0x5b0a1d35, probe: 0x5b0a1d32, outcome: 0x5b0a1d34, paid: 0x9b1c0d05, refunded: 0x9b1c0d06 };

const opOf = (c?: Cell) => (c && c.beginParse().remainingBits >= 32 ? c.beginParse().preloadUint(32) : -1);

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
    /// The StateInit every party derives for `owner`'s wallet of the token (its address is the wallet's).
    const walletInit = async (owner: Address) =>
        si((await ScaasJettonWallet.fromInit(owner, token.address, 0n, 0n, null, Dictionary.empty(), Dictionary.empty(), 0n, 0n, 0n)).init!);

    /// A served fee-less entry: `s`'s signed op (`set_key` clearing the passkey, or `revoke`) on its own wallet `w`,
    /// relayer open, its excess to `response` (the executor). `signer` signs (another key = a call the wallet refuses).
    function signedCall(s: Subject, w: Address, response: Address, o: { signer?: Subject; op?: number; relayer?: Address | null } = {}) {
        const op = metaOpCell({ network: f.network, op: o.op ?? OP.set_key, amount: 0n, nonce: 0n, validUntil: 1_800_000_600, contract: w,
            from: s.address, to: s.address, relayer: o.relayer ?? null, payRef: 0n, lane: randomU256(), extra: 0n });
        const auth = tonConnectAuth((o.signer ?? s).kp, s.address, 1_800_000_000, DOMAIN, op);
        return beginCell().store(storeSignedOp({ $$type: 'SignedOp', op, auth, params: null, stateInit: s.stateInit, responseDestination: response, forwardTon: 0n, matchWith: 0n })).endCell();
    }

    /// The payer's router-bound payment for (target, call, salt) and the RelayCall the relayer sends.
    async function relayCall(payer: Subject, targetInit: Init, call: Cell, salt: bigint,
                             o: { amount?: bigint; deadline?: number; over?: Partial<MetaOpFields>; signer?: Subject; target?: Address } = {}) {
        const w = await f.walletOf(token, payer.address);
        const target = o.target ?? addrOf(targetInit);
        const ref = await router.getGetRelayRef(target, call, salt);
        const fields = { contract: w.address, to: router.address, relayer: router.address, amount: o.amount ?? FEE, network: f.network,
            payRef: ref, lane: await w.getGetPayLane(ref), ...o.over };
        const sp = signedPay(o.signer ?? payer, { ...fields, from: payer.address }, { responseDestination: router.address });
        return {
            ref, sp, body: {
                $$type: 'RelayCall' as const, target, targetInit, call, salt, payWallet: w.address, payOp: sp.op, payAuth: sp.body.auth,
                payStateInit: payer.stateInit, master: token.address, deadline: BigInt(o.deadline ?? f.bc.now! + 600),
            },
        };
    }
    const cellOf = (body: any) => beginCell().store(storeRelayCall(body)).endCell();
    const value = (body: any) => router.getGetRelayValue(cellOf(body));
    const send = async (body: any, via = f.relayer, v?: bigint) => router.send(via.getSender(), { value: v ?? (await value(body)) }, body);
    /// Run a RelayCall only until `stop` (a transaction) has run: the rest of its messages are dropped (still in flight).
    async function sendUntil(body: any, stop: (t: any) => boolean) {
        const iter = await f.bc.sendMessageIter(internal({ from: f.relayer.address, to: router.address, value: await value(body), body: cellOf(body) }), { allowParallel: true });
        const seen: any[] = [];
        for (;;) {
            const n = await iter.next();
            if (n.done) return seen;
            seen.push(n.value);
            if (stop(n.value)) return seen;
        }
    }
    const refund = async (from: Address, ref: bigint, via = f.relayer, v?: bigint) =>
        router.send(via.getSender(), { value: v ?? (await router.getGetRefundValue()) }, { $$type: 'RelayRefund', from, ref });
    const ext = (txs: any[], op: number) => txs.flatMap((t) => t.outMessages.values().filter((m: any) => m.info.type === 'external-out' && opOf(m.body) === op));
    const paid = (txs: any[]) => ext(txs, OPS.paid).map((m: any) => loadRelayFeePaid(m.body.beginParse()));
    const refunded = (txs: any[]) => ext(txs, OPS.refunded).map((m: any) => loadRelayFeeRefunded(m.body.beginParse()));
    const state = (from: Address, ref: bigint) => router.getGetEscrowState(escrowKey(from, ref));
    return { ...f, token, alice, carol, mallory, router, aw, cw, mw, walletInit, signedCall, relayCall, cellOf, value, send, sendUntil, refund, paid, refunded, state, relayerBalance, routerBalance };
}

type Init = { $$type: 'StateInit'; code: Cell; data: Cell };

/// A StateInit as the Tact message field wants it.
function si(i: { code?: Cell | null; data?: Cell | null }): Init {
    return { $$type: 'StateInit', code: i.code!, data: i.data! };
}

function addrOf(init: Init) {
    return new Address(0, stateInitCell({ code: init.code, data: init.data }).hash());
}

/// `escrowKey(from, ref)` = the hash of the cell `from:MsgAddress ref:uint256` (relayfee.tact).
function escrowKey(from: Address, ref: bigint) {
    return BigInt('0x' + beginCell().storeAddress(from).storeUint(ref, 256).endCell().hash().toString('hex'));
}

describe('relay-fee escrow router (CTR-MTX-27, TON)', () => {
    it("release on the served entry's acknowledgment, before the probe's bounce", async () => {
        const c = await ctx();
        const salt = randomU256();
        const exec = await c.router.getGetExecutor(c.alice.address, salt);
        const call = c.signedCall(c.carol, c.cw.address, exec);
        const { ref, body } = await c.relayCall(c.alice, await c.walletInit(c.carol.address), call, salt);
        const ton0 = (await c.bc.getContract(c.router.address)).balance;
        const r = await c.send(body);
        const ton1 = (await c.bc.getContract(c.router.address)).balance;
        // the target sees the executor, never the router (rule 4 / R18), and acknowledges it
        expect(r.transactions).toHaveTransaction({ from: exec, to: c.cw.address, success: true });
        expect(r.transactions).toHaveTransaction({ from: c.cw.address, to: exec, op: OPS.ack, success: true });
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
        expect(c.refunded(r.transactions)).toHaveLength(0);
        // the router keeps this escrow's rent, never less than it had (minor 3)
        console.log('router TON', (ton1 - ton0).toString());
        expect(ton1 >= ton0 && ton1 - ton0 < toNano('0.01')).toBe(true);
        const fees = r.transactions.reduce((s, t) => s + t.totalFees.coins, 0n);
        const gas = r.transactions.map((t: any) => ({ to: t.inMessage?.info.dest?.toString().slice(-6), op: opOf(t.inMessage?.body).toString(16), gas: t.description.computePhase?.gasUsed?.toString() }));
        console.log('relay-fee release', JSON.stringify({ txs: r.transactions.length, fees: fees.toString(), value: (await c.value(body)).toString(), routerTon: (ton1 - ton0).toString(), gas }));
    });

    it("the Mandate's owner revoke is the other served entry: released on its ack", async () => {
        const c = await ctx();
        const ms = { $$type: 'MandateState' as const, revoked: false, periodStart: 0n, spent: 0n, balance: 0n,
            terms: { $$type: 'MandateTerms' as const, perPayment: 1n, perPeriod: 1n, periodSeconds: 1n, expiresAt: BigInt(c.bc.now! + 86400) },
            ownerPubkey: BigInt('0x' + c.carol.kp.publicKey.toString('hex')), delegatePubkey: 1n };
        const mandate = c.bc.openContract(await Mandate.fromInit(c.carol.address, c.token.address, ms, Dictionary.empty(), Dictionary.empty(), Dictionary.empty(), 0n, Dictionary.empty()));
        await mandate.send(c.admin.getSender(), { value: toNano('0.1') }, null);
        const salt = randomU256();
        const exec = await c.router.getGetExecutor(c.alice.address, salt);
        const call = c.signedCall(c.carol, mandate.address, exec, { op: OP.revoke });
        const r = await c.send((await c.relayCall(c.alice, si(mandate.init!), call, salt)).body);
        expect(r.transactions).toHaveTransaction({ from: exec, to: mandate.address, success: true });
        expect(r.transactions).toHaveTransaction({ from: mandate.address, to: exec, op: OPS.ack });
        expect((await mandate.getGetState()).revoked).toBe(true);
        expect(await c.relayerBalance()).toBe(FEE);
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n - FEE);
    });

    it('refund on call bounce: payer refunded, nothing to the relayer', async () => {
        const c = await ctx();
        const salt = randomU256();
        const exec = await c.router.getGetExecutor(c.alice.address, salt);
        // carol's wallet refuses a set_key signed by mallory (E_SIG): the call bounces back to the executor
        const call = c.signedCall(c.carol, c.cw.address, exec, { signer: c.mallory });
        const { ref, body } = await c.relayCall(c.alice, await c.walletInit(c.carol.address), call, salt);
        const r = await c.send(body);
        expect(r.transactions).toHaveTransaction({ from: exec, to: c.cw.address, success: false, exitCode: E.sig });
        expect(r.transactions).not.toHaveTransaction({ to: exec, op: OPS.ack });
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n);
        expect(await c.relayerBalance()).toBe(0n);
        expect(await c.routerBalance()).toBe(0n);
        expect(c.paid(r.transactions)).toHaveLength(0);
        expect(c.refunded(r.transactions).map((e) => [e.ref, e.payer.toString(), e.amount])).toEqual([[ref, c.alice.address.toString(), FEE]]);
        expect(await c.router.getGetPending(c.alice.address, ref)).toBeNull();
        expect(r.transactions).toHaveTransaction({ to: c.relayer.address, op: 0xd53276db }); // the relayer's TON comes back
        console.log('relay-fee refund', JSON.stringify({ txs: r.transactions.length, fees: r.transactions.reduce((s, t) => s + t.totalFees.coins, 0n).toString() }));
    });

    it('refund when the target does not exist: a served code at an address with no account bounces (rule 5)', async () => {
        const c = await ctx();
        const nobody = await subject(0x42);
        const init = await c.walletInit(nobody.address);
        const salt = randomU256();
        const call = c.signedCall(nobody, addrOf(init), await c.router.getGetExecutor(c.alice.address, salt));
        const { ref, body } = await c.relayCall(c.alice, init, call, salt);
        const r = await c.send(body);
        expect(r.transactions).toHaveTransaction({ to: addrOf(init), success: false });
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n);
        expect(await c.relayerBalance()).toBe(0n);
        expect(await c.router.getGetPending(c.alice.address, ref)).toBeNull();
    });

    it('executor: an action-phase failure sends no ack and is refunded; an ack is released; the start-value edge', async () => {
        const c = await ctx();
        const target = c.bc.openContract(await ActFail.fromInit(0n));
        await target.send(c.admin.getSender(), { value: toNano('1') }, null);
        // the router refuses a target outside its code set before any escrow
        const salt0 = randomU256();
        const actInit = si((await ActFail.fromInit(0n)).init!);
        const refused = await c.send((await c.relayCall(c.alice, actInit, c.signedCall(c.carol, target.address, await c.router.getGetExecutor(c.alice.address, salt0)), salt0)).body);
        expect(refused.transactions).toHaveTransaction({ to: c.router.address, success: false, exitCode: E.shape });
        // the executor alone (started as by the router): ActFail acks, then fails its action phase unless the call starts with 1
        const run = async (failing: boolean, delta = 0n) => {
            const salt = randomU256();
            const init = (await RelayExecutor.fromInit(c.router.address, c.alice.address, salt, 0n, null, 0n, 0n, false, false)).init!;
            const exec = addrOf(si(init));
            const call = beginCell().storeUint(failing ? 2 : 1, 32).storeRef(beginCell().storeUint(salt, 256).endCell()).endCell();
            const callMin = await c.router.getGetCallFloor();
            const start = await c.router.getGetExecStart(call, callMin); // the least TON it starts with, at the router's keep
            const body = beginCell().store(storeRelayExec({ $$type: 'RelayExec', ref: 7n, target: target.address, call, callMin, keep: await c.router.getGetExecKeep() })).endCell();
            const r = await c.bc.sendMessage(internal({ from: c.router.address, to: exec, value: start + delta, bounce: false, stateInit: init, body }));
            const out = r.transactions.flatMap((t) => t.outMessages.values()).find((m) => m.info.type === 'internal' && m.info.src.equals(exec) && opOf(m.body) === OPS.outcome);
            return { r, exec, outcome: out && loadRelayOutcome(out.body.beginParse()) };
        };
        const failed = await run(true);
        // compute ok, action phase failed: no message at all (no ack), no bounce of the call
        expect(failed.r.transactions).toHaveTransaction({ from: failed.exec, to: target.address, exitCode: 0, success: false, outMessagesCount: 0 });
        expect(failed.r.transactions).not.toHaveTransaction({ from: target.address, to: failed.exec, op: OPS.ack });
        expect(await target.getCounter()).toBe(0n); // the action failure rolled the state back
        expect(failed.outcome!.ok).toBe(false);
        const ok = await run(false);
        expect(ok.r.transactions).toHaveTransaction({ from: target.address, to: ok.exec, op: OPS.ack });
        expect(ok.outcome!.ok).toBe(true);
        // one nanoton below the start value: no call, a failure report (refund)
        const short = await run(false, -1n);
        expect(short.r.transactions).not.toHaveTransaction({ from: short.exec, to: target.address });
        expect(short.outcome!.ok).toBe(false);
    });

    it('refund by RelayRefund after deadline, refused before or below the settle TON; permissionless', async () => {
        const c = await ctx();
        const salt = randomU256();
        const exec = await c.router.getGetExecutor(c.alice.address, salt);
        const { ref, body } = await c.relayCall(c.alice, await c.walletInit(c.carol.address), c.signedCall(c.carol, c.cw.address, exec), salt);
        // the call and probe are sent, no outcome ever comes back (dropped in flight)
        await c.sendUntil(body, (t) => t.inMessage?.info.dest?.equals(exec));
        expect(await c.state(c.alice.address, ref)).toBe(2n);
        expect(await c.routerBalance()).toBe(FEE);
        const anyone = await c.bc.treasury('anyone');
        c.bc.now = Number(body.deadline) - 1;
        expect((await c.refund(c.alice.address, ref, anyone)).transactions).toHaveTransaction({ to: c.router.address, success: false, exitCode: E.early });
        c.bc.now = Number(body.deadline);
        const need = await c.router.getGetRefundValue();
        expect((await c.refund(c.alice.address, ref, anyone, need - 1n)).transactions).toHaveTransaction({ to: c.router.address, success: false, exitCode: E.value });
        const r = await c.refund(c.alice.address, ref, anyone, need);
        expect(r.transactions).toHaveTransaction({ to: c.router.address, success: true });
        expect(c.refunded(r.transactions)).toHaveLength(1);
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
        const rc = await c.relayCall(c.alice, await c.walletInit(c.carol.address), c.signedCall(c.carol, c.cw.address, exec2), salt2);
        await c.send(rc.body);
        expect(await c.relayerBalance()).toBe(FEE);
        c.bc.now = Number(rc.body.deadline);
        expect((await c.refund(c.alice.address, rc.ref)).transactions).toHaveTransaction({ to: c.router.address, exitCode: E.unknown });
        const forged = beginCell().store(storeRelayOutcome({ $$type: 'RelayOutcome', from: c.alice.address, ref: rc.ref, ok: false })).endCell();
        await c.bc.sendMessage(internal({ from: exec2, to: c.router.address, value: toNano('0.1'), bounce: false, body: forged }));
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n - FEE);
        expect(await c.relayerBalance()).toBe(FEE);
        // (b) funded, no outcome, refunded after the deadline; a late ack + probe bounce from the target pays nothing
        const salt = randomU256();
        const exec = await c.router.getGetExecutor(c.alice.address, salt);
        const call = c.signedCall(c.carol, c.cw.address, exec);
        const { ref, body } = await c.relayCall(c.alice, await c.walletInit(c.carol.address), call, salt, { over: { validUntil: c.bc.now! + 1200 } });
        const seen = await c.sendUntil(body, (t) => t.inMessage?.info.dest?.equals(exec));
        const probe = seen.flatMap((t) => t.outMessages.values()).find((m: any) => m.info.type === 'internal' && m.info.src.equals(exec) && opOf(m.body) === OPS.probe)!;
        c.bc.now = Number(body.deadline);
        await c.refund(c.alice.address, ref);
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n - FEE);
        const ack = beginCell().store(storeRelayAck({ $$type: 'RelayAck', digest: BigInt('0x' + call.refs[0].hash().toString('hex')) })).endCell();
        await c.bc.sendMessage(internal({ from: c.cw.address, to: exec, value: toNano('0.05'), bounce: false, body: ack }));
        const bounced = beginCell().storeUint(0xffffffff, 32).storeSlice(probe.body.beginParse()).endCell();
        const late = await c.bc.sendMessage(internal({ from: c.cw.address, to: exec, value: toNano('0.05'), bounce: false, bounced: true, body: bounced }));
        const report = late.transactions.flatMap((t) => t.outMessages.values()).find((m) => m.info.type === 'internal' && opOf(m.body) === OPS.outcome)!;
        expect(loadRelayOutcome(report.body.beginParse()).ok).toBe(true); // the executor reports the late success…
        expect(c.paid(late.transactions)).toHaveLength(0); // …and the router pays nothing
        expect(await c.relayerBalance()).toBe(FEE);
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n - FEE);
        expect(await c.routerBalance()).toBe(0n);
    });

    it('a settlement transfer that bounces restores the escrow; RelayRefund sends it again (important 3)', async () => {
        const c = await ctx();
        const salt = randomU256();
        const exec = await c.router.getGetExecutor(c.alice.address, salt);
        const { ref, body } = await c.relayCall(c.alice, await c.walletInit(c.carol.address), c.signedCall(c.carol, c.cw.address, exec), salt);
        await c.sendUntil(body, (t) => t.inMessage?.info.dest?.equals(exec));
        // a success report carrying too little TON: our wallet refuses the release transfer (E_VALUE) and it bounces
        const report = beginCell().store(storeRelayOutcome({ $$type: 'RelayOutcome', from: c.alice.address, ref, ok: true })).endCell();
        const r = await c.bc.sendMessage(internal({ from: exec, to: c.router.address, value: toNano('0.012'), bounce: false, body: report }));
        expect(r.transactions).toHaveTransaction({ to: await c.walletOf(c.token, c.router.address).then((w) => w.address), success: false, exitCode: E.value });
        expect(await c.state(c.alice.address, ref)).toBe(3n); // release owed
        expect(await c.relayerBalance()).toBe(0n);
        expect(await c.routerBalance()).toBe(FEE);
        // anyone settles it again, any time, as the release it was
        const again = await c.refund(c.alice.address, ref, await c.bc.treasury('anyone'));
        expect(c.paid(again.transactions)).toHaveLength(1);
        expect(await c.relayerBalance()).toBe(FEE);
        expect(await c.routerBalance()).toBe(0n);
        expect(await c.state(c.alice.address, ref)).toBe(0n);
    });

    it('second RelayCall for a pending (payer, ref) refused; another payer on the same target is not blocked', async () => {
        const c = await ctx();
        const salt = randomU256();
        const init = await c.walletInit(c.carol.address);
        const first = await c.relayCall(c.alice, init, c.signedCall(c.carol, c.cw.address, await c.router.getGetExecutor(c.alice.address, salt)), salt);
        await c.sendUntil(first.body, (t) => t.inMessage?.info.dest?.equals(c.router.address));
        expect(await c.state(c.alice.address, first.ref)).toBe(1n);
        const again = await c.send(first.body);
        expect(again.transactions).toHaveTransaction({ to: c.router.address, success: false, exitCode: E.pending });
        // another payer, the same target: its own escrow, settles
        const salt2 = randomU256();
        const other = await c.relayCall(c.mallory, init, c.signedCall(c.carol, c.cw.address, await c.router.getGetExecutor(c.mallory.address, salt2)), salt2);
        expect((await c.send(other.body)).transactions).toHaveTransaction({ to: c.router.address, success: true });
        expect(await c.relayerBalance()).toBe(FEE);
    });

    it("an attacker cannot pre-burn the victim's ref: the call names the victim's executor (per payer)", async () => {
        const c = await ctx();
        const salt = randomU256();
        const init = await c.walletInit(c.carol.address);
        const call = c.signedCall(c.carol, c.cw.address, await c.router.getGetExecutor(c.alice.address, salt));
        // mallory copies alice's (target, call, salt) and pays 1 from her own wallet first: refused before escrow
        const pre = await c.relayCall(c.mallory, init, call, salt, { amount: 1n });
        expect((await c.send(pre.body)).transactions).toHaveTransaction({ to: c.router.address, success: false, exitCode: E.shape });
        expect(await c.balanceOf(c.token, c.mallory.address)).toBe(1000n);
        const victim = await c.relayCall(c.alice, init, call, salt);
        expect(victim.ref).toBe(pre.ref);
        const r = await c.send(victim.body);
        expect(r.transactions).toHaveTransaction({ from: await c.router.getGetExecutor(c.alice.address, salt), to: c.cw.address, success: true });
        expect(await c.relayerBalance()).toBe(FEE);
        expect(await c.balanceOf(c.token, c.alice.address)).toBe(1000n - FEE);
        expect(await c.routerBalance()).toBe(0n);
    });

    it('payment bounce clears pending', async () => {
        const c = await ctx();
        const salt = randomU256();
        const init = await c.walletInit(c.carol.address);
        const call = c.signedCall(c.carol, c.cw.address, await c.router.getGetExecutor(c.alice.address, salt));
        // signed by mallory's key: alice's wallet refuses it (E_SIG) and the SignedOp bounces to the router
        const bad = await c.relayCall(c.alice, init, call, salt, { signer: c.mallory });
        const r = await c.send(bad.body);
        expect(r.transactions).toHaveTransaction({ from: c.router.address, to: c.aw.address, success: false, exitCode: E.sig });
        expect(await c.router.getGetPending(c.alice.address, bad.ref)).toBeNull();
        expect(c.refunded(r.transactions).map((e) => e.amount)).toEqual([0n]); // positive: nothing was escrowed
        expect(r.transactions).toHaveTransaction({ from: c.router.address, to: c.relayer.address }); // its TON goes back
        // the same (payer, ref) can be relayed again
        const good = await c.relayCall(c.alice, init, call, salt);
        expect((await c.send(good.body)).transactions).toHaveTransaction({ from: c.router.address, to: c.aw.address, success: true });
        expect(await c.relayerBalance()).toBe(FEE);
    });

    it('ton router bound pay refused direct', async () => {
        const c = await ctx();
        const { sp } = await c.relayCall(c.alice, await c.walletInit(c.carol.address), new Cell(), randomU256());
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
        const salt = randomU256();
        const inner = await c.relayCall(c.mallory, await c.walletInit(c.carol.address), new Cell(), randomU256());
        const call = beginCell().store(storeSignedOp({ ...inner.sp.body, responseDestination: await c.router.getGetExecutor(c.alice.address, salt) })).endCell();
        const r = await c.send((await c.relayCall(c.alice, await c.walletInit(c.mallory.address), call, salt)).body);
        expect(r.transactions).toHaveTransaction({ to: c.router.address, success: false, exitCode: E.relayer });
        expect(await c.balanceOf(c.token, c.mallory.address)).toBe(1000n);
    });

    it('notification from a foreign jetton wallet ignored; a stray payment is handed back', async () => {
        const c = await ctx();
        const salt = randomU256();
        const rc = await c.relayCall(c.alice, await c.walletInit(c.carol.address), c.signedCall(c.carol, c.cw.address, await c.router.getGetExecutor(c.alice.address, salt)), salt);
        // stop after the router's own transaction: the payment is still in flight (the entry is unfunded)
        await c.sendUntil(rc.body, (t) => t.inMessage?.info.dest?.equals(c.router.address));
        expect(await c.state(c.alice.address, rc.ref)).toBe(1n);
        // a real SCaaS-code wallet of another master, owned by the router, claims alice paid the ref
        const other = await c.newToken('B');
        const foreign = await c.walletOf(other, c.router.address);
        const note = beginCell().store(storeJettonNotification({ $$type: 'JettonNotification', queryId: 0n, amount: FEE, sender: c.alice.address,
            forwardPayload: beginCell().storeBit(true).storeRef(beginCell().storeUint(0x626d7074, 32).storeUint(rc.ref, 256).endCell()).asSlice() })).endCell();
        const r = await c.bc.sendMessage(internal({ from: foreign.address, to: c.router.address, value: toNano('0.6'), bounce: false, body: note }));
        expect(r.transactions).not.toHaveTransaction({ from: c.router.address, to: await c.router.getGetExecutor(c.alice.address, salt) });
        expect(await c.state(c.alice.address, rc.ref)).toBe(1n);
        // a plain transfer into the router (with a notification) goes straight back to its sender
        await c.mint(other, c.carol.address, 10n);
        const cb = await c.walletOf(other, c.carol.address);
        const sent = await c.bc.sendMessage(internal({ from: c.carol.address, to: cb.address, value: toNano('0.5'), body: beginCell().storeUint(0x0f8a7ea5, 32).storeUint(0, 64).storeCoins(4n)
            .storeAddress(c.router.address).storeAddress(c.carol.address).storeBit(false).storeCoins(toNano('0.1')).storeBit(false).endCell() }));
        expect(sent.transactions).toHaveTransaction({ from: c.router.address, to: foreign.address, success: true });
        expect(await c.balanceOf(other, c.carol.address)).toBe(10n);
        expect(await c.balanceOf(other, c.router.address)).toBe(0n);
        // the unfunded entry is dropped after its deadline (nothing to refund), with a positive event
        c.bc.now = Number(rc.body.deadline);
        const drop = await c.refund(c.alice.address, rc.ref);
        expect(drop.transactions).toHaveTransaction({ to: c.router.address, success: true });
        expect(c.refunded(drop.transactions).map((e) => e.amount)).toEqual([0n]);
        expect(await c.state(c.alice.address, rc.ref)).toBe(0n);
    });

    it('target, shape, deadline and value refusals (exact exit codes)', async () => {
        const c = await ctx();
        const fail = async (body: any, code: number, v?: bigint) =>
            expect((await c.send(body, c.relayer, v)).transactions).toHaveTransaction({ to: c.router.address, success: false, exitCode: code });
        const salt = randomU256();
        const exec = await c.router.getGetExecutor(c.alice.address, salt);
        const init = await c.walletInit(c.carol.address);
        const call = c.signedCall(c.carol, c.cw.address, exec);
        const ok = await c.relayCall(c.alice, init, call, salt);
        await fail({ ...ok.body, salt: salt + 1n }, E.shape); // ref recomputed from the actual call and salt
        await fail({ ...ok.body, call: beginCell().storeUint(1, 1).endCell() }, E.shape);
        await fail((await c.relayCall(c.alice, init, call, salt, { over: { lane: randomU256() } })).body, E.shape);
        await fail((await c.relayCall(c.alice, init, call, salt, { over: { nonce: 1n } })).body, E.shape);
        await fail((await c.relayCall(c.alice, init, call, salt, { over: { relayer: c.relayer.address } })).body, E.shape);
        await fail((await c.relayCall(c.alice, init, call, salt, { over: { to: c.relayer.address } })).body, E.shape);
        await fail((await c.relayCall(c.alice, init, call, salt, { over: { op: OP.trade } })).body, E.shape);
        await fail((await c.relayCall(c.alice, init, call, salt, { amount: 0n })).body, E.shape);
        await fail({ ...ok.body, payWallet: c.cw.address }, E.shape);
        // the target: its StateInit must derive its address, and its code be one of ours
        await fail((await c.relayCall(c.alice, init, call, salt, { target: c.aw.address })).body, E.shape);
        const dex = si((await ScaasDex.fromInit(c.admin.address, 0n, Dictionary.empty(), Dictionary.empty(), Dictionary.empty(), Dictionary.empty())).init!);
        await fail((await c.relayCall(c.alice, dex, call, salt)).body, E.shape);
        await fail((await c.relayCall(c.alice, si(c.router.init!), call, salt)).body, E.shape); // the router itself
        // the call: a served entry (not a pay), its excess to the payer's executor, never the probe
        await fail((await c.relayCall(c.alice, init, c.signedCall(c.carol, c.cw.address, exec, { op: OP.pay }), salt)).body, E.shape);
        await fail((await c.relayCall(c.alice, init, c.signedCall(c.carol, c.cw.address, c.relayer.address), salt)).body, E.shape);
        await fail((await c.relayCall(c.alice, init, beginCell().store(storeRelayProbe({ $$type: 'RelayProbe', queryId: 1n })).endCell(), salt)).body, E.shape);
        await fail({ ...ok.body, deadline: BigInt(c.bc.now!) }, E.deadline);
        await fail({ ...ok.body, deadline: BigInt(c.bc.now! + RELAY_TIMEOUT + 1) }, E.deadline);
        await fail(ok.body, E.value, (await c.value(ok.body)) - 1n);
        expect((await c.send({ ...ok.body, deadline: BigInt(c.bc.now! + RELAY_TIMEOUT) })).transactions).toHaveTransaction({ to: c.router.address, success: true });
        // the Mandate's code is the other served one
        const codes = await c.router.getGetCodes();
        expect(BigInt('0x' + init.code.hash().toString('hex'))).toBe(codes.wallet);
        expect(codes.mandate).not.toBe(codes.wallet);
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
        expect('0x' + escrowKey(Address.parse(v.from), BigInt(v.ref)).toString(16).padStart(64, '0')).toBe(v.escrow_key);
    });
});
