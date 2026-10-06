import { Address, Dictionary, toNano } from '@ton/core';
import '@ton/test-utils';
import { ScaasDex } from '../build/dex/dex_ScaasDex';
import { setup, signedPay, Subject } from './fixture';
import { OP, randomU256, subject, tradeParamsCell } from './helpers';

async function dexSetup(opts: { maker?: number; taker?: number; enabled?: boolean } = {}) {
    const f = await setup();
    const A = await f.newToken('A');
    const B = await f.newToken('B');
    const alice = await subject(1);
    const bob = await subject(2);
    const dex = f.bc.openContract(await ScaasDex.fromInit(f.admin.address, 0n, Dictionary.empty(), Dictionary.empty(), Dictionary.empty(), Dictionary.empty()));
    await dex.send(f.admin.getSender(), { value: toNano('1') }, null);
    await dex.send(f.admin.getSender(), { value: toNano('0.05') }, { $$type: 'SetMarket', a: A.address, b: B.address, enabled: opts.enabled ?? true, makerPpm: BigInt(opts.maker ?? 1000), takerPpm: BigInt(opts.taker ?? 2000) });
    await f.mint(A, alice.address, 1_000_000n);
    await f.mint(B, bob.address, 1_000_000n);
    const wA = await f.walletOf(A, alice.address);
    const wB = await f.walletOf(B, bob.address);
    /// A signed trade leg: `who` sells `amount` of `tin` for at least `minOut` of `tout`.
    const leg = (who: Subject, wallet: Address, tin: Address, tout: Address, amount: bigint, minOut: bigint, o: { maxFeePpm?: number; counterparty?: Address | null; matchWith?: bigint; lane?: bigint; validUntil?: number; forwardTon?: bigint } = {}) => {
        // the payer signs the forward TON floor (review H2); the relayer sends exactly that unless a test overrides it
        const params = tradeParamsCell({ tokenIn: tin, tokenOut: tout, minOut, counterparty: o.counterparty ?? null, maxFeePpm: o.maxFeePpm ?? 3000, forwardTon: toNano('0.2') });
        return signedPay(who, { contract: wallet, to: dex.address, amount, network: f.network, op: OP.trade, extra: BigInt('0x' + params.hash().toString('hex')), lane: o.lane ?? randomU256(), validUntil: o.validUntil ?? f.bc.now! + 600 }, { params, matchWith: o.matchWith ?? 0n, forwardTon: o.forwardTon ?? toNano('0.2'), responseDestination: f.relayer.address });
    };
    const send = (wallet: any, body: any) => wallet.send(f.relayer.getSender(), { value: toNano('0.35') }, body);
    const h = (sp: { digest: Buffer }) => BigInt('0x' + sp.digest.toString('hex'));
    const tonOf = async (a: Address) => (await f.bc.getContract(a)).balance;
    return { ...f, A, B, alice, bob, dex, wA, wB, leg, send, h, tonOf };
}

describe('ScaasDex escrow (R35 on TON, R10-7)', () => {
    it('two signed legs settle with maker/taker fees; fees accrue; nobody needs an allowance', async () => {
        const { A, B, alice, bob, dex, wA, wB, leg, send, h, balanceOf } = await dexSetup();
        const a = leg(alice, wA.address, A.address, B.address, 1_000_000n, 990_000n);
        await send(wA, a.body);
        expect((await dex.getGetOrder(h(a)))!.amountIn).toBe(1_000_000n);
        const b = leg(bob, wB.address, B.address, A.address, 1_000_000n, 990_000n, { matchWith: h(a) });
        await send(wB, b.body);
        expect(await balanceOf(B, alice.address)).toBe(999_000n); // maker 0.1 %
        expect(await balanceOf(A, bob.address)).toBe(998_000n);   // taker 0.2 %
        expect(await dex.getGetFees(B.address)).toBe(1000n);
        expect(await dex.getGetFees(A.address)).toBe(2000n);
        expect(await dex.getGetOrder(h(a))).toBeNull();
        expect(await dex.getGetOrder(h(b))).toBeNull();
    });

    it('price limit, fee cap and counterparty are enforced; Match is permissionless once valid', async () => {
        const { bc, A, B, alice, bob, dex, wA, wB, leg, send, h, balanceOf } = await dexSetup();
        const a = leg(alice, wA.address, A.address, B.address, 1_000_000n, 990_000n, { maxFeePpm: 500 }); // maker fee 1000 > 500
        await send(wA, a.body);
        const b = leg(bob, wB.address, B.address, A.address, 1_000_000n, 990_000n, { matchWith: h(a) });
        await send(wB, b.body);
        expect(await dex.getGetOrder(h(b))).not.toBeNull(); // hint failed, leg rests
        const stranger = await bc.treasury('stranger');
        const r = await dex.send(stranger.getSender(), { value: toNano('0.2') }, { $$type: 'Match', a: h(a), b: h(b) });
        expect(r.transactions).toHaveTransaction({ to: dex.address, success: false, exitCode: 731 });
        // refund both, then orders whose counterparty excludes the other side never match
        bc.now = bc.now! + 601;
        await dex.send(stranger.getSender(), { value: toNano('0.2') }, { $$type: 'Refund', orderHash: h(a) });
        await dex.send(stranger.getSender(), { value: toNano('0.2') }, { $$type: 'Refund', orderHash: h(b) });
        const a2 = leg(alice, wA.address, A.address, B.address, 1_000_000n, 990_000n, { counterparty: stranger.address });
        await send(wA, a2.body);
        const b2 = leg(bob, wB.address, B.address, A.address, 1_000_000n, 990_000n);
        await send(wB, b2.body);
        expect((await dex.send(stranger.getSender(), { value: toNano('0.2') }, { $$type: 'Match', a: h(a2), b: h(b2) })).transactions).toHaveTransaction({ to: dex.address, exitCode: 731 });
        expect(await balanceOf(A, bob.address)).toBe(0n);
    });

    it('two resting legs are matched by anyone with Match; price limit blocks a bad pair', async () => {
        const { bc, A, B, alice, bob, dex, wA, wB, leg, send, h, balanceOf } = await dexSetup();
        const a = leg(alice, wA.address, A.address, B.address, 500_000n, 499_000n);
        await send(wA, a.body);
        const tooGreedy = leg(bob, wB.address, B.address, A.address, 400_000n, 499_500n); // 500k - 0.2 % < 499.5k
        await send(wB, tooGreedy.body);
        const stranger = await bc.treasury('stranger');
        expect((await dex.send(stranger.getSender(), { value: toNano('0.2') }, { $$type: 'Match', a: h(a), b: h(tooGreedy) })).transactions).toHaveTransaction({ to: dex.address, exitCode: 731 });
        const fair = leg(bob, wB.address, B.address, A.address, 500_000n, 498_000n);
        await send(wB, fair.body);
        expect((await dex.send(stranger.getSender(), { value: toNano('0.2') }, { $$type: 'Match', a: h(a), b: h(fair) })).transactions).toHaveTransaction({ to: dex.address, success: true });
        expect(await balanceOf(B, alice.address)).toBe(499_500n);
        expect(await balanceOf(A, bob.address)).toBe(499_000n);
    });

    it('unmatched legs refund to their owner after expiry, by anyone; not before', async () => {
        const { bc, A, B, alice, bob, dex, wA, wB, leg, send, h, balanceOf } = await dexSetup();
        const a = leg(alice, wA.address, A.address, B.address, 400_000n, 1_000_000n);
        await send(wA, a.body);
        const b = leg(bob, wB.address, B.address, A.address, 300_000n, 500_000n, { matchWith: h(a) });
        await send(wB, b.body);
        expect(await balanceOf(A, alice.address)).toBe(600_000n);
        const stranger = await bc.treasury('stranger');
        expect((await dex.send(stranger.getSender(), { value: toNano('0.2') }, { $$type: 'Refund', orderHash: h(a) })).transactions).toHaveTransaction({ to: dex.address, exitCode: 733 });
        bc.now = bc.now! + 601;
        await dex.send(stranger.getSender(), { value: toNano('0.2') }, { $$type: 'Refund', orderHash: h(a) });
        await dex.send(stranger.getSender(), { value: toNano('0.2') }, { $$type: 'Refund', orderHash: h(b) });
        expect(await balanceOf(A, alice.address)).toBe(1_000_000n);
        expect(await balanceOf(B, bob.address)).toBe(1_000_000n);
        expect((await dex.send(stranger.getSender(), { value: toNano('0.2') }, { $$type: 'Refund', orderHash: h(a) })).transactions).toHaveTransaction({ to: dex.address, exitCode: 732 });
    });

    it('cancel by signed revoke: before sending, the order can never execute; after escrow, it is refunded', async () => {
        const { relayer, network, A, B, alice, dex, wA, leg, send, h, balanceOf } = await dexSetup();
        // before: revoke on the order's lane/nonce consumes it
        const lane = randomU256();
        const a = leg(alice, wA.address, A.address, B.address, 100n, 100n, { lane });
        const rv = signedPay(alice, { contract: wA.address, to: dex.address, amount: 0n, network, op: OP.revoke, lane, extra: h(a) }, { responseDestination: relayer.address });
        expect((await send(wA, rv.body)).transactions).toHaveTransaction({ to: wA.address, success: true });
        expect((await send(wA, a.body)).transactions).toHaveTransaction({ to: wA.address, success: false, exitCode: 706 });
        // after: order escrowed, then revoked (its lane already used) -> refund
        const lane2 = randomU256();
        const a2 = leg(alice, wA.address, A.address, B.address, 500n, 100n, { lane: lane2 });
        await send(wA, a2.body);
        expect(await balanceOf(A, alice.address)).toBe(999_500n);
        const rv2 = signedPay(alice, { contract: wA.address, to: dex.address, amount: 0n, network, op: OP.revoke, lane: lane2, extra: h(a2) }, { forwardTon: toNano('0.2'), responseDestination: relayer.address });
        await send(wA, rv2.body);
        expect(await dex.getGetOrder(h(a2))).toBeNull();
        expect(await balanceOf(A, alice.address)).toBe(1_000_000n);
    });

    it('a revoke of a sent order runs once, needs its cancel TON, and only its owner can cancel (review L11)', async () => {
        const { relayer, network, A, B, alice, dex, wA, leg, send, h, balanceOf, mint, walletOf } = await dexSetup();
        const lane = randomU256();
        const a = leg(alice, wA.address, A.address, B.address, 700n, 100n, { lane });
        await send(wA, a.body);
        expect(await balanceOf(A, alice.address)).toBe(999_300n);
        // Eve signs a revoke naming Alice's order from her own wallet, after her own order on that lane
        const eve = await subject(9);
        await mint(A, eve.address, 10n);
        const wE = await walletOf(A, eve.address);
        const eveLane = randomU256();
        await send(wE, leg(eve, wE.address, A.address, B.address, 10n, 1n, { lane: eveLane }).body);
        const evil = signedPay(eve, { contract: wE.address, to: dex.address, amount: 0n, network, op: OP.revoke, lane: eveLane, extra: h(a) }, { forwardTon: toNano('0.2'), responseDestination: relayer.address });
        expect((await send(wE, evil.body)).transactions).toHaveTransaction({ to: wE.address, success: true });
        expect(await dex.getGetOrder(h(a))).not.toBeNull();
        // Alice's own revoke: refused below the cancel TON floor, then runs, then can never run again
        const rv = signedPay(alice, { contract: wA.address, to: dex.address, amount: 0n, network, op: OP.revoke, lane, extra: h(a) }, { forwardTon: toNano('0.2'), responseDestination: relayer.address });
        expect((await send(wA, { ...rv.body, forwardTon: toNano('0.01') })).transactions).toHaveTransaction({ to: wA.address, success: false, exitCode: 714 });
        expect((await send(wA, rv.body)).transactions).toHaveTransaction({ to: wA.address, success: true });
        expect(await dex.getGetOrder(h(a))).toBeNull();
        expect(await balanceOf(A, alice.address)).toBe(1_000_000n);
        expect((await send(wA, rv.body)).transactions).toHaveTransaction({ to: wA.address, success: false, exitCode: 706 });
    });

    it('a payout our wallet bounces is kept on record for the admin, not lost (review L14)', async () => {
        const { bc, admin, A, dex } = await dexSetup();
        const { internal } = require('@ton/sandbox');
        const { beginCell } = require('@ton/core');
        const { storeJettonTransfer } = require('../build/dex/dex_ScaasDex');
        const body = beginCell().storeUint(0xffffffff, 32).store(storeJettonTransfer({ $$type: 'JettonTransfer', queryId: 0n, amount: 123n, destination: admin.address, responseDestination: null, customPayload: null, forwardTonAmount: 0n, forwardPayload: beginCell().storeBit(false).asSlice() })).endCell();
        const dexWalletA = await A.getGetWalletAddress(dex.address);
        await bc.sendMessage(internal({ from: dexWalletA, to: dex.address, value: toNano('0.01'), bounce: false, bounced: true, body }));
        expect(await dex.getGetFees(A.address)).toBe(123n);
        // a bounce from anyone else is ignored
        await bc.sendMessage(internal({ from: admin.address, to: dex.address, value: toNano('0.01'), bounce: false, bounced: true, body }));
        expect(await dex.getGetFees(A.address)).toBe(123n);
    });

    it('an under-funded copy of a signed leg is refused at the payer wallet: nothing is stranded (review H2)', async () => {
        const { A, B, alice, dex, wA, leg, send, h, tonOf, balanceOf, walletOf } = await dexSetup({ enabled: false });
        const before = await tonOf(dex.address);
        const ok = leg(alice, wA.address, A.address, B.address, 1000n, 1n);
        for (const fwd of [0n, 1n, toNano('0.05')]) {
            const r = await send(wA, { ...ok.body, forwardTon: fwd });
            expect(r.transactions).toHaveTransaction({ to: wA.address, success: false, exitCode: 714 });
            expect(await balanceOf(A, alice.address)).toBe(1_000_000n);
        }
        // the signed copy, with the forward the payer signed: a bad leg (disabled market) comes back on its own TON
        expect((await send(wA, ok.body)).transactions).toHaveTransaction({ to: wA.address, success: true });
        expect(await dex.getGetOrder(h(ok))).toBeNull();
        expect(await balanceOf(A, alice.address)).toBe(1_000_000n);
        expect(await balanceOf(A, dex.address)).toBe(0n);
        expect(before - (await tonOf(dex.address))).toBeLessThan(toNano('0.01'));
        expect(walletOf).toBeTruthy();
    });

    it('Match and Refund hand unspent TON back to the caller instead of keeping it', async () => {
        const { bc, A, B, alice, bob, dex, wA, wB, leg, send, h, tonOf, balanceOf } = await dexSetup();
        const a = leg(alice, wA.address, A.address, B.address, 500_000n, 499_000n);
        await send(wA, a.body);
        const b = leg(bob, wB.address, B.address, A.address, 500_000n, 498_000n);
        await send(wB, b.body);
        const stranger = await bc.treasury('stranger');
        let before = await tonOf(dex.address);
        await dex.send(stranger.getSender(), { value: toNano('1') }, { $$type: 'Match', a: h(a), b: h(b) });
        expect(await balanceOf(B, alice.address)).toBe(499_500n);
        expect((await tonOf(dex.address)) - before).toBeLessThan(toNano('0.01'));
        const c = leg(alice, wA.address, A.address, B.address, 1000n, 1n);
        await send(wA, c.body);
        bc.now = bc.now! + 601;
        before = await tonOf(dex.address);
        await dex.send(stranger.getSender(), { value: toNano('1') }, { $$type: 'Refund', orderHash: h(c) });
        expect(await balanceOf(A, alice.address)).toBe(500_000n);
        expect((await tonOf(dex.address)) - before).toBeLessThan(toNano('0.01'));
    });

    it('fees above 1 % are refused by SetMarket', async () => {
        const { admin, A, B, dex } = await dexSetup();
        const r = await dex.send(admin.getSender(), { value: toNano('0.05') }, { $$type: 'SetMarket', a: A.address, b: B.address, enabled: true, makerPpm: 10001n, takerPpm: 0n });
        expect(r.transactions).toHaveTransaction({ to: dex.address, success: false, exitCode: 713 });
    });
});
