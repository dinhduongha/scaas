import { Address, Dictionary, toNano } from '@ton/core';
import { keyPairFromSeed, sign } from '@ton/crypto';
import '@ton/test-utils';
import { Mandate } from '../build/mandate/mandate_Mandate';
import { events, setup, signedPay } from './fixture';
import { metaOpCell, OP, randomU256, subject } from './helpers';

const DAY = 86400;

async function mandateSetup() {
    const f = await setup();
    const token = await f.newToken('A');
    const alice = await subject(1);
    const bob = await subject(2);
    const carol = await subject(3);
    const delegate = keyPairFromSeed(Buffer.alloc(32, 0x44));
    const payees = Dictionary.empty(Dictionary.Keys.Address(), Dictionary.Values.Bool());
    payees.set(bob.address, true);
    const mandate = f.bc.openContract(await Mandate.fromInit(alice.address, token.address, {
        $$type: 'MandateState', revoked: false, periodStart: 0n, spent: 0n, balance: 0n,
        terms: { $$type: 'MandateTerms', perPayment: 50n, perPeriod: 80n, periodSeconds: BigInt(DAY), expiresAt: BigInt(f.bc.now! + 30 * DAY) },
        ownerPubkey: BigInt('0x' + alice.kp.publicKey.toString('hex')),
        delegatePubkey: BigInt('0x' + delegate.publicKey.toString('hex')),
    }, payees, Dictionary.empty(), Dictionary.empty()));
    await mandate.send(f.admin.getSender(), { value: toNano('0.1') }, null);
    await f.mint(token, alice.address, 1000n);
    const aw = await f.walletOf(token, alice.address);
    // Deposit: an ordinary signed pay to the Mandate, with forward TON so the Mandate is notified.
    const dep = signedPay(alice, { contract: aw.address, to: mandate.address, amount: 200n, network: f.network }, { forwardTon: toNano('0.02'), responseDestination: f.relayer.address });
    await aw.send(f.relayer.getSender(), { value: toNano('0.2') }, dep.body);
    const pay = (to: Address, amount: bigint, payRef = randomU256(), key = delegate.secretKey, over: Partial<Parameters<typeof metaOpCell>[0]> = {}) => {
        const op = metaOpCell({ network: f.network, op: OP.mandate_pay, amount, nonce: 0n, validUntil: f.bc.now! + 600, contract: mandate.address, from: mandate.address, to, payRef, lane: payRef, extra: 0n, ...over });
        return { op, body: { $$type: 'MandatePay' as const, op, signature: sign(op.hash(), key), responseDestination: f.relayer.address } };
    };
    const send = (body: any) => mandate.send(f.relayer.getSender(), { value: toNano('0.2') }, body);
    return { ...f, token, alice, bob, carol, delegate, mandate, pay, send };
}

describe('Mandate (R25 on TON)', () => {
    it('deposit is tracked; delegate pays listed payee within caps; PaymentSettled from the mandate', async () => {
        const { mandate, token, bob, pay, send, balanceOf } = await mandateSetup();
        expect((await mandate.getGetState()).balance).toBe(200n);
        expect(await balanceOf(token, mandate.address)).toBe(200n);
        const p = pay(bob.address, 50n);
        const r = await send(p.body);
        expect(r.transactions).toHaveTransaction({ to: mandate.address, success: true });
        expect(await balanceOf(token, bob.address)).toBe(50n);
        const ev = events(r.transactions);
        expect(ev.find((e) => e.name === 'MetaTransactionExecuted').digest).toBe(BigInt('0x' + p.op.hash().toString('hex')));
        expect(ev.find((e) => e.name === 'PaymentSettled').from.equals(mandate.address)).toBe(true);
    });

    it('enforces payee, per-payment, per-period, payRef once, signature, expiry; period resets', async () => {
        const { bc, mandate, bob, carol, alice, pay, send } = await mandateSetup();
        const code = async (body: any, c: number) => expect((await send(body)).transactions).toHaveTransaction({ to: mandate.address, success: false, exitCode: c });
        await code(pay(carol.address, 10n).body, 723);
        await code(pay(bob.address, 51n).body, 724);
        await code(pay(bob.address, 10n, randomU256(), alice.kp.secretKey).body, 708);
        await code(pay(bob.address, 10n, randomU256(), undefined, { validUntil: bc.now! }).body, 705);
        await code(pay(bob.address, 10n, randomU256(), undefined, { from: alice.address }).body, 704);
        const ref = randomU256();
        expect((await send(pay(bob.address, 50n, ref).body)).transactions).toHaveTransaction({ to: mandate.address, success: true });
        await code(pay(bob.address, 10n, ref).body, 726);
        await code(pay(bob.address, 40n).body, 725); // 50 + 40 > 80 per period
        expect((await send(pay(bob.address, 30n).body)).transactions).toHaveTransaction({ to: mandate.address, success: true });
        bc.now = bc.now! + 86400;
        expect((await send(pay(bob.address, 50n).body)).transactions).toHaveTransaction({ to: mandate.address, success: true });
        expect((await mandate.getGetState()).balance).toBe(70n);
        bc.now = bc.now! + 31 * 86400;
        await code(pay(bob.address, 1n, randomU256(), undefined, { validUntil: bc.now! + 60 }).body, 722);
    });

    it('owner revokes (signed op); delegate stops; owner withdraws the rest', async () => {
        const { mandate, alice, bob, pay, send, network, relayer, token, balanceOf } = await mandateSetup();
        const rv = signedPay(alice, { contract: mandate.address, to: alice.address, amount: 0n, network, op: OP.revoke }, { responseDestination: relayer.address });
        expect((await mandate.send(relayer.getSender(), { value: toNano('0.2') }, rv.body)).transactions).toHaveTransaction({ to: mandate.address, success: true });
        expect((await send(pay(bob.address, 10n).body)).transactions).toHaveTransaction({ to: mandate.address, success: false, exitCode: 721 });
        const wd = signedPay(alice, { contract: mandate.address, to: alice.address, amount: 200n, network }, { responseDestination: relayer.address });
        expect((await mandate.send(relayer.getSender(), { value: toNano('0.2') }, wd.body)).transactions).toHaveTransaction({ to: mandate.address, success: true });
        expect(await balanceOf(token, alice.address)).toBe(1000n);
        // a stranger's key cannot withdraw
        const bobKey = signedPay(bob, { contract: mandate.address, to: bob.address, amount: 1n, network, from: alice.address }, { responseDestination: relayer.address });
        expect((await mandate.send(relayer.getSender(), { value: toNano('0.2') }, bobKey.body)).transactions).toHaveTransaction({ to: mandate.address, success: false, exitCode: 708 });
    });

    it('a deposit through a wallet that is not the mandate wallet is not counted', async () => {
        const { bc, mandate } = await mandateSetup();
        const stranger = await bc.treasury('stranger');
        await mandate.send(stranger.getSender(), { value: toNano('0.1') }, { $$type: 'JettonNotification', queryId: 0n, amount: 1_000_000n, sender: stranger.address, forwardPayload: (await import('@ton/core')).beginCell().storeBit(false).asSlice() });
        expect((await mandate.getGetState()).balance).toBe(200n);
    });
});
