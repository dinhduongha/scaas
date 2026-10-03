import { beginCell, toNano } from '@ton/core';
import '@ton/test-utils';
import { DOMAIN, events, globalIdOf, setup, signedPay } from './fixture';
import { domainCell, metaOpCell, newPasskey, OP, passkeyAuth, passkeyRecord, randomU256, subject, tonConnectAuth } from './helpers';

const E = { domain: 701, network: 702, contract: 703, from: 704, expired: 705, nonce: 706, relayer: 707, sig: 708, noKey: 709, stateInit: 710, balance: 711, params: 713, value: 714, auth: 715, sender: 716 };

describe('BambooJettonWallet meta-tx (R30, R67)', () => {
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

    it('a forged wallet (same code, other master) cannot credit a real wallet', async () => {
        const { bc, relayer, network, newToken, mint, walletOf, balanceOf } = await setup();
        const real = await newToken('A');
        const fake = await newToken('FAKE');
        const alice = await subject(1);
        const bob = await subject(2);
        await mint(fake, alice.address, 1000n);
        const fw = await walletOf(fake, alice.address);
        // Alice's fake-token wallet sends to bob's REAL wallet address directly.
        const bobReal = await walletOf(real, bob.address);
        const sp = signedPay(alice, { contract: fw.address, to: bob.address, amount: 5n, network }, { responseDestination: relayer.address });
        await fw.send(relayer.getSender(), { value: toNano('0.15') }, sp.body);
        expect(await balanceOf(real, bob.address)).toBe(0n);
        expect(bobReal.address.equals((await walletOf(fake, bob.address)).address)).toBe(false);
    });

    it('passkey (P-256 WebAuthn via P256_CHKSIGNS): set by the ed25519 key, then signs a pay', async () => {
        const { relayer, network, newToken, mint, walletOf, balanceOf } = await setup();
        const token = await newToken('A');
        const alice = await subject(1);
        const bob = await subject(2);
        await mint(token, alice.address, 100n);
        const aw = await walletOf(token, alice.address);
        const pk = newPasskey();
        const rec = passkeyRecord(pk.compressed, 'pay.bamboo.example', 'https://pay.bamboo.example');
        const setKey = signedPay(alice, { contract: aw.address, to: alice.address, amount: 0n, network, op: OP.set_key, extra: BigInt('0x' + rec.hash().toString('hex')) }, { params: rec, responseDestination: relayer.address });
        expect((await aw.send(relayer.getSender(), { value: toNano('0.15') }, setKey.body)).transactions).toHaveTransaction({ to: aw.address, success: true });
        expect((await aw.getGetPasskey())!.hash().equals(rec.hash())).toBe(true);

        const fields = { op: OP.pay, network, amount: 30n, nonce: 0n, validUntil: 1_800_000_600, contract: aw.address, from: alice.address, to: bob.address, payRef: randomU256(), lane: randomU256(), extra: 0n };
        const op = metaOpCell(fields);
        const send = (auth: any) => aw.send(relayer.getSender(), { value: toNano('0.2') }, { $$type: 'SignedOp', op, auth, params: null, stateInit: null, responseDestination: relayer.address, forwardTon: 0n, matchWith: 0n });
        // wrong origin, missing UV, wrong digest, long client data (two suffix cells) — then the good one
        expect((await send(passkeyAuth(pk.privateKey, 'pay.bamboo.example', 'https://evil.example', op.hash()))).transactions).toHaveTransaction({ to: aw.address, exitCode: E.sig });
        expect((await send(passkeyAuth(pk.privateKey, 'pay.bamboo.example', 'https://pay.bamboo.example', op.hash(), 0x01))).transactions).toHaveTransaction({ to: aw.address, exitCode: E.sig });
        expect((await send(passkeyAuth(pk.privateKey, 'pay.bamboo.example', 'https://pay.bamboo.example', Buffer.alloc(32, 1)))).transactions).toHaveTransaction({ to: aw.address, exitCode: E.sig });
        const long = ',"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"';
        const r = await send(passkeyAuth(pk.privateKey, 'pay.bamboo.example', 'https://pay.bamboo.example', op.hash(), 0x05, long));
        expect(r.transactions).toHaveTransaction({ to: aw.address, success: true });
        expect(await balanceOf(token, bob.address)).toBe(30n);

        // a passkey cannot change keys
        const rm = metaOpCell({ ...fields, op: OP.set_key, to: alice.address, amount: 0n, lane: randomU256() });
        const r2 = await aw.send(relayer.getSender(), { value: toNano('0.2') }, { $$type: 'SignedOp', op: rm, auth: passkeyAuth(pk.privateKey, 'pay.bamboo.example', 'https://pay.bamboo.example', rm.hash()), params: null, stateInit: null, responseDestination: relayer.address, forwardTon: 0n, matchWith: 0n });
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
        expect(DOMAIN).toBe('pay.bamboo.example');
    });
});
