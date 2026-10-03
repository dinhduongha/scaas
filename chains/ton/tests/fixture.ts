import { Blockchain, SandboxContract, TreasuryContract } from '@ton/sandbox';
import { Address, beginCell, Cell, toNano } from '@ton/core';
import { BambooJettonMaster } from '../build/jetton/jetton_BambooJettonMaster';
import { BambooJettonWallet, loadMetaTransactionExecuted, loadPaymentSettled } from '../build/jetton/jetton_BambooJettonWallet';
import { metaOpCell, MetaOpFields, OP, randomU256, subject, tonConnectAuth } from './helpers';

export const DOMAIN = 'pay.bamboo.example';

export async function setup() {
    const bc = await Blockchain.create();
    bc.now = 1_800_000_000;
    const admin = await bc.treasury('admin');
    const relayer = await bc.treasury('relayer');
    const network = globalIdOf(bc);
    async function newToken(tag: string) {
        const master = bc.openContract(await BambooJettonMaster.fromInit(admin.address, 0n, beginCell().storeStringTail(tag).endCell()));
        await master.send(admin.getSender(), { value: toNano('0.1') }, { $$type: 'Mint', queryId: 0n, to: admin.address, amount: 1n, responseDestination: admin.address });
        return master;
    }
    async function mint(master: SandboxContract<BambooJettonMaster>, to: Address, amount: bigint) {
        await master.send(admin.getSender(), { value: toNano('0.1') }, { $$type: 'Mint', queryId: 0n, to, amount, responseDestination: admin.address });
    }
    async function walletOf(master: SandboxContract<BambooJettonMaster>, owner: Address) {
        return bc.openContract(BambooJettonWallet.fromAddress(await master.getGetWalletAddress(owner)));
    }
    async function balanceOf(master: SandboxContract<BambooJettonMaster>, owner: Address) {
        const w = await walletOf(master, owner);
        const st = await bc.getContract(w.address);
        if (st.accountState?.type !== 'active') return 0n;
        return (await w.getGetWalletData()).balance;
    }
    return { bc, admin, relayer, network, newToken, mint, walletOf, balanceOf };
}

/// Global id from sandbox config param 19.
export function globalIdOf(bc: Blockchain): number {
    const { Dictionary } = require('@ton/core');
    const dict = Dictionary.loadDirect(Dictionary.Keys.Int(32), Dictionary.Values.Cell(), Cell.fromBase64(bc.config.toBoc().toString('base64')));
    return dict.get(19).beginParse().loadInt(32);
}

export type Subject = Awaited<ReturnType<typeof subject>>;

/// A signed `SignedOp` body ready for the relayer to send.
export function signedPay(s: Subject, f: Partial<MetaOpFields> & Pick<MetaOpFields, 'contract' | 'to' | 'amount' | 'network'>, opts: { withInit?: boolean; domain?: string; ts?: number; params?: Cell | null; matchWith?: bigint; forwardTon?: bigint; responseDestination: Address }) {
    const fields: MetaOpFields = {
        op: OP.pay, nonce: 0n, validUntil: 1_800_000_600, from: s.address, payRef: randomU256(), lane: randomU256(), extra: 0n,
        ...f,
    };
    const op = metaOpCell(fields);
    const auth = tonConnectAuth(s.kp, s.address, opts.ts ?? 1_800_000_000, opts.domain ?? DOMAIN, op);
    return {
        fields, op, digest: op.hash(),
        body: {
            $$type: 'SignedOp' as const, op, auth, params: opts.params ?? null,
            stateInit: opts.withInit === false ? null : s.stateInit,
            responseDestination: opts.responseDestination, forwardTon: opts.forwardTon ?? 0n, matchWith: opts.matchWith ?? 0n,
        },
    };
}

export function events(txs: { outMessages: { values(): any[] } }[]) {
    const out: any[] = [];
    for (const tx of txs) {
        for (const m of tx.outMessages.values()) {
            if (m.info.type !== 'external-out') continue;
            const s = m.body.beginParse();
            const op = s.preloadUint(32);
            if (op === 0x9b1c0d01) out.push({ name: 'MetaTransactionExecuted', src: m.info.src, ...loadMetaTransactionExecuted(m.body.beginParse()) });
            if (op === 0x9b1c0d02) out.push({ name: 'PaymentSettled', src: m.info.src, ...loadPaymentSettled(m.body.beginParse()) });
        }
    }
    return out;
}
