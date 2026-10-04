//! Dựng instruction mandate / DEX cho test (dùng chung giữa mandate.rs, dex.rs, antilock.rs).
#![allow(dead_code)]
use anchor_lang::prelude::Pubkey;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::{InstructionData, ToAccountMetas};
use bamboo::auth::{self as A, Auth};
use bamboo::{MandateInit, Order};
use solana_signer::Signer;

use super::*;

pub fn mandate_addr(account: &Pubkey, seed: [u8; 32]) -> Pubkey {
    pda(&[b"mandate", account.as_ref(), &seed])
}

impl Env {
    pub fn mandate_init(&self, owner_account: &Pubkey, seed: [u8; 32], delegate: &Ed, payees: Vec<Pubkey>) -> MandateInit {
        MandateInit {
            seed,
            delegate: delegate.key(),
            max_per_payment: 50,
            max_per_period: 80,
            period_s: 100,
            expiry: 900,
            payees,
            nonce: self.subject(owner_account).key_nonce,
            valid_until: 1000,
        }
    }

    pub fn mandate_open(&mut self, owner: &Ed, init: &MandateInit) -> Res {
        self.mandate_open_as(owner, owner, init)
    }

    pub fn mandate_open_as(&mut self, owner: &Ed, signer: &Ed, init: &MandateInit) -> Res {
        let acct = owner.account();
        let m = mandate_addr(&acct, init.seed);
        let dg = sha(&[&init.bytes(&self.network, &acct, &m)]);
        let ix = Instruction {
            program_id: bamboo::ID,
            accounts: bamboo::accounts::MandateOpen {
                lane: self.lane.pubkey(),
                config: self.config(),
                subject: acct,
                mandate: m,
                instructions: IXS,
                system_program: SYSTEM,
            }
            .to_account_metas(None),
            data: bamboo::instruction::MandateOpen { init: init.clone(), auth: auth(A::KIND_RAW, 0, 0, 0) }.data(),
        };
        self.send(&[ed_ix(&[signer.sign(A::KIND_RAW, A::MANDATE_LABEL, &dg)]), ix], &[])
    }

    pub fn mandate_pay_ix(&self, mandate: &Pubkey, mint: &Pubkey, tp: Pubkey, args: &bamboo::PayArgs, a: Auth) -> Instruction {
        let to = Pubkey::new_from_array(args.to);
        Instruction {
            program_id: bamboo::ID,
            accounts: bamboo::accounts::MandatePay {
                lane: self.lane.pubkey(),
                config: self.config(),
                mandate: *mandate,
                mref: pda(&[b"mref", mandate.as_ref(), &args.pay_ref]),
                source: ata(mandate, mint, &tp),
                recipient: to,
                destination: ata(&to, mint, &tp),
                mint: *mint,
                token_program: tp,
                associated_token_program: ATA,
                system_program: SYSTEM,
                instructions: IXS,
                event_authority: event_authority(),
                program: bamboo::ID,
            }
            .to_account_metas(None),
            data: bamboo::instruction::MandatePay { args: args.clone(), auth: a }.data(),
        }
    }

    /// Delegate ký `MetaOp{op: mandate_pay, contract: mandate, from: owner}`.
    pub fn mandate_pay(&mut self, delegate: &Ed, owner: &Ed, mandate: &Pubkey, mint: &Pubkey, args: &bamboo::PayArgs) -> Res {
        let dg = self.metaop_digest(mandate, mint, A::OP_MANDATE_PAY, &owner.pk(), args);
        let ix = self.mandate_pay_ix(mandate, mint, TOKEN, args, auth(A::KIND_RAW, 0, 0, 0));
        self.send(&[ed_ix(&[delegate.sign(A::KIND_RAW, A::METAOP_LABEL, &dg)]), ix], &[])
    }

    pub fn mandate_revoke(&mut self, signer: &Ed, owner: &Ed, mandate: &Pubkey) -> Res {
        let op = bamboo::auth::MetaOp {
            network: self.network,
            contract: mandate.to_bytes(),
            asset: [0; 32],
            op: A::OP_REVOKE,
            from: owner.pk(),
            to: [0; 32],
            amount: 0,
            pay_ref: [0; 32],
            lane: [0; 32],
            nonce: 0,
            valid_until: 1000,
            relayer: [0; 32],
            extra: [0; 32],
        };
        let ix = Instruction {
            program_id: bamboo::ID,
            accounts: bamboo::accounts::MandateRevoke { lane: self.lane.pubkey(), config: self.config(), mandate: *mandate, instructions: IXS }
                .to_account_metas(None),
            data: bamboo::instruction::MandateRevokeSigned { valid_until: 1000, auth: auth(A::KIND_RAW, 0, 0, 0) }.data(),
        };
        self.send(&[ed_ix(&[signer.sign(A::KIND_RAW, A::METAOP_LABEL, &op.digest())]), ix], &[])
    }

    /// Khoá Account đóng Mandate; `quads` = (nguồn của Mandate, mint, đích của Account, token program).
    pub fn mandate_close(&mut self, owner: &Ed, mandate: &Pubkey, quads: &[(Pubkey, Pubkey, Pubkey, Pubkey)]) -> Res {
        self.mandate_close_as(owner, owner, mandate, quads)
    }

    pub fn mandate_close_as(&mut self, owner: &Ed, signer: &Ed, mandate: &Pubkey, quads: &[(Pubkey, Pubkey, Pubkey, Pubkey)]) -> Res {
        let acct = owner.account();
        let nonce = self.subject(&acct).key_nonce;
        let dg = sha(&[A::MCLOSE_LABEL.as_bytes(), &self.network, acct.as_ref(), mandate.as_ref(), &nonce.to_le_bytes(), &1000u64.to_le_bytes()]);
        let rent_payer = self.lane.pubkey();
        let mut accounts = bamboo::accounts::MandateClose {
            lane: self.lane.pubkey(),
            config: self.config(),
            subject: acct,
            mandate: *mandate,
            rent_payer,
            instructions: IXS,
        }
        .to_account_metas(None);
        for (src, mint, dst, tp) in quads {
            accounts.extend([AccountMeta::new(*src, false), AccountMeta::new_readonly(*mint, false), AccountMeta::new(*dst, false), AccountMeta::new_readonly(*tp, false)]);
        }
        let ix = Instruction {
            program_id: bamboo::ID,
            accounts,
            data: bamboo::instruction::MandateCloseSigned { nonce, valid_until: 1000, auth: auth(A::KIND_RAW, 0, 0, 0) }.data(),
        };
        self.send(&[ed_ix(&[signer.sign(A::KIND_RAW, A::MCLOSE_LABEL, &dg)]), ix], &[])
    }

    // -------------------------------------------------------------- DEX

    pub fn list_market(&mut self, base: &Pubkey, quote: &Pubkey, fee_ppm: u32, fee_recipient: &Pubkey) -> Res {
        let admin = self.admin.insecure_clone();
        let ix = Instruction {
            program_id: bamboo::ID,
            accounts: bamboo::accounts::ListMarket {
                admin: admin.pubkey(),
                config: self.config(),
                market: market_addr(base, quote),
                base_mint: *base,
                quote_mint: *quote,
                system_program: SYSTEM,
            }
            .to_account_metas(None),
            data: bamboo::instruction::ListMarket { fee_ppm, fee_recipient: *fee_recipient }.data(),
        };
        self.send_as(&admin, &[ix], &[])
    }

    pub fn set_market(&mut self, signer: &solana_keypair::Keypair, market: &Pubkey, fee_ppm: u32, enabled: bool, fee_recipient: &Pubkey) -> Res {
        let ix = Instruction {
            program_id: bamboo::ID,
            accounts: bamboo::accounts::SetMarket { admin: signer.pubkey(), config: self.config(), market: *market }.to_account_metas(None),
            data: bamboo::instruction::SetMarket { fee_ppm, enabled, fee_recipient: *fee_recipient }.data(),
        };
        let s = signer.insecure_clone();
        self.send_as(&s, &[ix], &[])
    }

    pub fn order_hash(&self, market: &Pubkey, o: &Order) -> [u8; 32] {
        o.hash(&self.network, market)
    }

    /// Một `settle`: `sig_a`/`sig_b` = chỉ số chữ ký trong instruction precompile ở `precompile_ix`.
    #[allow(clippy::too_many_arguments)]
    pub fn settle_ix(&self, market: &Pubkey, a: &Order, b: &Order, fill_a: u64, fill_b: u64, tp: Pubkey, fee: bool, precompile_ix: u8, sig_a: u8, sig_b: u8) -> Instruction {
        let (ha, hb) = (self.order_hash(market, a), self.order_hash(market, b));
        let (sa, sb) = (account_of(&a.maker), account_of(&b.maker));
        let (x, y) = (a.sell_mint, a.buy_mint);
        Instruction {
            program_id: bamboo::ID,
            accounts: bamboo::accounts::Settle {
                lane: self.lane.pubkey(),
                config: self.config(),
                market: *market,
                subject_a: sa,
                subject_b: sb,
                fill_a: pda(&[b"fill", market.as_ref(), &ha]),
                fill_b: pda(&[b"fill", market.as_ref(), &hb]),
                min_nonce_a: pda(&[b"minnonce", market.as_ref(), sa.as_ref()]),
                min_nonce_b: pda(&[b"minnonce", market.as_ref(), sb.as_ref()]),
                a_src: ata(&sa, &x, &tp),
                b_src: ata(&sb, &y, &tp),
                a_dst: ata(&sa, &y, &tp),
                b_dst: ata(&sb, &x, &tp),
                vault_x: fee.then(|| ata(market, &x, &tp)),
                vault_y: fee.then(|| ata(market, &y, &tp)),
                mint_x: x,
                mint_y: y,
                token_program_x: tp,
                token_program_y: tp,
                associated_token_program: ATA,
                system_program: SYSTEM,
                instructions: IXS,
                event_authority: event_authority(),
                program: bamboo::ID,
            }
            .to_account_metas(None),
            data: bamboo::instruction::Settle {
                a: a.clone(),
                b: b.clone(),
                hash_a: ha,
                hash_b: hb,
                fill_a,
                fill_b,
                auth_a: auth(A::KIND_RAW, 0, precompile_ix, sig_a),
                auth_b: auth(A::KIND_RAW, 0, precompile_ix, sig_b),
            }
            .data(),
        }
    }

    /// Hai lệnh ký trong một precompile + `settle`, CU 1,4M.
    #[allow(clippy::too_many_arguments)]
    pub fn settle(&mut self, market: &Pubkey, a: &Order, ka: &Ed, b: &Order, kb: &Ed, fill_a: u64, fill_b: u64, fee: bool) -> Res {
        let sigs = [ka.sign(A::KIND_RAW, A::ORDER_LABEL, &self.order_hash(market, a)), kb.sign(A::KIND_RAW, A::ORDER_LABEL, &self.order_hash(market, b))];
        let ix = self.settle_ix(market, a, b, fill_a, fill_b, TOKEN, fee, 1, 0, 1);
        self.send(&[cu(1_400_000), ed_ix(&sigs), ix], &[])
    }

    pub fn cancel(&mut self, market: &Pubkey, o: &Order, k: &Ed) -> Res {
        let h = self.order_hash(market, o);
        let dg = sha(&[A::CANCEL_LABEL.as_bytes(), &self.network, market.as_ref(), &h]);
        let ix = Instruction {
            program_id: bamboo::ID,
            accounts: bamboo::accounts::CancelSigned {
                lane: self.lane.pubkey(),
                config: self.config(),
                market: *market,
                subject: account_of(&o.maker),
                fill: pda(&[b"fill", market.as_ref(), &h]),
                instructions: IXS,
                system_program: SYSTEM,
            }
            .to_account_metas(None),
            data: bamboo::instruction::CancelSigned { order: o.clone(), order_hash: h, auth: auth(A::KIND_RAW, 0, 0, 0) }.data(),
        };
        self.send(&[ed_ix(&[k.sign(A::KIND_RAW, A::CANCEL_LABEL, &dg)]), ix], &[])
    }

    pub fn invalidate(&mut self, market: &Pubkey, k: &Ed, min_nonce: u64) -> Res {
        let acct = k.account();
        let dg = sha(&[A::MINNONCE_LABEL.as_bytes(), &self.network, market.as_ref(), acct.as_ref(), &min_nonce.to_le_bytes()]);
        let ix = Instruction {
            program_id: bamboo::ID,
            accounts: bamboo::accounts::InvalidateNonces {
                lane: self.lane.pubkey(),
                config: self.config(),
                market: *market,
                subject: acct,
                min_nonce: pda(&[b"minnonce", market.as_ref(), acct.as_ref()]),
                instructions: IXS,
                system_program: SYSTEM,
            }
            .to_account_metas(None),
            data: bamboo::instruction::InvalidateNoncesSigned { min_nonce, auth: auth(A::KIND_RAW, 0, 0, 0) }.data(),
        };
        self.send(&[ed_ix(&[k.sign(A::KIND_RAW, A::MINNONCE_LABEL, &dg)]), ix], &[])
    }

    pub fn sweep(&mut self, market: &Pubkey, source: &Pubkey, mint: &Pubkey, recipient: &Pubkey) -> Res {
        let ix = Instruction {
            program_id: bamboo::ID,
            accounts: bamboo::accounts::Sweep {
                payer: self.lane.pubkey(),
                market: *market,
                source: *source,
                mint: *mint,
                recipient: *recipient,
                destination: ata(recipient, mint, &TOKEN),
                token_program: TOKEN,
                associated_token_program: ATA,
                system_program: SYSTEM,
            }
            .to_account_metas(None),
            data: bamboo::instruction::Sweep {}.data(),
        };
        self.send(&[ix], &[])
    }
}

pub fn market_addr(base: &Pubkey, quote: &Pubkey) -> Pubkey {
    pda(&[b"mkt", base.as_ref(), quote.as_ref()])
}

/// `ComputeBudget::SetComputeUnitLimit`.
pub fn cu(units: u32) -> Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&units.to_le_bytes());
    Instruction { program_id: "ComputeBudget111111111111111111111111111111".parse().unwrap(), accounts: vec![], data }
}

pub fn order(maker: &Ed, sell: &Pubkey, buy: &Pubkey, sell_amount: u64, buy_amount: u64, nonce: u64) -> Order {
    Order {
        maker: maker.pk(),
        taker: [0; 32],
        sell_mint: *sell,
        buy_mint: *buy,
        sell_amount,
        buy_amount,
        nonce,
        expiry: 900,
        max_fee_ppm: 10_000,
        flags: 0,
        relayer: [0; 32],
    }
}
