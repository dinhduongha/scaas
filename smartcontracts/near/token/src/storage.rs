//! Storage (spec §3.2, §2 row 15): the caller pays every record it creates, from its attached deposit, the excess
//! refunded to the predecessor in the same receipt. NEP-145 with `min == max` (one fixed cost per holder);
//! deviations: `storage_unregister` of a registered account panics (balances are permanent, `force` included).
use crate::{Holder, Token, TokenExt};
use near_contract_standards::storage_management::{StorageBalance, StorageBalanceBounds, StorageManagement};
use near_sdk::{assert_one_yocto, env, near, require, AccountId, NearToken, Promise};

/// One NEP-145 registration of the longest (64-char) account id: key `f` ‖ Borsh(AccountId) 69 B + u128 16 B +
/// 40 B record overhead. Measured on near-sandbox (`runs/2026-10-28-near-storage.txt`); `new` checks the
/// standard's own measurement against it.
pub const ACCOUNT_STORAGE_BYTES: u64 = 125;
/// One UA ledger record: key `u` ‖ id 33 B + u128 16 B + 40 B overhead. Measured as above; `new` measures one too.
pub const UA_STORAGE_BYTES: u64 = 89;

impl Token {
    /// Before a credit to `to` (every entry that credits calls it first): a registered native receiver or an
    /// existing UA record needs exactly 1 yoctoNEAR (NEP-141); otherwise (deviation) the attached deposit must cover
    /// the new record, the record is created (registration / zero UA balance) and the excess goes back to the
    /// predecessor. Tasks 5–10 whose entries create other records charge them per §2 row 15 the same way.
    pub(crate) fn pay_receiver_storage(&mut self, to: &Holder) {
        let bytes = match to {
            Holder::Near(a) => {
                require!(*a != env::current_account_id(), "token refuses a transfer to the token itself");
                if self.ft.accounts.contains_key(a) {
                    0
                } else {
                    self.ft.internal_register_account(a);
                    ACCOUNT_STORAGE_BYTES
                }
            }
            Holder::Ua(id) => {
                if self.ua.contains_key(id) {
                    0
                } else {
                    self.ua.insert(*id, 0);
                    UA_STORAGE_BYTES
                }
            }
        };
        take_storage_deposit(bytes);
    }
}

/// `bytes == 0`: exactly 1 yoctoNEAR; else attached ≥ `bytes × storage_byte_cost`, the excess refunded.
fn take_storage_deposit(bytes: u64) {
    if bytes == 0 {
        return assert_one_yocto();
    }
    let need = env::storage_byte_cost().saturating_mul(bytes.into());
    let attached = env::attached_deposit();
    require!(attached >= need, "The attached deposit is less than the storage cost of the new record");
    let refund = attached.saturating_sub(need);
    if refund > NearToken::from_yoctonear(0) {
        Promise::new(env::predecessor_account_id()).transfer(refund).detach();
    }
}

#[near]
impl StorageManagement for Token {
    /// NEP-145, anyone for anyone; already registered: the deposit is refunded.
    #[payable]
    fn storage_deposit(&mut self, account_id: Option<AccountId>, registration_only: Option<bool>) -> StorageBalance {
        self.ft.storage_deposit(account_id, registration_only)
    }

    /// `available` is always 0: `amount > 0` panics.
    #[payable]
    fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
        self.ft.storage_withdraw(amount)
    }

    /// Deviation: registered → panics (`force` included); unregistered → `false`.
    #[payable]
    fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        let _ = force;
        assert_one_yocto();
        require!(
            !self.ft.accounts.contains_key(&env::predecessor_account_id()),
            "balances are permanent: storage_unregister refused (force included)"
        );
        false
    }

    fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        self.ft.storage_balance_bounds()
    }

    fn storage_balance_of(&self, account_id: AccountId) -> Option<StorageBalance> {
        self.ft.storage_balance_of(account_id)
    }
}
