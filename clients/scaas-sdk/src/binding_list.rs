// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The module objects and their calls, listed once (spec §16.1): `binding_list!(m)` invokes the macro `m` with the list, so every
//! binding reads the same one: `binding::surface!` (UniFFI: the async calls, or their `*_blocking` twins under `sync-api`) and
//! `wasm::wasm_surface!` (wasm-bindgen, plan T20g). A list entry is `async <call> / <call>_blocking (args) -> T;` on an object
//! `object <Name> = <the SDK's module type>`. The types resolve where the macro is invoked: each binding module imports them.
//! `tests/binding.rs` holds the list equal to the SDK's exported async calls both ways.

macro_rules! binding_list {
    ($m:ident) => {
        $m! {
            /// The SDK (spec §4): the module accessors, events, watching.
            object Sdk = crate::Sdk {
                #[cfg(feature = "evm")] async watch / watch_blocking (account: String, chains: Vec<String>) -> ();
                #[cfg(feature = "evm")] async state_rev / state_rev_blocking () -> u64;
            }
            /// Seeds (spec §6).
            object Vault = crate::vault::Vault {
                async enable_passkey_unlock / enable_passkey_unlock_blocking (seed: String, vault_passphrase: Arc<SecretBytes>) -> ();
                async enable_platform_unlock / enable_platform_unlock_blocking (seed: String, vault_passphrase: Arc<SecretBytes>, policy: KeyPolicy) -> ();
                async disable_prf_unlock / disable_prf_unlock_blocking (seed: String) -> ();
                async change_passphrase / change_passphrase_blocking (seed: String, old: Arc<SecretBytes>, new: Arc<SecretBytes>) -> ();
                #[cfg(feature = "classical-roots")] async derive_from_signature / derive_from_signature_blocking (req: DeriveFromSignature) -> NewSeed;
                #[cfg(feature = "classical-roots")] async derive_from_key / derive_from_key_blocking (req: DeriveFromKey) -> NewSeed;
                async keystore_rollback / keystore_rollback_blocking () -> bool;
                async accept_rollback / accept_rollback_blocking () -> ();
                async seeds / seeds_blocking () -> Vec<SeedInfo>;
                async generate / generate_blocking (req: Generate) -> NewSeed;
                async derive_child / derive_child_blocking (req: DeriveChild) -> NewSeed;
                async import_words / import_words_blocking (req: ImportWords) -> SeedInfo;
                async import_key / import_key_blocking (req: ImportKey) -> ImportedKey;
                async confirm_backup / confirm_backup_blocking (seed: String) -> ();
                async rename / rename_blocking (seed: String, label: String) -> ();
                async remove / remove_blocking (req: Remove) -> ();
                async unlock / unlock_blocking (seed: String, unlock: Unlock) -> ();
                async open_hidden / open_hidden_blocking (seed: String, unlock: Unlock, bip39_passphrase: Arc<SecretBytes>) -> SessionSet;
                async seed / seed_blocking (seed: String) -> SeedInfo;
            }
            /// Accounts (spec §7).
            #[cfg(feature = "account")]
            object Account = crate::account::Account {
                async accounts / accounts_blocking (seed: String) -> Vec<AccountInfo>;
                async next_account / next_account_blocking (seed: String) -> u32;
                async add_ua / add_ua_blocking (req: AddUa) -> AccountInfo;
                async add_native / add_native_blocking (req: AddNative) -> AccountInfo;
                #[cfg(feature = "evm")] async create_passkey_key / create_passkey_key_blocking (req: CreatePasskeyKey) -> KeyRef;
                #[cfg(feature = "evm")] async create_se_key / create_se_key_blocking (req: CreateSeKey) -> KeyRef;
                async add_watch / add_watch_blocking (req: AddWatch) -> AccountInfo;
                async signs / signs_blocking (seed: String, id: String) -> bool;
                #[cfg(feature = "evm")] async msig_state / msig_state_blocking (chain: String, ua: String) -> MsigState;
                #[cfg(feature = "evm")] async prepare_msig_register / prepare_msig_register_blocking (req: MsigRegister) -> Vec<Arc<RegistryWrite>>;
                #[cfg(feature = "evm")] async prepare_accept_membership / prepare_accept_membership_blocking (req: AcceptMembership) -> Option<Arc<RegistryWrite>>;
                #[cfg(feature = "evm")] async prepare_update_msig / prepare_update_msig_blocking (req: UpdateMsig) -> MsigUpdatePlan;
                #[cfg(feature = "evm")] async prepare_register / prepare_register_blocking (req: Register) -> Vec<Arc<RegistryWrite>>;
                #[cfg(feature = "evm")] async quote_registry_write / quote_registry_write_blocking (write: Arc<RegistryWrite>) -> SubmitQuote;
                #[cfg(feature = "evm")] async submit_registry_write / submit_registry_write_blocking (write: Arc<RegistryWrite>, quote: SubmitQuote) -> String;
                #[cfg(feature = "evm")] async registration_of / registration_of_blocking (chain: String, ua: String) -> RegistrationState;
                #[cfg(feature = "evm")] async ua_line / ua_line_blocking (chain: String, ua: String) -> UaLine;
                #[cfg(feature = "evm")] async register_target / register_target_blocking (chain: String, kind: u16) -> String;
                #[cfg(feature = "evm")] async pqz_decoy_candidates / pqz_decoy_candidates_blocking (chain: String) -> Vec<String>;
                #[cfg(feature = "evm")] async prepare_kem_repair / prepare_kem_repair_blocking (key: KeyRef, chain: String, payer: KeyRef) -> Option<Arc<RegistryWrite>>;
                #[cfg(feature = "evm")] async prepare_set_kem_key / prepare_set_kem_key_blocking (key: KeyRef, chain: String, version: u64, payer: KeyRef) -> Option<Arc<RegistryWrite>>;
                #[cfg(feature = "evm")] async marks / marks_blocking (seed: String, chain: String) -> Vec<AccountInfo>;
                #[cfg(feature = "evm")] async restore / restore_blocking (req: Restore) -> Vec<AccountInfo>;
                #[cfg(feature = "evm")] async prepare_smart_add_key / prepare_smart_add_key_blocking (op: SmartOp, key: SubjectKeyArgs) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_smart_remove_key / prepare_smart_remove_key_blocking (op: SmartOp, index: String) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_smart_rotate_key / prepare_smart_rotate_key_blocking (op: SmartOp, index: String, key: SubjectKeyArgs) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_smart_set_guardian / prepare_smart_set_guardian_blocking (op: SmartOp, guardian: String) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_smart_cancel_recovery / prepare_smart_cancel_recovery_blocking (op: SmartOp) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_smart_cancel_nonce / prepare_smart_cancel_nonce_blocking (op: SmartOp, lane: String) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_smart_execute / prepare_smart_execute_blocking (op: SmartOp, call: SmartCall) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_smart_deploy / prepare_smart_deploy_blocking (key: KeyRef, chain: String, factory: String, first_key: SubjectKeyArgs, guardian: String) -> NativeQuote;
                #[cfg(feature = "evm")] async prepare_complete_recovery / prepare_complete_recovery_blocking (key: KeyRef, chain: String, account: String, new_key: SubjectKeyArgs) -> NativeQuote;
                #[cfg(feature = "evm")] async prepare_initiate_recovery / prepare_initiate_recovery_blocking (op: SmartOp, account: String, new_key: SubjectKeyArgs) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async registration_blob / registration_blob_blocking (key: KeyRef, attrs: RegisterAttrs) -> RegistrationBlob;
                #[cfg(feature = "evm")] async prepare_submit_registration / prepare_submit_registration_blocking (blob: RegistrationBlob, chain: String, expected_ua: String, payer: KeyRef) -> Vec<Arc<RegistryWrite>>;
            }
            /// Tokens, balances, payments (spec §8).
            #[cfg(feature = "wallet")]
            object Wallet = crate::wallet::Wallet {
                async balances / balances_blocking (id: String, chain: String) -> Balances;
                #[cfg(feature = "evm")] async history / history_blocking (account: String, chain: String, before: Option<Cursor>, limit: u32) -> HistoryPage;
                async native_address / native_address_blocking (key: NativeKeyRef, ss58_prefix: Option<u16>) -> NativeAddress;
                #[cfg(feature = "evm")] async prepare_native_send / prepare_native_send_blocking (req: NativeSend) -> NativeQuote;
                #[cfg(feature = "evm")] async submit_native_send / submit_native_send_blocking (q: NativeQuote) -> String;
                #[cfg(feature = "evm")] async prepare_transfer / prepare_transfer_blocking (req: Transfer) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_pay / prepare_pay_blocking (req: Pay) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_pay_with_tax / prepare_pay_with_tax_blocking (req: PayWithTax) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_payee_fee / prepare_payee_fee_blocking (req: PayeeFee) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_pay_under_mandate / prepare_pay_under_mandate_blocking (req: PayUnderMandate) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_relay_fee / prepare_relay_fee_blocking (req: RelayFee) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_execute / prepare_execute_blocking (req: Execute) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async tokens / tokens_blocking (chain: String, with_index: bool) -> Vec<TokenInfo>;
                #[cfg(feature = "evm")] async prepare_cancel_nonce / prepare_cancel_nonce_blocking (req: CancelNonce) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_burn / prepare_burn_blocking (req: Burn) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_wrap / prepare_wrap_blocking (req: Wrap) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_wrap_leg / prepare_wrap_leg_blocking (req: WrapLeg) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_unwrap / prepare_unwrap_blocking (req: Unwrap) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_unwrap_leg / prepare_unwrap_leg_blocking (req: UnwrapLeg) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_add_reserve / prepare_add_reserve_blocking (req: AddReserve) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_wrap_to_ua / prepare_wrap_to_ua_blocking (req: WrapToUa) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_unwrap_to_ua / prepare_unwrap_to_ua_blocking (req: UnwrapToUa) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_set_mandate / prepare_set_mandate_blocking (req: SetMandate) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_set_payee / prepare_set_payee_blocking (req: SetPayee) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_revoke_mandate / prepare_revoke_mandate_blocking (req: RevokeMandate) -> Arc<Prepared>;
                #[cfg(feature = "evm")] async prepare_delegate_revoke / prepare_delegate_revoke_blocking (req: DelegateRevoke) -> Arc<Prepared>;
            }
            /// Operations: quote, submit, follow (spec §13).
            #[cfg(feature = "evm")]
            object Op = crate::op::Op {
                #[cfg(feature = "account")] async member_sign / member_sign_blocking (prepared: Arc<Prepared>) -> String;
                async state / state_blocking (op: String) -> OpState;
                async quote / quote_blocking (prepared: Arc<Prepared>, path: SubmitPath) -> SubmitQuote;
                async quote_with_gas / quote_with_gas_blocking (prepared: Arc<Prepared>, path: SubmitPath, gas: u64) -> SubmitQuote;
                async submit / submit_blocking (prepared: Arc<Prepared>, quote: SubmitQuote) -> String;
                async bls_multi_part / bls_multi_part_blocking (prepared: Arc<Prepared>, member: KeyRef) -> BlsMultiPart;
                async submit_bls_multi / submit_bls_multi_blocking (prepared: Arc<Prepared>, quote: SubmitQuote, parts: Vec<BlsMultiPart>, surplus: bool) -> String;
                async quote_register_bls_multi / quote_register_bls_multi_blocking (chain: String, key_data: String, payer: KeyRef) -> SubmitQuote;
                async register_bls_multi / register_bls_multi_blocking (chain: String, key_data: String, parts: Vec<BlsMultiPart>, quote: SubmitQuote) -> String;
                async resume / resume_blocking () -> u32;
                async resend / resend_blocking (op: String, quote: SubmitQuote) -> ();
                async hand_off / hand_off_blocking (prepared: Arc<Prepared>) -> SignedOpBlob;
                async import_signed / import_signed_blocking (blob: SignedOpBlob, expect: ImportExpect) -> Arc<Prepared>;
            }
            /// Zether and PQZ (spec §9).
            #[cfg(any(feature = "zether", feature = "pqz"))]
            object Confidential = crate::confidential::Confidential {
                #[cfg(feature = "zether")] async zether_key / zether_key_blocking (seed: String, account: u32) -> ZetherKeyInfo;
                #[cfg(feature = "zether")] async zether_balance / zether_balance_blocking (req: ZetherBalanceRequest) -> ZetherBalance;
                #[cfg(feature = "pqz")] async pqz_balance / pqz_balance_blocking (r: PqzBalanceRequest) -> PqzBalance;
                #[cfg(feature = "pqz")] async pqz_balance_all / pqz_balance_all_blocking (r: PqzBalanceRequest) -> PqzBalanceAll;
                #[cfg(feature = "pqz")] async prepare_pqz_shield / prepare_pqz_shield_blocking (r: PqzShield) -> Arc<Prepared>;
                #[cfg(feature = "pqz")] async prepare_pqz_wrap_shield / prepare_pqz_wrap_shield_blocking (r: PqzWrapShield) -> Arc<Prepared>;
                #[cfg(feature = "pqz")] async prepare_pqz_prepare_acc / prepare_pqz_prepare_acc_blocking (r: PqzAccountOp) -> Arc<Prepared>;
                #[cfg(feature = "pqz")] async prepare_pqz_roll_over / prepare_pqz_roll_over_blocking (r: PqzAccountOp) -> Arc<Prepared>;
                #[cfg(feature = "pqz")] async prepare_pqz_transfer / prepare_pqz_transfer_blocking (r: PqzTransfer) -> Arc<Prepared>;
                #[cfg(feature = "pqz")] async prepare_pqz_transfer_compact / prepare_pqz_transfer_compact_blocking (r: PqzTransfer) -> Arc<Prepared>;
                #[cfg(feature = "pqz")] async prepare_pqz_transfer_multi / prepare_pqz_transfer_multi_blocking (r: PqzTransferMulti) -> Arc<Prepared>;
                #[cfg(feature = "pqz")] async prepare_pqz_transfer_multi_compact / prepare_pqz_transfer_multi_compact_blocking (r: PqzTransferMulti) -> Arc<Prepared>;
                #[cfg(feature = "pqz")] async prepare_pqz_unshield / prepare_pqz_unshield_blocking (r: PqzUnshield) -> Arc<Prepared>;
                #[cfg(feature = "pqz")] async prepare_pqz_unshield_unwrap / prepare_pqz_unshield_unwrap_blocking (r: PqzUnshieldUnwrap) -> Arc<Prepared>;
                #[cfg(feature = "pqz")] async request_verdict / request_verdict_blocking (r: PqzVerdictRequest) -> Value;
                #[cfg(feature = "zether")] async prepare_zether_shield / prepare_zether_shield_blocking (r: ZetherShield) -> Arc<Prepared>;
                #[cfg(feature = "zether")] async prepare_zether_wrap_shield / prepare_zether_wrap_shield_blocking (r: ZetherWrapShield) -> Arc<Prepared>;
                #[cfg(feature = "zether")] async prepare_zether_roll_over / prepare_zether_roll_over_blocking (r: ZetherRollOver) -> Arc<Prepared>;
                #[cfg(feature = "zether")] async prepare_zether_roll_over_batch / prepare_zether_roll_over_batch_blocking (r: ZetherRollOverBatch) -> Arc<Prepared>;
                #[cfg(feature = "zether")] async prepare_zether_transfer / prepare_zether_transfer_blocking (r: ZetherTransfer) -> Arc<Prepared>;
                #[cfg(feature = "zether")] async prepare_zether_unshield / prepare_zether_unshield_blocking (r: ZetherUnshield) -> Arc<Prepared>;
                #[cfg(feature = "zether")] async prepare_zether_unshield_unwrap / prepare_zether_unshield_unwrap_blocking (r: ZetherUnshieldUnwrap) -> Arc<Prepared>;
                #[cfg(feature = "zether")] async prepare_zether_transfer_multi / prepare_zether_transfer_multi_blocking (r: ZetherTransferMulti) -> Arc<Prepared>;
                #[cfg(feature = "zether")] async prepare_zether_transfer_compact / prepare_zether_transfer_compact_blocking (r: ZetherTransferMulti) -> Arc<Prepared>;
                #[cfg(feature = "zether")] async prepare_zether_owner_roll_over / prepare_zether_owner_roll_over_blocking (r: ZetherOwnerRollOver) -> Arc<Prepared>;
                #[cfg(feature = "zether")] async prepare_zether_roll_over_signed / prepare_zether_roll_over_signed_blocking (r: ZetherOwnerRollOver, relay: OwnerRelay) -> Arc<Prepared>;
                #[cfg(feature = "zether")] async prepare_zether_owner_set_mode / prepare_zether_owner_set_mode_blocking (r: ZetherOwnerSetMode) -> Arc<Prepared>;
                #[cfg(feature = "zether")] async prepare_zether_set_roll_over_mode / prepare_zether_set_roll_over_mode_blocking (r: ZetherOwnerSetMode, relay: OwnerRelay) -> Arc<Prepared>;
            }
            /// The DEX (spec §10).
            #[cfg(feature = "dex")]
            object Dex = crate::dex::Dex {
                async markets / markets_blocking (chain: String) -> String;
                async depth / depth_blocking (chain: String, market: i64, levels: Option<u32>) -> String;
                async trades / trades_blocking (chain: String, market: i64) -> String;
                async ticker / ticker_blocking (chain: String, market: i64) -> String;
                async orders / orders_blocking (chain: String, maker: String) -> String;
                async prepare_trade_order / prepare_trade_order_blocking (req: TradeOrder) -> Arc<PreparedOrder>;
                async sign_order / sign_order_blocking (order: Arc<PreparedOrder>) -> SignedOrder;
                async place / place_blocking (order: Arc<PreparedOrder>) -> String;
                async cancel_all / cancel_all_blocking (req: CancelAll) -> String;
                async prepare_cancel_order / prepare_cancel_order_blocking (req: CancelOrder) -> Arc<Prepared>;
                async prepare_cancel_wrap_order / prepare_cancel_wrap_order_blocking (req: CancelWrapOrder) -> Arc<Prepared>;
                async prepare_wrap_order / prepare_wrap_order_blocking (req: WrapOrder) -> Arc<Prepared>;
                async prepare_liquidity_order / prepare_liquidity_order_blocking (req: LiquidityOrder) -> Arc<PreparedOrder>;
            }
            /// Governance and admin rows (spec §11).
            #[cfg(feature = "admin")]
            object Admin = crate::admin::Admin {
                async sign_rescue_vault / sign_rescue_vault_blocking (req: RescueVault) -> SignedRescue;
                async sign_pqz_auditor_consent / sign_pqz_auditor_consent_blocking (req: AuditorConsent) -> String;
                async sign_zether_auditor_consent / sign_zether_auditor_consent_blocking (req: AuditorConsent) -> String;
                async governance_delay / governance_delay_blocking (chain: String, token: String, bit: u16, holder: Option<HolderKind>) -> Vec<DelaySentence>;
                async admin_ua_grant_role / admin_ua_grant_role_blocking (req: UaGrantRole) -> Arc<Prepared>;
                async admin_ua_revoke_role / admin_ua_revoke_role_blocking (req: UaRevokeRole) -> Arc<Prepared>;
                async admin_ua_set_grant / admin_ua_set_grant_blocking (req: UaSetGrant) -> Arc<Prepared>;
                async admin_ua_cancel_grant / admin_ua_cancel_grant_blocking (req: UaCancelGrant) -> Arc<Prepared>;
                async admin_ua_disable_feature / admin_ua_disable_feature_blocking (req: UaDisableFeature) -> Arc<Prepared>;
                async admin_ua_transfer_admin / admin_ua_transfer_admin_blocking (req: UaTransferAdmin) -> Arc<Prepared>;
                async admin_ua_accept_admin / admin_ua_accept_admin_blocking (req: UaAcceptAdmin) -> Arc<Prepared>;
                async admin_ua_renounce_admin / admin_ua_renounce_admin_blocking (req: UaRenounceAdmin) -> Arc<Prepared>;
                async admin_ua_renounce_role / admin_ua_renounce_role_blocking (req: UaRenounceRole) -> Arc<Prepared>;
                async admin_ua_mint / admin_ua_mint_blocking (req: UaMint) -> Arc<Prepared>;
                async admin_ua_mint_to_ua / admin_ua_mint_to_ua_blocking (req: UaMintToUA) -> Arc<Prepared>;
                async admin_ua_disable_wrap / admin_ua_disable_wrap_blocking (req: UaDisableWrap) -> Arc<Prepared>;
                async admin_ua_propose_rate / admin_ua_propose_rate_blocking (req: UaProposeRate) -> Arc<Prepared>;
                async admin_ua_cancel_rate / admin_ua_cancel_rate_blocking (req: UaCancelRate) -> Arc<Prepared>;
                async admin_ua_execute_rate / admin_ua_execute_rate_blocking (req: UaExecuteRate) -> Arc<Prepared>;
                async admin_ua_set_market / admin_ua_set_market_blocking (req: UaSetMarket) -> Arc<Prepared>;
                async admin_ua_set_exchange_target / admin_ua_set_exchange_target_blocking (req: UaSetExchangeTarget) -> Arc<Prepared>;
                async admin_ua_set_listed_only / admin_ua_set_listed_only_blocking (req: UaSetListedOnly) -> Arc<Prepared>;
                async admin_ua_set_fee_split / admin_ua_set_fee_split_blocking (req: UaSetFeeSplit) -> Arc<Prepared>;
                async admin_ua_freeze / admin_ua_freeze_blocking (req: UaFreeze) -> Arc<Prepared>;
                async admin_ua_unfreeze / admin_ua_unfreeze_blocking (req: UaUnfreeze) -> Arc<Prepared>;
                async admin_ua_force_transfer / admin_ua_force_transfer_blocking (req: UaForceTransfer) -> Arc<Prepared>;
                async admin_ua_pause / admin_ua_pause_blocking (req: UaPause) -> Arc<Prepared>;
                async admin_ua_unpause / admin_ua_unpause_blocking (req: UaUnpause) -> Arc<Prepared>;
                async admin_ua_record_order / admin_ua_record_order_blocking (req: UaRecordOrder) -> Arc<Prepared>;
                async admin_ua_revoke_order / admin_ua_revoke_order_blocking (req: UaRevokeOrder) -> Arc<Prepared>;
                async admin_ua_operator_transfer / admin_ua_operator_transfer_blocking (req: UaOperatorTransfer) -> Arc<Prepared>;
                async admin_ua_set_tax_rate / admin_ua_set_tax_rate_blocking (req: UaSetTaxRate) -> Arc<Prepared>;
                async admin_ua_set_tax_recipient / admin_ua_set_tax_recipient_blocking (req: UaSetTaxRecipient) -> Arc<Prepared>;
                async admin_ua_pqz_set_verifier / admin_ua_pqz_set_verifier_blocking (req: UaPqzSetVerifier) -> Arc<Prepared>;
                async admin_ua_pqz_cancel_verifier / admin_ua_pqz_cancel_verifier_blocking (req: UaPqzCancelVerifier) -> Arc<Prepared>;
                async admin_ua_pqz_revoke_verifier / admin_ua_pqz_revoke_verifier_blocking (req: UaPqzRevokeVerifier) -> Arc<Prepared>;
                async admin_ua_set_proof_store / admin_ua_set_proof_store_blocking (req: UaSetProofStore) -> Arc<Prepared>;
                async admin_ua_set_auditor_key / admin_ua_set_auditor_key_blocking (req: UaSetAuditorKey) -> Arc<Prepared>;
                async admin_ua_set_auditor_ua / admin_ua_set_auditor_ua_blocking (req: UaSetAuditorUA) -> Arc<Prepared>;
                async admin_ua_set_verifier_fee / admin_ua_set_verifier_fee_blocking (req: UaSetVerifierFee) -> Arc<Prepared>;
                async admin_ua_set_wrap_limits / admin_ua_set_wrap_limits_blocking (req: UaSetWrapLimits) -> Arc<Prepared>;
                async admin_ua_set_wrap_member / admin_ua_set_wrap_member_blocking (req: UaSetWrapMember) -> Arc<Prepared>;
                async admin_ua_set_max_supply / admin_ua_set_max_supply_blocking (req: UaSetMaxSupply) -> Arc<Prepared>;
                async admin_ua_set_max_wrap_supply / admin_ua_set_max_wrap_supply_blocking (req: UaSetMaxWrapSupply) -> Arc<Prepared>;
                async admin_ua_set_allowed / admin_ua_set_allowed_blocking (req: UaSetAllowed) -> Arc<Prepared>;
                async admin_ua_set_denied / admin_ua_set_denied_blocking (req: UaSetDenied) -> Arc<Prepared>;
                async admin_ua_enable_feature / admin_ua_enable_feature_blocking (req: UaEnableFeature) -> Arc<Prepared>;
                async admin_ua_publish_token_env / admin_ua_publish_token_env_blocking (req: UaPublishTokenEnv) -> Arc<Prepared>;
                async admin_ua_publish_dex_env / admin_ua_publish_dex_env_blocking (req: UaPublishDexEnv) -> Arc<Prepared>;
                async admin_ua_publish_class_env / admin_ua_publish_class_env_blocking (req: UaPublishClassEnv) -> Arc<Prepared>;
                async admin_ua_deprecate_token / admin_ua_deprecate_token_blocking (req: UaDeprecateToken) -> Arc<Prepared>;
                async admin_ua_deprecate_dex / admin_ua_deprecate_dex_blocking (req: UaDeprecateDex) -> Arc<Prepared>;
                async admin_ua_deprecate_release / admin_ua_deprecate_release_blocking (req: UaDeprecateRelease) -> Arc<Prepared>;
                async admin_ua_set_token_kind_enabled / admin_ua_set_token_kind_enabled_blocking (req: UaSetTokenKindEnabled) -> Arc<Prepared>;
                async admin_ua_set_class_kind_enabled / admin_ua_set_class_kind_enabled_blocking (req: UaSetClassKindEnabled) -> Arc<Prepared>;
                async admin_ua_set_kyc_provider / admin_ua_set_kyc_provider_blocking (req: UaSetKycProvider) -> Arc<Prepared>;
                async admin_ua_set_compliance / admin_ua_set_compliance_blocking (req: UaSetCompliance) -> Arc<Prepared>;
                async admin_ua_create_token / admin_ua_create_token_blocking (req: UaCreateToken) -> Arc<Prepared>;
                async admin_ua_create_dex / admin_ua_create_dex_blocking (req: UaCreateDex) -> Arc<Prepared>;
                async admin_ua_create_instance / admin_ua_create_instance_blocking (req: UaCreateInstance) -> Arc<Prepared>;
                async admin_ua_set_chain_entries / admin_ua_set_chain_entries_blocking (req: UaSetChainEntries) -> Arc<Prepared>;
                async admin_ua_approve_token_release / admin_ua_approve_token_release_blocking (req: UaApproveTokenRelease) -> Arc<Prepared>;
                async admin_ua_approve_dex_release / admin_ua_approve_dex_release_blocking (req: UaApproveDexRelease) -> Arc<Prepared>;
                async admin_ua_approve_release / admin_ua_approve_release_blocking (req: UaApproveRelease) -> Arc<Prepared>;
                async admin_ua_revoke_approval / admin_ua_revoke_approval_blocking (req: UaRevokeApproval) -> Arc<Prepared>;
                async admin_ua_cancel_nonce / admin_ua_cancel_nonce_blocking (req: UaCancelNonce) -> Arc<Prepared>;
            }
        }
    };
}
pub(crate) use binding_list;
