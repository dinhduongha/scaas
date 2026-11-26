package uniffi.scaas_sdk;


final class NamespaceLibrary {
    static synchronized String findLibraryName(String componentName) {
        String libOverride = System.getProperty("uniffi.component." + componentName + ".libraryOverride");
        if (libOverride != null) {
            return libOverride;
        }
        return "scaas_sdk_ffi";
    }

    static java.lang.foreign.SymbolLookup loadLibrary() {
        String name = findLibraryName("scaas_sdk");
        if (name.startsWith("/") // Unix absolute path
                || name.startsWith("\\\\") // Windows UNC path
                || (name.length() > 2 && name.charAt(1) == ':')) // Windows drive path (e.g. C:\)
        {
            System.load(name);
        } else {
            System.loadLibrary(name);
        }
        return java.lang.foreign.SymbolLookup.loaderLookup();
    }

    static void uniffiCheckContractApiVersion() {
        int bindingsContractVersion = 30;
        int scaffoldingContractVersion = UniffiLib.ffi_scaas_sdk_uniffi_contract_version();
        if (bindingsContractVersion != scaffoldingContractVersion) {
            throw new RuntimeException("UniFFI contract version mismatch: try cleaning and rebuilding your project");
        }
    }
    static void uniffiCheckApiChecksums() {
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_accounts_json() != ((short) 19917)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_api_version() != ((short) 34391)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_features() != ((short) 2727)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_gas_rows_default() != ((short) 10931)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_gas_table_parse() != ((short) 32837)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_is_uuid4() != ((short) 36740)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_label_ok() != ((short) 33971)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_limits_default() != ((short) 40089)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_msig_structure() != ((short) 10986)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_msig_structure_ua() != ((short) 56327)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_new_label_ok() != ((short) 42888)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_op_state_is_terminal() != ((short) 39308)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_open() != ((short) 20993)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_register_attrs_default() != ((short) 65161)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_registration_blob_from_json() != ((short) 22501)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_registration_blob_to_json() != ((short) 5195)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_rev_of() != ((short) 58940)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_secret_id() != ((short) 27399)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_secret_len() != ((short) 20677)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_secret_new() != ((short) 26347)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_signed_op_blob_from_json() != ((short) 43577)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_signed_op_blob_to_json() != ((short) 49602)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_smart_account_address() != ((short) 22486)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_store_policy_default() != ((short) 49095)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_subject_key_args_secp256k1() != ((short) 20622)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_ua_line_key_target() != ((short) 60856)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_func_ua_line_pqz_target() != ((short) 29446)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_registrywrite_calldata() != ((short) 7040)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_registrywrite_chain() != ((short) 41334)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_registrywrite_entry() != ((short) 40467)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_registrywrite_id() != ((short) 10055)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_registrywrite_payer() != ((short) 40740)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_registrywrite_registration_gas() != ((short) 6697)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_registrywrite_review() != ((short) 57538)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_registrywrite_ua() != ((short) 49442)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_accounts() != ((short) 44679)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_add_native() != ((short) 12150)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_add_ua() != ((short) 52581)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_add_watch() != ((short) 34206)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_create_passkey_key() != ((short) 59069)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_create_se_key() != ((short) 56282)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_marks() != ((short) 5356)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_msig_state() != ((short) 50219)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_next_account() != ((short) 28699)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_pqz_decoy_candidates() != ((short) 49782)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_accept_membership() != ((short) 50844)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_complete_recovery() != ((short) 42468)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_initiate_recovery() != ((short) 13971)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_kem_repair() != ((short) 27628)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_msig_register() != ((short) 28431)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_register() != ((short) 55685)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_set_kem_key() != ((short) 57031)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_smart_add_key() != ((short) 63709)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_smart_cancel_nonce() != ((short) 45340)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_smart_cancel_recovery() != ((short) 60438)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_smart_deploy() != ((short) 49247)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_smart_execute() != ((short) 30602)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_smart_remove_key() != ((short) 21776)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_smart_rotate_key() != ((short) 39777)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_smart_set_guardian() != ((short) 63662)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_submit_registration() != ((short) 8777)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_prepare_update_msig() != ((short) 56707)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_quote_registry_write() != ((short) 20576)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_register_target() != ((short) 38916)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_registration_blob() != ((short) 44041)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_registration_of() != ((short) 3989)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_restore() != ((short) 54884)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_signs() != ((short) 33018)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_submit_registry_write() != ((short) 40795)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_account_ua_line() != ((short) 3220)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_accept_admin() != ((short) 54249)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_dex_release() != ((short) 10230)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_release() != ((short) 39167)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_token_release() != ((short) 8898)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_grant() != ((short) 48751)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_nonce() != ((short) 48105)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_nonce_for() != ((short) 20110)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_rate() != ((short) 38309)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_dex() != ((short) 41403)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_instance() != ((short) 46504)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_token() != ((short) 5350)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_dex() != ((short) 1043)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_release() != ((short) 22212)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_token() != ((short) 18802)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_disable_feature() != ((short) 61764)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_disable_wrap() != ((short) 10593)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_enable_feature() != ((short) 57431)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_execute_rate() != ((short) 9664)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_force_transfer() != ((short) 40247)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_freeze() != ((short) 58766)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_grant_role() != ((short) 2079)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_mint() != ((short) 51979)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_mint_to_ua() != ((short) 62178)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_operator_transfer() != ((short) 16398)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_pause() != ((short) 2042)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_cancel_verifier() != ((short) 62967)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_revoke_verifier() != ((short) 58285)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_set_verifier() != ((short) 51198)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_propose_rate() != ((short) 41845)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_class_env() != ((short) 38595)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_dex_env() != ((short) 17034)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_token_env() != ((short) 12922)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_record_order() != ((short) 51417)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_renounce_admin() != ((short) 31034)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_renounce_role() != ((short) 28231)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_approval() != ((short) 10694)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_order() != ((short) 53962)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_role() != ((short) 33162)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_allowed() != ((short) 24815)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_auditor_key() != ((short) 45885)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_auditor_ua() != ((short) 11024)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_chain_entries() != ((short) 12947)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_class_kind_enabled() != ((short) 32245)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_compliance() != ((short) 30905)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_denied() != ((short) 25199)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_exchange_target() != ((short) 19396)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_fee_split() != ((short) 3481)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_grant() != ((short) 49207)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_kyc_provider() != ((short) 55021)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_listed_only() != ((short) 45056)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_market() != ((short) 24100)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_max_supply() != ((short) 54643)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_max_wrap_supply() != ((short) 23392)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_proof_store() != ((short) 31913)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_tax_rate() != ((short) 64833)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_tax_recipient() != ((short) 30913)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_token_kind_enabled() != ((short) 56306)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_verifier_fee() != ((short) 34067)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_wrap_limits() != ((short) 40520)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_wrap_member() != ((short) 37505)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_transfer_admin() != ((short) 13036)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_unfreeze() != ((short) 24740)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_admin_ua_unpause() != ((short) 15496)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_create3_address() != ((short) 27184)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_governance_delay() != ((short) 64722)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_sign_pqz_auditor_consent() != ((short) 60535)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_sign_rescue_vault() != ((short) 43593)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_admin_sign_zether_auditor_consent() != ((short) 37655)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_pqz_balance() != ((short) 484)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_pqz_balance_all() != ((short) 48493)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_prepare_acc() != ((short) 32978)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_roll_over() != ((short) 48040)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_shield() != ((short) 32576)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer() != ((short) 50550)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_compact() != ((short) 21553)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_multi() != ((short) 24534)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_multi_compact() != ((short) 17661)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_unshield() != ((short) 50012)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_unshield_unwrap() != ((short) 49206)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_wrap_shield() != ((short) 9875)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_owner_roll_over() != ((short) 57236)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_owner_set_mode() != ((short) 22389)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over() != ((short) 6527)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over_batch() != ((short) 19372)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over_signed() != ((short) 58259)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_set_roll_over_mode() != ((short) 62087)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_shield() != ((short) 26147)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer() != ((short) 37591)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer_compact() != ((short) 37693)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer_multi() != ((short) 52426)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_unshield() != ((short) 62213)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_unshield_unwrap() != ((short) 13879)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_wrap_shield() != ((short) 22002)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_request_verdict() != ((short) 36043)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_zether_balance() != ((short) 55337)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_confidential_zether_key() != ((short) 57834)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_cancel_all() != ((short) 54752)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_depth() != ((short) 39012)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_markets() != ((short) 22708)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_orders() != ((short) 27424)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_place() != ((short) 49277)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_prepare_cancel_order() != ((short) 39441)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_prepare_cancel_wrap_order() != ((short) 12323)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_prepare_liquidity_order() != ((short) 53973)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_prepare_trade_order() != ((short) 2804)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_prepare_wrap_order() != ((short) 63215)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_sign_order() != ((short) 4336)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_ticker() != ((short) 3090)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_dex_trades() != ((short) 31897)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_foreignauthenticator_create_passkey() != ((short) 14769)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_foreignauthenticator_get_assertion() != ((short) 16153)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_foreignauthenticator_platform_secret() != ((short) 25032)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_foreignauthenticator_p256_generate() != ((short) 21302)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_foreignauthenticator_p256_sign() != ((short) 45943)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_foreignstore_get() != ((short) 59252)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_foreignstore_put_if() != ((short) 32664)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_foreignstore_delete() != ((short) 12174)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_foreignstore_lock() != ((short) 58987)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_foreignstore_unlock() != ((short) 44840)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_bls_multi_part() != ((short) 62133)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_bls_multi_part_ok() != ((short) 62102)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_bls_multi_pop_part() != ((short) 56760)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_bls_multi_pop_part_ok() != ((short) 1443)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_hand_off() != ((short) 2688)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_import_signed() != ((short) 37279)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_member_sign() != ((short) 30667)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_quote() != ((short) 16358)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_quote_register_bls_multi() != ((short) 14540)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_quote_with_gas() != ((short) 30578)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_register_bls_multi() != ((short) 57695)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_resend() != ((short) 18971)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_resume() != ((short) 6435)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_state() != ((short) 3893)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_submit() != ((short) 38006)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_op_submit_bls_multi() != ((short) 27762)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_sdk_account() != ((short) 4122)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_sdk_admin() != ((short) 6895)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_sdk_confidential() != ((short) 20051)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_sdk_dex() != ((short) 11988)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_sdk_limits() != ((short) 28914)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_sdk_op() != ((short) 23915)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_sdk_state_rev() != ((short) 41622)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_sdk_subscribe() != ((short) 50230)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_sdk_vault() != ((short) 47802)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_sdk_wallet() != ((short) 61223)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_sdk_watch() != ((short) 24897)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_subscription_next() != ((short) 46941)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_accept_rollback() != ((short) 51021)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_change_passphrase() != ((short) 63580)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_confirm_backup() != ((short) 1424)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_derive_child() != ((short) 2120)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_derive_from_key() != ((short) 59484)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_derive_from_signature() != ((short) 23563)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_disable_prf_unlock() != ((short) 57962)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_enable_passkey_unlock() != ((short) 25572)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_enable_platform_unlock() != ((short) 20819)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_generate() != ((short) 48629)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_import_key() != ((short) 51962)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_import_words() != ((short) 55937)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_key_derivation_typed_data() != ((short) 65074)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_keystore_rollback() != ((short) 2571)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_lock() != ((short) 6366)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_lock_all() != ((short) 17781)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_memory_protection() != ((short) 33961)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_open_hidden() != ((short) 52823)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_remove() != ((short) 29815)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_rename() != ((short) 57815)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_seed() != ((short) 398)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_seeds() != ((short) 24242)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_signature_from_compact() != ((short) 23931)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_unlock() != ((short) 7239)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_vault_word_in_list() != ((short) 54946)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_balances() != ((short) 21473)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_history() != ((short) 49308)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_native_address() != ((short) 63834)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_add_reserve() != ((short) 12179)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_burn() != ((short) 67)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_cancel_nonce() != ((short) 49272)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_delegate_revoke() != ((short) 23531)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_execute() != ((short) 52236)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_native_send() != ((short) 45223)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_pay() != ((short) 42397)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_pay_under_mandate() != ((short) 10015)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_pay_with_tax() != ((short) 29249)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_payee_fee() != ((short) 46083)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_relay_fee() != ((short) 20519)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_revoke_mandate() != ((short) 48384)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_set_mandate() != ((short) 36323)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_set_payee() != ((short) 13925)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_transfer() != ((short) 45946)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap() != ((short) 57827)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap_leg() != ((short) 40563)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap_to_ua() != ((short) 59872)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap() != ((short) 32644)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap_leg() != ((short) 39046)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap_to_ua() != ((short) 61311)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_submit_native_send() != ((short) 10412)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_wallet_tokens() != ((short) 2224)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_preparedorder_chain() != ((short) 63561)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_preparedorder_id() != ((short) 29042)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_preparedorder_review() != ((short) 34494)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_preparedorder_signer() != ((short) 48042)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_prepared_chain() != ((short) 53667)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_prepared_entry() != ((short) 41890)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_prepared_expires_at() != ((short) 37608)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_prepared_id() != ((short) 41875)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_prepared_opaque() != ((short) 22691)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_prepared_review() != ((short) 44659)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_prepared_signer() != ((short) 9876)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_seedbackup_challenge() != ((short) 21191)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_seedbackup_reveal() != ((short) 3344)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
        if (UniffiLib.uniffi_scaas_sdk_checksum_method_seedbackup_verify() != ((short) 53176)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
    }
}

// Define FFI callback types
