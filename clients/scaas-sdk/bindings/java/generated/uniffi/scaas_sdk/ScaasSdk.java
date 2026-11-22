package uniffi.scaas_sdk;


import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
public class ScaasSdk {
  
    /**
     * The account rows' JSON (the keystore's form).
     */public static java.lang.String accountsJson(java.util.List<AccountRow> rows)  {
            try {
                return FfiConverterString.INSTANCE.lift(
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_accounts_json(_allocator, 
            FfiConverterSequenceTypeAccountRow.INSTANCE.lower(rows), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * The binding surface's version this library was built with (spec §16.3).
     */public static int apiVersion()  {
            try {
                return 
    UniffiHelpers.uniffiRustCallInt( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_api_version(
            _status);
    })
    ;
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * This library's feature bits (spec §3.3).
     */public static long features()  {
            try {
                return 
    UniffiHelpers.uniffiRustCallLong( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_features(
            _status);
    })
    ;
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * No gas rows.
     */public static GasRows gasRowsDefault()  {
            try {
                return FfiConverterTypeGasRows.INSTANCE.lift(
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_gas_rows_default(_allocator, 
            _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * A gas table file (spec §13.3), parsed and checked.
     */public static GasTable gasTableParse(java.lang.String text) throws SdkException {
            try {
                return FfiConverterTypeGasTable.INSTANCE.lift(
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_gas_table_parse(_allocator, 
            FfiConverterString.INSTANCE.lower(text), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                if (SdkException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (SdkException)_uniffi_ex.getCause();
                }
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * Whether `s` is a UUID v4 (a seed's or an account's id).
     */public static boolean isUuid4(java.lang.String s)  {
            try {
                return FfiConverterBoolean.INSTANCE.lift(
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_is_uuid4(
            FfiConverterString.INSTANCE.lower(s), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * Whether `label` is a valid seed label (spec §6.1).
     */public static boolean labelOk(java.lang.String label)  {
            try {
                return FfiConverterBoolean.INSTANCE.lift(
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_label_ok(
            FfiConverterString.INSTANCE.lower(label), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * The default limits (spec §4).
     */public static Limits limitsDefault()  {
            try {
                return FfiConverterTypeLimits.INSTANCE.lift(
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_limits_default(_allocator, 
            _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * An `msig` structure: members sorted by id, the threshold checked (spec §7).
     */public static MsigStructureArgs msigStructure(java.util.List<MsigMemberArgs> members, short threshold) throws SdkException {
            try {
                return FfiConverterTypeMsigStructureArgs.INSTANCE.lift(
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_msig_structure(_allocator, 
            FfiConverterSequenceTypeMsigMemberArgs.INSTANCE.lower(members), threshold, _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                if (SdkException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (SdkException)_uniffi_ex.getCause();
                }
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * An `msig` structure's UA.
     */public static java.lang.String msigStructureUa(MsigStructureArgs args) throws SdkException {
            try {
                return FfiConverterString.INSTANCE.lift(
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_msig_structure_ua(_allocator, 
            FfiConverterTypeMsigStructureArgs.INSTANCE.lower(args), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                if (SdkException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (SdkException)_uniffi_ex.getCause();
                }
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * Whether `label` is a valid new seed label (NFC, spec §6.1).
     */public static boolean newLabelOk(java.lang.String label)  {
            try {
                return FfiConverterBoolean.INSTANCE.lift(
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_new_label_ok(
            FfiConverterString.INSTANCE.lower(label), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * Whether an operation's state is final.
     */public static boolean opStateIsTerminal(OpState state)  {
            try {
                return FfiConverterBoolean.INSTANCE.lift(
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_op_state_is_terminal(
            FfiConverterTypeOpState.INSTANCE.lower(state), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * Opens the SDK (spec §4) over the app's store and authenticator, on the SDK's own runtime. `AbiMismatch` is the binding's
     * load check (spec §16.3), run before this.
     */public static java.util.concurrent.CompletableFuture<Sdk> open(BindingConfig config, ForeignStore store, ForeignAuthenticator authenticator){
        return open(config, store, authenticator, java.util.concurrent.ForkJoinPool.commonPool());
    }public static java.util.concurrent.CompletableFuture<Sdk> open(BindingConfig config, ForeignStore store, ForeignAuthenticator authenticator, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        UniffiLib.uniffi_scaas_sdk_fn_func_open(FfiConverterTypeBindingConfig.INSTANCE.lower(config), FfiConverterTypeForeignStore.INSTANCE.lower(store), FfiConverterOptionalTypeForeignAuthenticator.INSTANCE.lower(authenticator)),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypeSdk.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    /**
     * No registration attributes (no PQZ key, no KEM key).
     */public static RegisterAttrs registerAttrsDefault()  {
            try {
                return FfiConverterTypeRegisterAttrs.INSTANCE.lift(
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_register_attrs_default(_allocator, 
            _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * A registration blob from its JSON (spec §7.1).
     */public static RegistrationBlob registrationBlobFromJson(java.lang.String text) throws SdkException {
            try {
                return FfiConverterTypeRegistrationBlob.INSTANCE.lift(
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_registration_blob_from_json(_allocator, 
            FfiConverterString.INSTANCE.lower(text), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                if (SdkException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (SdkException)_uniffi_ex.getCause();
                }
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * A registration blob's JSON (spec §7.1).
     */public static java.lang.String registrationBlobToJson(RegistrationBlob blob) throws SdkException {
            try {
                return FfiConverterString.INSTANCE.lift(
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_registration_blob_to_json(_allocator, 
            FfiConverterTypeRegistrationBlob.INSTANCE.lower(blob), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                if (SdkException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (SdkException)_uniffi_ex.getCause();
                }
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * The revision of an item's bytes: its top-level JSON `rev`, else `u64::MAX`.
     */public static long revOf(byte[] bytes)  {
            try {
                return 
    UniffiHelpers.uniffiRustCallLong( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_rev_of(
            FfiConverterByteArray.INSTANCE.lower(bytes), _status);
    })
    ;
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * A secret's id for the C copy calls.
     */public static long secretId(SecretBytes s)  {
            try {
                return 
    UniffiHelpers.uniffiRustCallLong( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_secret_id(
            FfiConverterTypeSecretBytes.INSTANCE.lower(s), _status);
    })
    ;
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * A secret's length in bytes.
     */public static int secretLen(SecretBytes s)  {
            try {
                return 
    UniffiHelpers.uniffiRustCallInt( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_secret_len(
            FfiConverterTypeSecretBytes.INSTANCE.lower(s), _status);
    })
    ;
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * A new secret of `len` zero bytes (16 MiB at most); its bytes move only through the C copy calls by [`secret_id`].
     */public static SecretBytes secretNew(int len) throws SdkException {
            try {
                return FfiConverterTypeSecretBytes.INSTANCE.lift(
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_secret_new(
            len, _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                if (SdkException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (SdkException)_uniffi_ex.getCause();
                }
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * A signed operation's hand-off blob from its JSON (spec §27.5 (c)).
     */public static SignedOpBlob signedOpBlobFromJson(java.lang.String text) throws SdkException {
            try {
                return FfiConverterTypeSignedOpBlob.INSTANCE.lift(
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_signed_op_blob_from_json(_allocator, 
            FfiConverterString.INSTANCE.lower(text), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                if (SdkException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (SdkException)_uniffi_ex.getCause();
                }
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * A hand-off blob's JSON (spec §27.5 (c)).
     */public static java.lang.String signedOpBlobToJson(SignedOpBlob blob) throws SdkException {
            try {
                return FfiConverterString.INSTANCE.lift(
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_signed_op_blob_to_json(_allocator, 
            FfiConverterTypeSignedOpBlob.INSTANCE.lower(blob), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                if (SdkException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (SdkException)_uniffi_ex.getCause();
                }
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * A `SmartKeyAccount`'s address before its deployment (spec §7).
     */public static java.lang.String smartAccountAddress(java.lang.String factory, java.lang.String implementation, SubjectKeyArgs firstKey, java.lang.String guardian) throws SdkException {
            try {
                return FfiConverterString.INSTANCE.lift(
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_smart_account_address(_allocator, 
            FfiConverterString.INSTANCE.lower(factory), FfiConverterString.INSTANCE.lower(implementation), FfiConverterTypeSubjectKeyArgs.INSTANCE.lower(firstKey), FfiConverterString.INSTANCE.lower(guardian), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                if (SdkException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (SdkException)_uniffi_ex.getCause();
                }
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * The default store policy of an item (spec §6.9).
     */public static StorePolicy storePolicyDefault()  {
            try {
                return FfiConverterTypeStorePolicy.INSTANCE.lift(
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_store_policy_default(_allocator, 
            _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * A secp256k1 subject key from its address.
     */public static SubjectKeyArgs subjectKeyArgsSecp256k1(java.lang.String address) throws SdkException {
            try {
                return FfiConverterTypeSubjectKeyArgs.INSTANCE.lift(
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_subject_key_args_secp256k1(_allocator, 
            FfiConverterString.INSTANCE.lower(address), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                if (SdkException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (SdkException)_uniffi_ex.getCause();
                }
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * The target of a key write of the UA (`UaLine::key_target`, §12): its holder.
     */public static java.lang.String uaLineKeyTarget(UaLine line)  {
            try {
                return FfiConverterString.INSTANCE.lift(
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_ua_line_key_target(_allocator, 
            FfiConverterTypeUaLine.INSTANCE.lower(line), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  
    /**
     * The target of a PQZ write of the UA (`UaLine::pqz_target`, §12): its PQZ home; `PqzHomeNone` where the walk has none.
     */public static java.lang.String uaLinePqzTarget(UaLine line) throws SdkException {
            try {
                return FfiConverterString.INSTANCE.lift(
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_func_ua_line_pqz_target(_allocator, 
            FfiConverterTypeUaLine.INSTANCE.lower(line), _status);
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                if (SdkException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (SdkException)_uniffi_ex.getCause();
                }
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

}

