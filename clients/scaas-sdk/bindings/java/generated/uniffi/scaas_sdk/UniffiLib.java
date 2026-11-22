package uniffi.scaas_sdk;


// FFM-based library binding. Each FFI function gets a MethodHandle and a wrapper method.
final class UniffiLib {
    private static final java.lang.foreign.Linker LINKER = java.lang.foreign.Linker.nativeLinker();
    private static final java.lang.foreign.SymbolLookup SYMBOLS;

    
    // The Cleaner for the whole library
    static UniffiCleaner CLEANER;

    static {
        SYMBOLS = NamespaceLibrary.loadLibrary();
    }

    private static java.lang.invoke.MethodHandle findDowncallHandle(String name, java.lang.foreign.FunctionDescriptor descriptor) {
        return SYMBOLS.find(name)
            .map(s -> LINKER.downcallHandle(s, descriptor))
            .orElseThrow(() -> new RuntimeException("Missing FFI symbol: " + name));
    }

    // uniffi_scaas_sdk_fn_clone_registrywrite
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_registrywrite = findDowncallHandle("uniffi_scaas_sdk_fn_clone_registrywrite", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_registrywrite(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_registrywrite.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_registrywrite
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_registrywrite = findDowncallHandle("uniffi_scaas_sdk_fn_free_registrywrite", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_registrywrite(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_registrywrite.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_registrywrite_calldata
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_registrywrite_calldata = findDowncallHandle("uniffi_scaas_sdk_fn_method_registrywrite_calldata", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_registrywrite_calldata(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_registrywrite_calldata.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_registrywrite_chain
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_registrywrite_chain = findDowncallHandle("uniffi_scaas_sdk_fn_method_registrywrite_chain", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_registrywrite_chain(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_registrywrite_chain.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_registrywrite_entry
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_registrywrite_entry = findDowncallHandle("uniffi_scaas_sdk_fn_method_registrywrite_entry", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_registrywrite_entry(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_registrywrite_entry.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_registrywrite_id
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_registrywrite_id = findDowncallHandle("uniffi_scaas_sdk_fn_method_registrywrite_id", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_registrywrite_id(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_registrywrite_id.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_registrywrite_payer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_registrywrite_payer = findDowncallHandle("uniffi_scaas_sdk_fn_method_registrywrite_payer", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_registrywrite_payer(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_registrywrite_payer.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_registrywrite_registration_gas
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_registrywrite_registration_gas = findDowncallHandle("uniffi_scaas_sdk_fn_method_registrywrite_registration_gas", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_registrywrite_registration_gas(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_registrywrite_registration_gas.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_registrywrite_review
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_registrywrite_review = findDowncallHandle("uniffi_scaas_sdk_fn_method_registrywrite_review", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_registrywrite_review(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_registrywrite_review.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_registrywrite_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_registrywrite_ua = findDowncallHandle("uniffi_scaas_sdk_fn_method_registrywrite_ua", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_registrywrite_ua(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_registrywrite_ua.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_account
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_account = findDowncallHandle("uniffi_scaas_sdk_fn_clone_account", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_account(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_account.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_account
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_account = findDowncallHandle("uniffi_scaas_sdk_fn_free_account", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_account(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_account.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_accounts
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_accounts = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_accounts", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_accounts(long ptr, java.lang.foreign.MemorySegment seed) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_accounts.invokeExact(ptr, seed);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_add_native
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_add_native = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_add_native", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_add_native(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_add_native.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_add_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_add_ua = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_add_ua", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_add_ua(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_add_ua.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_add_watch
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_add_watch = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_add_watch", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_add_watch(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_add_watch.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_create_passkey_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_create_passkey_key = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_create_passkey_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_create_passkey_key(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_create_passkey_key.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_create_se_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_create_se_key = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_create_se_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_create_se_key(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_create_se_key.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_marks
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_marks = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_marks", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_marks(long ptr, java.lang.foreign.MemorySegment seed, java.lang.foreign.MemorySegment chain) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_marks.invokeExact(ptr, seed, chain);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_msig_state
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_msig_state = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_msig_state", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_msig_state(long ptr, java.lang.foreign.MemorySegment chain, java.lang.foreign.MemorySegment ua) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_msig_state.invokeExact(ptr, chain, ua);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_next_account
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_next_account = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_next_account", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_next_account(long ptr, java.lang.foreign.MemorySegment seed) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_next_account.invokeExact(ptr, seed);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_pqz_decoy_candidates
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_pqz_decoy_candidates = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_pqz_decoy_candidates", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_pqz_decoy_candidates(long ptr, java.lang.foreign.MemorySegment chain) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_pqz_decoy_candidates.invokeExact(ptr, chain);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_accept_membership
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_accept_membership = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_accept_membership", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_accept_membership(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_accept_membership.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_complete_recovery
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_complete_recovery = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_complete_recovery", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_complete_recovery(long ptr, java.lang.foreign.MemorySegment key, java.lang.foreign.MemorySegment chain, java.lang.foreign.MemorySegment account, java.lang.foreign.MemorySegment newKey) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_complete_recovery.invokeExact(ptr, key, chain, account, newKey);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_initiate_recovery
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_initiate_recovery = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_initiate_recovery", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_initiate_recovery(long ptr, java.lang.foreign.MemorySegment op, java.lang.foreign.MemorySegment account, java.lang.foreign.MemorySegment newKey) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_initiate_recovery.invokeExact(ptr, op, account, newKey);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_kem_repair
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_kem_repair = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_kem_repair", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_kem_repair(long ptr, java.lang.foreign.MemorySegment key, java.lang.foreign.MemorySegment chain, java.lang.foreign.MemorySegment payer) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_kem_repair.invokeExact(ptr, key, chain, payer);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_msig_register
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_msig_register = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_msig_register", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_msig_register(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_msig_register.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_register
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_register = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_register", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_register(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_register.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_set_kem_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_set_kem_key = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_set_kem_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_set_kem_key(long ptr, java.lang.foreign.MemorySegment key, java.lang.foreign.MemorySegment chain, long version, java.lang.foreign.MemorySegment payer) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_set_kem_key.invokeExact(ptr, key, chain, version, payer);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_smart_add_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_add_key = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_smart_add_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_smart_add_key(long ptr, java.lang.foreign.MemorySegment op, java.lang.foreign.MemorySegment key) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_add_key.invokeExact(ptr, op, key);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_smart_cancel_nonce
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_cancel_nonce = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_smart_cancel_nonce", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_smart_cancel_nonce(long ptr, java.lang.foreign.MemorySegment op, java.lang.foreign.MemorySegment lane) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_cancel_nonce.invokeExact(ptr, op, lane);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_smart_cancel_recovery
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_cancel_recovery = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_smart_cancel_recovery", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_smart_cancel_recovery(long ptr, java.lang.foreign.MemorySegment op) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_cancel_recovery.invokeExact(ptr, op);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_smart_deploy
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_deploy = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_smart_deploy", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_smart_deploy(long ptr, java.lang.foreign.MemorySegment key, java.lang.foreign.MemorySegment chain, java.lang.foreign.MemorySegment factory, java.lang.foreign.MemorySegment firstKey, java.lang.foreign.MemorySegment guardian) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_deploy.invokeExact(ptr, key, chain, factory, firstKey, guardian);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_smart_execute
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_execute = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_smart_execute", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_smart_execute(long ptr, java.lang.foreign.MemorySegment op, java.lang.foreign.MemorySegment call) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_execute.invokeExact(ptr, op, call);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_smart_remove_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_remove_key = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_smart_remove_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_smart_remove_key(long ptr, java.lang.foreign.MemorySegment op, java.lang.foreign.MemorySegment index) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_remove_key.invokeExact(ptr, op, index);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_smart_rotate_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_rotate_key = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_smart_rotate_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_smart_rotate_key(long ptr, java.lang.foreign.MemorySegment op, java.lang.foreign.MemorySegment index, java.lang.foreign.MemorySegment key) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_rotate_key.invokeExact(ptr, op, index, key);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_smart_set_guardian
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_set_guardian = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_smart_set_guardian", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_smart_set_guardian(long ptr, java.lang.foreign.MemorySegment op, java.lang.foreign.MemorySegment guardian) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_smart_set_guardian.invokeExact(ptr, op, guardian);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_submit_registration
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_submit_registration = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_submit_registration", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_submit_registration(long ptr, java.lang.foreign.MemorySegment blob, java.lang.foreign.MemorySegment chain, java.lang.foreign.MemorySegment expectedUa, java.lang.foreign.MemorySegment payer) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_submit_registration.invokeExact(ptr, blob, chain, expectedUa, payer);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_prepare_update_msig
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_prepare_update_msig = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_prepare_update_msig", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_prepare_update_msig(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_prepare_update_msig.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_quote_registry_write
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_quote_registry_write = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_quote_registry_write", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_account_quote_registry_write(long ptr, long write) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_quote_registry_write.invokeExact(ptr, write);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_register_target
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_register_target = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_register_target", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_SHORT));

    static long uniffi_scaas_sdk_fn_method_account_register_target(long ptr, java.lang.foreign.MemorySegment chain, short kind) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_register_target.invokeExact(ptr, chain, kind);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_registration_blob
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_registration_blob = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_registration_blob", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_registration_blob(long ptr, java.lang.foreign.MemorySegment key, java.lang.foreign.MemorySegment attrs) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_registration_blob.invokeExact(ptr, key, attrs);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_registration_of
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_registration_of = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_registration_of", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_registration_of(long ptr, java.lang.foreign.MemorySegment chain, java.lang.foreign.MemorySegment ua) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_registration_of.invokeExact(ptr, chain, ua);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_restore
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_restore = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_restore", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_restore(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_restore.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_signs
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_signs = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_signs", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_signs(long ptr, java.lang.foreign.MemorySegment seed, java.lang.foreign.MemorySegment id) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_signs.invokeExact(ptr, seed, id);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_submit_registry_write
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_submit_registry_write = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_submit_registry_write", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_submit_registry_write(long ptr, long write, java.lang.foreign.MemorySegment quote) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_submit_registry_write.invokeExact(ptr, write, quote);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_account_ua_line
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_account_ua_line = findDowncallHandle("uniffi_scaas_sdk_fn_method_account_ua_line", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_account_ua_line(long ptr, java.lang.foreign.MemorySegment chain, java.lang.foreign.MemorySegment ua) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_account_ua_line.invokeExact(ptr, chain, ua);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_admin
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_admin = findDowncallHandle("uniffi_scaas_sdk_fn_clone_admin", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_admin(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_admin.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_admin
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_admin = findDowncallHandle("uniffi_scaas_sdk_fn_free_admin", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_admin(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_admin.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_accept_admin
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_accept_admin = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_accept_admin", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_accept_admin(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_accept_admin.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_dex_release
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_dex_release = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_dex_release", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_dex_release(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_dex_release.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_release
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_release = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_release", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_release(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_release.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_token_release
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_token_release = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_token_release", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_token_release(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_token_release.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_grant
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_grant = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_grant", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_grant(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_grant.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_nonce
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_nonce = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_nonce", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_nonce(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_nonce.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_rate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_rate = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_rate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_rate(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_rate.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_create_dex
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_create_dex = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_create_dex", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_create_dex(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_create_dex.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_create_instance
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_create_instance = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_create_instance", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_create_instance(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_create_instance.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_create_token
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_create_token = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_create_token", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_create_token(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_create_token.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_dex
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_dex = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_dex", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_dex(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_dex.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_release
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_release = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_release", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_release(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_release.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_token
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_token = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_token", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_token(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_token.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_disable_feature
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_disable_feature = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_disable_feature", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_disable_feature(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_disable_feature.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_disable_wrap
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_disable_wrap = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_disable_wrap", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_disable_wrap(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_disable_wrap.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_enable_feature
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_enable_feature = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_enable_feature", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_enable_feature(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_enable_feature.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_execute_rate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_execute_rate = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_execute_rate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_execute_rate(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_execute_rate.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_force_transfer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_force_transfer = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_force_transfer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_force_transfer(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_force_transfer.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_freeze
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_freeze = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_freeze", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_freeze(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_freeze.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_grant_role
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_grant_role = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_grant_role", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_grant_role(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_grant_role.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_mint
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_mint = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_mint", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_mint(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_mint.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_mint_to_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_mint_to_ua = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_mint_to_ua", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_mint_to_ua(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_mint_to_ua.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_operator_transfer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_operator_transfer = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_operator_transfer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_operator_transfer(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_operator_transfer.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_pause
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_pause = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_pause", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_pause(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_pause.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_cancel_verifier
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_cancel_verifier = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_cancel_verifier", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_cancel_verifier(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_cancel_verifier.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_revoke_verifier
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_revoke_verifier = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_revoke_verifier", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_revoke_verifier(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_revoke_verifier.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_set_verifier
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_set_verifier = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_set_verifier", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_set_verifier(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_set_verifier.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_propose_rate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_propose_rate = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_propose_rate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_propose_rate(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_propose_rate.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_class_env
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_class_env = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_class_env", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_class_env(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_class_env.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_dex_env
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_dex_env = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_dex_env", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_dex_env(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_dex_env.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_token_env
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_token_env = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_token_env", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_token_env(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_token_env.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_record_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_record_order = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_record_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_record_order(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_record_order.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_renounce_admin
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_renounce_admin = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_renounce_admin", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_renounce_admin(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_renounce_admin.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_renounce_role
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_renounce_role = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_renounce_role", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_renounce_role(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_renounce_role.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_approval
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_approval = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_approval", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_approval(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_approval.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_order = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_order(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_order.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_role
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_role = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_role", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_role(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_role.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_allowed
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_allowed = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_allowed", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_allowed(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_allowed.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_auditor_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_auditor_key = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_auditor_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_auditor_key(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_auditor_key.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_auditor_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_auditor_ua = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_auditor_ua", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_auditor_ua(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_auditor_ua.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_chain_entries
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_chain_entries = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_chain_entries", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_chain_entries(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_chain_entries.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_class_kind_enabled
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_class_kind_enabled = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_class_kind_enabled", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_class_kind_enabled(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_class_kind_enabled.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_compliance
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_compliance = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_compliance", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_compliance(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_compliance.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_denied
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_denied = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_denied", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_denied(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_denied.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_exchange_target
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_exchange_target = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_exchange_target", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_exchange_target(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_exchange_target.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_fee_split
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_fee_split = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_fee_split", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_fee_split(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_fee_split.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_grant
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_grant = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_grant", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_grant(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_grant.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_kyc_provider
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_kyc_provider = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_kyc_provider", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_kyc_provider(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_kyc_provider.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_listed_only
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_listed_only = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_listed_only", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_listed_only(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_listed_only.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_market
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_market = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_market", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_market(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_market.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_max_supply
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_max_supply = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_max_supply", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_max_supply(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_max_supply.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_max_wrap_supply
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_max_wrap_supply = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_max_wrap_supply", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_max_wrap_supply(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_max_wrap_supply.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_proof_store
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_proof_store = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_proof_store", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_proof_store(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_proof_store.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_tax_rate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_tax_rate = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_tax_rate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_tax_rate(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_tax_rate.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_tax_recipient
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_tax_recipient = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_tax_recipient", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_tax_recipient(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_tax_recipient.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_token_kind_enabled
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_token_kind_enabled = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_token_kind_enabled", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_token_kind_enabled(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_token_kind_enabled.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_verifier_fee
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_verifier_fee = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_verifier_fee", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_verifier_fee(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_verifier_fee.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_wrap_limits
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_wrap_limits = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_wrap_limits", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_wrap_limits(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_wrap_limits.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_set_wrap_member
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_wrap_member = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_set_wrap_member", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_set_wrap_member(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_set_wrap_member.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_transfer_admin
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_transfer_admin = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_transfer_admin", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_transfer_admin(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_transfer_admin.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_unfreeze
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_unfreeze = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_unfreeze", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_unfreeze(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_unfreeze.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_admin_ua_unpause
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_unpause = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_admin_ua_unpause", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_admin_ua_unpause(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_admin_ua_unpause.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_create3_address
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_create3_address = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_create3_address", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_SHORT, java.lang.foreign.ValueLayout.JAVA_SHORT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_admin_create3_address(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment factory, java.lang.foreign.MemorySegment creatorId, short contractClass, short kind, java.lang.foreign.MemorySegment salt, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_admin_create3_address.invokeExact(_allocator, ptr, factory, creatorId, contractClass, kind, salt, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_governance_delay
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_governance_delay = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_governance_delay", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_SHORT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_governance_delay(long ptr, java.lang.foreign.MemorySegment chain, java.lang.foreign.MemorySegment token, short bit, java.lang.foreign.MemorySegment holder) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_governance_delay.invokeExact(ptr, chain, token, bit, holder);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_sign_pqz_auditor_consent
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_sign_pqz_auditor_consent = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_sign_pqz_auditor_consent", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_sign_pqz_auditor_consent(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_sign_pqz_auditor_consent.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_sign_rescue_vault
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_sign_rescue_vault = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_sign_rescue_vault", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_sign_rescue_vault(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_sign_rescue_vault.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_admin_sign_zether_auditor_consent
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_admin_sign_zether_auditor_consent = findDowncallHandle("uniffi_scaas_sdk_fn_method_admin_sign_zether_auditor_consent", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_admin_sign_zether_auditor_consent(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_admin_sign_zether_auditor_consent.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_confidential
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_confidential = findDowncallHandle("uniffi_scaas_sdk_fn_clone_confidential", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_confidential(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_confidential.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_confidential
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_confidential = findDowncallHandle("uniffi_scaas_sdk_fn_free_confidential", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_confidential(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_confidential.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_pqz_balance
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_pqz_balance = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_pqz_balance", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_pqz_balance(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_pqz_balance.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_pqz_balance_all
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_pqz_balance_all = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_pqz_balance_all", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_pqz_balance_all(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_pqz_balance_all.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_prepare_acc
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_prepare_acc = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_prepare_acc", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_prepare_acc(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_prepare_acc.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_roll_over
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_roll_over = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_roll_over", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_roll_over(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_roll_over.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_shield
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_shield = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_shield", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_shield(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_shield.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_compact
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_compact = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_compact", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_compact(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_compact.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_multi
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_multi = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_multi", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_multi(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_multi.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_multi_compact
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_multi_compact = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_multi_compact", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_multi_compact(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_multi_compact.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_unshield
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_unshield = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_unshield", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_unshield(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_unshield.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_unshield_unwrap
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_unshield_unwrap = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_unshield_unwrap", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_unshield_unwrap(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_unshield_unwrap.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_wrap_shield
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_wrap_shield = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_wrap_shield", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_wrap_shield(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_wrap_shield.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_owner_roll_over
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_owner_roll_over = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_owner_roll_over", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_owner_roll_over(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_owner_roll_over.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_owner_set_mode
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_owner_set_mode = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_owner_set_mode", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_owner_set_mode(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_owner_set_mode.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over_batch
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over_batch = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over_batch", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over_batch(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over_batch.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over_signed
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over_signed = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over_signed", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over_signed(long ptr, java.lang.foreign.MemorySegment r, java.lang.foreign.MemorySegment relay) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over_signed.invokeExact(ptr, r, relay);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_set_roll_over_mode
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_set_roll_over_mode = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_set_roll_over_mode", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_set_roll_over_mode(long ptr, java.lang.foreign.MemorySegment r, java.lang.foreign.MemorySegment relay) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_set_roll_over_mode.invokeExact(ptr, r, relay);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_shield
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_shield = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_shield", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_shield(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_shield.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer_compact
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer_compact = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer_compact", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer_compact(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer_compact.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer_multi
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer_multi = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer_multi", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer_multi(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer_multi.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_unshield
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_unshield = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_unshield", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_unshield(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_unshield.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_unshield_unwrap
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_unshield_unwrap = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_unshield_unwrap", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_unshield_unwrap(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_unshield_unwrap.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_prepare_zether_wrap_shield
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_wrap_shield = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_prepare_zether_wrap_shield", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_prepare_zether_wrap_shield(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_prepare_zether_wrap_shield.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_request_verdict
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_request_verdict = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_request_verdict", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_request_verdict(long ptr, java.lang.foreign.MemorySegment r) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_request_verdict.invokeExact(ptr, r);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_zether_balance
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_zether_balance = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_zether_balance", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_confidential_zether_balance(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_zether_balance.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_confidential_zether_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_confidential_zether_key = findDowncallHandle("uniffi_scaas_sdk_fn_method_confidential_zether_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_INT));

    static long uniffi_scaas_sdk_fn_method_confidential_zether_key(long ptr, java.lang.foreign.MemorySegment seed, int account) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_confidential_zether_key.invokeExact(ptr, seed, account);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_dex
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_dex = findDowncallHandle("uniffi_scaas_sdk_fn_clone_dex", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_dex(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_dex.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_dex
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_dex = findDowncallHandle("uniffi_scaas_sdk_fn_free_dex", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_dex(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_dex.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_cancel_all
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_cancel_all = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_cancel_all", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_dex_cancel_all(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_cancel_all.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_depth
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_depth = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_depth", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_dex_depth(long ptr, java.lang.foreign.MemorySegment chain, long market, java.lang.foreign.MemorySegment levels) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_depth.invokeExact(ptr, chain, market, levels);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_markets
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_markets = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_markets", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_dex_markets(long ptr, java.lang.foreign.MemorySegment chain) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_markets.invokeExact(ptr, chain);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_orders
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_orders = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_orders", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_dex_orders(long ptr, java.lang.foreign.MemorySegment chain, java.lang.foreign.MemorySegment maker) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_orders.invokeExact(ptr, chain, maker);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_place
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_place = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_place", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_dex_place(long ptr, long order) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_place.invokeExact(ptr, order);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_prepare_cancel_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_prepare_cancel_order = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_prepare_cancel_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_dex_prepare_cancel_order(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_prepare_cancel_order.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_prepare_cancel_wrap_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_prepare_cancel_wrap_order = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_prepare_cancel_wrap_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_dex_prepare_cancel_wrap_order(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_prepare_cancel_wrap_order.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_prepare_liquidity_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_prepare_liquidity_order = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_prepare_liquidity_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_dex_prepare_liquidity_order(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_prepare_liquidity_order.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_prepare_trade_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_prepare_trade_order = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_prepare_trade_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_dex_prepare_trade_order(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_prepare_trade_order.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_prepare_wrap_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_prepare_wrap_order = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_prepare_wrap_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_dex_prepare_wrap_order(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_prepare_wrap_order.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_sign_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_sign_order = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_sign_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_dex_sign_order(long ptr, long order) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_sign_order.invokeExact(ptr, order);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_ticker
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_ticker = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_ticker", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_dex_ticker(long ptr, java.lang.foreign.MemorySegment chain, long market) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_ticker.invokeExact(ptr, chain, market);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_dex_trades
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_dex_trades = findDowncallHandle("uniffi_scaas_sdk_fn_method_dex_trades", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_dex_trades(long ptr, java.lang.foreign.MemorySegment chain, long market) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_dex_trades.invokeExact(ptr, chain, market);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_foreignauthenticator
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_foreignauthenticator = findDowncallHandle("uniffi_scaas_sdk_fn_clone_foreignauthenticator", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_foreignauthenticator(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_foreignauthenticator.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_foreignauthenticator
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_foreignauthenticator = findDowncallHandle("uniffi_scaas_sdk_fn_free_foreignauthenticator", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_foreignauthenticator(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_foreignauthenticator.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_init_callback_vtable_foreignauthenticator
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_init_callback_vtable_foreignauthenticator = findDowncallHandle("uniffi_scaas_sdk_fn_init_callback_vtable_foreignauthenticator", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_init_callback_vtable_foreignauthenticator(java.lang.foreign.MemorySegment vtable) {
        try {
            MH_uniffi_scaas_sdk_fn_init_callback_vtable_foreignauthenticator.invokeExact(vtable);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_foreignauthenticator_create_passkey
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_foreignauthenticator_create_passkey = findDowncallHandle("uniffi_scaas_sdk_fn_method_foreignauthenticator_create_passkey", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_foreignauthenticator_create_passkey(long ptr, java.lang.foreign.MemorySegment rpId, java.lang.foreign.MemorySegment userName, java.lang.foreign.MemorySegment exclude) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_foreignauthenticator_create_passkey.invokeExact(ptr, rpId, userName, exclude);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_foreignauthenticator_get_assertion
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_foreignauthenticator_get_assertion = findDowncallHandle("uniffi_scaas_sdk_fn_method_foreignauthenticator_get_assertion", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_foreignauthenticator_get_assertion(long ptr, java.lang.foreign.MemorySegment req, long prfOut) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_foreignauthenticator_get_assertion.invokeExact(ptr, req, prfOut);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_foreignauthenticator_platform_secret
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_foreignauthenticator_platform_secret = findDowncallHandle("uniffi_scaas_sdk_fn_method_foreignauthenticator_platform_secret", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_foreignauthenticator_platform_secret(long ptr, java.lang.foreign.MemorySegment keyHandle, java.lang.foreign.MemorySegment salt, java.lang.foreign.MemorySegment reason, java.lang.foreign.MemorySegment policy, long out) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_foreignauthenticator_platform_secret.invokeExact(ptr, keyHandle, salt, reason, policy, out);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_foreignauthenticator_p256_generate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_foreignauthenticator_p256_generate = findDowncallHandle("uniffi_scaas_sdk_fn_method_foreignauthenticator_p256_generate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_foreignauthenticator_p256_generate(long ptr, java.lang.foreign.MemorySegment policy) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_foreignauthenticator_p256_generate.invokeExact(ptr, policy);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_foreignauthenticator_p256_sign
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_foreignauthenticator_p256_sign = findDowncallHandle("uniffi_scaas_sdk_fn_method_foreignauthenticator_p256_sign", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_foreignauthenticator_p256_sign(long ptr, java.lang.foreign.MemorySegment keyHandle, java.lang.foreign.MemorySegment uaMsg, java.lang.foreign.MemorySegment reason) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_foreignauthenticator_p256_sign.invokeExact(ptr, keyHandle, uaMsg, reason);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_foreignstore
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_foreignstore = findDowncallHandle("uniffi_scaas_sdk_fn_clone_foreignstore", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_foreignstore(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_foreignstore.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_foreignstore
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_foreignstore = findDowncallHandle("uniffi_scaas_sdk_fn_free_foreignstore", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_foreignstore(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_foreignstore.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_init_callback_vtable_foreignstore
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_init_callback_vtable_foreignstore = findDowncallHandle("uniffi_scaas_sdk_fn_init_callback_vtable_foreignstore", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_init_callback_vtable_foreignstore(java.lang.foreign.MemorySegment vtable) {
        try {
            MH_uniffi_scaas_sdk_fn_init_callback_vtable_foreignstore.invokeExact(vtable);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_foreignstore_get
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_foreignstore_get = findDowncallHandle("uniffi_scaas_sdk_fn_method_foreignstore_get", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_foreignstore_get(long ptr, java.lang.foreign.MemorySegment name, java.lang.foreign.MemorySegment reason) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_foreignstore_get.invokeExact(ptr, name, reason);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_foreignstore_put_if
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_foreignstore_put_if = findDowncallHandle("uniffi_scaas_sdk_fn_method_foreignstore_put_if", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_foreignstore_put_if(long ptr, java.lang.foreign.MemorySegment name, java.lang.foreign.MemorySegment prevRev, java.lang.foreign.MemorySegment bytes, java.lang.foreign.MemorySegment policy) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_foreignstore_put_if.invokeExact(ptr, name, prevRev, bytes, policy);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_foreignstore_delete
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_foreignstore_delete = findDowncallHandle("uniffi_scaas_sdk_fn_method_foreignstore_delete", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_foreignstore_delete(long ptr, java.lang.foreign.MemorySegment name) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_foreignstore_delete.invokeExact(ptr, name);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_foreignstore_lock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_foreignstore_lock = findDowncallHandle("uniffi_scaas_sdk_fn_method_foreignstore_lock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_foreignstore_lock(long ptr, java.lang.foreign.MemorySegment name) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_foreignstore_lock.invokeExact(ptr, name);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_foreignstore_unlock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_foreignstore_unlock = findDowncallHandle("uniffi_scaas_sdk_fn_method_foreignstore_unlock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_foreignstore_unlock(long ptr, long token) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_foreignstore_unlock.invokeExact(ptr, token);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_op
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_op = findDowncallHandle("uniffi_scaas_sdk_fn_clone_op", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_op(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_op.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_op
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_op = findDowncallHandle("uniffi_scaas_sdk_fn_free_op", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_op(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_op.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_bls_multi_part
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_bls_multi_part = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_bls_multi_part", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_op_bls_multi_part(long ptr, long prepared, java.lang.foreign.MemorySegment member) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_bls_multi_part.invokeExact(ptr, prepared, member);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_bls_multi_part_ok
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_bls_multi_part_ok = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_bls_multi_part_ok", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static byte uniffi_scaas_sdk_fn_method_op_bls_multi_part_ok(long ptr, long prepared, java.lang.foreign.MemorySegment part, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_uniffi_scaas_sdk_fn_method_op_bls_multi_part_ok.invokeExact(ptr, prepared, part, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_bls_multi_pop_part
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_bls_multi_pop_part = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_bls_multi_pop_part", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_op_bls_multi_pop_part(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment member, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_op_bls_multi_pop_part.invokeExact(_allocator, ptr, member, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_bls_multi_pop_part_ok
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_bls_multi_pop_part_ok = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_bls_multi_pop_part_ok", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static byte uniffi_scaas_sdk_fn_method_op_bls_multi_pop_part_ok(long ptr, java.lang.foreign.MemorySegment keyData, java.lang.foreign.MemorySegment part, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_uniffi_scaas_sdk_fn_method_op_bls_multi_pop_part_ok.invokeExact(ptr, keyData, part, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_hand_off
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_hand_off = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_hand_off", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_op_hand_off(long ptr, long prepared) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_hand_off.invokeExact(ptr, prepared);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_import_signed
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_import_signed = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_import_signed", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_op_import_signed(long ptr, java.lang.foreign.MemorySegment blob, java.lang.foreign.MemorySegment expect) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_import_signed.invokeExact(ptr, blob, expect);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_member_sign
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_member_sign = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_member_sign", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_op_member_sign(long ptr, long prepared) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_member_sign.invokeExact(ptr, prepared);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_quote
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_quote = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_quote", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_op_quote(long ptr, long prepared, java.lang.foreign.MemorySegment path) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_quote.invokeExact(ptr, prepared, path);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_quote_register_bls_multi
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_quote_register_bls_multi = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_quote_register_bls_multi", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_op_quote_register_bls_multi(long ptr, java.lang.foreign.MemorySegment chain, java.lang.foreign.MemorySegment keyData, java.lang.foreign.MemorySegment payer) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_quote_register_bls_multi.invokeExact(ptr, chain, keyData, payer);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_quote_with_gas
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_quote_with_gas = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_quote_with_gas", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_op_quote_with_gas(long ptr, long prepared, java.lang.foreign.MemorySegment path, long gas) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_quote_with_gas.invokeExact(ptr, prepared, path, gas);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_register_bls_multi
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_register_bls_multi = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_register_bls_multi", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_op_register_bls_multi(long ptr, java.lang.foreign.MemorySegment chain, java.lang.foreign.MemorySegment keyData, java.lang.foreign.MemorySegment parts, java.lang.foreign.MemorySegment quote) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_register_bls_multi.invokeExact(ptr, chain, keyData, parts, quote);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_resend
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_resend = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_resend", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_op_resend(long ptr, java.lang.foreign.MemorySegment op, java.lang.foreign.MemorySegment quote) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_resend.invokeExact(ptr, op, quote);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_resume
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_resume = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_resume", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_op_resume(long ptr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_resume.invokeExact(ptr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_state
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_state = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_state", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_op_state(long ptr, java.lang.foreign.MemorySegment op) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_state.invokeExact(ptr, op);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_submit
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_submit = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_submit", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_op_submit(long ptr, long prepared, java.lang.foreign.MemorySegment quote) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_submit.invokeExact(ptr, prepared, quote);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_op_submit_bls_multi
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_op_submit_bls_multi = findDowncallHandle("uniffi_scaas_sdk_fn_method_op_submit_bls_multi", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_BYTE));

    static long uniffi_scaas_sdk_fn_method_op_submit_bls_multi(long ptr, long prepared, java.lang.foreign.MemorySegment quote, java.lang.foreign.MemorySegment parts, byte surplus) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_op_submit_bls_multi.invokeExact(ptr, prepared, quote, parts, surplus);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_sdk
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_sdk = findDowncallHandle("uniffi_scaas_sdk_fn_clone_sdk", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_sdk(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_sdk.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_sdk
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_sdk = findDowncallHandle("uniffi_scaas_sdk_fn_free_sdk", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_sdk(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_sdk.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_sdk_account
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_sdk_account = findDowncallHandle("uniffi_scaas_sdk_fn_method_sdk_account", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_method_sdk_account(long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_sdk_account.invokeExact(ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_sdk_admin
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_sdk_admin = findDowncallHandle("uniffi_scaas_sdk_fn_method_sdk_admin", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_method_sdk_admin(long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_sdk_admin.invokeExact(ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_sdk_confidential
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_sdk_confidential = findDowncallHandle("uniffi_scaas_sdk_fn_method_sdk_confidential", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_method_sdk_confidential(long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_sdk_confidential.invokeExact(ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_sdk_dex
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_sdk_dex = findDowncallHandle("uniffi_scaas_sdk_fn_method_sdk_dex", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_method_sdk_dex(long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_sdk_dex.invokeExact(ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_sdk_limits
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_sdk_limits = findDowncallHandle("uniffi_scaas_sdk_fn_method_sdk_limits", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_sdk_limits(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_sdk_limits.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_sdk_op
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_sdk_op = findDowncallHandle("uniffi_scaas_sdk_fn_method_sdk_op", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_method_sdk_op(long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_sdk_op.invokeExact(ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_sdk_state_rev
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_sdk_state_rev = findDowncallHandle("uniffi_scaas_sdk_fn_method_sdk_state_rev", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_sdk_state_rev(long ptr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_sdk_state_rev.invokeExact(ptr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_sdk_subscribe
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_sdk_subscribe = findDowncallHandle("uniffi_scaas_sdk_fn_method_sdk_subscribe", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_method_sdk_subscribe(long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_sdk_subscribe.invokeExact(ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_sdk_vault
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_sdk_vault = findDowncallHandle("uniffi_scaas_sdk_fn_method_sdk_vault", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_method_sdk_vault(long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_sdk_vault.invokeExact(ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_sdk_wallet
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_sdk_wallet = findDowncallHandle("uniffi_scaas_sdk_fn_method_sdk_wallet", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_method_sdk_wallet(long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_sdk_wallet.invokeExact(ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_sdk_watch
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_sdk_watch = findDowncallHandle("uniffi_scaas_sdk_fn_method_sdk_watch", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_sdk_watch(long ptr, java.lang.foreign.MemorySegment account, java.lang.foreign.MemorySegment chains) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_sdk_watch.invokeExact(ptr, account, chains);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_secretbytes
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_secretbytes = findDowncallHandle("uniffi_scaas_sdk_fn_clone_secretbytes", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_secretbytes(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_secretbytes.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_secretbytes
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_secretbytes = findDowncallHandle("uniffi_scaas_sdk_fn_free_secretbytes", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_secretbytes(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_secretbytes.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_subscription
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_subscription = findDowncallHandle("uniffi_scaas_sdk_fn_clone_subscription", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_subscription(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_subscription.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_subscription
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_subscription = findDowncallHandle("uniffi_scaas_sdk_fn_free_subscription", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_subscription(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_subscription.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_subscription_next
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_subscription_next = findDowncallHandle("uniffi_scaas_sdk_fn_method_subscription_next", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_subscription_next(long ptr, long timeoutMs) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_subscription_next.invokeExact(ptr, timeoutMs);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_vault
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_vault = findDowncallHandle("uniffi_scaas_sdk_fn_clone_vault", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_vault(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_vault.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_vault
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_vault = findDowncallHandle("uniffi_scaas_sdk_fn_free_vault", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_vault(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_vault.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_change_passphrase
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_change_passphrase = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_change_passphrase", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_vault_change_passphrase(long ptr, java.lang.foreign.MemorySegment seed, long old, long _new) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_change_passphrase.invokeExact(ptr, seed, old, _new);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_confirm_backup
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_confirm_backup = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_confirm_backup", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_confirm_backup(long ptr, java.lang.foreign.MemorySegment seed) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_confirm_backup.invokeExact(ptr, seed);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_derive_child
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_derive_child = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_derive_child", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_derive_child(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_derive_child.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_derive_from_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_derive_from_key = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_derive_from_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_derive_from_key(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_derive_from_key.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_derive_from_signature
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_derive_from_signature = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_derive_from_signature", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_derive_from_signature(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_derive_from_signature.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_disable_prf_unlock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_disable_prf_unlock = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_disable_prf_unlock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_disable_prf_unlock(long ptr, java.lang.foreign.MemorySegment seed) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_disable_prf_unlock.invokeExact(ptr, seed);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_enable_passkey_unlock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_enable_passkey_unlock = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_enable_passkey_unlock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_vault_enable_passkey_unlock(long ptr, java.lang.foreign.MemorySegment seed, long vaultPassphrase) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_enable_passkey_unlock.invokeExact(ptr, seed, vaultPassphrase);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_enable_platform_unlock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_enable_platform_unlock = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_enable_platform_unlock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_enable_platform_unlock(long ptr, java.lang.foreign.MemorySegment seed, long vaultPassphrase, java.lang.foreign.MemorySegment policy) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_enable_platform_unlock.invokeExact(ptr, seed, vaultPassphrase, policy);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_generate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_generate = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_generate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_generate(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_generate.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_import_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_import_key = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_import_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_import_key(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_import_key.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_import_words
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_import_words = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_import_words", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_import_words(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_import_words.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_key_derivation_typed_data
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_key_derivation_typed_data = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_key_derivation_typed_data", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_INT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_vault_key_derivation_typed_data(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment accountHex, int set, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_vault_key_derivation_typed_data.invokeExact(_allocator, ptr, accountHex, set, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_keystore_rollback
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_keystore_rollback = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_keystore_rollback", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_vault_keystore_rollback(long ptr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_keystore_rollback.invokeExact(ptr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_lock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_lock = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_lock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_lock(long ptr, java.lang.foreign.MemorySegment seed) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_lock.invokeExact(ptr, seed);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_lock_all
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_lock_all = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_lock_all", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_vault_lock_all(long ptr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_lock_all.invokeExact(ptr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_memory_protection
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_memory_protection = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_memory_protection", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_vault_memory_protection(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment seed, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_vault_memory_protection.invokeExact(_allocator, ptr, seed, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_open_hidden
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_open_hidden = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_open_hidden", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_vault_open_hidden(long ptr, java.lang.foreign.MemorySegment seed, java.lang.foreign.MemorySegment unlock, long bip39Passphrase) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_open_hidden.invokeExact(ptr, seed, unlock, bip39Passphrase);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_remove
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_remove = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_remove", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_remove(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_remove.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_rename
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_rename = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_rename", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_rename(long ptr, java.lang.foreign.MemorySegment seed, java.lang.foreign.MemorySegment label) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_rename.invokeExact(ptr, seed, label);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_seed
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_seed = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_seed", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_seed(long ptr, java.lang.foreign.MemorySegment seed) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_seed.invokeExact(ptr, seed);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_seeds
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_seeds = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_seeds", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_fn_method_vault_seeds(long ptr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_seeds.invokeExact(ptr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_signature_from_compact
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_signature_from_compact = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_signature_from_compact", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_method_vault_signature_from_compact(long ptr, long sig, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_signature_from_compact.invokeExact(ptr, sig, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_unlock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_unlock = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_unlock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_vault_unlock(long ptr, java.lang.foreign.MemorySegment seed, java.lang.foreign.MemorySegment unlock) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_vault_unlock.invokeExact(ptr, seed, unlock);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_vault_word_in_list
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_vault_word_in_list = findDowncallHandle("uniffi_scaas_sdk_fn_method_vault_word_in_list", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static byte uniffi_scaas_sdk_fn_method_vault_word_in_list(long ptr, long word, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_uniffi_scaas_sdk_fn_method_vault_word_in_list.invokeExact(ptr, word, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_wallet
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_wallet = findDowncallHandle("uniffi_scaas_sdk_fn_clone_wallet", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_wallet(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_wallet.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_wallet
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_wallet = findDowncallHandle("uniffi_scaas_sdk_fn_free_wallet", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_wallet(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_wallet.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_balances
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_balances = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_balances", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_balances(long ptr, java.lang.foreign.MemorySegment id, java.lang.foreign.MemorySegment chain) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_balances.invokeExact(ptr, id, chain);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_history
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_history = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_history", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_INT));

    static long uniffi_scaas_sdk_fn_method_wallet_history(long ptr, java.lang.foreign.MemorySegment account, java.lang.foreign.MemorySegment chain, java.lang.foreign.MemorySegment before, int limit) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_history.invokeExact(ptr, account, chain, before, limit);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_native_address
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_native_address = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_native_address", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_native_address(long ptr, java.lang.foreign.MemorySegment key, java.lang.foreign.MemorySegment ss58Prefix) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_native_address.invokeExact(ptr, key, ss58Prefix);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_add_reserve
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_add_reserve = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_add_reserve", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_add_reserve(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_add_reserve.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_burn
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_burn = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_burn", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_burn(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_burn.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_cancel_nonce
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_cancel_nonce = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_cancel_nonce", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_cancel_nonce(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_cancel_nonce.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_delegate_revoke
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_delegate_revoke = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_delegate_revoke", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_delegate_revoke(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_delegate_revoke.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_execute
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_execute = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_execute", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_execute(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_execute.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_native_send
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_native_send = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_native_send", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_native_send(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_native_send.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_pay
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_pay = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_pay", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_pay(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_pay.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_pay_under_mandate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_pay_under_mandate = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_pay_under_mandate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_pay_under_mandate(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_pay_under_mandate.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_pay_with_tax
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_pay_with_tax = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_pay_with_tax", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_pay_with_tax(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_pay_with_tax.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_payee_fee
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_payee_fee = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_payee_fee", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_payee_fee(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_payee_fee.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_relay_fee
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_relay_fee = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_relay_fee", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_relay_fee(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_relay_fee.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_revoke_mandate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_revoke_mandate = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_revoke_mandate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_revoke_mandate(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_revoke_mandate.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_set_mandate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_set_mandate = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_set_mandate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_set_mandate(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_set_mandate.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_set_payee
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_set_payee = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_set_payee", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_set_payee(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_set_payee.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_transfer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_transfer = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_transfer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_transfer(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_transfer.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap_leg
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap_leg = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap_leg", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap_leg(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap_leg.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap_to_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap_to_ua = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap_to_ua", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap_to_ua(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_unwrap_to_ua.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_wrap
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_wrap = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_wrap", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_wrap(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_wrap.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_wrap_leg
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_wrap_leg = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_wrap_leg", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_wrap_leg(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_wrap_leg.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_prepare_wrap_to_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_prepare_wrap_to_ua = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_prepare_wrap_to_ua", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_prepare_wrap_to_ua(long ptr, java.lang.foreign.MemorySegment req) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_prepare_wrap_to_ua.invokeExact(ptr, req);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_submit_native_send
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_submit_native_send = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_submit_native_send", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_method_wallet_submit_native_send(long ptr, java.lang.foreign.MemorySegment q) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_submit_native_send.invokeExact(ptr, q);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_wallet_tokens
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_wallet_tokens = findDowncallHandle("uniffi_scaas_sdk_fn_method_wallet_tokens", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_BYTE));

    static long uniffi_scaas_sdk_fn_method_wallet_tokens(long ptr, java.lang.foreign.MemorySegment chain, byte withIndex) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_wallet_tokens.invokeExact(ptr, chain, withIndex);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_preparedorder
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_preparedorder = findDowncallHandle("uniffi_scaas_sdk_fn_clone_preparedorder", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_preparedorder(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_preparedorder.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_preparedorder
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_preparedorder = findDowncallHandle("uniffi_scaas_sdk_fn_free_preparedorder", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_preparedorder(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_preparedorder.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_preparedorder_chain
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_preparedorder_chain = findDowncallHandle("uniffi_scaas_sdk_fn_method_preparedorder_chain", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_preparedorder_chain(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_preparedorder_chain.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_preparedorder_id
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_preparedorder_id = findDowncallHandle("uniffi_scaas_sdk_fn_method_preparedorder_id", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_preparedorder_id(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_preparedorder_id.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_preparedorder_review
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_preparedorder_review = findDowncallHandle("uniffi_scaas_sdk_fn_method_preparedorder_review", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_preparedorder_review(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_preparedorder_review.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_preparedorder_signer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_preparedorder_signer = findDowncallHandle("uniffi_scaas_sdk_fn_method_preparedorder_signer", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_preparedorder_signer(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_preparedorder_signer.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_prepared
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_prepared = findDowncallHandle("uniffi_scaas_sdk_fn_clone_prepared", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_prepared(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_prepared.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_prepared
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_prepared = findDowncallHandle("uniffi_scaas_sdk_fn_free_prepared", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_prepared(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_prepared.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_prepared_chain
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_prepared_chain = findDowncallHandle("uniffi_scaas_sdk_fn_method_prepared_chain", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_prepared_chain(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_prepared_chain.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_prepared_entry
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_prepared_entry = findDowncallHandle("uniffi_scaas_sdk_fn_method_prepared_entry", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_prepared_entry(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_prepared_entry.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_prepared_expires_at
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_prepared_expires_at = findDowncallHandle("uniffi_scaas_sdk_fn_method_prepared_expires_at", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_method_prepared_expires_at(long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_prepared_expires_at.invokeExact(ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_prepared_id
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_prepared_id = findDowncallHandle("uniffi_scaas_sdk_fn_method_prepared_id", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_prepared_id(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_prepared_id.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_prepared_opaque
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_prepared_opaque = findDowncallHandle("uniffi_scaas_sdk_fn_method_prepared_opaque", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static byte uniffi_scaas_sdk_fn_method_prepared_opaque(long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_uniffi_scaas_sdk_fn_method_prepared_opaque.invokeExact(ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_prepared_review
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_prepared_review = findDowncallHandle("uniffi_scaas_sdk_fn_method_prepared_review", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_prepared_review(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_prepared_review.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_prepared_signer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_prepared_signer = findDowncallHandle("uniffi_scaas_sdk_fn_method_prepared_signer", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_prepared_signer(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_prepared_signer.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_clone_seedbackup
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_clone_seedbackup = findDowncallHandle("uniffi_scaas_sdk_fn_clone_seedbackup", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_clone_seedbackup(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_clone_seedbackup.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_free_seedbackup
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_free_seedbackup = findDowncallHandle("uniffi_scaas_sdk_fn_free_seedbackup", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void uniffi_scaas_sdk_fn_free_seedbackup(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_uniffi_scaas_sdk_fn_free_seedbackup.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_seedbackup_challenge
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_seedbackup_challenge = findDowncallHandle("uniffi_scaas_sdk_fn_method_seedbackup_challenge", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_method_seedbackup_challenge(java.lang.foreign.SegmentAllocator _allocator, long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_method_seedbackup_challenge.invokeExact(_allocator, ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_seedbackup_reveal
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_seedbackup_reveal = findDowncallHandle("uniffi_scaas_sdk_fn_method_seedbackup_reveal", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_method_seedbackup_reveal(long ptr, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_method_seedbackup_reveal.invokeExact(ptr, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_method_seedbackup_verify
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_method_seedbackup_verify = findDowncallHandle("uniffi_scaas_sdk_fn_method_seedbackup_verify", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static byte uniffi_scaas_sdk_fn_method_seedbackup_verify(long ptr, long answers, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_uniffi_scaas_sdk_fn_method_seedbackup_verify.invokeExact(ptr, answers, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_accounts_json
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_accounts_json = findDowncallHandle("uniffi_scaas_sdk_fn_func_accounts_json", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_accounts_json(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment rows, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_accounts_json.invokeExact(_allocator, rows, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_api_version
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_api_version = findDowncallHandle("uniffi_scaas_sdk_fn_func_api_version", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_INT, java.lang.foreign.ValueLayout.ADDRESS));

    static int uniffi_scaas_sdk_fn_func_api_version(java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (int) MH_uniffi_scaas_sdk_fn_func_api_version.invokeExact(uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_features
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_features = findDowncallHandle("uniffi_scaas_sdk_fn_func_features", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_func_features(java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_func_features.invokeExact(uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_gas_rows_default
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_gas_rows_default = findDowncallHandle("uniffi_scaas_sdk_fn_func_gas_rows_default", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_gas_rows_default(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_gas_rows_default.invokeExact(_allocator, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_gas_table_parse
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_gas_table_parse = findDowncallHandle("uniffi_scaas_sdk_fn_func_gas_table_parse", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_gas_table_parse(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment text, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_gas_table_parse.invokeExact(_allocator, text, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_is_uuid4
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_is_uuid4 = findDowncallHandle("uniffi_scaas_sdk_fn_func_is_uuid4", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static byte uniffi_scaas_sdk_fn_func_is_uuid4(java.lang.foreign.MemorySegment s, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_uniffi_scaas_sdk_fn_func_is_uuid4.invokeExact(s, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_label_ok
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_label_ok = findDowncallHandle("uniffi_scaas_sdk_fn_func_label_ok", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static byte uniffi_scaas_sdk_fn_func_label_ok(java.lang.foreign.MemorySegment label, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_uniffi_scaas_sdk_fn_func_label_ok.invokeExact(label, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_limits_default
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_limits_default = findDowncallHandle("uniffi_scaas_sdk_fn_func_limits_default", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_limits_default(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_limits_default.invokeExact(_allocator, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_msig_structure
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_msig_structure = findDowncallHandle("uniffi_scaas_sdk_fn_func_msig_structure", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_SHORT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_msig_structure(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment members, short threshold, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_msig_structure.invokeExact(_allocator, members, threshold, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_msig_structure_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_msig_structure_ua = findDowncallHandle("uniffi_scaas_sdk_fn_func_msig_structure_ua", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_msig_structure_ua(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment args, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_msig_structure_ua.invokeExact(_allocator, args, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_new_label_ok
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_new_label_ok = findDowncallHandle("uniffi_scaas_sdk_fn_func_new_label_ok", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static byte uniffi_scaas_sdk_fn_func_new_label_ok(java.lang.foreign.MemorySegment label, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_uniffi_scaas_sdk_fn_func_new_label_ok.invokeExact(label, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_op_state_is_terminal
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_op_state_is_terminal = findDowncallHandle("uniffi_scaas_sdk_fn_func_op_state_is_terminal", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static byte uniffi_scaas_sdk_fn_func_op_state_is_terminal(java.lang.foreign.MemorySegment state, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_uniffi_scaas_sdk_fn_func_op_state_is_terminal.invokeExact(state, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_open
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_open = findDowncallHandle("uniffi_scaas_sdk_fn_func_open", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT));

    static long uniffi_scaas_sdk_fn_func_open(java.lang.foreign.MemorySegment config, long store, java.lang.foreign.MemorySegment authenticator) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_func_open.invokeExact(config, store, authenticator);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_register_attrs_default
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_register_attrs_default = findDowncallHandle("uniffi_scaas_sdk_fn_func_register_attrs_default", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_register_attrs_default(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_register_attrs_default.invokeExact(_allocator, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_registration_blob_from_json
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_registration_blob_from_json = findDowncallHandle("uniffi_scaas_sdk_fn_func_registration_blob_from_json", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_registration_blob_from_json(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment text, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_registration_blob_from_json.invokeExact(_allocator, text, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_registration_blob_to_json
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_registration_blob_to_json = findDowncallHandle("uniffi_scaas_sdk_fn_func_registration_blob_to_json", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_registration_blob_to_json(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment blob, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_registration_blob_to_json.invokeExact(_allocator, blob, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_rev_of
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_rev_of = findDowncallHandle("uniffi_scaas_sdk_fn_func_rev_of", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_func_rev_of(java.lang.foreign.MemorySegment bytes, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_func_rev_of.invokeExact(bytes, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_secret_id
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_secret_id = findDowncallHandle("uniffi_scaas_sdk_fn_func_secret_id", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_func_secret_id(long s, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_func_secret_id.invokeExact(s, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_secret_len
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_secret_len = findDowncallHandle("uniffi_scaas_sdk_fn_func_secret_len", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_INT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static int uniffi_scaas_sdk_fn_func_secret_len(long s, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (int) MH_uniffi_scaas_sdk_fn_func_secret_len.invokeExact(s, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_secret_new
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_secret_new = findDowncallHandle("uniffi_scaas_sdk_fn_func_secret_new", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_INT, java.lang.foreign.ValueLayout.ADDRESS));

    static long uniffi_scaas_sdk_fn_func_secret_new(int len, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_uniffi_scaas_sdk_fn_func_secret_new.invokeExact(len, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_signed_op_blob_from_json
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_signed_op_blob_from_json = findDowncallHandle("uniffi_scaas_sdk_fn_func_signed_op_blob_from_json", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_signed_op_blob_from_json(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment text, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_signed_op_blob_from_json.invokeExact(_allocator, text, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_signed_op_blob_to_json
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_signed_op_blob_to_json = findDowncallHandle("uniffi_scaas_sdk_fn_func_signed_op_blob_to_json", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_signed_op_blob_to_json(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment blob, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_signed_op_blob_to_json.invokeExact(_allocator, blob, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_smart_account_address
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_smart_account_address = findDowncallHandle("uniffi_scaas_sdk_fn_func_smart_account_address", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_smart_account_address(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment factory, java.lang.foreign.MemorySegment implementation, java.lang.foreign.MemorySegment firstKey, java.lang.foreign.MemorySegment guardian, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_smart_account_address.invokeExact(_allocator, factory, implementation, firstKey, guardian, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_store_policy_default
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_store_policy_default = findDowncallHandle("uniffi_scaas_sdk_fn_func_store_policy_default", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_store_policy_default(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_store_policy_default.invokeExact(_allocator, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_subject_key_args_secp256k1
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_subject_key_args_secp256k1 = findDowncallHandle("uniffi_scaas_sdk_fn_func_subject_key_args_secp256k1", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_subject_key_args_secp256k1(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment address, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_subject_key_args_secp256k1.invokeExact(_allocator, address, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_ua_line_key_target
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_ua_line_key_target = findDowncallHandle("uniffi_scaas_sdk_fn_func_ua_line_key_target", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_ua_line_key_target(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment line, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_ua_line_key_target.invokeExact(_allocator, line, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_fn_func_ua_line_pqz_target
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_fn_func_ua_line_pqz_target = findDowncallHandle("uniffi_scaas_sdk_fn_func_ua_line_pqz_target", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment uniffi_scaas_sdk_fn_func_ua_line_pqz_target(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment line, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_uniffi_scaas_sdk_fn_func_ua_line_pqz_target.invokeExact(_allocator, line, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rustbuffer_alloc
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rustbuffer_alloc = findDowncallHandle("ffi_scaas_sdk_rustbuffer_alloc", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment ffi_scaas_sdk_rustbuffer_alloc(java.lang.foreign.SegmentAllocator _allocator, long size, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_ffi_scaas_sdk_rustbuffer_alloc.invokeExact(_allocator, size, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rustbuffer_from_bytes
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rustbuffer_from_bytes = findDowncallHandle("ffi_scaas_sdk_rustbuffer_from_bytes", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, ForeignBytes.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment ffi_scaas_sdk_rustbuffer_from_bytes(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment bytes, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_ffi_scaas_sdk_rustbuffer_from_bytes.invokeExact(_allocator, bytes, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rustbuffer_free
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rustbuffer_free = findDowncallHandle("ffi_scaas_sdk_rustbuffer_free", java.lang.foreign.FunctionDescriptor.ofVoid(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static void ffi_scaas_sdk_rustbuffer_free(java.lang.foreign.MemorySegment buf, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_ffi_scaas_sdk_rustbuffer_free.invokeExact(buf, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rustbuffer_reserve
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rustbuffer_reserve = findDowncallHandle("ffi_scaas_sdk_rustbuffer_reserve", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment ffi_scaas_sdk_rustbuffer_reserve(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment buf, long additional, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_ffi_scaas_sdk_rustbuffer_reserve.invokeExact(_allocator, buf, additional, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_poll_u8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_poll_u8 = findDowncallHandle("ffi_scaas_sdk_rust_future_poll_u8", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_poll_u8(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_rust_future_poll_u8.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_cancel_u8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_cancel_u8 = findDowncallHandle("ffi_scaas_sdk_rust_future_cancel_u8", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_cancel_u8(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_cancel_u8.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_free_u8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_free_u8 = findDowncallHandle("ffi_scaas_sdk_rust_future_free_u8", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_free_u8(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_free_u8.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_complete_u8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_complete_u8 = findDowncallHandle("ffi_scaas_sdk_rust_future_complete_u8", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static byte ffi_scaas_sdk_rust_future_complete_u8(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_ffi_scaas_sdk_rust_future_complete_u8.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_poll_i8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_poll_i8 = findDowncallHandle("ffi_scaas_sdk_rust_future_poll_i8", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_poll_i8(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_rust_future_poll_i8.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_cancel_i8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_cancel_i8 = findDowncallHandle("ffi_scaas_sdk_rust_future_cancel_i8", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_cancel_i8(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_cancel_i8.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_free_i8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_free_i8 = findDowncallHandle("ffi_scaas_sdk_rust_future_free_i8", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_free_i8(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_free_i8.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_complete_i8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_complete_i8 = findDowncallHandle("ffi_scaas_sdk_rust_future_complete_i8", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static byte ffi_scaas_sdk_rust_future_complete_i8(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_ffi_scaas_sdk_rust_future_complete_i8.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_poll_u16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_poll_u16 = findDowncallHandle("ffi_scaas_sdk_rust_future_poll_u16", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_poll_u16(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_rust_future_poll_u16.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_cancel_u16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_cancel_u16 = findDowncallHandle("ffi_scaas_sdk_rust_future_cancel_u16", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_cancel_u16(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_cancel_u16.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_free_u16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_free_u16 = findDowncallHandle("ffi_scaas_sdk_rust_future_free_u16", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_free_u16(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_free_u16.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_complete_u16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_complete_u16 = findDowncallHandle("ffi_scaas_sdk_rust_future_complete_u16", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static short ffi_scaas_sdk_rust_future_complete_u16(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (short) MH_ffi_scaas_sdk_rust_future_complete_u16.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_poll_i16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_poll_i16 = findDowncallHandle("ffi_scaas_sdk_rust_future_poll_i16", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_poll_i16(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_rust_future_poll_i16.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_cancel_i16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_cancel_i16 = findDowncallHandle("ffi_scaas_sdk_rust_future_cancel_i16", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_cancel_i16(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_cancel_i16.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_free_i16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_free_i16 = findDowncallHandle("ffi_scaas_sdk_rust_future_free_i16", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_free_i16(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_free_i16.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_complete_i16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_complete_i16 = findDowncallHandle("ffi_scaas_sdk_rust_future_complete_i16", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static short ffi_scaas_sdk_rust_future_complete_i16(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (short) MH_ffi_scaas_sdk_rust_future_complete_i16.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_poll_u32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_poll_u32 = findDowncallHandle("ffi_scaas_sdk_rust_future_poll_u32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_poll_u32(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_rust_future_poll_u32.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_cancel_u32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_cancel_u32 = findDowncallHandle("ffi_scaas_sdk_rust_future_cancel_u32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_cancel_u32(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_cancel_u32.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_free_u32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_free_u32 = findDowncallHandle("ffi_scaas_sdk_rust_future_free_u32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_free_u32(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_free_u32.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_complete_u32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_complete_u32 = findDowncallHandle("ffi_scaas_sdk_rust_future_complete_u32", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_INT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static int ffi_scaas_sdk_rust_future_complete_u32(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (int) MH_ffi_scaas_sdk_rust_future_complete_u32.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_poll_i32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_poll_i32 = findDowncallHandle("ffi_scaas_sdk_rust_future_poll_i32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_poll_i32(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_rust_future_poll_i32.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_cancel_i32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_cancel_i32 = findDowncallHandle("ffi_scaas_sdk_rust_future_cancel_i32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_cancel_i32(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_cancel_i32.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_free_i32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_free_i32 = findDowncallHandle("ffi_scaas_sdk_rust_future_free_i32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_free_i32(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_free_i32.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_complete_i32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_complete_i32 = findDowncallHandle("ffi_scaas_sdk_rust_future_complete_i32", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_INT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static int ffi_scaas_sdk_rust_future_complete_i32(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (int) MH_ffi_scaas_sdk_rust_future_complete_i32.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_poll_u64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_poll_u64 = findDowncallHandle("ffi_scaas_sdk_rust_future_poll_u64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_poll_u64(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_rust_future_poll_u64.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_cancel_u64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_cancel_u64 = findDowncallHandle("ffi_scaas_sdk_rust_future_cancel_u64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_cancel_u64(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_cancel_u64.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_free_u64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_free_u64 = findDowncallHandle("ffi_scaas_sdk_rust_future_free_u64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_free_u64(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_free_u64.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_complete_u64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_complete_u64 = findDowncallHandle("ffi_scaas_sdk_rust_future_complete_u64", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long ffi_scaas_sdk_rust_future_complete_u64(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_ffi_scaas_sdk_rust_future_complete_u64.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_poll_i64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_poll_i64 = findDowncallHandle("ffi_scaas_sdk_rust_future_poll_i64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_poll_i64(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_rust_future_poll_i64.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_cancel_i64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_cancel_i64 = findDowncallHandle("ffi_scaas_sdk_rust_future_cancel_i64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_cancel_i64(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_cancel_i64.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_free_i64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_free_i64 = findDowncallHandle("ffi_scaas_sdk_rust_future_free_i64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_free_i64(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_free_i64.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_complete_i64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_complete_i64 = findDowncallHandle("ffi_scaas_sdk_rust_future_complete_i64", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long ffi_scaas_sdk_rust_future_complete_i64(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_ffi_scaas_sdk_rust_future_complete_i64.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_poll_f32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_poll_f32 = findDowncallHandle("ffi_scaas_sdk_rust_future_poll_f32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_poll_f32(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_rust_future_poll_f32.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_cancel_f32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_cancel_f32 = findDowncallHandle("ffi_scaas_sdk_rust_future_cancel_f32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_cancel_f32(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_cancel_f32.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_free_f32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_free_f32 = findDowncallHandle("ffi_scaas_sdk_rust_future_free_f32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_free_f32(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_free_f32.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_complete_f32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_complete_f32 = findDowncallHandle("ffi_scaas_sdk_rust_future_complete_f32", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_FLOAT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static float ffi_scaas_sdk_rust_future_complete_f32(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (float) MH_ffi_scaas_sdk_rust_future_complete_f32.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_poll_f64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_poll_f64 = findDowncallHandle("ffi_scaas_sdk_rust_future_poll_f64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_poll_f64(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_rust_future_poll_f64.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_cancel_f64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_cancel_f64 = findDowncallHandle("ffi_scaas_sdk_rust_future_cancel_f64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_cancel_f64(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_cancel_f64.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_free_f64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_free_f64 = findDowncallHandle("ffi_scaas_sdk_rust_future_free_f64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_free_f64(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_free_f64.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_complete_f64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_complete_f64 = findDowncallHandle("ffi_scaas_sdk_rust_future_complete_f64", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_DOUBLE, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static double ffi_scaas_sdk_rust_future_complete_f64(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (double) MH_ffi_scaas_sdk_rust_future_complete_f64.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_poll_rust_buffer
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_poll_rust_buffer = findDowncallHandle("ffi_scaas_sdk_rust_future_poll_rust_buffer", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_poll_rust_buffer(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_rust_future_poll_rust_buffer.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_cancel_rust_buffer
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_cancel_rust_buffer = findDowncallHandle("ffi_scaas_sdk_rust_future_cancel_rust_buffer", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_cancel_rust_buffer(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_cancel_rust_buffer.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_free_rust_buffer
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_free_rust_buffer = findDowncallHandle("ffi_scaas_sdk_rust_future_free_rust_buffer", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_free_rust_buffer(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_free_rust_buffer.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_complete_rust_buffer
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_complete_rust_buffer = findDowncallHandle("ffi_scaas_sdk_rust_future_complete_rust_buffer", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment ffi_scaas_sdk_rust_future_complete_rust_buffer(java.lang.foreign.SegmentAllocator _allocator, long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_ffi_scaas_sdk_rust_future_complete_rust_buffer.invokeExact(_allocator, handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_poll_void
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_poll_void = findDowncallHandle("ffi_scaas_sdk_rust_future_poll_void", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_poll_void(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_rust_future_poll_void.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_cancel_void
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_cancel_void = findDowncallHandle("ffi_scaas_sdk_rust_future_cancel_void", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_cancel_void(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_cancel_void.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_free_void
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_free_void = findDowncallHandle("ffi_scaas_sdk_rust_future_free_void", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_rust_future_free_void(long handle) {
        try {
            MH_ffi_scaas_sdk_rust_future_free_void.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_rust_future_complete_void
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_rust_future_complete_void = findDowncallHandle("ffi_scaas_sdk_rust_future_complete_void", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void ffi_scaas_sdk_rust_future_complete_void(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_ffi_scaas_sdk_rust_future_complete_void.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_accounts_json
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_accounts_json = findDowncallHandle("uniffi_scaas_sdk_checksum_func_accounts_json", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_accounts_json() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_accounts_json.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_api_version
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_api_version = findDowncallHandle("uniffi_scaas_sdk_checksum_func_api_version", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_api_version() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_api_version.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_features
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_features = findDowncallHandle("uniffi_scaas_sdk_checksum_func_features", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_features() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_features.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_gas_rows_default
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_gas_rows_default = findDowncallHandle("uniffi_scaas_sdk_checksum_func_gas_rows_default", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_gas_rows_default() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_gas_rows_default.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_gas_table_parse
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_gas_table_parse = findDowncallHandle("uniffi_scaas_sdk_checksum_func_gas_table_parse", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_gas_table_parse() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_gas_table_parse.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_is_uuid4
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_is_uuid4 = findDowncallHandle("uniffi_scaas_sdk_checksum_func_is_uuid4", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_is_uuid4() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_is_uuid4.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_label_ok
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_label_ok = findDowncallHandle("uniffi_scaas_sdk_checksum_func_label_ok", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_label_ok() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_label_ok.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_limits_default
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_limits_default = findDowncallHandle("uniffi_scaas_sdk_checksum_func_limits_default", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_limits_default() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_limits_default.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_msig_structure
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_msig_structure = findDowncallHandle("uniffi_scaas_sdk_checksum_func_msig_structure", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_msig_structure() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_msig_structure.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_msig_structure_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_msig_structure_ua = findDowncallHandle("uniffi_scaas_sdk_checksum_func_msig_structure_ua", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_msig_structure_ua() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_msig_structure_ua.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_new_label_ok
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_new_label_ok = findDowncallHandle("uniffi_scaas_sdk_checksum_func_new_label_ok", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_new_label_ok() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_new_label_ok.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_op_state_is_terminal
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_op_state_is_terminal = findDowncallHandle("uniffi_scaas_sdk_checksum_func_op_state_is_terminal", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_op_state_is_terminal() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_op_state_is_terminal.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_open
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_open = findDowncallHandle("uniffi_scaas_sdk_checksum_func_open", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_open() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_open.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_register_attrs_default
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_register_attrs_default = findDowncallHandle("uniffi_scaas_sdk_checksum_func_register_attrs_default", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_register_attrs_default() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_register_attrs_default.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_registration_blob_from_json
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_registration_blob_from_json = findDowncallHandle("uniffi_scaas_sdk_checksum_func_registration_blob_from_json", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_registration_blob_from_json() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_registration_blob_from_json.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_registration_blob_to_json
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_registration_blob_to_json = findDowncallHandle("uniffi_scaas_sdk_checksum_func_registration_blob_to_json", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_registration_blob_to_json() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_registration_blob_to_json.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_rev_of
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_rev_of = findDowncallHandle("uniffi_scaas_sdk_checksum_func_rev_of", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_rev_of() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_rev_of.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_secret_id
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_secret_id = findDowncallHandle("uniffi_scaas_sdk_checksum_func_secret_id", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_secret_id() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_secret_id.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_secret_len
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_secret_len = findDowncallHandle("uniffi_scaas_sdk_checksum_func_secret_len", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_secret_len() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_secret_len.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_secret_new
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_secret_new = findDowncallHandle("uniffi_scaas_sdk_checksum_func_secret_new", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_secret_new() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_secret_new.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_signed_op_blob_from_json
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_signed_op_blob_from_json = findDowncallHandle("uniffi_scaas_sdk_checksum_func_signed_op_blob_from_json", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_signed_op_blob_from_json() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_signed_op_blob_from_json.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_signed_op_blob_to_json
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_signed_op_blob_to_json = findDowncallHandle("uniffi_scaas_sdk_checksum_func_signed_op_blob_to_json", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_signed_op_blob_to_json() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_signed_op_blob_to_json.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_smart_account_address
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_smart_account_address = findDowncallHandle("uniffi_scaas_sdk_checksum_func_smart_account_address", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_smart_account_address() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_smart_account_address.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_store_policy_default
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_store_policy_default = findDowncallHandle("uniffi_scaas_sdk_checksum_func_store_policy_default", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_store_policy_default() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_store_policy_default.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_subject_key_args_secp256k1
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_subject_key_args_secp256k1 = findDowncallHandle("uniffi_scaas_sdk_checksum_func_subject_key_args_secp256k1", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_subject_key_args_secp256k1() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_subject_key_args_secp256k1.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_ua_line_key_target
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_ua_line_key_target = findDowncallHandle("uniffi_scaas_sdk_checksum_func_ua_line_key_target", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_ua_line_key_target() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_ua_line_key_target.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_func_ua_line_pqz_target
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_func_ua_line_pqz_target = findDowncallHandle("uniffi_scaas_sdk_checksum_func_ua_line_pqz_target", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_func_ua_line_pqz_target() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_func_ua_line_pqz_target.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_registrywrite_calldata
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_registrywrite_calldata = findDowncallHandle("uniffi_scaas_sdk_checksum_method_registrywrite_calldata", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_registrywrite_calldata() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_registrywrite_calldata.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_registrywrite_chain
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_registrywrite_chain = findDowncallHandle("uniffi_scaas_sdk_checksum_method_registrywrite_chain", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_registrywrite_chain() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_registrywrite_chain.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_registrywrite_entry
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_registrywrite_entry = findDowncallHandle("uniffi_scaas_sdk_checksum_method_registrywrite_entry", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_registrywrite_entry() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_registrywrite_entry.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_registrywrite_id
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_registrywrite_id = findDowncallHandle("uniffi_scaas_sdk_checksum_method_registrywrite_id", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_registrywrite_id() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_registrywrite_id.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_registrywrite_payer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_registrywrite_payer = findDowncallHandle("uniffi_scaas_sdk_checksum_method_registrywrite_payer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_registrywrite_payer() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_registrywrite_payer.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_registrywrite_registration_gas
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_registrywrite_registration_gas = findDowncallHandle("uniffi_scaas_sdk_checksum_method_registrywrite_registration_gas", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_registrywrite_registration_gas() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_registrywrite_registration_gas.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_registrywrite_review
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_registrywrite_review = findDowncallHandle("uniffi_scaas_sdk_checksum_method_registrywrite_review", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_registrywrite_review() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_registrywrite_review.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_registrywrite_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_registrywrite_ua = findDowncallHandle("uniffi_scaas_sdk_checksum_method_registrywrite_ua", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_registrywrite_ua() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_registrywrite_ua.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_accounts
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_accounts = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_accounts", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_accounts() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_accounts.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_add_native
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_add_native = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_add_native", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_add_native() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_add_native.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_add_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_add_ua = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_add_ua", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_add_ua() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_add_ua.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_add_watch
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_add_watch = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_add_watch", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_add_watch() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_add_watch.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_create_passkey_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_create_passkey_key = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_create_passkey_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_create_passkey_key() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_create_passkey_key.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_create_se_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_create_se_key = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_create_se_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_create_se_key() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_create_se_key.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_marks
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_marks = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_marks", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_marks() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_marks.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_msig_state
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_msig_state = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_msig_state", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_msig_state() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_msig_state.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_next_account
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_next_account = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_next_account", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_next_account() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_next_account.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_pqz_decoy_candidates
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_pqz_decoy_candidates = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_pqz_decoy_candidates", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_pqz_decoy_candidates() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_pqz_decoy_candidates.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_accept_membership
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_accept_membership = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_accept_membership", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_accept_membership() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_accept_membership.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_complete_recovery
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_complete_recovery = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_complete_recovery", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_complete_recovery() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_complete_recovery.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_initiate_recovery
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_initiate_recovery = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_initiate_recovery", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_initiate_recovery() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_initiate_recovery.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_kem_repair
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_kem_repair = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_kem_repair", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_kem_repair() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_kem_repair.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_msig_register
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_msig_register = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_msig_register", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_msig_register() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_msig_register.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_register
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_register = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_register", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_register() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_register.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_set_kem_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_set_kem_key = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_set_kem_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_set_kem_key() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_set_kem_key.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_smart_add_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_add_key = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_smart_add_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_smart_add_key() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_add_key.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_smart_cancel_nonce
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_cancel_nonce = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_smart_cancel_nonce", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_smart_cancel_nonce() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_cancel_nonce.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_smart_cancel_recovery
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_cancel_recovery = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_smart_cancel_recovery", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_smart_cancel_recovery() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_cancel_recovery.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_smart_deploy
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_deploy = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_smart_deploy", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_smart_deploy() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_deploy.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_smart_execute
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_execute = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_smart_execute", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_smart_execute() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_execute.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_smart_remove_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_remove_key = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_smart_remove_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_smart_remove_key() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_remove_key.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_smart_rotate_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_rotate_key = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_smart_rotate_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_smart_rotate_key() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_rotate_key.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_smart_set_guardian
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_set_guardian = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_smart_set_guardian", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_smart_set_guardian() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_smart_set_guardian.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_submit_registration
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_submit_registration = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_submit_registration", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_submit_registration() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_submit_registration.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_prepare_update_msig
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_prepare_update_msig = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_prepare_update_msig", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_prepare_update_msig() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_prepare_update_msig.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_quote_registry_write
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_quote_registry_write = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_quote_registry_write", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_quote_registry_write() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_quote_registry_write.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_register_target
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_register_target = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_register_target", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_register_target() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_register_target.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_registration_blob
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_registration_blob = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_registration_blob", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_registration_blob() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_registration_blob.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_registration_of
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_registration_of = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_registration_of", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_registration_of() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_registration_of.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_restore
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_restore = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_restore", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_restore() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_restore.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_signs
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_signs = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_signs", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_signs() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_signs.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_submit_registry_write
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_submit_registry_write = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_submit_registry_write", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_submit_registry_write() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_submit_registry_write.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_account_ua_line
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_account_ua_line = findDowncallHandle("uniffi_scaas_sdk_checksum_method_account_ua_line", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_account_ua_line() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_account_ua_line.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_accept_admin
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_accept_admin = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_accept_admin", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_accept_admin() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_accept_admin.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_dex_release
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_dex_release = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_dex_release", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_dex_release() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_dex_release.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_release
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_release = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_release", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_release() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_release.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_token_release
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_token_release = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_token_release", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_token_release() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_approve_token_release.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_grant
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_grant = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_grant", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_grant() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_grant.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_nonce
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_nonce = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_nonce", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_nonce() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_nonce.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_rate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_rate = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_rate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_rate() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_cancel_rate.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_dex
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_dex = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_dex", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_dex() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_dex.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_instance
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_instance = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_instance", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_instance() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_instance.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_token
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_token = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_token", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_token() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_create_token.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_dex
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_dex = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_dex", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_dex() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_dex.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_release
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_release = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_release", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_release() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_release.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_token
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_token = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_token", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_token() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_deprecate_token.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_disable_feature
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_disable_feature = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_disable_feature", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_disable_feature() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_disable_feature.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_disable_wrap
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_disable_wrap = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_disable_wrap", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_disable_wrap() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_disable_wrap.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_enable_feature
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_enable_feature = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_enable_feature", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_enable_feature() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_enable_feature.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_execute_rate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_execute_rate = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_execute_rate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_execute_rate() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_execute_rate.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_force_transfer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_force_transfer = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_force_transfer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_force_transfer() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_force_transfer.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_freeze
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_freeze = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_freeze", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_freeze() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_freeze.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_grant_role
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_grant_role = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_grant_role", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_grant_role() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_grant_role.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_mint
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_mint = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_mint", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_mint() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_mint.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_mint_to_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_mint_to_ua = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_mint_to_ua", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_mint_to_ua() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_mint_to_ua.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_operator_transfer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_operator_transfer = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_operator_transfer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_operator_transfer() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_operator_transfer.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_pause
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_pause = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_pause", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_pause() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_pause.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_cancel_verifier
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_cancel_verifier = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_cancel_verifier", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_cancel_verifier() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_cancel_verifier.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_revoke_verifier
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_revoke_verifier = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_revoke_verifier", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_revoke_verifier() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_revoke_verifier.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_set_verifier
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_set_verifier = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_set_verifier", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_set_verifier() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_pqz_set_verifier.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_propose_rate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_propose_rate = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_propose_rate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_propose_rate() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_propose_rate.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_class_env
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_class_env = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_class_env", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_class_env() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_class_env.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_dex_env
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_dex_env = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_dex_env", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_dex_env() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_dex_env.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_token_env
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_token_env = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_token_env", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_token_env() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_publish_token_env.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_record_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_record_order = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_record_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_record_order() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_record_order.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_renounce_admin
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_renounce_admin = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_renounce_admin", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_renounce_admin() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_renounce_admin.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_renounce_role
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_renounce_role = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_renounce_role", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_renounce_role() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_renounce_role.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_approval
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_approval = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_approval", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_approval() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_approval.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_order = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_order() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_order.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_role
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_role = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_role", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_role() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_revoke_role.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_allowed
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_allowed = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_allowed", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_allowed() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_allowed.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_auditor_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_auditor_key = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_auditor_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_auditor_key() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_auditor_key.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_auditor_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_auditor_ua = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_auditor_ua", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_auditor_ua() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_auditor_ua.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_chain_entries
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_chain_entries = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_chain_entries", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_chain_entries() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_chain_entries.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_class_kind_enabled
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_class_kind_enabled = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_class_kind_enabled", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_class_kind_enabled() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_class_kind_enabled.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_compliance
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_compliance = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_compliance", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_compliance() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_compliance.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_denied
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_denied = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_denied", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_denied() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_denied.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_exchange_target
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_exchange_target = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_exchange_target", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_exchange_target() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_exchange_target.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_fee_split
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_fee_split = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_fee_split", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_fee_split() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_fee_split.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_grant
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_grant = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_grant", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_grant() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_grant.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_kyc_provider
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_kyc_provider = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_kyc_provider", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_kyc_provider() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_kyc_provider.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_listed_only
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_listed_only = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_listed_only", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_listed_only() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_listed_only.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_market
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_market = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_market", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_market() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_market.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_max_supply
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_max_supply = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_max_supply", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_max_supply() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_max_supply.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_max_wrap_supply
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_max_wrap_supply = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_max_wrap_supply", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_max_wrap_supply() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_max_wrap_supply.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_proof_store
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_proof_store = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_proof_store", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_proof_store() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_proof_store.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_tax_rate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_tax_rate = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_tax_rate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_tax_rate() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_tax_rate.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_tax_recipient
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_tax_recipient = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_tax_recipient", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_tax_recipient() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_tax_recipient.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_token_kind_enabled
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_token_kind_enabled = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_token_kind_enabled", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_token_kind_enabled() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_token_kind_enabled.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_verifier_fee
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_verifier_fee = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_verifier_fee", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_verifier_fee() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_verifier_fee.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_wrap_limits
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_wrap_limits = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_wrap_limits", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_wrap_limits() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_wrap_limits.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_wrap_member
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_wrap_member = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_wrap_member", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_wrap_member() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_set_wrap_member.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_transfer_admin
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_transfer_admin = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_transfer_admin", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_transfer_admin() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_transfer_admin.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_unfreeze
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_unfreeze = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_unfreeze", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_unfreeze() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_unfreeze.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_admin_ua_unpause
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_unpause = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_admin_ua_unpause", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_admin_ua_unpause() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_admin_ua_unpause.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_create3_address
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_create3_address = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_create3_address", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_create3_address() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_create3_address.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_governance_delay
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_governance_delay = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_governance_delay", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_governance_delay() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_governance_delay.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_sign_pqz_auditor_consent
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_sign_pqz_auditor_consent = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_sign_pqz_auditor_consent", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_sign_pqz_auditor_consent() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_sign_pqz_auditor_consent.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_sign_rescue_vault
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_sign_rescue_vault = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_sign_rescue_vault", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_sign_rescue_vault() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_sign_rescue_vault.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_admin_sign_zether_auditor_consent
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_admin_sign_zether_auditor_consent = findDowncallHandle("uniffi_scaas_sdk_checksum_method_admin_sign_zether_auditor_consent", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_admin_sign_zether_auditor_consent() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_admin_sign_zether_auditor_consent.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_pqz_balance
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_pqz_balance = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_pqz_balance", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_pqz_balance() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_pqz_balance.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_pqz_balance_all
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_pqz_balance_all = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_pqz_balance_all", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_pqz_balance_all() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_pqz_balance_all.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_prepare_acc
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_prepare_acc = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_prepare_acc", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_prepare_acc() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_prepare_acc.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_roll_over
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_roll_over = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_roll_over", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_roll_over() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_roll_over.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_shield
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_shield = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_shield", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_shield() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_shield.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_compact
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_compact = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_compact", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_compact() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_compact.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_multi
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_multi = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_multi", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_multi() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_multi.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_multi_compact
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_multi_compact = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_multi_compact", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_multi_compact() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_transfer_multi_compact.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_unshield
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_unshield = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_unshield", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_unshield() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_unshield.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_unshield_unwrap
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_unshield_unwrap = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_unshield_unwrap", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_unshield_unwrap() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_unshield_unwrap.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_wrap_shield
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_wrap_shield = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_wrap_shield", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_wrap_shield() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_pqz_wrap_shield.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_owner_roll_over
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_owner_roll_over = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_owner_roll_over", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_owner_roll_over() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_owner_roll_over.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_owner_set_mode
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_owner_set_mode = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_owner_set_mode", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_owner_set_mode() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_owner_set_mode.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over_batch
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over_batch = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over_batch", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over_batch() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over_batch.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over_signed
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over_signed = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over_signed", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over_signed() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_roll_over_signed.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_set_roll_over_mode
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_set_roll_over_mode = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_set_roll_over_mode", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_set_roll_over_mode() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_set_roll_over_mode.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_shield
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_shield = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_shield", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_shield() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_shield.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer_compact
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer_compact = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer_compact", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer_compact() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer_compact.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer_multi
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer_multi = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer_multi", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer_multi() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_transfer_multi.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_unshield
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_unshield = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_unshield", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_unshield() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_unshield.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_unshield_unwrap
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_unshield_unwrap = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_unshield_unwrap", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_unshield_unwrap() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_unshield_unwrap.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_wrap_shield
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_wrap_shield = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_wrap_shield", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_wrap_shield() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_prepare_zether_wrap_shield.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_request_verdict
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_request_verdict = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_request_verdict", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_request_verdict() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_request_verdict.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_zether_balance
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_zether_balance = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_zether_balance", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_zether_balance() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_zether_balance.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_confidential_zether_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_confidential_zether_key = findDowncallHandle("uniffi_scaas_sdk_checksum_method_confidential_zether_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_confidential_zether_key() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_confidential_zether_key.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_cancel_all
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_cancel_all = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_cancel_all", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_cancel_all() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_cancel_all.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_depth
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_depth = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_depth", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_depth() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_depth.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_markets
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_markets = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_markets", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_markets() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_markets.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_orders
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_orders = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_orders", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_orders() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_orders.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_place
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_place = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_place", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_place() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_place.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_prepare_cancel_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_prepare_cancel_order = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_prepare_cancel_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_prepare_cancel_order() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_prepare_cancel_order.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_prepare_cancel_wrap_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_prepare_cancel_wrap_order = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_prepare_cancel_wrap_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_prepare_cancel_wrap_order() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_prepare_cancel_wrap_order.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_prepare_liquidity_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_prepare_liquidity_order = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_prepare_liquidity_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_prepare_liquidity_order() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_prepare_liquidity_order.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_prepare_trade_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_prepare_trade_order = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_prepare_trade_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_prepare_trade_order() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_prepare_trade_order.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_prepare_wrap_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_prepare_wrap_order = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_prepare_wrap_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_prepare_wrap_order() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_prepare_wrap_order.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_sign_order
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_sign_order = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_sign_order", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_sign_order() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_sign_order.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_ticker
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_ticker = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_ticker", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_ticker() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_ticker.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_dex_trades
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_dex_trades = findDowncallHandle("uniffi_scaas_sdk_checksum_method_dex_trades", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_dex_trades() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_dex_trades.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_foreignauthenticator_create_passkey
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_foreignauthenticator_create_passkey = findDowncallHandle("uniffi_scaas_sdk_checksum_method_foreignauthenticator_create_passkey", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_foreignauthenticator_create_passkey() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_foreignauthenticator_create_passkey.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_foreignauthenticator_get_assertion
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_foreignauthenticator_get_assertion = findDowncallHandle("uniffi_scaas_sdk_checksum_method_foreignauthenticator_get_assertion", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_foreignauthenticator_get_assertion() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_foreignauthenticator_get_assertion.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_foreignauthenticator_platform_secret
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_foreignauthenticator_platform_secret = findDowncallHandle("uniffi_scaas_sdk_checksum_method_foreignauthenticator_platform_secret", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_foreignauthenticator_platform_secret() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_foreignauthenticator_platform_secret.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_foreignauthenticator_p256_generate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_foreignauthenticator_p256_generate = findDowncallHandle("uniffi_scaas_sdk_checksum_method_foreignauthenticator_p256_generate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_foreignauthenticator_p256_generate() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_foreignauthenticator_p256_generate.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_foreignauthenticator_p256_sign
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_foreignauthenticator_p256_sign = findDowncallHandle("uniffi_scaas_sdk_checksum_method_foreignauthenticator_p256_sign", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_foreignauthenticator_p256_sign() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_foreignauthenticator_p256_sign.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_foreignstore_get
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_foreignstore_get = findDowncallHandle("uniffi_scaas_sdk_checksum_method_foreignstore_get", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_foreignstore_get() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_foreignstore_get.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_foreignstore_put_if
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_foreignstore_put_if = findDowncallHandle("uniffi_scaas_sdk_checksum_method_foreignstore_put_if", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_foreignstore_put_if() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_foreignstore_put_if.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_foreignstore_delete
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_foreignstore_delete = findDowncallHandle("uniffi_scaas_sdk_checksum_method_foreignstore_delete", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_foreignstore_delete() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_foreignstore_delete.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_foreignstore_lock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_foreignstore_lock = findDowncallHandle("uniffi_scaas_sdk_checksum_method_foreignstore_lock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_foreignstore_lock() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_foreignstore_lock.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_foreignstore_unlock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_foreignstore_unlock = findDowncallHandle("uniffi_scaas_sdk_checksum_method_foreignstore_unlock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_foreignstore_unlock() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_foreignstore_unlock.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_bls_multi_part
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_bls_multi_part = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_bls_multi_part", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_bls_multi_part() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_bls_multi_part.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_bls_multi_part_ok
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_bls_multi_part_ok = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_bls_multi_part_ok", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_bls_multi_part_ok() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_bls_multi_part_ok.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_bls_multi_pop_part
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_bls_multi_pop_part = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_bls_multi_pop_part", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_bls_multi_pop_part() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_bls_multi_pop_part.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_bls_multi_pop_part_ok
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_bls_multi_pop_part_ok = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_bls_multi_pop_part_ok", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_bls_multi_pop_part_ok() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_bls_multi_pop_part_ok.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_hand_off
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_hand_off = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_hand_off", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_hand_off() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_hand_off.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_import_signed
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_import_signed = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_import_signed", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_import_signed() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_import_signed.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_member_sign
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_member_sign = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_member_sign", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_member_sign() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_member_sign.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_quote
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_quote = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_quote", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_quote() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_quote.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_quote_register_bls_multi
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_quote_register_bls_multi = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_quote_register_bls_multi", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_quote_register_bls_multi() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_quote_register_bls_multi.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_quote_with_gas
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_quote_with_gas = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_quote_with_gas", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_quote_with_gas() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_quote_with_gas.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_register_bls_multi
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_register_bls_multi = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_register_bls_multi", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_register_bls_multi() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_register_bls_multi.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_resend
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_resend = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_resend", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_resend() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_resend.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_resume
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_resume = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_resume", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_resume() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_resume.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_state
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_state = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_state", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_state() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_state.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_submit
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_submit = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_submit", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_submit() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_submit.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_op_submit_bls_multi
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_op_submit_bls_multi = findDowncallHandle("uniffi_scaas_sdk_checksum_method_op_submit_bls_multi", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_op_submit_bls_multi() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_op_submit_bls_multi.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_sdk_account
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_sdk_account = findDowncallHandle("uniffi_scaas_sdk_checksum_method_sdk_account", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_sdk_account() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_sdk_account.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_sdk_admin
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_sdk_admin = findDowncallHandle("uniffi_scaas_sdk_checksum_method_sdk_admin", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_sdk_admin() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_sdk_admin.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_sdk_confidential
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_sdk_confidential = findDowncallHandle("uniffi_scaas_sdk_checksum_method_sdk_confidential", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_sdk_confidential() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_sdk_confidential.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_sdk_dex
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_sdk_dex = findDowncallHandle("uniffi_scaas_sdk_checksum_method_sdk_dex", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_sdk_dex() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_sdk_dex.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_sdk_limits
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_sdk_limits = findDowncallHandle("uniffi_scaas_sdk_checksum_method_sdk_limits", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_sdk_limits() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_sdk_limits.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_sdk_op
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_sdk_op = findDowncallHandle("uniffi_scaas_sdk_checksum_method_sdk_op", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_sdk_op() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_sdk_op.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_sdk_state_rev
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_sdk_state_rev = findDowncallHandle("uniffi_scaas_sdk_checksum_method_sdk_state_rev", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_sdk_state_rev() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_sdk_state_rev.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_sdk_subscribe
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_sdk_subscribe = findDowncallHandle("uniffi_scaas_sdk_checksum_method_sdk_subscribe", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_sdk_subscribe() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_sdk_subscribe.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_sdk_vault
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_sdk_vault = findDowncallHandle("uniffi_scaas_sdk_checksum_method_sdk_vault", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_sdk_vault() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_sdk_vault.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_sdk_wallet
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_sdk_wallet = findDowncallHandle("uniffi_scaas_sdk_checksum_method_sdk_wallet", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_sdk_wallet() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_sdk_wallet.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_sdk_watch
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_sdk_watch = findDowncallHandle("uniffi_scaas_sdk_checksum_method_sdk_watch", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_sdk_watch() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_sdk_watch.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_subscription_next
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_subscription_next = findDowncallHandle("uniffi_scaas_sdk_checksum_method_subscription_next", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_subscription_next() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_subscription_next.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_change_passphrase
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_change_passphrase = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_change_passphrase", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_change_passphrase() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_change_passphrase.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_confirm_backup
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_confirm_backup = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_confirm_backup", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_confirm_backup() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_confirm_backup.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_derive_child
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_derive_child = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_derive_child", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_derive_child() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_derive_child.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_derive_from_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_derive_from_key = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_derive_from_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_derive_from_key() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_derive_from_key.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_derive_from_signature
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_derive_from_signature = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_derive_from_signature", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_derive_from_signature() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_derive_from_signature.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_disable_prf_unlock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_disable_prf_unlock = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_disable_prf_unlock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_disable_prf_unlock() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_disable_prf_unlock.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_enable_passkey_unlock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_enable_passkey_unlock = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_enable_passkey_unlock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_enable_passkey_unlock() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_enable_passkey_unlock.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_enable_platform_unlock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_enable_platform_unlock = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_enable_platform_unlock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_enable_platform_unlock() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_enable_platform_unlock.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_generate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_generate = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_generate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_generate() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_generate.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_import_key
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_import_key = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_import_key", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_import_key() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_import_key.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_import_words
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_import_words = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_import_words", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_import_words() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_import_words.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_key_derivation_typed_data
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_key_derivation_typed_data = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_key_derivation_typed_data", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_key_derivation_typed_data() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_key_derivation_typed_data.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_keystore_rollback
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_keystore_rollback = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_keystore_rollback", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_keystore_rollback() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_keystore_rollback.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_lock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_lock = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_lock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_lock() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_lock.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_lock_all
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_lock_all = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_lock_all", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_lock_all() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_lock_all.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_memory_protection
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_memory_protection = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_memory_protection", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_memory_protection() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_memory_protection.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_open_hidden
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_open_hidden = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_open_hidden", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_open_hidden() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_open_hidden.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_remove
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_remove = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_remove", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_remove() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_remove.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_rename
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_rename = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_rename", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_rename() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_rename.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_seed
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_seed = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_seed", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_seed() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_seed.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_seeds
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_seeds = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_seeds", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_seeds() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_seeds.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_signature_from_compact
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_signature_from_compact = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_signature_from_compact", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_signature_from_compact() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_signature_from_compact.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_unlock
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_unlock = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_unlock", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_unlock() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_unlock.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_vault_word_in_list
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_vault_word_in_list = findDowncallHandle("uniffi_scaas_sdk_checksum_method_vault_word_in_list", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_vault_word_in_list() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_vault_word_in_list.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_balances
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_balances = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_balances", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_balances() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_balances.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_history
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_history = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_history", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_history() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_history.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_native_address
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_native_address = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_native_address", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_native_address() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_native_address.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_add_reserve
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_add_reserve = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_add_reserve", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_add_reserve() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_add_reserve.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_burn
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_burn = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_burn", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_burn() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_burn.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_cancel_nonce
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_cancel_nonce = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_cancel_nonce", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_cancel_nonce() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_cancel_nonce.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_delegate_revoke
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_delegate_revoke = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_delegate_revoke", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_delegate_revoke() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_delegate_revoke.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_execute
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_execute = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_execute", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_execute() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_execute.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_native_send
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_native_send = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_native_send", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_native_send() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_native_send.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_pay
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_pay = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_pay", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_pay() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_pay.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_pay_under_mandate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_pay_under_mandate = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_pay_under_mandate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_pay_under_mandate() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_pay_under_mandate.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_pay_with_tax
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_pay_with_tax = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_pay_with_tax", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_pay_with_tax() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_pay_with_tax.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_payee_fee
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_payee_fee = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_payee_fee", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_payee_fee() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_payee_fee.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_relay_fee
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_relay_fee = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_relay_fee", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_relay_fee() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_relay_fee.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_revoke_mandate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_revoke_mandate = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_revoke_mandate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_revoke_mandate() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_revoke_mandate.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_set_mandate
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_set_mandate = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_set_mandate", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_set_mandate() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_set_mandate.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_set_payee
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_set_payee = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_set_payee", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_set_payee() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_set_payee.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_transfer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_transfer = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_transfer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_transfer() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_transfer.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap_leg
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap_leg = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap_leg", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap_leg() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap_leg.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap_to_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap_to_ua = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap_to_ua", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap_to_ua() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_unwrap_to_ua.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap_leg
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap_leg = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap_leg", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap_leg() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap_leg.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap_to_ua
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap_to_ua = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap_to_ua", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap_to_ua() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_prepare_wrap_to_ua.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_submit_native_send
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_submit_native_send = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_submit_native_send", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_submit_native_send() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_submit_native_send.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_wallet_tokens
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_wallet_tokens = findDowncallHandle("uniffi_scaas_sdk_checksum_method_wallet_tokens", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_wallet_tokens() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_wallet_tokens.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_preparedorder_chain
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_preparedorder_chain = findDowncallHandle("uniffi_scaas_sdk_checksum_method_preparedorder_chain", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_preparedorder_chain() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_preparedorder_chain.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_preparedorder_id
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_preparedorder_id = findDowncallHandle("uniffi_scaas_sdk_checksum_method_preparedorder_id", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_preparedorder_id() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_preparedorder_id.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_preparedorder_review
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_preparedorder_review = findDowncallHandle("uniffi_scaas_sdk_checksum_method_preparedorder_review", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_preparedorder_review() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_preparedorder_review.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_preparedorder_signer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_preparedorder_signer = findDowncallHandle("uniffi_scaas_sdk_checksum_method_preparedorder_signer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_preparedorder_signer() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_preparedorder_signer.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_prepared_chain
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_prepared_chain = findDowncallHandle("uniffi_scaas_sdk_checksum_method_prepared_chain", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_prepared_chain() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_prepared_chain.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_prepared_entry
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_prepared_entry = findDowncallHandle("uniffi_scaas_sdk_checksum_method_prepared_entry", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_prepared_entry() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_prepared_entry.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_prepared_expires_at
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_prepared_expires_at = findDowncallHandle("uniffi_scaas_sdk_checksum_method_prepared_expires_at", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_prepared_expires_at() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_prepared_expires_at.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_prepared_id
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_prepared_id = findDowncallHandle("uniffi_scaas_sdk_checksum_method_prepared_id", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_prepared_id() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_prepared_id.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_prepared_opaque
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_prepared_opaque = findDowncallHandle("uniffi_scaas_sdk_checksum_method_prepared_opaque", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_prepared_opaque() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_prepared_opaque.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_prepared_review
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_prepared_review = findDowncallHandle("uniffi_scaas_sdk_checksum_method_prepared_review", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_prepared_review() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_prepared_review.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_prepared_signer
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_prepared_signer = findDowncallHandle("uniffi_scaas_sdk_checksum_method_prepared_signer", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_prepared_signer() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_prepared_signer.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_seedbackup_challenge
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_seedbackup_challenge = findDowncallHandle("uniffi_scaas_sdk_checksum_method_seedbackup_challenge", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_seedbackup_challenge() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_seedbackup_challenge.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_seedbackup_reveal
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_seedbackup_reveal = findDowncallHandle("uniffi_scaas_sdk_checksum_method_seedbackup_reveal", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_seedbackup_reveal() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_seedbackup_reveal.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_checksum_method_seedbackup_verify
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_checksum_method_seedbackup_verify = findDowncallHandle("uniffi_scaas_sdk_checksum_method_seedbackup_verify", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_checksum_method_seedbackup_verify() {
        try {
            return (short) MH_uniffi_scaas_sdk_checksum_method_seedbackup_verify.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_uniffi_contract_version
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_uniffi_contract_version = findDowncallHandle("ffi_scaas_sdk_uniffi_contract_version", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_INT));

    static int ffi_scaas_sdk_uniffi_contract_version() {
        try {
            return (int) MH_ffi_scaas_sdk_uniffi_contract_version.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    

    // Integrity checks and initialization must happen after all MethodHandle fields
    // are initialized (static fields are initialized in textual order in Java).
    static {
        NamespaceLibrary.uniffiCheckContractApiVersion();
        NamespaceLibrary.uniffiCheckApiChecksums();
        
        CLEANER = UniffiCleaner.create();
        UniffiCallbackInterfaceForeignAuthenticator.INSTANCE.register();
        UniffiCallbackInterfaceForeignStore.INSTANCE.register();
        }
}

