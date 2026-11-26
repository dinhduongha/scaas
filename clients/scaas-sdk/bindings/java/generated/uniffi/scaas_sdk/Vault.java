package uniffi.scaas_sdk;

/**
 * Seeds (spec §6).
 */
public class Vault implements AutoCloseable, VaultInterface {
  protected long handle;
  protected UniffiCleaner.Cleanable cleanable;

  private java.util.concurrent.atomic.AtomicBoolean wasDestroyed = new java.util.concurrent.atomic.AtomicBoolean(false);
  private java.util.concurrent.atomic.AtomicLong callCounter = new java.util.concurrent.atomic.AtomicLong(1);

  /**
   * Internal constructor to wrap a raw handle from FFI.
   * The UniffiWithHandle marker disambiguates this from other constructors.
   */
  public Vault(UniffiWithHandle phantom, long handle) {
    this.handle = handle;
    this.cleanable = UniffiLib.CLEANER.register(this, new UniffiCleanAction(handle));
  }

  /**
   * This constructor can be used to instantiate a fake object. Only used for tests. Any
   * attempt to actually use an object constructed this way will fail as there is no
   * connected Rust object.
   */
  public Vault(NoHandle noHandle) {
    this.handle = 0L;
    this.cleanable = null;
  }

  

  @Override
  public synchronized void close() {
    // Only allow a single call to this method.
    // TODO(uniffi): maybe we should log a warning if called more than once?
    if (this.wasDestroyed.compareAndSet(false, true)) {
      // This decrement always matches the initial count of 1 given at creation time.
      if (this.callCounter.decrementAndGet() == 0L) {
        if (cleanable != null) {
          cleanable.clean();
        }
      }
    }
  }

  public <R> R callWithHandle(java.util.function.Function<java.lang.Long, R> block) {
    // Check and increment the call counter, to keep the object alive.
    // This needs a compare-and-set retry loop in case of concurrent updates.
    long c;
    do {
      c = this.callCounter.get();
      if (c == 0L) {
        throw new java.lang.IllegalStateException("Vault object has already been destroyed");
      }
      if (c == java.lang.Long.MAX_VALUE) {
        throw new java.lang.IllegalStateException("Vault call counter would overflow");
      }
    } while (! this.callCounter.compareAndSet(c, c + 1L));
    // Now we can safely do the method call without the handle being freed concurrently.
    try {
      return block.apply(this.uniffiCloneHandle());
    } finally {
      // This decrement always matches the increment we performed above.
      if (this.callCounter.decrementAndGet() == 0L) {
        if (cleanable != null) {
          cleanable.clean();
        }
      }
    }
  }

  public void callWithHandle(java.util.function.Consumer<java.lang.Long> block) {
    callWithHandle((java.lang.Long uniffiHandle) -> {
      block.accept(uniffiHandle);
      return (java.lang.Void)null;
    });
  }

  private class UniffiCleanAction implements Runnable {
    private final long handle;

    public UniffiCleanAction(long handle) {
      this.handle = handle;
    }

    @Override
    public void run() {
      // If the handle is 0 this is a fake object created with `NoHandle`, don't try to free.
      if (handle != 0L) {
        UniffiHelpers.uniffiRustCall((_allocator, status) -> {
          UniffiLib.uniffi_scaas_sdk_fn_free_vault(handle, status);
          return null;
        });
      }
    }
  }

  long uniffiCloneHandle() {
    return UniffiHelpers.uniffiRustCall((_allocator, status) -> {
      if (handle == 0L) {
        throw new java.lang.NullPointerException();
      }
      return UniffiLib.uniffi_scaas_sdk_fn_clone_vault(handle, status);
    });
  }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> acceptRollback(){
        return acceptRollback(java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> acceptRollback(java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_accept_rollback(
                uniffiHandle
                
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> changePassphrase(java.lang.String seed, SecretBytes old, SecretBytes _new){
        return changePassphrase(seed, old, _new, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> changePassphrase(java.lang.String seed, SecretBytes old, SecretBytes _new, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_change_passphrase(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(seed), FfiConverterTypeSecretBytes.INSTANCE.lower(old), FfiConverterTypeSecretBytes.INSTANCE.lower(_new)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> confirmBackup(java.lang.String seed){
        return confirmBackup(seed, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> confirmBackup(java.lang.String seed, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_confirm_backup(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(seed)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<NewSeed> deriveChild(DeriveChild req){
        return deriveChild(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<NewSeed> deriveChild(DeriveChild req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_derive_child(
                uniffiHandle,
                FfiConverterTypeDeriveChild.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeNewSeed.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<NewSeed> deriveFromKey(DeriveFromKey req){
        return deriveFromKey(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<NewSeed> deriveFromKey(DeriveFromKey req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_derive_from_key(
                uniffiHandle,
                FfiConverterTypeDeriveFromKey.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeNewSeed.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<NewSeed> deriveFromSignature(DeriveFromSignature req){
        return deriveFromSignature(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<NewSeed> deriveFromSignature(DeriveFromSignature req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_derive_from_signature(
                uniffiHandle,
                FfiConverterTypeDeriveFromSignature.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeNewSeed.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> disablePrfUnlock(java.lang.String seed){
        return disablePrfUnlock(seed, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> disablePrfUnlock(java.lang.String seed, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_disable_prf_unlock(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(seed)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> enablePasskeyUnlock(java.lang.String seed, SecretBytes vaultPassphrase){
        return enablePasskeyUnlock(seed, vaultPassphrase, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> enablePasskeyUnlock(java.lang.String seed, SecretBytes vaultPassphrase, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_enable_passkey_unlock(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(seed), FfiConverterTypeSecretBytes.INSTANCE.lower(vaultPassphrase)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> enablePlatformUnlock(java.lang.String seed, SecretBytes vaultPassphrase, KeyPolicy policy){
        return enablePlatformUnlock(seed, vaultPassphrase, policy, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> enablePlatformUnlock(java.lang.String seed, SecretBytes vaultPassphrase, KeyPolicy policy, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_enable_platform_unlock(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(seed), FfiConverterTypeSecretBytes.INSTANCE.lower(vaultPassphrase), FfiConverterTypeKeyPolicy.INSTANCE.lower(policy)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<NewSeed> generate(Generate req){
        return generate(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<NewSeed> generate(Generate req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_generate(
                uniffiHandle,
                FfiConverterTypeGenerate.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeNewSeed.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<ImportedKey> importKey(ImportKey req){
        return importKey(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<ImportedKey> importKey(ImportKey req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_import_key(
                uniffiHandle,
                FfiConverterTypeImportKey.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeImportedKey.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<SeedInfo> importWords(ImportWords req){
        return importWords(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<SeedInfo> importWords(ImportWords req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_import_words(
                uniffiHandle,
                FfiConverterTypeImportWords.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeSeedInfo.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    /**
     * Root (c)'s typed data for the account `account_hex` and set `set` (spec §6.6).
     */
    @Override
    public java.lang.String keyDerivationTypedData(java.lang.String accountHex, int set) throws SdkException {
            try {
                return FfiConverterString.INSTANCE.lift(
    callWithHandle(uniffiHandle -> {
        try {
    
            return
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_method_vault_key_derivation_typed_data(_allocator, uniffiHandle,
            FfiConverterString.INSTANCE.lower(accountHex), set, _status);
    });
    
        } catch (java.lang.Exception _uniffi_ex) {
            throw new java.lang.RuntimeException(_uniffi_ex);
        }
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
    

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Boolean> keystoreRollback(){
        return keystoreRollback(java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Boolean> keystoreRollback(java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_keystore_rollback(
                uniffiHandle
                
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_i8(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_i8(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_i8(future),
        // lift function
        (it) -> FfiConverterBoolean.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    /**
     * Locks `seed`: the ids of the hidden sets abandoned with it. A failed call is its error (`Internal`), never an empty
     * answer: the seed is then not known locked.
     */
    @Override
    public java.util.concurrent.CompletableFuture<java.util.List<java.lang.String>> lock(java.lang.String seed){
        return lock(seed, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.util.List<java.lang.String>> lock(java.lang.String seed, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_lock(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(seed)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterSequenceString.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    /**
     * Locks every seed (a failed call is its error, as `lock`).
     */
    @Override
    public java.util.concurrent.CompletableFuture<java.util.List<java.lang.String>> lockAll(){
        return lockAll(java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.util.List<java.lang.String>> lockAll(java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_lock_all(
                uniffiHandle
                
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterSequenceString.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    /**
     * The memory protection of an unlocked seed's arena.
     */
    @Override
    public MemoryProtection memoryProtection(java.lang.String seed) throws SdkException {
            try {
                return FfiConverterTypeMemoryProtection.INSTANCE.lift(
    callWithHandle(uniffiHandle -> {
        try {
    
            return
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_method_vault_memory_protection(_allocator, uniffiHandle,
            FfiConverterString.INSTANCE.lower(seed), _status);
    });
    
        } catch (java.lang.Exception _uniffi_ex) {
            throw new java.lang.RuntimeException(_uniffi_ex);
        }
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
    

  
    @Override
    public java.util.concurrent.CompletableFuture<SessionSet> openHidden(java.lang.String seed, Unlock unlock, SecretBytes bip39Passphrase){
        return openHidden(seed, unlock, bip39Passphrase, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<SessionSet> openHidden(java.lang.String seed, Unlock unlock, SecretBytes bip39Passphrase, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_open_hidden(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(seed), FfiConverterTypeUnlock.INSTANCE.lower(unlock), FfiConverterTypeSecretBytes.INSTANCE.lower(bip39Passphrase)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeSessionSet.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> remove(Remove req){
        return remove(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> remove(Remove req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_remove(
                uniffiHandle,
                FfiConverterTypeRemove.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> rename(java.lang.String seed, java.lang.String label){
        return rename(seed, label, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> rename(java.lang.String seed, java.lang.String label, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_rename(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(seed), FfiConverterString.INSTANCE.lower(label)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<SeedInfo> seed(java.lang.String seed){
        return seed(seed, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<SeedInfo> seed(java.lang.String seed, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_seed(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(seed)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeSeedInfo.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.util.List<SeedInfo>> seeds(){
        return seeds(java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.util.List<SeedInfo>> seeds(java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_seeds(
                uniffiHandle
                
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterSequenceTypeSeedInfo.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    /**
     * A 65-byte signature from its compact form (a secret in, a secret out).
     */
    @Override
    public SecretBytes signatureFromCompact(SecretBytes sig) throws SdkException {
            try {
                return FfiConverterTypeSecretBytes.INSTANCE.lift(
    callWithHandle(uniffiHandle -> {
        try {
    
            return
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_method_vault_signature_from_compact(uniffiHandle,
            FfiConverterTypeSecretBytes.INSTANCE.lower(sig), _status);
    });
    
        } catch (java.lang.Exception _uniffi_ex) {
            throw new java.lang.RuntimeException(_uniffi_ex);
        }
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
    

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> unlock(java.lang.String seed, Unlock unlock){
        return unlock(seed, unlock, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> unlock(java.lang.String seed, Unlock unlock, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_vault_unlock(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(seed), FfiConverterTypeUnlock.INSTANCE.lower(unlock)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    /**
     * Whether a word (a secret) is on the BIP-39 list.
     */
    @Override
    public boolean wordInList(SecretBytes word)  {
            try {
                return FfiConverterBoolean.INSTANCE.lift(
    callWithHandle(uniffiHandle -> {
        try {
    
            return
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_method_vault_word_in_list(uniffiHandle,
            FfiConverterTypeSecretBytes.INSTANCE.lower(word), _status);
    });
    
        } catch (java.lang.Exception _uniffi_ex) {
            throw new java.lang.RuntimeException(_uniffi_ex);
        }
    })
    );
            } catch (java.lang.RuntimeException _uniffi_ex) {
                
                
                if (InternalException.class.isInstance(_uniffi_ex.getCause())) {
                    throw (InternalException)_uniffi_ex.getCause();
                }
                throw _uniffi_ex;
            }
    }
    

  

  


  
}

