package uniffi.scaas_sdk;

/**
 * The app's authenticator (spec §6.10) as a foreign async interface. A PRF output or platform secret is written by the app
 * through the copy calls into the secret whose id it is given (`prf_out`, `out`). A foreign exception arrives as
 * `AuthError::Unexpected`.
 */
public class ForeignAuthenticatorImpl implements AutoCloseable, ForeignAuthenticator {
  protected long handle;
  protected UniffiCleaner.Cleanable cleanable;

  private java.util.concurrent.atomic.AtomicBoolean wasDestroyed = new java.util.concurrent.atomic.AtomicBoolean(false);
  private java.util.concurrent.atomic.AtomicLong callCounter = new java.util.concurrent.atomic.AtomicLong(1);

  /**
   * Internal constructor to wrap a raw handle from FFI.
   * The UniffiWithHandle marker disambiguates this from other constructors.
   */
  public ForeignAuthenticatorImpl(UniffiWithHandle phantom, long handle) {
    this.handle = handle;
    this.cleanable = UniffiLib.CLEANER.register(this, new UniffiCleanAction(handle));
  }

  /**
   * This constructor can be used to instantiate a fake object. Only used for tests. Any
   * attempt to actually use an object constructed this way will fail as there is no
   * connected Rust object.
   */
  public ForeignAuthenticatorImpl(NoHandle noHandle) {
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
        throw new java.lang.IllegalStateException("ForeignAuthenticatorImpl object has already been destroyed");
      }
      if (c == java.lang.Long.MAX_VALUE) {
        throw new java.lang.IllegalStateException("ForeignAuthenticatorImpl call counter would overflow");
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
          UniffiLib.uniffi_scaas_sdk_fn_free_foreignauthenticator(handle, status);
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
      return UniffiLib.uniffi_scaas_sdk_fn_clone_foreignauthenticator(handle, status);
    });
  }

  
    @Override
    public java.util.concurrent.CompletableFuture<PasskeyCreated> createPasskey(java.lang.String rpId, java.lang.String userName, java.util.List<byte[]> exclude){
        return createPasskey(rpId, userName, exclude, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<PasskeyCreated> createPasskey(java.lang.String rpId, java.lang.String userName, java.util.List<byte[]> exclude, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_foreignauthenticator_create_passkey(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(rpId), FfiConverterString.INSTANCE.lower(userName), FfiConverterSequenceByteArray.INSTANCE.lower(exclude)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypePasskeyCreated.INSTANCE.lift(it),
        // Error FFI converter
        new AuthExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Assertion> getAssertion(AssertionRequest req, long prfOut){
        return getAssertion(req, prfOut, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Assertion> getAssertion(AssertionRequest req, long prfOut, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_foreignauthenticator_get_assertion(
                uniffiHandle,
                FfiConverterTypeAssertionRequest.INSTANCE.lower(req), prfOut
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeAssertion.INSTANCE.lift(it),
        // Error FFI converter
        new AuthExceptionErrorHandler()
    );
    }

  
    /**
     * `key_handle`: the platform key's handle (the Rust trait's `handle`; named apart from the generated callbacks' own local
     * `handle`, which uniffi-bindgen-cs and -go do not rename)
     */
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> platformSecret(java.lang.String keyHandle, byte[] salt, java.lang.String reason, KeyPolicy policy, long out){
        return platformSecret(keyHandle, salt, reason, policy, out, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> platformSecret(java.lang.String keyHandle, byte[] salt, java.lang.String reason, KeyPolicy policy, long out, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_foreignauthenticator_platform_secret(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(keyHandle), FfiConverterByteArray.INSTANCE.lower(salt), FfiConverterString.INSTANCE.lower(reason), FfiConverterOptionalTypeKeyPolicy.INSTANCE.lower(policy), out
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new AuthExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<SePublic> p256Generate(KeyPolicy policy){
        return p256Generate(policy, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<SePublic> p256Generate(KeyPolicy policy, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_foreignauthenticator_p256_generate(
                uniffiHandle,
                FfiConverterTypeKeyPolicy.INSTANCE.lower(policy)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeSePublic.INSTANCE.lift(it),
        // Error FFI converter
        new AuthExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<byte[]> p256Sign(java.lang.String keyHandle, byte[] uaMsg, java.lang.String reason){
        return p256Sign(keyHandle, uaMsg, reason, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<byte[]> p256Sign(java.lang.String keyHandle, byte[] uaMsg, java.lang.String reason, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_foreignauthenticator_p256_sign(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(keyHandle), FfiConverterByteArray.INSTANCE.lower(uaMsg), FfiConverterString.INSTANCE.lower(reason)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterByteArray.INSTANCE.lift(it),
        // Error FFI converter
        new AuthExceptionErrorHandler()
    );
    }

  

  


  
}


