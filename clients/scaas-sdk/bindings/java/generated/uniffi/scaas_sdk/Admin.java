package uniffi.scaas_sdk;

/**
 * Governance and admin rows (spec §11).
 */
public class Admin implements AutoCloseable, AdminInterface {
  protected long handle;
  protected UniffiCleaner.Cleanable cleanable;

  private java.util.concurrent.atomic.AtomicBoolean wasDestroyed = new java.util.concurrent.atomic.AtomicBoolean(false);
  private java.util.concurrent.atomic.AtomicLong callCounter = new java.util.concurrent.atomic.AtomicLong(1);

  /**
   * Internal constructor to wrap a raw handle from FFI.
   * The UniffiWithHandle marker disambiguates this from other constructors.
   */
  public Admin(UniffiWithHandle phantom, long handle) {
    this.handle = handle;
    this.cleanable = UniffiLib.CLEANER.register(this, new UniffiCleanAction(handle));
  }

  /**
   * This constructor can be used to instantiate a fake object. Only used for tests. Any
   * attempt to actually use an object constructed this way will fail as there is no
   * connected Rust object.
   */
  public Admin(NoHandle noHandle) {
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
        throw new java.lang.IllegalStateException("Admin object has already been destroyed");
      }
      if (c == java.lang.Long.MAX_VALUE) {
        throw new java.lang.IllegalStateException("Admin call counter would overflow");
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
          UniffiLib.uniffi_scaas_sdk_fn_free_admin(handle, status);
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
      return UniffiLib.uniffi_scaas_sdk_fn_clone_admin(handle, status);
    });
  }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaAcceptAdmin(UaAcceptAdmin req){
        return adminUaAcceptAdmin(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaAcceptAdmin(UaAcceptAdmin req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_accept_admin(
                uniffiHandle,
                FfiConverterTypeUaAcceptAdmin.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaApproveDexRelease(UaApproveDexRelease req){
        return adminUaApproveDexRelease(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaApproveDexRelease(UaApproveDexRelease req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_dex_release(
                uniffiHandle,
                FfiConverterTypeUaApproveDexRelease.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaApproveRelease(UaApproveRelease req){
        return adminUaApproveRelease(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaApproveRelease(UaApproveRelease req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_release(
                uniffiHandle,
                FfiConverterTypeUaApproveRelease.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaApproveTokenRelease(UaApproveTokenRelease req){
        return adminUaApproveTokenRelease(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaApproveTokenRelease(UaApproveTokenRelease req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_approve_token_release(
                uniffiHandle,
                FfiConverterTypeUaApproveTokenRelease.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaCancelGrant(UaCancelGrant req){
        return adminUaCancelGrant(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaCancelGrant(UaCancelGrant req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_grant(
                uniffiHandle,
                FfiConverterTypeUaCancelGrant.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaCancelNonce(UaCancelNonce req){
        return adminUaCancelNonce(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaCancelNonce(UaCancelNonce req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_nonce(
                uniffiHandle,
                FfiConverterTypeUaCancelNonce.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaCancelRate(UaCancelRate req){
        return adminUaCancelRate(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaCancelRate(UaCancelRate req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_cancel_rate(
                uniffiHandle,
                FfiConverterTypeUaCancelRate.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaCreateDex(UaCreateDex req){
        return adminUaCreateDex(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaCreateDex(UaCreateDex req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_create_dex(
                uniffiHandle,
                FfiConverterTypeUaCreateDex.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaCreateInstance(UaCreateInstance req){
        return adminUaCreateInstance(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaCreateInstance(UaCreateInstance req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_create_instance(
                uniffiHandle,
                FfiConverterTypeUaCreateInstance.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaCreateToken(UaCreateToken req){
        return adminUaCreateToken(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaCreateToken(UaCreateToken req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_create_token(
                uniffiHandle,
                FfiConverterTypeUaCreateToken.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaDeprecateDex(UaDeprecateDex req){
        return adminUaDeprecateDex(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaDeprecateDex(UaDeprecateDex req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_dex(
                uniffiHandle,
                FfiConverterTypeUaDeprecateDex.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaDeprecateRelease(UaDeprecateRelease req){
        return adminUaDeprecateRelease(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaDeprecateRelease(UaDeprecateRelease req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_release(
                uniffiHandle,
                FfiConverterTypeUaDeprecateRelease.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaDeprecateToken(UaDeprecateToken req){
        return adminUaDeprecateToken(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaDeprecateToken(UaDeprecateToken req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_deprecate_token(
                uniffiHandle,
                FfiConverterTypeUaDeprecateToken.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaDisableFeature(UaDisableFeature req){
        return adminUaDisableFeature(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaDisableFeature(UaDisableFeature req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_disable_feature(
                uniffiHandle,
                FfiConverterTypeUaDisableFeature.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaDisableWrap(UaDisableWrap req){
        return adminUaDisableWrap(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaDisableWrap(UaDisableWrap req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_disable_wrap(
                uniffiHandle,
                FfiConverterTypeUaDisableWrap.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaEnableFeature(UaEnableFeature req){
        return adminUaEnableFeature(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaEnableFeature(UaEnableFeature req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_enable_feature(
                uniffiHandle,
                FfiConverterTypeUaEnableFeature.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaExecuteRate(UaExecuteRate req){
        return adminUaExecuteRate(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaExecuteRate(UaExecuteRate req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_execute_rate(
                uniffiHandle,
                FfiConverterTypeUaExecuteRate.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaForceTransfer(UaForceTransfer req){
        return adminUaForceTransfer(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaForceTransfer(UaForceTransfer req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_force_transfer(
                uniffiHandle,
                FfiConverterTypeUaForceTransfer.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaFreeze(UaFreeze req){
        return adminUaFreeze(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaFreeze(UaFreeze req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_freeze(
                uniffiHandle,
                FfiConverterTypeUaFreeze.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaGrantRole(UaGrantRole req){
        return adminUaGrantRole(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaGrantRole(UaGrantRole req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_grant_role(
                uniffiHandle,
                FfiConverterTypeUaGrantRole.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaMint(UaMint req){
        return adminUaMint(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaMint(UaMint req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_mint(
                uniffiHandle,
                FfiConverterTypeUaMint.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaMintToUa(UaMintToUa req){
        return adminUaMintToUa(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaMintToUa(UaMintToUa req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_mint_to_ua(
                uniffiHandle,
                FfiConverterTypeUaMintToUA.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaOperatorTransfer(UaOperatorTransfer req){
        return adminUaOperatorTransfer(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaOperatorTransfer(UaOperatorTransfer req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_operator_transfer(
                uniffiHandle,
                FfiConverterTypeUaOperatorTransfer.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPause(UaPause req){
        return adminUaPause(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaPause(UaPause req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_pause(
                uniffiHandle,
                FfiConverterTypeUaPause.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPqzCancelVerifier(UaPqzCancelVerifier req){
        return adminUaPqzCancelVerifier(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaPqzCancelVerifier(UaPqzCancelVerifier req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_cancel_verifier(
                uniffiHandle,
                FfiConverterTypeUaPqzCancelVerifier.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPqzRevokeVerifier(UaPqzRevokeVerifier req){
        return adminUaPqzRevokeVerifier(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaPqzRevokeVerifier(UaPqzRevokeVerifier req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_revoke_verifier(
                uniffiHandle,
                FfiConverterTypeUaPqzRevokeVerifier.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPqzSetVerifier(UaPqzSetVerifier req){
        return adminUaPqzSetVerifier(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaPqzSetVerifier(UaPqzSetVerifier req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_pqz_set_verifier(
                uniffiHandle,
                FfiConverterTypeUaPqzSetVerifier.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaProposeRate(UaProposeRate req){
        return adminUaProposeRate(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaProposeRate(UaProposeRate req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_propose_rate(
                uniffiHandle,
                FfiConverterTypeUaProposeRate.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPublishClassEnv(UaPublishClassEnv req){
        return adminUaPublishClassEnv(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaPublishClassEnv(UaPublishClassEnv req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_class_env(
                uniffiHandle,
                FfiConverterTypeUaPublishClassEnv.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPublishDexEnv(UaPublishDexEnv req){
        return adminUaPublishDexEnv(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaPublishDexEnv(UaPublishDexEnv req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_dex_env(
                uniffiHandle,
                FfiConverterTypeUaPublishDexEnv.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaPublishTokenEnv(UaPublishTokenEnv req){
        return adminUaPublishTokenEnv(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaPublishTokenEnv(UaPublishTokenEnv req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_publish_token_env(
                uniffiHandle,
                FfiConverterTypeUaPublishTokenEnv.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaRecordOrder(UaRecordOrder req){
        return adminUaRecordOrder(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaRecordOrder(UaRecordOrder req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_record_order(
                uniffiHandle,
                FfiConverterTypeUaRecordOrder.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaRenounceAdmin(UaRenounceAdmin req){
        return adminUaRenounceAdmin(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaRenounceAdmin(UaRenounceAdmin req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_renounce_admin(
                uniffiHandle,
                FfiConverterTypeUaRenounceAdmin.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaRenounceRole(UaRenounceRole req){
        return adminUaRenounceRole(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaRenounceRole(UaRenounceRole req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_renounce_role(
                uniffiHandle,
                FfiConverterTypeUaRenounceRole.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaRevokeApproval(UaRevokeApproval req){
        return adminUaRevokeApproval(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaRevokeApproval(UaRevokeApproval req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_approval(
                uniffiHandle,
                FfiConverterTypeUaRevokeApproval.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaRevokeOrder(UaRevokeOrder req){
        return adminUaRevokeOrder(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaRevokeOrder(UaRevokeOrder req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_order(
                uniffiHandle,
                FfiConverterTypeUaRevokeOrder.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaRevokeRole(UaRevokeRole req){
        return adminUaRevokeRole(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaRevokeRole(UaRevokeRole req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_revoke_role(
                uniffiHandle,
                FfiConverterTypeUaRevokeRole.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetAllowed(UaSetAllowed req){
        return adminUaSetAllowed(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetAllowed(UaSetAllowed req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_allowed(
                uniffiHandle,
                FfiConverterTypeUaSetAllowed.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetAuditorKey(UaSetAuditorKey req){
        return adminUaSetAuditorKey(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetAuditorKey(UaSetAuditorKey req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_auditor_key(
                uniffiHandle,
                FfiConverterTypeUaSetAuditorKey.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetAuditorUa(UaSetAuditorUa req){
        return adminUaSetAuditorUa(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetAuditorUa(UaSetAuditorUa req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_auditor_ua(
                uniffiHandle,
                FfiConverterTypeUaSetAuditorUA.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetChainEntries(UaSetChainEntries req){
        return adminUaSetChainEntries(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetChainEntries(UaSetChainEntries req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_chain_entries(
                uniffiHandle,
                FfiConverterTypeUaSetChainEntries.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetClassKindEnabled(UaSetClassKindEnabled req){
        return adminUaSetClassKindEnabled(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetClassKindEnabled(UaSetClassKindEnabled req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_class_kind_enabled(
                uniffiHandle,
                FfiConverterTypeUaSetClassKindEnabled.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetCompliance(UaSetCompliance req){
        return adminUaSetCompliance(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetCompliance(UaSetCompliance req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_compliance(
                uniffiHandle,
                FfiConverterTypeUaSetCompliance.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetDenied(UaSetDenied req){
        return adminUaSetDenied(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetDenied(UaSetDenied req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_denied(
                uniffiHandle,
                FfiConverterTypeUaSetDenied.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetExchangeTarget(UaSetExchangeTarget req){
        return adminUaSetExchangeTarget(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetExchangeTarget(UaSetExchangeTarget req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_exchange_target(
                uniffiHandle,
                FfiConverterTypeUaSetExchangeTarget.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetFeeSplit(UaSetFeeSplit req){
        return adminUaSetFeeSplit(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetFeeSplit(UaSetFeeSplit req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_fee_split(
                uniffiHandle,
                FfiConverterTypeUaSetFeeSplit.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetGrant(UaSetGrant req){
        return adminUaSetGrant(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetGrant(UaSetGrant req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_grant(
                uniffiHandle,
                FfiConverterTypeUaSetGrant.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetKycProvider(UaSetKycProvider req){
        return adminUaSetKycProvider(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetKycProvider(UaSetKycProvider req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_kyc_provider(
                uniffiHandle,
                FfiConverterTypeUaSetKycProvider.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetListedOnly(UaSetListedOnly req){
        return adminUaSetListedOnly(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetListedOnly(UaSetListedOnly req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_listed_only(
                uniffiHandle,
                FfiConverterTypeUaSetListedOnly.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetMarket(UaSetMarket req){
        return adminUaSetMarket(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetMarket(UaSetMarket req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_market(
                uniffiHandle,
                FfiConverterTypeUaSetMarket.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetMaxSupply(UaSetMaxSupply req){
        return adminUaSetMaxSupply(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetMaxSupply(UaSetMaxSupply req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_max_supply(
                uniffiHandle,
                FfiConverterTypeUaSetMaxSupply.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetMaxWrapSupply(UaSetMaxWrapSupply req){
        return adminUaSetMaxWrapSupply(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetMaxWrapSupply(UaSetMaxWrapSupply req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_max_wrap_supply(
                uniffiHandle,
                FfiConverterTypeUaSetMaxWrapSupply.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetProofStore(UaSetProofStore req){
        return adminUaSetProofStore(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetProofStore(UaSetProofStore req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_proof_store(
                uniffiHandle,
                FfiConverterTypeUaSetProofStore.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetTaxRate(UaSetTaxRate req){
        return adminUaSetTaxRate(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetTaxRate(UaSetTaxRate req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_tax_rate(
                uniffiHandle,
                FfiConverterTypeUaSetTaxRate.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetTaxRecipient(UaSetTaxRecipient req){
        return adminUaSetTaxRecipient(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetTaxRecipient(UaSetTaxRecipient req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_tax_recipient(
                uniffiHandle,
                FfiConverterTypeUaSetTaxRecipient.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetTokenKindEnabled(UaSetTokenKindEnabled req){
        return adminUaSetTokenKindEnabled(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetTokenKindEnabled(UaSetTokenKindEnabled req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_token_kind_enabled(
                uniffiHandle,
                FfiConverterTypeUaSetTokenKindEnabled.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetVerifierFee(UaSetVerifierFee req){
        return adminUaSetVerifierFee(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetVerifierFee(UaSetVerifierFee req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_verifier_fee(
                uniffiHandle,
                FfiConverterTypeUaSetVerifierFee.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetWrapLimits(UaSetWrapLimits req){
        return adminUaSetWrapLimits(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetWrapLimits(UaSetWrapLimits req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_wrap_limits(
                uniffiHandle,
                FfiConverterTypeUaSetWrapLimits.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaSetWrapMember(UaSetWrapMember req){
        return adminUaSetWrapMember(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaSetWrapMember(UaSetWrapMember req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_set_wrap_member(
                uniffiHandle,
                FfiConverterTypeUaSetWrapMember.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaTransferAdmin(UaTransferAdmin req){
        return adminUaTransferAdmin(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaTransferAdmin(UaTransferAdmin req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_transfer_admin(
                uniffiHandle,
                FfiConverterTypeUaTransferAdmin.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaUnfreeze(UaUnfreeze req){
        return adminUaUnfreeze(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaUnfreeze(UaUnfreeze req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_unfreeze(
                uniffiHandle,
                FfiConverterTypeUaUnfreeze.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> adminUaUnpause(UaUnpause req){
        return adminUaUnpause(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> adminUaUnpause(UaUnpause req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_admin_ua_unpause(
                uniffiHandle,
                FfiConverterTypeUaUnpause.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePrepared.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    /**
     * A creation's CREATE3 addresses (`scaas-ua` `create3_address`).
     */
    @Override
    public Create3Preview create3Address(java.lang.String factory, java.lang.String creatorId, short contractClass, short kind, java.lang.String salt) throws SdkException {
            try {
                return FfiConverterTypeCreate3Preview.INSTANCE.lift(
    callWithHandle(uniffiHandle -> {
        try {
    
            return
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_method_admin_create3_address(_allocator, uniffiHandle,
            FfiConverterString.INSTANCE.lower(factory), FfiConverterString.INSTANCE.lower(creatorId), contractClass, kind, FfiConverterString.INSTANCE.lower(salt), _status);
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
    public java.util.concurrent.CompletableFuture<java.util.List<DelaySentence>> governanceDelay(java.lang.String chain, java.lang.String token, short bit, HolderKind holder){
        return governanceDelay(chain, token, bit, holder, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.util.List<DelaySentence>> governanceDelay(java.lang.String chain, java.lang.String token, short bit, HolderKind holder, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_governance_delay(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(chain), FfiConverterString.INSTANCE.lower(token), bit, FfiConverterOptionalTypeHolderKind.INSTANCE.lower(holder)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterSequenceTypeDelaySentence.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.String> signPqzAuditorConsent(AuditorConsent req){
        return signPqzAuditorConsent(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> signPqzAuditorConsent(AuditorConsent req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_sign_pqz_auditor_consent(
                uniffiHandle,
                FfiConverterTypeAuditorConsent.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterString.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<SignedRescue> signRescueVault(RescueVault req){
        return signRescueVault(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<SignedRescue> signRescueVault(RescueVault req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_sign_rescue_vault(
                uniffiHandle,
                FfiConverterTypeRescueVault.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeSignedRescue.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.String> signZetherAuditorConsent(AuditorConsent req){
        return signZetherAuditorConsent(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> signZetherAuditorConsent(AuditorConsent req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_admin_sign_zether_auditor_consent(
                uniffiHandle,
                FfiConverterTypeAuditorConsent.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterString.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  

  


  
}

