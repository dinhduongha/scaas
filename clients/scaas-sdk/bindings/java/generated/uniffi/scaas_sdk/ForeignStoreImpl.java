package uniffi.scaas_sdk;

/**
 * The app's store (spec §6.9) as a foreign async interface: `lock` answers a token that `unlock` releases when the SDK drops
 * the lock. A foreign exception arrives as `StoreError::Unexpected`.
 */
public class ForeignStoreImpl implements AutoCloseable, ForeignStore {
  protected long handle;
  protected UniffiCleaner.Cleanable cleanable;

  private java.util.concurrent.atomic.AtomicBoolean wasDestroyed = new java.util.concurrent.atomic.AtomicBoolean(false);
  private java.util.concurrent.atomic.AtomicLong callCounter = new java.util.concurrent.atomic.AtomicLong(1);

  /**
   * Internal constructor to wrap a raw handle from FFI.
   * The UniffiWithHandle marker disambiguates this from other constructors.
   */
  public ForeignStoreImpl(UniffiWithHandle phantom, long handle) {
    this.handle = handle;
    this.cleanable = UniffiLib.CLEANER.register(this, new UniffiCleanAction(handle));
  }

  /**
   * This constructor can be used to instantiate a fake object. Only used for tests. Any
   * attempt to actually use an object constructed this way will fail as there is no
   * connected Rust object.
   */
  public ForeignStoreImpl(NoHandle noHandle) {
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
        throw new java.lang.IllegalStateException("ForeignStoreImpl object has already been destroyed");
      }
      if (c == java.lang.Long.MAX_VALUE) {
        throw new java.lang.IllegalStateException("ForeignStoreImpl call counter would overflow");
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
          UniffiLib.uniffi_scaas_sdk_fn_free_foreignstore(handle, status);
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
      return UniffiLib.uniffi_scaas_sdk_fn_clone_foreignstore(handle, status);
    });
  }

  
    @Override
    public java.util.concurrent.CompletableFuture<StoredItem> get(java.lang.String name, java.lang.String reason){
        return get(name, reason, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<StoredItem> get(java.lang.String name, java.lang.String reason, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_foreignstore_get(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(name), FfiConverterString.INSTANCE.lower(reason)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterOptionalTypeStoredItem.INSTANCE.lift(it),
        // Error FFI converter
        new StoreExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> putIf(java.lang.String name, java.lang.Long prevRev, byte[] bytes, StorePolicy policy){
        return putIf(name, prevRev, bytes, policy, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> putIf(java.lang.String name, java.lang.Long prevRev, byte[] bytes, StorePolicy policy, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_foreignstore_put_if(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(name), FfiConverterOptionalLong.INSTANCE.lower(prevRev), FfiConverterByteArray.INSTANCE.lower(bytes), FfiConverterTypeStorePolicy.INSTANCE.lower(policy)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new StoreExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> delete(java.lang.String name){
        return delete(name, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> delete(java.lang.String name, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_foreignstore_delete(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(name)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new StoreExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Long> lock(java.lang.String name){
        return lock(name, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Long> lock(java.lang.String name, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_foreignstore_lock(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(name)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterLong.INSTANCE.lift(it),
        // Error FFI converter
        new StoreExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.Void> unlock(long token){
        return unlock(token, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> unlock(long token, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_foreignstore_unlock(
                uniffiHandle,
                token
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new UniffiNullRustCallStatusErrorHandler()
    );
    }

  

  


  
}




