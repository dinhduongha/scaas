package uniffi.scaas_sdk;

/**
 * Zether and PQZ (spec §9).
 */
public class Confidential implements AutoCloseable, ConfidentialInterface {
  protected long handle;
  protected UniffiCleaner.Cleanable cleanable;

  private java.util.concurrent.atomic.AtomicBoolean wasDestroyed = new java.util.concurrent.atomic.AtomicBoolean(false);
  private java.util.concurrent.atomic.AtomicLong callCounter = new java.util.concurrent.atomic.AtomicLong(1);

  /**
   * Internal constructor to wrap a raw handle from FFI.
   * The UniffiWithHandle marker disambiguates this from other constructors.
   */
  public Confidential(UniffiWithHandle phantom, long handle) {
    this.handle = handle;
    this.cleanable = UniffiLib.CLEANER.register(this, new UniffiCleanAction(handle));
  }

  /**
   * This constructor can be used to instantiate a fake object. Only used for tests. Any
   * attempt to actually use an object constructed this way will fail as there is no
   * connected Rust object.
   */
  public Confidential(NoHandle noHandle) {
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
        throw new java.lang.IllegalStateException("Confidential object has already been destroyed");
      }
      if (c == java.lang.Long.MAX_VALUE) {
        throw new java.lang.IllegalStateException("Confidential call counter would overflow");
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
          UniffiLib.uniffi_scaas_sdk_fn_free_confidential(handle, status);
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
      return UniffiLib.uniffi_scaas_sdk_fn_clone_confidential(handle, status);
    });
  }

  
    @Override
    public java.util.concurrent.CompletableFuture<PqzBalance> pqzBalance(PqzBalanceRequest r){
        return pqzBalance(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<PqzBalance> pqzBalance(PqzBalanceRequest r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_pqz_balance(
                uniffiHandle,
                FfiConverterTypePqzBalanceRequest.INSTANCE.lower(r)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypePqzBalance.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<PqzBalanceAll> pqzBalanceAll(PqzBalanceRequest r){
        return pqzBalanceAll(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<PqzBalanceAll> pqzBalanceAll(PqzBalanceRequest r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_pqz_balance_all(
                uniffiHandle,
                FfiConverterTypePqzBalanceRequest.INSTANCE.lower(r)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypePqzBalanceAll.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzPrepareAcc(PqzAccountOp r){
        return preparePqzPrepareAcc(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> preparePqzPrepareAcc(PqzAccountOp r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_prepare_acc(
                uniffiHandle,
                FfiConverterTypePqzAccountOp.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzRollOver(PqzAccountOp r){
        return preparePqzRollOver(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> preparePqzRollOver(PqzAccountOp r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_roll_over(
                uniffiHandle,
                FfiConverterTypePqzAccountOp.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzShield(PqzShield r){
        return preparePqzShield(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> preparePqzShield(PqzShield r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_shield(
                uniffiHandle,
                FfiConverterTypePqzShield.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzTransfer(PqzTransfer r){
        return preparePqzTransfer(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> preparePqzTransfer(PqzTransfer r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer(
                uniffiHandle,
                FfiConverterTypePqzTransfer.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzTransferCompact(PqzTransfer r){
        return preparePqzTransferCompact(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> preparePqzTransferCompact(PqzTransfer r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_compact(
                uniffiHandle,
                FfiConverterTypePqzTransfer.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzTransferMulti(PqzTransferMulti r){
        return preparePqzTransferMulti(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> preparePqzTransferMulti(PqzTransferMulti r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_multi(
                uniffiHandle,
                FfiConverterTypePqzTransferMulti.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzTransferMultiCompact(PqzTransferMulti r){
        return preparePqzTransferMultiCompact(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> preparePqzTransferMultiCompact(PqzTransferMulti r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_transfer_multi_compact(
                uniffiHandle,
                FfiConverterTypePqzTransferMulti.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzUnshield(PqzUnshield r){
        return preparePqzUnshield(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> preparePqzUnshield(PqzUnshield r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_unshield(
                uniffiHandle,
                FfiConverterTypePqzUnshield.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzUnshieldUnwrap(PqzUnshieldUnwrap r){
        return preparePqzUnshieldUnwrap(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> preparePqzUnshieldUnwrap(PqzUnshieldUnwrap r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_unshield_unwrap(
                uniffiHandle,
                FfiConverterTypePqzUnshieldUnwrap.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> preparePqzWrapShield(PqzWrapShield r){
        return preparePqzWrapShield(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> preparePqzWrapShield(PqzWrapShield r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_pqz_wrap_shield(
                uniffiHandle,
                FfiConverterTypePqzWrapShield.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherOwnerRollOver(ZetherOwnerRollOver r){
        return prepareZetherOwnerRollOver(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherOwnerRollOver(ZetherOwnerRollOver r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_owner_roll_over(
                uniffiHandle,
                FfiConverterTypeZetherOwnerRollOver.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherOwnerSetMode(ZetherOwnerSetMode r){
        return prepareZetherOwnerSetMode(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherOwnerSetMode(ZetherOwnerSetMode r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_owner_set_mode(
                uniffiHandle,
                FfiConverterTypeZetherOwnerSetMode.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherRollOver(ZetherRollOver r){
        return prepareZetherRollOver(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherRollOver(ZetherRollOver r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over(
                uniffiHandle,
                FfiConverterTypeZetherRollOver.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherRollOverBatch(ZetherRollOverBatch r){
        return prepareZetherRollOverBatch(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherRollOverBatch(ZetherRollOverBatch r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over_batch(
                uniffiHandle,
                FfiConverterTypeZetherRollOverBatch.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherRollOverSigned(ZetherOwnerRollOver r, OwnerRelay relay){
        return prepareZetherRollOverSigned(r, relay, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherRollOverSigned(ZetherOwnerRollOver r, OwnerRelay relay, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_roll_over_signed(
                uniffiHandle,
                FfiConverterTypeZetherOwnerRollOver.INSTANCE.lower(r), FfiConverterTypeOwnerRelay.INSTANCE.lower(relay)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherSetRollOverMode(ZetherOwnerSetMode r, OwnerRelay relay){
        return prepareZetherSetRollOverMode(r, relay, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherSetRollOverMode(ZetherOwnerSetMode r, OwnerRelay relay, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_set_roll_over_mode(
                uniffiHandle,
                FfiConverterTypeZetherOwnerSetMode.INSTANCE.lower(r), FfiConverterTypeOwnerRelay.INSTANCE.lower(relay)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherShield(ZetherShield r){
        return prepareZetherShield(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherShield(ZetherShield r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_shield(
                uniffiHandle,
                FfiConverterTypeZetherShield.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherTransfer(ZetherTransfer r){
        return prepareZetherTransfer(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherTransfer(ZetherTransfer r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer(
                uniffiHandle,
                FfiConverterTypeZetherTransfer.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherTransferCompact(ZetherTransferMulti r){
        return prepareZetherTransferCompact(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherTransferCompact(ZetherTransferMulti r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer_compact(
                uniffiHandle,
                FfiConverterTypeZetherTransferMulti.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherTransferMulti(ZetherTransferMulti r){
        return prepareZetherTransferMulti(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherTransferMulti(ZetherTransferMulti r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_transfer_multi(
                uniffiHandle,
                FfiConverterTypeZetherTransferMulti.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherUnshield(ZetherUnshield r){
        return prepareZetherUnshield(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherUnshield(ZetherUnshield r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_unshield(
                uniffiHandle,
                FfiConverterTypeZetherUnshield.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherUnshieldUnwrap(ZetherUnshieldUnwrap r){
        return prepareZetherUnshieldUnwrap(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherUnshieldUnwrap(ZetherUnshieldUnwrap r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_unshield_unwrap(
                uniffiHandle,
                FfiConverterTypeZetherUnshieldUnwrap.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareZetherWrapShield(ZetherWrapShield r){
        return prepareZetherWrapShield(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareZetherWrapShield(ZetherWrapShield r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_prepare_zether_wrap_shield(
                uniffiHandle,
                FfiConverterTypeZetherWrapShield.INSTANCE.lower(r)
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
    public java.util.concurrent.CompletableFuture<Value> requestVerdict(PqzVerdictRequest r){
        return requestVerdict(r, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Value> requestVerdict(PqzVerdictRequest r, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_request_verdict(
                uniffiHandle,
                FfiConverterTypePqzVerdictRequest.INSTANCE.lower(r)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeValue.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<ZetherBalance> zetherBalance(ZetherBalanceRequest req){
        return zetherBalance(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<ZetherBalance> zetherBalance(ZetherBalanceRequest req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_zether_balance(
                uniffiHandle,
                FfiConverterTypeZetherBalanceRequest.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeZetherBalance.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<ZetherKeyInfo> zetherKey(java.lang.String seed, int account){
        return zetherKey(seed, account, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<ZetherKeyInfo> zetherKey(java.lang.String seed, int account, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_confidential_zether_key(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(seed), account
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeZetherKeyInfo.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  

  


  
}

