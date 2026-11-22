package uniffi.scaas_sdk;

/**
 * The DEX (spec §10).
 */
public class Dex implements AutoCloseable, DexInterface {
  protected long handle;
  protected UniffiCleaner.Cleanable cleanable;

  private java.util.concurrent.atomic.AtomicBoolean wasDestroyed = new java.util.concurrent.atomic.AtomicBoolean(false);
  private java.util.concurrent.atomic.AtomicLong callCounter = new java.util.concurrent.atomic.AtomicLong(1);

  /**
   * Internal constructor to wrap a raw handle from FFI.
   * The UniffiWithHandle marker disambiguates this from other constructors.
   */
  public Dex(UniffiWithHandle phantom, long handle) {
    this.handle = handle;
    this.cleanable = UniffiLib.CLEANER.register(this, new UniffiCleanAction(handle));
  }

  /**
   * This constructor can be used to instantiate a fake object. Only used for tests. Any
   * attempt to actually use an object constructed this way will fail as there is no
   * connected Rust object.
   */
  public Dex(NoHandle noHandle) {
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
        throw new java.lang.IllegalStateException("Dex object has already been destroyed");
      }
      if (c == java.lang.Long.MAX_VALUE) {
        throw new java.lang.IllegalStateException("Dex call counter would overflow");
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
          UniffiLib.uniffi_scaas_sdk_fn_free_dex(handle, status);
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
      return UniffiLib.uniffi_scaas_sdk_fn_clone_dex(handle, status);
    });
  }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.String> cancelAll(CancelAll req){
        return cancelAll(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> cancelAll(CancelAll req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_cancel_all(
                uniffiHandle,
                FfiConverterTypeCancelAll.INSTANCE.lower(req)
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
    public java.util.concurrent.CompletableFuture<java.lang.String> depth(java.lang.String chain, long market, java.lang.Integer levels){
        return depth(chain, market, levels, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> depth(java.lang.String chain, long market, java.lang.Integer levels, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_depth(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(chain), market, FfiConverterOptionalInteger.INSTANCE.lower(levels)
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
    public java.util.concurrent.CompletableFuture<java.lang.String> markets(java.lang.String chain){
        return markets(chain, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> markets(java.lang.String chain, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_markets(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(chain)
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
    public java.util.concurrent.CompletableFuture<java.lang.String> orders(java.lang.String chain, java.lang.String maker){
        return orders(chain, maker, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> orders(java.lang.String chain, java.lang.String maker, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_orders(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(chain), FfiConverterString.INSTANCE.lower(maker)
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
    public java.util.concurrent.CompletableFuture<java.lang.String> place(PreparedOrder order){
        return place(order, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> place(PreparedOrder order, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_place(
                uniffiHandle,
                FfiConverterTypePreparedOrder.INSTANCE.lower(order)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareCancelOrder(CancelOrder req){
        return prepareCancelOrder(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareCancelOrder(CancelOrder req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_prepare_cancel_order(
                uniffiHandle,
                FfiConverterTypeCancelOrder.INSTANCE.lower(req)
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
    public java.util.concurrent.CompletableFuture<Prepared> prepareCancelWrapOrder(CancelWrapOrder req){
        return prepareCancelWrapOrder(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareCancelWrapOrder(CancelWrapOrder req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_prepare_cancel_wrap_order(
                uniffiHandle,
                FfiConverterTypeCancelWrapOrder.INSTANCE.lower(req)
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
    public java.util.concurrent.CompletableFuture<PreparedOrder> prepareLiquidityOrder(LiquidityOrder req){
        return prepareLiquidityOrder(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<PreparedOrder> prepareLiquidityOrder(LiquidityOrder req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_prepare_liquidity_order(
                uniffiHandle,
                FfiConverterTypeLiquidityOrder.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePreparedOrder.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<PreparedOrder> prepareTradeOrder(TradeOrder req){
        return prepareTradeOrder(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<PreparedOrder> prepareTradeOrder(TradeOrder req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_prepare_trade_order(
                uniffiHandle,
                FfiConverterTypeTradeOrder.INSTANCE.lower(req)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u64(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u64(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u64(future),
        // lift function
        (it) -> FfiConverterTypePreparedOrder.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> prepareWrapOrder(WrapOrder req){
        return prepareWrapOrder(req, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> prepareWrapOrder(WrapOrder req, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_prepare_wrap_order(
                uniffiHandle,
                FfiConverterTypeWrapOrder.INSTANCE.lower(req)
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
    public java.util.concurrent.CompletableFuture<SignedOrder> signOrder(PreparedOrder order){
        return signOrder(order, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<SignedOrder> signOrder(PreparedOrder order, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_sign_order(
                uniffiHandle,
                FfiConverterTypePreparedOrder.INSTANCE.lower(order)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeSignedOrder.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.String> ticker(java.lang.String chain, long market){
        return ticker(chain, market, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> ticker(java.lang.String chain, long market, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_ticker(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(chain), market
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
    public java.util.concurrent.CompletableFuture<java.lang.String> trades(java.lang.String chain, long market){
        return trades(chain, market, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> trades(java.lang.String chain, long market, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_dex_trades(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(chain), market
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

