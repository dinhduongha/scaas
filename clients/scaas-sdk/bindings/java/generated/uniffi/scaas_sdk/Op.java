package uniffi.scaas_sdk;

/**
 * Operations: quote, submit, follow (spec §13).
 */
public class Op implements AutoCloseable, OpInterface {
  protected long handle;
  protected UniffiCleaner.Cleanable cleanable;

  private java.util.concurrent.atomic.AtomicBoolean wasDestroyed = new java.util.concurrent.atomic.AtomicBoolean(false);
  private java.util.concurrent.atomic.AtomicLong callCounter = new java.util.concurrent.atomic.AtomicLong(1);

  /**
   * Internal constructor to wrap a raw handle from FFI.
   * The UniffiWithHandle marker disambiguates this from other constructors.
   */
  public Op(UniffiWithHandle phantom, long handle) {
    this.handle = handle;
    this.cleanable = UniffiLib.CLEANER.register(this, new UniffiCleanAction(handle));
  }

  /**
   * This constructor can be used to instantiate a fake object. Only used for tests. Any
   * attempt to actually use an object constructed this way will fail as there is no
   * connected Rust object.
   */
  public Op(NoHandle noHandle) {
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
        throw new java.lang.IllegalStateException("Op object has already been destroyed");
      }
      if (c == java.lang.Long.MAX_VALUE) {
        throw new java.lang.IllegalStateException("Op call counter would overflow");
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
          UniffiLib.uniffi_scaas_sdk_fn_free_op(handle, status);
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
      return UniffiLib.uniffi_scaas_sdk_fn_clone_op(handle, status);
    });
  }

  
    @Override
    public java.util.concurrent.CompletableFuture<BlsMultiPart> blsMultiPart(Prepared prepared, KeyRef member){
        return blsMultiPart(prepared, member, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<BlsMultiPart> blsMultiPart(Prepared prepared, KeyRef member, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_bls_multi_part(
                uniffiHandle,
                FfiConverterTypePrepared.INSTANCE.lower(prepared), FfiConverterTypeKeyRef.INSTANCE.lower(member)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeBlsMultiPart.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    /**
     * Whether `part` is a valid partial of `prepared`'s group on it (`bls12381-multi`, spec §5.4).
     */
    @Override
    public boolean blsMultiPartOk(Prepared prepared, BlsMultiPart part)  {
            try {
                return FfiConverterBoolean.INSTANCE.lift(
    callWithHandle(uniffiHandle -> {
        try {
    
            return
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_method_op_bls_multi_part_ok(uniffiHandle,
            FfiConverterTypePrepared.INSTANCE.lower(prepared), FfiConverterTypeBlsMultiPart.INSTANCE.lower(part), _status);
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
    

  
    /**
     * Member `member`'s PoP part for its group's registration.
     */
    @Override
    public BlsMultiPart blsMultiPopPart(KeyRef member) throws SdkException {
            try {
                return FfiConverterTypeBlsMultiPart.INSTANCE.lift(
    callWithHandle(uniffiHandle -> {
        try {
    
            return
    UniffiHelpers.uniffiRustCallWithError(new SdkExceptionErrorHandler(), (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_method_op_bls_multi_pop_part(_allocator, uniffiHandle,
            FfiConverterTypeKeyRef.INSTANCE.lower(member), _status);
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
    

  
    /**
     * Whether `part` is a valid PoP part of the group `key_data` (`0x` hex).
     */
    @Override
    public boolean blsMultiPopPartOk(java.lang.String keyData, BlsMultiPart part)  {
            try {
                return FfiConverterBoolean.INSTANCE.lift(
    callWithHandle(uniffiHandle -> {
        try {
    
            return
    UniffiHelpers.uniffiRustCall( (_allocator, _status) -> {
        return UniffiLib.uniffi_scaas_sdk_fn_method_op_bls_multi_pop_part_ok(uniffiHandle,
            FfiConverterString.INSTANCE.lower(keyData), FfiConverterTypeBlsMultiPart.INSTANCE.lower(part), _status);
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
    

  
    @Override
    public java.util.concurrent.CompletableFuture<SignedOpBlob> handOff(Prepared prepared){
        return handOff(prepared, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<SignedOpBlob> handOff(Prepared prepared, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_hand_off(
                uniffiHandle,
                FfiConverterTypePrepared.INSTANCE.lower(prepared)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeSignedOpBlob.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<Prepared> importSigned(SignedOpBlob blob, ImportExpect expect){
        return importSigned(blob, expect, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<Prepared> importSigned(SignedOpBlob blob, ImportExpect expect, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_import_signed(
                uniffiHandle,
                FfiConverterTypeSignedOpBlob.INSTANCE.lower(blob), FfiConverterTypeImportExpect.INSTANCE.lower(expect)
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
    public java.util.concurrent.CompletableFuture<java.lang.String> memberSign(Prepared prepared){
        return memberSign(prepared, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> memberSign(Prepared prepared, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_member_sign(
                uniffiHandle,
                FfiConverterTypePrepared.INSTANCE.lower(prepared)
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
    public java.util.concurrent.CompletableFuture<SubmitQuote> quote(Prepared prepared, SubmitPath path){
        return quote(prepared, path, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<SubmitQuote> quote(Prepared prepared, SubmitPath path, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_quote(
                uniffiHandle,
                FfiConverterTypePrepared.INSTANCE.lower(prepared), FfiConverterTypeSubmitPath.INSTANCE.lower(path)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeSubmitQuote.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<SubmitQuote> quoteRegisterBlsMulti(java.lang.String chain, java.lang.String keyData, KeyRef payer){
        return quoteRegisterBlsMulti(chain, keyData, payer, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<SubmitQuote> quoteRegisterBlsMulti(java.lang.String chain, java.lang.String keyData, KeyRef payer, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_quote_register_bls_multi(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(chain), FfiConverterString.INSTANCE.lower(keyData), FfiConverterTypeKeyRef.INSTANCE.lower(payer)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeSubmitQuote.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<SubmitQuote> quoteWithGas(Prepared prepared, SubmitPath path, long gas){
        return quoteWithGas(prepared, path, gas, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<SubmitQuote> quoteWithGas(Prepared prepared, SubmitPath path, long gas, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_quote_with_gas(
                uniffiHandle,
                FfiConverterTypePrepared.INSTANCE.lower(prepared), FfiConverterTypeSubmitPath.INSTANCE.lower(path), gas
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeSubmitQuote.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.String> registerBlsMulti(java.lang.String chain, java.lang.String keyData, java.util.List<BlsMultiPart> parts, SubmitQuote quote){
        return registerBlsMulti(chain, keyData, parts, quote, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> registerBlsMulti(java.lang.String chain, java.lang.String keyData, java.util.List<BlsMultiPart> parts, SubmitQuote quote, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_register_bls_multi(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(chain), FfiConverterString.INSTANCE.lower(keyData), FfiConverterSequenceTypeBlsMultiPart.INSTANCE.lower(parts), FfiConverterTypeSubmitQuote.INSTANCE.lower(quote)
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
    public java.util.concurrent.CompletableFuture<java.lang.Void> resend(java.lang.String op, SubmitQuote quote){
        return resend(op, quote, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Void> resend(java.lang.String op, SubmitQuote quote, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_resend(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(op), FfiConverterTypeSubmitQuote.INSTANCE.lower(quote)
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
    public java.util.concurrent.CompletableFuture<java.lang.Integer> resume(){
        return resume(java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.Integer> resume(java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_resume(
                uniffiHandle
                
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_u32(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_u32(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_u32(future),
        // lift function
        (it) -> FfiConverterInteger.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<OpState> state(java.lang.String op){
        return state(op, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<OpState> state(java.lang.String op, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_state(
                uniffiHandle,
                FfiConverterString.INSTANCE.lower(op)
            );
        }),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_rust_future_poll_rust_buffer(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_rust_future_complete_rust_buffer(_allocator, future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_rust_future_free_rust_buffer(future),
        // lift function
        (it) -> FfiConverterTypeOpState.INSTANCE.lift(it),
        // Error FFI converter
        new SdkExceptionErrorHandler()
    );
    }

  
    @Override
    public java.util.concurrent.CompletableFuture<java.lang.String> submit(Prepared prepared, SubmitQuote quote){
        return submit(prepared, quote, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> submit(Prepared prepared, SubmitQuote quote, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_submit(
                uniffiHandle,
                FfiConverterTypePrepared.INSTANCE.lower(prepared), FfiConverterTypeSubmitQuote.INSTANCE.lower(quote)
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
    public java.util.concurrent.CompletableFuture<java.lang.String> submitBlsMulti(Prepared prepared, SubmitQuote quote, java.util.List<BlsMultiPart> parts, boolean surplus){
        return submitBlsMulti(prepared, quote, parts, surplus, java.util.concurrent.ForkJoinPool.commonPool());
    }public java.util.concurrent.CompletableFuture<java.lang.String> submitBlsMulti(Prepared prepared, SubmitQuote quote, java.util.List<BlsMultiPart> parts, boolean surplus, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        callWithHandle(uniffiHandle -> {
            return UniffiLib.uniffi_scaas_sdk_fn_method_op_submit_bls_multi(
                uniffiHandle,
                FfiConverterTypePrepared.INSTANCE.lower(prepared), FfiConverterTypeSubmitQuote.INSTANCE.lower(quote), FfiConverterSequenceTypeBlsMultiPart.INSTANCE.lower(parts), FfiConverterBoolean.INSTANCE.lower(surplus)
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

