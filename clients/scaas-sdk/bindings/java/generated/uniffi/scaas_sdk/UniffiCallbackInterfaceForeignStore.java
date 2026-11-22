package uniffi.scaas_sdk;


// Put the implementation in an object so we don't pollute the top-level namespace
public class UniffiCallbackInterfaceForeignStore {
    public static final UniffiCallbackInterfaceForeignStore INSTANCE = new UniffiCallbackInterfaceForeignStore();
    java.lang.foreign.MemorySegment vtable;

    UniffiCallbackInterfaceForeignStore() {
        // Use Arena.global() for vtable and upcall stubs — they live for the program lifetime.
        // Arena.ofAuto() stubs can be GC'd since storing an address in a struct doesn't
        // prevent the Arena from being collected.
        vtable = java.lang.foreign.Arena.global().allocate(UniffiVTableCallbackInterfaceForeignStore.LAYOUT);
        UniffiVTableCallbackInterfaceForeignStore.setuniffiFree(vtable, UniffiCallbackInterfaceFree.toUpcallStub(UniffiFree.INSTANCE, java.lang.foreign.Arena.global()));
        UniffiVTableCallbackInterfaceForeignStore.setuniffiClone(vtable, UniffiCallbackInterfaceClone.toUpcallStub(UniffiClone.INSTANCE, java.lang.foreign.Arena.global()));
        UniffiVTableCallbackInterfaceForeignStore.setget(vtable, UniffiCallbackInterfaceForeignStoreMethod0.toUpcallStub(GetCallback.INSTANCE, java.lang.foreign.Arena.global()));
        UniffiVTableCallbackInterfaceForeignStore.setputIf(vtable, UniffiCallbackInterfaceForeignStoreMethod1.toUpcallStub(PutIfCallback.INSTANCE, java.lang.foreign.Arena.global()));
        UniffiVTableCallbackInterfaceForeignStore.setdelete(vtable, UniffiCallbackInterfaceForeignStoreMethod2.toUpcallStub(DeleteCallback.INSTANCE, java.lang.foreign.Arena.global()));
        UniffiVTableCallbackInterfaceForeignStore.setlock(vtable, UniffiCallbackInterfaceForeignStoreMethod3.toUpcallStub(LockCallback.INSTANCE, java.lang.foreign.Arena.global()));
        UniffiVTableCallbackInterfaceForeignStore.setunlock(vtable, UniffiCallbackInterfaceForeignStoreMethod4.toUpcallStub(UnlockCallback.INSTANCE, java.lang.foreign.Arena.global()));
    }

    // Registers the foreign callback with the Rust side.
    void register() {
        UniffiLib.uniffi_scaas_sdk_fn_init_callback_vtable_foreignstore(vtable);
    }
    
    public static final class GetCallback implements UniffiCallbackInterfaceForeignStoreMethod0.Fn {
        public static final GetCallback INSTANCE = new GetCallback();
        private GetCallback() {}

        @Override
        public void callback(long uniffiHandle,java.lang.foreign.MemorySegment name,java.lang.foreign.MemorySegment reason,java.lang.foreign.MemorySegment uniffiFutureCallback,long uniffiCallbackData,java.lang.foreign.MemorySegment uniffiOutDroppedCallback) {
            var uniffiObj = FfiConverterTypeForeignStore.INSTANCE.handleMap.get(uniffiHandle);
            java.util.function.Supplier<java.util.concurrent.CompletableFuture<StoredItem>> makeCall = () -> {
                return uniffiObj.get(
                    FfiConverterString.INSTANCE.lift(name),
                    FfiConverterString.INSTANCE.lift(reason)
                );
                
            };
            // The completion callback always has signature: (long callbackData, java.lang.foreign.MemorySegment result) -> void
            java.lang.foreign.FunctionDescriptor uniffiCompletionDescriptor = java.lang.foreign.FunctionDescriptor.ofVoid(
                java.lang.foreign.ValueLayout.JAVA_LONG, UniffiForeignFutureResultRustBuffer.LAYOUT
            );
            java.util.function.Consumer<StoredItem> uniffiHandleSuccess = (returnValue) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultRustBuffer.LAYOUT);
                java.lang.foreign.MemorySegment lowered = FfiConverterOptionalTypeStoredItem.INSTANCE.lower(returnValue);
                UniffiForeignFutureResultRustBuffer.setreturnValue(uniffiResult, lowered);
                // Set status to success (zeroed out already)
                try {
                    // Convert the upcall java.lang.foreign.MemorySegment to a globally-scoped one for cross-thread use
                    java.lang.foreign.MemorySegment globalCallback = java.lang.foreign.MemorySegment.ofAddress(uniffiFutureCallback.address());
                    java.lang.invoke.MethodHandle mh = java.lang.foreign.Linker.nativeLinker().downcallHandle(
                        globalCallback, uniffiCompletionDescriptor);
                    mh.invokeExact(uniffiCallbackData, uniffiResult);
                } catch (Throwable t) {
                    throw new AssertionError("invokeExact failed", t);
                }
            };
            java.util.function.Consumer<java.lang.foreign.MemorySegment> uniffiHandleError = (callStatus) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultRustBuffer.LAYOUT);
                UniffiForeignFutureResultRustBuffer.setcallStatus(uniffiResult, callStatus);
                try {
                    java.lang.foreign.MemorySegment globalCallback = java.lang.foreign.MemorySegment.ofAddress(uniffiFutureCallback.address());
                    java.lang.invoke.MethodHandle mh = java.lang.foreign.Linker.nativeLinker().downcallHandle(
                        globalCallback, uniffiCompletionDescriptor);
                    mh.invokeExact(uniffiCallbackData, uniffiResult);
                } catch (Throwable t) {
                    throw new AssertionError("invokeExact failed", t);
                }
            };
            UniffiAsyncHelpers.uniffiTraitInterfaceCallAsyncWithError(
                makeCall,
                uniffiHandleSuccess,
                uniffiHandleError,
                (StoreException e) -> FfiConverterTypeStoreError.INSTANCE.lower(e),
                StoreException.class,
                uniffiOutDroppedCallback
            );
        }
    }
    
    public static final class PutIfCallback implements UniffiCallbackInterfaceForeignStoreMethod1.Fn {
        public static final PutIfCallback INSTANCE = new PutIfCallback();
        private PutIfCallback() {}

        @Override
        public void callback(long uniffiHandle,java.lang.foreign.MemorySegment name,java.lang.foreign.MemorySegment prevRev,java.lang.foreign.MemorySegment bytes,java.lang.foreign.MemorySegment policy,java.lang.foreign.MemorySegment uniffiFutureCallback,long uniffiCallbackData,java.lang.foreign.MemorySegment uniffiOutDroppedCallback) {
            var uniffiObj = FfiConverterTypeForeignStore.INSTANCE.handleMap.get(uniffiHandle);
            java.util.function.Supplier<java.util.concurrent.CompletableFuture<java.lang.Void>> makeCall = () -> {
                return uniffiObj.putIf(
                    FfiConverterString.INSTANCE.lift(name),
                    FfiConverterOptionalLong.INSTANCE.lift(prevRev),
                    FfiConverterByteArray.INSTANCE.lift(bytes),
                    FfiConverterTypeStorePolicy.INSTANCE.lift(policy)
                );
                
            };
            // The completion callback always has signature: (long callbackData, java.lang.foreign.MemorySegment result) -> void
            java.lang.foreign.FunctionDescriptor uniffiCompletionDescriptor = java.lang.foreign.FunctionDescriptor.ofVoid(
                java.lang.foreign.ValueLayout.JAVA_LONG, UniffiForeignFutureResultVoid.LAYOUT
            );
            java.util.function.Consumer<java.lang.Void> uniffiHandleSuccess = (nothing) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultVoid.LAYOUT);
                // Set status to success (zeroed out already)
                try {
                    // Convert the upcall java.lang.foreign.MemorySegment to a globally-scoped one for cross-thread use
                    java.lang.foreign.MemorySegment globalCallback = java.lang.foreign.MemorySegment.ofAddress(uniffiFutureCallback.address());
                    java.lang.invoke.MethodHandle mh = java.lang.foreign.Linker.nativeLinker().downcallHandle(
                        globalCallback, uniffiCompletionDescriptor);
                    mh.invokeExact(uniffiCallbackData, uniffiResult);
                } catch (Throwable t) {
                    throw new AssertionError("invokeExact failed", t);
                }
            };
            java.util.function.Consumer<java.lang.foreign.MemorySegment> uniffiHandleError = (callStatus) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultVoid.LAYOUT);
                UniffiForeignFutureResultVoid.setcallStatus(uniffiResult, callStatus);
                try {
                    java.lang.foreign.MemorySegment globalCallback = java.lang.foreign.MemorySegment.ofAddress(uniffiFutureCallback.address());
                    java.lang.invoke.MethodHandle mh = java.lang.foreign.Linker.nativeLinker().downcallHandle(
                        globalCallback, uniffiCompletionDescriptor);
                    mh.invokeExact(uniffiCallbackData, uniffiResult);
                } catch (Throwable t) {
                    throw new AssertionError("invokeExact failed", t);
                }
            };
            UniffiAsyncHelpers.uniffiTraitInterfaceCallAsyncWithError(
                makeCall,
                uniffiHandleSuccess,
                uniffiHandleError,
                (StoreException e) -> FfiConverterTypeStoreError.INSTANCE.lower(e),
                StoreException.class,
                uniffiOutDroppedCallback
            );
        }
    }
    
    public static final class DeleteCallback implements UniffiCallbackInterfaceForeignStoreMethod2.Fn {
        public static final DeleteCallback INSTANCE = new DeleteCallback();
        private DeleteCallback() {}

        @Override
        public void callback(long uniffiHandle,java.lang.foreign.MemorySegment name,java.lang.foreign.MemorySegment uniffiFutureCallback,long uniffiCallbackData,java.lang.foreign.MemorySegment uniffiOutDroppedCallback) {
            var uniffiObj = FfiConverterTypeForeignStore.INSTANCE.handleMap.get(uniffiHandle);
            java.util.function.Supplier<java.util.concurrent.CompletableFuture<java.lang.Void>> makeCall = () -> {
                return uniffiObj.delete(
                    FfiConverterString.INSTANCE.lift(name)
                );
                
            };
            // The completion callback always has signature: (long callbackData, java.lang.foreign.MemorySegment result) -> void
            java.lang.foreign.FunctionDescriptor uniffiCompletionDescriptor = java.lang.foreign.FunctionDescriptor.ofVoid(
                java.lang.foreign.ValueLayout.JAVA_LONG, UniffiForeignFutureResultVoid.LAYOUT
            );
            java.util.function.Consumer<java.lang.Void> uniffiHandleSuccess = (nothing) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultVoid.LAYOUT);
                // Set status to success (zeroed out already)
                try {
                    // Convert the upcall java.lang.foreign.MemorySegment to a globally-scoped one for cross-thread use
                    java.lang.foreign.MemorySegment globalCallback = java.lang.foreign.MemorySegment.ofAddress(uniffiFutureCallback.address());
                    java.lang.invoke.MethodHandle mh = java.lang.foreign.Linker.nativeLinker().downcallHandle(
                        globalCallback, uniffiCompletionDescriptor);
                    mh.invokeExact(uniffiCallbackData, uniffiResult);
                } catch (Throwable t) {
                    throw new AssertionError("invokeExact failed", t);
                }
            };
            java.util.function.Consumer<java.lang.foreign.MemorySegment> uniffiHandleError = (callStatus) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultVoid.LAYOUT);
                UniffiForeignFutureResultVoid.setcallStatus(uniffiResult, callStatus);
                try {
                    java.lang.foreign.MemorySegment globalCallback = java.lang.foreign.MemorySegment.ofAddress(uniffiFutureCallback.address());
                    java.lang.invoke.MethodHandle mh = java.lang.foreign.Linker.nativeLinker().downcallHandle(
                        globalCallback, uniffiCompletionDescriptor);
                    mh.invokeExact(uniffiCallbackData, uniffiResult);
                } catch (Throwable t) {
                    throw new AssertionError("invokeExact failed", t);
                }
            };
            UniffiAsyncHelpers.uniffiTraitInterfaceCallAsyncWithError(
                makeCall,
                uniffiHandleSuccess,
                uniffiHandleError,
                (StoreException e) -> FfiConverterTypeStoreError.INSTANCE.lower(e),
                StoreException.class,
                uniffiOutDroppedCallback
            );
        }
    }
    
    public static final class LockCallback implements UniffiCallbackInterfaceForeignStoreMethod3.Fn {
        public static final LockCallback INSTANCE = new LockCallback();
        private LockCallback() {}

        @Override
        public void callback(long uniffiHandle,java.lang.foreign.MemorySegment name,java.lang.foreign.MemorySegment uniffiFutureCallback,long uniffiCallbackData,java.lang.foreign.MemorySegment uniffiOutDroppedCallback) {
            var uniffiObj = FfiConverterTypeForeignStore.INSTANCE.handleMap.get(uniffiHandle);
            java.util.function.Supplier<java.util.concurrent.CompletableFuture<java.lang.Long>> makeCall = () -> {
                return uniffiObj.lock(
                    FfiConverterString.INSTANCE.lift(name)
                );
                
            };
            // The completion callback always has signature: (long callbackData, java.lang.foreign.MemorySegment result) -> void
            java.lang.foreign.FunctionDescriptor uniffiCompletionDescriptor = java.lang.foreign.FunctionDescriptor.ofVoid(
                java.lang.foreign.ValueLayout.JAVA_LONG, UniffiForeignFutureResultU64.LAYOUT
            );
            java.util.function.Consumer<java.lang.Long> uniffiHandleSuccess = (returnValue) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultU64.LAYOUT);
                UniffiForeignFutureResultU64.setreturnValue(uniffiResult, FfiConverterLong.INSTANCE.lower(returnValue));
                // Set status to success (zeroed out already)
                try {
                    // Convert the upcall java.lang.foreign.MemorySegment to a globally-scoped one for cross-thread use
                    java.lang.foreign.MemorySegment globalCallback = java.lang.foreign.MemorySegment.ofAddress(uniffiFutureCallback.address());
                    java.lang.invoke.MethodHandle mh = java.lang.foreign.Linker.nativeLinker().downcallHandle(
                        globalCallback, uniffiCompletionDescriptor);
                    mh.invokeExact(uniffiCallbackData, uniffiResult);
                } catch (Throwable t) {
                    throw new AssertionError("invokeExact failed", t);
                }
            };
            java.util.function.Consumer<java.lang.foreign.MemorySegment> uniffiHandleError = (callStatus) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultU64.LAYOUT);
                UniffiForeignFutureResultU64.setcallStatus(uniffiResult, callStatus);
                try {
                    java.lang.foreign.MemorySegment globalCallback = java.lang.foreign.MemorySegment.ofAddress(uniffiFutureCallback.address());
                    java.lang.invoke.MethodHandle mh = java.lang.foreign.Linker.nativeLinker().downcallHandle(
                        globalCallback, uniffiCompletionDescriptor);
                    mh.invokeExact(uniffiCallbackData, uniffiResult);
                } catch (Throwable t) {
                    throw new AssertionError("invokeExact failed", t);
                }
            };
            UniffiAsyncHelpers.uniffiTraitInterfaceCallAsyncWithError(
                makeCall,
                uniffiHandleSuccess,
                uniffiHandleError,
                (StoreException e) -> FfiConverterTypeStoreError.INSTANCE.lower(e),
                StoreException.class,
                uniffiOutDroppedCallback
            );
        }
    }
    
    public static final class UnlockCallback implements UniffiCallbackInterfaceForeignStoreMethod4.Fn {
        public static final UnlockCallback INSTANCE = new UnlockCallback();
        private UnlockCallback() {}

        @Override
        public void callback(long uniffiHandle,long token,java.lang.foreign.MemorySegment uniffiFutureCallback,long uniffiCallbackData,java.lang.foreign.MemorySegment uniffiOutDroppedCallback) {
            var uniffiObj = FfiConverterTypeForeignStore.INSTANCE.handleMap.get(uniffiHandle);
            java.util.function.Supplier<java.util.concurrent.CompletableFuture<java.lang.Void>> makeCall = () -> {
                return uniffiObj.unlock(
                    FfiConverterLong.INSTANCE.lift(token)
                );
                
            };
            // The completion callback always has signature: (long callbackData, java.lang.foreign.MemorySegment result) -> void
            java.lang.foreign.FunctionDescriptor uniffiCompletionDescriptor = java.lang.foreign.FunctionDescriptor.ofVoid(
                java.lang.foreign.ValueLayout.JAVA_LONG, UniffiForeignFutureResultVoid.LAYOUT
            );
            java.util.function.Consumer<java.lang.Void> uniffiHandleSuccess = (nothing) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultVoid.LAYOUT);
                // Set status to success (zeroed out already)
                try {
                    // Convert the upcall java.lang.foreign.MemorySegment to a globally-scoped one for cross-thread use
                    java.lang.foreign.MemorySegment globalCallback = java.lang.foreign.MemorySegment.ofAddress(uniffiFutureCallback.address());
                    java.lang.invoke.MethodHandle mh = java.lang.foreign.Linker.nativeLinker().downcallHandle(
                        globalCallback, uniffiCompletionDescriptor);
                    mh.invokeExact(uniffiCallbackData, uniffiResult);
                } catch (Throwable t) {
                    throw new AssertionError("invokeExact failed", t);
                }
            };
            java.util.function.Consumer<java.lang.foreign.MemorySegment> uniffiHandleError = (callStatus) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultVoid.LAYOUT);
                UniffiForeignFutureResultVoid.setcallStatus(uniffiResult, callStatus);
                try {
                    java.lang.foreign.MemorySegment globalCallback = java.lang.foreign.MemorySegment.ofAddress(uniffiFutureCallback.address());
                    java.lang.invoke.MethodHandle mh = java.lang.foreign.Linker.nativeLinker().downcallHandle(
                        globalCallback, uniffiCompletionDescriptor);
                    mh.invokeExact(uniffiCallbackData, uniffiResult);
                } catch (Throwable t) {
                    throw new AssertionError("invokeExact failed", t);
                }
            };
            UniffiAsyncHelpers.uniffiTraitInterfaceCallAsync(
                makeCall,
                uniffiHandleSuccess,
                uniffiHandleError,
                uniffiOutDroppedCallback
            );
        }
    }

    public static class UniffiFree implements UniffiCallbackInterfaceFree.Fn {
        public static final UniffiFree INSTANCE = new UniffiFree();

        private UniffiFree() {}

        @Override
        public void callback(long handle) {
            FfiConverterTypeForeignStore.INSTANCE.handleMap.remove(handle);
        }
    }

    public static class UniffiClone implements UniffiCallbackInterfaceClone.Fn {
        public static final UniffiClone INSTANCE = new UniffiClone();

        private UniffiClone() {}

        @Override
        public long callback(long handle) {
            return FfiConverterTypeForeignStore.INSTANCE.handleMap.clone(handle);
        }
    }
}

