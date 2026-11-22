package uniffi.scaas_sdk;


// Put the implementation in an object so we don't pollute the top-level namespace
public class UniffiCallbackInterfaceForeignAuthenticator {
    public static final UniffiCallbackInterfaceForeignAuthenticator INSTANCE = new UniffiCallbackInterfaceForeignAuthenticator();
    java.lang.foreign.MemorySegment vtable;

    UniffiCallbackInterfaceForeignAuthenticator() {
        // Use Arena.global() for vtable and upcall stubs — they live for the program lifetime.
        // Arena.ofAuto() stubs can be GC'd since storing an address in a struct doesn't
        // prevent the Arena from being collected.
        vtable = java.lang.foreign.Arena.global().allocate(UniffiVTableCallbackInterfaceForeignAuthenticator.LAYOUT);
        UniffiVTableCallbackInterfaceForeignAuthenticator.setuniffiFree(vtable, UniffiCallbackInterfaceFree.toUpcallStub(UniffiFree.INSTANCE, java.lang.foreign.Arena.global()));
        UniffiVTableCallbackInterfaceForeignAuthenticator.setuniffiClone(vtable, UniffiCallbackInterfaceClone.toUpcallStub(UniffiClone.INSTANCE, java.lang.foreign.Arena.global()));
        UniffiVTableCallbackInterfaceForeignAuthenticator.setcreatePasskey(vtable, UniffiCallbackInterfaceForeignAuthenticatorMethod0.toUpcallStub(CreatePasskeyCallback.INSTANCE, java.lang.foreign.Arena.global()));
        UniffiVTableCallbackInterfaceForeignAuthenticator.setgetAssertion(vtable, UniffiCallbackInterfaceForeignAuthenticatorMethod1.toUpcallStub(GetAssertionCallback.INSTANCE, java.lang.foreign.Arena.global()));
        UniffiVTableCallbackInterfaceForeignAuthenticator.setplatformSecret(vtable, UniffiCallbackInterfaceForeignAuthenticatorMethod2.toUpcallStub(PlatformSecretCallback.INSTANCE, java.lang.foreign.Arena.global()));
        UniffiVTableCallbackInterfaceForeignAuthenticator.setp256Generate(vtable, UniffiCallbackInterfaceForeignAuthenticatorMethod3.toUpcallStub(P256GenerateCallback.INSTANCE, java.lang.foreign.Arena.global()));
        UniffiVTableCallbackInterfaceForeignAuthenticator.setp256Sign(vtable, UniffiCallbackInterfaceForeignAuthenticatorMethod4.toUpcallStub(P256SignCallback.INSTANCE, java.lang.foreign.Arena.global()));
    }

    // Registers the foreign callback with the Rust side.
    void register() {
        UniffiLib.uniffi_scaas_sdk_fn_init_callback_vtable_foreignauthenticator(vtable);
    }
    
    public static final class CreatePasskeyCallback implements UniffiCallbackInterfaceForeignAuthenticatorMethod0.Fn {
        public static final CreatePasskeyCallback INSTANCE = new CreatePasskeyCallback();
        private CreatePasskeyCallback() {}

        @Override
        public void callback(long uniffiHandle,java.lang.foreign.MemorySegment rpId,java.lang.foreign.MemorySegment userName,java.lang.foreign.MemorySegment exclude,java.lang.foreign.MemorySegment uniffiFutureCallback,long uniffiCallbackData,java.lang.foreign.MemorySegment uniffiOutDroppedCallback) {
            var uniffiObj = FfiConverterTypeForeignAuthenticator.INSTANCE.handleMap.get(uniffiHandle);
            java.util.function.Supplier<java.util.concurrent.CompletableFuture<PasskeyCreated>> makeCall = () -> {
                return uniffiObj.createPasskey(
                    FfiConverterString.INSTANCE.lift(rpId),
                    FfiConverterString.INSTANCE.lift(userName),
                    FfiConverterSequenceByteArray.INSTANCE.lift(exclude)
                );
                
            };
            // The completion callback always has signature: (long callbackData, java.lang.foreign.MemorySegment result) -> void
            java.lang.foreign.FunctionDescriptor uniffiCompletionDescriptor = java.lang.foreign.FunctionDescriptor.ofVoid(
                java.lang.foreign.ValueLayout.JAVA_LONG, UniffiForeignFutureResultRustBuffer.LAYOUT
            );
            java.util.function.Consumer<PasskeyCreated> uniffiHandleSuccess = (returnValue) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultRustBuffer.LAYOUT);
                java.lang.foreign.MemorySegment lowered = FfiConverterTypePasskeyCreated.INSTANCE.lower(returnValue);
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
                (AuthException e) -> FfiConverterTypeAuthError.INSTANCE.lower(e),
                AuthException.class,
                uniffiOutDroppedCallback
            );
        }
    }
    
    public static final class GetAssertionCallback implements UniffiCallbackInterfaceForeignAuthenticatorMethod1.Fn {
        public static final GetAssertionCallback INSTANCE = new GetAssertionCallback();
        private GetAssertionCallback() {}

        @Override
        public void callback(long uniffiHandle,java.lang.foreign.MemorySegment req,long prfOut,java.lang.foreign.MemorySegment uniffiFutureCallback,long uniffiCallbackData,java.lang.foreign.MemorySegment uniffiOutDroppedCallback) {
            var uniffiObj = FfiConverterTypeForeignAuthenticator.INSTANCE.handleMap.get(uniffiHandle);
            java.util.function.Supplier<java.util.concurrent.CompletableFuture<Assertion>> makeCall = () -> {
                return uniffiObj.getAssertion(
                    FfiConverterTypeAssertionRequest.INSTANCE.lift(req),
                    FfiConverterLong.INSTANCE.lift(prfOut)
                );
                
            };
            // The completion callback always has signature: (long callbackData, java.lang.foreign.MemorySegment result) -> void
            java.lang.foreign.FunctionDescriptor uniffiCompletionDescriptor = java.lang.foreign.FunctionDescriptor.ofVoid(
                java.lang.foreign.ValueLayout.JAVA_LONG, UniffiForeignFutureResultRustBuffer.LAYOUT
            );
            java.util.function.Consumer<Assertion> uniffiHandleSuccess = (returnValue) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultRustBuffer.LAYOUT);
                java.lang.foreign.MemorySegment lowered = FfiConverterTypeAssertion.INSTANCE.lower(returnValue);
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
                (AuthException e) -> FfiConverterTypeAuthError.INSTANCE.lower(e),
                AuthException.class,
                uniffiOutDroppedCallback
            );
        }
    }
    
    public static final class PlatformSecretCallback implements UniffiCallbackInterfaceForeignAuthenticatorMethod2.Fn {
        public static final PlatformSecretCallback INSTANCE = new PlatformSecretCallback();
        private PlatformSecretCallback() {}

        @Override
        public void callback(long uniffiHandle,java.lang.foreign.MemorySegment keyHandle,java.lang.foreign.MemorySegment salt,java.lang.foreign.MemorySegment reason,java.lang.foreign.MemorySegment policy,long out,java.lang.foreign.MemorySegment uniffiFutureCallback,long uniffiCallbackData,java.lang.foreign.MemorySegment uniffiOutDroppedCallback) {
            var uniffiObj = FfiConverterTypeForeignAuthenticator.INSTANCE.handleMap.get(uniffiHandle);
            java.util.function.Supplier<java.util.concurrent.CompletableFuture<java.lang.Void>> makeCall = () -> {
                return uniffiObj.platformSecret(
                    FfiConverterString.INSTANCE.lift(keyHandle),
                    FfiConverterByteArray.INSTANCE.lift(salt),
                    FfiConverterString.INSTANCE.lift(reason),
                    FfiConverterOptionalTypeKeyPolicy.INSTANCE.lift(policy),
                    FfiConverterLong.INSTANCE.lift(out)
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
                (AuthException e) -> FfiConverterTypeAuthError.INSTANCE.lower(e),
                AuthException.class,
                uniffiOutDroppedCallback
            );
        }
    }
    
    public static final class P256GenerateCallback implements UniffiCallbackInterfaceForeignAuthenticatorMethod3.Fn {
        public static final P256GenerateCallback INSTANCE = new P256GenerateCallback();
        private P256GenerateCallback() {}

        @Override
        public void callback(long uniffiHandle,java.lang.foreign.MemorySegment policy,java.lang.foreign.MemorySegment uniffiFutureCallback,long uniffiCallbackData,java.lang.foreign.MemorySegment uniffiOutDroppedCallback) {
            var uniffiObj = FfiConverterTypeForeignAuthenticator.INSTANCE.handleMap.get(uniffiHandle);
            java.util.function.Supplier<java.util.concurrent.CompletableFuture<SePublic>> makeCall = () -> {
                return uniffiObj.p256Generate(
                    FfiConverterTypeKeyPolicy.INSTANCE.lift(policy)
                );
                
            };
            // The completion callback always has signature: (long callbackData, java.lang.foreign.MemorySegment result) -> void
            java.lang.foreign.FunctionDescriptor uniffiCompletionDescriptor = java.lang.foreign.FunctionDescriptor.ofVoid(
                java.lang.foreign.ValueLayout.JAVA_LONG, UniffiForeignFutureResultRustBuffer.LAYOUT
            );
            java.util.function.Consumer<SePublic> uniffiHandleSuccess = (returnValue) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultRustBuffer.LAYOUT);
                java.lang.foreign.MemorySegment lowered = FfiConverterTypeSePublic.INSTANCE.lower(returnValue);
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
                (AuthException e) -> FfiConverterTypeAuthError.INSTANCE.lower(e),
                AuthException.class,
                uniffiOutDroppedCallback
            );
        }
    }
    
    public static final class P256SignCallback implements UniffiCallbackInterfaceForeignAuthenticatorMethod4.Fn {
        public static final P256SignCallback INSTANCE = new P256SignCallback();
        private P256SignCallback() {}

        @Override
        public void callback(long uniffiHandle,java.lang.foreign.MemorySegment keyHandle,java.lang.foreign.MemorySegment uaMsg,java.lang.foreign.MemorySegment reason,java.lang.foreign.MemorySegment uniffiFutureCallback,long uniffiCallbackData,java.lang.foreign.MemorySegment uniffiOutDroppedCallback) {
            var uniffiObj = FfiConverterTypeForeignAuthenticator.INSTANCE.handleMap.get(uniffiHandle);
            java.util.function.Supplier<java.util.concurrent.CompletableFuture<byte[]>> makeCall = () -> {
                return uniffiObj.p256Sign(
                    FfiConverterString.INSTANCE.lift(keyHandle),
                    FfiConverterByteArray.INSTANCE.lift(uaMsg),
                    FfiConverterString.INSTANCE.lift(reason)
                );
                
            };
            // The completion callback always has signature: (long callbackData, java.lang.foreign.MemorySegment result) -> void
            java.lang.foreign.FunctionDescriptor uniffiCompletionDescriptor = java.lang.foreign.FunctionDescriptor.ofVoid(
                java.lang.foreign.ValueLayout.JAVA_LONG, UniffiForeignFutureResultRustBuffer.LAYOUT
            );
            java.util.function.Consumer<byte[]> uniffiHandleSuccess = (returnValue) -> {
                java.lang.foreign.MemorySegment uniffiResult = java.lang.foreign.Arena.ofAuto().allocate(UniffiForeignFutureResultRustBuffer.LAYOUT);
                java.lang.foreign.MemorySegment lowered = FfiConverterByteArray.INSTANCE.lower(returnValue);
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
                (AuthException e) -> FfiConverterTypeAuthError.INSTANCE.lower(e),
                AuthException.class,
                uniffiOutDroppedCallback
            );
        }
    }

    public static class UniffiFree implements UniffiCallbackInterfaceFree.Fn {
        public static final UniffiFree INSTANCE = new UniffiFree();

        private UniffiFree() {}

        @Override
        public void callback(long handle) {
            FfiConverterTypeForeignAuthenticator.INSTANCE.handleMap.remove(handle);
        }
    }

    public static class UniffiClone implements UniffiCallbackInterfaceClone.Fn {
        public static final UniffiClone INSTANCE = new UniffiClone();

        private UniffiClone() {}

        @Override
        public long callback(long handle) {
            return FfiConverterTypeForeignAuthenticator.INSTANCE.handleMap.clone(handle);
        }
    }
}

