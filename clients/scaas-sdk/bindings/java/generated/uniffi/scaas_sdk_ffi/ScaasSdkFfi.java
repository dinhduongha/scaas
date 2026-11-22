package uniffi.scaas_sdk_ffi;


import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
public class ScaasSdkFfi {
  
    /**
     * Panics inside a call on the SDK's runtime: `Internal`.
     */public static java.util.concurrent.CompletableFuture<java.lang.Void> panicInCall(uniffi.scaas_sdk.Sdk sdk){
        return panicInCall(sdk, java.util.concurrent.ForkJoinPool.commonPool());
    }public static java.util.concurrent.CompletableFuture<java.lang.Void> panicInCall(uniffi.scaas_sdk.Sdk sdk, java.util.concurrent.Executor uniffiExecutor
    ){
        return UniffiAsyncHelpers.uniffiRustCallAsync(
        uniffiExecutor,
        UniffiLib.uniffi_scaas_sdk_ffi_fn_func_panic_in_call(uniffi.scaas_sdk.FfiConverterTypeSdk.INSTANCE.lower(sdk)),
        (future, callback, continuationHandle) -> UniffiLib.ffi_scaas_sdk_ffi_rust_future_poll_void(future, callback, continuationHandle),
        (_allocator, future, continuation) -> UniffiLib.ffi_scaas_sdk_ffi_rust_future_complete_void(future, continuation),
        (future) -> UniffiLib.ffi_scaas_sdk_ffi_rust_future_free_void(future),
        // lift function
        () -> {},
        // Error FFI converter
        new SdkExceptionExternalErrorHandler()
    );
    }

}

