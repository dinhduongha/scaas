#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UNIFFI_CPP_INTERNALSTRUCTS
#define UNIFFI_CPP_INTERNALSTRUCTS
struct ForeignBytes {
    int32_t len;
    uint8_t *data;
};

struct RustBuffer {
    uint64_t capacity;
    uint64_t len;
    uint8_t *data;
};

struct RustCallStatus {
    int8_t code;
    RustBuffer error_buf;
};

#endif
void uniffi_scaas_sdk_ffi_fn_func_panic_in_call_blocking(uint64_t sdk, RustCallStatus *out_status);
RustBuffer ffi_scaas_sdk_ffi_rustbuffer_alloc(uint64_t size, RustCallStatus *out_status);
RustBuffer ffi_scaas_sdk_ffi_rustbuffer_from_bytes(ForeignBytes bytes, RustCallStatus *out_status);
void ffi_scaas_sdk_ffi_rustbuffer_free(RustBuffer buf, RustCallStatus *out_status);
RustBuffer ffi_scaas_sdk_ffi_rustbuffer_reserve(RustBuffer buf, uint64_t additional, RustCallStatus *out_status);
uint16_t uniffi_scaas_sdk_ffi_checksum_func_panic_in_call_blocking();
uint32_t ffi_scaas_sdk_ffi_uniffi_contract_version();
#ifdef __cplusplus
}
#endif