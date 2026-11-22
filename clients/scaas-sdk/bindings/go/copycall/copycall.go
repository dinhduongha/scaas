// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0

// Package copycall is the reference library's secret copy calls (spec §5, §16.1) for Go (plan T20h; review B12). A secret's
// bytes cross only here, never through the generated codec: Write copies a slice into the secret named by its id and zeroes
// the slice, Read copies a secret out (the caller zeroes what it read once done), Dispose zeroes and frees a secret. A Go
// string cannot be zeroed: pass a []byte.
package copycall

// #include <stdint.h>
// #include <stddef.h>
// int32_t scaas_sdk_secret_write(uint64_t id, const uint8_t *src, size_t len);
// int64_t scaas_sdk_secret_read(uint64_t id, uint8_t *dst, size_t cap);
// int32_t scaas_sdk_secret_dispose(uint64_t id);
import "C"

import "unsafe"

// Write copies b into secret id (its length exactly) and zeroes b; 0 on success.
func Write(id uint64, b []byte) int32 {
	var p *C.uint8_t
	if len(b) > 0 {
		p = (*C.uint8_t)(unsafe.Pointer(&b[0]))
	}
	r := C.scaas_sdk_secret_write(C.uint64_t(id), p, C.size_t(len(b)))
	for i := range b {
		b[i] = 0
	}
	return int32(r)
}

// Read copies secret id (at most cap bytes) out; nil when refused.
func Read(id uint64, cap int) []byte {
	out := make([]byte, cap)
	var p *C.uint8_t
	if cap > 0 {
		p = (*C.uint8_t)(unsafe.Pointer(&out[0]))
	}
	n := C.scaas_sdk_secret_read(C.uint64_t(id), p, C.size_t(cap))
	if n < 0 {
		return nil
	}
	return out[:int(n)]
}

// Dispose zeroes and frees secret id; false when unknown.
func Dispose(id uint64) bool {
	return C.scaas_sdk_secret_dispose(C.uint64_t(id)) == 0
}
