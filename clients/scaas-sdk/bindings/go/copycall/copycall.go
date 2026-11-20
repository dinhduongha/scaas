// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0

// Package copycall is the reference library's secret copy call in (spec §5) for Go (plan T20h): the bytes into the secret
// `id`, then the caller's slice zeroed. A test file cannot use cgo, so the smoke test calls it here.
package copycall

// #include <stdint.h>
// #include <stddef.h>
// int32_t scaas_sdk_secret_write(uint64_t id, const uint8_t *src, size_t len);
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
