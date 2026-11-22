# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk spec §5, §16.1: the reference library's secret copy calls for Python (plan T20d; review B12).

A secret's bytes cross only here, never through the generated codec: `write` copies a `bytearray` into the secret named by its
id and zeroes the `bytearray`; `read` copies a secret out into a new `bytearray` (the caller zeroes it once done); `dispose`
zeroes and frees a secret. Python `bytes` and `str` are immutable and cannot be zeroed: pass a `bytearray`.
"""

import ctypes


class CopyCall:
    def __init__(self, library_path):
        lib = ctypes.CDLL(str(library_path))
        self._write = lib.scaas_sdk_secret_write
        self._write.argtypes = [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
        self._write.restype = ctypes.c_int32
        self._read = lib.scaas_sdk_secret_read
        self._read.argtypes = [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
        self._read.restype = ctypes.c_int64
        self._dispose = lib.scaas_sdk_secret_dispose
        self._dispose.argtypes = [ctypes.c_uint64]
        self._dispose.restype = ctypes.c_int32

    def write(self, secret_id, buf):
        """`buf` (a `bytearray`) into secret `secret_id` (its length exactly), then `buf` zeroed (also on a refusal)."""
        if not isinstance(buf, bytearray):
            raise TypeError("a bytearray, which can be zeroed")
        c = (ctypes.c_char * len(buf)).from_buffer(buf)
        try:
            r = self._write(secret_id, ctypes.addressof(c), len(buf))
        finally:
            ctypes.memset(ctypes.addressof(c), 0, len(buf))
            del c
        if r != 0:
            raise ValueError("scaas_sdk_secret_write")

    def read(self, secret_id, cap):
        """Secret `secret_id` (at most `cap` bytes) out, as a new `bytearray`."""
        out = bytearray(cap)
        c = (ctypes.c_char * cap).from_buffer(out)
        n = self._read(secret_id, ctypes.addressof(c), cap)
        del c
        if n < 0:
            raise ValueError("scaas_sdk_secret_read")
        del out[n:]
        return out

    def dispose(self, secret_id):
        """Secret `secret_id` zeroed and freed; whether it was known."""
        return self._dispose(secret_id) == 0
