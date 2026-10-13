// xcheck stub for google/cpu_features (no network): every AVX-512 flag false. On this AVX2-only host
// (Ryzen 5 7235HS) the real library would report the same, so HEXL takes its scalar ("native") path either way.
#pragma once
namespace cpu_features {
struct X86Features { int avx512f, avx512dq, avx512vl, avx512ifma, avx512vbmi2; };
struct X86Info { X86Features features; };
inline X86Info GetX86Info () { return X86Info{}; }
}
