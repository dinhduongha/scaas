// Offline stand-in for google/cpu_features (HEXL fetches it from GitHub at configure time otherwise): the five
// flags HEXL's runtime dispatch reads (hexl/util/cpu-features.hpp), from libgcc's CPUID probe. libgcc also
// checks XCR0, so a flag is set only when the OS enables the AVX-512 state. HEXL_DISABLE_AVX512IFMA=1 (or
// ..._AVX512DQ=1) in the environment still turns a path off at run time.
#pragma once
namespace cpu_features {
struct X86Features { int avx512f, avx512dq, avx512vl, avx512ifma, avx512vbmi2; };
struct X86Info { X86Features features; };
inline X86Info GetX86Info () {
  __builtin_cpu_init ();
  return X86Info{ { __builtin_cpu_supports ("avx512f"), __builtin_cpu_supports ("avx512dq"),
                    __builtin_cpu_supports ("avx512vl"), __builtin_cpu_supports ("avx512ifma"),
                    __builtin_cpu_supports ("avx512vbmi2") } };
}
}
