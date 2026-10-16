/* wasm32 builds of pqz-ffi: the branch-free 128-bit helpers of src/pqz_wasm_rt.c (__multi3, __ashlti3, __lshrti3;
   the fixed-point rejection shifts by amounts derived from secret data) override compiler_builtins' weak ones; its
   mem* functions are renamed away, Rust's compiler_builtins provides those. */
#define memcpy pqz_rt_memcpy_unused
#define memmove pqz_rt_memmove_unused
#define memset pqz_rt_memset_unused
#define memcmp pqz_rt_memcmp_unused
#include "../../pqzl/src/pqz_wasm_rt.c"
