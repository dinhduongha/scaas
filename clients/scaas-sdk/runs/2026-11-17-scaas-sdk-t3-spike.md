# scaas-sdk T3: the bindings spike (Q-B1)

> Spike record of plan T3 (`docs/superpowers/plans/2026-11-17-scaas-sdk.md`), spec §16.1 and §25 Q-B1. UNAUDITED.

**Decision: Q-B1 (a) does not hold. UniFFI with `uniffi-bindgen-cpp` cannot carry the SDK's async functions or its async
foreign interfaces, so the C++ binding cannot be generated from the SDK's surface as spec §16.1 states it. The plan stops here
(before T4): Q-B1's fallback (b), or another option below, is the owner's to confirm.** Spec §16 is not edited.

## What ran

| Item | Version |
|---|---|
| `uniffi` | `=0.31.0` (the uniffi-rs release the generator targets) |
| `uniffi-bindgen-cpp` | `v0.10.0+v0.31.0` (git tag, commit `c592133c`; the generator's latest tag on 2026-11-18), `cargo install --git … --tag … --locked` |
| C++ toolchain | g++ 13.3.0, CMake 3.28.3, C++20 |
| rustc | 1.97.1 (the repository pin) |

The probe (`2026-11-17-scaas-sdk-t3-spike/probe`, not part of the SDK) holds one item per shape of the SDK's binding surface,
each beside a sync control: a record list (`seeds`), a panicking call (`panics`), an error enum with the callback variant
(`ProbeError::Unexpected`), a sync foreign interface (`SyncStore`) and the SDK's shapes behind features: an async function
(`ping_async`, feature `async-fn`), an async foreign interface (`AsyncStore`, feature `async-callback`), and an async call
through it (`read_async`, both). `cpp/harness.cpp` and `cpp/CMakeLists.txt` run the control through the generated C++.

```text
cd probe && cargo build --features <f>
uniffi-bindgen-cpp --library target/debug/libsdk_spike_probe.so --out-dir ../cpp/generated-<f>
cd ../cpp && cmake -B build && cmake --build build && cd build && ctest      # the control (no features)
```

## Results

| Probe build | Generator | Result |
|---|---|---|
| no features (the sync control) | rc 0: `sdk_spike_probe.{hpp,cpp}`, `_scaffolding.hpp` (1,024 lines) | builds with CMake; `ctest` 1/1: the record list, the panic caught as a C++ exception (`std::runtime_error` with the panic text), a C++ `SyncStore` called from Rust, a C++ exception thrown in the callback arriving as `ProbeError::Unexpected` with no Rust panic |
| `async-callback` (an async foreign interface only) | rc 101: `not implemented: Cpp bindgen does not support async functions! Namespace: sdk_spike_probe` | nothing generated |
| `async-fn` (an async function only) | rc 101, the same panic | nothing generated |
| both | rc 101, the same panic | nothing generated |

The generator's README lists "Async functions" as its one unsupported feature, at its latest tag and on `main`. One async item
anywhere in the library stops the whole generation, so library mode over an app's one Rust library (spec §16.2) fails as soon
as the SDK is linked into it. Not reached therefore: the PRF return through an async `Authenticator`, `subscribe().next(timeout)`,
the dropped future, `no_reactor_panic`, the load checks. The FRB 2 part of the spike (Dart) was not run: the plan stops at the
C++ result.

What the control shows does carry over: records, errors, panics caught at the boundary and foreign exceptions as `Unexpected`
work in the generated C++.

## Options for the owner (Q-B1)

1. **(b), the spec's fallback**: the app's one library exposes the SDK to Qt through the mechanism it uses for `app-matrix`
   (generated over the SDK's API by the app's own choice). The SDK keeps its async surface; Dart keeps FRB 2.
2. **(a′) UniFFI with a sync C++ surface** (not in the spec; a controller observation, not a recommendation): the SDK would
   export, for C++ only, blocking forms of its calls (`block_on` on the SDK's runtime) and take sync foreign interfaces run on a
   blocking thread. It changes spec §16.1's rule "every exported async call" and §14's runtime model for that target, and a Qt
   UI thread must not call them.
3. Wait for `uniffi-bindgen-cpp` to support async (no date announced), pinned when it does.

(c) a `cxx` bridge and (d) an SDK C header are hand wrapping, outside the spec's rule without the owner's word.

## Files

- `2026-11-17-scaas-sdk-t3-spike/probe/{Cargo.toml,Cargo.lock,src/lib.rs}`: the probe (its own lockfile; `uniffi` 0.31.0 and
  its graph were fetched for it, outside the SDK's lockfile).
- `2026-11-17-scaas-sdk-t3-spike/cpp/{CMakeLists.txt,harness.cpp}`: the control's harness. The generated files are not
  committed (the commands above regenerate them).
