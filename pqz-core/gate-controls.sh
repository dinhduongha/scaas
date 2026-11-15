#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Negative controls of the gate's own scripts (review 3w u3-1, u5-1): each script must exit non-zero when one of its
# checks fails, and 0 when all pass. ffi/run.sh and fuzz/run.sh run against stub tools (cargo, node, strings, clang,
# the fuzz binary) in a temporary directory, so nothing is built; pqz_kat.py's file list runs on a temporary file.
#   sh pqz-core/gate-controls.sh          -> one line per control; exit 1 if any control gives the wrong status
# CTL_FFI / CTL_FUZZ: another copy of ffi/run.sh / fuzz/run.sh in the same directory (the mutant run: the scripts
# before the fix must give BAD lines)
# Seconds, no build: no scripts/capped needed.
set -u
cd "$(dirname "$0")"
T=$(mktemp -d)
trap 'rm -rf "$T" ffi/target/ctl ffi/target/ctl-wasm build/fuzz-ctl; rm -f ffi/runs/ctl-* fuzz/runs/ctl-*' EXIT
mkdir -p "$T/bin"
# cargo: `build` makes the cdylib and the wasm32 module, `test` with PQZ_FFI_DIGESTS writes the native digests, `tree` names the backend;
# CTL_CARGO_FAIL=<subcommand> makes that one exit 1
cat > "$T/bin/cargo" << 'EOF'
#!/bin/sh
for a; do case $a in build | test | tree | clippy | run) c=$a; break ;; esac; done
case $c in
  build) W=$CARGO_TARGET_DIR/wasm32-unknown-unknown/release
    mkdir -p "$CARGO_TARGET_DIR/release" "$W" && : > "$CARGO_TARGET_DIR/release/libpqz_ffi.so" && : > "$W/pqz_ffi_wasm.wasm" ;;
  test) [ -n "${PQZ_FFI_DIGESTS:-}" ] && echo '{"d": 1}' > "$PQZ_FFI_DIGESTS" ;;
  tree) echo 'pqz-ffi feature "pqzl-rust"' ;;
esac
[ "${CTL_CARGO_FAIL:-}" != "$c" ]
EOF
# node: the wasm32 digests (CTL_WASM_DIFF=1: another line)
printf '#!/bin/sh\n[ "${CTL_WASM_DIFF:-0}" = 1 ] && echo %s || echo %s\n' "'{\"d\": 2}'" "'{\"d\": 1}'" > "$T/bin/node"
# strings: the library's strings (CTL_HOOKS=1: a test hook name in the production cdylib)
printf '#!/bin/sh\n[ "${CTL_HOOKS:-0}" = 1 ] && echo TEST_ARENA_MB\nexit 0\n' > "$T/bin/strings"
# clang: an executable that exits 0
printf '#!/bin/sh\nwhile [ "$1" != -o ]; do shift; done\nprintf "#!/bin/sh\\nexit 0\\n" > "$2" && chmod +x "$2"\n' > "$T/bin/clang"
for t in readelf nm llvm-nm-18; do printf '#!/bin/sh\nexit 0\n' > "$T/bin/$t"; done
chmod +x "$T/bin"/*
P=$T/bin:$PATH
bad=0
ctl() { # ctl <expected status 0|1> <label> [VAR=value…] <cmd…>
  want=$1 lab=$2; shift 2
  env PATH="$P" PQZ_BUILD_TAG=ctl "$@" > "$T/out" 2>&1; got=$?
  [ $got != 0 ] && got=1
  if [ $got = "$want" ]; then echo "ok   $lab (exit $got)"; else echo "BAD  $lab: exit $got, want $want"; tail -5 "$T/out"; bad=1; fi
}
F=${CTL_FFI:-ffi/run.sh}
ctl 0 "ffi/run.sh, every check passes" sh $F ctl
ctl 1 "ffi/run.sh, cargo test fails (part ffi/test)" CTL_CARGO_FAIL=test sh $F ctl
ctl 1 "ffi/run.sh, cargo build fails (part ffi/native)" CTL_CARGO_FAIL=build sh $F ctl
ctl 1 "ffi/run.sh, clippy fails (part ffi/native)" CTL_CARGO_FAIL=clippy sh $F ctl
ctl 1 "ffi/run.sh, test hooks in the production cdylib" CTL_HOOKS=1 sh $F ctl
ctl 1 "ffi/run.sh, native != wasm32" CTL_WASM_DIFF=1 sh $F ctl
ctl 1 "ffi/run.sh, the bench fails (part ffi/bench)" CTL_CARGO_FAIL=run sh $F ctl
# fuzz/run.sh: a stub fuzz binary (CTL_FUZZ_RC: its status; CTL_FINDING=1: an oracle's FINDING line) and seeds.py's
# honest input file
B=build/fuzz-ctl
mkdir -p $B
printf '#!/bin/sh\n[ "${CTL_FINDING:-0}" = 1 ] && echo "pqz-fuzz FINDING (precompile): control" >&2\nexit ${CTL_FUZZ_RC:-0}\n' > $B/precompile
chmod +x $B/precompile
cat > "$T/bin/python3" << EOF
#!/bin/sh
case "\$*" in *seeds.py*) : > "$(pwd)/$B/honest.bin"; exit 0 ;; esac
exec $(command -v python3) "\$@"
EOF
chmod +x "$T/bin/python3"
ctl 0 "fuzz/run.sh, a clean run" sh ${CTL_FUZZ:-fuzz/run.sh} precompile 1 ctl
ctl 1 "fuzz/run.sh, the fuzz binary exits 77" CTL_FUZZ_RC=77 sh ${CTL_FUZZ:-fuzz/run.sh} precompile 1 ctl
ctl 1 "fuzz/run.sh, a pqz-fuzz FINDING line" CTL_FINDING=1 sh ${CTL_FUZZ:-fuzz/run.sh} precompile 1 ctl
# pqz_kat.py: another writer's file passes as such, an unknown file still fails
V=../smartcontracts/vectors/pqz
echo '{}' > "$T/verdict.json"; echo '{}' > "$T/unknown.json"
ctl 0 "pqz_kat.py, verdict.json (another writer's)" python3 -I -c "import importlib.util as u, sys
s = u.spec_from_file_location('k', '$V/pqz_kat.py'); k = u.module_from_spec(s); s.loader.exec_module(k)
sys.exit(1 if k.check_files(['$T/verdict.json'], print) else 0)"
ctl 1 "pqz_kat.py, an unknown extra file" python3 -I -c "import importlib.util as u, sys
s = u.spec_from_file_location('k', '$V/pqz_kat.py'); k = u.module_from_spec(s); s.loader.exec_module(k)
sys.exit(1 if k.check_files(['$T/unknown.json'], print) else 0)"
echo "gate-controls: $([ $bad = 0 ] && echo ok || echo FAIL)"
exit $bad
