#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Format the repository with the pinned tools (code-format plan, F9), or check it as CI does.
#   scripts/format.sh            format in place (every language below)
#   scripts/format.sh --check    change nothing; exit 1 if any file differs (the CI `format` job runs exactly this)
#   scripts/format.sh [--check] <part>...   only these parts: rust sol js yaml py go cs dart c sh toml lint
# Settings live in the committed configs (rustfmt.toml, foundry.toml [fmt], .prettierrc, pyproject.toml, .editorconfig,
# analysis_options.yaml, .clang-format, taplo.toml), never here. Pins: rustfmt by rust-toolchain.toml, forge 1.8.5,
# Prettier 3.3.3 (clients/clientkeys/package.json), ruff 0.16.4 (pyproject.toml), clang-format 19.1.7, shfmt 3.10.0,
# taplo 0.9.3, actionlint 1.7.12, hadolint 2.15.1; the CI job installs each at that version. Locally the tools come from
# PATH, then from the git-ignored scratchpad/tools/bin.
# Scope: the components formatted so far. Left out: generated, vendored (vendor/) and legacy/ files (.rustfmt-ignore,
# .clang-format-ignore, .prettierignore, foundry.toml [fmt] ignore, taplo.toml exclude), and runs/ except its shell,
# YAML and TOML. Not covered yet: the family contracts' Rust (formatted with their next redeploy: panic locations move
# the wasm), Python and JavaScript under docs/ (research and history notes), Move and TON.
set -u
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
cd "$root" || exit 2
[ -d scratchpad/tools/bin ] && PATH=$PATH:$root/scratchpad/tools/bin
check=0
[ "${1:-}" = --check ] && {
    check=1
    shift
}
parts=${*:-rust sol js yaml py go cs dart c sh toml lint}
bad=0
say() { echo "[format] $*"; }
fail() {
    say "FAIL $*"
    bad=1
}
want() {
    case " $parts " in *" $1 "*) return 0 ;; esac
    return 1
}
ls_all() { git ls-files -- "$@" | grep -v -E '(^|/)(legacy|vendor)/'; }
ls_files() { ls_all "$@" | grep -v -E '(^|/)runs/'; }

# Rust: one rustfmt run per crate root at its edition. rustfmt follows out-of-line `mod`s, so a file of .rustfmt-ignore
# it reaches is kept as it was (format) or not reported (check).
RUST_CRATES="scaas-node scaas-pqz-verifier clients/ua-rs clients/ua-c clients/zether-prover clients/scaas-rpc
  clients/scaas-ct clients/ua-cxx clients/ua-qt clients/ua-dart-frb/rust pqz-core smartcontracts/evm/script/pqz/wallet
  smartcontracts/soroban"
rust_ignored() { grep -v -E '^\s*(#|$)' .rustfmt-ignore | sed 's/^/:(glob)/' | xargs git ls-files --; }
if want rust; then
    ign=$(rust_ignored)
    for c in $RUST_CRATES; do
        ed=$(sed -n 's/^edition *= *"\([0-9]*\)".*/\1/p' "$c/Cargo.toml" 2>/dev/null | head -1)
        ed=${ed:-2021} # pqz-core has no root manifest: its crates are all 2021
        fs=$(ls_files "$c/*.rs" | grep -v -x -F "$ign")
        [ -n "$fs" ] || continue
        if [ $check = 1 ]; then
            d=$(rustfmt --edition "$ed" --check -l $fs 2>/dev/null | sed "s|^$root/||" | sort -u | grep -v -x -F "$ign")
            [ -z "$d" ] && say "rust $c ok" || fail "rust $c: $(echo $d)"
        else
            t=$(mktemp -d)
            for f in $ign; do mkdir -p "$t/$(dirname "$f")" && cp -p "$f" "$t/$f"; done
            rustfmt --edition "$ed" $fs || fail "rust $c"
            for f in $ign; do cmp -s "$f" "$t/$f" || cp -p "$t/$f" "$f"; done
            rm -rf "$t"
        fi
    done
fi

# Solidity: forge fmt over src, test and script (settings and the generated PqzSet.sol in foundry.toml [fmt])
if want sol; then
    (cd smartcontracts/evm && forge fmt $([ $check = 1 ] && echo --check) src test script >/dev/null) &&
        say "sol ok" || fail "sol (forge fmt in smartcontracts/evm)"
fi

# Prettier: the JavaScript and TypeScript outside runs/ and docs/ (clientkeys, the pqz-core wasm runners, the TON tests
# and shim, the family and vector scripts) and the YAML files
prettier_bin() { command -v prettier || echo clients/clientkeys/node_modules/.bin/prettier; }
if want js; then
    $(prettier_bin) --log-level warn $([ $check = 1 ] && echo --check || echo --write) \
        $(ls_files '*.js' '*.mjs' '*.cjs' '*.ts' | grep -v '^docs/') &&
        say "js ok" || fail js
fi
if want yaml; then
    $(prettier_bin) --log-level warn $([ $check = 1 ] && echo --check || echo --write) $(ls_all '*.yml' '*.yaml') &&
        say "yaml ok" || fail yaml
fi

# Python: ruff (pyproject.toml) over clients/ua-py and pqz-core, and every other tracked Python file outside runs/ and docs/
# (scripts/, the generators, smartcontracts/algorand, smartcontracts/evm/script, the clients' tools)
if want py; then
    ruff format $([ $check = 1 ] && echo --check) -q clients/ua-py pqz-core \
        $(ls_files '*.py' | grep -v -E '^(clients/ua-py|pqz-core|docs)/') && say "py ok" || fail py
fi

# Go: gofmt has no settings; in check mode any listed file fails (legacy/ left out)
if want go; then
    if [ $check = 1 ]; then
        d=$(gofmt -l $(ls_files 'clients/ua-go/*.go'))
        [ -z "$d" ] && say "go ok" || fail "go: $d"
    else gofmt -w $(ls_files 'clients/ua-go/*.go') && say "go ok" || fail go; fi
fi

# C#: dotnet format whitespace (.editorconfig) on clients/ua-cs and pqz-core/nethermind, folder mode (no restore), legacy/
# left out
if want cs; then
    for d in clients/ua-cs pqz-core/nethermind; do
        dotnet format whitespace --folder $d --exclude $d/legacy $([ $check = 1 ] && echo --verify-no-changes) \
            -v q && say "cs $d ok" || fail "cs $d"
    done
    dotnet build-server shutdown >/dev/null 2>&1
fi

# Dart: hand-written files only (flutter_rust_bridge writes lib/src/rust/)
if want dart; then
    dart format $([ $check = 1 ] && echo '--output=none --set-exit-if-changed') \
        $(ls_files 'clients/ua-dart/*.dart' 'clients/ua-dart-frb/*.dart' | grep -v '/lib/src/rust/') >/dev/null &&
        say "dart ok" || fail dart
fi

# C / C++ / Qt: clang-format (.clang-format, .clang-format-ignore)
if want c; then
    fs=$(ls_files '*.c' '*.h' '*.cpp' '*.hpp' '*.cc' '*.cxx')
    if [ $check = 1 ]; then
        clang-format --dry-run -Werror $fs 2>/dev/null && say "c ok" || fail c
    else clang-format -i $fs && say "c ok" || fail c; fi
fi

# Shell: shfmt reads .editorconfig ([*.sh]); the variant (POSIX sh or bash) comes from each shebang
if want sh; then
    fs=$(ls_all '*.sh')
    if [ $check = 1 ]; then
        d=$(shfmt -l $fs)
        [ -z "$d" ] && say "sh ok" || fail "sh: $(echo $d)"
    else shfmt -w $fs && say "sh ok" || fail sh; fi
fi

# TOML: taplo (taplo.toml: no key or array reordering)
if want toml; then
    taplo fmt $([ $check = 1 ] && echo --check) $(ls_all '*.toml') 2>/dev/null && say "toml ok" || fail toml
fi

# Lints (no formatter exists): the workflows (actionlint), the Dockerfiles (hadolint: fails on errors, shows warnings)
if want lint; then
    actionlint && say "actionlint ok" || fail actionlint
    hadolint --failure-threshold error $(ls_all '*Dockerfile') && say "hadolint ok" ||
        fail hadolint
fi

exit $bad
