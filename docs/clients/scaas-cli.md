# `scaas`: the command line over `scaas-sdk`

`scaas` is the command line of the SDK and, PLANNED, of the app cores above it: one command per call, a thin client with no
logic of its own, and the reference client of the SDK's end-to-end tests. Status: **BUILT** where a section says so (plan T22 of the SDK plan and its gaps of
2026-11-21; crate `clients/scaas-cli`, binary `scaas`), the rest SPECIFIED or PLANNED. Design, reasons and the owner's
rulings of 2026-11-27 on its questions: spec [2026-11-27-scaas-cli.md](../superpowers/specs/2026-11-27-scaas-cli.md), whose appendix lists every command;
the means are the T22 controller calls under [CLI-SDK-17](../decisions.md#cli-sdk-17--the-cli-scaas-is-a-thin-client-of-the-sdk)
in decisions.md. UNAUDITED.

**Contents**

1. [Scope](#1-scope)
2. [Commands](#2-commands)
3. [Output, errors and exit codes](#3-output-errors-and-exit-codes)
4. [Secrets](#4-secrets)
5. [Profiles, overlay and data directory](#5-profiles-overlay-and-data-directory)
6. [Features](#6-features)
7. [Tests](#7-tests)
8. [Not built](#8-not-built)

## 1. Scope

<a id="CLI-SDK-17"></a>**CLI-SDK-17** — **The CLI `scaas` is a thin client of the SDK and of the app cores above it** (BUILT
for the SDK: `clients/scaas-cli`, tests `clients/scaas-cli/tests/cli.rs`, `tests/e2e.rs`; the means are the T22 controller
calls in decisions.md, CLI-SDK-17; PLANNED for the app cores, owner 2026-11-27, §8). One subcommand per SDK call or app-core call, named
flags, JSON or a table; it shows the review and the quote and asks before submitting. Passphrases, words and keys come from the
terminal without echo or from a file descriptor, never from the command line or the environment; nothing secret is printed except a
new seed's one reveal. It shares its data directory with the TUI and the app under the keystore's lock, holds no logic of its own and
serves as the reference client of the SDK's end-to-end tests. Its profiles are pinned (owner 2026-11-17): compiled in or digest-pinned in a release build; a profile file only in a development build that says so on every run; an overlay may add a credential by file and lower caps, never change a `chain_uid`, a contract or an RPC list; a release build compiles in the profiles of the chains
[chain-support.md](../networks/chain-support.md) marks for release (owner 2026-11-27). It links the app cores `pqvault-core` and
`pqchat-core`, each behind its own feature, and `scaas-matrix` for PqChat's Matrix transport (owner 2026-11-27); every app-core
write is signed only after the confirm ([CLI-SDK-36](../decisions.md#CLI-SDK-36)). It shares its call and action names with
`scaas-tui`; neither calls the other.

The interactive front-end over the same SDK is `scaas-tui` ([CLI-TUI-01](scaas-tui.md#CLI-TUI-01)); the CLI runs one call per
command, or one per line in a session. Where the CLI sits among the client crates: [stack.md](stack.md).

## 2. Commands

**BUILT.** `scaas [options] <group> <call> [--flag value…]`. The group is the SDK module (`sdk`, `vault`, `account`, `wallet`,
`confidential`, `dex`, `admin`, `op`, `app-core`) or the SDK type a call belongs to (`prepared`, `registry-write`,
`prepared-order`, `seed-backup`, `keystore`, `ua-line`, `signed-op-blob`, `registration-blob`, `subscription`, `subject-key`,
`msig-structure`, `op-state`, `gas-table`); the call is the SDK call's name with `-` for `_` (`Wallet::prepare_pay` is `wallet
prepare-pay`). As at the branch point `66a39524c` there are 335 commands; `scaas commands` (no data directory needed) lists
each one with its SDK call, its flags, its secret descriptors and its confirm class, and the SDK calls without a command with
their reason. One table in `src/calls.rs` produces the dispatch, that list and the flags.

- **Flags.** A request struct's fields, flattened, or one flag per parameter; `--a.b x` sets a nested field; a repeated flag is
  a list; a value in `{…}` or `[…]` is JSON; other values are read as the SDK field's type asks (number, bool, text, `0x` hex
  bytes). `-` and `_` are the same in a flag's name. An unknown flag is refused.
- **Options** before the group: `--data-dir <dir>`, `--overlay <file>`, `--profiles <file>` (a `dev-profiles` build only),
  `--unlock <seed>` (repeatable) with `--passphrase-fd <n>`, `--app <file>` (the `AppDesc` JSON of the `app-core` group),
  `--path <SubmitPath>` (a name or JSON; default `Auto` without a payer), `--json`, `--yes`, `--as <name>` (a session).
- **Confirm classes.** `op` (130 commands): the call returns an operation object (a prepared operation, registry writes, a
  DEX order, a native send quote); the command quotes it, prints the review and the quote, asks, submits and waits up to 30 s
  for the send's state. `sign` (39 commands): the command signs with a held key or submits (submits and resends, hand-offs,
  `msig` member signatures, BLS parts, consents, the rescue vault, app and PqChat records, DEX place and cancel-all, seed
  removal) and asks before the SDK call. None (166 commands): no signature, no submit. The answer is `y` or `yes`; anything
  else is `NotConfirmed`, nothing signed or sent. `--yes` answers for a script, never for a seed's reveal (§4).
- **Sessions.** `scaas [options] session` reads one command per line from stdin, each a JSON array of words; `["--as", "p",
  …]` names what the line returns (a prepared operation, registry writes, an order, a quote, an app key, a subscription, a seed
  backup), and later lines pass it by that name. An `op` command in a session keeps its object instead of submitting it; the
  confirm reads the terminal (`/dev/tty`), and with no terminal it refuses (`NoTerminal`). Objects never cross processes,
  except the hand-off blob (`op hand-off`, `op import-signed`). An air-gapped signer uses that blob, which the payee imports,
  quotes and submits; the CLI has no other offline format (owner 2026-11-27).
- **The send.** A submitted operation is followed to its state by the SDK's event, at most 30 s; an operation ends only on a
  chain fact ([CLI-SDK-18](scaas-sdk.md#CLI-SDK-18)); `op state` follows it later and `op resume` sends a row not yet sent.
- **Shell completion** (PLANNED; owner 2026-11-27). `scaas completions <shell>` for bash, zsh and fish, generated from the same
  `calls!` table, with a test that every command appears in each; it carries no logic and no secret.
- **`pqvault`, `pqchat`, `pqchat topic`** (PLANNED; owner 2026-11-27; §8). One command per call of `pqvault-core` and
  `pqchat-core`, named flags, `--json`, the confirm classes above; every write prepared, shown (review and quote) and signed
  only after the confirm. Chat commands are non-interactive (send, list sessions, read a page, sync once); a long-running
  chat UI stays `scaas-tui`'s. Public topics (on chain, no Matrix) are included.

## 3. Output, errors and exit codes

**BUILT.** With `--json` every output is one JSON object on one line on stdout: an SDK type's `serde` form (named fields, the
SDK's own types) or a named result (`{"ok": true}`, `{"op": …, "state": …}`, `{"handle": …}`). Without it, named rows
`a.b: value`, one per leaf, with anything outside printable ASCII drawn as `\u{…}`. One output is at most 1 MiB, else
`OutputTooLarge` and nothing is printed.

<a id="CLI-CMD-02"></a>**CLI-CMD-02** — **The CLI's `--json` is the SDK's API, versioned by `Sdk::api_version()`'s minor**
(owner 2026-11-27; SPECIFIED). There is no separate CLI schema. Any change to the JSON's shape (a field added, renamed or
removed, or a type changed) moves the minor of `Sdk::api_version()` and is listed in the commit; the major moves only on an
explicit owner decision for a large change. A script reads `sdk api-version` first. Not enforced yet: `Sdk::api_version()` is
one `u32` (`API_VERSION = 1`, which a binding must equal), so it has no minor; and no test sees a shape change. The proposed
check: a field-set snapshot of each command's `--json` output in the CLI's tests, failing on any added, renamed, removed or
retyped field unless the minor moved with it.

<a id="CLI-CMD-01"></a>**CLI-CMD-01** — **A refusal is a named code on stderr and a fixed exit code** (BUILT: `src/main.rs`
`main`; tests `tests/cli.rs` `one_command_per_sdk_call_both_ways` (exit 2), `json_output_has_named_fields` (the named code)).
A refusal prints `error: <Code> <detail>` on stderr, or with `--json` `{"error": "<Code>", "detail": "<detail>"}`; nothing of it
goes to stdout. `<Code>` is the SDK's stable code (`SdkError::code`) or one of the CLI's own: `Argument`, `UnknownCommand`,
`UnknownFlag`, `NotConfirmed`, `NoTerminal`, `SecretUnreadable`, `OutputTooLarge`, `ProfilesPinned`, `ProfilesRefused`,
`DataDirMissing`, `DataDirUnusable`, `AppMissing`, `Internal`. The detail of a CLI code names a flag, a file or a count, at
most 64 characters, escaped as table output; an SDK refusal prints no detail, so no secret or remote text reaches the
terminal. Exit codes: 0 success; 1 a refusal; 2 an unknown command or flag; 70 the runtime cannot start.

## 4. Secrets

**BUILT.** A secret (a passphrase, a seed's words, a key, a signature, a backup's answers) comes only from `--<name>-fd <n>`,
read from `/dev/fd/<n>` (`0` is stdin in one command; two secrets on one descriptor are read in turn), or from the terminal
without echo. No flag takes a secret's value and no secret is read from the environment. One line, at most 4,096 bytes; a key
or a signature is `0x` + hex. `--unlock <seed>` unlocks with `--passphrase-fd` (or the terminal) before the command. A new
seed's words are shown once, after the typed word `reveal`, never on `--yes`; without an answer they stay hidden. No secret is
printed otherwise: an app key is a handle that is never readable, and `vault signature-from-compact` reports only validity.

## 5. Profiles, overlay and data directory

**BUILT** except the digest-pinned profile file.

- **Chain profiles.** A release build uses the profiles compiled into it (`clients/scaas-cli/profiles/release.json`) and no
  other: `--profiles` is `ProfilesPinned`. As at `66a39524c` that file holds no profile, so a release build reaches no chain
  yet. A `dev-profiles` build takes `--profiles <file>` (at most 64 KiB) and prints on every run a banner with the file's
  SHA-256, or that it runs the release profiles. A profile without a finality (the tag or a depth) is `ProfilesRefused`.
  The second pinned form of CLI-SDK-17, a profile file shipped beside the binary with a digest it pins, is SPECIFIED, not
  built, and stays unbuilt until a packager asks for it (owner 2026-11-27).
- **A release's profiles** (SPECIFIED; owner 2026-11-27). A release build compiles in the profiles of the chains
  [chain-support.md](../networks/chain-support.md) marks for release. Gap: `profiles/release.json` holds no profile, and
  chain-support.md marks no chain for release yet.
- **Overlay.** `--overlay <file>`, else `$XDG_CONFIG_HOME/scaas/overlay.json` when present: JSON, unknown fields refused, at
  most 64 KiB. It may only lower `limits` and add `credentials` per endpoint label, by a file (refused when group- or
  world-readable) or an environment variable's name, never a value; it has no field for a `chain_uid`, a contract or an
  endpoint list.
- **Data directory.** `--data-dir`, else `$XDG_DATA_HOME/scaas` (`~/.local/share/scaas`): the SDK's `FileStore`, under the
  keystore's lock, shared with `scaas-tui` and the app. None found is `DataDirMissing`; one the store cannot use,
  `DataDirUnusable`.

## 6. Features

**BUILT.** The crate links `scaas-sdk` with `vault`, `account`, `wallet`, `evm`, `file-store`, `mlock`, `zether`, `pqz` (one
set, `n2304-kmax4096`), `dex`, `admin`, `classical-roots`, `app-core`, `pqchat-records`, `native-networks` and every family
(`near`, `algorand`, `cosmos`, `aptos`, `solana`, `soroban`, `sui`, `ton`); `ua-rs` with `wallet` and every `fam-*`; `scaas-rpc`
without defaults. It never links `raw-native` or `opaque-calls` (no input that signs undecoded bytes, as
[CLI-TUI-17](scaas-tui.md#CLI-TUI-17)), `vectors` (the SDK's test feature, refused by `scripts/check_test_features.py`) or
`arweave` (a permanent public upload, [CLI-SDK-21](scaas-sdk.md#CLI-SDK-21)); the SDK calls those features add are listed by
`scaas commands` as excluded. Its own feature `dev-profiles` enables `--profiles` (§5). PLANNED (owner 2026-11-27): one feature
each for `pqvault-core` and `pqchat-core`, the latter with `scaas-matrix` and `pqchat-transport`. The CLI configures no `Authenticator`,
so passkey and platform unlock have nothing to answer them.

## 7. Tests

**BUILT.** `cargo test --locked` and `cargo test --locked --features dev-profiles` in `clients/scaas-cli` (CI job `scaas-cli`):
`tests/cli.rs` holds the command table equal to the SDK's public calls both ways, every command's confirm class against the
rule on its SDK call's name, every `sign` command reaching its confirm (answered `n`, nothing sent), review and quote before a
submit, no secret flag and no secret from the environment, the one reveal, sessions, named JSON fields and error codes, pinned
profiles and the shared data directory; unit tests hold the output bound, the escaping, the secret line bound, the overlay and
the profiles' parse. `tests/e2e.rs` `cli_pay_on_anvil` (ignored by default; gate step `cli-e2e`, local anvil) runs a `mtxPay`
through the binary: reviewed, refused on `n`, submitted on `y`, followed to `Landed`, and again in a session. The full list
and what is not covered: the spec's §7.

## 8. Not built

- **User profiles** (PLANNED): the `profile` commands over the SDK's `UserProfiles`
  ([CLI-UPR-01](scaas-sdk.md#CLI-UPR-01)), one per call as any other; the spec's §6.
- **`SignReview`** (PLANNED, after the pre-freeze tag): the confirm prints the SDK's `SignReview`
  ([CLI-SDK-35](../decisions.md#CLI-SDK-35)) instead of today's review rows.
- **The digest-pinned profile file** (SPECIFIED, unbuilt until a packager asks, §5) and **release profiles** (SPECIFIED, §5:
  none shipped yet; chain-support.md marks no chain for release).
- **JSON stability** (SPECIFIED, [CLI-CMD-02](#CLI-CMD-02)): the minor of `Sdk::api_version()` and the field-set snapshot test.
- **Shell completion** (PLANNED, §2).
- **PqVault and PqChat commands** (PLANNED, §2; owner 2026-11-27): the CLI links `pqvault-core`, `pqchat-core` and
  `scaas-matrix` (one Matrix client per open user profile, [CLI-PQC-20](../decisions.md#CLI-PQC-20),
  [CLI-UPR-29](../decisions.md#CLI-UPR-29)). Order (controller call, the owner may veto): after `pqvault-core`'s
  sign-after-confirm (branch `pqvault-ui-rules`), the `pqchat-core` round (CLI-SDK-36, G3, F6) and `scaas-matrix` have landed
  on `dev`; built after the pre-freeze tag, before the freeze. Today the CLI exposes the SDK's `AppCore` calls only.
