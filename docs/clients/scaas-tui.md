# `scaas-tui`: the terminal front-end over `scaas-sdk`

`scaas-tui` is an interactive terminal program for SCaaS accounts, tokens, confidential tokens, the DEX and governance. It is a
front-end only: every call goes to `scaas-sdk` ([CLI-SDK-01](scaas-sdk.md#CLI-SDK-01)), which signs through `ua-rs` and talks through
`scaas-rpc`. It implements the screens of scaas-app's view-model contract as that contract's fourth front-end, beside Qt, Flutter and
the Rust UI. Status: **SPECIFIED**, nothing built (spec `docs/superpowers/specs/2026-11-17-scaas-tui.md`, plan
`docs/superpowers/plans/2026-11-17-scaas-tui.md`, branch `scaas-tui`). The spec is a frame: parts that depend on SDK sections not yet
settled are marked there. Path when built: `clients/scaas-tui`. UNAUDITED.

These rules live in their own doc, not in [scaas-sdk.md](scaas-sdk.md) or [app.md](app.md): the SDK doc holds the rules every app
inherits, `app.md` the browser console and dApp; what a terminal adds (the screen, scrollback, escape sequences, SSH) belongs to this
one program.

**Contents**

1. [Scope](#1-scope)
2. [Review and operations](#2-review-and-operations)
3. [The terminal](#3-the-terminal)
4. [Endpoints and configuration](#4-endpoints-and-configuration)
5. [Accessibility](#5-accessibility)

## 1. Scope

<a id="CLI-TUI-01"></a>**CLI-TUI-01** — **The TUI is a front-end over `scaas-sdk` only, for SCaaS only, with no logic of its own**
(owner 2026-11-09, 2026-11-17; SPECIFIED). One Rust binary that links `scaas-sdk` as a crate and is its own one Rust library
([CLI-SDK-12](scaas-sdk.md#CLI-SDK-12)). It holds no cryptography, no transport, no signer and no byte format: everything it shows
comes from an SDK call or event, and everything it does is an SDK call. SCaaS only: no native-chain app core, no Trust Wallet Core,
no SDK feature `native-networks`, `raw-native` or `opaque-calls`; the one native key it uses is an EVM payer key through the SDK. Its
screens are the view-model contract's (`app-common/viewmodel/` in the scaas-app repository), with the SDK's names for every model,
action and state. It is not the CLI `scaas` ([CLI-SDK-17](scaas-sdk.md#CLI-SDK-17)): the CLI is one command per call for scripts and
the e2e tests; the TUI is a long-running interactive session that follows events. Both share one data directory under the
keystore's lock. Whether the TUI links app cores (`pqchat-core`, `pqvault-core`) is open (spec §16, Q-T2); none in its first build.

## 2. Review and operations

<a id="CLI-TUI-02"></a>**CLI-TUI-02** — **The review screen shows every field the SDK lists before anything is signed; nothing is
signed blind** (owner 2026-11-09; SPECIFIED). For every operation the TUI renders each field of the SDK's review
([CLI-SDK-08](scaas-sdk.md#CLI-SDK-08)) by name, with its decoded value and its source (signed, request, derived), and then the quote
([CLI-SDK-09](scaas-sdk.md#CLI-SDK-09)): path, payer, gas limit, maximum fee per gas, maximum cost, the fee to the relayer. Values are
shown whole: addresses and ids never shortened, amounts as the SDK's decimal strings with the token's symbol and decimals. The confirm
key is disabled until every field and the quote have been on screen (scrolled to the end); a field the TUI cannot render keeps it
disabled. A confirmed review submits exactly the prepared value and the quote shown. The TUI has no input that signs a digest, raw
bytes or an undecoded call. A test holds that every field of the review appears in the rendered frame.

<a id="CLI-TUI-03"></a>**CLI-TUI-03** — **Every write starts from a user action; operation states are the SDK's** (follows
[CLI-SDK-18](scaas-sdk.md#CLI-SDK-18); SPECIFIED). The TUI shows `Landed`, `Consumed` and `Expired` as the only ends, and everything
else as in flight with the SDK's detail; it never shows an operation as failed or dead while it may still land, a failed or replaced
self-relay transaction included. Resend (the same signed bytes) and cancel (a new operation on the lane, reviewed like any other) are
the user's actions only. Nothing is sent, resent, rolled over or cancelled by a timer, an event or a decrypted value; the only
automatic action is locking.

## 3. The terminal

<a id="CLI-TUI-04"></a>**CLI-TUI-04** — **No secret is echoed, kept in scrollback, put on the clipboard or logged** (owner 2026-11-09;
SPECIFIED). A passphrase, imported words or a key is typed into a field that shows nothing of it (no characters, no mask, no length),
read into the SDK's `SecretBytes` and the TUI's buffers zeroed ([CLI-SDK-02](scaas-sdk.md#CLI-SDK-02)); never taken from the command
line, the environment or the config file. The one secret ever shown is a new seed's words, once, on their own screen
([CLI-SDK-04](scaas-sdk.md#CLI-SDK-04)), with a warning when the session runs over SSH. The TUI draws in the alternate screen and clears
it when it leaves a secret screen, locks, is suspended, exits or panics, and restores the terminal on every exit path. It never
writes to the clipboard by default and never writes a secret there; it never sets the window title from data. No secret is in a log
line, a panic message or a core dump (core dumps off at start). Seeds lock after an idle timeout and when the terminal hangs up.

<a id="CLI-TUI-05"></a>**CLI-TUI-05** — **Text the TUI did not write is made inert before it reaches the terminal** (SPECIFIED). Every
string from outside the TUI (token names and symbols, labels, chain data, a node's `detail`, an endpoint's label) is bounded and
stripped of control characters, escape sequences and bidirectional overrides before it is drawn, so no escape sequence or direction
change reaches the terminal from data. Errors are shown by the SDK's `code` with the TUI's own message
([CLI-SDK-13](scaas-sdk.md#CLI-SDK-13)); a node's `detail` only on request, marked as raw text from the node.

## 4. Endpoints and configuration

<a id="CLI-TUI-06"></a>**CLI-TUI-06** — **Chain profiles come from pinned release data; the user may add named endpoints; the TUI
discovers none and shows no full URL** (follows [ARCH-POS-15](../decisions.md#ARCH-POS-15) and
[CLI-SDK-15](scaas-sdk.md#CLI-SDK-15); SPECIFIED). Profiles are read from the release's profile file. A local overlay may add `named`
endpoints and choose a profile's policy (`failover`, or `strict_majority` with at least two endpoints,
[CLI-RPC-05](scaas-rpc.md#CLI-RPC-05)); it cannot remove a profile's pinned contracts, change its `chain_uid` or add a token or DEX.
The TUI finds no endpoint at run time. An endpoint is shown by its index, label, class and host, never its full URL, which may carry
a credential ([CLI-RPC-11](scaas-rpc.md#CLI-RPC-11)); a credential is named in the config by an environment variable or a file,
never written as a value, and never stored in the keystore or the SDK's state. A dropped endpoint is shown by index and label.

## 5. Accessibility

<a id="CLI-TUI-07"></a>**CLI-TUI-07** — **Every screen works by keyboard alone, without colour and on a plain terminal** (SPECIFIED).
No meaning is carried by colour alone: every state also has a word or a symbol. `NO_COLOR` and a monochrome setting turn colour off;
an ASCII setting replaces box-drawing and symbol characters. Every action has a key shown in the footer; no mouse is needed. Below
80 × 24 the TUI shows only a message asking for a larger terminal.
