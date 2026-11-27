# `scaas-tui`: the terminal front-end over `scaas-sdk`

`scaas-tui` is an interactive terminal program for SCaaS accounts, tokens, confidential tokens, the DEX and governance. It is a
front-end only: every call goes to `scaas-sdk` ([CLI-SDK-01](scaas-sdk.md#CLI-SDK-01)), which signs through `ua-rs` and talks through
`scaas-rpc`. It implements the screens of scaas-app's view-model contract as that contract's fourth front-end, beside Qt, Flutter and
the Rust UI. Status: **SPECIFIED**, nothing built (spec `docs/superpowers/specs/2026-11-17-scaas-tui.md`, reviewed by Fable on
2026-11-17 with every finding applied, its §18; plan `docs/superpowers/plans/2026-11-17-scaas-tui.md`; branch `scaas-tui`). The spec
is a frame: parts that depend on SDK sections not yet settled are marked there. Path when built: `clients/scaas-tui`. The secret
rules are claimed only on the platforms the plan gates (Linux, then macOS). UNAUDITED.

These rules live in their own doc, not in [scaas-sdk.md](scaas-sdk.md) or [app.md](app.md): the SDK doc holds the rules every app
inherits, `app.md` the browser console and dApp; what a terminal adds (the screen, scrollback, escape sequences, SSH) belongs to this
one program. Rules marked owner below carry the owner's words only; every means and every proposal is in a rule of its own.

**Contents**

1. [Scope](#1-scope)
2. [Review and operations](#2-review-and-operations)
3. [The terminal](#3-the-terminal)
4. [Endpoints, profiles and limits](#4-endpoints-profiles-and-limits)
5. [Accessibility](#5-accessibility)
6. [Keys, clipboard and reveal](#6-keys-clipboard-and-reveal)

## 1. Scope

<a id="CLI-TUI-01"></a>**CLI-TUI-01** — **The TUI is a thin front-end over `scaas-sdk`, for SCaaS only** (owner 2026-11-09,
2026-11-17; SPECIFIED). One binary, working locally and over SSH, a thin layer over the same library API as the CLI and the app,
with no code path of its own: it calls `scaas-sdk` and nothing below it. It is the fourth front-end of scaas-app's view-model contract
(`app-common/viewmodel/`). SCaaS only: no native-chain app core and no Trust Wallet Core. It links the app cores `pqchat-core`
and `pqvault-core` (owner 2026-11-24, spec §16 Q-T2), each as a crate behind its own feature, so it has chat and vault screens; their
own rules hold in the TUI as in any app: every signature and key operation goes through the SDK, and no key reaches an app core
([CLI-PQC-03](pqchat-core.md#CLI-PQC-03), [CLI-PQC-04](pqchat-core.md#CLI-PQC-04), [CLI-PQV-12](ua-libraries.md#CLI-PQV-12)).

**Chat over Matrix and PqChat** (owner 2026-11-27; SPECIFIED): the TUI chats over plain Matrix too, its list holding Matrix rooms and
PqChat sessions as two row kinds that never mix ([CLI-PQC-19](../decisions.md#CLI-PQC-19)). Its Matrix client is the crate
`scaas-matrix` of this repository (PLANNED, [CLI-PQC-20](../decisions.md#CLI-PQC-20)), with Matrix end-to-end encryption, device
verification and recovery, every secret in a secret field; it replaces the spec's dependency on scaas-app's `app-matrix`. Each user
profile has its own Matrix: one `scaas-matrix` client per open profile, closed at a profile switch before the other opens.

**The view-model link** (owner 2026-11-27; SPECIFIED): the TUI pins a scaas-app commit of the view-model contract and replays its
flow fixtures in its tests, with no dependency on scaas-app: [CLI-TUI-19](../decisions.md#CLI-TUI-19).

<a id="CLI-TUI-17"></a>**CLI-TUI-17** — **The build and the process hold the TUI to the SDK's surface** (controller call; SPECIFIED).
The TUI links `scaas-sdk` as a crate and is its own one Rust library ([CLI-SDK-12](scaas-sdk.md#CLI-SDK-12)). It holds no
cryptography, transport, signer or byte format: everything it shows comes from an SDK call or event, everything it does is one. Its
build enables none of the SDK features `native-networks`, `raw-native`, `opaque-calls`, and at start it refuses to run when
`Sdk::features()` reports any of them. It is not the CLI `scaas` ([CLI-SDK-17](scaas-cli.md#CLI-SDK-17)): the CLI runs one call per
command for scripts and tests; the TUI is a session that follows events. Both use one data directory under the keystore's lock; the
TUI re-reads its activity list when that screen gains focus, since another process may change the SDK's state.

## 2. Review and operations

<a id="CLI-TUI-02"></a>**CLI-TUI-02** — **The signing screen shows every named field before anything is signed** (owner 2026-11-09;
SPECIFIED). For every operation the TUI shows each field of the SDK's review ([CLI-SDK-08](scaas-sdk.md#CLI-SDK-08)) by name with its
decoded value (`payNo` as UUID, `save`, and every other field), and the quote ([CLI-SDK-09](scaas-sdk.md#CLI-SDK-09)), before it
signs. A test holds that every field appears on screen. How the screen proves the user saw them is
[CLI-TUI-08](#CLI-TUI-08).

<a id="CLI-TUI-08"></a>**CLI-TUI-08** — **Confirm is a deliberate key at a settled prompt, after every line of this review and this
quote was drawn** (controller call; SPECIFIED). (1) What was seen is a set of rendered lines, counted only when drawn in a completed
frame, keyed to the `Prepared::id()` and the quote shown; a new quote, a new path or a new prepared value voids it. (2) The review
scrolls by line or page only, never jumps to the end; a field taller than the view scrolls in sub-pages and is never unrenderable.
(3) On entering review, quote and confirm the input queue is drained; a confirm key counts only when it arrives after the frame that
drew the last unseen line, the quote and the confirm prompt, and after a settle interval (500 ms). (4) A paste never acts as keys; an
unbracketed burst of keys is taken as a paste in forms, and no newline inside it submits. (5) The confirm key is one no form uses;
auto-repeat never confirms. (6) Confirm is dead while anything covers the prompt (help, a node-detail popup, an error line, the
too-small message) or the last completed frame did not show it. (7) Events change models, never focus; a list selection follows the
row's id, not its index. (8) Values are drawn whole (no ellipsis in an address, id, amount or hash), string values through the
value filter of [CLI-TUI-05](#CLI-TUI-05); for every token or market an operation touches the review shows its address whole and its
`unlisted` mark. The TUI has no input that signs a digest, raw bytes or an undecoded call.

<a id="CLI-TUI-03"></a>**CLI-TUI-03** — **Every write starts from a user action; operation states and their ends are the SDK's**
(follows [CLI-SDK-18](scaas-sdk.md#CLI-SDK-18); SPECIFIED). Two classes, each with its own ends: a relayed operation ends only
`Landed`, `Consumed` or `Expired`, and a failed or replaced self-relay transaction for it stays in flight with the SDK's detail; an EVM
native send ends on its transaction's own terminal facts (`Final`, `Replaced` from a decisive read). The TUI never shows an operation
as failed or dead while it may still land. Resend (the same signed bytes, shown with the stored operation's fields beside the new
quote) and cancel (a new operation on the lane, reviewed like any other) are the user's actions only. Nothing is sent, resent, rolled
over or cancelled by a timer, an event or a decrypted value; the only automatic action is locking.

<a id="CLI-TUI-09"></a>**CLI-TUI-09** — **After confirm there are two outcomes only: nothing signed, or an activity row; a second
operation on a busy lane or `payNo` is blocked** (controller call; SPECIFIED). An error before the SDK wrote the operation's row
returns to the review with the words "nothing was signed". Once a row exists the result is that row in the activity list, in flight
whatever the send did; no error dialog is drawn for it. The form shows the in-flight operations of its lane and refuses a second one
with the same `payNo` or on the same lane while one is in flight, offering wait, resend or cancel. Quit and hang-up wait, bounded
(30 s) and said on screen, for every signed row to reach `sent`, then lock and exit; on start the rows the SDK sent at open are listed
first.

<a id="CLI-TUI-10"></a>**CLI-TUI-10** — **A panic, or `Internal` from the SDK, ends the process after the terminal is restored**
(controller call; SPECIFIED). The panic hook restores the terminal, clears it, prints only the panic's location and aborts the process
(no unwind, no further drawing); the SDK's rows survive by its write ahead. An `Internal` error from any SDK call or task makes the TUI
lock all seeds, restore and clear the terminal, and exit. The TUI never draws or reads input after the terminal mode was restored.

## 3. The terminal

<a id="CLI-TUI-04"></a>**CLI-TUI-04** — **No secret on screen, in scrollback, on the clipboard or in a log** (owner 2026-11-09;
SPECIFIED). A passphrase, imported words or a key is never drawn, never kept in a terminal's scrollback, never put on the clipboard
and never written to a log. The one exception is a new seed's words, shown once ([CLI-SDK-04](scaas-sdk.md#CLI-SDK-04),
[CLI-SGN-11](signers-clientkeys.md#CLI-SGN-11)), under [CLI-TUI-15](#CLI-TUI-15). The means are [CLI-TUI-16](#CLI-TUI-16).

<a id="CLI-TUI-16"></a>**CLI-TUI-16** — **The means that keep secrets off the terminal** (controller call; SPECIFIED). A secret field
draws a fixed placeholder that does not change with input (no characters, no mask, no length) and reads into a fixed-capacity zeroed
buffer, then the SDK's `SecretBytes` ([CLI-SDK-02](scaas-sdk.md#CLI-SDK-02)); never argv, the environment or the config. In a text or
secret field every printable key is input; only `Esc`, `Tab` and `Enter` leave it, and the footer names the mode. Drawing is in the
alternate screen; leaving a secret screen overwrites its cells, homes the cursor and draws two full frames. A scrollback purge runs
only where the alternate screen is not confirmed, right after a reveal and with the user's consent, never at exit when it worked. Every
exit path the process handles (quit, `SIGHUP`, `SIGTERM`, panic) restores and clears the terminal; `SIGTSTP` locks all seeds and clears
before stopping. The idle lock is a deadline on a clock that keeps running across suspend, checked at each tick and at `SIGCONT`. On
`SeedLocked` the view models drop that seed's decrypted values, forms, prepared values and quotes before the next frame. Core dumps
off (`RLIMIT_CORE` 0; on Linux `PR_SET_DUMPABLE` 0, on macOS `PT_DENY_ATTACH`). The window title is never set from data. Logs only with
`--log`, a file created `0600`, appended, no symlink followed, carrying no form value. Not covered, stated: `SIGKILL`, `SIGSTOP`, a
stack overflow or an abort in a dependency (the screen and the tty mode stay as they were), recorders of the byte stream and typed
input, the draw path's own copies of the reveal.

<a id="CLI-TUI-05"></a>**CLI-TUI-05** — **Text the TUI did not write is drawn through an allow-list, typed so no screen can skip it**
(controller call; SPECIFIED). Outside text (from a chain, a node, a profile, the keystore's labels) has its own type, and render
functions take no other string from outside. Names and symbols from a chain or a node pass printable ASCII only; anything else is
drawn as a visible escape (`\u{202E}`). Seed and account labels may keep letters, numbers, punctuation, symbols and spaces of known
width, no format characters. Every such text is bounded (64 bytes for a name, 256 for a node's `detail`). A review or quote value is
never bounded or stripped: a character the filter would drop is drawn as an escape and the row is marked "contains hidden
characters". `://` in outside text is drawn broken so no terminal links it. Marks (`unlisted`, `unverified`) are drawn before the
outside string at a fixed column. A node `code` is shown only when it matches `[A-Za-z0-9_]{1,64}`, else `<invalid code>`. Errors are
shown by the SDK's `code` with the TUI's own message ([CLI-SDK-13](scaas-sdk.md#CLI-SDK-13)); a node's `detail` only on request,
marked as raw text from the node. Text printed outside the screen (start-up refusals) goes through the same filter.

## 4. Endpoints, profiles and limits

<a id="CLI-TUI-11"></a>**CLI-TUI-11** — **Release profiles are integrity-pinned; a profile file from the command line exists only in
a development build, under a banner** (controller call; SPECIFIED). The release's chain profiles ([CLI-SDK-15](scaas-sdk.md#CLI-SDK-15))
are compiled into the binary, or shipped beside it with a digest the binary pins; a profile that does not match is refused. The
option `--profiles <file>` exists only in a build with the feature `dev-profiles`; such a session draws a fixed banner with the file's
digest on every screen and on the review.

<a id="CLI-TUI-12"></a>**CLI-TUI-12** — **Fee and gas caps come from the build, may be lowered and never raised, and are shown on the
quote** (controller call; SPECIFIED). The SDK's `Limits` (`max_fee_per_gas`, `max_gas`, `max_cost`) are compiled defaults per
profile; the TUI's config may lower each, never raise it, and never takes one from an endpoint. The quote shows the caps that apply
beside the quoted values; above them the SDK refuses (`FeeAboveCap`). Forward note (SPECIFIED, with user profiles,
[CLI-UPR-11](scaas-sdk.md#CLI-UPR-11)): the lowered caps live in the profile's settings, not `tui.toml`.

<a id="CLI-TUI-06"></a>**CLI-TUI-06** — **The user may add named endpoints; the TUI discovers none and shows no full URL** (follows
[ARCH-POS-15](../decisions.md#ARCH-POS-15); the no-discovery narrowing is a proposal, owner may override; SPECIFIED). A local overlay,
one file for the CLI and the TUI (spec Q-T8), holds separate RPC and gateway lists of `named` endpoints, appended to a profile's list
unless an endpoint is marked `first`, which the endpoints screen shows as "decides" ([CLI-RPC-04](scaas-rpc.md#CLI-RPC-04)). The
overlay may strengthen a profile's policy (`failover` to `strict_majority`, [CLI-RPC-05](scaas-rpc.md#CLI-RPC-05)), never weaken it,
and cannot remove a pinned endpoint, change a contract or `chain_uid`, or add a token, DEX or verifier. Fan-out to gateways is the
profile's value, shown on the quote. The TUI finds no endpoint at run time, which narrows ARCH-POS-15's three classes to `named` and
`default`. An endpoint is shown by its index, label, class and host (userinfo dropped, an IDN as punycode, or the label only), never
its full URL ([CLI-RPC-11](scaas-rpc.md#CLI-RPC-11)). A credential is named by a file (preferred; refused when group- or
world-readable) or an environment variable, never written as a value, never stored in the keystore or the SDK's state. Forward
note (SPECIFIED, when user profiles are built: [CLI-UPR-11](scaas-sdk.md#CLI-UPR-11)): the overlay becomes the profile's sealed
settings, one per user profile, under these rules unchanged.

## 5. Accessibility

<a id="CLI-TUI-07"></a>**CLI-TUI-07** — **Every screen works by keyboard alone, without colour and on a plain terminal**
(controller call; SPECIFIED). No meaning is carried by colour alone: every state also has a word or a symbol. `NO_COLOR` and a
monochrome setting turn colour off; an ASCII setting replaces box-drawing and symbol characters. Every action has a key shown in the
footer; outside a text field keys are commands, inside one they are input (CLI-TUI-16). No mouse is needed. Below 80 × 24 the TUI
shows only a message asking for a larger terminal.

<a id="CLI-TUI-18"></a>**CLI-TUI-18** — **Two key maps, `basic` by default and `vim` as an option; no prefix keys** (owner 2026-11-24;
SPECIFIED).
- **`keymap = "basic"`, the default, is modeless:**
  - movement: the arrows, `Tab` / `Shift-Tab`, `PgUp` / `PgDn`, `Home` / `End`;
  - `Enter` opens and `Esc` goes back;
  - `/` searches, `Ctrl-P` opens the command palette, `?` opens help.
- **`keymap = "vim"`, chosen in the config, adds:** `h j k l`, `gg` / `G`, `Ctrl-D` / `Ctrl-U` and `:` commands.
- **The same under both maps:**
  - inside a text field every printable key is input (CLI-TUI-07, CLI-TUI-16), so there is no modal editing in fields;
  - a secret field and the confirm screen behave alike;
  - the confirm key is `Ctrl-Y` on the confirm screen only (CLI-TUI-08).
- **Footer:** it lists the current screen's keys under either map.
- **Never bound:**
  - prefix sequences in the manner of tmux;
  - `Ctrl-B` (tmux) and `Ctrl-A` (screen);
  - `Ctrl-S` / `Ctrl-Q` (flow control) and `Ctrl-\`.
- **Never needed** (each may be a second key, never the only one): `Alt` combinations and function keys, which break over SSH and
  on macOS terminals.
- **`Ctrl-Z`** locks the secret screens before the process suspends (CLI-TUI-16).

## 6. Keys, clipboard and reveal

No proposal awaits the owner here: Q-T5, Q-T6 and Q-T7 were agreed on 2026-11-24 and Q-T2 answered yes the same day (spec §16).

<a id="CLI-TUI-13"></a>**CLI-TUI-13** — **The one native key is an EVM payer key, through the SDK** (owner 2026-11-24, spec Q-T5;
SPECIFIED). The TUI shows the EVM payer key the SDK's self-relay needs (its address, balance, the "linked on chain to the subject" line)
and offers the SDK's EVM native send; no other native network. The native send stays out of the build until the SDK reports its ends
in `OpState` as CLI-TUI-03's second class.

<a id="CLI-TUI-14"></a>**CLI-TUI-14** — **The clipboard holds public values only, and only when the user turns it on** (owner
2026-11-24, spec Q-T6; SPECIFIED). Off by default. When turned on in the config, a key copies one public value (a UA id, an address, an
operation's digest) by OSC 52; no other value can be copied. Forward note (SPECIFIED, with user profiles,
[CLI-UPR-16](scaas-sdk.md#CLI-UPR-16)): the opt-in lives in the profile's settings, and a value the TUI copied is cleared when the
profile locks or switches.

<a id="CLI-TUI-15"></a>**CLI-TUI-15** — **A seed's words are revealed only after the user types `reveal`, with a warning where the
screen may be recorded** (owner 2026-11-24, spec Q-T7; SPECIFIED). The reveal screen always asks for the typed word `reveal`. It adds a warning
when the session looks remote or multiplexed (`SSH_CONNECTION`, `SSH_TTY`, `TMUX`, `STY`) or the terminal does not confirm the
alternate screen; these are hints, not a guarantee. Leaving the reveal follows [CLI-TUI-16](#CLI-TUI-16).
