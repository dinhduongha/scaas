> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Chat apps with a terminal UI: what scaas-tui can learn

Research of 2026-11-24, after the owner's answer to `scaas-tui` spec §16 Q-T2 (the TUI links `pqchat-core` and `pqvault-core`,
[CLI-TUI-01](../clients/scaas-tui.md#CLI-TUI-01); its Change of 2026-11-24 in [decisions](../decisions.md)). It surveys current terminal chat clients and maps what they do
to the TUI's rules (CLI-TUI-*, [clients/scaas-tui.md](../clients/scaas-tui.md)) and plan tasks
([plan](../superpowers/plans/2026-11-17-scaas-tui.md): T2 view models and golden frames, T3 secret fields, T14 app cores).
Nothing here is built or specified; every recommendation is a proposal and **UNAUDITED**.

**Method and sources.** Each client was checked on 2026-11-24: the Matrix, Signal and XMPP clients (sections 2 to 4) against
shallow clones of their default branches at their heads of 20–23 Nov 2026, read for the code points below; the others (sections 5
to 7) against the GitHub API, their READMEs, manuals, docs and single source files fetched that day; every client also against its
releases page or tags. Zalo (section 8) has no client to read: its section rests on Zalo's whitepaper, news reports and Vietnamese
third-party guides.
Versions and dates are as fetched that day. A feature that rests only on a project's README, help text or blog is marked
**(vendor claim)**. Line numbers are those of the fetched heads and drift. Facts about SCaaS come from this repository, cited by
path and rule id.

**Contents**

1. [Survey table](#1-survey-table)
2. [Matrix clients](#2-matrix-clients)
3. [Signal clients](#3-signal-clients)
4. [XMPP: profanity](#4-xmpp-profanity)
5. [IRC-style benchmarks: WeeChat, irssi, senpai](#5-irc-style-benchmarks-weechat-irssi-senpai)
6. [Telegram and WhatsApp: nchat, tg](#6-telegram-and-whatsapp-nchat-tg)
7. [SimpleX and Nostr](#7-simplex-and-nostr)
8. [Zalo](#8-zalo)
9. [Post-quantum messaging in a terminal](#9-post-quantum-messaging-in-a-terminal)
10. [Ratatui wallets, briefly](#10-ratatui-wallets-briefly)
11. [Patterns across the field](#11-patterns-across-the-field)
12. [PqChat specifics that change the lessons](#12-pqchat-specifics-that-change-the-lessons)
13. [What scaas-tui should adopt](#13-what-scaas-tui-should-adopt)
14. [What not to copy](#14-what-not-to-copy)
15. [Conflicts with SCaaS rules](#15-conflicts-with-scaas-rules)
16. [Not verified](#16-not-verified)

## 1. Survey table

| App | Protocol | Language | Toolkit | Licence | Latest release (as fetched 2026-11-24) | Status |
|---|---|---|---|---|---|---|
| iamb | Matrix | Rust | Ratatui 0.30, crossterm, modalkit; matrix-sdk 0.19 | Apache-2.0 | v0.13.1, 2026-10-21 | active (push 2026-11-21) |
| gomuks (new) | Matrix | Go | backend hicli (mautrix-go); web frontend; terminal frontend on tcell + mauview | AGPL-3.0 | v26.11.1 (tag v0.2611.1), 2026-11-18 | active; its terminal frontend "still experimental" (vendor claim) |
| gomuks legacy | Matrix | Go | mauview + tcell fork | AGPL-3.0 | v0.3.1, 2024-07-16 | superseded by the split above |
| matrix-commander | Matrix | Python | none (CLI); matrix-nio | GPL-3.0 | v8.0.6 (tag; PyPI), 2026-07-02 | maintained (commit 2026-11-04) |
| weechat-matrix | Matrix | Python | WeeChat script; matrix-nio | ISC | 0.3.0, 2021-07-03 | maintenance mode (vendor claim); last commit 2023-07-23 |
| weechat-matrix-rs | Matrix | Rust | WeeChat plugin; matrix-sdk 0.18 | ISC | none | work in progress (vendor claim); commit 2026-10-06 |
| gurk-rs | Signal | Rust | Ratatui 0.30, crossterm 0.29; presage, libsignal-service-rs | AGPL-3.0 | v0.10.2, 2026-10-12 | active |
| scli | Signal | Python | urwid; signal-cli over DBus | GPL-3.0 | v0.7.5, 2024-07-03 | dormant (last commit 2024-11-29) |
| profanity | XMPP | C | ncursesw; libstrophe | GPL-3.0-or-later | 0.20.0, 2026-11-19 | active |
| WeeChat | IRC (+ plugins) | C | own curses UI | GPL-3.0 | v4.10.4, 2026-11-09 | active |
| irssi | IRC | C | own curses UI | GPL-2.0 | 1.4.5, 2023-10-03 | code maintained (push 2026-11-06), no release since 2023 |
| senpai | IRC (bouncer-first) | Go | own (tcell-based, not verified) | ISC | v0.5.0, 2026-06-02 | active (mirror; sr.ht unreachable when fetched) |
| nchat | Telegram, WhatsApp, Signal | C++ | ncurses; tdlib, whatsmeow, signalmeow | MIT source, AGPL-3.0 binaries | v5.20.39, 2026-11-21 | active |
| tg | Telegram | Python | stdlib `curses`; TDLib | Unlicense | v0.27.0, 2026-11-16 | active |
| SimpleX Chat CLI | SimpleX | Haskell | line-oriented REPL | AGPL-3.0 | v7.1.4, 2026-11-14 | active |
| nostui | Nostr | Rust | Ratatui 0.30, crossterm 0.29; nostr-sdk 0.45 | MIT | v0.1.1, 2025-12-03 (main ahead) | active (push 2026-11-14) |
| algia | Nostr | Go | CLI | MIT | v0.0.140, 2026-11-19 | active |
| tualgia | Nostr | Go | TUI (toolkit not verified) | MIT | none (6 commits) | early |
| Zalo (official) | Zalo | — | no terminal client; mobile, PC, Web | proprietary | — | no TUI |
| zca-js | Zalo (unofficial) | JavaScript | library (browser imitation) | MIT | v2 (version not stated), push 2026-11-23 | active; ban risk (vendor claim) |
| noscl | Nostr | Go | CLI | — | — | archived (2024-01-27) |

Sources per row are in sections 2 to 10.

## 2. Matrix clients

### iamb

Repository [ulyssa/iamb](https://github.com/ulyssa/iamb); release
[v0.13.1](https://github.com/ulyssa/iamb/releases/tag/v0.13.1) (a version-scheme change, otherwise equal to v0.0.13 of the
same day); manuals [iamb(1)](https://github.com/ulyssa/iamb/blob/main/docs/iamb.1) and
[iamb(5)](https://github.com/ulyssa/iamb/blob/main/docs/iamb.5); CI
[ci.yml](https://github.com/ulyssa/iamb/blob/main/.github/workflows/ci.yml).

- **Layout.** Vim windows (`:split`, `:vsplit`, `:only`, `:resize`) and tabs (`:tabedit <room>`); list windows `:rooms`, `:dms`,
  `:spaces`, `:unreads`, `:mentions`, `:invites`, `:members`, `:pinned`; threads and spaces (vendor claim). The layout is
  restored from disk at start (`config::Layout::Restore` in `src/main.rs`).
- **Keys and discoverability.** Vim modes and `:commands` through modalkit, custom bindings, a `:welcome` window and man pages;
  no `:help` command in `commands.rs`. Discoverability rests on knowing Vim.
- **Notifications and unread.** Desktop notification or the terminal bell (`via = "bell"`); unread, mention, `marked_unread` and
  mute state drive the room lists' marks and order.
- **Media.** `ratatui-image` 11 with a `protocol` setting (sixel, kitty, iTerm2; half-blocks otherwise); `:upload`, `:download`,
  `:open`. A paste of an image from the clipboard asks first ("Do you really want to upload the image from your system
  clipboard?", `src/windows/room/chat.rs`).
- **Key verification.** Emoji SAS by `:verify request|accept|emoji|confirm|mismatch|cancel`; QR verification only when the other
  side scans (no QR drawn in the terminal that the source shows, `src/verifications.rs`). The recovery key is typed as
  `:verify recover <key>` and the key-export passphrase as `:keys export <path> <passphrase>`: both on the visible command line.
- **Accounts.** Several profiles in the config, one per process (`-P`).
- **Store.** matrix-sdk's SQLite store opened with **no passphrase** (`sqlite_store_with_cache_path(dir, cache_dir, None)`,
  `src/worker.rs`): no encryption at rest from iamb.
- **Secrets and logs.** Login password by `rpassword` (no echo) or a `password_file`. Logs are `tracing` daily files per
  profile with `DEFAULT_LOG_LEVEL = "off"` (`src/config/mod.rs`), raised by `RUST_LOG`; features `max_level_*` strip log
  strings from the binary (README). Clipboard through the system clipboard (modalkit); no OSC 52 found.
- **Crash, themes, accessibility.** A panic hook restores the tty and then runs the default hook (`src/main.rs`); themes in the
  config; screen readers not documented.
- **Tests.** Unit tests (command parsing, config, HTML and markdown); no `TestBackend` or snapshot render tests; CI runs
  `cargo test --locked`, clippy `-D warnings`, rustfmt.

### gomuks: legacy TUI and the 2025 split

Repository [gomuks/gomuks](https://github.com/gomuks/gomuks) ([README](https://github.com/gomuks/gomuks/blob/main/README.md),
[CHANGELOG](https://github.com/gomuks/gomuks/blob/main/CHANGELOG.md)); legacy
[v0.3.1](https://github.com/gomuks/gomuks/releases/tag/v0.3.1).

- **The split.** A backend (hicli over mautrix-go) runs embedded or as a remote "bouncer"; the web frontend is the "most mature"
  (also wrapped for desktop and Android); **gomuks terminal** is "a port of legacy gomuks, but it's still experimental and doesn't
  have many features beyond basic chatting" (vendor claim, README), a separate binary talking RPC to the backend. The new
  architecture first shipped in v25.11. Legacy v0.3.1 had its own image renderer and a verification modal.
- **Terminal UI** (`tui/`): room list, room view, member list, a fuzzy-search modal, a help modal, a password modal, a syncing
  modal; `/` commands (reply, react, redact, edit, copy, quit). Unread drawn bold from `MarkedUnread`, `UnreadNotifications`,
  `UnreadHighlights` (`tui/room-list.go`). Media rendering is commented out (`tui/room-view.go`). The help still lists
  `/verify-device` ("interactive emoji verification") and `/verify` ("Probably broken"); whether it works in the new TUI was
  not verified.
- **Store.** SQLite; **the crypto store's pickle key is the constant `[]byte("meow")`** (`pkg/gomuks/gomuks.go`): in effect no
  secret at rest.
- **Clipboard.** OS clipboard (clipboard and primary registers); no OSC 52.
- **Tests.** Two Go test files outside the UI; no TUI render tests.
- **Lesson.** A UI process separate from the key-holding backend is the shape SCaaS already has (TUI over the SDK,
  CLI-TUI-17), but gomuks shows the cost: two frontends, one of them always behind.

### matrix-commander

Repository [8go/matrix-commander](https://github.com/8go/matrix-commander),
[help.manual.txt](https://github.com/8go/matrix-commander/blob/master/help.manual.txt).

- A one-shot and `--listen` / `--tail` CLI for scripts; no UI. `--verify emoji|emojireq|manual` prints SAS questions to stdout.
- Credentials with the access token in `credentials.json`; a `./store/` directory (encryption not stated). `--password` exists
  on the command line (argv and shell history); its own CI passes the password that way.
- Tests: shell and Python integration scripts against a real homeserver; no unit tests.
- **Lesson.** The CLI/TUI split SCaaS has (CLI-SDK-17 vs CLI-TUI-17); the argv password is what CLI-TUI-16 forbids.

### weechat-matrix and weechat-matrix-rs

[poljar/weechat-matrix](https://github.com/poljar/weechat-matrix) ("maintenance mode", cross-signing unimplemented, vendor
claim) and [poljar/weechat-matrix-rs](https://github.com/poljar/weechat-matrix-rs) ("a work in progress and doesn't do much
yet", vendor claim). The Rust plugin draws SAS as emoji or decimals (`/verification accept|confirm|cancel`) and shows
encrypted, unverified-device and public marks in a bar item; **its store passphrase is the constant `"DEFAULT_PASSPHRASE"`**
(`src/server.rs`). Layout, hotlist and relay come from WeeChat (section 5).

## 3. Signal clients

### gurk-rs

Repository [boxdot/gurk-rs](https://github.com/boxdot/gurk-rs) ([README](https://github.com/boxdot/gurk-rs/blob/main/README.md),
[CHANGELOG](https://github.com/boxdot/gurk-rs/blob/main/CHANGELOG.md), [CI](https://github.com/boxdot/gurk-rs/blob/main/.github/workflows/ci.yaml));
built on [presage](https://github.com/whisperfish/presage) and
[libsignal-service-rs](https://github.com/whisperfish/libsignal-service-rs). The closest stack to scaas-tui's (Ratatui +
crossterm, Rust, an encrypted store).

- **Layout and keys.** Channel list and message view, a `ctrl+p` channel popup, an `f1` help panel, multi-line input
  (`alt+enter`); Emacs-style editing; keys configurable per mode (`keybindings.<mode>.<key> = "<command>"`); not Vim-modal.
- **Notifications.** notify-rust and the bell; `show_message_text`, `show_message_chat` (what a notification may reveal),
  `mute_reactions_bell`, per-channel mute (`alt+m`, marked `[M]`); receipts shown.
- **Media.** Inline images through `ratatui-image` 11.1 (Kitty, Ghostty, WezTerm, iTerm2, sixel, else coloured blocks) **on main
  only, not in v0.10.2**; image decoding in a background thread under `catch_unwind`; images sent from the clipboard (arboard).
- **Linking.** A linked secondary device only. The provisioning URL is printed to stdout as a Unicode QR code and as a PNG in a
  temporary directory (`src/signal/mod.rs`): a linking secret in scrollback and on disk.
- **Safety numbers.** The store is opened with `OnNewIdentity::Trust` (`src/signal/mod.rs`): identity changes are trusted
  automatically; no safety-number screen found.
- **Store.** Two SQLite stores (Signal's and gurk's) under SQLCipher; the passphrase is **mandatory** since "Make passphrase
  obligatory (#389)"; sources in order: argument, config, a command, `GURK_PASSPHRASE_COMMAND`, the macOS Keychain, a prompt;
  the `Passphrase` type is zeroized ([passphrase.rs](https://github.com/boxdot/gurk-rs/blob/main/src/passphrase.rs)).
- **Logs.** `--verbose` writes `gurk.log`, the docs suggest trace level; panics are logged (`log_panics`); a `dev` feature
  dumps raw messages to `messages.json`. Copy of a message by the OS clipboard; no OSC 52.
- **Crash handling.** A scope guard disables raw mode on drop (`src/main.rs`); no explicit leave of the alternate screen in a panic
  hook found.
- **Tests.** Ratatui `TestBackend` render tests in `src/ui/draw.rs` (14, at 100 × 30) and `src/images.rs` (12); no snapshot crate;
  quickcheck and many unit tests (input, cursor, window, passphrase, the SQL encryption migration); CI fmt, clippy, tests on
  several targets. **The only surveyed client with render tests.**
- **Post-quantum.** libsignal-service-rs handles Kyber prekeys (PQXDH); presage advertises the `spqr` capability and `spqr` 1.6.0
  is in the lockfile, so gurk inherits Signal's SPQR / Triple Ratchet. That live sessions negotiate it is inferred, not
  observed.

### scli

Repository [isamert/scli](https://github.com/isamert/scli): one Python file on urwid over signal-cli (DBus).

- Contacts and conversation panes; Vim-like movement and `:` commands (`:attach`, `:edit` in `$EDITOR`, `:read FILE|!CMD`);
  `/` search filters messages and contacts; `?` / F1 help and `:help keys|commands`; `--key-bind ACTION:KEY`.
- Notifications by flag or command. `--save-history` off by default, "History is saved in plain text" (help text). At DEBUG it
  pretty-prints the daemon's JSON envelopes, **message bodies included**. `scli link` prints the device-link URL as a terminal
  QR (scrollback). An untrusted identity is an error telling the user to run `signal-cli trust`. No tests.
- Post-quantum: inherits [signal-cli](https://github.com/AsamK/signal-cli) (v0.14.10, 2026-11-07: Kyber prekeys, `spqr = true`).

## 4. XMPP: profanity

Repository [profanity-im/profanity](https://github.com/profanity-im/profanity)
([CHANGELOG](https://github.com/profanity-im/profanity/blob/master/CHANGELOG), [tests](https://github.com/profanity-im/profanity/tree/master/tests)).

- **Layout and keys.** irssi-style numbered windows (`/wins`, `/wins unread|attention`), an occupants pane, status and title
  bars; `/` commands with tab completion; DBus notifications and a tray icon. 0.20.0 dropped `/paste` and the clipboard module and
  moved plugins to Lua.
- **Media.** `/sendfile` (HTTP upload); URLs opened externally; no inline images.
- **OMEMO verification.** `/omemo fingerprint`, `/omemo trust|untrust <fp>`, the title bar shows `[trusted]` / `[untrusted]`;
  `/omemo trustmode manual|firstusage|blind` (blind trust before verification new in 0.20); `/omemo qrcode` draws the user's own
  fingerprint as a QR code (libqrencode, a build option).
- **Store and logs.** Chat history in SQLite, unencrypted; **`PREF_OMEMO_LOG` defaults to `"on"`**, logging decrypted OMEMO
  messages in plaintext (`src/config/preferences.c`); `/omemo log redact` exists.
- **Accounts.** `/account` keeps several; whether several connect at once was not verified.
- **Tests.** 52 cmocka unit-test files and 14 functional tests that drive the real binary against **stabber**, a stub XMPP
  server; valgrind in CI images; CodeQL. The strongest end-to-end harness of the survey.
- **Post-quantum.** None (OMEMO on the libsignal-protocol-c lineage).

## 5. IRC-style benchmarks: WeeChat, irssi, senpai

### WeeChat

[weechat/weechat](https://github.com/weechat/weechat); [user guide](https://weechat.org/files/doc/weechat/stable/weechat_user.en.html);
[developer guide](https://weechat.org/files/doc/weechat/stable/weechat_dev.en.html).

- **Layout.** Bars (buflist, title, status, input, nicklist) all configurable (`/bar`); split windows; `/layout` saves and
  restores them. `Ctrl+s` searches the buffer, `Ctrl+r` the command history.
- **Discoverability.** `/help <command>` for every command, `/fset` as an interactive option browser, tab completion of commands
  and nicks. A Vim mode is a third-party script (not verified).
- **Hotlist.** A status-bar item listing buffers with activity by level (low, message, private, highlight), e.g.
  `H: 3:#abc(2,5), 5`; per-buffer notify levels; highlight words, regexes and tags. The benchmark for unread state.
- **Secured data.** `/secure` stores secrets in `sec.conf` ("highly sensitive", the guide), encrypted under an optional
  passphrase (without one: plain text); the passphrase may come from `passphrase_command` or `WEECHAT_PASSPHRASE`; config values
  reference `${sec.data.name}`, so the main config holds names only. (The cipher defaults, AES-256 and SHA-256, are from a
  [2013 post](https://blog.weechat.org/post/2013/08/04/Secured-data), not confirmed for 4.x.)
- **Logs.** `logger.file.auto_log` is **on by default** at level 9 ("log all messages displayed on buffer"), one file per buffer.
- **Remote.** The relay plugin (IRC proxy, the weechat protocol, an HTTP "api" protocol) and since 4.3 `/remote` from one WeeChat
  to another ([post](https://blog.weechat.org/post/2024/05/19/API-relay-and-remote-connection)); `weechat-headless --daemon`.
- **Copying.** `Alt+l` "bare display" drops WeeChat's decorations so the terminal can select text; no OSC 52 in the docs.
- **Crash and restart.** `/upgrade` restarts the binary in place, keeping buffers and connections.
- **Tests.** CppUTest unit tests (`tests/unit`: core, gui, plugins, relay api), generated scripting-API tests, OSS-Fuzz targets
  ([tests/unit/CMakeLists.txt](https://github.com/weechat/weechat/blob/main/tests/unit/CMakeLists.txt)).

### irssi

[irssi.org](https://irssi.org/) ([new users](https://irssi.org/New-users/), [settings](https://irssi.org/documentation/settings/),
[OTR help](https://irssi.org/documentation/help/otr/)).

- Windows as tabs (`Ctrl+n/p`, `Alt+<n>`), `/help <cmd>`; activity and highlight levels per message class.
- **`autolog` is off by default**, unlike WeeChat.
- **Paste safety:** `paste_verify_line_count = 5` asks before sending a paste longer than five lines; bracketed paste off by
  default; paste detected by timing (`paste_detect_time = 5 ms`).
- **OTR** is a default module: `/otr init|auth|authq|trust|distrust|genkey`, verification by shared secret or SMP question;
  keys and fingerprints in files under the irssi directory.
- Running under `screen` or `tmux` over SSH is the canonical pattern in third-party guides (e.g. the
  [ArchWiki](https://wiki.archlinux.org/title/Irssi)).

### senpai

[delthas/senpai](https://github.com/delthas/senpai) (mirror of sr.ht), [senpai(1)](https://man.archlinux.org/man/senpai.1.en),
[senpai(5)](https://man.archlinux.org/man/senpai.5.en).

- **"No logs are kept locally"** (vendor claim): history from the server (IRCv3 CHATHISTORY), search on the server, uploads via
  FILEHOST; built for a bouncer.
- Buffer list left or bottom, member list right, timeline, input with a typing line; `Alt+P/N` jump between highlights,
  `Shift+Left/Right` between unread buffers; a completion popup; `/HELP [search]` searches commands; full mouse support.
- `password-cmd` fetches the password at run time; a `transient` mode with no disk reads or writes.

## 6. Telegram and WhatsApp: nchat, tg

### nchat

[d99kris/nchat](https://github.com/d99kris/nchat) ([README](https://github.com/d99kris/nchat/blob/master/README.md),
[release](https://github.com/d99kris/nchat/releases/latest)).

- Top bar, status bar, a **help bar of key hints**, chat list, history, input; dialogs for chats, contacts, emoji, files. Readline
  keys, all remappable (`key.conf`); `Tab` between chats; unread chats marked `*`, `Ctrl+f` to the next unread;
  `mark_read_on_view = 1` by default; desktop notifications off by default.
- Media opened externally; attachments sent, downloaded and opened by keys; clipboard through configured commands.
- Several protocols and profiles in one directory, or one directory per account.
- **Storage:** a message cache with no application-level encryption; the README's security section relies on user-only file
  permissions and recommends disk encryption.
- Key verification UX (Telegram secret chats, Signal safety numbers) not documented. No test suite described.

### tg

[paul-nameless/tg](https://github.com/paul-nameless/tg) ([releases](https://github.com/paul-nameless/tg/releases)).

- Python `curses` over TDLib; "vi like keybindings" with counts (`4j`, `dd`); unread counts, "new" and "unseen" message flags, a
  "secret" chat flag (`tg/views.py`); notifications through an external `NOTIFY_CMD`; media opened by mailcap, photos as text
  placeholders. BiDi and Arabic/Persian reshaping, opt-in since v0.25.0.
- `ENC_KEY` encrypts the local TDLib database (vendor claim); the config is a Python file that may pull secrets from a password
  store.
- A CLI beside the TUI (`tg unread --json`, `history`, `search`, `watch`), sending off unless `CLI_SEND = True` with an allow-list
  (vendor claim).
- Tests include CLI rendering, text width and special keys ([tests](https://github.com/paul-nameless/tg/tree/master/tests)).

## 7. SimpleX and Nostr

### SimpleX Chat CLI

[simplex-chat/simplex-chat](https://github.com/simplex-chat/simplex-chat); [CLI docs](https://simplex.chat/docs/cli.html); source
on the `stable` branch (`src/Simplex/Chat/Terminal/Input.hs`, `Help.hs`, `View.hs`, `Options/SQLite.hs`, `tests/Test.hs`).

- **A line REPL, not panes:** `@name msg`, `#group msg`, `/c` to create or accept an invitation, `/f` to send a file; `/help` by
  topic; tab completion of contacts, groups, members and commands; Up recalls the last input only.
- **Security code:** `/code @name` prints the code "pass this code to your contact and use /verify to verify"; `/verify @name
  <code>` marks the contact verified; `/info` says "connection verified" or "not verified, use /code"; a key change prints
  "security code changed". The same for group members. No QR in the core CLI; links print as text.
- **Profiles:** `/create user`, `/hide user <pwd>`, incognito connections.
- **Store:** two SQLite files under SQLCipher: `/db encrypt <key>`, `/db key <old> <new>`, `/db decrypt <key>`, or `-k` at start;
  `/db export` makes an archive the mobile apps import.
- **Secrets on screen (inference from source, not run):** `Input.hs` echoes every command line that is not a message, so
  `/db encrypt <key>` and `/hide user <pwd>` probably land in scrollback; `-k` puts the key in argv.
- **Post-quantum:** sntrup761 in the double ratchet, opt-in in v5.6 (2024-03-14), "kick[s] in after 3-5 messages"
  ([post](https://simplex.chat/blog/20240314-simplex-chat-v5-6-quantum-resistance-signal-double-ratchet-algorithm.html)), on by
  default for direct chats from v5.7 (2024-04-26), none in groups then
  ([post](https://simplex.chat/blog/20240426-simplex-legally-binding-transparency-v5-7-better-user-experience.html)). The CLI
  prints an event line "quantum resistant / standard end-to-end encryption enabled"; `/info @contact` adds "quantum resistant
  end-to-end encryption" only when on and **prints nothing when off**; addresses take `pq_ratchet=on|off`.
- **Tests:** Hspec, including a "SimpleX chat view" suite and end-to-end chat-client tests.

### Nostr

- **nostui** ([akiomik/nostui](https://github.com/akiomik/nostui), [Cargo.toml](https://github.com/akiomik/nostui/blob/main/Cargo.toml)):
  Ratatui 0.30 + crossterm 0.29 over nostr-sdk; timeline, mentions, per-author tabs, Vim `j/k/g/G`; user bindings merged over
  defaults ("default keybindings cannot be removed"); **the secret key (nsec) in a plaintext `config.json`**; integration tests
  against nostr-sdk's local relay.
- **algia** ([mattn/algia](https://github.com/mattn/algia)): the key in plaintext, or NIP-49 `ncryptsec` with a password from the
  terminal or `$ALGIA_PASSWORD`, or a NIP-46 remote signer (`bunker://`); DMs NIP-17 gift wrap by default, NIP-04 opt-in.
- **tualgia** ([mattn/tualgia](https://github.com/mattn/tualgia)): sixel images, NIP-50 search, `?` help, a theme file.
- **TUIstr** ([alltheseas/TUIstr](https://github.com/alltheseas/TUIstr)): the key in a TOML file. **noscl** archived; **nostr_console**
  retired (vendor claim).
- NIP-44 v2 states it has no forward secrecy, no post-compromise security and "No post-quantum security"
  ([NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md)).
- **Lesson.** The remote-signer split (NIP-46) is the SCaaS shape already: keys behind the SDK and `ua-rs`, never in the UI's
  config (CLI-SDK-02, CLI-TUI-17).

## 8. Zalo

Added at the owner's request: Zalo (VNG) is the dominant messenger in Vietnam (about 80 million users there, per
[Tuoi Tre News](https://news.tuoitre.vn/zalo-responds-to-backlash-over-updated-terms-of-service-in-vietnam-10325123116381913.htm),
2026-01-01). It has **no official terminal client**. Most feature facts below come from Vietnamese how-to sites, not from Zalo's
own help pages (the search found none, and the help article the whitepaper links returned 404); they are marked
**(third-party guide)** and may be out of date.

### Unofficial clients and libraries

| Project | What | Licence | Status (fetched 2026-11-24) |
|---|---|---|---|
| [zca-js](https://github.com/RFS-ADRENO/zca-js) | JavaScript library for a personal account, "simulating the browser to interact with Zalo Web"; QR login (`loginQR`), message listener, send, quote, stickers, images | MIT | active (push 2026-11-23); v2 |
| [zcago](https://pkg.go.dev/github.com/amrakk/zcago) | Go port of the same approach: messages, groups, friends, polls; login by QR or by IMEI + cookie + user agent | MIT | v0.3.0, 2025-12-27, newer versions exist |
| [zlapi](https://github.com/Its-VrxxDev/zlapi) | Python, browser imitation, sync and async | MIT | **archived** (last push 2024-11-24); its PyPI page says the earlier `zaloapi` module "has been removed from Pypi and the reason is unknown" |
| zca-cli (zca-cli.dev) and [openzca](https://github.com/darkamenosa/openzca) | command-line tools over zca-js; openzca draws the login QR inline on Ghostty, Kitty, WezTerm and iTerm2, ASCII elsewhere (vendor claim) | not verified | — |
| [zca-desktop](https://awesome.ecosyste.ms/projects/github.com%2Ftuanle96%2Fzca-desktop) | a GUI client (Tauri), not a terminal one | not verified | — |
| Zalo Official Account API ([developers.zalo.me](https://developers.zalo.me/)) | the **official** bot path: an OA approved by Zalo, message endpoints under `openapi.zalo.me`, template notifications (ZNS), OAuth user tokens, mini apps | Zalo's terms | official; endpoint versions per third-party SDKs ([infobip](https://infobip.com/docs/zalo)) |

**Terms.** zca-js and zcago warn that use "could get your account locked or banned" and that only one web listener runs per
account (vendor claim, READMEs). Zalo's terms are reported to forbid logging in through software or systems Zalo did not develop
or approve ([cafef.vn](https://cafef.vn/thao-tac-co-the-khien-tai-khoan-zalo-cua-ban-bi-khoa-vinh-vien-188260910160926853.chn),
secondary source; the current terms text not read). So every personal-account library above very likely breaks the terms;
only the OA API is a sanctioned path, and it is for businesses, not for a user's own chats.

### Encryption model

- **Protocol (vendor claim).** Zalo's E2EE whitepaper ([PDF](https://res-zalo.zadn.vn/help/0620_E2EE_Whitepaper.pdf), created
  2022-06-20, in Vietnamese) describes Signal's design: X3DH with Curve25519 identity, signed and one-time prekeys stored on Zalo's
  server; the Double Ratchet (HKDF and HMAC-SHA256 chain steps); files under a random 256-bit key with AES-256-GCM, uploaded to
  Zalo's server and the key sent in the 1:1 session; **groups by per-sender chain keys** sent to each member over 1:1 sessions and
  renewed when a member joins or leaves (sender keys); **multi-device by Sesame**, a session to each device of the peer and of the
  sender. It names Signal's specifications as references. No independent audit was found.
- **Opt-in, per conversation.** The whitepaper says users "can" secure 1:1 and group chats; 2023–2025 guides describe turning it on
  by hand per conversation, call it a trial, and say calls and livestreams are not covered
  ([CellphoneS](https://cellphones.com.vn/sforum/cach-tat-ma-hoa-dau-cuoi-zalo), updated 2024-05-26, third-party guide). The
  same guide turns it off only through a third-party browser extension.
- **Conflicting status.** Zalo told Tuoi Tre News on 2025-12-31 that it "is in the process of seeking approval from relevant
  authorities to implement end-to-end encryption" and that it "does not store the content of personal messages or calls"
  ([article](https://news.tuoitre.vn/zalo-responds-to-backlash-over-updated-terms-of-service-in-vietnam-10325123116381913.htm)).
  How that fits the 2022 whitepaper and the per-chat switch was not resolved (section 16).
- **What server-side history means.** By default a chat is not end-to-end encrypted, so its plaintext can be read by the
  operator wherever it is kept; the "no storage" statement is a vendor claim under terms that, from December 2025, collect
  "interaction content" among other data (same article; the competition authority summoned VNG over the terms,
  [VnExpress](https://e.vnexpress.net/news/tech/enterprises/vietnam-competition-authority-summons-operator-vng-over-messaging-app-zalo-s-controversial-user-terms-4999853.html)).
  Multi-device history and new-phone restore rest on that server copy or on a backup ("encrypted chat backups should carry a
  password", the CellphoneS guide).

### Devices, groups and services

- **QR login** for Zalo PC and Web: the phone scans a QR code shown on the computer, then taps "Đăng nhập"; the code expires
  ([Quantrimang](https://quantrimang.com/cach-dang-nhap-zalo-bang-ma-qr-181434), third-party guide). After login the app offers to
  sync messages; Zalo PC has a text-message backup used to move history back to a phone (VnExpress, as quoted by guides).
- **Groups and communities:** regular groups up to 100 members (some guides say 200), a group upgraded to a **community** up to
  1,000 after the leader verifies the account; communities can hide the member list and restrict `@all` to admins
  ([CellphoneS](https://cellphones.com.vn/sforum/nang-cap-nhom-zalo-len-cong-dong), third-party guide).
- **Polls:** members vote, the creator sees who chose what, a poll cannot be deleted, only locked
  ([CellphoneS](https://cellphones.com.vn/sforum/cach-tao-binh-chon-tren-zalo), third-party guide).
- **Pinned messages:** at most 3 per chat; one can unpin only what one pinned
  ([Quantrimang](https://quantrimang.com/cach-ghim-tin-nhan-tren-zalo-166111), third-party guide).
- **Recall:** a sent message can be recalled for everyone; tools to view recalled messages are widely described
  ([CafeF](https://cafef.vn/cach-xem-tin-nhan-da-bi-thu-hoi-o-zalo-va-messenger-don-gian-nhanh-nhat-188261018152003956.chn),
  third-party guide), which shows that recall hides a message rather than erases it.
- **"Cloud của tôi" (My Cloud):** a personal space synced to every logged-in device, where a message is saved by "Lưu Cloud"
  (third-party guides via search; not fetched).
- **Phone-number discovery:** with contact access granted, Zalo matches phone numbers to accounts and suggests friends; guides
  advise turning off "allow strangers to find and add me by phone number", and say it cannot be blocked per person
  ([CafeF](https://cafef.vn/5-cai-dat-zalo-nen-lam-ngay-de-nguoi-la-ke-lua-dao-khong-tim-thay-18826102806225979.chn),
  [FPT Shop](https://fptshop.com.vn/tin-tuc/thu-thuat/cach-an-so-dien-thoai-zalo-214226), third-party guides).
- **Official accounts, mini apps, payments, stickers:** OAs are approved business accounts with a messaging API; mini apps run
  inside Zalo; ZaloPay is a separate payment platform with its own terms
  ([ZaloPay terms PDF](https://scdn.zalopay.com.vn/zst/zlp-website/resources/static/thoa-thuan-su-dung-nen-tang-zalopay-26-06.pdf));
  stickers are a core message type (they are among the whitepaper's encrypted types). The product page lists messaging,
  calls, a private feed, AI features and business tools ([zalo.me](https://zalo.me/en/product/zalo), vendor claim).
- **Clipboard.** A lawyer's commentary argues that the iOS app reads clipboard data on its own
  ([LSVN](https://lsvn.vn/zalo-tu-dong-lay-du-lieu-tu-bo-nho-iphone-mot-so-van-de-phap-ly-ma-nguoi-dung-can-biet-de-bao-ve-quyen-loi-ich-cua-minh-a54392.html),
  opinion, not a finding).

### Zalo: what to weigh for a PqChat front-end

| # | What Vietnamese users expect (Zalo) | Maps to | Note |
|---|---|---|---|
| Z1 | recall / unsend | `redact` content (CLI-PQC-02, UA-7 §6.4.1); T14 part B | the TUI says "recalled by the sender" and that the ciphertext stays in the chain store and the Matrix room (never lose ciphertext): recall hides, it does not erase. Zalo's recall viewers show the same truth |
| Z2 | reactions, edit | `react`, `edit` (CLI-PQC-02); T14 part B | built in the crate; the TUI draws them |
| Z3 | pinned messages (3 per chat) | **new** | no PqChat content type: a new type is a UA-7 byte format, so every client and vector at once (AGENTS.md "Clients and vectors"); not a TUI-only feature |
| Z4 | polls in groups | **new** for sessions; `PqTopicVote` exists for public topics (CTR-CHAT-03) | a session poll needs a content type (as Z3); a vote counted from decrypted messages must not trigger any send (ARCH-POS-13) |
| Z5 | "My Cloud" notes to self, synced to every device | PqVault personal vault `note` items (CLI-PQV-02); T14 part A | the vault is the state-only, encrypted place for it; no plaintext cloud |
| Z6 | QR login of the PC from the phone | device link with a short code (UA-7 P6); spec §5.3 shows the code as text | a QR in the TUI would be a spec change (spec §2) and, if it carries a link secret, CLI-TUI-04's concern |
| Z7 | full history on every new device | CLI-PQC-09: recovery from contract state; chain stores and the Matrix room's history | PqChat recovers sessions and the latest messages from state with the seed alone; no server-held plaintext |
| Z8 | groups to 100, communities to 1,000; hide the member list; `@all` for admins only | flat sessions and the tree mode (CTR-CHAT-26, CLI-PQC-17); **new** for the rest | large groups are what TreeKEM is for; whether a member list can be hidden depends on what the epoch records reveal on chain, a protocol question, not a UI switch |
| Z9 | official accounts and broadcast channels | PqChat public topics (CLI-PQC-02; `PqTopic*`, CTR-CHAT-03) | a topic is the SCaaS analogue; mini apps have none |
| Z10 | pay inside a chat (ZaloPay) | SCaaS send and pay (`mtxPay` with `PayMeta`) through the review (CLI-TUI-02, CLI-TUI-08; spec §5.5) | **new** as an in-chat action: it opens the normal pay form and review; nothing is signed from a message's content |
| Z11 | stickers, images, voice | `file` content sealed for Arweave (CLI-PQC-02); stickers **new** | the TUI shows a file as a row and fetches on the user's key; inline images conflict with the byte-stream scan (section 15) |
| Z12 | find friends by phone number | **not to copy**; identity is the UA, a Matrix id bound by a signed contact card (UA-7 §14 O7, CLI-PQC-05) | a phone directory links a real-world number to a UA for whoever runs it; contacts are added by UA id or contact card |
| Z13 | E2EE as an opt-in switch per chat | **not to copy**; PqChat has no plaintext mode (CLI-PQC-03, CLI-PQC-04) | every session is encrypted; the TUI shows the mode (flat or tree), not an on/off |
| Z14 | a browser-imitating client for a personal account (zca-js family) | **not to copy**; no Zalo bridge in scaas-tui | breaks Zalo's terms (as reported) and would bring a second identity and a plaintext path into a SCaaS-only program (CLI-TUI-01) |
| Z15 | an app that reads the clipboard by itself (alleged, iOS) | CLI-TUI-14, CLI-TUI-08 (4) | the TUI never reads the clipboard; a paste arrives only as the user's bracketed paste |

## 9. Post-quantum messaging in a terminal

- **Signal.** PQXDH (Kyber/ML-KEM prekeys) and, since 2025-10-02, SPQR mixed with the Double Ratchet as the "Triple Ratchet"
  ([Signal blog](https://signal.org/blog/spqr/)). The terminal clients that reach it are those over libsignal: **gurk-rs**
  (presage advertises `spqr`) and **signal-cli** (so scli), and nchat's Signal backend (signalmeow; inference). None shows a PQ
  status to the user.
- **SimpleX CLI.** sntrup761 in the ratchet for direct chats, shown as an event line and in `/info` (section 7).
- **Zalo.** Signal-style X3DH and Double Ratchet, opt-in per chat (section 8); no post-quantum part described.
- **Matrix.** No post-quantum Olm or Megolm in the spec; the team's direction is MLS
  ([matrix-spec#975](https://github.com/matrix-org/matrix-spec/issues/975)); academic Kyber work on vodozemac was presented at
  the Matrix Conference 2026 ([talk](https://cfp.2026.matrix.org/matrix-conference-2026/talk/TZ8ZYX/)).
- **XMPP, Nostr, IRC.** None.
- **Small experimental terminal chats** (vendor claims, unaudited, not reviewed): why2-chat (Rust, ECC + ML-KEM,
  [docs.rs](https://docs.rs/crate/why2-chat/2.0.0)), QuantTerm (Go, Kyber-1024 and Dilithium-5), ftw-cli (Kyber), NullNode
  (ML-KEM through GnuPG 2.5).
- **Where PqChat stands apart.** PqChat's key directory, sessions and epochs are on chain (CTR-CHAT-01,
  [contracts/pqchat.md](../contracts/pqchat.md#CTR-CHAT-01)), with ML-KEM-1024 wraps (UA-7 spec P4, P14). No surveyed client
  has a post-quantum group mode; PqChat specifies a TreeKEM mode over KEM keys (CTR-CHAT-26, CLI-PQC-17, SPECIFIED). The status
  lesson from SimpleX is the one to take: say the mode in words, including when it is weaker (section 13, A9).

## 10. Ratatui wallets, briefly

TODO item 11 already lists Solace, den, hodl, gm-tui and ledger-tui as prior art (early and unaudited). Two more seen: silo
(Solana, Ratatui, seed under Argon2 + XChaCha20-Poly1305, vendor claim, [repo](https://github.com/265866/silo)) and wui
(Solana, stack not verified, [repo](https://github.com/chambaz/wui)). Nothing in them changes the lessons below.

## 11. Patterns across the field

| Topic | What the field does | Best seen |
|---|---|---|
| Layout | a list pane (rooms, buffers, chats), a timeline, one input line at the bottom, optional member pane; splits and tabs in power tools | WeeChat bars and `/layout`; iamb windows; senpai's toggled side panels |
| Keys | either Vim modal (iamb, scli, tg, nostui) or readline/Emacs (gurk, nchat, senpai); `/` or `:` commands; remapping everywhere | a key-hint bar (nchat), `/help <cmd>` (WeeChat, irssi), `/HELP search` (senpai), `?` / F1 (scli, gurk) |
| Unread | bold or `*` rows, counts, jump-to-next-unread, highlight levels | WeeChat's hotlist with levels; senpai's jumps between unread and highlights |
| Media | `ratatui-image` (sixel, kitty, iTerm2, half-blocks) in Rust clients; external opener elsewhere | iamb; gurk-rs on main |
| Verification | Matrix emoji SAS by commands; OMEMO fingerprints and trust modes; SimpleX security codes; Signal safety numbers mostly absent in terminals; QR only for one's own key or device linking | SimpleX `/code` + `/verify` + "security code changed"; profanity's trust marks in the title bar |
| Store at rest | from none (iamb, nchat, profanity) or a constant key (gomuks `"meow"`, weechat-matrix-rs `"DEFAULT_PASSPHRASE"`) to a mandatory passphrase (gurk-rs SQLCipher, SimpleX SQLCipher on request) | gurk-rs |
| Secrets on screen | recovery keys and passphrases typed on visible command lines (iamb, SimpleX inference), passwords in argv (matrix-commander, SimpleX `-k`), linking QR printed to scrollback (gurk-rs, scli) | rpassword prompts (iamb), `password-cmd` (senpai), secured data referenced by name (WeeChat) |
| Logs | off by default (iamb, irssi, senpai) vs on by default with bodies (WeeChat `auto_log`, profanity `PREF_OMEMO_LOG`); debug dumps of bodies (scli, gurk `dev`) | iamb (off, and compiled out on request) |
| Clipboard | OS clipboard tools; **no surveyed client uses OSC 52**; tmux's `set-clipboard` defaults to `external`, so OSC 52 from inside tmux does not reach the system clipboard unless the user turns it on ([tmux wiki](https://github.com/tmux/tmux/wiki/Clipboard)) | — |
| Paste | bracketed paste rare; irssi confirms a paste above 5 lines; iamb confirms an image paste | irssi |
| SSH and tmux | the client inside tmux or screen over SSH (irssi tradition); or a relay or bouncer (WeeChat relay and `/remote`, gomuks backend, senpai with soju) | — |
| Crash | panic hooks that restore the tty (iamb); scope guards (gurk); `/upgrade` restart in place (WeeChat) | — |
| Accessibility | nothing documented for screen readers in any client; themes and `NO_COLOR`-like settings vary | — |
| Tests | mostly unit tests; render tests only in gurk-rs (`TestBackend`); a stub server driving the real binary in profanity; fuzzing in WeeChat; no snapshot crate seen | gurk-rs and profanity |

## 12. PqChat specifics that change the lessons

From [clients/pqchat-core.md](../clients/pqchat-core.md), [contracts/pqchat.md](../contracts/pqchat.md) and the UA-7 spec
([`2026-10-25-ua7-pq-e2e-sessions.md`](../superpowers/specs/2026-10-25-ua7-pq-e2e-sessions.md)):

- **Sessions and epochs are on chain.** The chain holds identity, the KEM key directory and the control plane (CTR-CHAT-01);
  rekeys are epochs, and members, rekey, remove and leave are signed records reviewed before signing (CLI-PQC-04). A room list
  is a session list, with states a Matrix client does not have: **pending** until accepted (CLI-PQC-08), and per epoch
  "followed" or "not followed".
- **Recovery is from state only** (CLI-PQC-09, CTR-CHAT-14): a fresh device finds its sessions from contract reads, never
  events; the local store is a cache with no secret and **no plaintext** until the sealed local history lands (PLANNED). So
  offline history in the TUI is what the chain stores and the Matrix room's history return, not a local message database.
- **Flat and tree modes.** `groupMode = 0` is the flat wrap mode (BUILT); `groupMode = 1` is TreeKEM (CTR-CHAT-26, CLI-PQC-17,
  SPECIFIED), refused by name until built, with the owner's rulings of 2026-11-23: a compromise warning, a warning before an
  Add of a key registered to another UA, freshness before a changed session info, "conflicting head" shown when reads disagree.
- **Receipts.** No automatic receipt in a tree session (CLI-PQC-17); `receipt` off by default while a chain store is listed
  (CLI-PQC-06); a failed record is no error, no receipt, no retry (CLI-PQC-07). In a bound Matrix room the transport sends **no
  Matrix read receipt, read marker, typing notice or presence** (CLI-PQC-05, UA-7 P15). So unread state is local only.
- **Transport.** Matrix carries the content (`net.scaas.pqchat.v1` events, without Megolm, so a device with the seed alone reads
  the room's history), the chain carries control and optionally messages (`storeMessage`, `postMessage`); one Matrix stack and one
  login per app (CLI-PQC-05; spec O6). Matrix's own device verification (emoji SAS, cross-signing) therefore protects nothing in
  PqChat: identity is the UA, bound to a Matrix id by a signed contact card (UA-7 §14 O7).
- **Fingerprints.** UA-7 P4 item 4: a client shows a fingerprint of each member's `kemPkHash` and warns when two UAs list the same
  KEM key; device linking (UA-7 P6) uses an ephemeral key and a short code (QR in the spec).
- **Secrets.** Every key stays in `ua-rs` behind handles; only decrypted plaintext leaves, as `SecretBytes` (CLI-PQC-03).

## 13. What scaas-tui should adopt

Each lesson maps to a rule or task, or is marked **new** (a proposal for the spec, not a rule).

| # | Lesson (from) | Maps to | Note |
|---|---|---|---|
| A1 | Render tests on `TestBackend` for every screen (gurk-rs `src/ui/draw.rs`); none of the others has them | T2 golden frames; spec §14; Q-T9 (plain files) | gurk-rs proves the approach at Ratatui 0.30; keep plain golden files, no snapshot crate |
| A2 | Drive the real binary against a stub server (profanity's stabber) | T1 PTY harness; T11 e2e; T14 part B with `pqchat-core`'s Matrix fake | the same shape: the real binary, a PTY, a fake transport, plus the local Synapse e2e `pqchat-core` already has |
| A3 | A key-hint bar on every screen (nchat), `/help <cmd>` (WeeChat), searchable help (senpai `/HELP search`) | CLI-TUI-07 (every action a key in the footer), T2 `footer_lists_the_keys` | add a searchable help screen: **new**, small; action names equal the CLI's subcommands (Q-T10) |
| A4 | Modal keys made visible (iamb's Vim modes; gurk's per-mode bindings) | CLI-TUI-16 (modal fields, the footer names the mode), CLI-TUI-07 | keep the TUI's own small modal map; no full Vim emulation (modalkit would be a new dependency) |
| A5 | Unread and highlight levels with jumps (WeeChat hotlist, senpai `Shift+Left/Right`, nchat `Ctrl+f`) | T14 part B | **new** for the chat screens: unread is local only (section 12), from the crate's read positions; never a Matrix receipt |
| A6 | Mute per room and what a notification may show (gurk `show_message_text`) | T14 part B; CLI-TUI-04 | **new**: the TUI has no notifications; if one is added it carries no body, no name and no room id (bell only) |
| A7 | A paste confirmed when large or binary (irssi 5 lines, iamb image paste) | CLI-TUI-08 (4) (paste never keys, no newline submits) | T14 part B: a paste into compose is text only, never sends; a file is attached by its own action |
| A8 | Security code as plain text, a verify command, "security code changed" on a key change (SimpleX) | UA-7 P4 item 4 (fingerprint of `kemPkHash`, warn on a shared KEM key); T14 part B | **new** for the TUI: show each member's KEM fingerprint in the members view and a visible mark when a member's KEM version rises (UA-7 P10 rekey reason) |
| A9 | Say the protection level in words, also when weaker (SimpleX prints "quantum resistant" only when on; better to print both) | CLI-TUI-07 (no colour-only meaning) | **new** for chat: each session shows its mode (`flat` or `tree`), its home and its stores in words; a tree session's compromise warning (CLI-PQC-17) |
| A10 | A mandatory passphrase for any local store (gurk-rs SQLCipher; zeroized type) | CLI-PQC-09 (the store encrypted at rest by the app, device-bound); CLI-SDK-02 | the TUI keeps no store of its own; `pqchat-core`'s cache needs the app's store key on a terminal: spec §5.10 "depends" |
| A11 | Panic hook restores the tty (iamb); decoding in a guarded worker (gurk `catch_unwind` around images) | CLI-TUI-10 (restore, clear, abort) | the TUI goes further (abort, no unwind); keep it |
| A12 | Secrets referenced by name, never as values (WeeChat `${sec.data.x}`, senpai `password-cmd`) | CLI-TUI-06 (credentials by file or env name), CLI-TUI-16 (no secret in argv, env or config) | the Matrix password of T14 part B is a secret field, never a config value |
| A13 | Logs off by default and compiled out on request (iamb `max_level_*`) | CLI-TUI-16 (`--log` only, `0600`, no form value) | T14 adds no message body, room id or Matrix id to a log line (`no_body_in_log`) |
| A14 | Layout: list pane, timeline, compose at the bottom, member pane toggled (senpai F7/F8) | spec §5.10, T14 part B | fits 80 × 24 with the member pane off; CLI-TUI-07's size floor holds |
| A15 | A CLI beside the TUI on one store (tg CLI mode, matrix-commander) | CLI-SDK-17, CLI-TUI-17 (shared data directory under the keystore lock) | already the design |
| A16 | Backend split from the UI (gomuks hicli; WeeChat relay; NIP-46 signers) | CLI-TUI-17, CLI-SDK-02 | already the design: the SDK and `ua-rs` hold every key |

## 14. What not to copy

| # | Seen in | Why not | SCaaS rule |
|---|---|---|---|
| N1 | a store with no key (iamb), a constant key (gomuks `"meow"`, weechat-matrix-rs `"DEFAULT_PASSPHRASE"`), plaintext history (profanity, scli `--save-history`, nchat cache) | at-rest encryption in name only | CLI-PQC-09 (no plaintext stored; encrypted by the app); CLI-SDK-02 |
| N2 | decrypted message bodies logged by default (profanity `PREF_OMEMO_LOG = on`, WeeChat `auto_log` on), body dumps at debug (scli envelopes, gurk `dev` `messages.json`) | a log is a plaintext copy outside every rule | CLI-TUI-04, CLI-TUI-16; CLI-PQC-03 (no plaintext in a log) |
| N3 | a recovery key or passphrase typed on the visible command line (iamb `:verify recover <key>`, `:keys export … <passphrase>`; SimpleX `/db encrypt <key>`, inference) | it is drawn, kept in scrollback and in command history | CLI-TUI-04, CLI-TUI-16 (secret fields only) |
| N4 | passwords and keys in argv or env (matrix-commander `--password`, SimpleX `-k`, `WEECHAT_PASSPHRASE`, `$ALGIA_PASSWORD`) | `/proc`, shell history, children | CLI-TUI-16 (never argv, the environment or the config) |
| N5 | a linking secret printed to stdout as a QR and saved as a PNG (gurk-rs, scli) | scrollback and a file outside the store | CLI-TUI-04; spec §2 (no QR codes in this frame) |
| N6 | identity changes trusted automatically (gurk `OnNewIdentity::Trust`), blind trust modes (profanity `trustmode blind`) | a changed key passes silently | UA-7 P4 (highest KEM version, fingerprint, shared-key warning); CLI-PQC-13 (trusted reads) |
| N7 | OSC 52 for anything but a public value; a clipboard copy of a secret (CLI-PQV-04's "copy" in the app) | a write any pane can make; tmux `set-clipboard on` lets every program set it | CLI-TUI-14 (public values only, off by default); CLI-TUI-04 |
| N8 | Matrix read receipts, read markers, typing and presence (iamb, gomuks, every Matrix client) | plaintext ephemeral events about the user's reading | CLI-PQC-05, UA-7 P15 |
| N9 | Matrix emoji SAS or cross-signing as the trust step | PqChat rooms carry no Megolm; identity is the UA | CLI-PQC-05 (a Matrix id counts only when bound) |
| N10 | automatic receipts or retries when a message fails to decrypt | a decryption oracle | ARCH-POS-13; CLI-PQC-07 |
| N11 | a secret key in the UI's config file (nostui `config.json`, TUIstr TOML) | key outside the signer | CLI-SDK-02, CLI-TUI-17 |
| N12 | the window title or a notification set from message data | an escape or a leak outside the screen | CLI-TUI-16 (title never from data); CLI-TUI-05 |
| N13 | full mouse support as the primary path (senpai) | not wrong, but outside the frame | CLI-TUI-07 (no mouse needed) |
| N14 | a remote UI to a key-holding daemon (WeeChat relay, gomuks bouncer) | a new network path to the SDK | CLI-TUI-01 (one binary, local or over SSH) |

## 15. Conflicts with SCaaS rules

- **Clipboard copy of vault secrets.** CLI-PQV-04 (controller call) lets an app copy a secret field with a sensitive clipboard
  and a 30 s clear; CLI-TUI-04 and CLI-TUI-14 (owner) allow only public values on the clipboard. The TUI follows the owner
  rules: no copy of a secret field (spec §5.10, plan T14 `no_copy_of_a_secret`). A terminal has no sensitive-clipboard flag
  and OSC 52 cannot be cleared reliably, so the TUI cannot meet CLI-PQV-04's means anyway.
- **Copying a message body.** gurk-rs, gomuks and nchat copy messages; a decrypted body is not a public value, so CLI-TUI-14
  forbids it. Users select text with the terminal's own selection, which the TUI does not control (state it in the help).
- **Unread state from receipts.** Every Matrix client reads and sends receipts; CLI-PQC-05 forbids them in bound rooms, so the
  TUI's unread marks are this device's only and do not follow the user to another device.
- **Inline images.** `ratatui-image` (iamb, gurk) writes sixel, kitty or iTerm2 sequences into the byte stream; the TUI's
  byte-stream scan (plan T3 `secret_scan`, T11) refuses OSC, DCS, APC and PM, which sixel (DCS) and the kitty protocol (APC)
  are. Images would need a rule change; the frame has none (spec §2: no themes, mouse or QR; files fetched on the user's key
  only, CLI-PQC-02's `file`).
- **QR codes in the terminal.** profanity draws its own fingerprint and gurk-rs / scli their link URL as QR codes; the TUI spec
  §2 excludes QR codes, while UA-7 P6's device link uses a short code "(QR)". The TUI's device link shows the short code as text
  (spec §5.3); a QR would be a spec change, and a linking secret drawn as a QR is CLI-TUI-04's concern.
- **Local plaintext history.** Offline reading in every surveyed client rests on a local message store; CLI-PQC-09 stores no
  plaintext until the sealed local history (PLANNED), so the TUI re-reads from chain stores and the Matrix room after a lock.
- **Zalo's model.** Server-held plaintext history and multi-device sync from the server (section 8) against CLI-PQC-09's
  recovery from contract state with no plaintext stored and CLI-PQC-03's plaintext only for the user; phone-number identity and
  discovery against the UA as identity (UA-7 §14 O7, CLI-PQC-05: a Matrix id counts only when bound); E2EE as an opt-in switch
  against PqChat's always-encrypted sessions; unofficial clients against Zalo's own terms. A Zalo-like history experience comes
  from the chain stores, the Matrix room and the sealed local history (PLANNED), not from a server copy.
- **Verification by commands on the input line** (iamb, SimpleX `/verify @name <code>`): a typed code is not secret, so this
  fits; a typed recovery key does not (N3).

## 16. Not verified

- Screen-reader support of any surveyed client (nothing documented, nothing found).
- iamb: in-buffer message search, OSC 52 inside modalkit. gomuks terminal: whether `/verify-device` works, its terminal
  restore on panic. gurk-rs: whether live sessions negotiate SPQR (only the capability and the libraries were read), whether a
  panic leaves the alternate screen. matrix-commander: whether its store is encrypted, tokens in debug logs. profanity: several
  accounts connected at once.
- WeeChat 4.x secured-data cipher defaults (source a 2013 post), a Vim mode, images. senpai: image previews, its 0.5.0 changelog
  (sr.ht unreachable). nchat and tg: key verification UX, nchat tests. SimpleX CLI: the echo of `/db encrypt` and `/hide user`
  (read from source, not run), a per-contact PQ toggle. tualgia's toolkit. The experimental PQ chats of section 9.
- Zalo: whether E2EE is available today, opt-in or default (the 2022 whitepaper and 2023–2025 guides against Zalo's
  2025-12-31 statement that it is seeking approval to implement it); every feature fact from third-party guides (no Zalo help
  page was reached); the current terms' wording on third-party software; licences of zca-cli, openzca and zca-desktop; any
  independent audit of Zalo's E2EE.
- SSH, tmux and mosh behaviour of every client (no client was run); Unicode QR under tmux.
