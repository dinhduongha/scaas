// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `scaas`: the command line over `scaas-sdk` (CLI-SDK-17; spec §20; plan T22). One command per SDK call
//! (`scaas <group> <call> --flag value…`, the call's own name with `-` for `_`), named flags read into the SDK's own types, JSON
//! (`--json`) or a table out. Operations print the review and the quote and ask before anything is submitted; secrets come
//! only from a file descriptor (`--<name>-fd N`) or the terminal without echo, never from argv or the environment. One data
//! directory under the keystore's lock, shared with the TUI and the app. No logic of its own. UNAUDITED.
//!
//! `scaas [options] <group> <call> [--flag value…]`; `scaas [options] session` reads one command per line from stdin, each a
//! JSON array of words, so objects an SDK call returns (a prepared operation, a quote, an app key) are named (`--as`) and
//! passed to later calls by name. `scaas commands` lists every command with its flags.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod calls;
mod config;
mod flex;

use scaas_sdk::op::{Prepared, ReviewField, SubmitPath, SubmitQuote};
use scaas_sdk::{Sdk, SdkError};
use scaas_ua::wallet::SecretBytes;
use serde_json::{json, Value};
use std::any::Any;
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex, PoisonError};
use zeroize::Zeroizing;

/// The largest output of one command (1 MiB): above it `OutputTooLarge`, nothing printed.
pub const OUTPUT_MAX: usize = 1 << 20;
/// How long a command waits for its operation's send to be reported (as CLI-TUI-09's bounded wait at quit).
const SEND_WAIT_MS: u64 = 30_000;
/// The secrets that are bytes (a key, a signature), read as `0x` + hex.
const BINARY_SECRETS: &[&str] = &["secret", "key", "sig", "signature1", "signature2"];
/// The longest secret line read from a descriptor or the terminal.
const SECRET_MAX: usize = 4096;

/// A refusal: an SDK code, or the CLI's own code with a short detail (never a secret: details name flags and files).
#[derive(Debug)]
pub enum Fail {
    Sdk(SdkError),
    Cli(&'static str, String),
}

impl Fail {
    pub fn cli(code: &'static str, detail: impl Into<String>) -> Fail {
        Fail::Cli(code, flex::short(&detail.into()))
    }
    fn code(&self) -> &'static str {
        match self {
            Fail::Sdk(e) => e.code(),
            Fail::Cli(c, _) => c,
        }
    }
}

impl From<SdkError> for Fail {
    fn from(e: SdkError) -> Fail {
        Fail::Sdk(e)
    }
}

impl From<flex::Error> for Fail {
    fn from(e: flex::Error) -> Fail {
        Fail::cli("Argument", e.to_string())
    }
}

/// The options before the command.
#[derive(Default)]
pub struct Globals {
    pub data_dir: Option<String>,
    pub profiles: Option<String>,
    pub overlay: Option<String>,
    pub json: bool,
    pub yes: bool,
    pub unlock: Vec<String>,
    pub passphrase_fd: Option<String>,
    pub app: Option<String>,
    pub path: Option<String>,
    pub name: Option<String>,
}

/// What a call returned: JSON, or an object kept for later calls (a session) or carried through its operation (one command).
pub enum Out {
    Json(Value),
    Prepared(Arc<Prepared>),
    Writes(Vec<Arc<scaas_sdk::account::RegistryWrite>>),
    Order(Arc<scaas_sdk::dex::PreparedOrder>),
    Native(Box<scaas_sdk::wallet::NativeQuote>),
    Seed(scaas_sdk::vault::NewSeed),
    Handle(Arc<dyn Any + Send + Sync>, Value),
}

/// Objects named in this process (`--as`), by name.
static HANDLES: Mutex<Option<HashMap<String, Arc<dyn Any + Send + Sync>>>> = Mutex::new(None);

fn keep(name: &str, h: Arc<dyn Any + Send + Sync>) {
    HANDLES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .insert(name.to_string(), h);
}

/// An object named earlier in the session, given to a call by its name.
pub struct H<T>(pub T);

impl<'de, T: Clone + Send + Sync + 'static> serde::Deserialize<'de> for H<T> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let name = String::deserialize(d)?;
        let found = HANDLES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(|m| m.get(&name).cloned());
        found
            .and_then(|h| h.downcast_ref::<T>().cloned())
            .map(H)
            .ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "no object named {} of this kind",
                    flex::short(&name)
                ))
            })
    }
}

/// The input the CLI reads lines from: stdin for one command, the terminal in a session (stdin carries the commands).
pub struct Cx {
    pub sdk: Arc<Sdk>,
    /// the SDK's events since the start: an operation's send result arrives here, never as `submit`'s error
    events: Arc<scaas_sdk::Subscription>,
    pub g: Globals,
    app: Option<Arc<scaas_sdk::app_core::AppCore>>,
    session: bool,
    stdin: std::io::StdinLock<'static>,
    fds: Vec<(String, String)>,
    /// descriptors opened by number, so two secrets on one descriptor are read in turn
    open_fds: HashMap<String, std::io::BufReader<std::fs::File>>,
}

impl Cx {
    /// The app core of `--app <file>` (an `AppDesc` as JSON).
    pub fn app(&mut self) -> Result<Arc<scaas_sdk::app_core::AppCore>, Fail> {
        if let Some(a) = &self.app {
            return Ok(a.clone());
        }
        let file = self
            .g
            .app
            .clone()
            .ok_or_else(|| Fail::cli("AppMissing", "--app <file>"))?;
        let desc: scaas_sdk::app_core::AppDesc =
            serde_json::from_str(&config::read_bounded(&file)?)?;
        let a = scaas_sdk::app_core::AppCore::new(self.sdk.clone(), desc)?;
        self.app = Some(a.clone());
        Ok(a)
    }

    /// Secret `name` (`--<name>-fd N`, else the terminal without echo); never argv, never the environment.
    pub fn secret(&mut self, name: &str) -> Result<Arc<SecretBytes>, Fail> {
        let fd = self
            .fds
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, fd)| fd.clone())
            .or_else(|| {
                (name == "passphrase")
                    .then(|| self.g.passphrase_fd.clone())
                    .flatten()
            });
        let mut line = Zeroizing::new(String::new());
        match fd {
            Some(fd) if fd == "0" && !self.session => {
                read_line(&mut self.stdin, &mut line)?;
            }
            Some(fd) => {
                if fd.is_empty() || !fd.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Fail::cli(
                        "Argument",
                        format!("--{name}-fd takes a descriptor number"),
                    ));
                }
                if !self.open_fds.contains_key(&fd) {
                    let f = std::fs::File::open(format!("/dev/fd/{fd}"))
                        .map_err(|_| Fail::cli("SecretUnreadable", format!("descriptor {fd}")))?;
                    self.open_fds.insert(fd.clone(), std::io::BufReader::new(f));
                }
                if let Some(r) = self.open_fds.get_mut(&fd) {
                    read_line(r, &mut line)?;
                }
            }
            None => {
                let p = rpassword::prompt_password(format!("{name}: ")).map_err(|_| {
                    Fail::cli(
                        "NoTerminal",
                        format!("no terminal for {name}; give --{name}-fd"),
                    )
                })?;
                line = Zeroizing::new(p);
            }
        }
        let text = line.trim_end_matches(['\n', '\r']);
        // a key or a signature is bytes, written `0x` + hex on its line; a passphrase or words are the line's text
        let bytes = if BINARY_SECRETS.contains(&name) {
            Zeroizing::new(
                flex::hex(text).map_err(|_| Fail::cli("Argument", format!("{name}: 0x + hex")))?,
            )
        } else {
            Zeroizing::new(text.as_bytes().to_vec())
        };
        Ok(Arc::new(
            SecretBytes::from_zeroizing(bytes).map_err(|e| Fail::Sdk(SdkError::Ua(e)))?,
        ))
    }

    /// One line from the user: stdin for one command, the terminal in a session.
    fn answer(&mut self) -> Result<String, Fail> {
        let mut s = String::new();
        if self.session {
            let tty = std::fs::File::open("/dev/tty")
                .map_err(|_| Fail::cli("NoTerminal", "no terminal to confirm on; give --yes"))?;
            std::io::BufReader::new(tty)
                .read_line(&mut s)
                .map_err(|_| Fail::cli("NoTerminal", "the terminal"))?;
        } else {
            self.stdin
                .read_line(&mut s)
                .map_err(|_| Fail::cli("NoTerminal", "stdin"))?;
        }
        Ok(s.trim().to_string())
    }

    /// The one reveal of a seed's words (CLI-SDK-04): the typed word `reveal`, never answered by `--yes`; no answer (no
    /// terminal in a session) keeps them hidden.
    pub fn typed_reveal(&mut self) -> bool {
        eprint!("type `reveal` to show the words once, anything else to keep them hidden: ");
        self.answer().is_ok_and(|a| a == "reveal")
    }

    /// Prints what is about to be signed or sent and asks; `--yes` answers for a script.
    pub fn confirm(&mut self, what: Value) -> Result<(), Fail> {
        print_out(&self.g, &what)?;
        if self.g.yes {
            return Ok(());
        }
        eprint!("confirm? [y/N] ");
        let a = self.answer()?;
        if a == "y" || a == "yes" {
            Ok(())
        } else {
            Err(Fail::cli("NotConfirmed", "nothing was signed or sent"))
        }
    }

    /// `{"op": id, "state": …}` once the SDK reports the send of `op` (CLI-SDK-18: in flight until a chain fact); the process
    /// waits for it, at most [`SEND_WAIT_MS`], so an exit never cuts a send short (a row not yet sent is sent again by `op
    /// resume` or the next start).
    pub async fn sent(&self, op: String) -> Out {
        let end = std::time::Instant::now() + std::time::Duration::from_millis(SEND_WAIT_MS);
        while let Some(left) = end.checked_duration_since(std::time::Instant::now()) {
            match self.events.next(left.as_millis() as u64).await {
                Some(scaas_sdk::Event::OpState { op: o, state }) if o == op => {
                    return Out::Json(json!({"op": op, "state": state}))
                }
                Some(_) => continue,
                None => break,
            }
        }
        Out::Json(
            json!({"op": op, "state": "not reported yet: `op state` follows it, `op resume` sends a row not sent"}),
        )
    }

    /// The review of `p` and `quote`, confirmed.
    pub fn confirm_op(&mut self, p: &Prepared, quote: &SubmitQuote) -> Result<(), Fail> {
        self.confirm(json!({"review": review(&p.review()), "quote": quote, "prepared": p.id(), "chain": p.chain(), "entry": p.entry()}))
    }

    /// `--path` (a `SubmitPath`; default `Auto` without a payer).
    fn path(&self) -> Result<SubmitPath, Fail> {
        match &self.g.path {
            None => Ok(SubmitPath::Auto { payer: None }),
            Some(p) => {
                let v = if p.starts_with('{') {
                    serde_json::from_str(p)?
                } else {
                    Value::String(p.clone())
                };
                Ok(serde::Deserialize::deserialize(flex::Flex(v))?)
            }
        }
    }
}

fn read_line(r: &mut impl BufRead, line: &mut Zeroizing<String>) -> Result<(), Fail> {
    let mut buf = Zeroizing::new(Vec::with_capacity(SECRET_MAX));
    let n = std::io::Read::take(&mut *r, SECRET_MAX as u64 + 1)
        .read_until(b'\n', &mut buf)
        .map_err(|_| Fail::cli("SecretUnreadable", "the descriptor"))?;
    if n == 0 || n > SECRET_MAX {
        return Err(Fail::cli(
            "SecretUnreadable",
            "an empty or oversized secret line",
        ));
    }
    let s = std::str::from_utf8(&buf).map_err(|_| Fail::cli("SecretUnreadable", "not UTF-8"))?;
    line.push_str(s);
    Ok(())
}

/// The review as named rows.
pub fn review(r: &[ReviewField]) -> Value {
    serde_json::to_value(r).unwrap_or(Value::Null)
}

/// Into the output's JSON (`Argument` if the value cannot be written, which no SDK type does).
pub fn js<T: serde::Serialize>(v: T) -> Out {
    Out::Json(serde_json::to_value(v).unwrap_or(Value::Null))
}

/// A named result: `{name: value}`.
pub fn named<T: serde::Serialize>(name: &str, v: T) -> Out {
    Out::Json(json!({ name: v }))
}

/// Bytes as `0x` hex under a name.
pub fn hexed(name: &str, b: &[u8]) -> Out {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Out::Json(json!({ name: format!("0x{h}") }))
}

fn out_json(o: Out) -> Value {
    match o {
        Out::Json(v) => v,
        _ => Value::Null,
    }
}

/// An object kept by name, with what may be shown of it.
pub fn handle<T: Send + Sync + 'static>(v: T, shown: Value) -> Out {
    Out::Handle(Arc::new(v), shown)
}

/// Escapes what a terminal could act on: anything outside printable ASCII is drawn as `\u{…}`.
fn plain(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == ' ' || c.is_ascii_graphic() {
                c.to_string()
            } else {
                format!("\\u{{{:x}}}", c as u32)
            }
        })
        .collect()
}

fn table(prefix: &str, v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => m.iter().for_each(|(k, x)| table(&join(prefix, k), x, out)),
        Value::Array(a) => a
            .iter()
            .enumerate()
            .for_each(|(i, x)| table(&join(prefix, &i.to_string()), x, out)),
        Value::String(s) => out.push_str(&format!("{}: {}\n", plain(prefix), plain(s))),
        x => out.push_str(&format!("{}: {x}\n", plain(prefix))),
    }
}

fn join(a: &str, b: &str) -> String {
    if a.is_empty() {
        b.to_string()
    } else {
        format!("{a}.{b}")
    }
}

/// One output: JSON on one line or a table of named rows, at most [`OUTPUT_MAX`].
fn print_out(g: &Globals, v: &Value) -> Result<(), Fail> {
    let text = if g.json {
        let mut t = serde_json::to_string(v).map_err(|_| Fail::cli("Internal", "output"))?;
        t.push('\n');
        t
    } else {
        let mut t = String::new();
        table("", v, &mut t);
        t
    };
    if text.len() > OUTPUT_MAX {
        return Err(Fail::cli("OutputTooLarge", format!("{} bytes", text.len())));
    }
    let mut o = std::io::stdout().lock();
    o.write_all(text.as_bytes())
        .and_then(|()| o.flush())
        .map_err(|_| Fail::cli("Internal", "stdout"))
}

/// An SDK call's warnings, before its review.
pub fn print_warnings(cx: &Cx, w: &[String]) -> Result<(), Fail> {
    print_out(&cx.g, &json!({ "warnings": w }))
}

/// What may be shown of a prepared operation.
fn shown_prepared(p: &Prepared) -> Value {
    json!({"id": p.id(), "chain": p.chain(), "entry": p.entry(), "expires_at": p.expires_at()})
}

/// One command's result: an operation runs to its end (review, quote, confirm, submit); a session keeps objects by name.
async fn finish(cx: &mut Cx, call: &str, out: Out) -> Result<Value, Fail> {
    let name = cx.g.name.clone();
    match (out, cx.session) {
        (Out::Json(v), _) => Ok(v),
        (Out::Prepared(p), false) => {
            let quote = cx.sdk.op().quote(p.clone(), cx.path()?).await?;
            cx.confirm_op(&p, &quote)?;
            let op = cx.sdk.op().submit(p, quote).await?;
            Ok(out_json(cx.sent(op).await))
        }
        (Out::Writes(ws), false) => {
            let mut ops = vec![];
            for w in ws {
                let quote = cx.sdk.account().quote_registry_write(w.clone()).await?;
                cx.confirm(json!({"review": review(&w.review()), "quote": quote, "write": w.id(), "chain": w.chain(), "entry": w.entry(), "ua": w.ua()}))?;
                let op = cx.sdk.account().submit_registry_write(w, quote).await?;
                ops.push(out_json(cx.sent(op).await));
            }
            Ok(json!({"ops": ops}))
        }
        (Out::Order(o), false) => {
            cx.confirm(
                json!({"review": review(&o.review()), "order": o.id(), "chain": o.chain()}),
            )?;
            Ok(json!({"placed": cx.sdk.dex().place(o).await?}))
        }
        (Out::Native(q), false) => {
            cx.confirm(json!({"quote": q}))?;
            Ok(json!({"tx": cx.sdk.wallet().submit_native_send(*q).await?}))
        }
        (Out::Seed(s), session) => {
            let info = serde_json::to_value(&s.info).unwrap_or(Value::Null);
            print_out(&cx.g, &json!({"seed": info}))?;
            if cx.typed_reveal() {
                let words = s.backup.reveal()?;
                let mut o = std::io::stdout().lock();
                let r = words.with(|w| {
                    o.write_all(if cx.g.json {
                        b"{\"words\":\""
                    } else {
                        b"words: "
                    })
                    .and_then(|()| o.write_all(w))
                    .and_then(|()| o.write_all(if cx.g.json { b"\"}\n" } else { b"\n" }))
                    .and_then(|()| o.flush())
                });
                r.map_err(|_| Fail::cli("Internal", "stdout"))?;
            }
            if session {
                keep(name.as_deref().unwrap_or(call), s.backup.clone());
            }
            Ok(
                json!({"backup": if session { name.unwrap_or_else(|| call.to_string()) } else { "closed".into() }}),
            )
        }
        (Out::Prepared(p), true) => {
            let n = name.unwrap_or_else(|| call.to_string());
            let shown = shown_prepared(&p);
            keep(&n, p);
            Ok(json!({"handle": n, "prepared": shown}))
        }
        (Out::Writes(ws), true) => {
            let n = name.unwrap_or_else(|| call.to_string());
            let shown: Vec<Value> = ws
                .iter()
                .map(
                    |w| json!({"id": w.id(), "chain": w.chain(), "entry": w.entry(), "ua": w.ua()}),
                )
                .collect();
            for (i, w) in ws.iter().enumerate() {
                keep(&format!("{n}.{i}"), w.clone());
            }
            keep(&n, Arc::new(ws));
            Ok(json!({"handle": n, "writes": shown}))
        }
        (Out::Order(o), true) => {
            let n = name.unwrap_or_else(|| call.to_string());
            let shown = json!({"id": o.id(), "chain": o.chain()});
            keep(&n, o);
            Ok(json!({"handle": n, "order": shown}))
        }
        (Out::Native(q), true) => {
            let n = name.unwrap_or_else(|| call.to_string());
            let shown = serde_json::to_value(&q).unwrap_or(Value::Null);
            keep(&n, Arc::new(*q));
            Ok(json!({"handle": n, "quote": shown}))
        }
        (Out::Handle(h, shown), true) => {
            let n = name.unwrap_or_else(|| call.to_string());
            keep(&n, h);
            Ok(json!({"handle": n, "value": shown}))
        }
        (Out::Handle(_, shown), false) => Ok(
            json!({"value": shown, "note": "an object lives in one process: use `scaas session` to pass it on"}),
        ),
    }
}

/// Runs one command (`<group> <call> --flags…`).
async fn run_one(cx: &mut Cx, words: &[String]) -> Result<Value, Fail> {
    let (group, rest) = words
        .split_first()
        .ok_or_else(|| Fail::cli("UnknownCommand", "no command"))?;
    let (call, flags) = rest
        .split_first()
        .ok_or_else(|| Fail::cli("UnknownCommand", group.as_str()))?;
    let cmd = format!("{group} {call}");
    let (map, fds) = flex::flags(flags)?;
    cx.fds = fds;
    let out = calls::dispatch(cx, &cmd, map).await?;
    let v = finish(cx, call, out).await?;
    cx.fds.clear();
    Ok(v)
}

/// The options before the command, and the rest.
fn globals(args: &[String]) -> Result<(Globals, Vec<String>), Fail> {
    let mut g = Globals::default();
    let mut i = 0;
    while let Some(a) = args.get(i) {
        let Some(opt) = a.strip_prefix("--") else {
            break;
        };
        let mut val = || {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| Fail::cli("Argument", format!("--{opt} takes a value")))
        };
        match opt {
            "data-dir" => g.data_dir = Some(val()?),
            "profiles" => g.profiles = Some(val()?),
            "overlay" => g.overlay = Some(val()?),
            "unlock" => g.unlock.push(val()?),
            "passphrase-fd" => g.passphrase_fd = Some(val()?),
            "app" => g.app = Some(val()?),
            "path" => g.path = Some(val()?),
            "as" => g.name = Some(val()?),
            "json" => g.json = true,
            "yes" => g.yes = true,
            _ => return Err(Fail::cli("UnknownFlag", format!("--{opt}"))),
        }
        i += 1;
    }
    Ok((g, args.get(i..).unwrap_or_default().to_vec()))
}

/// `scaas commands`: every command, its SDK call and its flags.
fn commands() -> Value {
    let list: Vec<Value> = calls::CALLS
        .iter()
        .map(|(cli, sdk)| json!({"command": cli, "sdk": sdk, "flags": calls::describe(cli).unwrap_or_default(), "secret_fds": calls::secrets(cli)}))
        .collect();
    json!({"commands": list, "excluded": calls::EXCLUDED.iter().map(|(s, why)| json!({"sdk": s, "why": why})).collect::<Vec<_>>()})
}

async fn main_inner(args: Vec<String>) -> Result<(), Fail> {
    let (g, rest) = globals(&args)?;
    config::banner(&g);
    if rest.first().map(String::as_str) == Some("commands") {
        return print_out(&g, &commands());
    }
    let session = rest.first().map(String::as_str) == Some("session");
    let sdk = config::open(&g).await?;
    let events = sdk.subscribe();
    let mut cx = Cx {
        sdk,
        events,
        g,
        app: None,
        session,
        stdin: std::io::stdin().lock(),
        fds: vec![],
        open_fds: HashMap::new(),
    };
    for seed in cx.g.unlock.clone() {
        let p = cx.secret("passphrase")?;
        cx.sdk
            .vault()
            .unlock(seed, scaas_sdk::vault::Unlock::Passphrase(p))
            .await?;
    }
    if !session {
        let v = run_one(&mut cx, &rest).await?;
        return print_out(&cx.g, &v);
    }
    let mut line = String::new();
    loop {
        line.clear();
        let n = cx
            .stdin
            .read_line(&mut line)
            .map_err(|_| Fail::cli("Internal", "stdin"))?;
        if n == 0 {
            return Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }
        let words: Vec<String> = serde_json::from_str(&line)?;
        // `--as <name>` before the command names what it returns
        let (name, words) = match words.split_first() {
            Some((a, r)) if a == "--as" => match r.split_first() {
                Some((n, r)) => (Some(n.clone()), r.to_vec()),
                None => return Err(Fail::cli("Argument", "--as takes a name")),
            },
            _ => (None, words),
        };
        cx.g.name = name;
        let v = run_one(&mut cx, &words).await?;
        print_out(&cx.g, &v)?;
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args
        .iter()
        .take_while(|a| a.starts_with("--"))
        .any(|a| a == "--json");
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => std::process::exit(70),
    };
    if let Err(f) = rt.block_on(main_inner(args)) {
        let detail = match &f {
            Fail::Cli(_, d) => plain(d),
            Fail::Sdk(_) => String::new(),
        };
        if json {
            eprintln!("{}", json!({"error": f.code(), "detail": detail}));
        } else {
            eprintln!("error: {} {}", f.code(), detail);
        }
        std::process::exit(
            if matches!(f, Fail::Cli("UnknownCommand" | "UnknownFlag", _)) {
                2
            } else {
                1
            },
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn output_bounded() {
        let g = Globals {
            json: true,
            ..Globals::default()
        };
        assert!(print_out(&g, &json!({"x": 1})).is_ok());
        let big = json!({ "x": "a".repeat(OUTPUT_MAX) });
        assert!(matches!(
            print_out(&g, &big),
            Err(Fail::Cli("OutputTooLarge", _))
        ));
    }

    #[test]
    fn table_escapes_what_a_terminal_acts_on() {
        assert_eq!(plain("ab c-1"), "ab c-1");
        assert_eq!(plain("a\u{202e}b\x1b[2J"), "a\\u{202e}b\\u{1b}[2J");
    }

    #[test]
    fn secret_line_bounded() {
        let mut l = Zeroizing::new(String::new());
        assert!(read_line(&mut "pass\n".as_bytes(), &mut l).is_ok());
        assert_eq!(l.as_str(), "pass\n");
        let long = format!("{}\n", "a".repeat(SECRET_MAX));
        assert!(read_line(&mut long.as_bytes(), &mut Zeroizing::new(String::new())).is_err());
        assert!(read_line(&mut "".as_bytes(), &mut Zeroizing::new(String::new())).is_err());
    }
}
