// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The e2e's homeserver and Matrix client (plan T11, spec §13 O10 (a)): one Synapse in Docker (`--memory 1g --cpus 1`, a
//! data directory made at run time, removed with the container by `Drop`), users registered through its shared-secret admin
//! API (Synapse's own `register_new_matrix_user`), and a test-only [`MatrixTransport`] over the client-server HTTP API with
//! `reqwest` (matrix-rust-sdk is not in the offline cargo cache; controller call, T11). The [`Witness`] reads what the server
//! holds: receipts, read markers, membership, encryption and events from its database, typing and presence requests from
//! its access log.
use async_trait::async_trait;
use pqchat_core::matrix::{HistoryPage, MatrixTransport, RoomEvent, Seen, Witness, EVENT_TYPE};
use pqchat_core::PqChatError;
use serde_json::{json, Value};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// The image, pinned by version (pulled once if absent; never the testnet stack).
pub const IMAGE: &str = "matrixdotorg/synapse:v1.165.0";
const PASSWORD: &str = "e2e-password-not-a-secret";

fn docker(args: &[&str]) -> std::process::Output {
    Command::new("docker")
        .args(args)
        .output()
        .expect("docker in PATH")
}

fn ok(args: &[&str]) -> String {
    let o = docker(args);
    assert!(
        o.status.success(),
        "docker {:?}: {}",
        &args[..2.min(args.len())],
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// A running Synapse: its container, data directory and client-server base URL.
pub struct Synapse {
    pub name: String,
    dir: std::path::PathBuf,
    pub base: String,
}

impl Drop for Synapse {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", &self.name]);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn id_of() -> (String, String) {
    let id = |f: &str| {
        String::from_utf8(Command::new("id").arg(f).output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string()
    };
    (id("-u"), id("-g"))
}

impl Synapse {
    /// The container started (no rate limits, so a test's sends are not throttled) and answering.
    pub async fn start() -> Synapse {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .unwrap()
            .port();
        let dir =
            std::env::temp_dir().join(format!("pqchat-e2e-synapse-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (uid, gid) = id_of();
        let vol = format!("{}:/data", dir.display());
        let (u, g) = (format!("UID={uid}"), format!("GID={gid}"));
        ok(&[
            "run",
            "--rm",
            "--memory",
            "1g",
            "--cpus",
            "1",
            "-e",
            "SYNAPSE_SERVER_NAME=localhost",
            "-e",
            "SYNAPSE_REPORT_STATS=no",
            "-e",
            &u,
            "-e",
            &g,
            "-v",
            &vol,
            IMAGE,
            "generate",
        ]);
        let conf = dir.join("homeserver.yaml");
        let mut y = std::fs::read_to_string(&conf).unwrap();
        // the generated file ends without a newline; no key server (the run makes no federation request)
        y.push_str("\ntrusted_key_servers: []\n");
        for k in [
            "rc_message",
            "rc_registration",
            "rc_joins",
            "rc_invites",
            "rc_admin_redaction",
            "rc_room_creation",
        ] {
            y.push_str(&format!(
                "{k}:\n  per_second: 10000\n  burst_count: 100000\n"
            ));
        }
        y.push_str("rc_login:\n  address:\n    per_second: 10000\n    burst_count: 100000\n  account:\n    per_second: 10000\n    burst_count: 100000\n");
        std::fs::write(&conf, y).unwrap();
        let name = format!("pqchat-e2e-synapse-{}-{port}", std::process::id());
        let p = format!("127.0.0.1:{port}:8008");
        ok(&[
            "run", "-d", "--name", &name, "--memory", "1g", "--cpus", "1", "-e", &u, "-e", &g,
            "-v", &vol, "-p", &p, IMAGE,
        ]);
        let s = Synapse {
            name,
            dir,
            base: format!("http://127.0.0.1:{port}"),
        };
        let c = reqwest::Client::new();
        for _ in 0..600 {
            if let Ok(r) = c.get(format!("{}/health", s.base)).send().await {
                if r.status().is_success() {
                    println!("[matrix] {IMAGE} up as {} on 127.0.0.1:{port}", s.name);
                    return s;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("synapse never answered");
    }

    /// `user` registered through the shared-secret admin API.
    pub fn register(&self, user: &str, admin: bool) {
        let a = if admin { "--admin" } else { "--no-admin" };
        ok(&[
            "exec",
            &self.name,
            "register_new_matrix_user",
            "-u",
            user,
            "-p",
            PASSWORD,
            a,
            "-c",
            "/data/homeserver.yaml",
            "http://localhost:8008",
        ]);
    }

    /// `user` logged in once: its client.
    pub async fn login(&self, user: &str) -> Http {
        let c = reqwest::Client::new();
        let v: Value = c
            .post(format!("{}/_matrix/client/v3/login", self.base))
            .json(&json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": user},
                "password": PASSWORD}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        Http {
            base: reqwest::Url::parse(&self.base).unwrap(),
            token: v["access_token"].as_str().expect("a token").into(),
            user: v["user_id"].as_str().unwrap().into(),
            c,
            txn: AtomicU64::new(0),
            calls: Mutex::new(vec![]),
            last: Mutex::new(None),
        }
    }

    fn sql(&self, q: &str, args: &[&str]) -> u64 {
        let py = "import sqlite3,sys; c=sqlite3.connect('/data/homeserver.db'); print(c.execute(sys.argv[1], sys.argv[2:]).fetchone()[0])";
        let mut a = vec!["exec", &self.name, "python3", "-c", py, q];
        a.extend_from_slice(args);
        ok(&a).parse().unwrap()
    }

    /// The access log's request lines of `user` (its `{user}` field) whose path holds `part`.
    fn requests(&self, user: &str, part: &str) -> u64 {
        let o = docker(&["logs", &self.name]);
        let all = [o.stdout, o.stderr].concat();
        let tag = format!("{{{user}}}");
        String::from_utf8_lossy(&all)
            .lines()
            .filter(|l| l.contains(&tag) && l.contains(part))
            .count() as u64
    }

    /// What the server holds of `user` in `room`.
    pub fn seen_of(&self, room: &str, user: &str) -> Seen {
        let room_enc = room.replace('!', "%21").replace(':', "%3A");
        Seen {
            receipts: self.sql("select count(*) from receipts_linearized where room_id=? and user_id=?", &[room, user]),
            read_markers: self.sql(
                "select count(*) from room_account_data where room_id=? and user_id=? and account_data_type='m.fully_read'",
                &[room, user],
            ),
            typing: self.requests(user, &format!("{room_enc}/typing/")) + self.requests(user, &format!("{room}/typing/")),
            presence: self.requests(user, "/presence/") + self.requests(user, "/sync"),
            joined: self.sql(
                "select count(*) from local_current_membership where room_id=? and user_id=? and membership='join'",
                &[room, user],
            ) == 1,
            encrypted: self.sql(
                "select count(*) from current_state_events where room_id=? and type='m.room.encryption'",
                &[room],
            ) > 0,
            events: self.sql("select count(*) from events where room_id=? and type=?", &[room, EVENT_TYPE]),
        }
    }
}

/// The server's side of the conformance test: what it holds, and another account (`other`) that invites and posts.
pub struct SynapseWitness<'a> {
    pub s: &'a Synapse,
    pub other: Http,
}

#[async_trait]
impl Witness for SynapseWitness<'_> {
    async fn seen(&self, room: &str, user: &str) -> Result<Seen, PqChatError> {
        Ok(self.s.seen_of(room, user))
    }
    async fn invite_me(&self, user: &str) -> Result<String, PqChatError> {
        let room = self.other.create_room().await?;
        self.other.invite(&room, user).await?;
        Ok(room)
    }
    async fn post(&self, room: &str, content: Value) -> Result<(), PqChatError> {
        self.other.send_event(room, content).await
    }
}

/// One account's client over the client-server API: every call recorded by name (`join` with its room), so a test asserts
/// which calls a step made.
pub struct Http {
    base: reqwest::Url,
    token: String,
    pub user: String,
    c: reqwest::Client,
    txn: AtomicU64,
    pub calls: Mutex<Vec<String>>,
    /// the code of the last refused request (a test reads why)
    pub last: Mutex<Option<u16>>,
}

fn e<T>(_: T) -> PqChatError {
    PqChatError::MatrixRoom
}

impl Http {
    fn url(&self, segs: &[&str]) -> reqwest::Url {
        let mut u = self.base.clone();
        u.path_segments_mut()
            .unwrap()
            .extend(["_matrix", "client", "v3"])
            .extend(segs);
        u
    }

    fn rec(&self, c: String) {
        self.calls.lock().unwrap().push(c);
    }

    pub fn calls_of(&self, name: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.split(' ').next() == Some(name))
            .count()
    }

    async fn go(&self, r: reqwest::RequestBuilder) -> Result<Value, PqChatError> {
        let r = r.bearer_auth(&self.token).send().await.map_err(e)?;
        let st = r.status();
        if !st.is_success() {
            *self.last.lock().unwrap() = Some(st.as_u16());
            return Err(PqChatError::MatrixRoom);
        }
        r.json().await.map_err(e)
    }
}

impl Http {
    /// The witness's positive control: a typing notice, a read receipt and a read marker of this account in `room`, on
    /// its newest event (what the transport under test never sends).
    pub async fn signals(&self, room: &str) {
        let h = self
            .go(self
                .c
                .get(self.url(&["rooms", room, "messages"]))
                .query(&[("dir", "b"), ("limit", "1")]))
            .await
            .unwrap();
        let ev = h["chunk"][0]["event_id"].as_str().unwrap().to_string();
        let user = self.user.clone();
        self.go(self
            .c
            .put(self.url(&["rooms", room, "typing", &user]))
            .json(&json!({"typing": true, "timeout": 30000})))
            .await
            .unwrap();
        self.go(self
            .c
            .post(self.url(&["rooms", room, "receipt", "m.read", &ev]))
            .json(&json!({})))
            .await
            .unwrap();
        self.go(self
            .c
            .post(self.url(&["rooms", room, "read_markers"]))
            .json(&json!({ "m.fully_read": ev })))
            .await
            .unwrap();
    }
}

#[async_trait]
impl MatrixTransport for Http {
    fn user_id(&self) -> String {
        self.user.clone()
    }
    async fn create_room(&self) -> Result<String, PqChatError> {
        self.rec("create_room".into());
        let v = self
            .go(self
                .c
                .post(self.url(&["createRoom"]))
                .json(&json!({"preset": "private_chat"})))
            .await?;
        v["room_id"]
            .as_str()
            .map(String::from)
            .ok_or(PqChatError::MatrixRoom)
    }
    async fn joined(&self, room: &str) -> Result<bool, PqChatError> {
        let v = self.go(self.c.get(self.url(&["joined_rooms"]))).await?;
        Ok(v["joined_rooms"]
            .as_array()
            .is_some_and(|a| a.iter().any(|r| r == room)))
    }
    async fn members(&self, room: &str) -> Result<Vec<String>, PqChatError> {
        let v = self
            .go(self.c.get(self.url(&["rooms", room, "members"])))
            .await?;
        Ok(v["chunk"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| matches!(e["content"]["membership"].as_str(), Some("join" | "invite")))
            .filter_map(|e| e["state_key"].as_str().map(String::from))
            .collect())
    }
    async fn join(&self, room: &str) -> Result<(), PqChatError> {
        self.rec(format!("join {room}"));
        self.go(self.c.post(self.url(&["join", room])).json(&json!({})))
            .await
            .map(|_| ())
    }
    async fn invite(&self, room: &str, user: &str) -> Result<(), PqChatError> {
        self.rec("invite".into());
        self.go(self
            .c
            .post(self.url(&["rooms", room, "invite"]))
            .json(&json!({ "user_id": user })))
            .await
            .map(|_| ())
    }
    async fn remove(&self, room: &str, user: &str) -> Result<(), PqChatError> {
        self.rec("remove".into());
        self.go(self
            .c
            .post(self.url(&["rooms", room, "kick"]))
            .json(&json!({ "user_id": user })))
            .await
            .map(|_| ())
    }
    async fn set_admin(&self, room: &str, user: &str, admin: bool) -> Result<(), PqChatError> {
        self.rec("set_admin".into());
        let u = self.url(&["rooms", room, "state", "m.room.power_levels", ""]);
        let mut pl = self.go(self.c.get(u.clone())).await?;
        if admin {
            pl["users"][user] = json!(50);
        } else if let Some(m) = pl["users"].as_object_mut() {
            m.remove(user);
        }
        self.go(self.c.put(u).json(&pl)).await.map(|_| ())
    }
    async fn send_event(&self, room: &str, content: Value) -> Result<(), PqChatError> {
        self.rec("send_event".into());
        let t = format!(
            "pqc{}-{}",
            std::process::id(),
            self.txn.fetch_add(1, Ordering::SeqCst)
        );
        self.go(self
            .c
            .put(self.url(&["rooms", room, "send", EVENT_TYPE, &t]))
            .json(&content))
            .await
            .map(|_| ())
    }
    async fn history(
        &self,
        room: &str,
        before: Option<String>,
    ) -> Result<HistoryPage, PqChatError> {
        self.rec("history".into());
        let mut u = self.url(&["rooms", room, "messages"]);
        {
            let mut q = u.query_pairs_mut();
            q.append_pair("dir", "b")
                .append_pair("limit", "100")
                .append_pair("filter", &json!({ "types": [EVENT_TYPE] }).to_string());
            if let Some(b) = &before {
                q.append_pair("from", b);
            }
        }
        let v = self.go(self.c.get(u)).await?;
        let chunk = v["chunk"].as_array().cloned().unwrap_or_default();
        let mut events: Vec<RoomEvent> = chunk
            .iter()
            .filter(|x| x["type"] == EVENT_TYPE)
            .map(|x| RoomEvent {
                sender: x["sender"].as_str().unwrap_or_default().into(),
                content: serde_json::to_vec(&x["content"]).unwrap_or_default(),
            })
            .collect();
        events.reverse();
        let before = match (chunk.is_empty(), v["end"].as_str()) {
            (false, Some(t)) => Some(t.to_string()),
            _ => None,
        };
        Ok(HistoryPage { events, before })
    }
    async fn hold_invite(&self, room: &str, hold: bool) {
        // this client never answers an invite by itself: holding is recording
        self.rec(format!("hold_invite {room} {hold}"));
    }
}
