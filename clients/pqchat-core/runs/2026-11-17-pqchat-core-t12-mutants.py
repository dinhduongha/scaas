# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T12's mutants (owner 2026-11-22, "Handle SecretBytes"; 2026-11-23, send takes the content JSON as a
handle): each killed by its own check, the bindings check
(runs/2026-11-17-pqchat-core-bind.sh, its TAP `not ok` line) or the crate's named test:
python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-t12-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

ORD = "clients/pqchat-core/src/order.rs"
CON = "clients/pqchat-core/src/content.rs"
CSN = "clients/pqchat-core/src/consent.rs"
LIB = "clients/pqchat-core/ffi/src/lib.rs"
STO = "clients/pqchat-core/src/stores.rs"
API = "clients/pqchat-core/ffi/src/api/mod.rs"
BIND = "bash clients/pqchat-core/runs/2026-11-17-pqchat-core-bind.sh"
TPQ = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test message "
TST = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test stores "
SEND = "    /// [`PqChat::send`] of a content built in Rust (Rust-only: the bindings send only a handle).\n"
REACTION = "/// A reaction value on a message and how many UAs gave it.\n"
MUTANTS = [
    ("bind: a String content accessor on Message",
     [(ORD, REACTION, "impl Message {\n    pub fn text(&self) -> String {\n"
       "        self.content.with(|b| String::from_utf8_lossy(b).into_owned())\n    }\n}\n\n" + REACTION)],
     BIND, "Message has a member that is no field"),
    # (owner 2026-11-23: `Content` is Rust-only and FRB emits a type only through a call that takes it, so neither dropping
    # `value`'s ignore nor the enum's reaches the surface (both survived at 2958d6c5b); a call of a `Content` does)
    ("bind: PqChat::seal of a Content in the surface",
     [("clients/pqchat-core/src/message.rs",
       "    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]\n    pub async fn seal(", "    pub async fn seal(")],
     BIND, "PqChat.seal is not a send entry"),
    ("bind: the session's name back in Preview",
     [(CSN, "    pub info: Arc<scaas_sdk::SecretBytes>,\n",
       "    pub info: Arc<scaas_sdk::SecretBytes>,\n    pub name: String,\n"),
      (CSN, "            info: handle,\n", "            name: info.name.clone(),\n            info: handle,\n")],
     BIND, "Preview's members"),
    ("bind: the handle's id for the copy calls gone",
     [(API, "#[frb(sync)]\npub fn secret_id(s: &Arc<SecretBytes>) -> u64 {", "pub(crate) fn secret_id(s: &Arc<SecretBytes>) -> u64 {")],
     BIND, "no secretId of the handle in the surface"),
    ("bind: the read copy call not exported",
     [(LIB, "#[no_mangle]\npub unsafe extern \"C\" fn scaas_sdk_secret_read(",
       "#[allow(dead_code)]\nunsafe extern \"C\" fn scaas_sdk_secret_read(")],
     BIND, "copy call scaas_sdk_secret_read not exported"),
    ("crate: a reaction counted per react, not per UA",
     [(ORD, "e.0.insert(a.sender.as_str());", "e.0.insert(a.id.as_str());")],
     TPQ + "content_leaves_only_as_handles"),
    ("crate: the newest edit's content not shown",
     [(ORD, "content: Arc::clone(edit.copied().unwrap_or(&m.content)),", "content: Arc::clone(&m.content),")],
     TPQ + "content_leaves_only_as_handles"),
    ("bind: a plain String send entry added back",
     [(STO, SEND, "    pub async fn send_text(\n        &self,\n        s: &SessionRef,\n        me: &Me,\n        body: String,\n"
       "        o: &SendOpts,\n    ) -> Result<SendReport, PqChatError> {\n        let c = Content::Text {\n"
       "            media_type: None,\n            body,\n        };\n        self.send_content(s, me, &c, None, o).await\n"
       "    }\n\n" + SEND)],
     BIND, "PqChat.sendText is not a send entry"),
    ("bind: send takes the content JSON as a String",
     [(STO, "        content: Arc<SecretBytes>,\n        ts: Option<u64>,\n        o: &SendOpts,\n    ) -> Result<SendReport, PqChatError> {\n"
       "        let c = content.with(Content::from_json)?;\n",
       "        content: String,\n        ts: Option<u64>,\n        o: &SendOpts,\n    ) -> Result<SendReport, PqChatError> {\n"
       "        let c = Content::from_json(content.as_bytes())?;\n")],
     BIND, "PqChat.send's parameters"),
    ("bind: the Rust-only send of a Content in the surface",
     [(STO, SEND + "    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]\n    pub async fn send_content(", SEND + "    pub async fn send_content(")],
     BIND, "PqChat.sendContent is not a send entry"),
    ("bind: no new handle in the surface",
     [(API, "#[frb(sync)]\npub fn secret_new(", "pub(crate) fn secret_new(")],
     BIND, "no secretNew in the surface"),
    ("crate: send parses the handle without the content rules",
     [(STO, "        let c = content.with(Content::from_json)?;\n", "        let c = content.with(Content::parse).content;\n")],
     TST + "send_takes_the_content_json_as_a_handle"),
    ("crate: from_json takes a content that is not exactly its form",
     [(CON, "        if c.value(None)? != v {\n", "        if c.value(None).is_err() {\n")],
     TST + "send_takes_the_content_json_as_a_handle"),
    ("crate: from_json without the body bound's own error",
     [(CON, "        if long {\n            return Err(PqChatError::ContentTooLarge);\n", "        if long {\n            return Err(PqChatError::ContentInvalid);\n")],
     TST + "send_takes_the_content_json_as_a_handle"),
    ("crate: a file content sent as a plain content (no key entered)",
     [(STO, "            Body::Content(Content::File { .. }) => return Err(PqChatError::ContentInvalid),\n", "")],
     TST + "send_takes_the_content_json_as_a_handle"),
]

if __name__ == "__main__":
    main("t12", MUTANTS)
