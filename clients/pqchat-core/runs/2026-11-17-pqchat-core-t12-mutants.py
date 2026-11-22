# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T12's mutants (owner 2026-11-22, "Handle SecretBytes"): each killed by its own check, the bindings check
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
API = "clients/pqchat-core/ffi/src/api/mod.rs"
BIND = "bash clients/pqchat-core/runs/2026-11-17-pqchat-core-bind.sh"
TPQ = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test message "
REACTION = "/// A reaction value on a message and how many UAs gave it.\n"
MUTANTS = [
    ("bind: a String content accessor on Message",
     [(ORD, REACTION, "impl Message {\n    pub fn text(&self) -> String {\n"
       "        self.content.with(|b| String::from_utf8_lossy(b).into_owned())\n    }\n}\n\n" + REACTION)],
     BIND, "Message has a member that is no field"),
    ("bind: Content::value in the surface",
     [(CON, "    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]\n    pub fn value(", "    pub fn value(")],
     BIND, "decrypted content through the codec (Content_value)"),
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
]

if __name__ == "__main__":
    main("t12", MUTANTS)
