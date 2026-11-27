# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""CLI-SDK-36, CLI-PQC-18 (F3, F6, G5, G7), CLI-PQC-21 and NODE-GW-09 (branch pqchat-core-confirm): a mutant of each new check,
the scaas-sdk plan's `mutants_lib` with this crate's record: python3 clients/pqchat-core/runs/2026-11-28-pqchat-core-confirm-mutants.py
check | run [name...]. Each test command goes through scripts/capped, foreground (mutant_guard's deadline and restore)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scaas-sdk" / "runs"))
import mutants_lib as L  # noqa: E402

R = "clients/pqchat-core/runs"
L.OUT = Path(__file__).parent
L.PREFIX = "2026-11-28-pqchat-core-"
L.RUNS = R
L.NOT_CODE = [f":!{R}/*-mutants.txt", f":!{R}/2026-11-17-pqchat-core-summary.txt"]

CF = "clients/pqchat-core/src/confirm.rs"
SE = "clients/pqchat-core/src/session.rs"
TO = "clients/pqchat-core/src/topics.rs"
AC = "clients/scaas-sdk/src/app_core.rs"
GW = "scaas-node/src/gateway.rs"
CD = "cd clients/pqchat-core && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
SES = CD + "--test session "
TOP = CD + "--test topics "
SDK = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
       "--features app-core --test app_core ")
NODE = "cd scaas-node && CARGO_INCREMENTAL=0 ../scripts/capped cargo test --locked --offline -j2 --lib "

MUTANTS = [
    # CLI-SDK-36: nothing signed before the confirm, one signing call on it
    (
        "the confirm signs outside the port",
        [(CF, "        let s = self.net.sign(p.unsigned).await?;",
          "        let s = crate::net::sign_now(p.unsigned).await?;")],
        SES + "nothing_is_signed_before_the_confirm",
    ),
    (
        "a session's record signed when it is built",
        [(SE, "        let quote = self\n            .quote_unsigned(&then.at, then.item, args, &then.payer, &me.key)",
          "        let _ = self\n            .net\n            .sign(Unsigned::Record(self.app.prepare_pqchat_leave(me.key.clone(), PqChatLeave {\n"
          "                session_id: then.session_id.clone(), epoch_id: then.epoch_id.clone(), member: me.ua.clone(), nonce: 0,\n"
          "            }).await?))\n            .await;\n"
          "        let quote = self\n            .quote_unsigned(&then.at, then.item, args, &then.payer, &me.key)")],
        SES + "nothing_is_signed_before_the_confirm",
    ),
    (
        "a creation accepts its session before the review",
        [(SE, "        let k = self.app.pqchat_epoch_key(seed)?;\n        let w = self\n            .wrap_members(&r.chain, &k, &sid, &sid, &members)",
          "        self.set_consent(&SessionRef { chain: r.chain.clone(), home: r.home.to_ascii_lowercase(), session_id: sid.clone() },\n"
          "            crate::consent::Consent::Accepted, true)?;\n"
          "        let k = self.app.pqchat_epoch_key(seed)?;\n        let w = self\n            .wrap_members(&r.chain, &k, &sid, &sid, &members)")],
        SES + "nothing_is_signed_before_the_confirm",
    ),
    (
        "a topic record signed when it is built",
        [(TO, "        let quote = match path {\n            Path::Relayed => None,",
          "        let _ = self.net.sign(Unsigned::Record(self.app.prepare_pqchat_topic_vote(me.key.clone(), PqTopicVote {\n"
          "            entry_id: ZERO32.into(), voter: me.ua.clone(), value: 0, seq: 0 }).await?)).await;\n"
          "        let quote = match path {\n            Path::Relayed => None,")],
        TOP + "topic_writes_sign_after_confirm_relayed_by_default",
    ),
    # CLI-PQC-18 F3: relayed by default, no payer quote
    (
        "a relayed write dispatched as the payer's call",
        [(CF, "            Path::Relayed => Ok(Sent::Relayed {\n                queued: self\n                    .net\n"
              "                    .relay(&w.at.chain, &w.at.instance, w.item, w.args.clone())\n                    .await?,\n            }),",
          "            Path::Relayed => Err(PqChatError::RelayUnavailable),")],
        TOP + "topic_writes_sign_after_confirm_relayed_by_default",
    ),
    (
        "an int8 sent as a string to the gateway",
        [(AC, "            *v = n.into();", "            let _ = n;")],
        SDK + "relay_app_call_posts_the_job_to_the_gateways",
    ),
    (
        "any kind relayed",
        [(AC, '        if !matches!(kind.as_str(), "pqchat" | "pqvault") {', "        if kind.is_empty() {")],
        SDK + "relay_app_call_posts_the_job_to_the_gateways",
    ),
    # NODE-GW-09
    (
        "door A takes every PqChat write",
        [(GW, '            .is_some_and(|e| PQCHAT_TOPIC_ENTRIES.contains(&e))', '            .is_some()')],
        NODE + "gateway::tests::door_a_takes_a_pqchat_topic_write",
    ),
    # CLI-PQV-18's rule in pqchat-core
    (
        "a higher fresh cost sent on the first confirm",
        [(CF, "if a <= b", "if a >= b")],
        TOP + "a_fresh_quote_within_the_review_needs_no_second_confirm",
    ),
    (
        "another payer sent on the first confirm",
        [(CF, "            && f.payer == r.payer\n", "")],
        TOP + "a_fresh_quote_within_the_review_needs_no_second_confirm",
    ),
    # F6: sorts, fold, rows, window
    (
        "Top's ties by the higher index",
        [(TO, "Rank::Top => rows.sort_by(|a, b| net(&b.1).cmp(&net(&a.1)).then(a.0.cmp(&b.0))),",
          "Rank::Top => rows.sort_by(|a, b| net(&b.1).cmp(&net(&a.1)).then(b.0.cmp(&a.0))),")],
        TOP + "window_sorts_are_deterministic",
    ),
    (
        "Controversial without its exponent",
        [(TO, "    l * (lo >> shift) / (hi >> shift)", "    l")],
        TOP + "window_sorts_are_deterministic",
    ),
    (
        "Best's bound plus instead of minus",
        [(TO, "    (p + z2 / (2.0 * n) - z * ((p", "    (p + z2 / (2.0 * n) + z * ((p")],
        TOP + "window_sorts_are_deterministic",
    ),
    (
        "the fold one vote late",
        [(TO, "folded: fold_at.is_some_and(|t| down >= up.saturating_add(u128::from(t))),",
          "folded: fold_at.is_some_and(|t| down > up.saturating_add(u128::from(t))),")],
        TOP + "entry_rows_fold_and_newest_pages",
    ),
    (
        "a short rows answer taken",
        [(TO, "            if rows.len() != chunk.len() {", "            if rows.len() > chunk.len() {")],
        TOP + "entry_rows_fold_and_newest_pages",
    ),
    (
        "the window from the list's start",
        [(TO, "            Rank::Top | Rank::Controversial => (snapshot.saturating_sub(WINDOW), snapshot),",
          "            Rank::Top | Rank::Controversial => (0, snapshot.min(WINDOW)),")],
        TOP + "a_window_is_the_newest_256",
    ),
    (
        "a newest page in list order",
        [(TO, "        p.ids.reverse();\n", "")],
        TOP + "entry_rows_fold_and_newest_pages",
    ),
    # G5: the pinned contentHash
    (
        "a pinned hash taken unchecked",
        [(TO, "        if r.content_hash.eq_ignore_ascii_case(ZERO32) {\n            return Ok(());\n        }",
          "        if !r.content_hash.is_empty() {\n            return Ok(());\n        }")],
        TOP + "a_pinned_content_hash_is_checked",
    ),
    (
        "version 1 hashed as an edit",
        [(TO, "            1 => self.app.pqchat_entry_hash(PqTopicEntry {", "            0 => self.app.pqchat_entry_hash(PqTopicEntry {")],
        TOP + "a_pinned_content_hash_is_checked",
    ),
    (
        "only the latest version read",
        [(TO, "e.version_count.saturating_sub(REF_VERSIONS_MAX - 1).max(1);", "e.version_count.max(1);")],
        TOP + "a_pinned_content_hash_is_checked",
    ),
]

if __name__ == "__main__":
    L.main("confirm", MUTANTS)
