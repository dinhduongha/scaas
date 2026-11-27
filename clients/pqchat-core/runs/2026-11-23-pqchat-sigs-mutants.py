# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan 2026-11-23-pqchat-signatures S4's client mutants (CLI-PQC-15, CLI-PQC-16; the SDK's and scaas-rpc's agreed read), each
killed by its own named test through a fixture that reaches its check:
python3 clients/pqchat-core/runs/2026-11-23-pqchat-sigs-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

SG = "clients/pqchat-core/src/signed.rs"
MS = "clients/pqchat-core/src/message.rs"
NT = "clients/pqchat-core/src/net.rs"
SE = "clients/pqchat-core/src/session.rs"
AG = "clients/scaas-sdk/src/app_core.rs"
CK = "clients/pqchat-core/src/check.rs"
RD = "clients/pqchat-core/src/reads.rs"
TD = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test devices "
EV = "clients/scaas-rpc/src/evm.rs"
T = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test signed "
TSDK = ("cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features "
        "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots,app-core,pqchat-records,vectors --test pqchat_keys ")
TRPC = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test evm_fakes "
MUTANTS = [
    ("a kept signature not verified (the session and epoch records)",
     [(SG, "        if verify {\n            let (name, rec, sig_item)", "        if false {\n            let (name, rec, sig_item)")],
     T + "a_kept_signature_counts_and_a_substituted_sealed_info_does_not"),
    ("a none home read under require_signed_records",
     [(SG, "            _ if self.conf.require_signed_records => Err(DropReason::Unsigned),\n", "")],
     T + "a_none_home_is_read_as_before_or_refused_when_required"),
    ("the setting not pinned (a downgrade to none taken)",
     [(SG, "                Some(s) if s != got => Err(crate::PqChatError::Internal),\n", "")],
     T + "the_setting_is_pinned_so_a_downgrade_is_refused"),
    ("a setting of 1 (log) taken",
     [(SG, "        if got != SIG_NONE && got != SIG_SSTORE2 {", "        if got > SIG_SSTORE2 {")],
     T + "the_setting_is_pinned_so_a_downgrade_is_refused"),
    ("a leave of another epoch counted",
     [(SG, "            if mine(l) {\n", "            if true {\n")],
     T + "leaves_and_removals_count_by_their_signatures"),
    ("a leave's signature not verified",
     [(SG, '                ("IPqChat.leaveSig", a),\n                )\n                .await?;', '                ("IPqChat.leaveSig", a),\n                );')],
     T + "leaves_and_removals_count_by_their_signatures"),
    ("an sstore2 epoch's leaves read from the flags",
     [(SG, "        if !self.verifies(chain, contract).await? {\n            for m in", "        if true {\n            for m in")],
     T + "leaves_and_removals_count_by_their_signatures"),
    ("a posted message's kept signature not verified",
     [(MS, '                ("IPqChat.messageSig", a),\n            )\n            .await?;', '                ("IPqChat.messageSig", a),\n            );')],
     T + "a_posted_message_counts_by_its_kept_signature"),
    ("a session created on a none home under require_signed_records",
     [(SE, "            return Err(PqChatError::HomeUnsigned);", "            let _ = 0;")],
     T + "a_session_is_not_created_on_a_none_home_when_required"),
    ("the agreed option ignored",
     [(NT, "        if !agreed_item(item) {\n            return self.0.read(chain, contract, item, args).await;", "        if true {\n            return self.0.read(chain, contract, item, args).await;")],
     T + "agreed_reads_cover_the_control_plane_only"),
    ("PqChat::new ignores agreed_reads",
     [("clients/pqchat-core/src/lib.rs", "        let net: Arc<dyn net::Net> = if conf.agreed_reads {", "        let net: Arc<dyn net::Net> = if false {")],
     T + "pqchat_new_wires_the_agreed_option"),
    ("the agreed option over every read",
     [(NT, "    (item.starts_with(\"IPqChat.\") || item.starts_with(\"IPqChatTreeViews.\"))\n        && matches!(trust(item), Ok(Trusted))", "    item.starts_with(\"I\")")],
     T + "agreed_reads_cover_the_control_plane_only"),
    # owner (M) 2026-11-23 (CTR-CHAT-24): several KEM keys per member
    ("(M) keys of a member in any order",
     [(CK, "all(|w| matches!(w, [a, b] if (a.ua.as_str(), a.key_id) < (b.ua.as_str(), b.key_id)))", "all(|w| matches!(w, [a, b] if a.ua <= b.ua))")],
     TD + "shapes_take_several_keys_per_member_in_order"),
    ("(M) no cap on a member's keys",
     [(CK, "count() <= KEYS_PER_UA_MAX)", "count() <= usize::MAX)")],
     TD + "shapes_take_several_keys_per_member_in_order"),
    ("(M) the plain-rekey rule per key, not per UA",
     [(CK, "    let plain = distinct(child)\n        .into_iter()\n        .eq(distinct(parent).into_iter().filter(|u| kept(u)))", "    let plain = child.members.iter().map(|m| &m.ua)\n        .eq(parent.members.iter().map(|m| &m.ua).filter(|u| kept(u)))")],
     TD + "a_members_keys_change_in_a_plain_rekey"),
    ("(M) only the first own wrap tried",
     [(RD, "                Err(d) => last = d,", "                Err(d) => return Err(d),")],
     TD + "the_first_own_wrap_that_opens_is_used"),
    ("SDK: read_app_agreed not agreed",
     [(AG, "            By::Agreed => pool.read_at_block_agreed(choice, purpose, call).await?,", "            By::Agreed => pool.read_at_block(choice, purpose, call).await?,")],
     TSDK + "read_app_agreed_is_the_agreed_read"),
    ("scaas-rpc: read_at_block_agreed by the list's failover",
     [(EV, "        self.pool.agree(self, choice, purpose, f).await\n    }\n\n    /// [`EvmPool::read_at_block_agreed`] over",
       "        self.read_at_block(choice, purpose, f).await\n    }\n\n    /// [`EvmPool::read_at_block_agreed`] over")],
     TRPC + "an_agreed_read_on_a_failover_list_outvotes_one_liar"),
]

if __name__ == "__main__":
    main("sigs", MUTANTS)
