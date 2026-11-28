# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The `chainstore` entry (owner 2026-11-28, CLI-PQC-02, branch pqchat-chainstore): a mutant of each new check, the scaas-sdk
plan's `mutants_lib` with this crate's record:
  python3 clients/pqchat-core/runs/2026-11-28-pqchat-chainstore-mutants.py check | run [name...]
Each test command goes through scripts/capped, foreground (mutant_guard's deadline and restore)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scaas-sdk" / "runs"))
import mutants_lib as L  # noqa: E402

R = "clients/pqchat-core/runs"
L.OUT = Path(__file__).parent
L.PREFIX = "2026-11-28-pqchat-"
L.RUNS = R
L.NOT_CODE = [f":!{R}/*-mutants.txt", f":!{R}/2026-11-17-pqchat-core-summary.txt"]

SE = "clients/pqchat-core/src/session.rs"
CS = "clients/pqchat-core/src/chain_store.rs"
ST = "clients/pqchat-core/src/stores.rs"
CD = "cd clients/pqchat-core && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
STORES = CD + "--test stores "
CHAIN = CD + "--test chain_chainstore -- --ignored --test-threads 1 "
REL = "smartcontracts/evm/release-data/PqChatStore.json"

MUTANTS = [
    # spec 2026-11-21 §5.5 (C4): the pinned runtime code hash
    (
        "the code hash check skipped",
        [(CS, "        if !code.eq_ignore_ascii_case(pin) {", "        if false && !code.eq_ignore_ascii_case(pin) {")],
        STORES + "chainstore_code_hash_pinned",
    ),
    (
        "a code hash other than the pin accepted",
        [
            (
                CS,
                "        if !code.eq_ignore_ascii_case(pin) {",
                "        if !code.eq_ignore_ascii_case(pin) && code.len() != pin.len() {",
            )
        ],
        STORES + "chainstore_code_hash_pinned",
    ),
    (
        "a pin that is not the build's accepted (the release data's hash)",
        [(REL, '"runtimeCodeHash": "0xb7c1', '"runtimeCodeHash": "0xb7c2')],
        CHAIN + "chain_chainstore_over_matrix_and_pqchatstore",
    ),
    (
        "implemented() leaves chainstore out again",
        [
            (
                SE,
                "        matches!(\n            self,\n            StoreEntry::Matrix { .. } | StoreEntry::Chain { .. } | StoreEntry::Chainstore { .. }\n        )",
                "        matches!(self, StoreEntry::Matrix { .. } | StoreEntry::Chain { .. })",
            )
        ],
        STORES + "chainstore_written_and_read",
    ),
    (
        "the identity read asks another interface id (a wrong selector)",
        [(CS, 'pub const IPQCHATSTORE_ID: &str = "0xf33ad180";', 'pub const IPQCHATSTORE_ID: &str = "0x95660a78";')],
        STORES + "chainstore_written_and_read",
    ),
    (
        "the identity check skipped",
        [
            (
                CS,
                "            Some(_) => self.is_chat_store(&c, &contract).await?,",
                "            Some(_) => true,",
            )
        ],
        STORES + "chainstore_identity_checked",
    ),
    (
        "the chain id of the entry not compared",
        [(CS, "                    && chainstore.is_none_or(|id| id_of(c, id))", "")],
        STORES + "chainstore_names_its_chain_id",
    ),
    (
        "chainstore gas spent without the consent",
        [
            (
                ST,
                "        if (post || targets.iter().any(|e| e.on_chain())) && !prefs.chain_spend {",
                "        if (post || targets.iter().any(|e| matches!(e, StoreEntry::Chain { .. }))) && !prefs.chain_spend {",
            )
        ],
        STORES + "chainstore_cost_unconfirmed",
    ),
    (
        "an unconfirmed store read",
        [
            (
                CS,
                "        if !self.info_of(ep)?.stores.contains(e) || !self.prefs(&sid)?.confirmed.contains(e) {",
                "        if !self.info_of(ep)?.stores.contains(e) {",
            )
        ],
        STORES + "chainstore_unconfirmed_neither_read_nor_written",
    ),
    (
        "the store written at another address than its own",
        [
            (
                CS,
                '            .prepare(&c.chain, &contract, "IPqChat.storeMessage", a, payer)',
                '            .prepare(&c.chain, &c.factory, "IPqChat.storeMessage", a, payer)',
            )
        ],
        STORES + "chainstore_written_and_read",
    ),
]

if __name__ == "__main__":
    L.main("chainstore", MUTANTS)
