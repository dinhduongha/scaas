# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqChat TreeKEM T5 mutants (the SDK's tree plan and the registry's KEM view), each killed by its named test of
`scaas-sdk` (`pqchat_tree::tests`, through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py, ARCH-POS-23):
python3 clients/scaas-sdk/runs/2026-11-26-pqchat-treekem-t5-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "runs"))
from mutants_lib import main

T = "clients/scaas-sdk/src/pqchat_tree.rs"
CMD = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked -j 2 "
       "--features pqchat-records --lib pqchat_tree")
MUTANTS = [
    ("a chunk plan that exceeds the block-limit rule",
     [(T, "while k > 0 && !l.fits(gas(k)) {", "while k > 0 && false && !l.fits(gas(k)) {")],
     CMD, "a_20m_block_takes_a_plain_commit_and_refuses_the_bound_record"),
    ("every ciphertext released before the node keys are final",
     [(T, ".filter(|x| matches!(x.entry, \"commit\" | \"addPathList\" | \"addPathKeys\"));",
       ".filter(|x| matches!(x.entry, \"commit\"));")],
     CMD, "the_order_broken_and_its_controls"),
    ("a refusal by a protocol-wide constant (60 M), not the chain's block",
     [(T, "g.regular < self.tx_regular && g.asked() <= self.block", "g.regular < self.tx_regular && g.asked() <= 60_000_000")],
     CMD, "a_20m_block_takes_a_plain_commit_and_refuses_the_bound_record"),
    ("the decoder that drops the signature again",
     [(T, '"sig": hex(&r.sig)', '"sig": "0x"')], CMD, "the_kem_view_keeps_the_signature"),
    ("the order broken taken as complete",
     [(T, "        if !l.fits(last) {\n", "        if false && !l.fits(last) {\n")], CMD, "the_order_broken_and_its_controls"),
]

if __name__ == "__main__":
    main("t5", MUTANTS, prefix="2026-11-26-pqchat-treekem")
