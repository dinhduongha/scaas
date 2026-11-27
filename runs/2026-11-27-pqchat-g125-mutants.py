# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqChat public topics G1, G2, G5 (owner 2026-11-27; CTR-CHAT-29 to CTR-CHAT-31): one mutant per new check, each killed by
its named test (`expect`: the test's name in the failing output); the contract's in `PqChatTopics`, pqchat-core's decoders. python3 runs/2026-11-27-pqchat-g125-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main  # noqa: E402

S = "smartcontracts/evm/src/pqchat/PqChatTopics.sol"
FT = "cd smartcontracts/evm && ../../scripts/capped forge test --match-path test/pqchat/PqTopicRows.t.sol --match-test "
TIMES, NONCE = "test_topics_postedAtAndEditedAt", "test_topics_versionNonceRebuildsTheDigest"
ROWS, BOUND = "test_topics_entryRows", "test_topics_entryRowsBound"
C = "clients/pqchat-core/src/topics.rs"
CTEST = "entry_and_version_times_and_nonce"
CT = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test topics " + CTEST
MUTANTS = [
    # G1: the times
    ("postedAt not set", [(S, "limit), depth, uint64(block.timestamp));", "limit), depth, 0);")], FT + TIMES, TIMES),
    ("editedAt not set on edit", [(S, "limit), uint64(block.timestamp)));", "limit), 0));")], FT + TIMES, TIMES),
    ("entryOf: no editedAt", [(S, "(v.editedAt, v.nonce) = (last.editedAt, d.nonce);", "v.nonce = d.nonce;")], FT + TIMES,
     TIMES),
    ("versionAt: version 1 takes postedAt as editedAt", [(S, "e.nonce, postedAt, 0);", "e.nonce, postedAt, postedAt);")],
     FT + TIMES, TIMES),
    ("versionAt: the latest version's slot for every edit",
     [(S, "Version storage ver = vs[version - 2];", "Version storage ver = vs[vs.length - 1];")], FT + TIMES, TIMES),
    # G5: the nonce
    ("entryOf: the original's nonce after an edit", [(S, "(last.editedAt, d.nonce);", "(last.editedAt, e.nonce);")],
     FT + NONCE, NONCE),
    ("versionAt: version 1's nonce zero", [(S, "return (e.mediaType, e.body, sh, e.nonce,", "return (e.mediaType, e.body, sh, 0,")],
     FT + NONCE, NONCE),
    ("versionAt: an edit's nonce altered",
     [(S, "return (d.mediaType, d.body, dh, d.nonce,", "return (d.mediaType, d.body, dh, d.nonce + 1,")], FT + NONCE, NONCE),
    # G2: the rows
    ("entryRows: the bound off by one (64 refused)",
     [(S, "if (entryIds.length > ENTRY_ROWS_MAX)", "if (entryIds.length >= ENTRY_ROWS_MAX)")], FT + BOUND, BOUND),
    ("entryRows: the bound off by one (65 taken)",
     [(S, "uint256 internal constant ENTRY_ROWS_MAX = 64;", "uint256 internal constant ENTRY_ROWS_MAX = 65;")], FT + BOUND,
     BOUND),
    ("entryRows: an unknown id answered",
     [(S, "        if (o == address(0)) revert IPqChat.PqTopicUnknown(id);\n", "")], FT + BOUND, BOUND),
    ("entryRows: the original's version after an edit", [(S, "        if (n != 0) {\n            Version storage last",
                                                          "        if (false) {\n            Version storage last")],
     FT + ROWS, ROWS),
    ("entryRows: no editedAt", [(S, "(l, mt, bd, w.editedAt) = (last.record, 192, 224, last.editedAt);",
                                 "(l, mt, bd) = (last.record, 192, 224);")], FT + ROWS, ROWS),
    ("entryRows: the original's nonce", [(S, "uint64(uint256(_word(l, 128)))", "uint64(uint256(_word(o, 128)))")], FT + ROWS,
     ROWS),
    ("entryRows: bodyLength from the media type's offset",
     [(S, "w.bodyLength = uint256(_word(l, 64 + uint256(_word(l, bd))));",
       "w.bodyLength = uint256(_word(l, 64 + uint256(_word(l, mt))));")], FT + ROWS, ROWS),
    ("entryRows: the media type one word off", [(S, "_bytesAt(l, m + 32,", "_bytesAt(l, m + 64,")], FT + ROWS, ROWS),
    ("entryRows: up and down swapped", [(S, "(w.up, w.down) = (sc.up, sc.down);", "(w.up, w.down) = (sc.down, sc.up);")],
     FT + ROWS, ROWS),
    ("entryRows: the author's vote, not the viewer's", [(S, "s.votes[id][viewer].value", "s.votes[id][w.author].value")],
     FT + ROWS, ROWS),
    ("entryRows: the replies of another list", [(S, "s.replies[id].length", "s.byAuthor[id].length")], FT + ROWS, ROWS),
    # pqchat-core's decoders of the new fields
    ("pqchat-core: entry's postedAt read as editedAt",
     [(C, 'posted_at: model::num(at(e, "postedAt"))?,', 'posted_at: model::num(at(e, "editedAt"))?,')], CT, CTEST),
    ("pqchat-core: entry's nonce not read", [(C, 'nonce: model::num(at(e, "nonce"))?,', "nonce: 0,")], CT, CTEST),
    ("pqchat-core: version_at's nonce not read", [(C, 'nonce: model::num(at(&v, "nonce"))?,', "nonce: 0,")], CT, CTEST),
    ("pqchat-core: version_at's editedAt read as postedAt",
     [(C, 'edited_at: model::num(at(&v, "editedAt"))?,', 'edited_at: model::num(at(&v, "postedAt"))?,')], CT, CTEST),
]

if __name__ == "__main__":
    main("all", MUTANTS, prefix="2026-11-27-pqchat-g125")
