# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core T10b's mutants (the `file` content, UA-7 §6.4.1 with its 2026-11-21 Change; owner 2026-11-22): one per check,
each killed by its own named test: ctSha256 skipped on each open path, the length check skipped, the size not padded, a key
entering the content from above `ua-rs`, the key handed to the app, the file key not entered:
python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-t10b-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

AR = "clients/clientkeys/src/arweave.js"
CK = "clients/clientkeys/src/pqchat.js"
OB = "clients/ua-rs/src/file.rs"
WF = "clients/ua-rs/src/wallet/file.rs"
PF = "clients/ua-rs/src/wallet/pqchat_file.rs"
ST = "clients/pqchat-core/src/message.rs"
FI = "clients/pqchat-core/src/file.rs"
TAR = "cd clients/clientkeys && node --test --test-reporter=tap --test-name-pattern 'open_file checks the length' test/arweave.test.js"
TCK = "cd clients/clientkeys && node --test --test-reporter=tap --test-name-pattern 'file content' test/pqchat.test.js"
TUA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --features app-core,vectors "
TPQ = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test stores "
MUTANTS = [
    ("clientkeys: openFile's check before decryption skipped (openFileContent's path too)",
     [(AR, "  checkObject(object, size, ctSha256, cap);\n  let fr;", "  let fr;")],
     TAR, "open_file checks the length"),
    ("clientkeys: a key given to the sealer kept",
     [(CK, "fields.type !== \"file\" || \"key\" in fields", "fields.type !== \"file\"")],
     TCK, "file content"),
    ("ua-rs: open_file's ctSha256 not the signed one (the object's own)",
     [(WF, "        open_object(&kb, object, size, sha256, ct_sha256)",
       "        open_object(&kb, object, size, sha256, &Sha256::digest(object).into())")],
     TUA + "--test file_seal open_file_checks_ct_sha256_before_decryption"),
    ("ua-rs: pqchat_open_file's ctSha256 not the content's (the object's own)",
     [(PF, "open_object(&f.key, object, f.size, &f.sha256, &f.ct_sha256)",
       "open_object(&f.key, object, f.size, &f.sha256, &<[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(object)))")],
     TUA + "--test pqchat_keys file_message_rows"),
    ("ua-rs: the ctSha256 comparison skipped (check_object)",
     [(OB, "    if h.iter().zip(ct_sha256).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 {",
       "    if false && h.iter().zip(ct_sha256).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 {")],
     TUA + "--test file_seal open_file_checks_ct_sha256_before_decryption"),
    ("ua-rs: the length check skipped (check_object)",
     [(OB, "    if object.len() as u64 != want {", "    if false && object.len() as u64 != want {")],
     TUA + "--test file_seal open_file_checks_ct_sha256_before_decryption"),
    ("ua-rs: the size not padded to its bucket",
     [(WF, "    let b = bucket(size, cap).ok_or(Error::FileTooLarge)?;",
       "    let _ = bucket(size, cap).ok_or(Error::FileTooLarge)?;\n    let b = size + 8;")],
     TUA + "--test pqchat_keys file_message_rows"),
    ("ua-rs: a key given to the sealer kept (the key from above ua-rs)",
     [(PF, "!= Some(\"file\") || o.contains_key(\"key\")", "!= Some(\"file\")")],
     TUA + "--test pqchat_keys file_message_rows"),
    ("ua-rs: a file content's url not held to ar://",
     [(PF, "    ar_url(text(o.get(\"url\"), 1, 2048)?).ok_or(Error::PqChatContent)?;\n",
       "    text(o.get(\"url\"), 1, 2048)?;\n")],
     TUA + "--test pqchat_keys file_message_rows"),
    ("crate: file_info hands out the content itself (the key leaving ua-rs to the app)",
     [(FI, "        let v = serde_json::json!({\"mediaType\": media_type, \"name\": name, \"size\": size, \"url\": url,\n            \"ctSha256\": ct_sha256})\n        .to_string();",
       "        let _ = (media_type, name, size, url, ct_sha256);\n        let v = content.with(|b| String::from_utf8_lossy(b).into_owned());")],
     TPQ + "a_file_is_sent_and_read"),
    ("crate: the file sealed as a plain content (its key never entered)",
     [(ST, "                    .pqchat_seal_file_message(key, k, pos, header, v.to_string(), f)",
       "                    .pqchat_seal_message(key, k, pos, header, v.to_string())")],
     TPQ + "a_file_is_sent_and_read"),
]

if __name__ == "__main__":
    main("t10b", MUTANTS)
