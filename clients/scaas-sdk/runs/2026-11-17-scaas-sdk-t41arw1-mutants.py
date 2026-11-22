# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T41.arweave's ua-rs part (chains-arweave plan T16 and T17) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t41arw1-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

JS = "clients/clientkeys/src/arweave.js"
CK = "cd clients/clientkeys && node --test test/arweave.test.js"
AR = "clients/ua-rs/src/arweave.rs"
WA = "clients/ua-rs/src/wallet/arweave.rs"
WF = "clients/ua-rs/src/wallet/file.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 "
CORE = UA + "--no-default-features --features wallet,fam-arweave --test arweave "
ROWS = UA + "--no-default-features --features app-core,fam-arweave,vectors --test arweave_rows "
SEAL = UA + "--no-default-features --features app-core --test file_seal "
MUTANTS = [
    # CA-T16 (clientkeys), the plan's list
    ("the type string left out of the deep hash", [(JS, "    utf8ToBytes(String(type)),\n    owner,", "    owner,")], CK),
    ("the type as a binary byte", [(JS, "    utf8ToBytes(String(type)),\n    owner,", "    Uint8Array.of(type),\n    owner,")], CK),
    ("an empty tag list as 0x00", [(JS, "  if (!tags.length) return new Uint8Array(0);", "  if (!tags.length) return Uint8Array.of(0);")], CK),
    ("blob with a binary length", [(JS, "sha384(utf8ToBytes(`blob${chunk.length}`))", "sha384(concatBytes(utf8ToBytes(\"blob\"), Uint8Array.of(chunk.length & 255)))")], CK),
    ("the id as SHA-256 of the item", [(JS, "  return { item, id: itemId(signature),", "  return { item, id: itemId(item),")], CK),
    ("v written as 0 or 1", [(JS, "return concatBytes(rec.subarray(1), Uint8Array.of(27 + rec[0]));", "return concatBytes(rec.subarray(1), Uint8Array.of(rec[0]));")], CK),
    ("the bucket floor at 2^15", [(JS, "export const BUCKET_MIN = 2 ** 16;", "export const BUCKET_MIN = 2 ** 15;")], CK),
    ("the bucket from size + 16", [(JS, "  while (b < size + 8) b *= 2;", "  while (b < size + 16) b *= 2;")], CK),
    ("the pad check skipped (clientkeys)", [(JS, "  if (fr.subarray(8 + size).some((b) => b !== 0)) fail(\"FileFrame\");\n", "")], CK),
    ("type 4 over the 48 bytes", [(JS, "(type === 4 ? utf8ToBytes(bytesToHex(msg)) : msg)", "msg")], CK),
    # CA-T17 (ua-rs), the plan's list and the parser's refusals
    ("the presence byte 2 accepted", [(AR, "                1 => Ok(Some(\n                    take(32)?", "                1 | 2 => Ok(Some(\n                    take(32)?")], CORE + "every_refusal_row"),
    ("UploadSign without re-checking the data hash", [(WA, "        if h != self.ct_sha256 {\n            return Err(Error::AppKeyUsage);\n        }\n", "        let _ = h;\n")],
     UA + "--no-default-features --features app-core,fam-arweave --lib an_upload_key_signs_only_its_object"),
    ("the upload key without the file key", [(WA, "[&self.bytes(root)?[..], &self.bytes(&sealed.key)?[..]].concat()", "self.bytes(root)?.to_vec()")], ROWS + "upload_keys_and_seal_for_arweave_rows"),
    ("the pad check skipped (ua-rs)", [(WF, "        if pad.iter().fold(0u8, |a, x| a | x) != 0 {", "        if false && pad.iter().fold(0u8, |a, x| a | x) != 0 {")], ROWS + "sealed_objects_frames_and_checks"),
    ("the plaintext sha256 check skipped", [(WF, "        if h.iter().zip(sha256).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 {", "        if false && h.iter().zip(sha256).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 {")], SEAL + "open_file_refuses_each_mismatch"),
    ("the frame's len unchecked", [(WF, "        if len != size.to_be_bytes() {", "        if false && len != size.to_be_bytes() {")], SEAL + "open_file_refuses_each_mismatch"),
    ("the object's length unchecked", [(WF, "        if object.len() as u64 != b + 16 {", "        if false && object.len() as u64 != b + 16 {")], SEAL + "open_file_refuses_each_mismatch"),
    ("a negative block count read", [(AR, "        if n < 0 {\n            return Err(ArweaveError::TagBlockNegative);\n        }\n        if tags.len() as i128 + n > MAX_TAGS as i128 {\n            return Err(ArweaveError::TagCount);\n        }\n        for _ in 0..n {\n            let mut field = |max: usize| -> Result<Vec<u8>, ArweaveError> {\n                let len = long_at", "        if tags.len() as i128 + n > MAX_TAGS as i128 {\n            return Err(ArweaveError::TagCount);\n        }\n        for _ in 0..n.abs() {\n            let mut field = |max: usize| -> Result<Vec<u8>, ArweaveError> {\n                let len = long_at")], CORE + "every_refusal_row"),
    ("type 4 signed over the 48 bytes (ua-rs)", [(AR, "                    .sign(&hex_text(msg))", "                    .sign(msg)")], ROWS + "every_item_row_built_byte_for_byte"),
    ("a high s accepted", [(AR, "            if s.normalize_s() != s {\n                return false;\n            }\n            let Some(rec)", "            let Some(rec)")], CORE + "every_refusal_row"),
]

if __name__ == "__main__":
    main("t41arw1", MUTANTS)
