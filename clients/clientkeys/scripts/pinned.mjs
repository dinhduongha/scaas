// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The pinned-source rule of the vector importers (pq-external.mjs, ua-wallet-vectors.mjs): a downloaded file is read only when
// its SHA-256 is the pinned one, before it is parsed. Downloads stay out of the repository; the rows taken from them and their
// source URL and SHA-256 are committed.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

export function readPinned(path, sha256, name = path) {
  const b = readFileSync(path);
  const got = createHash('sha256').update(b).digest('hex');
  if (got !== String(sha256).replace(/^0x/, '')) throw new Error(`sha256 mismatch ${name}`);
  return b;
}
