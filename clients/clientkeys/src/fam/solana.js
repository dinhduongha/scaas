// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Solana (plan 2026-11-17-scaas-sdk T24.solana): the program address of a seed list (`Pubkey::find_program_address`) and the
// SCaaS Account of an owner (`["acct", owner]` under the program), as scaas-node/src/adapters/solana.rs `find_pda` and
// `account_of`. Rows: smartcontracts/vectors/families/solana.json (scripts/families-vectors.mjs). UNAUDITED.
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256, concatBytes, utf8ToBytes } from "../bytes.js";

/** Solana's bounds on a seed list: at most 16 seeds of at most 32 bytes each (`MAX_SEEDS`, `MAX_SEED_LEN`). */
export const MAX_SEEDS = 16;
export const MAX_SEED_LEN = 32;
const MARKER = utf8ToBytes("ProgramDerivedAddress");

export class SolanaError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/** On the ed25519 curve as curve25519-dalek's `CompressedEdwardsY::decompress` decides (ZIP-215 decoding: y below 2^255). */
export function onCurve(b) {
  try {
    ed25519.Point.fromBytes(b, true);
    return true;
  } catch {
    return false;
  }
}

const key32 = (k, what) => {
  if (!(k instanceof Uint8Array) || k.length !== 32) throw new SolanaError(`${what}: 32 bytes`);
  return k;
};

/** `Pubkey::find_program_address(seeds, program)`: the first bump from 255 down whose hash is off the curve. */
export function findPda(seeds, program) {
  key32(program, "program");
  if (seeds.length > MAX_SEEDS - 1) throw new SolanaError("Argument: too many seeds"); // the bump is the 16th
  for (const s of seeds)
    if (!(s instanceof Uint8Array) || s.length > MAX_SEED_LEN) throw new SolanaError("Argument: seed");
  for (let bump = 255; bump >= 0; bump--) {
    const h = sha256(concatBytes(...seeds, Uint8Array.of(bump), program, MARKER));
    if (!onCurve(h)) return { address: h, bump };
  }
  throw new SolanaError("NoViableBump");
}

/** The SCaaS Account of `owner` under `program` (NET-SOL's `["acct", owner]` seeds). */
export function accountOf(program, owner) {
  return findPda([utf8ToBytes("acct"), key32(owner, "owner")], program).address;
}
