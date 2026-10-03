// R33 seam: the Zether confidentiality key `x` comes from the SAME seed on a separate path
// (EIP-2333-style, `m/12381|254/<coin>/<account>/7`), derived by stream S3's Rust/WASM
// (`zether-prover/`). It is NOT reimplemented here. We only load the wasm when present, ask it for
// `x`, and keep `x` encrypted at rest exactly like the seed (vault.js), never sent anywhere.
//
// Expected wasm-bindgen export (needs from S3):
//   zether_conf_key(curve: "bn254" | "bls12-381", seed: Uint8Array, coin: u32, account: u32) -> Uint8Array
//   (32-byte big-endian scalar, key_use = 7 fixed inside the prover).
import { createVault, openVault } from './vault.js';
import { wipe } from './bytes.js';

export const DEFAULT_PROVER_URL = '/dms_blockchain_bridge/static/lib/zether/zether_prover.js';

/** The prover module, or null when S3's wasm is not deployed (the feature stays off). */
export async function loadZetherProver(url = DEFAULT_PROVER_URL, importer = (u) => import(/* @vite-ignore */ u)) {
  let mod;
  try {
    mod = await importer(url);
  } catch {
    return null;
  }
  if (typeof mod.default === 'function') await mod.default();   // wasm-bindgen init
  return typeof mod.zether_conf_key === 'function' ? mod : null;
}

export function confLabel(curve, coin, account) {
  return `zether-conf:${curve}:${coin}:${account}`;
}

/** Derive `x` with the prover and seal it under the same PIN (and PRF) as the seed vault. */
export async function sealConfKey(prover, { seed, curve, coin, account, pin, prf }) {
  const x = prover.zether_conf_key(curve, seed, coin, account);
  if (!(x instanceof Uint8Array) || x.length !== 32 || x.every((b) => b === 0)) {
    throw new Error('The Zether prover returned an invalid key.');
  }
  try {
    return await createVault(x, { label: confLabel(curve, coin, account), pin, prf });
  } finally {
    wipe(x);
  }
}

export const openConfKey = openVault;
