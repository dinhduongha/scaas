// Backup, not built or tested (B P3-2, commit be8d0772): the Safe-style ERC-1271 wrap of `SmartKeyAccount` and
// `MandateWallet`, superseded by ERC-7739 (owner 2026-11-12: only ERC-7739; src/evm.js `erc7739TypedData`). As it stood in
// src/evm.js (it used that file's `hashTypedData`).
import { hashTypedData } from '../../../src/evm.js';

/** The typed data a key signs for an ERC-1271 answer over `hash` (CTR-ACC-02): `ERC1271Message(bytes32 hash)` in the
 *  wallet's own salted domain, never the raw `hash`. `wallet`: `SmartKeyAccount` or `MandateWallet` (also
 *  `HederaMandateWallet`); `address`: the wallet's. A batch signs the root over these digests. */
export function erc1271TypedData({ wallet, address, chainId, chainUid, hash }) {
  const name = { SmartKeyAccount: 'SCaaS SmartKeyAccount', MandateWallet: 'SCaaS MandateWallet' }[wallet];
  if (!name) throw new Error(`no ERC-1271 wrap for ${wallet}`);
  return {
    types: { EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
      { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }, { name: 'salt', type: 'bytes32' }],
    ERC1271Message: [{ name: 'hash', type: 'bytes32' }] },
    primaryType: 'ERC1271Message',
    domain: { name, version: '1', chainId, verifyingContract: address, salt: chainUid },
    message: { hash },
  };
}

/** `wallet.erc1271Digest(hash)`: the message a key signs for the wallet's ERC-1271 answer (CTR-ACC-02). */
export function erc1271Digest(args) {
  return hashTypedData(erc1271TypedData(args));
}
