# Polkadot Hub TestNet (Paseo) (`polkadot-hub-testnet`)

Public EVM testnet. Row `polkadot-hub-testnet` of [`chain-uids.json`](../../../chain-uids.json): chain id **420420417**, chain_uid
`0xd6eec26135305a8ad257a20d003357284c8aa03d0bdb2b357ab0a22371e11ef2`, network `testnet`. A chain is (chainId, chain_uid) (NET-ALL-22). The EVM side (pallet-revive on REVM, `eth-rpc`, accounts as mapped H160) carries SCaaS; the Substrate side (sr25519, `System.Account`) is the chain-support Native column, read by the SDK (T41.dot). NET-EVM-17.

Profile [`profile.json`](profile.json) (`draft`, chains-arweave plan T11; the format of SDK plan T40), from the probes of
2026-11-22 (`clients/scaas-rpc/runs/2026-11-22-evm-probes.py`, chains-arweave T12; summary `2026-11-22-evm-probes-summary.txt`
beside it; **one sample each**: the 24-h and 7-day windows of NET-EVM-19 are the operator's scheduler's, still to run):

- **Block 0 (H1 FAIL):** the chain's only public eth-rpc provider answers `eth_getBlockByNumber("0x0")` (and block 1) with
  `null`: it serves no early blocks, so `scaas-rpc` refuses it `ChainIdentityUnreadable` unless its endpoint entry names a
  checkpoint (a block number and hash) it then matches (CLI-RPC-03). The pin is the Substrate genesis hash, read from two Substrate
  providers (`chain_getBlockHash(0)`, equal), as Westend Hub's eth-rpc maps block 0 to it (controller call, chains-arweave T11).
  H1 also needs two independent eth-rpc providers and the chain has one: the owner's question.
- **Fork:** `osaka` by opcodes (PUSH0, TLOAD, CLZ answered); no `blockAccessListHash`. No SCaaS set deploys before NET-EVM-06
  holds here.
- **Caps:** runtime 24,576 B, init code 49,152 B (measured; REVM's hard cap). The header's gas limit is u64::MAX: no block cap.
  Hub gas folds `ref_time`, `proof_size` and the storage deposit into one figure; the per-transaction limit is 50 % of the
  maximum extrinsic weight, with no Ethereum gas figure, and an `eth_call` without a sender carried 2^30 gas. So the PQ fit
  table of the other profiles does not apply here: `max_tx_gas` and the per-op verdict wait for chains-arweave T13 (the Paseo
  measurement, on the owner's word) and T14. Nothing is disabled.
- **Sender balance:** an `eth_call` naming a `from` is refused unless that account holds gas × price (the probe asks without a
  sender for that reason).
- **Finality:** `tag finalized` (GRANDPA): `latest` − `finalized` 14–17 blocks, 24–36 s in the sample (H5); H7 served it.
- **Reads by hash:** H2 and H4 passed (a made-up hash refused or null).
- **Logs:** `eth_getLogs` answered a 100,000-block span (H6).
- **Transaction type:** 2 (the head carries a base fee).
- **L1 fee:** none. **Storage deposit:** per item and per byte, refunded only when cleared; SCaaS clears nothing, so it is a fee
  inside the gas figure (spec §6.4); NET-EVM-17 adds the existential deposit to a lane's balance alert (SPECIFIED, with T14).
- **EIP-2537:** absent (no BLS12-381): Zether waits for the software path (ARCH-POS-18). P-256 only on `master` (unconfirmed).
- **No PQZ or ML-DSA precompile:** a new precompile is a runtime upgrade through Polkadot governance.
- **Weight-to-gas (T13):** every SCaaS line priced in Ethereum gas (the 60 M deploy line, a 23 M PQZ op, a 5.8 M ML-DSA-65
  verify) is measured again on Paseo before `enabled`; that task waits for the owner's deploy ruling (no deploy before the
  freeze, owner 2026-11-22).
- **Explorer:** Blockscout (`blockscout.com`, Hub instances); verification (NET-EVM-12) when a deploy is ruled.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
