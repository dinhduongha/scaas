# Westend Asset Hub (`polkadot-hub-westend`)

Public EVM testnet. Row `polkadot-hub-westend` of [`chain-uids.json`](../../../chain-uids.json): chain id **420420421**, chain_uid
`0x67f9723393ef76214df0118c34bbbd3dbebc8ed46a10973a8c969d48fe7598c9`, network `testnet`. A chain is (chainId, chain_uid) (NET-ALL-22). The EVM side (pallet-revive on REVM, `eth-rpc`, accounts as mapped H160) carries SCaaS; the Substrate side (sr25519, `System.Account`) is the chain-support Native column, read by the SDK (T41.dot). NET-EVM-17.

Profile [`profile.json`](profile.json) (`draft`, chains-arweave plan T11; the format of SDK plan T40), from the probes of
2026-11-22 (`clients/scaas-rpc/runs/2026-11-22-evm-probes.py`, chains-arweave T12; summary `2026-11-22-evm-probes-summary.txt`
beside it; **one sample each**: the 24-h and 7-day windows of NET-EVM-19 are the operator's scheduler's, still to run):

- **eth-rpc broken that day:** `https://westend-asset-hub-eth-rpc.polkadot.io` (the one public eth-rpc provider listed) answered
  every `eth_call` with "Metadata error: The generated code is not compatible with the node": H2 FAIL (3 of 5 pinned reads
  answered), `fork`, `codesize`, `eip2537` and `caps` unread. The profile's fork, caps and EIP-2537 are Polkadot Hub's
  (the research note §3.1), not measured here.
- **Block 0:** the eth-rpc answers block 0 with the Substrate genesis hash (equal to `chain_getBlockHash(0)` on a second,
  Substrate provider): the chain_uid convention the other two Hub rows follow.
- **Transaction type:** 2 (the head carries a base fee).
- **L1 fee:** none. **Storage deposit:** per item and per byte, refunded only when cleared; SCaaS clears nothing, so it is a fee
  inside the gas figure (spec §6.4); a lane's balance alert adds the existential deposit.
- **EIP-2537:** absent (no BLS12-381): Zether waits for the software path (ARCH-POS-18). P-256 only on `master` (unconfirmed).
- **No PQZ or ML-DSA precompile:** a new precompile is a runtime upgrade through Polkadot governance.
- **Weight-to-gas (T13):** every SCaaS line priced in Ethereum gas (the 60 M deploy line, a 23 M PQZ op, a 5.8 M ML-DSA-65
  verify) is measured again on Paseo before `enabled`; that task waits for the owner's deploy ruling (no deploy before the
  freeze, owner 2026-11-22).
- **Explorer:** Blockscout (`blockscout.com`, Hub instances); verification (NET-EVM-12) when a deploy is ruled.
- **RPC:** from the environment, passed to `smartcontracts/scripts/deploy.sh evm <rpc>`; no URL or key committed.
