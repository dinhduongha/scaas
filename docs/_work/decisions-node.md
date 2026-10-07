# Register fragment: node (NODE-*)

Phase-1 fragment of `docs/decisions.md` for the node area. Entries follow plan §3.3.

## General

### NODE-GEN-01 — Node holds no subject funds or keys
- old: SCaaS:N1, UD:§23.2 · status: current · owner: yes · date: 2026-10-07 · normative: node/README.md#NODE-GEN-01 · superseded-by: —

**Why.** Funds and subject keys stay with subjects and contracts; a compromised node can only stop working or lie on its feed. A relayer signs only the outer transaction, with its `authKey`; it never needs a subject's confidential key `x`: it cannot decrypt the amount, build the proof or change any field (all are in the signed digest), and that blindness is the property, not a limitation. A server holds `x` only when the company itself sends from its own confidential treasury, which is custody, not relay; the key oracle that serves it is small (under 300 lines; the enclave image under 5,000 lines including the crypto backend), so it stays out of the node process, which parses strangers' bytes.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 880; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2055.

### NODE-GEN-02 — No broadcast without committed journal
- old: SCaaS:N2 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-02 · superseded-by: —

**Why.** A transaction broadcast without a durable record can be signed twice after a crash.
**Cost if wrong.** Double spends of lane nonces.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 881.

### NODE-GEN-03 — No outer nonce abandoned
- old: SCaaS:N3 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-03 · superseded-by: —

**Why.** An abandoned nonce blocks every later transaction of the lane.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 882.

### NODE-GEN-04 — One live outer tx per intent
- old: SCaaS:N4 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-04 · superseded-by: —

**Why.** Two live outer transactions for one intent waste gas and confuse tracking.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 883.

### NODE-GEN-05 — No bump after consumption
- old: SCaaS:N5 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-05 · superseded-by: —

**Why.** Once the subject nonce is consumed, a bump can only revert and burn gas.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 884.

### NODE-GEN-06 — Never dead because landed elsewhere
- old: SCaaS:N6 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-06 · superseded-by: —

**Why.** An intent that landed through another relayer succeeded; reporting it dead would make clients re-ask the subject.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 885.

### NODE-GEN-07 — Unbound wire values never submitted
- old: SCaaS:N7 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-07 · superseded-by: —

**Why.** Unbound wire values (relayer, fee recipient) are normalized first, so nobody can steer our lane to pay them.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 886.

### NODE-GEN-08 — Nothing booked before finality
- old: SCaaS:N8 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-08 · superseded-by: —

**Why.** Clients book money; booking before finality books reorged payments.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 887.

### NODE-GEN-09 — Breakers never block indexing or rescues
- old: SCaaS:N9 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-09 · superseded-by: —

**Why.** Breakers limit new spending; stopping rescues or indexing would turn a cost guard into an outage.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 888.

### NODE-GEN-10 — One owner process per store
- old: SCaaS:N10 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-10 · superseded-by: —

**Why.** Two writers on one store break nonce and journal guarantees.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 889.

### NODE-GEN-11 — Every paid outer tx metered
- old: SCaaS:N11 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-11 · superseded-by: —

**Why.** Every outer transaction costs the lane; unmetered ones escape budgets.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 890.

### NODE-GEN-12 — Signed fields read from payload
- old: SCaaS:N12 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-12 · superseded-by: —

**Why.** The signed payload is the truth; side fields from the caller can disagree with it.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 891.

### NODE-GEN-13 — Value out and deposits capped
- old: SCaaS:N13 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-13 · superseded-by: —

**Why.** Jobs that move lane value out must be capped, or a client can drain gas float.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 892.

### NODE-GEN-14 — Intents signature-checked before chain calls
- old: SCaaS:N14 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-14 · superseded-by: —

**Why.** Checking signatures first keeps forged intents from costing RPC calls.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 893.

### NODE-GEN-15 — Adapter restart state in store
- old: SCaaS:N15 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-15 · superseded-by: —

**Why.** Adapter state outside the store is lost on restore and cannot be fenced.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 894.

### NODE-GEN-16 — No upgradeable program, one key per family
- old: SCaaS:N16 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-16 · superseded-by: —

**Why.** An upgradeable program can change under the node; one key per family keeps custody simple.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 895.

### NODE-GEN-17 — One Rust app for the daemon tier
- old: UD:§23, UD:§23.3 · status: current · owner: yes · date: 2026-08-31 · normative: node/README.md#NODE-GEN-17 · superseded-by: —

**Why.** One binary with roles by configuration means one release, one test matrix and one operations story.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2014; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2154.

### NODE-GEN-18 — scaas-node layout: module moves and job seam first
- old: reorg:Q12 · status: current · owner: yes · date: 2026-10-07 · normative: node/README.md#NODE-GEN-18 · superseded-by: —

**Why.** Code that mirrors the docs is easier to review; the job seam first keeps tests green during the move.
**Source.** [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) line 1228.

### NODE-GEN-80 — One Rust node, ERP as control plane
- old: UD:§21.2 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05

It said: one Rust node, ERP as control plane.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1341.

### NODE-GEN-81 — Lane diagram with ERP control plane
- old: UD:§23.6 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05, NODE-JOB-06, INT-ERP-16

It said: lane diagram with ERP control plane.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2261.

### NODE-GEN-82 — ERP addon is control plane, not a node
- old: UD:§23.8 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05

It said: eRP addon is control plane, not a node.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2319.

## Store

### NODE-STO-01 — Node refuses max_valid_for_secs above horizon
- old: CR-PD-4(node), CR-R3-8(node) · status: current · owner: no · date: 2026-10-07 · normative: node/store.md#NODE-STO-01 · superseded-by: —

**Why.** A signature valid longer than the family keeps replay state would be replayable.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 901; [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 700.

### NODE-STO-02 — paused blocks sending, halted blocks indexing
- old: R53 · status: current · owner: no · date: 2026-10-06 · normative: node/store.md#NODE-STO-02 · superseded-by: —

**Why.** Pause stops spending, halt also stops reading; two levers for two situations.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 526.

### NODE-STO-03 — RPC endpoints only in node config
- old: R20, R95 · status: current · owner: yes · date: 2026-10-06 · normative: node/store.md#NODE-STO-03 · superseded-by: —

**Why.** RPC URLs may embed keys and are dial targets; only the host's config may set them. Config authority is the node store, in the owner's words "toml bootstraps; admin API mutations persist"; the one admin-editable dial target, mesh peer URLs, is admin-only, audited and behind its own SSRF guard.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 727; [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 1019.

### NODE-STO-04 — One store always on, one owner
- old: R88, UD:§23.1, UD:§23.7 · status: current · owner: yes · date: 2026-10-06 · normative: node/store.md#NODE-STO-04 · superseded-by: —

**Why.** One store with one owner keeps every guarantee in one transaction domain.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 110; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2024; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2297.

### NODE-STO-05 — Finality, pause, index cursor in node
- old: R96 · status: current · owner: no · date: 2026-10-06 · normative: node/store.md#NODE-STO-05 · superseded-by: —

**Why.** Finality and pause are node decisions; clients only read them.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 119.

### NODE-STO-06 — SQLite, PostgreSQL or MySQL, storage only
- old: R111 · status: current · owner: yes · date: 2026-10-06 · normative: node/store.md#NODE-STO-06 · superseded-by: —

**Why.** Operators choose the database they run; the store is storage only, with fencing for safety.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 136.

### NODE-STO-07 — Node halts chains with upgradeable programs
- old: R348 · status: current · owner: yes · date: 2026-10-07 · normative: node/store.md#NODE-STO-07 · superseded-by: —

**Why.** An upgradeable program can change under the node's assumptions.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 154.

### NODE-STO-08 — Paused chain accepts and holds jobs
- old: NI:I2 · status: open · owner: no · date: 2026-10-07 · normative: node/store.md#NODE-STO-08 · superseded-by: —

**Why.** A paused chain keeps accepting so clients need not retry; jobs wait.
**Cost if wrong.** Default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1611.

### NODE-STO-09 — Names chosen where sources gave none
- old: NI:I7 · status: open · owner: no · date: 2026-10-07 · normative: node/store.md#NODE-STO-09 · superseded-by: —

**Why.** Names had to be chosen where the design gave none; recorded so they can be revisited.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1617.

### NODE-STO-10 — Gas cap warning for confidential tokens
- old: — · status: current · owner: no · date: 2026-10-07 · normative: node/store.md#NODE-STO-10 · superseded-by: —

**Why.** Classical Zether transfers need about 3.36 M gas; the 3 M default would silently reject them, so configuration warns.

### NODE-STO-80 — In-memory gateway queue and DEX book
- old: R16 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-DEX-01, NODE-DEX-01, INT-ERP-12, NODE-STO-04, NODE-DEX-14

It said: in-memory gateway queue and DEX book.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 718.

## Job API

### NODE-JOB-01 — Call jobs limited to selector/target table
- old: CR-PD-1(c) · status: current · owner: yes · date: 2026-10-07 · normative: node/job-api.md#NODE-JOB-01 · superseded-by: —

**Why.** A `call` job is signed by our lane; an open-ended call would let a tenant spend or move anything the lane can.
**Cost if wrong.** Rows added later need review.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 247.

### NODE-JOB-02 — One journal, node-computed digests
- old: R89 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-02 · superseded-by: —

**Why.** One journal and node-computed digests let no tenant squat another's intent.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 111.

### NODE-JOB-03 — Namespaces are the tenant unit
- old: R90 · status: current · owner: yes · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-03 · superseded-by: —

**Why.** Namespaces bound everything a credential can see and do.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 112.

### NODE-JOB-04 — Idempotency key and payload hash
- old: R91 · status: current · owner: yes · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-04 · superseded-by: —

**Why.** Retries never duplicate; JCS makes the hash independent of key order and whitespace.
**Cost if wrong.** A changed payload under one key flags attention instead of a duplicate.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 113.

### NODE-JOB-05 — Machine credentials: namespaced HMAC keys
- old: R92 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-05 · superseded-by: —

**Why.** HMAC sends no secret on the wire and binds requests to a namespace.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 114.

### NODE-JOB-06 — Claim is a CAS inside one owner
- old: R97(claim) · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-06 · superseded-by: —

**Why.** With one owner process a claim is a compare-and-set, no distributed lock.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 120.

### NODE-JOB-07 — Cancel is a node CAS
- old: R98(node) · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-07 · superseded-by: —

**Why.** Cancel races with leasing; a CAS in the node decides it once.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 121.

### NODE-JOB-08 — Relayer-bound jobs pinned to their lane
- old: R102 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-08 · superseded-by: —

**Why.** A relayer-bound intent can only be landed by its lane.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 126.

### NODE-JOB-09 — call jobs are a namespace capability
- old: R103 · status: current · owner: no · date: 2026-10-07 · normative: node/job-api.md#NODE-JOB-09 · superseded-by: —

**Why.** Only namespaces that need calls may make them.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 127.

### NODE-JOB-10 — Per-chain pull/push flag, then removal
- old: R104 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-10 · superseded-by: —

**Why.** Clients move chain by chain from pull to push; legacy code is removed in one step once all chains are on push.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 128.

### NODE-JOB-11 — Cancel-by-origin tombstones bounded
- old: R323 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-11 · superseded-by: —

**Why.** Tombstones for jobs not yet pushed must not grow without bound.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 140.

### NODE-JOB-12 — Empty namespace token subset means none
- old: R324 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-12 · superseded-by: —

**Why.** An empty subset must not mean 'all tokens'; fail closed.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 141.

### NODE-JOB-13 — Live-call uniqueness per namespace
- old: R325 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-13 · superseded-by: —

**Why.** Live-call dedupe per namespace prevents one tenant from blocking another's call.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 142.

### NODE-JOB-14 — Intake authority re-checked in insert tx
- old: R327 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-14 · superseded-by: —

**Why.** Grants may change between check and insert; re-checking in the transaction closes the race.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 144.

### NODE-JOB-15 — Migrated ERP namespace gets allow_call
- old: NI:I1 · status: open · owner: no · date: 2026-10-07 · normative: node/job-api.md#NODE-JOB-15 · superseded-by: —

**Why.** A migrated ERP client needs calls it used before; default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1610.

### NODE-JOB-16 — Shared namespace via origin.scope
- old: NI:I3 · status: open · owner: no · date: 2026-10-07 · normative: node/job-api.md#NODE-JOB-16 · superseded-by: —

**Why.** Several entities of one client can share a namespace if origin.scope separates their keys; default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1612.

### NODE-JOB-17 — Cancel of published job reports already sent
- old: NI:I5 · status: open · owner: no · date: 2026-10-07 · normative: node/job-api.md#NODE-JOB-17 · superseded-by: —

**Why.** A published job may land; cancel reports that instead of pretending.
**Cost if wrong.** Default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1614.

### NODE-JOB-18 — Tombstone quota and rate defaults
- old: NI:I8(tombstones) · status: open · owner: no · date: 2026-10-07 · normative: node/job-api.md#NODE-JOB-18 · superseded-by: —

**Why.** Default quotas bound tombstone abuse; default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1619.

### NODE-JOB-19 — Call table: permissionless selectors, role-holder Safe row
- old: reorg:Q1 · status: current · owner: yes · date: 2026-10-07 · normative: node/job-api.md#NODE-JOB-19 · superseded-by: —

**Why.** Permissionless and self-authenticating calls cannot be abused through our lane; a role holder executes only what its owners signed. The factory stays excluded.
**Source.** [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) line 1215.

### NODE-JOB-80 — Node talks to ERP only over json/2
- old: R6 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: ARCH-POS-05, NODE-JOB-06, INT-ERP-16, INT-ERP-18

It said: node talks to ERP only over json/2.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 677.

### NODE-JOB-81 — Result queue default, node-configured callbacks
- old: UD:§22.9 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: NODE-IDX-04, ARCH-POS-05

It said: result queue default, node-configured callbacks.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1955.

## Submit lanes

### NODE-LANE-01 — USD-denominated gas velocity limits
- old: req:blockchain.md:usd-velocity · status: open · owner: yes · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-01 · superseded-by: —

**Why.** Limits in a reporting currency need a price source the node does not have.
**Cost if wrong.** Open; gas-unit limits apply meanwhile.
**Source.** [history/blockchain.md](history/blockchain.md) line 353.

### NODE-LANE-02 — Legacy pull: signed report idempotent, nonce held
- old: CR-PD-5 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-02 · superseded-by: —

**Why.** The legacy client may resend reports; idempotency keeps nonces consistent.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 244.

### NODE-LANE-03 — Outer tx keys behind Signer trait
- old: R15, UD:§1:custody, UD:§23.5 · status: current · owner: yes · date: 2026-10-03 · normative: node/submit-lanes.md#NODE-LANE-03 · superseded-by: —

**Why.** A Signer trait lets KMS or HSM replace local keys without touching lanes.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 715; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 43; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2233.

### NODE-LANE-04 — Never abandon an outer nonce
- old: R18 · status: current · owner: no · date: 2026-10-03 · normative: node/submit-lanes.md#NODE-LANE-04 · superseded-by: —

**Why.** A skipped nonce blocks the lane forever.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 720.

### NODE-LANE-05 — Circuit breakers never block indexing
- old: R55 · status: current · owner: no · date: 2026-10-03 · normative: node/submit-lanes.md#NODE-LANE-05 · superseded-by: —

**Why.** Breakers stop spending, never the reading of the chain.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 528.

### NODE-LANE-06 — ChainAdapter and per-lane runner
- old: R58(adapter) · status: current · owner: no · date: 2026-10-03 · normative: node/submit-lanes.md#NODE-LANE-06 · superseded-by: —

**Why.** One adapter trait per family and one runner per lane keep families independent.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 531.

### NODE-LANE-07 — Local secp256k1/ed25519 signer, KMS seam
- old: R59 · status: current · owner: no · date: 2026-10-03 · normative: node/submit-lanes.md#NODE-LANE-07 · superseded-by: —

**Why.** Local signing suffices for development and private chains; production public chains use KMS.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 532.

### NODE-LANE-08 — Lane keys: raw key or mnemonic
- old: R60 · status: current · owner: no · date: 2026-10-03 · normative: node/submit-lanes.md#NODE-LANE-08 · superseded-by: —

**Why.** A mnemonic derives many lanes from one backup.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 533.

### NODE-LANE-09 — Consumption check before bump or resend
- old: R80, UD:§22.1, UD:§22.8 · status: current · owner: yes · date: 2026-10-05 · normative: node/submit-lanes.md#NODE-LANE-09 · superseded-by: —

**Why.** A bump after the subject nonce is consumed only burns gas.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 80; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1690; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1930.

### NODE-LANE-10 — Normalize unbound relayer and feeRecipient
- old: R84, R100 · status: current · owner: no · date: 2026-10-06 · normative: node/submit-lanes.md#NODE-LANE-10 · superseded-by: —

**Why.** Unbound relayer and feeRecipient fields would let anyone redirect the fee.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 84; [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 124.

### NODE-LANE-11 — A batch is several jobs journaled together
- old: R321 · status: current · owner: no · date: 2026-10-06 · normative: node/submit-lanes.md#NODE-LANE-11 · superseded-by: —

**Why.** A batch lands several jobs in one transaction; journaling them together keeps them atomic in the store.
**Cost if wrong.** Planned.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 138.

### NODE-LANE-12 — Outer transaction is a store row
- old: R326 · status: current · owner: no · date: 2026-10-06 · normative: node/submit-lanes.md#NODE-LANE-12 · superseded-by: —

**Why.** Tracking outer transactions as rows makes bumps, gap-fills and costs auditable.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 143.

### NODE-LANE-13 — Breaker meters what the lane pays
- old: R340 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-13 · superseded-by: —

**Why.** Budgets must meter what the lane actually pays, including failures.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 146.

### NODE-LANE-14 — One retry after billed failure, attempt cap
- old: R341 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-14 · superseded-by: —

**Why.** A failure that cost gas is retried once; more retries are a grief vector.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 147.

### NODE-LANE-15 — Per-subject grief score, every family
- old: R342 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-15 · superseded-by: —

**Why.** Subjects that repeatedly cost us gas get throttled, on every family.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 148.

### NODE-LANE-16 — Signed fields read from the payload
- old: R344 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-16 · superseded-by: —

**Why.** The payload is what the chain executes; read fields from it.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 150.

### NODE-LANE-17 — Value out per job capped
- old: R345 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-17 · superseded-by: —

**Why.** Value out of the lane must be capped per job.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 151.

### NODE-LANE-18 — Lane-funded deposits refunded or bounded
- old: R346 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-18 · superseded-by: —

**Why.** Deposits funded by the lane must come back or stay bounded.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 152.

### NODE-LANE-19 — Adapter journals live in the store
- old: R347 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-19 · superseded-by: —

**Why.** Adapter journals in the store survive restarts and restores with the rest.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 153.

### NODE-LANE-20 — One custody key per family
- old: R349 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-20 · superseded-by: —

**Why.** Raw-digest signing on several families needs exactly one custody key per family.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 155.

### NODE-LANE-21 — outer_tx row for every signed tx
- old: NI:I8(outer-tx) · status: open · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-21 · superseded-by: —

**Why.** Every signed transaction gets a row so none is lost from tracking; default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1619.

### NODE-LANE-22 — Node simulates unwrap jobs, never batches them
- old: R148(node) · status: current · owner: yes · date: 2026-10-06 · normative: node/submit-lanes.md#NODE-LANE-22 · superseded-by: —

**Why.** Unwraps move value out; full simulation catches failures, and batching would mix them.
**Source.** [history/specs/2026-10-06-token-wrappers-v2.md](history/specs/2026-10-06-token-wrappers-v2.md) line 172.

### NODE-LANE-23 — Simulation gate before every broadcast
- old: — · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-23 · superseded-by: —

**Why.** Simulating before broadcast keeps predictable reverts from spending gas; a simulation that cannot run fails closed.
**Cost if wrong.** Some reverts remain (state changes between simulation and inclusion); they are measured (W3B-02).

### NODE-LANE-80 — Six-member Family enum
- old: R58(family-enum) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: ARCH-POS-02

It said: six-member Family enum.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 531.

## Indexer and feeds

### NODE-IDX-01 — Finality quorum over normalized event sets
- old: CR-PD-2, CR-R3-2 · status: current · owner: no · date: 2026-10-07 · normative: node/indexer-feeds.md#NODE-IDX-01 · superseded-by: —

**Why.** Comparing one block hash cannot detect a provider that drops or invents logs; comparing the normalized event set can.
**Cost if wrong.** A lying RPC books fake payments.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 275; [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 646.

### NODE-IDX-02 — Node decides finality: depth or tag
- old: R11(gate) · status: current · owner: no · date: 2026-10-06 · normative: node/indexer-feeds.md#NODE-IDX-02 · superseded-by: —

**Why.** Finality differs per family; the node, not the client, applies the right rule.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 699.

### NODE-IDX-03 — No reorg handling after hard finality
- old: R12 · status: current · owner: no · date: 2026-10-03 · normative: node/indexer-feeds.md#NODE-IDX-03 · superseded-by: —

**Why.** Hard finality is the model's base; reorg handling after it would add complexity for an event outside the model.
**Cost if wrong.** A violation needs manual reconciliation (runbook).
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 703.

### NODE-IDX-04 — Change feeds for jobs and events
- old: R93 · status: current · owner: no · date: 2026-10-06 · normative: node/indexer-feeds.md#NODE-IDX-04 · superseded-by: —

**Why.** Clients poll two cursors (jobs, events) instead of receiving callbacks the node must retry.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 115.

### NODE-IDX-05 — Event feed items equal ingest arguments
- old: R94 · status: current · owner: no · date: 2026-10-06 · normative: node/indexer-feeds.md#NODE-IDX-05 · superseded-by: —

**Why.** Feed items carry exactly what the ingest needs, so clients do not re-read the chain.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 116.

### NODE-IDX-06 — Repeated entryRef handling on the feed
- old: NI:I6 · status: open · owner: no · date: 2026-10-07 · normative: node/indexer-feeds.md#NODE-IDX-06 · superseded-by: —

**Why.** A repeated entryRef is a client-side matching question; the feed reports facts only.
**Cost if wrong.** Default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1615.

### NODE-IDX-07 — Second independent event source
- old: reorg:Q7 · status: open · owner: yes · date: 2026-10-07 · normative: node/indexer-feeds.md#NODE-IDX-07 · superseded-by: —

**Why.** A compromised node can lie on its feed; a second independent source would detect it.
**Cost if wrong.** Planned.
**Source.** [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) line 1221.

### NODE-IDX-80 — Quorum on one block hash
- old: R11(quorum) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: NODE-IDX-01

It said: quorum on one block hash.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 699.

## Gateway

### NODE-GW-01 — Door A is not a free gas faucet
- old: CR-PD-3 · status: current · owner: no · date: 2026-10-07 · normative: node/gateway.md#NODE-GW-01 · superseded-by: —

**Why.** A public door that relays fee-0 intents from fresh keys is a free gas faucet.
**Cost if wrong.** Lane gas drained, breaker trips.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 891.

### NODE-GW-02 — Gateway auth bearer or hmac
- old: R54 · status: current · owner: no · date: 2026-10-06 · normative: node/gateway.md#NODE-GW-02 · superseded-by: —

**Why.** Operators choose an open or authenticated door; one credential kind per listener.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 527.

### NODE-GW-03 — Gateway call jobs only for UA registration
- old: R320 · status: current · owner: no · date: 2026-10-06 · normative: node/gateway.md#NODE-GW-03 · superseded-by: —

**Why.** Only UA registration needs a call through the gateway; everything else is signed by subjects.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 137.

### NODE-GW-04 — Gateway CORS only with auth none
- old: R328 · status: current · owner: no · date: 2026-10-06 · normative: node/gateway.md#NODE-GW-04 · superseded-by: —

**Why.** Browsers may call an open gateway directly; with credentials, CORS would expose them.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 145.

### NODE-GW-05 — Gateway info route, CORS, error contract
- old: R159(gateway) · status: current · owner: no · date: 2026-10-06 · normative: node/gateway.md#NODE-GW-05 · superseded-by: —

**Why.** Clients discover what a gateway serves before they sign.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 113.

### NODE-GW-06 — Stable gateway error contract
- old: R178 · status: current · owner: no · date: 2026-10-06 · normative: node/gateway.md#NODE-GW-06 · superseded-by: —

**Why.** Wallets and apps branch on error codes; a stable contract keeps them working across releases.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 132.

### NODE-GW-80 — Three intake doors with trust levels
- old: UD:§22.2 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05, NODE-GSP-01, NODE-GSP-04

It said: three intake doors with trust levels.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1750.

## Admin and auth

### NODE-ADM-01 — Gossip admin routes and columns
- old: R127(admin) · status: current · owner: no · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-01 · superseded-by: —

**Why.** Gossip state (peers, scores, bans, trust) is operator data like any other; one admin surface keeps one auth and audit path.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 88.

### NODE-ADM-02 — Admin auth: built-in users plus optional OIDC
- old: R106 · status: current · owner: yes · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-02 · superseded-by: —

**Why.** Small deployments need no IdP; organisations with one get SSO. Two modes, one role model.
**Cost if wrong.** A deployment without OIDC relies on node passwords; Argon2id and lockout bound guessing.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 1021.

### NODE-ADM-03 — OIDC JWT validation rules
- old: R106a(oidc) · status: current · owner: yes · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-03 · superseded-by: —

**Why.** A strict, allowlisted validator closes the known JWT confusion attacks (alg, key, audience, ID-token-as-access).
**Cost if wrong.** A lax check is an admin takeover.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 131.

### NODE-ADM-04 — Admin roles and no escalation
- old: R107 · status: current · owner: yes · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-04 · superseded-by: —

**Why.** Separating config power from credential power makes fee redirection or key minting a two-role act.
**Cost if wrong.** One person holding both can still misuse; the RACI procedure covers it.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 132.

### NODE-ADM-05 — Bootstrap and break-glass via host CLI
- old: R108 · status: current · owner: yes · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-05 · superseded-by: —

**Why.** The first admin and recovery must work with no running API and no IdP; host access already implies full power.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 133.

### NODE-ADM-06 — API keys and admin credentials never cross
- old: R109 · status: current · owner: no · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-06 · superseded-by: —

**Why.** A leaked client key must never reach configuration, and admin credentials must never be scripted into clients.
**Cost if wrong.** Mixing them turns a client compromise into a node compromise.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 134.

### NODE-ADM-07 — Hash-chained audit log per mutation
- old: R110(audit) · status: current · owner: no · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-07 · superseded-by: —

**Why.** A hash chain makes silent edits of the audit table detectable; the off-host log mirror survives store loss.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 135.

### NODE-ADM-08 — Admin-user mutations never exceed caller
- old: R322 · status: current · owner: no · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-08 · superseded-by: —

**Why.** Without the superset rule an operator could create or reset a stronger admin and take over.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 139.

### NODE-ADM-09 — LAST_ADMIN counts built-in users only
- old: NI:I8(last-admin) · status: open · owner: no · date: 2026-10-07 · normative: node/admin-auth.md#NODE-ADM-09 · superseded-by: —

**Why.** OIDC callers are not node users; counting them would let an IdP change lock the node out.
**Cost if wrong.** Default applied; an owner may revisit.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1619.

### NODE-ADM-10 — App serving with CSP on admin listener
- old: R159(serving) · status: current · owner: no · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-10 · superseded-by: —

**Why.** Serving the console from the node avoids a second web host; a strict CSP bounds script injection.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 113.

### NODE-ADM-11 — App served only on admin listener
- old: R160 · status: current · owner: no · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-11 · superseded-by: —

**Why.** The public listeners stay API-only; static files there would widen their attack surface.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 114.

### NODE-ADM-80 — JWS verification on ring
- old: R106a(ring) · status: superseded · owner: yes · date: 2026-10-06 · normative: — · superseded-by: NODE-GSP-03

It said: jWS verification on ring.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 131.

## Sponsorship

### NODE-SPN-01 — Sponsorship policy is a node store row
- old: R189 · status: current · owner: yes · date: 2026-10-07 · normative: node/sponsorship.md#NODE-SPN-01 · superseded-by: —

**Why.** Sponsorship is an operator choice, configured as data, matched per job.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 132.

### NODE-SPN-02 — Budget unit, reservation and rate counters
- old: R190 · status: current · owner: no · date: 2026-10-07 · normative: node/sponsorship.md#NODE-SPN-02 · superseded-by: —

**Why.** Budgets in native units are exact; reservations at accept prevent overspend.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 152.

### NODE-SPN-03 — Sponsorship admin routes and audit
- old: R191 · status: current · owner: no · date: 2026-10-06 · normative: node/sponsorship.md#NODE-SPN-03 · superseded-by: —

**Why.** Sponsorship changes spend money; they are admin-only and audited.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 167.

### NODE-SPN-04 — SponsorshipPool opt-in contract, mesh fee-only
- old: R194 · status: current · owner: no · date: 2026-10-06 · normative: node/sponsorship.md#NODE-SPN-04 · superseded-by: —

**Why.** An on-chain pool lets sponsors fund relays without trusting one node; on the mesh only the fee path applies.
**Cost if wrong.** Planned.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 199.

## DEX venue

### NODE-DEX-01 — Durable off-chain book, price-time, partial fills
- old: R35(book) · status: current · owner: yes · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-01 · superseded-by: —

**Why.** A venue needs a durable book that survives restarts and serves partial fills in a fair order.
**Cost if wrong.** A lost book cancels resting orders silently.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 554.

### NODE-DEX-02 — Fee token limited; failed pairs attributed by evidence
- old: RS5-13 · status: current · owner: no · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-02 · superseded-by: —

**Why.** Settlement failures must be pinned on the party whose signed data caused them, from chain evidence, not guessed.
**Cost if wrong.** Wrong attribution punishes honest makers.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 271.

### NODE-DEX-03 — No WebSocket; clients poll
- old: RS5-5 · status: current · owner: no · date: 2026-10-03 · normative: node/dex-venue.md#NODE-DEX-03 · superseded-by: —

**Why.** Polling is enough for book depth and trades and keeps the node free of long-lived push connections.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 406.

### NODE-DEX-04 — DEX watcher has its own cursor
- old: RS5-8 · status: current · owner: no · date: 2026-10-06 · normative: node/dex-venue.md#NODE-DEX-04 · superseded-by: —

**Why.** The DEX watcher reads different events at a different pace; its own cursor keeps it independent of the main indexer.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 410.

### NODE-DEX-05 — Rounding dust: skip and remove dust makers
- old: RS5-12 · status: current · owner: no · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-05 · superseded-by: —

**Why.** Fills that round to zero cannot settle; skipping and removing dust makers keeps the book matchable.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 420.

### NODE-DEX-06 — OOG ERC-1271 orders are never restored
- old: RS5-14(node) · status: current · owner: no · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-06 · superseded-by: —

**Why.** An ERC-1271 check that ran out of gas cannot be proven valid again; restoring it would loop failures.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 431.

### NODE-DEX-07 — Committed balance includes unsettled fills
- old: RS5-16 · status: current · owner: no · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-07 · superseded-by: —

**Why.** Counting unsettled fills in the committed balance prevents over-commitment of one maker's funds.
**Cost if wrong.** Without it a maker can be matched beyond what it holds.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 442.

### NODE-DEX-08 — Re-check on-chain market every poll
- old: RS5-17 · status: current · owner: no · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-08 · superseded-by: —

**Why.** Markets can be paused or changed on chain at any time; the venue must notice within one poll.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 444.

### NODE-DEX-09 — IOC single maker on Move/Solana
- old: RS5-18 · status: current · owner: no · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-09 · superseded-by: —

**Why.** Move and Solana settle one maker per transaction; multi-maker IOC would need atomicity they lack.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 446.

### NODE-DEX-10 — Late settled trade debits restored order
- old: RS5-20(r105) · status: current · owner: no · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-10 · superseded-by: —

**Why.** A trade that settles after its order was restored must still reduce that order, else it is filled twice.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 449.

### NODE-DEX-11 — Managed markets: home-bound, eligibility at intake
- old: R214(node) · status: current · owner: yes · date: 2026-10-06 · normative: node/dex-venue.md#NODE-DEX-11 · superseded-by: —

**Why.** Managed markets enforce eligibility on chain; checking at intake avoids matches that would revert.
**Source.** [history/specs/2026-10-06-asset-suite-design.md](history/specs/2026-10-06-asset-suite-design.md) line 176.

### NODE-DEX-12 — DEX book gossip, two order modes
- old: R124 · status: current · owner: yes · date: 2026-10-06 · normative: node/dex-venue.md#NODE-DEX-12 · superseded-by: —

**Why.** Book gossip lets several venues show one market; two modes separate home-bound orders from settle-by-anyone orders.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 85.

### NODE-DEX-13 — DEX homes trusted automatically
- old: R128 · status: current · owner: yes · date: 2026-10-06 · normative: node/dex-venue.md#NODE-DEX-13 · superseded-by: —

**Why.** Wallets need a default set of homes that settle honestly; trust is earned from chain-credited settles.
**Cost if wrong.** Auto-trust can be farmed; the credit rules bound it.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 89.

### NODE-DEX-14 — DEX book lives in the node store
- old: R105 · status: current · owner: no · date: 2026-10-06 · normative: node/dex-venue.md#NODE-DEX-14 · superseded-by: —

**Why.** The book belongs to the node's single store, with one owner and one backup story.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 129.

### NODE-DEX-80 — DEX book persisted in ERP
- old: RS5-2 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: NODE-DEX-14

It said: dEX book persisted in ERP.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 13.

### NODE-DEX-81 — Book accepts only own-relayer orders
- old: RS5-9 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: NODE-DEX-12

It said: book accepts only own-relayer orders.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 15.

### NODE-DEX-82 — DEX chains run one lane only
- old: RS5-11 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: NODE-JOB-08

It said: dEX chains run one lane only.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 16.

## Mesh

### NODE-MESH-01 — Pull bus for admitted peers
- old: R70 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-01 · superseded-by: —

**Why.** Admitted partners exchange intents by pull; the receiver controls its load.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 70.

### NODE-MESH-02 — Commit-ordered bus seq and store id
- old: R71(seq) · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-02 · superseded-by: —

**Why.** A commit-ordered seq gives gap-free cursors; a new store id resets them after a restore.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 71.

### NODE-MESH-03 — mTLS peers pinned by SPKI, Ed25519
- old: R72 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-03 · superseded-by: —

**Why.** SPKI pins need no CA and identify peers by key.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 72.

### NODE-MESH-04 — Origin is in its own round-robin
- old: MESH:I1, MESH:I2, MESH:I3, R74, UD:§22.5 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-04 · superseded-by: —

**Why.** Round-robin exclusivity shares submissions fairly; the origin takes its turn too.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 1386; [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 1387; [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 1388; [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 74; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1842.

### NODE-MESH-05 — Mesh reward is the intent fee only
- old: R75 · status: current · owner: yes · date: 2026-10-05 · normative: node/mesh.md#NODE-MESH-05 · superseded-by: —

**Why.** The intent fee is the only reward; no token, no extra economics.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 75.

### NODE-MESH-06 — Chain profile, default private
- old: R76 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-06 · superseded-by: —

**Why.** Chains default to private so nothing leaks before an operator opts in.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 76.

### NODE-MESH-07 — Families on the bus; Soroban out
- old: R77 · status: current · owner: yes · date: 2026-10-05 · normative: node/mesh.md#NODE-MESH-07 · superseded-by: —

**Why.** v1 covers families whose intents are self-contained; Soroban is not.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 77.

### NODE-MESH-08 — intent_id is the contract digest
- old: R78 · status: current · owner: yes · date: 2026-10-05 · normative: node/mesh.md#NODE-MESH-08 · superseded-by: —

**Why.** Using the contract's digest as id lets every node dedupe and match events without a separate registry.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 78.

### NODE-MESH-09 — Envelope spec scaas-intent/1.2
- old: R81 · status: current · owner: no · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-09 · superseded-by: —

**Why.** A versioned, public envelope lets independent implementations interoperate.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 81.

### NODE-MESH-10 — Mesh numbers, all config
- old: R82 · status: current · owner: no · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-10 · superseded-by: —

**Why.** All mesh numbers are configuration, with published defaults.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 82.

### NODE-MESH-11 — Multi-process one-binary test topology
- old: R83, UD:§21.3 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-11 · superseded-by: —

**Why.** Several processes of one binary test the mesh as deployed. Two processes of one binary with different configuration catch wire-format errors but not misreadings of the spec; only the public conformance vectors stand in for a second implementation, so they must be complete, not token.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 83; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1365.

### NODE-MESH-12 — Private rows served only by origin
- old: R85 · status: current · owner: no · date: 2026-10-05 · normative: node/mesh.md#NODE-MESH-12 · superseded-by: —

**Why.** Private rows never leave their origin, so no forwarder can leak them.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 85.

### NODE-MESH-13 — may_submit needs a registered token
- old: R86, UD:§22.6 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-13 · superseded-by: —

**Why.** A node only submits for tokens it knows and has registered.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 86; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1877.

### NODE-MESH-14 — Missing policy row means forward only
- old: MESH:I4 · status: current · owner: yes · date: 2026-10-05 · normative: node/mesh.md#NODE-MESH-14 · superseded-by: —

**Why.** Without a policy row the safe default is forward-only.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 1389.

### NODE-MESH-15 — Bus scope arrives per job
- old: R99 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-15 · superseded-by: —

**Why.** Bus scope belongs to each job, set by its producer.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 1020.

### NODE-MESH-16 — Verify signatures before any chain call
- old: R343 · status: current · owner: no · date: 2026-10-07 · normative: node/mesh.md#NODE-MESH-16 · superseded-by: —

**Why.** Signature checks before chain calls stop forged intents from costing RPC.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 149.

### NODE-MESH-17 — receiver_fee jobs use restricted bus scope
- old: R193(node) · status: current · owner: no · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-17 · superseded-by: —

**Why.** A receiver-fee co-signature must not travel to open peers.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 181.

### NODE-MESH-18 — UA intents in scaas-intent/1.3
- old: R316 · status: current · owner: no · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-18 · superseded-by: —

**Why.** UA intents need a different body; a minor version keeps old nodes safe.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 320.

### NODE-MESH-19 — Fee-0 intents allowed; acceptance policy decides
- old: UD:§3.4b · status: current · owner: yes · date: 2026-08-30 · normative: node/mesh.md#NODE-MESH-19 · superseded-by: —

**Why.** Fee-0 intents are legitimate for sponsored or B2B flows; the acceptance policy decides.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 179.

### NODE-MESH-20 — Node is a capability matrix, not modes
- old: UD:§21.4 · status: current · owner: yes · date: 2026-08-31 · normative: node/README.md#NODE-MESH-20 · superseded-by: —

**Why.** Capabilities combine freely; fixed modes would need a second implementation. The earlier "Mode 1 / mode 2" split suggested a global enum, while there are three independent axes (ingest, pool, submit) and submit varies per `(chain, contract)`: a node may submit on one chain and only forward for another. The gateway shape is the old "mode 1". The research shapes "private pool" and "private relayer" (a private-mempool pair) showed that the mesh needs a pull mode next to gossip, with an explicit peer allowlist instead of discovery; the bus pull with pinned peers is that mode (the research table had called the mesh module "ingest + pool" and assumed gossip). Two queues shared the name "pool": the mesh-facing intent queue and the submit job queue, which exists even when nothing is pooled; the research note named "relay-pool" described the second. The store is now the mesh-facing queue.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1394.

### NODE-MESH-21 — One policy lookup table, static columns
- old: UD:§22.4 · status: current · owner: yes · date: 2026-08-31 · normative: node/mesh.md#NODE-MESH-21 · superseded-by: —

**Why.** One lookup with static columns keeps acceptance cheap and predictable.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1817.

### NODE-MESH-22 — Open lifecycle questions
- old: UD:§22.10 · status: open · owner: yes · date: 2026-08-31 · normative: node/mesh.md#NODE-MESH-22 · superseded-by: —

**Why.** Two lifecycle questions stay open until real traffic answers them.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1997.

### NODE-MESH-23 — MAX_HOPS = 4 is arbitrary
- old: UD:§22.10.1 · status: open · owner: yes · date: 2026-08-31 · normative: node/mesh.md#NODE-MESH-23 · superseded-by: —

**Why.** Four hops is a guess; re-tuned after a multi-site run. "Arbitrary" marks a number with no measurement behind it; node docs label such defaults so they are re-tuned after a measured run.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1999.

### NODE-MESH-24 — Soroban stays on the job API, not the mesh
- old: reorg:Q6 · status: open · owner: yes · date: 2026-10-07 · normative: node/mesh.md#NODE-MESH-24 · superseded-by: —

**Why.** Soroban intents need simulation footprints a forwarder cannot verify; job API only until a design exists.
**Cost if wrong.** Default applied.
**Source.** [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) line 1220.

### NODE-MESH-80 — R68-R69 left unused
- old: R68, R69 · status: unused · owner: no · date: 2026-10-05 · normative: — · superseded-by: —

Numbers left unused in the old scheme; registered so the alias index is complete.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 5.

### NODE-MESH-81 — Mesh SQLite store, ERP control plane
- old: R71(store) · status: superseded · owner: yes · date: 2026-10-05 · normative: — · superseded-by: ARCH-POS-05, NODE-STO-04, NODE-JOB-02, NODE-DEX-14, NODE-STO-06

It said: mesh SQLite store, ERP control plane.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 71.

### NODE-MESH-82 — Acceptance policy authoritative in ERP
- old: R79 · status: superseded · owner: yes · date: 2026-10-05 · normative: — · superseded-by: NODE-STO-03, NODE-MESH-15

It said: acceptance policy authoritative in ERP.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 79.

### NODE-MESH-83 — Open relayer: two modes, two implementations
- old: UD:§21 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: NODE-MESH-20, ARCH-POS-05

It said: open relayer: two modes, two implementations.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1304.

### NODE-MESH-84 — Relay-only vs network-node modes
- old: UD:§21.1 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: NODE-MESH-20

It said: relay-only vs network-node modes.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1316.

### NODE-MESH-85 — Lifecycle common to Rust and ERP nodes
- old: UD:§22 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05

It said: lifecycle common to Rust and ERP nodes.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1671.

### NODE-MESH-86 — Queue clocks and promote-after window
- old: UD:§22.7 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: INT-ERP-15, NODE-MESH-10

It said: queue clocks and promote-after window.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1912.

### NODE-MESH-87 — promote_after vs 300 s ERC-20 expiry
- old: UD:§22.10.2 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: INT-ERP-15

It said: promote_after vs 300 s ERC-20 expiry.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2001.

### NODE-MESH-88 — Callback subject registry on public nodes
- old: UD:§22.10.4 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05

It said: callback subject registry on public nodes.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2008.

## Gossip

### NODE-GSP-01 — Gossip required alongside the pull bus
- old: R112, UD:§6 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-01 · superseded-by: —

**Why.** The pull bus covers admitted partners; gossip reaches the open network. Both are needed. The open network uses libp2p gossipsub v1.1 instead of a home-grown protocol: it is the stack the ERC-4337 shared mempool mandates (`eth-infinitism/bundler-spec/p2p-specs/p2p-interface.md`), and its peer scoring is the network-layer anti-spam primitive; intents are validated before they are forwarded, so spam costs real money.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 73; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 224.

### NODE-GSP-02 — Selectable carriers; admitted peers PQ only
- old: R113 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-02 · superseded-by: —

**Why.** QUIC is the default; TCP covers networks that block UDP. Admitted peers carry private data, so PQ only.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 74.

### NODE-GSP-03 — PQ key exchange via aws-lc-rs, classical identity
- old: R114 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-03 · superseded-by: —

**Why.** Harvest-now-decrypt-later threatens key exchange today; identity forgery needs a live quantum attacker. One crypto library keeps the build small.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 75.

### NODE-GSP-04 — Wire names and topics use scaas and chain_key
- old: R115 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-04 · superseded-by: —

**Why.** Product-neutral names and chain keys make topics unambiguous across networks.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 76.

### NODE-GSP-05 — One Ed25519 node key for all identities
- old: R116 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-05 · superseded-by: —

**Why.** One key and separate signing contexts make rotation one action and keep signatures non-interchangeable.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 77.

### NODE-GSP-06 — Gossip wire is bus JSON, content message-id
- old: R117 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-06 · superseded-by: —

**Why.** Reusing the bus JSON keeps one codec; a content-addressed message id makes duplicates collapse.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 78.

### NODE-GSP-07 — Gossip validation pipeline and Reject rule
- old: R118, UD:§22.3 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-07 · superseded-by: —

**Why.** Rejects cost the sender score; only faults decidable from the bytes may reject, so honest peers are never punished. Checking the meta nonce with `eth_call` at receipt is exact but does not run at gossip speed: a node receiving 500 intents a second would make 500 RPC calls a second just to filter garbage. The freshness check is therefore one batched read, off the event loop and failing open for forwarding.
**Cost if wrong.** Over-rejecting eclipses a node by itself.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 79; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1767.

### NODE-GSP-08 — Peer scoring and limits
- old: R119 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-08 · superseded-by: —

**Why.** Fixed, published scoring numbers make peer behaviour predictable and testable.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 80.

### NODE-GSP-09 — Own Kademlia DHT with dial filter
- old: R120 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-09 · superseded-by: —

**Why.** An own DHT namespace and dial filter stop the node from being used to scan private networks.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 81.

### NODE-GSP-10 — Exclusivity over gossip, automatic trust
- old: R121 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-10 · superseded-by: —

**Why.** Exclusivity reduces duplicate submissions; automatic trust requires a chain-credited track record.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 82.

### NODE-GSP-11 — Landed hints only trigger a chain read
- old: R122 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-11 · superseded-by: —

**Why.** A hint can be false; only a chain read may change state.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 83.

### NODE-GSP-12 — Signed versioned announce
- old: R123 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-12 · superseded-by: —

**Why.** Announces are signed and versioned so replays and rollbacks are refused.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 84.

### NODE-GSP-13 — Anti-entropy sync protocol
- old: R125 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-13 · superseded-by: —

**Why.** Anti-entropy fills gaps after partitions without replaying the whole pool.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 86.

### NODE-GSP-14 — Gossip crates and resource budget
- old: R126 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-14 · superseded-by: —

**Why.** Pinned crates and a resource budget keep gossip from crowding the host.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 87.

### NODE-GSP-15 — Native UA verification before gossip
- old: R317 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-15 · superseded-by: —

**Why.** UA intents must be verified natively before forwarding, else invalid ones spread.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 327.

### NODE-GSP-16 — Sybil resistance of forward scoring
- old: UD:§22.10.3 · status: open · owner: yes · date: 2026-08-31 · normative: node/gossip.md#NODE-GSP-16 · superseded-by: —

**Why.** Forward scoring can be gamed by Sybils; no known cheap fix.
**Cost if wrong.** Open.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2004.

### NODE-GSP-80 — rustls ring crypto provider
- old: — · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: NODE-GSP-03

An earlier design used the rustls ring provider for TLS; replaced by aws-lc-rs for PQ key exchange.

## Operations

### NODE-OPS-01 — readyz and metrics on admin port
- old: R51 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-01 · superseded-by: —

**Why.** Monitoring must not depend on the public gateway; the admin port always exists.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 524.

### NODE-OPS-02 — Gossip metrics
- old: R127(metrics) · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-02 · superseded-by: —

**Why.** Gossip health is visible without per-peer labels, which would be unbounded.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 88.

### NODE-OPS-03 — Prometheus metrics, label allowlist
- old: R230 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-03 · superseded-by: —

**Why.** A hand-written renderer avoids a dependency; the label allowlist keeps cardinality bounded.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 61.

### NODE-OPS-04 — SLOs evaluated outside the node
- old: R231 · status: current · owner: yes · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-04 · superseded-by: —

**Why.** Monitoring on the monitored host fails with it; an external dead-man's switch catches that.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 71.

### NODE-OPS-05 — Three severities
- old: R232 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-05 · superseded-by: —

**Why.** Pages that do not mean integrity or outage train people to ignore pages.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 77.

### NODE-OPS-06 — W3B as the node measures it
- old: R233 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-06 · superseded-by: —

**Why.** Each job counts once; landed-elsewhere is success; a revert streak opens a breaker.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 79.

### NODE-OPS-07 — Job stage timing metric
- old: R234 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-07 · superseded-by: —

**Why.** Stage timings show where latency comes from; in-memory samples lost on restart are acceptable.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 92.

### NODE-OPS-08 — Ops watch for registered tokens
- old: R235 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-08 · superseded-by: —

**Why.** Leg backing needs node data; code-hash pins need none, so they stay outside the node.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 99.

### NODE-OPS-09 — Traces without OpenTelemetry SDK
- old: R236 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-09 · superseded-by: —

**Why.** OpenTelemetry would be the heaviest dependency set; logs plus job events already trace a job.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 109.

### NODE-OPS-10 — JSON logs, redaction, retention
- old: R237 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-10 · superseded-by: —

**Why.** Logs must never carry personal or secret data; retention bounds what a node holds.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 114.

### NODE-OPS-11 — FinOps measurement and usage_day
- old: R238 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-11 · superseded-by: —

**Why.** Jobs are purged after 30 days; a durable daily rollup keeps a fiscal year of cost data.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 124.

### NODE-OPS-12 — Integrity rechecks of index and audit
- old: R242 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-12 · superseded-by: —

**Why.** A finality violation or audit break is a human-judgement event; holding stops the damage.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 162.

### NODE-OPS-13 — Capacity rating and label caps
- old: R244 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-13 · superseded-by: —

**Why.** Unbounded labels are a monitoring outage; caps are constants.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 176.

### NODE-OPS-14 — Subject denylist, operator choice
- old: R246 · status: current · owner: yes · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-14 · superseded-by: —

**Why.** An order binds the operator it is addressed to; a precise, evidenced lever beats pausing a namespace.
**Cost if wrong.** No on-chain effect; the party can use other operators.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 185.

### NODE-OPS-15 — Operators independent; ops are recommendations
- old: R247, UD:§13.1 · status: current · owner: yes · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-15 · superseded-by: —

**Why.** Contracts carry the guarantees; node operators are independent and set their own policies.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 192; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 706.

### NODE-OPS-16 — OPS default numbers approved as stated
- old: reorg:Q8 · status: current · owner: yes · date: 2026-10-07 · normative: node/ops.md#NODE-OPS-16 · superseded-by: —

**Why.** Defaults are needed to start; each stays operator-tunable.
**Source.** [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) line 1222.

## Runbooks

### NODE-RUN-01 — RACI roles
- old: R239 · status: current · owner: no · date: 2026-10-06 · normative: node/runbooks.md#NODE-RUN-01 · superseded-by: —

**Why.** Separating credential power from config power, and roles across keys, bounds single-person misuse.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 130.

### NODE-RUN-02 — Restore is fixed and starts paused
- old: R240 · status: current · owner: no · date: 2026-10-06 · normative: node/runbooks.md#NODE-RUN-02 · superseded-by: —

**Why.** A restored store holds jobs cancelled after the backup; starting paused gives clients time to cancel them.
**Cost if wrong.** One manual resume per chain.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 137.

### NODE-RUN-03 — CLI lane accept-nonce
- old: R241 · status: current · owner: no · date: 2026-10-06 · normative: node/runbooks.md#NODE-RUN-03 · superseded-by: —

**Why.** After a restore the chain is ahead of the journal; adopting nonces is the only way back besides a new lane.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 148.

### NODE-RUN-04 — DR drills scheduled and exported
- old: R243 · status: current · owner: no · date: 2026-10-06 · normative: node/runbooks.md#NODE-RUN-04 · superseded-by: —

**Why.** An untested restore is not a restore.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 172.

### NODE-RUN-05 — Incident command by accountable role
- old: R245 · status: current · owner: no · date: 2026-10-06 · normative: node/runbooks.md#NODE-RUN-05 · superseded-by: —

**Why.** The accountable role of the failing component leads; evidence first, no silent rewinds.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 180.

## Threat model

### NODE-SEC-01 — Merge processes, not privileges
- old: — · status: current · owner: no · date: 2026-10-07 · normative: node/threat-model.md#NODE-SEC-01 · superseded-by: —

**Why.** One process can still keep trust boundaries; bounding each credential to its listener limits compromise.

### NODE-SEC-80 — Separate DB roles per module
- old: UD:§23.4 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05, NODE-STO-04

It said: separate DB roles per module.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2211.
