# `scaas-rpc`: the shared network crate

`scaas-rpc` is the one Rust crate through which the node, `scaas-pqz-verifier`, `scaas-sdk`, the CLI and the bindings read chains,
send signed bytes, and call a scaas-node. It applies [ARCH-POS-15](../decisions.md#ARCH-POS-15) (every RPC consumer takes a list
of nodes) once, so every consumer has the same rule. Status: **BUILT** on branch `scaas-sdk` where a rule says so, the rest
SPECIFIED or PLANNED (spec `docs/superpowers/specs/2026-11-17-scaas-rpc.md`, plan `docs/superpowers/plans/2026-11-17-scaas-rpc.md`
T1–T22, the gates and commits in `clients/scaas-rpc/runs/2026-11-17-scaas-rpc-summary.txt`; the spec reviewed by Fable 2026-11-17,
the EVM part by Fable in plan T13; the families' review is plan T24, pending). Path: `clients/scaas-rpc` (owner 2026-11-17,
[CLI-RPC-50](../decisions.md#CLI-RPC-50)). Compiles for wasm32 (CI job), not run there. UNAUDITED.

**Contents**

1. [Scope](#1-scope)
2. [Endpoints and the node list](#2-endpoints-and-the-node-list)
3. [Reads](#3-reads)
4. [Writes and transaction state](#4-writes-and-transaction-state)
5. [Bounds and logs](#5-bounds-and-logs)
6. [The scaas-node client](#6-the-scaas-node-client)
7. [The verifier's agreement option](#7-the-verifiers-agreement-option)
8. [Errors](#8-errors)
9. [Arweave gateways and bundlers](#9-arweave-gateways-and-bundlers)

## 1. Scope

<a id="CLI-RPC-01"></a>**CLI-RPC-01** — **One network crate; no keys, no signing, no lane sends** (owner 2026-11-11, 2026-11-17;
BUILT: `clients/scaas-rpc`, plan T1; the node's EVM reads (T5), `scaas-pqz-verifier` (T8) and the node's Hedera, Soroban, Solana, NEAR, Algorand, Aptos, Sui, Cosmos and TON adapters
(T14–T22) read through it; the SDK is another branch's). `scaas-rpc` holds: the endpoint list and its read and write rules (§2–§4); a reader per chain family, EVM through
alloy first (§3.1); the scaas-node client (§6). The node's adapters, `scaas-pqz-verifier` and `scaas-sdk` read through it. It holds
no subject key, no lane key and no signer, and signs nothing: signed bytes come from `ua-rs` (apps) or from the node's lanes. The
node's lane sends (journal before broadcast, one transaction per nonce, replacement, gap-fill,
[NODE-GEN-01](../node/README.md#NODE-GEN-01)) and every decision that makes a job `dead` stay in the node; the crate gives the node
its reads and the facts those decisions read. No consumer-specific name appears in the crate. An endpoint's credential (a
gateway's secret, a provider's API key) is not a chain key; it goes to its own endpoint only and is never logged.

## 2. Endpoints and the node list

<a id="CLI-RPC-02"></a>**CLI-RPC-02** — **An endpoint is `{url, class, label, auth}`; the list keeps its order** (BUILT, plan T1,
T2, T13 S12: `an_empty_list_is_refused`, `a_scheme_other_than_http_is_refused`, `equal_parsed_urls_are_refused`,
`a_label_is_capped_and_stripped`, `the_credential_goes_to_its_endpoint_only`, `a_redirect_is_not_followed`; the
classes are ARCH-POS-15's). `class` is `named` (given by the operator or holder), `default` (the release's own reviewed list) or
`discovered` (found at run time by the caller; the crate discovers nothing). `label` is optional text for logs, at most 64 bytes,
control characters removed. `auth` is the endpoint's own credential and is sent to that endpoint only; a list has no list-wide
credential. When the list is built it refuses: no endpoint (`EndpointListEmpty`); a scheme other than `http` / `https`
(`EndpointScheme`); two endpoints equal in scheme, host, port and path (`Argument`; whether two URLs of one provider are independent
is the operator's to judge); a zero timeout (`Argument`); `strict_majority` with one endpoint, or with `rpc_timeout_ms` at or above `rpc_read_timeout_ms` (`Argument`: an agreed read waits for each endpoint's answer, so one hung endpoint would hold it to its deadline). A plain list of URL
strings (the node's and the verifier's `rpc_urls`) is a list of `named` endpoints in that order, without credentials. No request
follows a redirect: a 3xx is the endpoint's HTTP failure. In a browser (wasm32) the fetch follows a redirect before the crate sees it, so there an endpoint with `auth` is refused (`Argument`); a credential in the URL's path or query cannot be told apart and is the caller's to avoid. The URL may carry a credential in its path or query: it never appears in a
log line, an error or a `Debug` output (§5). A list also names its read policy: `failover` (the default) or `strict_majority`
([CLI-RPC-05](#CLI-RPC-05)).

<a id="CLI-RPC-03"></a>**CLI-RPC-03** — **An endpoint answers only for the configured chain** (BUILT for EVM and Hedera, plan T3, T4,
T13 point 6 and S16: `the_first_endpoint_is_identity_checked_too`, `a_wrong_chain_endpoint_is_dropped_for_good`,
`chain_uid_is_block_zero_and_a_wrong_pin_is_refused`; for Soroban, Solana, NEAR, Algorand, Aptos and Sui by their network id
(Sui's chain identifier compared with `params.chain_identifier` when configured, every endpoint the first included, else with the first endpoint's: T24.11, owner 2026-11-18), TON's endpoint 0 by the profile constant and a later endpoint by its masterchain root hash at the seqno endpoint 0 last showed (T24.6, owner 2026-11-18), plan
T15–T22 (`the_failover_drops_another_network_and_skips_an_endpoint_behind` per family), Cosmos's REST gateways by `node_info`'s network (T21) and its first CometBFT endpoint by `status`'s `node_info.network`; endpoint 0's own reads, outside the failover, in every family too (T24.8: `<family>_endpoint_0_of_another_network_answers_no_read`); lifted from the node,
[submit-lanes.md](../node/submit-lanes.md#rpc-failover), and [NET-ALL-22](../networks/README.md#NET-ALL-22)). Before any endpoint,
the first included, answers its first read, its identity is read and compared with the configuration: EVM and Hedera
`eth_chainId` and the block 0 hash (the pinned `chain_uid`, else the first endpoint's block 0); another family its network id where
the RPC exposes it, else the profile constant (NET-ALL-22). Equal: kept for the process. Different: the endpoint is dropped from
every read, with one log line. Unreadable: that read fails over, the identity is asked again next time. An endpoint that serves
no block 0 (a pruned node) is refused by name (`ChainIdentityUnreadable`), for the process, unless its list entry names a
checkpoint (a block number and its hash) that it then matches; it is never trusted on the pinned `chain_uid` alone. `strict_majority` and every
read that feeds a decryption ([CLI-RPC-06](#CLI-RPC-06)) need a pinned `chain_uid` (`Argument` otherwise).

## 3. Reads

<a id="CLI-RPC-04"></a>**CLI-RPC-04** — **Failover: one endpoint answers a whole read; status reads stay on the first endpoint**
(ARCH-POS-15, failover; BUILT in the crate, plan T3: `a_revert_from_the_first_is_final`,
`a_revert_from_a_later_endpoint_moves_on_and_keeps_its_data`, `a_later_endpoint_behind_the_head_is_skipped`,
`failover_answers_are_counted`, `answers_are_never_mixed`; in the node's EVM reads, T5,
[submit-lanes.md](../node/submit-lanes.md#rpc-failover); in the Hedera, Soroban, Solana, NEAR, Algorand, Aptos, Sui, Cosmos and TON adapters, plan T14–T22, each with its
`<family>_tx_status_…_never_fail_over` and `<family>_build_reads_fail_over_and_a_failover_refusal_is_no_verdict` tests and the
endpoints paragraph of its network doc).
Endpoints are asked in list order. One endpoint answers the whole read; answers of two endpoints are never mixed. The next endpoint
starts the read from scratch when the current one: fails in transport, times out, answers any HTTP error status or an error that is
no revert, answers too large, too deep or malformed (§5), is another chain ([CLI-RPC-03](#CLI-RPC-03)), or (an endpoint after the
first used) has a head below the highest block seen from the first endpoint. "The first endpoint" is the first one the read uses:
endpoint 0, or for a read that feeds a decryption the first endpoint that is not `discovered`. A revert is the contract's answer and
final only from the first endpoint; a later endpoint's revert moves the read on and its data is kept in the final error. Every
answer carries the index of the endpoint that gave it, and the crate counts the answers of later endpoints: such an answer is a
value, never a verdict (the node requeues a refusal read while the count moved). The highest block seen is raised only by the first
endpoint's heads and receipts, never lowered, and cleared by a restart. One pass over the list, no retry inside a read; every
endpoint failing is `EndpointAllFailed`, carrying the last failure. **In every family** the lane's own status reads, the
transaction status, whether an operation was consumed, the lane's nonce or sequence, its fee and a landed transaction's fee, read
the first endpoint only and never fail over; what fails over is the building of a transaction (simulations and views), under the
rules above.

<a id="CLI-RPC-05"></a>**CLI-RPC-05** — **Strict majority: the same complete answer at the same block from ⌊n/2⌋ + 1 of the list**
(ARCH-POS-15, the agreement option; SPECIFIED). `n` is the length of the list, at least 2, with a pinned `chain_uid`. (1) Every
endpoint passes CLI-RPC-03 and names its block for the read (`head − depth`, by default depth 1; `latest`; or `finalized`).
(2) The read block `b` is the (⌊n/2⌋ + 1)-th highest named number; it may not be below the highest block the list agreed on
before for the same block choice (one floor per choice; else `BehindHead`, counted as no majority). An endpoint counts at `b` only when `b` is at most `max_lag` below the number it
named itself (default 4, a list setting; else `BehindHead` for that endpoint), so a liar below ⌊n/2⌋ + 1 honest names cannot choose an
old state: the honest endpoints refuse it. (3) Each endpoint reads its header at `b` and runs the whole read pinned to that
header's hash (EIP-1898, `requireCanonical`). (4) The answers are compared as complete decoded values projected to the fields the
read defines, the block hash included, never field by field and never as raw JSON text; a revert is a value, compared by its data.
(5) As soon as ⌊n/2⌋ + 1 endpoints hold equal answers and each still carries that hash at `b`, the read stands and the other
endpoints are no longer waited for. (6) Otherwise one more round runs at the next lower named number (not below the floor of (2));
then `EndpointNoMajority`. A failing endpoint counts against the majority. Each request has its timeout and the whole read one
deadline. A read stands while at most ⌈n/2⌉ − 1 endpoints fail or lie: `n = 2` detects one liar (on content, and on the block's age
through `max_lag`) and tolerates no failure,
tolerance of one needs `n ≥ 3`, an even `n` adds nothing over `n − 1`. Simulations and gas estimates stay failover; under this policy
a new transaction's nonce is the agreed committed nonce at `b` plus the caller's own count, and fee data is the (⌊n/2⌋ + 1)-th highest
of the endpoints' values. Under `failover` the caller caps fee and gas from its own configuration, never from the answering
endpoint; in the node every family has its caps (Soroban `max_resource_fee_per_job`, Solana `max_cu` and
`max_priority_lamports`, Sui `max_gas_budget`, Cosmos `max_gas_per_tx`, Aptos `max_gas_unit_price`, Algorand `max_min_fee` and
`max_fee_per_byte`, NEAR `max_deposit_per_job`; owner 2026-11-18, plan T24.4), and a figure above its cap is no verdict. BUILT for EVM, plan T3, T6, T13 S1, S2: `three_honest_agree`, `one_altered_storage_slot_is_outvoted`,
`two_altered_differently_is_no_majority` against three anvils, EIP-1898 verified against anvil and a local Nethermind 2.2.0
(plan T0; Hedera's relay not verified); on another family PLANNED.

<a id="CLI-RPC-06"></a>**CLI-RPC-06** — **A read that feeds a decryption never rests on a discovered endpoint alone** (ARCH-POS-15,
ARCH-POS-13, as stated; BUILT, plan T3: `discovered_is_skipped_under_failover`, `only_discovered_is_no_trusted_endpoint`,
`discovered_with_n_2_under_agreement_is_refused_before_any_request`, `a_read_feeding_a_decryption_skips_a_discovered_endpoint`). Every read whose bytes enter a decryption (PQZ and Zether words, chat ciphertexts read from
state) is marked so by the caller; a read without that mark cannot be used for one. Under `failover`, `discovered` endpoints are
skipped for it; none left is `NoTrustedEndpoint`. Under `strict_majority`, a list that holds a `discovered` endpoint serves it only
when `n ≥ 3`, else `AgreementNeedsThree`. `named` and `default` endpoints may serve it alone. Under `strict_majority` the agreeing group
also holds at least one `named` or `default` endpoint (owner 2026-11-17, the spec's Q6 (b)): a list with none is
`NoTrustedEndpoint` before any request; equal answers from discovered endpoints alone decide nothing; a round whose agreeing
group has none is `EndpointNoMajority` after the fallback round.

### 3.1 Readers

`ChainReader` (SPECIFIED; no such trait is built: each family's generic reads are its family client
`scaas_rpc::<family>`, plan T14–T22) is the family-neutral read surface every family implements: the final head, a block hash, a
transaction's status (`Pending`, `Mined`, `Reverted`, `Unknown`; never `dead`), an account's committed sequence, a native balance
and a landed transaction's fee. The EVM reader adds calls, storage, code, transactions and receipts, logs over a bounded range,
simulation and fee data, at a block the caller names, on the crate's bounded transport. Each other family lifts its transport and
these generic reads from the node's adapter, after the EVM part; parsing of events and of `build`'s family reads stays in the node
for now, reading through the family's pooled client so CLI-RPC-04 and §5 apply to every read (BUILT for the Hedera, Soroban, Solana, NEAR, Algorand, Aptos, Sui, Cosmos and TON
adapters, plan T14–T22; Sui's reads over GraphQL too, `sui::SuiGraphql` on `Client::graphql_at`, BUILT, SDK plan rpc
T24.sui-graphql; TON's getters and account read at one masterchain seqno, `Ton::run_get_at` / `Ton::account_at` on TON
Center's `/api/v2/` paths, the stack's cells through the bounded `boc` reader, BUILT, SDK plan rpc T24.ton-seqno; Substrate's reads, feature `substrate`,
`substrate::Substrate`: identity `chain_getBlockHash(0)`, the finalized head and its number, `System.Account` at a block hash
through a bounded `AccountInfo` reader (80 bytes exactly), one code path for Polkadot Hub's Substrate side and the relay chain,
BUILT, SDK plan T32's read part; Bitcoin's reads, feature `bitcoin`, `bitcoin::Esplora` (UTXOs, history pages, a transaction's height,
fee estimates) and `bitcoin::Core` (`getblockhash`, `gettxout`), two lists with their own credentials, and `cross_check`
(`BitcoinCrossCheck`: Esplora's tip and every UTXO to spend against Core), BUILT, SDK plan T36's read part). The indexer's event-set quorum
([NODE-IDX-01](../node/indexer-feeds.md#NODE-IDX-01)) is unchanged; its helper (`agreed`, NEAR and Aptos) is the crate's.

## 4. Writes and transaction state

<a id="CLI-RPC-08"></a>**CLI-RPC-08** — **The same signed bytes to one or more endpoints; outcomes merged, never final**
(ARCH-POS-15, writes; BUILT for EVM, plan T7: `one_signed_transfer_to_two_anvils_is_sent_then_final`,
`anvils_already_known_answer_is_accepted`, `all_refused_is_rejected_and_not_final`; for scaas-node gateways, T11; for Soroban, SDK plan T30.soroban: `Soroban::send`, `tests/soroban_send.rs`). A send takes the bytes once and posts the same bytes to the first endpoint or to all; nothing is
signed again per endpoint. The transaction id is computed locally from the bytes (EVM: `keccak256` of the raw transaction; a blob
transaction in its network form is refused by name); an endpoint that answers another id is counted as not accepting. Per endpoint
the outcome is `accepted` (an "already known" answer included), `refused` (a well-formed rejection, its reason kept, capped), or
`unreachable`. The merge is `Sent` when at least one endpoint accepted, else `Rejected` (code `BroadcastRejected`) with every
endpoint's outcome. Neither is a final verdict on the transaction ([CLI-RPC-09](#CLI-RPC-09)), and no consumer re-sends
automatically on either (one exception, a controller call of 2026-11-21 ([ARCH-POS-20](../decisions.md#ARCH-POS-20) C20, owner:
no): the SDK's bounded re-post of the same bytes of an unsettled Arweave item, [CLI-SDK-21](scaas-sdk.md#CLI-SDK-21)). The same rule holds for a signed operation posted to several scaas-node gateways (§6).

<a id="CLI-RPC-09"></a>**CLI-RPC-09** — **A transaction ends only on facts from a decisive read at a final block** (follows "never
report `dead` while a transaction may still land"; BUILT for EVM, plan T7, T13 S7: `final_from_an_agreed_read_is_terminal`,
`final_from_a_discovered_first_endpoint_is_not_terminal`, `replaced_needs_the_transaction_unknown`,
`replaced_from_a_later_endpoint_is_pending`, `replaced_under_strict_majority_rests_on_the_finalized_block`,
`failed_for_good_under_strict_majority_rests_on_the_finalized_block`; the merged node states, T11). A read is decisive when it is agreed under `strict_majority`, or under
`failover` answered whole by the first endpoint of the list when that endpoint is not `discovered`. A transaction is `Final` when a
decisive read finds its receipt in a block at or below the final block, the receipt's block hash equal to that endpoint's header
hash at its number. It is `Replaced` only when one decisive read finds, all at the final block, the sender's nonce (pinned by
hash) above the transaction's nonce, the transaction by hash unknown and its receipt unknown. Under `strict_majority`, `Replaced`
and a relayed operation's failed-for-good need the majority's agreed read at the `finalized` block (a read at another depth that
shows them reads the finalized block again); under `failover` they are endpoint 0's alone and their text says they rest on one
endpoint (owner 2026-11-17). The same facts from any other
endpoint are reported with its index and are never terminal; anything else is `Pending` or `Included`. `Replaced` never triggers an
automatic re-send. A relayed operation ends only on chain facts read the same way: landed when its executed event is at or below
the final block; failed for good when the subject's operation nonce is spent at the final block without its executed event, or its
deadline is below the final block's timestamp while the nonce is unspent. Several scaas-nodes holding one operation give a merged
state that is never terminal: `Landed` (a node reports it mined: the caller then reads the chain facts), `InFlight`, or
`GivenUpByEveryNode` (every node the bytes were sent to, whatever it answered at submit, reports `dead` or does not know it; an
unreachable node keeps it `InFlight`) ([job-api.md](../node/job-api.md#states)).

## 5. Bounds and logs

<a id="CLI-RPC-07"></a>**CLI-RPC-07** — **Every answer is bounded by length and depth before it is decoded** (follows the bounded
decode rule of every untrusted input; BUILT for EVM, plan T2, T4: `an_announced_length_above_the_cap_is_refused_unread`,
`a_depth_of_65_is_too_deep_and_64_read`, `an_evm_answer_above_the_cap_is_that_endpoints_failure`; for the Hedera, Soroban, Solana, NEAR, Algorand, Aptos, Sui, Cosmos and TON
family clients, plan T14–T22, `a_<family>_answer_above_16_mib_is_refused`; a raw answer, Algorand's msgpack, has no JSON scan and
keeps its reader's depth bound). Every answer, those of the EVM reader's providers included (the crate's own
transport under alloy), is read in chunks up to its call's byte cap (default 16 MiB, lower per call where the answer is small; an
announced length above the cap stops before reading), then its JSON nesting depth is checked by a flat scan (at most 64), and only
then parsed, once. Family binary decoders keep their own caps (XDR depth 64, msgpack depth 64, BOC 4096 cells). Too large, too deep
or malformed is that endpoint's failure ([CLI-RPC-04](#CLI-RPC-04)), never a panic. The requests of one read are bounded too: a log
range is read in spans, at most about 25 requests per window.

<a id="CLI-RPC-11"></a>**CLI-RPC-11** — **No URL, credential or request body in a log line or an error** (follows the node's
redaction, [gateway.md](../node/gateway.md#NODE-GW-06); BUILT, plan T1, T2, T13 S4, S5: `debug_and_display_carry_no_url_or_secret`,
`secrets_never_in_debug`, `a_job_error_carries_no_endpoint_url`). An endpoint is named by its index and label. Every `scheme://…`
token in an error or a log line becomes `<url>`; text an endpoint sends back (a rejection reason, an error message) is cut to 256
bytes with control characters removed, since a key echoed without a scheme is not recognised. Request bodies (signed bytes,
ciphertexts, proofs), credentials and headers are not logged; hashes, block numbers, chain ids and addresses may be. Health
counters (failover answers, refusals per endpoint) carry no URL.

## 6. The scaas-node client

<a id="CLI-RPC-10"></a>**CLI-RPC-10** — **The scaas-node client sends named fields and reads the node's error contract by code**
(BUILT for the routes the node serves, plan T10, T11, T13 S14: `bodies_are_sent_byte_for_byte`, `a_body_above_64_kib_is_refused_unsent`,
`an_error_is_read_by_code_else_by_error_string`, `hmac_headers_follow_node_gw_02`, `a_second_gateway_receives_no_credential_of_the_first`;
the job API client PLANNED). The client covers the gateway routes the node serves ([gateway.md](../node/gateway.md#NODE-GW-05)): `POST /v1/op`,
`POST /v1/ua-metatx`, the DEX routes and `POST /v1/ops` (`submit_ops` / `submit_ops_at`, `{chain, op}` with the family's chain
key, merged as `submit_op`'s; plan T28, test `submit_ops_sends_the_same_bytes_and_merges`), BUILT in the node; `GET /v1/gateway`,
`POST /v1/ua/register` and the client of `GET /v1/intents/{intent_id}` follow. Bodies are the named-field objects `ua-rs` builds; the client never
packs fields into hex and never rewrites an operation. A request above the route's body cap is refused before it is sent. An error
answer is read by its `code` (else the legacy `error` string) with its `detail` and `revert_data`
([NODE-GW-06](../node/gateway.md#NODE-GW-06)); no logic keys on free text. `api` of `GET /v1/gateway` other than `1` is
`NodeApiVersion`. Gateway auth `none`, `bearer` or `hmac` ([NODE-GW-02](../node/gateway.md#NODE-GW-02)), per endpoint
([CLI-RPC-02](#CLI-RPC-02)). Several nodes take the endpoint list and [CLI-RPC-08](#CLI-RPC-08), [CLI-RPC-09](#CLI-RPC-09). A job
API client (namespaced HMAC keys, [NODE-JOB-05](../node/job-api.md#NODE-JOB-05), the change feeds) comes with its first route the node
serves, as a separate feature for server-side clients only, never built into an end-user app
([NODE-ADM-06](../node/admin-auth.md#NODE-ADM-06)); PLANNED.

## 7. The verifier's agreement option

<a id="CLI-RPC-12"></a>**CLI-RPC-12** — **`scaas-pqz-verifier` reads through the crate and gains the agreement option** (owner
2026-11-11; **BUILT** for EVM, branch `scaas-sdk` (plan T8, T9), verified against anvil and a local Nethermind 2.2.0 for EIP-1898
(plan T0); UNAUDITED). The verifier's `rpc_urls` become a node list on the crate's bounded transport. Under `failover` (the
default) its request path is unchanged. `rpc_policy = "strict_majority"` (two endpoints or more) makes every chain read of a
`verdict` or `probe` request one agreed read ([CLI-RPC-05](#CLI-RPC-05)): every read the request makes, in the order of the failover
path and pinned by block hash, before the proof is checked, compared whole, then the same checks in the same order on the agreed
values, so a request gets the same refusal under both policies and no endpoint is asked after the proof is checked; reads per
request then rise to at most the key count times the reads per key times `n`, bounded by the service's concurrency and rate limits.
No majority is `RPC_NO_MAJORITY`, nothing signed. Under both policies an error answer is a revert by the crate's rule, its data
kept as bytes, and a revert is a refusal by name, never a signature (owner 2026-11-17, CLI-RPC-50). Until this is built, every
`rpc_urls` endpoint of a PQZ verifier must be a node its operator trusts ([ops.md](../node/ops.md#pqz-verifier),
[CTR-PQZ-29](../contracts/pq-zero-knowledge.md#CTR-PQZ-29)); with it, that holds under `failover`, and under `strict_majority` the
operator trusts that fewer than ⌊n/2⌋ + 1 endpoints lie together (`n = 2` detects one liar and tolerates no failure; tolerance of
one needs `n ≥ 3`).

## 8. Errors

Named, stable codes; the names shared with the app's endpoint lists are the same names.

| Code | When |
|---|---|
| `EndpointScheme` | a URL that is not `http` or `https` |
| `EndpointListEmpty` | a list with no endpoint |
| `EndpointAllFailed` | failover: no endpoint answered the whole read (the last endpoint's failure attached, its URL redacted; a later endpoint's revert data kept) |
| `EndpointNoMajority` | strict majority: no ⌊n/2⌋ + 1 equal complete answers at one block after the fallback round (`n`, `need`, the largest group's size) |
| `NoTrustedEndpoint` | a read that feeds a decryption with no `named` or `default` endpoint in the list (failover: only discovered endpoints; strict majority: Q6 (b)) |
| `AgreementNeedsThree` | the same under strict majority with a discovered endpoint and `n < 3` |
| `PinnedReadsUntrusted` | a pinned read (CLI-RPC-05; a read feeding a decryption included) on a pool built `with_pinned_reads(false)`: the chain's profile states `"pinnedReads": false` (Moonbeam, Moonbase: a read pinned by a made-up hash is answered; owner 2026-11-22, [ARCH-POS-20](../decisions.md#ARCH-POS-20)); refused before any request, plain reads still work; BUILT, the SDK's wiring PLANNED (T41 family) |
| `Revert` | the first endpoint's revert (failover), or the agreed revert (strict majority), with its data as bytes |
| `NodeRefused` | a scaas-node's error contract: `code`, `detail`, `revert_data` |
| `NodeApiVersion` | a node's `api` this client does not speak |
| `BodyTooLarge` | a request above the route's body cap, refused before sending |
| `Argument` | a malformed input or configuration (a duplicate endpoint, `strict_majority` with one endpoint or without a pinned `chain_uid`, a list-wide credential, a blob transaction in network form, an operation that is not a JSON object) |

`BroadcastRejected` is the code of a send's `Rejected` outcome ([CLI-RPC-08](#CLI-RPC-08)), not an error. The failure of one
endpoint inside `EndpointAllFailed` or `EndpointNoMajority` is one of `Transport`, `Timeout`, `Http`, `AnswerTooLarge`,
`AnswerTooDeep`, `AnswerMalformed`, `WrongChain`, `IdentityUnread`, `BehindHead`, `BlockChanged` or `FailoverRevert`.

## 9. Arweave gateways and bundlers

Status: **SPECIFIED**, nothing built (owner 2026-11-21, [ARCH-POS-19](../decisions.md#ARCH-POS-19) (3) and Q5; the rules below
controller calls of [ARCH-POS-20](../decisions.md#ARCH-POS-20); the [spec](../superpowers/specs/2026-11-21-avax-polkadot-arweave.md) part D). A module `arweave` behind the feature
`arweave`, under CLI-RPC-01 to CLI-RPC-11: no key, no signing, no payment; compiles for wasm32. The Avalanche and Polkadot EVM
profiles need no new rule here: they are configuration of the EVM reader ([NET-EVM-16](../networks/evm.md#NET-EVM-16),
[NET-EVM-17](../networks/evm.md#NET-EVM-17)).

<a id="CLI-RPC-13"></a>**CLI-RPC-13** — **Arweave reads go to a list of gateways, streamed within an exact length; every
attachment read feeds a decryption and is accepted only when the caller's check passes; "settled" needs agreement, depth and
the bytes** (SPECIFIED). The list is [CLI-RPC-02](#CLI-RPC-02)'s: `default` the release's reviewed gateways, `named` the
operator's or holder's, `discovered` only as the caller passes them (the crate discovers nothing and follows no redirect); each
entry names its operator. A gateway answers `GET /info` with the configured `network` or is dropped for the process
([CLI-RPC-03](#CLI-RPC-03)). `data(id, len, purpose, check)` reads `GET /raw/{id}`: `id` is checked as 43 canonical base64url
characters before any request; `len` above the platform's cap (2^30 + 16 B on 64-bit targets, 2^27 + 16 B on wasm32) is refused
before any request; an announced length other than `len` is refused unread; the body is streamed, its SHA-256 computed as it
arrives, into a buffer of at most `len` bytes, and a body longer or shorter than `len` is refused; no `Range` request is sent
(a range would tell the gateway the size). A body that fails `check` is that gateway's failure (`EndpointAnswerRefused`), so
failover moves on. Failover by default; under strict majority ⌊n/2⌋ + 1 gateways return bytes with the same SHA-256 that also
pass `check` (the id fixes the content; no block). Every attachment read is marked as feeding a decryption
([CLI-RPC-06](#CLI-RPC-06)). `status(id)` reads GraphQL `transactions(ids: [id])` from each gateway, each answer capped at 64 KiB
and depth 64, with the tip height. `settled(id, depth, object_sha256)` is true only when (a) a strict majority of at least two
gateways run by different operators (`default` or `named`; discovered gateways never count) report the item in one block, (b)
that block is at least `depth` blocks below the tip they report (`depth` a list setting, default 50), and (c) one `data` read
returns bytes whose SHA-256 is `object_sha256`; with fewer than two such gateways nothing is ever settled. Logs carry ids and
sizes only ([CLI-RPC-11](#CLI-RPC-11)).

<a id="CLI-RPC-14"></a>**CLI-RPC-14** — **An upload posts the same signed data item to a list of bundlers; a receipt counts only
when its id equals the id computed locally; never final** (SPECIFIED). `upload(item, paid_by)` parses the item's header within
bounds (signature types 2, 3 and 4 only), computes its id (base64url of SHA-256 of the signature), and posts the same bytes
(`POST /tx`, `application/octet-stream`) to the first or to every bundler of the list (`default` Turbo). Per bundler: `accepted`
(the receipt kept, capped), `refused` (HTTP 402 as `PaymentRequired`) or `unreachable`; a receipt for another id is `refused`;
merged `Sent` or `Rejected` as [CLI-RPC-08](#CLI-RPC-08). `paid_by` is the caller's, sent as `x-paid-by` to that bundler only.
The body cap is the largest single-request object plus 1,024 B. Settlement is read later through [CLI-RPC-13](#CLI-RPC-13)'s
`settled`, never taken from a receipt. The crate re-sends nothing; the SDK's bounded re-post of an unsettled item
([CLI-SDK-21](scaas-sdk.md#CLI-SDK-21)) is the one exception to CLI-RPC-08's "no automatic re-send". The owner agreed to this exception (2026-11-21).

