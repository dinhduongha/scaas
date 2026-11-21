> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Hedera HAPI broadcast: gRPC or gRPC-web (2026-11-22)

Context: the owner's `fam-hedera` (decisions CLI-SDK-32, CLI-SDK-33 (33)) puts Hedera's native side (`0.0.x` accounts with
ed25519 keys, HBAR, HTS) in a feature of its own: mirror-node REST reads and the HAPI protobuf transaction from named fields.
How a signed HAPI transaction reaches a consensus node is open (spec Q-R5); it carries the native sends and HCS writes alike
(`ConsensusSubmitMessage`, PqChat's HCS store kind, the owner's HCS ruling of the same day), so it decides that store too; CLI-SDK-33 (5) said "HAPI is not offered" because
gRPC is heavy. No gRPC crate is added without the owner's word.

## What exists (read 2026-11-22, public, read-only)

- The testnet mirror node's `/api/v1/network/nodes` lists each consensus node's `service_endpoints` as IPv4 addresses on ports
  50211 (plain gRPC) and 50212 (TLS gRPC), and a `grpc_proxy_endpoint` field (HIP-1046's gRPC-web proxy) that was `null` for
  `0.0.3`, `0.0.4` and `0.0.5`. So no gRPC-web endpoint is published there today; a gRPC-web path needs a proxy that some
  operator runs (the JS SDK's web client relies on such proxies), or HIP-1046's field filled in later.
- A hostname of the form `testnet-node00-00-grpc.hedera.com:443` did not answer a plain HTTPS request from this machine.

## The two transports

| | gRPC (HTTP/2) | gRPC-web (HTTP/1.1 or 2, through a proxy) |
|---|---|---|
| Crates | `tonic` (+ `h2`, `hyper`, `tower`, `prost`); not built for `wasm32-unknown-unknown` with its transport | none beyond `reqwest`: a POST of `application/grpc-web+proto`, body = 1 flag byte, a 4-byte length, the protobuf bytes; the answer's trailers in a final frame |
| Protobuf | `prost` codegen, or the bytes built from named fields as every other family | the bytes built from named fields (the transaction is built that way anyway); the answer (`TransactionResponse`, a few varint fields) read by a small bounded reader |
| Endpoints | every consensus node (IPs on 50211 / 50212 from the mirror node) | only where a proxy exists (none listed on testnet's mirror node today) |
| wasm32 | no (without a separate web transport) | yes (`reqwest`'s fetch backend) |
| Size | not measured here (the owner's word first; a measurement is a build, not a dependency) | ~0 new dependencies |

## Open question for the owner (spec Q-R5)

Broadcast HAPI by (a) gRPC-web over `reqwest` to a proxy list the profile names (no new crate, wasm32 works, but public proxies
must exist), (b) `tonic` gRPC to the consensus nodes (native only, a heavy dependency set), or (c) neither: Hedera's native sends
stay off and its native side is read-only (the EVM side through the JSON-RPC Relay stays BUILT). Until the answer, the reads
and the transaction format are built; no broadcast.
