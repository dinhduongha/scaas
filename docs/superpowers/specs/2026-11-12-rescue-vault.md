# RescueVault: the dev rescue destination becomes a one-owner contract wallet — design

**Status:** BUILT on branch `ua-mtx-rescue-vault` (from `ua-mtx-fix2-contracts` at `202a05a9`), **UNAUDITED**. Recorded in
`decisions.md` as a Change of [CTR-GOV-25](../../decisions.md#CTR-GOV-25) (owner: yes). Code `smartcontracts/evm/src/governance/RescueVault.sol`,
tests `smartcontracts/evm/test/governance/RescueVault.t.sol`, deploy `smartcontracts/evm/script/DeployRescueVault.s.sol`.

## 1. Owner rulings (2026-11-12, in chat, relayed by the controller)

1. On how to make the dev rescue destination's key replaceable: "Cách 2. Tại sao không dùng Deployer công cộng như hiện dùng, mà
   phải dùng EOA deployer?" (option 2; why not use the public deployer we use today instead of an EOA deployer?), then "Dùng địa
   chỉ public dev vừa rồi." (use the dev's public address just given) and "OK, làm vậy đi." (OK, do that).
2. On withdraw: "RescueVault hàm withdraw ai gọi cũng được. Nếu chủ gọi thì về địa chỉ to, nếu người khác gọi thì về địa chỉ của
   chủ." (anyone may call withdraw; if the owner calls, the funds go to `to`; if someone else calls, they go to the owner's address),
   then "chủ gọi, nhưng to = 0 thì cũng về địa chỉ chủ." (the owner calls with `to` 0: also to the owner's address), and "tham số
   to để cuối cùng" (`to` is the last parameter).
3. Controller calls on these rulings: one owner (an EOA), not k-of-n (with several owners one owner's direct call would bypass
   any threshold); the owner change stays signed and chain-neutral with a sequence number, the only signature in the contract.

So `RescueLib.SCAAS_DEV_RESCUE` stops being the EOA `0x0389f77E846ff687d44db57bcC9DCB55dd6f4131` and becomes the address of a
`RescueVault` whose first owner is that EOA, deployed through the public deterministic deployer: one address on every EVM chain,
and the key behind it can change without touching the constant compiled into every SCaaS contract.

## 2. The contract

```solidity
contract RescueVault {
    constructor(address initialOwner);                                   // != 0 (OwnerInvalid)
    receive() external payable;                                          // the native coin is accepted from anyone
    function withdraw(address token, uint256 amount, address to) external;
    function rotate(uint64 seq, address newOwner, bytes calldata sig) external;
    function owner() external view returns (address);
    function seq() external view returns (uint64);
    function rotateDigest(uint64 seq, address newOwner) external view returns (bytes32);
    function eip712Domain() external view returns (...);                 // ERC-5267, fields 0x0d
}
```

State: `owner` (one EOA) and `seq` (the number of rotations applied, 0 at deploy). Nothing else: no admin, no upgrade, no
`delegatecall`, no arbitrary call, no chain value.

### 2.1 withdraw

`withdraw(token, amount, to)` (`to` last, owner 2026-11-12: "tham số to để cuối cùng"), `token` 0 for the native coin. Anyone may call it, with no signature. One rule: the destination is
`to` when `msg.sender == owner && to != 0`, else the owner (the owner's call with `to` 0, and any other caller's call, whose `to` is
ignored).

| caller | `to` | destination |
|---|---|---|
| `owner` | not 0 | `to` |
| `owner` | 0 | `owner` |
| anyone else | any (ignored) | `owner` |

The owner directing funds to `to` must not be an EIP-7702 designator (`CallerDelegated(owner)`, the `SigCheck.requireNotDelegated`
rule of CTR-UA-24: an EOA runs no code); every call that pays the owner is open to anyone, so it needs no such check. The native coin is sent by `Address.sendValue` and refused to a
designator destination (`ToInvalid(dest)`), as `RescueLib.send` refuses it; an ERC-20 goes by `safeTransfer` to any destination.
`Withdrawn(token, dest, amount, msg.sender)`. The vault holds no other state, so a re-entry has nothing to corrupt.

A stranger's call moves funds only to the current owner, so it is a convenience (a keeper may sweep the vault to the dev) and
never a loss, as long as the owner is current on that chain (§4, R2).

### 2.2 rotate (the only signature)

`rotate(seq, newOwner, sig)`, anyone submits: `seq == seq() + 1` (`SeqInvalid(expected, got)`), `newOwner != 0`
(`OwnerInvalid`), `sig` a 65-byte low-s ECDSA signature by the current `owner` over

```
Rotate(uint64 seq,address newOwner)
EIP712Domain(string name,string version,address verifyingContract)
name "SCaaS RescueVault", version "1", verifyingContract = the vault
```

(`SignatureInvalid` otherwise; OpenZeppelin `ECDSA.tryRecover`, which refuses high-s and lengths other than 65). Then
`owner = newOwner`, `seq = seq`, `Rotated(seq, previousOwner, newOwner)`.

The domain has no `chainId` and no `salt` on purpose: the same signed rotation is valid on the vault on every chain (they share one
address), which is how a chain catches up (§5). `seq` orders the rotations and makes each one usable exactly once per vault.
There is no direct owner rotation: a rotation without a signature could not be replayed on the other chains, and they would drift
apart. The owner submits his own signed rotation like anyone else. No deadline: a rotation must still apply on a chain that gets
its vault years later.

**EIP-7702 owner.** Neither the constructor nor `rotate` reads the new owner's code: a check of code is chain-local, so a rotation
could pass on one chain and fail on another, and the log would fork. The vault never runs or asks the owner's code (ECDSA by the
owner's own key; no ERC-1271), so a delegate gains nothing; only the owner's direct `withdraw` refuses a designator caller (§2.1).
A contract (or a typo) as `newOwner` is a key nobody holds: no further rotation, and only a direct call by that contract or a
stranger's sweep to it remains. Owners sign rotations only to EOAs whose keys they hold.

### 2.3 Deterministic address

Init code = `type(RescueVault).creationCode ‖ abi.encode(0x0389f77E846ff687d44db57bcC9DCB55dd6f4131)`, salt
`keccak256("scaas.rescue-vault.v1")`, deployer `0x4e59b44847b379578588920ca78fbf26c0b4956c` (NET-EVM-05). The init code holds no
chain id, chain uid, block value or other per-chain value, so the address is one on every EVM chain. Funds may be sent to it before
the vault exists there (EIP-7610 refuses a CREATE2 only onto code, a nonce or storage, never onto a balance); deploying is open to
anyone and always gives the same contract with the same first owner.

The creation code carries the Solidity metadata hash, which covers the text of `RescueVault.sol` and of every file it imports
(OpenZeppelin `IERC20`, `SafeERC20`, `Address`, `ECDSA` and their imports, pinned by `scripts/evm_libs.sh`) and the compiler
settings (solc 0.8.37, optimizer 200 runs, no via-IR, Amsterdam). The vault imports no SCaaS file, so no other edit in the repo
moves it; the designator check is a copy of `SigCheck.isDesignator` for that reason. **`RescueVault.sol` must never be edited**:
`test_addressIsTheConstant` pins the creation code hash and the computed address against `RescueLib.SCAAS_DEV_RESCUE`, and the
deploy script refuses a mismatch. A new vault means a new file, a new salt and a new constant, under a new owner ruling.

## 3. Constant and pins

`RescueLib.SCAAS_DEV_RESCUE` = the computed vault address (decisions.md CTR-GOV-25 Change). Every contract that embeds `RescueLib`
moves its code and metadata hash, so CREATE2 addresses and code-hash pins move, listed old → new in the commit. Sizes do not move
(one 20-byte constant for another).

## 4. Threat model and residuals

- **The relayer / submitter** of a rotation can delay it, never alter it (every field is signed); anyone may submit it.
- **Rotation replay** onto any vault at this address is intended; onto any other contract it is void (`verifyingContract`).
  Within one vault, `seq` makes it single-use and ordered.
- **Withdraw** carries no signature, so it has no replay question; its only power for a non-owner is to pay the current owner.
- **R1 — a retired key on a lagging chain.** On a chain where the vault is not yet deployed, or not yet caught up, the owner there
  is an older key. Whoever holds that key can sign a different rotation for the next `seq` there and take that chain's vault
  (equivocation). The init code fixes the first owner, so this cannot be closed by the contract: after any rotation, catch up every
  chain that holds or may receive funds, and treat the compromise of a retired key as the loss of the vault on every chain not yet
  caught up.
- **R2 — a stranger's sweep on a lagging chain** pays the stale owner there. Same remedy as R1: catch up first.
- **R3 — equivocation by a current owner.** Two different signed rotations for the same `seq` split the chains. Owners sign exactly
  one rotation per `seq` and publish it in the rotation log (§5) before submitting it anywhere.
- **R4 — no deployer.** A chain without the deterministic deployer at `0x4e59…` cannot hold the vault; funds rescued there are
  stuck until the deployer is placed (its keyless transaction needs pre-EIP-155 support). NET-EVM-05 already requires it.
- **R5 — a lost owner key** freezes the destination on every chain (no recovery path, by design: no admin). Same as the EOA today.
- **R6 — reproducibility.** Rebuilding the init code needs solc 0.8.37 and the pinned OpenZeppelin commit; both are pinned in the
  repo.

## 5. Deploy and catch-up

`script/DeployRescueVault.s.sol` (never run against a live chain from this branch): refuses without the deterministic deployer,
recomputes the address and refuses unless it equals `RescueLib.SCAAS_DEV_RESCUE`, deploys only when there is no code at it, then
applies the public rotation log `smartcontracts/evm/rescue-vault-rotations.json` (committed, `[]` today; env `RESCUE_VAULT_LOG`
for another file), a JSON array of `{seq, newOwner, sig}` in order, skipping the rows at or below the vault's `seq()`, and logs
the final `owner()` and `seq()`. Anyone may run it; it needs no key of
the vault, only gas. A new chain catches up the same way: deploy, then replay the log.

Signing a rotation: the current owner signs `Rotate(seq, newOwner)` in the chain-neutral domain (clientkeys
`rescueVaultRotateTypedData`, KAT `smartcontracts/vectors/governance/rescue_vault_kat.json`), appends the row to the log, then
submits it on every chain.

## 6. Tests and evidence

`test/governance/RescueVault.t.sol`, 14 tests: the address equals the constant and the creation code hash is pinned
(`0x18529081…85047`), counterfactual balance kept, a second deploy fails; the zero first owner; the owner pays `to`; the owner with
`to` 0 and a stranger (any `to`) pay the owner, ERC-20 and native; a designator owner cannot direct, a call paying it still works;
native refused to a designator `to` with the ERC-20 and plain-address controls; rotate by anyone, then the old owner is a
stranger and its key no longer rotates; skipped, stale and replayed `seq`; wrong signer, another `newOwner`, another vault's
domain, the high-s twin, 64 bytes, a zero `newOwner`, each with the positive control; a rotation log replayed on a second deploy
at the same address after a fresh fork state with another chain id, in order only, once; a real `RelayFeeRouter.rescue` pays the
vault (ERC-20 and native) and a stranger sweeps it to the dev EOA; the deploy script deploys, catches up, and is a no-op on a rerun;
the KAT. Mutants 16/16 killed, each against the one test that names its rule (the address pin excluded, since any edit of the file
moves it): `smartcontracts/evm/runs/2026-11-12-rescue-vault/mutants.json`. clientkeys `test/rescue-vault.test.js` against the KAT.
