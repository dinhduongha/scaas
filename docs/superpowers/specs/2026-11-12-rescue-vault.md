# RescueVault: the dev rescue destination becomes a two-role contract wallet — design

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
   to để cuối cùng" (`to` is the last parameter). Ruling 5 renames the receiving "owner" the `rescuer`.
3. After review of the residuals:
   - "đổi chủ chỉ bằng chữ ký => OK." (the owner changes only by signature: OK): every admin operation is signed, none direct (§2.2).
   - "Khi đổi chủ, vault không kiểm chủ mới => OK." (at an owner change the vault does not check the new owner: OK): no code or
     designator check of the new value (§2.2).
   - "mỗi lần đổi chủ phải áp ngay lên mọi chain => Không cần." (each owner change must be applied at once on every chain: not
     needed): an admin operation is caught up on a chain when needed, not everywhere at once (§5); the residual this leaves (R1,
     R2) is accepted by the owner.
4. Two roles: "RescueVault: Có nên tách address nhận tài sản riêng, UA làm admin riêng không (không rút về UA)? UA có thể set
   rescueTo sang địa chỉ mới .v.v." (should the address that receives the assets be separate, with a UA as a separate admin — not
   withdrawing to the UA? The UA can set rescueTo to a new address, etc.), then "withdraw(token, amount, to) => vẫn cho phép
   rescuer gọi, admin chỉ quản trị ai là rescuer thôi." (withdraw(token, amount, to): still lets the rescuer call; the admin only
   administers who the rescuer is).
5. The first admin: "admin: 0xAb92b0E9bD2E18F7003c30dAFE93Ef9bc3e1248C" (EIP-55 checksum verified; it replaces an address given
   earlier the same day), as a native UA. The first
   rescuer stays the dev EOA `0x0389f77E846ff687d44db57bcC9DCB55dd6f4131`.
6. Controller calls on these rulings: one admin, not k-of-n; the admin is a native UA only (§2.2, a known limit); one shared `seq`
   for both admin operations.

So `RescueLib.SCAAS_DEV_RESCUE` stops being the EOA `0x0389f77E846ff687d44db57bcC9DCB55dd6f4131` and becomes the address of a
`RescueVault` with that EOA as first rescuer and `0xAb92b0E9bD2E18F7003c30dAFE93Ef9bc3e1248C` as first admin, deployed through
the public deterministic deployer: one address on every EVM chain, and both the receiving address and the key that administers it
can change without touching the constant compiled into every SCaaS contract.

## 2. The contract

```solidity
contract RescueVault {
    constructor(bytes32 initialAdmin, address initialRescuer);   // a native UA (AdminInvalid); != 0 (RescuerInvalid)
    receive() external payable;                                  // the native coin is accepted from anyone
    function withdraw(address token, uint256 amount, address to) external;
    function setRescuer(uint64 seq, address newRescuer, bytes calldata sig) external;
    function rotateAdmin(uint64 seq, bytes32 newAdmin, bytes calldata sig) external;
    function admin() external view returns (bytes32);
    function rescuer() external view returns (address);
    function seq() external view returns (uint64);
    function setRescuerDigest(uint64 seq, address newRescuer) external view returns (bytes32);
    function rotateAdminDigest(uint64 seq, bytes32 newAdmin) external view returns (bytes32);
    function eip712Domain() external view returns (...);         // ERC-5267, fields 0x0b
}
```

State: `admin` (a native UA), `rescuer` (an address) and `seq` (the number of admin operations applied, both kinds together, 0 at
deploy). Nothing else: no upgrade, no `delegatecall`, no arbitrary call, no chain value.

### 2.1 withdraw (the rescuer)

`withdraw(token, amount, to)` (`to` last), `token` 0 for the native coin. Anyone may call it, with no signature. One rule: the
destination is `to` when `msg.sender == rescuer && to != 0`, else the rescuer (the rescuer's call with `to` 0, and any other
caller's call, whose `to` is ignored).

| caller | `to` | destination |
|---|---|---|
| `rescuer` | not 0 | `to` |
| `rescuer` | 0 | `rescuer` |
| anyone else, the admin included | any (ignored) | `rescuer` |

The admin never receives and cannot direct funds: its `withdraw` is a stranger's and pays the rescuer. It becomes a rescuer only
by setting its own address as `rescuer`. The rescuer directing funds to `to` must not be an EIP-7702 designator
(`CallerDelegated(rescuer)`, the `SigCheck.requireNotDelegated` rule of CTR-UA-24: an EOA runs no code); every call that pays the
rescuer is open to anyone, so it needs no such check. The native coin is sent by `Address.sendValue` and refused to a designator
destination (`ToInvalid(dest)`), as `RescueLib.send` refuses it; an ERC-20 goes by `safeTransfer` to any destination.
`Withdrawn(token, dest, amount, msg.sender)`. A re-entry finds only the same rule.

A stranger's call moves funds only to the current rescuer, so it is a convenience (a keeper may sweep the vault to the rescuer)
and never a loss, as long as the rescuer is current on that chain (§4, R2).

### 2.2 setRescuer and rotateAdmin (the admin, the only signatures)

Both are submitted by anyone and carry the current admin's 65-byte low-s ECDSA signature (OpenZeppelin `ECDSA.tryRecover`, which
refuses high s and lengths other than 65; `SignatureInvalid` otherwise), with `seq == seq() + 1` (`SeqInvalid(expected, got)`):

```
SetRescuer(uint64 seq,address newRescuer)        newRescuer != 0 (RescuerInvalid)
RotateAdmin(uint64 seq,bytes32 newAdmin)         newAdmin a native UA (AdminInvalid)
EIP712Domain(string name,string version,address verifyingContract)
name "SCaaS RescueVault", version "1", verifyingContract = the vault
```

Then the value moves, `seq = seq`, and `RescuerSet(seq, previous, new)` or `AdminRotated(seq, previous, new)`. The two typehashes
keep the kinds apart (a `SetRescuer` signature never passes as a `RotateAdmin` for the same 32 bytes); the one `seq` orders every
admin operation of both kinds in one log.

The domain has no `chainId` and no `salt` on purpose: the same signed operation is valid on the vault on every chain (they share
one address), which is how a chain catches up (§5). `seq` makes each one usable exactly once per vault. There is no direct admin
call (owner: "đổi chủ chỉ bằng chữ ký => OK."): an unsigned change could not be replayed on the other chains, and they would drift
apart. No deadline: an operation must still apply on a chain that gets its vault years later.

**The admin is a native UA only.** `admin` is a `bytes32` UA, restricted to the native space (`UAKinds.inNativeSpace`: the high 96
bits 0, not 0), and its signature is checked by `ecrecover` of the address in the low 160 bits. A derived or PQ UA needs the
chain's `UARegistry` to verify, and the registry's address differs per chain (its constructor takes `chainUid`), which a
chain-neutral vault cannot trust. **Known limit:** a PQ admin later needs a trusted per-chain registry lookup, so a new vault.
Neither the native-space check nor any other check reads chain state, so it cannot split the log.

**No check of the new value** (owner: "Khi đổi chủ, vault không kiểm chủ mới => OK."). Neither the constructor nor an admin
operation reads the code of the new rescuer or admin: a check of code is chain-local, so an operation could pass on one chain and
fail on another, and the log would fork. The vault never runs or asks anyone's code (ECDSA by the admin's own key; no ERC-1271),
so a delegate gains nothing; only the rescuer's direct `withdraw` to a `to` refuses a designator caller (§2.1). A native UA whose
address is a contract (or a typo) is an admin key nobody holds: no further admin operation. Admins sign only to EOAs whose keys
they hold.

### 2.3 Deterministic address

Init code = `type(RescueVault).creationCode ‖ abi.encode(bytes32(uint256(uint160(0xAb92b0E9bD2E18F7003c30dAFE93Ef9bc3e1248C))),
0x0389f77E846ff687d44db57bcC9DCB55dd6f4131)`, salt `keccak256("scaas.rescue-vault.v1")`, deployer
`0x4e59b44847b379578588920ca78fbf26c0b4956c` (NET-EVM-05): `0xd33d17991f57BefB4CcBb3E57c477c10BdE5B465` (was `0xE20dddfC…dF34` with ERC-5267 fields `0x0d`, a wrong field
set: chainId instead of version; never deployed, Fable fix2 V-1). The init code holds no
chain id, chain uid, block value or other per-chain value, so the address is one on every EVM chain. Funds may be sent to it before
the vault exists there (EIP-7610 refuses a CREATE2 only onto code, a nonce or storage, never onto a balance); deploying is open to
anyone and always gives the same contract with the same first admin and rescuer.

The creation code carries the Solidity metadata hash, which covers the text of `RescueVault.sol` and of every file it imports
(OpenZeppelin `IERC20`, `SafeERC20`, `Address`, `ECDSA` and their imports, pinned by `scripts/evm_libs.sh`) and the compiler
settings (solc 0.8.37, optimizer 200 runs, no via-IR, Amsterdam). The vault imports no SCaaS file, so no other edit in the repo
moves it; the designator and native-space checks are copies of `SigCheck.isDesignator` and `UAKinds.inNativeSpace` for that reason.

**The init code is committed** as `smartcontracts/evm/rescue-vault-init.hex` (one line, `0x`, the creation code followed by the
two constructor arguments; keccak `0xd42ad5b7…d1dcd4fd`), and the deploy script sends those bytes, never a fresh compile: a later
compiler, OpenZeppelin commit or setting cannot move the address. `test_addressIsTheConstant` pins the artifact's keccak and its
CREATE2 address against `RescueLib.SCAAS_DEV_RESCUE` and deploys it; `test_artifactIsTheSource` pins today's compile (creation
code hash `0xa103dbdc…c153dc66`) to the artifact, so every behaviour test of the source tests the deployed bytes; the deploy
script refuses an artifact whose address is not the constant. **`RescueVault.sol` must never be edited**; under a later compiler
`test_artifactIsTheSource` may fail while the artifact stays the deploy truth. A new vault means a new file, a new salt and a new
constant, under a new owner ruling.

## 3. Constant and pins

`RescueLib.SCAAS_DEV_RESCUE` = the computed vault address (decisions.md CTR-GOV-25 Change). Every contract that embeds `RescueLib`
moves its code and metadata hash, so CREATE2 addresses and code-hash pins move, listed old → new in the commit. Sizes do not move
(one 20-byte constant for another).

## 4. Threat model and residuals

- **The relayer / submitter** of an admin operation can delay it, never alter it (every field is signed); anyone may submit it.
- **Replay** onto any vault at this address is intended; onto any other contract it is void (`verifyingContract`). Within one
  vault, `seq` makes each operation single-use and ordered; the typehash keeps the two kinds apart.
- **Withdraw** carries no signature, so it has no replay question; its only power for anyone but the rescuer, the admin included,
  is to pay the current rescuer.
- **A compromised rescuer key** loses what the vault holds on chains where it acts before the admin replaces it; the admin key,
  kept apart, replaces the rescuer and the constant does not move.
- **R1 — an old admin key still rules a chain not yet caught up (accepted by the owner).** Admin operations are not applied on
  every chain at once (owner: "mỗi lần đổi chủ phải áp ngay lên mọi chain => Không cần."): on a chain where the vault is not yet
  deployed, or not yet caught up, the admin there is an older key. Whoever holds that key can sign a different operation for the
  next `seq` there and take that chain's vault (equivocation). The init code fixes the first admin, so the contract cannot close
  this. The owner accepts it: a chain is caught up when needed (§5), and the compromise of a retired admin key is the loss of the
  vault on every chain not yet caught up.
- **R2 — a stranger's sweep on a chain not yet caught up** pays the old rescuer there (accepted by the owner with R1). Catching the
  chain up first avoids it.
- **R3 — equivocation by a current admin.** Two different signed operations for the same `seq` split the chains. Admins sign
  exactly one operation per `seq` and publish it in the admin log (§5) before submitting it anywhere.
- **R4 — no deployer.** A chain without the deterministic deployer at `0x4e59…` cannot hold the vault; funds rescued there are
  stuck until the deployer is placed (its keyless transaction needs pre-EIP-155 support). NET-EVM-05 already requires it.
- **R5 — a lost admin key** freezes the rescuer on every chain (no recovery path, by design); the rescuer still withdraws.
- **R6 — reproducibility** is not needed to deploy (the init code is committed, §2.3); rebuilding it to check the artifact needs
  solc 0.8.37 and the pinned OpenZeppelin commit, both pinned in the repo.
- **R7 — native admin only** (§2.2): a PQ admin is a known limit, closed only by a new vault with a trusted per-chain registry
  lookup.

## 5. Deploy and catch-up

`script/DeployRescueVault.s.sol` (never run against a live chain from this branch): refuses without the deterministic deployer,
reads the committed init code `rescue-vault-init.hex` (§2.3), computes its address and refuses unless it equals
`RescueLib.SCAAS_DEV_RESCUE`, deploys only when there is no code at it, then reads the public admin log
`smartcontracts/evm/rescue-vault-admin-log.json` (committed, `[]` today; env `RESCUE_VAULT_LOG` for another file), a JSON array in
`seq` order of `{"seq", "op": "setRescuer", "newRescuer", "sig"}` and `{"seq", "op": "rotateAdmin", "newAdmin", "sig"}`, applying
the rows above the vault's `seq()` (any other `op` refused), logs the final `rescuer()`, `admin()` and `seq()`, and refuses
unless they equal the log's last `seq` (0 for `[]`), last `newRescuer` and last `newAdmin` (the init code's for a kind with no
row): a chain whose vault took an operation outside the log (R1, R3) fails instead of reading as caught up. Anyone may
run it; it needs no key of the vault, only gas. A new chain catches up the same way: deploy, then replay the log.

**When.** An admin operation is not applied on every chain at once (owner 2026-11-12: "mỗi lần đổi chủ phải áp ngay lên mọi chain
=> Không cần."). A chain is caught up when needed, for example before a withdrawal there, by running the script against it; the
log keeps every operation, so a chain left behind for years catches up in one run. Until then R1 and R2 (§4) hold on that chain,
accepted by the owner.

Signing: the current admin signs `SetRescuer(seq, newRescuer)` or `RotateAdmin(seq, newAdmin)` in the chain-neutral domain
(clientkeys `rescueVaultSetRescuerTypedData`, `rescueVaultRotateAdminTypedData`; KAT
`smartcontracts/vectors/governance/rescue_vault_kat.json`), appends the row to the log, then submits it on the chains where it is
needed (any chain may be caught up later from the log).

## 6. Tests and evidence

`test/governance/RescueVault.t.sol`, 22 tests: the committed init code's address equals the constant (first admin and rescuer),
counterfactual balance kept, a second deploy fails; the init code equals today's compile; `eip712Domain()`'s declared fields rebuild both digests (fails on `0x0d`); the constructor refuses a zero or
non-native admin and a zero rescuer; the rescuer pays `to`; the rescuer with `to` 0 and a stranger (any `to`) pay the rescuer,
ERC-20 and native; the admin is not a rescuer (its `withdraw` with `to` pays the rescuer) until it sets itself; a designator rescuer
cannot direct, a call paying it still works; native refused to a designator `to` with the ERC-20 and plain-address controls; a no-return (USDT-style) token withdraws through
`SafeERC20`;
`setRescuer` by anyone, the old rescuer then a stranger; `rotateAdmin`, the old admin key then void, the new one signs; a non-native
or zero admin and a zero rescuer refused; the shared `seq` (a signature of one kind fails as the other; `seq` 1 spent by one kind
voids the other kind's `seq` 1; replay); skipped, stale and replayed `seq`; wrong signer, the rescuer's key, another value, another
vault's domain (both kinds), the high-s twin, 64 bytes, each with the positive control; an admin log replayed on a second deploy at
the same address after a fresh fork state with another chain id, in order only, once; a real `RelayFeeRouter.rescue` pays the vault
(ERC-20 and native) and a stranger sweeps it to the dev EOA; the deploy script deploys, applies a mixed log, and is a no-op on a
rerun; it refuses a chain without the deployer, init code at another address and a vault that took an operation outside the
log, each with its control; the KAT (both digests). Mutants: `smartcontracts/evm/runs/2026-11-12-rescue-vault/mutants.json`, each against the one test
that names its rule (the address and artifact pins excluded, since any edit of the file moves them). The Fable fix2 check's mutants (the 0x0d field set, the three script refusals, `transfer` for `safeTransfer`):
`smartcontracts/evm/runs/2026-11-12-fix2-check-contracts.txt`. clientkeys
`test/rescue-vault.test.js` against the KAT, with negatives.
