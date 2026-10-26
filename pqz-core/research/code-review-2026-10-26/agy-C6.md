# Independent Security Review Report: Unit C6 — DEX and Trade (Code)

**Repository:** `scaas` at frozen detached checkout commit `64549aa4`  
**Review Profile:** Ethereum / EVM (Solidity 0.8.24, Foundry 1.8.5, Amsterdam profile)  
**Scope:**  
- `smartcontracts/evm/src/dex/SCaaSDex.sol`
- `smartcontracts/evm/src/dex/ISCaaSDex.sol`
- `smartcontracts/evm/src/dex/DexPuller.sol`
- `smartcontracts/evm/src/trade/TradeLib.sol`
- `smartcontracts/evm/src/trade/ITradeToken.sol`

---

## Findings

### C6-1 — P3 — Cascading Batch Revert in `mtxSettle` via EIP-150 Gas Depletion Starving Subsequent Contract / UA Legs

- **File:line(s):** [`SCaaSDex.sol:275-300`](smartcontracts/evm/src/dex/SCaaSDex.sol#L275-L300)
- **Claim:** In [`SCaaSDex.mtxSettle`](smartcontracts/evm/src/dex/SCaaSDex.sol#L275), an adversarial or gas-heavy settlement at index `i` that exhausts its forwarded gas will leave only $\frac{1}{64}$ of the remaining gas for subsequent settlements. If a subsequent settlement `i + k` in the same call contains a contract wallet (`SmartKeyAccount`, 400,000 gas cap) or a post-quantum Universal Account (UA) leg (`mldsa44` at 4.25M gas, `mldsa65` at 5.95M gas), that subsequent settlement will revert with [`SigCheckGasStarved`](smartcontracts/evm/src/common/SigCheck.sol#L24) or [`UAVerifyGas`](smartcontracts/evm/src/dex/ISCaaSDex.sol#L143). Because [`SCaaSDex.mtxSettle`](smartcontracts/evm/src/dex/SCaaSDex.sol#L275) catches those two selectors and re-reverts the entire transaction, an isolated out-of-gas failure in an earlier settlement cascades into an involuntary abort of the whole batch.
- **Evidence:**
  In [`SCaaSDex.sol:283`](smartcontracts/evm/src/dex/SCaaSDex.sol#L283):
  ```solidity
  success := call(gas(), address(), 0, add(data, 0x20), mload(data), 0, 0)
  ```
  `call(gas(), ...)` forwards $\frac{63}{64}$ of `gasleft()` under EIP-150. If settlement 0 runs out of gas (e.g. an outside token or contract destination loops or burns gas until OOG), it reverts empty (`returndatasize() == 0`), which causes `reason.length == 0` and falls through to:
  ```solidity
  emit MatchFailed(ss[i].ref, reason);
  ```
  At loop index `i = 1`, the outer frame has only $\approx \frac{1}{64}$ of the original transaction gas left (at 16M gas, $\approx 250,000$ gas). Settlement 1 then calls [`settleOne`](smartcontracts/evm/src/dex/SCaaSDex.sol#L305). When verifying a `SmartKeyAccount` (cap 400k) or a UA PQ leg (cap 4.25M–5.95M), [`SigCheck.sol:63`](smartcontracts/evm/src/common/SigCheck.sol#L63) or [`UARegistry`](smartcontracts/evm/src/ua/UARegistry.sol) detects `gasleft() < cap * 64 / 63 + margin` and reverts with [`SigCheckGasStarved`](smartcontracts/evm/src/common/SigCheck.sol#L24) or [`UAVerifyGas`](smartcontracts/evm/src/dex/ISCaaSDex.sol#L143).
  Then in [`SCaaSDex.sol:294-297`](smartcontracts/evm/src/dex/SCaaSDex.sol#L294-L297):
  ```solidity
  } else if (reason.length >= 4
      && (bytes4(reason) == SigCheckGasStarved.selector || bytes4(reason) == UAVerifyGas.selector)) {
      assembly ("memory-safe") { revert(add(reason, 0x20), mload(reason)) }
  }
  ```
  This immediately aborts the entire `mtxSettle` call, rolling back any previously successful settlements in the same batch.
- **Suggested fix:** In [`SCaaSDex.mtxSettle`](smartcontracts/evm/src/dex/SCaaSDex.sol#L275), only re-revert on [`SigCheckGasStarved`](smartcontracts/evm/src/common/SigCheck.sol#L24) or [`UAVerifyGas`](smartcontracts/evm/src/dex/ISCaaSDex.sol#L143) if the outer frame itself still holds sufficient gas to have satisfied the required cap (or cap the gas forwarded to each `settleOne`), treating secondary starvation caused by an earlier settlement as `MatchFailed` instead of a whole-call revert.

---

### C6-2 — P3 — `setMarket` Permits Reflexive and Zero-Address Pairs, Polluting Listing Counters for Exchange Routes

- **File:line(s):** [`SCaaSDex.sol:148-164`](smartcontracts/evm/src/dex/SCaaSDex.sol#L148-L164)
- **Claim:** [`SCaaSDex.setMarket`](smartcontracts/evm/src/dex/SCaaSDex.sol#L148) does not validate that `base != quote` or that neither token is `address(0)`. If called reflexively (`setMarket(A, A, true)`), `s.listings[A]` is incremented by 2, marking token `A` as known (`s.listings[A] > 0`) even if no valid two-token market exists for it.
- **Evidence:**
  In [`SCaaSDex.sol:148-160`](smartcontracts/evm/src/dex/SCaaSDex.sol#L148-L160):
  ```solidity
  function setMarket(address base, address quote, bool listed) external {
      DexStorage storage s = _onlyAdmin();
      bytes32 k = _pair(base, quote);
      if (s.listed[k] != listed) {
          s.listed[k] = listed;
          if (listed) {
              ++s.listings[base];
              ++s.listings[quote];
          } else {
              --s.listings[base];
              --s.listings[quote];
          }
      }
  ...
  ```
  [`settleOne`](smartcontracts/evm/src/dex/SCaaSDex.sol#L305) guards itself via [`_checkMarket`](smartcontracts/evm/src/dex/SCaaSDex.sol#L341) (`if (a == b) revert TokenMismatch()`). However, on the exchange path, [`_exchangeIn`](smartcontracts/evm/src/dex/SCaaSDex.sol#L498) lines 509–510 only check:
  ```solidity
  if (s.listings[l.sellToken] == 0) revert TokenNotKnown(l.sellToken);
  if (s.listings[rt] == 0) revert TokenNotKnown(rt);
  ```
  A reflexive listing entry allows an admin misconfiguration to activate `tokenKnown` for an unpairable token.
- **Suggested fix:** In [`SCaaSDex.setMarket`](smartcontracts/evm/src/dex/SCaaSDex.sol#L148), require `base != quote && base != address(0) && quote != address(0)`.

---

### C6-3 — P3 — Residual Approval Exposure for Non-Standard Allowance Selectors in `mtxExchange`

- **File:line(s):** [`SCaaSDex.sol:451-458, 545-546`](smartcontracts/evm/src/dex/SCaaSDex.sol#L451-L458), [`docs/contracts/dex.md:538`](docs/contracts/dex.md#L538)
- **Claim:** In [`SCaaSDex.mtxExchange`](smartcontracts/evm/src/dex/SCaaSDex.sol#L446), the interaction blocklist only filters `increaseAllowance` (`0x39509351`) and Permit2 `approve` (`0x87517c45`), while tracking and resetting only standard ERC-20 `approve(address,uint256)`. Alternative allowance selectors (e.g. legacy OpenZeppelin `increaseApproval(address,uint256)` `0xd73dd623`) are neither forbidden nor recorded for zeroing.
- **Evidence:**
  In [`SCaaSDex.sol:545-546`](smartcontracts/evm/src/dex/SCaaSDex.sol#L545-L546):
  ```solidity
  if (sel == INCREASE_ALLOWANCE || sel == PERMIT2_APPROVE) revert ForbiddenSelector(x.target, sel);
  ```
  And in [`SCaaSDex.sol:453-458`](smartcontracts/evm/src/dex/SCaaSDex.sol#L453-L458):
  ```solidity
  if (sel == IERC20.approve.selector) {
      approvedToken[na] = xs[i].target;
      (approvedSpender[na++],) = abi.decode(xs[i].data[4:], (address, uint256));
  }
  ...
  for (uint256 i; i < na; ++i) IERC20(approvedToken[i]).forceApprove(approvedSpender[i], 0);
  ```
  `docs/contracts/dex.md:538` documents: *"other allowance-raising calls (e.g. increaseApproval) are neither refused nor reset, so the admin lists only targets whose flows do not need them, and conservation still bounds a call"*.
  While residual allowances cannot move funds between calls because the DEX balance is restored to snapshot, if the admin lists an interaction target that uses alternative allowance interfaces, residual approvals remain active on the DEX contract.
- **Suggested fix:** Either add `increaseApproval` (`0xd73dd623`) to [`ForbiddenSelector`](smartcontracts/evm/src/dex/ISCaaSDex.sol#L154) or enforce DEX listed-only mode (`listedOnly = true`) globally.

---

## Checked and Sound

1. **Order signatures cover every term and cannot be replayed or cross-matched:**  
   [`TradeLib.hashStruct`](smartcontracts/evm/src/trade/TradeLib.sol#L54) and [`hashStructUA`](smartcontracts/evm/src/trade/TradeLib.sol#L60) hash all 13 order fields (`from`, `receiveToken`, `amount`, `receiveAmount`, `minFill`, `fee`, `relayer`, `dex`, `destination`, `flags`, `batch`, `nonce`, `validUntil`), bound to the chain and contract via [`SaltedEIP712`](smartcontracts/evm/src/common/SaltedEIP712.sol#L15) with `salt = CHAIN_UID`, while [`SCaaSDex.settleOne`](smartcontracts/evm/src/dex/SCaaSDex.sol#L305) lines 319, 325, 343 and 378 enforce strict token pair symmetry, unique maker orders, and `o.dex == address(this)`.

2. **Fill amount tracking and partial fill boundaries:**  
   [`TradeLib.record`](smartcontracts/evm/src/trade/TradeLib.sol#L102) lines 107–113 assert `p < o.amount` and `move <= o.amount - p`, strictly enforcing effective minimum fill `max(minFill, ceil(amount/2))` on every partial fill unless closing the exact remaining balance.

3. **Cancel and nonce invalidation effectiveness and non-griefability:**  
   [`TradeLib.cancel`](smartcontracts/evm/src/trade/TradeLib.sol#L146) permanently closes orders by setting `pulled[h] = amount` (idempotent, unexpirable per CTR-DEX-02), and [`TradeLib.invalidate`](smartcontracts/evm/src/trade/TradeLib.sol#L155) lines 158–160 enforces strictly increasing nonces capped at `MAX_MIN_NONCE = 2**128` to prevent lane denial-of-service.

4. **Settlement atomicity and value conservation:**  
   Each settlement in [`SCaaSDex.mtxSettle`](smartcontracts/evm/src/dex/SCaaSDex.sol#L275) executes via an isolated self-call to [`settleOne`](smartcontracts/evm/src/dex/SCaaSDex.sol#L305) that verifies `_bal(tokenA) == balA` and `_bal(tokenB) == balB` (reverting [`ConservationBroken`](smartcontracts/evm/src/dex/ISCaaSDex.sol#L149) on fee-on-transfer, rebasing, or rounding mismatch), while [`_exchangeOut`](smartcontracts/evm/src/dex/SCaaSDex.sol#L554) enforces exact balance restoration to snapshot across every plan token.

5. **Lying-router resistance on the exchange path:**  
   [`SCaaSDex._exchangeOut`](smartcontracts/evm/src/dex/SCaaSDex.sol#L554) lines 558–561 measures contract balances directly (`bal = _bal(x.token)`) against `keep = snap + refunds + floors`, reverting [`InsufficientOutput`](smartcontracts/evm/src/dex/ISCaaSDex.sol#L156) without trusting any external router return values.

6. **Pull authorization and single-use (`DexPuller`, `pulled`):**  
   [`DexPuller.pull`](smartcontracts/evm/src/dex/DexPuller.sol#L23) lines 24–27 restricts caller strictly to immutable `dex`, hardcodes recipient to `dex`, and is only invoked by [`SCaaSDex._pull`](smartcontracts/evm/src/dex/SCaaSDex.sol#L398) after signature verification and [`TradeLib.record`](smartcontracts/evm/src/trade/TradeLib.sol#L102) updates `pulled[h]`.

7. **Immunity to forged gas starvation selectors (review W-O verification):**  
   [`DexPuller.pull`](smartcontracts/evm/src/dex/DexPuller.sol#L23) lines 28–32, [`SCaaSDex._send`](smartcontracts/evm/src/dex/SCaaSDex.sol#L600), and [`SCaaSDex._tokenFailed`](smartcontracts/evm/src/dex/SCaaSDex.sol#L608) drop all callee revert data and revert [`SafeERC20FailedOperation`](smartcontracts/evm/src/dex/DexPuller.sol#L31), completely closing the V3-01 forged selector vulnerability.

8. **Customer chain gas bounds and EIP-7825 ($2^{24}$ limit):**  
   No `block.gaslimit` or zero-gas-price assumptions exist in code, returndata copies are strictly capped by [`MAX_REASON = 256`](smartcontracts/evm/src/dex/SCaaSDex.sol#L51) and 32 bytes in [`SigCheck`](smartcontracts/evm/src/common/SigCheck.sol#L67) / [`_bal`](smartcontracts/evm/src/dex/SCaaSDex.sol#L620), and ERC-1271 checks execute under strict staticcall gas limits (50k / 400k).

9. **Relayability and `fee = 0` validity:**  
   Every state-changing `mtx*` function is callable by any relayer (respecting signed `o.relayer`), and zero fees (`o.fee == 0`) calculate `c.fee = 0`, `relayerShare = 0`, and `treasuryShare = 0` with zero-amount payouts skipped via [`_send`](smartcontracts/evm/src/dex/SCaaSDex.sol#L600) line 601 (`if (amount != 0 ...)`).

10. **Access control and initialization integrity:**  
    [`SCaaSDex.initialize`](smartcontracts/evm/src/dex/SCaaSDex.sol#L135) is callable only once by immutable `FACTORY`, `admin` has no setter and holds zero fund-withdrawal capabilities, and [`settleOne`](smartcontracts/evm/src/dex/SCaaSDex.sol#L305) enforces `msg.sender == address(this)`.

---

## Not Covered

- **Non-EVM settlement programs:** Cosmos CW20, Soroban, Sui, Aptos, and TON/GRAM settlement implementations under `networks/` (out of EVM C6 unit scope).
- **Core precompile internals:** The C / Rust cryptographic implementation of the PQZ precompile at `0x...5caa0f01` (covered separately in review 2026-10-25).
- **Off-chain node venue and matcher:** Off-chain order intake, book state, price-time priority matching engine, and simulation heuristics in `node/`.
- **Token wrapper contracts outside DEX interfaces:** Minting, reserve calculation, and collateral mechanics in `smartcontracts/evm/src/metatx/UnderlyingToken.sol` beyond the `mtxTrade` / `uaTrade` pull and transfer interface.
