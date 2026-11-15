# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Sourced by the matrix's forge runners (run.sh, zether.sh, pqzkeys.sh, wraplimits.sh). remote_fee <rpc>: on a remote
# target (ONCHAIN_REMOTE=1) every transaction forge signs carries a fee with headroom, exported for forge and its children
# (ETH_PRIORITY_GAS_PRICE = --priority-gas-price, the tip; ETH_GAS_PRICE = --with-gas-price, maxFeePerGas of an EIP-1559
# transaction): tip ONCHAIN_TIP (wei, default 1 gwei), max fee ONCHAIN_MAXFEE (wei, default 2 x the current base fee +
# the tip). Old: the fee forge estimated at the simulation, which on a quiet chain (base fee 0) was 1 wei for both; without
# --slow forge signs a whole run up front, the run's first large deploys raised the base fee to 1 wei, and the rest
# (tip 0 at that base fee) were never sealed (wraplimits setup on the SCaaS testnet, 2026-11-15). Call it before each
# forge run: the base fee is read then. A local target keeps forge's own fee.
remote_fee() {
  [ "${ONCHAIN_REMOTE:-0}" = 1 ] || return 0
  _tip=${ONCHAIN_TIP:-1000000000}
  _base=$(cast base-fee --rpc-url "$1")
  ETH_PRIORITY_GAS_PRICE=$_tip
  ETH_GAS_PRICE=${ONCHAIN_MAXFEE:-$((2 * _base + _tip))}
  export ETH_PRIORITY_GAS_PRICE ETH_GAS_PRICE
}
