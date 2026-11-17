# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-liquidity L8 (spec 2026-11-10-dex-liquidity.md §14) mutants: one at a time, each edit applied to its src/ file, forge
through `scripts/capped` on test/liquidity (the invariant left out; the tree's own out and cache, so each run is incremental), the
file restored in the same process and checked
byte-equal to its content before the run. Each must turn a named negative (or positive) red while the original stays green.

Usage (from smartcontracts/evm): python3 runs/2026-11-10-ua-mtx-liquidity/mutants.py list | run [<id> ...]
Full output: runs/2026-11-10-ua-mtx-liquidity/mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-10-ua-mtx-liquidity/mutants.txt.
"""
import hashlib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
M = "src/dex/SCaaSDexLiquidityModule.sol"
C = "src/dex/SCaaSDexCore.sol"
D = "src/dex/SCaaSDex.sol"
T = "src/metatx/ERC20MetaTx.sol"
L = "src/trade/LiquidityLib.sol"
ALL = "test/liquidity/*.t.sol"


def drop(f, line, n=1):
    return (f, line, "", n)


MUTANTS = {
    "M-L1": [drop(M, "        if ((ni == 0 && o.positionIn == 0) || (no == 0 && !received)) revert ISCaaSDex.LiquidityShape(1);\n")],
    "M-L2": [drop(M, "        if (ni > MAX_ITEMS || no > MAX_ITEMS || ne > MAX_ITEMS) revert ISCaaSDex.LiquidityShape(2);\n")],
    "M-L3": [drop(M, "            for (uint256 b; b < a; ++b) if (tok[b] == tok[a]) revert ISCaaSDex.LiquidityShape(3);\n")],
    "M-L4": [drop(M, "        if ((p.positionId != 0) != received) revert ISCaaSDex.LiquidityShape(4);\n")],
    "M-L5": [drop(M, "        for (uint256 a; a < tok.length; ++a) if (to == TradeLib.pad(tok[a])) revert ISCaaSDex.LiquidityShape(5);\n")],
    "M-L6": [drop(M, "        if (o.relayer != address(0) && o.relayer != submitter) revert ISCaaSDex.WrongRelayer(submitter);\n")],
    "M-L7": [drop(M, "        if (block.timestamp > o.validUntil) revert ISCaaSDex.OrderExpired(h);\n")],
    "M-L8": [drop(M, "        if (o.nonce >= TradeLib.MAX_MIN_NONCE) revert ISCaaSDex.NonceAboveCap(h);\n")],
    "M-L9": [drop(M, "        if (o.nonce < t.minNonce[o.from][o.batch]) revert ISCaaSDex.NonceInvalidated(h);\n")],
    "M-L10": [drop(M, "        if (o.flags & ~LISTED_POOLS != 0) revert ISCaaSDex.BadFlags(h);\n")],
    "M-L11": [drop(M, "        if (o.fee > TradeLib.MAX_FEE_PPM) revert ISCaaSDex.FeeAboveCap(h);\n")],
    "M-L12": [drop(M, "        if (t.pulled[h] != 0) revert ISCaaSDex.OrderClosed(h);\n")],
    "M-L13": [drop(M, "            if (p.pull[i] > o.inputs[i].amount) revert ISCaaSDex.Overfill(h);\n")],
    "M-L14": [drop(M, "            if (derived && !_ledgerOn(tk)) revert ISCaaSDex.UALegNotLedger(tk);\n")],
    "M-L15": [drop(M, "                if (!_ledgerOn(o.outputs[j].token)) revert ISCaaSDex.UAReceiveNotLedger(o.outputs[j].token);\n")],
    "M-L16": [(M, "        if (verify && !SigCheck.isValid(", "        if (false && !SigCheck.isValid(", 1)],
    "M-L17": [(M, "            if (_bal(r.tok[i]) != r.snap[i] + p.pull[i]) revert", "            if (false) revert", 1)],
    "M-L18": [(M, "            if (_ownerOf(o.positionManager, o.positionIn) != uint160(address(this))) {", "            if (false) {", 1)],
    "M-L19a": [(C, "if (sel == ILiquidityPullToken.mtxLiquidityPull.selector || sel == SET_APPROVAL_FOR_ALL) {",
                "if (sel == SET_APPROVAL_FOR_ALL) {", 1)],
    "M-L19b": [(C, "if (sel == ILiquidityPullToken.mtxLiquidityPull.selector || sel == SET_APPROVAL_FOR_ALL) {",
                "if (sel == ILiquidityPullToken.mtxLiquidityPull.selector) {", 1)],
    "M-L19c": [(M, "if (xs[i].target == pm && bytes4(xs[i].data) == IERC20.approve.selector) {", "if (false) {", 1)],
    "M-L21": [(M, "            if (_ownerOf(pm, id) != uint160(address(this))) revert ISCaaSDex.PositionNotReceived(id);\n", "", 1)],
    "M-L22": [(M, "if (!_s().exchangeTarget[rd] || !ok || m != uint160(pm))", "if (!ok || m != uint160(pm))", 1)],
    "M-L23a": [(M, "        if (bytes32(pool) != o.positionPool || lo != uint256(int256(o.tickLower)) || hi != uint256(int256(o.tickUpper))\n"
                   "            || enc != 0) revert ISCaaSDex.PositionMismatch(id);\n", "", 1)],
    "M-L23b": [drop(M, "            ok := and(ok, gt(returndatasize(), 0x9f))\n")],
    "M-L24": [drop(M, "        if (liq < o.minLiquidity) revert ISCaaSDex.PositionBelowMin(id, uint128(liq));\n")],
    "M-L26a": [drop(M, "            if (got - fee < min) revert ISCaaSDex.InsufficientOutput(tk);\n")],
    "M-L26b": [drop(M, "            if (rb < r.rsnap[j] || rb - r.rsnap[j] < min) revert ISCaaSDex.InsufficientOutput(tk);\n")],
    "M-L26c": [(M, "            uint256 rb = _balOf(tk, r.to);\n            if (rb < r.rsnap[j] || rb - r.rsnap[j] < min) revert ISCaaSDex.InsufficientOutput(tk);\n"
                   "            uint256 share = Math.mulDiv(fee, s.relayerSharePpm, PPM);\n            _send(tk, r.submitter, share);\n"
                   "            _send(tk, s.treasury, fee - share);\n",
                "            uint256 share = Math.mulDiv(fee, s.relayerSharePpm, PPM);\n            _send(tk, r.submitter, share);\n"
                "            _send(tk, s.treasury, fee - share);\n            uint256 rb = _balOf(tk, r.to);\n"
                "            if (rb < r.rsnap[j] || rb - r.rsnap[j] < min) revert ISCaaSDex.InsufficientOutput(tk);\n", 1)],
    "M-L27": [(M, "Math.mulDiv(got, o.fee, PPM, Math.Rounding.Ceil)", "Math.mulDiv(got, o.fee, PPM, Math.Rounding.Floor)", 1)],
    "M-L28a": [(M, "            r.refunded[i] = b - r.snap[i];\n",
                "            r.refunded[i] = b - r.snap[i];\n            if (r.refunded[i] > o.inputs[i].amount) revert ISCaaSDex.ConservationBroken(tk);\n", 1)],
    "M-L28b": [drop(M, "            _sendTo(tk, o.from, r.refunded[i]);\n")],
    "M-L29": [(M, "            r.liquidity = _readPosition(o, id);", "            if (id != o.positionIn) r.liquidity = _readPosition(o, id);", 1)],
    "M-L30": [(M, "            (bool ok, uint256 w) = _word(pm, abi.encodeWithSelector(OWNER_OF, o.positionIn));",
               "            (bool ok, uint256 w) = (true, _ownerOf(pm, o.positionIn));", 1)],
    "M-L31": [(M, "            if (_bal(r.tok[i]) != r.snap[i]) revert ISCaaSDex.ConservationBroken(r.tok[i]);", "", 1)],
    "M-L32": [(M, "        if (address(this) == _SELF) revert NotDelegated();\n", "", 1)],
    "M-L34": [(D, "    function mtxLiquidity(LiquidityPlan calldata, Interaction[] calldata) external nonReentrant {",
               "    function mtxLiquidity(LiquidityPlan calldata, Interaction[] calldata) external {", 1)],
    "M-L37": [(L, 'bytes32 internal constant DEX_VERSION_HASH = keccak256("1");', 'bytes32 internal constant DEX_VERSION_HASH = keccak256("2");', 1)],
    "M-T1": [drop(T, "        if (dex == address(this) || !SigCheck.isContract(dex)) revert ITradeToken.DexNotContract(dex); // T1\n")],
    "M-T5": [(T, "        if (seen != 1) revert ITradeToken.LiquidityShape(6);\n", "", 1)],
    "M-T7a": [(T, "        if (!_liquidityDex(dex, abi.encodeCall(ILiquidityDex.liquidityOrderDigest, (o)), h)) {",
               "        if (false && !_liquidityDex(dex, abi.encodeCall(ILiquidityDex.liquidityOrderDigest, (o)), h)) {", 1)],
    "M-T7b": [(D, "    function liquidityOrderDigest(ITradeToken.LiquidityOrder calldata) external view returns (bytes32 r) {\n",
               "    function liquidityOrderDigest(ITradeToken.LiquidityOrder calldata) external view returns (bytes32 r) {\n"
               "        _guardIn();\n", 1)],
    "M-T8b": [(T, "        bytes32 h = LiquidityLib.digest(o, dex, _chainUid());", "        bytes32 h = LiquidityLib.digest(o, submitter, _chainUid());", 1)],
    "M-T9": [drop(T, "        if (t.pulled[h] != 0) revert ITradeToken.OrderClosed(h); // T9\n")],
}


def sha(b):
    return hashlib.sha256(b.encode()).hexdigest()


def run(mid):
    edits = MUTANTS[mid]
    files = sorted({f for f, *_ in edits})
    orig = {f: open(os.path.join(EVM, f)).read() for f in files}
    before = {f: sha(orig[f]) for f in files}
    mut = dict(orig)
    for f, old, new, n in edits:
        if mut[f].count(old) != n:
            raise SystemExit(f"{mid}: the mutated text occurs {mut[f].count(old)} times in {f}, not {n}")
        mut[f] = mut[f].replace(old, new)
    logp = os.path.join(HERE, f"mut-{mid}.log")
    env = {**os.environ, "FOUNDRY_TEST": "test/liquidity"}
    try:
        for f in files:
            open(os.path.join(EVM, f), "w").write(mut[f])
        with open(logp, "w") as log:
            rc = subprocess.call([CAPPED, FORGE, "test", "--no-match-contract", "LiquidityInvariantTest"], cwd=EVM, env=env,
                                 stdout=log, stderr=subprocess.STDOUT)
    finally:
        for f in files:
            open(os.path.join(EVM, f), "w").write(orig[f])
    for f in files:
        if sha(open(os.path.join(EVM, f)).read()) != before[f]:
            raise SystemExit(f"{mid}: {f} not restored byte-equal")
    out = open(logp).read()
    red = sorted(set(re.findall(r"\[FAIL[^\]]*\] (\w+)", out)))
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in out
                                       else "red, unnamed (see the log)" if rc else "none (survived)")
    line = f"{mid} | {note} | {rc}"
    print(line, flush=True)
    with open(os.path.join(HERE, "mutants.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    else:
        for mid in sys.argv[2:] or list(MUTANTS):
            run(mid)
