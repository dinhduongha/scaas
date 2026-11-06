# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutant harness of group 3e (pay-meta-tax spec §14; plan T37-T43). One mutant per run, on a clean tree: the source
edit is applied, the named tests run through `scripts/capped`, the file is restored in the same process (finally), then
`git diff --exit-code -- src` must hold. A mutant is killed when the run fails (rc != 0) and a test went red.

Usage (from smartcontracts/evm): python3 runs/2026-11-07-ua-mtx-merge-paytax/mutants.py list
                                 python3 runs/2026-11-07-ua-mtx-merge-paytax/mutants.py run <id> [<id> ...]
Full output: runs/<date>-ua-mtx-merge-<task>-mut-<id>.log (git-ignored); the line `mutant | test that went red | rc` is
appended to runs/2026-11-07-ua-mtx-merge-<task>-mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
DATE = "2026-11-07"

MTB = "src/metatx/MetaTokenBase.sol"
MW = "src/wallet/MandateWallet.sol"

# id: (task, file, old, new, --match-path glob)
MUTANTS = {
    # ---- T37: PayMeta, free pay lanes, the mandate wallets
    "payno-not-hashed": ("t37", MTB, "keccak256(abi.encode(meta.payNo, meta.schema, meta.body))",
                         "keccak256(abi.encode(meta.schema, meta.body))", "test/metatx/Pay*.t.sol"),
    "old-tag": ("t37", MTB, '"scaas.pay.meta.v2", meta.salt', '"scaas.pay.meta", meta.salt', "test/metatx/Pay*.t.sol"),
    "salt0-allowed": ("t37", MTB, "if (m.salt == 0 || (m.schema == 0)", "if ((m.schema == 0)", "test/metatx/PayMeta.t.sol"),
    "schema-body-rule-dropped": ("t37", MTB, "if (m.salt == 0 || (m.schema == 0) != (m.body.length == 0)) revert",
                                 "if (m.salt == 0) revert", "test/metatx/PayMeta.t.sol"),
    "paymeta-after-transfer": ("t37", MTB,
                               "        _payMeta(t.entryRef, meta);\n        _uaExecuteTransfer(t, 0, auth);\n        return true;",
                               "        _uaExecuteTransfer(t, 0, auth);\n        _payMeta(t.entryRef, meta);\n        return true;",
                               "test/metatx/Pay*.t.sol"),
    "payno-bound-255": ("t37", MTB, "bytes(m.payNo).length > 256", "bytes(m.payNo).length > 255", "test/metatx/PayMeta.t.sol"),
    "payno-bound-257": ("t37", MTB, "bytes(m.payNo).length > 256", "bytes(m.payNo).length > 257", "test/metatx/PayMeta.t.sol"),
    "paymentmeta-skipped": ("t37", MTB, "        emit PaymentMeta(id, m.payNo, m.schema, m.body);\n", "",
                            "test/metatx/Pay*.t.sol"),
    "receiver-fee-paylane-enforced": ("t37", MTB, "|| t.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || feeRecipient == address(0))",
                                      "|| t.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || feeRecipient == address(0)"
                                      " || t.batch != payLane(t.entryRef) || t.nonce != 0)", "test/metatx/PayLanes.t.sol"),
    "wallet-empty-paymeta": ("t37", MW, "amount, FeeMode.NONE, 0, address(0), entryRef,\n                meta)",
                             "amount, FeeMode.NONE, 0, address(0), entryRef,\n                MetaTxLib.PayMeta(0, \"\", 0, \"\"))",
                             "test/wallet/MandateWallet.t.sol"),

    # ---- T38: the relay fee on free lanes
    "relayfee-batch-not-hashed": ("t38", MTB, "t.to, t.value, t.batch, t.nonce,\n            t.validUntil, msg.sender",
                                  "t.to, t.value, t.nonce,\n            t.validUntil, msg.sender", "test/metatx/MtxRelayFee.t.sol"),
    "relayfee-nonce-not-hashed": ("t38", MTB, "t.to, t.value, t.batch, t.nonce,\n            t.validUntil, msg.sender",
                                  "t.to, t.value, t.batch,\n            t.validUntil, msg.sender", "test/metatx/MtxRelayFee.t.sol"),
    "router-nonce-not-passed": ("t38", "src/metatx/MtxRelayFee.sol", "payee, value, batch, nonce, validUntil, auth);",
                                "payee, value, batch, 0, validUntil, auth);", "test/metatx/MtxRelayFee.t.sol"),
    "relayref-changed": ("t38", MTB, 'abi.encodePacked("scaas.relayfee", block.chainid, target, callDataHash)',
                         'abi.encodePacked("scaas.relayfee.v2", block.chainid, target, callDataHash)',
                         "test/metatx/MtxRelayFee.t.sol"),

    # ---- T39: bit 23 `TAX`, the rate and the recipient
    "tax-bit-on-plain-kind": ("t39", "src/governance/GovernanceBits.sol",
                              "uint256 internal constant NORMAL_BITS = (1 << PAYABLE) | (1 << MINTABLE) | (1 << BURNABLE) | (1 << RESCUABLE);",
                              "uint256 internal constant NORMAL_BITS = (1 << PAYABLE) | (1 << MINTABLE) | (1 << BURNABLE) | (1 << RESCUABLE) | (1 << TAX);",
                              "test/governance/GovRegulatedBits.t.sol"),
    "tax-bit-contract-only": ("t39", "src/regulated/RegulatedBase.sol",
                              "uint256 internal constant REG_CONTRACT_ONLY = GovernanceBits.REGULATED_ROLES;",
                              "uint256 internal constant REG_CONTRACT_ONLY = GovernanceBits.REGULATED_ROLES | (1 << GovernanceBits.TAX);",
                              "test/as/{Tax,RegulatedSkeleton}.t.sol"),
    "tax-bit-not-issuer": ("t39", "src/governance/GovernanceBits.sol",
                           "(1 << FREEZE) | (1 << FORCE) | (1 << PAUSE) | (1 << TAX);", "(1 << FREEZE) | (1 << FORCE) | (1 << PAUSE);",
                           "test/as/Tax.t.sol"),
    "tax-bit-delay-relaxed": ("t39", "src/regulated/RegulatedBase.sol",
                              "return GovernanceBits.ISSUER_BITS & ~(uint256(1) << GovernanceBits.TAX);",
                              "return GovernanceBits.ISSUER_BITS;", "test/as/{Tax,RegulatedSkeleton}.t.sol"),
    "tax-increase-before-eta": ("t39", "src/regulated/RegulatedLib.sol", "return t.eta != 0 && block.timestamp >= t.eta",
                                "return t.eta != 0 && block.timestamp + 1 >= t.eta", "test/as/Tax.t.sol"),
    "tax-decrease-delayed": ("t39", "src/regulated/RegulatedLib.sol", "if (ratePpm <= eff) (t.ratePpm",
                             "if (ratePpm < 0) (t.ratePpm", "test/as/Tax.t.sol"),
    "tax-recipient-no-R": ("t39", "src/regulated/RegulatedBase.sol",
                           "        RegulatedLib.setTaxRecipient(taxRecipient, _govSubject(), _REGISTRY);\n        _eligible(taxRecipient);",
                           "        RegulatedLib.setTaxRecipient(taxRecipient, _govSubject(), _REGISTRY);",
                           "test/as/Tax.t.sol"),

    # ---- T40: mtxPayWithTax, payWithTax
    "percent-rounds-up": ("t40", "src/regulated/RegulatedLib.sol", "Math.mulDiv(value, effectiveRate(), 1_000_000)",
                          "Math.mulDiv(value, effectiveRate(), 1_000_000, Math.Rounding.Ceil)", "test/as/Tax.t.sol"),
    "tax-above-amount-allowed": ("t40", "src/regulated/RegulatedLib.sol",
                                 "        if (tax > value) revert IRegulatedToken.TaxExceedsAmount(tax, value);\n", "",
                                 "test/as/Tax.t.sol"),
    "tax-leg-from-payee": ("t40", "src/metatx/ERC20MetaTx.sol", "if (withheld != 0) _uaMove(t.from, withheldTo, withheld);",
                           "if (withheld != 0) _uaMove(t.to, withheldTo, withheld);", "test/as/Tax.t.sol"),
    "payee-credited-gross": ("t40", "src/metatx/ERC20MetaTx.sol", "_uaMove(t.from, t.to, t.value - withheld);",
                             "_uaMove(t.from, t.to, t.value);", "test/as/Tax.t.sol"),
    "recipient-from-calldata": ("t40", "src/regulated/RegulatedLib.sol", "        r = $().taxRecipient;\n",
                                "        r = bytes32(uint256(uint160(msg.sender)));\n", "test/as/Tax.t.sol"),
    "regfeeto-skipped": ("t40", "src/regulated/RegulatedBase.sol", "        _regFeeTo(r, tax);\n", "", "test/as/Tax.t.sol"),
    "paymenttaxed-skipped-at-zero": ("t40", "src/regulated/RegulatedBase.sol",
                                     "        emit PaymentTaxed(t.entryRef, t.to, r, t.from, taxMode, tax, d);",
                                     "        if (tax != 0) emit PaymentTaxed(t.entryRef, t.to, r, t.from, taxMode, tax, d);",
                                     "test/as/Tax.t.sol"),
    "paymenttaxed-without-from": ("t40", "src/regulated/RegulatedBase.sol",
                                  "        emit PaymentTaxed(t.entryRef, t.to, r, t.from, taxMode, tax, d);",
                                  "        emit PaymentTaxed(t.entryRef, t.to, r, 0, taxMode, tax, d);", "test/as/Tax.t.sol"),
    "recipient-hashed-into-struct": ("t40", "src/regulated/RegulatedBase.sol", "MetaTxLib.hashStruct(t), taxMode, tax)",
                                     "MetaTxLib.hashStruct(t), taxMode, tax, r)", "test/as/Tax.t.sol"),
    "paywithtax-payer-is-payee": ("t40", "src/regulated/RegulatedBase.sol", "bytes32 payer = MetaTxLib.pad(_msgSender());",
                                  "bytes32 payer = MetaTxLib.pad(tx.origin);", "test/as/Tax.t.sol"),
}


def red_tests(log):
    return sorted(set(re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log)))


def run(mid):
    task, path, old, new, match = MUTANTS[mid]
    full = os.path.join(EVM, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    logp = os.path.join(EVM, "runs", f"{DATE}-ua-mtx-merge-{task}-mut-{mid}.log")
    try:
        open(full, "w").write(src.replace(old, new))
        with open(logp, "w") as log:
            rc = subprocess.call([CAPPED, FORGE, "test", "--match-path", match], cwd=EVM, stdout=log, stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    clean = subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=EVM)
    if clean != 0:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    red = red_tests(out)
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in out else "none")
    line = f"{mid} | {note} | {rc}"
    print(line)
    with open(os.path.join(EVM, "runs", f"{DATE}-ua-mtx-merge-{task}-mutants.txt"), "a") as f:
        f.write(line + "\n")
    return rc


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "list":
        for k, v in MUTANTS.items():
            print(v[0], k)
    elif sys.argv[1] == "run":
        for mid in sys.argv[2:]:
            run(mid)
