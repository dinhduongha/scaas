// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";

import {Test} from "forge-std/Test.sol";
import {GovernanceBits as B} from "../../src/governance/GovernanceBits.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {plainEnv, regArgs} from "../helpers/Catalogue.sol";

/// @notice `smartcontracts/vectors/governance/governance_bits.json` (spec 2026-11-02-governance §1.2, §1.8, §4.3, §5.5; plan T14):
///         bit → name → type → disclosure sentence, rows 0-24 of the global band (bits 25-127 are free, 128-255 the application's,
///         labelled by `bitLabel`, CTR-GOV-10's Change of 2026-11-04: no row). Written from `GovernanceBits` and the kinds' masks;
///         `WRITE_BITS=true forge test --match-path test/governance/GovBitsVector.t.sol` rewrites it, otherwise the file must equal
///         what this test builds. Every client reads the file (`clientkeys`, `ua-rs` and its wrappers, `ua-py`, `ua-go`, `ua-cs`,
///         `ua-dart`). One row per line: `ua-rs` finds a row by its line. ua-mtx-merge T34 (regulated-kinds spec §7; CTR-GOV-17,
///         CTR-GOV-20): the regulated rows name their kinds (`kinds`, `RegulatedBase`'s masks) and holder rule (`holder`:
///         `contractOrMsig`, RK-1, or `any`, bit 22); bit 21 has no entry; bit 22 `OPERATOR_TRANSFER`; the decoy-fee sentence.
///         Group 3h T61: bit 24 `PQZ_PROOF` (kinds 4, 5, 12, 13; any holder; PQZ proof path spec §5). Group 3l: bits 25
///         `WRAP_LIMIT`, 26 `WRAP_LIST`, 27 `REDEEMER` (the hybrids of 1, 3, 5, 9, 11, 13; wrap limits spec 2026-11-10 §2, §9).
contract GovBitsVectorTest is Test {
    string constant OUT = "../vectors/governance/governance_bits.json";

    /// The bits that have holders on some kind of this release (`_roleBits()` of `NORMAL*`, `WRAPPED*`, `SCaaSDex`).
    uint256 constant ROLES = B.NORMAL_ROLES | B.WRAPPED_ROLES | B.DEX_BITS | B.REGULATED_ROLES | (1 << B.OPERATOR_TRANSFER)
        | (1 << B.TAX) | (1 << B.PQZ_PROOF) | (1 << B.ALLOWLIST) | (1 << B.DENYLIST);
    /// The last row (CTR-GOV-20).
    uint256 constant LAST = B.KYC; // round 3s (CTR-GOV-24; was B.REDEEMER, group 3l; B.PQZ_PROOF, group 3h T61)
    /// `RegulatedBase`'s masks (internal there), composed from the same constants: the bits 8-13 add, without `ALLOWLIST` on
    /// 10-13 (CTR-GOV-17); the contract-only ones (an `msig` UA counts, RK-1); bit 22 any holder. Kind 8's `validBits()` is
    /// held to `REG` below, kinds 9 and 13 in `RegulatedSkeleton.test_masks`.
    uint256 constant REG = B.REGULATED | (1 << B.RECORD) | (1 << B.MODERATE) | (1 << B.OPERATOR_TRANSFER) | (1 << B.TAX);
    uint256 constant REG_CONFIDENTIAL = REG & ~(uint256(1) << B.ALLOWLIST);
    uint256 constant REG_CONTRACT_ONLY = B.REGULATED_ROLES;
    uint256 constant REG_ROLES =
        B.REGULATED_ROLES | (1 << B.ALLOWLIST) | (1 << B.DENYLIST) | (1 << B.OPERATOR_TRANSFER) | (1 << B.TAX);

    uint256 private _next;

    /// One row. `type` is checked against the masks where they decide it: a role bit is a power, an always-locked bit a capability.
    function _row(uint256 bit, string memory name, string memory ty, string memory sentences)
        private
        returns (string memory)
    {
        assertEq(bit, _next, "rows in bit order, none missing");
        _next = bit + 1;
        if (ROLES & (1 << bit) != 0) assertEq(ty, "power", name);
        if (B.ALWAYS_LOCKED & (1 << bit) != 0) assertEq(ty, "capability", name);
        return string.concat(
            '    {"bit": ',
            vm.toString(bit),
            ', "name": "',
            name,
            '", "type": "',
            ty,
            '", ',
            _regulated(bit),
            '"sentences": {',
            sentences,
            "}}",
            bit == LAST ? "\n" : ",\n"
        );
    }

    /// The kinds a regulated bit is valid on (`REG` on 8 and 9, `REG_CONFIDENTIAL` on 10-13) and its
    /// holder rule: `contractOrMsig` for the contract-only regulated roles (an `msig` UA counts, RK-1), `any` for bit 22.
    function _regulated(uint256 bit) private pure returns (string memory r) {
        uint256 m = 1 << bit;
        // group 3h T61: bit 24 is a PQZ kinds' bit (4, 5, 12, 13), any holder, never contract-only (spec §5, O10)
        if (bit == B.PQZ_PROOF) return '"kinds": [4, 5, 12, 13], "holder": "any", ';
        // group 3l: the hybrids of the wrapped kinds; 25 a capability, 26 and 27 any holder (spec §2)
        if (bit == B.WRAP_LIMIT) return '"kinds": [1, 3, 5, 9, 11, 13], ';
        if (bit == B.WRAP_LIST || bit == B.REDEEMER) return '"kinds": [1, 3, 5, 9, 11, 13], "holder": "any", ';
        if (REG & m == 0) return "";
        r = REG_CONFIDENTIAL & m != 0 ? '"kinds": [8, 9, 10, 11, 12, 13], ' : '"kinds": [8, 9], ';
        if (REG_CONTRACT_ONLY & m != 0) return string.concat(r, '"holder": "contractOrMsig", ');
        if (REG_ROLES & m != 0) return string.concat(r, '"holder": "any", ');
    }

    function _one(string memory key, string memory text) private pure returns (string memory) {
        return string.concat('"', key, '": "', text, '"');
    }

    function _build() private returns (string memory j) {
        j = string.concat(
            "{\n",
            '  "note": "Generated by smartcontracts/evm/test/governance/GovBitsVector.t.sol (WRITE_BITS=true) from GovernanceBits and the kinds',
            " masks; never edit by hand. Spec 2026-11-02-governance 1.2, 1.8, 4.3, 5.5. A wallet prints one sentence per set bit of features()",
            " (sentences.all, or the one its class selects: bit 1 plain or hybrid on maxSupply() != 0, bit 5 public or confidential by kind).",
            " type: capability (no holder), power (has holders), unused, reserved. kinds: the token kinds a regulated bit, bit 24 or bits 25-27 (hybrids only) is valid on;",
            " holder: contractOrMsig (a native id with code or a threshold msig UA, sentences.msig) or any. Bits 29-127 are free; bits 128-255 are the application",
            " contract's own, the word is bitLabel(bit), never a row here (CTR-GOV-10 Change, owner 2026-11-04). {x} is a value the wallet",
            ' reads on chain.",\n',
            '  "version": 1,\n',
            '  "bits": [\n'
        );
        j = string.concat(
            j,
            _row(
                B.PAYABLE,
                "PAYABLE",
                "capability",
                _one("all", "Anyone may pay through the pay entries; always locked.")
            )
        );
        j = string.concat(
            j,
            _row(
                B.MINTABLE,
                "MINTABLE",
                "power",
                string.concat(
                    _one("plain", "A holder of this power creates new units, within its grant."),
                    ", ",
                    _one(
                        "hybrid",
                        unicode"This token is not fully backed. Supply, wraps included, is capped at {maxSupply}; at the cap, deposits stop. [Its issuer can mint up to {maxSupply − totalSupply} more units, and by filling the cap it can stop deposits.] [Its issuer can lower the rate with no top-up, which also leaves the reserve short.] Any unit, the issuer's included, redeems for the underlying at the rate while the reserve lasts, first come, with no share and no queue. When the reserve is empty your units stay valid, and redeeming the underlying on chain stops; your way out is then off chain."
                    ),
                    ", ",
                    _one(
                        "hybridBrackets",
                        "Printed when maxSupply() != 0, before a wrap. The first bracket prints only while bit 1 is set, the second only while bit 3 is set."
                    )
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.BURNABLE,
                "BURNABLE",
                "capability",
                _one("all", "Any holder of units may destroy its own; always locked.")
            )
        );
        j = string.concat(
            j,
            _row(
                B.RATE_ADJUSTABLE,
                "RATE_ADJUSTABLE",
                "power",
                _one("all", "A holder changes a conversion rate under the rate timelock; the holder is a contract.")
            )
        );
        j = string.concat(
            j, _row(B.WRAP_DISABLEABLE, "WRAP_DISABLEABLE", "power", _one("all", "A holder closes an inflow, one-way."))
        );
        j = string.concat(
            j,
            _row(
                B.FREEZE,
                "FREEZE",
                "power",
                string.concat(
                    _one(
                        "public",
                        "A holder stops one account from sending, bounded in time: that account in any role, the envelope from of a meta-tx op included."
                    ),
                    ", ",
                    _one(
                        "confidential",
                        "A holder stops one account from sending, bounded in time: that account as a proof's sender; an envelope from is not read."
                    )
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.FORCE,
                "FORCE",
                "power",
                _one(
                    "all",
                    "A holder moves units out of a frozen account to a recorded beneficiary; public balances only."
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.PAUSE,
                "PAUSE",
                "power",
                _one(
                    "all",
                    "A holder stops transfers, mints, wraps, shields, unshields and every relayed fee, bounded in time; unwrap of public units, holder burn, a forced transfer and roll-over are never paused."
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.ALLOWLIST,
                "ALLOWLIST",
                "power",
                string.concat(
                    _one(
                        "on",
                        "Only listed accounts may hold and move this token's public balance: an unlisted account can neither send, receive, burn nor unwrap, contracts such as the DEX included; a holder of this power lists or unlists an account at once. Once on, this check is never switched off."
                    ),
                    ", ",
                    _one(
                        "enableable",
                        "The admin can switch on an allow list at any time, at once, with no notice but the event; it is never switched off."
                    )
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.DENYLIST,
                "DENYLIST",
                "power",
                string.concat(
                    _one(
                        "on",
                        "An account on the deny list can neither send, receive, burn nor unwrap this token's public balance, contracts such as the DEX included; a holder of this power denies or clears an account at once. Unlike a freeze it has no end date and no record behind it, and a single key may hold this power. Once on, this check is never switched off."
                    ),
                    ", ",
                    _one(
                        "confidential",
                        "On a confidential kind a denied account still receives shielded credits and each leg's decoyFee; its public balance, its sends and its unshields are stopped."
                    ),
                    ", ",
                    _one(
                        "enableable",
                        "The admin can switch on a deny list at any time, at once, with no notice but the event; it is never switched off."
                    )
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.RECORD,
                "RECORD",
                "power",
                _one(
                    "all",
                    "A holder writes a compliance record another power relies on; one holder is refused both this and FORCE."
                )
            )
        );
        j = string.concat(
            j,
            _row(B.LISTING, "LISTING", "power", _one("all", "A holder decides what this instance trades or accepts."))
        );
        j = string.concat(
            j,
            _row(
                B.FEE_ROUTING,
                "FEE_ROUTING",
                "power",
                _one("all", "A holder decides who receives this instance's fees, never how much.")
            )
        );
        j = string.concat(j, _row(13, "", "unused", _one("all", "Never allocated, never reused.")));
        j = string.concat(j, _row(14, "", "unused", _one("all", "Never allocated, never reused.")));
        j = string.concat(
            j, _row(15, "ARBITRATE", "reserved", _one("all", "Reserved name, no spec behind it, no meaning yet."))
        );
        j = string.concat(
            j, _row(16, "CORRECT", "reserved", _one("all", "Reserved name, no spec behind it, no meaning yet."))
        );
        j = string.concat(
            j,
            _row(
                B.RESCUABLE,
                "RESCUABLE",
                "capability",
                _one("all", "Anyone may move what this instance does not owe to rescueTo(); always locked.")
            )
        );
        j = string.concat(
            j, _row(18, "PUBLISH", "power", _one("all", "A holder adds a release or an environment to a catalogue."))
        );
        j = string.concat(
            j,
            _row(
                19,
                "DEPRECATE",
                "power",
                _one("all", "A holder marks a release unusable for new instances, never undone.")
            )
        );
        j = string.concat(
            j, _row(20, "ENABLE_KIND", "power", _one("all", "A holder turns a catalogue kind on or off."))
        );
        j = string.concat(
            j,
            _row(
                B.MODERATE,
                "MODERATE",
                "power",
                _one(
                    "all",
                    "A power with no entry yet: its meaning, hierarchical moderation, is still open (owner 2026-11-05); a holder can do nothing with it."
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.OPERATOR_TRANSFER,
                "OPERATOR_TRANSFER",
                "power",
                _one(
                    "all",
                    "A holder moves public units out of an account to another, no record, within its grant, subject to FREEZE, PAUSE and the receiver check; any holder, a person's key included."
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.TAX,
                "TAX",
                "power",
                _one(
                    "all",
                    "Any holder (an EOA too) sets the tax recipient and the one PERCENT rate; a rate increase waits the factory's notice period (shown; it may be 0 on a test chain), a decrease is immediate and makes PERCENT payments in flight fail; a recipient change is immediate and is not signed by the payer; an AMOUNT tax is the payer's signed figure, unchecked by the contract; the owner can stop tax collection at once."
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.PQZ_PROOF,
                "PQZ_PROOF",
                "power",
                _one(
                    "all",
                    "A holder chooses whether the token also logs each later debit's proof as an event, or leaves it in the transaction's calldata only. Both live in the chain's history. Disabling the bit keeps the current choice for good."
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.WRAP_LIMIT,
                "WRAP_LIMIT",
                "capability",
                _one(
                    "all",
                    "The admin may limit wraps and unwraps per leg: a short and a long fixed window per direction, per account and optionally for all accounts together, counted in the underlying moved in quanta of 10^unitExp of the leg; it may require that an account unwraps at most what it wrapped net of its unwraps (rounded against the account), and let that entitlement decay linearly to 0 over a horizon counted from a weighted-average start (an unwrap and a new wrap make the start younger). Tightening the unwrap side and loosening the wrap side wait the factory's notice period {noticePeriod} (0: at once); the rest applies at once. A window can pass up to twice its cap across its boundary; per-account limits can be split across accounts; a token-wide unwrap cap can be used up by one holder; an account that wrapped before the first configuration has no entitlement; units the issuer mints never count; after a rate rise the extra underlying is not redeemable under the rule; an account with unused entitlement can unwrap other holders' units; a shielded account is a separate account from the public one that wrapped."
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.WRAP_LIST,
                "WRAP_LIST",
                "power",
                _one(
                    "all",
                    "The admin may let only listed accounts wrap, or only listed accounts unwrap (turning the unwrap list on waits the notice period); any holder of this power adds or removes an account at once, which can stop that account's unwraps at once."
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.REDEEMER,
                "REDEEMER",
                "power",
                _one(
                    "all",
                    "A holder unwraps beyond its net-wrapped entitlement, within its grant's budget in the leg's units and the unwrap limits; it can take reserve that other holders' entitlements count on. A revoke is immediate."
                )
            )
        );
        j = string.concat(
            j,
            _row(
                B.KYC,
                "KYC",
                "capability",
                string.concat(
                    _one(
                        "all",
                        "No holder, parameters complianceRegistry(), requiredFlags() and deniedFlags(): a receiver of a public balance must hold requiredFlags and none of deniedFlags in that ComplianceRegistry, pinned at creation. The admin can switch it on at once, and off after grantDelay. Read complianceRegistry(), never registry(), which is the UA registry."
                    ),
                    ", ",
                    _one(
                        "enableable",
                        "The admin can switch on the compliance registry check at any time, at once, with no notice but the event."
                    )
                )
            )
        );
        j = string.concat(
            j,
            "  ],\n",
            '  "sentences": {\n',
            '    "delegable": "Can add unlimited leaves at once, sharing a remaining budget of {N}.",\n',
            '    "leg": "Its issuer can stop unwraps of this leg.",\n',
            '    "legWhen": "Per leg of underlyings() that is a registered token with bit 5, 7, 8, 9 or 28 set, or one of 8, 9, 28 enableable on it (spec 1.8 step 6; round 3s: read the leg\'s features() and lockedFeatures() live).",\n',
            '    "enableableWhen": "Bit 8, 9 or 28 is enableable when it is valid for the kind, not set, not locked (off), admin() is not 0, and for 28 complianceRegistry() is not 0 (round 3s, CTR-GOV-24). A wallet prints the bit\'s enableable sentence then, and never for a bit locked off.",\n',
            '    "grantDelay": "grantDelay delays an address, never who controls it.",\n',
            '    "grantDelayWhen": "Once, for every holder that is a contract (CTR-GOV-15).",\n',
            '    "msig": "On a regulated kind a holder of bit 5, 6, 7, 10 or 21 is a contract: a native id with code or a threshold (msig) UA; a single-key UA is refused (RK-1).",\n',
            '    "decoyFee": "A multi-recipient shielded transfer pays each leg its decoyFee unchecked: a frozen or denied account named as a leg still receives it, bounded only by minDecoyFee <= d < 2^64, and one leg is enough to reach a denied account\'s public balance.",\n',
            '    "decoyFeeWhen": "On kinds 10-13 with bit 5, 9 or 28 set (CTR-GOV-17; round 3s: denied by the token\'s list or by the registry)."\n',
            "  }\n",
            "}\n"
        );
    }

    /// The file equals what the constants build; `WRITE_BITS=true` writes it first. A bit moved in `GovernanceBits` breaks the bit
    /// order; a type against the masks fails its row; an edit of the file fails the comparison.
    function test_bitsVectorEqualsTheConstants() public {
        string memory j = _build();
        assertEq(_next, LAST + 1, "rows 0-28");
        if (vm.envOr("WRITE_BITS", false)) vm.writeFile(OUT, j);
        assertEq(
            vm.readFile(OUT),
            j,
            "governance_bits.json is stale: WRITE_BITS=true forge test --match-path test/governance/GovBitsVector.t.sol"
        );
    }

    /// The regulated rows' masks are kind 8's: its `validBits()` is its base kind's plus `REG`.
    function test_regulatedRowsEqualKind8() public {
        address impl = address(new NormalRegulatedToken(address(this), kindArgs(8, address(this), regArgs())));
        assertEq(NormalRegulatedToken(impl).validBits(), B.NORMAL_BITS | REG);
    }

    /// The kinds' masks are what the rows say: every role bit and every valid bit of this release has a row with a name.
    function test_everyBitOfAKindHasANamedRow() public {
        string memory j = _build();
        uint256 all =
            ROLES | B.NORMAL_BITS | B.WRAPPED_BITS | B.DEX_BITS | REG;
        for (uint256 bit; bit < 256; ++bit) {
            if (all & (1 << bit) == 0) continue;
            assertLe(bit, LAST, "a row exists");
            assertFalse(vm.parseJsonUint(j, string.concat(".bits[", vm.toString(bit), "].bit")) != bit, "row index");
            assertGt(
                bytes(vm.parseJsonString(j, string.concat(".bits[", vm.toString(bit), "].name"))).length, 0, "named"
            );
        }
    }
}
