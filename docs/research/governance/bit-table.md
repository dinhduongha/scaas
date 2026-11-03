> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Governance bit table (2026-11-02)

The table after the owner's decisions of 2026-11-02 (CTR-GOV-10 to CTR-GOV-18). One table on every SCaaS contract: a bit is
allocated once, never reused, never renumbered, and a contract without the power leaves the bit off.

Bits 0-8 are the existing flags. Bits 13 and 14 are settled as unused. The rest are proposed until the governance spec fixes
them. Nothing above bit 4 is built.

| Bit | Mask | Name | Meaning | Type | Status |
|---|---|---|---|---|---|
| 0 | `0x1` | `PAYABLE` | anyone may pay through the pay entries | capability | built |
| 1 | `0x2` | `MINTABLE` | a holder creates units | power | built |
| 2 | `0x4` | `BURNABLE` | any holder of units destroys its own | capability | built |
| 3 | `0x8` | `RATE_ADJUSTABLE` | a holder changes a rate under the rate timelock | power | built |
| 4 | `0x10` | `WRAP_DISABLEABLE` | a holder closes an inflow, one-way | power | built |
| 5 | `0x20` | `FREEZE` | a holder stops one account, bounded in time | power | specified, refused by code |
| 6 | `0x40` | `FORCE` | a holder moves units out of a frozen account to a recorded beneficiary | power | specified, refused by code |
| 7 | `0x80` | `PAUSE` | a holder stops the whole token, bounded in time | power | specified, refused by code |
| 8 | `0x100` | `ALLOWLIST` | a receiver must hold `requiredFlags` | capability | specified, refused by code |
| 9 | `0x200` | `DENYLIST` | a receiver must not hold `deniedFlags` | capability | new, CTR-GOV-18, refused by code |
| 10 | `0x400` | `RECORD` | a holder writes a compliance record | power | proposed, later |
| 11 | `0x800` | `LISTING` | a holder decides what the instance trades | power | the DEX `admin` has it today |
| 12 | `0x1000` | `FEE_ROUTING` | a holder decides who receives fees | power | the DEX `admin` has it today |
| 13 | `0x2000` | unused | never reused, CTR-GOV-14 | | settled |
| 14 | `0x4000` | unused | never reused, CTR-GOV-14 | | settled |
| 15 | `0x8000` | `ARBITRATE` | a holder releases held value to a party fixed at creation | power | reserved name, no spec |
| 16 | `0x10000` | `CORRECT` | a holder appends a correction to a record | power | reserved name, no spec |
| 17 | `0x20000` | `RESCUABLE` | anyone moves what the instance does not owe to `rescueTo` | capability | decided, CTR-GOV-06 |
| 18 | `0x40000` | `PUBLISH` | a holder adds a release to a catalogue | power | later |
| 19 | `0x80000` | `DEPRECATE` | a holder marks a release unusable for new instances | power | later |
| 20 | `0x100000` | `ENABLE_KIND` | a holder turns a catalogue kind on or off | power | later |
| 21 | `0x200000` | `MODERATE` | a holder moves units out of an account, public balances only | power | decided, CTR-GOV-08, -13, later |
| 22-127 | | free | | | |

**Bands (CTR-GOV-10 and its Change, owner 2026-11-04).** 0-127 SCaaS, one meaning everywhere. 128-255 per application
contract, with a label (`APPROVE_LOAN`, `ADD_MEMBER`). No band is refused: a contract's `_validBits()` is the only check.

**Types.** A capability is a behaviour of the instance with no holder. A power is tied to persons: it has holders, and a
`Grant` can limit one.

**Open points.**

- `MINTABLE` is valid only on `NORMAL*` today; hybrid underlying (CTR-GOV-12) needs it on a wrapped kind.
- Flags 5-9 are refused on the confidential kinds today. CTR-GOV-17 opens 5, 6, 7 and 9 on the regulated forms of those kinds,
  with `FORCE` and `MODERATE` on public balances only; bit 8 `ALLOWLIST` stays invalid there.
- `publishEnv`, the factory's strongest power, has no bit.
