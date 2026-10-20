// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";
import {IPqzToken} from "./IPqzToken.sol";
import {PqzCt} from "./PqzCt.sol";
import {PqzSafety} from "./PqzSafety.sol";
import {UAPqzVerifier} from "./UAPqzVerifier.sol";
import {PqzCore} from "./PqzCore.sol";

/// @title init, shield, rollover (the account state; D14): one of the four `DELEGATECALL` libraries of the PQZ release (plan 5h D14), in the ERC-7201
///        namespace `scaas.pqz`; the shared steps are `internal` in `PqzCore`, compiled into each.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** `address(this)` is the token.
library PqzStateLib {
    /// @notice The kind's `_init` (P6g plan D9): `verifier` the release's `UAPqzVerifier` (CTR-ZTH-20: the creator never
    ///         chooses one; precompile and proof system: exactly `PqzSafety.PQZ`, PQZL or PQZH,
    ///         the self-test passing now; review W-B), `auditorKey` empty or the auditor's 32-byte `pqz-mlwe` UA, cap
    ///         `≤ 2^62`, fee `< 2^64` and `< cap`.
    function init(IFactoryToken.ConfidentialConfig memory c, address registry, address verifier) public {
        PqzSafety.requireAllowedChain();
        bytes memory aud = c.auditorKey;
        if (c.shieldScale == 0 || c.maxShielded == 0 || c.maxShielded > PqzCore.MAX_TOTAL_SHIELDED
            || c.confidentialFee >= PqzCore.VALUE_BOUND || c.confidentialFee >= c.maxShielded
            || c.confidentialFee + 8 * c.multiLegFee >= PqzCore.VALUE_BOUND || c.confidentialFee + 8 * c.multiLegFee >= c.maxShielded
            || (aud.length != 0 && aud.length != 32) || c.maxShielded > type(uint256).max / c.shieldScale) {
            revert IPqzToken.BadInit();
        }
        if (c.disclosureMode > uint8(ZetherTypes.DisclosureMode.COMPACT)) revert IPqzToken.BadDisclosureMode(c.disclosureMode);
        if (c.auditorMode > uint8(ZetherTypes.AuditorMode.OPTIONAL)
            || (aud.length == 0) != (c.auditorMode == uint8(ZetherTypes.AuditorMode.NONE))) {
            revert IPqzToken.BadAuditorMode(c.auditorMode);
        }
        bytes32 a = aud.length == 32 ? bytes32(aud) : bytes32(0);
        if (a != 0 && !PqzCore._registered(registry, a)) revert IPqzToken.AccountNotRegistered(a);
        PqzCore.PqzStorage storage s = PqzCore.$();
        UAPqzVerifier v = UAPqzVerifier(verifier);
        s.pqz = v.PRECOMPILE();
        s.psid = v.PROOF_SYSTEM_ID();
        PqzSafety.requirePqz(s.pqz, s.psid); // the token's verdicts come from `s.pqz`, never from the verifier (W-B)
        s.verifier = verifier;
        s.disclosureMode = ZetherTypes.DisclosureMode(c.disclosureMode);
        s.auditorMode = ZetherTypes.AuditorMode(c.auditorMode);
        s.shieldScale = c.shieldScale;
        s.maxShielded = c.maxShielded;
        s.confidentialFee = c.confidentialFee;
        s.multiLegFee = c.multiLegFee;
        s.auditorUA = a;
    }

    /// @notice `plainPending[ua] += amount`, `totalShielded += amount` within the cap. The token takes the public units
    ///         (`pqzShield`) or a leg's underlying (`pqzWrapShield`).
    function shield(bytes32 ua, uint256 amount, address registry) public {
        PqzCore.PqzStorage storage s = PqzCore.$();
        if (!PqzCore._registered(registry, ua)) revert IPqzToken.AccountNotRegistered(ua);
        uint256 room = s.maxShielded - s.totalShielded;
        if (amount == 0 || amount > room) revert IPqzToken.AmountOutOfRange(amount, room);
        s.totalShielded += amount;
        PqzCore._plain(ua, amount);
    }

    /// @notice Anyone: `acc += Σ cts` for the next `1 ≤ n ≤ 16` pending credits.
    function rollOver(bytes32 ua, bytes calldata acc, bytes[] calldata cts) public {
        PqzCore.Account storage a = PqzCore.$().acct[ua];
        uint256 n = cts.length;
        uint64 r = a.rolled;
        if (n == 0 || n > PqzCore.ROLL_MAX || r + n > a.pendingCount) revert IPqzToken.RollOverRange(n);
        if (acc.length != PqzCt.CT || keccak256(acc) != PqzCt.stored(a.accHash)) revert IPqzToken.AccMismatch();
        bytes memory c = PqzCt.load(acc);
        for (uint256 j; j < n; ++j) {
            if (cts[j].length != PqzCt.CT || keccak256(cts[j]) != a.pendingHash[uint64(r + j)]) {
                revert IPqzToken.InlineMismatch(j);
            }
            PqzCt.plus(c, cts[j]);
        }
        PqzCt.reduce(c);
        bytes32 h = keccak256(c);
        a.accHash = h;
        a.rolled = uint64(r + n);
        a.accUnits += uint16(n);
        emit IPqzToken.PqzRolled(ua, uint64(r + n), h);
    }
}
