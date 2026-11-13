// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUALedger} from "../../../src/metatx/IUALedger.sol";
import {NormalZetherToken} from "../../../src/zether/NormalZetherToken.sol";

import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";

import {noVerdict} from "../../pqz/helpers/PqzVerdicts.sol";
import {PayMetaKit} from "../../helpers/PayMetaKit.sol";
import {Test} from "forge-std/Test.sol";
import {Vm, VmSafe} from "forge-std/Vm.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture} from "../helpers/RegFixture.sol";
import {ZetherRegFixture, IZetherUnwrapDirect} from "../confidential/ZetherRegFixture.sol";
import {PqzRegFixture} from "../confidential/PqzRegFixture.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IGovernance} from "../../../src/governance/IGovernance.sol";
import {IAdmin} from "../../../src/governance/IAdmin.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {MetaTokenBase} from "../../../src/metatx/MetaTokenBase.sol";
import {ERC20MetaTx} from "../../../src/metatx/ERC20MetaTx.sol";
import {UAMetaTxBase} from "../../../src/metatx/UAMetaTxBase.sol";
import {NormalToken} from "../../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../../src/metatx/WrappedToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../../src/common/FeePolicy.sol";
import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {ComplianceRegistry} from "../../../src/regulated/ComplianceRegistry.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../../../src/confidential/IConfidentialToken.sol";
import {IZetherToken} from "../../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";
import {IPqzToken, IPqzWrappedToken} from "../../../src/pqz/IPqzToken.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {WrappedPqzToken} from "../../../src/pqz/WrappedPqzToken.sol";
import {ZetherLayer} from "../../../src/zether/ZetherLayer.sol";
import {nid} from "../../helpers/Ids.sol";
import {EnvKit} from "../../helpers/EnvKit.sol";

interface IShielded {
    function totalShielded() external view returns (uint256);
}

/// Plan T36 (regulated-kinds spec §8): the ghost state and the per-call checks of I1-I13 on one regulated token, shared by
/// the three handlers (public 8, 9; Zether 10, 11; PQZ 12, 13; Zether ≠ PQZ, each its own handler). Every call to the token
/// is a low-level call bracketed by `_pre` and `_post`: a refusal is data, not a handler revert. A broken invariant counts
/// in `vio[k]` (the first reason in `why`); `hits[k]` counts the times a check had something to check, so a vacuous pass
/// shows as 0. The controls (the eight direct entries of spec §3.1 but bit 21's, which has no body), the relaxation calls
/// (`revokeRole`, `renounceRole`, `disableFeature`, `cancelGrant`, `grantRole` of bit 22, an owner handover) and the time
/// live here; the ledger paths in each handler.
abstract contract RegCore is Test {
    /// @dev What the handler's op is (I4, I6): a move `F`/`P` may refuse, a pause-open row (burn or unwrap at fee `NONE`), a
    ///      row never refused (roll-over, prepare, a refresh without `shieldIn`), a control, `forceTransfer`,
    ///      `operatorTransfer`, a governance call, a registry write (not the token).
    uint8 internal constant K_MOVE = 0;
    uint8 internal constant K_OPEN = 1;
    uint8 internal constant K_ROLL = 2;
    uint8 internal constant K_CTRL = 3;
    uint8 internal constant K_FORCE = 4;
    uint8 internal constant K_OPER = 5;
    uint8 internal constant K_GOV = 6;
    uint8 internal constant K_REG = 7;
    /// Round 3s (spec 2026-11-10-token-lists.md §4.5): a list edit (`setAllowed` / `setDenied`), an `enableFeature(8 | 9)`.
    uint8 internal constant K_LIST = 8;
    uint8 internal constant K_ENABLE = 9;
    uint8 internal constant C_LIST_BITS = (1 << 3) | (1 << 4);
    uint8 internal constant C_ENABLEABLE = (1 << 3) | (1 << 4) | (1 << 6);

    bytes32 internal constant UAP = bytes32(uint256(uint160(MetaTxLib.UA_POOL)));
    bytes32 internal constant SHP = bytes32(uint256(uint160(MetaTxLib.SHIELD_POOL)));
    // keccak256(abi.encode(uint256(keccak256("scaas.governance")) - 1)) & ~bytes32(uint256(0xff)) (GovernanceLib._STORAGE)
    uint256 internal constant GOV_SLOT = 0x0a3a361961b35589cdb03530b6f9e23a4db6ca9a0dad5ddf5d7761c7fabc8700;
    uint256 internal constant REG_GAS = 50_000; // RegulatedBase.COMPLIANCE_REGISTRY_GAS
    bytes32 internal constant CREF = bytes32(uint256(0xC0FFEE));

    address internal cT;
    ComplianceRegistry internal cReg;
    address internal cAttester;
    address internal cAdmin; // the registry admin: `ELIGIBLE_CONTRACT` is its (CTR-AS-16)
    bytes32[] internal cIds; // every id whose public balance moves (natives and derived), pools aside
    /// @dev [0] owner A, [1] owner B, [2] issuer, [3] compliance, [4] operator (bit 22), [5] a stranger.
    address[6] internal cGov;
    uint256 internal cOwner; // 0 or 1: the current owner in `cGov`
    uint64 internal cGd;
    bool internal cWrapped;
    bool internal cConf;
    address internal cLeg;
    bytes32 internal cMinter;
    bytes32[] internal cRecs;
    uint256 internal cGen;
    uint256 internal cLane = 1000;

    // ghosts
    mapping(bytes32 => uint256) internal gExec; // I2: Σ forced per record
    mapping(bytes32 => uint64) internal gEp; // I7: the issuer-only episode last seen
    mapping(bytes32 => uint64) internal gEnd; // I7: its last observed `until`
    mapping(bytes32 => uint64) internal gUntil; // I7: `until` last seen
    uint64 internal gPauseEnd; // I4: the last pause's actual end
    struct Pend {
        uint8 action;
        bytes32 proposer;
        uint64 eta;
        uint256 gen;
    }
    mapping(bytes32 => Pend) internal gPend; // I13: key keccak256(bit, account)

    // the call under test
    uint256[] internal pBal;
    bool[] internal pFz;
    bool internal pP;
    uint8 internal pCtl;
    uint256 internal pFeat;
    uint8[] internal pList; // I15: each id's `listFlagsOf` before the call
    uint256 internal pSupply;
    bytes32 internal pLegs;
    bool internal pMint;
    bytes32 internal pShield;
    bytes32 internal pRec; // the record a forceTransfer names (I2)
    IRegulatedToken.OrderRecord internal pOrder;
    bool internal pRecActive;
    bytes32 internal pLower; // the id an unfreeze / revokeOrder may lower `until` of (I7)
    bool internal pExpect; // I9: the op must succeed
    uint256 internal pGasCap; // I10: a refusal's bound (0: none)
    mapping(bytes32 => bool) internal pDecoy; // I5: a decoy leg's `decoyFee` (spec §4)
    bytes32[] internal pDecoys;
    bool internal pDiff; // I8: state-diff recording on
    uint256[] internal pViewSlots;

    mapping(uint256 => uint256) public vio;
    mapping(uint256 => uint256) public hits;
    string public why;
    mapping(uint256 => uint256) public calls; // per kind: [k] tried, [k + 10] succeeded
    bytes4[] public errs; // the refusals' selectors seen, and how often
    mapping(bytes4 => uint256) public errCount;

    function errsLength() external view returns (uint256) {
        return errs.length;
    }

    // ------------------------------------------------------------------ the family's facts

    /// @dev A pause-open, fee-bearing or other probe of the confidential state (I8): a family's views read every shielded
    ///      slot an account has; the default reads nothing.
    function _shieldViews() internal view virtual {}

    /// @dev I1 beyond `Σ balances == totalSupply`: the D19 pool rule on the confidential kinds.
    function _i1Extra() internal view virtual returns (bool) {
        return true;
    }

    // ------------------------------------------------------------------ init

    function _coreInit(address t, ComplianceRegistry reg, address[2] memory att, address[6] memory gov, bool wrapped,
        address leg, bytes32 minter) internal
    {
        (cT, cReg, cAttester, cAdmin) = (t, reg, att[0], att[1]);
        (cGov, cWrapped, cLeg, cMinter) = (gov, wrapped, leg, minter);
        cGd = NormalToken(t).grantDelay();
        for (uint256 k; k < cIds.length; ++k) gUntil[cIds[k]] = IRegulatedToken(t).freezeOf(cIds[k]).until;
        // bit 22 to the operator: the owner's two calls (grantRole keeps two calls on every bit, spec §3.6)
        for (uint256 i; i < 2; ++i) {
            vm.prank(gov[0]);
            NormalToken(t).grantRole(GovernanceBits.OPERATOR_TRANSFER, nid(gov[4]), EnvKit.codeUidOf(address(NormalToken(t))));
            if (i == 0) vm.warp(block.timestamp + cGd);
        }
    }

    function _owner() internal view returns (address) {
        return cGov[cOwner];
    }

    // ------------------------------------------------------------------ the bracket

    function _roots(uint8 bit) internal view returns (uint256) {
        return uint256(vm.load(cT, keccak256(abi.encode(uint256(bit), GOV_SLOT + 6)))) >> 128;
    }

    /// `P` of spec §3.2: bit 7 in `controls`, `pausedUntil > now`, a live root of bit 7.
    function _paused() internal view returns (bool) {
        IRegulatedToken.RegulatedConfig memory c = IRegulatedToken(cT).regulatedConfig();
        return c.controls & 4 != 0 && c.pausedUntil > block.timestamp && _roots(7) != 0;
    }

    function _fz(bytes32 a) internal view returns (bool) {
        return IRegulatedToken(cT).isFrozen(a);
    }

    /// A sender or payer the token lets act: not frozen, and (round 3s) not refused by a list that is on (`L`).
    function _free(bytes32 a) internal view returns (bool) {
        uint8 c = IRegulatedToken(cT).regulatedConfig().controls;
        uint8 fl = IRegulatedToken(cT).listFlagsOf(a);
        return !_fz(a) && !(c & (1 << 3) != 0 && fl & 1 == 0) && !(c & (1 << 4) != 0 && fl & 2 != 0);
    }

    function _canRecv(bytes32 a) internal view returns (bool ok) {
        (ok,) = IRegulatedToken(cT).canReceive(a);
    }

    function _bal(bytes32 a) internal view returns (uint256) {
        return NormalToken(cT).balanceOfUA(a);
    }

    function _legsHash() internal view returns (bytes32) {
        if (!cWrapped) return 0;
        (uint96 n, uint96 d, uint256 r,, bool e) = WrappedToken(payable(cT)).legOf(cLeg);
        return keccak256(abi.encode(n, d, r, e));
    }

    function _pre() internal {
        delete pBal;
        delete pFz;
        for (uint256 k; k < cIds.length; ++k) {
            pBal.push(_bal(cIds[k]));
            pFz.push(_fz(cIds[k]));
        }
        pP = _paused();
        delete pList;
        for (uint256 k; k < cIds.length; ++k) pList.push(IRegulatedToken(cT).listFlagsOf(cIds[k]));
        pCtl = IRegulatedToken(cT).regulatedConfig().controls;
        pFeat = NormalToken(cT).features();
        pSupply = IERC20(cT).totalSupply();
        pLegs = _legsHash();
        pMint = cMinter != 0 && NormalToken(cT).hasRole(GovernanceBits.MINTABLE, cMinter);
        pShield = _shieldHash();
        vm.recordLogs();
    }

    /// `cd` on the token as `who`: success, the revert data, the gas the token's frame used. Through `exec`, a fresh frame:
    /// the handler's own memory (proof blobs, the snapshot) would otherwise make the call's argument copy quadratic (I10).
    function _call(address who, bytes memory cd) internal returns (bool ok, bytes memory ret, uint256 used) {
        if (pDiff) vm.startStateDiffRecording();
        return this.exec(who, cd);
    }

    function exec(address who, bytes calldata cd) external returns (bool ok, bytes memory ret, uint256 used) {
        require(msg.sender == address(this), "self only");
        vm.prank(who);
        uint256 g = gasleft();
        (ok, ret) = cT.call(cd);
        used = g - gasleft();
    }

    function _flag(uint256 i, string memory reason) internal {
        if (vio[i]++ == 0 && bytes(why).length == 0) why = string.concat("I", vm.toString(i), ": ", reason);
    }

    function _post(uint8 kind, bool ok, bytes memory ret, uint256 used) internal {
        Vm.AccountAccess[] memory acc;
        if (pDiff) acc = vm.stopAndReturnStateDiff();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        ++calls[kind];
        if (ok) ++calls[kind + 10];
        // a reverted call's events are recorded too (Foundry's `recordLogs`): only a success's count
        uint256[] memory forcedOut = ok ? _logs(logs) : new uint256[](cIds.length);
        _balances(kind, ok, forcedOut);
        _state(kind);
        if (!ok) {
            _refusal(kind, ret, used);
            bytes4 e = ret.length >= 4 ? bytes4(ret) : bytes4(0);
            if (errCount[e]++ == 0) errs.push(e);
        }
        if (pExpect) {
            ++hits[9];
            if (!ok) _flag(9, string.concat("an op with frozen or denied legs refused: ", vm.toString(ret)));
        }
        if (pDiff) _i8(acc);
        for (uint256 k; k < pDecoys.length; ++k) pDecoy[pDecoys[k]] = false;
        delete pDecoys;
        (pRec, pLower, pExpect, pGasCap, pDiff) = (0, 0, false, 0, false);
    }

    /// I2, I4 (pause bounds), I13 from the call's events; returns each tracked id's forced debit.
    bytes32 internal constant TRANSFER = keccak256("Transfer(address,address,uint256)");

    /// I14 (round 3s, spec §4.5): every party a balance change of the call names, read from its `Transfer` / `UATransfer` logs
    /// (not from what the handler meant to call): `ALLOWED` while the allow list was on, not `DENIED` while the deny list was
    /// on; but 0 (a mint or a burn), the two pools, a forced transfer's subject and a confidential leg's `decoyFee` (I9).
    bytes32 internal gForcedFrom; // the call's forced transfer's subject (I14 skips it)

    function _i14(bytes32 from, bytes32 to) internal {
        if (pCtl & C_LIST_BITS == 0) return;
        bytes32[2] memory ps = [from, to];
        for (uint256 i; i < 2; ++i) {
            bytes32 a = ps[i];
            if (a == 0 || a == MetaTxLib.pad(MetaTxLib.UA_POOL) || a == MetaTxLib.pad(MetaTxLib.SHIELD_POOL)) continue;
            if ((i == 0 && a == gForcedFrom) || (i == 1 && pDecoy[a])) continue;
            ++hits[14];
            uint8 fl = IRegulatedToken(cT).listFlagsOf(a);
            if (pCtl & (1 << 3) != 0 && fl & 1 == 0) _flag(14, string.concat("a party not on the allow list: ", vm.toString(a)));
            if (pCtl & (1 << 4) != 0 && fl & 2 != 0) _flag(14, string.concat("a party on the deny list: ", vm.toString(a)));
        }
    }

    function _logs(Vm.Log[] memory logs) internal returns (uint256[] memory out) {
        out = new uint256[](cIds.length);
        gForcedFrom = 0;
        for (uint256 i; i < logs.length; ++i) {
            Vm.Log memory l = logs[i];
            if (l.emitter != cT || l.topics.length == 0) continue;
            bytes32 s = l.topics[0];
            if (s == TRANSFER || s == IUALedger.UATransfer.selector) {
                _i14(l.topics[1], l.topics[2]);
            } else if (s == IRegulatedToken.ForcedTransfer.selector) {
                gForcedFrom = l.topics[2];
                _i2(l.topics[1], l.topics[2], l.topics[3], abi.decode(l.data, (uint256)));
                for (uint256 k; k < cIds.length; ++k) if (cIds[k] == l.topics[2]) out[k] += abi.decode(l.data, (uint256));
            } else if (s == IRegulatedToken.Paused.selector) {
                uint64 until = abi.decode(l.data, (uint64));
                ++hits[4];
                if (until > block.timestamp + 7 days) _flag(4, "a pause longer than 7 d");
                if (gPauseEnd != 0 && block.timestamp < uint256(gPauseEnd) + 7 days) _flag(4, "pauses less than 7 d apart");
                gPauseEnd = until;
            } else if (s == IRegulatedToken.Unpaused.selector) {
                gPauseEnd = uint64(block.timestamp);
            } else if (s == IAdmin.AdminTransferred.selector) {
                ++cGen;
            } else if (s == IGovernance.RelaxProposed.selector) {
                (uint8 action, bytes32 proposer, uint64 eta) = abi.decode(l.data, (uint8, bytes32, uint64));
                gPend[keccak256(abi.encode(l.topics[1], l.topics[2]))] = Pend(action, proposer, eta, cGen);
            } else if (s == IGovernance.GrantProposed.selector) {
                (uint64 eta, bool whole) = abi.decode(l.data, (uint64, bool));
                gPend[keccak256(abi.encode(l.topics[1], l.topics[2]))] = Pend(whole ? 1 : 2, l.topics[3], eta, cGen);
            } else if (s == IGovernance.GrantCancelled.selector) {
                delete gPend[keccak256(abi.encode(l.topics[1], l.topics[2]))];
            } else if (s == IGovernance.RoleRevoked.selector) {
                uint256 bit = uint256(l.topics[1]);
                if (bit >= 5 && bit <= 7) _i13(l.topics[1], l.topics[2], l.topics[3] == l.topics[2] ? 4 : 3, l.topics[3]);
            } else if (s == IGovernance.FeatureDisabled.selector) {
                uint256 bit = uint256(l.topics[1]);
                if (bit >= 5 && bit <= 7) _i13(l.topics[1], 0, 5, l.topics[2]);
            } else if (s == IGovernance.RoleGranted.selector) {
                _i13(l.topics[1], l.topics[2], 1, l.topics[3]);
            }
        }
    }

    /// I2: a live record, `RECORD` active, the subject frozen before the call, `to` its beneficiary, `amount != 0`,
    ///     cumulative `executed <= maxAmount`, and the record's `executed` the ghost's.
    function _i2(bytes32 recordId, bytes32 from, bytes32 to, uint256 amount) internal {
        ++hits[2];
        if (recordId != pRec) return _flag(2, "a ForcedTransfer the call did not name");
        if (pOrder.subject == 0 || pOrder.revoked || !pRecActive) _flag(2, "no live record or RECORD inactive");
        if (from != pOrder.subject || to != pOrder.beneficiary) _flag(2, "from / to are not the record's");
        bool frozenBefore;
        for (uint256 k; k < cIds.length; ++k) if (cIds[k] == from) frozenBefore = pFz[k];
        if (!frozenBefore) _flag(2, "the subject was not frozen");
        if (amount == 0) _flag(2, "amount 0");
        gExec[recordId] += amount;
        if (gExec[recordId] > pOrder.maxAmount) _flag(2, "executed > maxAmount");
        uint256 ex = IRegulatedToken(cT).order(recordId).executed;
        if (ex != gExec[recordId]) {
            _flag(2, string.concat("executed ", vm.toString(ex), " is not the sum forced ", vm.toString(gExec[recordId])));
        }
    }

    /// I13: the pending's own action (commit), its proposer, `[eta, eta + grantDelay]`, the owner generation it was proposed in.
    function _i13(bytes32 bit, bytes32 account, uint8 action, bytes32 by) internal {
        ++hits[13];
        bytes32 key = keccak256(abi.encode(bit, account));
        Pend memory p = gPend[key];
        delete gPend[key];
        if (p.eta == 0) return _flag(13, "an effect without a pending");
        if (p.action != action) _flag(13, "another action's pending confirmed");
        if (p.proposer != by) _flag(13, "confirmed by another id than the proposer");
        if (block.timestamp < p.eta || block.timestamp > uint256(p.eta) + cGd) _flag(13, "confirmed outside [eta, eta + gd]");
        if (p.gen != cGen) _flag(13, "confirmed in another owner generation");
    }

    /// I3, I4 (moves while paused), I5.
    function _balances(uint8 kind, bool ok, uint256[] memory forcedOut) internal {
        bool moved = IERC20(cT).totalSupply() != pSupply;
        for (uint256 k; k < cIds.length; ++k) {
            uint256 b = _bal(cIds[k]);
            if (b != pBal[k]) moved = true;
            if (pFz[k]) {
                ++hits[3];
                if (b + forcedOut[k] < pBal[k]) _flag(3, string.concat("a frozen balance decreased: ", vm.toString(cIds[k])));
            }
            if (ok && b > pBal[k] && !pDecoy[cIds[k]]) {
                ++hits[5];
                if (!_canRecv(cIds[k])) _flag(5, string.concat("a credit to an id R refuses: ", vm.toString(cIds[k])));
            }
        }
        if (pP && ok && kind != K_OPEN && kind != K_FORCE && kind != K_ROLL) {
            ++hits[4];
            if (moved || pShield != _shieldHash()) _flag(4, "a balance moved while paused off the open rows");
        }
    }

    function _shieldHash() internal view returns (bytes32) {
        return cConf ? keccak256(abi.encode(IShielded(cT).totalShielded(), IERC20(cT).balanceOf(MetaTxLib.SHIELD_POOL)))
            : bytes32(0);
    }

    /// I1, I6, I7, I12.
    function _state(uint8 kind) internal {
        // I1
        ++hits[1];
        uint256 sum = IERC20(cT).balanceOf(MetaTxLib.UA_POOL) + IERC20(cT).balanceOf(MetaTxLib.SHIELD_POOL);
        uint256 uas;
        for (uint256 k; k < cIds.length; ++k) {
            if (uint256(cIds[k]) >> 160 == 0) sum += _bal(cIds[k]);
            else uas += _bal(cIds[k]);
        }
        if (sum != IERC20(cT).totalSupply()) _flag(1, "sum of balances != totalSupply");
        if (uas != IERC20(cT).balanceOf(MetaTxLib.UA_POOL)) _flag(1, "sum of UA balances != balanceOf(UA_POOL)");
        if (cWrapped && WrappedToken(payable(cT)).collateralValue() < IERC20(cT).totalSupply()) _flag(1, "undercollateralised");
        if (!_i1Extra()) _flag(1, "balanceOf(SHIELD_POOL) != totalShielded x scale");
        // I6, I12
        uint8 c = IRegulatedToken(cT).regulatedConfig().controls;
        uint256 f = NormalToken(cT).features();
        ++hits[12];
        if (c != uint8((f >> 5) & 0x3F) | uint8((f >> 28) & 1) << 6) _flag(12, "controls != mirror(features)");
        ++hits[6];
        _i15(kind, c, f);
        if (kind >= K_CTRL && kind <= K_GOV) {
            if (_legsHash() != pLegs) _flag(6, "a regulated call moved a leg's reserve, rate or wrapEnabled");
            if (cMinter != 0 && NormalToken(cT).hasRole(GovernanceBits.MINTABLE, cMinter) != pMint) _flag(6, "the minter moved");
        }
        // I7
        for (uint256 k; k < cIds.length; ++k) _i7(cIds[k], k);
    }

    /// I6's round-3s rows (8, 9, 28 come back only by `enableFeature`; 8 and 9 never leave) and I15 (spec §4.5): `listFlags`
    /// changes only by a list edit; 8, 9 never leave `features`; a locked bit never changes.
    function _i15(uint8 kind, uint8 c, uint256 f) internal {
        if (c & ~pCtl != 0 && (kind != K_ENABLE || c & ~pCtl & ~C_ENABLEABLE != 0)) _flag(6, "controls gained a bit");
        if (pCtl & ~c & C_LIST_BITS != 0) _flag(6, "controls lost a list bit");
        ++hits[15];
        for (uint256 k; k < cIds.length; ++k) {
            if (kind != K_LIST && IRegulatedToken(cT).listFlagsOf(cIds[k]) != pList[k]) _flag(15, "listFlags moved off a list edit");
        }
        if (pFeat & ~f & (3 << 8) != 0) _flag(15, "a list bit left features");
        if ((pFeat ^ f) & NormalToken(cT).lockedFeatures() != 0) _flag(15, "a locked bit changed");
    }

    function _i7(bytes32 a, uint256 k) internal {
        IRegulatedToken.FreezeState memory s = IRegulatedToken(cT).freezeOf(a);
        if (s.until < gUntil[a] && a != pLower) {
            // T1 replacing a value that no longer counts is the only other lowering (spec §3.3)
            if (pFz[k] || s.episodeStart != block.timestamp) _flag(7, "until decreased off unfreeze / revokeOrder");
        }
        gUntil[a] = s.until;
        if (s.recordBacked) return;
        if (s.episodeStart != gEp[a]) {
            ++hits[7];
            if (gEnd[a] != 0 && s.episodeStart < uint256(gEnd[a]) + 30 days) _flag(7, "issuer episodes less than 30 d apart");
            gEp[a] = s.episodeStart;
        }
        if (s.episodeStart == gEp[a]) {
            if (s.until > block.timestamp && s.until > uint256(s.episodeStart) + 60 days) _flag(7, "an issuer episode > 60 d");
            if (s.until != 0) gEnd[a] = s.until;
        }
    }

    /// The refusals: an open row refused by `P` (I4) or a never-refused row refused by `F` or `P` (I3, I4); I10's bound.
    function _refusal(uint8 kind, bytes memory ret, uint256 used) internal {
        bytes4 e = ret.length >= 4 ? bytes4(ret) : bytes4(0);
        bool reg = e == IRegulatedToken.Frozen.selector || e == IRegulatedToken.TokenPaused.selector
            || e == IRegulatedToken.NotEligible.selector || e == IRegulatedToken.FeeRecipientFrozen.selector;
        if ((kind == K_OPEN || kind == K_ROLL) && e == IRegulatedToken.TokenPaused.selector) {
            ++hits[4];
            _flag(4, "a pause-open row refused TokenPaused");
        }
        if (kind == K_ROLL && reg) {
            ++hits[3];
            _flag(3, "a row never refused (roll-over, prepare, refresh) refused by a regulated check");
        }
        // the pre row's `F` / `P` within `pGasCap`; a receiver or fee-leg refusal after the authorization: + 4 registry calls
        bool pre = e == IRegulatedToken.Frozen.selector || e == IRegulatedToken.TokenPaused.selector;
        if (pGasCap != 0 && reg) {
            ++hits[10];
            if (used > (pre ? pGasCap : pGasCap + 4 * REG_GAS + 50_000)) {
                _flag(10, string.concat("a refusal cost ", vm.toString(used), ": ", vm.toString(ret)));
            }
        }
    }

    /// I8: `forceTransfer` and `operatorTransfer` read and write no slot the shielded views read.
    function _i8(Vm.AccountAccess[] memory acc) internal {
        ++hits[8];
        for (uint256 i; i < acc.length; ++i) {
            VmSafe.StorageAccess[] memory sa = acc[i].storageAccesses;
            for (uint256 j; j < sa.length; ++j) {
                if (sa[j].account != cT) continue;
                for (uint256 v; v < pViewSlots.length; ++v) {
                    if (uint256(sa[j].slot) == pViewSlots[v]) return _flag(8, "FORCE / OPERATOR touched shielded state");
                }
            }
        }
    }

    /// The slots the shielded views read (I8), recorded before the op.
    function _viewSlots() internal {
        delete pViewSlots;
        vm.startStateDiffRecording();
        _shieldViews();
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        for (uint256 i; i < acc.length; ++i) {
            VmSafe.StorageAccess[] memory sa = acc[i].storageAccesses;
            for (uint256 j; j < sa.length; ++j) if (sa[j].account == cT) pViewSlots.push(uint256(sa[j].slot));
        }
    }

    /// One bracketed call: `_pre`, the call as `who`, `_post`.
    function _op(uint8 kind, address who, bytes memory cd) internal returns (bool ok) {
        if (pDiff) _viewSlots();
        _pre();
        (bool ok_, bytes memory ret, uint256 used) = _call(who, cd);
        _post(kind, ok_, ret, used);
        return ok_;
    }

    function _id(uint256 i) internal view returns (bytes32) {
        return cIds[i % cIds.length];
    }

    // ------------------------------------------------------------------ the lists (round 3s, spec §6)

    /// The issuer seat (bits 8, 9 while they can be enabled) writes id `i`'s flag of the allow (`deny` false) or the deny list.
    function listEdit(uint256 i, bool deny, bool on) external {
        bytes32[] memory one = new bytes32[](1);
        one[0] = _id(i);
        _op(K_LIST, cGov[2], deny ? abi.encodeCall(IRegulatedToken.setDenied, (one, on))
            : abi.encodeCall(IRegulatedToken.setAllowed, (one, on)));
    }

    /// The admin switches a list on, at once (bit 8 on 10-13: `FeatureInvalidForKind`).
    function enableList(bool deny) external {
        _op(K_ENABLE, cGov[0], abi.encodeCall(IRegulatedToken.enableFeature, (deny ? uint8(9) : uint8(8), EnvKit.codeUidOf(cT))));
    }

    // ------------------------------------------------------------------ the controls (spec §3.1)

    function freeze(uint256 i, uint256 r, bool backed) external {
        bytes32 a = _id(i);
        bytes32 rec = backed && cRecs.length != 0 ? cRecs[r % cRecs.length] : bytes32(0);
        if (rec != 0) a = IRegulatedToken(cT).order(rec).subject;
        _op(K_CTRL, cGov[2], abi.encodeCall(IRegulatedToken.freeze, (a, CREF, rec)));
    }

    function unfreeze(uint256 i) external {
        pLower = _id(i);
        _op(K_CTRL, cGov[2], abi.encodeCall(IRegulatedToken.unfreeze, (_id(i), CREF)));
    }

    /// A record of `s` for `b` (a pool or the token now and then, which `recordOrder` refuses: spec §3.3).
    function recordOrder(uint256 s, uint256 b, uint256 max, uint256 days_, uint256 odd) external {
        bytes32 sub = _id(s);
        bytes32 ben = _id(b);
        if (odd % 8 == 0) ben = [UAP, SHP, nid(cT)][odd % 3];
        else if (odd % 8 == 1) sub = [UAP, SHP, nid(cT)][odd % 3];
        max = bound(max, 0, 1000);
        uint64 fu = uint64(block.timestamp + bound(days_, 0, 90) * 1 days);
        bytes32 orderId = keccak256(abi.encode(cRecs.length, odd));
        if (_op(K_CTRL, cGov[3], abi.encodeCall(IRegulatedToken.recordOrder, (orderId, keccak256("doc"), sub, ben, max, fu)))) {
            cRecs.push(keccak256(abi.encode(orderId, sub, ben)));
        }
    }

    function revokeOrder(uint256 r) external {
        if (cRecs.length == 0) return;
        bytes32 rec = cRecs[r % cRecs.length];
        pLower = IRegulatedToken(cT).order(rec).subject;
        _op(K_CTRL, cGov[3], abi.encodeCall(IRegulatedToken.revokeOrder, (rec, CREF)));
    }

    function forceTransfer(uint256 r, uint256 amount) external {
        if (cRecs.length == 0) return;
        bytes32 rec = cRecs[r % cRecs.length];
        // half the time the record-backed freeze first (T4), so a force has a frozen subject to act on
        bytes32 sub = IRegulatedToken(cT).order(rec).subject;
        if (r % 2 == 0 && !_fz(sub)) _op(K_CTRL, cGov[2], abi.encodeCall(IRegulatedToken.freeze, (sub, CREF, rec)));
        pRec = rec;
        pOrder = IRegulatedToken(cT).order(rec);
        pRecActive = IRegulatedToken(cT).regulatedConfig().controls & 32 != 0 && _roots(10) != 0;
        pDiff = cConf;
        _op(K_FORCE, cGov[2], abi.encodeCall(IRegulatedToken.forceTransfer, (rec, bound(amount, 0, 300))));
    }

    function pause(uint256 secs) external {
        _op(K_CTRL, cGov[2], abi.encodeCall(IRegulatedToken.pause, (CREF, uint64(block.timestamp + bound(secs, 0, 8 days)))));
    }

    function unpause() external {
        _op(K_CTRL, cGov[2], abi.encodeCall(IRegulatedToken.unpause, (CREF)));
    }

    function operatorTransfer(uint256 i, uint256 j, uint256 amount) external {
        pDiff = cConf;
        _op(K_OPER, cGov[4], abi.encodeCall(IRegulatedToken.operatorTransfer, (_id(i), _id(j), bound(amount, 0, 300), CREF)));
    }

    // ------------------------------------------------------------------ the relaxation calls (spec §3.6)

    /// `act` 0 revokeRole (the holder of `bit`), 1 renounceRole, 2 disableFeature, 3 cancelGrant, 4 grantRole of bit 22, on
    /// bits 5, 6, 7 (delayed), 10, 22; by the caller the action needs (the owner, the holder) three times in four, else by
    /// any id of `cGov`. Every other call is followed by a second one after a warp (early, in `[eta, eta + gd]`, or after
    /// it), by the same caller or now and then another: the confirm paths of spec §3.6.
    function relax(uint256 act, uint256 b, uint256 w, uint256 twice) external {
        uint8 bit = [5, 6, 7, 10, 22][b % 5];
        address hAddr = bit == 10 ? cGov[3] : bit == 22 ? cGov[4] : cGov[2];
        bytes32 holder = nid(hAddr);
        act %= 5;
        address who = w % 4 == 0 ? cGov[w % 6] : act == 1 ? hAddr : _owner();
        bytes32 u = EnvKit.codeUidOf(cT);
        bytes memory cd = act == 0 ? abi.encodeCall(IGovernance.revokeRole, (bit, holder, u))
            : act == 1 ? abi.encodeCall(IGovernance.renounceRole, (bit, u))
            : act == 2 ? abi.encodeCall(IGovernance.disableFeature, (bit, u))
            : act == 3 ? abi.encodeCall(IGovernance.cancelGrant, (bit, act == 3 && w % 2 == 0 ? bytes32(0) : holder, u))
            : abi.encodeCall(IGovernance.grantRole, (22, nid(cGov[4]), u));
        _op(K_GOV, who, cd);
        if (twice % 2 == 0) {
            uint256 j = twice % 7;
            vm.warp(block.timestamp + (j == 0 ? cGd - 1 : j == 1 ? 2 * cGd + 1 : cGd + j * 1 hours));
            _op(K_GOV, twice % 5 == 0 ? cGov[(w % 6 + 1) % 6] : who, cd);
        }
    }

    /// The owner hands over to the other owner (`acceptAdmin` kills every pending, Codex 2).
    function handover() external {
        address next = cGov[1 - cOwner];
        _op(K_GOV, _owner(), abi.encodeCall(IAdmin.transferAdmin, (nid(next), EnvKit.codeUidOf(cT))));
        if (_op(K_GOV, next, abi.encodeCall(IAdmin.acceptAdmin, ()))) cOwner = 1 - cOwner;
    }

    function attest(uint256 i, uint256 how) external {
        bytes32 a = _id(i);
        how %= 5;
        uint64 fl = [uint64(1), 1 | (1 << 16), 0, 8, 1][how];
        uint64 vu = how == 4 ? uint64(block.timestamp + 1 days) : type(uint64).max;
        bytes32[] memory as_ = new bytes32[](1);
        uint64[] memory f_ = new uint64[](1);
        uint64[] memory v_ = new uint64[](1);
        (as_[0], f_[0], v_[0]) = (a, fl, vu);
        _pre();
        vm.prank(how == 3 ? cAdmin : cAttester); // ELIGIBLE_CONTRACT: the admin's, a contract's only (CTR-AS-16)
        (bool ok, bytes memory ret) = address(cReg).call(abi.encodeCall(ComplianceRegistry.setCompliance, (as_, f_, v_, EnvKit.regUidOf(address(cReg)))));
        _post(K_REG, ok, ret, 0);
    }

    function warp(uint256 secs) external {
        _pre();
        vm.warp(block.timestamp + bound(secs, 1 hours, 12 days));
        vm.roll(block.number + 10);
        _post(K_REG, true, "", 0);
    }
}

/// Kinds 8 and 9 (`which` 0 or 1): `RegFixture`'s factory and registry, one token with every control, the registry
/// check `KYC` (bit 28; masks `KYC` and `SANCTIONED`) on `creg`, bit 22 granted to an operator EOA. Ids: `alice`, `bob`, `carol` (EOAs
/// with keys), `UA_X` (a derived SIGNING UA), this handler (the minter or the wrapper) and `relayer`. The ledger paths:
/// `transfer`, `transferToUA` (`_update`, `_uaMove`), the generic `mtxExecute` with a fee to the relayer (the pre row, the
/// fee leg), `payWithFee`, mint / burn (8), wrap / unwrap (9), the pause-open set at fee `NONE` and fee-bearing.
contract RegPublicHandler is RegFixture, RegCore {
    uint256 internal constant CAROL_PK = 0xCA401;
    address internal carol = vm.addr(CAROL_PK);
    uint256 internal which;

    constructor(uint256 which_) {
        which = which_;
    }

    function init() external {
        setUp();
        _attest(nid(address(this)), KYC, type(uint64).max);
        _attest(nid(bob), KYC, type(uint64).max);
        _attest(nid(carol), KYC, type(uint64).max);
        _attest(UA_X, KYC, type(uint64).max);
        _attest(nid(relayer), KYC, type(uint64).max);
        IFactoryToken.TokenConfig memory c = which == 0 ? _cfg8() : _cfg9();
        c.features |= (1 << GovernanceBits.KYC) | (1 << GovernanceBits.OPERATOR_TRANSFER); // round 3s: both masks under KYC
        (c.reg.complianceRegistry, c.reg.requiredFlags, c.reg.deniedFlags) = (address(creg), KYC, SANCTIONED);
        _attest(nid(alice), KYC, type(uint64).max);
        address t = f.createToken(which == 0 ? IOpenFactory.TokenKind.NORMAL_REGULATED : IOpenFactory.TokenKind.WRAPPED_REGULATED,
            1, abi.encode(c), "inv");
        if (which == 1) _wrapFor(t, alice, SUPPLY);
        bytes32[7] memory ids = [nid(alice), nid(bob), nid(carol), UA_X, nid(address(this)), nid(relayer), bytes32(0)];
        for (uint256 k; k < 6; ++k) cIds.push(ids[k]);
        vm.prank(alice);
        IERC20(t).transfer(bob, SUPPLY / 4);
        vm.prank(alice);
        NormalToken(t).transferToUA(UA_X, SUPPLY / 4);
        _coreInit(t, creg, [attester, cadmin], [ownerA, address(0x0B22), issuer, compliance, address(0x0BE7), address(0x5EE)],
            which == 1, address(usd), which == 0 ? nid(address(this)) : bytes32(0));
        if (which == 1) usd.approve(t, type(uint256).max);
    }

    function _eoa(uint256 i) internal view returns (address, uint256) {
        i %= 3;
        return i == 0 ? (alice, ALICE_PK) : i == 1 ? (bob, BOB_PK) : (carol, CAROL_PK);
    }

    /// `from` an EOA, to any id: `transfer` (native `to`) or `transferToUA` (derived).
    function pubTransfer(uint256 i, uint256 j, uint256 amount) external {
        (address from,) = _eoa(i);
        bytes32 to = _id(j);
        amount = bound(amount, 0, 500);
        _op(K_MOVE, from, uint256(to) >> 160 == 0 ? abi.encodeCall(IERC20.transfer, (address(uint160(uint256(to))), amount))
            : abi.encodeCall(IUALedger.transferToUA, (to, amount)));
    }

    /// The generic `mtxExecute` of `inner` signed by EOA `i`, relayed by `rel` (an EOA or `relayer`), fee `fee` (0: `NONE`).
    function _relayed(uint256 i, bytes memory inner, uint256 fee, uint256 rel) internal returns (bool feeBearing, address r,
        bytes memory cd)
    {
        (address from, uint256 pk) = _eoa(i);
        feeBearing = fee % 3 != 0;
        uint32 mode = feeBearing ? MetaTxLib.MODE_FEE_FIXED : MetaTxLib.MODE_FEE_NONE;
        MetaTxLib.UAMetaTransaction memory m = MetaTxLib.UAMetaTransaction(nid(from), inner, ++cLane, 0,
            block.timestamp + 300, mode, address(0), feeBearing ? fee % 7 : 0, address(0));
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(pk, NormalToken(cT).mtxDigest(m));
        IUARegistry.UASig memory s;
        s.signature = abi.encodePacked(rr, ss, v);
        (r,) = rel % 4 == 3 ? (relayer, 0) : _eoa(rel);
        cd = abi.encodeCall(UAMetaTxBase.mtxExecute, (m, s));
        pGasCap = 200_000; // I10: a `_regPre` refusal, before the signature
    }

    /// The typed transfer `mtxExecuteTransfer` of EOA `i` to any id, relayed by `rel`, fee `fee` to the relayer (0: `NONE`).
    function pubRelayed(uint256 i, uint256 j, uint256 amount, uint256 fee, uint256 rel) external {
        (address from, uint256 pk) = _eoa(i);
        bool fb = fee % 3 != 0;
        MetaTxLib.UAMetaTransfer memory t = MetaTxLib.UAMetaTransfer(nid(from), _id(j), bound(amount, 0, 500), CREF, ++cLane,
            0, block.timestamp + 300, fb ? MetaTxLib.MODE_FEE_FIXED : MetaTxLib.MODE_FEE_NONE, address(0), fb ? fee % 7 : 0,
            address(0));
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(pk, NormalToken(cT).mtxTransferDigest(t));
        IUARegistry.UASig memory s;
        s.signature = abi.encodePacked(rr, ss, v);
        (address r,) = rel % 4 == 3 ? (relayer, 0) : _eoa(rel);
        pGasCap = 200_000; // I10: a `_regPre` refusal, before the signature
        _op(K_MOVE, r, abi.encodeCall(NormalToken.mtxExecuteTransfer, (t, s)));
    }

    function pubPay(uint256 i, uint256 j, uint256 amount, uint256 fee, uint256 rel) external {
        (address from,) = _eoa(i);
        (address to,) = _eoa(j);
        (address feeTo,) = rel % 4 == 3 ? (relayer, 0) : _eoa(rel);
        if (feeTo == to) feeTo = relayer;
        _op(K_MOVE, from, abi.encodeCall(NormalToken.payWithFee, (to, bound(amount, 0, 500), FeeMode.FIXED, fee % 5,
            feeTo, PayMetaKit.ref(CREF), PayMetaKit.meta(CREF))));
    }

    /// Kind 8: the minter mints to an id; kind 9: this handler wraps (a mint of the wrapped unit to itself).
    function pubMint(uint256 j, uint256 amount) external {
        amount = bound(amount, 1, 500);
        if (which == 0) {
            bytes32 to = _id(j);
            if (uint256(to) >> 160 != 0) to = nid(carol);
            _op(K_MOVE, address(this), abi.encodeCall(NormalToken.mint, (address(uint160(uint256(to))), amount)));
        } else {
            usd.mint(address(this), amount);
            _op(K_MOVE, address(this), abi.encodeWithSignature("wrap(uint256)", amount));
        }
    }

    /// The holder's burn (8) or unwrap (9), direct: open under `P` (spec §3.2), `F(from)` still applies.
    function pubBurn(uint256 i, uint256 amount) external {
        (address from,) = _eoa(i);
        amount = bound(amount, 1, 200);
        _op(K_OPEN, from, which == 0 ? abi.encodeCall(NormalToken.burn, (amount))
            : abi.encodeWithSignature("unwrap(uint256,address,uint256)", amount, from, 0));
    }

    /// The pause-open set through `mtxExecute`: at fee `NONE` an open row; fee-bearing a move `P` refuses.
    function pubOpenRelayed(uint256 i, uint256 amount, uint256 fee, uint256 rel) external {
        (address from,) = _eoa(i);
        amount = bound(amount, 1, 200);
        bytes memory inner = which == 0 ? abi.encodeWithSignature("burn(uint256)", amount)
            : abi.encodeWithSignature("unwrap(uint256,address,uint256)", amount, from, 0);
        (bool fb, address r, bytes memory cd) = _relayed(i, inner, fee, rel);
        _op(fb ? K_MOVE : K_OPEN, r, cd);
    }
}

/// Kinds 12 and 13 (`PqzRegFixture`, the precompile mocked: a proof passes): one token with every control, `DENYLIST`
/// (`SANCTIONED`; `ALLOWLIST` is not a confidential bit, CTR-GOV-17) and bit 22 to an operator. Ids: `alice` (the PQZ
/// sender), `bob`, `carol` (PQZ UAs), two decoy legs, this handler (the shield payer, the `shieldIn` payer, the minter or the
/// wrapper) and an EOA payee. The ledger paths: shield, wrap-shield (13), the four transfer entries with `shieldIn`, a
/// beneficiary and decoy legs, unshield, refresh, unshield-unwrap (13), prepare and roll-over; public `transfer` and
/// `transferToUA`. Expected successes (I9): a shield to a frozen or denied `toUA`, a transfer whose legs or recipient are
/// frozen or denied, when neither `P` nor the sender's or payer's `F` nor the beneficiary's `F`/`R` refuses it.
abstract contract RegPqzHandler is PqzRegFixture, RegCore {
    address internal constant PAYEE = address(0xE0A1);
    uint256 internal seed = 1000;
    bytes32 internal leg0;
    bytes32 internal leg1;

    function _denylist() internal pure override returns (bool) {
        return true;
    }

    function init() external {
        setUp();
        IFactoryToken.TokenConfig memory c = _regCfg();
        c.features |= 1 << GovernanceBits.OPERATOR_TRANSFER;
        tok = NormalPqzToken(factory.createToken(_kind(), 1, abi.encode(c), "inv"));
        w = WrappedPqzToken(payable(address(tok)));
        cConf = true;
        (leg0, leg1) = (more[3], more[4]);
        _pub(address(this), 1e12);
        tok.transfer(PAYEE, 1e6);
        tok.transferToUA(bob, 1e6);
        tok.transferToUA(carol, 1e6);
        tok.transferToUA(alice, 1e6);
        tok.mtxShield(alice, 50_000);
        usd.approve(address(tok), type(uint256).max);
        bytes32[7] memory ids = [alice, bob, carol, leg0, leg1, nid(address(this)), nid(PAYEE)];
        for (uint256 k; k < 7; ++k) cIds.push(ids[k]);
        _coreInit(address(tok), creg, [attester, cadmin], [ownerA, address(0x0B22), issuer, compliance, address(0x0BE7), address(0x5EE)],
            _isWrapped(), address(usd), _isWrapped() ? bytes32(0) : nid(address(this)));
    }

    function _shieldViews() internal view override {
        for (uint256 k; k < 5; ++k) {
            IPqzToken.AccountState memory a = tok.pqzAccount(cIds[k], 0);
            if (a.pendingCount != 0) tok.pqzPendingCt(cIds[k], 0, a.pendingCount - 1);
        }
        tok.totalShielded();
    }

    function _i1Extra() internal view override returns (bool) {
        return tok.balanceOf(MetaTxLib.SHIELD_POOL) == tok.totalShielded() * SCALE;
    }

    /// A beneficiary: none, `bob` or `carol` (a registered PQZ UA, never a decoy leg).
    function _ben(uint256 b) internal view returns (bytes32) {
        return b % 3 == 0 ? bytes32(0) : b % 3 == 1 ? bob : carol;
    }

    function _benOk(bytes32 ben) internal view returns (bool) {
        return ben == 0 || (!_fz(ben) && _canRecv(ben));
    }

    /// I10: a confidential site's refusal precedes the proof: at most four registry calls and 200 k (direct: no authorization).
    function _conf() internal {
        pGasCap = 4 * REG_GAS + 200_000;
    }

    function pqShield(uint256 j, uint256 a) external {
        bytes32 to = cIds[j % 5];
        pExpect = !_paused() && _free(nid(address(this)));
        _conf();
        _op(K_MOVE, address(this), abi.encodeCall(IConfidentialToken.mtxShield, (to, bound(a, 1, 1000))));
    }

    function pqWrapShield(uint256 j, uint256 a) external {
        if (!_isWrapped()) return;
        a = bound(a, 1, 1000) * SCALE;
        usd.mint(address(this), a);
        pExpect = !_paused() && _free(nid(address(this)));
        _conf();
        _op(K_MOVE, address(this), abi.encodeCall(IConfidentialWrappedToken.mtxWrapShield, (address(usd), a, cIds[j % 5])));
    }

    /// `form` 0 the multi (two decoy legs, `decoyFee` each), 1 its COMPACT entry, 2 the single to `bob`, 3 its COMPACT entry.
    function pqTransfer(uint256 form, uint256 top, uint256 b, uint256 d) external {
        form %= 4;
        bytes32 ben = _ben(b);
        top = bound(top, 0, 3);
        decoy = form < 2 ? bound(d, 0, 2) : 0;
        if (tok.totalShielded() + top < (ben == 0 ? 0 : tok.confidentialFee()) + 2 * decoy) return;
        bytes memory cd;
        if (form < 2) {
            bytes32[] memory rec = new bytes32[](2);
            (rec[0], rec[1]) = (leg0, leg1);
            (pDecoy[leg0], pDecoy[leg1]) = (true, true);
            pDecoys.push(leg0);
            pDecoys.push(leg1);
            cd = abi.encodeWithSelector(form == 0 ? IPqzToken.mtxConfidentialTransfer.selector
                : IPqzToken.mtxConfidentialTransferCompact.selector, _multi(form == 1, rec, ben, top, ++seed), PROOF, _pqAuth(), "",
                noVerdict());
        } else {
            cd = abi.encodeWithSelector(form == 2 ? IPqzToken.mtxConfidentialTransferSingle.selector
                : IPqzToken.mtxConfidentialTransferSingleCompact.selector, _single(form == 3, bob, ben, top, ++seed), PROOF,
                _pqAuth(), "", noVerdict());
        }
        pExpect = !_paused() && _free(alice) && (top == 0 || _free(nid(address(this)))) && _benOk(ben);
        _conf();
        _op(K_MOVE, address(this), cd);
        decoy = 0;
    }

    function pqUnshield(uint256 a, uint256 r, uint256 b) external {
        bytes32 ben = _ben(b);
        uint256 fee = ben == 0 ? 0 : tok.confidentialFee();
        if (tok.totalShielded() <= fee) return;
        bytes32 to = [nid(PAYEE), bob, nid(address(this)), carol][r % 4];
        _conf();
        _op(K_MOVE, address(this), abi.encodeWithSelector(IPqzToken.mtxUnshield.selector, _burnArgs(ben, 0, ++seed),
            bound(a, 1, tok.totalShielded() - fee), to, PROOF, _pqAuth(), bytes(""), noVerdict()));
    }

    /// A refresh (amount 0, recipient 0): never refused without `shieldIn` (spec §4.2); with it, the payer's `P` and `F`.
    function pqRefresh(uint256 top) external {
        top = bound(top, 0, 2);
        _conf();
        _op(top == 0 ? K_ROLL : K_MOVE, address(this), abi.encodeWithSelector(IPqzToken.mtxUnshield.selector,
            _burnArgs(0, top, ++seed), 0, bytes32(0), PROOF, _pqAuth(), bytes(""), noVerdict()));
    }

    function pqUnshieldUnwrap(uint256 a, uint256 b) external {
        if (!_isWrapped()) return;
        bytes32 ben = _ben(b);
        uint256 fee = ben == 0 ? 0 : tok.confidentialFee();
        if (tok.totalShielded() <= fee) return;
        a = bound(a, 1, tok.totalShielded() - fee);
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(PAYEE), a, a * SCALE);
        _conf();
        _op(K_MOVE, address(this), abi.encodeCall(IPqzWrappedToken.mtxUnshieldUnwrap, (_burnArgs(ben, 0, ++seed), x, PROOF,
            _pqAuth(), bytes(""), noVerdict())));
    }

    /// Prepare (both halves, once) and roll-over of a PQZ id: never refused (spec §4.2, §4.3).
    function pqRoll(uint256 j) external {
        bytes32 ua = cIds[j % 5];
        uint8 fl = tok.pqzAccount(ua, 0).flags;
        if (fl & 2 == 0) _op(K_ROLL, address(this), abi.encodeCall(IPqzToken.mtxPrepareAcc, (ua, uint64(0), 0)));
        if (fl & 4 == 0) _op(K_ROLL, address(this), abi.encodeCall(IPqzToken.mtxPrepareAcc, (ua, uint64(0), 1)));
        vm.roll(block.number + 5);
        _op(K_ROLL, address(this), abi.encodeCall(IPqzToken.mtxRollOver, (ua, uint64(0), 4)));
    }

    /// Public units: this handler or the payee to any id (`transfer`, `transferToUA`).
    function pubTransfer(uint256 i, uint256 j, uint256 amount) external {
        address from = i % 2 == 0 ? address(this) : PAYEE;
        bytes32 to = _id(j);
        amount = bound(amount, 0, 5000);
        _op(K_MOVE, from, uint256(to) >> 160 == 0 ? abi.encodeCall(IERC20.transfer, (address(uint160(uint256(to))), amount))
            : abi.encodeCall(IUALedger.transferToUA, (to, amount)));
    }
}

contract RegPqzHandler12 is RegPqzHandler {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract RegPqzHandler13 is RegPqzHandler {
    function _isWrapped() internal pure override returns (bool) { return true; }
}

/// Kinds 10 and 11 (`ZetherRegFixture`: the real Zether stack and test prover, BLS12-381): one token with every control,
/// `DENYLIST` and bit 22 to an operator. Ids: `alice`, `bob`, `carol` (Zether UAs; the plaintext ghosts `zacc`, `zpend` let
/// the handler prove), this handler (shield payer, minter or wrapper) and an EOA payee. The ledger paths: shield,
/// wrap-shield (11), the single and the multi transfer (BUNDLE and COMPACT, a decoy leg with `decoyFee`), unshield,
/// unshield-unwrap (11), roll-over; public `transfer` and `transferToUA`.
abstract contract RegZetherHandler is ZetherRegFixture, RegCore {
    address internal constant PAYEE = address(0xE0A1);
    User[3] internal us;
    uint256[3] public zacc;
    uint256[3] public zpend;

    function _denylist() internal pure override returns (bool) {
        return true;
    }

    function init() external {
        setUp();
        IFactoryToken.TokenConfig memory c = _regCfg(true, uint256(1) << 40);
        c.features |= 1 << GovernanceBits.OPERATOR_TRANSFER;
        tok = NormalZetherToken(factory.createToken(_kind(), 1, abi.encode(c), "inv"));
        cConf = true;
        (us[0], us[1], us[2]) = (alice, bob, carol);
        _public(tok, address(this), 1e10);
        tok.transfer(PAYEE, 1e6);
        for (uint256 i; i < 3; ++i) {
            tok.transferToUA(_zid(i), 1e6);
            tok.mtxShield(_zid(i), 60);
            tok.mtxRollOver(_zid(i), 1);
            zacc[i] = 60;
        }
        usd.approve(address(tok), type(uint256).max);
        bytes32[5] memory ids = [_zid(0), _zid(1), _zid(2), nid(address(this)), nid(PAYEE)];
        for (uint256 k; k < 5; ++k) cIds.push(ids[k]);
        _coreInit(address(tok), creg, [attester, cadmin], [ownerA, address(0x0B22), issuer, compliance, address(0x0BE7), address(0x5EE)],
            _isWrapped(), address(usd), _isWrapped() ? bytes32(0) : nid(address(this)));
    }

    function _zid(uint256 i) internal view returns (bytes32) {
        return ZetherTypes.UA.unwrap(us[i].ua);
    }

    function _shieldViews() internal view override {
        for (uint256 i; i < 3; ++i) tok.accountState(us[i].ua);
        tok.totalShielded();
    }

    function _i1Extra() internal view override returns (bool) {
        return tok.balanceOf(MetaTxLib.SHIELD_POOL) == tok.totalShielded() * SCALE;
    }

    function _conf() internal {
        pGasCap = 4 * REG_GAS + 200_000;
    }

    function zShield(uint256 i, uint256 a) external {
        i %= 3;
        a = bound(a, 1, 40);
        pExpect = !_paused() && _free(nid(address(this)));
        _conf();
        if (_op(K_MOVE, address(this), abi.encodeCall(IConfidentialToken.mtxShield, (_zid(i), a)))) zpend[i] += a;
    }

    function zWrapShield(uint256 i, uint256 a) external {
        if (!_isWrapped()) return;
        i %= 3;
        a = bound(a, 1, 40);
        usd.mint(address(this), a * SCALE);
        pExpect = !_paused() && _free(nid(address(this)));
        _conf();
        if (_op(K_MOVE, address(this), abi.encodeCall(IConfidentialWrappedToken.mtxWrapShield, (address(usd), a * SCALE,
            _zid(i))))) zpend[i] += a;
    }

    /// Roll-over: never refused (spec §4.3).
    function zRoll(uint256 i) external {
        i %= 3;
        if (_op(K_ROLL, address(this), abi.encodeCall(IZetherToken.mtxRollOver, (_zid(i), 1)))) {
            zacc[i] += zpend[i];
            zpend[i] = 0;
        }
    }

    function zTransfer(uint256 i, uint256 j, uint256 v) external {
        (i, j) = (i % 3, j % 3);
        if (i == j) j = (i + 1) % 3;
        if (zacc[i] == 0) return;
        v = bound(v, 1, zacc[i]);
        Tx memory x = _proveTransfer(tok, us[i], us[j], v, zacc[i], _none(), 0);
        pExpect = !_paused() && _free(_zid(i));
        _conf();
        if (_op(K_MOVE, address(this), abi.encodeCall(IZetherToken.mtxConfidentialTransferSingle,
            (_zSingle(x.payload, _none()), x.proof))))
        {
            zacc[i] -= v;
            zpend[j] += v;
        }
    }

    /// `i` to `j` (value `v`) and to the third user (a decoy of 0), `decoyFee` `d` on both legs; BUNDLE or COMPACT.
    function zMulti(uint256 i, uint256 j, uint256 v, uint256 d, bool compact) external {
        (i, j) = (i % 3, j % 3);
        if (i == j) j = (i + 1) % 3;
        uint256 o = 3 - i - j;
        d = bound(d, 0, 2);
        if (zacc[i] <= 2 * d) return;
        v = bound(v, 1, zacc[i] - 2 * d);
        User[] memory to = new User[](2);
        (to[0], to[1]) = (us[j], us[o]);
        uint256[] memory vs = new uint256[](2);
        vs[0] = v;
        decoyFee = d;
        Tx memory x = _proveMulti(tok, us[i], to, vs, zacc[i], _none(), compact ? ZetherTypes.TransferMode.HASH
            : _defaultForm(tok));
        decoyFee = 0;
        (pDecoy[_zid(j)], pDecoy[_zid(o)]) = (true, true);
        pDecoys.push(_zid(j));
        pDecoys.push(_zid(o));
        pExpect = !_paused() && _free(_zid(i));
        _conf();
        if (_op(K_MOVE, address(this), abi.encodeWithSelector(compact ? IZetherToken.mtxConfidentialTransferCompact.selector
            : IZetherToken.mtxConfidentialTransfer.selector, _zMulti(x.payload, _none()), x.proof)))
        {
            zacc[i] -= v + 2 * d;
            zpend[j] += v;
        }
    }

    function zUnshield(uint256 i, uint256 a, uint256 r) external {
        i %= 3;
        if (zacc[i] == 0) return;
        a = bound(a, 1, zacc[i]);
        bytes32 rc = [nid(PAYEE), nid(address(this)), _zid((i + 1) % 3)][r % 3];
        (bytes memory pl, bytes memory pr) = _proveUnshieldTo(tok, us[i], a, zacc[i], rc, _none(), 0);
        _conf();
        if (_op(K_MOVE, address(this), abi.encodeCall(IZetherToken.mtxUnshield, (_zBurn(pl, _none()), a, rc, pr)))) zacc[i] -= a;
    }

    function zUnshieldUnwrap(uint256 i, uint256 a) external {
        if (!_isWrapped()) return;
        i %= 3;
        if (zacc[i] == 0) return;
        a = bound(a, 1, zacc[i]);
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(PAYEE), a, a * SCALE);
        IZetherToken.ZetherBurn memory b = _zBurn(_unshieldPayload(tok, us[i]), _none());
        bytes memory pr = _proveU(us[i], stm.unshieldUnwrapStatement(address(tok), b, x.amount, x.recipient, x.underlying,
            x.minOut, 0), a, zacc[i], _none(), tok);
        _conf();
        if (_op(K_MOVE, address(this), abi.encodeCall(IZetherUnwrapDirect.mtxUnshieldUnwrap, (b, x, pr)))) zacc[i] -= a;
    }

    function pubTransfer(uint256 i, uint256 j, uint256 amount) external {
        address from = i % 2 == 0 ? address(this) : PAYEE;
        bytes32 to = _id(j);
        amount = bound(amount, 0, 5000);
        _op(K_MOVE, from, uint256(to) >> 160 == 0 ? abi.encodeCall(IERC20.transfer, (address(uint160(uint256(to))), amount))
            : abi.encodeCall(IUALedger.transferToUA, (to, amount)));
    }
}

contract RegZetherHandler10 is RegZetherHandler {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract RegZetherHandler11 is RegZetherHandler {
    function _isWrapped() internal pure override returns (bool) { return true; }
}
