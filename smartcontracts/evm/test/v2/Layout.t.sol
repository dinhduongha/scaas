// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {stdJson} from "forge-std/StdJson.sol";
import {V2Fixture} from "./helpers/V2Fixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {TokenStore} from "../../src/metatx/TokenStore.sol";
import {WrappedLib} from "../../src/metatx/WrappedLib.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UAMetaTxBase, UAMetaTxBaseCore} from "../../src/metatx/UAMetaTxBase.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {RegulatedLib} from "../../src/regulated/RegulatedLib.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {ZetherLib} from "../../src/zether/ZetherLib.sol";
import {UAAdmin} from "../../src/governance/UAAdmin.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IZetherVerifier} from "../../src/zether/IZetherVerifier.sol";

library NamespaceProbeIds {
    bytes32 internal constant U = 0xcafe00000000000000000000000000000000000000000000000000000000a11a;
    bytes32 internal constant V = 0xbeef00000000000000000000000000000000000000000000000000000000b22b;

    /// A `bytes` value of `len` bytes, its words `keccak256(len, j)`: distinct lengths tell two `bytes` fields apart.
    function blob(uint256 len) internal pure returns (bytes memory b) {
        for (uint256 j; 32 * j < len; ++j) b = bytes.concat(b, keccak256(abi.encode(len, j)));
        assembly ("memory-safe") { mstore(b, len) }
    }
}

/// Writes every field of the five ERC-7201 namespaces through the source's own accessor, so the test reads where the
/// compiler put each one (spec §1.4, §10.4).
contract NamespaceProbe is UAMetaTxBase {
    address internal constant A = address(0xA11);
    address internal constant B = address(0xB22);
    /// Two derived UA ids, top 96 bits set, so a field that kept 20 bytes would not hold them.
    bytes32 internal constant U = NamespaceProbeIds.U;
    bytes32 internal constant V = NamespaceProbeIds.V;

    constructor() UAMetaTxBaseCore("P", bytes32(uint256(1)), address(0), address(0), false) {}

    function poke() external {
        TokenStore.TokenStorage storage t = TokenStore.$();
        (t.creator, t.version, t.kind, t.decimals, t.initialized) = (A, 0x71, 0x72, 0x73, true);
        (t.name, t.symbol) = ("N", "S");
        GovernanceLib.GovernanceStorage storage g = GovernanceLib.$();
        // every governance identity a UA id (CTR-GOV-01 Change): the owner words and the mapping keys are `bytes32`
        (g.features, g.lockedFeatures, g.admin) = (0x81, 0x82, U);
        (g.grantDelay, g.adminGeneration) = (0x83, 0x84);
        (g.pendingAdmin, g.lastProposedAt, g.rescueTo) = (V, 0x85, B);
        g.roles[1][U] = 2;
        (g.counts[1].holders, g.counts[1].roots) = (0x86, 0x87);
        (g.grants[1][U].grantorEpoch, g.grants[1][U].barred, g.grants[1][U].grantor) = (0x8c, true, V);
        g.epoch[1][U] = 0x88;
        g.pending[1][U] = GovernanceLib.PendingGrant(0x89, 0x8a, V, bytes32(uint256(0x8b)));
        WrappedLib.WrappedStorage storage w = WrappedLib.$();
        WrappedLib.Leg storage l = w.legs[1];
        (l.token, l.decimals, l.wrapEnabled, l.adjustable, l.capped) = (A, 0x91, true, true, true);
        (l.num, l.den, l.reserve) = (0x92, 0x93, 0x94);
        w.legIndex[A] = 0x95;
        w.pending = WrappedLib.PendingRate(0x96, 0x97, 0x98, 0x99);
        (w.legCount, w.rateDelay, w.maxRateStepBps, w.maxSupply) = (0x9a, 0x9b, 0x9c, 0x9d);
        l.ctl = 0x9e; // group 3l (wrap limits spec §5): byte 24 of slot a
        _pokeWrapLimit();
        _ua().balance[bytes32(uint256(0xa1))] = 0xa2;
        _ua().cancelUsed[bytes32(uint256(0xa3))] = true;
        MtxPipelineLib._mtxStorage().nonce[bytes32(uint256(0xb1))][2] = 0xb2;
        // plan T83: `scaas.pay.records`, two records of `V` (amount 24 bytes, blockNumber 8: both bounds at their top)
        MtxPipelineLib._payRecords().records[V].push(MetaTxLib.PayRecord(U, type(uint192).max - 1, 0x0b));
        MtxPipelineLib._payRecords().records[V].push(MetaTxLib.PayRecord(V, 0x0c, type(uint64).max - 1));
        // plan T28: `scaas.regulated` (regulated-kinds spec §2.3)
        RegulatedLib.RegulatedStorage storage r = RegulatedLib.$();
        (r.complianceRegistry, r.controls, r.pausedUntil) = (B, 0xc1, 0xc2);
        (r.requiredFlags, r.deniedFlags, r.pauseCooldownUntil, r.termsHash) = (0xc3, 0xc4, 0xc5, bytes32(uint256(0xc6)));
        r.freezes[U] = IRegulatedToken.FreezeState(0xc7, 0xc8, 0xc9, true, V);
        r.orders[U] = IRegulatedToken.OrderRecord(V, U, 0xca, true, 0xcb, 0xcc);
        // pay-meta-tax T39 (spec §6.2): +5 `taxRecipient`, +6 `TaxRate`
        (r.taxRecipient, r.taxRate) = (bytes32(uint256(0xc0)), IRegulatedToken.TaxRate(0xbd, 0xbe, 0xbf));
        // plan T19c (no-decryption-oracle spec §4.4, §4.7): `scaas.pqz` and `scaas.zether`, read by `ua-rs` from the pin
        PqzCore.PqzStorage storage q = PqzCore.$();
        (q.pqz, q.disclosureMode, q.auditorMode, q.verifier) =
            (A, ZetherTypes.DisclosureMode.COMPACT, ZetherTypes.AuditorMode.OPTIONAL, B);
        (q.psid, q.shieldScale, q.maxShielded, q.confidentialFee) = (bytes32(uint256(0xd1)), 0xd2, 0xd3, 0xd4);
        (q.totalShielded, q.auditorUA, q.minDecoyFee) = (0xd5, V, 0xd6);
        // group 3f (PQZ verifier mode spec §3, §4.4): the mode at byte 22 of slot 0, the verifier state appended
        (q.pqzVerifyMode, q.pqzVerifierUA, q.pqzVerifierShape) = (1, U, bytes32(uint256(0xd7)));
        (q.pqzVerifierEpoch, q.pqzVerifierFixed, q.noticePeriod, q.eta) = (0xd8, true, 0xd9, 0xda);
        (q.pqzPendingVerifier, q.pqzProposer, q.pqzProposerGeneration) = (V, bytes32(uint256(0xdb)), 0xdc);
        // group 3g T52 (KV-6): the account per `(ua, key version)`, `sendCounter` per UA
        PqzCore.Account storage qa = q.acct[U][7];
        (qa.pendingCount, qa.rolled, qa.floor, qa.cleared) = (0xe1, 0xe2, 0xe3, 0xe4);
        (qa.accBlob, qa.accU, qa.accV, qa.accUnits, qa.flags) = (B, 0xe5, 0xe6, 0xe7, 0xe8);
        (q.sendCounter[U], qa.accHash) = (0xe9, bytes32(uint256(0xea)));
        qa.pending[3] = 0xeb;
        (qa.accWords[0], qa.accWords[1]) = (0xec, 0xed);
        // group 3h T58 (pqz-proof-path spec §2.2, §6): the account's `lastDebit`, the debit record appended
        (qa.lastDebit, q.debitRec[U][7]) = (0xdd, PqzCore.DebitRecord(0xde, 0xdf));
        q.proofStore = 1; // group 3h T60: byte 23 of slot 0
        q.entryPtr[V] = A;
        (q.memos[V], q.memos[U]) = (NamespaceProbeIds.blob(58), NamespaceProbeIds.blob(21));
        ZetherLib.ZetherStorage storage z = ZetherLib.$();
        (z.verifier, z.disclosureMode, z.auditorMode) =
            (IZetherVerifier(A), ZetherTypes.DisclosureMode.COMPACT, ZetherTypes.AuditorMode.OPTIONAL);
        (z.shieldScale, z.maxShielded, z.confidentialFee, z.totalShielded) = (0xf1, 0xf2, 0xf3, 0xf4);
        (z.auditorKey, z.psid, z.p, z.minDecoyFee) = (NamespaceProbeIds.blob(124), bytes32(uint256(0xf5)), 0xf6, 0xf7);
        ZetherLib.Account storage za = z.acct[ZetherTypes.UA.wrap(U)];
        (za.accC, za.accD) = (NamespaceProbeIds.blob(128), NamespaceProbeIds.blob(127));
        (za.pendC, za.pendD) = (NamespaceProbeIds.blob(126), NamespaceProbeIds.blob(125));
        (za.accSeq, za.pendingSeq, za.lastRolledPendingSeq, za.sendCounter) = (0xf8, 0xf9, 0xfa, 0xfb);
        (za.modeNonce, za.mode) = (0xfc, ZetherTypes.RollOverMode.OWNER_ONLY);
        z.entries[V] = NamespaceProbeIds.blob(200);
        z.entryPtrs[V] = B;
        (z.memos[V], z.memos[U]) = (NamespaceProbeIds.blob(33), NamespaceProbeIds.blob(20));
    }

    /// Group 3l (wrap limits spec §5, R26): `scaas.wraplimit`, leg 1's two config words and two token-wide window words by
    /// field, `U`'s quota word on leg 1, its member byte, the pending.
    function _pokeWrapLimit() internal {
        WrappedLib.WrapLimitStorage storage x = WrappedLib.wl();
        WrappedLib.LegConfig storage c = x.config[1];
        (c.wrapShortPerUser, c.wrapShortTokenWide, c.wrapShortPeriodMin, c.wrapLongPerUser) = (0x101, 0x102, 0x103, 0x104);
        (c.wrapLongTokenWide, c.wrapLongPeriodMin, c.unitExp, c.decayDays) = (0x105, 0x106, 0x07, 0x108);
        (c.unwrapShortPerUser, c.unwrapShortTokenWide, c.unwrapShortPeriodMin, c.unwrapLongPerUser) = (0x109, 0x10a, 0x10b, 0x10c);
        (c.unwrapLongTokenWide, c.unwrapLongPeriodMin, c.unitExpCopy, c.decayDaysCopy) = (0x10d, 0x10e, 0x0f, 0x110);
        WrappedLib.TokenWindow storage t = x.total[1][0];
        (t.shortStart, t.shortUsed, t.longStart, t.longUsed) = (0x111, 0x112, 0x113, 0x114);
        t = x.total[1][1];
        (t.shortStart, t.shortUsed, t.longStart, t.longUsed) = (0x115, 0x116, 0x117, 0x118);
        x.quota[U][1] = 0x119;
        x.member[U] = 3;
        (x.pendingCommit, x.pendingEta, x.pendingGeneration) = (bytes32(uint256(0x11a)), 0x11b, 0x11c);
    }
}

/// Round 3r T5 (admin-not-owner spec §5.1): writes `scaas.admin` through `UAAdmin`'s own accessor.
contract AdminProbe is UAAdmin {
    function _adminRouter() internal pure override returns (address) {}

    function poke() external {
        AdminStorage storage s = _adminStorage();
        (s.admin, s.pendingAdmin, s.adminGeneration) = (NamespaceProbeIds.U, NamespaceProbeIds.V, 0x12345678);
    }
}

/// @title Ghim storage layout của từng implementation v2 (TW2 §10.1): indexer và storage proof đọc `reserve`.
/// @notice So `storageLayout` của artifact solc (`extra_output`) với `test/v2/layout/<Contract>.json` đã commit
///         (nhãn, slot, offset). Đổi layout là đổi file pin — có chủ ý, trong cùng commit.
contract LayoutTest is V2Fixture {
    using stdJson for string;

    function _pin(string memory file, string memory name) internal view {
        string memory art = vm.readFile(string.concat("./", vm.envOr("FOUNDRY_OUT", string("out")), "/", file, ".sol/", name, ".json"));
        string memory pin = vm.readFile(string.concat("./test/v2/layout/", name, ".json"));
        string[] memory pl = pin.readStringArray(".labels");
        string[] memory ps = pin.readStringArray(".slots");
        uint256[] memory po = pin.readUintArray(".offsets");
        for (uint256 i; i < pl.length; ++i) {
            string memory e = string.concat(".storageLayout.storage[", vm.toString(i), "]");
            assertEq(art.readString(string.concat(e, ".label")), pl[i], name);
            assertEq(art.readString(string.concat(e, ".slot")), ps[i], name);
            assertEq(art.readUint(string.concat(e, ".offset")), po[i], name);
        }
        // no variable appended past the pin
        assertFalse(vm.keyExistsJson(art, string.concat(".storageLayout.storage[", vm.toString(pl.length), "]")), name);
    }

    function test_storageLayoutIsPinned() public view {
        _pin("NormalToken", "NormalToken");
        _pin("WrappedToken", "WrappedToken");
        _pin("NormalZetherToken", "NormalZetherToken"); // the Zether layer lives in `scaas.zether`
        _pin("WrappedZetherToken", "WrappedZetherToken");
        _pin("NormalPqzToken", "NormalPqzToken"); // the PQZ layer lives in `scaas.pqz`
        _pin("WrappedPqzToken", "WrappedPqzToken");
        _pin("SCaaSDex", "SCaaSDex"); // its state lives in `scaas.dex`
        _pin("SCaaSDexLiquidityModule", "SCaaSDexLiquidityModule"); // the DEX's layout (M6): none of its own
        _pin("GovernanceRouter", "GovernanceRouter"); // no state of its own: nonces in `scaas.metatx`, the pair transient
    }

    /// One field of a namespace: its label, the keys of the mapping it sits in (0 = none; `k2` the inner key), the value
    /// `NamespaceProbe.poke` wrote and its width in bytes.
    struct F {
        string label;
        uint256 k1;
        uint256 k2;
        uint256 value;
        uint256 width;
    }

    /// Spec §1.4, §10.4: each namespace's root is ERC-7201 of its id, and each field sits at the pinned slot, inner slot
    /// and byte (`test/v2/layout/namespaces.json`), read with `vm.load` after a write through the source's accessor.
    function test_namespaceRootsAndOffsetsArePinned() public {
        NamespaceProbe p = new NamespaceProbe();
        p.poke();
        uint256 a = uint160(address(0xA11));
        uint256 b = uint160(address(0xB22));
        F[] memory f = new F[](7);
        f[0] = F("creator", 0, 0, a, 20);
        f[1] = F("version", 0, 0, 0x71, 8);
        f[2] = F("kind", 0, 0, 0x72, 1);
        f[3] = F("decimals", 0, 0, 0x73, 1);
        f[4] = F("initialized", 0, 0, 1, 1);
        f[5] = F("name", 0, 0, uint256(bytes32("N")) | 2, 32);
        f[6] = F("symbol", 0, 0, uint256(bytes32("S")) | 2, 32);
        _ns(address(p), "token", "scaas.token", f);
        uint256 u = uint256(NamespaceProbeIds.U);
        uint256 v = uint256(NamespaceProbeIds.V);
        f = new F[](19);
        f[0] = F("features", 0, 0, 0x81, 32);
        f[1] = F("lockedFeatures", 0, 0, 0x82, 32);
        f[2] = F("admin", 0, 0, u, 32);
        f[3] = F("pendingAdmin", 0, 0, v, 32);
        f[4] = F("grantDelay", 0, 0, 0x83, 8);
        f[5] = F("adminGeneration", 0, 0, 0x84, 4);
        f[6] = F("lastProposedAt", 0, 0, 0x85, 8);
        f[7] = F("roles[1][A]", 1, u, 2, 1);
        f[8] = F("counts[1].holders", 1, 0, 0x86, 16);
        f[9] = F("counts[1].roots", 1, 0, 0x87, 16);
        f[10] = F("grants[1][A].grantorEpoch", 1, u, 0x8c, 4);
        f[11] = F("grants[1][A].barred", 1, u, 1, 1);
        f[12] = F("grants[1][A].grantor", 1, u, v, 32);
        f[13] = F("epoch[1][A]", 1, u, 0x88, 4);
        f[14] = F("pending[1][A].eta", 1, u, 0x89, 8);
        f[15] = F("pending[1][A].generation", 1, u, 0x8a, 4);
        f[16] = F("pending[1][A].proposer", 1, u, v, 32);
        f[17] = F("pending[1][A].commit", 1, u, 0x8b, 32);
        f[18] = F("rescueTo", 0, 0, b, 20);
        _ns(address(p), "governance", "scaas.governance", f);
        f = new F[](14);
        f[0] = F("legs[1].token", 1, 0, a, 20);
        f[1] = F("legs[1].decimals", 1, 0, 0x91, 1);
        f[2] = F("legs[1].wrapEnabled", 1, 0, 1, 1);
        f[3] = F("legs[1].adjustable", 1, 0, 1, 1);
        f[4] = F("legs[1].num", 1, 0, 0x92, 12);
        f[5] = F("legs[1].den", 1, 0, 0x93, 12);
        f[6] = F("legs[1].reserve", 1, 0, 0x94, 32);
        f[7] = F("legIndex[A]", a, 0, 0x95, 32);
        f[8] = F("pending.leg", 0, 0, 0x96, 1);
        f[9] = F("pending.num", 0, 0, 0x97, 12);
        f[10] = F("pending.den", 0, 0, 0x98, 12);
        f[11] = F("pending.eta", 0, 0, 0x99, 7);
        f[12] = F("legCount", 0, 0, 0x9a, 1);
        f[13] = F("rateDelay", 0, 0, 0x9b, 4);
        f = _more(f, F("maxRateStepBps", 0, 0, 0x9c, 2));
        f = _more(f, F("legs[1].capped", 1, 0, 1, 1)); // governance T9 (spec §5.2): appended, `reserve` unmoved
        f = _more(f, F("maxSupply", 0, 0, 0x9d, 32));
        f = _more(f, F("legs[1].ctl", 1, 0, 0x9e, 1)); // group 3l: appended, slots b and c unmoved
        _ns(address(p), "underlying", "scaas.underlying", f);
        _wrapLimitPinned(address(p), u);
        f = new F[](2);
        f[0] = F("balance[0xa1]", 0xa1, 0, 0xa2, 32);
        f[1] = F("cancelUsed[0xa3]", 0xa3, 0, 1, 1);
        _ns(address(p), "uaLedger", "scaas.ua.ledger", f);
        f = new F[](1);
        f[0] = F("nonce[0xb1][2]", 0xb1, 2, 0xb2, 32);
        _ns(address(p), "metatx", "scaas.metatx", f);
        _payRecordsPinned(address(p));
        f = new F[](17);
        f[0] = F("complianceRegistry", 0, 0, b, 20);
        f[1] = F("controls", 0, 0, 0xc1, 1);
        f[2] = F("pausedUntil", 0, 0, 0xc2, 8);
        f[3] = F("requiredFlags", 0, 0, 0xc3, 8);
        f[4] = F("deniedFlags", 0, 0, 0xc4, 8);
        f[5] = F("pauseCooldownUntil", 0, 0, 0xc5, 8);
        f[6] = F("termsHash", 0, 0, 0xc6, 32);
        f[7] = F("freezes[A].until", u, 0, 0xc7, 8);
        f[8] = F("freezes[A].episodeStart", u, 0, 0xc8, 8);
        f[9] = F("freezes[A].issuerCooldownUntil", u, 0, 0xc9, 8);
        f[10] = F("freezes[A].recordBacked", u, 0, 1, 1);
        f[11] = F("freezes[A].recordId", u, 0, v, 32);
        f[12] = F("orders[A].subject", u, 0, v, 32);
        f[13] = F("orders[A].beneficiary", u, 0, u, 32);
        f[14] = F("orders[A].freezeUntil", u, 0, 0xca, 8);
        f[15] = F("orders[A].revoked", u, 0, 1, 1);
        f[16] = F("orders[A].maxAmount", u, 0, 0xcb, 32);
        f = _more(f, F("orders[A].executed", u, 0, 0xcc, 32));
        f = _more(f, F("taxRecipient", 0, 0, 0xc0, 32));
        f = _more(f, F("taxRate.ratePpm", 0, 0, 0xbd, 4));
        f = _more(f, F("taxRate.pendingPpm", 0, 0, 0xbe, 4));
        f = _more(f, F("taxRate.eta", 0, 0, 0xbf, 8));
        _ns(address(p), "regulated", "scaas.regulated", f);
        // plan T19c: a `bytes` row's value is its length; a `mapping` row's `k2` is the key of the struct member's mapping
        f = new F[](29);
        f[0] = F("pqz", 0, 0, a, 20);
        f[1] = F("disclosureMode", 0, 0, 1, 1);
        f[2] = F("auditorMode", 0, 0, 2, 1);
        f[3] = F("verifier", 0, 0, b, 20);
        f[4] = F("psid", 0, 0, 0xd1, 32);
        f[5] = F("shieldScale", 0, 0, 0xd2, 32);
        f[6] = F("maxShielded", 0, 0, 0xd3, 32);
        f[7] = F("confidentialFee", 0, 0, 0xd4, 32);
        f[8] = F("totalShielded", 0, 0, 0xd5, 32);
        f[9] = F("auditorUA", 0, 0, v, 32);
        f[10] = F("acct[U][7].pendingCount", u, 0, 0xe1, 8);
        f[11] = F("acct[U][7].rolled", u, 0, 0xe2, 8);
        f[12] = F("acct[U][7].floor", u, 0, 0xe3, 8);
        f[13] = F("acct[U][7].cleared", u, 0, 0xe4, 8);
        f[14] = F("acct[U][7].accBlob", u, 0, b, 20);
        f[15] = F("acct[U][7].accU", u, 0, 0xe5, 2);
        f[16] = F("acct[U][7].accV", u, 0, 0xe6, 2);
        f[17] = F("acct[U][7].accUnits", u, 0, 0xe7, 4);
        f[18] = F("acct[U][7].flags", u, 0, 0xe8, 1);
        f[19] = F("acct[U][7].lastDebit", u, 0, 0xdd, 8);
        f[20] = F("acct[U][7].accHash", u, 0, 0xea, 32);
        f[21] = F("acct[U][7].pending[3]", u, 3, 0xeb, 32);
        f[22] = F("acct[U][7].accWords[0]", u, 0, 0xec, 32);
        f[23] = F("acct[U][7].accWords[1]", u, 0, 0xed, 32);
        f[24] = F("entryPtr[V]", v, 0, a, 20);
        f[25] = F("memos[V]", v, 0, 58, 32);
        f[26] = F("memos[U]", u, 0, 21, 32);
        f[27] = F("minDecoyFee", 0, 0, 0xd6, 32);
        f[28] = F("sendCounter[U]", u, 0, 0xe9, 8);
        f = _more(f, F("pqzVerifyMode", 0, 0, 1, 1));
        f = _more(f, F("pqzVerifierUA", 0, 0, u, 32));
        f = _more(f, F("pqzVerifierShape", 0, 0, 0xd7, 32));
        f = _more(f, F("pqzVerifierEpoch", 0, 0, 0xd8, 4));
        f = _more(f, F("pqzVerifierFixed", 0, 0, 1, 1));
        f = _more(f, F("noticePeriod", 0, 0, 0xd9, 8));
        f = _more(f, F("eta", 0, 0, 0xda, 8));
        f = _more(f, F("pqzPendingVerifier", 0, 0, v, 32));
        f = _more(f, F("pqzProposer", 0, 0, 0xdb, 32));
        f = _more(f, F("pqzProposerGeneration", 0, 0, 0xdc, 4));
        f = _more(f, F("debitRec[U][7].w0", u, 0, 0xde, 32));
        f = _more(f, F("debitRec[U][7].w1", u, 0, 0xdf, 32));
        f = _more(f, F("proofStore", 0, 0, 1, 1));
        _ns(address(p), "pqz", "scaas.pqz", f);
        f = new F[](25);
        f[0] = F("verifier", 0, 0, a, 20);
        f[1] = F("disclosureMode", 0, 0, 1, 1);
        f[2] = F("auditorMode", 0, 0, 2, 1);
        f[3] = F("shieldScale", 0, 0, 0xf1, 32);
        f[4] = F("maxShielded", 0, 0, 0xf2, 32);
        f[5] = F("confidentialFee", 0, 0, 0xf3, 32);
        f[6] = F("totalShielded", 0, 0, 0xf4, 32);
        f[7] = F("auditorKey", 0, 0, 124, 32);
        f[8] = F("psid", 0, 0, 0xf5, 32);
        f[9] = F("p", 0, 0, 0xf6, 32);
        f[10] = F("acct[U].accC", u, 0, 128, 32);
        f[11] = F("acct[U].accD", u, 0, 127, 32);
        f[12] = F("acct[U].pendC", u, 0, 126, 32);
        f[13] = F("acct[U].pendD", u, 0, 125, 32);
        f[14] = F("acct[U].accSeq", u, 0, 0xf8, 8);
        f[15] = F("acct[U].pendingSeq", u, 0, 0xf9, 8);
        f[16] = F("acct[U].lastRolledPendingSeq", u, 0, 0xfa, 8);
        f[17] = F("acct[U].sendCounter", u, 0, 0xfb, 8);
        f[18] = F("acct[U].modeNonce", u, 0, 0xfc, 8);
        f[19] = F("acct[U].mode", u, 0, 1, 1);
        f[20] = F("entries[V]", v, 0, 200, 32);
        f[21] = F("entryPtrs[V]", v, 0, b, 20);
        f[22] = F("memos[V]", v, 0, 33, 32);
        f[23] = F("memos[U]", u, 0, 20, 32);
        f[24] = F("minDecoyFee", 0, 0, 0xf7, 32);
        _ns(address(p), "zether", "scaas.zether", f);
        AdminProbe ap = new AdminProbe();
        ap.poke();
        f = new F[](3);
        f[0] = F("admin", 0, 0, u, 32);
        f[1] = F("pendingAdmin", 0, 0, v, 32);
        f[2] = F("adminGeneration", 0, 0, 0x12345678, 4);
        _ns(address(ap), "admin", "scaas.admin", f);
    }

    /// Plan T83: `scaas.pay.records` (`payRecords` in the pin): the root is ERC-7201 of its id and `PAY_RECORDS_SLOT`;
    /// `records[V]`'s length at `keccak256(V ‖ root + slot)`; record `index` from `keccak256(that slot) + 2·index + inner`,
    /// the value at `bytes` of the word, `widths` bytes wide.
    function _payRecordsPinned(address p) internal view {
        string memory pin = vm.readFile("./test/v2/layout/namespaces.json");
        assertEq(pin.readString(".payRecords.id"), "scaas.pay.records");
        bytes32 root = keccak256(abi.encode(uint256(keccak256("scaas.pay.records")) - 1)) & ~bytes32(uint256(0xff));
        assertEq(pin.readBytes32(".payRecords.root"), root, "payRecords root");
        assertEq(MtxPipelineLib.PAY_RECORDS_SLOT, root, "PAY_RECORDS_SLOT");
        string[] memory labels = pin.readStringArray(".payRecords.labels");
        uint256[7] memory want = [uint256(2), uint256(NamespaceProbeIds.U), type(uint192).max - 1, 0x0b,
            uint256(NamespaceProbeIds.V), 0x0c, type(uint64).max - 1];
        uint256[7] memory width = [uint256(32), 32, 24, 8, 32, 24, 8];
        assertEq(labels.length, 7, "payRecords rows");
        for (uint256 i; i < 7; ++i) {
            assertEq(pin.readUintArray(".payRecords.widths")[i], width[i], labels[i]);
            assertEq(_payRecordAt(p, pin, uint256(root), i, width[i]), want[i], labels[i]);
        }
    }

    /// Row `i` of `payRecords`: the word at its slot (`length`: the length slot; `array`: the record's), shifted to `bytes`.
    function _payRecordAt(address p, string memory pin, uint256 root, uint256 i, uint256 width)
        internal view returns (uint256)
    {
        uint256 len = uint256(keccak256(abi.encode(NamespaceProbeIds.V, root + pin.readUintArray(".payRecords.slots")[i])));
        uint256 s = keccak256(bytes(pin.readStringArray(".payRecords.encodings")[i])) == keccak256("length") ? len
            : uint256(keccak256(abi.encode(len))) + 2 * pin.readUintArray(".payRecords.index")[i]
                + pin.readUintArray(".payRecords.inner")[i];
        uint256 mask = width == 32 ? type(uint256).max : (uint256(1) << (8 * width)) - 1;
        return (uint256(vm.load(p, bytes32(s))) >> (8 * pin.readUintArray(".payRecords.bytes")[i])) & mask;
    }

    /// Group 3l (wrap limits spec §5, R26): `scaas.wraplimit` at the probe's keys (leg 1, `U`).
    function _wrapLimitPinned(address p, uint256 u) internal {
        string[16] memory cfg = ["wrapShortPerUser", "wrapShortTokenWide", "wrapShortPeriodMin", "wrapLongPerUser",
            "wrapLongTokenWide", "wrapLongPeriodMin", "unitExp", "decayDays", "unwrapShortPerUser", "unwrapShortTokenWide",
            "unwrapShortPeriodMin", "unwrapLongPerUser", "unwrapLongTokenWide", "unwrapLongPeriodMin", "unitExpCopy", "decayDaysCopy"];
        uint8[8] memory cw = [3, 8, 3, 3, 8, 3, 1, 2];
        string[8] memory tot = ["[0].shortStart", "[0].shortUsed", "[0].longStart", "[0].longUsed", "[1].shortStart",
            "[1].shortUsed", "[1].longStart", "[1].longUsed"];
        uint8[4] memory tw = [3, 8, 3, 8];
        F[] memory f = new F[](29);
        for (uint256 i; i < 16; ++i) {
            uint256 v = i % 8 == 6 ? 0x07 + 8 * (i / 8) : 0x101 + i;
            f[i] = F(string.concat("config[1].", cfg[i]), 1, 0, v, cw[i % 8]);
        }
        for (uint256 i; i < 8; ++i) f[16 + i] = F(string.concat("total[1]", tot[i]), 1, 0, 0x111 + i, tw[i % 4]);
        f[24] = F("quota[U][1]", u, 1, 0x119, 32);
        f[25] = F("member[U]", u, 0, 3, 1);
        f[26] = F("pendingCommit", 0, 0, 0x11a, 32);
        f[27] = F("pendingEta", 0, 0, 0x11b, 8);
        f[28] = F("pendingGeneration", 0, 0, 0x11c, 4);
        _ns(p, "wrapLimit", "scaas.wraplimit", f);
    }

    function _more(F[] memory f, F memory x) internal pure returns (F[] memory g) {
        g = new F[](f.length + 1);
        for (uint256 i; i < f.length; ++i) g[i] = f[i];
        g[f.length] = x;
    }

    /// The root, then each field at `keccak(k2, keccak(k1, root + slot)) + inner`, byte `bytes` (no key: `root + slot`);
    /// where the namespace has `encodings` (plan T19c), a `mapping` member's key `k2` applies after `inner` and a `bytes`
    /// field is checked as solc stores it (`_bytesAt`), and each `widths` entry equals the test's width.
    function _ns(address p, string memory key, string memory id, F[] memory f) internal view {
        string memory pin = vm.readFile("./test/v2/layout/namespaces.json");
        string memory k = string.concat(".", key);
        assertEq(pin.readString(string.concat(k, ".id")), id, key);
        bytes32 root = keccak256(abi.encode(uint256(keccak256(bytes(id))) - 1)) & ~bytes32(uint256(0xff));
        assertEq(pin.readBytes32(string.concat(k, ".root")), root, id);
        {
            string[] memory labels = pin.readStringArray(string.concat(k, ".labels"));
            assertEq(labels.length, f.length, id);
            for (uint256 i; i < f.length; ++i) assertEq(labels[i], f[i].label, id);
        }
        Pin memory q;
        q.slots = pin.readUintArray(string.concat(k, ".slots"));
        q.inner = pin.readUintArray(string.concat(k, ".inner"));
        q.at = pin.readUintArray(string.concat(k, ".bytes"));
        q.enc = new string[](f.length);
        q.ver = vm.keyExistsJson(pin, string.concat(k, ".keyVersions"))
            ? pin.readUintArray(string.concat(k, ".keyVersions")) : new uint256[](f.length);
        assertEq(q.ver.length, f.length, id);
        if (vm.keyExistsJson(pin, string.concat(k, ".encodings"))) {
            q.enc = pin.readStringArray(string.concat(k, ".encodings"));
            uint256[] memory widths = pin.readUintArray(string.concat(k, ".widths"));
            assertEq(q.enc.length, f.length, id);
            assertEq(widths.length, f.length, id);
            for (uint256 i; i < f.length; ++i) assertEq(widths[i], f[i].width, string.concat(id, " ", f[i].label));
        }
        for (uint256 i; i < f.length; ++i) _field(p, uint256(root), q, i, f[i], id);
    }

    struct Pin {
        uint256[] slots;
        uint256[] inner;
        uint256[] at;
        string[] enc;
        uint256[] ver; // group 3g: `keyVersions`, the version key hashed after the first key (0 = none)
    }

    function _field(address p, uint256 root, Pin memory q, uint256 i, F memory f, string memory id) internal view {
        string memory what = string.concat(id, " ", f.label);
        bool member = keccak256(bytes(q.enc[i])) == keccak256("mapping");
        uint256 s = root + q.slots[i];
        if (f.k1 != 0 || f.k2 != 0) s = uint256(keccak256(abi.encode(f.k1, s)));
        if (q.ver[i] != 0) s = uint256(keccak256(abi.encode(q.ver[i], s)));
        if (f.k2 != 0 && !member) s = uint256(keccak256(abi.encode(f.k2, s)));
        s += q.inner[i];
        if (member) s = uint256(keccak256(abi.encode(f.k2, s)));
        uint256 word = uint256(vm.load(p, bytes32(s)));
        if (keccak256(bytes(q.enc[i])) == keccak256("bytes")) return _bytesAt(p, s, word, f.value, what);
        uint256 mask = f.width == 32 ? type(uint256).max : (uint256(1) << (8 * f.width)) - 1;
        assertEq((word >> (8 * q.at[i])) & mask, f.value, what);
    }

    /// solc's `bytes` in storage: `len < 32` in one word (data, low byte `2·len`); else the word `2·len + 1` and the data
    /// from `keccak256(slot)`, the last word's tail ignored. The data is `NamespaceProbeIds.blob(len)`.
    function _bytesAt(address p, uint256 s, uint256 word, uint256 len, string memory what) internal view {
        bytes memory d = NamespaceProbeIds.blob(len);
        if (len < 32) {
            assertEq(word, uint256(bytes32(d)) | (2 * len), what);
            return;
        }
        assertEq(word, 2 * len + 1, what);
        uint256 data = uint256(keccak256(abi.encode(s)));
        for (uint256 j; 32 * j < len; ++j) {
            uint256 got = uint256(vm.load(p, bytes32(data + j)));
            uint256 want = uint256(keccak256(abi.encode(len, j)));
            uint256 tail = 32 * (j + 1) > len ? 8 * (32 * (j + 1) - len) : 0;
            assertEq(got >> tail, want >> tail, what);
        }
    }

    /// Thứ indexer thật sự đọc (ERC-7201 `scaas.underlying`): chân i ở `keccak256(i ‖ NS)`: `token`, `+ 1` `num ‖ den`,
    /// `+ 2` `reserve`; `legCount` là byte thấp của `NS + 3`.
    function test_reserveSlotIsWhereIndexersReadIt() public {
        MockERC20 u = new MockERC20("U", "U", 6);
        WrappedToken t = _single(address(u), 6, 3, 7, _fixedRate());
        u.mint(address(this), 1_000);
        u.approve(address(t), 1_000);
        t.wrap(1_000);
        bytes32 NS = 0x38d6f7edefffa65376a58a6aced8a2c86698d3a0b5d15a785f69ed89d0cd1000;
        bytes32 leg0 = keccak256(abi.encode(uint256(0), NS));
        assertEq(uint256(vm.load(address(t), bytes32(uint256(leg0) + 2))), 1_000);
        uint256 b = uint256(vm.load(address(t), bytes32(uint256(leg0) + 1)));
        assertEq(b & type(uint96).max, 3);
        assertEq(b >> 96, 7);
        assertEq(address(uint160(uint256(vm.load(address(t), leg0)))), address(u));
        assertEq(uint256(vm.load(address(t), bytes32(uint256(NS) + 3))) & 0xff, 1); // legCount
        assertEq(vm.load(address(t), bytes32(uint256(5))), bytes32(0)); // the linear layout ends at slot 4
    }
}
