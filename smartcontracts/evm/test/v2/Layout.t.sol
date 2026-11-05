// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {stdJson} from "forge-std/StdJson.sol";
import {V2Fixture} from "./helpers/V2Fixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {TokenStore} from "../../src/metatx/TokenStore.sol";
import {WrappedLib} from "../../src/metatx/WrappedLib.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {UAMetaTxBase} from "../../src/metatx/UAMetaTxBase.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {RegulatedLib} from "../../src/regulated/RegulatedLib.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";

library NamespaceProbeIds {
    bytes32 internal constant U = 0xcafe00000000000000000000000000000000000000000000000000000000a11a;
    bytes32 internal constant V = 0xbeef00000000000000000000000000000000000000000000000000000000b22b;
}

/// Writes every field of the five ERC-7201 namespaces through the source's own accessor, so the test reads where the
/// compiler put each one (spec §1.4, §10.4).
contract NamespaceProbe is UAMetaTxBase {
    address internal constant A = address(0xA11);
    address internal constant B = address(0xB22);
    /// Two derived UA ids, top 96 bits set, so a field that kept 20 bytes would not hold them.
    bytes32 internal constant U = NamespaceProbeIds.U;
    bytes32 internal constant V = NamespaceProbeIds.V;

    constructor() UAMetaTxBase("P", bytes32(uint256(1)), address(0), address(0), false) {}

    function poke() external {
        TokenStore.TokenStorage storage t = TokenStore.$();
        (t.creator, t.version, t.kind, t.decimals, t.initialized) = (A, 0x71, 0x72, 0x73, true);
        (t.name, t.symbol) = ("N", "S");
        GovernanceLib.GovernanceStorage storage g = GovernanceLib.$();
        // every governance identity a UA id (CTR-GOV-01 Change): the owner words and the mapping keys are `bytes32`
        (g.features, g.lockedFeatures, g.owner) = (0x81, 0x82, U);
        (g.grantDelay, g.ownerGeneration) = (0x83, 0x84);
        (g.pendingOwner, g.lastProposedAt, g.rescueTo) = (V, 0x85, B);
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
        _ua().balance[bytes32(uint256(0xa1))] = 0xa2;
        _ua().cancelUsed[bytes32(uint256(0xa3))] = true;
        MtxPipelineLib._mtxStorage().nonce[bytes32(uint256(0xb1))][2] = 0xb2;
        // plan T28: `scaas.regulated` (regulated-kinds spec §2.3)
        RegulatedLib.RegulatedStorage storage r = RegulatedLib.$();
        (r.complianceRegistry, r.controls, r.pausedUntil) = (B, 0xc1, 0xc2);
        (r.requiredFlags, r.deniedFlags, r.pauseCooldownUntil, r.termsHash) = (0xc3, 0xc4, 0xc5, bytes32(uint256(0xc6)));
        r.freezes[U] = IRegulatedToken.FreezeState(0xc7, 0xc8, 0xc9, true, V);
        r.orders[U] = IRegulatedToken.OrderRecord(V, U, 0xca, true, 0xcb, 0xcc);
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
        f[2] = F("owner", 0, 0, u, 32);
        f[3] = F("pendingOwner", 0, 0, v, 32);
        f[4] = F("grantDelay", 0, 0, 0x83, 8);
        f[5] = F("ownerGeneration", 0, 0, 0x84, 4);
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
        _ns(address(p), "underlying", "scaas.underlying", f);
        f = new F[](2);
        f[0] = F("balance[0xa1]", 0xa1, 0, 0xa2, 32);
        f[1] = F("cancelUsed[0xa3]", 0xa3, 0, 1, 1);
        _ns(address(p), "uaLedger", "scaas.ua.ledger", f);
        f = new F[](1);
        f[0] = F("nonce[0xb1][2]", 0xb1, 2, 0xb2, 32);
        _ns(address(p), "metatx", "scaas.metatx", f);
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
        _ns(address(p), "regulated", "scaas.regulated", f);
    }

    function _more(F[] memory f, F memory x) internal pure returns (F[] memory g) {
        g = new F[](f.length + 1);
        for (uint256 i; i < f.length; ++i) g[i] = f[i];
        g[f.length] = x;
    }

    /// The root, then each field at `keccak(k2, keccak(k1, root + slot)) + inner`, byte `bytes` (no key: `root + slot`).
    function _ns(address p, string memory key, string memory id, F[] memory f) internal view {
        string memory pin = vm.readFile("./test/v2/layout/namespaces.json");
        string memory k = string.concat(".", key);
        assertEq(pin.readString(string.concat(k, ".id")), id, key);
        bytes32 root = keccak256(abi.encode(uint256(keccak256(bytes(id))) - 1)) & ~bytes32(uint256(0xff));
        assertEq(pin.readBytes32(string.concat(k, ".root")), root, id);
        string[] memory labels = pin.readStringArray(string.concat(k, ".labels"));
        uint256[] memory slots = pin.readUintArray(string.concat(k, ".slots"));
        uint256[] memory inner = pin.readUintArray(string.concat(k, ".inner"));
        uint256[] memory at = pin.readUintArray(string.concat(k, ".bytes"));
        assertEq(labels.length, f.length, id);
        for (uint256 i; i < f.length; ++i) {
            assertEq(labels[i], f[i].label, id);
            uint256 s = uint256(root) + slots[i];
            if (f[i].k1 != 0 || f[i].k2 != 0) s = uint256(keccak256(abi.encode(f[i].k1, s)));
            if (f[i].k2 != 0) s = uint256(keccak256(abi.encode(f[i].k2, s)));
            uint256 word = uint256(vm.load(p, bytes32(s + inner[i])));
            uint256 mask = f[i].width == 32 ? type(uint256).max : (uint256(1) << (8 * f[i].width)) - 1;
            assertEq((word >> (8 * at[i])) & mask, f[i].value, string.concat(id, " ", f[i].label));
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
