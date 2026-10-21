// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {
    UASafeVerifier,
    SchnorrBn254Verifier,
    SchnorrBls12381Verifier,
    BlsMinSigBls12381Verifier,
    BlsMinSigBn254Verifier
} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {Ed25519Verifier} from "../../src/ua/verifiers/Ed25519Verifier.sol";
import {UARegistryBase, MockWallet} from "./UARegistryBase.sol";

/// T-GAS (accounts.md §1.15/§1.16) for the UA-2a registry: the `msig` per-member overhead behind `MSIG_MEMBER_GAS`,
/// the structure bound, the native paths, and the gas a `register` of the heaviest kind needs. Per-kind verifier
/// gas with the real verifiers: `UARegistryVectors.t.sol` (`-vv`). Numbers are logged with `-vv`.
/// Accepts every signature: real-size signature blobs without a real verifier.
contract AcceptAll {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }

    function verifyPop(bytes calldata, bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }
}

/// Burns all the gas it is given (down to what its return needs), then accepts: the worst case of every capped call —
/// verifier, PoP and, behind a `SmartKeyAccount` clone, ERC-1271.
contract BurnAll {
    function verify(bytes calldata, bytes32, bytes calldata) external view returns (bool) {
        _burn();
        return true;
    }

    function verifyPop(bytes calldata, bytes32, bytes calldata) external view returns (bool) {
        _burn();
        return true;
    }

    function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {
        _burn();
        return 0x1626ba7e;
    }

    function _burn() private view {
        while (gasleft() > 1_000) {}
    }
}

/// Calls `target` giving its frame exactly `gas`.
contract GasProbe {
    function probe(address target, bytes calldata data, uint256 gas) external returns (bool ok) {
        (ok,) = target.call{gas: gas}(data);
    }
}

contract UAGasTest is UARegistryBase {
    uint256 internal constant SMART_KEY_1271_GAS = 400_000;
    uint256 internal constant MSIG_MEMBER_GAS = 35_000; // UARegistry.MSIG_MEMBER_GAS

    bytes internal _big;
    address internal _impl;

    /// Per-member gas of `msig` beyond the member's own verifier, measured in the worst state: every touched account and
    /// storage slot cold (`vm.cool`), signatures of the largest real size in signatures.json, derived members verified
    /// here, derived members handed to gen 1, and native members as EOA, EIP-7702 designator and ERC-1271 wallet. The
    /// verifier/1271 execution itself (the cap covers it) is ~0 for the accept-all verifier, a few k for the wallet
    /// (which over-counts). The `MSIG_MEMBER_GAS` NatSpec cites the worst plus what the caller must hold for the largest
    /// cap; the bound's soundness is `test_T_GAS_msigAtBudget` (end to end), which logs these first.
    function _logMemberOverhead() internal {
        bytes memory big = _bigSig();
        address[] memory v = new address[](8); // one verifier account per kind: each member's is cold
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](8);
        for (uint256 i; i < 8; ++i) {
            v[i] = address(new AcceptAll());
            c[i] = UARegistry.KindConfig(KINDS[i], v[i], _cap(KINDS[i]));
        }
        UARegistry home = _deploy(address(0x5ca1), chainUidA, address(0), false, BUDGET, address(0), true, c);
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry gen2 = _deploy(address(0x5ca2), chainUidA, address(home), false, BUDGET, address(0), true, none);
        uint256 local = _derivedOverhead(home, home, big, v, 1);
        uint256 handed = _derivedOverhead(gen2, home, big, v, 2); // other weights: other ids; gen 2 reads its record, then gen 1's
        uint256 eoa = _nativeOverhead(0);
        uint256 designator = _nativeOverhead(1);
        uint256 wallet = _nativeOverhead(2);
        emit log_named_uint("sig bytes (largest real)", big.length);
        emit log_named_uint("msig per derived member (cold)", local);
        emit log_named_uint("msig per gen-1 member via gen 2 (cold)", handed);
        emit log_named_uint("msig per native EOA member (cold)", eoa);
        emit log_named_uint("msig per native 7702-designator member (cold)", designator);
        emit log_named_uint("msig per native ERC-1271 wallet member (cold, incl. wallet exec)", wallet);
        uint256 worst = local > handed ? local : handed;
        worst = worst > eoa ? worst : eoa;
        worst = worst > designator ? worst : designator;
        worst = worst > wallet ? worst : wallet;
        // + what the caller holds for the largest cap (400 k / 63) + the call margin
        // `vm.cool` does not make accounts cold in a single-transaction test: unless run with `--isolate` (every call its
        // own transaction, the true cold measure), a member's verifier/wallet account is warm here, so add its cold
        // surcharge (2,600 - 100) per member. Probe: a first call to a fresh verifier costs > 2,000 only when cold.
        uint256 g = gasleft();
        AcceptAll(v[0]).verify("", 0, "");
        uint256 surcharge = g - gasleft() > 2_000 ? 0 : 2_500;
        emit log_named_uint("account cold surcharge added (0 under --isolate)", surcharge);
        uint256 total = worst + surcharge + SMART_KEY_1271_GAS / 63 + 5_000;
        emit log_named_uint("msig member overhead + largest local hold", total);
    }

    /// Register step 4 end to end: an msig registered exactly at `verifyBudget` (one gas less: `UAKeyData`) authorizes
    /// with `verifyBudget` gas for the `requireAuthorized` frame, every capped call burning its whole cap and every
    /// signature of the largest real size. c = 16 (8 derived + 8 native `SmartKeyAccount` clones) and c = 1 (a 400 k
    /// derived member; a native clone), in gen 1 and in gen 2 (a derived member handed to gen 1 counts with gen 1's
    /// own hold, `cap / 63 + 5 k`). Fixed call overhead: none inside the frame; on top of it the caller pays only its
    /// transaction's intrinsic gas and the registry account access. Run it with `--isolate` too: every probe is then a
    /// transaction of its own, all accounts and slots cold (the binding case).
    function test_T_GAS_msigAtBudget() public {
        _logMemberOverhead();
        _big = _bigSig();
        BurnAll impl = new BurnAll();
        _impl = address(impl);
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](8);
        for (uint256 i; i < 8; ++i) {
            c[i] = UARegistry.KindConfig(KINDS[i], address(new BurnAll()), _cap(KINDS[i]));
        }
        UARegistry home = _deploy(address(0x5ce0), chainUidA, address(0), false, BUDGET, address(impl), true, c);
        Member[] memory all = new Member[](16);
        for (uint256 i; i < 8; ++i) {
            all[i] = Member(KINDS[i], home.register(KINDS[i], _key(KINDS[i]), "", "", ""), 1);
        }
        bytes memory clone = abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3");
        for (uint256 i; i < 8; ++i) {
            address a = address(uint160(0x5cf00 + i));
            vm.etch(a, clone);
            all[8 + i] = Member(UAKinds.EVM_EOA, _pad(a), 1);
        }
        Member[] memory p256 = new Member[](1);
        p256[0] = all[1];
        Member[] memory native = new Member[](1);
        native[0] = all[8];
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        for (uint256 gen = 1; gen <= 2; ++gen) {
            address pred = gen == 1 ? address(0) : address(home);
            UARegistry.KindConfig[] memory cfg = gen == 1 ? c : none;
            _atBudget(gen, 0, pred, cfg, _msigKey(16, all));
            _atBudget(gen, 1, pred, cfg, _msigKey(1, p256));
            _atBudget(gen, 2, pred, cfg, _msigKey(1, native));
        }
    }

    /// The bound of msig key data `d` whose threshold needs every member (weights 1, threshold = count) or whose only
    /// member is the threshold: Σ (cap + MSIG_MEMBER_GAS), + gen 1's hold for a derived member handed to gen 1, + the
    /// registry's own hold (held - 400 k) / 63 for the largest held cap above 400 k (a handed member holds in gen 2 too).
    function _boundOf(bytes memory d, bool handed) internal pure returns (uint256 b) {
        uint256 count = uint16(bytes2(abi.encodePacked(d[2], d[3])));
        uint256 held;
        for (uint256 j; j < count; ++j) {
            uint16 kind = uint16(bytes2(abi.encodePacked(d[4 + 36 * j], d[5 + 36 * j])));
            uint256 cap = kind < 0x0100 ? SMART_KEY_1271_GAS : _cap(kind);
            uint256 e = cap + (handed && kind >= 0x0100 ? cap / 63 + 5_000 : 0);
            b += e + MSIG_MEMBER_GAS;
            if (e > held) held = e;
        }
        if (held > SMART_KEY_1271_GAS) b += (held - SMART_KEY_1271_GAS) / 63;
    }

    function _atBudget(uint256 gen, uint256 n, address pred, UARegistry.KindConfig[] memory cfg, bytes memory d)
        internal
    {
        uint256 bound = _boundOf(d, gen == 2);
        (UARegistry r, bytes32 ua) = _registerAt(address(uint160(0x5ce00 + 16 * gen + 2 * n)), pred, cfg, d, bound);
        uint256 least = _leastGas(
            address(r), abi.encodeCall(r.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, _burnAuth(d))), bound
        );
        emit log_named_uint(string.concat("gen ", vm.toString(gen), " case ", vm.toString(n), " bound"), bound);
        emit log_named_uint("  least requireAuthorized frame gas", least);
    }

    /// One gas below the bound is refused; at the bound `d` registers. A gen-1 registry first registers the members.
    function _registerAt(address at, address pred, UARegistry.KindConfig[] memory cfg, bytes memory d, uint256 bound)
        internal
        returns (UARegistry r, bytes32 ua)
    {
        UARegistry tight = _deploy(at, chainUidA, pred, false, uint64(bound - 1), _impl, true, cfg);
        r = _deploy(address(uint160(at) + 1), chainUidA, pred, false, uint64(bound), _impl, true, cfg);
        if (pred == address(0)) {
            _registerMembers(tight, d); // gen 2 reads gen 1's (`home`'s) records
            _registerMembers(r, d);
        }
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        tight.register(UAKinds.MSIG, d, "", "", "");
        ua = r.register(UAKinds.MSIG, d, "", "", "");
    }

    /// Asserts `call` succeeds with `bound` gas for the callee frame; returns the least frame gas that succeeds. Each
    /// probe goes through `GasProbe`, so the frame gets exactly that gas (under `--isolate` each probe is a transaction
    /// of its own, all accounts and slots cold; its calldata is paid by that transaction, not by the frame).
    /// F185: EIP-8037 state gas of `register`'s new storage slots (the record), charged inside the call's gas: `gas used`
    /// of `register` 312,557 -> 658,937 (ed25519) and 346,533 -> 692,913 (bls-bn254-minsig) from Osaka to Amsterdam, +346 k.
    uint256 internal constant REGISTER_STATE_GAS = 350_000;

    function _registerLimit() internal view returns (uint256) {
        return _cap(0x0102) + 100_000 + REGISTER_STATE_GAS;
    }

    function _leastGas(address r, bytes memory call, uint256 bound) internal returns (uint256 hi) {
        GasProbe p = new GasProbe();
        assertTrue(p.probe(r, call, bound), "authorizes with verifyBudget");
        uint256 lo;
        for (hi = bound; hi - lo > 1;) {
            uint256 mid = (lo + hi) / 2;
            if (p.probe(r, call, mid)) hi = mid;
            else lo = mid;
        }
    }

    /// Registers `d`'s derived members in `r` (BurnAll PoPs accept anything).
    function _registerMembers(UARegistry r, bytes memory d) internal {
        uint256 count = uint16(bytes2(abi.encodePacked(d[2], d[3])));
        for (uint256 j; j < count; ++j) {
            uint16 kind = uint16(bytes2(abi.encodePacked(d[4 + 36 * j], d[5 + 36 * j])));
            if (kind >= 0x0100) r.register(kind, _key(kind), "", "", "");
        }
    }

    /// Every member signs, in index order: derived with its key data, natives without; `_big` as every signature.
    function _burnAuth(bytes memory d) internal view returns (bytes memory) {
        uint16 count = uint16(bytes2(abi.encodePacked(d[2], d[3])));
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](count);
        for (uint16 j; j < count; ++j) {
            uint16 kind = uint16(bytes2(abi.encodePacked(d[4 + 36 * uint256(j)], d[5 + 36 * uint256(j)])));
            s[j] = UARegistry.MemberSig(j, kind < 0x0100 ? bytes("") : _key(kind), _big);
        }
        return _msigAuth(d, s);
    }

    /// The largest `sig` in signatures.json (derived rows and negatives), as zero-padded-length stand-in bytes.
    function _bigSig() internal view returns (bytes memory) {
        string memory sj = vm.readFile("../vectors/ua/signatures.json");
        uint256 max;
        uint256 rows;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            for (uint256 k; k < 2; ++k) {
                string memory arr = k == 0 ? "sigs" : "negatives";
                for (
                    uint256 s;
                    vm.keyExistsJson(
                        sj, string.concat(".derived[", vm.toString(i), "].", arr, "[", vm.toString(s), "]")
                    );
                    ++s
                ) {
                    uint256 n = vm.parseJsonBytes(
                        sj, string.concat(".derived[", vm.toString(i), "].", arr, "[", vm.toString(s), "].sig")
                    ).length;
                    if (n > max) max = n;
                    ++rows;
                }
            }
        }
        assertEq(rows, 22 + 91, "signature rows scanned");
        assertGe(max, 256, "largest real signature");
        return new bytes(max);
    }

    function _cool(address[] memory a) internal {
        for (uint256 i; i < a.length; ++i) {
            vm.cool(a[i]);
        }
    }

    /// msig over the 8 single-key kinds (weights 1); (gas with 8 member sigs - gas with 1) / 7, all cold.
    function _derivedOverhead(UARegistry r, UARegistry home, bytes memory big, address[] memory verifiers, uint16 w)
        internal
        returns (uint256)
    {
        Member[] memory m = new Member[](8);
        for (uint256 i; i < 8; ++i) {
            bytes memory k = _key(KINDS[i]);
            bytes32 id = UAKinds.uaOf(KINDS[i], k);
            if (!home.isRegistered(id)) home.register(KINDS[i], k, big, "", "");
            m[i] = Member(KINDS[i], id, w);
        }
        uint256[2] memory used;
        uint16[2] memory t = [uint16(1), uint16(8)];
        for (uint256 x; x < 2; ++x) {
            bytes memory d = _msigKey(t[x] * w, m);
            bytes32 ua = r.register(UAKinds.MSIG, d, "", "", "");
            UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](t[x]);
            for (uint16 j; j < t[x]; ++j) {
                (, bytes memory k) = _memberAt(d, j);
                s[j] = UARegistry.MemberSig(j, k, big);
            }
            bytes memory auth = _msigAuth(d, s);
            vm.cool(address(r));
            vm.cool(address(home));
            _cool(verifiers);
            uint256 g = gasleft();
            r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, auth);
            used[x] = g - gasleft();
        }
        return (used[1] - used[0]) / 7;
    }

    function _memberAt(bytes memory d, uint16 j) internal view returns (uint16 kind, bytes memory k) {
        uint256 o = 4 + 36 * uint256(j);
        kind = uint16(bytes2(abi.encodePacked(d[o], d[o + 1])));
        k = _key(kind);
    }

    /// msig over 16 native members of one flavor (0 EOA, 1 EIP-7702 designator, 2 ERC-1271 wallet); (gas with 16 - gas
    /// with 1) / 15, all cold.
    function _nativeOverhead(uint8 flavor) internal returns (uint256) {
        UARegistry r = _deploy(
            address(uint160(0x5cd0 + flavor)),
            chainUidA,
            address(0),
            false,
            BUDGET,
            address(0),
            true,
            _cfgs(address(mock))
        );
        Member[] memory m = new Member[](16);
        bytes32[] memory ids = new bytes32[](16);
        address[] memory accounts = new address[](16);
        for (uint256 i; i < 16; ++i) {
            address a = vm.addr(1000 + i);
            if (flavor == 1) {
                vm.etch(a, abi.encodePacked(hex"ef0100", address(0xdE1e6A7e)));
            } else if (flavor == 2) {
                a = address(new MockWallet(a, 0, 0, address(0)));
            }
            accounts[i] = a;
            ids[i] = _pad(a);
            m[i] = Member(UAKinds.EVM_EOA, ids[i], 1);
        }
        uint256[2] memory used;
        uint16[2] memory t = [uint16(1), uint16(16)];
        for (uint256 x; x < 2; ++x) {
            bytes memory d = _msigKey(t[x], m);
            bytes32 ua = r.register(UAKinds.MSIG, d, "", "", "");
            bytes memory auth = _nativeAuth(r, d, ua, t[x], ids);
            vm.cool(address(r));
            _cool(accounts);
            uint256 g = gasleft();
            r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, auth);
            used[x] = g - gasleft();
        }
        return (used[1] - used[0]) / 15;
    }

    function _nativeAuth(UARegistry r, bytes memory d, bytes32 ua, uint16 n, bytes32[] memory ids)
        internal
        view
        returns (bytes memory)
    {
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](n);
        for (uint16 j; j < n; ++j) {
            bytes32 id;
            assembly ("memory-safe") {
                id := mload(add(add(d, 38), mul(36, j)))
            }
            s[j] = UARegistry.MemberSig(j, "", _ecdsa(_pkOf(id, ids), r.uaAuthDigest(id, UAKinds.PURPOSE_MEMBER, md)));
        }
        return _msigAuth(d, s);
    }

    function _pkOf(bytes32 id, bytes32[] memory ids) internal pure returns (uint256) {
        for (uint256 i; i < ids.length; ++i) {
            if (ids[i] == id) return 1000 + i;
        }
        revert("pk");
    }

    /// Register step 4: Σ of the c largest caps + c × MSIG_MEMBER_GAS ≤ verifyBudget (here 1,145,000 + 105,000).
    function test_T_GAS_structureOverBudgetRefused() public {
        Member[] memory m = new Member[](3);
        uint16[3] memory kinds = [uint16(0x0100), uint16(0x0101), uint16(0x0107)];
        UARegistry tight =
            _deploy(address(0x5cc1), chainUidA, address(0), false, 1_200_000, address(0), true, _cfgs(address(mock)));
        UARegistry roomy =
            _deploy(address(0x5cc2), chainUidA, address(0), false, 1_250_000, address(0), true, _cfgs(address(mock)));
        for (uint256 i; i < 3; ++i) {
            bytes memory k = _key(kinds[i]);
            m[i] = Member(kinds[i], _register(tight, kinds[i], k), 1);
            _register(roomy, kinds[i], k);
        }
        bytes memory d = _msigKey(3, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        tight.register(UAKinds.MSIG, d, "", "", "");
        roomy.register(UAKinds.MSIG, d, "", "", ""); // exactly at the budget
        // threshold 2 of the same three: c = 2, the two largest caps
        d = _msigKey(2, m);
        tight.register(UAKinds.MSIG, d, "", "", "");
        // 16 native members on a chain with SmartKeyAccount clones: 16 × 435 k = 6.96 M ≤ 12 M
        UARegistry ska = _deploy(
            address(0x5cc3),
            chainUidA,
            address(0),
            false,
            BUDGET,
            address(new MockWallet(address(0), 0, 0, address(0))),
            true,
            _cfgs(address(mock))
        );
        Member[] memory n = new Member[](16);
        for (uint256 i; i < 16; ++i) {
            n[i] = Member(UAKinds.EVM_EOA, _pad(vm.addr(1000 + i)), 1);
        }
        uint256 g = gasleft();
        ska.register(UAKinds.MSIG, _msigKey(16, n), "", "", "");
        emit log_named_uint("register msig 16 natives", g - gasleft());
        UARegistry small = _deploy(
            address(0x5cc4),
            chainUidA,
            address(0),
            false,
            6_000_000,
            address(new MockWallet(address(0), 0, 0, address(0))),
            true,
            _cfgs(address(mock))
        );
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        small.register(UAKinds.MSIG, _msigKey(16, n), "", "", "");
    }

    /// Caps of the gen-1 default config: ≤ 50 % of `verifyBudget` (public-chain rule, CTR-UA-23); each pairing kind's
    /// cap ≥ its verifier's floor `CHECK_GAS + CHECK_GAS / 63 + 5 k` (below it every call reverts `UAVerifyGas`); and
    /// the largest msig worst case — 16 members of the largest cap, handed to gen 1 — fits `verifyBudget`.
    function test_T_GAS_capsWithinBudget() public {
        UASafeVerifier[4] memory v = [
            UASafeVerifier(new SchnorrBn254Verifier()),
            new SchnorrBls12381Verifier(),
            new BlsMinSigBls12381Verifier(),
            new BlsMinSigBn254Verifier()
        ];
        uint256 maxCap = SMART_KEY_1271_GAS;
        for (uint256 i; i < KINDS.length; ++i) {
            uint256 cap = reg.verifyCap(KINDS[i]);
            assertEq(cap, _cap(KINDS[i]));
            assertLe(cap, BUDGET / 2, "cap over 50 % of the budget");
            if (KINDS[i] >= 0x0104) {
                uint256 g = v[KINDS[i] - 0x0104].CHECK_GAS();
                assertGe(cap, g + g / 63 + 5_000, "cap below the verifier's CHECK_GAS floor");
            }
            if (cap > maxCap) maxCap = cap;
        }
        uint256 worst = 16 * (maxCap + maxCap / 63 + 5_000 + MSIG_MEMBER_GAS);
        emit log_named_uint("msig worst case (16 x largest cap, handed)", worst);
        assertLe(worst, BUDGET, "msig worst case over the budget");
    }

    /// Native paths: ECDSA, ERC-1271 (an ECDSA wallet), the 7702 base key.
    function test_T_GAS_native() public {
        uint256 pk = 0xA11CE;
        bytes32 ua = _pad(vm.addr(pk));
        bytes memory sig = _nativeSig(reg, pk, UAKinds.PURPOSE_METATX, DIGEST);
        uint256 g = gasleft();
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, sig);
        g -= gasleft();
        emit log_named_uint("requireAuthorized native ECDSA (registry warm)", g);
        // §1.15: ECDSA ~3.5 k + the EIP-712 hash ~1 k + the registry's ~5 k, + a cold account (`--isolate`); F185: the
        // bound was 12,100; Foundry 1.8.5 isolates by default (13,413 on Osaka) and Amsterdam's EIP-8038 raises the cold
        // account and slot reads again (14,413), so + 2,400 -> 14,500
        assertLe(g, 3_500 + 1_000 + 5_000 + 2_600 + 2_400, "native ECDSA over the documented cost");
        MockWallet w = new MockWallet(vm.addr(pk), 0, 0, address(0));
        bytes32 wua = _pad(address(w));
        sig = _ecdsa(pk, reg.uaAuthDigest(wua, UAKinds.PURPOSE_METATX, DIGEST));
        g = gasleft();
        reg.requireAuthorized(wua, UAKinds.PURPOSE_METATX, DIGEST, sig);
        g -= gasleft();
        emit log_named_uint("requireAuthorized native ERC-1271 (ECDSA wallet)", g);
        assertLe(g, 50_000, "native ERC-1271 over the 50 k cap");
    }

    /// Addendum (b): `register(bls-bn254-minsig)` runs the G2 pairing check of `UAKinds` (needs ≥ 165,508 gas left at
    /// that point) and then the PoP under the 345 k cap (needs ≥ 355,476 left): the smallest call gas that registers.
    function test_T_GAS_registerHeadroomBlsBn254() public {
        string memory sj = vm.readFile("../vectors/ua/signatures.json");
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0107, address(new BlsMinSigBn254Verifier()), 345_000);
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), false, c);
        bytes memory call = abi.encodeCall(
            r.register,
            (0x0107, vm.parseJsonBytes(sj, ".derived[6].keyData"), vm.parseJsonBytes(sj, ".derived[6].pop.sig"), "", "")
        );
        uint256 lo = 100_000;
        uint256 hi = 1_000_000;
        while (hi - lo > 500) {
            uint256 mid = (lo + hi) / 2;
            uint256 snap = vm.snapshotState();
            (bool ok,) = address(r).call{gas: mid}(call);
            vm.revertToState(snap);
            if (ok) hi = mid;
            else lo = mid;
        }
        emit log_named_uint("register bls-bn254-minsig: least call gas", hi);
        uint256 g = gasleft();
        (bool ok2,) = address(r).call(call);
        assertTrue(ok2);
        emit log_named_uint("register bls-bn254-minsig: gas used", g - gasleft());
        assertLt(hi, 500_000 + REGISTER_STATE_GAS); // F185: was 500,000 (452,440 on Osaka); 673,046 under Amsterdam
    }

    /// UA-2b `ed25519`: the least frame gas of the verifier on its most expensive accepted input (every Straus window
    /// adds, decompression takes the √−1 branch; the vector of `Ed25519Verifier.t.sol`) fits the cap with ~23 %
    /// margin; `register` (PoP under the cap) and `requireAuthorized` on the signatures.json row.
    function test_T_GAS_ed25519() public {
        Ed25519Verifier ev = new Ed25519Verifier();
        bytes memory worst = abi.encodeCall(
            ev.verify,
            (
                hex"e3d99115142bc70561544c8d38361c63e65f9edd1b9f5d9a0654d4b397563bb0",
                0xd31914fd312462c05580de6faa34902e29bc9bea23cf9bdbe9aa7782b474ee38,
                hex"6df5f8952c2953fd66ed2e2fca68b3e5ce989a965408052c6a330edfab577a5e55b2456ed2289bb6971134389c1ff3d562addadb3749185ca834ebb98956490c"
            )
        );
        uint256 cap = _cap(0x0102);
        uint256 least = _leastGas(address(ev), worst, cap);
        emit log_named_uint("ed25519 verify worst: least frame gas", least);
        emit log_named_uint("ed25519 cap", cap);
        assertLe(least * 6 / 5, cap + 5_000, "cap >= 1.2 x measured worst");
        assertLe(cap, BUDGET / 2, "cap over 50 % of the budget");

        string memory sj = vm.readFile("../vectors/ua/signatures.json");
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0102, address(ev), uint64(cap));
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), false, c);
        bytes memory k = vm.parseJsonBytes(sj, ".derived[7].keyData");
        bytes memory call = abi.encodeCall(r.register, (0x0102, k, vm.parseJsonBytes(sj, ".derived[7].pop.sig"), "", ""));
        uint256 lo = 100_000;
        uint256 hi = 1_000_000;
        while (hi - lo > 500) {
            uint256 mid = (lo + hi) / 2;
            uint256 snap = vm.snapshotState();
            (bool ok,) = address(r).call{gas: mid}(call);
            vm.revertToState(snap);
            if (ok) hi = mid;
            else lo = mid;
        }
        emit log_named_uint("register ed25519: least call gas", hi);
        uint256 g = gasleft();
        (bool ok2,) = address(r).call(call);
        assertTrue(ok2);
        emit log_named_uint("register ed25519: gas used", g - gasleft());
        bytes32 ua = vm.parseJsonBytes32(sj, ".derived[7].ua");
        bytes memory auth = abi.encode(k, vm.parseJsonBytes(sj, ".derived[7].sigs[0].sig"));
        bytes32 dg = vm.parseJsonBytes32(sj, ".derived[7].sigs[0].digest");
        g = gasleft();
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, dg, auth);
        emit log_named_uint("requireAuthorized ed25519", g - gasleft());
        assertLt(hi, _registerLimit()); // F185: was cap + 100,000 (288,524 on Osaka); 640,966 under Amsterdam
    }
}
