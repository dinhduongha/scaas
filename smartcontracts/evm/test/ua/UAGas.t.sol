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
import {UACall} from "./UACall.sol";
import {Test} from "forge-std/Test.sol";
import {Vm, VmSafe} from "forge-std/Vm.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";
import {BlsMultiBls12381Verifier} from "../../src/ua/verifiers/BlsMultiBls12381Verifier.sol";
import {BlsMultiKit} from "./BlsMultiKit.sol";
import {UARegistryCoreLib} from "../../src/ua/UARegistryCoreLib.sol";
import {UARegistryAuxLib} from "../../src/ua/UARegistryAuxLib.sol";
import {UARegistryRegLib} from "../../src/ua/UARegistryRegLib.sol";

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
    uint256 internal constant MSIG_MEMBER_GAS = 45_000; // UARegistry.MSIG_MEMBER_GAS
    uint256 internal constant MSIG_ACCEPTED_GAS = 3_500; // UARegistryCoreLib.MSIG_ACCEPTED_GAS: once per authorization (3ze: was 2,500)

    bytes internal _big;
    bytes internal _memberPop; // `_derivedOverhead`'s registration pop when set (I1: a padded pop)
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
            c[i] = UARegistry.KindConfig(KINDS[i], v[i], _cap(KINDS[i]), false, 0);
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
        _allAtBudget();
    }

    /// The structures of `test_T_GAS_msigAtBudget`, the derived members registered with `_memberPop` as their pop.
    function _allAtBudget() internal {
        _big = _bigSig();
        BurnAll impl = new BurnAll();
        _impl = address(impl);
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](8);
        for (uint256 i; i < 8; ++i) {
            c[i] = UARegistry.KindConfig(KINDS[i], address(new BurnAll()), _cap(KINDS[i]), false, 0);
        }
        UARegistry home = _deploy(address(0x5ce0), chainUidA, address(0), false, BUDGET, address(impl), true, c);
        Member[] memory all = new Member[](16);
        for (uint256 i; i < 8; ++i) {
            all[i] = Member(KINDS[i], UACall.register(home, KINDS[i], _key(KINDS[i]), _none(), _memberPop, ""), 1);
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

    /// msig-pophash I1: a member's check reads only its key from its record, never its registration `pop`, so a member
    /// registered with a padded `pop` (a `webauthn-p256` pop has no length limit; here 40,000 B: two blob chunks) costs
    /// what a canonical one costs: the per-member overhead is the same, and `test_T_GAS_msigAtBudget`'s structures,
    /// every member registered with the padded pop, still authorize within the bound (gen 1 and gen 2).
    function test_T_GAS_memberPopSizeFree() public {
        bytes memory big = _bigSig();
        address[] memory v = new address[](8);
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](8);
        for (uint256 i; i < 8; ++i) {
            v[i] = address(new AcceptAll());
            c[i] = UARegistry.KindConfig(KINDS[i], v[i], _cap(KINDS[i]), false, 0);
        }
        UARegistry small = _deploy(address(0x5cb1), chainUidA, address(0), false, BUDGET, address(0), true, c);
        UARegistry padded = _deploy(address(0x5cb2), chainUidA, address(0), false, BUDGET, address(0), true, c);
        uint256 s = _derivedOverhead(small, small, big, v, 1);
        _memberPop = new bytes(40_000);
        uint256 p = _derivedOverhead(padded, padded, big, v, 1);
        emit log_named_uint("msig per derived member, canonical pop (cold)", s);
        emit log_named_uint("msig per derived member, 40,000 B pop (cold)", p);
        assertEq(p, s, "the member's pop size does not enter its check");
        _allAtBudget(); // every member registered with the 40,000 B pop
        delete _memberPop;
    }

    /// Review2 C4-2: `MSIG_MEMBER_GAS` was calibrated with signatures <= 512 B; PQ member signatures are copied three
    /// times into memory (quadratic). 8 `slhdsa128s` (cap 1.4 M, 7,856 B signatures) + 1 native `SmartKeyAccount`
    /// clone, threshold 9, registered exactly at `verifyBudget`-tight bound (one gas less: `UAKeyData`), authorizes with
    /// the bound as the frame's gas, every capped call burning its whole cap.
    function test_T_GAS_msigPqAtBudget() public {
        BurnAll impl = new BurnAll();
        _impl = address(impl);
        _big = new bytes(7_856);
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0133, address(new BurnAll()), 1_400_000, false, 0);
        address clone = address(0x5cf40);
        vm.etch(clone, abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"));
        // bound: 8 x (cap + member gas) + the clone (400 k + member gas) + the registry's own hold (1.4 M - 400 k) / 63
        uint256 bound = 8 * (1_400_000 + MSIG_MEMBER_GAS) + SMART_KEY_1271_GAS + MSIG_MEMBER_GAS
            + (1_400_000 - SMART_KEY_1271_GAS) / 63 + MSIG_ACCEPTED_GAS;
        UARegistry tight = _deploy(address(0x5ce30), chainUidA, address(0), false, uint64(bound - 1), _impl, true, c);
        UARegistry r = _deploy(address(0x5ce31), chainUidA, address(0), false, uint64(bound), _impl, true, c);
        Member[] memory m = new Member[](9);
        for (uint256 i; i < 8; ++i) {
            bytes memory pk = abi.encodePacked(keccak256(abi.encode("slh", i)));
            UACall.register(tight, 0x0133, pk, _none(), hex"01", "");
            m[i] = Member(0x0133, UACall.register(r, 0x0133, pk, _none(), hex"01", ""), 1);
        }
        m[8] = Member(UAKinds.EVM_EOA, _pad(clone), 1);
        bytes memory d = _msigKey(9, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        UACall.register(tight, UAKinds.MSIG, d, _none(), "", "");
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](9);
        for (uint16 j; j < 9; ++j) {
            s[j] = IUARegistry.MemberSig(j, new IUARegistry.InnerSig[](0), _big);
        }
        bytes32 ua = UACall.register(r, UAKinds.MSIG, d, _none(), abi.encode(s), ""); // all PQ but the clone: PQ-eligible, m-of-n PoP
        uint256 least = _leastGas(
            address(r),
            abi.encodeCall(r.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, UACall.auth(ua, _msigAuth(d, s)))),
            bound
        );
        emit log_named_uint("pq msig bound", bound);
        emit log_named_uint("  least requireAuthorized frame gas", least);
    }

    /// The bound of msig key data `d` whose threshold needs every member (weights 1, threshold = count) or whose only
    /// member is the threshold: MSIG_ACCEPTED_GAS + Σ (cap + MSIG_MEMBER_GAS), + gen 1's hold for a derived member handed to gen 1, + the
    /// registry's own hold (held - 400 k) / 63 for the largest held cap above 400 k (a handed member holds in gen 2 too).
    function _boundOf(bytes memory d, bool handed) internal pure returns (uint256 b) {
        uint256 count = uint16(bytes2(abi.encodePacked(d[2], d[3])));
        uint256 held;
        b = MSIG_ACCEPTED_GAS;
        for (uint256 j; j < count; ++j) {
            uint16 kind = uint16(bytes2(abi.encodePacked(d[4 + 36 * j], d[5 + 36 * j])));
            uint256 cap = kind < 0x0100 ? SMART_KEY_1271_GAS : _cap(kind);
            // handed: one hand-off and the walk of one generation (`LINE_HOP_GAS`, spec 2026-11-19-registry-verify-only-kinds §4 P3)
            uint256 e = cap + (handed && kind >= 0x0100 ? cap / 63 + 5_000 + 10_000 : 0);
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
            address(r),
            abi.encodeCall(r.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, UACall.auth(ua, _burnAuth(d)))),
            bound
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
        UACall.register(tight, UAKinds.MSIG, d, _none(), "", "");
        ua = UACall.register(r, UAKinds.MSIG, d, _none(), "", "");
        _acceptWith(r, d, _big);
    }

    /// Asserts `call` succeeds with `bound` gas for the callee frame; returns the least frame gas that succeeds. Each
    /// probe goes through `GasProbe`, so the frame gets exactly that gas (under `--isolate` each probe is a transaction
    /// of its own, all accounts and slots cold; its calldata is paid by that transaction, not by the frame).
    /// F185: EIP-8037 state gas of `register`'s new storage slots (the record), charged inside the call's gas: `gas used`
    /// of `register` 312,557 -> 658,937 (ed25519) and 346,533 -> 692,913 (bls-bn254-minsig) from Osaka to Amsterdam, +346 k.
    /// A8 (UA-8, D7): `register` also writes the whole registration as SSTORE2 code (state gas 1,164,330 for ed25519,
    /// 1,311,210 for bls-bn254-minsig), so the least call gas is 1,460,619 / 1,635,814. REGRESSION GUARDS ONLY: pinned
    /// from the first measured run on this build ("/ 1.0"), not derived bounds. Full table: runs/2026-10-30-ua8-gas.txt.
    uint256 internal constant HEADROOM_ED25519 = 1_461_571;
    uint256 internal constant HEADROOM_BLS_BN254 = 1_636_290;

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

    /// Registers `d`'s derived members in `r` with `_memberPop` as pop (BurnAll PoPs accept anything).
    function _registerMembers(UARegistry r, bytes memory d) internal {
        uint256 count = uint16(bytes2(abi.encodePacked(d[2], d[3])));
        for (uint256 j; j < count; ++j) {
            uint16 kind = uint16(bytes2(abi.encodePacked(d[4 + 36 * j], d[5 + 36 * j])));
            if (kind >= 0x0100) UACall.register(r, kind, _key(kind), _none(), _memberPop, "");
        }
    }

    /// Every member signs, in index order, without key data (CTR-UA-33); `_big` as every signature.
    function _burnAuth(bytes memory d) internal view returns (bytes memory) {
        uint16 count = uint16(bytes2(abi.encodePacked(d[2], d[3])));
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](count);
        for (uint16 j; j < count; ++j) {
            s[j] = IUARegistry.MemberSig(j, new IUARegistry.InnerSig[](0), _big);
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
                    uint256 n =
                        vm.parseJsonBytes(
                        sj, string.concat(".derived[", vm.toString(i), "].", arr, "[", vm.toString(s), "].sig")
                    )
                    .length;
                    if (n > max) max = n;
                    ++rows;
                }
            }
        }
        assertEq(rows, 22 + 99, "signature rows scanned");
        assertGe(max, 256, "largest real signature");
        return new bytes(max);
    }

    function _cool(address[] memory a) internal {
        for (uint256 i; i < a.length; ++i) {
            vm.cool(a[i]);
        }
    }

    /// msig over the 8 single-key kinds (weights 1), each registered (if not yet) with `_memberPop`, else `big`, as its
    /// pop; (gas with 8 member sigs - gas with 1) / 7, all cold.
    function _derivedOverhead(UARegistry r, UARegistry home, bytes memory big, address[] memory verifiers, uint16 w)
        internal
        returns (uint256)
    {
        Member[] memory m = new Member[](8);
        for (uint256 i; i < 8; ++i) {
            bytes memory k = _key(KINDS[i]);
            bytes32 id = UAKinds.uaOf(KINDS[i], k);
            if (!home.isRegistered(id)) {
                UACall.register(home, KINDS[i], k, _none(), _memberPop.length != 0 ? _memberPop : big, "");
            }
            m[i] = Member(KINDS[i], id, w);
        }
        uint256[2] memory used;
        uint16[2] memory t = [uint16(1), uint16(8)];
        for (uint256 x; x < 2; ++x) {
            bytes memory d = _msigKey(t[x] * w, m);
            bytes32 ua = UACall.register(r, UAKinds.MSIG, d, _none(), "", "");
            _acceptWith(r, d, big);
            IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](t[x]);
            for (uint16 j; j < t[x]; ++j) {
                s[j] = IUARegistry.MemberSig(j, new IUARegistry.InnerSig[](0), big); // CTR-UA-33: the registry reads each key from its record
            }
            IUARegistry.UASig memory auth;
            auth.members = s; // TS-D12: an msig's `UASig` is its members only
            vm.cool(address(r));
            vm.cool(address(home));
            _cool(verifiers);
            r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, auth);
            // the registry's own gas (typed-signing R1): the caller-side ABI encoding of the struct depends on how much
            // memory this frame already holds (the padded pops), not on the registry
            used[x] = vm.lastCallGas().gasTotalUsed;
        }
        return (used[1] - used[0]) / 7;
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
            bytes32 ua = UACall.register(r, UAKinds.MSIG, d, _none(), "", "");
            _acceptNatives(r, d, ua, t[x], ids);
            bytes memory auth = _nativeAuth(r, d, ua, t[x], ids);
            vm.cool(address(r));
            _cool(accounts);
            IUARegistry.UASig memory au409 = UACall.auth(ua, auth); // converted before the measurement
            uint256 g = gasleft();
            r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, au409);
            used[x] = g - gasleft();
        }
        return (used[1] - used[0]) / 15;
    }

    /// The first `n` slots accept, each by its key (a wallet's owner, as `_nativeAuth`).
    function _acceptNatives(UARegistry r, bytes memory d, bytes32 ua, uint16 n, bytes32[] memory ids) internal {
        for (uint16 j; j < n; ++j) {
            bytes32 id;
            assembly ("memory-safe") {
                id := mload(add(add(d, 38), mul(36, j)))
            }
            r.acceptMembership(
                ua,
                IUARegistry.MemberSig(
                    j, new IUARegistry.InnerSig[](0), _ecdsa(_pkOf(id, ids), UAKinds.membershipDigest(ua, id))
                )
            );
        }
    }

    function _nativeAuth(UARegistry r, bytes memory d, bytes32 ua, uint16 n, bytes32[] memory ids)
        internal
        view
        returns (bytes memory)
    {
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](n);
        for (uint16 j; j < n; ++j) {
            bytes32 id;
            assembly ("memory-safe") {
                id := mload(add(add(d, 38), mul(36, j)))
            }
            s[j] = IUARegistry.MemberSig(
                j, new IUARegistry.InnerSig[](0), _ecdsa(_pkOf(id, ids), r.uaAuthDigest(id, UAKinds.PURPOSE_MEMBER, md))
            );
        }
        return _msigAuth(d, s);
    }

    function _pkOf(bytes32 id, bytes32[] memory ids) internal pure returns (uint256) {
        for (uint256 i; i < ids.length; ++i) {
            if (ids[i] == id) return 1000 + i;
        }
        revert("pk");
    }

    /// Register step 4: Σ of the c largest caps + c × MSIG_MEMBER_GAS + MSIG_ACCEPTED_GAS ≤ verifyBudget (here 1,145,000 + 135,000
    /// + 3,500; 3ze: + 2,500 before).
    function test_T_GAS_structureOverBudgetRefused() public {
        Member[] memory m = new Member[](3);
        uint16[3] memory kinds = [uint16(0x0100), uint16(0x0101), uint16(0x0107)];
        UARegistry tight =
            _deploy(address(0x5cc1), chainUidA, address(0), false, 1_200_000, address(0), true, _cfgs(address(mock)));
        UARegistry roomy =
            _deploy(address(0x5cc2), chainUidA, address(0), false, 1_283_500, address(0), true, _cfgs(address(mock)));
        for (uint256 i; i < 3; ++i) {
            bytes memory k = _key(kinds[i]);
            m[i] = Member(kinds[i], _register(tight, kinds[i], k), 1);
            _register(roomy, kinds[i], k);
        }
        bytes memory d = _msigKey(3, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        UACall.register(tight, UAKinds.MSIG, d, _none(), "", "");
        UACall.register(roomy, UAKinds.MSIG, d, _none(), "", ""); // exactly at the budget
        // threshold 2 of the same three: c = 2, the two largest caps
        d = _msigKey(2, m);
        UACall.register(tight, UAKinds.MSIG, d, _none(), "", "");
        // 16 native members on a chain with SmartKeyAccount clones: 16 × 445 k = 7.12 M ≤ 12 M
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
        UACall.register(ska, UAKinds.MSIG, _msigKey(16, n), _none(), "", "");
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
        UACall.register(small, UAKinds.MSIG, _msigKey(16, n), _none(), "", "");
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
        uint256 worst = 16 * (maxCap + maxCap / 63 + 5_000 + MSIG_MEMBER_GAS) + MSIG_ACCEPTED_GAS;
        emit log_named_uint("msig worst case (16 x largest cap, handed)", worst);
        assertLe(worst, BUDGET, "msig worst case over the budget");
    }

    /// Native paths: ECDSA, ERC-1271 (an ECDSA wallet), the 7702 base key.
    function test_T_GAS_native() public {
        uint256 pk = 0xA11CE;
        bytes32 ua = _pad(vm.addr(pk));
        bytes memory sig = _nativeSig(reg, pk, UAKinds.PURPOSE_METATX, DIGEST);
        IUARegistry.UASig memory au524 = UACall.auth(ua, sig); // converted before the measurement
        uint256 g = gasleft();
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, au524);
        g -= gasleft();
        emit log_named_uint("requireAuthorized native ECDSA (registry warm)", g);
        emit log_named_uint("requireAuthorized native ECDSA, the registry's frame", vm.lastCallGas().gasTotalUsed);
        // §1.15: ECDSA ~3.5 k + the EIP-712 hash ~1 k + the registry's ~5 k, + a cold account (`--isolate`); F185: the
        // bound was 12,100; Foundry 1.8.5 isolates by default (13,413 on Osaka) and Amsterdam's EIP-8038 raises the cold
        // account and slot reads again (14,413), so + 2,400 -> 14,500; typed-signing R1 (TS-D12): the `UASig` struct
        // (three dynamic fields: the caller's encoding, the registry's calldata checks) 14,413 -> 15,452, so + 1,100
        assertLe(g, 3_500 + 1_000 + 5_000 + 2_600 + 2_400 + 1_100, "native ECDSA over the documented cost");
        MockWallet w = new MockWallet(vm.addr(pk), 0, 0, address(0));
        bytes32 wua = _pad(address(w));
        sig = _ecdsa(pk, reg.uaAuthDigest(wua, UAKinds.PURPOSE_METATX, DIGEST));
        IUARegistry.UASig memory au536 = UACall.auth(wua, sig); // converted before the measurement
        g = gasleft();
        reg.requireAuthorized(wua, UAKinds.PURPOSE_METATX, DIGEST, au536);
        g -= gasleft();
        emit log_named_uint("requireAuthorized native ERC-1271 (ECDSA wallet)", g);
        assertLe(g, 50_000, "native ERC-1271 over the 50 k cap");
    }

    /// Addendum (b): `register(bls-bn254-minsig)` runs the G2 pairing check of `UAKinds` (needs ≥ 165,508 gas left at
    /// that point) and then the PoP under the 345 k cap (needs ≥ 355,476 left): the smallest call gas that registers.
    function test_T_GAS_registerHeadroomBlsBn254() public {
        string memory sj = vm.readFile("../vectors/ua/signatures.json");
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0107, address(new BlsMinSigBn254Verifier()), 345_000, false, 0);
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), false, c);
        bytes memory call = abi.encodeCall(
            r.register,
            (
                0x0107,
                vm.parseJsonBytes(sj, ".derived[6].keyData"),
                _none(),
                vm.parseJsonBytes(sj, ".derived[6].pop.sig"),
                ""
            )
        );
        uint256 lo = 100_000;
        uint256 hi = 4_000_000; // A8: the state gas of the record counts in the call gas (F185), so the least gas is > 1 M
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
        assertLe(hi, HEADROOM_BLS_BN254); // F185: was 500,000 (452,440 on Osaka); A8: the UA-8 record, 1,635,814; typed-signing P3 (typed portable digest): 1,636,290
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
        c[0] = UARegistry.KindConfig(0x0102, address(ev), uint64(cap), false, 0);
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), false, c);
        bytes memory k = vm.parseJsonBytes(sj, ".derived[7].keyData");
        bytes memory call =
            abi.encodeCall(r.register, (0x0102, k, _none(), vm.parseJsonBytes(sj, ".derived[7].pop.sig"), ""));
        uint256 lo = 100_000;
        uint256 hi = 4_000_000; // A8: the state gas of the record counts in the call gas (F185), so the least gas is > 1 M
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
        IUARegistry.UASig memory au617 = UACall.auth(ua, auth); // converted before the measurement
        g = gasleft();
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, dg, au617);
        emit log_named_uint("requireAuthorized ed25519", g - gasleft());
        assertLe(hi, HEADROOM_ED25519); // F185: was cap + 100,000 (288,524 on Osaka); A8: the UA-8 record, 1,460,619; typed-signing P3 (typed portable digest): 1,461,571
    }
}

/// Plan Task 9 (spec 2026-11-19-bls12381-multi §8): `bls12381-multi` (0x0121) gas rows with the real verifier on the EIP-2537
/// precompiles, two columns (regular, EIP-8037 state) under `--isolate`; the cap gate (owner ruling Q4: regular gas of
/// `registerBlsMulti` at n = 64 at most 75 % of 2^24 = 12,582,912); `CHECK_GAS`, `POP_GAS` and `DeployBase.CAP_BLS12381_MULTI`
/// against the measured worst; N4, an `msig` of `0x0121` members at n = 64 registered exactly at `verifyBudget`. Rows
/// `GAS|label|regular|state` with `-vv`. Forge gas is deterministic, not calibration (owner ruling 2026-11-19). UNAUDITED.
contract UAGasBlsMultiTest is Test {
    uint16 internal constant K = 0x0121;
    bytes32 internal constant UID = keccak256("scaas.bls-multi.gas");
    uint64 internal constant BUDGET = 12_000_000; // DeployBase.UA_VERIFY_BUDGET
    uint64 internal constant CAP = 330_000; // DeployBase.CAP_BLS12381_MULTI
    uint256 internal constant CAP_GATE = 12_582_912; // 75 % of 2^24 (owner ruling Q4)

    BlsMultiBls12381Verifier internal verifier;
    CheckMeter internal meter;

    function setUp() public {
        verifier = new BlsMultiBls12381Verifier();
        meter = new CheckMeter();
    }

    function _reg(uint64 budget, uint64 cap) internal returns (UARegistry) {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(K, address(verifier), cap, false, 0);
        return new UARegistry(UID, address(0), false, budget, 1 << 24, address(0), true, k);
    }

    function _none() internal pure returns (IUARegistry.UAAttrs memory) {}

    function _group(uint256 n, uint16 t, uint256 seed) internal view returns (BlsMultiKit.Group memory) {
        uint256[] memory sks = new uint256[](n);
        uint16[] memory w = new uint16[](n);
        for (uint256 i; i < n; ++i) {
            sks[i] = uint256(keccak256(abi.encode(seed, i)))
                % 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
            w[i] = 1;
        }
        return BlsMultiKit.group(sks, w, t);
    }

    function _typed(bytes memory d) internal pure returns (IUARegistry.BlsMultiKey memory key) {
        uint256 n = uint16(bytes2(BlsMultiKit._cut(d, 258, 2)));
        key.aggKey = BlsMultiKit._cut(d, 0, 256);
        key.threshold = uint16(bytes2(BlsMultiKit._cut(d, 256, 2)));
        key.members = new IUARegistry.BlsMultiMember[](n);
        for (uint256 i; i < n; ++i) {
            key.members[i] = IUARegistry.BlsMultiMember(
                BlsMultiKit._cut(d, 260 + 258 * i, 256), uint16(bytes2(BlsMultiKit._cut(d, 516 + 258 * i, 2)))
            );
        }
    }

    function _row(string memory label, uint256 regular, uint256 state) internal {
        emit log_string(string.concat("GAS|", label, "|", vm.toString(regular), "|", vm.toString(state)));
    }

    /// `registerBlsMulti` at n = 2, 16, 32, 64 (t = n / 2): regular and state gas of the call, each on a registry where the
    /// kind's list already has a row (its count slot is not new); the cap gate on n = 64's regular gas.
    function test_T_GAS_registerBlsMulti_n2_16_32_64() public {
        UARegistry r = _reg(BUDGET, CAP);
        BlsMultiKit.Group memory g0 = _group(2, 1, 900);
        r.register(K, g0.d, _none(), BlsMultiKit.pop(g0, BlsMultiKit.popMsg(g0.ua)), "");
        uint256[4] memory ns = [uint256(2), 16, 32, 64];
        uint256 last;
        for (uint256 i; i < 4; ++i) {
            BlsMultiKit.Group memory g = _group(ns[i], uint16(ns[i] / 2), 901 + i);
            (IUARegistry.BlsMultiKey memory key, bytes memory pop) =
                (_typed(g.d), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)));
            r.registerBlsMulti(key, _none(), pop, "");
            Vm.Gas memory lg = vm.lastCallGas();
            (uint256 regular, uint256 st) = (lg.gasTotalUsed, uint256(int256(lg.gasStateUsed))); // as `UARegistryUaPortable._gas`
            _row(string.concat("registerBlsMulti n", vm.toString(ns[i])), regular, st);
            last = regular;
        }
        assertLe(last, CAP_GATE, "the cap gate: registerBlsMulti n = 64 regular gas over 75 % of 2^24 (cap 32)");
    }

    /// The state column is EIP-8037's charge for what a registration creates: 1,530 a byte of new code (the stored `ua ‖ s`, the
    /// registration blob), 183,600 a new account (120 x 1,530, measured) and 97,920 a new storage slot (n = 16; the count slot not
    /// new).
    function test_T_GAS_blsMultiStateEqualsBytes() public {
        UARegistry r = _reg(BUDGET, CAP);
        BlsMultiKit.Group memory g0 = _group(2, 1, 910);
        r.register(K, g0.d, _none(), BlsMultiKit.pop(g0, BlsMultiKit.popMsg(g0.ua)), "");
        BlsMultiKit.Group memory g = _group(16, 8, 911);
        bytes memory pop = BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua));
        vm.startStateDiffRecording();
        r.register(K, g.d, _none(), pop, "");
        uint256 st = uint256(int256(vm.lastCallGas().gasStateUsed));
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        (uint256 codeBytes, uint256 slots, uint256 accounts) = (0, 0, 0);
        for (uint256 i; i < acc.length; ++i) {
            // not the linked libraries: forge books their creation in a test's first recording
            if (
                acc[i].kind == VmSafe.AccountAccessKind.Create && !acc[i].reverted
                    && acc[i].account != address(UARegistryCoreLib) && acc[i].account != address(UARegistryAuxLib)
                    && acc[i].account != address(UARegistryRegLib)
            ) {
                codeBytes += acc[i].deployedCode.length;
                ++accounts;
            }
            for (uint256 j; j < acc[i].storageAccesses.length; ++j) {
                Vm.StorageAccess memory a = acc[i].storageAccesses[j];
                if (a.isWrite && !a.reverted && a.previousValue == 0 && a.newValue != 0) ++slots;
            }
        }
        _row("registerBlsMulti n16 state (code bytes | new slots)", codeBytes, slots);
        emit log_named_uint("new accounts", accounts);
        // measured: each new account (an SSTORE2 contract) is charged 183,600 = 120 x 1,530 besides its code (plan Task 9's
        // formula has no account term; a proposal for the plan's correction, not a ruling)
        assertEq(
            st,
            1530 * (codeBytes + 120 * accounts) + 97_920 * slots,
            "state = 1,530 x (code bytes + 120 x new accounts) + 97,920 x new slots"
        );
    }

    /// The verify rows inside `check` (n, k): (2, 2), (16, 8), (64, 1), (64, 32) add, (64, 33) subtract with the negation, (64, 64)
    /// the stored apk; `verify` and `verifyMinimal` (unit weights, t = k: every row minimal). The worst within `CHECK_GAS`.
    function test_T_GAS_blsMultiVerify() public {
        UARegistry r = _reg(BUDGET, CAP);
        uint256[2][6] memory rows = [
            [uint256(2), 2], [uint256(16), 8], [uint256(64), 1], [uint256(64), 32], [uint256(64), 33], [uint256(64), 64]
        ];
        BlsMultiKit.Group memory g64;
        uint256 worst;
        for (uint256 i; i < 6; ++i) {
            (uint256 n, uint256 k) = (rows[i][0], rows[i][1]);
            BlsMultiKit.Group memory g;
            if (n == 64 && g64.sk.length != 0) {
                g = g64; // the same keys, another threshold: only `t` and the id differ
                g = BlsMultiKit.group(g.sk, _ones(64), uint16(k));
            } else {
                g = _group(n, uint16(k), 920 + n);
                if (n == 64) g64 = g;
            }
            r.register(K, g.d, _none(), BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua)), "");
            (IUARegistry.Record memory rec,) = r.recordOf(g.ua);
            bytes memory p = SSTORE2.read(rec.keyPtr);
            bytes32 m = UAKinds.uaMessage(K, UAKinds.PURPOSE_METATX, keccak256("op"));
            bytes memory sig = BlsMultiKit.sign(g, k == 64 ? type(uint64).max : (uint256(1) << k) - 1, m);
            uint256 gv = meter.measure(verifier, p, m, sig, UASafeVerifier.Mode.Verify);
            uint256 gm = meter.measure(verifier, p, m, sig, UASafeVerifier.Mode.Minimal);
            string memory label = string.concat("verify n", vm.toString(n), " k", vm.toString(k));
            _row(label, gv, 0);
            _row(string.concat(label, " minimal"), gm, 0);
            if (gv > worst) worst = gv;
            if (gm > worst) worst = gm;
        }
        emit log_named_uint("worst check", worst);
        assertLe(worst, verifier.CHECK_GAS(), "CHECK_GAS below the measured worst");
    }

    /// The registration PoP inside `check` (n + 1 pairings, n hash-to-G1 in Solidity) at n = 2, 16, 64; the worst within `POP_GAS`.
    function test_T_GAS_blsMultiPop() public {
        uint256[3] memory ns = [uint256(2), 16, 64];
        uint256 worst;
        for (uint256 i; i < 3; ++i) {
            BlsMultiKit.Group memory g = _group(ns[i], 1, 940 + i);
            bytes32 pm = BlsMultiKit.popMsg(g.ua);
            uint256 gp = meter.measure(verifier, g.d, pm, BlsMultiKit.pop(g, pm), UASafeVerifier.Mode.Pop);
            _row(string.concat("pop n", vm.toString(ns[i])), gp, 0);
            if (gp > worst) worst = gp;
        }
        assertLe(worst, verifier.POP_GAS(), "POP_GAS below the measured worst");
    }

    /// The least `verifyCap` at which the worst verify (n = 64, k = 33, the subtract path) passes on the hot path
    /// (`requireAuthorized`: `verify`) and on a stored path (`requirePortable`: `verifyMinimal`), each with the registry's hold
    /// and the stored `p` (12,644 B) as calldata; `CAP_BLS12381_MULTI` at or above both.
    function test_T_GAS_blsMultiLeastCap() public {
        BlsMultiKit.Group memory g = _group(64, 33, 950);
        bytes memory pop = BlsMultiKit.pop(g, BlsMultiKit.popMsg(g.ua));
        bytes32 digest = keccak256("op");
        bytes memory hot =
            BlsMultiKit.sign(g, (uint256(1) << 33) - 1, UAKinds.uaMessage(K, UAKinds.PURPOSE_METATX, digest));
        bytes memory kem =
            BlsMultiKit.sign(g, (uint256(1) << 33) - 1, UAKinds.uaMessage(K, UAKinds.PURPOSE_KEM, digest));
        uint256[2] memory least;
        for (uint256 path; path < 2; ++path) {
            (uint256 lo, uint256 hi) = (250_000, 400_000);
            while (hi - lo > 1) {
                uint256 mid = (lo + hi) / 2;
                UARegistry r = _reg(BUDGET, uint64(mid));
                r.register(K, g.d, _none(), pop, "");
                IUARegistry.UASig memory a;
                a.signature = path == 0 ? hot : kem;
                bool ok;
                if (path == 0) {
                    try r.requireAuthorized(g.ua, UAKinds.PURPOSE_METATX, digest, a) {
                        ok = true;
                    } catch {}
                } else {
                    try r.requirePortable(g.ua, UAKinds.PURPOSE_KEM, digest, a) {
                        ok = true;
                    } catch {}
                }
                if (ok) hi = mid;
                else lo = mid;
            }
            least[path] = hi;
        }
        _row("least verifyCap n64 k33: requireAuthorized | requirePortable", least[0], least[1]);
        assertGe(CAP, least[0], "CAP_BLS12381_MULTI below the hot path's need");
        assertGe(CAP, least[1], "CAP_BLS12381_MULTI below the stored path's need");
    }

    function _ones(uint256 n) internal pure returns (uint16[] memory w) {
        w = new uint16[](n);
        for (uint256 i; i < n; ++i) {
            w[i] = 1;
        }
    }

    /// `POP_GAS` (with the hold) fits the deploy budget; `CAP_BLS12381_MULTI` holds `CHECK_GAS` with its hold.
    function test_T_GAS_blsMultiCapsWithinBudget() public view {
        uint256 pop = verifier.POP_GAS();
        assertLe(pop + pop / 63 + 5_000, BUDGET, "POP_GAS with the hold over the budget");
        uint256 c = verifier.CHECK_GAS();
        assertGe(CAP, c + c / 63 + 5_000, "the cap below CHECK_GAS with the hold");
    }

    /// N4 (beside `UAGasTest.test_T_GAS_msigPqAtBudget`): an `msig` of 16 `0x0121` members (the most enabled slots), each n = 64 with
    /// t = 33 … 48 (every minimal set on the subtract path, the worst verify), threshold 16 (every member), each member cap 400,000
    /// (so the bound, 16 x (400,000 + MSIG_MEMBER_GAS) + MSIG_ACCEPTED_GAS, holds a registration's `POP_GAS`), registered exactly at
    /// `verifyBudget` (one gas less: `UAKeyData(msig)`); it authorises within the bound on the hot path (`requireAuthorized`) and on
    /// a stored path (`requirePortableApp`, every slot accepted), the frame given exactly the bound.
    function test_T_GAS_msigBlsMultiAtBudget() public {
        uint64 cap = 400_000;
        uint256 bound = 16 * (cap + 45_000) + 3_500;
        UARegistry tight = _reg(uint64(bound - 1), cap);
        UARegistry r = _reg(uint64(bound), cap);
        BlsMultiKit.Group memory g = _group(64, 33, 930);
        IUARegistry.MsigStructure memory st;
        st.threshold = 16;
        st.members = new IUARegistry.MsigMember[](16);
        BlsMultiKit.Group[] memory gs = new BlsMultiKit.Group[](16);
        for (uint256 i; i < 16; ++i) {
            gs[i] = BlsMultiKit.group(g.sk, _ones(64), uint16(33 + i));
            bytes memory pop = BlsMultiKit.pop(gs[i], BlsMultiKit.popMsg(gs[i].ua));
            tight.register(K, gs[i].d, _none(), pop, "");
            r.register(K, gs[i].d, _none(), pop, "");
        }
        _sortById(gs);
        for (uint256 i; i < 16; ++i) {
            st.members[i] = IUARegistry.MsigMember(K, gs[i].ua, 1);
        }
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        tight.registerMsig(st, _none(), new IUARegistry.MemberSig[](0), "");
        bytes32 mu = r.registerMsig(st, _none(), new IUARegistry.MemberSig[](0), "");
        for (uint16 i; i < 16; ++i) {
            bytes32 md = UAKinds.memberDigest(
                mu, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBERSHIP, UAKinds.membershipDigest(mu, gs[i].ua))
            );
            r.acceptMembership(mu, _slot(gs[i], i, md));
        }
        bytes32 digest = keccak256("op");
        IUARegistry.UASig memory hot =
            _quorum(gs, UAKinds.memberDigest(mu, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_METATX, digest)));
        uint256 least =
            _least(address(r), abi.encodeCall(r.requireAuthorized, (mu, UAKinds.PURPOSE_METATX, digest, hot)), bound);
        _row("msig 16 x 0x0121 n64 requireAuthorized least frame gas (bound)", least, bound);
        bytes32 app = UAKinds.appPurpose(bytes32("app"));
        IUARegistry.UASig memory stored =
            _quorum(gs, UAKinds.memberDigest(mu, UAKinds.uaMessage(UAKinds.MSIG, app, digest)));
        least = _least(address(r), abi.encodeCall(r.requirePortableApp, (mu, bytes32("app"), digest, stored)), bound);
        _row("msig 16 x 0x0121 n64 requirePortableApp least frame gas (bound)", least, bound);
    }

    /// Slot `i`'s signature by its group's minimal set (the first t members) over `md` under `member`.
    function _slot(BlsMultiKit.Group memory g, uint16 i, bytes32 md)
        internal
        view
        returns (IUARegistry.MemberSig memory s)
    {
        uint256 t = uint16(bytes2(BlsMultiKit._cut(g.d, 256, 2)));
        s.index = i;
        s.sig = BlsMultiKit.sign(g, (uint256(1) << t) - 1, UAKinds.uaMessage(K, UAKinds.PURPOSE_MEMBER, md));
    }

    function _quorum(BlsMultiKit.Group[] memory gs, bytes32 md) internal view returns (IUARegistry.UASig memory a) {
        a.members = new IUARegistry.MemberSig[](16);
        for (uint16 i; i < 16; ++i) {
            a.members[i] = _slot(gs[i], i, md);
        }
    }

    function _sortById(BlsMultiKit.Group[] memory gs) internal pure {
        for (uint256 i = 1; i < gs.length; ++i) {
            for (uint256 j = i; j > 0 && uint256(gs[j].ua) < uint256(gs[j - 1].ua); --j) {
                (gs[j], gs[j - 1]) = (gs[j - 1], gs[j]);
            }
        }
    }

    /// `call` on `r` succeeds with `bound` gas for its frame; the least frame gas that succeeds.
    function _least(address r, bytes memory call, uint256 bound) internal returns (uint256 hi) {
        GasProbe p = new GasProbe();
        assertTrue(p.probe(r, call, bound), "authorizes with verifyBudget");
        uint256 lo;
        for (hi = bound; hi - lo > 1;) {
            uint256 mid = (lo + hi) / 2;
            if (p.probe(r, call, mid)) hi = mid;
            else lo = mid;
        }
    }
}

/// The execution gas of one `check` (what `UASafeVerifier` gives its self-call, `CHECK_GAS` / `POP_GAS`), measured inside one frame:
/// under `--isolate` a test's own top-level call is a transaction of its own (intrinsic and calldata gas, the EIP-7976 floor).
contract CheckMeter {
    function measure(
        BlsMultiBls12381Verifier v,
        bytes calldata keyData,
        bytes32 message,
        bytes calldata sig,
        UASafeVerifier.Mode mode
    ) external view returns (uint256 g) {
        g = gasleft();
        bool ok = v.check(keyData, message, sig, mode);
        g -= gasleft();
        require(ok, "check");
    }
}
