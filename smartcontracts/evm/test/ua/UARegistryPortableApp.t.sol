// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UARegistry as UARegistryPreApp} from "../../legacy/ua-pre-app/ua/UARegistry.preapp.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "./UACall.sol";
import {UARegistryPortableTest} from "./UARegistryPortable.t.sol";

/// CTR-UA-45 / CTR-UA-46 (owner 2026-11-17, N1; pqvault spec §4.1): `requirePortableApp(ua, appId, typedDigest, UASig)`, the open
/// portable app namespace: `requirePortable`'s checks under `appPurpose(appId)`, the purpose computed by the registry. The fixtures
/// are `UARegistryPortableTest`'s (its own tests run here too, unchanged). Every refusal next to its positive control, one change
/// at a time.
contract UARegistryPortableAppTest is UARegistryPortableTest {
    bytes32 internal constant APP_A = keccak256("scaas.pqvault.v1"); // PQVAULT_APP_ID
    bytes32 internal constant APP_B = keccak256("scaas.test.app.v1");
    address internal constant REG_G2B = 0x5cA0000000000000000000000000000000000009;

    function _app(UARegistry r, bytes32 ua, bytes32 appId, IUARegistry.UASig memory s) internal view {
        r.requirePortableApp(ua, appId, TYPED, s);
    }

    function _appRefused(UARegistry r, bytes32 ua, bytes32 appId, IUARegistry.UASig memory s) internal {
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        r.requirePortableApp(ua, appId, TYPED, s);
    }

    // ----- the purpose -----

    /// The namespace and the purpose form, pinned against an inline encoding and against `vectors/ua/sign.json` `portableApp`
    /// (written by clientkeys): each app's purpose and one row's `uaMessage` per app.
    function test_appPurpose_pinned() public view {
        assertEq(UAKinds.APP_PURPOSE_NS, keccak256("scaas.ua.purpose.app.v1"));
        assertEq(UAKinds.appPurpose(APP_A), keccak256(abi.encode(keccak256("scaas.ua.purpose.app.v1"), APP_A)));
        assertTrue(UAKinds.appPurpose(APP_A) != UAKinds.appPurpose(APP_B));
        string memory j = vm.readFile("../vectors/ua/sign.json");
        assertEq(vm.parseJsonBytes32(j, ".portableApp.namespace"), UAKinds.APP_PURPOSE_NS);
        bytes32[2] memory ids = [APP_A, APP_B];
        for (uint256 i; i < 2; ++i) {
            string memory a = string.concat(".portableApp.apps[", vm.toString(i), "]");
            assertEq(vm.parseJsonBytes32(j, string.concat(a, ".appId")), ids[i]);
            assertEq(vm.parseJsonBytes32(j, string.concat(a, ".purposeTag")), UAKinds.appPurpose(ids[i]));
            string memory r = string.concat(".portableApp.rows[", vm.toString(i * 14), "]");
            assertEq(vm.parseJsonBytes32(j, string.concat(r, ".appId")), ids[i]);
            uint16 kind = uint16(vm.parseJsonUint(j, string.concat(r, ".kind")));
            bytes32 digest = vm.parseJsonBytes32(j, string.concat(r, ".digest"));
            assertEq(
                vm.parseJsonBytes32(j, string.concat(r, ".uaMsg")),
                UAKinds.uaMessage(kind, UAKinds.appPurpose(ids[i]), digest)
            );
        }
    }

    // ----- single keys -----

    /// Every PQ holder kind and a classical kind sign under `PQVAULT_APP_ID` and under a second `appId`; app A's signature is refused
    /// under app B and the reverse; `keyData` or `members` beside the signature are refused.
    function test_requirePortableApp_singleKeyEveryHolderKind() public {
        uint16[6] memory kinds = [PQ[0], PQ[1], PQ[2], PQ[3], PQ[4], uint16(0x0101)];
        for (uint256 i; i < kinds.length; ++i) {
            uint16 k = kinds[i];
            bytes memory key = k == 0x0101 ? _key(0x0101) : _pqKey(k, uint8(i + 1));
            bytes32 ua = _register(p, k, key);
            IUARegistry.UASig memory a = _single(k, key, UAKinds.appPurpose(APP_A));
            IUARegistry.UASig memory b = _single(k, key, UAKinds.appPurpose(APP_B));
            _app(p, ua, APP_A, a);
            _app(p, ua, APP_B, b);
            _appRefused(p, ua, APP_B, a);
            _appRefused(p, ua, APP_A, b);
            IUARegistry.UASig memory s = _single(k, key, UAKinds.appPurpose(APP_A));
            s.keyData = key;
            _appRefused(p, ua, APP_A, s);
            s = _single(k, key, UAKinds.appPurpose(APP_A));
            s.members = new IUARegistry.MemberSig[](1);
            _appRefused(p, ua, APP_A, s);
        }
    }

    /// `appId` 0 is refused, even with a signature over `appPurpose(0)`; the same construction under app A passes.
    function test_requirePortableApp_appIdZero() public {
        bytes memory key = _pqKey(UAKinds.MLDSA44, 4);
        bytes32 ua = _register(p, UAKinds.MLDSA44, key);
        _app(p, ua, APP_A, _single(UAKinds.MLDSA44, key, UAKinds.appPurpose(APP_A)));
        _appRefused(p, ua, bytes32(0), _single(UAKinds.MLDSA44, key, UAKinds.appPurpose(bytes32(0))));
    }

    /// The two directions of separation: `requirePortable` refuses an app purpose (its list is closed) though the signature is good
    /// under it, and `requirePortableApp` refuses a `PURPOSE_PQCHAT` and a `PURPOSE_KEM` signature that `requirePortable` takes.
    function test_requirePortableApp_separation() public {
        bytes memory key = _pqKey(UAKinds.FNDSA512, 5);
        bytes32 ua = _register(p, UAKinds.FNDSA512, key);
        IUARegistry.UASig memory a = _single(UAKinds.FNDSA512, key, UAKinds.appPurpose(APP_A));
        _app(p, ua, APP_A, a);
        _refused(p, ua, UAKinds.appPurpose(APP_A), a);
        IUARegistry.UASig memory chat = _single(UAKinds.FNDSA512, key, UAKinds.PURPOSE_PQCHAT);
        _portable(p, ua, UAKinds.PURPOSE_PQCHAT, chat);
        _appRefused(p, ua, APP_A, chat);
        IUARegistry.UASig memory kem = _single(UAKinds.FNDSA512, key, UAKinds.PURPOSE_KEM);
        _portable(p, ua, UAKinds.PURPOSE_KEM, kem);
        _appRefused(p, ua, APP_A, kem);
    }

    /// An unregistered id and a native id are refused: neither an ECDSA over the typed digest nor its chain-bound `UAAuth`
    /// signature (which `requireAuthorized` takes under the same purpose) passes.
    function test_requirePortableApp_unregisteredAndNative() public {
        bytes memory key = _pqKey(UAKinds.MLDSA44, 6);
        bytes32 none = UAKinds.uaOf(UAKinds.MLDSA44, key);
        _appRefused(p, none, APP_A, _single(UAKinds.MLDSA44, key, UAKinds.appPurpose(APP_A)));
        bytes32 eoa = _pad(vm.addr(SK));
        IUARegistry.UASig memory s;
        s.signature = _nativeSig(p, SK, UAKinds.appPurpose(APP_A), TYPED);
        p.requireAuthorized(eoa, UAKinds.appPurpose(APP_A), TYPED, s);
        _appRefused(p, eoa, APP_A, s);
        s.signature = _ecdsa(SK, TYPED);
        _appRefused(p, eoa, APP_A, s);
    }

    // ----- msig -----

    /// A classical-dominant `msig` signs by a quorum of accepted members: derived members only, and a derived member with the native
    /// one (over the typed digest itself). A derived member's signature under app A is refused under app B; one slot, an empty
    /// list (the classical shortcut `_sigOk` keeps for `register`'s `pop`), and `signature` beside the list are refused.
    function test_requirePortableApp_msig() public {
        (d3, u3, ml3) = _msig3(p, 3);
        (bytes32 e, bytes32 k1, bytes32 k2) =
            (_pad(vm.addr(SK)), UAKinds.uaOf(0x0101, _key(0x0101)), UAKinds.uaOf(UAKinds.MLDSA65, ml3));
        bytes32 pa = UAKinds.appPurpose(APP_A);
        _app(p, u3, APP_A, _m3(_ids(k1, k2), pa, false));
        _app(p, u3, APP_A, _m3(_ids(e, k1), pa, false));
        _app(p, u3, APP_B, _m3(_ids(k1, k2), UAKinds.appPurpose(APP_B), false));
        _appRefused(p, u3, APP_B, _m3(_ids(k1, k2), pa, false));
        _appRefused(p, u3, APP_B, _m3(_ids(e, k1), pa, false)); // the derived slot binds the app
        IUARegistry.UASig memory two = _m3(_ids(e, k1), pa, false);
        IUARegistry.UASig memory s;
        s.members = new IUARegistry.MemberSig[](1);
        s.members[0] = two.members[0];
        _appRefused(p, u3, APP_A, s);
        _appRefused(p, u3, APP_A, IUARegistry.UASig("", "", new IUARegistry.MemberSig[](0)));
        two.signature = hex"01";
        _appRefused(p, u3, APP_A, two);
    }

    /// Spec §4.1 (ii), documented: a native member signs the typed digest itself, so neither the purpose nor the `ua` is in what it
    /// signs, and its slot signature passes under every `appId` (and under `PURPOSE_PQCHAT`) for the same digest. A 1-of-1 `msig`
    /// over the EOA: the same `UASig` under app A and app B; its chain-bound `UAAuth` signature instead is refused.
    function test_requirePortableApp_nativeMemberUnderEveryApp() public {
        Member[] memory m = new Member[](1);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(SK)), 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = UACall.register(p, UAKinds.MSIG, d, _none(), "", "");
        p.acceptMembership(ua, _acceptEoaSig(d, SK));
        IUARegistry.UASig memory s;
        s.members = new IUARegistry.MemberSig[](1);
        s.members[0] = IUARegistry.MemberSig(0, new IUARegistry.InnerSig[](0), _ecdsa(SK, TYPED));
        _app(p, ua, APP_A, s);
        _app(p, ua, APP_B, s);
        _portable(p, ua, UAKinds.PURPOSE_PQCHAT, s);
        s.members[0].sig =
            _nativeSig(p, SK, UAKinds.PURPOSE_MEMBER, _memberDigest(ua, UAKinds.appPurpose(APP_A), TYPED));
        _appRefused(p, ua, APP_A, s);
    }

    // ----- generations -----

    /// UA8-D11: gen 2 forwards a record gen 1 holds to gen 1's `requirePortableApp` and returns its verdict (a single key, an `msig`);
    /// a refusal is gen 1's `UAUnauthorized(ua)`, as is an unregistered id.
    function test_requirePortableApp_gen2() public {
        (bytes memory d, bytes32 ua, bytes memory ml) = _msig3(p, 3);
        UARegistry g2 =
            _deploy(REG_G2, chainUidA, address(p), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        bytes32 pa = UAKinds.appPurpose(APP_A);
        bytes32[] memory two = _ids(_pad(vm.addr(SK)), UAKinds.uaOf(0x0101, _key(0x0101)));
        _app(g2, ua, APP_A, _members(p, d, ua, two, ml, pa, false));
        _appRefused(g2, ua, APP_B, _members(p, d, ua, two, ml, pa, false));
        bytes32 single = UAKinds.uaOf(UAKinds.MLDSA65, ml);
        _app(g2, single, APP_A, _single(UAKinds.MLDSA65, ml, pa));
        _appRefused(g2, single, APP_B, _single(UAKinds.MLDSA65, ml, pa));
        _appRefused(g2, keccak256("unregistered"), APP_A, _single(UAKinds.MLDSA65, ml, pa));
    }

    /// Spec §4.1 (iii), review r2 R10: gen 1 deployed from the pre-change `UARegistry` bytecode (no stub, which could have a fallback)
    /// holds a record and answers `requirePortable` (directly and through gen 2: the positive control). It has no `requirePortableApp`
    /// and no fallback, so the entry reverts with empty data, called directly and forwarded by gen 2: a refusal of a void view.
    function test_requirePortableApp_gen2PreChangeGen1() public {
        UARegistry g1 = _preApp(_cfgs(address(mock)));
        bytes memory key = _key(0x0101);
        bytes32 ua = _register(g1, 0x0101, key);
        UARegistry g2 =
            _deploy(REG_G2B, chainUidA, address(g1), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        IUARegistry.UASig memory chat = _single(0x0101, key, UAKinds.PURPOSE_PQCHAT);
        _portable(g1, ua, UAKinds.PURPOSE_PQCHAT, chat);
        _portable(g2, ua, UAKinds.PURPOSE_PQCHAT, chat);
        IUARegistry.UASig memory a = _single(0x0101, key, UAKinds.appPurpose(APP_A));
        vm.expectRevert(bytes(""));
        g1.requirePortableApp(ua, APP_A, TYPED, a);
        vm.expectRevert(bytes(""));
        g2.requirePortableApp(ua, APP_A, TYPED, a);
        // the same record on a gen 1 of this tree: accepted through gen 2
        bytes32 ua2 = _register(p, 0x0101, key);
        UARegistry g2p =
            _deploy(REG_G2, chainUidA, address(p), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        _app(g2p, ua2, APP_A, a);
    }

    /// The pre-change `UARegistry` (legacy/ua-pre-app/: its source and its libraries as of f655cb0e0, compiled with this build;
    /// owner 2026-11-18, no bytecode in the repository) deployed with `cfgs`, its libraries linked by forge: a gen 1 without
    /// `requirePortableApp` and without a fallback. Its creation code with the constructor arguments, so the arguments are this
    /// tree's `KindConfig` (the same struct at f655cb0e0).
    function _preApp(UARegistry.KindConfig[] memory cfgs) internal returns (UARegistry r) {
        bytes memory init = abi.encodePacked(
            type(UARegistryPreApp).creationCode,
            abi.encode(chainUidA, address(0), false, BUDGET, address(0), true, cfgs)
        );
        assembly ("memory-safe") {
            r := create(0, add(init, 32), mload(init))
        }
        assertTrue(address(r).code.length != 0, "pre-change registry deployed");
    }
}
