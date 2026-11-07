// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {P256Verifier} from "../../src/ua/verifiers/P256Verifier.sol";
import {Ed25519Verifier} from "../../src/ua/verifiers/Ed25519Verifier.sol";
import {UAFndsaVerifier} from "../../src/ua/FnDsa.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {UACall} from "./UACall.sol";

/// `smartcontracts/vectors/ua/nested.json` on the registry, real verifiers: every row a client reads, so a client and the chain give
/// one verdict (`clients/clientkeys/test/ua-nested.test.js`; spec `2026-11-02-msig-nested`).
contract UARegistryNestedVectorsTest is UARegistryBase {
    string internal j;
    UARegistry internal r;

    function setUp() public override {
        super.setUp();
        j = vm.readFile("../vectors/ua/nested.json");
        r = _registry(REG_A);
    }

    function _registry(address at) internal returns (UARegistry) {
        UARegistry.KindConfig[] memory base = _cfgs(address(mock));
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](base.length + 1);
        for (uint256 i; i < base.length; ++i) c[i] = base[i];
        c[1].verifier = address(new P256Verifier());
        c[2].verifier = address(new Ed25519Verifier());
        c[base.length] = UARegistry.KindConfig(UAKinds.FNDSA512, address(new UAFndsaVerifier(0x0132)), 2_500_000);
        return _deploy(at, chainUidA, address(0), false, BUDGET, address(0), true, c);
    }

    function _p(string memory section, uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".", section, "[", vm.toString(i), "]", field);
    }

    function _count(string memory path) internal view returns (uint256 n) {
        while (vm.keyExistsJson(j, string.concat(path, "[", vm.toString(n), "]"))) ++n;
    }

    function _bytes(string memory path) internal view returns (bytes memory) {
        return vm.parseJsonBytes(j, path);
    }

    function _attrs(string memory row) internal view returns (IUARegistry.UAAttrs memory) {
        return UACall.attrs(_bytes(string.concat(row, ".attrs.pqzKey")), vm.parseJsonBytes32(j, string.concat(row, ".attrs.pqzPopHash")),
            _bytes(string.concat(row, ".attrs.kemPk")));
    }

    /// The `registrations` or `afterAcceptance` row `name`.
    function _row(string memory name) internal view returns (string memory) {
        string[2] memory sections = ["registrations", "afterAcceptance"];
        for (uint256 k; k < 2; ++k) {
            for (uint256 i; i < _count(string.concat(".", sections[k])); ++i) {
                if (keccak256(bytes(vm.parseJsonString(j, _p(sections[k], i, ".name")))) == keccak256(bytes(name))) {
                    return _p(sections[k], i, "");
                }
            }
        }
        revert(string.concat("no row ", name));
    }

    function _uint16(string memory path) internal view returns (uint16) {
        return uint16(vm.parseJsonUint(j, path));
    }

    /// The typed `MemberSig` list at `path`, as a client's JSON holds it.
    function _typed(string memory path) internal view returns (IUARegistry.MemberSig[] memory s) {
        s = new IUARegistry.MemberSig[](_count(path));
        for (uint256 i; i < s.length; ++i) {
            string memory e = string.concat(path, "[", vm.toString(i), "]");
            s[i].index = _uint16(string.concat(e, ".index"));
            s[i].sig = _bytes(string.concat(e, ".sig"));
            s[i].members = _inner(string.concat(e, ".members"));
        }
    }

    function _inner(string memory path) internal view returns (IUARegistry.InnerSig[] memory l) {
        l = new IUARegistry.InnerSig[](_count(path));
        for (uint256 k; k < l.length; ++k) {
            string memory e = string.concat(path, "[", vm.toString(k), "]");
            l[k] = IUARegistry.InnerSig(_uint16(string.concat(e, ".index")), _bytes(string.concat(e, ".sig")));
        }
    }

    function _register(uint256 i) internal returns (bytes32 ua) {
        string memory row = _p("registrations", i, "");
        ua = UACall.register(r, _uint16(string.concat(row, ".kind")), _bytes(string.concat(row, ".keyData")), _attrs(row),
            _bytes(string.concat(row, ".pop")), _bytes(string.concat(row, ".pqzPop")));
    }

    /// Up to the row `last`, which this does not register (`""`: every row).
    function _registerUpTo(string memory last) internal {
        for (uint256 i; i < _count(".registrations"); ++i) {
            if (keccak256(bytes(vm.parseJsonString(j, _p("registrations", i, ".name")))) == keccak256(bytes(last))) return;
            _register(i);
        }
    }

    function test_nestedVectors_registrations() public {
        uint256 n = _count(".registrations");
        assertEq(n, 16);
        uint256 nestedRows;
        for (uint256 i; i < n; ++i) {
            string memory row = _p("registrations", i, "");
            bytes32 want = vm.parseJsonBytes32(j, string.concat(row, ".ua"));
            assertEq(_register(i), want, row);
            if (_uint16(string.concat(row, ".kind")) != UAKinds.MSIG) continue;
            bytes memory pop = _bytes(string.concat(row, ".pop"));
            assertEq(r.popOf(want), pop.length == 0 ? bytes("") : abi.encodePacked(keccak256(pop)), "an msig keeps keccak256(pop)");
            assertEq(_memberSigHashes(row, want), pop.length == 0 ? 0 : UACall.memberSigs(pop).length, "a hash per slot of the pop");
            string memory digests = string.concat(row, ".innerDigests");
            for (uint256 d; d < _count(digests); ++d) {
                string memory e = string.concat(digests, "[", vm.toString(d), "]");
                bytes32 md = vm.parseJsonBytes32(j, string.concat(row, ".memberDigest"));
                bytes32 inner = vm.parseJsonBytes32(j, string.concat(e, ".inner"));
                assertEq(UAKinds.memberDigest(inner, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBER, md)),
                    vm.parseJsonBytes32(j, string.concat(e, ".memberDigest")));
                ++nestedRows;
            }
        }
        assertEq(nestedRows, 7, "an inner of each nested row, two in msig-nested-twice");
    }

    /// The row's `memberSigHashes`, each equal to `r`'s `memberSigHashOf(ua, index)`; their count.
    function _memberSigHashes(string memory row, bytes32 ua) internal view returns (uint256 nh) {
        string memory hs = string.concat(row, ".memberSigHashes");
        nh = _count(hs);
        for (uint256 h; h < nh; ++h) {
            string memory e = string.concat(hs, "[", vm.toString(h), "]");
            assertEq(r.memberSigHashOf(ua, _uint16(string.concat(e, ".index"))), vm.parseJsonBytes32(j, string.concat(e, ".hash")), e);
        }
    }

    function test_nestedVectors_typedPopIsTheBlob() public view {
        uint256 pops;
        for (uint256 i; i < _count(".registrations"); ++i) {
            string memory row = _p("registrations", i, "");
            if (_uint16(string.concat(row, ".kind")) != UAKinds.MSIG || _bytes(string.concat(row, ".pop")).length == 0) continue;
            assertEq(abi.encode(_typed(string.concat(row, ".args.pop"))), _bytes(string.concat(row, ".pop")), row);
            ++pops;
        }
        for (uint256 i; i < _count(".negatives"); ++i) {
            assertEq(abi.encode(_typed(_p("negatives", i, ".popTyped"))), _bytes(_p("negatives", i, ".pop")));
        }
        assertEq(pops, 9);
    }

    function test_nestedVectors_records() public {
        _registerUpTo("");
        string memory k = _p("kemRecords", 0, "");
        bytes32 ua = vm.parseJsonBytes32(j, string.concat(k, ".ua"));
        bytes memory kemPk = _bytes(string.concat(k, ".kemPk"));
        r.setKemKey(ua, 1, UACall.kem(kemPk), _sigOf(string.concat(k, ".args.sig")));
        (IUARegistry.KemKey memory got, bytes memory sig) = r.kemKeyAt(ua, 1);
        assertEq(UACall.kemPk(got), kemPk);
        assertEq(sig, _bytes(string.concat(k, ".sig")), "stored as abi.encode(members)");
        uint256 n = _count(".pqzKeyRecords");
        assertEq(n, 4);
        bool ran;
        for (uint256 i; i < n; ++i) {
            string memory p = _p("pqzKeyRecords", i, "");
            if (keccak256(bytes(vm.parseJsonString(j, string.concat(p, ".set")))) != keccak256(bytes(PqzSet.NAME))) continue;
            bytes32 u = vm.parseJsonBytes32(j, string.concat(p, ".ua"));
            r.setPqzKey(u, 0, _bytes(string.concat(p, ".pqzKey")), vm.parseJsonBytes32(j, string.concat(p, ".pqzPopHash")),
                _sigOf(string.concat(p, ".args.sig")));
            assertEq(r.pqzKeySigOf(u, 0), _bytes(string.concat(p, ".sig")));
            ran = true;
        }
        assertTrue(ran, "this set's row");
    }

    function _sigOf(string memory path) internal view returns (IUARegistry.UASig memory s) {
        s.keyData = _bytes(string.concat(path, ".keyData"));
        s.signature = _bytes(string.concat(path, ".signature"));
        s.members = _typed(string.concat(path, ".members"));
    }

    /// In the row order: the inner's own signer first, then its slot in the outer by its accepted threshold.
    function test_nestedVectors_memberships() public {
        _registerUpTo("");
        uint256 n = _count(".memberships");
        assertEq(n, 4);
        for (uint256 i; i < n; ++i) {
            string memory m = _p("memberships", i, "");
            bytes32 ua = vm.parseJsonBytes32(j, string.concat(m, ".ua"));
            uint16 index = _uint16(string.concat(m, ".index"));
            IUARegistry.MemberSig memory s = IUARegistry.MemberSig(index, _inner(string.concat(m, ".members")), _bytes(string.concat(m, ".sig")));
            assertFalse(r.memberAccepted(ua, index));
            if (s.members.length != 0) {
                IUARegistry.MemberSig memory bad = IUARegistry.MemberSig(index, s.members, hex"01");
                vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
                r.acceptMembership(ua, bad);
            }
            bytes memory stored = _bytes(string.concat(m, ".stored"));
            bytes32 storedHash = vm.parseJsonBytes32(j, string.concat(m, ".storedHash"));
            assertEq(keccak256(stored), storedHash, "storedHash");
            vm.expectEmit(address(r));
            emit IUARegistry.UAMemberSig(ua, vm.parseJsonBytes32(j, string.concat(m, ".member")), index, UAKinds.PURPOSE_MEMBERSHIP, stored);
            r.acceptMembership(ua, s);
            assertTrue(r.memberAccepted(ua, index));
            assertEq(r.memberSigHashOf(ua, index), storedHash);
        }
    }

    /// CTR-UA-37: on a second registry the row's `pop` is refused until each acceptance is replayed from the first's events, checked against
    /// its kept hash, then the same bytes register, with no new signature.
    function test_nestedVectors_copyReplaysTheAcceptance() public {
        vm.pauseGasMetering(); // a 700 KB JSON string per cheatcode call
        _registerUpTo("");
        vm.recordLogs();
        for (uint256 i; i < _count(".memberships"); ++i) _accept(new Vm.Log[](0), r, r, i);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        string memory row = ".afterAcceptance[0]";
        IUARegistry.MsigStructure memory st = UACall.structure(_bytes(string.concat(row, ".keyData")));
        IUARegistry.MemberSig[] memory pop = _typed(string.concat(row, ".args.pop"));
        bytes32 ua = r.registerMsig(st, _none(), pop, "");
        assertEq(ua, vm.parseJsonBytes32(j, string.concat(row, ".ua")));
        assertEq(abi.encode(pop), _bytes(string.concat(row, ".pop")));
        assertGt(_memberSigHashes(row, ua), 0, "afterAcceptance: its memberSigHashes on the chain");

        UARegistry first = r;
        r = _registry(address(0x5cb0));
        _registerUpTo("");
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.registerMsig(st, _none(), pop, "");
        for (uint256 i; i < _count(".memberships"); ++i) _accept(logs, first, r, i);
        assertEq(r.registerMsig(st, _none(), pop, ""), ua);
        assertEq(r.popOf(ua), first.popOf(ua));
        _memberSigHashes(row, ua);
    }

    /// Row `i` of `memberships` on `to`, read back from `from`'s events (`logs`) and hash only.
    function _accept(Vm.Log[] memory logs, UARegistry from, UARegistry to, uint256 i) internal {
        string memory m = _p("memberships", i, "");
        bytes32 ua = vm.parseJsonBytes32(j, string.concat(m, ".ua"));
        uint16 index = _uint16(string.concat(m, ".index"));
        if (from == to) {
            to.acceptMembership(ua, IUARegistry.MemberSig(index, _inner(string.concat(m, ".members")), _bytes(string.concat(m, ".sig"))));
            return;
        }
        bytes memory stored = _acceptedSig(logs, from, ua, index);
        if (from.msigOf(ua).members[index].kind == UAKinds.MSIG) {
            to.acceptMembership(ua, IUARegistry.MemberSig(index, abi.decode(stored, (IUARegistry.InnerSig[])), ""));
        } else {
            to.acceptMembership(ua, IUARegistry.MemberSig(index, new IUARegistry.InnerSig[](0), stored));
        }
    }

    function test_nestedVectors_authorizations() public {
        _registerUpTo("");
        uint256 n = _count(".authorizations");
        assertEq(n, 5);
        uint256 valid;
        for (uint256 i; i < n; ++i) {
            string memory a = _p("authorizations", i, "");
            bytes32 ua = vm.parseJsonBytes32(j, string.concat(a, ".ua"));
            bytes32 purpose = vm.parseJsonBytes32(j, string.concat(a, ".purposeTag"));
            bytes32 digest = vm.parseJsonBytes32(j, string.concat(a, ".digest"));
            IUARegistry.UASig memory s = _sigOf(string.concat(a, ".uaSig"));
            assertEq(abi.encode(s.members), _bytes(string.concat(a, ".sig")));
            if (vm.parseJsonBool(j, string.concat(a, ".valid"))) {
                r.requireAuthorized(ua, purpose, digest, s);
                ++valid;
            } else {
                vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
                r.requireAuthorized(ua, purpose, digest, s);
            }
        }
        assertEq(valid, 1);
    }

    /// Each row names a record whose members are registered and which is not itself: the first nested row and every row after it, or
    /// afterAcceptance's, whose own pop is refused here because no memberships row has run (inner-slot-not-accepted).
    function test_nestedVectors_negatives() public {
        vm.pauseGasMetering(); // a 700 KB JSON string per cheatcode call; a verdict test, not a gas test
        _registerUpTo("msig-nested-pq");
        uint256 n = _count(".negatives");
        assertEq(n, 13);
        for (uint256 i; i < n; ++i) {
            string memory neg = _p("negatives", i, "");
            string memory row = _row(vm.parseJsonString(j, string.concat(neg, ".row")));
            assertFalse(r.isRegistered(vm.parseJsonBytes32(j, string.concat(row, ".ua"))), "a negative's row is not registered yet");
            assertEq(vm.parseJsonString(j, string.concat(neg, ".error")), "UAPoP");
            IUARegistry.MsigStructure memory s = UACall.structure(_bytes(string.concat(row, ".keyData")));
            vm.expectRevert(IUARegistry.UAPoP.selector);
            r.registerMsig(s, _attrs(row), _typed(string.concat(neg, ".popTyped")), "");
        }
    }

    function test_nestedVectors_structures() public {
        _registerUpTo("");
        uint256 n = _count(".structures");
        assertEq(n, 2);
        for (uint256 i; i < n; ++i) {
            string memory s = _p("structures", i, "");
            bytes32 member = vm.parseJsonBytes32(j, string.concat(s, ".member"));
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, member));
            UACall.register(r, UAKinds.MSIG, _bytes(string.concat(s, ".keyData")), _none(), "", "");
        }
    }

    /// A holder passes the holder check and stops at the signature, a classical-dominant `msig` at the holder check.
    function test_nestedVectors_eligibility() public {
        _registerUpTo("");
        uint256 n = _count(".eligibility");
        assertEq(n, 3);
        IUARegistry.KemKey memory kem = UACall.kem(_bytes(_p("kemRecords", 0, ".kemPk")));
        for (uint256 i; i < n; ++i) {
            string memory e = _p("eligibility", i, "");
            bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, _bytes(string.concat(e, ".keyData")));
            bool eligible = vm.parseJsonBool(j, string.concat(e, ".eligible"));
            vm.expectRevert(abi.encodeWithSelector(eligible ? IUARegistry.UAUnauthorized.selector : IUARegistry.UAKemHolder.selector, ua));
            r.setKemKey(ua, 2, kem, IUARegistry.UASig("", "", new IUARegistry.MemberSig[](0)));
        }
    }
}
