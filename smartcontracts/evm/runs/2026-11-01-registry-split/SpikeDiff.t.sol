// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryBase, MockWallet} from "./UARegistryBase.sol";
import {UACall} from "./UACall.sol";
import {GasMeter} from "./GroupFixtures.sol";

contract Create2er {
    function create(bytes32 salt, bytes memory init) external returns (address a) {
        assembly ("memory-safe") {
            a := create2(0, add(init, 32), mload(init), salt)
        }
        require(a != address(0), "create2");
    }
}

/// SPIKE, the same file in every variant, needs no signed vector (the stale typed vectors are the gap): a scripted scenario
/// on two generations with stand-in verifiers. `test_diff` logs a hash of the raw return bytes (or revert data) of every
/// view, and of every log, so the variants compare byte for byte; `test_gas` logs `register` and `requireAuthorized` per
/// kind; `test_deployGas` each deployment transaction (CREATE2 with a salt, as `DeployBase`).
contract SpikeDiffTest is UARegistryBase {
    address constant R1 = 0x5cA00000000000000000000000000000000000a1;
    address constant R2 = 0x5ca00000000000000000000000000000000000A2;
    address constant RG = 0x5ca00000000000000000000000000000000000a3;
    uint64 constant PQ = 1_000_000;
    uint256 constant ALICE = 0xA11CE;
    bytes32[] internal ids;
    GasMeter internal gm;

    function setUp() public override {
        super.setUp();
        gm = new GasMeter();
    }

    function _pk(uint16 kind, uint256 salt) internal pure returns (bytes memory pk) {
        uint256 len = kind == 0x0130 ? 1312 : kind == 0x0131 ? 1952 : kind == 0x0132 ? 897 : kind == 0x0133 ? 32 : 18_432;
        pk = new bytes(len);
        for (uint256 i; i < len; i += 32) {
            bytes32 w = keccak256(abi.encode(kind, salt, i));
            for (uint256 j; j < 32 && i + j < len; ++j) pk[i + j] = w[j];
        }
        if (kind == 0x0132) {
            pk[0] = 0x09;
            for (uint256 i = 1; i < len; ++i) pk[i] = 0;
        }
    }

    function _kemPk(uint256 salt) internal pure returns (bytes memory pk) {
        pk = new bytes(1601);
        for (uint256 i; i < 1601; i += 32) {
            bytes32 w = keccak256(abi.encode("kem", salt, i));
            for (uint256 j; j < 32 && i + j < 1601; ++j) pk[i + j] = w[j];
        }
        pk[0] = 0x01;
    }

    function _rows() internal view returns (uint16[] memory k, bytes[] memory d) {
        string memory j = _kindsJson();
        uint256[] memory all = abi.decode(vm.parseJson(j, ".valid[*].kind"), (uint256[]));
        k = new uint16[](all.length);
        d = new bytes[](all.length);
        uint256 n;
        for (uint256 i; i < all.length; ++i) {
            bool seen = all[i] == UAKinds.MSIG;
            for (uint256 m; m < n; ++m) seen = seen || k[m] == all[i];
            if (seen) continue;
            k[n] = uint16(all[i]);
            d[n++] = vm.parseJsonBytes(j, string.concat(".valid[", vm.toString(i), "].keyData"));
        }
        assembly ("memory-safe") {
            mstore(k, n)
            mstore(d, n)
        }
    }

    function _all(bool pqz) internal view returns (UARegistry.KindConfig[] memory c) {
        (uint16[] memory k,) = _rows();
        c = new UARegistry.KindConfig[](k.length + (pqz ? 1 : 0));
        for (uint256 i; i < k.length; ++i) {
            c[i] = UARegistry.KindConfig(k[i], address(mock), k[i] >= 0x0110 ? PQ : _cap(k[i]));
        }
        if (pqz) c[k.length] = UARegistry.KindConfig(0x0142, address(mock), PQ);
    }

    function _only0142() internal view returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0142, address(mock), PQ);
    }

    function _h(bytes memory pqzKey) internal pure returns (bytes32) {
        return UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqzKey);
    }

    function _kemHash(bytes32 ua, uint64 v, bytes memory kemPk) internal pure returns (bytes32) {
        return UAKinds.kemRecordHash(ua, v, kemPk);
    }

    /// A holder with a PQZ key (unproven) and a KEM key, full or by hash; the proof it could give.
    function _holderProof(uint16 kind, bytes32 ua, bytes memory pqzKey, bytes memory kem, bool commit)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 kh = commit ? UAKinds.kemRecordHash(ua, 0, 1, keccak256(kem)) : _kemHash(ua, 0, kem);
        bytes32 rec = UAKinds.portableRecordDigest(ua, kind, _h(pqzKey), kh);
        return _sig(pqzKey, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, rec));
    }

    function _holder(UARegistry r, uint16 kind, bytes memory pk, uint256 salt, bool commit)
        internal
        returns (bytes32 ua, bytes memory pqzPop)
    {
        bytes memory pqzKey = _pk(0x0142, salt);
        bytes memory kem = _kemPk(salt);
        ua = UAKinds.uaOf(kind, pk);
        pqzPop = _holderProof(kind, ua, pqzKey, kem, commit);
        IUARegistry.UAAttrs memory a = UACall.attrs(pqzKey, keccak256(pqzPop), kem);
        if (commit) a = UACall.commit(a);
        _regWith(r, kind, pk, a);
    }

    function _regWith(UARegistry r, uint16 kind, bytes memory pk, IUARegistry.UAAttrs memory a) internal {
        bytes memory pop = _pop(r, kind, pk, a);
        ids.push(UACall.register(IUARegistry(address(r)), kind, pk, a, pop, ""));
    }

    function _sigFor(bytes memory key, uint16 kind, bytes32 purpose, bytes32 digest) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = _sig(key, UAKinds.uaMessage(kind, purpose, digest));
    }

    /// An `msig` of an EOA and two PQ members, threshold 2: PQ-eligible, m-of-n PoP (native typed + derived).
    function _msig(UARegistry r, bytes memory ml, bytes memory fn) internal returns (bytes32 ua) {
        (bytes32 mlUa, bytes32 fnUa) = (UAKinds.uaOf(0x0130, ml), UAKinds.uaOf(0x0132, fn));
        Member[] memory m = new Member[](3);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(ALICE)), 1);
        m[1] = Member(0x0130, mlUa, 1);
        m[2] = Member(0x0132, fnUa, 1);
        bytes memory d = _msigKey(2, m);
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 rd = _regDigest(ua, UAKinds.MSIG);
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_POP_V2, rd);
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](2);
        s[0] = IUARegistry.MemberSig(_indexOf(d, _pad(vm.addr(ALICE))), "", _ecdsa(ALICE, rd));
        s[1] = IUARegistry.MemberSig(_indexOf(d, fnUa), "", _sig(fn, UAKinds.uaMessage(0x0132, UAKinds.PURPOSE_MEMBER, md)));
        if (s[0].index > s[1].index) (s[0], s[1]) = (s[1], s[0]);
        ids.push(r.registerMsig(UACall.structure(d), _none(), s, ""));
    }

    function _x(address r, string memory label, bytes memory data) internal {
        (bool ok, bytes memory ret) = r.staticcall(data);
        emit log_named_bytes32(string.concat(r == R1 ? "g1 " : "g2 ", label, ok ? " ok" : " revert"), keccak256(ret));
    }

    function _dump(address r) internal {
        for (uint256 i; i < ids.length; ++i) {
            bytes32 u = ids[i];
            string memory n = vm.toString(i);
            _x(r, string.concat(n, " recordOf"), abi.encodeCall(IUARegistry.recordOf, (u)));
            _x(r, string.concat(n, " registrationOf"), abi.encodeCall(IUARegistry.registrationOf, (u)));
            _x(r, string.concat(n, " popOf"), abi.encodeCall(IUARegistry.popOf, (u)));
            _x(r, string.concat(n, " msigOf"), abi.encodeCall(IUARegistry.msigOf, (u)));
            _x(r, string.concat(n, " webAuthnKeyOf"), abi.encodeCall(IUARegistry.webAuthnKeyOf, (u)));
            _x(r, string.concat(n, " muSig2KeyOf"), abi.encodeCall(IUARegistry.muSig2KeyOf, (u)));
            _x(r, string.concat(n, " frostKeyOf"), abi.encodeCall(IUARegistry.frostKeyOf, (u)));
            _x(r, string.concat(n, " pqzPopOf"), abi.encodeCall(IUARegistry.pqzPopOf, (u)));
            _x(r, string.concat(n, " pqzKeySigOf"), abi.encodeCall(IUARegistry.pqzKeySigOf, (u)));
            _x(r, string.concat(n, " pqzKeyOf"), abi.encodeCall(IUARegistry.pqzKeyOf, (u)));
            _x(r, string.concat(n, " checkedOf"), abi.encodeCall(IUARegistry.checkedOf, (u)));
            _x(r, string.concat(n, " kemKeyOf"), abi.encodeCall(IUARegistry.kemKeyOf, (u)));
            _x(r, string.concat(n, " kemKeyAt0"), abi.encodeCall(IUARegistry.kemKeyAt, (u, 0)));
            _x(r, string.concat(n, " kemKeyAt1"), abi.encodeCall(IUARegistry.kemKeyAt, (u, 1)));
            _x(r, string.concat(n, " keyOf"), abi.encodeCall(IUARegistry.keyOf, (u)));
            _x(r, string.concat(n, " uaIndex"), abi.encodeCall(IUARegistry.uaIndex, (u)));
            _x(r, string.concat(n, " expandedKeyOf"), abi.encodeCall(IUARegistry.expandedKeyOf, (u)));
            _x(r, string.concat(n, " kindOf"), abi.encodeCall(IUARegistry.kindOf, (u)));
            _x(r, string.concat(n, " isRegistered"), abi.encodeCall(IUARegistry.isRegistered, (u)));
        }
        _x(r, "unknown recordOf", abi.encodeCall(IUARegistry.recordOf, (bytes32(uint256(0xdead)))));
        _x(r, "unknown registrationOf", abi.encodeCall(IUARegistry.registrationOf, (bytes32(uint256(0xdead)))));
        _x(r, "unknown uaIndex", abi.encodeCall(IUARegistry.uaIndex, (bytes32(uint256(0xdead)))));
        (uint16[] memory k,) = _rows();
        for (uint256 i; i < k.length + 3; ++i) {
            uint16 c = i < k.length ? k[i] : [uint16(0x0120), 0x0142, 0x0777][i - k.length];
            string memory n = vm.toString(uint256(c));
            _x(r, string.concat(n, " uaCount"), abi.encodeCall(IUARegistry.uaCount, (c)));
            _x(r, string.concat(n, " uaAt0"), abi.encodeCall(IUARegistry.uaAt, (c, 0)));
            _x(r, string.concat(n, " uaAt9"), abi.encodeCall(IUARegistry.uaAt, (c, 9)));
            _x(r, string.concat(n, " uaPage"), abi.encodeCall(IUARegistry.uaPage, (c, 0, 5)));
            _x(r, string.concat(n, " kindName"), abi.encodeCall(IUARegistry.kindName, (c)));
            _x(r, string.concat(n, " kindEnabled"), abi.encodeCall(IUARegistry.kindEnabled, (c)));
            _x(r, string.concat(n, " verifyCap"), abi.encodeCall(IUARegistry.verifyCap, (c)));
        }
        (bytes32 a, bytes32 b, bytes32 c2) = (keccak256("a"), keccak256("b"), keccak256("c"));
        IUARegistry.KemKey memory kk = UACall.kem(_kemPk(7));
        _x(r, "uaOf", abi.encodeCall(IUARegistry.uaOf, (0x0101, _key(0x0101))));
        _x(r, "uaOf bad", abi.encodeCall(IUARegistry.uaOf, (0x0777, hex"00")));
        _x(r, "keyHashOf", abi.encodeCall(IUARegistry.keyHashOf, (0x0101, _key(0x0101))));
        _x(r, "uaMessage", abi.encodeCall(IUARegistry.uaMessage, (0x0101, a, b)));
        _x(r, "uaAuthDigest", abi.encodeCall(IUARegistry.uaAuthDigest, (a, b, c2)));
        _x(r, "portableDomainSeparator", abi.encodeCall(IUARegistry.portableDomainSeparator, ()));
        _x(r, "portableRecordDigest", abi.encodeCall(IUARegistry.portableRecordDigest, (a, 0x0130, b, c2)));
        _x(r, "registrationDigest", abi.encodeCall(IUARegistry.registrationDigest, (a, 0x0130, b, c2, a)));
        _x(r, "pqzKeyDigest", abi.encodeCall(IUARegistry.pqzKeyDigest, (a, b)));
        _x(r, "pqzKeyRecordDigest", abi.encodeCall(IUARegistry.pqzKeyRecordDigest, (a, b, c2)));
        _x(r, "kemRecordHash", abi.encodeCall(IUARegistry.kemRecordHash, (a, 3, kk)));
        _x(r, "kemRecordDigest", abi.encodeCall(IUARegistry.kemRecordDigest, (a, 3, kk)));
        _x(r, "eip712Domain", abi.encodeWithSignature("eip712Domain()"));
    }

    function _kk(Vm.Log[] memory l, string memory label) internal {
        for (uint256 i; i < l.length; ++i) {
            emit log_named_bytes32(string.concat(label, " log ", vm.toString(i)), keccak256(abi.encode(l[i].emitter, l[i].topics, l[i].data)));
        }
    }

    bytes32 internal h2;
    bytes internal proof2;

    function _gen1(UARegistry g1) internal {
        (uint16[] memory k, bytes[] memory d) = _rows();
        for (uint256 i; i < k.length; ++i) {
            ids.push(UACall.register(IUARegistry(R1), k[i], d[i], _none(), _pop(g1, k[i], d[i]), ""));
        }
    }

    function _attachments(UARegistry g1, bytes memory ml) internal {
        (bytes32 h1, bytes memory proof1) = _holder(g1, 0x0131, _pk(0x0131, 1), 1, false); // full KEM key, proof later
        (h2, proof2) = _holder(g1, 0x0130, _pk(0x0130, 2), 2, true); // committed KEM key
        g1.storePqzPop(h1, proof1);
        // setKemKey: fill version 0 of the commit, then a signed version 1
        g1.setKemKey(h2, 0, UACall.kem(_kemPk(2)), _noSig());
        bytes memory kem3 = _kemPk(3);
        g1.setKemKey(h2, 1, UACall.kem(kem3),
            _sigFor(_pk(0x0130, 2), 0x0130, UAKinds.PURPOSE_KEM, UAKinds.kemRecordDigest(h2, 1, kem3)));
        // setPqzKey on a record without a key
        bytes memory later = _pk(0x0142, 9);
        bytes32 mlUa = UAKinds.uaOf(0x0130, ml);
        g1.setPqzKey(mlUa, later, keccak256("later proof"), _sigFor(ml, 0x0130, UAKinds.PURPOSE_PQZ_KEY,
            UAKinds.pqzKeyRecordDigest(mlUa, _h(later), keccak256("later proof"))));
    }

    function test_diff() public {
        vm.recordLogs();
        UARegistry g1 = _deploy(R1, chainUidA, address(0), false, BUDGET, address(0), true, _all(false));
        _gen1(g1);
        (uint16[] memory k, bytes[] memory d) = _rows();
        bytes memory ml = _pk(0x0130, 11);
        ids.push(UACall.register(IUARegistry(R1), 0x0130, ml, _none(), _pop(g1, 0x0130, ml), ""));
        _attachments(g1, ml);
        bytes32 ms = _msig(g1, ml, _fnKey(k, d));
        // the msig's KEM record: members under `member` over the record (m-of-n, native typed)
        _msigKem(g1, ms, ml, _fnKey(k, d), _kemPk(5));
        _kk(vm.getRecordedLogs(), "g1");
        _dump(R1);

        // gen 2 with 0x0142 in front of gen 1 without: forwarded reads, its own attachment, an msig of gen-1 members
        vm.recordLogs();
        UARegistry g2 = _deploy(R2, chainUidA, R1, false, BUDGET, address(0), true, _only0142());
        g2.storePqzPop(h2, proof2);
        ids.push(_classicalMsig(g2));
        _kk(vm.getRecordedLogs(), "g2");
        _dump(R2);
    }

    function _noSig() internal pure returns (IUARegistry.UASig memory) {}

    function _fnKey(uint16[] memory k, bytes[] memory d) internal pure returns (bytes memory) {
        for (uint256 i; i < k.length; ++i) if (k[i] == 0x0132) return d[i];
        revert("no fndsa row");
    }

    function _msigKem(UARegistry r, bytes32 ms, bytes memory ml, bytes memory fn, bytes memory kem) internal {
        (bytes32 mlUa, bytes32 fnUa) = (UAKinds.uaOf(0x0130, ml), UAKinds.uaOf(0x0132, fn));
        (IUARegistry.MsigStructure memory st) = r.msigOf(ms);
        bytes32 rd = UAKinds.kemRecordDigest(ms, 1, kem);
        bytes32 md = _memberDigest(ms, UAKinds.PURPOSE_KEM, rd);
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](2);
        uint256 n;
        for (uint16 i; i < st.members.length; ++i) {
            if (st.members[i].id == mlUa) {
                s[n++] = IUARegistry.MemberSig(i, "", _sig(ml, UAKinds.uaMessage(0x0130, UAKinds.PURPOSE_MEMBER, md)));
            } else if (st.members[i].id == fnUa) {
                s[n++] = IUARegistry.MemberSig(i, "", _sig(fn, UAKinds.uaMessage(0x0132, UAKinds.PURPOSE_MEMBER, md)));
            }
        }
        IUARegistry.UASig memory sig;
        sig.members = s;
        r.setKemKey(ms, 1, UACall.kem(kem), sig);
    }

    function _classicalMsig(UARegistry g2) internal returns (bytes32) {
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(ALICE)), 1);
        m[1] = Member(0x0101, UAKinds.uaOf(0x0101, _key(0x0101)), 1);
        return g2.registerMsig(UACall.structure(_msigKey(2, m)), _none(), new IUARegistry.MemberSig[](0), "");
    }

    // ----- gas -----

    function _meter(UARegistry r, bytes32 ua, IUARegistry.UASig memory s, string memory label) internal {
        (bool ok,, uint256 used) =
            gm.measure(address(r), abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, s)));
        assertTrue(ok, label);
        emit log_named_uint(string.concat("gas requireAuthorized ", label), used);
    }

    function test_gas() public {
        UARegistry r = _deploy(RG, chainUidA, address(0), false, BUDGET, address(0), true, _all(false));
        _gasKinds(r);
        _gasNative(r);
        bytes32 mu = _gasMsig(r);
        _view(r, "kindOf", abi.encodeCall(IUARegistry.kindOf, (mu)));
        _view(r, "pqzKeyOf", abi.encodeCall(IUARegistry.pqzKeyOf, (mu)));
        _view(r, "chainUid", abi.encodeCall(IUARegistry.chainUid, ()));
        _view(r, "recordOf (off chain)", abi.encodeCall(IUARegistry.recordOf, (mu)));
    }

    function _view(UARegistry r, string memory label, bytes memory data) internal {
        (bool ok,, uint256 used) = gm.measure(address(r), data);
        assertTrue(ok, label);
        emit log_named_uint(string.concat("gas ", label), used);
    }

    function _gasKinds(UARegistry r) internal {
        (uint16[] memory k, bytes[] memory d) = _rows();
        for (uint256 i; i < k.length; ++i) {
            string memory n = vm.toString(uint256(k[i]));
            bytes memory pop = _pop(r, k[i], d[i]);
            bytes32 ua = UACall.register(IUARegistry(RG), k[i], d[i], _none(), pop, "");
            Vm.Gas memory g = vm.lastCallGas();
            emit log_named_uint(string.concat("gas register regular ", n), g.gasTotalUsed);
            emit log_named_int(string.concat("gas register state ", n), g.gasStateUsed);
            bytes memory key = r.keyOf(ua);
            IUARegistry.UASig memory s;
            if (key.length == 0) {
                s.keyData = d[i];
                key = d[i];
            }
            s.signature = _sig(key, UAKinds.uaMessage(k[i], UAKinds.PURPOSE_METATX, DIGEST));
            _meter(r, ua, s, n);
        }
    }

    function _gasNative(UARegistry r) internal {
        IUARegistry.UASig memory e;
        bytes32 alice = _pad(vm.addr(ALICE));
        e.signature = _ecdsa(ALICE, r.uaAuthDigest(alice, UAKinds.PURPOSE_METATX, DIGEST));
        _meter(r, alice, e, "native eoa");
        MockWallet w = new MockWallet(vm.addr(ALICE), 0, 0, RG);
        bytes32 wa = _pad(address(w));
        e.signature = _ecdsa(ALICE, r.uaAuthDigest(wa, UAKinds.PURPOSE_METATX, DIGEST));
        _meter(r, wa, e, "native 1271");
    }

    function _gasMsig(UARegistry r) internal returns (bytes32 mu) {
        bytes32 alice = _pad(vm.addr(ALICE));
        bytes32 p = UAKinds.uaOf(0x0101, _key(0x0101));
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, alice, 1);
        m[1] = Member(0x0101, p, 1);
        bytes memory ds = _msigKey(2, m);
        mu = r.registerMsig(UACall.structure(ds), _none(), new IUARegistry.MemberSig[](0), "");
        Vm.Gas memory gg = vm.lastCallGas();
        emit log_named_uint("gas registerMsig regular classical", gg.gasTotalUsed);
        emit log_named_int("gas registerMsig state classical", gg.gasStateUsed);
        bytes32 md = _memberDigest(mu, UAKinds.PURPOSE_METATX, DIGEST);
        IUARegistry.MemberSig[] memory s2 = new IUARegistry.MemberSig[](2);
        s2[_indexOf(ds, alice)] = IUARegistry.MemberSig(_indexOf(ds, alice), "",
            _ecdsa(ALICE, r.uaAuthDigest(alice, UAKinds.PURPOSE_MEMBER, md)));
        s2[_indexOf(ds, p)] = IUARegistry.MemberSig(_indexOf(ds, p), "",
            _sig(_key(0x0101), UAKinds.uaMessage(0x0101, UAKinds.PURPOSE_MEMBER, md)));
        IUARegistry.UASig memory sm;
        sm.members = s2;
        _meter(r, mu, sm, "msig 2-of-2");
    }

    /// `register` of a PQ holder with a PQZ key, a full KEM key and an `msig` PoP: the calldata-heavy paths.
    function test_gasHolder() public {
        UARegistry r = _deploy(RG, chainUidA, address(0), false, BUDGET, address(0), true, _all(true));
        bytes memory pk = _pk(0x0131, 1);
        bytes memory pqzKey = _pk(0x0142, 1);
        bytes memory kem = _kemPk(1);
        bytes32 ua = UAKinds.uaOf(0x0131, pk);
        bytes memory pqzPop = _holderProof(0x0131, ua, pqzKey, kem, false);
        IUARegistry.UAAttrs memory a = UACall.attrs(pqzKey, keccak256(pqzPop), kem);
        bytes memory pop = _pop(r, 0x0131, pk, a);
        r.register(0x0131, pk, a, pop, pqzPop);
        Vm.Gas memory g = vm.lastCallGas();
        emit log_named_uint("gas register regular holder mldsa65+pqz+kem", g.gasTotalUsed);
        emit log_named_int("gas register state holder mldsa65+pqz+kem", g.gasStateUsed);
    }

    function _lib(string memory art) internal returns (bool, uint256, int256) {
        try vm.getCode(art) returns (bytes memory init) {
            Create2er c = new Create2er();
            c.create(keccak256("scaas.deploy.v1"), init);
            Vm.Gas memory g = vm.lastCallGas();
            return (true, g.gasTotalUsed, g.gasStateUsed);
        } catch {
            return (false, 0, 0);
        }
    }

    function test_deployGas() public {
        Create2er c = new Create2er();
        UARegistry.KindConfig[] memory k = _all(true);
        bytes memory init = abi.encodePacked(type(UARegistry).creationCode,
            abi.encode(chainUidA, address(0), false, BUDGET, address(0), true, k));
        emit log_named_uint("deploy init bytes", init.length);
        c.create(keccak256("scaas.deploy.v1"), init);
        Vm.Gas memory g = vm.lastCallGas();
        emit log_named_uint("deploy UARegistry regular", g.gasTotalUsed);
        emit log_named_int("deploy UARegistry state", g.gasStateUsed);
        (bool ok, uint256 reg, int256 st) = _lib("UAViewLib.sol:UAViewLib");
        if (ok) {
            emit log_named_uint("deploy UAViewLib regular", reg);
            emit log_named_int("deploy UAViewLib state", st);
        }
        (ok, reg, st) = _lib("UARegisterLib.sol:UARegisterLib");
        if (ok) {
            emit log_named_uint("deploy UARegisterLib regular", reg);
            emit log_named_int("deploy UARegisterLib state", st);
        }
    }
}
