// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {ComplianceRegistry} from "../../src/regulated/ComplianceRegistry.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {UACall} from "../ua/UACall.sol";
import {UARegistryBase} from "../ua/UARegistryBase.sol";
import {RegFixture} from "./helpers/RegFixture.sol";
import {Catalogue, plainEnv, regArgs} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// The registry's admin and KYC-provider ABI (spec 2026-11-10-admin-not-owner.md §4.1-§4.3, §5.3, §5.3.1), written out here
/// so the test pins it apart from the source's declarations (and compiles against the registry before T6: the red run).
interface IRegistryAdmin {
    event AdminTransferStarted(bytes32 indexed previousAdmin, bytes32 indexed newAdmin);
    event AdminTransferred(bytes32 indexed previousAdmin, bytes32 indexed newAdmin);
    event KycProviderSet(bytes32 indexed provider, uint32 indexed providerId, bool enabled);
    event ComplianceSet(bytes32 indexed account, uint64 flags, uint64 validUntil, uint32 indexed providerId);

    error NotAdmin(bytes32 caller);
    error NotPendingAdmin(bytes32 caller);
    error AdminZero();
    error AdminUnreachable(bytes32 admin);
    error RouterNotContract(address govRouter);
    error NotKycProvider();
    error KycProviderZero();
    error TooManyRows(uint256 n);
    error LengthMismatch();
    error EligibleContractAdminOnly();
    error AdminWrittenSlot(bytes32 account);
    /// `RegulatedLib.init` (spec §5.3, Fable P1-1).
    error ComplianceRegistryRouterMismatch(address complianceRegistry, address got);

    function admin() external view returns (bytes32);
    function pendingAdmin() external view returns (bytes32);
    function govRouter() external view returns (address);
    function transferAdmin(bytes32 newAdmin) external;
    function acceptAdmin() external;
    function setKycProvider(bytes32 provider, bool enabled) external;
    function kycProviderId(bytes32 provider) external view returns (uint32);
    function kycProviderEnabled(uint32 id) external view returns (bool);
    function setCompliance(bytes32[] calldata accounts, uint64[] calldata flags, uint64[] calldata until) external;
    function complianceOf(bytes32 account) external view returns (uint64 flags, uint64 validUntil, uint32 providerId);
    function hasFlags(bytes32 account, uint64 required, uint64 denied) external view returns (bool);
}

/// A stand-in for the chain's router (T6; T7 adds the real router's `mtxSetKycProvider` / `mtxSetCompliance`): it names
/// `chainUid()` (a factory's `configureChain`) and answers `subject()` with the UA it is told to act for, to its live target
/// only, as `GovernanceRouter.subject()` does. It checks no signature. Not a registry's `govRouter`, it is the fake router
/// of §8 (a contract answering `subject() = admin`).
contract RegistryTestRouter {
    bytes32 public immutable chainUid;
    address public immutable registry; // a factory's `configureChain` reads it and its `smartKeyCloneHash()` (spec §13.3)
    bytes32 private _subject;
    address private _target;

    constructor(bytes32 uid, address registry_) {
        (chainUid, registry) = (uid, registry_);
    }

    function smartKeyCloneHash() external view returns (bytes32) {
        return IUARegistry(registry).smartKeyCloneHash();
    }

    function subject() external view returns (bytes32) {
        return msg.sender == _target ? _subject : bytes32(0);
    }

    function exec(bytes32 s, address target, bytes calldata data) external {
        (_subject, _target) = (s, target);
        (bool ok, bytes memory ret) = target.call(data);
        (_subject, _target) = (bytes32(0), address(0));
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }
}

/// Shared by the two suites: the registry by CREATE (a refused constructor returns its revert data) and the calls.
abstract contract RegistryCalls {
    function _create(bytes32 admin_, address router_) internal returns (address a, bytes memory err) {
        bytes memory code = abi.encodePacked(type(ComplianceRegistry).creationCode, abi.encode(admin_, router_));
        assembly ("memory-safe") {
            a := create(0, add(code, 32), mload(code))
            if iszero(a) {
                err := mload(0x40)
                mstore(err, returndatasize())
                returndatacopy(add(err, 32), 0, returndatasize())
                mstore(0x40, add(add(err, 32), returndatasize()))
            }
        }
    }

    function _reg(bytes32 admin_, address router_) internal returns (IRegistryAdmin c) {
        (address a,) = _create(admin_, router_);
        require(a != address(0), "registry not created");
        c = IRegistryAdmin(a);
    }

    /// `setCompliance` of one row.
    function _row(bytes32 account, uint64 flags, uint64 until) internal pure returns (bytes memory) {
        bytes32[] memory a = new bytes32[](1);
        uint64[] memory f = new uint64[](1);
        uint64[] memory u = new uint64[](1);
        (a[0], f[0], u[0]) = (account, flags, until);
        return abi.encodeCall(IRegistryAdmin.setCompliance, (a, f, u));
    }
}

/// `ComplianceRegistry`'s UA admin and its KYC providers (round 3r, CTR-GOV-23; spec §5.1, §5.3, §5.3.1, §8): the constructor
/// (`AdminZero`, `AdminUnreachable`, `RouterNotContract`; any UA, an EOA too), the admin and the router written once, every
/// admin op `onlyAdmin` (direct as the native id, or the registry's router's `subject()`), the two-step transfer, no
/// renounce; the KYC provider a UA id, `setCompliance` by the admin (id 0) or an enabled provider (its id), at most 256 rows;
/// every row rule kept; one runtime for every admin and router (F-11). The accept and transfer rows run through the real
/// `GovernanceRouter` over the registry with derived secp256k1, mldsa44 and an `msig` of three mldsa44 at 2-of-3 (the
/// stand-in verifier of `UARegistryBase`); `setKycProvider` / `setCompliance` through a router use `RegistryTestRouter` (T7
/// builds those router ops). **UNAUDITED.**
contract RegistryAdminTest is UARegistryBase, RegistryCalls {
    uint16 constant ML44 = 0x0130;
    uint16 constant K1 = 0x0108;
    uint64 constant CAP = 4_250_000;
    address constant PREG = 0x5CA00000000000000000000000000000000000A5;
    address constant RELAYER = address(0xBEEF);
    address constant STRANGER = address(0x5757);
    uint64 constant MAX = type(uint64).max;
    uint64 constant KYC = 1;
    uint64 constant ELIGIBLE = 8;
    bytes32 constant ACC = bytes32(uint256(0xACC));
    string constant TAIL =
        ",uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

    address admin = makeAddr("admin");
    address next = makeAddr("next");
    address prov = makeAddr("provider");
    UARegistry preg;
    GovernanceRouter router;
    RegistryTestRouter trouter;
    bytes k1Key;
    bytes32 k1;
    bytes mlKey;
    bytes32 ml;
    bytes32 mlProv; // an mldsa44 KYC provider
    bytes[3] mkeys;
    bytes msigData;
    bytes32 msig;

    function setUp() public override {
        super.setUp();
        vm.warp(1_800_000_000);
        preg = _deploy(PREG, chainUidA, address(0), false, BUDGET, address(0), true, _kinds());
        router = new GovernanceRouter(chainUidA, PREG, address(0), false);
        trouter = new RegistryTestRouter(chainUidA, PREG);
        k1Key = _k1Key();
        k1 = _register(preg, K1, k1Key);
        mlKey = _ml(1);
        ml = _register(preg, ML44, mlKey);
        mlProv = _register(preg, ML44, _ml(2));
        Member[] memory m = new Member[](3);
        for (uint256 i; i < 3; ++i) {
            mkeys[i] = _ml(10 + i);
            m[i] = Member(ML44, _register(preg, ML44, mkeys[i]), 1);
        }
        msigData = _msigKey(2, m);
        bytes32 id = UAKinds.uaOf(UAKinds.MSIG, msigData);
        msig = UACall.register(preg, UAKinds.MSIG, msigData, _none(),
            abi.encode(_memberSigs(id, UAKinds.PURPOSE_POP_V2, _regDigest(id, UAKinds.MSIG), 2)), "");
        for (uint256 i; i < 3; ++i) preg.acceptMembership(msig, _acceptKeySig(msigData, ML44, mkeys[i]));
    }

    // ------------------------------------------------------------------ fixture

    function _kinds() internal view returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](2);
        c[0] = UARegistry.KindConfig(K1, address(mock), 50_000);
        c[1] = UARegistry.KindConfig(ML44, address(mock), CAP);
    }

    function _k1Key() internal returns (bytes memory) {
        Vm.Wallet memory w = vm.createWallet("k1 signer");
        return abi.encodePacked(w.publicKeyX, w.publicKeyY);
    }

    /// An mldsa44 public key of the right length (the stand-in verifier reads no structure).
    function _ml(uint256 salt) internal pure returns (bytes memory pk) {
        pk = new bytes(1312);
        for (uint256 i; i < 1312; i += 32) {
            bytes32 w = keccak256(abi.encode(ML44, salt, i));
            for (uint256 j; j < 32 && i + j < 1312; ++j) pk[i + j] = w[j];
        }
    }

    /// `from` calls `to` with `cd`; a revert is bubbled.
    function _call(address from, address to, bytes memory cd) internal {
        vm.prank(from);
        (bool ok, bytes memory ret) = to.call(cd);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    /// `from` calls `to` with `cd`, which must revert with exactly `err`.
    function _refused(address from, address to, bytes memory cd, bytes memory err) internal {
        vm.prank(from);
        (bool ok, bytes memory ret) = to.call(cd);
        assertFalse(ok, "refused");
        assertEq(ret, err);
    }

    /// `r` acts for `s` on `c` with `cd`.
    function _via(RegistryTestRouter r, bytes32 s, IRegistryAdmin c, bytes memory cd) internal {
        _call(RELAYER, address(r), abi.encodeCall(RegistryTestRouter.exec, (s, address(c), cd)));
    }

    function _viaRefused(RegistryTestRouter r, bytes32 s, IRegistryAdmin c, bytes memory cd, bytes memory err) internal {
        _refused(RELAYER, address(r), abi.encodeCall(RegistryTestRouter.exec, (s, address(c), cd)), err);
    }

    function _notAdmin(bytes32 c) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IRegistryAdmin.NotAdmin.selector, c);
    }

    function _notPending(bytes32 c) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IRegistryAdmin.NotPendingAdmin.selector, c);
    }

    function _notProvider() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IRegistryAdmin.NotKycProvider.selector);
    }

    function _enable(bytes32 p, bool on) internal pure returns (bytes memory) {
        return abi.encodeCall(IRegistryAdmin.setKycProvider, (p, on));
    }

    function _xfer(bytes32 to) internal pure returns (bytes memory) {
        return abi.encodeCall(IRegistryAdmin.transferAdmin, (to));
    }

    function _accept() internal pure returns (bytes memory) {
        return abi.encodeCall(IRegistryAdmin.acceptAdmin, ());
    }

    function _rowOf(IRegistryAdmin c, bytes32 a) internal view returns (uint64 f, uint64 u, uint32 id) {
        (f, u, id) = c.complianceOf(a);
    }

    // ------------------------------------------------------------------ the real router: signing

    function _domain(GovernanceRouter r) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) = r.eip712Domain();
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying, salt));
    }

    function _env(GovernanceRouter r, bytes32 from) internal view returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(from, 0, r.mtxNonce(from, 0), block.timestamp + 1 hours, 0, address(0), 0, address(0));
    }

    /// The digest of `UA<op>(bytes32 from,address target<params>,E)` over `words` in `r`'s domain.
    function _digest(GovernanceRouter r, string memory op, string memory params, MetaTxLib.UAEnvelope memory e,
        address target, bytes memory words) internal view returns (bytes32)
    {
        bytes32 th = keccak256(bytes(string.concat("UA", op, "(bytes32 from,address target", params, TAIL)));
        bytes32 h = keccak256(bytes.concat(abi.encode(th, e.from, target), words,
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        return keccak256(abi.encodePacked("\x19\x01", _domain(r), h));
    }

    function _auth(bytes32 id, bytes32 d) internal view returns (IUARegistry.UASig memory a) {
        if (id == k1) (a.keyData, a.signature) = (k1Key, _sig(k1Key, UAKinds.uaMessage(K1, UAKinds.PURPOSE_METATX, d)));
        else if (id == ml) a.signature = _sig(mlKey, UAKinds.uaMessage(ML44, UAKinds.PURPOSE_METATX, d));
        else if (id == msig) a.members = _memberSigs(msig, UAKinds.PURPOSE_METATX, d, 2);
        else revert("no signer");
    }

    /// Slots 0..n-1 of the `msig` (index order), each over `(purpose, digest)` under `PURPOSE_MEMBER`.
    function _memberSigs(bytes32 ua, bytes32 purpose, bytes32 digest, uint256 n)
        internal view returns (IUARegistry.MemberSig[] memory s)
    {
        s = new IUARegistry.MemberSig[](n);
        bytes32 md = _memberDigest(ua, purpose, digest);
        for (uint16 i; i < n; ++i) {
            for (uint256 j; j < 3; ++j) {
                if (_indexOf(msigData, UAKinds.uaOf(ML44, mkeys[j])) != i) continue;
                s[i] = IUARegistry.MemberSig(i, new IUARegistry.InnerSig[](0),
                    _sig(mkeys[j], UAKinds.uaMessage(ML44, UAKinds.PURPOSE_MEMBER, md)));
            }
        }
    }

    /// `by`'s signed `mtxAcceptAdmin` of `target` on router `r` (sent by a stranger relayer, fee 0).
    function _acceptCd(GovernanceRouter r, bytes32 by, address target) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _env(r, by);
        return abi.encodeCall(r.mtxAcceptAdmin, (e, target, _auth(by, _digest(r, "AcceptAdmin", "", e, target, ""))));
    }

    function _transferCd(bytes32 by, address target, bytes32 to) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _env(router, by);
        IUARegistry.UASig memory a =
            _auth(by, _digest(router, "TransferAdmin", ",bytes32 newAdmin", e, target, abi.encode(to)));
        return abi.encodeCall(router.mtxTransferAdmin, (e, target, to, a));
    }

    function _renounceCd(bytes32 by, address target) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _env(router, by);
        return abi.encodeCall(router.mtxRenounceAdmin, (e, target, _auth(by, _digest(router, "RenounceAdmin", "", e, target, ""))));
    }

    // ------------------------------------------------------------------ the ABI (§4.2, §4.3)

    /// The selectors and topics of spec §4.2 / §4.3 (recomputed there with `cast`), on this test's declarations.
    function test_selectorsAreTheSpecs() public pure {
        assertEq(IRegistryAdmin.setKycProvider.selector, bytes4(0x105b99c7));
        assertEq(IRegistryAdmin.kycProviderId.selector, bytes4(0x2d4138d7));
        assertEq(IRegistryAdmin.kycProviderEnabled.selector, bytes4(0xbbc8fe54));
        assertEq(IRegistryAdmin.setCompliance.selector, bytes4(0x7fa569a5));
        assertEq(IRegistryAdmin.complianceOf.selector, bytes4(0x996ee3f2));
        assertEq(IRegistryAdmin.NotKycProvider.selector, bytes4(0x3f153a68));
        assertEq(IRegistryAdmin.KycProviderZero.selector, bytes4(0x42a1ea7f));
        assertEq(IRegistryAdmin.NotAdmin.selector, bytes4(0xba963c12));
        assertEq(IRegistryAdmin.ComplianceRegistryRouterMismatch.selector, bytes4(0x6c36f6ee));
        assertEq(bytes4(IRegistryAdmin.KycProviderSet.selector), bytes4(0xa2ead380));
        assertEq(bytes4(IRegistryAdmin.ComplianceSet.selector), bytes4(0xe6da38c5));
    }

    // ------------------------------------------------------------------ the constructor (§5.3)

    /// M21: 0 is refused (`AdminZero`); a derived admin with no router (`AdminUnreachable`), a router without code
    /// (`RouterNotContract`), each after its control: any UA with a reachable path is taken, an EOA too (no
    /// `AdminNotContract`), and `AdminTransferred(0, admin)` is emitted.
    function test_constructor_refusals() public {
        address noCode = address(0xDEAD);
        bytes32 high = bytes32(uint256(1) << 160);
        (address a, bytes memory err) = _create(bytes32(0), address(0));
        assertEq(a, address(0));
        assertEq(err, abi.encodeWithSelector(IRegistryAdmin.AdminZero.selector));
        (a, err) = _create(bytes32(0), address(router));
        assertEq(err, abi.encodeWithSelector(IRegistryAdmin.AdminZero.selector));
        bytes32[3] memory derived = [ml, msig, high];
        for (uint256 i; i < 3; ++i) {
            (a, err) = _create(derived[i], address(0));
            assertEq(a, address(0));
            assertEq(err, abi.encodeWithSelector(IRegistryAdmin.AdminUnreachable.selector, derived[i]));
            (a,) = _create(derived[i], address(router)); // the control: reachable through the router
            assertEq(IRegistryAdmin(a).admin(), derived[i]);
        }
        (a, err) = _create(nid(admin), noCode);
        assertEq(a, address(0));
        assertEq(err, abi.encodeWithSelector(IRegistryAdmin.RouterNotContract.selector, noCode));
        (a, err) = _create(ml, noCode);
        assertEq(err, abi.encodeWithSelector(IRegistryAdmin.RouterNotContract.selector, noCode));
        // the controls: a native EOA with no router, a contract with a router
        address next_ = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectEmit(true, true, true, true, next_);
        emit IRegistryAdmin.AdminTransferred(bytes32(0), nid(admin));
        IRegistryAdmin c = _reg(nid(admin), address(0));
        assertEq(address(c), next_);
        assertEq(admin.code.length, 0, "an EOA admin");
        assertEq(c.admin(), nid(admin));
        assertEq(c.pendingAdmin(), bytes32(0));
        assertEq(c.govRouter(), address(0));
        c = _reg(nid(address(trouter)), address(router));
        assertEq(c.admin(), nid(address(trouter)));
        assertEq(c.govRouter(), address(router));
    }

    /// F-11's positive control: every registry has one runtime (the admin and the router in storage), the code hash of
    /// `type(ComplianceRegistry).runtimeCode`, whatever the admin and the router.
    function test_codeHash_oneRuntime() public {
        bytes32 h = keccak256(type(ComplianceRegistry).runtimeCode);
        IRegistryAdmin a = _reg(nid(admin), address(0));
        IRegistryAdmin b = _reg(msig, address(router));
        IRegistryAdmin c = _reg(nid(next), address(trouter));
        assertEq(address(a).codehash, h);
        assertEq(address(b).codehash, h, "another admin and router");
        assertEq(address(c).codehash, h, "a third");
    }

    // ------------------------------------------------------------------ the direct native admin (§8)

    /// Every op directly by the native admin: a KYC provider enabled and disabled, an admin row (`ELIGIBLE_CONTRACT`), the
    /// two-step transfer; then the old admin is no one.
    function test_directAdmin_everyOp() public {
        IRegistryAdmin c = _reg(nid(admin), address(trouter));
        vm.expectEmit(true, true, true, true, address(c));
        emit IRegistryAdmin.KycProviderSet(nid(prov), 1, true);
        _call(admin, address(c), _enable(nid(prov), true));
        assertEq(c.kycProviderId(nid(prov)), 1);
        assertTrue(c.kycProviderEnabled(1));
        vm.expectEmit(true, true, true, true, address(c));
        emit IRegistryAdmin.ComplianceSet(ACC, ELIGIBLE, MAX, 0);
        _call(admin, address(c), _row(ACC, ELIGIBLE, MAX));
        (uint64 f, uint64 u, uint32 id) = _rowOf(c, ACC);
        assertEq(f, ELIGIBLE);
        assertEq(u, MAX);
        assertEq(id, 0, "the admin's row");
        _call(admin, address(c), _enable(nid(prov), false));
        assertFalse(c.kycProviderEnabled(1));
        vm.expectEmit(true, true, true, true, address(c));
        emit IRegistryAdmin.AdminTransferStarted(nid(admin), nid(next));
        _call(admin, address(c), _xfer(nid(next)));
        assertEq(c.admin(), nid(admin), "two steps");
        assertEq(c.pendingAdmin(), nid(next));
        vm.expectEmit(true, true, true, true, address(c));
        emit IRegistryAdmin.AdminTransferred(nid(admin), nid(next));
        _call(next, address(c), _accept());
        assertEq(c.admin(), nid(next));
        assertEq(c.pendingAdmin(), bytes32(0));
        _refused(admin, address(c), _enable(nid(prov), true), _notAdmin(nid(admin)));
        _refused(admin, address(c), _row(ACC, 0, 0), _notProvider());
        _call(next, address(c), _enable(nid(prov), true));
    }

    function test_stranger_refused() public {
        IRegistryAdmin c = _reg(nid(admin), address(trouter));
        _refused(STRANGER, address(c), _enable(nid(STRANGER), true), _notAdmin(nid(STRANGER)));
        _refused(STRANGER, address(c), _xfer(nid(STRANGER)), _notAdmin(nid(STRANGER)));
        _refused(STRANGER, address(c), _row(ACC, KYC, MAX), _notProvider());
        _refused(STRANGER, address(c), _accept(), _notPending(nid(STRANGER)));
    }

    /// M4 on the registry: an admin or a KYC provider that is an EIP-7702 designator is no direct authority (D2).
    function test_designator_callerDelegated() public {
        IRegistryAdmin c = _reg(nid(admin), address(trouter));
        _call(admin, address(c), _enable(nid(prov), true)); // the controls, before the designators
        _call(prov, address(c), _row(ACC, KYC, MAX));
        _call(admin, address(c), _xfer(nid(next)));
        vm.etch(admin, abi.encodePacked(hex"ef0100", address(0x5EE9)));
        vm.etch(prov, abi.encodePacked(hex"ef0100", address(0x5EE9)));
        vm.etch(next, abi.encodePacked(hex"ef0100", address(0x5EE9)));
        bytes memory da = abi.encodeWithSelector(SigCheck.CallerDelegated.selector, admin);
        _refused(admin, address(c), _enable(nid(prov), false), da);
        _refused(admin, address(c), _row(ACC, 0, 0), da);
        _refused(admin, address(c), _xfer(bytes32(0)), da);
        _refused(prov, address(c), _row(ACC, 0, 0), abi.encodeWithSelector(SigCheck.CallerDelegated.selector, prov));
        _refused(next, address(c), _accept(), abi.encodeWithSelector(SigCheck.CallerDelegated.selector, next));
    }

    // ------------------------------------------------------------------ derived admins through the real router (§8)

    /// M20 (each kind): the native admin transfers, the derived UA accepts by its signed `mtxAcceptAdmin` (a stranger
    /// relayer, fee 0), then transfers on through the router; the old admin is no one.
    function test_derivedAdmin_k1() public {
        _derivedAccepts(k1);
    }

    function test_derivedAdmin_mldsa() public {
        _derivedAccepts(ml);
    }

    function test_derivedAdmin_msig() public {
        _derivedAccepts(msig);
    }

    function _derivedAccepts(bytes32 id) internal {
        IRegistryAdmin c = _reg(nid(admin), address(router));
        _call(admin, address(c), _xfer(id));
        assertEq(c.pendingAdmin(), id);
        bytes memory cd = _acceptCd(router, id, address(c));
        vm.expectEmit(true, true, true, true, address(c));
        emit IRegistryAdmin.AdminTransferred(nid(admin), id);
        _call(RELAYER, address(router), cd);
        assertEq(c.admin(), id);
        assertEq(c.pendingAdmin(), bytes32(0));
        _refused(admin, address(c), _xfer(nid(admin)), _notAdmin(nid(admin)));
        _refused(admin, address(c), _enable(nid(prov), true), _notAdmin(nid(admin)));
        _call(RELAYER, address(router), _transferCd(id, address(c), nid(next)));
        assertEq(c.pendingAdmin(), nid(next));
        _call(next, address(c), _accept());
        assertEq(c.admin(), nid(next));
    }

    /// Another signer through the router is its own subject (`NotAdmin(signer)`); the registry has no renounce, through
    /// the router either (the router's call reverts with no data).
    function test_router_anotherSignerNotAdmin() public {
        IRegistryAdmin c = _reg(nid(admin), address(router));
        _call(admin, address(c), _xfer(ml));
        _call(RELAYER, address(router), _acceptCd(router, ml, address(c)));
        _refused(RELAYER, address(router), _transferCd(k1, address(c), k1), _notAdmin(k1));
        _refused(RELAYER, address(router), _renounceCd(ml, address(c)), "");
        assertEq(c.admin(), ml, "no renounce");
    }

    /// The same signed accept on a second registry of the same router (the same pending) and on another chain's router
    /// (another `chain_uid`, router and registry) is refused; each control (its own signature) passes.
    function test_router_replayRefused() public {
        IRegistryAdmin a = _reg(nid(admin), address(router));
        IRegistryAdmin b = _reg(nid(admin), address(router));
        _call(admin, address(a), _xfer(ml));
        _call(admin, address(b), _xfer(ml));
        MetaTxLib.UAEnvelope memory e = _env(router, ml);
        IUARegistry.UASig memory s = _auth(ml, _digest(router, "AcceptAdmin", "", e, address(a), ""));
        vm.prank(RELAYER);
        (bool ok,) = address(router).call(abi.encodeCall(router.mtxAcceptAdmin, (e, address(b), s)));
        assertFalse(ok, "a's signature on b");
        assertEq(b.admin(), nid(admin));
        _call(RELAYER, address(router), abi.encodeCall(router.mtxAcceptAdmin, (e, address(a), s))); // the control
        assertEq(a.admin(), ml);

        bytes32 uidB = keccak256("chain B");
        UARegistry pregB = _deploy(address(uint160(uint256(keccak256("scaas.test.preg.b")))), uidB, address(0), false,
            BUDGET, address(0), true, _kinds());
        GovernanceRouter routerB = new GovernanceRouter(uidB, address(pregB), address(0), false);
        assertEq(_register(pregB, ML44, mlKey), ml, "one derived id on both chains");
        IRegistryAdmin cb = _reg(nid(admin), address(routerB));
        _call(admin, address(cb), _xfer(ml));
        e = _env(routerB, ml);
        s = _auth(ml, _digest(router, "AcceptAdmin", "", e, address(cb), "")); // chain A's domain
        vm.prank(RELAYER);
        (ok,) = address(routerB).call(abi.encodeCall(routerB.mtxAcceptAdmin, (e, address(cb), s)));
        assertFalse(ok, "chain A's signature on chain B");
        assertEq(cb.admin(), nid(admin));
        _call(RELAYER, address(routerB), _acceptCd(routerB, ml, address(cb))); // the control
        assertEq(cb.admin(), ml);
    }

    /// M1: a contract answering `subject() = admin` that is not the registry's router is its own native id.
    function test_fakeRouter_refused() public {
        IRegistryAdmin c = _reg(nid(admin), address(router));
        RegistryTestRouter fake = new RegistryTestRouter(chainUidA, PREG);
        bytes memory e = _notAdmin(nid(address(fake)));
        _viaRefused(fake, nid(admin), c, _enable(nid(prov), true), e);
        _viaRefused(fake, nid(admin), c, _xfer(ml), e);
        _viaRefused(fake, nid(admin), c, _row(ACC, ELIGIBLE, MAX), _notProvider());
        _call(admin, address(c), _xfer(nid(next)));
        _viaRefused(fake, nid(next), c, _accept(), _notPending(nid(address(fake))));
    }

    /// M3, M19 on the registry: the router answering 0 (outside a live call) is no one: no admin op, no row, no accept.
    function test_routerAnsweringZero_refused() public {
        IRegistryAdmin c = _reg(nid(admin), address(trouter));
        _viaRefused(trouter, bytes32(0), c, _enable(nid(prov), true), _notAdmin(bytes32(0)));
        _viaRefused(trouter, bytes32(0), c, _xfer(nid(next)), _notAdmin(bytes32(0)));
        _viaRefused(trouter, bytes32(0), c, _row(ACC, KYC, MAX), _notProvider());
        _viaRefused(trouter, bytes32(0), c, _accept(), _notPending(bytes32(0)));
        assertEq(c.admin(), nid(admin));
    }

    /// M9 on the registry: a non-pending caller, a second accept, and a cancelled pending are refused.
    function test_acceptAdmin_nonPending() public {
        IRegistryAdmin c = _reg(nid(admin), address(trouter));
        _refused(next, address(c), _accept(), _notPending(nid(next)));
        _call(admin, address(c), _xfer(nid(next)));
        _refused(STRANGER, address(c), _accept(), _notPending(nid(STRANGER)));
        _call(next, address(c), _accept());
        _refused(next, address(c), _accept(), _notPending(nid(next)));
        _call(next, address(c), _xfer(nid(admin)));
        _call(next, address(c), _xfer(bytes32(0)));
        _refused(admin, address(c), _accept(), _notPending(nid(admin)));
        assertEq(c.admin(), nid(next));
    }

    /// M14 (owner, Q2): the registry has no `renounceAdmin`, its selector reverts with no data; the admin stays.
    function test_noRenounce() public {
        IRegistryAdmin c = _reg(nid(admin), address(trouter));
        _refused(admin, address(c), abi.encodeWithSelector(bytes4(0x8bad0c0a)), "");
        _viaRefused(trouter, nid(admin), c, abi.encodeWithSelector(bytes4(0x8bad0c0a)), "");
        assertEq(c.admin(), nid(admin));
    }

    // ------------------------------------------------------------------ the KYC providers (§5.3.1, §8)

    /// The old attester entries revert with no data (every chain test-only: no alias).
    function test_oldSelectorsGone() public {
        IRegistryAdmin c = _reg(nid(admin), address(0));
        bytes[5] memory old = [
            abi.encodeWithSelector(bytes4(0x5c0204d9), prov, true), // setAttester(address,bool)
            abi.encodeWithSelector(bytes4(0xfff67e1b), new bytes32[](0), new uint64[](0), new uint64[](0)), // attest
            abi.encodeWithSelector(bytes4(0xb174a9c4), ACC), // attestationOf(bytes32)
            abi.encodeWithSelector(bytes4(0xf358d481), uint32(0)), // attesterEnabled(uint32)
            abi.encodeWithSelector(bytes4(0xf146f55a), prov) // attesterId(address)
        ];
        for (uint256 i; i < old.length; ++i) _refused(admin, address(c), old[i], "");
        _call(admin, address(c), _row(ACC, KYC, MAX)); // the control: the new entry
    }

    /// Ids: assigned at the first enabling from 1, never reused or reassigned; a disable keeps the id; id 0 is the admin,
    /// always enabled; an id never assigned is not; disabling a provider never enabled `NotKycProvider`; provider 0
    /// `KycProviderZero` (what a router read outside a live call answers).
    function test_kycProvider_ids() public {
        IRegistryAdmin c = _reg(nid(admin), address(0));
        assertTrue(c.kycProviderEnabled(0), "the admin");
        assertFalse(c.kycProviderEnabled(1), "not assigned");
        _call(admin, address(c), _enable(nid(prov), true));
        _call(admin, address(c), _enable(msig, true));
        assertEq(c.kycProviderId(nid(prov)), 1);
        assertEq(c.kycProviderId(msig), 2, "the next id");
        _call(admin, address(c), _enable(nid(prov), false));
        assertEq(c.kycProviderId(nid(prov)), 1, "a disable keeps the id");
        _call(admin, address(c), _enable(nid(prov), true));
        assertEq(c.kycProviderId(nid(prov)), 1, "never reassigned");
        _refused(admin, address(c), _enable(mlProv, false), _notProvider());
        bytes memory z = abi.encodeWithSelector(IRegistryAdmin.KycProviderZero.selector);
        _refused(admin, address(c), _enable(bytes32(0), true), z);
        _refused(admin, address(c), _enable(bytes32(0), false), z);
        assertEq(c.kycProviderId(bytes32(0)), 0);
    }

    /// A native provider writes directly under its own id, `ComplianceSet(…, id)`; the rows of `hasFlags` follow.
    function test_kycProvider_nativeDirect() public {
        IRegistryAdmin c = _reg(nid(admin), address(trouter));
        _call(admin, address(c), _enable(nid(prov), true));
        vm.expectEmit(true, true, true, true, address(c));
        emit IRegistryAdmin.ComplianceSet(ACC, KYC, MAX, 1);
        _call(prov, address(c), _row(ACC, KYC, MAX));
        (uint64 f, uint64 u, uint32 id) = _rowOf(c, ACC);
        assertEq(f, KYC);
        assertEq(u, MAX);
        assertEq(id, 1);
        assertTrue(c.hasFlags(ACC, KYC, 0));
    }

    /// M11, M13: a derived provider (`msig`, mldsa44) writes through the router under its own id, never the admin's 0 (so
    /// an admin row stays the admin's); the admin through the router writes id 0; a subject that is no provider is
    /// refused there too; a derived provider's id has no direct path (`pad(msg.sender)` is not it).
    function test_kycProvider_derivedThroughRouter() public {
        IRegistryAdmin c = _reg(ml, address(trouter));
        _via(trouter, ml, c, _enable(msig, true));
        _via(trouter, ml, c, _enable(mlProv, true));
        bytes32[2] memory ps = [msig, mlProv];
        for (uint256 i; i < 2; ++i) {
            bytes32 a = bytes32(uint256(0xA0 + i));
            vm.expectEmit(true, true, true, true, address(c));
            emit IRegistryAdmin.ComplianceSet(a, KYC, MAX, uint32(i + 1));
            _via(trouter, ps[i], c, _row(a, KYC, MAX));
            (, , uint32 id) = _rowOf(c, a);
            assertEq(id, c.kycProviderId(ps[i]), "its own id");
        }
        _via(trouter, ml, c, _row(ACC, KYC, MAX)); // the admin through the router: id 0
        (, , uint32 aid) = _rowOf(c, ACC);
        assertEq(aid, 0);
        _viaRefused(trouter, msig, c, _row(ACC, ELIGIBLE, MAX), abi.encodeWithSelector(IRegistryAdmin.EligibleContractAdminOnly.selector));
        _viaRefused(trouter, msig, c, _row(ACC, 2, MAX), abi.encodeWithSelector(IRegistryAdmin.AdminWrittenSlot.selector, ACC));
        _viaRefused(trouter, k1, c, _row(ACC, KYC, MAX), _notProvider());
        _refused(STRANGER, address(c), _row(ACC, KYC, MAX), _notProvider());
        _refused(address(trouter), address(c), _row(ACC, KYC, MAX), _notProvider()); // the router itself is no one
    }

    /// Disabling a provider voids its rows at once (`hasFlags`, the enabled bit), nothing erased; it can no longer write;
    /// enabled again its rows count again; the admin's rows never lapse by it.
    function test_kycProvider_disableVoids() public {
        IRegistryAdmin c = _reg(nid(admin), address(0));
        bytes32 b = bytes32(uint256(0xB0B));
        _call(admin, address(c), _enable(nid(prov), true));
        _call(prov, address(c), _row(ACC, KYC, MAX));
        _call(admin, address(c), _row(b, KYC, MAX));
        assertTrue(c.hasFlags(ACC, KYC, 0), "the control");
        _call(admin, address(c), _enable(nid(prov), false));
        assertFalse(c.hasFlags(ACC, KYC, 0), "void at once");
        assertFalse(c.kycProviderEnabled(1));
        (uint64 f,, uint32 id) = _rowOf(c, ACC);
        assertEq(f, KYC);
        assertEq(id, 1);
        assertTrue(c.hasFlags(b, KYC, 0), "the admin's row");
        _refused(prov, address(c), _row(ACC, KYC, MAX), _notProvider());
        _call(admin, address(c), _enable(nid(prov), true));
        assertTrue(c.hasFlags(ACC, KYC, 0), "enabled again");
    }

    /// The row rules (owner 2026-11-06, CTR-AS-16): a provider over an admin row `AdminWrittenSlot`; `ELIGIBLE_CONTRACT`
    /// only by the admin with `validUntil` max, else `EligibleContractAdminOnly`; lengths checked.
    function test_kycProvider_rowRules() public {
        IRegistryAdmin c = _reg(nid(admin), address(0));
        _call(admin, address(c), _enable(nid(prov), true));
        _call(prov, address(c), _row(ACC, KYC, MAX)); // the control: an empty slot is open
        _call(admin, address(c), _row(ACC, KYC, MAX));
        _refused(prov, address(c), _row(ACC, 2, MAX), abi.encodeWithSelector(IRegistryAdmin.AdminWrittenSlot.selector, ACC));
        bytes memory ec = abi.encodeWithSelector(IRegistryAdmin.EligibleContractAdminOnly.selector);
        _refused(prov, address(c), _row(bytes32(uint256(1)), ELIGIBLE, MAX), ec);
        _refused(admin, address(c), _row(bytes32(uint256(1)), ELIGIBLE, MAX - 1), ec);
        _call(admin, address(c), _row(bytes32(uint256(1)), ELIGIBLE, MAX));
        _refused(admin, address(c), abi.encodeCall(IRegistryAdmin.setCompliance, (new bytes32[](2), new uint64[](1),
            new uint64[](2))), abi.encodeWithSelector(IRegistryAdmin.LengthMismatch.selector));
    }

    /// At most 256 rows per call (the node's decode bound): 256 pass, 257 `TooManyRows(257)`.
    function test_setCompliance_rowBound() public {
        IRegistryAdmin c = _reg(nid(admin), address(0));
        for (uint256 n = 256; n <= 257; ++n) {
            bytes32[] memory a = new bytes32[](n);
            uint64[] memory f = new uint64[](n);
            uint64[] memory u = new uint64[](n);
            for (uint256 i; i < n; ++i) (a[i], f[i], u[i]) = (bytes32(i + 1), KYC, MAX);
            bytes memory cd = abi.encodeCall(IRegistryAdmin.setCompliance, (a, f, u));
            if (n == 256) _call(admin, address(c), cd);
            else _refused(admin, address(c), cd, abi.encodeWithSelector(IRegistryAdmin.TooManyRows.selector, n));
        }
        assertTrue(c.hasFlags(bytes32(uint256(256)), KYC, 0));
    }
}

/// Spec §5.3 (Fable P1-1), M16: a regulated token refuses a canonical-code registry whose `govRouter()` is another router
/// (`ComplianceRegistryRouterMismatch(registry, got)`) and takes one with 0 or its own `ChainEnv.govRouter`: on the
/// fixture's factory (no router) and on a factory configured with a router.
contract RegistryRouterCheckTest is RegFixture, RegistryCalls {
    function _denyCfg(address reg) internal view returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg8();
        c.features |= 1 << GovernanceBits.DENYLIST;
        (c.reg.deniedFlags, c.reg.complianceRegistry) = (SANCTIONED, reg);
    }

    function _mismatch(address reg, address got) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IRegistryAdmin.ComplianceRegistryRouterMismatch.selector, reg, got);
    }

    function test_routerMismatch_noRouter() public {
        RegistryTestRouter other = new RegistryTestRouter(UID, address(ureg));
        address r0 = address(_reg(nid(cadmin), address(0)));
        address rx = address(_reg(nid(cadmin), address(other)));
        address t = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(_denyCfg(r0)), "r0"); // control
        assertEq(IRegulatedToken(t).regulatedConfig().complianceRegistry, r0);
        vm.expectRevert(_mismatch(rx, address(other)));
        f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(_denyCfg(rx)), "rx");
    }

    function test_routerMismatch_ownRouter() public {
        RegistryTestRouter own = new RegistryTestRouter(UID, address(ureg));
        RegistryTestRouter other = new RegistryTestRouter(UID, address(ureg));
        OpenFactory g = EnvKit.factory(address(this), UID, 0, address(own));
        Catalogue.release(g, IOpenFactory.TokenKind.NORMAL_REGULATED, 1, plainEnv(address(g), address(0), UID, address(ureg),
            false), type(NormalRegulatedToken).creationCode, regArgs());
        g.setKindEnabled(IOpenFactory.TokenKind.NORMAL_REGULATED, true);
        address r0 = address(_reg(nid(cadmin), address(0)));
        address ro = address(_reg(nid(cadmin), address(own)));
        address rx = address(_reg(nid(cadmin), address(other)));
        assertEq(ro.codehash, rx.codehash, "one canonical code: the hash pins no router");
        g.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(_denyCfg(r0)), "r0");
        address t = g.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(_denyCfg(ro)), "ro");
        assertEq(IRegulatedToken(t).regulatedConfig().complianceRegistry, ro);
        vm.expectRevert(_mismatch(rx, address(other)));
        g.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(_denyCfg(rx)), "rx");
        // the fixture's router-less token side: a registry naming `own` is another router there
        vm.expectRevert(_mismatch(ro, address(own)));
        f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(_denyCfg(ro)), "ro");
    }
}
