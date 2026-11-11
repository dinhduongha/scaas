// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {OnchainBase} from "./OnchainBase.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {ImplArgs, ITokenModules} from "../../src/metatx/ITokenModule.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {NormalTokenP, NormalTokenT, NormalTokenA} from "../../src/metatx/NormalTokenModules.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {SCaaSDexGovernanceModule} from "../../src/dex/SCaaSDexAdmin.sol";
import {SCaaSDexLiquidityModule} from "../../src/dex/SCaaSDexLiquidityModule.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {RefServiceEscrow} from "../../test/metatx/helpers/RefServiceEscrow.sol";
import {NoteKind, INoteKind} from "../../test/v2/mocks/GenericKinds.sol";
import {UACall} from "../../test/ua/UACall.sol";
import {MtxHash} from "../../test/helpers/MtxHash.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {console2} from "forge-std/console2.sol";
import {VmSafe} from "forge-std/Vm.sol";

/// @notice T66b Step 5b, group `misc`: (1) the Step 5 UA registry (its two libraries by DELEGATECALL): `register` of a
///         secp256k1 UA (twice, one with a KEM hash commit) and a P-256 UA, `registerWebAuthn`, `registerMsig` (a native and a
///         derived member, no PoP: not PQ-eligible) and both `acceptMembership`s, `cacheExpandedKey` (ML-DSA-44, the Solidity verifier of this deploy), and one UA of every kind
///         the portable vectors sign (UA-8: no chain context; vectors/ua/signatures.json `derived[]`, pq_signatures.json
///         FN-DSA-512 / -1024 and SLH-DSA-128s, groups.json's four main MuSig2 / FROST groups), so each kind's verifier runs
///         inside `register` (a vector UA already on the chain is skipped and logged; ML-DSA: the PQ node's run); (2) a factory of this
///         run (test key 1 its registrar) on the Step 5 chain values: every release path, kind 0 with its modules, the DEX
///         with its own module D, the generic class kind of `test/v2/mocks/GenericKinds.sol` (`NoteKind`, class 4);
///         (3) a MandateWallet on a kind-0 token of the Step 5 factory, every entry direct and relayed; (4) the reference
///         service (RefServiceEscrow) on a kind-0 and a regulated kind-8 token of the Step 5 factory: deposit, note,
///         release. Test key 1 signs and owns, key 2 is the mandate's delegate, key 3 relays. Negatives by eth_call after
///         the broadcast (`_neg`). Not here: setKemKey (a KEM key is an ML-DSA / FN-DSA holder's, CTR-UA-32: no
///         signer of those kinds in Solidity; here only its refusal on a secp256k1 UA), setPqzKey / storePqzPop (the PQ
///         node's run). UNAUDITED.
contract Misc is OnchainBase {
    string internal constant E_TAIL =
        "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    uint256 internal constant SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint16 internal constant NOTE_CLASS = 4;
    /// @dev The gas limit of a call whose storage clears earn a refund (a revoke, a release): forge sets a broadcast's limit
    ///      from the simulation's gas used (after the refund) x the multiplier, below what the call needs before its refund
    ///      (seen on the local copy: `mtxRevokeMandate` out of gas at 118,611, `eth_estimateGas` 126,858). An explicit call
    ///      gas is the transaction's limit.
    uint256 internal constant REFUND_GAS = 1_000_000;
    /// @dev The SCaaSDex release (`deployDexImplementation`): at most 60 M asked (NET-EVM-11).
    uint256 internal constant DEX_RELEASE_GAS = 59_000_000;

    IUARegistry reg;
    OpenFactory f5; // the Step 5 factory
    OpenFactory f2; // this run's factory
    bytes32 uid;
    uint256 s1; // the secp256k1 UA's key
    bytes32 u1;
    address t0; // a kind-0 token of the Step 5 factory (key 1 holds its supply)
    address t8; // a kind-8 token of the Step 5 factory
    address impl2; // an unregistered kind-0 implementation of f2
    address[] ms; // f2's kind-0 modules
    bytes cfg0; // the kind-0 config of f2's tokens
    uint256 lane = 100; // key 1's next free lane on the wallet
    bytes32 um; // the msig (`_msig`): f2's admin from `_factoryRouter` (round 3r)
    GovernanceRouter gr; // the chain's router (f5's)
    string internal constant E3R =
        "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant ENV_T = "Env(address registry,address smartKeyAccountImpl,bool hedera,address[] deps,bytes32[] params,address[] libs,bytes32[] libCodeHashes)";

    function run() external {
        _init("misc");
        reg = IUARegistry(_dep("ua_registry"));
        f5 = OpenFactory(_dep("token_factory"));
        uid = vm.parseJsonBytes32(dj, ".chain_uid");
        _book(address(reg), "UARegistry");
        _book(_dep("ua_registry_core_lib"), "UARegistryCoreLib");
        _book(_dep("ua_registry_aux_lib"), "UARegistryAuxLib");
        _book(address(f5), "OpenFactory");
        _book(_dep("compliance_registry"), "ComplianceRegistry");
        _registry();
        _factory();
        _factoryRouter();
        t0 = _token0();
        _mandate();
        _escrow(t0, "k0");
        t8 = _token8();
        _escrow(t8, "k8");
        _writeBook();
    }

    // ------------------------------------------------------------------ (1) the registry

    function _rd(bytes32 ua, uint16 kind, bytes32 kemHash) internal pure returns (bytes32) {
        return UAKinds.registrationDigest(ua, kind, 0, kemHash, 0);
    }

    function _secpKey(uint256 sk) internal returns (bytes memory) {
        VmSafe.Wallet memory w = vm.createWallet(sk);
        return abi.encodePacked(w.publicKeyX, w.publicKeyY);
    }

    function _kem(bytes32 seed) internal pure returns (IUARegistry.KemKey memory k, bytes memory pk) {
        bytes memory ek;
        for (uint256 i; i < 49; ++i) ek = bytes.concat(ek, keccak256(abi.encode(seed, i))); // 1,568 B (ML-KEM-1024 ek)
        k = IUARegistry.KemKey(UAKinds.KEM_SCHEME_MLKEM1024_X25519, ek, keccak256(abi.encode(seed, "x25519")));
        pk = UAKinds.kemPk(k);
    }

    function _p256(uint256 sk, bytes32 h) internal pure returns (bytes32 r, bytes32 s) {
        (r, s) = vm.signP256(sk, h);
        if (uint256(s) > P256_N / 2) s = bytes32(P256_N - uint256(s)); // the verifiers take low s only
    }

    function _registry() internal {
        IUARegistry.UAAttrs memory none;
        // a secp256k1 UA (kind 0x0108): its portable PoP over the registration digest
        s1 = uint256(_salt("secp-1")) % SECP_N;
        bytes memory kd = _secpKey(s1);
        bytes32 ua = UAKinds.uaOf(UAKinds.SECP256K1, kd);
        bytes memory pop = _ecdsa(s1, UAKinds.uaMessage(UAKinds.SECP256K1, UAKinds.PURPOSE_POP_V2,
            _rd(ua, UAKinds.SECP256K1, UAKinds.kemRecordHash(ua, 0, ""))));
        vm.broadcast(k1);
        u1 = reg.register(UAKinds.SECP256K1, kd, none, pop, "");
        require(u1 == ua, "secp UA id");
        // setKemKey: a KEM key is for ML-DSA / FN-DSA holders only (CTR-UA-32); a secp256k1 UA's signed version 1 is refused
        (IUARegistry.KemKey memory kem, bytes memory kemPk) = _kem(_salt("kem-1"));
        IUARegistry.UASig memory sig;
        sig.signature = _ecdsa(s1, UAKinds.uaMessage(UAKinds.SECP256K1, UAKinds.PURPOSE_KEM, UAKinds.kemRecordDigest(u1, 1, kemPk)));
        _neg(a1, address(reg), abi.encodeCall(IUARegistry.setKemKey, (u1, 1, kem, sig)), IUARegistry.UAKemHolder.selector,
            "registry: setKemKey on a kind that holds no KEM key");
        _neg(a1, address(reg), abi.encodeCall(IUARegistry.register, (UAKinds.SECP256K1, kd, none, pop, bytes(""))),
            IUARegistry.UAAlreadyRegistered.selector, "registry: register an id twice");
        bytes memory kd3 = _secpKey(uint256(_salt("secp-3")) % SECP_N);
        _neg(a1, address(reg), abi.encodeCall(IUARegistry.register, (UAKinds.SECP256K1, kd3, none, pop, bytes(""))),
            IUARegistry.UAPoP.selector, "registry: register with another key's PoP");
        _verifiers();
        _vectors();
        bytes32 up = _p256UA();
        _webAuthnUA();
        _msig(up);
        _expandedKey();
    }

    /// @dev The UA kinds' verifiers: booked by the target's base book (basebook.py, from the target's own deploy), so the
    ///      script names no address of one chain.
    function _verifiers() internal {}

    /// @dev The portable vectors' UAs, one per kind (their PoPs carry no chain context, UA-8): each registered as it is.
    function _vectors() internal {
        string memory j = vm.readFile("../vectors/ua/signatures.json");
        for (uint256 i; vm.keyExistsJson(j, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            string memory p = string.concat(".derived[", vm.toString(i), "]");
            _vecReg(j, p, string.concat(p, ".pop.sig"));
        }
        j = vm.readFile("../vectors/ua/pq_signatures.json");
        uint8[3] memory pq = [2, 3, 5]; // fndsa512, slhdsa128s, fndsa1024 (ML-DSA: the PQ node's run)
        for (uint256 i; i < 3; ++i) {
            string memory p = string.concat(".kinds[", vm.toString(pq[i]), "]");
            _vecReg(j, p, string.concat(p, ".pop.sig"));
        }
        j = vm.readFile("../vectors/ua/groups.json");
        uint8[4] memory gs = [0, 4, 10, 14]; // the main musig2-secp256k1, frost-secp256k1, musig2-bn254, frost-bn254 groups
        for (uint256 i; i < 4; ++i) {
            string memory p = string.concat(".groups[", vm.toString(gs[i]), "]");
            _vecReg(j, p, string.concat(p, ".pop.blob"));
        }
    }

    /// @dev One vector row: skipped when its kind is off or its UA is already registered; else its gas measured on the
    ///      script's copy first (a snapshot, reverted), then sent when it stays under the 60 M line.
    function _vecReg(string memory j, string memory p, string memory popPath) internal {
        string memory name = vm.parseJsonString(j, string.concat(p, ".name"));
        uint16 kind = uint16(vm.parseJsonUint(j, string.concat(p, ".kind")));
        bytes32 ua = vm.parseJsonBytes32(j, string.concat(p, ".ua"));
        if (!reg.kindEnabled(kind) || reg.kindOf(ua) != 0) {
            console2.log(string.concat("vector UA skipped (kind off or registered): ", name));
            return;
        }
        IUARegistry.UAAttrs memory none;
        bytes memory data = UACall.registerCall(kind, vm.parseJsonBytes(j, string.concat(p, ".keyData")), none,
            vm.parseJsonBytes(j, popPath), "");
        uint256 snap = vm.snapshotState();
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = address(reg).call(data);
        g -= gasleft();
        vm.revertToState(snap);
        require(ok, string.concat("vector UA refused: ", name, " ", vm.toString(ret)));
        console2.log(string.concat("vector UA ", name, ": register gas (script copy)"), g);
        if (g > 50_000_000) {
            console2.log(string.concat("vector UA not sent (over the 60 M line): ", name));
            return;
        }
        vm.broadcast(k1);
        (ok,) = address(reg).call(data);
        require(ok && reg.kindOf(ua) == kind, name);
    }

    function _p256UA() internal returns (bytes32 ua) {
        uint256 sk = uint256(_salt("p256")) % P256_N;
        (uint256 x, uint256 y) = vm.publicKeyP256(sk);
        bytes memory kd = abi.encodePacked(x, y);
        ua = UAKinds.uaOf(UAKinds.P256, kd);
        bytes32 m = UAKinds.uaMessage(UAKinds.P256, UAKinds.PURPOSE_POP_V2, _rd(ua, UAKinds.P256, UAKinds.kemRecordHash(ua, 0, "")));
        (bytes32 r, bytes32 s) = _p256(sk, sha256(abi.encodePacked(m)));
        IUARegistry.UAAttrs memory none;
        vm.broadcast(k1);
        reg.register(UAKinds.P256, kd, none, abi.encodePacked(r, s), "");
    }

    function _webAuthnUA() internal {
        uint256 sk = uint256(_salt("webauthn")) % P256_N;
        (uint256 x, uint256 y) = vm.publicKeyP256(sk);
        bytes32 rp = sha256("onchain.scaas.test");
        bytes32 ua = UAKinds.uaOf(UAKinds.WEBAUTHN_P256, abi.encodePacked(x, y, rp));
        bytes32 m = UAKinds.uaMessage(UAKinds.WEBAUTHN_P256, UAKinds.PURPOSE_POP_V2,
            _rd(ua, UAKinds.WEBAUTHN_P256, UAKinds.kemRecordHash(ua, 0, "")));
        bytes memory authData = abi.encodePacked(rp, uint8(0x05), uint32(0)); // UP | UV
        bytes memory cd = abi.encodePacked('{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(m)),
            '","origin":"https://onchain.scaas.test"}');
        (bytes32 r, bytes32 s) = _p256(sk, sha256(abi.encodePacked(authData, sha256(cd))));
        IUARegistry.UAAttrs memory none;
        vm.broadcast(k1);
        reg.registerWebAuthn(IUARegistry.WebAuthnKey(bytes32(x), bytes32(y), rp), none, abi.encode(authData, cd, r, s), "");
    }

    /// @dev An msig of a native id (key 2) and the secp256k1 UA, threshold 1: neither is a PQ kind, so the registration has
    ///      no PoP (CTR-UA-37) and each member accepts by `acceptMembership`. `up` (the P-256 UA) is unused as a member.
    function _msig(bytes32 up) internal {
        up;
        IUARegistry.MsigStructure memory st;
        st.threshold = 1;
        st.members = new IUARegistry.MsigMember[](2);
        st.members[0] = IUARegistry.MsigMember(UAKinds.EVM_EOA, _pad(a2), 1); // ids ascending: a native id first
        st.members[1] = IUARegistry.MsigMember(UAKinds.SECP256K1, u1, 1);
        IUARegistry.UAAttrs memory none;
        IUARegistry.MemberSig[] memory pop;
        vm.broadcast(k1);
        bytes32 mu = reg.registerMsig(st, none, pop, "");
        // slot 0, the native id: its own signature over the typed membership digest
        IUARegistry.MemberSig memory s0;
        s0.sig = _ecdsa(k2, UAKinds.membershipDigest(mu, _pad(a2)));
        vm.broadcast(k1);
        reg.acceptMembership(mu, s0);
        // slot 1, the derived UA: under `member` over the member digest
        bytes32 md = UAKinds.memberDigest(mu, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBERSHIP,
            UAKinds.membershipDigest(mu, u1)));
        IUARegistry.MemberSig memory s1_;
        (s1_.index, s1_.sig) = (1, _ecdsa(s1, UAKinds.uaMessage(UAKinds.SECP256K1, UAKinds.PURPOSE_MEMBER, md)));
        vm.broadcast(k3);
        reg.acceptMembership(mu, s1_);
        um = mu;
    }

    /// @dev ML-DSA-44's expanded key (one part) of the vector key, cached by anyone (this deploy's ML-DSA verifier runs in
    ///      Solidity: `PRECOMPILE() == 0`); a second run of the same key returns at once. A kind with no cache: refused.
    function _expandedKey() internal {
        string memory j = vm.readFile("../vectors/ua/pq_signatures.json");
        bytes memory pk;
        for (uint256 i;; ++i) {
            string memory p = string.concat(".kinds[", vm.toString(i), "]");
            if (keccak256(bytes(vm.parseJsonString(j, string.concat(p, ".name")))) == keccak256("mldsa44")) {
                pk = vm.parseJsonBytes(j, string.concat(p, ".keyData"));
                break;
            }
        }
        vm.broadcast(k1);
        reg.cacheExpandedKey(UAKinds.MLDSA44, pk, 0);
        _neg(a1, address(reg), abi.encodeCall(IUARegistry.cacheExpandedKey, (UAKinds.SECP256K1, pk, 0)),
            IUARegistry.UAKeyCache.selector, "registry: cacheExpandedKey of a kind without a cache");
    }

    // ------------------------------------------------------------------ (2) a factory of this run: the release paths

    function _factory() internal {
        vm.startBroadcast(k1);
        f2 = new OpenFactory(_pad(a1));
        f2.configureChain(uid, 0, f5.govRouter(), f5.govRouter().codehash, 0, bytes32(0));
        ms.push(address(new NormalTokenP(address(f2), "")));
        ms.push(address(new NormalTokenT(address(f2), "")));
        ms.push(address(new NormalTokenA(address(f2), "")));
        vm.stopBroadcast();
        _book(address(f2), "OpenFactory");
        for (uint256 i; i < 3; ++i) _book(ms[i], "NormalToken");
        IFactoryToken.Env memory e = _plainEnv();
        IFactoryToken.Env memory withMs = _withModules(e);
        bytes memory implArgs = abi.encode(ImplArgs(ms));
        cfg0 = abi.encode(_cfg0("Onchain f2", "oF2"));
        vm.startBroadcast(k1);
        f2.publishTokenEnv(IOpenFactory.TokenKind.NORMAL, 1, withMs);
        address impl = f2.deployTokenImplementation(IOpenFactory.TokenKind.NORMAL, 1, 1, type(NormalToken).creationCode, implArgs);
        address tok = f2.createToken(IOpenFactory.TokenKind.NORMAL, 1, cfg0, _salt("f2-t1"));
        impl2 = address(new NormalToken(address(f2), implArgs));
        address tokU = f2.createTokenUnregistered(IOpenFactory.TokenKind.NORMAL, impl2, cfg0, _salt("f2-tu"));
        f2.publishTokenEnv(IOpenFactory.TokenKind.NORMAL, 2, e); // env 2: no module pinned (the ModuleNotPinned negative)
        f2.publishTokenEnv(IOpenFactory.TokenKind.NORMAL, 3, withMs); // env 3, the latest: the modules again (KindDisabled's)
        vm.stopBroadcast();
        _book(impl, "NormalToken");
        _book(tok, "NormalToken");
        _book(impl2, "NormalToken");
        _book(tokU, "NormalToken");
        _dex();
        _classKind();
        vm.startBroadcast(k1);
        f2.deprecateToken(IOpenFactory.TokenKind.NORMAL, 1, "onchain matrix: deprecated after its use");
        // already on (the default 0 and 1): an idempotent write. Both carry REFUND_GAS: the simulated 21,147 x 1.10 ran out
        // of gas on a fresh anvil (the fork's receipt: 19,904), and the NORMAL write frees a slot
        f2.setTokenKindEnabled{gas: REFUND_GAS}(IOpenFactory.TokenKind.WRAPPED, true);
        f2.setTokenKindEnabled{gas: REFUND_GAS}(IOpenFactory.TokenKind.NORMAL, false);
        vm.stopBroadcast();
        _neg(a1, address(f2), abi.encodeCall(OpenFactory.deployTokenImplementation, (IOpenFactory.TokenKind.NORMAL, 3, 2,
            type(NormalToken).creationCode, implArgs)), IOpenFactory.ModuleNotPinned.selector,
            "factory: a release whose modules its env does not pin (approved through the router: `_factoryRouter`)");
        _neg(a1, address(f2), abi.encodeCall(OpenFactory.createToken, (IOpenFactory.TokenKind.NORMAL, 1, cfg0, _salt("n1"))),
            IOpenFactory.VersionDeprecated.selector, "factory: createToken of a deprecated release");
        _neg(a1, address(f2), abi.encodeCall(OpenFactory.createTokenUnregistered, (IOpenFactory.TokenKind.NORMAL, impl2, cfg0,
            _salt("n2"))), IOpenFactory.KindDisabled.selector, "factory: a disabled kind");
        _neg(a1, address(f2), abi.encodeCall(OpenFactory.createToken, (IOpenFactory.TokenKind.NORMAL_REGULATED, 1, cfg0,
            _salt("n3"))), IOpenFactory.VersionUnknown.selector, "factory: a kind outside the catalogue");
        _neg(a2, address(f2), abi.encodeCall(OpenFactory.publishTokenEnv, (IOpenFactory.TokenKind.NORMAL, 4, e)),
            IAdmin.NotAdmin.selector, "factory: publishTokenEnv by another than the admin");
        _neg(a1, address(f2), abi.encodeCall(OpenFactory.configureChain, (uid, 0, address(0), bytes32(0), 0, bytes32(0))),
            IAdmin.NotAdmin.selector, "factory: configureChain by the former admin (the msig is the admin: `_factoryRouter`)");
    }

    // ------------------------------------------------------------------ (2b) f2's admin an msig: every op through the router

    /// @dev Round 3r (CTR-GOV-23, spec 2026-11-10-admin-not-owner.md §7 "Matrix"): f2's admin moves from key 1's native id to
    ///      the `msig` of `_msig` (the two-step transfer, its `mtxAcceptAdmin`); then every admin op of the factory is the
    ///      msig's signed router op (slot 1, the secp256k1 UA), sent by key 3 at fee 0: the three env publishes, the three
    ///      approvals (the token release deployed by key 3 through its approval, the class release likewise; the DEX one
    ///      revoked), the deprecations, the kind switches, the directory's relay pair. Key 1 has no shortcut any more.
    function _factoryRouter() internal {
        gr = GovernanceRouter(f5.govRouter());
        vm.broadcast(k1);
        f2.transferAdmin(um);
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory a) = _mauth("UAAcceptAdmin", "", address(f2), "");
        vm.broadcast(k3);
        gr.mtxAcceptAdmin(e, address(f2), a);
        require(f2.admin() == um && f2.pendingAdmin() == bytes32(0), "f2: the msig is the admin");
        uint64 until = uint64(vu);
        uint32 gen = f2.adminGeneration();
        // the token: env 4 (the modules pinned), release 2 on it approved and deployed by key 3, then deprecated; release 3
        // on env 2 approved and left live (its deploy is the ModuleNotPinned negative of `_factory`)
        IFactoryToken.Env memory withMs = _withModules(_plainEnv());
        (e, a) = _mauth("UAPublishTokenEnv", "uint8 kind,uint16 envVersion,Env env,", address(f2),
            abi.encode(IOpenFactory.TokenKind.NORMAL, uint16(4), _envHash(withMs)));
        vm.broadcast(k3);
        gr.mtxPublishTokenEnv(e, address(f2), IOpenFactory.TokenKind.NORMAL, 4, withMs, a);
        bytes memory code = type(NormalToken).creationCode;
        bytes memory implArgs = abi.encode(ImplArgs(ms));
        _approveToken(2, 4, code, implArgs, gen, until);
        _approveToken(3, 2, code, implArgs, gen, until);
        vm.broadcast(k3);
        address impl = f2.deployTokenImplementation(IOpenFactory.TokenKind.NORMAL, 2, 4, code, implArgs);
        _book(impl, "NormalToken");
        string memory why = "onchain matrix: deprecated after its use (the msig admin, through the router)";
        (e, a) = _mauth("UADeprecateToken", "uint8 kind,uint64 version,string reason,", address(f2),
            abi.encode(IOpenFactory.TokenKind.NORMAL, uint64(2), keccak256(bytes(why))));
        vm.broadcast(k3);
        gr.mtxDeprecateToken(e, address(f2), IOpenFactory.TokenKind.NORMAL, 2, why, a);
        (e, a) = _mauth("UASetTokenKindEnabled", "uint8 kind,bool on,", address(f2), abi.encode(IOpenFactory.TokenKind.WRAPPED, false));
        vm.broadcast(k3);
        gr.mtxSetTokenKindEnabled{gas: REFUND_GAS}(e, address(f2), IOpenFactory.TokenKind.WRAPPED, false, a);
        _neg(a1, address(f2), abi.encodeCall(OpenFactory.publishTokenEnv, (IOpenFactory.TokenKind.NORMAL, 5, withMs)),
            IAdmin.NotAdmin.selector, "factory: publishTokenEnv by the former admin (key 1)");
        _neg(a1, address(f2), abi.encodeCall(OpenFactory.deployTokenImplementation, (IOpenFactory.TokenKind.NORMAL, 4, 4, code,
            implArgs)), IOpenFactory.ReleaseNotApproved.selector, "factory: the former admin's deploy without an approval");
        _dexRouter(gen, until);
        _classRouter(gen, until);
        _entriesRouter();
    }

    /// @dev f2's directory through the router: the relay pair of the Step 5 deploy (its code hashes, the executor's binding).
    function _entriesRouter() internal {
        address rf = _dep("relay_fee_router");
        address ex = _dep("relay_fee_executor");
        _sendStatic(gr.mtxSetChainEntries.selector, "UASetChainEntries", "address relayFeeRouter,bytes32 relayFeeRouterCodeHash,"
            "bytes32 relayFeeExecutorCodeHash,address complianceRegistry,bytes32 complianceRegistryCodeHash,"
            "address smartKeyAccountFactory,bytes32 smartKeyAccountFactoryCodeHash,address zetherStatements,"
            "bytes32 zetherStatementsCodeHash,", abi.encode(rf, rf.codehash, ex.codehash, address(0), bytes32(0), address(0),
            bytes32(0), address(0), bytes32(0)));
        require(f2.relayFeeRouter() == rf && f2.relayFeeExecutor() == ex, "f2: the directory's relay pair");
    }

    function _approveToken(uint64 version, uint16 env, bytes memory code, bytes memory implArgs, uint32 gen, uint64 until)
        internal
    {
        bytes memory w = abi.encode(IOpenFactory.TokenKind.NORMAL, version, env, keccak256(code), keccak256(implArgs), uid,
            address(f2), gen, until);
        _sendStatic(gr.mtxApproveTokenRelease.selector, "UAApproveTokenRelease", "uint8 kind,uint64 version,uint16 envVersion,"
            "bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until,", w);
    }

    /// @dev The msig's router op whose params are all static (`words` after `target`), sent by key 3: the calldata built
    ///      in parts (the envelope, `target`, the words, then the `UASig` offset and tail), so no long argument list.
    function _sendStatic(bytes4 sel, string memory op, string memory fields, bytes memory words) internal {
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory a) = _mauth(op, fields, address(f2), words);
        bytes memory sig = abi.encode(a);
        bytes memory tail = new bytes(sig.length - 32);
        for (uint256 i; i < tail.length; ++i) tail[i] = sig[i + 32];
        bytes memory cd = bytes.concat(sel, abi.encode(e), abi.encode(address(f2)), words,
            abi.encode(uint256(32 * (8 + 1 + words.length / 32 + 1))), tail);
        vm.broadcast(k3);
        (bool ok,) = address(gr).call(cd);
        require(ok, string.concat("router op ", op));
    }

    /// @dev The DEX through the router: env 2 published, release 2 approved then revoked (its deploy the negative), release 1
    ///      deprecated (it was created from in `_dex`).
    function _dexRouter(uint32 gen, uint64 until) internal {
        IFactoryToken.Env memory de = f2.dexEnvOf(1);
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory a) =
            _mauth("UAPublishDexEnv", "uint16 envVersion,Env env,", address(f2), abi.encode(uint16(2), _envHash(de)));
        vm.broadcast(k3);
        gr.mtxPublishDexEnv(e, address(f2), 2, de, a);
        _dexApproveRevoke(abi.encode(ImplArgs(_dexModules(de))), gen, until);
        string memory why = "onchain matrix: deprecated after its use (the msig admin, through the router)";
        (e, a) = _mauth("UADeprecateDex", "uint64 version,string reason,", address(f2), abi.encode(uint64(1), keccak256(bytes(why))));
        vm.broadcast(k3);
        gr.mtxDeprecateDex(e, address(f2), 1, why, a);
    }

    /// @dev DEX release 2 approved through the router, then revoked; its deploy is the ReleaseNotApproved negative.
    function _dexApproveRevoke(bytes memory dexArgs, uint32 gen, uint64 until) internal {
        (bytes32 h1, bytes32 h2) = (keccak256(type(SCaaSDex).creationCode), keccak256(dexArgs));
        _sendStatic(gr.mtxApproveDexRelease.selector, "UAApproveDexRelease", "uint64 version,uint16 envVersion,"
            "bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until,",
            abi.encode(uint64(2), uint16(2), h1, h2, uid, address(f2), gen, until));
        bytes32 key = keccak256(abi.encode(keccak256("scaas.factory.release.dex"), uid, address(f2), uint64(2), uint16(2), h1, h2));
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory a) = _mauth("UARevokeApproval", "bytes32 key,", address(f2), abi.encode(key));
        vm.broadcast(k3);
        gr.mtxRevokeApproval(e, address(f2), key, a);
        _neg(a3, address(f2), abi.encodeCall(OpenFactory.deployDexImplementation, (2, 2, type(SCaaSDex).creationCode, dexArgs)),
            IOpenFactory.ReleaseNotApproved.selector, "factory: a DEX release whose approval the msig revoked");
    }

    function _dexModules(IFactoryToken.Env memory de) internal pure returns (address[] memory d) {
        d = new address[](2);
        (d[0], d[1]) = (de.libs[2], de.libs[3]);
    }

    /// @dev The class kind through the router: kind 2's env 1, its release approved and deployed by key 3, the kind switched on;
    ///      `_classKind`'s release 1 of kind 0 deprecated.
    function _classRouter(uint32 gen, uint64 until) internal {
        IFactoryToken.Env memory ce;
        ce.params = new bytes32[](1);
        ce.params[0] = bytes32(uint256(131_072));
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory a) = _mauth("UAPublishClassEnv",
            "uint16 contractClass,uint16 kind,uint16 envVersion,Env env,", address(f2),
            abi.encode(NOTE_CLASS, uint16(2), uint16(1), _envHash(ce)));
        vm.broadcast(k3);
        gr.mtxPublishClassEnv(e, address(f2), NOTE_CLASS, 2, 1, ce, a);
        _sendStatic(gr.mtxApproveRelease.selector, "UAApproveRelease", "uint16 contractClass,uint16 kind,uint64 version,"
            "uint16 envVersion,bytes4 initSelector,bytes4 interfaceId,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,"
            "address factory,uint32 adminGeneration,uint64 until,", bytes.concat(abi.encode(NOTE_CLASS, uint16(2), uint64(1),
            uint16(1), INoteKind.initialize.selector, type(INoteKind).interfaceId, keccak256(type(NoteKind).creationCode),
            keccak256("")), abi.encode(uid, address(f2), gen, until)));
        vm.broadcast(k3);
        f2.deployImplementation(IOpenFactory.ReleaseId(NOTE_CLASS, 2, 1), 1, INoteKind.initialize.selector,
            type(INoteKind).interfaceId, type(NoteKind).creationCode, "");
        (e, a) = _mauth("UASetClassKindEnabled", "uint16 contractClass,uint16 kind,bool on,", address(f2),
            abi.encode(NOTE_CLASS, uint16(2), true));
        vm.broadcast(k3);
        gr.mtxSetClassKindEnabled(e, address(f2), NOTE_CLASS, 2, true, a);
        string memory why = "onchain matrix: deprecated after its use (the msig admin, through the router)";
        (e, a) = _mauth("UADeprecateRelease", "uint16 contractClass,uint16 kind,uint64 version,string reason,", address(f2),
            abi.encode(NOTE_CLASS, uint16(0), uint64(1), keccak256(bytes(why))));
        vm.broadcast(k3);
        gr.mtxDeprecateRelease(e, address(f2), NOTE_CLASS, 0, 1, why, a);
    }

    /// @dev The msig's router envelope (lane 0, its next nonce, open mode, fee 0) and its `UASig`: slot 1 (the secp256k1 UA)
    ///      over the member digest of the named digest (`fields` the op's own, each followed by a comma).
    function _mauth(string memory op, string memory fields, address target, bytes memory words)
        internal view returns (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory s)
    {
        (e.from, e.nonce, e.validUntil) = (um, gr.mtxNonce(um, 0), vu);
        string memory typ = string.concat(op, "(bytes32 from,address target,", fields, E3R);
        if (bytes(fields).length != 0 && _hasEnv(fields)) typ = string.concat(typ, ENV_T);
        bytes32 d = _named(address(gr), typ, bytes.concat(abi.encode(target), words), e);
        bytes32 md = UAKinds.memberDigest(um, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_METATX, d));
        s.members = new IUARegistry.MemberSig[](1);
        (s.members[0].index, s.members[0].sig) = (1, _ecdsa(s1, UAKinds.uaMessage(UAKinds.SECP256K1, UAKinds.PURPOSE_MEMBER, md)));
    }

    function _hasEnv(string memory fields) internal pure returns (bool) {
        bytes memory f = bytes(fields);
        for (uint256 i; i + 8 <= f.length; ++i) {
            if (keccak256(abi.encodePacked(f[i], f[i + 1], f[i + 2], f[i + 3], f[i + 4], f[i + 5], f[i + 6], f[i + 7]))
                == keccak256("Env env,")) return true;
        }
        return false;
    }

    /// @dev `hashStruct(Env)` as the router hashes it (each array the `keccak256` of its 32-byte words).
    function _envHash(IFactoryToken.Env memory v) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256(bytes(ENV_T)), v.registry, v.smartKeyAccountImpl, v.hedera,
            keccak256(abi.encodePacked(v.deps)), keccak256(abi.encodePacked(v.params)), keccak256(abi.encodePacked(v.libs)),
            keccak256(abi.encodePacked(v.libCodeHashes))));
    }

    /// @dev The Step 5 env of kind 0 without its modules: registry, SmartKeyAccount implementation, libraries.
    function _plainEnv() internal returns (IFactoryToken.Env memory e) {
        e = f5.tokenEnvOf(IOpenFactory.TokenKind.NORMAL, 1);
        address[] memory m5 = ITokenModules(f5.implementationOf(IOpenFactory.TokenKind.NORMAL, 1)).modules();
        uint256 n;
        for (uint256 i; i < e.libs.length; ++i) if (!_in(e.libs[i], m5)) ++n;
        address[] memory l = new address[](n);
        bytes32[] memory h = new bytes32[](n);
        n = 0;
        string[3] memory names = ["GovernanceLib", "HederaLib", "MtxPipelineLib"]; // DeployBase's order
        for (uint256 i; i < e.libs.length; ++i) {
            if (_in(e.libs[i], m5)) continue;
            (l[n], h[n]) = (e.libs[i], e.libCodeHashes[i]);
            if (n < 3) _book(l[n], names[n]);
            ++n;
        }
        (e.libs, e.libCodeHashes) = (l, h);
    }

    function _in(address a, address[] memory xs) internal pure returns (bool) {
        for (uint256 i; i < xs.length; ++i) if (xs[i] == a) return true;
        return false;
    }

    /// @dev A new env (not an alias of `e`: env 2 is `e` itself, without the modules).
    function _withModules(IFactoryToken.Env memory e) internal view returns (IFactoryToken.Env memory w) {
        uint256 k = e.libs.length;
        address[] memory l = new address[](k + ms.length);
        bytes32[] memory h = new bytes32[](l.length);
        for (uint256 i; i < k; ++i) (l[i], h[i]) = (e.libs[i], e.libCodeHashes[i]);
        for (uint256 i; i < ms.length; ++i) (l[k + i], h[k + i]) = (ms[i], ms[i].codehash);
        w = IFactoryToken.Env(e.registry, e.smartKeyAccountImpl, e.hedera, e.deps, e.params, l, h);
    }

    function _cfg0(string memory name, string memory symbol) internal view returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals) = (name, symbol, 6);
        c.features = 1 << GovernanceBits.PAYABLE | 1 << GovernanceBits.MINTABLE | 1 << GovernanceBits.BURNABLE;
        c.admin = _pad(a1);
        c.roles.minter = _pad(a1);
        (c.initialSupply, c.initialHolder) = (1e12, a1);
    }

    /// @dev The DEX on f2: the deployed DEX env (GovernanceLib, TradeLib, the governance and liquidity modules) and the
    ///      release, one clone, deprecated.
    function _dex() internal {
        IFactoryToken.Env memory e = f5.dexEnvOf(1); // GovernanceLib, TradeLib, the deployed factory's two modules
        _book(e.libs[1], "TradeLib");
        _book(e.libs[2], "SCaaSDexGovernanceModule");
        _book(e.libs[3], "SCaaSDexLiquidityModule");
        address[] memory d = new address[](2);
        vm.startBroadcast(k1);
        d[0] = address(new SCaaSDexGovernanceModule(address(f2), "")); // a module names its factory (M1): this factory's own
        d[1] = address(new SCaaSDexLiquidityModule(address(f2), ""));
        vm.stopBroadcast();
        _book(d[0], "SCaaSDexGovernanceModule");
        _book(d[1], "SCaaSDexLiquidityModule");
        (e.libs[2], e.libCodeHashes[2]) = (d[0], d[0].codehash);
        (e.libs[3], e.libCodeHashes[3]) = (d[1], d[1].codehash);
        ISCaaSDex.DexConfig memory c = ISCaaSDex.DexConfig(_pad(a1), 0, a1, false, 0, a1);
        vm.startBroadcast(k1);
        f2.publishDexEnv(1, e);
        // a fixed limit: the release's regular + EIP-8037 state gas, simulated 51.9 M on the SCaaS testnet and 55.1 M on a
        // fresh anvil, would ask more than 60 M at the group's x 1.30
        address impl = f2.deployDexImplementation{gas: DEX_RELEASE_GAS}(1, 1, type(SCaaSDex).creationCode, abi.encode(ImplArgs(d)));
        address dex = f2.createDex(1, abi.encode(c), _salt("f2-dex"));
        vm.stopBroadcast(); // deprecated through the router by f2's msig admin (`_factoryRouter`)
        _book(impl, "SCaaSDex");
        _book(dex, "SCaaSDex");
        _neg(a1, address(f2), abi.encodeCall(OpenFactory.createDex, (1, abi.encode(c), _salt("n4"))),
            IOpenFactory.DexVersionDeprecated.selector, "factory: createDex of a deprecated release");
    }

    /// @dev A generic class kind (factory index spec §8): `NoteKind` as class 4, kind 0, version 1.
    function _classKind() internal {
        IFactoryToken.Env memory e;
        e.params = new bytes32[](1);
        e.params[0] = bytes32(uint256(131_072));
        IOpenFactory.ReleaseId memory id = IOpenFactory.ReleaseId(NOTE_CLASS, 0, 1);
        bytes memory init = abi.encodeCall(INoteKind.initialize, (_pad(a1), "onchain"));
        vm.startBroadcast(k1);
        f2.publishClassEnv(NOTE_CLASS, 0, 1, e);
        f2.deployImplementation(id, 1, INoteKind.initialize.selector, type(INoteKind).interfaceId, type(NoteKind).creationCode, "");
        f2.setClassKindEnabled(NOTE_CLASS, 0, true);
        f2.createInstance(id, _salt("note-1"), init);
        vm.stopBroadcast(); // deprecated through the router by f2's msig admin (`_factoryRouter`)
        _neg(a1, address(f2), abi.encodeCall(OpenFactory.createInstance, (id, _salt("n5"), init)),
            IOpenFactory.ReleaseIsDeprecated.selector, "factory: createInstance of a deprecated release");
        _neg(a1, address(f2), abi.encodeCall(OpenFactory.createInstance, (IOpenFactory.ReleaseId(NOTE_CLASS, 1, 1),
            _salt("n6"), init)), IOpenFactory.ReleaseUnknown.selector, "factory: createInstance of a kind with no release");
    }

    // ------------------------------------------------------------------ (3) MandateWallet

    function _token0() internal returns (address t) {
        vm.broadcast(k1);
        t = f5.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(_cfg0("Onchain misc", "oM0")), _salt("t0"));
        _book(t, "NormalToken");
        address impl = f5.implementationOf(IOpenFactory.TokenKind.NORMAL, 1);
        _book(impl, "NormalToken");
        address[] memory m5 = ITokenModules(impl).modules();
        for (uint256 i; i < m5.length; ++i) _book(m5[i], "NormalToken");
    }

    function _wsig(address w, uint256 pk, string memory head, MetaTxLib.UAEnvelope memory e, bytes memory args)
        internal view returns (IUARegistry.UASig memory)
    {
        return _sig(pk, _named(w, string.concat(head, E_TAIL), args, e));
    }

    function _mandate() internal {
        vm.broadcast(k1);
        MandateWallet w = new MandateWallet(_pad(a1), uid, address(reg), false);
        _book(address(w), "MandateWallet");
        (bytes32 d, bytes32 p) = (_pad(a2), _pad(a3));
        uint64 exp = uint64(vu);
        vm.startBroadcast(k1);
        IERC20(t0).transfer(address(w), 1_000_000);
        w.setMandate(t0, d, 1_000, 5_000, 1 days, exp); // epoch 1
        w.setPayee(t0, p, true);
        vm.stopBroadcast();
        // the delegate pays, direct then relayed (its pay lane `mandatePayLane(entryRef)`, nonce 0)
        MetaTxLib.PayMeta memory m = _meta("mw-1", 0, false);
        vm.broadcast(k2);
        w.payUnderMandate(t0, p, 100, _metaId(m), 1, m);
        m = _meta("mw-2", 0, false);
        bytes32 ref = _metaId(m);
        MetaTxLib.UAEnvelope memory e = _env(a2, w.mandatePayLane(ref), 0);
        IUARegistry.UASig memory s = _wsig(address(w), k2, "UAPayUnderMandate(bytes32 from,address token,bytes32 payee,"
            "uint256 amount,bytes32 entryRef,uint64 epoch,", e, abi.encode(t0, p, uint256(100), ref, uint64(1)));
        vm.broadcast(k3);
        w.mtxPayUnderMandate(e, t0, p, 100, ref, 1, s, m);
        _ownerRelayed(w, d, p, exp);
        _delegateRevokes(w, d, exp);
        _generic(w);
        _neg(a3, address(w), abi.encodeCall(MandateWallet.setMandate, (t0, d, 1, 1, 1, exp)), MandateWallet.NotOwner.selector,
            "wallet: setMandate by another than the owner");
        _neg(a2, address(w), abi.encodeCall(MandateWallet.payUnderMandate, (t0, p, 1, bytes32(0), w.epoch(t0), m)),
            MandateWallet.NoMandate.selector, "wallet: payUnderMandate after the revoke");
        _negMetaTx(w);
    }

    /// @dev The owner's signed entries, relayed by key 3 (lane `lane`, nonces in order).
    function _ownerRelayed(MandateWallet w, bytes32 d, bytes32 p, uint64 exp) internal {
        MetaTxLib.UAEnvelope memory e = _env(a1, lane, w.mtxNonce(_pad(a1), lane));
        IUARegistry.UASig memory s = _wsig(address(w), k1, "UASetPayee(bytes32 from,address token,bytes32 payee,bool allowed,", e,
            abi.encode(t0, d, true));
        vm.broadcast(k3);
        w.mtxSetPayee(e, t0, d, true, s);
        e.nonce++;
        s = _wsig(address(w), k1, "UASetMandate(bytes32 from,address token,bytes32 delegate,uint128 maxPerPayment,"
            "uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry,", e,
            abi.encode(t0, d, uint128(2_000), uint128(6_000), uint64(1 days), exp));
        vm.broadcast(k3);
        w.mtxSetMandate(e, t0, d, 2_000, 6_000, 1 days, exp, s); // epoch 2
        e.nonce++;
        s = _wsig(address(w), k1, "UARevokeMandate(bytes32 from,address token,", e, abi.encode(t0));
        vm.broadcast(k3);
        w.mtxRevokeMandate{gas: REFUND_GAS}(e, t0, s); // epoch 3
        e.nonce++;
        bytes memory data = abi.encodeCall(IERC20.transfer, (a1, 10));
        s = _wsig(address(w), k1, "UAExecute(bytes32 from,address target,uint256 value,bytes data,", e,
            abi.encode(t0, uint256(0), keccak256(data)));
        vm.broadcast(k3);
        w.mtxExecute{gas: REFUND_GAS}(e, t0, 0, data, s);
        vm.startBroadcast(k1);
        w.execute{gas: REFUND_GAS}(t0, 0, abi.encodeCall(IERC20.transfer, (a1, 10)));
        w.setMandate(t0, d, 1_000, 5_000, 1 days, exp); // epoch 4
        w.revoke{gas: REFUND_GAS}(t0); // epoch 5
        w.setMandate(t0, d, 1_000, 5_000, 1 days, exp); // epoch 6
        vm.stopBroadcast();
        p;
    }

    /// @dev The delegate's two revokes: direct, then signed (its revoke lane `mandateRevokeLane(token, epoch)`, nonce 0).
    function _delegateRevokes(MandateWallet w, bytes32 d, uint64 exp) internal {
        vm.broadcast(k2);
        w.revoke{gas: REFUND_GAS}(t0, 6); // epoch 7
        vm.broadcast(k1);
        w.setMandate(t0, d, 1_000, 5_000, 1 days, exp); // epoch 8
        MetaTxLib.UAEnvelope memory e = _env(a2, w.mandateRevokeLane(t0, 8), 0);
        IUARegistry.UASig memory s = _wsig(address(w), k2, "UADelegateRevoke(bytes32 from,address token,uint64 epoch,", e,
            abi.encode(t0, uint64(8)));
        vm.broadcast(k3);
        w.mtxDelegateRevoke{gas: REFUND_GAS}(e, t0, 8, s); // epoch 9
    }

    /// @dev The generic UA path (UAMetaTxBase): mtxExecute and mtxBatch over `UAMetaTransaction`, mtxCancelNonce, cancelNonce.
    function _generic(MandateWallet w) internal {
        bytes32 me = _pad(a1);
        MetaTxLib.UAMetaTransaction memory m =
            MetaTxLib.UAMetaTransaction(me, abi.encodeCall(MandateWallet.setPayee, (t0, _pad(a3), false)), lane + 1, 0, vu, 0,
            address(0), 0, address(0));
        IUARegistry.UASig memory s = _sig(k1, w.mtxDigest(m));
        vm.broadcast(k3);
        w.mtxExecute{gas: REFUND_GAS}(m, s);
        MetaTxLib.UAMetaTransaction[] memory b = new MetaTxLib.UAMetaTransaction[](2);
        IUARegistry.UASig[] memory bs = new IUARegistry.UASig[](2);
        for (uint256 i; i < 2; ++i) {
            b[i] = MetaTxLib.UAMetaTransaction(me, abi.encodeCall(MandateWallet.setPayee, (t0, bytes32(uint256(0xbeef + i)), true)),
                lane + 2, i, vu, 0, address(0), 0, address(0));
            bs[i] = _sig(k1, w.mtxDigest(b[i]));
        }
        vm.broadcast(k3);
        w.mtxBatch(b, bs);
        MetaTxLib.UAEnvelope memory e = _env(a1, lane + 3, 0);
        s = _wsig(address(w), k1, "UACancelNonce(bytes32 from,uint256 lane,", e, abi.encode(lane + 4));
        vm.broadcast(k3);
        w.mtxCancelNonce(e, lane + 4, s);
        vm.broadcast(k1);
        w.cancelNonce(lane + 5);
    }

    /// @dev The address `executeMetaTransaction` (MetaTxBase): the wallet takes no address meta-transaction (`_execute`
    ///      refuses every selector), so a correctly signed one is refused by name.
    function _negMetaTx(MandateWallet w) internal {
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.batch, m.nonce, m.validUntil) =
            (a1, abi.encodeCall(MandateWallet.setPayee, (t0, _pad(a3), true)), lane + 6, 0, vu);
        bytes memory sig = _ecdsa(k1, _digest(address(w), MtxHash.hashStruct(m)));
        _neg(a3, address(w), abi.encodeCall(IMetaTx.executeMetaTransaction, (m, sig)),
            bytes4(keccak256("MtxSelectorNotAllowed(bytes4)")), "wallet: an address meta-transaction (none is taken)");
    }

    // ------------------------------------------------------------------ (4) the reference service

    function _token8() internal returns (address t) {
        IFactoryToken.TokenConfig memory c = _cfg0("Onchain misc reg", "oM8");
        c.features |= 1 << GovernanceBits.KYC; // round 3s: the registry check is bit 28
        c.reg.complianceRegistry = _dep("compliance_registry");
        c.reg.deniedFlags = 1 << 16; // an issuer flag nobody holds here: the check runs and refuses nobody
        c.reg.termsHash = keccak256("onchain matrix terms");
        c.roles.issuer = _pad(a1); // group 3s: the list bits 8, 9 (off, enableable), any holder
        vm.broadcast(k1);
        t = f5.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), _salt("t8"));
        _denyList(t);
        _book(t, "NormalRegulatedToken");
        address impl = f5.implementationOf(IOpenFactory.TokenKind.NORMAL_REGULATED, 1);
        _book(impl, "NormalRegulatedToken");
        address[] memory m5 = ITokenModules(impl).modules();
        for (uint256 i; i < m5.length; ++i) _book(m5[i], "NormalRegulatedToken");
    }

    /// Group 3s (spec 2026-11-10-token-lists.md §5.2, §6, §15 T8): a deny list written while off by a1's issuer seat, switched
    /// on at once (`FeatureEnabled(9)`): a transfer to a denied account refused `Denied` (a negative), and a second denied
    /// account cleared, at once, then a transfer to it passes. The negative is an `eth_call` at the run's last block
    /// (`coverage.py neg`), so the account it names stays denied; the cleared one is another.
    function _denyList(address t) internal {
        (address denied, address cleared) = (address(0xDE41ED), address(0xC1EA2ED));
        bytes32[] memory two = new bytes32[](2);
        (two[0], two[1]) = (_pad(denied), _pad(cleared));
        bytes32[] memory one = new bytes32[](1);
        one[0] = _pad(cleared);
        vm.startBroadcast(k1);
        IRegulatedToken(t).setDenied(two, true);
        IRegulatedToken(t).enableFeature(GovernanceBits.DENYLIST);
        vm.stopBroadcast();
        _neg(a1, t, abi.encodeCall(IERC20.transfer, (denied, 1)), IRegulatedToken.Denied.selector,
            "transfer to an account on the deny list (kind 8, DENYLIST switched on at once)");
        vm.startBroadcast(k1);
        IRegulatedToken(t).setDenied(one, false);
        IERC20(t).transfer(cleared, 1);
        vm.stopBroadcast();
    }

    function _pull(address t, address s, uint256 v, bytes32 ref) internal view returns (MetaTxLib.UAMetaTransfer memory x) {
        uint256 b = 7;
        x = MetaTxLib.UAMetaTransfer(_pad(a1), _pad(s), v, ref, b, NormalToken(t).mtxNonce(_pad(a1), b), vu,
            MetaTxLib.MODE_RESTRICT_RELAYER, s, 0, address(0));
    }

    function _escrow(address t, string memory tag) internal {
        vm.broadcast(k1);
        RefServiceEscrow s = new RefServiceEscrow(t);
        _book(address(s), "RefServiceEscrow");
        RefServiceEscrow.Deposit memory op =
            RefServiceEscrow.Deposit(_pad(a1), 500, uint64(block.timestamp), _salt(string.concat("dep-", tag)));
        bytes32 ref = s.depositRef(op);
        MetaTxLib.UAMetaTransfer memory x = _pull(t, address(s), 500, ref);
        IUARegistry.UASig memory a = _sig(k1, NormalToken(t).mtxTransferDigest(x));
        vm.broadcast(k3);
        s.deposit(op, x, a);
        _neg(a3, address(s), abi.encodeCall(RefServiceEscrow.deposit, (op, x, a)), RefServiceEscrow.ServicePullReplayed.selector,
            string.concat("escrow ", tag, ": a deposit replayed"));
        RefServiceEscrow.Note memory n = RefServiceEscrow.Note(_pad(a1), 300, "onchain matrix note", hex"c0ffee",
            _salt(string.concat("note-", tag)));
        bytes32 nref = s.noteRef(n);
        x = _pull(t, address(s), 300, nref);
        a = _sig(k1, NormalToken(t).mtxTransferDigest(x));
        vm.broadcast(k3);
        s.note(n, x, a);
        vm.startBroadcast(k2); // release is permissionless
        s.release{gas: REFUND_GAS}(ref);
        s.release{gas: REFUND_GAS}(nref);
        vm.stopBroadcast();
        _neg(a2, address(s), abi.encodeCall(RefServiceEscrow.release, (ref)), RefServiceEscrow.NotReleasable.selector,
            string.concat("escrow ", tag, ": a release twice"));
    }
}
