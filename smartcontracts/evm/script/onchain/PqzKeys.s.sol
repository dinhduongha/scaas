// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/console2.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Tokens} from "./Tokens.s.sol";
import {kindModuleNames, kindImplArgs} from "../KindModules.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {IPqzToken, IPqzWrappedToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {HederaLib} from "../../src/hedera/HederaLib.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {WrappedLib} from "../../src/metatx/WrappedLib.sol";
import {RegulatedLib} from "../../src/regulated/RegulatedLib.sol";
import {PqzStateLib} from "../../src/pqz/PqzStateLib.sol";
import {PqzTransferLib} from "../../src/pqz/PqzTransferLib.sol";
import {PqzBurnLib} from "../../src/pqz/PqzBurnLib.sol";
import {PqzViewLib} from "../../src/pqz/PqzViewLib.sol";
import {PqzWrappedLib} from "../../src/pqz/PqzWrappedLib.sol";
import {MockERC20} from "../../test/helpers/Mocks.sol";
import {PqzArgs} from "../../test/pqz/helpers/PqzArgs.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {OnchainRouter} from "./Dex.s.sol";
import {ImplArgs} from "../../src/metatx/ITokenModule.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {SCaaSDexGovernanceModule} from "../../src/dex/SCaaSDexAdmin.sol";
import {SCaaSDexLiquidityModule} from "../../src/dex/SCaaSDexLiquidityModule.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {MockV2Factory, MockV2LiquidityPair} from "../../test/liquidity/LiquidityMocks.sol";

/// @notice Group `pqzkeys` (spec 2026-11-13-pqz-three-keys §15.2, step 7c): the PQZ kinds 4, 5, 12, 13 on the local chain in
///         the `OFFCHAIN` verify mode (no PQZ precompile on anvil: the releases on deps `[0]`, a verifier EOA signs each
///         `PqzVerdict`), released by this group's own factory (notice 0). Holders are ML-DSA-65 UAs (keys and signatures
///         by script/pqz/mldsa.mjs through `vm.ffi`: run with `--ffi`), each with scoped PQZ key records (K3-3). Two runs
///         (`pqzkeys.sh`): `PqzKeysSetup.setup()` the factory, the holders and their records, the public layer of every
///         PQZ kind (`Tokens`' sweep, the 212 entries the pq groups left uncalled), the confidential layer per class
///         (class 2 `offchain-shared`, class 3 with and without the sealed opening) and their negatives; then, after the
///         `ROLL_AGE` blocks, `PqzKeysRoll.roll()` the rollovers, whose signed form binds the pending slots as they are on
///         chain (a forge run simulates before it sends: a slot written in the same run would carry another block).
///         Ciphertexts and proofs are filler bytes (an `OFFCHAIN` token checks the verifier's verdict, not the proof);
///         what a wallet checks of an opening (it opens, the credit is spent; a planted bad credit) needs pqz-ffi and is
///         the pq group's (pending its three-key path). Round 3zb: a `BURNER` token of kinds 4 and 12 (`_burnerPqz`).
///         Test keys only. UNAUDITED.
abstract contract PqzKeysKit is Tokens, PqzArgs {
    bytes internal constant VPROOF = hex"c0de";
    uint64 internal constant WIN = 10_000; // validUntilBlock windows: the simulation lags the chain by the run's sends

    OpenFactory internal fp; // this group's factory
    uint256 internal vk; // the verifier EOA's key (derived from test key 1; it signs only, no funds)
    bytes32 internal vA; // its native id
    bytes32 internal bobSeed;
    bytes32 internal carolSeed;
    bytes32 internal bob;
    bytes32 internal carol;
    bytes32 internal mu; // a PQ-eligible msig of bob and carol (threshold 1; bob signs)
    bytes32 internal daveSeed; // set-auditor: the replacement auditor (`_auditorPqz`)
    bytes32 internal dave;
    address internal c2; // kind 4, class 2 (scope 0, the opening)
    address internal c3o; // kind 4, class 3 with the opening
    address internal c3; // kind 4, class 3 without the opening
    address internal t5; // kind 5, class 3 without the opening
    address internal t12; // kind 12, class 3 without the opening
    address internal t13; // kind 13, class 3 without the opening
    MockERC20 internal leg; // the confidential wrapped kinds' leg
    address internal o5; // kind 5, class 3 with the opening (the signed rollover per kind)
    address internal o12; // kind 12, likewise
    address internal o13; // kind 13, likewise
    uint256 internal keySeed;
    mapping(string => string) internal typeOf; // the named entries' type strings read so far

    function _vInit() internal {
        vk = uint256(keccak256(abi.encode("scaas.onchain.pqzkeys.verifier", k1))) % (type(uint128).max) + 1;
        vA = _pad(vm.addr(vk));
    }

    function _deps() internal {
        _init("pqzkeys");
        _vInit();
        f = OpenFactory(_dep("token_factory"));
        router = _dep("relay_fee_router");
        registry = _dep("ua_registry");
        compliance = _dep("compliance_registry");
        _book(address(f), "OpenFactory");
        _book(router, "RelayFeeRouter");
        _book(_dep("relay_fee_executor"), "RelayFeeExecutor");
        _book(registry, "UARegistry");
    }

    function _state() internal view returns (string memory) {
        return string.concat("deployments/pqzkeys-", net, "-state.json");
    }

    // ------------------------------------------------------------------ ML-DSA-65 holders

    function _mlBy(bytes32 seed, bytes32 uaMsg) internal returns (bytes memory) {
        return _ml(string.concat("sign 65 ", _bare(seed), " ", _bare(PqUA.pqMessage(PqUA.tag(ML65), uaMsg))));
    }

    function _uaSig(bytes32 seed, bytes32 purpose, bytes32 digest) internal returns (IUARegistry.UASig memory s) {
        s.signature = _mlBy(seed, IUARegistry(registry).uaMessage(ML65, purpose, digest));
    }

    /// The msig's `UASig`: slot `_bobSlot()` (bob, an accepted member) under `member` over `memberDigest(mu, uaMessage(msig,
    /// purpose, digest))` (CTR-UA-37).
    function _msigSig(bytes32 purpose, bytes32 digest) internal returns (IUARegistry.UASig memory s) {
        bytes32 md = UAKinds.memberDigest(mu, UAKinds.uaMessage(UAKinds.MSIG, purpose, digest));
        s.members = new IUARegistry.MemberSig[](1);
        (s.members[0].index, s.members[0].sig) =
        (_bobSlot(), _mlBy(bobSeed, IUARegistry(registry).uaMessage(ML65, UAKinds.PURPOSE_MEMBER, md)));
    }

    function _bobSlot() internal view returns (uint16) {
        return uint256(bob) < uint256(carol) ? 0 : 1;
    }

    function _seedOf(bytes32 ua) internal view returns (bytes32) {
        return ua == uaM ? mlSeed : ua == bob ? bobSeed : ua == dave ? daveSeed : carolSeed;
    }

    // ------------------------------------------------------------------ the client's bytes

    /// `n` canonical bytes from `seed` (every 64-bit lane < 2^40 < q at every set).
    function _blob(uint256 seed, uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            uint256 w = uint256(keccak256(abi.encode(seed, i)))
                & 0x000000ffffffffff000000ffffffffff000000ffffffffff000000ffffffffff;
            assembly ("memory-safe") { mstore(add(add(b, 32), i), w) }
        }
    }

    function _opening(uint256 seed) internal pure returns (IPqzToken.PqzOpening memory o) {
        (o.mlkemCt, o.x25519Eph, o.sealedSeed) =
        (_blob(seed, PqzCore.MLKEM_CT), keccak256(abi.encode("eph", seed)), _blob(seed + 1, PqzCore.SEALED_SEED));
    }

    function _opens(address t) internal view returns (bool) {
        return IPqzToken(t).pqzVerifyConfig().pqzOpening;
    }

    /// Op 1 of `from` to `to` at its `pendingCount` (no fee, no auditor); on an opening token `uFrom` and `openingTo`.
    function _op1(address t, bytes32 from, bytes32 to, uint256 seed)
        internal
        view
        returns (IPqzToken.PqzTransferArgs memory a)
    {
        (a.p, a.validUntilBlock, a.fromUA, a.toUA) =
        (IPqzToken(t).pqzAccount(from, 0).pendingCount, block.number + WIN, from, to);
        (a.salt, a.u, a.vTo, a.vFrom) =
        (
            bytes16(keccak256(abi.encode(seed))),
            _blob(seed, PqzCt.PK),
            _blob(seed + 1, PqzCt.V),
            _blob(seed + 2, PqzCt.V)
        );
        if (_opens(t)) (a.uFrom, a.openingTo) = (_blob(seed + 7, PqzCt.PK), _opening(seed));
    }

    /// Op 7 of `from` to `to` and a decoy leg (`M = 2`), no auditor.
    function _op7(address t, bytes32 from, bytes32 to, bytes32 decoy, uint256 seed)
        internal
        view
        returns (IPqzToken.PqzMultiArgs memory a)
    {
        (a.p, a.validUntilBlock, a.fromUA) = (IPqzToken(t).pqzAccount(from, 0).pendingCount, block.number + WIN, from);
        (a.salt, a.vFrom) = (bytes16(keccak256(abi.encode(seed))), _blob(seed + 2, PqzCt.V));
        a.u = new bytes[](1);
        a.u[0] = _blob(seed, PqzCt.PK);
        a.legs = new IPqzToken.PqzLeg[](2);
        a.legs[0] = IPqzToken.PqzLeg(to, _blob(seed + 3, PqzCt.V), "");
        a.legs[1] = IPqzToken.PqzLeg(decoy, _blob(seed + 4, PqzCt.V), "");
    }

    /// A burn of `from` at its `pendingCount`.
    function _burnArgs(address t, bytes32 from, uint256 seed) internal view returns (IPqzToken.PqzBurnArgs memory b) {
        (b.p, b.validUntilBlock, b.fromUA) = (IPqzToken(t).pqzAccount(from, 0).pendingCount, block.number + WIN, from);
        (b.u, b.vFrom) = (_blob(seed, PqzCt.PK), _blob(seed + 1, PqzCt.V));
    }

    /// The holder's `PqzAuth` digest of statement `st` under op byte `op` (PqzCore.authDigest), in `t`'s domain.
    function _authDigest(address t, uint8 op, bytes memory st) internal view returns (bytes32) {
        bytes memory head = new bytes(640);
        for (uint256 i; i < 640; ++i) {
            head[i] = st[i];
        }
        bytes memory body = new bytes(st.length - 640);
        for (uint256 i; i < body.length; ++i) {
            body[i] = st[640 + i];
        }
        return _digest(t, keccak256(abi.encodePacked(PqzCore.AUTH_TYPEHASH, uint256(op), head, keccak256(body))));
    }

    function _auth(address t, bytes32 from, uint8 op, bytes memory st) internal returns (IUARegistry.UASig memory) {
        return _uaSig(_seedOf(from), UAKinds.PURPOSE_ZETHER_AUTH, _authDigest(t, op, st));
    }

    /// The verifier's signed verdict over `st` and `VPROOF` on `t` (its epoch; a day).
    function _sv(address t, bytes memory st) internal view returns (IPqzToken.PqzSignedVerdict memory sv) {
        IPqzToken.PqzVerdict memory v = IPqzToken.PqzVerdict(
            t,
            block.chainid,
            NormalPqzToken(t).proofSystemId(),
            keccak256(st),
            keccak256(VPROOF),
            IPqzToken(t).pqzVerifyConfig().pqzVerifierEpoch,
            uint64(block.timestamp + 1 days)
        );
        bytes32 d = _digest(t, keccak256(abi.encode(PqzCore.VERDICT_TYPEHASH, v)));
        (uint8 w, bytes32 r, bytes32 s) =
            vm.sign(vk, IUARegistry(registry).uaAuthDigest(vA, UAKinds.PURPOSE_PQZ_VERDICT, d));
        sv.pqzVerdict = v;
        sv.sig.signature = abi.encodePacked(r, s, w);
    }

    // ------------------------------------------------------------------ the confidential entries, direct (sent by test key 2)

    function _send1(address t, IPqzToken.PqzTransferArgs memory a, bool compact) internal {
        if (compact) a.sealedMemo = _blob(uint256(keccak256(abi.encode(a.salt))), PqzCore.SEALED); // the commit-reveal memo
        bytes memory st = NormalPqzToken(t).transferSingleStatement(a, 0);
        IUARegistry.UASig memory au = _auth(t, a.fromUA, 1, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        vm.broadcast(k2);
        if (compact) IPqzToken(t).mtxConfidentialTransferSingleCompact(a, VPROOF, au, "", sv);
        else IPqzToken(t).mtxConfidentialTransferSingle(a, VPROOF, au, "", sv);
    }

    function _send7(address t, IPqzToken.PqzMultiArgs memory a, bool compact) internal {
        if (compact) a.sealedMemo = _blob(uint256(keccak256(abi.encode(a.salt))), 2 + 40 * a.legs.length);
        bytes memory st = NormalPqzToken(t).transferStatement(a, 0);
        IUARegistry.UASig memory au = _auth(t, a.fromUA, 7, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        vm.broadcast(k2);
        if (compact) IPqzToken(t).mtxConfidentialTransferCompact(a, VPROOF, au, "", sv);
        else IPqzToken(t).mtxConfidentialTransfer(a, VPROOF, au, "", sv);
    }

    function _unshield(address t, bytes32 from, uint256 amount, bytes32 recipient, uint256 seed) internal {
        IPqzToken.PqzBurnArgs memory b = _burnArgs(t, from, seed);
        bytes memory st = NormalPqzToken(t).burnStatement(b, amount, recipient, 0);
        IUARegistry.UASig memory au = _auth(t, from, 2, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        vm.broadcast(k2);
        IPqzToken(t).mtxUnshield(b, amount, recipient, VPROOF, au, "", sv);
    }

    function _unshieldUnwrap(address t, bytes32 from, uint256 amount, uint256 seed) internal {
        IPqzToken.PqzBurnArgs memory b = _burnArgs(t, from, seed);
        IConfidentialWrappedToken.Unwrap memory x = IConfidentialWrappedToken.Unwrap(address(leg), _pad(a3), amount, 0);
        bytes memory st = WrappedPqzToken(payable(t)).unshieldUnwrapStatement(b, x, 0);
        IUARegistry.UASig memory au = _auth(t, from, 2, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        vm.broadcast(k2);
        IPqzWrappedToken(t).mtxUnshieldUnwrap(b, x, VPROOF, au, "", sv);
    }

    // ------------------------------------------------------------------ the named entries (the UA envelope, relayed)

    /// A named entry's EIP-712 type string, as clientkeys' typed_ops.json has it (the contract's, pinned by forge and clientkeys).
    function _typ(string memory op) internal returns (string memory) {
        if (bytes(typeOf[op]).length != 0) return typeOf[op];
        string[] memory c = new string[](5);
        (c[0], c[1], c[2], c[3]) =
        (
            "python3",
            "-I",
            "-c",
            "import json,sys; sys.stdout.write(json.load(open("
            "'../vectors/typed/typed_ops.json'))['ops'][sys.argv[1]]['typeString'])"
        );
        c[4] = op;
        typeOf[op] = string(vm.ffi(c)); // only the line read: the whole file in the script's memory costs its gas
        return typeOf[op];
    }

    /// The holder's UA envelope on `t` (lane 20, mode 0, no fee).
    function _henv(address t, bytes32 from) internal view returns (MetaTxLib.UAEnvelope memory e) {
        (e.from, e.batch, e.nonce, e.validUntil) = (from, 20, NormalPqzToken(t).mtxNonce(from, 20), vu);
    }

    /// The statement's `binding` of a relayed op (`envelopeBinding`: every envelope field but `data`).
    function _bindingOf(address t, MetaTxLib.UAEnvelope memory e) internal view returns (bytes32) {
        MetaTxLib.UAMetaTransaction memory m;
        (m.from, m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient) =
        (e.from, e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee, e.feeRecipient);
        return NormalPqzToken(t).envelopeBinding(m);
    }

    /// The envelope signer's (the holder's ML-DSA key) signature of named entry `op` over `words`.
    function _envAuth(address t, string memory op, MetaTxLib.UAEnvelope memory e, bytes memory words)
        internal
        returns (IUARegistry.UASig memory)
    {
        return _uaSig(_seedOf(e.from), UAKinds.PURPOSE_METATX, _named(t, _typ(op), words, e));
    }

    function _named1(address t, IPqzToken.PqzTransferArgs memory a, bool compact) internal {
        if (compact) a.sealedMemo = _blob(uint256(keccak256(abi.encode(a.salt))), PqzCore.SEALED);
        MetaTxLib.UAEnvelope memory e = _henv(t, a.fromUA);
        bytes memory st = NormalPqzToken(t).transferSingleStatement(a, _bindingOf(t, e));
        IUARegistry.UASig memory pa = _auth(t, a.fromUA, 1, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        IUARegistry.UASig memory au = _envAuth(
            t,
            compact ? "UAPqzTransferSingleCompact" : "UAPqzTransferSingle",
            e,
            abi.encode(_hashT(a), keccak256(VPROOF), keccak256(""))
        );
        vm.broadcast(k2);
        if (compact) NormalPqzToken(t).mtxConfidentialTransferSingleCompact(e, a, VPROOF, pa, "", au, sv);
        else NormalPqzToken(t).mtxConfidentialTransferSingle(e, a, VPROOF, pa, "", au, sv);
    }

    function _named7(address t, IPqzToken.PqzMultiArgs memory a, bool compact) internal {
        if (compact) a.sealedMemo = _blob(uint256(keccak256(abi.encode(a.salt))), 2 + 40 * a.legs.length);
        MetaTxLib.UAEnvelope memory e = _henv(t, a.fromUA);
        bytes memory st = NormalPqzToken(t).transferStatement(a, _bindingOf(t, e));
        IUARegistry.UASig memory pa = _auth(t, a.fromUA, 7, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        IUARegistry.UASig memory au = _envAuth(
            t,
            compact ? "UAPqzTransferCompact" : "UAPqzTransfer",
            e,
            abi.encode(_hashM(a), keccak256(VPROOF), keccak256(""))
        );
        vm.broadcast(k2);
        if (compact) NormalPqzToken(t).mtxConfidentialTransferCompact(e, a, VPROOF, pa, "", au, sv);
        else NormalPqzToken(t).mtxConfidentialTransfer(e, a, VPROOF, pa, "", au, sv);
    }

    function _namedUnshield(address t, bytes32 from, uint256 amount, bytes32 recipient, uint256 seed) internal {
        IPqzToken.PqzBurnArgs memory b = _burnArgs(t, from, seed);
        MetaTxLib.UAEnvelope memory e = _henv(t, from);
        bytes memory st = NormalPqzToken(t).burnStatement(b, amount, recipient, _bindingOf(t, e));
        IUARegistry.UASig memory pa = _auth(t, from, 2, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        IUARegistry.UASig memory au =
            _envAuth(t, "UAPqzUnshield", e, abi.encode(_hashB(b), amount, recipient, keccak256(VPROOF), keccak256("")));
        vm.broadcast(k2);
        NormalPqzToken(t).mtxUnshield(e, b, IPqzToken.Payout(amount, recipient), VPROOF, pa, "", au, sv);
    }

    bytes32 internal constant TH_UNWRAP =
        keccak256("Unwrap(address underlying,bytes32 recipient,uint256 amount,uint256 minOut)");

    function _namedUnwrap(address t, bytes32 from, uint256 amount, uint256 seed) internal {
        IPqzToken.PqzBurnArgs memory b = _burnArgs(t, from, seed);
        IConfidentialWrappedToken.Unwrap memory x = IConfidentialWrappedToken.Unwrap(address(leg), _pad(a3), amount, 0);
        MetaTxLib.UAEnvelope memory e = _henv(t, from);
        bytes memory st = WrappedPqzToken(payable(t)).unshieldUnwrapStatement(b, x, _bindingOf(t, e));
        IUARegistry.UASig memory pa = _auth(t, from, 2, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        IUARegistry.UASig memory au = _envAuth(
            t,
            "UAPqzUnshieldUnwrap",
            e,
            abi.encode(
                _hashB(b),
                keccak256(abi.encode(TH_UNWRAP, x.underlying, x.recipient, x.amount, x.minOut)),
                keccak256(VPROOF),
                keccak256("")
            )
        );
        vm.broadcast(k2);
        WrappedPqzToken(payable(t)).mtxUnshieldUnwrap(e, b, x, VPROOF, pa, "", au, sv);
    }

    /// `mtxPrepareAcc` / `mtxRollOver` relayed: test key 1's native id signs the envelope, test key 2 sends.
    function _namedAccOp(address t, bool roll, bytes32 ua, uint256 x) internal {
        MetaTxLib.UAEnvelope memory e = _env(a1, 21, NormalPqzToken(t).mtxNonce(_pad(a1), 21));
        IUARegistry.UASig memory s =
            _sig(k1, _named(t, _typ(roll ? "UAPqzRollOver" : "UAPrepareAcc"), abi.encode(ua, uint64(0), x), e));
        vm.broadcast(k2);
        if (roll) NormalPqzToken(t).mtxRollOver(e, ua, 0, x, s);
        else NormalPqzToken(t).mtxPrepareAcc(e, ua, 0, x, s);
    }

    // ------------------------------------------------------------------ the owner's ops: direct, and through the router

    function _routerAuth(string memory op, address target, bytes memory words)
        internal
        returns (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory s)
    {
        address gr = _dep("governance_router");
        (e.from, e.nonce, e.validUntil) = (_pad(a1), GovernanceRouter(gr).mtxNonce(_pad(a1), 0), vu);
        s = _sig(k1, _named(gr, _typ(op), bytes.concat(abi.encode(target), words), e));
    }

    /// The owner's verifier transfer proposed and cancelled, the proof store to LOG and back (bit 24 granted to the owner),
    /// a verifier fee increase proposed and cancelled, then the revocation (last on the token). `router`: each through the
    /// GovernanceRouter (test key 1's native id signs, test key 2 sends), the bit's grant direct.
    function _ownerOps(address t, bool router) internal {
        bytes32 uid = NormalPqzToken(t).chainUid();
        vm.broadcast(k1);
        IGovernance(t).grantRole(GovernanceBits.PQZ_PROOF, _pad(a1), uid);
        if (!router) {
            vm.startBroadcast(k1);
            IPqzToken(t).pqzSetVerifier(_pad(a3), uid);
            IPqzToken(t).pqzCancelVerifier(uid);
            IPqzToken(t).setProofStore(1, uid);
            IPqzToken(t).setProofStore(0, uid);
            IPqzToken(t).setVerifierFee(2, uid);
            IPqzToken(t).setVerifierFee(0, uid);
            IPqzToken(t).pqzRevokeVerifier(uid);
            vm.stopBroadcast();
        } else {
            _routerOps(t, uid);
        }
        require(IPqzToken(t).pqzVerifyConfig().verifier == 0, "revoked");
    }

    function _routerOps(address t, bytes32 uid) internal {
        GovernanceRouter gr = GovernanceRouter(_dep("governance_router"));
        (MetaTxLib.UAEnvelope memory e, IUARegistry.UASig memory s) =
            _routerAuth("UAPqzSetVerifier", t, abi.encode(_pad(a3), uid));
        vm.broadcast(k2);
        gr.mtxPqzSetVerifier(e, t, _pad(a3), uid, s);
        (e, s) = _routerAuth("UAPqzCancelVerifier", t, abi.encode(uid));
        vm.broadcast(k2);
        gr.mtxPqzCancelVerifier(e, t, uid, s);
        (e, s) = _routerAuth("UASetProofStore", t, abi.encode(uint8(1), uid));
        vm.broadcast(k2);
        gr.mtxSetProofStore(e, t, 1, uid, s);
        (e, s) = _routerAuth("UASetVerifierFee", t, abi.encode(uint64(2), uid));
        vm.broadcast(k2);
        gr.mtxSetVerifierFee(e, t, 2, uid, s);
        (e, s) = _routerAuth("UAPqzRevokeVerifier", t, abi.encode(uid));
        vm.broadcast(k2);
        gr.mtxPqzRevokeVerifier(e, t, uid, s);
    }

    // ------------------------------------------------------------------ the signed rollover (CTR-PQZ-41)

    bytes32 internal constant ROLL_TH = keccak256(
        "PqzRollOver(bytes32 ua,uint64 keyVersion,uint64 rollSeq,uint64 rolled,uint64 n,uint64[] skip,bytes32 entriesHash,uint64 validUntilBlock,bytes32 chainUid)"
    );

    /// The client's `h(i)`: the slot without the mark, the blob's code hash or 0 for a TRIVIAL entry.
    function _eh(address t, bytes32 ua, uint256 i) internal view returns (bytes32) {
        uint256 e = IPqzToken(t).pqzPending(ua, 0, uint64(i)) & ~uint256(PqzCore.SKIP);
        bytes32 c = uint16(e >> 64) == 0 ? bytes32(0) : address(uint160(e >> 96)).codehash;
        return keccak256(abi.encode(i, e, c));
    }

    function _entries(address t, bytes32 ua, uint64 n, uint64[] memory skip) internal view returns (bytes32) {
        uint64 r = IPqzToken(t).pqzAccount(ua, 0).rolled;
        bytes32[] memory h = new bytes32[](n + skip.length);
        for (uint256 k_; k_ < n; ++k_) {
            h[k_] = _eh(t, ua, r + k_);
        }
        for (uint256 j; j < skip.length; ++j) {
            h[n + j] = _eh(t, ua, skip[j]);
        }
        return keccak256(abi.encodePacked(h));
    }

    function _rollDigest(address t, bytes32 ua, uint64 n, uint64[] memory skip, uint64 vub, bytes32 eh)
        internal
        view
        returns (bytes32)
    {
        IPqzToken.AccountState memory s = IPqzToken(t).pqzAccount(ua, 0);
        return _digest(
            t,
            keccak256(
                bytes.concat(
                    abi.encode(ROLL_TH, ua, uint64(0), s.rollSeq, s.rolled, n),
                    abi.encode(keccak256(abi.encodePacked(skip)), eh, vub, NormalPqzToken(t).chainUid())
                )
            )
        );
    }

    function _rollSig(address t, bytes32 ua, uint64 n, uint64[] memory skip, uint64 vub)
        internal
        returns (IUARegistry.UASig memory)
    {
        return _uaSig(
            _seedOf(ua), UAKinds.PURPOSE_ZETHER_AUTH, _rollDigest(t, ua, n, skip, vub, _entries(t, ua, n, skip))
        );
    }

    function _sk(uint64 a) internal pure returns (uint64[] memory s) {
        s = new uint64[](1);
        s[0] = a;
    }

    // ------------------------------------------------------------------ the PQZ kinds of `Tokens`' sweep

    function _pqzKind(uint8 kind) internal pure returns (bool) {
        return kind == 4 || kind == 5 || kind == 12 || kind == 13;
    }

    function _label(uint8 kind) internal pure override returns (string memory) {
        if (kind == 4) return "NormalPqzToken";
        if (kind == 5) return "WrappedPqzToken";
        if (kind == 12) return "NormalPqzRegulatedToken";
        if (kind == 13) return "WrappedPqzRegulatedToken";
        return super._label(kind);
    }

    /// A PQZ kind: `OFFCHAIN`, class 3 without the opening (the verifier `vA`, transferable).
    function _conf(bool own, bool open) internal view returns (IFactoryToken.ConfidentialConfig memory) {
        return
            IFactoryToken.ConfidentialConfig("", 10_000, uint256(1) << 40, 0, 0, 0, 0, 1, vA, false, 0, 0, 3, own, open);
    }

    function _base(uint8 kind, string memory sym) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = super._base(kind, sym);
        if (_pqzKind(kind)) c.conf = _conf(true, false);
    }

    function _create(uint8 kind, IFactoryToken.TokenConfig memory c, string memory what)
        internal
        override
        returns (address x)
    {
        if (!_pqzKind(kind)) return super._create(kind, c, what);
        vm.broadcast(k1);
        x = fp.createToken(IOpenFactory.TokenKind(kind), 1, abi.encode(c), _salt(what));
        _book(x, _label(kind));
    }
}

/// @notice Run 1: the factory and the releases, the holders and their records, the public layer of the PQZ kinds, the
///         confidential layer per class, the negatives.
contract PqzKeysSetup is PqzKeysKit {
    function setup() external {
        _deps();
        string memory j = vm.readFile(_state()); // PqzKeysPublic's run: its factory and leg
        (fp, leg) = (OpenFactory(vm.parseJsonAddress(j, ".fp")), MockERC20(vm.parseJsonAddress(j, ".leg")));
        _fixtures();
        _registerMl();
        (bobSeed, bob) = _holder("bob");
        (carolSeed, carol) = _holder("carol");
        _msig();
        // the public layer's `_pq` rows (PqzKeysPublic ran the sweep without them)
        uint8[4] memory pk = [uint8(4), 12, 5, 13];
        for (uint256 i; i < 4; ++i) {
            _pqOn(pk[i], string.concat("pqzkeys-pq", vm.toString(pk[i])));
        }
        _confidential();
        _registryKeys();
        _burnerPqz(4);
        _burnerPqz(12);
        _auditorPqz();
        _registryNegatives();
        _save();
        _writeBook();
    }

    /// An ML-DSA-65 UA registered as `_registerMl` (Tokens), its seed from this run.
    function _holder(string memory who) internal returns (bytes32 seed, bytes32 ua) {
        seed = keccak256(abi.encode(runSalt, "pqzkeys", who));
        bytes memory pk = _ml(string.concat("keygen 65 ", _bare(seed)));
        ua = UAKinds.uaOf(ML65, pk);
        bytes32 rd = UAKinds.registrationDigest(ua, ML65, 0, UAKinds.kemRecordHash(ua, 0, bytes("")), 0);
        bytes memory pop = _mlBy(seed, IUARegistry(registry).uaMessage(ML65, UAKinds.PURPOSE_POP_V2, rd));
        IUARegistry.UAAttrs memory none;
        vm.startBroadcast(k1);
        if (_mldsaCache(ML65)) {
            // 3zh: the cache path only (a precompile verifier refuses the cache)
            IUARegistry(registry).cacheExpandedKey{gas: 56_000_000}(ML65, pk, 0);
            IUARegistry(registry).cacheExpandedKey{gas: 56_000_000}(ML65, pk, 1);
        }
        require(IUARegistry(registry).register{gas: 56_000_000}(ML65, pk, none, pop, "") == ua, "holder UA");
        vm.stopBroadcast();
    }

    /// A PQ-eligible msig (two ML-DSA-65 members, bob and carol, ids ascending, threshold 1, no classical weight): its PoP
    /// bob's member signature over the registration digest (CTR-UA-37), then bob's membership accepted (the slot it signs with).
    function _msig() internal {
        (bytes32 m0, bytes32 m1) = uint256(bob) < uint256(carol) ? (bob, carol) : (carol, bob);
        IUARegistry.MsigStructure memory st;
        st.threshold = 1;
        st.members = new IUARegistry.MsigMember[](2);
        (st.members[0], st.members[1]) = (IUARegistry.MsigMember(ML65, m0, 1), IUARegistry.MsigMember(ML65, m1, 1));
        bytes memory d = abi.encodePacked(uint16(1), uint16(2), ML65, m0, uint16(1), ML65, m1, uint16(1));
        mu = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 rd = UAKinds.registrationDigest(mu, UAKinds.MSIG, 0, UAKinds.kemRecordHash(mu, 0, bytes("")), 0);
        IUARegistry.MemberSig[] memory pop = _msigSig(UAKinds.PURPOSE_POP_V2, rd).members;
        IUARegistry.UAAttrs memory none;
        vm.broadcast(k1);
        require(IUARegistry(registry).registerMsig{gas: 56_000_000}(st, none, pop, "") == mu, "msig UA");
        bytes32 md = UAKinds.memberDigest(
            mu, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBERSHIP, UAKinds.membershipDigest(mu, bob))
        );
        IUARegistry.MemberSig memory ms;
        (ms.index, ms.sig) =
        (_bobSlot(), _mlBy(bobSeed, IUARegistry(registry).uaMessage(ML65, UAKinds.PURPOSE_MEMBER, md)));
        vm.broadcast(k1);
        IUARegistry(registry).acceptMembership{gas: 56_000_000}(mu, ms);
    }

    // ------------------------------------------------------------------ the factory: kinds 4, 5, 12, 13 on deps [0]

    function _factory() internal {
        vm.broadcast(k1);
        fp = new OpenFactory(_pad(a1));
        _book(address(fp), "OpenFactory");
        bytes32 uid = vm.parseJsonBytes32(dj, ".chain_uid");
        address gr = _dep("governance_router");
        vm.broadcast(k1);
        fp.configureChain(uid, 0, gr, gr.codehash, 0, bytes32(0));
        IFactoryToken.Env memory e = f.tokenEnvOf(IOpenFactory.TokenKind.WRAPPED, 1);
        uint8[4] memory ks = [uint8(4), 5, 12, 13];
        for (uint256 i; i < 4; ++i) {
            _release(ks[i], e);
        }
        vm.startBroadcast(k1);
        leg = new MockERC20("Onchain PQZ leg", "oPQL", 6);
        leg.mint(a1, 1e18);
        vm.stopBroadcast();
        _book(address(leg), "MockERC20");
    }

    function _libs(uint8 k_) internal pure returns (address[] memory l) {
        l = new address[](k_ >= 12 ? 10 : 9);
        (l[0], l[1], l[2], l[3]) =
        (address(GovernanceLib), address(HederaLib), address(MtxPipelineLib), address(WrappedLib));
        (l[4], l[5], l[6], l[7], l[8]) =
        (
            address(PqzStateLib),
            address(PqzTransferLib),
            address(PqzBurnLib),
            address(PqzViewLib),
            address(PqzWrappedLib)
        );
        if (k_ >= 12) l[9] = address(RegulatedLib);
    }

    function _release(uint8 k_, IFactoryToken.Env memory e) internal {
        bytes memory core = k_ >= 12 ? abi.encode(vm.parseJsonBytes32(dj, ".compliance_registry_codehash")) : bytes("");
        address[] memory ms = _modules(k_, core);
        IOpenFactory.TokenKind kind = IOpenFactory.TokenKind(k_);
        bytes32 uid = fp.chainUid();
        vm.broadcast(k1);
        fp.publishTokenEnv(kind, 1, uid, _envOf(k_, e, ms));
        _implement(k_, kindImplArgs(k_, ms, core), uid);
    }

    function _modules(uint8 k_, bytes memory core) internal returns (address[] memory ms) {
        string[] memory n = kindModuleNames(k_);
        ms = new address[](n.length);
        for (uint256 j; j < n.length; ++j) {
            bytes memory init = bytes.concat(vm.getCode(n[j]), abi.encode(address(fp), core));
            bytes32 sl = _salt(string.concat("pqzkeys-module-", n[j]));
            ms[j] = vm.computeCreate2Address(sl, keccak256(init), CREATE2_FACTORY);
            vm.broadcast(k1);
            (bool ok,) = CREATE2_FACTORY.call(bytes.concat(sl, init));
            require(ok && ms[j].code.length != 0, n[j]);
        }
    }

    function _envOf(uint8 k_, IFactoryToken.Env memory e, address[] memory ms)
        internal
        view
        returns (IFactoryToken.Env memory)
    {
        address[] memory libs = _libs(k_);
        address[] memory l = new address[](libs.length + ms.length);
        bytes32[] memory h = new bytes32[](l.length);
        for (uint256 j; j < l.length; ++j) {
            l[j] = j < libs.length ? libs[j] : ms[j - libs.length];
            h[j] = l[j].codehash;
        }
        return IFactoryToken.Env(e.registry, e.smartKeyAccountImpl, false, new address[](1), new bytes32[](0), l, h);
    }

    function _implement(uint8 k_, bytes memory implArgs, bytes32 uid) internal {
        IOpenFactory.TokenKind kind = IOpenFactory.TokenKind(k_);
        bytes memory code = vm.getCode(string.concat(_label(k_), ".sol:", _label(k_)));
        vm.startBroadcast(k1);
        fp.deployTokenImplementation{gas: 56_000_000}(kind, 1, 1, code, implArgs, uid);
        fp.setTokenKindEnabled(kind, true, uid);
        vm.stopBroadcast();
    }

    // ------------------------------------------------------------------ the public layer (Tokens' sweep on the PQZ kinds)

    function _publicLayer() internal {
        // W2's SCaaS ledger leg: a kind-0 token of the Step 5 factory
        IFactoryToken.TokenConfig memory c = super._base(0, "oNb");
        c.features = 1 << GovernanceBits.PAYABLE;
        (c.initialSupply, c.initialHolder) = (1e15, a1);
        base = _create(0, c, "pqzkeys-base");
        _normalKind(4);
        _normalKind(12);
        _wrappedKind(5);
        _wrappedKind(13);
    }

    // ------------------------------------------------------------------ trades and liquidity (as Dex.s.sol and Liquidity.s.sol)

    uint256 internal constant GT = 3_000_000; // Dex.s.sol's fixed gas of a trade (forge's estimate fell short there)
    ISCaaSDex internal dx; // on this group's factory: the PQZ kinds (a DEX trades the tokens its own factory released)
    ISCaaSDex internal dxF; // on the Step 5 factory: the other kinds' pulls
    address internal pA; // the PQZ trades' counter tokens: kind 4 of this group's factory (a DEX's legs are its factory's),
    address internal pB; // held by test keys 1 and 2
    OnchainRouter internal rt;
    MockERC20 internal usdl; // the liquidity rows' outside token
    MockV2Factory internal v2f;
    uint256 internal tn; // order nonces
    uint256 internal wn; // wrap orders' nonces on `base` (lane 7)

    /// The trade entries of the PQZ kinds' public layer (the dex group's per-kind rows on kinds 1-3, 8-11): on a DEX of the
    /// this group's factory, a token X of each kind 4, 5, 12, 13 against two kind-4 tokens: a settle (`mtxTrade` on X), a hybrid
    /// whose route sells 400 of the 500 X sent outside (`restorePulled` on X), a cancelled order (`mtxCancelOrder`), X of
    /// a wrapped kind minted by a signed `mtxWrapOrder` on `base`. Then `mtxLiquidityPull` on a token of every kind but 0
    /// (the liquidity group's kind): one SCaaS input X and one outside input into a v2-style pair (the TEST ONLY mocks).
    function _trades() internal {
        pA = _counter(a1, "pqzkeys-dexA");
        pB = _counter(a2, "pqzkeys-dexB");
        bytes memory cfg =
            abi.encode(ISCaaSDex.DexConfig(_pad(a1), 200_000, address(0x7EA5), false, 0, address(0), 0, 0));
        _dexRelease();
        vm.startBroadcast(k1);
        dx = ISCaaSDex(fp.createDex(1, cfg, _salt("pqzkeys-dex")));
        dxF = ISCaaSDex(f.createDex(1, cfg, _salt("pqzkeys-dexF")));
        vm.stopBroadcast();
        _book(address(dx), "SCaaSDex");
        _book(address(dxF), "SCaaSDex");
        rt = OnchainRouter(_c2(type(OnchainRouter).creationCode, "pqzkeys-router"));
        usdl = MockERC20(
            _c2(
                abi.encodePacked(type(MockERC20).creationCode, abi.encode("Onchain USD K", "oUSDK", uint8(6))),
                "pqzkeys-usd"
            )
        );
        v2f = MockV2Factory(_c2(type(MockV2Factory).creationCode, "pqzkeys-v2f"));
        _book(address(usdl), "MockERC20");
        _book(address(v2f), "MockV2Factory");
        (address pl, address plF) = (dx.puller(), dxF.puller());
        vm.startBroadcast(k1);
        IERC20(pA).transfer(address(rt), 1e8);
        IERC20(pA).transfer(a2, 1e8);
        usdl.mint(a1, 1e12);
        usdl.approve(pl, type(uint256).max);
        usdl.approve(plF, type(uint256).max);
        vm.stopBroadcast();
        vm.broadcast(k2);
        IERC20(pB).transfer(address(rt), 1e8);
        uint8[4] memory pk = [uint8(4), 5, 12, 13];
        for (uint256 i; i < 4; ++i) {
            _tradeKind(pk[i]);
        }
        uint8[11] memory lk = [uint8(1), 2, 3, 8, 9, 10, 11, 4, 5, 12, 13];
        for (uint256 i; i < 11; ++i) {
            _pull(lk[i]);
        }
    }

    /// DEX release 1 on this group's factory, as DeployBase's: env 1 the libraries forge links for this script (GovernanceLib,
    /// TradeLib) and this factory's two modules (governance, liquidity), then the implementation.
    function _dexRelease() internal {
        IFactoryToken.Env memory e = f.dexEnvOf(1);
        address[] memory ms = new address[](2);
        ms[0] = _c2(
            bytes.concat(type(SCaaSDexGovernanceModule).creationCode, abi.encode(address(fp), bytes(""))),
            "pqzkeys-dex-gov"
        );
        ms[1] = _c2(
            bytes.concat(type(SCaaSDexLiquidityModule).creationCode, abi.encode(address(fp), bytes(""))),
            "pqzkeys-dex-liq"
        );
        address[] memory l = new address[](4);
        bytes32[] memory h = new bytes32[](4);
        (l[0], l[1], l[2], l[3]) = (address(GovernanceLib), address(TradeLib), ms[0], ms[1]);
        for (uint256 i; i < 4; ++i) {
            h[i] = l[i].codehash;
        }
        (e.libs, e.libCodeHashes) = (l, h);
        bytes32 uid = fp.chainUid();
        vm.startBroadcast(k1);
        fp.publishDexEnv(1, uid, e);
        fp.deployDexImplementation{gas: 56_000_000}(1, 1, type(SCaaSDex).creationCode, abi.encode(ImplArgs(ms)), uid);
        vm.stopBroadcast();
    }

    function _counter(address holder, string memory what) internal returns (address x) {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin) = ("Onchain PQZ counter", "oPQC", 6, _pad(a1));
        c.features = 1 << GovernanceBits.PAYABLE;
        (c.initialSupply, c.initialHolder, c.conf) = (1e15, holder, _conf(true, false));
        x = _create(4, c, what);
    }

    function _c2(bytes memory init, string memory what) internal returns (address a) {
        bytes32 sl = _salt(what);
        a = vm.computeCreate2Address(sl, keccak256(init), CREATE2_FACTORY);
        // reset 5: the SCaaS testnet's release gas rule (NET-EVM-06: code x 1,530 + 2^24, the init code bounding the
        // runtime) within the block; a fixed 30 M fell short of SCaaSDexLiquidityModule's code-deposit state gas (EIP-8037:
        // 29.85 M at the deploy), which forge's EVM and anvil do not price
        uint256 gl = init.length * 1_530 + (1 << 24);
        if (gl > block.gaslimit) gl = block.gaslimit;
        vm.broadcast(k1);
        (bool ok,) = CREATE2_FACTORY.call{gas: gl}(abi.encodePacked(sl, init));
        require(ok && a.code.length != 0, what);
    }

    /// A token of kind `n` for a trade or a pull, a1 holding 1e7 of it (a wrapped kind: one leg `base`, minted by a signed wrap
    /// order); a PQZ kind on this group's factory (`OFFCHAIN`, class 3), Zether on BLS12-381 version 1 without an auditor.
    function _kindToken(uint8 n, string memory what) internal returns (address x) {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin) = ("Onchain PQZ K", string.concat("oPK", vm.toString(n)), 6, _pad(a1));
        c.features = 1 << GovernanceBits.PAYABLE;
        if (n == 2 || n == 3 || n == 10 || n == 11) {
            c.conf = IFactoryToken.ConfidentialConfig(
                "", 1, 1 << 40, 0, 0, 0, 0, 0, bytes32(0), false, 0, 0, 0, false, false
            );
        }
        if (_pqzKind(n)) c.conf = _conf(true, false);
        if (n % 2 == 1) {
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(base, 1, 1);
        } else {
            (c.initialSupply, c.initialHolder) = (1e12, a1);
        }
        if (n >= 8) c.reg.termsHash = keccak256("onchain pqzkeys terms");
        x = _create(n, c, string.concat("pqzkeys-", what, vm.toString(n)));
        if (n % 2 == 1) _wrapOrderOn(x, 1e7);
    }

    function _wrapOrderOn(address wt, uint256 amt) internal {
        ITradeToken.UAWrapOrder memory o;
        (o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill) = (_pad(a1), wt, amt, amt, amt);
        (o.batch, o.nonce, o.validUntil) = (7, ++wn, vu);
        ITradeToken.UATradeOrder memory t = ITradeToken.UATradeOrder(
            o.from,
            wt,
            o.amount,
            o.minMinted,
            o.minFill,
            o.fee,
            o.relayer,
            wt,
            o.destination,
            o.flags,
            o.batch,
            o.nonce,
            o.validUntil
        );
        IUARegistry.UASig memory sg;
        sg.signature = _ecdsa(k1, ITradeToken(base).tradeOrderDigest(t));
        vm.broadcast(k2);
        IWrappedToken(wt).mtxWrapOrder{gas: GT}(base, o, sg);
    }

    function _o(bytes32 from, address recv, uint256 amt, uint256 recvAmt)
        internal
        returns (ITradeToken.UATradeOrder memory o)
    {
        (o.from, o.receiveToken, o.amount, o.receiveAmount) = (from, recv, amt, recvAmt);
        (o.dex, o.batch, o.nonce, o.validUntil) = (address(dx), 1, ++tn, vu);
    }

    function _leg(address sell, ITradeToken.UATradeOrder memory o, uint256 pk_, uint256 fill)
        internal
        view
        returns (ISCaaSDex.DexLeg memory l)
    {
        (l.sellToken, l.shape, l.uaOrder, l.fill) = (sell, 1, o, fill);
        l.auth.signature = _ecdsa(pk_, ITradeToken(sell).tradeOrderDigest(o));
    }

    function _tradeKind(uint8 n) internal {
        address x = _kindToken(n, "trade");
        vm.startBroadcast(k1);
        dx.setMarket{gas: GT}(x, pA, true, dx.chainUid());
        dx.setMarket{gas: GT}(x, pB, true, dx.chainUid());
        vm.stopBroadcast();
        ISCaaSDex.Settlement[] memory ss = new ISCaaSDex.Settlement[](1);
        (ss[0].ref, ss[0].taker) =
        (keccak256(abi.encode(runSalt, "pqzkeys-kind", n)), _leg(x, _o(_pad(a1), pA, 1000, 1000), k1, 1000));
        ss[0].makers = new ISCaaSDex.DexLeg[](1);
        ss[0].makers[0] = _leg(pA, _o(_pad(a2), x, 1000, 1000), k2, 1000);
        vm.broadcast(k2);
        require(dx.mtxSettle{gas: GT}(ss)[0], "settle");
        _hybridKind(x, n);
        ITradeToken.UATradeOrder memory o = _o(_pad(a1), pB, 1000, 1900);
        IUARegistry.UASig memory sg;
        sg.signature = _ecdsa(k1, ITradeToken(x).cancelOrderDigest(o));
        vm.broadcast(k2);
        ITradeToken(x).mtxCancelOrder{gas: GT}(o, sg);
    }

    function _hybridKind(address x, uint8 n) internal {
        ISCaaSDex.HybridPlan memory p;
        p.ref = keccak256(abi.encode(runSalt, "pqzkeys-hybrid", n));
        p.taker = _leg(x, _o(_pad(a1), pB, 1000, 1000), k1, 1000);
        p.makers = new ISCaaSDex.DexLeg[](1);
        p.makers[0] = _leg(pB, _o(_pad(a2), x, 500, 500), k2, 500);
        (p.outsideSell, p.outsideFloor) = (500, 500);
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](2);
        xs[0] = ISCaaSDex.Interaction(x, abi.encodeCall(IERC20.approve, (address(rt), 400)));
        xs[1] = ISCaaSDex.Interaction(address(rt), abi.encodeCall(OnchainRouter.swap, (x, pB, 400, 500, address(dx))));
        bytes32 h = ITradeToken(x).tradeOrderDigest(p.taker.uaOrder);
        vm.broadcast(k3);
        dx.mtxHybrid{gas: GT}(p, xs);
        require(ITradeToken(x).pulled(h) == 900, "restorePulled");
    }

    /// `mtxLiquidityPull` on X (kind `n`): a1 adds 1e6 X and 1e6 of the outside token into a fresh X / outside pair.
    function _pull(uint8 n) internal {
        address x = _kindToken(n, "pull");
        ISCaaSDex d = _pqzKind(n) ? dx : dxF;
        bytes32 wd = d.chainUid();
        vm.broadcast(k1);
        d.setMarket{gas: GT}(x, address(usdl), true, wd);
        vm.broadcast(k1);
        address pair = v2f.createPair{gas: 30_000_000}(x, address(usdl));
        _book(pair, "MockV2LiquidityPair");
        ITradeToken.LiquidityOrder memory o;
        (o.from, o.recipient, o.fee, o.relayer, o.batch, o.nonce, o.validUntil) =
        (_pad(a1), _pad(a2), 3_000, a3, 11, ++tn, vu);
        o.inputs = new ITradeToken.LiquidityToken[](2);
        (o.inputs[0], o.inputs[1]) =
        (ITradeToken.LiquidityToken(x, 1e6), ITradeToken.LiquidityToken(address(usdl), 1e6));
        o.outputs = new ITradeToken.LiquidityToken[](1);
        o.outputs[0] = ITradeToken.LiquidityToken(pair, 9e5);
        ISCaaSDex.LiquidityPlan memory lp;
        (lp.ref, lp.order, lp.auth) =
        (keccak256(abi.encode(runSalt, "pqzkeys-pull", n)), o, _sig(k1, d.liquidityOrderDigest(o)));
        lp.pull = new uint256[](2);
        (lp.pull[0], lp.pull[1]) = (1e6, 1e6);
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](3);
        xs[0] = ISCaaSDex.Interaction(x, abi.encodeCall(IERC20.transfer, (pair, 1e6)));
        xs[1] = ISCaaSDex.Interaction(address(usdl), abi.encodeCall(IERC20.transfer, (pair, 1e6)));
        xs[2] = ISCaaSDex.Interaction(pair, abi.encodeCall(MockV2LiquidityPair.mint, (address(d))));
        vm.broadcast(k3);
        d.mtxLiquidity{gas: 30_000_000}(lp, xs);
    }

    // ------------------------------------------------------------------ the confidential layer

    function _token(uint8 kind, bool own, bool open, string memory what) internal returns (address x) {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin) = (string.concat("Onchain PQZ ", what), "oPQ", 6, _pad(a1));
        c.features = 1 << GovernanceBits.PAYABLE;
        if (kind == 4 || kind == 12) (c.initialSupply, c.initialHolder) = (1e15, a1);
        c.conf = _conf(own, open);
        if (kind == 5 || kind == 13) {
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(leg), 1, 1);
        }
        if (kind >= 12) c.reg.termsHash = keccak256("onchain pqzkeys terms");
        c.features |= 1 << GovernanceBits.PQZ_PROOF; // the proof store's switch (`_ownerOps`)
        x = _create(kind, c, string.concat("pqzkeys-", what));
        if (kind == 5 || kind == 13) {
            vm.startBroadcast(k1);
            leg.approve(x, type(uint256).max);
            WrappedPqzToken(payable(x)).wrap(uint256(1e15));
            vm.stopBroadcast();
        }
    }

    /// K3-3: `ua`'s scoped record of `scope` at version `v` (fresh key bytes; `kem`: the opening KEM key), signed by its
    /// ML-DSA key, then its proof bytes stored (unchecked: no 0x0142 verifier on anvil).
    function _scoped(bytes32 ua, address scope, uint64 v, bool kem) internal {
        (bytes memory key, IUARegistry.KemKey memory k, bytes memory pop) = _record(ua, scope, v, kem);
        uint64 vub = uint64(block.number + WIN);
        IUARegistry.UASig memory s = _recordSig(ua, scope, v, key, k, pop, vub, IUARegistry(registry).chainUid());
        vm.startBroadcast(k1);
        IUARegistry(registry).setPqzScopedKey{gas: 56_000_000}(ua, scope, v, key, keccak256(pop), k, vub, s);
        IUARegistry(registry).storePqzScopedPop{gas: 56_000_000}(ua, scope, v, pop);
        vm.stopBroadcast();
    }

    function _record(bytes32 ua, address scope, uint64 v, bool kem)
        internal
        returns (bytes memory key, IUARegistry.KemKey memory k, bytes memory pop)
    {
        key = new bytes(PqzCt.PK);
        (key[13], key[14], key[15]) = (bytes1(0x5c), bytes1(uint8(++keySeed >> 8)), bytes1(uint8(keySeed)));
        if (kem) {
            (k.scheme, k.mlkemEk, k.x25519) =
            (1, _blob(uint256(keccak256(abi.encode(ua, scope, v))), 1568), keccak256(abi.encode(ua, scope, v)));
        }
        pop = abi.encodePacked(keccak256(abi.encode(runSalt, ua, scope, v)));
    }

    struct RecDigest {
        bytes32 ua;
        address scope;
        uint64 v;
        bytes32 keyHash;
        bytes32 popHash;
        bytes32 kemHash;
        uint64 vub;
        bytes32 uid;
    }

    function _recordSig(
        bytes32 ua,
        address scope,
        uint64 v,
        bytes memory key,
        IUARegistry.KemKey memory k,
        bytes memory pop,
        uint64 vub,
        bytes32 uid
    ) internal returns (IUARegistry.UASig memory) {
        bytes memory kp = UAKinds.kemPk(k);
        RecDigest memory r = RecDigest(
            ua,
            scope,
            v,
            UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key),
            keccak256(pop),
            kp.length == 0 ? bytes32(0) : keccak256(kp),
            vub,
            uid
        );
        if (ua == mu) return _msigSig(UAKinds.PURPOSE_PQZ_SCOPED_KEY, _rd(r));
        return _uaSig(_seedOf(ua), UAKinds.PURPOSE_PQZ_SCOPED_KEY, _rd(r));
    }

    function _rd(RecDigest memory r) internal view returns (bytes32) {
        return IUARegistry(registry)
            .pqzScopedKeyRecordDigest(
                r.ua, r.scope == address(0) ? 2 : 3, r.uid, r.scope, r.v, r.keyHash, r.popHash, r.kemHash, r.vub
            );
    }

    function _shield(address t, bytes32 ua, uint256 amount) internal {
        vm.broadcast(k1);
        NormalPqzToken(t).mtxShield(ua, amount);
    }

    function _confidential() internal {
        c2 = _token(4, false, true, "c2");
        c3o = _token(4, true, true, "c3o");
        c3 = _token(4, true, false, "c3");
        t5 = _token(5, true, false, "t5");
        t12 = _token(12, true, false, "t12");
        t13 = _token(13, true, false, "t13");
        bytes32[3] memory hs = [uaM, bob, carol];
        for (uint256 i; i < 3; ++i) {
            _scoped(hs[i], address(0), 0, true); // class 2: the shared key, its opening KEM key
            _scoped(hs[i], c3o, 0, true);
            _scoped(hs[i], c3, 0, false);
            _scoped(hs[i], t5, 0, false);
            _scoped(hs[i], t12, 0, false);
            _scoped(hs[i], t13, 0, false);
        }
        // the scoped views
        require(
            IUARegistry(registry).pqzScopedKeyLatest(bob, c3o) == 0 && IUARegistry(registry).pqzScopedCount(c3) == 3,
            "scoped"
        );
        address[6] memory ts = [c2, c3o, c3, t5, t12, t13];
        for (uint256 i; i < 6; ++i) {
            _life(ts[i], i);
        }
        // the msig on a class-3 token with the opening: its record with the opening KEM key, then a credit to it
        _scoped(mu, c3o, 0, true);
        _send1(c3o, _op1(c3o, carol, mu, 0x7f11), false); // from carol: bob's `rolled` stays below run 2's mark
        address[4] memory ns = [c3, t5, t12, t13];
        for (uint256 i; i < 4; ++i) {
            _namedLife(ns[i], 0x7a00 + 0x100 * i);
        }
        _wrapShield(t5);
        _wrapShield(t13);
        _rotation();
        _openingKinds();
        console2.log(
            string.concat("pqzkeys setup c2 ", vm.toString(c2), " c3o ", vm.toString(c3o), " c3 ", vm.toString(c3))
        );
    }

    /// A token's life before its rollovers: three shields (the holder's TRIVIAL entry first), credits to the holder uaM from bob
    /// (op 1, op 1 compact) and carol (op 1: on an opening token the planted credit the holder marks), then the forms each
    /// class takes: op 7 and its compact form without the opening (`OpUnsupported` with it, a negative), an unshield and a
    /// refresh, an unshield-unwrap on a wrapped kind.
    function _life(address t, uint256 i) internal {
        uint256 s = 0x7c00 + 0x100 * i;
        _shield(t, bob, 50);
        _shield(t, carol, 50);
        _shield(t, uaM, 100);
        _send1(t, _op1(t, bob, uaM, s + 1), false);
        _send1(t, _op1(t, carol, uaM, s + 11), false);
        _send1(t, _op1(t, bob, uaM, s + 21), true);
        if (_opens(t)) {
            IPqzToken.PqzMultiArgs memory m = _op7(t, carol, bob, uaM, s + 41);
            IPqzToken.PqzSignedVerdict memory none;
            _neg(
                a2,
                t,
                abi.encodeCall(IPqzToken.mtxConfidentialTransfer, (m, VPROOF, _pqStub(), "", none)),
                IPqzToken.OpUnsupported.selector,
                string.concat(_label(t), ": op 7 with the opening on")
            );
        } else {
            _send7(t, _op7(t, carol, bob, uaM, s + 31), false);
            _send7(t, _op7(t, carol, bob, uaM, s + 41), true);
        }
        _unshield(t, bob, 5, _pad(a3), s + 51);
        _unshield(t, bob, 0, bytes32(0), s + 61);
        if (t == t5 || t == t13) _unshieldUnwrap(t, carol, 3, s + 71);
        // bob's credit after his debits (each sets his `rolled` to its p): run 2's mark-only account
        if (_opens(t)) {
            _send1(t, _op1(t, carol, bob, s + 31), false);
            _shield(t, bob, 10); // bob's entry 2, TRIVIAL and above his `rolled`: run 2's SkipTrivial negative
        }
        vm.startBroadcast(k1);
        IPqzToken(t).mtxPrepareAcc(uaM, 0, 0);
        IPqzToken(t).mtxPrepareAcc(uaM, 0, 1);
        vm.stopBroadcast();
    }

    // ------------------------------------------------------------------ AUDITOR (set-auditor: CTR-GOV-31, CTR-PQZ-43)

    /// Bit 32 on a kind-4 token of class 2 with the opening (the scope-0 records of `_confidential`; anvil's registry has no
    /// 0x0142 verifier, so no proven check, spec §5.2), OPTIONAL auditor carol, admin test key 1's native id, grantDelay 0 and
    /// this group's factory notice 0 (the delay 0). Bit 32 granted to bob (a single ML-DSA key) and to the msig `mu`. An audited
    /// op 1 (bob -> uaM) at epoch 0; bob, through the router (his ML-DSA signature over `UASetAuditorUA`, test key 2 relays at
    /// fee 0), names dave (a fresh holder with its scope-0 record and opening KEM key) with dave's consent under
    /// `PURPOSE_AUDITOR_CONSENT` over the token's `AuditorConsent`: applied at once; an audited op 1 at epoch 1; `auditorUAOf`
    /// answers carol for the first entry and dave for the second. Then the msig names carol back (epoch 2), bob signing for it.
    function _auditorPqz() internal {
        (daveSeed, dave) = _holder("dave");
        _scoped(dave, address(0), 0, true);
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin) = ("Onchain PQZ auditor", "oPQA", 6, _pad(a1));
        c.features = 1 << GovernanceBits.PAYABLE | uint256(1) << GovernanceBits.AUDITOR;
        (c.initialSupply, c.initialHolder) = (1e15, a1);
        c.conf = _conf(false, true);
        (c.conf.auditorKey, c.conf.auditorMode) = (abi.encode(carol), 2); // OPTIONAL
        address t = _create(4, c, "pqzkeys-auditor");
        bytes32 uid = NormalPqzToken(t).chainUid();
        vm.startBroadcast(k1);
        IGovernance(t).grantRole(GovernanceBits.AUDITOR, bob, uid);
        IGovernance(t).grantRole(GovernanceBits.AUDITOR, mu, uid);
        vm.stopBroadcast();
        require(
            IGovernance(t).hasRole(GovernanceBits.AUDITOR, bob) && IGovernance(t).hasRole(GovernanceBits.AUDITOR, mu),
            "auditor token: bit 32 granted to bob and to the msig"
        );
        _shield(t, bob, 100);
        bytes32 r0 = _audited1(t, 0x7e01);
        _setAuditorUA(t, bob, dave, 1, uid);
        (uint32 epoch,,,, uint8 st) = IPqzToken(t).auditorState();
        require(
            epoch == 1 && st == 0 && NormalPqzToken(t).auditorUA() == dave,
            "auditor token: dave applied at once (delay 0)"
        );
        bytes32 r1 = _audited1(t, 0x7e11);
        require(
            IPqzToken(t).auditorUAOf(r0) == carol && IPqzToken(t).auditorUAOf(r1) == dave,
            "auditor token: auditorUAOf by epoch"
        );
        _setAuditorUA(t, mu, carol, 2, uid);
        require(NormalPqzToken(t).auditorUA() == carol, "auditor token: the msig's op applied (epoch 2)");
        console2.log(
            string.concat(
                "pqzkeys auditor ", vm.toString(t), ": bit 32 to bob and the msig; dave at epoch 1, carol back at 2"
            )
        );
    }

    /// An audited op 1 of bob to uaM (the auditor's ciphertext and opening as filler; OPTIONAL: the sender's choice); its entry ref.
    function _audited1(address t, uint256 seed) internal returns (bytes32 ref) {
        IPqzToken.PqzTransferArgs memory a = _op1(t, bob, uaM, seed);
        (a.vAuditor, a.openingAuditor) = (_blob(seed + 5, PqzCt.V), _opening(seed + 6));
        bytes memory st = NormalPqzToken(t).transferSingleStatement(a, 0);
        IUARegistry.UASig memory au = _auth(t, bob, 1, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        vm.broadcast(k2);
        ref = IPqzToken(t).mtxConfidentialTransferSingle(a, VPROOF, au, "", sv);
    }

    /// `holder` (bob, or the msig with bob's member signature) names `next` at `epoch` through the router, with `next`'s consent
    /// (its ML-DSA signature under `PURPOSE_AUDITOR_CONSENT` over the token's `AuditorConsent` digest); test key 2 relays.
    function _setAuditorUA(address t, bytes32 holder, bytes32 next, uint32 epoch, bytes32 uid) internal {
        GovernanceRouter gr = GovernanceRouter(_dep("governance_router"));
        bytes32 cd = _digest(
            t,
            keccak256(
                abi.encode(
                    keccak256("AuditorConsent(address token,bytes32 auditor,uint32 epoch,bytes32 chainUid)"),
                    t,
                    next,
                    epoch,
                    uid
                )
            )
        );
        IUARegistry.UASig memory consent = _uaSig(_seedOf(next), UAKinds.PURPOSE_AUDITOR_CONSENT, cd);
        MetaTxLib.UAEnvelope memory e;
        (e.from, e.nonce, e.validUntil) = (holder, gr.mtxNonce(holder, 0), vu);
        bytes32 d = _named(address(gr), _typ("UASetAuditorUA"), abi.encode(t, next, epoch, uid), e);
        IUARegistry.UASig memory s =
            holder == mu ? _msigSig(UAKinds.PURPOSE_METATX, d) : _uaSig(_seedOf(holder), UAKinds.PURPOSE_METATX, d);
        vm.broadcast(k2);
        gr.mtxSetAuditorUA(e, t, next, epoch, consent, uid, s);
    }

    /// Round 3zb (CTR-GOV-29, O1): a Normal PQZ token of `kind` with bit 30 (`BURNABLE` off), the seat test key 1's native
    /// id, class 2 with the opening (bob's scope-0 record from `_confidential`). bob (no role) is shielded 50 and unshields 5
    /// to test key 3, sent by test key 2 (no role either): not gated, `totalSupply()` unchanged; the seat's `burn(10)` lowers
    /// it by 10; test key 2's `burn` (a balance, no role) is the negative `MissingRole(30, id)`.
    function _burnerPqz(uint8 kind) internal {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin) = ("Onchain PQZ burner", "oPQB", 6, _pad(a1));
        c.features = 1 << GovernanceBits.PAYABLE | uint256(1) << GovernanceBits.BURNER;
        (c.initialSupply, c.initialHolder, c.roles.burner) = (1e15, a1, _pad(a1));
        c.conf = _conf(false, true);
        if (kind >= 12) c.reg.termsHash = keccak256("onchain pqzkeys terms");
        address x = _create(kind, c, string.concat("pqzkeys-burner", vm.toString(kind)));
        _shield(x, bob, 50);
        vm.broadcast(k1);
        IERC20(x).transfer(a2, 1_000);
        uint256 s0 = IERC20(x).totalSupply();
        _unshield(x, bob, 5, _pad(a3), 0x7e00 + kind);
        // 5 confidential units at `_conf`'s scale of 10,000 public units each
        require(
            IERC20(x).totalSupply() == s0 && IERC20(x).balanceOf(a3) == 5 * 10_000,
            "BURNER: the unshield not gated, supply kept"
        );
        vm.broadcast(k1);
        NormalPqzToken(x).burn(10);
        require(IERC20(x).totalSupply() == s0 - 10, "BURNER: the seat's burn");
        console2.log(
            string.concat(
                "pqzkeys BURNER kind ",
                vm.toString(kind),
                " ",
                vm.toString(x),
                ": unshield by a non-holder, supply unchanged; the seat's burn(10), supply -10"
            )
        );
        _negData(
            a2,
            x,
            abi.encodeCall(NormalPqzToken.burn, (uint256(1))),
            abi.encodeWithSelector(IGovernance.MissingRole.selector, GovernanceBits.BURNER, _pad(a2)),
            string.concat(
                "burn by a non-holder with a balance (kind ", vm.toString(kind), ", BURNER): MissingRole(30, id)"
            )
        );
    }

    function _label(address t) internal view returns (string memory) {
        return t == c2 ? "c2" : t == c3o ? "c3o" : t == c3 ? "c3" : t == t5 ? "t5" : t == t12 ? "t12" : "t13";
    }

    function _pqStub() internal pure returns (IUARegistry.UASig memory s) {
        s.signature = new bytes(3309);
    }

    string internal constant UA_SHIELD =
        "UAShield(bytes32 from,bytes32 toUA,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant WRAP_SHIELD =
        "WrapShield(address from,address underlying,uint256 amountIn,bytes32 toUA,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

    /// `mtxShield` relayed: test key 1's native id signs, test key 2 sends.
    function _relayedShield(address t) internal {
        MetaTxLib.UAEnvelope memory e = _env(a1, 13, NormalPqzToken(t).mtxNonce(_pad(a1), 13));
        IUARegistry.UASig memory s = _sig(k1, _named(t, UA_SHIELD, abi.encode(bob, uint256(5)), e));
        vm.broadcast(k2);
        NormalPqzToken(t).mtxShield(e, bob, 5, s);
    }

    /// `mtxWrapShield` direct and relayed (the leg wrapped and shielded in one call).
    function _wrapShield(address t) internal {
        vm.broadcast(k1);
        WrappedPqzToken(payable(t)).mtxWrapShield(address(leg), 100_000, carol);
        MetaTxLib.Envelope memory e = _aenv(a1, 14, NormalPqzToken(t).mtxNonce(_pad(a1), 14));
        bytes memory s = _ecdsa(k1, _namedA(t, WRAP_SHIELD, abi.encode(address(leg), uint256(100_000), carol), e));
        vm.broadcast(k2);
        WrappedPqzToken(payable(t)).mtxWrapShield(e, address(leg), 100_000, carol, s);
    }

    /// Key rotation on a class-3 token: carol's scoped version 1, then her migration to herself from version 0 (op 1, KV-9).
    function _rotation() internal {
        _scoped(carol, c3, 1, false);
        require(IUARegistry(registry).pqzScopedKeyLatest(carol, c3) == 1, "carol v1");
        IPqzToken.PqzTransferArgs memory a = _op1(c3, carol, carol, 0x7f01);
        _send1(c3, a, false);
    }

    /// The named (UA-envelope) forms on a token without the opening: op 1 and its compact form, op 7 and its compact form,
    /// an unshield, an unshield-unwrap on a wrapped kind (the holder's ML-DSA key signs the envelope and `pqzAuth`), a
    /// relayed shield and a relayed prepare (test key 1's native id).
    function _namedLife(address t, uint256 s) internal {
        _named1(t, _op1(t, bob, uaM, s + 1), false);
        _named1(t, _op1(t, bob, uaM, s + 2), true);
        _named7(t, _op7(t, carol, bob, uaM, s + 3), false);
        _named7(t, _op7(t, carol, bob, uaM, s + 4), true);
        _namedUnshield(t, bob, 2, _pad(a3), s + 5);
        if (t == t5 || t == t13) _namedUnwrap(t, carol, 1, s + 6);
        _relayedShield(t);
        _namedAccOp(t, false, carol, 0);
    }

    /// Kinds 5, 12, 13 with the opening (class 3): uaM's TRIVIAL entry and two credits from bob (op 1, compact) for its
    /// signed rollover (run 2), both halves of its `acc` prepared.
    function _openingKinds() internal {
        (o5, o12, o13) = (_token(5, true, true, "o5"), _token(12, true, true, "o12"), _token(13, true, true, "o13"));
        address[3] memory os = [o5, o12, o13];
        for (uint256 i; i < 3; ++i) {
            address t = os[i];
            _scoped(uaM, t, 0, true);
            _scoped(bob, t, 0, true);
            _shield(t, bob, 50);
            _shield(t, uaM, 100);
            _send1(t, _op1(t, bob, uaM, 0x7d01 + 0x10 * i), false);
            _send1(t, _op1(t, bob, uaM, 0x7d02 + 0x10 * i), true);
            vm.startBroadcast(k1);
            IPqzToken(t).mtxPrepareAcc(uaM, 0, 0);
            IPqzToken(t).mtxPrepareAcc(uaM, 0, 1);
            vm.stopBroadcast();
        }
    }

    /// The registry key records (class 1's space): carol's PQZ key at version 0 (`setPqzKey`, then its proof bytes
    /// `storePqzPop`, unchecked here), bob's KEM key at version 1 (`setKemKey`); each signed by the holder's ML-DSA key.
    function _registryKeys() internal {
        (bytes memory key,, bytes memory pop) = _record(carol, address(0xC1A55), 0, false);
        bytes32 ph = keccak256(pop);
        bytes32 rd = UAKinds.pqzKeyRecordDigest(carol, UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key), ph);
        IUARegistry.UASig memory s = _uaSig(carolSeed, UAKinds.PURPOSE_PQZ_KEY, rd);
        vm.startBroadcast(k1);
        IUARegistry(registry).setPqzKey{gas: 56_000_000}(carol, 0, key, ph, s);
        IUARegistry(registry).storePqzPop{gas: 56_000_000}(carol, 0, pop);
        vm.stopBroadcast();
        IUARegistry.KemKey memory k = IUARegistry.KemKey(1, _blob(0x4b45, 1568), keccak256("bob kem v1"));
        s = _uaSig(bobSeed, UAKinds.PURPOSE_KEM, UAKinds.kemRecordDigest(bob, 1, UAKinds.kemPk(k)));
        vm.broadcast(k1);
        IUARegistry(registry).setKemKey{gas: 56_000_000}(bob, 1, k, s);
    }

    /// The regulated powers on a PQZ regulated kind's public layer (as Gov.s.sol on kinds 8-11; the issuer, compliance and
    /// operator test key 1's native id, the issuer and compliance seats Tokens' forwarders fA, fB): freeze, unfreeze, pause, unpause, an order recorded, its freeze, a forced transfer,
    /// the order revoked, an operator transfer, the deny list written and switched on.
    function _regulatedPowers(uint8 kind) internal {
        address t = _regToken(kind);
        bytes32 uid = NormalPqzToken(t).chainUid();
        IRegulatedToken r = IRegulatedToken(t);
        bytes32 ref = keccak256(abi.encode(runSalt, "pqzkeys-ref", kind));
        bytes32 oid = keccak256(abi.encode(runSalt, "pqzkeys-order", kind));
        bytes32 rid = keccak256(abi.encode(oid, _pad(a2), _pad(a3)));
        uint64 now_ = uint64(block.timestamp);
        vm.startBroadcast(k1);
        IERC20(t).transfer(a2, 1_000);
        fA.forwardCall(t, abi.encodeCall(r.freeze, (_pad(a3), ref, bytes32(0), uid)));
        fA.forwardCall(t, abi.encodeCall(r.unfreeze, (_pad(a3), ref, uid)));
        // reset 5: + 1 day (within PAUSE_SPAN, 7 days): a forge run simulates first and sends for about an hour on the SCaaS
        // testnet, so the simulation's now + 1 hour was already past when this send landed (PauseTooLong)
        fA.forwardCall(t, abi.encodeCall(r.pause, (ref, now_ + 1 days, uid)));
        fA.forwardCall(t, abi.encodeCall(r.unpause, (ref, uid)));
        fB.forwardCall(
            t,
            abi.encodeCall(
                IRegulatedToken.recordOrder, (oid, keccak256("order doc"), _pad(a2), _pad(a3), 100, now_ + 1 days, uid)
            )
        );
        fA.forwardCall(t, abi.encodeCall(r.freeze, (_pad(a2), ref, rid, uid)));
        fA.forwardCall(t, abi.encodeCall(r.forceTransfer, (rid, 40, uid)));
        fB.forwardCall(t, abi.encodeCall(r.revokeOrder, (rid, ref, uid)));
        IGovernance(t).grantRole(GovernanceBits.OPERATOR_TRANSFER, _pad(a1), uid);
        r.operatorTransfer(_pad(a2), _pad(a3), 10, ref, uid);
        bytes32[] memory d = new bytes32[](1);
        d[0] = _pad(address(0xDE41ED));
        IGovernance(t).grantRole(GovernanceBits.DENYLIST, _pad(a1), uid);
        r.setDenied(d, true, uid);
        r.enableFeature(GovernanceBits.DENYLIST, uid);
        vm.stopBroadcast();
    }

    function _regToken(uint8 kind) internal returns (address t) {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin) = ("Onchain PQZ regulated", "oPQR", 6, _pad(a1));
        c.features = 1 << GovernanceBits.PAYABLE | 1 << GovernanceBits.FREEZE | 1 << GovernanceBits.FORCE | 1
            << GovernanceBits.PAUSE | 1 << GovernanceBits.RECORD | 1 << GovernanceBits.OPERATOR_TRANSFER;
        (c.roles.issuer, c.roles.compliance) = (_pad(address(fA)), _pad(address(fB))); // contracts (RoleNotContract)
        c.reg.termsHash = keccak256("onchain pqzkeys terms");
        c.conf = _conf(true, false);
        if (kind == 12) {
            (c.initialSupply, c.initialHolder) = (1e15, a1);
        } else {
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(leg), 1, 1);
        }
        t = _create(kind, c, string.concat("pqzkeys-reg", vm.toString(kind)));
        if (kind == 13) {
            vm.startBroadcast(k1);
            leg.approve(t, type(uint256).max);
            WrappedPqzToken(payable(t)).wrap(uint256(1e9));
            vm.stopBroadcast();
        }
    }

    /// The wrap limits and the wrapper list, direct, on the wrapped kinds the wraplimits group does not create (3, 9, 11):
    /// the admin sets one leg's limits (bit 25 has no role), bit 26 granted to it for a member.
    function _wrapLimits(uint8 kind) internal {
        IFactoryToken.TokenConfig memory c = super._base(kind, "oWL");
        c.features = 1 << GovernanceBits.PAYABLE | 1 << GovernanceBits.WRAP_LIMIT | 1 << GovernanceBits.WRAP_LIST | 1
            << GovernanceBits.MINTABLE; // a wrap control needs a hybrid (WrapControlNeedsHybrid)
        (c.roles.minter, c.maxSupply) = (_pad(a1), 1e30);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(m1), 1, 1);
        if (_regulated(kind)) c.reg.termsHash = keccak256("scaas.onchain.terms");
        address t = _create(kind, c, string.concat("pqzkeys-wl", vm.toString(kind)));
        IWrappedToken.WrapLegLimits[] memory l = new IWrappedToken.WrapLegLimits[](1);
        (l[0].underlying, l[0].unitExp) = (address(m1), 4);
        (l[0].wrapShort, l[0].wrapLong) =
        (IWrappedToken.WrapLimit(100, 200, 3600), IWrappedToken.WrapLimit(150, 0, 86_400));
        bytes32 uid = IMetaTx(t).chainUid();
        vm.startBroadcast(k1);
        IGovernance(t).grantRole(GovernanceBits.WRAP_LIST, _pad(a1), uid);
        IWrappedToken(t).setWrapLimits(l, false, true, false, uid);
        IWrappedToken(t).setWrapMember(_pad(a2), true, true, uid);
        vm.stopBroadcast();
    }

    // ------------------------------------------------------------------ negatives: the scoped records (§15.2)

    struct RecNeg {
        bytes32 ua;
        address scope; // the record's scope as sent
        address signedScope; // the scope the signature is for
        bool kem;
        bytes32 uid;
        uint64 vub;
        uint256 keyLen;
    }

    /// A `setPqzScopedKey` call (eth_call at the run's end) at `ua`'s next version, one thing changed: refused with `want`.
    function _recNeg(RecNeg memory r, bytes memory want, string memory what) internal {
        _negData(a1, registry, _recCall(r, IUARegistry(registry).pqzScopedKeyLatest(r.ua, r.scope) + 1), want, what);
    }

    function _recCall(RecNeg memory r, uint64 v) internal returns (bytes memory) {
        (bytes memory key, IUARegistry.KemKey memory k, bytes memory pop) = _record(r.ua, r.scope, v, r.kem);
        if (r.keyLen != key.length) key = _resized(key, r.keyLen);
        IUARegistry.UASig memory s = _recordSig(r.ua, r.signedScope, v, key, k, pop, r.vub, r.uid);
        return abi.encodeCall(IUARegistry.setPqzScopedKey, (r.ua, r.scope, v, key, keccak256(pop), k, r.vub, s));
    }

    function _resized(bytes memory key, uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < 16; ++i) {
            b[i] = key[i];
        }
    }

    function _registryNegatives() internal {
        bytes32 uid = IUARegistry(registry).chainUid();
        uint64 vub = uint64(block.number + WIN);
        uint256 pk = PqzCt.PK;
        bytes32 sib = SIBLING_WORD;
        bytes memory unauth = abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, bob);
        _recNeg(
            RecNeg(bob, address(0), address(0), false, uid, vub, pk),
            abi.encodeWithSelector(IUARegistry.UAPqzOpenKem.selector, address(0)),
            "class 2 record without openKem"
        );
        _recNeg(
            RecNeg(bob, address(0), address(0), true, sib, vub, pk),
            unauth,
            "class 2 record signed for another chainUid"
        );
        _recNeg(
            RecNeg(bob, address(0), address(0), true, uid, uint64(block.number - 1), pk),
            abi.encodeWithSelector(IUARegistry.UAPqzRecordExpired.selector, bob),
            "class 2 record expired"
        );
        _recNeg(
            RecNeg(bob, address(0), address(0), true, uid, vub, pk == 18_432 ? 16_384 : 18_432),
            abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.PQZ_MLWE),
            "class 2 version 1 of another key length"
        );
        _recNeg(
            RecNeg(bob, c3o, c3o, false, uid, vub, pk),
            abi.encodeWithSelector(IUARegistry.UAPqzOpenKem.selector, c3o),
            "class 3 opening on: record without openKem"
        );
        _recNeg(RecNeg(bob, c3o, c3o, true, sib, vub, pk), unauth, "class 3 opening on: another chainUid");
        _recNeg(
            RecNeg(bob, c3, c3, true, uid, vub, pk),
            abi.encodeWithSelector(IUARegistry.UAPqzOpenKem.selector, c3),
            "class 3 opening off: record with openKem"
        );
        _recNeg(RecNeg(bob, c3, c3, false, sib, vub, pk), unauth, "class 3 opening off: another chainUid");
        _recNeg(RecNeg(bob, t5, c3, false, uid, vub, pk), unauth, "class 3: the record of another token");
        _recNeg(
            RecNeg(mu, address(0), address(0), true, uid, vub, pk),
            abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, mu),
            "class 2: an msig holds no shared key (ruling 9)"
        );
        _recNeg(
            RecNeg(mu, c3o, c3o, false, uid, vub, pk),
            abi.encodeWithSelector(IUARegistry.UAPqzOpenKem.selector, c3o),
            "class 3 opening on: the msig's record without openKem"
        );
        // the public rollover on an opening token, the signed one without the opening
        _neg(
            a2,
            c2,
            abi.encodeCall(IPqzToken.mtxRollOver, (uaM, 0, 1)),
            IPqzToken.RollOverSignedOnly.selector,
            "c2: the public rollover with the opening on"
        );
        _neg(
            a2,
            c3o,
            abi.encodeCall(IPqzToken.mtxRollOver, (uaM, 0, 1)),
            IPqzToken.RollOverSignedOnly.selector,
            "c3o: the public rollover with the opening on"
        );
        _neg(
            a2,
            c3,
            abi.encodeCall(IPqzToken.mtxRollOverSigned, (uaM, 0, 1, new uint64[](0), vub, _pqStub())),
            IPqzToken.OpUnsupported.selector,
            "c3: the signed rollover without the opening"
        );
        // disclosures: with the opening on, RECEIVER_X and AUDITOR refused, SENDER_S answers
        bytes32 ref = IPqzToken(c2).pqzAccount(uaM, 0).accHash; // any ref: the form is refused before the entry is read
        _neg(
            a2,
            c2,
            abi.encodeCall(NormalPqzToken.disclosureStatement, (ref, 0, 1, 1, 0)),
            IPqzToken.OpUnsupported.selector,
            "c2: a RECEIVER_X disclosure with the opening on"
        );
        _neg(
            a2,
            c2,
            abi.encodeCall(NormalPqzToken.disclosureStatement, (ref, 0, 1, 2, 0)),
            IPqzToken.OpUnsupported.selector,
            "c2: an AUDITOR disclosure with the opening on"
        );
    }

    // ------------------------------------------------------------------ negatives: the factory's key classes

    function _factoryNegatives() internal {
        bytes memory bad = abi.encodeWithSelector(IPqzToken.PqzVerifyConfigInvalid.selector);
        _cfgNeg(4, 1, false, false, bad, "OFFCHAIN class 2 without the opening (pqzOpening = false)");
        _cfgNeg(4, 0, true, false, bad, "PRECOMPILE with pqzOwnKey");
        _cfgNeg(4, 0, false, true, bad, "PRECOMPILE with pqzOpening");
    }

    function _cfgNeg(uint8 kind, uint8 mode, bool own, bool open, bytes memory want, string memory what) internal {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin, c.features) =
        ("Onchain PQZ neg", "oPQN", 6, _pad(a1), 1 << GovernanceBits.PAYABLE);
        c.conf = _conf(own, open);
        if (mode == 0) (c.conf.pqzVerifyMode, c.conf.pqzVerifierUA, c.conf.verifierFeeMax) = (0, bytes32(0), 0);
        _negData(
            a1,
            address(fp),
            abi.encodeCall(OpenFactory.createToken, (IOpenFactory.TokenKind(kind), 1, abi.encode(c), _salt(what))),
            want,
            what
        );
    }

    function _save() internal {
        vm.serializeAddress("pk", "fp", address(fp));
        vm.serializeAddress("pk", "c2", c2);
        vm.serializeAddress("pk", "c3o", c3o);
        vm.serializeAddress("pk", "c3", c3);
        vm.serializeAddress("pk", "t5", t5);
        vm.serializeAddress("pk", "t12", t12);
        vm.serializeAddress("pk", "t13", t13);
        vm.serializeAddress("pk", "leg", address(leg));
        vm.serializeAddress("pk", "o5", o5);
        vm.serializeAddress("pk", "o12", o12);
        vm.serializeAddress("pk", "o13", o13);
        vm.serializeBytes32("pk", "uaM", uaM);
        vm.serializeBytes32("pk", "mlSeed", mlSeed);
        vm.serializeBytes32("pk", "bob", bob);
        vm.serializeBytes32("pk", "bobSeed", bobSeed);
        vm.serializeBytes32("pk", "carol", carol);
        vm.serializeAddress("pk", "registry", registry);
        string memory j = vm.serializeBytes32("pk", "carolSeed", carolSeed);
        vm.writeJson(j, _state());
    }
}

/// @notice Run 0 (owner 2026-11-16, D1): the rows with no ML-DSA signer and no `R_REG` proof, so this run sends on any chain
///         whose forge simulation lacks the ML-DSA and PQZ precompiles (the SCaaS testnet's set `mldsa-off`): the factory and
///         its releases (`pub()`), the public layer of the PQZ kinds (`Tokens`' sweep without `_pq`: `skipPq`), the trades and pulls,
///         the regulated powers on 12 and 13, the wrap limits, the factory negatives. Its factory and leg go to the state
///         file for `PqzKeysSetup` (whose helpers it inherits; its `setup()` is the next run).
contract PqzKeysPublic is PqzKeysSetup {
    function pub() external {
        _deps();
        _fixtures();
        _registerDerived();
        _factory();
        skipPq = true;
        _publicLayer();
        _trades();
        _regulatedPowers(12);
        _regulatedPowers(13);
        uint8[3] memory wk = [uint8(3), 9, 11];
        for (uint256 i; i < 3; ++i) {
            _wrapLimits(wk[i]);
        }
        _factoryNegatives();
        vm.serializeAddress("pk0", "fp", address(fp));
        vm.writeJson(vm.serializeAddress("pk0", "leg", address(leg)), _state());
        _writeBook();
    }
}

/// @notice Run 2 (after `ROLL_AGE` blocks): the rollovers. On the opening tokens the holder's signed form over the slots as
///         they are on chain: a mark-only call (`n = 0`) over the planted credit, a roll direct, a roll relayed by the UA
///         envelope (`mtxExecute`) and one by the address envelope (`executeMetaTransaction`), fee 0; negatives: a stale
///         `entriesHash`, the same call replayed (`rollSeq` moved), a mark on a TRIVIAL entry. Without the opening the public
///         rollover. Then a debit over the rolled `acc`.
contract PqzKeysRoll is PqzKeysKit {
    function roll() external {
        _init("pqzkeys");
        _vInit();
        registry = _dep("ua_registry");
        string memory j = vm.readFile(_state());
        (c2, c3o, c3) = (vm.parseJsonAddress(j, ".c2"), vm.parseJsonAddress(j, ".c3o"), vm.parseJsonAddress(j, ".c3"));
        (t5, t12, t13) = (vm.parseJsonAddress(j, ".t5"), vm.parseJsonAddress(j, ".t12"), vm.parseJsonAddress(j, ".t13"));
        (uaM, mlSeed) = (vm.parseJsonBytes32(j, ".uaM"), vm.parseJsonBytes32(j, ".mlSeed"));
        (bob, bobSeed) = (vm.parseJsonBytes32(j, ".bob"), vm.parseJsonBytes32(j, ".bobSeed"));
        (carol, carolSeed) = (vm.parseJsonBytes32(j, ".carol"), vm.parseJsonBytes32(j, ".carolSeed"));
        (o5, o12, o13) = (vm.parseJsonAddress(j, ".o5"), vm.parseJsonAddress(j, ".o12"), vm.parseJsonAddress(j, ".o13"));
        _signed(c2);
        _signed(c3o);
        address[3] memory os = [o5, o12, o13];
        for (uint256 i; i < 3; ++i) {
            IUARegistry.UASig memory s = _rollSig(os[i], uaM, 3, _sk(1), uint64(block.number + WIN));
            vm.broadcast(k2);
            IPqzToken(os[i]).mtxRollOverSigned(uaM, 0, 3, _sk(1), uint64(block.number + WIN), s);
        }
        // without the opening: one entry by the named form (test key 1's envelope), the rest public
        address[4] memory pub = [c3, t5, t12, t13];
        for (uint256 i; i < 4; ++i) {
            _namedAccOp(pub[i], true, uaM, 1);
            IPqzToken.AccountState memory a = IPqzToken(pub[i]).pqzAccount(uaM, 0);
            vm.broadcast(k2);
            IPqzToken(pub[i]).mtxRollOver(uaM, 0, a.pendingCount - a.rolled);
        }
        _send1(c2, _op1(c2, uaM, bob, 0x7e01), false); // a debit over the rolled acc (the book is run 1's)
        // the owner's ops last (each ends with the revocation): direct on kinds 4, 5, 12, through the router on 13
        _ownerOps(c3, false);
        _ownerOps(t5, false);
        _ownerOps(t12, false);
        _ownerOps(t13, true);
    }

    /// On an opening token: uaM's entries 0 TRIVIAL (its shield), 1 bob, 2 carol (the planted credit), 3 bob (compact); bob's 0
    /// TRIVIAL, 1 carol, 2 TRIVIAL (a shield). uaM rolls 2 marking 2 (direct), then 1 relayed by the UA envelope (`mtxExecute`, test key 1's native id
    /// signs, test key 3 sends) and 1 by the address envelope (`executeMetaTransaction`), fee 0; bob marks 1 only (`n = 0`).
    /// The negatives hold on the final state (`coverage.py neg` runs after): bob's mark-only call replayed (`rollSeq` moved),
    /// a stale `entriesHash`, a mark on his TRIVIAL entry.
    function _signed(address t) internal {
        uint64 vub = uint64(block.number + WIN);
        IUARegistry.UASig memory s = _rollSig(t, uaM, 2, _sk(2), vub);
        vm.broadcast(k2);
        IPqzToken(t).mtxRollOverSigned(uaM, 0, 2, _sk(2), vub, s);
        require(IPqzToken(t).pqzSkipped(uaM, 0, 2) && !IPqzToken(t).pqzSkipped(uaM, 0, 1), "marked");
        s = _rollSig(t, uaM, 1, new uint64[](0), vub);
        MetaTxLib.UAMetaTransaction memory m;
        (m.from, m.data, m.batch, m.validUntil) =
        (_pad(a1), abi.encodeCall(IPqzToken.mtxRollOverSigned, (uaM, 0, 1, new uint64[](0), vub, s)), 15, vu);
        m.nonce = NormalPqzToken(t).mtxNonce(_pad(a1), 15);
        IUARegistry.UASig memory es = _sig(k1, NormalPqzToken(t).mtxDigest(m));
        vm.broadcast(k3);
        NormalPqzToken(t).mtxExecute(m, es);
        _rollByAddress(t, vub);
    }

    function _rollByAddress(address t, uint64 vub) internal {
        IUARegistry.UASig memory s = _rollSig(t, uaM, 1, new uint64[](0), vub);
        MetaTxLib.MetaTransaction memory mt;
        (mt.from, mt.data, mt.batch, mt.nonce, mt.validUntil) =
        (
            a1,
            abi.encodeCall(IPqzToken.mtxRollOverSigned, (uaM, 0, 1, new uint64[](0), vub, s)),
            16,
            NormalPqzToken(t).mtxNonce(_pad(a1), 16),
            vu
        );
        bytes32 h = keccak256(
            abi.encode(
                MetaTxLib.METATX_TYPEHASH,
                mt.from,
                keccak256(mt.data),
                mt.batch,
                mt.nonce,
                mt.validUntil,
                mt.mode,
                address(0),
                mt.fee,
                address(0)
            )
        );
        bytes memory sg = _ecdsa(k1, _digest(t, h));
        vm.broadcast(k3);
        NormalPqzToken(t).executeMetaTransaction(mt, sg);
        IPqzToken.AccountState memory st = IPqzToken(t).pqzAccount(uaM, 0);
        require(st.rolled == 4 && st.rolled == st.pendingCount && st.rollSeq == 3, "rolled");
        _signedBob(t);
    }

    function _signedBob(address t) internal {
        uint64 vub = uint64(block.number + WIN);
        // bob: mark only
        IUARegistry.UASig memory s = _rollSig(t, bob, 0, _sk(1), vub);
        uint64 r0 = IPqzToken(t).pqzAccount(bob, 0).rolled;
        vm.broadcast(k2);
        IPqzToken(t).mtxRollOverSigned(bob, 0, 0, _sk(1), vub, s);
        require(
            IPqzToken(t).pqzSkipped(bob, 0, 1) && IPqzToken(t).pqzAccount(bob, 0).rolled == r0,
            "bob marked, nothing rolled"
        );
        _neg(
            a2,
            t,
            abi.encodeCall(IPqzToken.mtxRollOverSigned, (bob, 0, 0, _sk(1), vub, s)),
            IPqzToken.AuthRejected.selector,
            string.concat(_tag(t), ": the mark-only call replayed (rollSeq moved)")
        );
        IUARegistry.UASig memory stale = _uaSig(
            bobSeed, UAKinds.PURPOSE_ZETHER_AUTH, _rollDigest(t, bob, 0, _sk(1), vub, keccak256("another entry"))
        );
        _neg(
            a2,
            t,
            abi.encodeCall(IPqzToken.mtxRollOverSigned, (bob, 0, 0, _sk(1), vub, stale)),
            IPqzToken.AuthRejected.selector,
            string.concat(_tag(t), ": a stale entriesHash")
        );
        IUARegistry.UASig memory triv = _rollSig(t, bob, 0, _sk(2), vub);
        _negData(
            a2,
            t,
            abi.encodeCall(IPqzToken.mtxRollOverSigned, (bob, 0, 0, _sk(2), vub, triv)),
            abi.encodeWithSelector(IPqzToken.SkipTrivial.selector, uint256(2)),
            string.concat(_tag(t), ": a mark on a TRIVIAL entry")
        );
    }

    function _tag(address t) internal view returns (string memory) {
        return t == c2 ? "c2" : "c3o";
    }
}
