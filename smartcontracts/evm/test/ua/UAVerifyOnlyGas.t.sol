// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UARegistryRegLib} from "../../src/ua/UARegistryRegLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {VerifyOnlyStandIn} from "./UARegistryLine.t.sol";
import {UACall} from "./UACall.sol";

/// @notice T-GAS of the verify-only path and the line (spec 2026-11-19-registry-verify-only-kinds §13 Gas, §11.1 N11, §4; plan
///         Task 15): per depth 1 – 4 (the hops from the generation asked to the holder, gen 1), the consumer path on this
///         generation's verify-only verifier (a stand-in of the precompile path), its fallback to the holder (the stand-in gives
///         no answer), the write path of W1 (`acceptMembership` of a member held in gen 1, checked by the holder), the miss at
///         depth 16 (the verify-only `msig` members at the budget: `UARegistryHardBound.t.sol` test_voMember_boundCountsReads and
///         test_voMember_readsWithinConstant). Gen 1's verifiers follow the `MockVerifier` rule, so a row
///         is the registry's own work beside a verifier call of known cost: what the bounds' constants (`LINE_HOP_GAS`,
///         `VO_READ_GAS`) must cover. Each row is logged; the assertions are those bounds. UNAUDITED.
contract UAVerifyOnlyGasTest is UARegistryBase {
    uint16 internal constant P256 = 0x0101;
    uint16 internal constant FN = UAKinds.FNDSA512;
    address internal constant PC = address(0x5caa0013);
    uint64 internal constant CAP_VO = 250_000;

    UARegistry internal g1;
    bytes internal fnKey;
    bytes32 internal fnId;
    bytes32 internal pId;
    uint256 internal at = 0x7e10;

    function setUp() public override {
        super.setUp();
        UARegistry.KindConfig[] memory b = _cfgs(address(mock));
        UARegistry.KindConfig[] memory k1 = new UARegistry.KindConfig[](b.length + 1);
        for (uint256 i; i < b.length; ++i) {
            k1[i] = b[i];
        }
        k1[b.length] = UARegistry.KindConfig(FN, address(mock), 2_500_000, false, 0);
        g1 = _deploy(address(0x7e01), chainUidA, address(0), false, BUDGET, address(0), true, k1);
        fnKey = new bytes(897);
        (fnKey[0], fnKey[3]) = (bytes1(0x09), bytes1(0x01));
        fnId = _register(g1, FN, fnKey);
        pId = _register(g1, P256, _key(P256));
    }

    function _plain(address pred) internal returns (UARegistry) {
        return _deploy(
            address(uint160(++at)), chainUidA, pred, false, BUDGET, address(0), true, new UARegistry.KindConfig[](0)
        );
    }

    /// The generation `depth` hops above gen 1: plain generations between, the top one carrying `p256` and `fndsa512` verify-only
    /// with a stand-in of `mode` (0 answers by the holder's rule, 2 refuses all, 3 no answer: the fallback).
    function _top(uint256 depth, uint8 mode) internal returns (UARegistry r) {
        r = g1;
        for (uint256 d = 1; d < depth; ++d) {
            r = _plain(address(r));
        }
        address v = address(new VerifyOnlyStandIn(PC, 0, mode));
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](2);
        k[0] = UARegistry.KindConfig(P256, v, CAP_VO, true, 0);
        k[1] = UARegistry.KindConfig(FN, v, CAP_VO, true, 0);
        r = _deploy(address(uint160(++at)), chainUidA, address(r), false, BUDGET, address(0), true, k);
    }

    function _gas(address r, bytes memory call) internal returns (uint256 g) {
        uint256 b = gasleft();
        (bool ok,) = r.call(call);
        g = b - gasleft();
        assertTrue(ok, "the row's call");
    }

    bytes32 internal constant TYPED = keccak256("scaas.test.typed");

    /// The `p256` record's consumer check (`requireAuthorized`), the `fndsa512` record's portable check (`requirePortable`: a PQ
    /// key's 897 B read at the holder).
    function _call(uint16 kind) internal view returns (bytes memory) {
        if (kind == P256) {
            return
                _reqCall(
                    pId, UAKinds.PURPOSE_METATX, DIGEST, _auth(g1, P256, _key(P256), UAKinds.PURPOSE_METATX, DIGEST)
                );
        }
        IUARegistry.UASig memory s;
        s.signature = _sig(fnKey, UAKinds.uaMessage(FN, UAKinds.PURPOSE_PQCHAT, TYPED));
        return abi.encodeCall(IUARegistry.requirePortable, (fnId, UAKinds.PURPOSE_PQCHAT, TYPED, s));
    }

    /// The consumer path (`requireAuthorized`) per depth, on this generation's verifier and on the fallback, beside the holder's
    /// own check at gen 1: the walk per hop within `LINE_HOP_GAS`, the verify-only reads within `VO_READ_GAS`, the fallback within
    /// the holder's cap, one hand-off and the reads (the `_slotCap` `FALLBACK` row).
    function test_T_GAS_voConsumer_perDepth() public {
        uint16[2] memory kinds = [P256, FN];
        uint256 hop; // the dearest further generation on the consumer path
        for (uint256 j; j < 2; ++j) {
            uint16 kind = kinds[j];
            string memory name = j == 0 ? "p256 requireAuthorized" : "fndsa512 requirePortable";
            uint256 direct = _gas(address(g1), _call(kind));
            emit log_named_uint(string.concat(name, " holder's own check (gen 1)"), direct);
            uint256 prev;
            for (uint256 d = 1; d <= 4; ++d) {
                uint256 own = _gas(address(_top(d, 0)), _call(kind));
                uint256 fb = _gas(address(_top(d, 3)), _call(kind));
                emit log_named_uint(string.concat(name, " verify-only, depth ", vm.toString(d)), own);
                emit log_named_uint(string.concat(name, " fallback, depth ", vm.toString(d)), fb);
                assertLe(own, direct + d * UARegistryRegLib.LINE_HOP_GAS + UARegistryRegLib.VO_READ_GAS, "own path");
                if (d > 1 && own - prev > hop) hop = own - prev;
                uint256 hc = g1.verifyCap(kind);
                assertLe(
                    fb,
                    own + hc + hc / 63 + 5_000 + d * UARegistryRegLib.LINE_HOP_GAS + UARegistryRegLib.VO_READ_GAS,
                    "fallback: the holder's cap, one hand-off, the reads"
                );
                prev = own;
            }
        }
        emit log_named_uint("one further generation on the consumer path (dearest)", hop);
        assertLe(hop, UARegistryRegLib.LINE_HOP_GAS, "one more hop within LINE_HOP_GAS");
    }

    /// W1's write path per depth: `acceptMembership` at the top generation of a member gen 1 holds, its signature checked by the
    /// holder through the walk (the top's verify-only verifier refuses all: never asked on a write).
    function test_T_GAS_voWrite_perDepth() public {
        uint256 prev;
        for (uint256 d = 1; d <= 4; ++d) {
            UARegistry top = _top(d, 2);
            Member[] memory m = new Member[](1);
            m[0] = Member(P256, pId, 1);
            bytes memory key = _msigKey(1, m);
            bytes32 ua = UACall.register(top, UAKinds.MSIG, key, _none(), "", "");
            uint256 g = _gas(
                address(top), abi.encodeCall(IUARegistry.acceptMembership, (ua, _acceptKeySig(key, P256, _key(P256))))
            );
            emit log_named_uint(string.concat("acceptMembership (W1, the holder checks), depth ", vm.toString(d)), g);
            if (d > 1) assertLe(g - prev, UARegistryRegLib.LINE_HOP_GAS, "one more hop on the write path");
            prev = g;
        }
    }

    /// The miss at depth 16: an id no generation holds, asked at generation 16, walks 15 predecessors and is refused.
    function test_T_GAS_missAtDepth16() public {
        UARegistry r = g1;
        for (uint256 g = 2; g <= 16; ++g) {
            r = _plain(address(r));
        }
        assertEq(r.generation(), 16);
        bytes memory call = _reqCall(keccak256("scaas.test.nobody"), UAKinds.PURPOSE_METATX, DIGEST, hex"00");
        uint256 b = gasleft();
        (bool ok,) = address(r).call(call);
        uint256 g16 = b - gasleft();
        assertFalse(ok, "unregistered");
        emit log_named_uint("requireAuthorized miss at generation 16 (15 hops)", g16);
        assertLe(g16, 15 * UARegistryRegLib.LINE_HOP_GAS + 30_000, "within the hops' bound and the frame");
    }
}
