// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {P256Verifier} from "../../src/ua/verifiers/P256Verifier.sol";
import {WebAuthnP256Verifier} from "../../src/ua/verifiers/WebAuthnP256Verifier.sol";
import {Bip340Verifier} from "../../src/ua/verifiers/Bip340Verifier.sol";
import {Secp256k1Verifier} from "../../src/ua/verifiers/Secp256k1Verifier.sol";
import {Ed25519Verifier} from "../../src/ua/verifiers/Ed25519Verifier.sol";
import {
    SchnorrBn254Verifier,
    SchnorrBls12381Verifier,
    BlsMinSigBls12381Verifier,
    BlsMinSigBn254Verifier,
    ZetherSchnorrBls12381Verifier
} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {UAMldsaVerifier} from "../../src/ua/MlDsa.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {noneInit} from "../v2/helpers/V2Fixture.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {plainEnv} from "../helpers/Catalogue.sol";

/// Classifies every token as a registered SCaaS token, so a DEX clone at a vector address can list the vector tokens.
contract KindFactory {
    function isToken(address) external pure returns (bool) {
        return true;
    }

    function versionOf(address) external pure returns (IOpenFactory.TokenKind, uint64) {
        return (IOpenFactory.TokenKind.NONE, 1);
    }

    function isDeprecated(IOpenFactory.TokenKind, uint64) external pure returns (bool) {
        return false;
    }
}

/// smartcontracts/vectors/ua/uatrade_kat.json (UA-5b, dex.md CTR-DEX-25/26) on context A with the real verifiers: `NONE`
/// clones at the vector's token addresses, a `SCaaSDex` clone at its DEX address. Every row's order, cancel and
/// invalidation digest is recomputed by the token, every auth passes through the token under the purpose `trade`
/// (`uaCancelOrder`, `uaInvalidateNonces`, and the order in a settlement against the native maker, gas logged per kind);
/// the `mldsa65` rows bound one transaction (EIP-7825, 16,777,216 gas): two PQ legs fit, three revert `UAVerifyGas`.
contract UATradeVectorsTest is UARegistryBase {
    uint256 internal constant TX_GAS_CAP = 16_777_216;
    address internal constant RELAYER = address(0xBEEF);
    address internal constant TREASURY = address(0x7EA5);
    string internal vj;
    NoUnderlyingToken internal A;
    NoUnderlyingToken internal B;
    SCaaSDex internal dex;

    function setUp() public override {
        super.setUp();
        string memory sj = vm.readFile("../vectors/ua/signatures.json");
        string memory pj = vm.readFile("../vectors/ua/pq_signatures.json");
        vj = vm.readFile("../vectors/ua/uatrade_kat.json");
        assertEq(vm.parseJsonAddress(vj, ".registry"), REG_A);
        assertEq(vm.parseJsonBytes32(vj, ".chainUid"), chainUidA);
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _realCfgs());
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            string memory d = string.concat(".derived[", vm.toString(i), "].");
            reg.register(uint16(vm.parseJsonUint(sj, string.concat(d, "kind"))),
                vm.parseJsonBytes(sj, string.concat(d, "keyData")), vm.parseJsonBytes(sj, string.concat(d, "pop.sig")), "", "");
        }
        for (uint256 i; i < 4; ++i) {
            string memory k = string.concat(".kinds[", vm.toString(i), "].");
            if (vm.parseJsonUint(pj, string.concat(k, "kind")) == 0x0131) _registerMldsa65(pj, k);
        }
        _registerMldsa65(pj, ".extraKeys[0].");
        _registerMldsa65(pj, ".extraKeys[1].");
        A = _token(vm.parseJsonAddress(vj, ".tokenA"));
        B = _token(vm.parseJsonAddress(vj, ".tokenB"));
        KindFactory kf = new KindFactory();
        address impl = address(new SCaaSDex(1, plainEnv(address(kf), address(0), chainUidA, address(0), false), ""));
        address at = vm.parseJsonAddress(vj, ".dex");
        vm.etch(at, abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"));
        dex = SCaaSDex(at);
        vm.prank(address(kf));
        dex.initialize(address(this), 1, abi.encode(ISCaaSDex.DexConfig(address(this), 200_000, TREASURY, false)));
        dex.setMarket(address(A), address(B), true);
        vm.warp(1_800_000_000);
    }

    function _registerMldsa65(string memory pj, string memory k) internal {
        bytes memory pk = vm.parseJsonBytes(pj, string.concat(k, "keyData"));
        for (uint256 p; p < 2; ++p) reg.cacheExpandedKey(0x0131, pk, p);
        reg.register(0x0131, pk, vm.parseJsonBytes(pj, string.concat(k, "pop.sig")), "", "");
    }

    function _token(address at) internal returns (NoUnderlyingToken t) {
        address impl = address(new NoUnderlyingToken(1, plainEnv(address(this), address(0), chainUidA, REG_A, false), ""));
        vm.etch(at, abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"));
        t = NoUnderlyingToken(at);
        t.initialize(address(this), 1, abi.encode(noneInit("T", "T", 6, 1e15, address(this), address(this))));
    }

    function _realCfgs() internal returns (UARegistry.KindConfig[] memory c) {
        address[8] memory v = [
            address(new WebAuthnP256Verifier()), address(new P256Verifier()), address(new Ed25519Verifier()),
            address(new Bip340Verifier()), address(new SchnorrBn254Verifier()), address(new SchnorrBls12381Verifier()),
            address(new BlsMinSigBls12381Verifier()), address(new BlsMinSigBn254Verifier())
        ];
        c = new UARegistry.KindConfig[](11);
        for (uint256 i; i < 8; ++i) c[i] = UARegistry.KindConfig(KINDS[i], v[i], _cap(KINDS[i]));
        c[8] = UARegistry.KindConfig(0x0131, address(new UAMldsaVerifier(0x0131, address(0), "", "")), 5_950_000);
        c[9] = UARegistry.KindConfig(0x0108, address(new Secp256k1Verifier()), 50_000);
        c[10] = UARegistry.KindConfig(0x0141, address(new ZetherSchnorrBls12381Verifier()), 70_000);
    }

    // ----- vector reading -----

    function _order(string memory p) internal view returns (ITradeToken.UATradeOrder memory o) {
        o.from = vm.parseJsonBytes32(vj, string.concat(p, "from"));
        o.receiveToken = vm.parseJsonAddress(vj, string.concat(p, "receiveToken"));
        o.amount = vm.parseJsonUint(vj, string.concat(p, "amount"));
        o.receiveAmount = vm.parseJsonUint(vj, string.concat(p, "receiveAmount"));
        o.minFill = vm.parseJsonUint(vj, string.concat(p, "minFill"));
        o.fee = vm.parseJsonUint(vj, string.concat(p, "fee"));
        o.relayer = vm.parseJsonAddress(vj, string.concat(p, "relayer"));
        o.dex = vm.parseJsonAddress(vj, string.concat(p, "dex"));
        o.destination = vm.parseJsonBytes32(vj, string.concat(p, "destination"));
        o.flags = uint8(vm.parseJsonUint(vj, string.concat(p, "flags")));
        o.batch = vm.parseJsonUint(vj, string.concat(p, "batch"));
        o.nonce = vm.parseJsonUint(vj, string.concat(p, "nonce"));
        o.validUntil = vm.parseJsonUint(vj, string.concat(p, "validUntil"));
    }

    function _row(uint256 i) internal pure returns (string memory) {
        return string.concat(".rows[", vm.toString(i), "].");
    }

    /// A shape-1 leg from an order at path `r` (`order.message.`, `auth`).
    function _leg(address sell, string memory r, uint256 fill) internal view returns (ISCaaSDex.Leg memory) {
        ITradeToken.UATradeOrder memory o = _order(string.concat(r, "order.message."));
        return ISCaaSDex.Leg(sell, 1, abi.encode(o), vm.parseJsonBytes(vj, string.concat(r, "auth")), fill);
    }

    function _fund(NoUnderlyingToken t, bytes32 id, uint256 v) internal {
        if (UAKinds.inNativeSpace(id)) t.transfer(address(uint160(uint256(id))), v);
        else t.transferToUA(id, v);
    }

    // ----- tests -----

    function test_typeHashesPurposeDomain() public view {
        assertEq(vm.parseJsonBytes32(vj, ".typeHashes.UATradeOrder"), TradeLib.UA_TRADE_ORDER_TYPEHASH);
        assertEq(vm.parseJsonBytes32(vj, ".typeHashes.UAInvalidateNonces"), TradeLib.UA_INVALIDATE_NONCES_TYPEHASH);
        assertEq(vm.parseJsonBytes32(vj, ".typeHashes.CancelOrder"), TradeLib.CANCEL_ORDER_TYPEHASH);
        assertEq(vm.parseJsonBytes32(vj, ".purposeTag"), UAKinds.PURPOSE_TRADE);
        bytes32 ds = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), block.chainid, address(A), chainUidA));
        assertEq(vm.parseJsonBytes32(vj, ".domainSeparatorA"), ds);
    }

    /// Every signer: the token recomputes the three digests; the order settles against the native maker (the native row
    /// is the maker's own id: no settlement, `SelfTrade`); the cancel and the invalidation pass through the token.
    function test_rows_digests_settle_cancel_invalidate() public {
        ISCaaSDex.Leg memory maker = _leg(address(B), ".nativeMaker.", 2000);
        bytes32 makerId = abi.decode(maker.order, (ITradeToken.UATradeOrder)).from;
        uint256 n;
        for (uint256 i; vm.keyExistsJson(vj, string.concat(".rows[", vm.toString(i), "]")); ++i) {
            string memory r = _row(i);
            ITradeToken.UATradeOrder memory o = _order(string.concat(r, "order.message."));
            bytes32 h = vm.parseJsonBytes32(vj, string.concat(r, "orderHash"));
            assertEq(A.uaTradeOrderDigest(o), h);
            assertEq(A.cancelOrderDigest(h), vm.parseJsonBytes32(vj, string.concat(r, "cancelDigest")));
            assertEq(A.uaInvalidateNoncesDigest(o.from, 1, 5), vm.parseJsonBytes32(vj, string.concat(r, "invalidateDigest")));
            uint256 snap = vm.snapshotState();
            if (o.from != makerId) {
                _fund(A, o.from, 1000);
                _fund(B, makerId, 2000);
                ISCaaSDex.Settlement[] memory ss = new ISCaaSDex.Settlement[](1);
                ss[0].ref = h;
                ss[0].taker = _leg(address(A), r, 1000);
                ss[0].makers = new ISCaaSDex.Leg[](1);
                ss[0].makers[0] = maker;
                vm.prank(RELAYER);
                uint256 g = gasleft();
                bool ok = dex.mtxSettle(ss)[0];
                g -= gasleft();
                assertTrue(ok);
                emit log_named_uint(string.concat("mtxSettle UA taker x native maker (shape 1 x 1): ",
                    vm.parseJsonString(vj, string.concat(r, "name"))), g);
                assertEq(B.balanceOfUA(o.from), 2000 - 6);
                assertEq(A.pulled(h), 1000);
            }
            A.uaCancelOrder(o, vm.parseJsonBytes(vj, string.concat(r, "cancelAuth")));
            assertEq(A.pulled(h), 1000);
            A.uaInvalidateNonces(o.from, 1, 5, vm.parseJsonBytes(vj, string.concat(r, "invalidateAuth")));
            assertEq(A.uaMinNonce(o.from, 1), 5);
            vm.revertToState(snap);
            ++n;
        }
        assertEq(n, 11);
    }

    function _pqLeg(uint256 i, uint256 fill) internal view returns (ISCaaSDex.Leg memory) {
        string memory r = string.concat(".pq[", vm.toString(i), "].");
        return _leg(vm.parseJsonAddress(vj, string.concat(r, "sellToken")), r, fill);
    }

    /// `mldsa65` taker (#0) and makers: funds them and returns the `mtxSettle` calldata of one settlement.
    function _pqSettle(uint256 makers) internal returns (bytes memory) {
        ISCaaSDex.Settlement[] memory ss = new ISCaaSDex.Settlement[](1);
        ss[0].ref = "pq";
        ss[0].taker = _pqLeg(0, 500 * makers);
        _fund(A, abi.decode(ss[0].taker.order, (ITradeToken.UATradeOrder)).from, 1000);
        ss[0].makers = new ISCaaSDex.Leg[](makers);
        for (uint256 i; i < makers; ++i) {
            ss[0].makers[i] = _pqLeg(i + 1, 1000);
            _fund(B, abi.decode(ss[0].makers[i].order, (ITradeToken.UATradeOrder)).from, 1000);
        }
        return abi.encodeCall(ISCaaSDex.mtxSettle, (ss));
    }

    /// EIP-2028 calldata gas and the EIP-7623 floor (as UAMetaTx3Pq.t.sol).
    function _calldataGas(bytes memory cd) internal pure returns (uint256 std, uint256 floor) {
        uint256 zeros;
        for (uint256 i; i < cd.length; ++i) if (cd[i] == 0) ++zeros;
        std = 4 * zeros + 16 * (cd.length - zeros);
        floor = 10 * (zeros + 4 * (cd.length - zeros));
    }

    /// A PQ taker against one PQ maker: two `mldsa65` verifies (each held at its 5.95 M cap) settle inside one capped
    /// transaction, intrinsic and calldata included.
    function test_pq_twoMldsa65Legs_fitOneTransaction() public {
        bytes memory cd = _pqSettle(1);
        (uint256 std, uint256 floor) = _calldataGas(cd);
        vm.prank(RELAYER);
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = address(dex).call{gas: TX_GAS_CAP - 21_000 - std}(cd);
        g -= gasleft();
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        assertTrue(abi.decode(ret, (bool[]))[0]);
        uint256 txGas = 21_000 + (std + g > floor ? std + g : floor);
        emit log_named_uint("calldata bytes", cd.length);
        emit log_named_uint("calldata gas (EIP-2028)", std);
        emit log_named_uint("execution gas", g);
        emit log_named_uint("transaction gas, 2 x mldsa65 legs", txGas);
        assertLt(txGas, TX_GAS_CAP);
    }

    /// Against two PQ makers (three `mldsa65` verifies) the third cannot get its cap: the registry reverts
    /// `UAVerifyGas` and `mtxSettle` re-raises it for the whole call (never `MatchFailed`); with more gas it settles.
    function test_pq_threeMldsa65Legs_revertUAVerifyGas() public {
        bytes memory cd = _pqSettle(2);
        (uint256 std,) = _calldataGas(cd);
        vm.prank(RELAYER);
        (bool ok, bytes memory ret) = address(dex).call{gas: TX_GAS_CAP - 21_000 - std}(cd);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(UAKinds.UAVerifyGas.selector));
        vm.prank(RELAYER);
        uint256 g = gasleft();
        (ok, ret) = address(dex).call{gas: 3 * TX_GAS_CAP}(cd);
        g -= gasleft();
        assertTrue(ok);
        assertTrue(abi.decode(ret, (bool[]))[0]);
        emit log_named_uint("execution gas, 3 x mldsa65 legs (over the cap)", g);
    }
}
