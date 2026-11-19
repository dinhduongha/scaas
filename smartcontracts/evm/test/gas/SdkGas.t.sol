// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";

interface ISdkGasNonce {
    function mtxNonce(bytes32 from, uint256 batch) external view returns (uint256);
}

interface ISdkGasBurn {
    function mtxBurn(MetaTxLib.UAEnvelope calldata e, uint256 amount, IUARegistry.UASig calldata auth)
        external
        returns (bytes memory);
}

/// @notice The SDK gas table's measurement (scaas-sdk spec §13.3, owner 2026-11-19, part 3b): each base row's execution gas,
///         `gasTotalUsed - 15,000 (the Amsterdam intrinsic cost) - the call's standard calldata gas (4 a zero byte, 16 a
///         non-zero byte)`, of one isolated call (`foundry.toml`: `isolate = true`) signed by the reference signer, a native
///         EVM key (no registry call), on a fresh lane (nonce 0) and on a used one (the lane's nonce slot set to 1 before the
///         call, everything else the same). The figure is regular gas (`gasTotalUsed`); the call's net state gas
///         (EIP-8037, `gasStateUsed`) is recorded beside it under `<key>_state`, not added: see the open question in the
///         spec (§13.3). Every call starts from the same state (a snapshot), so the payee holds nothing
///         before it: the worst case of a first write. `SDK_GAS_WRITE=true` merges each key into `SDK_GAS_OUT` (default
///         `test/vectors/sdk_gas.json`); run it with `--threads 1`. The SDK table's generator (PLANNED) reads the
///         file. Keys: `<kind>_<entry>_<fresh|used>_<variant>`.
abstract contract SdkGasRows is Test {
    string internal constant SDK_GAS = "test/vectors/sdk_gas.json";
    address internal constant SG_RELAYER = address(0x5EAD);
    address internal constant SG_PAYEE = address(0xFA11);
    uint256 internal constant SG_LANE = 9;

    /// The standard calldata gas of `cd`: 4 a zero byte, 16 a non-zero one.
    function _cdGas(bytes memory cd) internal pure returns (uint256 g) {
        for (uint256 i; i < cd.length; ++i) {
            g += cd[i] == 0 ? 4 : 16;
        }
    }

    /// `from`'s nonce on `lane` of `c` set to `n` (the slot `mtxNonce` reads, found by `vm.record`).
    function _setNonce(address c, bytes32 from, uint256 lane, uint256 n) internal {
        vm.record();
        ISdkGasNonce(c).mtxNonce(from, lane);
        (bytes32[] memory r,) = vm.accesses(c);
        vm.store(c, r[r.length - 1], bytes32(n));
        assertEq(ISdkGasNonce(c).mtxNonce(from, lane), n, "the lane's nonce slot");
    }

    /// The call by the relayer, its execution gas recorded under `key`.
    function _measure(string memory key, address c, bytes memory cd) internal returns (uint256 g) {
        vm.prank(SG_RELAYER);
        (bool ok, bytes memory ret) = c.call(cd);
        if (!ok) {
            assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        }
        Vm.Gas memory used = vm.lastFrameGas();
        g = used.gasTotalUsed - 15_000 - _cdGas(cd);
        assertGe(used.gasStateUsed, 0, "net state gas of a top-level call");
        if (vm.envOr("SDK_GAS_WRITE", false)) {
            string memory out = vm.envOr("SDK_GAS_OUT", SDK_GAS);
            if (vm.exists(out)) vm.serializeJson("sdkgas", vm.readFile(out));
            vm.serializeUint("sdkgas", string.concat(key, "_state"), uint256(int256(used.gasStateUsed)));
            vm.writeJson(vm.serializeUint("sdkgas", key, g), out);
        }
    }

    /// One row on both lane states, each from the same snapshot: `build(c, nonce)` gives the calldata at that nonce.
    function _both(
        string memory kind,
        string memory entry,
        string memory variant,
        address c,
        bytes32 from,
        function(address, uint256) internal view returns (bytes memory) build
    ) internal {
        uint256 s = vm.snapshotState();
        _measure(string.concat(kind, "_", entry, "_fresh_", variant), c, build(c, 0));
        vm.revertToState(s);
        _setNonce(c, from, SG_LANE, 1);
        _measure(string.concat(kind, "_", entry, "_used_", variant), c, build(c, 1));
        vm.revertToState(s);
    }
}

/// The `token` domain kind's base rows on `NormalToken` and `WrappedToken` (the generator stores the worst of the two): the
/// transfer on ids, the pay, the ordered cancel, the burn (Normal only). Calldata by `abi.encodeCall` on the contracts' own
/// functions, the digests from the type strings (`MtxDigest`) or the token's views, as the vector tests build them.
contract SdkGasTokenTest is SdkGasRows, UALedgerBase {
    string internal constant E_TAIL =
        "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

    function setUp() public override {
        super.setUp();
        _wrapFor(alice, 1_000);
    }

    function _from() internal view returns (bytes32) {
        return MetaTxLib.pad(alice);
    }

    function _t(uint256 nonce, bytes32 entryRef) internal view returns (MetaTxLib.UAMetaTransfer memory x) {
        (x.from, x.to, x.value, x.entryRef) = (_from(), MetaTxLib.pad(SG_PAYEE), 1, entryRef);
        (x.batch, x.nonce, x.validUntil) = (SG_LANE, nonce, block.timestamp + 600);
    }

    function _e(uint256 nonce) internal view returns (MetaTxLib.UAEnvelope memory e) {
        (e.from, e.batch, e.nonce, e.validUntil) = (_from(), SG_LANE, nonce, block.timestamp + 600);
    }

    function _sig(bytes32 digest) internal view returns (IUARegistry.UASig memory a) {
        a.signature = _ecdsa(ALICE_PK, digest);
    }

    /// `<head><E>` over `(from, args…, E)` in `c`'s domain, relayer and fee recipient unbound.
    function _named(address c, string memory head, bytes memory args, MetaTxLib.UAEnvelope memory e)
        internal
        view
        returns (IUARegistry.UASig memory)
    {
        bytes32 h = keccak256(
            bytes.concat(
                abi.encode(keccak256(bytes(string.concat(head, E_TAIL))), e.from),
                args,
                abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))
            )
        );
        return _sig(MtxDigest.typed(c, h));
    }

    function _transfer(address c, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAMetaTransfer memory x = _t(nonce, 0);
        return abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (x, _sig(NormalToken(c).mtxTransferDigest(x))));
    }

    function _pay(address c, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.PayMeta memory m = PayMetaKit.meta(keccak256("sdk-gas"));
        MetaTxLib.UAMetaTransfer memory x = _t(nonce, PayMetaKit.id(m));
        return abi.encodeCall(IMetaTokenV2.mtxPay, (x, _sig(NormalToken(c).mtxTransferDigest(x)), m));
    }

    function _cancel(address c, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _e(nonce);
        uint256 lane = SG_LANE + 1;
        return abi.encodeCall(
            NormalToken.mtxCancelNonce,
            (e, lane, _named(c, "UACancelNonce(bytes32 from,uint256 lane,", abi.encode(lane), e))
        );
    }

    function _burn(address c, uint256 nonce) internal view returns (bytes memory) {
        MetaTxLib.UAEnvelope memory e = _e(nonce);
        return abi.encodeCall(
            ISdkGasBurn.mtxBurn, (e, 1, _named(c, "UABurn(bytes32 from,uint256 amount,", abi.encode(uint256(1)), e))
        );
    }

    function test_sdkGas_token() public {
        _both("token", "mtxExecuteTransfer", "normal", address(tok), _from(), _transfer);
        _both("token", "mtxExecuteTransfer", "wrapped", address(wrp), _from(), _transfer);
        _both("token", "mtxPay", "normal", address(tok), _from(), _pay);
        _both("token", "mtxPay", "wrapped", address(wrp), _from(), _pay);
        _both("token", "mtxCancelNonce", "normal", address(tok), _from(), _cancel);
        _both("token", "mtxCancelNonce", "wrapped", address(wrp), _from(), _cancel);
        _both("token", "mtxBurn", "normal", address(tok), _from(), _burn);
    }
}
