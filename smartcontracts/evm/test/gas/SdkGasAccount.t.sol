// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {SmartKeyAccount, SubjectKey, KeyKind, AccountSig} from "../../src/account/SmartKeyAccount.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTxAddress} from "../../src/metatx/IMetaTxAddress.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {UID_} from "../v2/helpers/V2Fixture.sol";
import {SdkGasOps} from "./SdkGasOps.sol";
import {SdkGasMetered} from "./SdkGasMeter.sol";

interface ISdkGasAddrNonce {
    function mtxNonce(address from, uint256 batch) external view returns (uint256);
}

/// The `account` domain kind's base rows on `SmartKeyAccount` (scaas-sdk spec §13.3, owner 2026-11-19, part 3b): the
/// account's own typed entries, `from` the account, signed by its key 0, the reference signer `sgPk`'s secp256k1 key (a
/// native EVM key), in an `AccountSig` with an empty proof. `acct` holds three keys (0 the signer's, 1 another secp256k1
/// key, 2 a passkey) and no guardian; `rec` the signer's key and a guardian whose recovery is pending (what
/// `mtxCancelRecovery` needs). Lanes as `SdkGasRows._both`: fresh = nonce 0 on `SG_LANE`, used = its slot set to 1. A
/// variant names the state where an entry has more than one, each counting toward the worst: the key added (`secp`,
/// `p256`), the key removed or replaced (`secp`, `p256`; the replacement always a passkey, the larger write), a guardian set
/// with no recovery pending (`none`) or replacing one (`pending`); else `account`. `mtxExecute` calls an account without
/// code with no value (the account's own cost, the target's never in a row), its `data` with the per-byte coefficient as
/// the wallet's. No `_ua_` row: the account signs with its own key set (`AccountSig`), never a UA; no fee row: its entries
/// take fee `NONE` (as the wallet's).
contract SdkGasAccountTest is SdkGasOps, SdkGasMetered {
    string internal constant RP_ID = "pay.example.com";
    string internal constant ORIGIN = "https://pay.example.com";
    uint256 internal constant SG_PASSKEY = 0xC0FFEE1234567890;
    uint256 internal constant SG_PASSKEY2 = 0xBADC0DE5;
    uint256 internal constant SG_SEED2 = 0x5EED;
    uint256 internal constant SG_SEED3 = 0x5EED3;
    address internal constant SG_GUARDIAN = address(0x6A2D);
    address internal constant SG_GUARDIAN2 = address(0x6A2E);
    SmartKeyAccount internal acct;
    SmartKeyAccount internal rec;
    /// the operand of the row under measurement: the key added, the index removed or replaced
    SubjectKey internal sgKey;
    uint256 internal sgIndex;

    function _passkey(uint256 pk) internal pure returns (SubjectKey memory) {
        (uint256 x, uint256 y) = vm.publicKeyP256(pk);
        return SubjectKey(KeyKind.P256_WEBAUTHN, bytes32(x), bytes32(y), sha256(bytes(RP_ID)), keccak256(bytes(ORIGIN)));
    }

    function _seed(uint256 pk) internal pure returns (SubjectKey memory) {
        return SubjectKey(KeyKind.SECP256K1, bytes32(uint256(uint160(vm.addr(pk)))), 0, 0, 0);
    }

    /// The account's own call on lane 0 (`mtxExecuteAsOwner`), signed by key 0: the fixture's set-up only.
    function _own(SmartKeyAccount a, bytes memory data, uint256 nonce) internal {
        MetaTxLib.MetaTransaction memory m;
        (m.from, m.data, m.nonce, m.validUntil) = (address(a), data, nonce, block.timestamp + 600);
        bytes memory sig = abi.encode(uint256(0), new bytes32[](0), _sgSign(sgPk, a.mtxDigest(m)));
        a.mtxExecuteAsOwner(data, nonce, m.validUntil, sig);
    }

    function setUp() public {
        vm.warp(1_800_000_000);
        sgPk = 0xA11CE;
        SmartKeyAccountFactory fac = new SmartKeyAccountFactory(UID_);
        acct = SmartKeyAccount(payable(fac.deploy(_seed(sgPk), address(0))));
        _own(acct, abi.encodeCall(SmartKeyAccount.addKey, (_seed(SG_SEED2))), 0);
        _own(acct, abi.encodeCall(SmartKeyAccount.addKey, (_passkey(SG_PASSKEY))), 1);
        assertEq(acct.keyCount(), 3);
        rec = SmartKeyAccount(payable(fac.deploy(_seed(sgPk), SG_GUARDIAN)));
        SubjectKey memory k = _passkey(SG_PASSKEY2);
        vm.prank(SG_GUARDIAN);
        rec.initiateRecovery(k);
    }

    function _e(address c, uint256 nonce) internal view returns (MetaTxLib.Envelope memory e) {
        (e.from, e.batch, e.nonce, e.validUntil) = (c, SG_LANE, nonce, block.timestamp + 600);
    }

    /// Key 0's `AccountSig` over `<head><E>` of `(from = c, args…, E)` in `c`'s domain, relayer and fee recipient unbound.
    function _aSig(address c, string memory head, bytes memory args, uint256 nonce)
        internal
        view
        returns (AccountSig memory)
    {
        MetaTxLib.Envelope memory e = _e(c, nonce);
        bytes32 d = MtxDigest.typed(
            c,
            keccak256(
                bytes.concat(
                    abi.encode(keccak256(bytes(string.concat(head, E_TAIL))), c),
                    args,
                    abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))
                )
            )
        );
        return AccountSig(0, new bytes32[](0), _sgSign(sgPk, d));
    }

    function _addKey(address c, uint256 nonce) internal view returns (bytes memory) {
        SubjectKey memory k = sgKey;
        AccountSig memory s = _aSig(
            c,
            "AddKey(address from,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash,",
            abi.encode(uint8(k.kind), k.x, k.y, k.rpIdHash, k.originHash),
            nonce
        );
        return
            abi.encodeCall(
                SmartKeyAccount.mtxAddKey, (_e(c, nonce), uint8(k.kind), k.x, k.y, k.rpIdHash, k.originHash, s)
            );
    }

    function _removeKey(address c, uint256 nonce) internal view returns (bytes memory) {
        AccountSig memory s = _aSig(c, "RemoveKey(address from,uint256 index,", abi.encode(sgIndex), nonce);
        return abi.encodeCall(SmartKeyAccount.mtxRemoveKey, (_e(c, nonce), sgIndex, s));
    }

    function _rotateKey(address c, uint256 nonce) internal view returns (bytes memory) {
        SubjectKey memory k = sgKey;
        AccountSig memory s = _aSig(
            c,
            "RotateKey(address from,uint256 index,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash,",
            abi.encode(sgIndex, uint8(k.kind), k.x, k.y, k.rpIdHash, k.originHash),
            nonce
        );
        return abi.encodeCall(
            SmartKeyAccount.mtxRotateKey, (_e(c, nonce), sgIndex, uint8(k.kind), k.x, k.y, k.rpIdHash, k.originHash, s)
        );
    }

    function _setGuardian(address c, uint256 nonce) internal view returns (bytes memory) {
        AccountSig memory s = _aSig(c, "SetGuardian(address from,address guardian,", abi.encode(SG_GUARDIAN2), nonce);
        return abi.encodeCall(SmartKeyAccount.mtxSetGuardian, (_e(c, nonce), SG_GUARDIAN2, s));
    }

    function _cancelRecovery(address c, uint256 nonce) internal view returns (bytes memory) {
        AccountSig memory s = _aSig(c, "CancelRecovery(address from,", "", nonce);
        return abi.encodeCall(SmartKeyAccount.mtxCancelRecovery, (_e(c, nonce), s));
    }

    /// `data` of `sgBody` bytes (0 the base row) to an account without code, no value.
    function _aExecute(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes memory data = new bytes(sgBody);
        for (uint256 i; i < data.length; ++i) {
            data[i] = 0xab;
        }
        AccountSig memory s = _aSig(
            c,
            "Execute(address from,address target,uint256 value,bytes data,",
            abi.encode(SG_PAYEE, uint256(0), keccak256(data)),
            nonce
        );
        return abi.encodeCall(SmartKeyAccount.mtxExecute, (_e(c, nonce), SG_PAYEE, 0, data, s));
    }

    /// The ordered cancel of the next lane; its signature the `AccountSig` as `bytes`.
    function _aCancel(address c, uint256 nonce) internal view returns (bytes memory) {
        uint256 lane = SG_LANE + 1;
        AccountSig memory s = _aSig(c, "CancelNonce(address from,uint256 lane,", abi.encode(lane), nonce);
        return abi.encodeCall(
            IMetaTxAddress.mtxCancelNonce, (_e(c, nonce), lane, abi.encode(s.keyIndex, s.proof, s.signature))
        );
    }

    /// `_both` of an address-signed account: its lane read by `mtxNonce(address, uint256)`.
    function _bothA(
        string memory entry,
        string memory variant,
        address c,
        function(address, uint256) internal view returns (bytes memory) build
    ) internal {
        string memory k = string.concat("account_", entry, "_");
        uint256 s = vm.snapshotState();
        _measure(string.concat(k, "fresh_", variant), c, build(c, 0));
        vm.revertToState(s);
        vm.record();
        ISdkGasAddrNonce(c).mtxNonce(c, SG_LANE);
        (bytes32[] memory r,) = vm.accesses(c);
        vm.store(c, r[r.length - 1], bytes32(uint256(1)));
        assertEq(ISdkGasAddrNonce(c).mtxNonce(c, SG_LANE), 1, "the lane's nonce slot");
        _measure(string.concat(k, "used_", variant), c, build(c, 1));
        vm.revertToState(s);
    }

    function test_sdkGas_account() public {
        address a = address(acct);
        sgKey = _seed(SG_SEED3);
        _bothA("mtxAddKey", "secp", a, _addKey);
        sgKey = _passkey(SG_PASSKEY2);
        _bothA("mtxAddKey", "p256", a, _addKey);
        sgIndex = 1;
        _bothA("mtxRemoveKey", "secp", a, _removeKey);
        _bothA("mtxRotateKey", "secp", a, _rotateKey);
        sgIndex = 2;
        _bothA("mtxRemoveKey", "p256", a, _removeKey);
        _bothA("mtxRotateKey", "p256", a, _rotateKey);
        _bothA("mtxSetGuardian", "none", a, _setGuardian);
        _bothA("mtxSetGuardian", "pending", address(rec), _setGuardian);
        _bothA("mtxCancelRecovery", "account", address(rec), _cancelRecovery);
        _bothA("mtxExecute", "account", a, _aExecute);
        _bothA("mtxCancelNonce", "account", a, _aCancel);
    }

    /// Ruling B's treatment of `mtxExecute`'s `data` (as the wallet's): 32 and 160 bytes, a fresh lane, measured inside the
    /// transaction (`SdkGasMetered`: with the account's signature, 160 bytes of data put the call on the calldata floor).
    function test_sdkGas_account_body() public {
        address a = address(acct);
        uint256 s = vm.snapshotState();
        sgBody = 32;
        uint256 lo = _measureMetered("account_mtxExecute_body32_account", a, _aExecute(a, 0));
        vm.revertToState(s);
        sgBody = 160;
        uint256 hi = _measureMetered("account_mtxExecute_body160_account", a, _aExecute(a, 0));
        vm.revertToState(s);
        _perByte("account_mtxExecute_per_byte_account", lo, hi, 128);
    }
}
