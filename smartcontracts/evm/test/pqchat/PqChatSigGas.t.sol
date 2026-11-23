// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {MockVerifier} from "../ua/UARegistryBase.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// CTR-CHAT-23 (owner 2026-11-23): the gas of the signature-storage setting, `isolate = true`, one transaction per row: the
/// 2-member writes at `none` and `sstore2` with a real signature's size, ML-DSA-65 (3,309 B) and FN-DSA-512 (666 B). The
/// verifier is a stand-in that accepts every signature (its own gas excluded, as in `PqChatGas.t.sol`), so a row is `PqChat`'s
/// and the registry's own cost plus the signature's calldata and, at `sstore2`, its bytes in the record's blob. Regular within
/// ±500 gas, state exact; a move needs old -> new figures in its commit. At these sizes each row's regular gas is the
/// calldata floor (EIP-7623 / EIP-7976), equal in both modes; `sstore2` adds the encoded signature and one head word to the
/// blob at 1,530 state gas a byte: ML-DSA-65 3,552 B (5,434,560), FN-DSA-512 896 B (1,370,880).
contract PqChatSigGasTest is PqChatBase {
    uint256 internal constant SLACK = 500;
    address internal constant STRANGER_ = address(0x5758);

    PqChat internal none_;
    bytes32[] internal fn; // FN-DSA-512 members, sorted

    function setUp() public override {
        super.setUp();
        none_ = _instanceWith("none", bytes32(0), 0);
        vm.mockCall(address(mock), abi.encodeWithSelector(MockVerifier.verify.selector), abi.encode(true));
        vm.mockCall(address(mock), abi.encodeWithSelector(MockVerifier.verifyPop.selector), abi.encode(true));
        for (uint8 i = 1; i <= 2; ++i) {
            // FN-DSA-512's public-key form: header 0x09, then 512 coefficients of 14 bits below q = 12,289 (bytes 0x11 or
            // 0x22 repeated read as at most 0x2222)
            bytes memory key = new bytes(897);
            key[0] = 0x09;
            for (uint256 j = 1; j < key.length; ++j) {
                key[j] = bytes1(0x11 * i);
            }
            IUARegistry.UAAttrs memory a;
            a.kem = _kem(i + 0x40);
            bytes32 ua = _register(p, UAKinds.FNDSA512, key, a, _pop(p, UAKinds.FNDSA512, key, a), "");
            fn.push(ua);
        }
        if (fn[0] > fn[1]) (fn[0], fn[1]) = (fn[1], fn[0]);
    }

    function _row(string memory what, uint256 regular, uint256 state) internal {
        Vm.Gas memory g = vm.lastCallGas();
        uint256 s = uint256(int256(g.gasStateUsed));
        emit log_named_uint(string.concat("GAS ", what, " regular"), g.gasTotalUsed);
        emit log_named_uint(string.concat("GAS ", what, " state"), s);
        if (regular != 0 && !vm.envOr("GAS_MEASURE", false)) {
            assertApproxEqAbs(g.gasTotalUsed, regular, SLACK, string.concat(what, " regular"));
            assertEq(s, state, string.concat(what, " state"));
        }
    }

    /// A signature of `len` bytes (the stand-in verifier accepts it), no key data, no members.
    function _sized(uint256 len, uint8 tag) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = new bytes(len);
        for (uint256 i; i < len; ++i) {
            s.signature[i] = bytes1(uint8(i) ^ tag);
        }
    }

    function _members2(bytes32[] storage who) internal view returns (IPqChat.MemberKey[] memory m) {
        m = new IPqChat.MemberKey[](2);
        (m[0], m[1]) = (IPqChat.MemberKey(who[0], 0, bytes32(0)), IPqChat.MemberKey(who[1], 0, bytes32(0)));
    }

    /// A 2-member session of `who` at `c`, both wraps.
    function _session2(PqChat c, bytes32[] storage who, uint64 nonce)
        internal
        view
        returns (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w)
    {
        (s.creator, s.nonce, s.homeChain, s.homeChatContract) = (who[0], nonce, chainUidA, address(c));
        s.admins = _list(who[0]);
        s.members = _members2(who);
        w = _wraps(s.members, keccak256(abi.encode(keccak256("scaas/pqchat/v1/session"), who[0], nonce)));
        s.wrapHashes = _hashes(w);
        s.sealedInfo = new bytes(400);
    }

    /// createSession, then a plain rekey, 2 members of `who`, signatures of `len` bytes, at `c`.
    function _pair(PqChat c, bytes32[] storage who, uint256 len, string memory tag, uint256[4] memory pins) internal {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session2(c, who, 1);
        vm.prank(STRANGER_);
        bytes32 sid = c.createSession(s, w, _sized(len, 1));
        _row(string.concat("createSession 2 members, both wraps, ", tag), pins[0], pins[1]);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(sid, who[1], 1, 1, sid, s.admins, s.members);
        e.sealedInfo = new bytes(400);
        vm.prank(STRANGER_);
        c.rekey(e, ew, _sized(len, 2));
        _row(string.concat("rekey 2 members, plain, ", tag), pins[2], pins[3]);
    }

    function test_gas_none_mldsa65() public {
        _pair(none_, ids, 3_309, "none, ML-DSA-65", [uint256(560_024), 8_278_830, 562_072, 8_327_790]);
    }

    function test_gas_sstore2_mldsa65() public {
        _pair(chat, ids, 3_309, "sstore2, ML-DSA-65", [uint256(560_024), 13_713_390, 562_072, 13_762_350]);
    }

    function test_gas_none_fndsa512() public {
        _pair(none_, fn, 666, "none, FN-DSA-512", [uint256(390_040), 8_278_830, 392_088, 8_327_790]);
    }

    function test_gas_sstore2_fndsa512() public {
        _pair(chat, fn, 666, "sstore2, FN-DSA-512", [uint256(390_040), 9_649_710, 392_088, 9_698_670]);
    }

    /// leave, remove and postMessage, ML-DSA-65-sized signatures, at `c`: a 3-member session, a removal, a message, a leave.
    function _rest(PqChat c, string memory tag, uint256[6] memory pins) internal {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 1, address(c));
        bytes32 sid = c.createSession(s, w, _sized(3_309, 1));
        IPqChat.PqChatRemove memory r = IPqChat.PqChatRemove(sid, sid, 1, _list(ids[2]), ids[0], 7);
        vm.prank(STRANGER_);
        c.remove(r, _sized(3_309, 3));
        _row(string.concat("remove 1 of 3 members, ", tag), pins[0], pins[1]);
        IPqChat.PqChatMessage memory m;
        (m.sessionId, m.epochId, m.sender, m.device, m.counter) = (sid, sid, ids[1], bytes16(uint128(5)), 0);
        m.ciphertext = new bytes(1040);
        vm.prank(STRANGER_);
        c.postMessage(m, _sized(3_309, 4));
        _row(string.concat("postMessage 1,040 B ciphertext, ", tag), pins[2], pins[3]);
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, sid, ids[1], 9);
        vm.prank(STRANGER_);
        c.leave(l, _sized(3_309, 5));
        _row(string.concat("leave, ", tag), pins[4], pins[5]);
    }

    function test_gas_rest_none() public {
        _rest(none_, "none, ML-DSA-65", [uint256(261_016), 1_067_940, 330_648, 2_634_660, 250_776, 195_840]);
    }

    function test_gas_rest_sstore2() public {
        _rest(chat, "sstore2, ML-DSA-65", [uint256(261_016), 6_502_500, 330_648, 8_069_220, 250_776, 6_257_700]);
    }
}
