// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {UAMetaTxBase} from "../../src/metatx/UAMetaTxBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";

/// A contract that is no token, on the UA path (owner ruling 2026-11-01): one allowlisted op that records its subject.
contract UAOnly is UAMetaTxBase {
    bytes32 public subject;
    address public sender;

    constructor(bytes32 uid, address reg) UAMetaTxBase("SCaaS UAOnly", uid, reg, address(0), false) {}

    function poke() external nonReentrant {
        subject = _ticketSubject();
        sender = _msgSender();
    }

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == this.poke.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 4);
        return super._mtxRule(sel);
    }

    function _uaAllowed(bytes4 sel) internal view override returns (bool) {
        return sel == this.poke.selector;
    }
}

contract UAMetaTxBaseTest is Test {
    uint256 constant PK = 0xA11CE;
    address constant REG = address(0x5CA);
    bytes32 constant UA = keccak256("a derived UA");
    uint32 constant FIX = MetaTxLib.MODE_FEE_FIXED;
    address signer = vm.addr(PK);
    UAOnly c;

    function setUp() public {
        vm.etch(REG, hex"00");
        vm.mockCall(REG, abi.encodeWithSelector(IUARegistry.requireAuthorized.selector), "");
        c = new UAOnly(keccak256("chain"), REG);
    }

    function _m(bytes32 from, uint256 nonce, uint32 mode, uint256 fee)
        internal view returns (MetaTxLib.UAMetaTransaction memory)
    {
        return MetaTxLib.UAMetaTransaction(from, abi.encodeCall(UAOnly.poke, ()), 0, nonce, block.timestamp + 300, mode,
            address(0), fee, address(0));
    }

    function _auth(MetaTxLib.UAMetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, c.uaDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function test_uaBaseRefusesFee() public {
        // a native id at fee 0: the id as the subject, its address as the sender
        MetaTxLib.UAMetaTransaction memory m = _m(MetaTxLib.pad(signer), 0, 0, 0);
        c.uaExecute(m, _auth(m));
        assertEq(c.subject(), MetaTxLib.pad(signer));
        assertEq(c.sender(), signer);
        assertEq(c.uaNonce(m.from, 0), 1);

        // a derived UA: `_msgSender()` is the pool, only `_ticketSubject()` names it
        m = _m(UA, 0, 0, 0);
        c.uaExecute(m, abi.encode(bytes(""), bytes(hex"01")));
        assertEq(c.subject(), UA);
        assertEq(c.sender(), MetaTxLib.UA_POOL);

        // a fee mode with fee 0 charges nothing, so it runs (the owner's relayable rule)
        m = _m(MetaTxLib.pad(signer), 1, FIX, 0);
        c.uaExecute(m, _auth(m));
        assertEq(c.uaNonce(m.from, 0), 2);

        // fee ≠ 0: no ledger to charge, and the whole call reverts
        m = _m(MetaTxLib.pad(signer), 2, FIX, 1);
        bytes memory auth = _auth(m);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxUnknownMode.selector, FIX));
        c.uaExecute(m, auth);
        assertEq(c.uaNonce(m.from, 0), 2);
    }

    function test_uaBaseOffWithoutRegistry() public {
        UAOnly off = new UAOnly(keccak256("chain"), address(0));
        MetaTxLib.UAMetaTransaction memory m = _m(MetaTxLib.pad(signer), 0, 0, 0);
        vm.expectRevert(IUALedger.UALedgerOff.selector);
        off.uaExecute(m, "");
    }

    /// Only the `_uaAllowed` selectors run; `cancelNonce` is on the address allowlist, not this one.
    function test_uaBaseAllowlist() public {
        MetaTxLib.UAMetaTransaction memory m = _m(MetaTxLib.pad(signer), 0, 0, 0);
        m.data = abi.encodeCall(IMetaTx.cancelNonce, (1));
        bytes memory auth = _auth(m);
        vm.expectRevert(abi.encodeWithSelector(IUALedger.MetaTxUnknownOp.selector, IMetaTx.cancelNonce.selector));
        c.uaExecute(m, auth);
    }

    function test_uaBaseBatch() public {
        MetaTxLib.UAMetaTransaction[] memory ms = new MetaTxLib.UAMetaTransaction[](2);
        bytes[] memory auths = new bytes[](2);
        ms[0] = _m(MetaTxLib.pad(signer), 0, 0, 0);
        ms[1] = _m(UA, 0, 0, 0);
        auths[0] = _auth(ms[0]);
        auths[1] = abi.encode(bytes(""), bytes(hex"01"));
        assertTrue(c.uaBatch(ms, auths));
        assertEq(c.subject(), UA);
    }
}
