// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs, dexArgs} from "../../script/KindModules.sol";

import {Test, Vm} from "forge-std/Test.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {regArgs} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// Round 3zb + 3zc (spec 2026-11-13-burner-wrap-caps.md §3.9, §3.10, §6 "O6"; CTR-GOV-28 Change, owner 2026-11-13 "(2), gộp
/// vào round 3zb + 3zc."): every direct entry of a role holder carries the chain word, the 24 of §3.9 on every kind that has
/// them and the DEX. On a bare clone of each release (the test plays the factory; features and holders written into the
/// governance namespace, as `AdminChainWord.t.sol`), per entry:
/// - a stranger is refused exactly as before, whatever word it passes (the caller's check is first; the word changes no
///   existing refusal);
/// - a `WHOLE` holder with a sibling's word: `ChainUidMismatch(own, sibling)`;
/// - a `LIMITED` holder whose grant has expired, with a sibling's word: `ChainUidMismatch` (the word before the grant is
///   read: kills "word after the library call"); with the own word: past the word (the grant's refusal or the entry's own);
/// - the holder with the own word passes the word (the control; on a bare clone some entries stop at their next check,
///   their acting control is the kind's own suite and `GovRouter.t.sol`'s rows);
/// - the entry's old selector (no word) has no entry.
/// The DEX's four entries run in `SCaaSDexGovernanceModule` (O8, §3.10): they act on the DEX's address and emit from it; a
/// direct call on a module is refused. UNAUDITED.
contract HolderChainWordTest is Test {
    bytes32 internal constant NS = 0x0a3a361961b35589cdb03530b6f9e23a4db6ca9a0dad5ddf5d7761c7fabc8700;
    bytes32 internal constant UID = bytes32(uint256(0x3A)); // the clones' chain word
    bytes32 internal constant SIB = bytes32(uint256(0x3B)); // a sibling's, the same chain id
    address internal constant A1 = address(0xA11CE); // the admin
    address internal constant STRANGER = address(0x5742A9E5);
    address internal constant HOLDER = address(0x40001); // given code: some bits are contract only
    address internal constant LIM = address(0x40002);
    uint8 internal constant WHOLE = 1;

    /// The test plays the factory: no token of it is registered (`SCaaSDexCore._scaas`).
    function versionOf(address) external pure returns (uint8, uint64) {
        return (0, 0);
    }

    struct Entry {
        string sig; // the entry with the word
        string old; // the entry before (no word)
        uint8 bit;
    }

    // ------------------------------------------------------------------ fixtures

    function _clone(address impl) internal returns (address) {
        return EnvKit.clone(
            impl, EnvKit.env(UID, address(0x5Ca0000000000000000000000000000000000003), address(0), false, address(0))
        );
    }

    function _kind(string memory name, uint8 kind) internal returns (address t) {
        bytes memory core = kind >= 8 ? regArgs() : bytes("");
        t = _clone(
            vm.deployCode(
                string.concat(name, ".sol:", name), abi.encode(address(this), kindArgs(kind, address(this), core))
            )
        );
    }

    function _dex() internal returns (address) {
        return _clone(vm.deployCode("SCaaSDex.sol:SCaaSDex", abi.encode(address(this), dexArgs(address(this)))));
    }

    /// The feature `bit`, the admin `A1`, `HOLDER` a WHOLE holder of `bit` (roles[bit] at +5), both holders with code.
    function _seat(address t, uint8 bit) internal {
        vm.store(t, NS, bytes32(uint256(1) << bit));
        vm.store(t, bytes32(uint256(NS) + 2), nid(A1));
        bytes32 inner = keccak256(abi.encode(uint256(bit), uint256(NS) + 5));
        vm.store(t, keccak256(abi.encode(nid(HOLDER), inner)), bytes32(uint256(WHOLE)));
        vm.etch(HOLDER, hex"00");
        vm.etch(LIM, hex"00");
        assertTrue(IGovernance(t).hasRole(bit, nid(HOLDER)), "the seat");
        assertEq(EnvKit.codeUidOf(t), UID, "the clone's word");
    }

    function _mismatch() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, UID, SIB);
    }

    function _call(address t, address from, bytes memory cd) internal returns (bool ok, bytes memory ret) {
        vm.prank(from);
        (ok, ret) = t.call(cd);
    }

    /// The calldata of entry `e` with `word`: static parameters, or the list entries' dynamic array.
    function _cd(Entry memory e, bytes32 word) internal view returns (bytes memory) {
        bytes4 sel = bytes4(keccak256(bytes(e.sig)));
        bytes32 k = keccak256(bytes(e.sig));
        if (k == keccak256("setAllowed(bytes32[],bool,bytes32)") || k == keccak256("setDenied(bytes32[],bool,bytes32)"))
        {
            bytes32[] memory a = new bytes32[](1);
            a[0] = bytes32(uint256(0xACC));
            return abi.encodeWithSelector(sel, a, true, word);
        }
        if (k == keccak256("mint(address,uint256,bytes32)")) {
            return abi.encodeWithSelector(sel, address(0xD0), uint256(1), word);
        }
        if (k == keccak256("mintToUA(bytes32,uint256,bytes32)")) {
            return abi.encodeWithSelector(sel, bytes32(uint256(0xD1)), uint256(1), word);
        }
        if (k == keccak256("disableWrap(address,bytes32,bytes32)")) {
            return abi.encodeWithSelector(sel, address(0xD2), bytes32("r"), word);
        }
        if (k == keccak256("proposeRate(address,uint96,uint96,bytes32)")) {
            return abi.encodeWithSelector(sel, address(0xD2), uint96(101), uint96(100), word);
        }
        if (k == keccak256("cancelRate(bytes32)") || k == keccak256("executeRate(bytes32)")) {
            return abi.encodeWithSelector(sel, word);
        }
        if (k == keccak256("setWrapMember(bytes32,bool,bool,bytes32)")) {
            return abi.encodeWithSelector(sel, bytes32(uint256(0xACC)), true, true, word);
        }
        if (k == keccak256("freeze(bytes32,bytes32,bytes32,bytes32)")) {
            return abi.encodeWithSelector(sel, bytes32(uint256(0xACC)), bytes32("ref"), bytes32(0), word);
        }
        if (k == keccak256("unfreeze(bytes32,bytes32,bytes32)")) {
            return abi.encodeWithSelector(sel, bytes32(uint256(0xACC)), bytes32("ref"), word);
        }
        if (k == keccak256("forceTransfer(bytes32,uint256,bytes32)")) {
            return abi.encodeWithSelector(sel, bytes32("rid"), uint256(1), word);
        }
        if (k == keccak256("pause(bytes32,uint64,bytes32)")) {
            return abi.encodeWithSelector(sel, bytes32("ref"), uint64(block.timestamp + 1 days), word);
        }
        if (k == keccak256("unpause(bytes32,bytes32)")) return abi.encodeWithSelector(sel, bytes32("ref"), word);
        if (k == keccak256("recordOrder(bytes32,bytes32,bytes32,bytes32,uint256,uint64,bytes32)")) {
            return abi.encodeWithSelector(
                sel,
                bytes32("o"),
                bytes32("d"),
                bytes32(uint256(0xACC)),
                bytes32(uint256(0xBE)),
                uint256(1),
                uint64(0),
                word
            );
        }
        if (k == keccak256("revokeOrder(bytes32,bytes32,bytes32)")) {
            return abi.encodeWithSelector(sel, bytes32("rid"), bytes32("why"), word);
        }
        if (k == keccak256("operatorTransfer(bytes32,bytes32,uint256,bytes32,bytes32)")) {
            return abi.encodeWithSelector(
                sel, bytes32(uint256(0xACC)), bytes32(uint256(0xBE)), uint256(1), bytes32("ref"), word
            );
        }
        if (k == keccak256("setTaxRate(uint32,bytes32)")) return abi.encodeWithSelector(sel, uint32(7), word);
        if (k == keccak256("setTaxRecipient(bytes32,bytes32)")) {
            return abi.encodeWithSelector(sel, bytes32(uint256(0x7A1)), word);
        }
        if (k == keccak256("setProofStore(uint8,bytes32)")) return abi.encodeWithSelector(sel, uint8(1), word);
        if (k == keccak256("setMarket(address,address,bool,bytes32)")) {
            return abi.encodeWithSelector(sel, address(0xBA5E), address(0x0907E), true, word);
        }
        if (k == keccak256("setExchangeTarget(address,bool,bytes32)")) {
            return abi.encodeWithSelector(sel, address(0xE7), true, word);
        }
        if (k == keccak256("setListedOnly(bool,bytes32)")) return abi.encodeWithSelector(sel, true, word);
        if (k == keccak256("setFeeSplit(uint32,address,bytes32)")) {
            return abi.encodeWithSelector(sel, uint32(500_000), address(0x7EA5), word);
        }
        revert(string.concat("no calldata for ", e.sig));
    }

    /// One entry on one fresh clone (`t` seated for `e.bit`).
    function _entry(string memory name, address t, Entry memory e) internal {
        string memory w = string.concat(name, " ", e.sig);
        _seat(t, e.bit);
        // a stranger: the same refusal whatever the word, never the word's
        (bool ok1, bytes memory r1) = _call(t, STRANGER, _cd(e, SIB));
        (bool ok2, bytes memory r2) = _call(t, STRANGER, _cd(e, UID));
        assertTrue(!ok1 && !ok2, string.concat(w, ": a stranger passed"));
        assertEq(r1, r2, string.concat(w, ": the stranger's refusal depends on the word"));
        assertTrue(keccak256(r1) != keccak256(_mismatch()), string.concat(w, ": a stranger reached the word"));
        // a WHOLE holder: the sibling's word refused by name, the own word passes it
        (bool ok, bytes memory ret) = _call(t, HOLDER, _cd(e, SIB));
        assertFalse(ok, string.concat(w, ": a sibling's word passed"));
        assertEq(ret, _mismatch(), string.concat(w, ": the holder's word, by name"));
        (ok, ret) = _call(t, HOLDER, _cd(e, UID));
        assertTrue(ok || bytes4(ret) != IAdmin.ChainUidMismatch.selector, string.concat(w, ": the own word refused"));
        // the old selector (no word) has no entry
        (ok, ret) = _call(t, HOLDER, abi.encodePacked(bytes4(keccak256(bytes(e.old))), new bytes(32 * 8)));
        assertTrue(!ok && ret.length == 0, string.concat(w, ": the old selector answers"));
    }

    /// A LIMITED holder whose grant has expired: the word is read before the grant (`_holderOnChain` first).
    function _limited(string memory name, address t, Entry memory e) internal {
        string memory w = string.concat(name, " ", e.sig, " limited");
        _seat(t, e.bit);
        IGovernance.GrantTerms memory g;
        g.validUntil = uint64(block.timestamp + 1);
        g.max = type(uint128).max; // a non-scalar bit takes only an open max (`GrantWordRefused(bit, 1)`)
        vm.prank(A1);
        IGovernance(t).setGrant(e.bit, nid(LIM), g, UID);
        vm.warp(block.timestamp + 2);
        (bool ok, bytes memory ret) = _call(t, LIM, _cd(e, SIB));
        assertFalse(ok, w);
        assertEq(ret, _mismatch(), string.concat(w, ": the word before the grant"));
        (ok, ret) = _call(t, LIM, _cd(e, UID));
        assertTrue(!ok && bytes4(ret) != IAdmin.ChainUidMismatch.selector, string.concat(w, ": past the word"));
        vm.warp(block.timestamp - 2);
    }

    function _entries() internal pure returns (Entry[] memory es) {
        es = new Entry[](24);
        es[0] = Entry("mint(address,uint256,bytes32)", "mint(address,uint256)", GovernanceBits.MINTABLE);
        es[1] = Entry("mintToUA(bytes32,uint256,bytes32)", "mintToUA(bytes32,uint256)", GovernanceBits.MINTABLE);
        es[2] = Entry(
            "disableWrap(address,bytes32,bytes32)", "disableWrap(address,bytes32)", GovernanceBits.WRAP_DISABLEABLE
        );
        es[3] = Entry(
            "proposeRate(address,uint96,uint96,bytes32)",
            "proposeRate(address,uint96,uint96)",
            GovernanceBits.RATE_ADJUSTABLE
        );
        es[4] = Entry("cancelRate(bytes32)", "cancelRate()", GovernanceBits.RATE_ADJUSTABLE);
        es[5] = Entry("executeRate(bytes32)", "executeRate()", GovernanceBits.RATE_ADJUSTABLE);
        es[6] = Entry(
            "setWrapMember(bytes32,bool,bool,bytes32)", "setWrapMember(bytes32,bool,bool)", GovernanceBits.WRAP_LIST
        );
        es[7] = Entry("setAllowed(bytes32[],bool,bytes32)", "setAllowed(bytes32[],bool)", GovernanceBits.ALLOWLIST);
        es[8] = Entry("setDenied(bytes32[],bool,bytes32)", "setDenied(bytes32[],bool)", GovernanceBits.DENYLIST);
        es[9] =
            Entry("freeze(bytes32,bytes32,bytes32,bytes32)", "freeze(bytes32,bytes32,bytes32)", GovernanceBits.FREEZE);
        es[10] = Entry("unfreeze(bytes32,bytes32,bytes32)", "unfreeze(bytes32,bytes32)", GovernanceBits.FREEZE);
        es[11] = Entry("forceTransfer(bytes32,uint256,bytes32)", "forceTransfer(bytes32,uint256)", GovernanceBits.FORCE);
        es[12] = Entry("pause(bytes32,uint64,bytes32)", "pause(bytes32,uint64)", GovernanceBits.PAUSE);
        es[13] = Entry("unpause(bytes32,bytes32)", "unpause(bytes32)", GovernanceBits.PAUSE);
        es[14] = Entry(
            "recordOrder(bytes32,bytes32,bytes32,bytes32,uint256,uint64,bytes32)",
            "recordOrder(bytes32,bytes32,bytes32,bytes32,uint256,uint64)",
            GovernanceBits.RECORD
        );
        es[15] = Entry("revokeOrder(bytes32,bytes32,bytes32)", "revokeOrder(bytes32,bytes32)", GovernanceBits.RECORD);
        es[16] = Entry(
            "operatorTransfer(bytes32,bytes32,uint256,bytes32,bytes32)",
            "operatorTransfer(bytes32,bytes32,uint256,bytes32)",
            GovernanceBits.OPERATOR_TRANSFER
        );
        es[17] = Entry("setTaxRate(uint32,bytes32)", "setTaxRate(uint32)", GovernanceBits.TAX);
        es[18] = Entry("setTaxRecipient(bytes32,bytes32)", "setTaxRecipient(bytes32)", GovernanceBits.TAX);
        es[19] = Entry("setProofStore(uint8,bytes32)", "setProofStore(uint8)", GovernanceBits.PQZ_PROOF);
        es[20] =
            Entry("setMarket(address,address,bool,bytes32)", "setMarket(address,address,bool)", GovernanceBits.LISTING);
        es[21] =
            Entry("setExchangeTarget(address,bool,bytes32)", "setExchangeTarget(address,bool)", GovernanceBits.LISTING);
        es[22] = Entry("setListedOnly(bool,bytes32)", "setListedOnly(bool)", GovernanceBits.LISTING);
        es[23] = Entry("setFeeSplit(uint32,address,bytes32)", "setFeeSplit(uint32,address)", GovernanceBits.FEE_ROUTING);
    }

    /// Whether kind `k` has entry `i` (§3.9's table): 0-1 every kind, 2-6 wrapped, 7-18 regulated, 19 PQZ, 20-23 the DEX
    /// (`k == 255`).
    function _has(uint8 k, uint256 i) internal pure returns (bool) {
        if (k == 255) return i >= 20;
        if (i <= 1) return true;
        bool wrapped = k % 2 == 1;
        if (i <= 6) return wrapped;
        if (i <= 18) return k >= 8; // `setAllowed` on 10-13 too: the entry exists; its bit is outside their mask (CTR-GOV-17)
        if (i == 19) return k == 4 || k == 5 || k == 12 || k == 13;
        return false;
    }

    /// Spec §3.9: mint / mintToUA on every kind, + 5 on the wrapped kinds, + 12 on the regulated, + setProofStore on the PQZ
    /// kinds; the DEX's 4.
    function _count(uint8 k) internal pure returns (uint256 c) {
        if (k == 255) return 4;
        c = 2;
        if (k % 2 == 1) c += 5;
        if (k >= 8) c += 12;
        if (k == 4 || k == 5 || k == 12 || k == 13) c += 1;
    }

    function _token(string memory name, uint8 kind) internal {
        Entry[] memory es = _entries();
        uint256 n;
        for (uint256 i; i < es.length; ++i) {
            if (!_has(kind, i)) continue;
            uint256 s = vm.snapshotState();
            _entry(name, kind == 255 ? _dex() : _kind(name, kind), es[i]);
            vm.revertToState(s);
            // no limited grant of `ALLOWLIST` where the bit is outside the kind's mask (10-13: `NoSuchRole(8)`)
            if (!(i == 7 && kind >= 10)) _limited(name, kind == 255 ? _dex() : _kind(name, kind), es[i]);
            vm.revertToState(s);
            ++n;
        }
        assertEq(n, _count(kind), "entries walked (spec 3.9 table)");
    }

    function test_kind0_NormalToken() public {
        _token("NormalToken", 0);
    }

    function test_kind1_WrappedToken() public {
        _token("WrappedToken", 1);
    }

    function test_kind2_NormalZetherToken() public {
        _token("NormalZetherToken", 2);
    }

    function test_kind3_WrappedZetherToken() public {
        _token("WrappedZetherToken", 3);
    }

    function test_kind4_NormalPqzToken() public {
        _token("NormalPqzToken", 4);
    }

    function test_kind5_WrappedPqzToken() public {
        _token("WrappedPqzToken", 5);
    }

    function test_kind8_NormalRegulatedToken() public {
        _token("NormalRegulatedToken", 8);
    }

    function test_kind9_WrappedRegulatedToken() public {
        _token("WrappedRegulatedToken", 9);
    }

    function test_kind10_NormalZetherRegulatedToken() public {
        _token("NormalZetherRegulatedToken", 10);
    }

    function test_kind11_WrappedZetherRegulatedToken() public {
        _token("WrappedZetherRegulatedToken", 11);
    }

    function test_kind12_NormalPqzRegulatedToken() public {
        _token("NormalPqzRegulatedToken", 12);
    }

    function test_kind13_WrappedPqzRegulatedToken() public {
        _token("WrappedPqzRegulatedToken", 13);
    }

    function test_dex_SCaaSDex() public {
        _token("SCaaSDex", 255);
    }

    /// The acting control on kind 0: the holder's `mint` with the own word mints.
    function test_kind0_mintActs() public {
        address t = _kind("NormalToken", 0);
        _seat(t, GovernanceBits.MINTABLE);
        vm.prank(HOLDER);
        (bool ok,) = t.call(abi.encodeWithSignature("mint(address,uint256,bytes32)", address(0xD0), uint256(7), UID));
        assertTrue(ok);
        (, bytes memory b) = t.staticcall(abi.encodeWithSignature("balanceOf(address)", address(0xD0)));
        assertEq(abi.decode(b, (uint256)), 7);
    }

    /// Acting controls on bare clones (Fable F-6): with the own word, the holder's `setWrapMember` (kind 1) and `pause`
    /// (kind 8) act.
    function test_actingControls() public {
        address t = _kind("WrappedToken", 1);
        _seat(t, GovernanceBits.WRAP_LIST);
        vm.prank(HOLDER);
        (bool ok, bytes memory ret) = t.call(
            abi.encodeWithSignature(
                "setWrapMember(bytes32,bool,bool,bytes32)", bytes32(uint256(0xACC)), true, true, UID
            )
        );
        assertTrue(ok, string(ret));
        address r = _kind("NormalRegulatedToken", 8);
        _seat(r, GovernanceBits.PAUSE);
        vm.prank(HOLDER);
        (ok, ret) = r.call(
            abi.encodeWithSignature(
                "pause(bytes32,uint64,bytes32)", bytes32("ref"), uint64(block.timestamp + 1 days), UID
            )
        );
        assertTrue(ok, string(ret));
    }

    // ------------------------------------------------------------------ the DEX's four entries in its module (O8, §3.10)

    /// Each acts on the DEX's address, its event emitted from it; a direct call on either module is refused.
    function test_dexEntriesActInTheDexsFrame() public {
        address d = _dex();
        _seat(d, GovernanceBits.LISTING);
        vm.recordLogs();
        vm.prank(HOLDER);
        ISCaaSDex(d).setListedOnly(true, UID);
        assertTrue(SCaaSDex(payable(d)).listedOnly(), "the DEX's state");
        Vm.Log[] memory ls = vm.getRecordedLogs();
        assertEq(ls.length, 1);
        assertEq(ls[0].emitter, d, "emitted from the DEX's address");
        assertEq(ls[0].topics[0], ISCaaSDex.ListedOnlySet.selector);
        vm.prank(HOLDER);
        ISCaaSDex(d).setExchangeTarget(address(0xE7), true, UID);
        assertTrue(SCaaSDex(payable(d)).exchangeTarget(address(0xE7)));
        vm.prank(HOLDER);
        ISCaaSDex(d).setMarket(address(0xBA5E), address(0x0907E), true, UID);
        assertTrue(SCaaSDex(payable(d)).marketListed(address(0xBA5E), address(0x0907E)));
        address[] memory ms = SCaaSDex(payable(d)).modules();
        // the governance module (ms[0]) refuses a direct call of each of the four by name before its body runs
        // (`onlyDelegated`); the liquidity module has no such entry
        bytes[4] memory direct = [
            abi.encodeWithSignature("setListedOnly(bool,bytes32)", false, UID),
            abi.encodeWithSignature(
                "setMarket(address,address,bool,bytes32)", address(0xBA5E), address(0x0907E), false, UID
            ),
            abi.encodeWithSignature("setExchangeTarget(address,bool,bytes32)", address(0xE7), false, UID),
            abi.encodeWithSignature("setFeeSplit(uint32,address,bytes32)", uint32(2), address(0x7EA5), UID)
        ];
        for (uint256 i; i < 4; ++i) {
            vm.prank(HOLDER);
            (bool ok0, bytes memory r0) = ms[0].call(direct[i]);
            assertFalse(ok0, "the governance module called directly");
            assertEq(r0, abi.encodeWithSignature("NotDelegated()"), "NotDelegated, before the body");
        }
        vm.prank(HOLDER);
        (bool ok1,) = ms[1].call(abi.encodeWithSignature("setListedOnly(bool,bytes32)", false, UID));
        assertFalse(ok1, "the liquidity module called directly");
        assertTrue(SCaaSDex(payable(d)).listedOnly(), "unchanged");
    }

    /// `setFeeSplit` refuses `treasury == this` (the DEX under DELEGATECALL), accepts the module's address (not `this`).
    function test_dexFeeSplitThisIsTheDex() public {
        address d = _dex();
        _seat(d, GovernanceBits.FEE_ROUTING);
        vm.prank(HOLDER);
        (bool ok, bytes memory ret) =
            d.call(abi.encodeWithSignature("setFeeSplit(uint32,address,bytes32)", uint32(1), d, UID));
        assertFalse(ok);
        assertEq(bytes4(ret), ISCaaSDex.FeeSplitInvalid.selector, "treasury = the DEX refused");
        address[] memory ms = SCaaSDex(payable(d)).modules();
        vm.prank(HOLDER);
        ISCaaSDex(d).setFeeSplit(1, ms[0], UID);
        assertEq(SCaaSDex(payable(d)).relayerSharePpm(), 1);
    }
}
