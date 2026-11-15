// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs, dexArgs} from "../../script/KindModules.sol";

import {Test} from "forge-std/Test.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {regArgs} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// CTR-GOV-28 (owner 2026-11-13, "có thêm."): every direct admin entry of the 12 token kinds and the DEX carries the chain
/// word. On a bare clone of each release (the test plays the factory; the admin and the features written into the governance
/// namespace, as `AdminNames.t.sol` does), per entry: the admin's call made for a sibling with the same chain id (another
/// word) is refused by name, `ChainUidMismatch(own, sibling)`, nothing written; a stranger is refused `NotAdmin` first (the
/// admin before the word); the entry's old selector (no word) has no entry; the same call with the clone's own word is the
/// control. A holder's own `setGrant` of a leaf and a grantor's `revokeRole` of its leaf check the word too, after the
/// caller. A holder's own `renounceRole` (owner 2026-11-13, renounceRole carries the chain word too): a caller without the bit
/// `MissingRole` first, the holder's sibling word refused, the role kept; the own word the control. The PQZ verifier setters of 4, 5, 12, 13 on a bare clone stop at the next check after the word
/// (`PqzVerifyConfigInvalid`: no `OFFCHAIN` configuration), their success with the word is `PqzOffchainEntries.t.sol` /
/// `PqzVerifierFee.t.sol`. UNAUDITED.
contract AdminChainWordTest is Test {
    bytes32 internal constant NS = 0x0a3a361961b35589cdb03530b6f9e23a4db6ca9a0dad5ddf5d7761c7fabc8700;
    bytes32 internal constant UID = bytes32(uint256(0x3A)); // the clones' chain word (`_clone`)
    bytes32 internal constant SIB = bytes32(uint256(0x3B)); // a sibling's, the same chain id
    address internal constant A1 = address(0xA11CE);
    address internal constant STRANGER = address(0x5742A9E5);
    bytes32 internal constant H = bytes32(uint256(0x40001));
    bytes32 internal constant L = bytes32(uint256(0x40002));
    bytes32 internal constant K = bytes32(uint256(0x40003));

    // ------------------------------------------------------------------ fixtures (`AdminNames.t.sol`'s)

    function _clone(address impl) internal returns (address) {
        return EnvKit.clone(impl, EnvKit.env(UID, address(0x5Ca0000000000000000000000000000000000003),
            address(0), false, address(0)));
    }

    function _kind(string memory name, uint8 kind) internal returns (address t) {
        bytes memory core = kind >= 8 ? regArgs() : bytes("");
        t = _clone(vm.deployCode(string.concat(name, ".sol:", name), abi.encode(address(this), kindArgs(kind, address(this), core))));
    }

    function _dex() internal returns (address) {
        return _clone(vm.deployCode("SCaaSDex.sol:SCaaSDex", abi.encode(address(this), dexArgs(address(this)))));
    }

    /// The admin `A1` and the features `bit` written into the governance namespace (`features` +0, `admin` +2).
    function _seat(address t, uint8 bit) internal {
        vm.store(t, NS, bytes32(uint256(1) << bit));
        vm.store(t, bytes32(uint256(NS) + 2), nid(A1));
        assertEq(EnvKit.codeUidOf(t), UID, "the clone's word");
    }

    function _mismatch() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, UID, SIB);
    }

    function _notAdmin(address who) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(who));
    }

    /// `cd` by `from` reverts with exactly `err`.
    function _refused(string memory what, address t, address from, bytes memory cd, bytes memory err) internal {
        vm.prank(from);
        (bool ok, bytes memory ret) = t.call(cd);
        assertFalse(ok, string.concat(what, ": passed"));
        assertEq(ret, err, string.concat(what, ": refused by name"));
    }

    function _ok(string memory what, address t, address from, bytes memory cd) internal {
        vm.prank(from);
        (bool ok, bytes memory ret) = t.call(cd);
        assertTrue(ok, string.concat(what, ": the control"));
        ret;
    }

    /// The entry's old selector (no word) has no entry: an empty revert.
    function _noOld(string memory what, address t, string memory oldSig) internal {
        vm.prank(A1);
        (bool ok, bytes memory ret) = t.call(abi.encodePacked(bytes4(keccak256(bytes(oldSig))), new bytes(32 * 12)));
        assertTrue(!ok && ret.length == 0, string.concat(what, ": the old selector answers"));
    }

    function _open() internal pure returns (IGovernance.GrantTerms memory g) {
        g.max = type(uint128).max;
    }

    // ------------------------------------------------------------------ the governance entries, every kind and the DEX

    function _governance(string memory name, address t, uint8 bit) internal {
        _seat(t, bit);
        IGovernance g = IGovernance(t);
        // grantRole: the admin, then the word
        _refused(string.concat(name, " grantRole stranger"), t, STRANGER,
            abi.encodeCall(g.grantRole, (bit, H, SIB)), _notAdmin(STRANGER));
        _refused(string.concat(name, " grantRole"), t, A1, abi.encodeCall(g.grantRole, (bit, H, SIB)), _mismatch());
        assertFalse(g.hasRole(bit, H), string.concat(name, ": nothing granted"));
        _noOld(string.concat(name, " grantRole"), t, "grantRole(uint8,bytes32)");
        _ok(string.concat(name, " grantRole"), t, A1, abi.encodeCall(g.grantRole, (bit, H, UID)));
        assertTrue(g.hasRole(bit, H), string.concat(name, ": granted with the own word"));
        // setGrant: a stranger NotAdmin first, the admin's word
        _refused(string.concat(name, " setGrant stranger"), t, STRANGER,
            abi.encodeCall(g.setGrant, (bit, L, _open(), SIB)), _notAdmin(STRANGER));
        _refused(string.concat(name, " setGrant"), t, A1, abi.encodeCall(g.setGrant, (bit, L, _open(), SIB)), _mismatch());
        assertFalse(g.hasRole(bit, L), string.concat(name, ": nothing set"));
        _noOld(string.concat(name, " setGrant"), t,
            "setGrant(uint8,bytes32,(uint128,uint128,uint128,uint128,uint32,uint64,uint32,bool,bytes32))");
        _ok(string.concat(name, " setGrant"), t, A1, abi.encodeCall(g.setGrant, (bit, L, _open(), UID)));
        assertTrue(g.hasRole(bit, L), string.concat(name, ": set with the own word"));
        // cancelGrant (no pending: a no-op once the word passes)
        _refused(string.concat(name, " cancelGrant stranger"), t, STRANGER,
            abi.encodeCall(g.cancelGrant, (bit, H, SIB)), _notAdmin(STRANGER));
        _refused(string.concat(name, " cancelGrant"), t, A1, abi.encodeCall(g.cancelGrant, (bit, H, SIB)), _mismatch());
        _noOld(string.concat(name, " cancelGrant"), t, "cancelGrant(uint8,bytes32)");
        _ok(string.concat(name, " cancelGrant"), t, A1, abi.encodeCall(g.cancelGrant, (bit, H, UID)));
        // revokeRole
        _refused(string.concat(name, " revokeRole stranger"), t, STRANGER,
            abi.encodeCall(g.revokeRole, (bit, H, SIB)), _notAdmin(STRANGER));
        _refused(string.concat(name, " revokeRole"), t, A1, abi.encodeCall(g.revokeRole, (bit, H, SIB)), _mismatch());
        assertTrue(g.hasRole(bit, H), string.concat(name, ": nothing revoked"));
        _noOld(string.concat(name, " revokeRole"), t, "revokeRole(uint8,bytes32)");
        _ok(string.concat(name, " revokeRole"), t, A1, abi.encodeCall(g.revokeRole, (bit, H, UID)));
        assertFalse(g.hasRole(bit, H), string.concat(name, ": revoked with the own word"));
        _ok(string.concat(name, " revokeRole"), t, A1, abi.encodeCall(g.revokeRole, (bit, L, UID)));
        // renounceRole: the holder's own; a caller without the bit MissingRole first, then the holder's word
        _ok(string.concat(name, " renounceRole's holder"), t, A1, abi.encodeCall(g.grantRole, (bit, K, UID)));
        address k = address(uint160(uint256(K)));
        _refused(string.concat(name, " renounceRole stranger"), t, STRANGER, abi.encodeCall(g.renounceRole, (bit, SIB)),
            abi.encodeWithSelector(IGovernance.MissingRole.selector, bit, nid(STRANGER)));
        _refused(string.concat(name, " renounceRole"), t, k, abi.encodeCall(g.renounceRole, (bit, SIB)), _mismatch());
        assertTrue(g.hasRole(bit, K), string.concat(name, ": nothing renounced"));
        _noOld(string.concat(name, " renounceRole"), t, "renounceRole(uint8)");
        _ok(string.concat(name, " renounceRole"), t, k, abi.encodeCall(g.renounceRole, (bit, UID)));
        assertFalse(g.hasRole(bit, K), string.concat(name, ": renounced with the own word"));
        // disableFeature, one-way
        _refused(string.concat(name, " disableFeature stranger"), t, STRANGER,
            abi.encodeCall(g.disableFeature, (bit, SIB)), _notAdmin(STRANGER));
        _refused(string.concat(name, " disableFeature"), t, A1, abi.encodeCall(g.disableFeature, (bit, SIB)), _mismatch());
        assertEq(g.features(), uint256(1) << bit, string.concat(name, ": the feature stays"));
        _noOld(string.concat(name, " disableFeature"), t, "disableFeature(uint8)");
        _ok(string.concat(name, " disableFeature"), t, A1, abi.encodeCall(g.disableFeature, (bit, UID)));
        assertEq(g.features(), 0, string.concat(name, ": disabled with the own word"));
    }

    /// A holder's leaf and its grantor's revoke (the "another caller" path): the caller's own checks, then the word.
    function _holderPath(string memory name, address t, uint8 bit) internal {
        _seat(t, bit);
        IGovernance g = IGovernance(t);
        IGovernance.GrantTerms memory d = _open();
        (d.total, d.delegable) = (1000, true);
        _ok(string.concat(name, " a delegable root"), t, A1, abi.encodeCall(g.setGrant, (bit, H, d, UID)));
        IGovernance.GrantTerms memory leaf = _open();
        leaf.total = 10;
        address h = address(uint160(uint256(H)));
        _refused(string.concat(name, " a holder's leaf"), t, h, abi.encodeCall(g.setGrant, (bit, L, leaf, SIB)), _mismatch());
        assertFalse(g.hasRole(bit, L), string.concat(name, ": no leaf"));
        _ok(string.concat(name, " a holder's leaf"), t, h, abi.encodeCall(g.setGrant, (bit, L, leaf, UID)));
        assertTrue(g.hasRole(bit, L), string.concat(name, ": the leaf with the own word"));
        _refused(string.concat(name, " a grantor's revoke"), t, h, abi.encodeCall(g.revokeRole, (bit, L, SIB)), _mismatch());
        assertTrue(g.hasRole(bit, L), string.concat(name, ": the leaf stays"));
        _ok(string.concat(name, " a grantor's revoke"), t, h, abi.encodeCall(g.revokeRole, (bit, L, UID)));
        assertFalse(g.hasRole(bit, L), string.concat(name, ": revoked by its grantor with the own word"));
    }

    /// Kinds 8-13: `enableFeature` of the deny list (valid on every regulated kind), one-way; its holder first (Fable P1-1).
    function _enable(string memory name, address t) internal {
        _seat(t, GovernanceBits.MINTABLE);
        uint8 bit = GovernanceBits.DENYLIST;
        _ok(string.concat(name, " the list's holder"), t, A1, abi.encodeCall(IGovernance.grantRole, (bit, H, UID)));
        _refused(string.concat(name, " enableFeature stranger"), t, STRANGER,
            abi.encodeCall(IRegulatedToken.enableFeature, (bit, SIB)), _notAdmin(STRANGER));
        _refused(string.concat(name, " enableFeature"), t, A1, abi.encodeCall(IRegulatedToken.enableFeature, (bit, SIB)),
            _mismatch());
        assertEq(IGovernance(t).features() & (uint256(1) << bit), 0, string.concat(name, ": still off"));
        _noOld(string.concat(name, " enableFeature"), t, "enableFeature(uint8)");
        _ok(string.concat(name, " enableFeature"), t, A1, abi.encodeCall(IRegulatedToken.enableFeature, (bit, UID)));
        assertTrue(IGovernance(t).features() & (uint256(1) << bit) != 0, string.concat(name, ": on with the own word"));
    }

    /// Kinds 4, 5, 12, 13: the verifier setters. A bare clone has no `OFFCHAIN` configuration, so the own word reaches the
    /// next check (`PqzVerifyConfigInvalid`); the sibling's stops at the word.
    function _pqz(string memory name, address t) internal {
        _seat(t, GovernanceBits.MINTABLE);
        bytes memory invalid = abi.encodeWithSelector(IPqzToken.PqzVerifyConfigInvalid.selector);
        bytes32 v = bytes32(uint256(0xFE));
        bytes[4] memory sib = [abi.encodeCall(IPqzToken.pqzSetVerifier, (v, SIB)),
            abi.encodeCall(IPqzToken.pqzCancelVerifier, (SIB)), abi.encodeCall(IPqzToken.pqzRevokeVerifier, (SIB)),
            abi.encodeCall(IPqzToken.setVerifierFee, (1, SIB))];
        bytes[4] memory own = [abi.encodeCall(IPqzToken.pqzSetVerifier, (v, UID)),
            abi.encodeCall(IPqzToken.pqzCancelVerifier, (UID)), abi.encodeCall(IPqzToken.pqzRevokeVerifier, (UID)),
            abi.encodeCall(IPqzToken.setVerifierFee, (1, UID))];
        string[4] memory old = ["pqzSetVerifier(bytes32)", "pqzCancelVerifier()", "pqzRevokeVerifier()", "setVerifierFee(uint64)"];
        for (uint256 i; i < 4; ++i) {
            string memory w = string.concat(name, " ", old[i]);
            _refused(string.concat(w, " stranger"), t, STRANGER, sib[i], _notAdmin(STRANGER));
            _refused(w, t, A1, sib[i], _mismatch());
            _refused(string.concat(w, " own word"), t, A1, own[i], invalid);
            _noOld(w, t, old[i]);
        }
    }

    function _token(string memory name, uint8 kind) internal {
        uint256 s = vm.snapshotState();
        _governance(name, _kind(name, kind), GovernanceBits.MINTABLE);
        vm.revertToState(s);
        _holderPath(name, _kind(name, kind), GovernanceBits.MINTABLE);
        vm.revertToState(s);
        if (kind >= 8) {
            _enable(name, _kind(name, kind));
            vm.revertToState(s);
        }
        if (kind == 4 || kind == 5 || kind == 12 || kind == 13) _pqz(name, _kind(name, kind));
    }

    function test_kind0_NormalToken() public { _token("NormalToken", 0); }

    function test_kind1_WrappedToken() public { _token("WrappedToken", 1); }

    function test_kind2_NormalZetherToken() public { _token("NormalZetherToken", 2); }

    function test_kind3_WrappedZetherToken() public { _token("WrappedZetherToken", 3); }

    function test_kind4_NormalPqzToken() public { _token("NormalPqzToken", 4); }

    function test_kind5_WrappedPqzToken() public { _token("WrappedPqzToken", 5); }

    function test_kind8_NormalRegulatedToken() public { _token("NormalRegulatedToken", 8); }

    function test_kind9_WrappedRegulatedToken() public { _token("WrappedRegulatedToken", 9); }

    function test_kind10_NormalZetherRegulatedToken() public { _token("NormalZetherRegulatedToken", 10); }

    function test_kind11_WrappedZetherRegulatedToken() public { _token("WrappedZetherRegulatedToken", 11); }

    function test_kind12_NormalPqzRegulatedToken() public { _token("NormalPqzRegulatedToken", 12); }

    function test_kind13_WrappedPqzRegulatedToken() public { _token("WrappedPqzRegulatedToken", 13); }

    /// A proposer's own `cancelGrant` (not the admin): kind 8 with a `grantDelay`, `H` a whole holder of `FREEZE` (5, a
    /// delayed relaxation on 8-13) whose `renounceRole(5)` proposes; its cancel with a sibling's word is refused after its
    /// own check (the proposer), the pending kept; with the own word the pending goes.
    function test_proposerCancel() public {
        address t = _kind("NormalRegulatedToken", 8);
        uint8 bit = GovernanceBits.FREEZE;
        _seat(t, bit);
        vm.store(t, bytes32(uint256(NS) + 4), bytes32(uint256(1 hours))); // grantDelay (+4, the low 64 bits)
        bytes32 inner = keccak256(abi.encode(uint256(bit), uint256(NS) + 5)); // roles[bit] (+5)
        vm.store(t, keccak256(abi.encode(H, inner)), bytes32(uint256(1))); // WHOLE
        IGovernance g = IGovernance(t);
        assertTrue(g.hasRole(bit, H), "the holder");
        address h = address(uint160(uint256(H)));
        _refused("renounceRole, a sibling's word", t, h, abi.encodeCall(g.renounceRole, (bit, SIB)), _mismatch());
        (uint64 eta0,,,) = g.pendingGrant(bit, H);
        assertEq(eta0, 0, "nothing proposed");
        _ok("renounceRole proposes", t, h, abi.encodeCall(g.renounceRole, (bit, UID)));
        (uint64 eta, bytes32 proposer,,) = g.pendingGrant(bit, H);
        assertTrue(eta != 0 && proposer == H, "proposed by the holder");
        _refused("a stranger's cancel", t, STRANGER, abi.encodeCall(g.cancelGrant, (bit, H, SIB)), _notAdmin(STRANGER));
        _refused("the proposer's cancel", t, h, abi.encodeCall(g.cancelGrant, (bit, H, SIB)), _mismatch());
        (eta,,,) = g.pendingGrant(bit, H);
        assertTrue(eta != 0, "the pending stays");
        _ok("the proposer's cancel", t, h, abi.encodeCall(g.cancelGrant, (bit, H, UID)));
        (eta,,,) = g.pendingGrant(bit, H);
        assertEq(eta, 0, "cancelled with the own word");
    }

    /// The DEX's governance module behind its stubs: `LISTING` (bit 11), a role with no scalar.
    function test_dex_SCaaSDex() public {
        _governance("SCaaSDex", _dex(), GovernanceBits.LISTING);
    }
}
