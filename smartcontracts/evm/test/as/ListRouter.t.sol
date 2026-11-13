// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ListFixture, IListOps} from "./helpers/ListFixture.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {StubUARegistry} from "../helpers/Mocks.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";

/// Round 3s, spec 2026-11-10-token-lists.md §5.3, §6.2, §13 (3), (6): `mtxSetAllowed`, `mtxSetDenied`, `mtxEnableFeature` on
/// the chain's `GovernanceRouter`, fee mode `NONE` at fee 0, sent by a stranger relayer; the binding matrix (B1-B3): each
/// signed word changed alone (`target`, one element of `accounts`, its length, its order, `on`; `bit`) is refused with the
/// untouched call's signature and spends no nonce; the untouched call then passes and has its effect (the positive
/// control). Called by selector so the suite compiles before the build.
contract ListRouterTest is ListFixture {
    string constant TAIL =
        ",uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string constant ENV = "(bytes32,uint256,uint256,uint256,uint32,address,uint256,address)";
    string constant SIG = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";
    uint256 constant SIGNER_PK = 0x5161;
    address constant STRANGER = address(0x5757);
    GovernanceRouter router;
    address signer = vm.addr(SIGNER_PK);
    bytes32 s;
    address t;
    address other;

    function _router() internal override returns (address) {
        ureg = new StubUARegistry(UID);
        router = new GovernanceRouter(UID, address(ureg), address(0), false);
        return address(router);
    }

    function setUp() public override {
        super.setUp();
        s = nid(signer);
        t = _signerToken("a");
        other = _signerToken("b");
    }

    /// Kind 8, `signer` its admin and its issuer seat (8 and 9: any holder), no control of 5-7.
    function _signerToken(bytes32 salt) internal returns (address x) {
        IFactoryToken.TokenConfig memory c = _cfg8();
        c.features &= ~REG_FEATURES;
        (c.admin, c.roles.issuer, c.roles.compliance, c.grantDelay) = (s, s, 0, 0);
        x = _create(0, c, salt);
    }

    function _domain() internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) =
            router.eip712Domain();
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying, salt));
    }

    function _env() internal view returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(s, 0, router.mtxNonce(s, 0), block.timestamp + 1 hours, 0, address(0), 0, address(0));
    }

    /// The digest over `typeString` with the words after `target` (EIP-712: an array as the `keccak256` of its words).
    function _auth(string memory typeString, MetaTxLib.UAEnvelope memory e, address target, bytes memory words)
        internal view returns (IUARegistry.UASig memory a)
    {
        bytes32 h = keccak256(bytes.concat(abi.encode(keccak256(bytes(typeString)), e.from, target), words,
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(SIGNER_PK, keccak256(abi.encodePacked("\x19\x01", _domain(), h)));
        a.signature = abi.encodePacked(r, ss, v);
    }

    function _listType(bool allow) internal pure returns (string memory) {
        return string.concat(allow ? "UASetAllowed" : "UASetDenied", "(bytes32 from,address target,bytes32[] accounts,bool on",
            TAIL);
    }

    function _listCd(bool allow, MetaTxLib.UAEnvelope memory e, address target, bytes32[] memory as_, bool on,
        IUARegistry.UASig memory a) internal pure returns (bytes memory)
    {
        return abi.encodeWithSignature(string.concat(allow ? "mtxSetAllowed(" : "mtxSetDenied(", ENV, ",address,bytes32[],bool,",
            SIG, ")"), e, target, as_, on, a);
    }

    /// `u` the target's chain word, the op's last field (CTR-GOV-28).
    function _enableCd(MetaTxLib.UAEnvelope memory e, address target, uint8 bit, bytes32 u, IUARegistry.UASig memory a)
        internal pure returns (bytes memory)
    {
        return abi.encodeWithSignature(string.concat("mtxEnableFeature(", ENV, ",address,uint8,bytes32,", SIG, ")"), e, target,
            bit, u, a);
    }

    function _send(bytes memory cd) internal returns (bool ok) {
        vm.prank(STRANGER);
        (ok,) = address(router).call(cd);
    }

    function _accounts() internal pure returns (bytes32[] memory as_) {
        as_ = new bytes32[](2);
        (as_[0], as_[1]) = (bytes32(uint256(0xA1)), bytes32(uint256(0xA2)));
    }

    /// B1, B2: `UASetAllowed` / `UASetDenied`; five variants each.
    function _listMatrix(bool allow) internal returns (uint256 n) {
        MetaTxLib.UAEnvelope memory e = _env();
        bytes32[] memory as_ = _accounts();
        IUARegistry.UASig memory a = _auth(_listType(allow), e, t, abi.encode(keccak256(abi.encodePacked(as_)), true));
        bytes32[] memory el = _accounts();
        el[1] = bytes32(uint256(0xA3));
        bytes32[] memory longer = new bytes32[](3);
        (longer[0], longer[1], longer[2]) = (as_[0], as_[1], bytes32(uint256(0xA3)));
        bytes32[] memory shorter = new bytes32[](1);
        shorter[0] = as_[0];
        bytes32[] memory swapped = new bytes32[](2);
        (swapped[0], swapped[1]) = (as_[1], as_[0]);
        bytes[5] memory v = [_listCd(allow, e, other, as_, true, a), _listCd(allow, e, t, el, true, a),
            _listCd(allow, e, t, longer, true, a), _listCd(allow, e, t, shorter, true, a), _listCd(allow, e, t, swapped, true, a)];
        for (uint256 k; k < 5; ++k) assertFalse(_send(v[k]), "a variant passed");
        bool flip = _send(_listCd(allow, e, t, as_, false, a));
        assertFalse(flip, "on flipped passed");
        n = 6;
        assertEq(router.mtxNonce(s, 0), e.nonce, "no nonce spent");
        assertTrue(_send(_listCd(allow, e, t, as_, true, a)), "the control");
        assertEq(router.mtxNonce(s, 0), e.nonce + 1);
        uint8 fl = allow ? ALLOWED : DENIED;
        assertEq(_flags(t, as_[0]), fl);
        assertEq(_flags(t, as_[1]), fl);
        assertEq(_flags(other, as_[0]), 0);
    }

    function test_binding_SetAllowed() public {
        assertEq(_listMatrix(true), 6);
    }

    function test_binding_SetDenied() public {
        assertEq(_listMatrix(false), 6);
    }

    /// B3: `UAEnableFeature`: `target`, `bit`, `chainUid` (CTR-GOV-28: a sibling's word signed reaches the token, which
    /// refuses it by name).
    function test_binding_EnableFeature() public {
        string memory ty = string.concat("UAEnableFeature(bytes32 from,address target,uint8 bit,bytes32 chainUid", TAIL);
        MetaTxLib.UAEnvelope memory e = _env();
        bytes32 u = EnvKit.codeUidOf(t);
        IUARegistry.UASig memory a = _auth(ty, e, t, abi.encode(uint8(DENY), u));
        assertFalse(_send(_enableCd(e, other, DENY, u, a)), "target");
        assertFalse(_send(_enableCd(e, t, ALLOW, u, a)), "bit");
        assertFalse(_send(_enableCd(e, t, DENY, ~u, a)), "chainUid");
        bytes32 sib = keccak256("a sibling with the same chain id");
        IUARegistry.UASig memory as_ = _auth(ty, e, t, abi.encode(uint8(DENY), sib));
        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, u, sib));
        router.mtxEnableFeature(e, t, DENY, sib, as_);
        assertEq(router.mtxNonce(s, 0), e.nonce, "no nonce spent");
        assertTrue(_send(_enableCd(e, t, DENY, u, a)), "the control");
        assertEq(NormalToken(t).features() & (1 << DENY), 1 << DENY);
        assertEq(NormalToken(other).features() & (1 << DENY), 0);
    }

    /// The flow end to end through the router at fee 0 by a stranger relayer: the signer lists, enables the deny list and
    /// denies `bob`; `bob`'s receive stops.
    function test_router_endToEnd() public {
        MetaTxLib.UAEnvelope memory e = _env();
        bytes32[] memory one = new bytes32[](1);
        one[0] = nid(bob);
        assertTrue(_send(_listCd(false, e, t, one, true,
            _auth(_listType(false), e, t, abi.encode(keccak256(abi.encodePacked(one)), true)))));
        vm.prank(alice);
        IERC20(t).transfer(bob, 1); // the list off: the row is dormant
        e = _env();
        string memory ty = string.concat("UAEnableFeature(bytes32 from,address target,uint8 bit,bytes32 chainUid", TAIL);
        bytes32 u = EnvKit.codeUidOf(t);
        assertTrue(_send(_enableCd(e, t, DENY, u, _auth(ty, e, t, abi.encode(uint8(DENY), u)))));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(DENIED_ERR, nid(bob)));
        IERC20(t).transfer(bob, 1);
    }
}
