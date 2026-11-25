// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PqzOffchainBase} from "../pqz/helpers/PqzOffchainBase.sol";
import {PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";
import {ZetherFixture, ZUID} from "../zether/helpers/ZetherFixture.sol";
import {ZetherKeys} from "../zether/helpers/ZetherKeys.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {IConfidentialToken} from "../../src/confidential/IConfidentialToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceRouterTypes} from "../../src/governance/GovernanceRouterBase.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {Catalogue, pqzEnv, zetherEnv} from "../helpers/Catalogue.sol";
import {ZetherVerifierBase} from "../../src/zether/ZetherVerifier.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// The router's typed ops of bit 32 (set-auditor spec §8, plan A6, CTR-GOV-31): a native holder signs `UASetAuditorKey` /
/// `UASetAuditorUA` (fee mode `NONE`, relayer and fee recipient unbound), any relayer submits; the struct binds the target, the
/// new auditor (`keccak256(newKey)` on Zether), the epoch and the target's chain word; the new auditor's consent rides beside
/// it and is forwarded as given. A sibling word, another epoch and a struct over another key are refused. UNAUDITED.
abstract contract RouterSig {
    uint256 internal constant LANE = 9;
    uint256 internal constant NKEY = 0x32B17;

    /// `words` the op's words after `target`; `u` the envelope; the digest under `router`'s domain.
    function _digest(
        GovernanceRouter router,
        bytes32 th,
        MetaTxLib.UAEnvelope memory u,
        address target,
        bytes memory words
    ) internal view returns (bytes32) {
        bytes32 sh = keccak256(
            bytes.concat(
                abi.encode(th, u.from),
                abi.encode(target),
                words,
                abi.encode(u.batch, u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))
            )
        );
        (, string memory n, string memory v, uint256 cid, address vc, bytes32 salt,) = router.eip712Domain();
        bytes32 sep = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
                ),
                keccak256(bytes(n)),
                keccak256(bytes(v)),
                cid,
                vc,
                salt
            )
        );
        return MessageHashUtils.toTypedDataHash(sep, sh);
    }
}

contract GovRouterAuditorPqzTest is PqzOffchainBase, RouterSig {
    GovernanceRouter internal router;
    OpenFactory internal f;
    bytes32 internal nId;
    bytes32 internal a1;

    function setUp() public {
        _offStack();
        nId = nid(vm.addr(NKEY));
        router = new GovernanceRouter(PQZ_UID, address(reg), address(0), false, EnvKit.nextCreate(2)); // G-3: names the factory built next
        f = new OpenFactory(nid(registrar));
        EnvKit.configure(f, PQZ_UID, 0, address(router));
        Catalogue.release(
            f,
            IOpenFactory.TokenKind.NORMAL_PQZ,
            1,
            pqzEnv(address(f), PQZ_UID, address(reg), address(pqv)),
            type(NormalPqzToken).creationCode
        );
        vm.prank(registrar);
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true, EnvKit.uidOf(address(f)));
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features |= uint256(1) << GovernanceBits.AUDITOR;
        (c.admin, c.lockedFeatures) = (nid(address(this)), 0);
        tok = NormalPqzToken(f.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "router-aud"));
        IGovernance(address(tok)).grantRole(GovernanceBits.AUDITOR, nId, EnvKit.codeUidOf(address(tok)));
        a1 = _pqzUA(_pk(41), 41);
    }

    function _send(bytes32 ua, uint32 epoch, bytes32 signedWord, bytes32 sentWord, bytes32 signedUA)
        internal
        returns (bool ok, bytes memory ret)
    {
        MetaTxLib.UAEnvelope memory u = MetaTxLib.UAEnvelope(
            nId, LANE, router.mtxNonce(nId, LANE), block.timestamp + 300, 0, address(0xBEEF), 0, address(0xFEE)
        );
        bytes32 d = _digest(
            router, GovernanceRouterTypes.UA_SET_AUDITOR_UA, u, address(tok), abi.encode(signedUA, epoch, signedWord)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(NKEY, d);
        IUARegistry.UASig memory auth;
        auth.signature = abi.encodePacked(r, s, v);
        vm.prank(address(0x4E1A));
        (ok, ret) = address(router)
            .call(
                abi.encodeCall(
                    GovernanceRouter.mtxSetAuditorUA, (u, address(tok), ua, epoch, _pqAuth(), sentWord, auth)
                )
            );
    }

    /// The op applies (delay 0) and forwards the consent as given: `requireAuthorized(a1, PURPOSE_AUDITOR_CONSENT, d, consent)`.
    function test_router_setAuditorUA() public {
        bytes32 uid = EnvKit.codeUidOf(address(tok));
        bytes32 d = MessageHashUtils.toTypedDataHash(
            _sepOf(address(tok)),
            keccak256(
                abi.encode(
                    keccak256("AuditorConsent(address token,bytes32 auditor,uint32 epoch,bytes32 chainUid)"),
                    address(tok),
                    a1,
                    uint32(1),
                    uid
                )
            )
        );
        vm.expectCall(
            address(reg),
            abi.encodeCall(IUARegistry.requireAuthorized, (a1, UAKinds.PURPOSE_AUDITOR_CONSENT, d, _pqAuth()))
        );
        (bool ok,) = _send(a1, 1, uid, uid, a1);
        assertTrue(ok, "applied");
        assertEq(tok.auditorUA(), a1);
    }

    /// A sibling word (signed and sent) is the token's `ChainUidMismatch`; another epoch the token's `AuditorEpochMismatch`; a
    /// struct over another UA than sent, or another word than sent, a refused signature; nothing applied.
    function test_router_setAuditorUA_refusals() public {
        bytes32 uid = EnvKit.codeUidOf(address(tok));
        bytes32 other = bytes32(uint256(uid) ^ 1);
        (bool ok, bytes memory ret) = _send(a1, 1, other, other, a1);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, uid, other));
        (ok, ret) = _send(a1, 2, uid, uid, a1);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IConfidentialToken.AuditorEpochMismatch.selector, uint32(1), uint32(2)));
        (ok,) = _send(a1, 1, uid, uid, aud);
        assertFalse(ok, "the struct names another UA");
        (ok,) = _send(a1, 1, other, uid, a1);
        assertFalse(ok, "the struct names another word");
        assertEq(tok.auditorUA(), aud, "nothing applied");
    }
}

contract GovRouterAuditorZetherTest is ZetherFixture, RouterSig {
    GovernanceRouter internal router;
    OpenFactory internal f;
    bytes32 internal nId;
    uint256 internal constant XB = 0xB0D1E5;

    function setUp() public {
        _stack();
        _users();
        nId = nid(vm.addr(NKEY));
        router = new GovernanceRouter(ZUID, address(reg), address(0), false, EnvKit.nextCreate(2)); // G-3: names the factory built next
        f = new OpenFactory(nid(registrar));
        EnvKit.configure(f, ZUID, 0, address(router));
        Catalogue.release(
            f,
            IOpenFactory.TokenKind.NORMAL_ZETHER,
            1,
            zetherEnv(
                address(f),
                ZUID,
                address(reg),
                address(ver),
                address(burnVer),
                address(ZetherVerifierBase(address(ver)).innerProduct()),
                address(dis)
            ),
            type(NormalZetherToken).creationCode
        );
        vm.prank(registrar);
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER, true, EnvKit.uidOf(address(f)));
        IFactoryToken.TokenConfig memory c = _cfg(true, uint256(1) << 40);
        c.features |= uint256(1) << GovernanceBits.AUDITOR;
        (c.admin, c.lockedFeatures) = (nid(address(this)), 0);
        tok = NormalZetherToken(f.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "router-aud"));
        IGovernance(address(tok)).grantRole(GovernanceBits.AUDITOR, nId, EnvKit.codeUidOf(address(tok)));
    }

    function _send(bytes memory key, uint32 epoch, bytes memory pop, bytes32 word, bytes memory signedKey)
        internal
        returns (bool ok, bytes memory ret)
    {
        MetaTxLib.UAEnvelope memory u = MetaTxLib.UAEnvelope(
            nId, LANE, router.mtxNonce(nId, LANE), block.timestamp + 300, 0, address(0xBEEF), 0, address(0xFEE)
        );
        bytes32 d = _digest(
            router,
            GovernanceRouterTypes.UA_SET_AUDITOR_KEY,
            u,
            address(tok),
            abi.encode(keccak256(signedKey), epoch, word)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(NKEY, d);
        IUARegistry.UASig memory auth;
        auth.signature = abi.encodePacked(r, s, v);
        vm.prank(address(0x4E1A));
        (ok, ret) = address(router)
            .call(abi.encodeCall(GovernanceRouter.mtxSetAuditorKey, (u, address(tok), key, epoch, pop, word, auth)));
    }

    /// The op applies (delay 0) with the new key's proof forwarded; a broken proof is the token's `AuditorConsentInvalid`; a
    /// struct over another key than sent a refused signature; another epoch `AuditorEpochMismatch`.
    function test_router_setAuditorKey() public {
        bytes32 uid = EnvKit.codeUidOf(address(tok));
        bytes memory y = ZetherKeys.pub(XB, bls);
        bytes memory pop = _auditorPop(tok, XB, 1);
        bytes memory bad = bytes.concat(pop);
        bad[159] = bytes1(uint8(bad[159]) ^ 1);
        (bool ok, bytes memory ret) = _send(y, 1, bad, uid, y);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IZetherToken.AuditorConsentInvalid.selector));
        (ok,) = _send(y, 1, pop, uid, ZetherKeys.pub(X_AUD, bls));
        assertFalse(ok, "the struct names another key");
        (ok, ret) = _send(y, 2, pop, uid, y);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IConfidentialToken.AuditorEpochMismatch.selector, uint32(1), uint32(2)));
        (ok,) = _send(y, 1, pop, uid, y);
        assertTrue(ok, "applied");
        assertEq(tok.auditorKey(), y);
    }
}
