// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceRouterTypes as T} from "../../src/governance/GovernanceRouterBase.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {ZetherKeys} from "../zether/helpers/ZetherKeys.sol";
import {ZetherFixture, ZUID} from "../zether/helpers/ZetherFixture.sol";
import {PqzOffchainBase} from "../pqz/helpers/PqzOffchainBase.sol";
import {PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {SdkGasOps} from "./SdkGasOps.sol";
import {_sgPqzKeep} from "./SdkGasFixtures.sol";

/// The router's confidential-token entries signed by the reference signer (a native key), each on a router-configured
/// factory with a notice period of 0 (a change applies at once): the op's digest `(typehash, from, target, words…, E)` in the
/// router's domain, relayer and fee recipient unbound, fee `NONE`.
abstract contract SdkGasRouterConfOps is SdkGasOps {
    GovernanceRouter internal gcRouter;
    /// the op under measurement: its typehash, selector, target and the words after `target` (each static)
    bytes32 internal gcTh;
    bytes4 internal gcSel;
    address internal gcT;
    bytes internal gcWords;

    /// `gcSel(E, target, words…, auth)`: every argument static but the envelope's tail and the signature.
    function _gc(address c, uint256 nonce) internal view returns (bytes memory) {
        bytes32 d = MtxDigest.typed(
            c,
            keccak256(
                bytes.concat(
                    abi.encode(gcTh, _sgFrom(), gcT),
                    gcWords,
                    abi.encode(SG_LANE, nonce, block.timestamp + 600, uint32(0), address(0), uint256(0), address(0))
                )
            )
        );
        bytes memory head = bytes.concat(abi.encode(_sgE(nonce)), abi.encode(gcT), gcWords);
        bytes memory sig = abi.encode(_sgUaSig(d));
        // the `UASig` tuple's offset (the head's length plus its own word), then its body (`abi.encode` of a dynamic
        // tuple: its offset word first, dropped)
        bytes memory body = new bytes(sig.length - 32);
        for (uint256 i; i < body.length; ++i) {
            body[i] = sig[i + 32];
        }
        return bytes.concat(gcSel, head, abi.encode(head.length + 32), body);
    }

    function _gcRow(string memory entry, string memory variant, bytes32 th, bytes4 sel, address t, bytes memory w)
        internal
    {
        (gcTh, gcSel, gcT, gcWords) = (th, sel, t, w);
        _both("gov_router", entry, variant, address(gcRouter), _sgFrom(), _gc);
    }
}

/// The PQZ verifier, verifier-fee and proof-store entries (variant `pqz`) on an `OFFCHAIN` `NORMAL_PQZ` token whose admin and
/// issuer seat (bit 24 `PQZ_PROOF` granted with it) is the signer, the verifier transferable, the verifier fee 0 with a cap:
/// `mtxPqzSetVerifier` to another verifier (applied at once), `mtxPqzCancelVerifier` and `mtxPqzRevokeVerifier` of the
/// current one, `mtxSetVerifierFee` 0 to 1 (a first write), `mtxSetProofStore` `NONE` to `LOG` (a first write). Each from the
/// same state. The fixture's `PQZ` precompile is mocked; none of these entries calls it.
contract SdkGasRouterPqzTest is SdkGasRouterConfOps, PqzOffchainBase {
    NormalPqzToken internal gcTok;

    function setUp() public {
        _sgSkaSetup(PQZ_UID); // G4: the registry, the router and the releases as a deploy configures them
        _offStack();
        _sgDeployRegistry(address(reg), PQZ_UID, _sgPqzKeep(address(mlv), address(pqv)));
        sgPk = 0xA11CE;
        gcRouter = new GovernanceRouter(PQZ_UID, address(reg), sgSka, false);
        OpenFactory f = new OpenFactory(nid(registrar));
        EnvKit.configure(f, PQZ_UID, 0, address(gcRouter));
        Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_PQZ, 1, _penv(), type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true, EnvKit.uidOf(address(f)));
        (vMode, vUA, vFixed, vOwnKey, vFeeMax) = (PqzCore.OFFCHAIN, vA, false, true, 10);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        (vMode, vUA, vFixed, vOwnKey, vFeeMax) = (0, bytes32(0), false, false, 0);
        c.features |= uint256(1) << GovernanceBits.PQZ_PROOF;
        (c.admin, c.roles.issuer) = (_sgFrom(), _sgFrom());
        gcTok = NormalPqzToken(f.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "sg-router-pqz"));
        _holders(address(gcTok));
    }

    function _fixtureSka() internal view override returns (address) {
        return sgSka;
    }

    function test_sdkGas_routerPqz() public {
        address t = address(gcTok);
        bytes32 u = EnvKit.codeUidOf(t);
        GovernanceRouter r = gcRouter;
        _gcRow("mtxPqzSetVerifier", "pqz", T.UA_PQZ_SET_VERIFIER, r.mtxPqzSetVerifier.selector, t, abi.encode(vB, u));
        _gcRow(
            "mtxPqzCancelVerifier", "pqz", T.UA_PQZ_CANCEL_VERIFIER, r.mtxPqzCancelVerifier.selector, t, abi.encode(u)
        );
        _gcRow(
            "mtxPqzRevokeVerifier", "pqz", T.UA_PQZ_REVOKE_VERIFIER, r.mtxPqzRevokeVerifier.selector, t, abi.encode(u)
        );
        _gcRow(
            "mtxSetVerifierFee", "pqz", T.UA_SET_VERIFIER_FEE, r.mtxSetVerifierFee.selector, t, abi.encode(uint64(1), u)
        );
        _gcRow("mtxSetProofStore", "pqz", T.UA_SET_PROOF_STORE, r.mtxSetProofStore.selector, t, abi.encode(uint8(1), u));
    }
}

/// `mtxSetAuditorKey` (variant `zether`) on a `NORMAL_ZETHER` token with bit 32 `AUDITOR` granted to the signer, at notice 0:
/// the new key with its real proof of possession (the fixture's BLS12-381 stack), applied at once.
contract SdkGasRouterZetherTest is SdkGasRouterConfOps, ZetherFixture {
    uint256 internal constant XB = 0xB0D1E5;

    function setUp() public {
        _sgSkaSetup(ZUID); // G4: the registry, the router and the releases as a deploy configures them
        _stack();
        _sgDeployRegistry(address(reg), ZUID, _sgNoKeep());
        _users();
        sgPk = 0xA11CE;
        gcRouter = new GovernanceRouter(ZUID, address(reg), sgSka, false);
        OpenFactory f = new OpenFactory(nid(registrar));
        EnvKit.configure(f, ZUID, 0, address(gcRouter));
        Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_ZETHER, 1, _zenv(), type(NormalZetherToken).creationCode);
        vm.prank(registrar);
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER, true, EnvKit.uidOf(address(f)));
        IFactoryToken.TokenConfig memory c = _cfg(true, uint256(1) << 40);
        c.features |= uint256(1) << GovernanceBits.AUDITOR;
        (c.admin, c.lockedFeatures) = (nid(address(this)), 0);
        tok = NormalZetherToken(f.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "sg-router-aud"));
        IGovernance(address(tok)).grantRole(GovernanceBits.AUDITOR, _sgFrom(), EnvKit.codeUidOf(address(tok)));
    }

    /// `mtxSetAuditorKey(E, target, newKey, epoch, pop, chainUid, auth)`: the struct signs `keccak256(newKey)`.
    function _auditorKey(address c, uint256 nonce) internal view returns (bytes memory) {
        (bytes memory y, bytes32 u) = (ZetherKeys.pub(XB, bls), EnvKit.codeUidOf(address(tok)));
        bytes32 d = MtxDigest.typed(
            c,
            keccak256(
                bytes.concat(
                    abi.encode(T.UA_SET_AUDITOR_KEY, _sgFrom(), address(tok)),
                    abi.encode(keccak256(y), uint32(1), u),
                    abi.encode(SG_LANE, nonce, block.timestamp + 600, uint32(0), address(0), uint256(0), address(0))
                )
            )
        );
        return abi.encodeCall(
            GovernanceRouter.mtxSetAuditorKey,
            (_sgE(nonce), address(tok), y, uint32(1), _auditorPop(tok, XB, 1), u, _sgUaSig(d))
        );
    }

    function _fixtureSka() internal view override returns (address) {
        return sgSka;
    }

    function test_sdkGas_routerZether() public {
        _both("gov_router", "mtxSetAuditorKey", "zether", address(gcRouter), _sgFrom(), _auditorKey);
    }
}
