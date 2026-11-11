// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PqzFixture} from "./PqzFixture.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {OpenFactory} from "../../../src/factory/OpenFactory.sol";
import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../../src/ua/UARegistry.sol";
import {Catalogue, pqzEnv} from "../../helpers/Catalogue.sol";
import {EnvKit} from "../../helpers/EnvKit.sol";
import {nid} from "../../helpers/Ids.sol";
import {PQZ_UID} from "./PqzRegistryBase.sol";

/// @notice `requireAuthorized` (by `vm.mockFunction`, selector only) starved out of gas for the verdict purpose (an empty
///         revert burning its frame's gas), every other purpose accepted (the holder's mocked ML-DSA consent, as before).
contract VerdictOutOfGas {
    fallback() external {
        bytes32 purpose = keccak256("scaas.ua.purpose.pqz-verdict.v1");
        assembly ("memory-safe") {
            if eq(calldataload(36), purpose) { invalid() }
        }
    }
}

/// @notice Group 3f (PQZ verifier mode spec §3-§6): `PqzFixture` with `OFFCHAIN` tokens. The verifier is an EOA (`VKEY`) by
///         default: its `UASig` is real ECDSA over the registry's `uaAuthDigest`, so a wrong key, domain or struct is a real
///         refusal. `PQZ` stays mocked as in the fixture; an `OFFCHAIN` token never calls it (I5). UNAUDITED.
abstract contract PqzOffchainBase is PqzFixture {
    bytes internal constant VPROOF = hex"c0de";
    uint256 internal constant VKEY = 0xA77E57;
    uint256 internal constant VKEY2 = 0xB0B2;
    bytes32 internal constant EIP712_DOMAIN =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");

    bytes32 internal vA; // the EOA verifier of `VKEY`
    bytes32 internal vB; // of `VKEY2`

    function _offStack() internal {
        _stack();
        _mockOp(7, 1);
        vA = nid(vm.addr(VKEY));
        vB = nid(vm.addr(VKEY2));
    }

    /// An `OFFCHAIN` `NORMAL_PQZ` token of the fixture's factory with verifier `v`.
    function _offToken(bytes32 s, bytes32 v, bool fixed_) internal returns (NormalPqzToken t) {
        (vMode, vUA, vFixed) = (PqzCore.OFFCHAIN, v, fixed_);
        t = _newToken(s);
        (vMode, vUA, vFixed) = (0, bytes32(0), false);
    }

    /// The token's EIP-712 domain separator from its ERC-5267 view.
    function _sepOf(address t) internal view returns (bytes32) {
        (, string memory n, string memory ver, uint256 cid, address vc, bytes32 salt_,) = NormalPqzToken(t).eip712Domain();
        return keccak256(abi.encode(EIP712_DOMAIN, keccak256(bytes(n)), keccak256(bytes(ver)), cid, vc, salt_));
    }

    /// The verdict the verifier would sign for `st` and `proof` on `t` now (valid ten minutes).
    function _verdict(NormalPqzToken t, bytes memory st, bytes memory proof) internal view returns (IPqzToken.PqzVerdict memory) {
        return IPqzToken.PqzVerdict(address(t), block.chainid, t.proofSystemId(), keccak256(st), keccak256(proof),
            t.pqzVerifyConfig().pqzVerifierEpoch, uint64(block.timestamp + 600));
    }

    function _verdictDigest(address t, IPqzToken.PqzVerdict memory v) internal view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(_sepOf(t), keccak256(abi.encode(PqzCore.VERDICT_TYPEHASH, v)));
    }

    /// `v` signed by the EOA of `key` in `t`'s domain (`domainOf` another token's domain for a negative).
    function _signAt(address domainOf, uint256 key, IPqzToken.PqzVerdict memory v)
        internal view returns (IPqzToken.PqzSignedVerdict memory sv)
    {
        bytes32 d = _verdictDigest(domainOf, v);
        // the registry of the token whose verdict this is (its env), whose domain the native signature is under
        UARegistry r = UARegistry(IFactoryToken(domainOf).chainEnv().registry);
        (uint8 w, bytes32 r_, bytes32 s_) = vm.sign(key, r.uaAuthDigest(nid(vm.addr(key)), UAKinds.PURPOSE_PQZ_VERDICT, d));
        sv.pqzVerdict = v;
        sv.sig.signature = abi.encodePacked(r_, s_, w);
    }

    function _sign(NormalPqzToken t, uint256 key, IPqzToken.PqzVerdict memory v)
        internal view returns (IPqzToken.PqzSignedVerdict memory)
    {
        return _signAt(address(t), key, v);
    }

    /// The verifier `VKEY`'s verdict over `st` and `VPROOF`.
    function _sv(NormalPqzToken t, bytes memory st) internal view returns (IPqzToken.PqzSignedVerdict memory) {
        return _sign(t, VKEY, _verdict(t, st, VPROOF));
    }

    /// An op 1 of `from` to `to` on `t` at its `pendingCount`, no fee; its statement (direct).
    function _op1Of(NormalPqzToken t, bytes32 from, bytes32 to, uint256 seed, bool withAud)
        internal view returns (IPqzToken.PqzTransferArgs memory a, bytes memory st)
    {
        a = _ts(_payloadFor(t, from, to, bytes32(0), _out(seed, withAud)));
        st = t.transferSingleStatement(a, 0);
    }

    /// A burn (`amount`, `recipient`; 0, 0 a refresh) of `from` at its `pendingCount`; its statement (direct).
    function _burnOf(NormalPqzToken t, bytes32 from, uint256 amount, bytes32 recipient, uint256 seed)
        internal view returns (IPqzToken.PqzBurnArgs memory b, bytes memory st)
    {
        b = _bs(bytes.concat(abi.encode(uint256(t.pqzAccount(from, 0).pendingCount), block.number + 50, uint256(0), from,
            bytes32(0)), _blob(seed, PqzCt.CT)));
        st = t.burnStatement(b, amount, recipient, 0);
    }

    /// Shield `amount` into `ua` on `t` from the test's public balance.
    function _shieldOn(NormalPqzToken t, bytes32 ua, uint256 amount) internal {
        _public(t, address(this), amount * SCALE);
        t.mtxShield(ua, amount);
    }

    /// A second registry like the fixture's but WITHOUT the `0x0142` verifier (`pqz-mlwe` not enabled: every PQZ key is
    /// unproven, `current` the highest version whose proof bytes are stored, KV-12), its factory and `NORMAL_PQZ` release,
    /// and an `OFFCHAIN` token on it with verifier `v`.
    function _noVerifierToken(bytes32 v) internal returns (NormalPqzToken t, UARegistry r2) {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(UAKinds.MLDSA65, address(mlv), 100_000);
        r2 = new UARegistry(PQZ_UID, address(0), false, 12_000_000, address(0), true, k);
        OpenFactory f2 = new OpenFactory(nid(registrar));
        EnvKit.configure(f2, PQZ_UID, 0, address(0));
        Catalogue.release(f2, IOpenFactory.TokenKind.NORMAL_PQZ, 1, pqzEnv(address(f2), PQZ_UID, address(r2), address(0)),
            type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        f2.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true, EnvKit.uidOf(address(f2)));
        (vMode, vUA, vFixed) = (PqzCore.OFFCHAIN, v, false);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.conf.auditorKey = "";
        c.conf.auditorMode = 0;
        (vMode, vUA, vFixed) = (0, bytes32(0), false);
        t = NormalPqzToken(f2.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "noverifier"));
    }
}
