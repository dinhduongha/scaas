// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {AuthScheme} from "../common/AuthScheme.sol";
import {MultiSig} from "../common/MultiSig.sol";
import {Bls12381} from "../common/Bls12381.sol";
import {HashToCurve} from "../common/HashToCurve.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";
import {ZetherTranscript} from "../zether/ZetherTranscript.sol";
import {ZetherSafety} from "../zether/ZetherSafety.sol";
import {G1Bn254, G1Bls12381} from "../zether/ZetherCurves.sol";
import {IUniversalAccountRegistry} from "./IUniversalAccountRegistry.sol";

/// @title Universal Account Registry — singleton theo chain, dùng chung cho mọi Zether token.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Chỉ deploy được trên chain dev (RS2-1).
///
///         Hai bằng chứng lúc đăng ký (đặc tả §11.2):
///         1. `schnorrPop` — Schnorr bằng `x` của khoá ElGamal trên `c`: không ai đăng ký được khoá mà mình
///            không biết dlog (rogue key, điểm "đen" không ai giải mã được).
///         2. `authPop` — nắm khoá **uỷ quyền** (group key FROST/MuSig2, khoá BLS G2, chủ multisig, smart
///            account) trên cùng `c`. Rogue key trong tổng hợp khoá chết ở đây.
///
///         Không xoay khoá, không đổi link (RS2-9): đổi khoá = UA mới.
contract UniversalAccountRegistry is IUniversalAccountRegistry {
    using ZetherTypes for bytes;

    struct Account {
        bool registered;
        AuthScheme scheme;
        uint16 keyLength;
        address linked;
        bytes authData;
        /// @dev `encodedY`: a sender rebuilds its commit-reveal record from the memo's recipient UAs (zether.md CTR-ZTH-50).
        bytes key;
    }

    bytes private constant SCHNORR_TAG = "SCAAS-ZETHER-SCHNORR-V1"; // ASCII thô, 23 byte (§11.1)
    bytes private constant BLS_BN254_SIG = "SCAAS-BLS-BN254-SIG-V1";
    bytes private constant BLS_BN254_POP = "SCAAS-BLS-BN254-POP-V1";
    bytes private constant BLS381_DST_SIG = "SCAAS-AUTH-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_";
    bytes private constant BLS381_DST_POP = "SCAAS-AUTH-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
    /// bn254 G2 generator, thứ tự EIP-197: x_im, x_re, y_im, y_re.
    bytes private constant BN254_G2 = abi.encodePacked(
        uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
        uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781),
        uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),
        uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930)
    );

    mapping(ZetherTypes.UA => Account) private _accounts;
    mapping(address => ZetherTypes.UA) public links;
    // solhint-disable-next-line var-name-mixedcase
    mapping(ZetherTypes.UA => address) public link_eth;

    constructor() {
        ZetherSafety.requireDevChain();
    }

    // ------------------------------------------------------------------ đăng ký

    function register(
        bytes calldata encodedY,
        AuthScheme authScheme,
        bytes calldata authData,
        bytes calldata popSignature,
        bool linkEVM
    ) external returns (ZetherTypes.UA ua) {
        uint256 len = encodedY.length;
        if (!_validKey(encodedY)) revert InvalidPublicKey();
        ua = ZetherTypes.toUA(encodedY);
        if (_accounts[ua].registered) revert AccountAlreadyRegistered(ua);
        // canon C6.1: công bố [x]G2 trên CÙNG đường cong làm DDH trong G1 quyết định được ⇒ lộ số dư
        if ((authScheme == AuthScheme.BLS_BN254 && len == 64) || (authScheme == AuthScheme.BLS_12381 && len == 128)) {
            revert UnauthorizedScheme(authScheme);
        }
        _validateAuthData(authScheme, authData);

        bytes32 c = popChallenge(encodedY, msg.sender);
        (bytes memory schnorrPop, bytes memory authPop) = abi.decode(popSignature, (bytes, bytes));
        if (!_schnorr(encodedY, c, schnorrPop)) revert InvalidProofOfPossession();
        if (!_authValid(authScheme, authData, c, authPop, true)) revert InvalidProofOfPossession();

        address linked;
        if (linkEVM) {
            if (ZetherTypes.UA.unwrap(links[msg.sender]) != 0) revert EVMAlreadyLinked(msg.sender);
            links[msg.sender] = ua;
            link_eth[ua] = msg.sender;
            linked = msg.sender;
        }
        _accounts[ua] = Account({
            registered: true, scheme: authScheme, keyLength: uint16(len), linked: linked, authData: authData,
            key: encodedY
        });
        emit AccountRegistered(ua, authScheme, linked, authData);
    }

    function popChallenge(bytes calldata encodedY, address account) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), encodedY, account));
    }

    // ------------------------------------------------------------------ đọc

    function accounts(ZetherTypes.UA ua)
        external view returns (bool registered, AuthScheme scheme, address linkedEVMAddress, bytes memory authData)
    {
        Account storage a = _accounts[ua];
        return (a.registered, a.scheme, a.linked, a.authData);
    }

    function isRegistered(ZetherTypes.UA ua) external view returns (bool) {
        return _accounts[ua].registered;
    }

    function keyLengthOf(ZetherTypes.UA ua) external view returns (uint256) {
        return _accounts[ua].keyLength;
    }

    function keyOf(ZetherTypes.UA ua) external view returns (bytes memory) {
        return _accounts[ua].key;
    }

    // ------------------------------------------------------------------ uỷ quyền

    function requireAuthorized(ZetherTypes.UA ua, bytes32 digest, bytes calldata sig, bool zkCovered) external view {
        Account storage a = _accounts[ua];
        if (!a.registered) revert Unauthorized(ua);
        AuthScheme s = a.scheme;
        if (s == AuthScheme.SELF_SCHNORR || s == AuthScheme.PQ_COMMITMENT) {
            // RS2-10: proof biết x là uỷ quyền; ngoài proof, Schnorr bằng x (Y đi kèm, so với UA)
            if (zkCovered) {
                if (sig.length != 0) revert Unauthorized(ua);
                return;
            }
            (bytes memory y, bytes memory schnorrSig) = abi.decode(sig, (bytes, bytes));
            if (ZetherTypes.UA.unwrap(y.toUA()) != ZetherTypes.UA.unwrap(ua) || !_schnorr(y, digest, schnorrSig)) {
                revert Unauthorized(ua);
            }
            return;
        }
        if (!_authValid(s, a.authData, digest, sig, false)) revert Unauthorized(ua);
    }

    // ------------------------------------------------------------------ nội bộ

    function _validKey(bytes calldata y) private view returns (bool) {
        if (y.length == 64) return G1Bn254.isValid(y) && !G1Bn254.isIdentity(y);
        if (y.length == 128) return G1Bls12381.isValid(y) && !G1Bls12381.isIdentity(y); // isValid: subgroup
        return false;
    }

    function _validateAuthData(AuthScheme s, bytes calldata d) private view {
        if (s == AuthScheme.SELF_SCHNORR) {
            if (d.length != 0) revert InvalidAuthData();
        } else if (s == AuthScheme.ECDSA_MULTISIG) {
            (address[] memory owners, uint256 t) = abi.decode(d, (address[], uint256));
            if (t == 0 || t > owners.length) revert InvalidAuthData();
            address last;
            for (uint256 i; i < owners.length; ++i) {
                if (owners[i] <= last) revert InvalidAuthData(); // khác 0, tăng nghiêm ngặt
                last = owners[i];
            }
        } else if (s == AuthScheme.FROST_BN254) {
            (bytes memory key, uint256 t, uint256 total) = abi.decode(d, (bytes, uint256, uint256));
            if (!_bnKey(key) || t == 0 || t > total) revert InvalidAuthData();
        } else if (s == AuthScheme.MUSIG2_BN254) {
            (bytes memory key, uint256 total) = abi.decode(d, (bytes, uint256));
            if (!_bnKey(key) || total == 0) revert InvalidAuthData();
        } else if (s == AuthScheme.BLS_BN254) {
            bytes memory pk = abi.decode(d, (bytes));
            if (pk.length != 128 || _isZero(pk)) revert InvalidAuthData();
        } else if (s == AuthScheme.BLS_12381) {
            // requireInG2Subgroup revert nếu sai độ dài / ngoài subgroup. pk = vô cực làm pairing tầm thường:
            // chữ ký vô cực qua mọi digest ⇒ "custody BLS" giả, x một mình tiêu được (bất biến #1).
            if (_isZero(Bls12381.requireInG2Subgroup(abi.decode(d, (bytes))))) revert InvalidAuthData();
        } else if (s == AuthScheme.PQ_COMMITMENT) {
            if (abi.decode(d, (bytes32)) == bytes32(0)) revert InvalidAuthData();
        } else {
            if (abi.decode(d, (address)).code.length == 0) revert InvalidAuthData();
        }
    }

    /// @dev Mã hoá điểm vô cực của EIP-197/EIP-2537 là toàn 0.
    function _isZero(bytes memory b) private pure returns (bool) {
        return keccak256(b) == keccak256(new bytes(b.length));
    }

    function _bnKey(bytes memory key) private view returns (bool) {
        return key.length == 64 && G1Bn254.isValid(key) && !G1Bn254.isIdentity(key);
    }

    /// @dev Đường xác minh theo scheme cho các scheme có khoá uỷ quyền riêng. `pop` chọn nhãn PoP.
    function _authValid(AuthScheme s, bytes memory d, bytes32 m, bytes memory sig, bool pop)
        private view returns (bool)
    {
        if (s == AuthScheme.SELF_SCHNORR || s == AuthScheme.PQ_COMMITMENT) return sig.length == 0;
        if (s == AuthScheme.ECDSA_MULTISIG) {
            (address[] memory owners, uint256 t) = abi.decode(d, (address[], uint256));
            MultiSig.requireQuorum(owners, t, m, abi.decode(sig, (bytes[]))); // revert nếu thiếu
            return true;
        }
        if (s == AuthScheme.FROST_BN254 || s == AuthScheme.MUSIG2_BN254) {
            (bytes memory key) = abi.decode(d, (bytes)); // tiền tố chung của cả hai bố cục authData
            return _schnorr(key, m, sig);
        }
        if (s == AuthScheme.BLS_BN254) return _blsBn254(abi.decode(d, (bytes)), m, sig, pop);
        if (s == AuthScheme.BLS_12381) {
            if (sig.length != 128 || _isZero(sig)) return false;
            bytes memory h = HashToCurve.hashToG1(abi.encodePacked(m), pop ? BLS381_DST_POP : BLS381_DST_SIG);
            return Bls12381.verifyMinSig(h, abi.decode(d, (bytes)), sig);
        }
        // SMART_ACCOUNT_1271 — trần gas như ERC20MetaTx
        (bool ok, bytes memory ret) = abi.decode(d, (address)).staticcall{gas: 50_000}(
            abi.encodeCall(IERC1271.isValidSignature, (m, sig))
        );
        return ok && ret.length == 32 && abi.decode(ret, (bytes4)) == IERC1271.isValidSignature.selector;
    }

    /// @dev Schnorr §11.1 trên đường cong của `y`: `[z]G − R − [e]Y == O`.
    function _schnorr(bytes memory y, bytes32 m, bytes memory sig) private view returns (bool) {
        uint256 p = y.length;
        if ((p != 64 && p != 128) || sig.length != p + 32) return false;
        bytes memory rPt = new bytes(p);
        uint256 z;
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, p) { i := add(i, 32) } { mstore(add(add(rPt, 32), i), mload(add(add(sig, 32), i))) }
            z := mload(add(add(sig, 32), p))
        }
        uint256 r = p == 64 ? G1Bn254.R : G1Bls12381.R;
        uint256 e = ZetherTranscript.hashToScalar(keccak256(abi.encodePacked(SCHNORR_TAG, rPt, y, m)), r);
        if (z >= r || e == 0 || keccak256(rPt) == keccak256(new bytes(p)) || keccak256(y) == keccak256(new bytes(p))) {
            return false;
        }
        uint256[] memory sc = new uint256[](3);
        (sc[0], sc[1], sc[2]) = (z, r - 1, r - e);
        bytes memory out = p == 64
            ? G1Bn254.msm(bytes.concat(G1Bn254.generator(), rPt, y), sc)
            : G1Bls12381.msm(bytes.concat(G1Bls12381.generator(), rPt, y), sc);
        return keccak256(out) == keccak256(new bytes(p));
    }

    /// @dev BLS min-sig trên bn254: `e(−sig, G2) · e(H(m), pk) == 1`, H = try-and-increment (§3.1, §11.2).
    function _blsBn254(bytes memory pk, bytes32 m, bytes memory sig, bool pop) private view returns (bool) {
        if (sig.length != 64 || !G1Bn254.isValid(sig) || G1Bn254.isIdentity(sig)) return false;
        bytes memory h = G1Bn254.mapToG1(abi.encodePacked(pop ? BLS_BN254_POP : BLS_BN254_SIG, m));
        (bool ok, bytes memory out) = address(0x08).staticcall(
            bytes.concat(G1Bn254.neg(sig), BN254_G2, h, pk)
        );
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }
}
