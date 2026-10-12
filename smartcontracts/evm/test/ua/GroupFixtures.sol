// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {G1Bn254} from "../../src/zether/ZetherCurves.sol";
import {ZetherTranscript} from "../../src/zether/ZetherTranscript.sol";
import {FrostSecp256k1} from "../../src/ua/verifiers/UAFrostSecp256k1Verifier.sol";

/// Runs a call in its own small frame and returns the gas it used: a gasleft() delta in the test itself would include
/// the expansion of the test's large memory (parsed JSON) while encoding the call.
contract GasMeter {
    function measure(address target, bytes calldata data) external returns (bool ok, bytes memory ret, uint256 used) {
        uint256 g = gasleft();
        (ok, ret) = target.call(data);
        used = g - gasleft();
    }
}

/// The UA-2c groups of `vectors/ua/groups.json` (Rust signers: BIP-327 MuSig2, ZF frost-secp256k1 3.0.0 and the bn254
/// ports; PoPs under structures.json context A = this suite's `REG_A` on chain 31337) and signers over the group secret
/// for messages the file does not carry: BIP-340 by `x(Q)` (musig2-secp256k1), RFC 9591 FROST(secp256k1, SHA-256)
/// (frost-secp256k1), the scaas Schnorr (both bn254 kinds). An aggregate MuSig2 / FROST signature has the same form as
/// the single-signer one by the group secret.
abstract contract GroupFixtures is Test {
    uint256 internal constant N_K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint16 internal constant MS = 0x0110;
    uint16 internal constant FS = 0x0111;
    uint16 internal constant MB = 0x0112;
    uint16 internal constant FB = 0x0113;

    GasMeter internal meter = new GasMeter();

    struct Group {
        string row; // ".groups[i]"
        uint16 kind;
        uint256 n;
        uint256 t;
        bytes keyData;
        bytes vk;
        bytes hints; // musig2-secp256k1: n × (x ‖ y), concatenated
        uint256 secret; // groupSecret: MuSig2 d = Σ a_i·sk_i, FROST s = Σ a_i0
        bytes32 ua;
        bytes32 keyHash;
        bytes32 popMessage;
        bytes pop; // pop.blob, context A
    }

    function _gj() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/groups.json");
    }

    /// The group of `kind` with `n` members / participants and threshold `t` (MuSig2: t = n).
    function _group(uint16 kind, uint256 n, uint256 t) internal view returns (Group memory g) {
        string memory j = _gj();
        for (uint256 i; vm.keyExistsJson(j, string.concat(".groups[", vm.toString(i), "]")); ++i) {
            string memory row = string.concat(".groups[", vm.toString(i), "]");
            if (
                vm.parseJsonUint(j, string.concat(row, ".kind")) == kind
                    && vm.parseJsonUint(j, string.concat(row, ".n")) == n
                    && vm.parseJsonUint(j, string.concat(row, ".t")) == t
            ) return _load(j, row);
        }
        revert("group not in groups.json");
    }

    function _load(string memory j, string memory row) internal pure returns (Group memory g) {
        g.row = row;
        g.kind = uint16(vm.parseJsonUint(j, string.concat(row, ".kind")));
        g.n = vm.parseJsonUint(j, string.concat(row, ".n"));
        g.t = vm.parseJsonUint(j, string.concat(row, ".t"));
        g.keyData = vm.parseJsonBytes(j, string.concat(row, ".keyData"));
        g.vk = vm.parseJsonBytes(j, string.concat(row, ".vk"));
        bytes[] memory h = vm.parseJsonBytesArray(j, string.concat(row, ".hints"));
        for (uint256 i; i < h.length; ++i) {
            g.hints = bytes.concat(g.hints, h[i]);
        }
        g.secret = vm.parseJsonUint(j, string.concat(row, ".groupSecret"));
        g.ua = vm.parseJsonBytes32(j, string.concat(row, ".ua"));
        g.keyHash = vm.parseJsonBytes32(j, string.concat(row, ".keyHash"));
        g.popMessage = vm.parseJsonBytes32(j, string.concat(row, ".pop.message"));
        g.pop = vm.parseJsonBytes(j, string.concat(row, ".pop.blob"));
    }

    /// The `main` group of `kind`: MuSig2 n = 3, FROST t = 2, n = 3.
    function _main(uint16 kind) internal view returns (Group memory) {
        return _group(kind, 3, kind == MS || kind == MB ? 3 : 2);
    }

    // ----- signers over the group secret -----

    /// BIP-340 signature of `m` by the secret `d` (any parity; the signer negates as BIP-340 says).
    function _bip340Sign(uint256 d, bytes32 m) internal returns (bytes memory) {
        Vm.Wallet memory w = vm.createWallet(d);
        if (w.publicKeyY & 1 == 1) d = N_K1 - d;
        uint256 k = uint256(keccak256(abi.encode("nonce", d, m))) % (N_K1 - 1) + 1;
        Vm.Wallet memory wr = vm.createWallet(k);
        if (wr.publicKeyY & 1 == 1) k = N_K1 - k;
        bytes32 t = sha256("BIP0340/challenge");
        uint256 e = uint256(sha256(abi.encodePacked(t, t, wr.publicKeyX, w.publicKeyX, m))) % N_K1;
        return abi.encodePacked(wr.publicKeyX, addmod(k, mulmod(e, d, N_K1), N_K1));
    }

    /// RFC 9591 FROST(secp256k1, SHA-256) by the group secret: `R ‖ z`, `c = H2(R ‖ Y ‖ m)`, `z = k + c·s`.
    function _frostSign(uint256 s, bytes memory y, bytes32 m) internal returns (bytes memory) {
        uint256 k = uint256(keccak256(abi.encode("frost-nonce", s, m))) % (N_K1 - 1) + 1;
        Vm.Wallet memory w = vm.createWallet(k);
        bytes memory r = abi.encodePacked(bytes1(uint8(2 + (w.publicKeyY & 1))), w.publicKeyX);
        uint256 c = FrostSecp256k1.hashToScalar(abi.encodePacked(r, y, m), FrostSecp256k1.DST_CHAL);
        return bytes.concat(r, bytes32(addmod(k, mulmod(c, s, N_K1), N_K1)));
    }

    /// scaas Schnorr on bn254 (`schnorr-bn254`): `R ‖ z`, `e = hashToScalar(keccak256(tag ‖ R ‖ Y ‖ m))`.
    function _bnSign(uint256 x, bytes memory y, bytes32 m) internal view returns (bytes memory) {
        uint256 k = uint256(keccak256(abi.encode("nonce", x, m))) % (G1Bn254.R - 1) + 1;
        bytes memory r = G1Bn254.mulBase(k);
        uint256 e =
            ZetherTranscript.hashToScalar(keccak256(abi.encodePacked("scaas.ua.schnorr.v1", r, y, m)), G1Bn254.R);
        return bytes.concat(r, bytes32(addmod(k, mulmod(e, x, G1Bn254.R), G1Bn254.R)));
    }

    /// The group signature of `kind` over `m` by `secret` for the key `vk` (no hints).
    function _gsign(uint16 kind, uint256 secret, bytes memory vk, bytes32 m) internal returns (bytes memory) {
        if (kind == MS) return _bip340Sign(secret, m);
        if (kind == FS) return _frostSign(secret, vk, m);
        return _bnSign(secret, vk, m);
    }

    /// `target.call(data)` measured by `meter`; true iff it returned exactly `abi.encode(true)`.
    function _metered(address target, bytes memory data) internal returns (bool, uint256 used) {
        (bool ok, bytes memory ret, uint256 g) = meter.measure(target, data);
        return (ok && ret.length == 32 && abi.decode(ret, (bool)), g);
    }

    // ----- bytes -----

    function _head(bytes memory d, uint256 len) internal pure returns (bytes memory) {
        return _slice(d, 0, len);
    }

    function _slice(bytes memory b, uint256 o, uint256 len) internal pure returns (bytes memory c) {
        c = new bytes(len);
        for (uint256 i; i < len; ++i) {
            c[i] = b[o + i];
        }
    }

    function _flip(bytes memory b, uint256 i) internal pure returns (bytes memory c) {
        c = bytes.concat(b);
        c[i] = c[i] ^ 0x01;
    }

    /// Swaps the `size`-byte members at offsets `a` and `b`.
    function _swap(bytes memory d, uint256 a, uint256 b, uint256 size) internal pure returns (bytes memory c) {
        c = bytes.concat(d);
        for (uint256 i; i < size; ++i) {
            (c[a + i], c[b + i]) = (d[b + i], d[a + i]);
        }
    }
}
