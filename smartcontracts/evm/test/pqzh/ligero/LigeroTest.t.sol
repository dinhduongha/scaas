// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {LigeroVerifier} from "./LigeroVerifier.sol";

/// PQZH-Ligero EVM verifier on real proofs of pqz-core/pqzh/ligero (fixtures from `ligero_export`, same bytes as
/// the Rust verifier takes): honest proofs accepted with per-stage gas, the EIP-7623 calldata floor and the
/// transaction total against the EIP-7825 cap; mutated inputs and invalid witnesses rejected.
/// Run alone: scripts/capped forge test --match-contract LigeroTest -vv   (docs/research/pqzh-ligero.md §11)
contract LigeroTest is Test {
    string internal constant DIR = "test/vectors/pqzh-ligero/";
    uint256 internal constant CAP = 16_777_216;
    uint256 internal constant Q = 4398046510889;
    LigeroVerifier internal ver;

    function setUp() public {
        bytes memory a = vm.readFileBinary(string.concat(DIR, "a.bin"));
        uint256 nc = a.length / 24_576;
        address[] memory ad = new address[](nc);
        for (uint256 c; c < nc; ++c) {
            bytes memory chunk = new bytes(24_576);
            for (uint256 i; i < 24_576; i += 32) {
                assembly {
                    mstore(add(add(chunk, 32), i), mload(add(add(a, 32), add(mul(c, 24576), i))))
                }
            }
            ad[c] = address(uint160(0xA11CE000 + c));
            vm.etch(ad[c], chunk);
        }
        ver = new LigeroVerifier(ad);
    }

    function op(string memory rel) internal pure returns (uint8) {
        return keccak256(bytes(rel)) == keccak256("reg") ? 3 : 1;
    }

    function params(string memory rel, string memory pre) internal view returns (LigeroVerifier.Params memory p) {
        bytes memory b = vm.readFileBinary(string.concat(DIR, rel, "-", pre, ".params"));
        (p.n, p.k, p.ell, p.t, p.powBits) = abi.decode(b, (uint256, uint256, uint256, uint256, uint256));
    }

    function file(string memory name) internal view returns (bytes memory) {
        return vm.readFileBinary(string.concat(DIR, name));
    }

    /// EIP-7623 tokens: zero bytes 1, other bytes 4
    function tokens(bytes memory b) internal pure returns (uint256 t) {
        for (uint256 i; i < b.length; ++i) t += b[i] == 0 ? 1 : 4;
    }

    function measure(string memory rel, string memory pre) internal {
        uint8 o = op(rel);
        LigeroVerifier.Params memory p = params(rel, pre);
        bytes memory pf = file(string.concat(rel, "-", pre, ".proof"));
        (bool ok, uint256[9] memory g) = ver.verifyProfiled(o, file(string.concat(rel, "-", pre, ".stmt")), pf, p);
        assertTrue(ok, "honest proof rejected");
        console2.log(string.concat(
            '{"rel": "', rel, '", "preset": "', pre, '", "n": ', vm.toString(p.n), ', "k": ', vm.toString(p.k),
            ', "t": ', vm.toString(p.t), ', "distinct": ', vm.toString(g[8]), ', "proof_bytes": ', vm.toString(pf.length),
            ', "verify_gas": ', vm.toString(g[7])
        ));
        console2.log(string.concat(
            '  "stages": {"stmt_seed": ', vm.toString(g[0]), ', "transcript_pow_indices": ', vm.toString(g[1]),
            ', "columns_merkle": ', vm.toString(g[2]), ', "a_copy": ', vm.toString(g[3]), ', "comb_ring": ',
            vm.toString(g[4]), ', "comb_rest_sum": ', vm.toString(g[5]), ', "column_checks": ', vm.toString(g[6]), '}'
        ));
        txLine(o, tokens(pf), g[7]);
    }

    /// tx = 21,000 + max(4 tokens + execution, 10 tokens) (EIP-7623), with the op's other calldata and execution
    /// (pq-zether.md §9.3 as pqz-core/pqzh/sol/model.py: transfer 119 k tokens, 0.31 M; register 67 k tokens, 3.45 M
    /// incl. the SSTORE2 of the key)
    function txLine(uint8 o, uint256 tk, uint256 verifyGas) internal pure {
        (uint256 otk, uint256 oex) = o == 1 ? (119_000, 310_000) : (67_000, 3_450_000);
        uint256 all = tk + otk;
        uint256 exe = verifyGas + oex;
        uint256 txg = 21_000 + (4 * all + exe > 10 * all ? 4 * all + exe : 10 * all);
        console2.log(string.concat(
            '  "tx": {"proof_tokens": ', vm.toString(tk), ', "proof_floor_7623": ', vm.toString(10 * tk),
            ', "other_tokens": ', vm.toString(otk), ', "other_exec": ', vm.toString(oex), ', "tx_std_2028": ',
            vm.toString(21_000 + 4 * all + exe), ', "tx_eip7623": ', vm.toString(txg), ', "cap": ', vm.toString(CAP),
            ', "fits": ', txg <= CAP ? "true" : "false", "}}"
        ));
    }

    function test_gas_reg_proven() public {
        measure("reg", "proven");
    }

    function test_gas_tx_proven() public {
        measure("tx", "proven");
    }

    function test_gas_reg_conj() public {
        measure("reg", "conj");
    }

    function test_gas_tx_conj() public {
        measure("tx", "conj");
    }

    function test_gas_reg_johnson() public {
        measure("reg", "johnson");
    }

    function test_gas_tx_johnson() public {
        measure("tx", "johnson");
    }

    // ---------------------------------------------------------------- negative tests
    uint256 internal rs;

    function rnd() internal returns (uint256) {
        rs ^= rs << 13;
        rs ^= rs >> 7;
        rs ^= rs << 17;
        rs &= type(uint64).max;
        return rs;
    }

    /// pqzh client::mutate kinds, adapted to this proof format (field_noncanon: an F_q element of the proof + q)
    function mutate(uint256 kind, uint8 o, bytes memory st, bytes memory pf, bytes memory other)
        internal
        returns (bytes memory s, bytes memory p)
    {
        s = bytes.concat(st);
        p = bytes.concat(pf);
        uint256 body = o == 3 ? 96 : 640;
        uint256 ncoef = (s.length - body) / 8;
        if (kind == 0) {
            uint256 b = rnd() % (8 * p.length);
            p[b / 8] ^= bytes1(uint8(1 << (b % 8)));
        } else if (kind == 1) {
            uint256 i = rnd() % p.length;
            p[i] = bytes1(uint8((uint256(uint8(p[i])) + 1 + rnd() % 255) % 256));
        } else if (kind == 2) {
            for (uint256 i; i < p.length; i += 32) {
                uint256 r = uint256(keccak256(abi.encode(rnd(), i)));
                assembly {
                    mstore(add(add(p, 32), i), r)
                }
            }
        } else if (kind == 3) {
            uint256 cut = 1 + rnd() % 64;
            assembly {
                mstore(p, sub(mload(p), cut))
            }
        } else if (kind == 4) {
            p = bytes.concat(p, abi.encodePacked(keccak256(abi.encode(rnd()))), new bytes(rnd() % 32));
        } else if (kind == 5 || kind == 6) {
            uint256 off = body + 8 * (rnd() % ncoef);
            uint64 v = uint64(bytes8(slice8(s, off)));
            uint64 nv = kind == 5 ? uint64((uint256(v) + 1) % Q) : uint64(uint256(v) + Q);
            for (uint256 i; i < 8; ++i) s[off + i] = bytes1(uint8(nv >> (56 - 8 * i)));
        } else if (kind == 7) {
            s[rnd() % 64] ^= bytes1(uint8(1 << (rnd() % 8)));
        } else if (kind == 8) {
            uint256 i = o == 3 ? 64 + rnd() % 32 : 280 + rnd() % 8;
            s[i] ^= bytes1(uint8(1 << (rnd() % 8)));
        } else if (kind == 9) {
            p = bytes.concat(other);
        } else if (kind == 10) {
            // an F_q element of w (offset 32 + 6 r) set to its value + q (non-canonical, still 6 bytes)
            uint256 off = 32 + 6 * (rnd() % 64);
            uint256 x;
            for (uint256 i; i < 6; ++i) x = x << 8 | uint8(p[off + i]);
            x += Q;
            for (uint256 i; i < 6; ++i) p[off + i] = bytes1(uint8(x >> (40 - 8 * i)));
        } else {
            p = "";
        }
    }

    function slice8(bytes memory b, uint256 o) internal pure returns (bytes8 r) {
        assembly {
            r := mload(add(add(b, 32), o))
        }
    }

    function rejects(uint8 o, bytes memory s, bytes memory p, LigeroVerifier.Params memory pp) internal view returns (bool, bool) {
        try ver.verify(o, s, p, pp) returns (bool ok) {
            return (!ok, false);
        } catch {
            return (true, true); // a revert is a rejection; counted separately
        }
    }

    function mutations(string memory rel, string memory pre, uint256 perKind) internal {
        uint8 o = op(rel);
        bytes memory st = file(string.concat(rel, "-", pre, ".stmt"));
        bytes memory pf = file(string.concat(rel, "-", pre, ".proof"));
        bytes memory other = file(string.concat(rel, "-", pre, ".other"));
        LigeroVerifier.Params memory pp = params(rel, pre);
        rs = 0x9E3779B97F4A7C15 ^ o;
        uint256 reverts;
        for (uint256 kind; kind < 12; ++kind) {
            for (uint256 i; i < perKind; ++i) {
                (bytes memory s, bytes memory p) = mutate(kind, o, st, pf, other);
                (bool rej, bool rev) = rejects(o, s, p, pp);
                assertTrue(rej, string.concat("mutation accepted, kind ", vm.toString(kind)));
                if (rev) ++reverts;
            }
        }
        // the other statement's proof verifies against its own statement (st with byte 0 flipped)
        bytes memory st2 = bytes.concat(st);
        st2[0] ^= 0x80;
        assertTrue(ver.verify(o, st2, other, pp), "other statement's proof");
        // wrong op
        (bool r2,) = rejects(o == 1 ? 3 : 1, st, pf, pp);
        assertTrue(r2);
        console2.log(string.concat(
            '{"rel": "', rel, '", "preset": "', pre, '", "mutations": ', vm.toString(12 * perKind),
            ', "accepted": 0, "reverts": ', vm.toString(reverts), "}"
        ));
    }

    function test_mutations_reg_proven() public {
        mutations("reg", "proven", 9);
    }

    function test_mutations_tx_proven() public {
        mutations("tx", "proven", 9);
    }

    function test_mutations_reg_conj() public {
        mutations("reg", "conj", 9);
    }

    function test_mutations_tx_conj() public {
        mutations("tx", "conj", 9);
    }

    function test_mutations_reg_johnson() public {
        mutations("reg", "johnson", 9);
    }

    function test_mutations_tx_johnson() public {
        mutations("tx", "johnson", 9);
    }

    /// invalid witnesses proved without the honest prover's checks (Rust tests/attacks.rs), conjectured preset
    function test_negative_witnesses() public {
        string[7] memory cases = ["reg-norm", "reg-coef", "tx-norm", "tx-digit", "tx-e2", "tx-overspend", "tx-ring"];
        for (uint256 i; i < cases.length; ++i) {
            bool reg = i < 2;
            uint8 o = reg ? 3 : 1;
            bytes memory s = file(string.concat("neg-", cases[i], ".stmt"));
            bytes memory p = file(string.concat("neg-", cases[i], ".proof"));
            (bool rej, bool rev) = rejects(o, s, p, params(reg ? "reg" : "tx", "conj"));
            assertTrue(rej, cases[i]);
            console2.log(string.concat('{"negative": "', cases[i], '", "rejected": true, "revert": ', rev ? "true" : "false", "}"));
        }
    }
}
