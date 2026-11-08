// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";

/// Group 3f, T46 (PQZ verifier mode spec §5.1, §11.3): `smartcontracts/vectors/pqz/verdict.json`, the `PqzVerdict` digests in a
/// token's domain over the `(stmt_keccak, proof_keccak)` pairs of the build's set's `proof_pqzl.json` (real statements and
/// proofs; `REGISTER` left out: no token proof), and an EOA verifier's `UASig` over the registry's `uaAuthDigest`. Read by
/// clientkeys, ua-rs, the node and `scaas-pqz-verifier`. `WRITE_VERDICT_VECTORS=true` writes the file; otherwise every row is
/// recomputed here and compared (the pin). Fixed token, chain, `chain_uid`, registry and key: a vector, not a deployment.
contract PqzVerdictVectorsTest is Test {
    using stdJson for string;

    string internal constant OUT = "../vectors/pqz/verdict.json";
    address internal constant TOKEN = 0x7A7a7A7a7a7a7a7A7a7a7a7A7a7A7A7A7A7A7a7A;
    address internal constant REGISTRY = 0x5ca5000000000000000000000000000000000001;
    uint256 internal constant CHAIN_ID = 7622;
    bytes32 internal constant CHAIN_UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint256 internal constant VKEY = 0xA77E57;
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");

    function _sep(string memory name, string memory version, address at) internal pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), CHAIN_ID, at, CHAIN_UID));
    }

    function _hex32(string memory s) internal pure returns (bytes32) {
        return vm.parseBytes32(string.concat("0x", s));
    }

    struct Row {
        string form;
        bytes32 statementHash;
        bytes32 proofHash;
        uint32 epoch;
        uint64 validUntil;
        bytes32 structHash;
        bytes32 digest;
        bytes32 uaAuthDigest;
        bytes signature;
    }

    function _row(string memory src, uint256 i, uint32 epoch) internal pure returns (Row memory r) {
        string memory k = string.concat(".rows[", vm.toString(i), "]");
        r.form = src.readString(string.concat(k, ".form"));
        r.statementHash = _hex32(src.readString(string.concat(k, ".stmt_keccak")));
        r.proofHash = _hex32(src.readString(string.concat(k, ".proof_keccak")));
        r.epoch = epoch;
        r.validUntil = 1_800_000_000 + uint64(i);
        IPqzToken.PqzVerdict memory v = IPqzToken.PqzVerdict(TOKEN, CHAIN_ID, PqzSet.PQZL_ID, r.statementHash, r.proofHash,
            r.epoch, r.validUntil);
        r.structHash = keccak256(abi.encode(PqzCore.VERDICT_TYPEHASH, v));
        r.digest = MessageHashUtils.toTypedDataHash(_sep("SCaaS PqzToken", "1", TOKEN), r.structHash);
        r.uaAuthDigest = UAKinds.uaAuthDigest(_sep("SCaaS UARegistry", "1", REGISTRY), bytes32(uint256(uint160(vm.addr(VKEY)))),
            UAKinds.PURPOSE_PQZ_VERDICT, r.digest);
        (uint8 w, bytes32 rr, bytes32 ss) = vm.sign(VKEY, r.uaAuthDigest);
        r.signature = abi.encodePacked(rr, ss, w);
    }

    /// The build's set's `proof_pqzl.json` (`smartcontracts/vectors/pqz/` for `n2048-kmax1024`, else its `<set>/`).
    function _src() internal view returns (string memory) {
        string memory d = "../vectors/pqz/";
        if (keccak256(bytes(PqzSet.NAME)) != keccak256("n2048-kmax1024")) d = string.concat(d, PqzSet.NAME, "/");
        return vm.readFile(string.concat(d, "proof_pqzl.json"));
    }

    function _rows() internal view returns (Row[] memory rows) {
        string memory src = _src();
        uint256 n;
        while (vm.keyExistsJson(src, string.concat(".rows[", vm.toString(n), "]"))) ++n;
        uint256 m;
        for (uint256 i; i < n; ++i) {
            if (keccak256(bytes(src.readString(string.concat(".rows[", vm.toString(i), "].form")))) != keccak256("REGISTER")) ++m;
        }
        rows = new Row[](m);
        uint256 j;
        for (uint256 i; i < n; ++i) {
            if (keccak256(bytes(src.readString(string.concat(".rows[", vm.toString(i), "].form")))) == keccak256("REGISTER")) continue;
            rows[j] = _row(src, i, uint32(j % 3)); // epochs 0, 1, 2
            ++j;
        }
    }

    function _json(Row[] memory rows) internal returns (string memory out) {
        string memory arr = "[";
        for (uint256 i; i < rows.length; ++i) {
            string memory o = string.concat("r", vm.toString(i));
            vm.serializeString(o, "form", rows[i].form);
            vm.serializeBytes32(o, "statementHash", rows[i].statementHash);
            vm.serializeBytes32(o, "proofHash", rows[i].proofHash);
            vm.serializeUint(o, "pqzVerifierEpoch", rows[i].epoch);
            vm.serializeUint(o, "validUntil", rows[i].validUntil);
            vm.serializeBytes32(o, "structHash", rows[i].structHash);
            vm.serializeBytes32(o, "digest", rows[i].digest);
            vm.serializeBytes32(o, "uaAuthDigest", rows[i].uaAuthDigest);
            arr = string.concat(arr, i == 0 ? "" : ",", vm.serializeBytes(o, "signature", rows[i].signature));
        }
        arr = string.concat(arr, "]");
        string memory d = "d";
        vm.serializeString(d, "name", "SCaaS PqzToken");
        vm.serializeString(d, "version", "1");
        vm.serializeUint(d, "chainId", CHAIN_ID);
        vm.serializeAddress(d, "verifyingContract", TOKEN);
        vm.serializeBytes32(d, "salt", CHAIN_UID);
        string memory dom = vm.serializeBytes32(d, "separator", _sep("SCaaS PqzToken", "1", TOKEN));
        string memory g = "g";
        vm.serializeString(g, "name", "SCaaS UARegistry");
        vm.serializeString(g, "version", "1");
        vm.serializeUint(g, "chainId", CHAIN_ID);
        vm.serializeAddress(g, "verifyingContract", REGISTRY);
        vm.serializeBytes32(g, "salt", CHAIN_UID);
        string memory reg = vm.serializeBytes32(g, "separator", _sep("SCaaS UARegistry", "1", REGISTRY));
        string memory t = "top";
        vm.serializeString(t, "file", "pqz/verdict.json");
        vm.serializeString(t, "description",
            "Group 3f (PQZ verifier mode spec 5.1, 11.3): PqzVerdict struct hashes and digests in a PqzToken domain over the (stmt_keccak, proof_keccak) pairs of proof_pqzl.json (REGISTER left out), and the EOA verifier's 65-byte ECDSA UASig.signature over the registry's uaAuthDigest(ua, PURPOSE_PQZ_VERDICT, digest). statementHash = keccak256 of the statement bytes the token's views return; proofHash = keccak256 of the proof bytes. UNAUDITED.");
        vm.serializeString(t, "generator", "smartcontracts/evm/test/pqz/PqzVerdictVectors.t.sol (WRITE_VERDICT_VECTORS=true)");
        vm.serializeString(t, "set", PqzSet.NAME);
        vm.serializeString(t, "typeString",
            "PqzVerdict(address token,uint256 chainId,bytes32 proofSystemId,bytes32 statementHash,bytes32 proofHash,uint32 pqzVerifierEpoch,uint64 validUntil)");
        vm.serializeBytes32(t, "typehash", PqzCore.VERDICT_TYPEHASH);
        vm.serializeString(t, "purpose", "scaas.ua.purpose.pqz-verdict.v1");
        vm.serializeBytes32(t, "purposeTag", UAKinds.PURPOSE_PQZ_VERDICT);
        vm.serializeBytes32(t, "proofSystemId", PqzSet.PQZL_ID);
        vm.serializeString(t, "domain", dom);
        vm.serializeString(t, "registryDomain", reg);
        vm.serializeUint(t, "verifierKey", VKEY);
        vm.serializeBytes32(t, "verifierUA", bytes32(uint256(uint160(vm.addr(VKEY)))));
        // the rows as a JSON array (a serialized string would be quoted)
        out = vm.replace(vm.serializeString(t, "rows", "__ROWS__"), '"__ROWS__"', arr);
    }

    /// The file is the default build's set's (`set`); another set's build (`script/pqz/at-set.sh`) skips the pin.
    function test_verdictVectors() public {
        bool write = vm.envOr("WRITE_VERDICT_VECTORS", false);
        if (!write && keccak256(bytes(vm.readFile(OUT).readString(".set"))) != keccak256(bytes(PqzSet.NAME))) vm.skip(true);
        Row[] memory rows = _rows();
        assertGt(rows.length, 10);
        if (write) {
            vm.writeJson(_json(rows), OUT);
            return;
        }
        string memory pin = vm.readFile(OUT);
        assertEq(pin.readBytes32(".typehash"), PqzCore.VERDICT_TYPEHASH, "typehash");
        assertEq(pin.readBytes32(".purposeTag"), UAKinds.PURPOSE_PQZ_VERDICT, "purpose");
        assertEq(pin.readBytes32(".proofSystemId"), PqzSet.PQZL_ID, "the build's set");
        for (uint256 i; i < rows.length; ++i) {
            string memory k = string.concat(".rows[", vm.toString(i), "]");
            assertEq(pin.readBytes32(string.concat(k, ".statementHash")), rows[i].statementHash, k);
            assertEq(pin.readBytes32(string.concat(k, ".proofHash")), rows[i].proofHash, k);
            assertEq(pin.readBytes32(string.concat(k, ".structHash")), rows[i].structHash, k);
            assertEq(pin.readBytes32(string.concat(k, ".digest")), rows[i].digest, k);
            assertEq(pin.readBytes32(string.concat(k, ".uaAuthDigest")), rows[i].uaAuthDigest, k);
            assertEq(pin.readBytes(string.concat(k, ".signature")), rows[i].signature, k);
        }
        assertFalse(vm.keyExistsJson(pin, string.concat(".rows[", vm.toString(rows.length), "]")), "no extra row");
    }
}
