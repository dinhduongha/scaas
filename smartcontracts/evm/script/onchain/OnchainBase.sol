// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";

/// @notice T66b Step 5b, the base of every `script/onchain/<Group>.s.sol`: broadcastable (no cheatcode reaches the chain:
///         `vm.broadcast` / `vm.startBroadcast` with a key, `vm.sign` off chain, reads of the deploy JSON). Each group
///         writes its book `deployments/onchain-<net>-<group>.json` (address -> contract label of groups.json) for
///         `coverage.py`. Keys from the environment, never printed: ONCHAIN_K1..K3 (default the 7622 genesis test keys
///         0x…01-0x…03). ONCHAIN_NET (the target: local | scaas-testnet | <name>) names the book. Test chains only. UNAUDITED.
abstract contract OnchainBase is Script {
    bytes32 internal constant SALTED_DOMAIN =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 internal constant PLAIN_DOMAIN =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    string internal net;
    string internal group;
    string internal dj; // deployments/<chain>.json of the Step 5 deploy (DEPLOY_JSON)
    string internal bookJson;
    uint256 internal k1;
    uint256 internal k2;
    uint256 internal k3;
    address internal a1;
    address internal a2;
    address internal a3;
    uint256 internal vu; // validUntil of every signed op: now + 1 day
    bytes32 internal runSalt; // ONCHAIN_SALT: a fresh salt per run (CREATE2 / factory salts, pay salts)

    function _init(string memory g) internal {
        group = g;
        net = vm.envOr("ONCHAIN_NET", string("local"));
        dj = vm.readFile(vm.envOr("DEPLOY_JSON", string("deployments/7622.json")));
        k1 = vm.envOr("ONCHAIN_K1", uint256(1));
        k2 = vm.envOr("ONCHAIN_K2", uint256(2));
        k3 = vm.envOr("ONCHAIN_K3", uint256(3));
        (a1, a2, a3) = (vm.addr(k1), vm.addr(k2), vm.addr(k3));
        vu = block.timestamp + 1 days;
        runSalt = keccak256(abi.encode("scaas.onchain.t66b-5b", g, vm.envOr("ONCHAIN_SALT", uint256(block.number))));
        if (vm.exists(_negFile())) vm.removeFile(_negFile());
    }

    /// @dev An address of the Step 5 deploy JSON.
    function _dep(string memory key) internal view returns (address) {
        return vm.parseJsonAddress(dj, string.concat(".", key));
    }

    /// @dev A negative: `from` calling `to` with `data` must be refused with `expected` (the error selector). The script
    ///      only lists it (deployments/onchain-<net>-<group>-neg.txt); `coverage.py neg` runs each by eth_call on the node
    ///      after the broadcast, against the final state, and records the refusal it got.
    function _neg(address from, address to, bytes memory data, bytes4 expected, string memory what) internal {
        vm.writeLine(_negFile(), string.concat(vm.toString(from), " ", vm.toString(to), " ", vm.toString(data), " ",
            vm.toString(abi.encodePacked(expected)), " ", what));
    }

    /// @dev `_neg` with the whole revert data expected (the error and its arguments), where the arguments are fixed.
    function _negData(address from, address to, bytes memory data, bytes memory expected, string memory what) internal {
        vm.writeLine(_negFile(), string.concat(vm.toString(from), " ", vm.toString(to), " ", vm.toString(data), " ",
            vm.toString(expected), " ", what));
    }

    function _negFile() internal view returns (string memory) {
        return string.concat("deployments/onchain-", net, "-", group, "-neg.txt");
    }

    function _book(address a, string memory label) internal {
        bookJson = vm.serializeString(string.concat("book-", group), vm.toString(a), label);
    }

    function _writeBook() internal {
        vm.writeJson(bookJson, string.concat("deployments/onchain-", net, "-", group, ".json"));
    }

    function _salt(string memory what) internal view returns (bytes32) {
        return keccak256(abi.encode(runSalt, what));
    }

    function _pad(address a) internal pure returns (bytes32) {
        return MetaTxLib.pad(a);
    }

    /// @dev The EIP-712 domain separator of `c` from its ERC-5267 view (salted when it has a salt).
    function _domain(address c) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) = IERC5267(c).eip712Domain();
        if (salt == 0) {
            return keccak256(abi.encode(PLAIN_DOMAIN, keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc));
        }
        return keccak256(abi.encode(SALTED_DOMAIN, keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt));
    }

    function _digest(address c, bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", _domain(c), structHash));
    }

    function _ecdsa(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    /// @dev A native id's `UASig`: its own ECDSA signature, no key data, no members.
    function _sig(uint256 pk, bytes32 d) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = _ecdsa(pk, d);
    }

    /// @dev A `UAEnvelope` from the native id of `from`, open mode, no fee.
    function _env(address from, uint256 batch, uint256 nonce) internal view returns (MetaTxLib.UAEnvelope memory e) {
        (e.from, e.batch, e.nonce, e.validUntil) = (_pad(from), batch, nonce, vu);
    }

    /// @dev The address `Envelope` twin of `_env`.
    function _aenv(address from, uint256 batch, uint256 nonce) internal view returns (MetaTxLib.Envelope memory e) {
        (e.from, e.batch, e.nonce, e.validUntil) = (from, batch, nonce, vu);
    }

    /// @dev The digest of a named entry (TS-D14) on `c`: `typ` is the struct's type string, `args` the ABI words of the op's own
    ///      fields between `from` and `batch` (a dynamic field already hashed), relayer / fee recipient canonical
    ///      (`MetaTxLib.canon`: 0 unless the mode binds them).
    function _named(address c, string memory typ, bytes memory args, MetaTxLib.UAEnvelope memory e)
        internal view returns (bytes32)
    {
        return _digest(c, keccak256(bytes.concat(keccak256(bytes(typ)), e.from, args, _tail(e.batch, e.nonce, e.validUntil,
            e.mode, e.relayer, e.fee, e.feeRecipient))));
    }

    function _namedA(address c, string memory typ, bytes memory args, MetaTxLib.Envelope memory e)
        internal view returns (bytes32)
    {
        return _digest(c, keccak256(bytes.concat(keccak256(bytes(typ)), abi.encode(e.from), args, _tail(e.batch, e.nonce,
            e.validUntil, e.mode, e.relayer, e.fee, e.feeRecipient))));
    }

    function _tail(uint256 batch, uint256 nonce, uint256 validUntil, uint32 mode, address relayer, uint256 fee, address feeTo)
        internal pure returns (bytes memory)
    {
        address r = mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 ? relayer : address(0);
        address f = mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT != 0 ? feeTo : address(0);
        return abi.encode(batch, nonce, validUntil, mode, r, fee, f);
    }

    /// @dev A `PayMeta` (salt from `seed`) and its id (`metaPayId`, IMetaTokenV2): the pay entries' `entryRef`.
    function _meta(bytes32 seed, bytes32 payNo, bool save) internal view returns (MetaTxLib.PayMeta memory m) {
        m.salt = keccak256(abi.encode(runSalt, "paymeta", seed));
        (m.payNo, m.save) = (payNo, save);
    }

    function _metaId(MetaTxLib.PayMeta memory m) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("scaas.pay.meta.v3", m.salt, keccak256(abi.encode(m.payNo, m.save, m.schema, m.body))));
    }
}
