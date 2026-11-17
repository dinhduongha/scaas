// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../../src/ua/UARegistry.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {UAMldsaVerifier} from "../../../src/ua/MlDsa.sol";
import {UARegistryBase} from "../../../test/ua/UARegistryBase.sol";

/// The execution gas of one call, measured inside its own transaction (no intrinsic gas, no calldata floor: those depend on the
/// arguments only and hide the library's cost on the larger rows).
contract GasProbe {
    function measure(address target, bytes calldata data) external returns (uint256 used) {
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = target.call(data);
        used = g - gasleft();
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }
}

/// T66b 3.1c (owner 2026-11-09, spec §11 (f)): the gas of every `UARegistryAuxLib` entry, each its own transaction (`isolate`)
/// through `GasProbe` (the registry call's execution gas, cold accounts included), on the registry's public ABI only, so the same file runs on the 3.1b tree (old) and the 3.1c tree (new).
/// Fixture: the mock verifier on the PQ kinds and 0x0142, an `mldsa44` UA; `cacheExpandedKey` on the real `mldsa44` verifier.
/// Prints `AUXGAS|<row>|<gasTotalUsed>`. Measurement only, no pin. UNAUDITED.
contract AuxGasTest is UARegistryBase {
    address internal constant REG_G = 0x5Ca0000000000000000000000000000000000c32;

    GasProbe internal probe;

    function _row(string memory name, address target, bytes memory data) internal {
        uint256 used = probe.measure(target, data);
        emit log_string(string.concat("AUXGAS|", name, "|", vm.toString(used)));
    }

    function test_auxGas() public {
        probe = new GasProbe();
        uint16[8] memory ks = [uint16(0x0101), 0x0130, 0x0131, 0x0132, 0x0133, 0x0134, 0x0135, 0x0142];
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](8);
        for (uint256 i; i < 8; ++i) c[i] = UARegistry.KindConfig(ks[i], address(mock), i == 0 ? 400_000 : 4_250_000);
        UARegistry r = _deploy(REG_G, chainUidA, address(0), false, BUDGET, address(0), true, c);
        bytes memory pk = new bytes(1312);
        for (uint256 i; i < pk.length; ++i) pk[i] = bytes1(uint8(i * 7 + 1));
        bytes32 ua = _register(r, UAKinds.MLDSA44, pk);

        IUARegistry.KemKey memory k = IUARegistry.KemKey(UAKinds.KEM_SCHEME_MLKEM1024_X25519, new bytes(1568), bytes32(uint256(1)));
        IUARegistry.UASig memory s;
        s.signature = _sig(pk, UAKinds.uaMessage(UAKinds.MLDSA44, UAKinds.PURPOSE_KEM,
            UAKinds.kemRecordDigest(ua, 1, UAKinds.kemPk(k))));
        _row("setKemKey mldsa44 v1", address(r), abi.encodeCall(UARegistry.setKemKey, (ua, 1, k, s)));

        bytes memory key = new bytes(16_384);
        for (uint256 i; i < key.length; i += 32) key[i] = bytes1(uint8(i >> 5) | 1);
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key);
        bytes memory pqzPop = _sig(key, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyDigest(ua, h)));
        IUARegistry.UASig memory ps;
        ps.signature = _sig(pk, UAKinds.uaMessage(UAKinds.MLDSA44, UAKinds.PURPOSE_PQZ_KEY,
            UAKinds.pqzKeyRecordDigest(ua, h, keccak256(pqzPop))));
        _row("setPqzKey mldsa44 v0 (16,384 B key)", address(r), abi.encodeCall(UARegistry.setPqzKey, (ua, 0, key, keccak256(pqzPop), ps)));
        _row("storePqzPop mldsa44 v0 (proven by the mock)", address(r), abi.encodeCall(UARegistry.storePqzPop, (ua, 0, pqzPop)));
        _row("storePqzPop again (no-op)", address(r), abi.encodeCall(UARegistry.storePqzPop, (ua, 0, pqzPop)));

        _row("registrationOf mldsa44", address(r), abi.encodeCall(UARegistry.registrationOf, (ua)));
        _row("uaCount", address(r), abi.encodeCall(UARegistry.uaCount, (UAKinds.MLDSA44)));
        _row("uaAt", address(r), abi.encodeCall(UARegistry.uaAt, (UAKinds.MLDSA44, 0)));
        _row("uaPage", address(r), abi.encodeCall(UARegistry.uaPage, (UAKinds.MLDSA44, 0, 4)));
        _row("uaIndex", address(r), abi.encodeCall(UARegistry.uaIndex, (ua)));
        _row("popOf mldsa44", address(r), abi.encodeCall(UARegistry.popOf, (ua)));
        _row("popSlotsOf (no msig)", address(r), abi.encodeCall(UARegistry.popSlotsOf, (ua)));
        _row("webAuthnKeyOf (other kind)", address(r), abi.encodeCall(UARegistry.webAuthnKeyOf, (ua)));
        _row("pqzPopOf v0", address(r), abi.encodeCall(UARegistry.pqzPopOf, (ua, 0)));
        _row("pqzKeySigOf v0", address(r), abi.encodeCall(UARegistry.pqzKeySigOf, (ua, 0)));
        // 3.1d: the five `*Digest` views (`_libPure`), core -> Aux library
        bytes32 x = keccak256("x");
        _row("registrationDigest", address(r), abi.encodeCall(UARegistry.registrationDigest, (ua, UAKinds.MLDSA44, x, x, x)));
        _row("portableRecordDigest", address(r), abi.encodeCall(UARegistry.portableRecordDigest, (ua, UAKinds.MLDSA44, x, x)));
        _row("pqzKeyRecordDigest", address(r), abi.encodeCall(UARegistry.pqzKeyRecordDigest, (ua, x, x)));
        _row("pqzKeyVersionDigest", address(r), abi.encodeCall(UARegistry.pqzKeyVersionDigest, (ua, 2, x)));
        _row("pqzKeyVersionRecordDigest", address(r), abi.encodeCall(UARegistry.pqzKeyVersionRecordDigest, (ua, 2, x, x)));

        UARegistry.KindConfig[] memory c2 = new UARegistry.KindConfig[](2);
        c2[0] = UARegistry.KindConfig(0x0101, address(mock), 400_000);
        c2[1] = UARegistry.KindConfig(UAKinds.MLDSA44, address(new UAMldsaVerifier(UAKinds.MLDSA44, address(0), "", "")), 4_250_000);
        UARegistry r2 = _deploy(address(uint160(REG_G) + 1), chainUidA, address(0), false, BUDGET, address(0), true, c2);
        _row("cacheExpandedKey mldsa44 part 0", address(r2), abi.encodeCall(UARegistry.cacheExpandedKey, (UAKinds.MLDSA44, pk, 0)));
    }
}
