// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";

/// Owner 2026-11-12, Fable recheck 2 P3-7 (NODE-JOB-26): `smartcontracts/vectors/factory/create_config.json` pins a creation's
/// named config against the contracts' own structs: its `initArgs` is `abi.encode` of `IFactoryToken.TokenConfig` /
/// `ISCaaSDex.DexConfig` built here, `initHash` its keccak, and every named field of `config` equals the struct's field of that
/// name. A field added, removed, retyped or moved in Solidity fails here (or does not compile) until the vector is rewritten:
/// `WRITE_CREATE_CONFIG_KAT=true forge test --match-path test/factory/CreateConfigKat.t.sol`. Read by `scaas-node` and
/// `clientkeys`. **UNAUDITED.**
contract CreateConfigKatTest is Test {
    string constant KAT = "../vectors/factory/create_config.json";

    function _token() internal pure returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals, c.features, c.lockedFeatures) = ("Named", "NMD", 6, 1, 2);
        c.admin = _w(0xad);
        c.roles.minter = _w(0x01);
        c.roles.rateAdmin = _w(0x02);
        c.roles.guardian = _w(0x03);
        c.roles.issuer = _w(0x04);
        c.roles.compliance = _w(0x05);
        (c.initialSupply, c.initialHolder) = (1000, _a(0x40));
        c.legs = new IFactoryToken.Leg[](2);
        c.legs[0] = IFactoryToken.Leg(_a(0x11), 1, 2);
        c.legs[1] = IFactoryToken.Leg(_a(0x12), 3, 4);
        c.rate = IFactoryToken.RateConfig(172_800, 1000);
        c.conf.auditorKey = hex"0102";
        (c.conf.shieldScale, c.conf.maxShielded, c.conf.confidentialFee) = (10, 1_000_000, 5);
        (c.conf.disclosureMode, c.conf.auditorMode, c.conf.minDecoyFee) = (1, 2, 6);
        (c.conf.pqzVerifyMode, c.conf.pqzVerifierUA, c.conf.pqzVerifierFixed) = (1, _w(0x99), true);
        (c.conf.proofStore, c.conf.verifierFee, c.conf.verifierFeeMax) = (1, 7, 9);
        (c.grantDelay, c.rescueTo, c.maxSupply) = (3600, _a(0x5e), 5000);
        c.reg = IFactoryToken.RegulatedParams(_a(0xc0), 3, 4, _w(0x7e), _w(0x7a));
    }

    function _dex() internal pure returns (ISCaaSDex.DexConfig memory d) {
        d = ISCaaSDex.DexConfig(_w(0xad), 1000, _a(0x7e), true, 3600, _a(0x5e));
    }

    function _w(uint8 b) internal pure returns (bytes32) {
        return bytes32(type(uint256).max / 255 * b);
    }

    function _a(uint8 b) internal pure returns (address) {
        return address(uint160(type(uint160).max / 255 * b));
    }

    function test_createConfigKat() public {
        bytes memory t = abi.encode(_token());
        bytes memory d = abi.encode(_dex());
        if (vm.envOr("WRITE_CREATE_CONFIG_KAT", false)) {
            vm.writeJson(string.concat('"', vm.toString(t), '"'), KAT, ".token.initArgs");
            vm.writeJson(string.concat('"', vm.toString(keccak256(t)), '"'), KAT, ".token.initHash");
            vm.writeJson(string.concat('"', vm.toString(d), '"'), KAT, ".dex.initArgs");
            vm.writeJson(string.concat('"', vm.toString(keccak256(d)), '"'), KAT, ".dex.initHash");
        }
        string memory j = vm.readFile(KAT);
        assertEq(vm.parseJsonBytes(j, ".token.initArgs"), t, "token initArgs");
        assertEq(vm.parseJsonBytes32(j, ".token.initHash"), keccak256(t), "token initHash");
        assertEq(vm.parseJsonBytes(j, ".dex.initArgs"), d, "dex initArgs");
        assertEq(vm.parseJsonBytes32(j, ".dex.initHash"), keccak256(d), "dex initHash");
        _namedToken(j, _token());
        _namedDex(j, _dex());
    }

    /// The vector's named `config` is the struct, field by field, by the struct's own field names.
    function _namedToken(string memory j, IFactoryToken.TokenConfig memory c) internal view {
        string memory p = ".token.config.";
        assertEq(vm.parseJsonString(j, string.concat(p, "name")), c.name);
        assertEq(vm.parseJsonString(j, string.concat(p, "symbol")), c.symbol);
        assertEq(vm.parseJsonUint(j, string.concat(p, "decimals")), c.decimals);
        assertEq(vm.parseJsonUint(j, string.concat(p, "features")), c.features);
        assertEq(vm.parseJsonUint(j, string.concat(p, "lockedFeatures")), c.lockedFeatures);
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "admin")), c.admin);
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "roles.minter")), c.roles.minter);
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "roles.rateAdmin")), c.roles.rateAdmin);
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "roles.guardian")), c.roles.guardian);
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "roles.issuer")), c.roles.issuer);
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "roles.compliance")), c.roles.compliance);
        assertEq(vm.parseJsonUint(j, string.concat(p, "initialSupply")), c.initialSupply);
        assertEq(vm.parseJsonAddress(j, string.concat(p, "initialHolder")), c.initialHolder);
        for (uint256 i; i < c.legs.length; ++i) {
            string memory l = string.concat(p, "legs[", vm.toString(i), "].");
            assertEq(vm.parseJsonAddress(j, string.concat(l, "underlying")), c.legs[i].underlying);
            assertEq(vm.parseJsonUint(j, string.concat(l, "num")), c.legs[i].num);
            assertEq(vm.parseJsonUint(j, string.concat(l, "den")), c.legs[i].den);
        }
        assertFalse(vm.keyExistsJson(j, string.concat(p, "legs[", vm.toString(c.legs.length), "]")), "no extra leg");
        assertEq(vm.parseJsonUint(j, string.concat(p, "rate.rateDelay")), c.rate.rateDelay);
        assertEq(vm.parseJsonUint(j, string.concat(p, "rate.maxRateStepBps")), c.rate.maxRateStepBps);
        assertEq(vm.parseJsonBytes(j, string.concat(p, "conf.auditorKey")), c.conf.auditorKey);
        assertEq(vm.parseJsonUint(j, string.concat(p, "conf.shieldScale")), c.conf.shieldScale);
        assertEq(vm.parseJsonUint(j, string.concat(p, "conf.maxShielded")), c.conf.maxShielded);
        assertEq(vm.parseJsonUint(j, string.concat(p, "conf.confidentialFee")), c.conf.confidentialFee);
        assertEq(vm.parseJsonUint(j, string.concat(p, "conf.disclosureMode")), c.conf.disclosureMode);
        assertEq(vm.parseJsonUint(j, string.concat(p, "conf.auditorMode")), c.conf.auditorMode);
        assertEq(vm.parseJsonUint(j, string.concat(p, "conf.minDecoyFee")), c.conf.minDecoyFee);
        assertEq(vm.parseJsonUint(j, string.concat(p, "conf.pqzVerifyMode")), c.conf.pqzVerifyMode);
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "conf.pqzVerifierUA")), c.conf.pqzVerifierUA);
        assertEq(vm.parseJsonBool(j, string.concat(p, "conf.pqzVerifierFixed")), c.conf.pqzVerifierFixed);
        assertEq(vm.parseJsonUint(j, string.concat(p, "conf.proofStore")), c.conf.proofStore);
        assertEq(vm.parseJsonUint(j, string.concat(p, "conf.verifierFee")), c.conf.verifierFee);
        assertEq(vm.parseJsonUint(j, string.concat(p, "conf.verifierFeeMax")), c.conf.verifierFeeMax);
        assertEq(vm.parseJsonUint(j, string.concat(p, "grantDelay")), c.grantDelay);
        assertEq(vm.parseJsonAddress(j, string.concat(p, "rescueTo")), c.rescueTo);
        assertEq(vm.parseJsonUint(j, string.concat(p, "maxSupply")), c.maxSupply);
        assertEq(vm.parseJsonAddress(j, string.concat(p, "reg.complianceRegistry")), c.reg.complianceRegistry);
        assertEq(vm.parseJsonUint(j, string.concat(p, "reg.requiredFlags")), c.reg.requiredFlags);
        assertEq(vm.parseJsonUint(j, string.concat(p, "reg.deniedFlags")), c.reg.deniedFlags);
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "reg.termsHash")), c.reg.termsHash);
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "reg.taxRecipient")), c.reg.taxRecipient);
    }

    function _namedDex(string memory j, ISCaaSDex.DexConfig memory d) internal view {
        string memory p = ".dex.config.";
        assertEq(vm.parseJsonBytes32(j, string.concat(p, "admin")), d.admin);
        assertEq(vm.parseJsonUint(j, string.concat(p, "relayerSharePpm")), d.relayerSharePpm);
        assertEq(vm.parseJsonAddress(j, string.concat(p, "treasury")), d.treasury);
        assertEq(vm.parseJsonBool(j, string.concat(p, "listedOnly")), d.listedOnly);
        assertEq(vm.parseJsonUint(j, string.concat(p, "grantDelay")), d.grantDelay);
        assertEq(vm.parseJsonAddress(j, string.concat(p, "rescueTo")), d.rescueTo);
    }
}
