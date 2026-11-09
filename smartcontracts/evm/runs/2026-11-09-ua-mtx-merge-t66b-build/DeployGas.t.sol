// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindModuleNames, kindImplArgs} from "../../script/KindModules.sol";
import {ImplArgs} from "../../src/metatx/ITokenModule.sol";
import {Test, Vm} from "forge-std/Test.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {SmartKeyAccount} from "../../src/account/SmartKeyAccount.sol";
import {MandateWallet} from "../../src/wallet/MandateWallet.sol";
import {HederaMandateWallet} from "../../src/hedera/HederaMandateWallet.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {WrappedLib} from "../../src/metatx/WrappedLib.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";
import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {ZetherLib} from "../../src/zether/ZetherLib.sol";
import {ZetherWrappedLib} from "../../src/zether/ZetherWrappedLib.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {PqzViewLib} from "../../src/pqz/PqzViewLib.sol";
import {PqzTransferLib} from "../../src/pqz/PqzTransferLib.sol";
import {PqzBurnLib} from "../../src/pqz/PqzBurnLib.sol";
import {PqzStateLib} from "../../src/pqz/PqzStateLib.sol";
import {PqzWrappedLib} from "../../src/pqz/PqzWrappedLib.sol";
import {NormalRegulatedToken} from "../../src/regulated/NormalRegulatedToken.sol";
import {WrappedRegulatedToken} from "../../src/regulated/WrappedRegulatedToken.sol";
import {NormalZetherRegulatedToken} from "../../src/regulated/NormalZetherRegulatedToken.sol";
import {WrappedZetherRegulatedToken} from "../../src/regulated/WrappedZetherRegulatedToken.sol";
import {NormalPqzRegulatedToken} from "../../src/regulated/NormalPqzRegulatedToken.sol";
import {WrappedPqzRegulatedToken} from "../../src/regulated/WrappedPqzRegulatedToken.sol";
import {RegulatedLib} from "../../src/regulated/RegulatedLib.sol";
import {ComplianceRegistry} from "../../src/regulated/ComplianceRegistry.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {TradeLib} from "../../src/trade/TradeLib.sol";
import {HederaLib} from "../../src/hedera/HederaLib.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UARegistryCoreLib} from "../../src/ua/UARegistryCoreLib.sol";
import {UARegistryAuxLib} from "../../src/ua/UARegistryAuxLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {regArgs} from "../../test/helpers/Catalogue.sol";
import {DeployHarness} from "../../test/helpers/DeployHarness.sol";
import {ZUID} from "../../test/zether/helpers/ZetherFixture.sol";

/// A verifier stand-in: code, nothing else (the registry's constructor checks only that a verifier has code).
contract VerifierStandIn {
    function verify(bytes calldata, bytes32, bytes calldata) external pure returns (bool) {
        return false;
    }
}

contract T66bCreate2Probe {
    function deploy(bytes calldata code, bytes32 salt) external returns (address a) {
        bytes memory c = code;
        assembly ("memory-safe") { a := create2(0, add(c, 32), mload(c), salt) }
    }
}

/// @notice ua-mtx-merge T66b Step 1: every deployed contract's deploy gas at the tip after 3h, by T10's public-gate formula.
///         Each contract is its own CREATE2 transaction through a probe (the T33 / T51 method): regular =
///         `lastCallGas.gasTotalUsed` x 64/63, state = EIP-8037's, asked = (regular + state) x 1.05, against 57 M / 60 M /
///         70 M and regular x 1.05 < 2^24 (EIP-7825). The probe call is a top-level call of the test, so under `isolate` it is
///         its own transaction: the intrinsic gas and the calldata (with the EIP-7976 floor) are in `gasTotalUsed`.
///         Releases carry their constructor arguments as GovDeploy's `test_releaseGasPerKind`; the registry DeployBase's
///         gen-1 list as T51 (19 kinds, verifier stand-ins, budget 12 M). A release's factory frame is
///         `test_t66bReleaseFrame`'s. Forge gas is deterministic: a measurement of gas used, not a timing calibration.
///         Line: `T66B | name | runtime | init | regular | state | asked | regular x 1.05 < 2^24`.
contract T66bDeployGasTest is Test {
    bytes32 constant UID = keccak256("scaas-testnet");
    T66bCreate2Probe probe;
    uint256 salt;

    function _m(string memory name, bytes memory code) internal returns (address a) {
        a = probe.deploy(code, bytes32(++salt));
        Vm.Gas memory g = vm.lastCallGas();
        assertTrue(a != address(0), name);
        _line(name, a.code.length, code, g.gasTotalUsed * 64 / 63, uint256(int256(g.gasStateUsed)));
    }

    function _line(string memory name, uint256 runtime, bytes memory code, uint256 regular, uint256 state) internal {
        string memory s = string.concat("T66B | ", name, " | ", vm.toString(runtime), " | ", vm.toString(code.length), " | ");
        s = string.concat(s, vm.toString(regular), " | ", vm.toString(state), " | ");
        s = string.concat(s, vm.toString((regular + state) * 105 / 100), " | ");
        emit log(string.concat(s, regular * 105 / 100 < 1 << 24 ? "yes" : "NO"));
    }

    /// T66b §4.5: the kind's body modules first (each its own transaction, a row each), then the release naming them.
    function _rel(bytes memory code, IOpenFactory.TokenKind kind) internal returns (bytes memory) {
        bytes memory core = uint8(kind) >= 8 ? regArgs() : bytes("");
        string[] memory n = kindModuleNames(uint8(kind));
        address[] memory ms = new address[](n.length);
        for (uint256 i; i < n.length; ++i) {
            ms[i] = _m(vm.split(n[i], ":")[1], bytes.concat(vm.getCode(n[i]), abi.encode(address(this), core)));
        }
        return abi.encodePacked(code, abi.encode(address(this), kindImplArgs(uint8(kind), ms, core)));
    }

    /// The DEX's admin module D (its own transaction), then the DEX release naming it.
    function _dex() internal returns (bytes memory) {
        address[] memory ms = new address[](1);
        ms[0] = _m("SCaaSDexD", bytes.concat(vm.getCode("SCaaSDexAdmin.sol:SCaaSDexD"), abi.encode(address(this), bytes(""))));
        return abi.encodePacked(type(SCaaSDex).creationCode, abi.encode(address(this), abi.encode(ImplArgs(ms))));
    }

    function test_t66bDeployGas() public {
        probe = new T66bCreate2Probe();
        address ska = new SmartKeyAccountFactory(UID).IMPLEMENTATION();
        // the releases (kinds 0-5, 8-13) and the dex
        _m("NormalToken", _rel(type(NormalToken).creationCode, IOpenFactory.TokenKind.NORMAL));
        _m("WrappedToken", _rel(type(WrappedToken).creationCode, IOpenFactory.TokenKind.WRAPPED));
        _m("NormalZetherToken", _rel(type(NormalZetherToken).creationCode, IOpenFactory.TokenKind.NORMAL_ZETHER));
        _m("WrappedZetherToken", _rel(type(WrappedZetherToken).creationCode, IOpenFactory.TokenKind.WRAPPED_ZETHER));
        _m("NormalPqzToken", _rel(type(NormalPqzToken).creationCode, IOpenFactory.TokenKind.NORMAL_PQZ));
        _m("WrappedPqzToken", _rel(type(WrappedPqzToken).creationCode, IOpenFactory.TokenKind.WRAPPED_PQZ));
        _m("NormalRegulatedToken", _rel(type(NormalRegulatedToken).creationCode, IOpenFactory.TokenKind.NORMAL_REGULATED));
        _m("WrappedRegulatedToken", _rel(type(WrappedRegulatedToken).creationCode, IOpenFactory.TokenKind.WRAPPED_REGULATED));
        _m("NormalZetherRegulatedToken",
            _rel(type(NormalZetherRegulatedToken).creationCode, IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED));
        _m("WrappedZetherRegulatedToken",
            _rel(type(WrappedZetherRegulatedToken).creationCode, IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED));
        _m("NormalPqzRegulatedToken",
            _rel(type(NormalPqzRegulatedToken).creationCode, IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED));
        _m("WrappedPqzRegulatedToken",
            _rel(type(WrappedPqzRegulatedToken).creationCode, IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED));
        _m("SCaaSDex", _dex());
        // the chain's own contracts
        _m("GovernanceRouter", abi.encodePacked(type(GovernanceRouter).creationCode, abi.encode(UID, address(this), ska, false)));
        _m("OpenFactory", abi.encodePacked(type(OpenFactory).creationCode, abi.encode(address(this))));
        _m("RelayFeeRouter", type(RelayFeeRouter).creationCode);
        _m("ComplianceRegistry", abi.encodePacked(type(ComplianceRegistry).creationCode, abi.encode(address(probe))));
        _m("SmartKeyAccountFactory", abi.encodePacked(type(SmartKeyAccountFactory).creationCode, abi.encode(UID)));
        // the wallets (4.4: each its own transaction; the SmartKeyAccount implementation is also inside the factory's row)
        _m("SmartKeyAccount", abi.encodePacked(type(SmartKeyAccount).creationCode, abi.encode(UID)));
        _m("MandateWallet", abi.encodePacked(type(MandateWallet).creationCode, abi.encode(bytes32(uint256(1)), UID, address(0), false)));
        _m("HederaMandateWallet",
            abi.encodePacked(type(HederaMandateWallet).creationCode, abi.encode(bytes32(uint256(1)), UID, address(0))));
        // every library with external functions (each its own transaction)
        _m("UARegistryCoreLib", type(UARegistryCoreLib).creationCode);
        _m("UARegistryAuxLib", type(UARegistryAuxLib).creationCode);
        _m("ZetherLib", type(ZetherLib).creationCode);
        _m("PqzTransferLib", type(PqzTransferLib).creationCode);
        _m("PqzViewLib", type(PqzViewLib).creationCode);
        _m("WrappedLib", type(WrappedLib).creationCode);
        _m("PqzBurnLib", type(PqzBurnLib).creationCode);
        _m("GovernanceLib", type(GovernanceLib).creationCode);
        _m("PqzStateLib", type(PqzStateLib).creationCode);
        _m("ZetherWrappedLib", type(ZetherWrappedLib).creationCode);
        _m("MtxPipelineLib", type(MtxPipelineLib).creationCode);
        _m("RegulatedLib", type(RegulatedLib).creationCode);
        _m("PqzWrappedLib", type(PqzWrappedLib).creationCode);
        _m("TradeLib", type(TradeLib).creationCode);
        _m("HederaLib", type(HederaLib).creationCode);
        _registry();
    }

    /// Tasks 3.1 and 3.1b: the registry and its libraries alone (R-1; the two libraries by domain).
    function test_t66bPair() public {
        probe = new T66bCreate2Probe();
        _m("UARegistryCoreLib", type(UARegistryCoreLib).creationCode);
        _m("UARegistryAuxLib", type(UARegistryAuxLib).creationCode);
        _registry();
    }

    /// The registry, DeployBase's gen-1 list as T51 measured it.
    function _registry() internal {
        address v = address(new VerifierStandIn());
        uint16[19] memory kinds = [UAKinds.WEBAUTHN_P256, UAKinds.P256, UAKinds.ED25519, UAKinds.BIP340, UAKinds.SECP256K1,
            UAKinds.SCHNORR_BN254, UAKinds.SCHNORR_BLS12381, UAKinds.BLS12381_MINSIG, UAKinds.BLS_BN254_MINSIG,
            UAKinds.MUSIG2_SECP256K1, UAKinds.FROST_SECP256K1, UAKinds.MUSIG2_BN254, UAKinds.FROST_BN254,
            UAKinds.ZETHER_BLS12381, UAKinds.MLDSA44, UAKinds.MLDSA65, UAKinds.FNDSA512, UAKinds.SLHDSA128S, UAKinds.FNDSA1024];
        uint64[19] memory caps = [uint64(400_000), 400_000, 210_000, 50_000, 50_000, 50_000, 70_000, 200_000, 345_000, 50_000,
            50_000, 50_000, 50_000, 70_000, 4_250_000, 5_950_000, 2_500_000, 1_400_000, 5_250_000];
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](19);
        for (uint256 i; i < 19; ++i) k[i] = UARegistry.KindConfig(kinds[i], v, caps[i]);
        _m("UARegistry", abi.encodePacked(type(UARegistry).creationCode,
            abi.encode(UID, address(0), false, uint64(12_000_000), address(0), true, k)));
    }

    /// The factory frame of a release: `deployImplementation` as its own transaction (the registrar's, version 2 of a
    /// kind DeployBase released as version 1) against the probe's CREATE2 of the same init code; both include the
    /// intrinsic gas and calldata of their transaction (`isolate`), so the difference is the frame (the closure's code-hash
    /// checks, `_checkImplementation`, the release record, the event).
    function test_t66bReleaseFrame() public {
        probe = new T66bCreate2Probe();
        address ska = new SmartKeyAccountFactory(ZUID).IMPLEMENTATION();
        DeployHarness h = new DeployHarness();
        (OpenFactory f,) = h.deploy(ZUID, false, ska);
        bytes memory code = type(NormalToken).creationCode;
        // T66b: version 2 names version 1's body modules, pinned in env 1 by DeployBase
        bytes memory args = abi.encode(ImplArgs(NormalToken(f.implementationOf(IOpenFactory.TokenKind.NORMAL, 1)).modules()));
        probe.deploy(abi.encodePacked(code, abi.encode(address(f), args)), bytes32(uint256(7)));
        Vm.Gas memory p = vm.lastCallGas();
        vm.prank(address(h));
        f.deployImplementation(IOpenFactory.TokenKind.NORMAL, 2, 1, code, args);
        Vm.Gas memory r = vm.lastCallGas();
        uint256 pr = p.gasTotalUsed * 64 / 63;
        uint256 rr = r.gasTotalUsed * 64 / 63;
        uint256 ps = uint256(int256(p.gasStateUsed));
        uint256 rs = uint256(int256(r.gasStateUsed));
        emit log(string.concat("FRAME | NormalToken | probe ", vm.toString(pr), " + ", vm.toString(ps), " | deployImplementation ",
            vm.toString(rr), " + ", vm.toString(rs), " | frame x1.05 ", vm.toString(((rr + rs) - (pr + ps)) * 105 / 100)));
    }
}
