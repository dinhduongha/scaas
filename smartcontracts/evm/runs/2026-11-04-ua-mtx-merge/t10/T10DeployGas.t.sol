// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {OpenFactory} from "../../../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../../src/factory/IFactoryToken.sol";
import {GovernanceRouter} from "../../../../src/governance/GovernanceRouter.sol";
import {SmartKeyAccountFactory} from "../../../../src/account/SmartKeyAccountFactory.sol";
import {NormalToken} from "../../../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../../../src/metatx/WrappedToken.sol";
import {NormalZetherToken} from "../../../../src/zether/NormalZetherToken.sol";
import {WrappedZetherToken} from "../../../../src/zether/WrappedZetherToken.sol";
import {NormalPqzToken} from "../../../../src/pqz/NormalPqzToken.sol";
import {WrappedPqzToken} from "../../../../src/pqz/WrappedPqzToken.sol";
import {SCaaSDex} from "../../../../src/dex/SCaaSDex.sol";
import {GovernanceLib} from "../../../../src/governance/GovernanceLib.sol";
import {TradeLib} from "../../../../src/trade/TradeLib.sol";
import {MtxPipelineLib} from "../../../../src/metatx/MtxPipelineLib.sol";
import {WrappedLib} from "../../../../src/metatx/WrappedLib.sol";
import {MtxRelayFee} from "../../../../src/metatx/MtxRelayFee.sol";
import {ZetherLib} from "../../../../src/zether/ZetherLib.sol";
import {ZetherWrappedLib} from "../../../../src/zether/ZetherWrappedLib.sol";
import {PqzWrappedLib} from "../../../../src/pqz/PqzWrappedLib.sol";
import {PqzStateLib} from "../../../../src/pqz/PqzStateLib.sol";
import {PqzTransferLib} from "../../../../src/pqz/PqzTransferLib.sol";
import {PqzBurnLib} from "../../../../src/pqz/PqzBurnLib.sol";
import {PqzViewLib} from "../../../../src/pqz/PqzViewLib.sol";
import {HederaLib} from "../../../../src/hedera/HederaLib.sol";
import {UARegistryLib} from "../../../../src/ua/UARegistryLib.sol";
import {plainEnv, pinned} from "../../../../test/helpers/Catalogue.sol";
import {ZUID} from "../../../../test/zether/helpers/ZetherFixture.sol";
import {ZetherDisclosure} from "../../../../src/zether/ZetherDisclosure.sol";
import {
    ZetherInnerProductVerifierBls12381,
    ZetherTransferVerifierBls12381,
    ZetherBurnVerifierBls12381
} from "../../../../src/zether/ZetherVerifier.sol";

/// @notice `ZetherDeploy.t.sol`'s probe, here so the D runs need not compile that test.
contract T0Create2Probe {
    function deploy(bytes calldata code, bytes32 salt) external returns (address a) {
        bytes memory c = code;
        assembly ("memory-safe") { a := create2(0, add(c, 32), mload(c), salt) }
    }
}

/// @notice ua-mtx-merge T10 (plan step 4, the deploy-gas summary): T0's `T0Deploy.t.sol` (branch `ua-mtx-merge-t0`, kept
///         there) on the merged tree, the same method and line format, plus `HederaLib`, the four PQZ libraries and
///         `UARegistryLib` (each its own transaction). Run by `t10_deploy_gas.sh`; not part of the suite.
/// @notice T0 of the ua*/mtx* merge plan (spec §9 step 3): the deploy gas of every implementation and library, each its own
///         transaction, by `GovDeploy.t.sol`'s `test_releaseGasPerKind` method: regular x 64/63 (the probe's call) + EIP-8037
///         state gas, x 1.05 (`--gas-estimate-multiplier 105`). Printed against 60 M and 70 M (regular + state <= the limit,
///         never `gas_used`), and regular x 1.05 against 2^24. ABI-free: the same file runs on the base and every lever run.
///         `TokenBodyLib` (lever L) and the regulated stand-ins are measured by their own files in their runs.
contract T10DeployGasTest is Test {
    address ska = new SmartKeyAccountFactory(ZUID).IMPLEMENTATION();
    address[] zdeps;
    T0Create2Probe probe;

    function _line(string memory name, bytes memory code, address a, Vm.Gas memory g) internal {
        uint256 regular = g.gasTotalUsed * 64 / 63;
        uint256 state = uint256(int256(g.gasStateUsed));
        uint256 asked = (regular + state) * 105 / 100;
        emit log(string.concat("T0DEPLOY | ", name, " | runtime ", vm.toString(a.code.length), " | init ",
            vm.toString(code.length), " | regular ", vm.toString(regular), " | state ", vm.toString(state), " | asked ",
            vm.toString(asked), " | 60M ", asked <= 60_000_000 ? "fits" : "NO", " | 70M ", asked <= 70_000_000 ? "fits" : "NO",
            " | reg105<2^24 ", regular * 105 / 100 < 1 << 24 ? "yes" : "NO"));
    }

    function _one(string memory name, bytes memory code, uint256 salt) internal {
        address a = probe.deploy(code, bytes32(salt));
        Vm.Gas memory g = vm.lastCallGas();
        assertTrue(a != address(0), name);
        _line(name, code, a, g);
    }

    function test_t0DeployGas() public {
        probe = new T0Create2Probe();
        address router = address(new GovernanceRouter(ZUID, address(this), ska, false));
        ZetherInnerProductVerifierBls12381 ip = new ZetherInnerProductVerifierBls12381();
        zdeps = [address(new ZetherTransferVerifierBls12381(ip)), address(new ZetherBurnVerifierBls12381(ip)), address(ip),
            address(new ZetherDisclosure())];
        _one("NormalToken", _release(type(NormalToken).creationCode, IOpenFactory.TokenKind.NORMAL, router), 1);
        _one("WrappedToken", _release(type(WrappedToken).creationCode, IOpenFactory.TokenKind.WRAPPED, router), 2);
        _one("NormalZetherToken", _release(type(NormalZetherToken).creationCode, IOpenFactory.TokenKind.NORMAL_ZETHER, router), 3);
        _one("WrappedZetherToken", _release(type(WrappedZetherToken).creationCode, IOpenFactory.TokenKind.WRAPPED_ZETHER, router), 4);
        _one("NormalPqzToken", _release(type(NormalPqzToken).creationCode, IOpenFactory.TokenKind.NORMAL_PQZ, router), 5);
        _one("WrappedPqzToken", _release(type(WrappedPqzToken).creationCode, IOpenFactory.TokenKind.WRAPPED_PQZ, router), 6);
        _one("SCaaSDex", _dex(router), 7);
        _one("GovernanceRouter", abi.encodePacked(type(GovernanceRouter).creationCode, abi.encode(ZUID, address(this), ska, false)), 8);
        _one("MtxRelayFee", type(MtxRelayFee).creationCode, 9);
        _one("MtxPipelineLib", type(MtxPipelineLib).creationCode, 10);
        _one("WrappedLib", type(WrappedLib).creationCode, 11);
        _one("TradeLib", type(TradeLib).creationCode, 12);
        _one("GovernanceLib", type(GovernanceLib).creationCode, 13);
        _one("ZetherLib", type(ZetherLib).creationCode, 14);
        _one("ZetherWrappedLib", type(ZetherWrappedLib).creationCode, 15);
        _one("PqzWrappedLib", type(PqzWrappedLib).creationCode, 16);
        _one("HederaLib", type(HederaLib).creationCode, 17);
        _one("PqzStateLib", type(PqzStateLib).creationCode, 18);
        _one("PqzTransferLib", type(PqzTransferLib).creationCode, 19);
        _one("PqzBurnLib", type(PqzBurnLib).creationCode, 20);
        _one("PqzViewLib", type(PqzViewLib).creationCode, 21);
        _one("UARegistryLib", type(UARegistryLib).creationCode, 22);
    }

    /// The frame `deployImplementation` adds (spec §9 step 3), once: the `NORMAL` release through the factory against the
    /// same init code through the probe; the difference is the frame (the factory's checks, its CREATE2, the release record).
    function test_t0FactoryFrame() public {
        probe = new T0Create2Probe();
        address router = address(new GovernanceRouter(ZUID, address(this), ska, false));
        OpenFactory f = new OpenFactory(address(this), ZUID, 0);
        IFactoryToken.Env memory e = pinned(plainEnv(address(f), ska, ZUID, address(this), false), IOpenFactory.TokenKind.NORMAL);
        e.govRouter = router;
        uint16 v = 1;
        f.publishEnv(IOpenFactory.TokenKind.NORMAL, v, e);
        bytes memory code = type(NormalToken).creationCode;
        address a = f.deployImplementation(IOpenFactory.TokenKind.NORMAL, 1, v, code, "");
        Vm.Gas memory g = vm.lastCallGas();
        _line("NormalToken via deployImplementation", code, a, g);
        _one("NormalToken via probe, same env", abi.encodePacked(code, abi.encode(v, e, bytes(""))), 99);
    }

    function _release(bytes memory code, IOpenFactory.TokenKind kind, address router) internal view returns (bytes memory) {
        IFactoryToken.Env memory e = pinned(plainEnv(address(this), ska, ZUID, address(this), false), kind);
        e.govRouter = router;
        if (uint8(kind) >= 2) e.smartKeyAccountImpl = address(0);
        if (uint8(kind) == 2 || uint8(kind) == 3) e.deps = zdeps;
        if (uint8(kind) >= 4) {
            e.deps = new address[](1);
            e.deps[0] = router;
        }
        return abi.encodePacked(code, abi.encode(uint16(1), e, bytes("")));
    }

    function _dex(address router) internal view returns (bytes memory) {
        IFactoryToken.Env memory e = plainEnv(address(this), ska, ZUID, address(0), false);
        e.libs = new address[](2);
        (e.libs[0], e.libs[1]) = (address(GovernanceLib), address(TradeLib));
        e.libCodeHashes = new bytes32[](2);
        (e.libCodeHashes[0], e.libCodeHashes[1]) = (address(GovernanceLib).codehash, address(TradeLib).codehash);
        e.govRouter = router;
        return abi.encodePacked(type(SCaaSDex).creationCode, abi.encode(uint16(1), e, bytes("")));
    }
}
