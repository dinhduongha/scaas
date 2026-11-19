// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UALedgerBase} from "../ua/UALedgerBase.sol";
import {SdkGasOps} from "./SdkGasOps.sol";

/// The UA ledger fixture for the SDK gas rows with derived signers (owner 2026-11-19, item 7 and A1): the ledger's registry
/// redeployed at `REG_L` as a deploy makes it (G4, `SdkGasDeploy`: every gen-1 kind on its real verifier at the deploy's cap,
/// the forge-signable P-256 (0x0101), ed25519 (0x0102) and secp256k1 (0x0108) among them, and the `SmartKeyAccount`
/// implementation the fixture's tokens name too); the fixture's earlier registrations stay (the storage is kept).
abstract contract SdkGasLedger is SdkGasOps, UALedgerBase {
    /// G4: the deploy's `SmartKeyAccount` implementation first, so the fixture's tokens name it.
    function setUp() public virtual override {
        _sgSkaSetup(vm.parseJsonBytes32(_structures(), ".contexts.A.chainUid"));
        super.setUp();
    }

    function _fixtureSka() internal view override returns (address) {
        return sgSka;
    }

    /// The ledger's registry made again as a deploy makes it (G4, `SdkGasDeploy`): the real verifiers of every gen-1 kind.
    function _sgVerifiers() internal {
        _sgDeployRegistry(REG_L, chainUidA, _sgNoKeep());
        lreg = UARegistry(REG_L);
    }

    /// The UA of `kind` from secret `sk`, registered on the ledger's registry with its PoP: its id and key data.
    function _sgRegister(uint16 kind, uint256 sk) internal returns (bytes32 ua, bytes memory k) {
        return _sgRegisterOn(address(lreg), kind, sk);
    }

    /// A1: the derived reference signer, registered; the fixture gives it what the native signer holds.
    function _sgUaSigner() internal returns (bytes32) {
        return _sgUaSignerOn(address(lreg));
    }
}
