// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {AdminLib} from "../metatx/AdminLib.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {MtxPipelineLib} from "../metatx/MtxPipelineLib.sol";
import {WrappedLib} from "../metatx/WrappedLib.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../confidential/IConfidentialToken.sol";
import {IPqzToken, IPqzWrappedToken} from "./IPqzToken.sol";
import {PqzStateLib} from "./PqzStateLib.sol";

/// @title The hot-path-free code of `WrappedPqzToken` behind external calls (size lever 1, owner 2026-11-01): the init path
///        and the selector table, the two parts of the token no signed op runs.
/// @notice **UNAUDITED.** External library in the release's link closure of `WRAPPED_PQZ` only. `init` chains `WrappedLib` and
///         `PqzStateLib` by DELEGATECALL, still in the token's context: `LinkClosure.test_libraryOpcodes` pins exactly these
///         two. No state of its own, no immutable.
library PqzWrappedLib {
    uint8 private constant ABSOLUTE = MtxPipelineLib.FEE_CLASS_ABSOLUTE;
    uint8 private constant AMOUNT = MtxPipelineLib.FEE_CLASS_AMOUNT;

    /// @notice The kind's init from the factory's raw `initArgs`: `initialSupply` and `initialHolder` empty, `legs`, the
    ///         rate and `conf` are checked by the two libraries. Never on Hedera (`PqzLayer` refuses that env).
    function init(bytes calldata initArgs, address registry, address verifier) public {
        IFactoryToken.TokenConfig memory cfg = abi.decode(initArgs, (IFactoryToken.TokenConfig));
        if (cfg.initialSupply != 0 || cfg.initialHolder != address(0)) revert IFactoryToken.ConfigFieldForOtherKind(1);
        WrappedLib.initToken(cfg, false, AdminLib.KIND_WRAPPED_PQZ);
        PqzStateLib.init(cfg.conf, registry, verifier);
    }

    /// @notice `mtxSelectors()` of the kind: `WrappedToken`'s eight, then the PQZ ops and the two leg paths, each `ABSOLUTE`
    ///         (incl. the rollover and `mtxPrepareAcc`).
    function selectors() public pure returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a) {
        s = new bytes4[](18);
        c = new uint8[](18);
        a = new uint8[](18);
        (s[0], c[0]) = (IMetaTx.cancelNonce.selector, ABSOLUTE);
        (s[1], c[1]) = (bytes4(keccak256("wrap(uint256)")), ABSOLUTE);
        (s[2], c[2]) = (bytes4(keccak256("unwrap(uint256,address,uint256)")), AMOUNT);
        (s[3], c[3]) = (bytes4(keccak256("wrap(address,uint256)")), ABSOLUTE);
        (s[4], c[4], a[4]) = (bytes4(keccak256("unwrap(address,uint256,address,uint256)")), AMOUNT, 1);
        (s[5], c[5]) = (bytes4(keccak256("addReserve(address,uint256)")), ABSOLUTE);
        (s[6], c[6]) = (bytes4(keccak256("wrapToUA(address,uint256,bytes32)")), ABSOLUTE);
        (s[7], c[7], a[7]) = (bytes4(keccak256("unwrapToUA(address,uint256,bytes32,uint256)")), AMOUNT, 1);
        (s[8], c[8]) = (IConfidentialToken.mtxShield.selector, ABSOLUTE);
        (s[9], c[9]) = (IPqzToken.mtxConfidentialTransfer.selector, ABSOLUTE);
        (s[10], c[10]) = (IPqzToken.mtxConfidentialTransferCompact.selector, ABSOLUTE);
        (s[11], c[11]) = (IPqzToken.mtxUnshield.selector, ABSOLUTE);
        (s[12], c[12]) = (IConfidentialWrappedToken.mtxWrapShield.selector, ABSOLUTE);
        (s[13], c[13]) = (IPqzWrappedToken.mtxUnshieldUnwrap.selector, ABSOLUTE);
        (s[14], c[14]) = (IPqzToken.mtxConfidentialTransferSingle.selector, ABSOLUTE);
        (s[15], c[15]) = (IPqzToken.mtxConfidentialTransferSingleCompact.selector, ABSOLUTE);
        (s[16], c[16]) = (IConfidentialToken.mtxRollOver.selector, ABSOLUTE);
        (s[17], c[17]) = (IPqzToken.mtxPrepareAcc.selector, ABSOLUTE);
    }
}
