// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {nid} from "../helpers/Ids.sol";
import {SdkGasPqzBase} from "./SdkGasConfidential.t.sol";

/// The enveloped (relayed) forms of the `pqz` kind's non-debit entries the SDK prepares (`entries/pqz.rs`, `zether.rs`'s
/// shields).
interface ISdkGasPqz {
    function mtxShield(MetaTxLib.UAEnvelope calldata e, bytes32 toUA, uint256 amount, IUARegistry.UASig calldata auth)
        external
        returns (bytes memory);
    function mtxWrapShield(
        MetaTxLib.Envelope calldata e,
        address underlying,
        uint256 amountIn,
        bytes32 toUA,
        bytes calldata sig
    ) external returns (bytes memory);
    function mtxRollOver(
        MetaTxLib.UAEnvelope calldata e,
        bytes32 ua,
        uint64 keyVersion,
        uint256 n,
        IUARegistry.UASig calldata auth
    ) external returns (bytes memory);
    function mtxPrepareAcc(
        MetaTxLib.UAEnvelope calldata e,
        bytes32 ua,
        uint64 keyVersion,
        uint256 half,
        IUARegistry.UASig calldata auth
    ) external returns (bytes memory);
}

/// The `pqz` kind's confidential base rows (scaas-sdk spec §13.3; PQZ only, Zether ≠ PQZ) at the build's parameter set,
/// the default `n2304-kmax4096` (`PqzSet.NAME`; no `at-set.sh` run): each entry's enveloped form on the kind's Normal
/// and Wrapped tokens, plain and regulated (`SdkGasKindBase`'s config), relayed and signed by the reference signer
/// (`signer`'s native key). Each token's state before a row: `signer` holds public units (and, on a Wrapped, the leg
/// `usd` approved); `alice` holds `BAL` shielded units (a TRIVIAL entry), the sender of the debits; `more[3]` holds one
/// pending entry of an earlier block and no `acc` (the first roll-over); `more[4]` is registered and holds nothing (the
/// first prepare of each half); `bob`, the receiver of the shields and transfers, holds nothing (a first write), as do
/// `carol`, the multi transfers' second receiver, and `0xD00D`, the unshields' recipient. `mtxPrepareAcc` counts both
/// halves (`<variant>` half 0, `<variant>_half1`). G2: the derived reference signer
/// (`SdkGasPqzBase`, on the fixture's registry made again as a deploy makes it) holds `signer`'s public units in its run.
///
/// The debits (`mtxConfidentialTransfer`, `…Compact`, `…Single`, `…SingleCompact`, `mtxUnshield`, `mtxUnshieldUnwrap`) are
/// not here: the fixture mocks the `PQZ` precompile and the holder's ML-DSA authorization, the bulk of a real debit, so a
/// row of it would understate (still unmeasured, reported).
contract SdkGasConfPqzTest is SdkGasPqzBase {
    function setUp() public override {
        super.setUp();
        sgPk = PK; // the fixture's debit builders sign by `signer`
        _proofs(1);
    }

    // ------------------------------------------------------------------ fixture

    /// `units` public units of `t` to `to`: a mint, or a 1:1 wrap of `usd` on a Wrapped.
    function _pPub(address t, bool wrapped, address to, uint256 units) internal {
        if (!wrapped) return _public(NormalPqzToken(t), to, units);
        usd.mint(address(this), units);
        usd.approve(t, units);
        WrappedToken(payable(t)).wrap(address(usd), units);
        if (to != address(this)) WrappedToken(payable(t)).transfer(to, units);
    }

    function _pPrep(address t, bool wrapped) internal {
        (tok, w) = (NormalPqzToken(t), WrappedPqzToken(payable(t))); // the fixture's builders read `tok`
        _pPub(t, wrapped, signer, 1e10);
        if (wrapped) {
            usd.mint(signer, 1e10);
            vm.prank(signer);
            usd.approve(t, type(uint256).max);
        }
        _pPub(t, wrapped, address(this), (BAL + 20) * SCALE);
        tok.mtxShield(alice, BAL);
        tok.mtxShield(more[3], 20);
        vm.roll(block.number + 1);
    }

    function _pAttest() internal {
        address[7] memory ps = [signer, SG_PAYEE, SG_TAX_TO, SG_RELAYER, SG_FEE_TO, address(this), address(0xD00D)];
        for (uint256 i; i < ps.length; ++i) {
            _sgAttest(nid(ps[i]));
        }
        _sgAttest(UAKinds.uaOf(sgUaKind, sgUaKey)); // G2: the derived reference signer
        bytes32[5] memory us = [alice, bob, carol, more[3], more[4]];
        for (uint256 i; i < us.length; ++i) {
            _sgAttest(us[i]);
        }
    }

    function _pToken(bool wrapped, bool reg) internal returns (address t, string memory v) {
        v = wrapped ? (reg ? "wrapped_reg" : "wrapped") : (reg ? "normal_reg" : "normal");
        t = _sgCreate(wrapped, reg, wrapped ? address(usd) : address(0), keccak256(abi.encode("sgp", wrapped, reg)));
        _pPrep(t, wrapped);
    }

    function _pRows(bool reg) internal {
        if (reg) _pAttest();
        for (uint256 i; i < 2; ++i) {
            (address t, string memory v) = _pToken(i == 1, reg);
            bytes32 from = _sgFrom();
            _both("pqz", "mtxShield", v, t, from, _pShield);
            _both("pqz", "mtxPrepareAcc", v, t, from, _pPrepare0);
            _both("pqz", "mtxPrepareAcc", string.concat(v, "_half1"), t, from, _pPrepare1);
            if (i == 1) _both("pqz", "mtxWrapShield", v, t, from, _pWrapShield);
        }
    }

    function test_sdkGas_pqzConf() public {
        _pRows(false);
    }

    function test_sdkGas_pqzConfRegulated() public {
        _pRows(true);
    }

    // ------------------------------------------------------------------ the entries' calldata

    function _pShield(address c, uint256 nonce) internal view returns (bytes memory) {
        uint256 amt = _amt(10);
        bytes32 d = _sgNamed(c, "UAShield(bytes32 from,bytes32 toUA,uint256 amount,", abi.encode(bob, amt), nonce);
        return abi.encodeCall(ISdkGasPqz.mtxShield, (_sgE(nonce), bob, amt, _sgUaSig(d)));
    }

    function _pWrapShield(address c, uint256 nonce) internal view returns (bytes memory) {
        uint256 amt = 10 * SCALE;
        bytes32 d = _sgNamed(
            c,
            "WrapShield(address from,address underlying,uint256 amountIn,bytes32 toUA,",
            abi.encode(address(usd), amt, bob),
            nonce
        );
        return abi.encodeCall(ISdkGasPqz.mtxWrapShield, (_sgAddrE(nonce), address(usd), amt, bob, _sgSign(sgPk, d)));
    }

    function _pPrepare(address c, uint256 nonce, uint256 half) internal view returns (bytes memory) {
        bytes32 d = _sgNamed(
            c,
            "UAPrepareAcc(bytes32 from,bytes32 ua,uint64 keyVersion,uint256 half,",
            abi.encode(more[4], 0, half),
            nonce
        );
        return abi.encodeCall(ISdkGasPqz.mtxPrepareAcc, (_sgE(nonce), more[4], 0, half, _sgUaSig(d)));
    }

    function _pPrepare0(address c, uint256 nonce) internal view returns (bytes memory) {
        return _pPrepare(c, nonce, 0);
    }

    function _pPrepare1(address c, uint256 nonce) internal view returns (bytes memory) {
        return _pPrepare(c, nonce, 1);
    }
}
